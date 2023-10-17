use hashbrown::HashSet;
use p256k1::{point::Point, scalar::Scalar};
use std::collections::BTreeMap;
use tracing::{debug, info};

use crate::{
    common::{MerkleRoot, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    net::{
        DkgBegin, DkgPublicShares, Message, NonceRequest, NonceResponse, Packet, Signable,
        SignatureShareRequest,
    },
    state_machine::{
        coordinator::{Coordinator as CoordinatorTrait, Error, State},
        OperationResult, StateMachine,
    },
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
};

/// The coordinator for the FIRE algorithm
pub struct Coordinator<Aggregator: AggregatorTrait> {
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    current_sign_id: u64,
    /// current signing iteration ID
    current_sign_iter_id: u64,
    /// total number of signers
    pub total_signers: u32, // Assuming the signers cover all id:s in {1, 2, ..., total_signers}
    /// total number of keys
    pub total_keys: u32,
    /// the threshold of the keys needed for a valid signature
    pub threshold: u32,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    party_polynomials: BTreeMap<u32, PolyCommitment>,
    public_nonces: BTreeMap<u32, NonceResponse>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// key used to sign packet messages
    pub message_private_key: Scalar,
    /// which signers we're currently waiting on for DKG
    pub dkg_wait_ids: HashSet<u32>,
    /// which signers we're currently waiting on for nonces
    pub nonce_wait_ids: HashSet<u32>,
    /// which signers we're currently waiting on for sig shares
    pub sig_share_wait_ids: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: Aggregator,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        loop {
            match self.state {
                State::Idle => {
                    // do nothing
                    // We are the coordinator and should be the only thing triggering messages right now
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let packet = self.start_public_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(packet)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let packet = self.start_private_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgEndGather => {
                    self.gather_dkg_end(packet)?;
                    if self.state == State::DkgEndGather {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
                    }
                }
                State::NonceRequest(is_taproot, merkle_root) => {
                    let packet = self.request_nonces(is_taproot, merkle_root)?;
                    return Ok((Some(packet), None));
                }
                State::NonceGather(is_taproot, merkle_root) => {
                    self.gather_nonces(packet, is_taproot, merkle_root)?;
                    if self.state == State::NonceGather(is_taproot, merkle_root) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(is_taproot, merkle_root) => {
                    let packet = self.request_sig_shares(is_taproot, merkle_root)?;
                    return Ok((Some(packet), None));
                }
                State::SigShareGather(is_taproot, merkle_root) => {
                    self.gather_sig_shares(packet, is_taproot, merkle_root)?;
                    if self.state == State::SigShareGather(is_taproot, merkle_root) {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        if is_taproot {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignTaproot(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else {
                            let signature =
                                self.signature.as_ref().ok_or(Error::MissingSignature)?;
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Start a DKG round
    pub fn start_dkg_round(&mut self) -> Result<Packet, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    pub fn start_signing_round(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.current_sign_id = self.current_sign_id.wrapping_add(1);
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(is_taproot, merkle_root))?;
        self.request_nonces(is_taproot, merkle_root)
    }

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        info!(
            "DKG Round {}: Starting Public Share Distribution",
            self.current_dkg_id,
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_packet = Packet {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: Message::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_packet)
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        info!(
            "DKG Round {}: Starting Private Share Distribution",
            self.current_dkg_id
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(dkg_private_begin_msg)
    }

    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            self.dkg_wait_ids.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                "DKG round {} DkgPublicShares from signer {}",
                dkg_public_shares.dkg_id, dkg_public_shares.signer_id
            );
        }

        if self.dkg_wait_ids.is_empty() {
            // Calculate the aggregate public key
            let key = self
                .party_polynomials
                .iter()
                .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

            info!("Aggregate public key: {}", key);
            self.aggregate_public_key = Some(key);
            self.move_to(State::DkgPrivateDistribute)?;
            self.dkg_wait_ids = (0..self.total_signers).collect();
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
        debug!(
            "DKG Round {}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.dkg_wait_ids
        );
        if let Message::DkgEnd(dkg_end) = &packet.msg {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            self.dkg_wait_ids.remove(&dkg_end.signer_id);
            debug!(
                "DKG_End round {} from signer {}. Waiting on {:?}",
                dkg_end.dkg_id, dkg_end.signer_id, self.dkg_wait_ids
            );
        }

        if self.dkg_wait_ids.is_empty() {
            self.dkg_wait_ids = (0..self.total_signers).collect();
            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    fn request_nonces(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.public_nonces.clear();
        info!(
            "Sign Round {} Nonce round {} Requesting Nonces",
            self.current_sign_id, self.current_sign_iter_id,
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request.sign(&self.message_private_key).expect(""),
            msg: Message::NonceRequest(nonce_request),
        };
        self.nonce_wait_ids = (0..self.total_signers).collect();
        self.move_to(State::NonceGather(is_taproot, merkle_root))?;
        Ok(nonce_request_msg)
    }

    fn gather_nonces(
        &mut self,
        packet: &Packet,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.nonce_wait_ids.remove(&nonce_response.signer_id);
            debug!(
                "Sign round {} nonce round {} NonceResponse from signer {}. Waiting on {:?}",
                nonce_response.sign_id,
                nonce_response.sign_iter_id,
                nonce_response.signer_id,
                self.nonce_wait_ids
            );
        }
        if self.nonce_wait_ids.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!("Aggregate nonce: {}", aggregate_nonce);

            self.move_to(State::SigShareRequest(is_taproot, merkle_root))?;
        }
        Ok(())
    }

    fn request_sig_shares(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            "Sign Round {} Requesting Signature Shares",
            self.current_sign_id,
        );
        let nonce_responses = (0..self.total_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            is_taproot,
            merkle_root,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request.sign(&self.message_private_key).expect(""),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.sig_share_wait_ids = (0..self.total_signers).collect();
        self.move_to(State::SigShareGather(is_taproot, merkle_root))?;

        Ok(sig_share_request_msg)
    }

    fn gather_sig_shares(
        &mut self,
        packet: &Packet,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<(), Error> {
        if let Message::SignatureShareResponse(sig_share_response) = &packet.msg {
            if sig_share_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    sig_share_response.dkg_id,
                    self.current_dkg_id,
                ));
            }
            if sig_share_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    sig_share_response.sign_id,
                    self.current_sign_id,
                ));
            }
            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            self.sig_share_wait_ids
                .remove(&sig_share_response.signer_id);
            debug!(
                "Sign round {} SignatureShareResponse from signer {}. Waiting on {:?}",
                sig_share_response.sign_id, sig_share_response.signer_id, self.sig_share_wait_ids
            );
        }
        if self.sig_share_wait_ids.is_empty() {
            // Calculate the aggregate signature
            let polys: Vec<PolyCommitment> = self.party_polynomials.values().cloned().collect();

            let nonce_responses = (0..self.total_signers)
                .map(|i| self.public_nonces[&i].clone())
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = &self
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({:?}, {:?}, {:?})",
                self.message,
                nonces.len(),
                shares.len()
            );

            self.aggregator.init(polys)?;

            if is_taproot {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    shares,
                    &key_ids,
                    merkle_root,
                )?;
                info!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, shares, &key_ids)?;
                info!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }

            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let party_ids = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.key_ids.clone())
            .collect::<Vec<u32>>();
        let nonces = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.nonces.clone())
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }
}

impl<Aggregator: AggregatorTrait> StateMachine<State, Error> for Coordinator<Aggregator> {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgPublicGather
                    || prev_state == &State::DkgEndGather
            }
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgEndGather => prev_state == &State::DkgPrivateDistribute,
            State::NonceRequest(_, _) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
            }
            State::NonceGather(is_taproot, merkle_root) => {
                prev_state == &State::NonceRequest(*is_taproot, *merkle_root)
                    || prev_state == &State::NonceGather(*is_taproot, *merkle_root)
            }
            State::SigShareRequest(is_taproot, merkle_root) => {
                prev_state == &State::NonceGather(*is_taproot, *merkle_root)
            }
            State::SigShareGather(is_taproot, merkle_root) => {
                prev_state == &State::SigShareRequest(*is_taproot, *merkle_root)
                    || prev_state == &State::SigShareGather(*is_taproot, *merkle_root)
            }
        };
        if accepted {
            debug!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}

impl<Aggregator: AggregatorTrait> CoordinatorTrait for Coordinator<Aggregator> {
    /// Create a new coordinator
    fn new(
        total_signers: u32,
        total_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Self {
            current_dkg_id: 0,
            current_sign_id: 0,
            current_sign_iter_id: 0,
            total_signers,
            total_keys,
            threshold,
            dkg_public_shares: Default::default(),
            party_polynomials: Default::default(),
            public_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            message_private_key,
            dkg_wait_ids: Default::default(),
            nonce_wait_ids: Default::default(),
            sig_share_wait_ids: Default::default(),
            state: State::Idle,
            aggregator: Aggregator::new(total_keys, threshold),
        }
    }

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: &[Packet],
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error> {
        let mut outbound_packets = vec![];
        let mut operation_results = vec![];
        for packet in packets {
            let (outbound_packet, operation_result) = self.process_message(packet)?;
            if let Some(outbound_packet) = outbound_packet {
                outbound_packets.push(outbound_packet);
            }
            if let Some(operation_result) = operation_result {
                operation_results.push(operation_result);
            }
        }
        Ok((outbound_packets, operation_results))
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point> {
        self.aggregate_public_key
    }

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>) {
        self.aggregate_public_key = aggregate_public_key;
    }

    /// Retrive the current state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Set the current state
    fn set_state(&mut self, state: State) {
        self.state = state;
    }

    /// Trigger a DKG round
    fn start_distributed_key_generation(&mut self) -> Result<Packet, Error> {
        self.start_dkg_round()
    }

    // Trigger a signing round
    fn start_signing_message(
        &mut self,
        message: &[u8],
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.message = message.to_vec();
        self.start_signing_round(is_taproot, merkle_root)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.public_nonces.clear();
        self.signature_shares.clear();
        self.dkg_wait_ids = (0..self.total_signers).collect();
        self.nonce_wait_ids = (0..self.total_signers).collect();
        self.sig_share_wait_ids = (0..self.total_signers).collect();
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        net::Message,
        state_machine::{
            coordinator::{
                fire::Coordinator as FireCoordinator, Coordinator as CoordinatorTrait,
                State as CoordinatorState,
            },
            test::{feedback_messages, setup, test_process_inbound_messages},
            OperationResult,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        v1, v2, Point,
    };

    #[test]
    fn test_process_inbound_messages_v1() {
        test_process_inbound_messages::<FireCoordinator<v1::Aggregator>, v1::Signer>();
    }

    #[test]
    fn test_process_inbound_messages_v2() {
        test_process_inbound_messages::<FireCoordinator<v2::Aggregator>, v2::Signer>();
    }

    #[test]
    fn test_valid_threshold_v1() {
        test_valid_threshold::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn test_valid_threshold_v2() {
        test_valid_threshold::<v2::Aggregator, v2::Signer>();
    }

    fn test_valid_threshold<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let (mut coordinator, mut signing_rounds) = setup::<FireCoordinator<Aggregator>, Signer>();

        // We have started a dkg round
        let message = coordinator.start_distributed_key_generation().unwrap();
        assert!(coordinator.aggregate_public_key.is_none());
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(coordinator.state, CoordinatorState::DkgEndGather);

        // Successfully got an Aggregate Public Key...
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }
        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                assert_eq!(coordinator.aggregate_public_key, Some(point));
                assert_eq!(coordinator.state, CoordinatorState::Idle);
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // We have started a signing round
        let msg = vec![1, 2, 3];
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinator
            .start_signing_message(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            coordinator.state,
            CoordinatorState::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinator.state,
            CoordinatorState::SigShareGather(is_taproot, merkle_root)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinator
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        assert_eq!(coordinator.state, CoordinatorState::Idle);
    }
}
