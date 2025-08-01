use hashbrown::{HashMap, HashSet};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::{
    common::{PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{ecdsa, point::Point},
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares,
        DkgStatus, Message, NonceRequest, NonceResponse, Packet, Signable, SignatureShareRequest,
        SignatureType,
    },
    state_machine::{
        coordinator::{
            Config, Coordinator as CoordinatorTrait, Error, SavedState, SignRoundInfo, State,
        },
        DkgError, OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
};

/// The coordinator for the FROST algorithm
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator<Aggregator: AggregatorTrait> {
    /// common config fields
    config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    current_sign_id: u64,
    /// current signing iteration ID
    current_sign_iter_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    dkg_end_messages: BTreeMap<u32, DkgEnd>,
    party_polynomials: HashMap<u32, PolyCommitment>,
    public_nonces: BTreeMap<u32, NonceResponse>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on
    pub ids_to_await: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: Aggregator,
    /// coordinator public key
    pub coordinator_public_key: Option<ecdsa::PublicKey>,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
        loop {
            match self.state.clone() {
                State::Idle => {
                    // Did we receive a coordinator message?
                    if let Message::DkgBegin(dkg_begin) = &packet.msg {
                        if self.current_dkg_id == dkg_begin.dkg_id {
                            // We have already processed this DKG round
                            return Ok((None, None));
                        }
                        // use dkg_id from DkgBegin
                        let packet = self.start_dkg_round(Some(dkg_begin.dkg_id))?;
                        return Ok((Some(packet), None));
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        if self.current_sign_id == nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        self.current_sign_iter_id = nonce_request.sign_iter_id;
                        // use sign_id from NonceRequest
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                            Some(nonce_request.sign_id),
                        )?;
                        return Ok((Some(packet), None));
                    }
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
                State::DkgPrivateGather => {
                    self.gather_private_shares(packet)?;
                    if self.state == State::DkgPrivateGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgEndDistribute => {
                    let packet = self.start_dkg_end()?;
                    return Ok((Some(packet), None));
                }
                State::DkgEndGather => {
                    if let Err(error) = self.gather_dkg_end(packet) {
                        if let Error::DkgFailure {
                            reported_failures,
                            malicious_signers,
                        } = error
                        {
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndFailure {
                                    reported_failures,
                                    malicious_signers,
                                })),
                            ));
                        } else {
                            return Err(error);
                        }
                    }
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
                State::NonceRequest(signature_type) => {
                    let packet = self.request_nonces(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::NonceGather(signature_type) => {
                    self.gather_nonces(packet, signature_type)?;
                    if self.state == State::NonceGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(signature_type) => {
                    let packet = self.request_sig_shares(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
                    }
                    if self.state == State::SigShareGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        if let SignatureType::Taproot(_) = signature_type {
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
                        } else if let SignatureType::Schnorr = signature_type {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignSchnorr(SchnorrProof {
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

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_packet)
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Private Share Distribution"
        );
        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (1..self.config.num_keys + 1).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgPrivateGather)?;
        Ok(dkg_private_begin_msg)
    }

    /// Ask signers to compute secrets and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting DKG End Distribution"
        );
        let dkg_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (0..self.config.num_keys).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        let dkg_end_begin_msg = Packet {
            sig: dkg_begin.sign(&self.config.message_private_key).expect(""),
            msg: Message::DkgEndBegin(dkg_begin),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(dkg_end_begin_msg)
    }

    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }

            self.ids_to_await.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgPrivateDistribute)?;
        }
        Ok(())
    }

    fn gather_private_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPrivateShares(dkg_private_shares) = &packet.msg {
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_private_shares.signer_id) {
                warn!(signer_id = %dkg_private_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let has_received_shares = self
                .dkg_private_shares
                .contains_key(&dkg_private_shares.signer_id);
            if has_received_shares {
                info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
                return Ok(());
            }

            self.ids_to_await.remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                dkg_id = %dkg_private_shares.dkg_id,
                signer_id = %dkg_private_shares.signer_id,
                "DkgPrivateShares received"
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgEndDistribute)?;
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
        debug!(
            dkg_id = %self.current_dkg_id,
            waiting = ?self.ids_to_await,
            "Waiting for Dkg End from signers"
        );
        if let Message::DkgEnd(dkg_end) = &packet.msg {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            if self.ids_to_await.contains(&dkg_end.signer_id) {
                self.ids_to_await.remove(&dkg_end.signer_id);
                self.dkg_end_messages
                    .insert(dkg_end.signer_id, dkg_end.clone());
                debug!(
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    waiting = ?self.ids_to_await,
                    "DkgEnd received"
                );
            }
        }

        if self.ids_to_await.is_empty() {
            let mut reported_failures = HashMap::new();

            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    reported_failures.insert(*signer_id, dkg_failure.clone());
                }
            }

            if reported_failures.is_empty() {
                self.dkg_end_gathered()?;
            } else {
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers: Default::default(),
                });
            }
        }
        Ok(())
    }

    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            let Some(dkg_public_shares) = self.dkg_public_shares.get(signer_id) else {
                warn!(%signer_id, "no DkgPublicShares");
                return Err(Error::BadStateChange(format!("Should not have transitioned to DkgEndGather since we were missing DkgPublicShares from signer {signer_id}")));
            };
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!(
            %key,
            "Aggregate public key"
        );
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }

    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.public_nonces.clear();
        info!(
            sign_id = %self.current_sign_id,
            sign_iter_id = %self.current_sign_iter_id,
            "Requesting Nonces"
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request
                .sign(&self.config.message_private_key)
                .expect(""),
            msg: Message::NonceRequest(nonce_request),
        };
        self.ids_to_await = (0..self.config.num_signers).collect();
        self.move_to(State::NonceGather(signature_type))?;
        Ok(nonce_request_msg)
    }

    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
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

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }

            let have_nonces = self.public_nonces.contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                waiting = ?self.ids_to_await,
                "NonceResponse received"
            );
        }
        if self.ids_to_await.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!(
                %aggregate_nonce,
                "Aggregate nonce"
            );

            self.move_to(State::SigShareRequest(signature_type))?;
        }
        Ok(())
    }

    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            sign_id = %self.current_sign_id,
            "Requesting Signature Shares"
        );
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request
                .sign(&self.config.message_private_key)
                .expect(""),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.ids_to_await = (0..self.config.num_signers).collect();
        self.move_to(State::SigShareGather(signature_type))?;

        Ok(sig_share_request_msg)
    }

    fn gather_sig_shares(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
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

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&sig_share_response.signer_id) {
                warn!(signer_id = %sig_share_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&sig_share_response.signer_id)
            else {
                warn!(signer_id = %sig_share_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let mut sig_share_response_key_ids = HashSet::new();
            for sig_share in &sig_share_response.signature_shares {
                for key_id in &sig_share.key_ids {
                    sig_share_response_key_ids.insert(*key_id);
                }
            }

            if *signer_key_ids != sig_share_response_key_ids {
                warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
                return Ok(());
            }

            let have_shares = self
                .signature_shares
                .contains_key(&sig_share_response.signer_id);

            if have_shares {
                info!(signer_id = %sig_share_response.signer_id, "received duplicate SignatureShareResponse");
                return Ok(());
            }

            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            self.ids_to_await.remove(&sig_share_response.signer_id);
            debug!(
                sign_id = %sig_share_response.sign_id,
                signer_id = %sig_share_response.signer_id,
                waiting = ?self.ids_to_await,
                "SignatureShareResponse received"
            );
        }
        if self.ids_to_await.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = (0..self.config.num_signers)
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
                nonces_len = %nonces.len(),
                shares_len = %shares.len(),
                "aggregator.sign"
            );

            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!(
                    r = %schnorr_proof.r,
                    s = %schnorr_proof.s,
                    "SchnorrProof"
                );
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, shares, &key_ids)?;
                debug!(
                    r = %schnorr_proof.r,
                    s = %schnorr_proof.s,
                    "SchnorrProof"
                );
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, shares, &key_ids)?;
                debug!(
                    R = %signature.R,
                    z = %signature.z,
                    "Signature"
                );
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
            State::DkgPublicDistribute => prev_state == &State::Idle,
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => {
                prev_state == &State::DkgPrivateDistribute || prev_state == &State::DkgPrivateGather
            }
            State::DkgEndDistribute => prev_state == &State::DkgPrivateGather,
            State::DkgEndGather => prev_state == &State::DkgEndDistribute,
            State::NonceRequest(_) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
            }
            State::NonceGather(signature_type) => {
                prev_state == &State::NonceRequest(*signature_type)
                    || prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareRequest(signature_type) => {
                prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareGather(signature_type) => {
                prev_state == &State::SigShareRequest(*signature_type)
                    || prev_state == &State::SigShareGather(*signature_type)
            }
        };
        if accepted {
            debug!("state change from {prev_state:?} to {state:?}");
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{prev_state:?} to {state:?}"
            )))
        }
    }
}

impl<Aggregator: AggregatorTrait> CoordinatorTrait for Coordinator<Aggregator> {
    /// Create a new coordinator
    fn new(config: Config) -> Self {
        Self {
            aggregator: Aggregator::new(config.num_keys, config.threshold),
            config,
            current_dkg_id: 0,
            current_sign_id: 0,
            current_sign_iter_id: 0,
            dkg_public_shares: Default::default(),
            dkg_private_shares: Default::default(),
            dkg_end_messages: Default::default(),
            party_polynomials: Default::default(),
            public_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            ids_to_await: Default::default(),
            state: State::Idle,
            coordinator_public_key: None,
        }
    }

    fn load(state: &SavedState) -> Self {
        Self {
            aggregator: Aggregator::new(state.config.num_keys, state.config.threshold),
            config: state.config.clone(),
            current_dkg_id: state.current_dkg_id,
            current_sign_id: state.current_sign_id,
            current_sign_iter_id: state.current_sign_iter_id,
            dkg_public_shares: state.dkg_public_shares.clone(),
            dkg_private_shares: state.dkg_private_shares.clone(),
            dkg_end_messages: state.dkg_end_messages.clone(),
            party_polynomials: state.party_polynomials.clone(),
            public_nonces: state.message_nonces[&Vec::new()].public_nonces.clone(),
            signature_shares: state.signature_shares.clone(),
            aggregate_public_key: state.aggregate_public_key,
            signature: state.signature.clone(),
            schnorr_proof: state.schnorr_proof.clone(),
            message: state.message.clone(),
            ids_to_await: state.dkg_wait_signer_ids.clone(),
            state: state.state.clone(),
            coordinator_public_key: state.coordinator_public_key,
        }
    }

    fn save(&self) -> SavedState {
        let round_info = SignRoundInfo {
            public_nonces: self.public_nonces.clone(),
            nonce_recv_key_ids: Default::default(),
            sign_recv_key_ids: Default::default(),
            sign_wait_signer_ids: Default::default(),
        };
        let mut message_nonces = BTreeMap::new();

        message_nonces.insert(Vec::new(), round_info);

        SavedState {
            config: self.config.clone(),
            current_dkg_id: self.current_dkg_id,
            current_sign_id: self.current_sign_id,
            current_sign_iter_id: self.current_sign_iter_id,
            dkg_public_shares: self.dkg_public_shares.clone(),
            dkg_private_shares: self.dkg_private_shares.clone(),
            dkg_end_messages: self.dkg_end_messages.clone(),
            party_polynomials: self.party_polynomials.clone(),
            message_nonces,
            signature_shares: self.signature_shares.clone(),
            aggregate_public_key: self.aggregate_public_key,
            signature: self.signature.clone(),
            schnorr_proof: self.schnorr_proof.clone(),
            message: self.message.clone(),
            dkg_wait_signer_ids: self.ids_to_await.clone(),
            state: self.state.clone(),
            dkg_public_start: Default::default(),
            dkg_private_start: Default::default(),
            dkg_end_start: Default::default(),
            nonce_start: Default::default(),
            sign_start: Default::default(),
            malicious_signer_ids: Default::default(),
            malicious_dkg_signer_ids: Default::default(),
            coordinator_public_key: self.coordinator_public_key,
        }
    }

    /// Retrieve the config
    fn get_config(&self) -> Config {
        self.config.clone()
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    fn set_coordinator_public_key(&mut self, key: Option<ecdsa::PublicKey>) {
        self.coordinator_public_key = key;
    }

    /// Set the aggregate key and polynomial commitments used to form that key.
    ///  Check if the polynomial commitments match the key
    fn set_key_and_party_polynomials(
        &mut self,
        aggregate_key: Point,
        party_polynomials: Vec<(u32, PolyCommitment)>,
    ) -> Result<(), Error> {
        let computed_key = party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
        if computed_key != aggregate_key {
            return Err(Error::AggregateKeyPolynomialMismatch(
                computed_key,
                aggregate_key,
            ));
        }
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
        self.aggregate_public_key = Some(aggregate_key);
        self.party_polynomials = party_polynomials;
        Ok(())
    }

    /// Process the message inside the passed packet
    fn process(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        self.process_message(packet)
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point> {
        self.aggregate_public_key
    }

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>) {
        self.aggregate_public_key = aggregate_public_key;
    }

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Retrive the current state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Start a DKG round
    fn start_dkg_round(&mut self, dkg_id: Option<u64>) -> Result<Packet, Error> {
        if let Some(id) = dkg_id {
            self.current_dkg_id = id;
        } else {
            self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        }
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
        sign_id: Option<u64>,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.message = message.to_vec();
        if let Some(id) = sign_id {
            self.current_sign_id = id;
        } else {
            self.current_sign_id = self.current_sign_id.wrapping_add(1);
        }
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(signature_type))?;
        self.request_nonces(signature_type)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.public_nonces.clear();
        self.signature_shares.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
    }
}

#[cfg(test)]
/// Test module for coordinator functionality
pub mod test {
    use super::*;
    #[cfg(feature = "with_v1")]
    use crate::v1;
    use crate::{
        curve::scalar::Scalar,
        net::{DkgBegin, Message, NonceRequest, Packet, SignatureShareResponse, SignatureType},
        schnorr::ID,
        state_machine::coordinator::{
            frost::Coordinator as FrostCoordinator,
            test::{
                bad_signature_share_request, check_signature_shares, coordinator_state_machine,
                empty_private_shares, empty_public_shares, equal_after_save_load, invalid_nonce,
                new_coordinator, run_dkg_sign, setup, start_dkg_round, start_signing_round,
                verify_packet_sigs,
            },
            Config, Coordinator as CoordinatorTrait, State,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        util::create_rng,
        v2,
    };

    #[test]
    #[cfg(feature = "with_v1")]
    fn new_coordinator_v1() {
        new_coordinator::<FrostCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FrostCoordinator<v2::Aggregator>>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn equal_after_save_load_v1() {
        equal_after_save_load::<FrostCoordinator<v1::Aggregator>, v1::Signer>(2, 2);
    }

    #[test]
    fn equal_after_save_load_v2() {
        equal_after_save_load::<FrostCoordinator<v2::Aggregator>, v2::Signer>(2, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn coordinator_state_machine_v1() {
        coordinator_state_machine::<FrostCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FrostCoordinator<v2::Aggregator>>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_dkg_round_v1() {
        start_dkg_round::<FrostCoordinator<v1::Aggregator>>(None);
        start_dkg_round::<FrostCoordinator<v1::Aggregator>>(Some(12345u64));
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FrostCoordinator<v2::Aggregator>>(None);
        start_dkg_round::<FrostCoordinator<v2::Aggregator>>(Some(12345u64));
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_signing_round_v1() {
        start_signing_round::<FrostCoordinator<v1::Aggregator>>(None);
        start_signing_round::<FrostCoordinator<v1::Aggregator>>(Some(12345u64));
    }

    #[test]
    fn start_signing_round_v2() {
        start_signing_round::<FrostCoordinator<v2::Aggregator>>(None);
        start_signing_round::<FrostCoordinator<v2::Aggregator>>(Some(12345u64));
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_public_shares_v1() {
        start_public_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_public_shares_v2() {
        start_public_shares::<v2::Aggregator>();
    }

    fn start_public_shares<Aggregator: AggregatorTrait>() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_private_shares_v1() {
        start_private_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_private_shares_v2() {
        start_private_shares::<v2::Aggregator>();
    }

    fn start_private_shares<Aggregator: AggregatorTrait>() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn dkg_public_share_v1() {
        dkg_public_share::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn dkg_public_share_v2() {
        dkg_public_share::<v1::Aggregator, v2::Signer>();
    }

    /// test basic insertion and detection of duplicates for DkgPublicShares
    #[allow(dead_code)]
    fn dkg_public_share<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let ctx = 0u64.to_be_bytes();
        let mut rng = create_rng();
        let (coordinators, _) = setup::<FrostCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FrostCoordinator<Aggregator> = coordinators[0].clone();

        coordinator.start_dkg_round(None).unwrap(); // = State::DkgPublicGather;
        let public_shares = DkgPublicShares {
            dkg_id: 1,
            signer_id: 0,
            comms: vec![(
                0,
                PolyCommitment {
                    id: ID::new(&Scalar::new(), &Scalar::new(), &ctx, &mut rng),
                    poly: vec![],
                },
            )],
            kex_public_key: Point::from(Scalar::random(&mut rng)),
        };
        let packet = Packet {
            msg: Message::DkgPublicShares(public_shares.clone()),
            sig: Default::default(),
        };
        coordinator.gather_public_shares(&packet).unwrap();
        assert_eq!(1, coordinator.dkg_public_shares.len());

        // check that a duplicate public share is ignored
        let dup_public_shares = DkgPublicShares {
            dkg_id: 1,
            signer_id: 0,
            comms: vec![(
                0,
                PolyCommitment {
                    id: ID::new(&Scalar::new(), &Scalar::new(), &ctx, &mut rng),
                    poly: vec![],
                },
            )],
            kex_public_key: Point::from(Scalar::random(&mut rng)),
        };
        let dup_packet = Packet {
            msg: Message::DkgPublicShares(dup_public_shares.clone()),
            sig: Default::default(),
        };

        coordinator.gather_public_shares(&dup_packet).unwrap();
        assert_eq!(1, coordinator.dkg_public_shares.len());
        assert_eq!(
            public_shares,
            coordinator
                .dkg_public_shares
                .iter()
                .next()
                .unwrap()
                .1
                .clone()
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn dkg_private_share_v1() {
        dkg_private_share::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn dkg_private_share_v2() {
        dkg_private_share::<v2::Aggregator, v2::Signer>();
    }

    /// test basic insertion and detection of duplicates for DkgPrivateShares
    fn dkg_private_share<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let (coordinators, _) = setup::<FrostCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FrostCoordinator<Aggregator> = coordinators[0].clone();

        coordinator.state = State::DkgPrivateGather;

        let private_share = DkgPrivateShares {
            dkg_id: 0,
            signer_id: 0,
            shares: vec![(1, HashMap::new())],
        };
        let packet = Packet {
            msg: Message::DkgPrivateShares(private_share.clone()),
            sig: Default::default(),
        };
        coordinator.gather_private_shares(&packet).unwrap();
        assert_eq!(1, coordinator.dkg_private_shares.len());

        // check that a duplicate private share is ignored
        let dup_private_share = DkgPrivateShares {
            dkg_id: 0,
            signer_id: 0,
            shares: vec![(1, HashMap::new())],
        };
        let packet = Packet {
            msg: Message::DkgPrivateShares(dup_private_share.clone()),
            sig: Default::default(),
        };
        coordinator.gather_private_shares(&packet).unwrap();
        assert_eq!(1, coordinator.dkg_private_shares.len());
        assert_eq!(
            private_share,
            coordinator
                .dkg_private_shares
                .iter()
                .next()
                .unwrap()
                .1
                .clone()
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn nonce_response_v1() {
        nonce_response::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn nonce_response_v2() {
        nonce_response::<v2::Aggregator, v2::Signer>();
    }

    /// test basic insertion and detection of duplicates for NonceResponse
    fn nonce_response<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let mut rng = create_rng();
        let (coordinators, _) = setup::<FrostCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FrostCoordinator<Aggregator> = coordinators[0].clone();
        let signature_type = SignatureType::Frost;
        let message = vec![0u8];
        coordinator.state = State::NonceGather(signature_type);

        let nonce_response = NonceResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            key_ids: vec![1u32],
            nonces: vec![PublicNonce {
                D: Point::from(Scalar::random(&mut rng)),
                E: Point::from(Scalar::random(&mut rng)),
            }],
            message: message.clone(),
        };
        let packet = Packet {
            msg: Message::NonceResponse(nonce_response.clone()),
            sig: Default::default(),
        };
        coordinator.gather_nonces(&packet, signature_type).unwrap();
        assert_eq!(1, coordinator.public_nonces.len());

        // check that a duplicate private share is ignored
        let dup_nonce_response = NonceResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            key_ids: vec![1u32],
            nonces: vec![PublicNonce {
                D: Point::from(Scalar::random(&mut rng)),
                E: Point::from(Scalar::random(&mut rng)),
            }],
            message: message.clone(),
        };
        let packet = Packet {
            msg: Message::NonceResponse(dup_nonce_response.clone()),
            sig: Default::default(),
        };
        coordinator.gather_nonces(&packet, signature_type).unwrap();
        assert_eq!(1, coordinator.public_nonces.len());
        assert_eq!(
            nonce_response,
            coordinator.public_nonces.iter().next().unwrap().1.clone()
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn sig_share_v1() {
        sig_share::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn sig_share_v2() {
        sig_share::<v2::Aggregator, v1::Signer>();
    }

    /// test basic insertion and detection of duplicates for SignatureShareResponse
    #[allow(dead_code)]
    fn sig_share<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let mut rng = create_rng();
        let (coordinators, _) = setup::<FrostCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator = coordinators[0].clone();
        let signature_type = SignatureType::Frost;

        coordinator.ids_to_await = (0..coordinator.config.num_signers).collect();
        coordinator.state = State::SigShareGather(signature_type);

        let signature_share = SignatureShare {
            id: 1,
            z_i: Scalar::random(&mut rng),
            key_ids: vec![1],
        };
        let sig_share_response = SignatureShareResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            signature_shares: vec![signature_share.clone()],
        };
        let packet = Packet {
            msg: Message::SignatureShareResponse(sig_share_response.clone()),
            sig: Default::default(),
        };
        coordinator
            .gather_sig_shares(&packet, signature_type)
            .unwrap();
        assert_eq!(1, coordinator.signature_shares.len());

        // check that a duplicate private share is ignored
        let dup_signature_share = SignatureShare {
            id: 1,
            z_i: Scalar::random(&mut rng),
            key_ids: vec![1],
        };
        let dup_sig_share_response = SignatureShareResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            signature_shares: vec![dup_signature_share.clone()],
        };
        let packet = Packet {
            msg: Message::SignatureShareResponse(dup_sig_share_response.clone()),
            sig: Default::default(),
        };
        coordinator
            .gather_sig_shares(&packet, signature_type)
            .unwrap();
        assert_eq!(1, coordinator.signature_shares.len());
        assert_eq!(
            vec![signature_share],
            coordinator
                .signature_shares
                .iter()
                .next()
                .unwrap()
                .1
                .clone()
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn run_dkg_sign_v1() {
        run_dkg_sign::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn run_dkg_sign_v2() {
        run_dkg_sign::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn check_signature_shares_v1() {
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Frost,
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Schnorr,
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Taproot(None),
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![1],
        );
    }

    #[test]
    fn check_signature_shares_v2() {
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Frost,
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Schnorr,
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(None),
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![0],
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn bad_signature_share_request_v1() {
        bad_signature_share_request::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn bad_signature_share_request_v2() {
        bad_signature_share_request::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn invalid_nonce_v1() {
        invalid_nonce::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn invalid_nonce_v2() {
        invalid_nonce::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    fn process_inbound_messages_v2() {
        run_dkg_sign::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn old_round_ids_are_ignored_v1() {
        old_round_ids_are_ignored::<v1::Aggregator>();
    }

    #[test]
    fn old_round_ids_are_ignored_v2() {
        old_round_ids_are_ignored::<v2::Aggregator>();
    }

    fn old_round_ids_are_ignored<Aggregator: AggregatorTrait>() {
        let mut rng = create_rng();
        let mut config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        config.verify_packet_sigs = false;
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);
        let id: u64 = 10;
        let old_id = id;
        coordinator.current_dkg_id = id;
        coordinator.current_sign_id = id;
        // Attempt to start an old DKG round
        let (packet, result) = coordinator
            .process(&Packet {
                sig: vec![],
                msg: Message::DkgBegin(DkgBegin { dkg_id: old_id }),
            })
            .unwrap();
        assert!(packet.is_none());
        assert!(result.is_none());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_dkg_id, id);

        // Attempt to start the same DKG round
        let (packet, result) = coordinator
            .process(&Packet {
                sig: vec![],
                msg: Message::DkgBegin(DkgBegin { dkg_id: id }),
            })
            .unwrap();
        assert!(packet.is_none());
        assert!(result.is_none());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_dkg_id, id);

        // Attempt to start an old Sign round
        let (packet, result) = coordinator
            .process(&Packet {
                sig: vec![],
                msg: Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: old_id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                }),
            })
            .unwrap();
        assert!(packet.is_none());
        assert!(result.is_none());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_sign_id, id);

        // Attempt to start the same Sign round
        let (packet, result) = coordinator
            .process(&Packet {
                sig: vec![],
                msg: Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                }),
            })
            .unwrap();
        assert!(packet.is_none());
        assert!(result.is_none());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_sign_id, id);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn empty_public_shares_v1() {
        empty_public_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn empty_public_shares_v2() {
        empty_public_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn empty_private_shares_v1() {
        empty_private_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn empty_private_shares_v2() {
        empty_private_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn verify_packet_sigs_v1() {
        verify_packet_sigs::<FrostCoordinator<v1::Aggregator>, v1::Signer>();
    }

    #[test]
    fn verify_packet_sigs_v2() {
        verify_packet_sigs::<FrostCoordinator<v2::Aggregator>, v2::Signer>();
    }
}
