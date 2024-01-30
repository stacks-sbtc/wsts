use hashbrown::{HashMap, HashSet};
use std::{collections::BTreeMap, time::Instant};
use tracing::{debug, error, info, warn};

use crate::{
    common::{MerkleRoot, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{point::Point, scalar::Scalar},
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgFailure, DkgPrivateBegin, DkgPrivateShares,
        DkgPublicShares, DkgStatus, Message, NonceRequest, NonceResponse, Packet, Signable,
        SignatureShareRequest,
    },
    state_machine::{
        coordinator::{Config, Coordinator as CoordinatorTrait, Error, State},
        DkgError, OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
    util::{decrypt, make_shared_secret_from_key},
};

#[derive(Clone, Default)]
/// The Nonce response information for a sign round over specific message bytes
pub struct ResponseInfo {
    /// the nonce response of a signer id
    pub public_nonces: BTreeMap<u32, NonceResponse>,
    /// which key_ids we've received nonces for this iteration
    pub nonce_recv_key_ids: HashSet<u32>,
    /// which key_ids we're received sig shares for this iteration
    pub sign_recv_key_ids: HashSet<u32>,
    /// which signer_ids we're expecting sig shares from this iteration
    pub sign_wait_signer_ids: HashSet<u32>,
}

/// The coordinator for the FIRE algorithm
#[derive(Clone)]
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
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    message_nonces: BTreeMap<Vec<u8>, ResponseInfo>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on for DKG
    pub dkg_wait_signer_ids: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: Aggregator,
    nonce_start: Option<Instant>,
    dkg_public_start: Option<Instant>,
    dkg_private_start: Option<Instant>,
    dkg_end_start: Option<Instant>,
    sign_start: Option<Instant>,
    malicious_signer_ids: HashSet<u32>,
    malicious_dkg_signer_ids: HashSet<u32>,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Process the message inside the passed packet
    pub fn process_timeout(&mut self) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        let now = Instant::now();
        match self.state {
            State::Idle => {}
            State::DkgPublicDistribute => {}
            State::DkgPublicGather => {
                if let Some(start) = self.dkg_public_start {
                    if let Some(timeout) = self.config.dkg_public_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_public_size();

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, dkg_size, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPublicTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, dkg_size, self.config.dkg_threshold);
                                self.public_shares_gathered()?;
                                let packet = self.start_private_shares()?;
                                return Ok((Some(packet), None));
                            }
                        }
                    }
                }
            }
            State::DkgPrivateDistribute => {}
            State::DkgPrivateGather => {
                if let Some(start) = self.dkg_private_start {
                    if let Some(timeout) = self.config.dkg_private_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_private_size();

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, dkg_size, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPrivateTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, dkg_size, self.config.dkg_threshold);
                                self.private_shares_gathered()?;
                                let packet = self.start_dkg_end()?;
                                return Ok((Some(packet), None));
                            }
                        }
                    }
                }
            }
            State::DkgEndDistribute => {}
            State::DkgEndGather => {
                if let Some(start) = self.dkg_end_start {
                    if let Some(timeout) = self.config.dkg_end_timeout {
                        if now.duration_since(start) > timeout {
                            error!("Timeout gathering DkgEnd for dkg round {} signing round {} iteration {}, unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id);
                            let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndTimeout(wait))),
                            ));
                        }
                    }
                }
            }
            State::NonceRequest(_is_taproot, _merkle_root) => {}
            State::SigShareRequest(_is_taproot, _merkle_root) => {}
            State::NonceGather(_is_taproot, _merkle_root) => {
                if let Some(start) = self.nonce_start {
                    if let Some(timeout) = self.config.nonce_timeout {
                        if now.duration_since(start) > timeout {
                            error!("Timeout gathering nonces for signing round {} iteration {}, unable to continue", self.current_sign_id, self.current_sign_iter_id);
                            let recv = self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                                .iter()
                                .copied()
                                .collect();
                            let mal = self.malicious_signer_ids.iter().copied().collect();
                            return Ok((
                                None,
                                Some(OperationResult::SignError(SignError::NonceTimeout(
                                    recv, mal,
                                ))),
                            ));
                        }
                    }
                }
            }
            State::SigShareGather(is_taproot, merkle_root) => {
                if let Some(start) = self.sign_start {
                    if let Some(timeout) = self.config.sign_timeout {
                        if now.duration_since(start) > timeout {
                            warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {} as malicious", signer_id);
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 = self
                                .malicious_signer_ids
                                .iter()
                                .map(|signer_id| self.config.signer_key_ids[signer_id].len() as u32)
                                .sum();

                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
                                error!("Insufficient non-malicious signers, unable to continue");
                                let mal = self.malicious_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(
                                        SignError::InsufficientSigners(mal),
                                    )),
                                ));
                            }

                            self.move_to(State::NonceRequest(is_taproot, merkle_root))?;
                            let packet = self.request_nonces(is_taproot, merkle_root)?;
                            return Ok((Some(packet), None));
                        }
                    }
                }
            }
        }
        Ok((None, None))
    }
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        loop {
            match self.state {
                State::Idle => {
                    // Did we receive a coordinator message?
                    if let Message::DkgBegin(dkg_begin) = &packet.msg {
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // than overwriting afterwards to ensure logging is accurate)
                        self.current_dkg_id = dkg_begin.dkg_id.wrapping_sub(1);
                        let packet = self.start_dkg_round()?;
                        return Ok((Some(packet), None));
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // than overwriting afterwards to ensure logging is accurate)
                        self.current_sign_id = nonce_request.sign_id.wrapping_sub(1);
                        self.current_sign_iter_id = nonce_request.sign_iter_id.wrapping_sub(1);
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.is_taproot,
                            nonce_request.merkle_root,
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
                        if let Error::DkgFailure(dkg_failures) = error {
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndFailure(
                                    dkg_failures,
                                ))),
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

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.dkg_wait_signer_ids = (0..self.config.num_signers).collect();
        info!(
            "DKG Round {}: Starting Public Share Distribution",
            self.current_dkg_id,
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
        self.dkg_public_start = Some(Instant::now());
        Ok(dkg_begin_packet)
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_public_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            "DKG Round {}: Starting Private Share Distribution",
            self.current_dkg_id
        );
        let active_key_ids = self
            .dkg_public_shares
            .keys()
            .flat_map(|signer_id| self.config.signer_key_ids[signer_id].clone())
            .collect::<Vec<u32>>();

        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            key_ids: active_key_ids,
            signer_ids: self.dkg_public_shares.keys().cloned().collect(),
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgPrivateGather)?;
        self.dkg_private_start = Some(Instant::now());
        Ok(dkg_private_begin_msg)
    }

    /// Ask signers to compute shares and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_private_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            "DKG Round {}: Starting DkgEnd Distribution",
            self.current_dkg_id
        );
        let active_key_ids = self
            .dkg_private_shares
            .keys()
            .flat_map(|signer_id| self.config.signer_key_ids[signer_id].clone())
            .collect::<Vec<u32>>();

        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            key_ids: active_key_ids,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
        };
        let dkg_end_begin_msg = Packet {
            sig: dkg_end_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgEndBegin(dkg_end_begin),
        };
        self.move_to(State::DkgEndGather)?;
        self.dkg_end_start = Some(Instant::now());
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

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                "DKG round {} DkgPublicShares from signer {}",
                dkg_public_shares.dkg_id, dkg_public_shares.signer_id
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.public_shares_gathered()?;
        }
        Ok(())
    }

    fn public_shares_gathered(&mut self) -> Result<(), Error> {
        self.move_to(State::DkgPrivateDistribute)?;
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

            self.dkg_wait_signer_ids
                .remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                "DKG round {} DkgPrivateShares from signer {}",
                dkg_private_shares.dkg_id, dkg_private_shares.signer_id
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.private_shares_gathered()?;
        }
        Ok(())
    }

    fn private_shares_gathered(&mut self) -> Result<(), Error> {
        self.move_to(State::DkgEndDistribute)?;
        Ok(())
    }

    fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
        debug!(
            "DKG Round {}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.dkg_wait_signer_ids
        );
        if let Message::DkgEnd(dkg_end) = &packet.msg {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            if self.dkg_wait_signer_ids.contains(&dkg_end.signer_id) {
                self.dkg_wait_signer_ids.remove(&dkg_end.signer_id);
                self.dkg_end_messages
                    .insert(dkg_end.signer_id, dkg_end.clone());
                debug!(
                    "DKG_End round {} from signer {}. Waiting on {:?}",
                    dkg_end.dkg_id, dkg_end.signer_id, self.dkg_wait_signer_ids
                );
            } else {
                warn!(
                    "Got DkgEnd from signer {} who we weren't waiting on",
                    &dkg_end.signer_id
                );
            }
        }

        let mut dkg_failures = HashMap::new();

        if self.dkg_wait_signer_ids.is_empty() {
            // if there are any errors, mark signers malicious and retry
            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    match dkg_failure {
                        DkgFailure::BadState => {
                            // signer should not be in a bad state so treat as malicious
                            self.malicious_dkg_signer_ids.insert(*signer_id);
                        }
                        DkgFailure::BadPublicShares(bad_shares) => {
                            // bad_shares is a set of signer_ids
                            for bad_signer_id in bad_shares {
                                // verify public shares are bad
                                let dkg_public_shares = &self.dkg_public_shares[bad_signer_id];
                                let mut bad_party_ids = Vec::new();
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !comm.verify() {
                                        bad_party_ids.push(party_id);
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if bad_party_ids.is_empty() {
                                    warn!("Signer {} reported BadPublicShares from {} but the shares were valid, mark {} as malicious", signer_id, bad_signer_id, signer_id);
                                    self.malicious_dkg_signer_ids.insert(*signer_id);
                                } else {
                                    warn!("Signer {} reported BadPublicShares from {}, mark {} as malicious", signer_id, bad_signer_id, bad_signer_id);
                                    self.malicious_dkg_signer_ids.insert(*bad_signer_id);
                                }
                            }
                        }
                        DkgFailure::BadPrivateShares(bad_shares) => {
                            // bad_shares is a map of signer_id to BadPrivateShare
                            for (bad_signer_id, bad_private_share) in bad_shares {
                                // verify the DH tuple proof first so we know the shared key is correct
                                let signer_public_key = &self.config.signer_public_keys[signer_id];
                                let bad_signer_public_key =
                                    &self.config.signer_public_keys[bad_signer_id];
                                let mut is_bad = false;

                                if bad_private_share.tuple_proof.verify(
                                    signer_public_key,
                                    bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);

                                    let dkg_public_shares = &self.dkg_public_shares[bad_signer_id]
                                        .comms
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<u32, PolyCommitment>>();
                                    let dkg_private_shares =
                                        &self.dkg_private_shares[bad_signer_id];
                                    let signer_key_ids = &self.config.signer_key_ids[signer_id];

                                    for (src_party_id, key_shares) in &dkg_private_shares.shares {
                                        let _poly = &dkg_public_shares[src_party_id];
                                        for key_id in signer_key_ids {
                                            let bytes = &key_shares[key_id];
                                            match decrypt(&shared_secret, &bytes) {
                                                Ok(plain) => match Scalar::try_from(&plain[..]) {
                                                    Ok(_s) => {
                                                        // TODO: verify share is good by comparing to poly evaluated at key_id
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse Scalar for dkg private share from signer_id {} to key_id {}: {:?}", bad_signer_id, key_id, e);

                                                        is_bad = true;
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {} to key_id {}: {:?}", bad_signer_id, key_id, e);
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if !is_bad {
                                    warn!("Signer {} reported BadPrivateShare from {} but the shares were valid, mark {} as malicious", signer_id, bad_signer_id, signer_id);
                                    self.malicious_dkg_signer_ids.insert(*signer_id);
                                } else {
                                    warn!("Signer {} reported BadPrivateShare from {}, mark {} as malicious", signer_id, bad_signer_id, bad_signer_id);
                                    self.malicious_dkg_signer_ids.insert(*bad_signer_id);
                                }
                            }
                        }
                        _ => (),
                    }
                    dkg_failures.insert(*signer_id, dkg_failure.clone());
                }
            }
            if dkg_failures.is_empty() {
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                return Err(Error::DkgFailure(dkg_failures));
            }
        }
        Ok(())
    }

    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {}", key);
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }

    fn request_nonces(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
        info!(
            "Sign round {} iteration {} Requesting Nonces",
            self.current_sign_id, self.current_sign_iter_id,
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            is_taproot,
            merkle_root,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign NonceRequest"),
            msg: Message::NonceRequest(nonce_request),
        };
        self.move_to(State::NonceGather(is_taproot, merkle_root))?;
        self.nonce_start = Some(Instant::now());

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

            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    "Sign round {} iteration {} received malicious NonceResponse from signer {})",
                    nonce_response.sign_id, nonce_response.sign_iter_id, nonce_response.signer_id,
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }

            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();
            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            for key_id in &nonce_response.key_ids {
                if let Some(key_ids) = self.config.signer_key_ids.get(&nonce_response.signer_id) {
                    if key_ids.contains(key_id) {
                        nonce_info.nonce_recv_key_ids.insert(*key_id);
                    } else {
                        //TODO: should we mark this signer as malicious?
                        debug!("Key id {} not in signer key ids {:?}", key_id, key_ids);
                    }
                }
            }
            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                "Sign round {} iteration {} received NonceResponse from signer {} ({}/{})",
                nonce_response.sign_id,
                nonce_response.sign_iter_id,
                nonce_response.signer_id,
                nonce_info.nonce_recv_key_ids.len(),
                self.config.threshold,
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message = nonce_response.message.clone();
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {}", aggregate_nonce);

                self.move_to(State::SigShareRequest(is_taproot, merkle_root))?;
            }
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
        let nonce_responses = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?
            .public_nonces
            .values()
            .cloned()
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
            sig: sig_share_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign SignatureShareRequest"),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.move_to(State::SigShareGather(is_taproot, merkle_root))?;
        self.sign_start = Some(Instant::now());

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
            let response_info = self.message_nonces.entry(self.message.clone()).or_default();
            if response_info
                .sign_wait_signer_ids
                .contains(&sig_share_response.signer_id)
            {
                response_info
                    .sign_wait_signer_ids
                    .remove(&sig_share_response.signer_id);
                for sig_share in &sig_share_response.signature_shares {
                    for key_id in &sig_share.key_ids {
                        response_info.sign_recv_key_ids.insert(*key_id);
                    }
                }

                debug!(
                    "Sign round {} SignatureShareResponse from signer {} ({}/{} key_ids). Waiting on {:?}",
                    sig_share_response.sign_id,
                    sig_share_response.signer_id,
                    response_info.sign_recv_key_ids.len(),
                    response_info.nonce_recv_key_ids.len(),
                    response_info.sign_wait_signer_ids
                );
            } else {
                warn!(
                    "Sign round {} SignatureShareResponse from signer {} not in the wait list",
                    sig_share_response.sign_id, sig_share_response.signer_id,
                );
            }
        }
        let message_nonce = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?;
        if message_nonce.sign_wait_signer_ids.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = message_nonce
                .public_nonces
                .values()
                .cloned()
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({}, {:?}, {:?}, {})",
                bs58::encode(&self.message).into_string(),
                nonces.len(),
                shares.len(),
                self.party_polynomials.len(),
            );

            self.aggregator.init(&self.party_polynomials)?;

            if is_taproot {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    merkle_root,
                )?;
                info!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
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
        let public_nonces = self
            .message_nonces
            .get(&self.message)
            .cloned()
            .unwrap_or_default()
            .public_nonces;
        let party_ids = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.key_ids)
            .collect::<Vec<u32>>();
        let nonces = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.nonces)
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }

    fn compute_dkg_public_size(&self) -> u32 {
        self.dkg_public_shares
            .keys()
            .map(|signer_id| self.config.signer_key_ids[signer_id].len() as u32)
            .sum()
    }

    fn compute_dkg_private_size(&self) -> u32 {
        self.dkg_private_shares
            .keys()
            .map(|signer_id| self.config.signer_key_ids[signer_id].len() as u32)
            .sum()
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
            State::NonceRequest(is_taproot, merkle_root) => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgEndGather
                    || prev_state == &State::SigShareGather(*is_taproot, *merkle_root)
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
            message_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            dkg_wait_signer_ids: Default::default(),
            state: State::Idle,
            dkg_public_start: None,
            dkg_private_start: None,
            dkg_end_start: None,
            nonce_start: None,
            sign_start: None,
            malicious_signer_ids: Default::default(),
            malicious_dkg_signer_ids: Default::default(),
        }
    }

    /// Retrieve the config
    fn get_config(&self) -> Config {
        self.config.clone()
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

        let (outbound_packet, operation_result) = self.process_timeout()?;
        if let Some(outbound_packet) = outbound_packet {
            outbound_packets.push(outbound_packet);
        }
        if let Some(operation_result) = operation_result {
            operation_results.push(operation_result);
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

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Retrive the current state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Start a DKG round
    fn start_dkg_round(&mut self) -> Result<Packet, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.message = message.to_vec();
        self.current_sign_id = self.current_sign_id.wrapping_add(1);
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(is_taproot, merkle_root))?;
        self.request_nonces(is_taproot, merkle_root)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_end_messages.clear();
        self.party_polynomials.clear();
        self.message_nonces.clear();
        self.signature_shares.clear();
        self.dkg_wait_signer_ids.clear();
        self.nonce_start = None;
        self.sign_start = None;
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        curve::{point::Point, scalar::Scalar},
        net::Message,
        state_machine::{
            coordinator::{
                fire::Coordinator as FireCoordinator,
                test::{
                    coordinator_state_machine, feedback_messages, new_coordinator,
                    process_inbound_messages, setup, setup_with_timeouts, start_dkg_round,
                },
                Config, Coordinator as CoordinatorTrait, State,
            },
            signer::Signer,
            DkgError, OperationResult, SignError,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        v1, v2,
    };
    use rand_core::OsRng;
    use std::{thread, time::Duration};

    #[test]
    fn new_coordinator_v1() {
        new_coordinator::<FireCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FireCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn coordinator_state_machine_v1() {
        coordinator_state_machine::<FireCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FireCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn start_dkg_round_v1() {
        start_dkg_round::<FireCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FireCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn start_public_shares_v1() {
        start_public_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_public_shares_v2() {
        start_public_shares::<v2::Aggregator>();
    }

    fn start_public_shares<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FireCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn start_private_shares_v1() {
        start_private_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_private_shares_v2() {
        start_private_shares::<v2::Aggregator>();
    }

    fn start_private_shares<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FireCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn process_inbound_messages_v1() {
        process_inbound_messages::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn process_inbound_messages_v2() {
        process_inbound_messages::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    fn all_signers_dkg_v1() {
        all_signers_dkg::<v1::Aggregator, v1::Signer>(5, 2);
    }

    #[test]
    fn all_signers_dkg_v2() {
        all_signers_dkg::<v2::Aggregator, v2::Signer>(5, 2);
    }

    fn all_signers_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator<Aggregator>>, Vec<Signer<SignerType>>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinators
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        // Successfully got an Aggregate Public Key...
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }
        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in coordinators.iter() {
                    assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                    assert_eq!(coordinator.get_state(), State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }
        (coordinators, signers)
    }

    #[test]
    fn minimum_signers_dkg_v1() {
        minimum_signers_dkg::<v1::Aggregator, v1::Signer>(10, 2);
    }

    #[test]
    fn minimum_signers_dkg_v2() {
        minimum_signers_dkg::<v2::Aggregator, v2::Signer>(10, 2);
    }

    fn minimum_signers_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator<Aggregator>>, Vec<Signer<SignerType>>) {
        let timeout = Duration::from_millis(1024);
        let expire = Duration::from_millis(1280);
        let (mut coordinators, signers) =
            setup_with_timeouts::<FireCoordinator<Aggregator>, SignerType>(
                num_signers,
                keys_per_signer,
                Some(timeout),
                Some(timeout),
                Some(timeout),
                Some(timeout),
                Some(timeout),
            );

        // Start a DKG round where we will not allow all signers to recv DkgBegin, so they will not respond with DkgPublicShares
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // DKG threshold is 9/10, so need to remove 1
        let num_signers_to_remove = 1;

        let mut minimum_coordinators = coordinators.clone();
        let mut minimum_signers = signers.clone();

        for _ in 0..num_signers_to_remove {
            minimum_signers.pop();
        }

        // Send the DKG Begin message to minimum signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            &[message.clone()],
        );

        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPublicGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = minimum_coordinators
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert_eq!(outbound_messages.len(), 1);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Run DKG again with fresh coordinator and signers, this time allow gathering DkgPublicShares but timeout getting DkgEnd
        let mut minimum_coordinator = coordinators.clone();
        let mut minimum_signers = signers.clone();

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut minimum_coordinator, &mut minimum_signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            minimum_coordinator.first().unwrap().state,
            State::DkgPrivateGather
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // now remove signers so the set is minimum
        for _ in 0..num_signers_to_remove {
            minimum_signers.pop();
        }

        // Send the DKG Private Begin message to minimum signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinator,
            &mut minimum_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 0);
        assert_eq!(
            minimum_coordinator.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = minimum_coordinator
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert_eq!(outbound_messages.len(), 1);
        assert_eq!(operation_results.len(), 0);
        match &outbound_messages[0].msg {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }
        assert_eq!(
            minimum_coordinator.first().unwrap().state,
            State::DkgEndGather,
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinator,
            &mut minimum_signers,
            &outbound_messages,
        );
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in minimum_coordinator.iter() {
                    assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                    assert_eq!(coordinator.get_state(), State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        (minimum_coordinator, minimum_signers)
    }

    #[test]
    fn insufficient_signers_dkg_v1() {
        insufficient_signers_dkg::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn insufficient_signers_dkg_v2() {
        insufficient_signers_dkg::<v2::Aggregator, v2::Signer>();
    }

    fn insufficient_signers_dkg<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let timeout = Duration::from_millis(1024);
        let expire = Duration::from_millis(1280);
        let num_signers = 10;
        let keys_per_signer = 2;
        let (mut coordinators, signers) = setup_with_timeouts::<FireCoordinator<Aggregator>, Signer>(
            num_signers,
            keys_per_signer,
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
        );

        // Start a DKG round where we will not allow all signers to recv DkgBegin, so they will not respond with DkgPublicShares
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // DKG threshold is 9/10, so need to remove 2
        let num_signers_to_remove = 2;

        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        for _ in 0..num_signers_to_remove {
            insufficient_signers.pop();
        }

        // Send the DKG Begin message to insufficient signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message.clone()],
        );

        // Failed to get an aggregate public key
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 0);
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::DkgPublicGather);
        }

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::DkgPublicGather,
        );
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => match dkg_error {
                DkgError::DkgPublicTimeout(_) => {}
                _ => panic!("Expected DkgError::DkgPublicTimeout"),
            },
            _ => panic!("Expected OperationResult::DkgError"),
        }

        // Run DKG again with fresh coordinator and signers, this time allow gathering DkgPublicShares but timeout getting DkgEnd
        let mut insufficient_coordinator = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinator,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        assert_eq!(
            insufficient_coordinator.first().unwrap().state,
            State::DkgPrivateGather
        );

        // Successfully got an Aggregate Public Key...
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // now remove signers so the set is insufficient
        for _ in 0..num_signers_to_remove {
            insufficient_signers.pop();
        }

        // Send the DKG Private Begin message to insufficient signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinator,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 0);
        assert_eq!(
            insufficient_coordinator.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = insufficient_coordinator
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        assert_eq!(
            insufficient_coordinator.first().unwrap().state,
            State::DkgPrivateGather,
        );
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => match dkg_error {
                DkgError::DkgPrivateTimeout(_) => {}
                _ => panic!("Expected DkgError::DkgPrivateTimeout"),
            },
            _ => panic!("Expected OperationResult::DkgError"),
        }
    }

    #[test]
    fn all_signers_sign_v1() {
        all_signers_sign::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn all_signers_sign_v2() {
        all_signers_sign::<v2::Aggregator, v2::Signer>();
    }

    fn all_signers_sign<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let (mut coordinators, mut signers) = all_signers_dkg::<Aggregator, Signer>(5, 2);

        // We have started a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
                for coordinator in &coordinators {
                    assert_eq!(coordinator.state, State::Idle);
                }
            }
            _ => panic!("Expected Signature Operation result"),
        }
    }

    #[test]
    fn minimum_signers_sign_v1() {
        minimum_signers_sign::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn minimum_signers_sign_v2() {
        minimum_signers_sign::<v2::Aggregator, v2::Signer>();
    }

    fn minimum_signers_sign<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let num_signers = 10;
        let keys_per_signer = 2;

        let (mut coordinators, mut signers) =
            minimum_signers_dkg::<Aggregator, Signer>(num_signers, keys_per_signer);
        let config = coordinators.first().unwrap().get_config();

        // Figure out how many signers we can remove and still be above the threshold
        let num_keys = config.num_keys as f64;
        let threshold = config.threshold as f64;
        let mut num_signers_to_remove =
            ((num_keys - threshold) / keys_per_signer as f64).floor() as usize;
        if num_signers as usize > signers.len() {
            num_signers_to_remove -= (num_signers - signers.len() as u32) as usize;
        }
        for _ in 0..num_signers_to_remove {
            signers.pop();
        }

        // Start a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }

    #[test]
    fn insufficient_signers_sign_v1() {
        insufficient_signers_sign::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn insufficient_signers_sign_v2() {
        insufficient_signers_sign::<v2::Aggregator, v2::Signer>();
    }

    fn insufficient_signers_sign<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let num_signers = 5;
        let keys_per_signer = 2;
        let (mut coordinators, mut signers) =
            setup_with_timeouts::<FireCoordinator<Aggregator>, Signer>(
                num_signers,
                keys_per_signer,
                None,
                None,
                None,
                Some(Duration::from_millis(128)),
                Some(Duration::from_millis(128)),
            );
        let config = coordinators.first().unwrap().get_config();

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DKG End Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in &coordinators {
                    assert_eq!(coordinator.aggregate_public_key, Some(point));
                    assert_eq!(coordinator.state, State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // Figure out how many signers we can remove and still be above the threshold
        let num_keys = config.num_keys as f64;
        let threshold = config.threshold as f64;
        let num_signers_to_remove =
            (((num_keys - threshold) / keys_per_signer as f64).floor() + 1_f64) as usize;
        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        for _ in 0..num_signers_to_remove {
            insufficient_signers.pop();
        }

        // Start a signing round with an insufficient number of signers
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let is_taproot = false;
        let merkle_root = None;
        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::NonceGather(is_taproot, merkle_root)
            );
        }

        assert!(outbound_messages.is_empty());

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_messages, operation_results) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::NonceGather(is_taproot, merkle_root)
            );
        }
        match &operation_results[0] {
            OperationResult::SignError(sign_error) => match sign_error {
                SignError::NonceTimeout(_, _) => {}
                _ => panic!("Expected SignError::NonceTimeout"),
            },
            _ => panic!("Expected OperationResult::SignError"),
        }

        // Start a new signing round with a sufficient number of signers for nonces but not sig shares
        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and insufficient_coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        assert_eq!(outbound_messages.len(), 1);

        let mut malicious = Vec::new();
        // now remove signers so the number is insufficient
        for _ in 0..num_signers_to_remove {
            malicious.push(insufficient_signers.pop().unwrap());
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_messages, operation_results) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert_eq!(outbound_messages.len(), 1);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // put the malicious signers back in
        while let Some(element) = malicious.pop() {
            insufficient_signers.push(element);
        }

        // Send the NonceRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert_eq!(outbound_messages.len(), 1);
        assert_eq!(operation_results.len(), 0);

        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        // again remove signers so the number is insufficient
        for _ in 0..num_signers_to_remove {
            malicious.push(insufficient_signers.pop().unwrap());
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_messages, operation_results) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_inbound_messages(&[])
            .unwrap();

        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        assert_eq!(
            insufficient_coordinators.first_mut().unwrap().state,
            State::SigShareGather(is_taproot, merkle_root)
        );
        match &operation_results[0] {
            OperationResult::SignError(sign_error) => match sign_error {
                SignError::InsufficientSigners(_) => {}
                _ => panic!("Expected SignError::InsufficientSigners"),
            },
            _ => panic!("Expected OperationResult::SignError"),
        }
    }

    #[test]
    fn multiple_nonce_request_messages_sign_v1() {
        multiple_nonce_request_messages::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn multiple_nonce_request_messages_sign_v2() {
        multiple_nonce_request_messages::<v2::Aggregator, v2::Signer>();
    }

    fn multiple_nonce_request_messages<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let num_signers = 12;
        let keys_per_signer = 1;
        let (mut coordinators, mut signers) =
            all_signers_dkg::<Aggregator, Signer>(num_signers, keys_per_signer);

        // Start a signing round
        let orig_msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&orig_msg, is_taproot, merkle_root)
            .unwrap();

        let mut alt_packet = message.clone();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(is_taproot, merkle_root)
        );

        // Send the original message to the first 1/4 of the signers and gather responses by sharing with the rest of the signers and the coordinators
        let signers_len = signers.len();
        let (outbound_messages, operation_results) = feedback_messages(
            &mut coordinators,
            &mut signers[0..signers_len / 4],
            &[message],
        );

        let alt_message = "It was many and many a year ago, in a kingdom by the hill"
            .as_bytes()
            .to_vec();
        match &mut alt_packet.msg {
            Message::NonceRequest(nonce_request) => {
                nonce_request.message = alt_message.clone();
            }
            _ => panic!("Expected NonceRequest message"),
        };

        // Send the alternative message to the last 3/4 of signers and gather responses by sharing with the rest of the signers and the coordinators
        let (alt_outbound_messages, alt_operation_results) = feedback_messages(
            &mut coordinators,
            &mut signers[signers_len / 4..],
            &[alt_packet],
        );

        assert!(operation_results.is_empty());
        assert!(alt_operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(
                coordinator.state,
                State::SigShareGather(is_taproot, merkle_root)
            );
        }
        // Assert that the first 1/4 signers did not receive a result
        assert!(outbound_messages.is_empty());
        assert_eq!(alt_outbound_messages.len(), 1);
        match &alt_outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &alt_outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                // Verify that the winning message was the alternative message that had majority vote
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &alt_message
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }
}
