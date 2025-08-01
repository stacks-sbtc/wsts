use hashbrown::{HashMap, HashSet};
use std::{collections::BTreeMap, time::Instant};
use tracing::{debug, error, info, warn};

use crate::{
    common::{check_public_shares, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{
        ecdsa,
        point::{Point, G},
        scalar::Scalar,
    },
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgFailure, DkgPrivateBegin, DkgPrivateShares,
        DkgPublicShares, DkgStatus, Message, NonceRequest, NonceResponse, Packet, Signable,
        SignatureShareRequest, SignatureType,
    },
    state_machine::{
        coordinator::{
            Config, Coordinator as CoordinatorTrait, Error, SavedState, SignRoundInfo, State,
        },
        DkgError, OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
    util::{decrypt, make_shared_secret_from_key},
};

/// The coordinator for the FIRE algorithm
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator<Aggregator: AggregatorTrait> {
    /// common config fields
    config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    pub current_sign_id: u64,
    /// current signing iteration ID
    pub current_sign_iter_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    dkg_end_messages: BTreeMap<u32, DkgEnd>,
    /// the current view of a successful DKG's participants' commitments
    pub party_polynomials: HashMap<u32, PolyCommitment>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
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
    /// coordinator public key
    pub coordinator_public_key: Option<ecdsa::PublicKey>,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Check the timeout
    pub fn process_timeout(&mut self) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        let now = Instant::now();
        match self.state.clone() {
            State::Idle => {}
            State::DkgPublicDistribute => {}
            State::DkgPublicGather => {
                if let Some(start) = self.dkg_public_start {
                    if let Some(timeout) = self.config.dkg_public_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_public_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPublicTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
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
                            let dkg_size = self.compute_dkg_private_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPrivateTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
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
            State::NonceRequest(_signature_type) => {}
            State::SigShareRequest(_signature_type) => {}
            State::NonceGather(_signature_type) => {
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
            State::SigShareGather(signature_type) => {
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
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 =
                                self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

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

                            self.move_to(State::NonceRequest(signature_type))?;
                            let packet = self.request_nonces(signature_type)?;
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
                        self.current_sign_iter_id = nonce_request.sign_iter_id.wrapping_sub(1);
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
                            if let Some(schnorr_proof) = &self.schnorr_proof {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignTaproot(SchnorrProof {
                                        r: schnorr_proof.r,
                                        s: schnorr_proof.s,
                                    })),
                                ));
                            } else {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(SignError::Coordinator(
                                        Error::MissingSchnorrProof,
                                    ))),
                                ));
                            }
                        } else if let SignatureType::Schnorr = signature_type {
                            if let Some(schnorr_proof) = &self.schnorr_proof {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignSchnorr(SchnorrProof {
                                        r: schnorr_proof.r,
                                        s: schnorr_proof.s,
                                    })),
                                ));
                            } else {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(SignError::Coordinator(
                                        Error::MissingSchnorrProof,
                                    ))),
                                ));
                            }
                        } else if let Some(signature) = &self.signature {
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
                            ));
                        } else {
                            return Ok((
                                None,
                                Some(OperationResult::SignError(SignError::Coordinator(
                                    Error::MissingSignature,
                                ))),
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
            dkg_id = %self.current_dkg_id,
            "Starting Private Share Distribution"
        );

        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_public_shares.keys().cloned().collect(),
            key_ids: vec![],
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
            dkg_id = %self.current_dkg_id,
            "Starting DkgEnd Distribution"
        );

        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
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

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
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

            self.dkg_wait_signer_ids
                .remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                dkg_id = %dkg_private_shares.dkg_id,
                signer_id = %dkg_private_shares.signer_id,
                "DkgPrivateShares received"
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
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    waiting = ?self.dkg_wait_signer_ids,
                    "DkgEnd received"
                );
            } else {
                warn!(
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    "Got DkgEnd from signer who we weren't waiting on"
                );
            }
        }

        let mut reported_failures = HashMap::new();
        // this will be used to report signers who were malicious in this DKG round, as opposed to
        // self.malicious_dkg_signer_ids which contains all DKG signers who were ever malicious
        let mut malicious_signers = HashSet::new();
        let threshold: usize = self.config.threshold.try_into().unwrap();
        if self.dkg_wait_signer_ids.is_empty() {
            // if there are any errors, mark signers malicious and retry
            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    reported_failures.insert(*signer_id, dkg_failure.clone());

                    match dkg_failure {
                        DkgFailure::BadState => {
                            // signer should not be in a bad state so treat as malicious
                            malicious_signers.insert(*signer_id);
                        }
                        DkgFailure::Threshold => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
                        DkgFailure::BadPublicShares(bad_shares) => {
                            // bad_shares is a set of signer_ids
                            for bad_signer_id in bad_shares {
                                // verify public shares are bad
                                let Some(dkg_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but there are no public shares from that signer, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let mut bad_party_ids = Vec::new();
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
                                        bad_party_ids.push(party_id);
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if bad_party_ids.is_empty() {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
                                }
                            }
                        }
                        DkgFailure::BadPrivateShares(bad_shares) => {
                            // bad_shares is a map of signer_id to BadPrivateShare
                            for (bad_signer_id, bad_private_share) in bad_shares {
                                // verify the DH tuple proof first so we know the shared key is correct
                                let Some(signer_key_ids) =
                                    self.config.public_keys.signer_key_ids.get(signer_id)
                                else {
                                    warn!("No key IDs for signer_id {signer_id} DkgEnd");
                                    continue;
                                };
                                let Some(signer_public_shares) =
                                    self.dkg_public_shares.get(signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {signer_id}");
                                    continue;
                                };
                                let signer_public_key = signer_public_shares.kex_public_key;

                                let Some(bad_signer_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {bad_signer_id}, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let bad_signer_public_key = bad_signer_public_shares.kex_public_key;

                                let mut is_bad = false;

                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);

                                    let polys = bad_signer_public_shares
                                        .comms
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<u32, PolyCommitment>>();
                                    let Some(dkg_private_shares) =
                                        self.dkg_private_shares.get(bad_signer_id)
                                    else {
                                        warn!("Signer {signer_id} reported BadPrivateShare from signer {bad_signer_id} who didn't send public shares, mark {signer_id} as malicious");
                                        malicious_signers.insert(*signer_id);
                                        continue;
                                    };

                                    for (src_party_id, key_shares) in &dkg_private_shares.shares {
                                        let Some(poly) = polys.get(src_party_id) else {
                                            warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but the private shares from {bad_signer_id} dont have a polynomial for party {src_party_id}");
                                            continue;
                                        };
                                        for key_id in signer_key_ids {
                                            let Some(bytes) = key_shares.get(key_id) else {
                                                warn!("DkgPrivateShares from party_id {src_party_id} did not include a share for key_id {key_id}");
                                                continue;
                                            };
                                            match decrypt(&shared_secret, bytes) {
                                                Ok(plain) => match Scalar::try_from(&plain[..]) {
                                                    Ok(private_eval) => {
                                                        let poly_eval = match compute::poly(
                                                            &compute::id(*key_id),
                                                            &poly.poly,
                                                        ) {
                                                            Ok(p) => p,
                                                            Err(e) => {
                                                                warn!("Failed to evaluate public poly from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                                is_bad = true;
                                                                break;
                                                            }
                                                        };

                                                        if private_eval * G != poly_eval {
                                                            warn!("Invalid dkg private share from signer_id {bad_signer_id} to key_id {key_id}");

                                                            is_bad = true;
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse Scalar for dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");

                                                        is_bad = true;
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    warn!("TupleProof failed to verify, mark {signer_id} as malicious");
                                    is_bad = false;
                                }

                                // if tuple proof failed or none of the shares were bad sender was malicious
                                if !is_bad {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
                                }
                            }
                        }
                        DkgFailure::MissingPublicShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
                        DkgFailure::MissingPrivateShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
                    }
                }
            }

            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }

            if reported_failures.is_empty() {
                debug!("no dkg failures");
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
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

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }

    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
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
                .expect("Failed to sign NonceRequest"),
            msg: Message::NonceRequest(nonce_request),
        };
        self.move_to(State::NonceGather(signature_type))?;
        self.nonce_start = Some(Instant::now());

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

            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }

            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();

            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {aggregate_nonce}");

                self.move_to(State::SigShareRequest(signature_type))?;
            }
        }
        Ok(())
    }

    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            sign_id = %self.current_sign_id,
            "Requesting Signature Shares"
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
            signature_type,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign SignatureShareRequest"),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.move_to(State::SigShareGather(signature_type))?;
        self.sign_start = Some(Instant::now());

        Ok(sig_share_request_msg)
    }

    fn gather_sig_shares(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        let Message::SignatureShareResponse(sig_share_response) = &packet.msg else {
            return Ok(());
        };

        let Some(response_info) = self.message_nonces.get_mut(&self.message) else {
            warn!(
                "Sign round {} SignatureShareResponse for round {} from signer {} no message nonces entry",
                self.current_sign_id, sig_share_response.sign_id, sig_share_response.signer_id,
            );
            return Ok(());
        };

        let waiting = response_info
            .sign_wait_signer_ids
            .contains(&sig_share_response.signer_id);

        if !waiting {
            warn!(
                "Sign round {} SignatureShareResponse for round {} from signer {} not in the wait list",
                self.current_sign_id, sig_share_response.sign_id, sig_share_response.signer_id,
            );
            return Ok(());
        }

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

        // we were waiting on you, and you sent a packet for this sign round, so we won't take
        // another packet from you
        response_info
            .sign_wait_signer_ids
            .remove(&sig_share_response.signer_id);

        // check that the signer_id exists in the config
        let signer_public_keys = &self.config.public_keys.signers;
        if !signer_public_keys.contains_key(&sig_share_response.signer_id) {
            warn!(signer_id = %sig_share_response.signer_id, "No public key in config");
            return Err(Error::MissingPublicKeyForSigner(
                sig_share_response.signer_id,
            ));
        };

        // check that the key_ids match the config
        let Some(signer_key_ids) = self
            .config
            .public_keys
            .signer_key_ids
            .get(&sig_share_response.signer_id)
        else {
            warn!(signer_id = %sig_share_response.signer_id, "No keys IDs configured");
            return Err(Error::MissingKeyIDsForSigner(sig_share_response.signer_id));
        };

        let mut sig_share_response_key_ids = HashSet::new();
        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                sig_share_response_key_ids.insert(*key_id);
            }
        }

        if *signer_key_ids != sig_share_response_key_ids {
            warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
            return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
        }

        let have_shares = self
            .signature_shares
            .contains_key(&sig_share_response.signer_id);

        if have_shares {
            info!(signer_id = %sig_share_response.signer_id, "received duplicate SignatureShareResponse");
            // XXX should this be an error?  We should have already removed signer from wait set
            return Ok(());
        }

        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
        );

        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                response_info.sign_recv_key_ids.insert(*key_id);
            }
        }

        debug!(
            "Sign round {} SignatureShareResponse for round {} from signer {} ({}/{} key_ids). Waiting on {:?}",
            self.current_sign_id,
            sig_share_response.sign_id,
            sig_share_response.signer_id,
            response_info.sign_recv_key_ids.len(),
            response_info.nonce_recv_key_ids.len(),
            response_info.sign_wait_signer_ids
        );

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

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, &shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
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

    fn compute_num_key_ids<'a, I>(&self, signer_ids: I) -> Result<u32, Error>
    where
        I: Iterator<Item = &'a u32>,
    {
        signer_ids
            .map(
                |signer_id| match self.config.public_keys.signer_key_ids.get(signer_id) {
                    Some(key_ids) => key_ids.len(),
                    None => {
                        error!("No key_ids for signer {signer_id}");
                        0usize
                    }
                },
            )
            .sum::<usize>()
            .try_into()
            .map_err(Error::TryFromInt)
    }

    fn compute_dkg_public_size(&self) -> Result<u32, Error> {
        self.compute_num_key_ids(self.dkg_public_shares.keys())
    }

    fn compute_dkg_private_size(&self) -> Result<u32, Error> {
        self.compute_num_key_ids(self.dkg_private_shares.keys())
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
            State::NonceRequest(signature_type) => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgEndGather
                    || prev_state == &State::SigShareGather(*signature_type)
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
            message_nonces: state.message_nonces.clone(),
            signature_shares: state.signature_shares.clone(),
            aggregate_public_key: state.aggregate_public_key,
            signature: state.signature.clone(),
            schnorr_proof: state.schnorr_proof.clone(),
            message: state.message.clone(),
            dkg_wait_signer_ids: state.dkg_wait_signer_ids.clone(),
            state: state.state.clone(),
            dkg_public_start: state.dkg_public_start,
            dkg_private_start: state.dkg_private_start,
            dkg_end_start: state.dkg_end_start,
            nonce_start: state.nonce_start,
            sign_start: state.sign_start,
            malicious_signer_ids: state.malicious_signer_ids.clone(),
            malicious_dkg_signer_ids: state.malicious_dkg_signer_ids.clone(),
            coordinator_public_key: state.coordinator_public_key,
        }
    }

    fn save(&self) -> SavedState {
        SavedState {
            config: self.config.clone(),
            current_dkg_id: self.current_dkg_id,
            current_sign_id: self.current_sign_id,
            current_sign_iter_id: self.current_sign_iter_id,
            dkg_public_shares: self.dkg_public_shares.clone(),
            dkg_private_shares: self.dkg_private_shares.clone(),
            dkg_end_messages: self.dkg_end_messages.clone(),
            party_polynomials: self.party_polynomials.clone(),
            message_nonces: self.message_nonces.clone(),
            signature_shares: self.signature_shares.clone(),
            aggregate_public_key: self.aggregate_public_key,
            signature: self.signature.clone(),
            schnorr_proof: self.schnorr_proof.clone(),
            message: self.message.clone(),
            dkg_wait_signer_ids: self.dkg_wait_signer_ids.clone(),
            state: self.state.clone(),
            dkg_public_start: self.dkg_public_start,
            dkg_private_start: self.dkg_private_start,
            dkg_end_start: self.dkg_end_start,
            nonce_start: self.nonce_start,
            sign_start: self.sign_start,
            malicious_signer_ids: self.malicious_signer_ids.clone(),
            malicious_dkg_signer_ids: self.malicious_dkg_signer_ids.clone(),
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

    /// Start a DKG round, with an optional `dkg_id`
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

    /// Process the timeouts, and if none of them fire then process the passed packet
    /// If a timeout does fire, then the coordinator state has changed; this means the
    /// packet is now stale and must be dropped
    fn process(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        let (outbound_packet, operation_result) = self.process_timeout()?;
        if outbound_packet.is_some() || operation_result.is_some() {
            return Ok((outbound_packet, operation_result));
        }

        self.process_message(packet)
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
/// Test module for coordinator functionality
pub mod test {
    use super::*;
    #[cfg(feature = "with_v1")]
    use crate::v1;
    use crate::{
        curve::{point::Point, scalar::Scalar},
        net::{
            DkgBegin, DkgFailure, DkgPrivateShares, DkgPublicShares, Message, NonceRequest, Packet,
            SignatureShareResponse, SignatureType,
        },
        schnorr::ID,
        state_machine::{
            coordinator::{
                fire::Coordinator as FireCoordinator,
                test::{
                    bad_signature_share_request, check_signature_shares, coordinator_state_machine,
                    empty_private_shares, empty_public_shares, equal_after_save_load,
                    feedback_messages, feedback_mutated_messages, gen_nonces, invalid_nonce,
                    new_coordinator, run_dkg_sign, setup, setup_with_timeouts, start_dkg_round,
                    start_signing_round, verify_packet_sigs,
                },
                Config, Coordinator as CoordinatorTrait, State,
            },
            signer::Signer,
            DkgError, OperationResult, SignError,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        util::create_rng,
        v2,
    };
    use hashbrown::HashMap;
    use std::{thread, time::Duration};

    #[test]
    #[cfg(feature = "with_v1")]
    fn new_coordinator_v1() {
        new_coordinator::<FireCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FireCoordinator<v2::Aggregator>>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn equal_after_save_load_v1() {
        equal_after_save_load::<FireCoordinator<v1::Aggregator>, v1::Signer>(2, 2);
    }

    #[test]
    fn equal_after_save_load_v2() {
        equal_after_save_load::<FireCoordinator<v2::Aggregator>, v2::Signer>(2, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn coordinator_state_machine_v1() {
        coordinator_state_machine::<FireCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FireCoordinator<v2::Aggregator>>();
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_dkg_round_v1() {
        start_dkg_round::<FireCoordinator<v1::Aggregator>>(None);
        start_dkg_round::<FireCoordinator<v1::Aggregator>>(Some(12345u64));
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FireCoordinator<v2::Aggregator>>(None);
        start_dkg_round::<FireCoordinator<v2::Aggregator>>(Some(12345u64));
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn start_signing_round_v1() {
        start_signing_round::<FireCoordinator<v1::Aggregator>>(None);
        start_signing_round::<FireCoordinator<v1::Aggregator>>(Some(12345u64));
    }

    #[test]
    fn start_signing_round_v2() {
        start_signing_round::<FireCoordinator<v2::Aggregator>>(None);
        start_signing_round::<FireCoordinator<v2::Aggregator>>(Some(12345u64));
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn dkg_public_share_v1() {
        dkg_public_share::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn dkg_public_share_v2() {
        dkg_public_share::<v2::Aggregator, v2::Signer>();
    }

    /// test basic insertion and detection of duplicates for DkgPublicShares
    #[allow(dead_code)]
    fn dkg_public_share<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let ctx = 0u64.to_be_bytes();
        let mut rng = create_rng();
        let (coordinators, _) = setup::<FireCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FireCoordinator<Aggregator> = coordinators[0].clone();

        coordinator.state = State::DkgPublicGather;
        let public_shares = DkgPublicShares {
            dkg_id: 0,
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
            dkg_id: 0,
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
        let (coordinators, _) = setup::<FireCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FireCoordinator<Aggregator> = coordinators[0].clone();

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
        let (coordinators, _) = setup::<FireCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator: FireCoordinator<Aggregator> = coordinators[0].clone();
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
        assert_eq!(1, coordinator.message_nonces[&message].public_nonces.len());

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
        assert_eq!(1, coordinator.message_nonces[&message].public_nonces.len());
        assert_eq!(
            nonce_response,
            coordinator.message_nonces[&message]
                .public_nonces
                .iter()
                .next()
                .unwrap()
                .1
                .clone()
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn sig_share_v1() {
        sig_share::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn sig_share_v2() {
        sig_share::<v2::Aggregator, v2::Signer>();
    }

    /// test basic insertion and detection of duplicates for SignatureShareResponse
    #[allow(dead_code)]
    fn sig_share<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let mut rng = create_rng();
        let (coordinators, _) = setup::<FireCoordinator<Aggregator>, Signer>(2, 1);
        let mut coordinator = coordinators[0].clone();
        let signature_type = SignatureType::Frost;

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

        // check that a signature share is ignored due to not being on the wait list
        coordinator
            .gather_sig_shares(&packet, signature_type)
            .unwrap();
        assert_eq!(0, coordinator.signature_shares.len());

        // add the signer to the wait list then verify that the signature share is accepted
        let response_info = coordinator
            .message_nonces
            .entry(coordinator.message.clone())
            .or_default();
        response_info.sign_wait_signer_ids.insert(0);

        coordinator
            .gather_sig_shares(&packet, signature_type)
            .unwrap();
        assert_eq!(1, coordinator.signature_shares.len());

        // check that a duplicate signature share is ignored even if on the wait list
        let response_info = coordinator
            .message_nonces
            .entry(coordinator.message.clone())
            .or_default();
        response_info.sign_wait_signer_ids.insert(0);

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
        let mut coordinator = FireCoordinator::<Aggregator>::new(config);

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
        let mut coordinator = FireCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn run_dkg_sign_v1() {
        for _ in 0..4 {
            run_dkg_sign::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
        }
    }

    #[test]
    fn run_dkg_sign_v2() {
        for _ in 0..4 {
            run_dkg_sign::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
        }
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn check_signature_shares_v1() {
        check_signature_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            2,
            SignatureType::Frost,
            vec![1, 2],
        );
        check_signature_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            2,
            SignatureType::Schnorr,
            vec![1, 2],
        );
        check_signature_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            2,
            SignatureType::Taproot(None),
            vec![1, 2],
        );
        check_signature_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            2,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![1, 2],
        );
    }

    #[test]
    fn check_signature_shares_v2() {
        check_signature_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Frost,
            vec![0],
        );
        check_signature_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Schnorr,
            vec![0],
        );
        check_signature_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(None),
            vec![0],
        );
        check_signature_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![0],
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
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
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
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
        assert!(
            matches!(&outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrviateBegin message"
        );
        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Dkg(point) = operation_results[0] else {
            panic!("Expected Dkg Operation result");
        };
        assert_ne!(point, Point::default());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
            assert_eq!(coordinator.get_state(), State::Idle);
        }
        (coordinators, signers)
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn missing_public_keys_dkg_v1() {
        missing_public_keys_dkg::<v1::Aggregator, v1::Signer>(10, 1);
    }

    #[test]
    fn missing_public_keys_dkg_v2() {
        missing_public_keys_dkg::<v2::Aggregator, v2::Signer>(10, 1);
    }

    fn missing_public_keys_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
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
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        let mut minimum_coordinators = coordinators.clone();
        let mut minimum_signers = signers.clone();

        // Let us also remove that signers public key from the config including all of its key ids
        let mut removed_signer = minimum_signers.pop().expect("Failed to pop signer");
        let public_key = removed_signer
            .public_keys
            .signers
            .remove(&removed_signer.signer_id)
            .expect("Failed to remove public key");
        removed_signer
            .public_keys
            .key_ids
            .retain(|_k, pk| pk.to_bytes() != public_key.to_bytes());

        for signer in minimum_signers.iter_mut() {
            // Overwrite all other signers to use the new public keys missing the removed signers public key
            signer.public_keys = removed_signer.public_keys.clone();
        }

        // Send the DKG Begin message to minimum signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            &[message.clone()],
        );

        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather,);

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = minimum_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_messages.is_some());
        assert!(operation_results.is_none());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPrivateGather,
        );
        (minimum_coordinators, minimum_signers)
    }

    #[test]
    #[cfg(feature = "with_v1")]
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
        let (coordinators, signers) = setup_with_timeouts::<FireCoordinator<Aggregator>, SignerType>(
            num_signers,
            keys_per_signer,
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
        );

        // Start a DKG round where we will not allow all signers to recv DkgBegin, so they will not respond with DkgPublicShares

        // DKG threshold is 9/10, so need to remove 1
        let num_signers_to_remove = 1;

        let mut minimum_coordinators = coordinators.clone();
        let mut minimum_signers = signers.clone();

        minimum_signers.truncate(minimum_signers.len().saturating_sub(num_signers_to_remove));

        let message = minimum_coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(minimum_coordinators
            .first()
            .unwrap()
            .aggregate_public_key
            .is_none());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPublicGather
        );

        // Send the DKG Begin message to minimum signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            &[message.clone()],
        );

        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPublicGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_messages, operation_results) = minimum_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_messages.is_some());
        assert!(operation_results.is_none());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Run DKG again with fresh coordinator and signers, this time allow gathering DkgPublicShares but timeout getting DkgEnd
        let mut minimum_coordinators = coordinators.clone();
        let mut minimum_signers = signers.clone();

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut minimum_coordinators, &mut minimum_signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPrivateGather
        );

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // now remove signers so the set is minimum
        minimum_signers.truncate(minimum_signers.len().saturating_sub(num_signers_to_remove));

        // Send the DKG Private Begin message to minimum signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_message, operation_result) = minimum_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_some());
        assert!(operation_result.is_none());
        assert!(
            matches!(
                outbound_message.clone().unwrap().msg,
                Message::DkgEndBegin(_)
            ),
            "Expected DkgEndBegin message"
        );
        assert_eq!(
            minimum_coordinators.first().unwrap().state,
            State::DkgEndGather,
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            &[outbound_message.unwrap()],
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Dkg(point) = operation_results[0] else {
            panic!("Expected Dkg Operation result");
        };
        assert_ne!(point, Point::default());
        for coordinator in minimum_coordinators.iter() {
            assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
            assert_eq!(coordinator.get_state(), State::Idle);
        }

        (minimum_coordinators, minimum_signers)
    }

    #[test]
    #[cfg(feature = "with_v1")]
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
        let (coordinators, signers) = setup_with_timeouts::<FireCoordinator<Aggregator>, Signer>(
            num_signers,
            keys_per_signer,
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
            Some(timeout),
        );

        // Start a DKG round where we will not allow all signers to recv DkgBegin, so they will not respond with DkgPublicShares

        // DKG threshold is 9/10, so need to remove 2
        let num_signers_to_remove = 2;

        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        insufficient_signers.truncate(
            insufficient_signers
                .len()
                .saturating_sub(num_signers_to_remove),
        );

        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(insufficient_coordinators
            .first()
            .unwrap()
            .aggregate_public_key
            .is_none());
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::DkgPublicGather
        );

        // Send the DKG Begin message to insufficient signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message.clone()],
        );

        // Failed to get an aggregate public key
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::DkgPublicGather);
        }

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_none());
        assert!(operation_result.is_some());
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::DkgPublicGather,
        );
        assert!(
            matches!(
                operation_result.unwrap(),
                OperationResult::DkgError(DkgError::DkgPublicTimeout(_))
            ),
            "Expected OperationResult::DkgError(DkgError::DkgPublicTimeout"
        );

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
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // now remove signers so the set is insufficient
        insufficient_signers.truncate(
            insufficient_signers
                .len()
                .saturating_sub(num_signers_to_remove),
        );

        // Send the DKG Private Begin message to insufficient signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinator,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        assert_eq!(
            insufficient_coordinator.first().unwrap().state,
            State::DkgPrivateGather,
        );

        // Sleep long enough to hit the timeout
        thread::sleep(expire);

        let (outbound_message, operation_result) = insufficient_coordinator
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_none());
        assert!(operation_result.is_some());
        assert_eq!(
            insufficient_coordinator.first().unwrap().state,
            State::DkgPrivateGather,
        );
        assert!(
            matches!(
                operation_result.unwrap(),
                OperationResult::DkgError(DkgError::DkgPrivateTimeout(_))
            ),
            "Expected OperationResult::DkgError(DkgError::DkgPrivateTimeout)"
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn malicious_signers_dkg_v1() {
        malicious_signers_dkg::<v1::Aggregator, v1::Signer>(5, 2);
    }

    #[test]
    fn malicious_signers_dkg_v2() {
        malicious_signers_dkg::<v2::Aggregator, v2::Signer>(5, 2);
    }

    fn malicious_signers_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator<Aggregator>>, Vec<Signer<SignerType>>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinators
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers, but mutate one signer's DkgPrivateShares so it is marked malicious
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &outbound_messages,
            |signer, msgs| {
                if signer.signer_id != 0 {
                    return msgs;
                }
                msgs.iter()
                    .map(|packet| {
                        let Message::DkgPrivateShares(shares) = &packet.msg else {
                            return packet.clone();
                        };
                        // mutate one of the shares
                        let sshares: Vec<(u32, HashMap<u32, Vec<u8>>)> = shares
                            .shares
                            .iter()
                            .map(|(src_party_id, share_map)| {
                                (
                                    *src_party_id,
                                    share_map
                                        .iter()
                                        .map(|(dst_key_id, bytes)| {
                                            let mut bytes = bytes.clone();
                                            bytes.insert(0, 234);
                                            (*dst_key_id, bytes)
                                        })
                                        .collect(),
                                )
                            })
                            .collect();

                        Packet {
                            msg: Message::DkgPrivateShares(DkgPrivateShares {
                                dkg_id: shares.dkg_id,
                                signer_id: shares.signer_id,
                                shares: sshares.clone(),
                            }),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
        else {
            panic!("Expected OperationResult::DkgError(DkgError::DkgEndFailure");
        };

        for (_signer_id, dkg_failure) in reported_failures {
            let DkgFailure::BadPrivateShares(bad_share_map) = dkg_failure else {
                panic!("Expected DkgFailure::BadPrivateShares");
            };
            for (bad_signer_id, _bad_private_share) in bad_share_map {
                assert_eq!(*bad_signer_id, 0u32);
            }
        }
        (coordinators, signers)
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn bad_poly_length_dkg_v1() {
        bad_poly_length_dkg::<v1::Aggregator, v1::Signer>(5, 2);
    }

    #[test]
    fn bad_poly_length_dkg_v2() {
        bad_poly_length_dkg::<v2::Aggregator, v2::Signer>(5, 2);
    }

    fn bad_poly_length_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator<Aggregator>>, Vec<Signer<SignerType>>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DkgBegin message to all signers and share their responses with the coordinators and signers, but mutate two signers' DkgPublicShares: make one polynomial larger than the threshold, and the other smaller
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[message],
            |signer, msgs| {
                if signer.signer_id != 0 && signer.signer_id != 1 {
                    return msgs;
                }
                msgs.iter()
                    .map(|packet| {
                        let Message::DkgPublicShares(shares) = &packet.msg else {
                            return packet.clone();
                        };
                        let comms = shares
                            .comms
                            .iter()
                            .map(|(id, comm)| {
                                let mut c = comm.clone();
                                if signer.signer_id == 0 {
                                    c.poly.push(Point::new());
                                } else {
                                    c.poly.pop();
                                }
                                (*id, c)
                            })
                            .collect();
                        Packet {
                            msg: Message::DkgPublicShares(DkgPublicShares {
                                dkg_id: shares.dkg_id,
                                signer_id: shares.signer_id,
                                comms,
                                kex_public_key: Point::new(),
                            }),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );

        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
        else {
            panic!("Expected OperationResult::DkgError(DkgError::DkgEndFailure)");
        };

        for (_signer_id, dkg_failure) in reported_failures {
            let DkgFailure::BadPublicShares(bad_shares) = dkg_failure else {
                panic!("Expected DkgFailure::BadPublicShares");
            };
            for bad_signer_id in bad_shares {
                assert!(*bad_signer_id == 0u32 || *bad_signer_id == 1u32);
            }
        }
        (coordinators, signers)
    }

    #[test]
    #[cfg(feature = "with_v1")]
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
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::SignatureShareRequest(_)),
            "Expected SignatureShareRequest message"
        );
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Sign(sig) = &operation_results[0] else {
            panic!("Expected Signature Operation result")
        };
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

    #[test]
    #[cfg(feature = "with_v1")]
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

        signers.truncate(signers.len().saturating_sub(num_signers_to_remove));

        // Start a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::SignatureShareRequest(_)),
            "Expected SignatureShareRequest message"
        );
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Sign(sig) = &operation_results[0] else {
            panic!("Expected Signature Operation result");
        };
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

    #[test]
    #[cfg(feature = "with_v1")]
    fn missing_public_keys_sign_v1() {
        missing_public_keys_sign::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn missing_public_keys_sign_v2() {
        missing_public_keys_sign::<v2::Aggregator, v2::Signer>();
    }

    fn missing_public_keys_sign<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let num_signers = 10;
        let keys_per_signer = 2;

        let (mut coordinators, mut signers) =
            all_signers_dkg::<Aggregator, Signer>(num_signers, keys_per_signer);

        // Let us also remove that signers public key from the config including all of its key ids
        let mut removed_signer = signers.pop().expect("Failed to pop signer");
        let public_key = removed_signer
            .public_keys
            .signers
            .remove(&removed_signer.signer_id)
            .expect("Failed to remove public key");
        removed_signer
            .public_keys
            .key_ids
            .retain(|_k, pk| pk.to_bytes() != public_key.to_bytes());

        for signer in signers.iter_mut() {
            signer.public_keys = removed_signer.public_keys.clone();
        }

        // Start a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(&outbound_messages[0].msg, Message::SignatureShareRequest(_)),
            "Expected SignatureShareRequest message"
        );
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Sign(sig) = &operation_results[0] else {
            panic!("Expected Signature Operation result");
        };
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

    #[test]
    #[cfg(feature = "with_v1")]
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
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
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
        assert!(
            matches!(&outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(&outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DKG End Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Dkg(point) = operation_results[0] else {
            panic!("Expected Dkg Operationr result");
        };
        assert_ne!(point, Point::default());
        for coordinator in &coordinators {
            assert_eq!(coordinator.aggregate_public_key, Some(point));
            assert_eq!(coordinator.state, State::Idle);
        }

        // Figure out how many signers we can remove and still be above the threshold
        let num_keys = config.num_keys as f64;
        let threshold = config.threshold as f64;
        let num_signers_to_remove =
            (((num_keys - threshold) / keys_per_signer as f64).floor() + 1_f64) as usize;
        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        insufficient_signers.truncate(
            insufficient_signers
                .len()
                .saturating_sub(num_signers_to_remove),
        );

        // Start a signing round with an insufficient number of signers
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::NonceGather(signature_type));
        }

        assert!(outbound_messages.is_empty());

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_none());
        assert!(operation_result.is_some());
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::NonceGather(signature_type));
        }

        assert!(
            matches!(
                operation_result.unwrap(),
                OperationResult::SignError(SignError::NonceTimeout(..))
            ),
            "Expected OperationResult::SignError(SignError::NonceTimeout)"
        );

        // Start a new signing round with a sufficient number of signers for nonces but not sig shares
        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and insufficient_coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);

        let mut malicious = Vec::new();

        // now remove signers so the number is insufficient
        let num_signers_to_drain = insufficient_signers
            .len()
            .saturating_sub(num_signers_to_remove);
        malicious.extend(insufficient_signers.drain(num_signers_to_drain..));

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_some());
        assert!(operation_result.is_none());
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // put the malicious signers back in
        insufficient_signers.append(&mut malicious);

        // Send the NonceRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[outbound_message.unwrap()],
        );
        assert_eq!(outbound_messages.len(), 1);
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // again remove signers so the number is insufficient
        let num_signers_to_drain = insufficient_signers
            .len()
            .saturating_sub(num_signers_to_remove);
        malicious.extend(insufficient_signers.drain(num_signers_to_drain..));

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_none());
        assert!(operation_result.is_some());
        assert_eq!(
            insufficient_coordinators.first_mut().unwrap().state,
            State::SigShareGather(signature_type)
        );
        assert!(
            matches!(
                operation_result.unwrap(),
                OperationResult::SignError(SignError::InsufficientSigners(_))
            ),
            "Expected OperationResult::SignError(SignError::InsufficientSigners)"
        );
    }

    #[test]
    #[cfg(feature = "with_v1")]
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
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&orig_msg, signature_type, None)
            .unwrap();

        let mut alt_packet = message.clone();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
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
        let Message::NonceRequest(nonce_request) = &mut alt_packet.msg else {
            panic!("Expected NonceRequest message");
        };
        nonce_request.message = alt_message.clone();

        // Send the alternative message to the last 3/4 of signers and gather responses by sharing with the rest of the signers and the coordinators
        let (alt_outbound_messages, alt_operation_results) = feedback_messages(
            &mut coordinators,
            &mut signers[signers_len / 4..],
            &[alt_packet],
        );

        assert!(operation_results.is_empty());
        assert!(alt_operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }
        // Assert that the first 1/4 signers did not receive a result
        assert!(outbound_messages.is_empty());
        assert_eq!(alt_outbound_messages.len(), 1);
        assert!(
            matches!(
                &alt_outbound_messages[0].msg,
                Message::SignatureShareRequest(_)
            ),
            "Expected SignatureShareRequest message"
        );

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &alt_outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::Sign(sig) = &operation_results[0] else {
            panic!("Expected Signature Operation result");
        };
        // Verify that the winning message was the alternative message that had majority vote
        assert!(sig.verify(
            &coordinators
                .first()
                .unwrap()
                .aggregate_public_key
                .expect("No aggregate public key set!"),
            &alt_message
        ));

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn old_round_ids_are_ignored_v1() {
        old_round_ids_are_ignored::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn old_round_ids_are_ignored_v2() {
        old_round_ids_are_ignored::<v2::Aggregator, v2::Signer>();
    }

    fn old_round_ids_are_ignored<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let (mut coordinators, _) = setup::<FireCoordinator<Aggregator>, Signer>(3, 10);
        for coordinator in &mut coordinators {
            let id: u64 = 10;
            let old_id = id;
            coordinator.current_dkg_id = id;
            coordinator.current_sign_id = id;
            // Attempt to start an old DKG round
            let (packets, results) = coordinator
                .process(&Packet {
                    sig: vec![],
                    msg: Message::DkgBegin(DkgBegin { dkg_id: old_id }),
                })
                .unwrap();
            assert!(packets.is_none());
            assert!(results.is_none());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_dkg_id, id);

            // Attempt to start the same DKG round
            let (packets, results) = coordinator
                .process(&Packet {
                    sig: vec![],
                    msg: Message::DkgBegin(DkgBegin { dkg_id: id }),
                })
                .unwrap();
            assert!(packets.is_none());
            assert!(results.is_none());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_dkg_id, id);

            // Attempt to start an old Sign round
            let (packets, results) = coordinator
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
            assert!(packets.is_none());
            assert!(results.is_none());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_sign_id, id);

            // Attempt to start the same Sign round
            let (packets, results) = coordinator
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
            assert!(packets.is_none());
            assert!(results.is_none());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_sign_id, id);
        }
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn gen_nonces_v1() {
        gen_nonces::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 1);
    }

    #[test]
    fn gen_nonces_v2() {
        gen_nonces::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 1);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn bad_signature_share_request_v1() {
        bad_signature_share_request::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn bad_signature_share_request_v2() {
        bad_signature_share_request::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn invalid_nonce_v1() {
        invalid_nonce::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn invalid_nonce_v2() {
        invalid_nonce::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn one_signer_bad_threshold_v1() {
        one_signer_bad_threshold::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn one_signer_bad_threshold_v2() {
        one_signer_bad_threshold::<v2::Aggregator, v2::Signer>();
    }

    fn one_signer_bad_threshold<Aggregator: AggregatorTrait, SignerType: SignerTrait>() {
        let mut rng = create_rng();
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(10, 1);

        // persist one signer, change the threshold, reset polys
        let mut state = signers[0].save();

        state.threshold -= 1;
        state.signer.threshold -= 1;

        signers[0] = Signer::<SignerType>::load(&state);

        signers[0].signer.reset_polys(&mut rng);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures,
            malicious_signers,
        }) = &operation_results[0]
        else {
            panic!(
                "Expected OperationResult::DkgError(DkgError::DkgEndFailure), got {:?}",
                operation_results[0]
            );
        };
        for i in 1..10 {
            match reported_failures.get(&i) {
                Some(DkgFailure::BadPublicShares(set)) => {
                    if set.len() != 1 {
                        panic!("signer {i} should have reported a single BadPublicShares");
                    } else if !set.contains(&0) {
                        panic!("signer {i} should have reported BadPublicShares from signer 0");
                    }
                }
                Some(failure) => {
                    panic!("signer {i} should have reported BadPublicShares, instead reported {failure:?}");
                }
                None => {
                    panic!("signer {i} should have reported BadPublicShares");
                }
            }
        }

        match reported_failures.get(&0) {
            Some(DkgFailure::BadPublicShares(set)) => {
                if set.len() != 9 {
                    panic!("signer 0 should have reported BadPublicShares from all others");
                } else if set.contains(&0) {
                    panic!("signer 0 should not have reported BadPublicShares from signer 0");
                }
            }
            Some(failure) => {
                panic!(
                    "signer 0 should have reported BadPublicShares, instead reported {failure:?}"
                );
            }
            None => {
                panic!("signer 0 should have reported BadPublicShares");
            }
        }

        if !malicious_signers.len() == 1 || !malicious_signers.contains(&0) {
            panic!(
                "Coordinator should have marked signer 0 as malicious, instead marked {malicious_signers:?}",
            );
        }
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn bad_dkg_threshold_v1() {
        bad_dkg_threshold::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn bad_dkg_threshold_v2() {
        bad_dkg_threshold::<v2::Aggregator, v2::Signer>();
    }

    fn bad_dkg_threshold<Aggregator: AggregatorTrait, SignerType: SignerTrait>() {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(10, 1);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(&outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // alter the DkgEndBegin message
        let mut packet = outbound_messages[0].clone();
        if let Message::DkgEndBegin(ref mut dkg_end_begin) = packet.msg {
            dkg_end_begin.signer_ids = vec![0u32];
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[packet]);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
        else {
            panic!("Expected DkgEndFailure got {:?}", operation_results[0]);
        };
        for (signer_id, failure) in reported_failures {
            assert!(
                matches!(failure, DkgFailure::Threshold),
                "{signer_id} had wrong failure {failure:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn empty_public_shares_v1() {
        empty_public_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn empty_public_shares_v2() {
        empty_public_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn empty_private_shares_v1() {
        empty_private_shares::<FireCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn empty_private_shares_v2() {
        empty_private_shares::<FireCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    #[cfg(feature = "with_v1")]
    fn verify_packet_sigs_v1() {
        verify_packet_sigs::<FireCoordinator<v1::Aggregator>, v1::Signer>();
    }

    #[test]
    fn verify_packet_sigs_v2() {
        verify_packet_sigs::<FireCoordinator<v2::Aggregator>, v2::Signer>();
    }
}
