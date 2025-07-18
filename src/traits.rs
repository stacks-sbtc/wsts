use core::{cmp::PartialEq, fmt::Debug};
use hashbrown::{HashMap, HashSet};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{
    common::{MerkleRoot, Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare},
    curve::{point::Point, scalar::Scalar},
    errors::{AggregatorError, DkgError},
    taproot::SchnorrProof,
};

#[derive(Clone, Deserialize, Serialize, PartialEq)]
/// The saved state required to reconstruct a party
pub struct PartyState {
    /// The party's private polynomial
    pub polynomial: Option<Polynomial<Scalar>>,
    /// The key IDS and associate private keys for this party
    pub private_keys: Vec<(u32, Scalar)>,
    /// The nonce being used by this party
    pub nonce: Nonce,
}

impl fmt::Debug for PartyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartyState").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// The saved state required to reconstruct a signer
pub struct SignerState {
    /// The signer ID
    pub id: u32,
    /// The key IDs this signer controls
    pub key_ids: Vec<u32>,
    /// The total number of keys
    pub num_keys: u32,
    /// The total number of parties
    pub num_parties: u32,
    /// The threshold for signing
    pub threshold: u32,
    /// The aggregate group public key
    pub group_key: Point,
    /// The party IDs and associated state for this signer
    pub parties: Vec<(u32, PartyState)>,
}

/// A trait which provides a common `Signer` interface for `v1` and `v2`
pub trait Signer: Clone + Debug + PartialEq {
    /// Create a new `Signer`
    fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self;

    /// Load a signer from the previously saved `state`
    fn load(state: &SignerState) -> Self;

    /// Save the state required to reconstruct the party
    fn save(&self) -> SignerState;

    /// Get the signer ID for this signer
    fn get_id(&self) -> u32;

    /// Get all key IDs for this signer
    fn get_key_ids(&self) -> Vec<u32>;

    /// Get the total number of parties
    fn get_num_parties(&self) -> u32;

    /// Get all poly commitments for this signer and the passed context
    fn get_poly_commitments<RNG: RngCore + CryptoRng>(
        &self,
        ctx: &[u8],
        rng: &mut RNG,
    ) -> Vec<PolyCommitment>;

    /// Reset all polynomials for this signer
    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG);

    /// Clear all polynomials for this signer
    fn clear_polys(&mut self);

    /// Get all private shares for this signer
    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>>;

    /// Compute all secrets for this signer
    fn compute_secrets(
        &mut self,
        shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), HashMap<u32, DkgError>>;

    /// Generate all nonces for this signer
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce>;

    /// Compute intermediate values
    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point);

    /// Validate that signer_id owns party_id
    fn validate_party_id(
        signer_id: u32,
        party_id: u32,
        signer_key_ids: &HashMap<u32, HashSet<u32>>,
    ) -> bool;

    /// Sign `msg` using all this signer's keys
    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare>;

    /// Sign `msg` using all this signer's keys
    fn sign_schnorr(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare>;

    /// Sign `msg` using all this signer's keys and a tweaked public key
    fn sign_taproot(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        merkle_root: Option<MerkleRoot>,
    ) -> Vec<SignatureShare>;
}

/// A trait which provides a common `Aggregator` interface for `v1` and `v2`
pub trait Aggregator: Clone + Debug + PartialEq {
    /// Construct an Aggregator with the passed parameters
    fn new(num_keys: u32, threshold: u32) -> Self;

    /// Initialize an Aggregator with the passed polynomial commitments
    fn init(&mut self, poly_comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError>;

    /// Check and aggregate the signature shares into a FROST `Signature`
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError>;

    /// Check and aggregate the signature shares into a BIP-340 `SchnorrProof`.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>
    fn sign_schnorr(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<SchnorrProof, AggregatorError>;

    /// Check and aggregate the signature shares into a BIP-340 `SchnorrProof` with BIP-341 key tweaks
    /// <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>
    /// <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
    fn sign_taproot(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        merkle_root: Option<MerkleRoot>,
    ) -> Result<SchnorrProof, AggregatorError>;
}

/// Helper functions for tests
pub mod test_helpers {
    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    use crate::{common::PolyCommitment, errors::DkgError, traits::Scalar, util::create_rng};

    /// Run DKG on the passed signers
    pub fn dkg<RNG: RngCore + CryptoRng, Signer: super::Signer>(
        signers: &mut [Signer],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let ctx = 0u64.to_be_bytes();
        let public_shares: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(&ctx, rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) =
                signer.compute_secrets(&private_shares, &public_shares, &ctx)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(public_shares)
        } else {
            Err(secret_errors)
        }
    }

    /// Remove the provided key ids from the list of private shares and execute compute secrets
    fn compute_secrets_missing_private_shares<RNG: RngCore + CryptoRng, Signer: super::Signer>(
        signers: &mut [Signer],
        rng: &mut RNG,
        missing_key_ids: &[u32],
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        assert!(
            !missing_key_ids.is_empty(),
            "Cannot run a missing shares test without specificying at least one missing key id"
        );
        let ctx = 0u64.to_be_bytes();
        let polys: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(&ctx, rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, mut signer_shares) in signer.get_shares() {
                for key_id in missing_key_ids {
                    if signer.get_key_ids().contains(key_id) {
                        signer_shares.remove(key_id);
                    }
                }
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) = signer.compute_secrets(&private_shares, &polys, &ctx)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(polys)
        } else {
            Err(secret_errors)
        }
    }

    #[allow(non_snake_case)]
    /// Run compute secrets test to trigger MissingPrivateShares code path
    pub fn run_compute_secrets_missing_private_shares<Signer: super::Signer>() {
        let Nk: u32 = 10;
        let Np: u32 = 4;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], vec![9, 10]];
        let missing_key_ids = vec![1, 7];
        let mut rng = create_rng();
        let mut signers: Vec<Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| Signer::new(id.try_into().unwrap(), ids, Nk, Np, T, &mut rng))
            .collect();

        match compute_secrets_missing_private_shares(&mut signers, &mut rng, &missing_key_ids) {
            Ok(polys) => panic!("Got a result with missing public shares: {polys:?}"),
            Err(secret_errors) => {
                for (_, error) in secret_errors {
                    assert!(matches!(error, DkgError::MissingPrivateShares(_)));
                }
            }
        }
    }

    /// Check that bad polynomial lengths are properly caught as errors during DKG
    pub fn bad_polynomial_length<Signer: super::Signer, F: Fn(u32) -> u32>(func: F) {
        let num_keys: u32 = 10;
        let num_signers: u32 = 4;
        let threshold: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9], vec![10]];
        let mut rng = create_rng();
        let mut signers: Vec<Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| {
                if *ids == vec![10] {
                    Signer::new(
                        id.try_into().unwrap(),
                        ids,
                        num_signers,
                        num_keys,
                        func(threshold),
                        &mut rng,
                    )
                } else {
                    Signer::new(
                        id.try_into().unwrap(),
                        ids,
                        num_signers,
                        num_keys,
                        threshold,
                        &mut rng,
                    )
                }
            })
            .collect();

        if dkg(&mut signers, &mut rng).is_ok() {
            panic!("DKG should have failed")
        }
    }

    /// Check that bad polynomial commitments are properly caught as errors during DKG
    pub fn bad_polynomial_commitment<Signer: super::Signer>() {
        let num_keys: u32 = 10;
        let num_signers: u32 = 4;
        let threshold: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9], vec![10]];
        let mut rng = create_rng();
        let mut signers: Vec<Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| {
                Signer::new(
                    id.try_into().unwrap(),
                    ids,
                    num_signers,
                    num_keys,
                    threshold,
                    &mut rng,
                )
            })
            .collect();

        // The code that follows is essentially the same code that we have
        // in the `dkg` helper function above, except we've corrupted the
        // schnorr proof so that we can test verification would fail at
        // the end.
        let ctx = 0u64.to_be_bytes();
        let bad_party_id = 2u32;
        let public_shares: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(&ctx, &mut rng))
            .map(|comm| {
                let party_id = comm.id.id.get_u32();
                if party_id == bad_party_id {
                    // alter the schnorr proof so it will fail verification
                    let mut bad_comm = comm.clone();
                    bad_comm.id.kca += Scalar::from(1);
                    (party_id, bad_comm)
                } else {
                    (party_id, comm)
                }
            })
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) =
                signer.compute_secrets(&private_shares, &public_shares, &ctx)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        assert!(!secret_errors.is_empty());
    }
}
