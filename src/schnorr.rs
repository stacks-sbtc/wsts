use num_traits::Zero;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    curve::{
        point::{Point, G},
        scalar::Scalar,
    },
    util::hash_to_scalar,
};

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// Encapsulatetion of the ID and a zero knowledge proof of ownership of a private key bound to ID
pub struct ID {
    /// ID
    pub id: Scalar,
    /// Commitment to the proof random value
    pub random_commitment: Point,
    /// Sigma protocol response
    pub sigma_response: Scalar,
}

#[allow(non_snake_case)]
impl ID {
    /// Construct a new schnorr ID which binds the passed `Scalar` `id` and `Scalar` `x`, with a
    /// zero-knowledge proof of ownership of `x`.  The `ctx` is a common reference string used to
    /// prevent replay attacks; it can be any length, but will typically be a `u64` value in
    /// big endian format.
    pub fn new<RNG: RngCore + CryptoRng>(
        id: &Scalar,
        x: &Scalar,
        ctx: &[u8],
        rng: &mut RNG,
    ) -> Self {
        let r = Scalar::random(rng);
        let random_commitment = r * G;
        let public_key = x * G;
        let c = Self::challenge(id, &random_commitment, &public_key, ctx);
        let sigma_response = r + c * x;

        Self {
            id: *id,
            random_commitment,
            sigma_response,
        }
    }

    /// Compute the schnorr challenge
    pub fn challenge(
        id: &Scalar,
        random_commitment: &Point,
        public_key: &Point,
        ctx: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        let tag = "WSTS/polynomial-constant";

        hasher.update(tag.as_bytes());
        hasher.update(id.to_bytes());

        hasher.update(random_commitment.compress().as_bytes());
        hasher.update(public_key.compress().as_bytes());
        hasher.update(ctx);

        hash_to_scalar(&mut hasher)
    }

    /// Verify the proof
    pub fn verify(&self, public_key: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.random_commitment, public_key, ctx);
        &self.sigma_response * &G == &self.random_commitment + c * public_key
    }

    /// Zero out the schnorr proof
    pub fn zeroize(&mut self) {
        self.random_commitment = Point::new();
        self.sigma_response = Scalar::zero();
    }

    /// Check if schnorr proof is zeroed out
    pub fn is_zero(&self) -> bool {
        self.random_commitment == Point::new() && self.sigma_response == Scalar::zero()
    }
}
