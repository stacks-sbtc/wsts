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
    pub R: Point,
    /// Sigma protocol response
    pub s: Scalar,
}

#[allow(non_snake_case)]
impl ID {
    /// Construct a new schnorr ID that proves ownership of private key `x` bound to `id`
    pub fn new<RNG: RngCore + CryptoRng>(id: &Scalar, x: &Scalar, rng: &mut RNG) -> Self {
        let r = Scalar::random(rng);
        let R = r * G;
        let X = x * G;
        let c = Self::challenge(id, &R, &X);
        let s = r + c * x;

        Self { id: *id, R, s }
    }

    /// Compute the schnorr challenge
    pub fn challenge(id: &Scalar, R: &Point, X: &Point) -> Scalar {
        let mut hasher = Sha256::new();
        let tag = "WSTS/polynomial-constant";

        hasher.update(tag.as_bytes());
        hasher.update(id.to_bytes());
        hasher.update(R.compress().as_bytes());
        hasher.update(X.compress().as_bytes());

        hash_to_scalar(&mut hasher)
    }

    /// Verify the proof against the public key `X`
    pub fn verify(&self, X: &Point) -> bool {
        let c = Self::challenge(&self.id, &self.R, X);
        &self.s * &G == &self.R + c * X
    }

    /// Zero out the schnorr proof
    pub fn zero(&mut self) {
        self.R = Point::new();
        self.s = Scalar::zero();
    }

    /// Check if schnorr proof is zeroed out
    pub fn is_zero(&self) -> bool {
        self.R == Point::new() && self.s == Scalar::zero()
    }
}
