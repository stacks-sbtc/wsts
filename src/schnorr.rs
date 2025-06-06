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
/// ID type which encapsulates the ID and a schnorr proof of ownership of the polynomial
pub struct ID {
    /// The ID
    pub id: Scalar,
    /// The public schnorr response
    pub kG: Point,
    /// The aggregate of the schnorr committed values
    pub kca: Scalar,
}

#[allow(non_snake_case)]
impl ID {
    /// Construct a new schnorr ID which binds the passed `Scalar` `id` and `Scalar` `a`, with a
    /// zero-knowledge proof of ownership of `a`.  The `ctx` is a common reference string used to
    /// prevent replay attacks; it can be any length, but will typically be a `u64` value in
    /// big endian format.
    pub fn new<RNG: RngCore + CryptoRng>(
        id: &Scalar,
        a: &Scalar,
        ctx: &[u8],
        rng: &mut RNG,
    ) -> Self {
        let k = Scalar::random(rng);
        let c = Self::challenge(id, &(&k * &G), &(a * &G), ctx);

        Self {
            id: *id,
            kG: &k * G,
            kca: &k + c * a,
        }
    }

    /// Compute the schnorr challenge
    pub fn challenge(id: &Scalar, K: &Point, A: &Point, ctx: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();
        let tag = "WSTS/polynomial-constant";

        hasher.update(tag.as_bytes());
        hasher.update(id.to_bytes());
        hasher.update(K.compress().as_bytes());
        hasher.update(A.compress().as_bytes());
        hasher.update(ctx);

        hash_to_scalar(&mut hasher)
    }

    /// Verify the proof
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
}
