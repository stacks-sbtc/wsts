use core::iter::zip;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

use crate::{
    common::PublicNonce,
    curve::{
        ecdsa,
        point::{Compressed, Error as PointError, Point, G},
        scalar::Scalar,
    },
    util::{expand_to_scalar, hash_to_scalar},
};

/// What type of message expansion to use, i.e. how do we take a stream of bytes and turn it into
/// a digest.  The original FROST paper simply says to use "a hash function whose outputs are in
/// $Z_q^*$".  The IETF FROST RFC, however, uses XMD message expansion, which is used when hashing
/// to curves and their scalars/field elements in order to get a more even distribution than a raw
/// hash would provide.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub enum ExpansionType {
    /// Expand hash directly from bytes
    #[default]
    Default,
    /// Expand hash using XMD
    Xmd,
}

/// Compute a binding value from the party ID, public nonces, and signed message using the passed expansion type.
pub fn binding(
    id: &Scalar,
    public_nonces: &[PublicNonce],
    msg: &[u8],
    expansion_type: ExpansionType,
) -> Scalar {
    match expansion_type {
        ExpansionType::Default => binding_default(id, public_nonces, msg),
        ExpansionType::Xmd => binding_xmd(id, public_nonces, msg),
    }
}

/// Compute a binding value from the party ID, public nonces, and signed message using the passed expansion type.
pub fn binding_compressed(
    id: &Scalar,
    public_nonces: &[(Compressed, Compressed)],
    msg: &[u8],
    expansion_type: ExpansionType,
) -> Scalar {
    match expansion_type {
        ExpansionType::Default => binding_compressed_default(id, public_nonces, msg),
        ExpansionType::Xmd => binding_compressed_xmd(id, public_nonces, msg),
    }
}

/// Compute a binding value from the party ID, public nonces, and signed message using XMD-based expansion.
pub fn binding_xmd(id: &Scalar, public_nonces: &[PublicNonce], msg: &[u8]) -> Scalar {
    let prefix = b"WSTS/binding";

    // Serialize all input into a buffer
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_bytes());

    for public_nonce in public_nonces {
        buf.extend_from_slice(public_nonce.D.compress().as_bytes());
        buf.extend_from_slice(public_nonce.E.compress().as_bytes());
    }

    buf.extend_from_slice(msg);

    expand_to_scalar(&buf, prefix)
        .expect("FATAL: DST is less than 256 bytes so operation should not fail")
}

/// Compute a binding value from the party ID, public nonces, and signed message using XMD-based expansion.
pub fn binding_compressed_xmd(
    id: &Scalar,
    public_nonces: &[(Compressed, Compressed)],
    msg: &[u8],
) -> Scalar {
    let prefix = b"WSTS/binding";

    // Serialize all input into a buffer
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_bytes());

    for (binding, hiding) in public_nonces {
        buf.extend_from_slice(binding.as_bytes());
        buf.extend_from_slice(hiding.as_bytes());
    }

    buf.extend_from_slice(msg);

    expand_to_scalar(&buf, prefix)
        .expect("FATAL: DST is less than 256 bytes so operation should not fail")
}

/// Compute a binding value from the party ID, public nonces, and signed message using default expansion.
pub fn binding_default(id: &Scalar, public_nonces: &[PublicNonce], msg: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    let prefix = "WSTS/binding";

    hasher.update(prefix.as_bytes());
    hasher.update(id.to_bytes());
    for public_nonce in public_nonces {
        hasher.update(public_nonce.D.compress().as_bytes());
        hasher.update(public_nonce.E.compress().as_bytes());
    }
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

/// Compute a binding value from the party ID, public nonces, and signed message using default expansion.
pub fn binding_compressed_default(
    id: &Scalar,
    public_nonces: &[(Compressed, Compressed)],
    msg: &[u8],
) -> Scalar {
    let mut hasher = Sha256::new();
    let prefix = "WSTS/binding";

    hasher.update(prefix.as_bytes());
    hasher.update(id.to_bytes());
    for (binding, hiding) in public_nonces {
        hasher.update(binding.as_bytes());
        hasher.update(hiding.as_bytes());
    }
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
/// Compute the schnorr challenge from the public key, aggregated commitments, and the signed message using XMD-based expansion.
pub fn challenge(publicKey: &Point, R: &Point, msg: &[u8]) -> Scalar {
    let tag = "BIP0340/challenge";

    let mut hasher = tagged_hash(tag);

    hasher.update(R.x().to_bytes());
    hasher.update(publicKey.x().to_bytes());
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

/// Compute the Lagrange interpolation value
pub fn lambda(i: u32, key_ids: &[u32]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in key_ids {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}

// Is this the best way to return these values?
#[allow(non_snake_case)]
/// Compute the intermediate values used in both the parties and the aggregator
pub fn intermediate(
    msg: &[u8],
    party_ids: &[u32],
    nonces: &[PublicNonce],
    expansion_type: ExpansionType,
) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg, expansion_type))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}

#[allow(non_snake_case)]
/// Compute the aggregate nonce
pub fn aggregate_nonce(
    msg: &[u8],
    party_ids: &[u32],
    nonces: &[PublicNonce],
    expansion_type: ExpansionType,
) -> Result<Point, PointError> {
    let compressed_nonces: Vec<(Compressed, Compressed)> = nonces
        .iter()
        .map(|nonce| (nonce.D.compress(), nonce.E.compress()))
        .collect();
    let scalars: Vec<Scalar> = party_ids
        .iter()
        .flat_map(|&i| {
            [
                Scalar::from(1),
                binding_compressed(&id(i), &compressed_nonces, msg, expansion_type),
            ]
        })
        .collect();
    let points: Vec<Point> = nonces.iter().flat_map(|nonce| [nonce.D, nonce.E]).collect();

    Point::multimult(scalars, points)
}

/// Compute a one-based Scalar from a zero-based integer
pub fn id(i: u32) -> Scalar {
    Scalar::from(i)
}

/// Evaluate the public polynomial `f` at scalar `x` using multi-exponentiation
#[allow(clippy::ptr_arg)]
pub fn poly(x: &Scalar, f: &Vec<Point>) -> Result<Point, PointError> {
    let mut s = Vec::with_capacity(f.len());
    let mut pow = Scalar::one();
    for _ in 0..f.len() {
        s.push(pow);
        pow *= x;
    }

    Point::multimult(s, f.clone())
}

/// Create a BIP340 compliant tagged hash by double hashing the tag
pub fn tagged_hash(tag: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    let mut tag_hasher = Sha256::new();

    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();

    hasher.update(tag_hash);
    hasher.update(tag_hash);

    hasher
}

/// Create a BIP341 compliant taproot tweak from a public key and merkle root
pub fn tweak(public_key: &Point, merkle_root: Option<[u8; 32]>) -> Scalar {
    let mut hasher = tagged_hash("TapTweak");

    hasher.update(public_key.x().to_bytes());
    if let Some(root) = merkle_root {
        hasher.update(root);
    }

    hash_to_scalar(&mut hasher)
}

/// Create a BIP341 compliant taproot tweak from a public key and merkle root
pub fn tweaked_public_key(public_key: &Point, merkle_root: Option<[u8; 32]>) -> Point {
    tweaked_public_key_from_tweak(public_key, tweak(public_key, merkle_root))
}

/// Create a BIP341 compliant taproot tweak from a public key and a pre-calculated tweak
///
/// We should never trigger the unwrap here, because Point::lift_x only returns an error
/// when the x-coordinate is not on the secp256k1 curve, but we know that public_key.x()
/// is on the curve because it is a Point.
pub fn tweaked_public_key_from_tweak(public_key: &Point, tweak: Scalar) -> Point {
    Point::lift_x(&public_key.x()).unwrap() + tweak * G
}

/// Create a taproot style merkle root from the serialized script data
pub fn merkle_root(data: &[u8]) -> [u8; 32] {
    let mut hasher = tagged_hash("TapLeaf");

    hasher.update(data);

    hasher.finalize().into()
}

/// Get a Point from an ecdsa::PublicKey
pub fn point(key: &ecdsa::PublicKey) -> Result<Point, PointError> {
    let compressed = Compressed::from(key.to_bytes());
    // this should not fail as long as the public key above was valid
    Point::try_from(&compressed)
}
