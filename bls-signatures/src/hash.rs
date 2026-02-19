use {
    crate::proof_of_possession::POP_DST,
    blstrs::{G2Affine, G2Projective},
};

/// Domain separation tag used for hashing messages to curve points to prevent
/// potential conflicts between different BLS implementations. This is defined
/// as the ciphersuite ID string as recommended in the
/// [standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.1).
pub const HASH_TO_POINT_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_POP_";

/// Hash a message to a G2 point for signature generation and verification
///
/// If hashing a payload for a Proof-of-Possession (PoP), use
/// `hash_pop_payload_to_point` instead.
#[deprecated(since = "3.1.0", note = "Use `HashedMessage::new` instead")]
pub fn hash_signature_message_to_point(message: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
}

/// A pre-hashed message (G2 point) for optimized verification.
/// For certain applications, re-using hash-to-curve operation can be used as a form of
/// optimization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashedMessage(pub(crate) G2Affine);

impl HashedMessage {
    /// Hash a message to a curve point (G2) and prepare it for verification.
    pub fn new(message: &[u8]) -> Self {
        let point = G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[]);
        Self(point.into())
    }
}

/// A pre-hashed Proof-of-Possession (G2 point) for optimized verification.
/// For certain applications, re-using hash-to-curve operation can be used as a form of
/// optimization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashedPoPPayload(pub(crate) G2Affine);

impl HashedPoPPayload {
    /// Hash a message to a curve point (G2) and prepare it for verification.
    pub fn new(payload: &[u8]) -> Self {
        let point = G2Projective::hash_to_curve(payload, POP_DST, &[]);
        Self(point.into())
    }
}

pub(crate) fn hash_message_to_projective(message: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
}

pub(crate) fn hash_pop_to_projective(payload: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(payload, POP_DST, &[])
}
