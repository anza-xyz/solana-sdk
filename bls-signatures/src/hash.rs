use {
    crate::proof_of_possession::POP_DST,
    blstrs::{G2Affine, G2Prepared, G2Projective},
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

/// A hashed message (G2 affine point) for optimized verification.
///
/// Reusing this value avoids repeating hash-to-curve work when the same message
/// is verified multiple times. This type is relatively compact (an affine
/// point), and does not include pairing precomputation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashedMessage(pub(crate) G2Affine);

impl HashedMessage {
    /// Hash a message to a curve point (G2) and prepare it for verification.
    pub fn new(message: &[u8]) -> Self {
        let point = G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[]);
        Self(point.into())
    }
}

/// A hashed-and-prepared message for pairing verification.
///
/// This type stores both the hashed G2 affine point and a prepared G2 pairing
/// representation. It is useful when the same message is verified repeatedly
/// against many signatures because it skips the pairing preparation step.
///
/// Memory note: each `PreparedHashedMessage` includes a `G2Prepared`, which is
/// significantly larger than a plain `HashedMessage` (roughly ~19 KiB per
/// element in current `blstrs` implementations).
#[derive(Clone, Debug)]
pub struct PreparedHashedMessage {
    pub(crate) hashed_message: HashedMessage,
    pub(crate) prepared: G2Prepared,
}

impl PreparedHashedMessage {
    /// Hash a message to a curve point (G2), then prepare it for pairing verification.
    pub fn new(message: &[u8]) -> Self {
        Self::from_hashed_message(&HashedMessage::new(message))
    }

    /// Convert an existing `HashedMessage` into a pairing-prepared representation.
    pub fn from_hashed_message(hashed_message: &HashedMessage) -> Self {
        Self {
            hashed_message: *hashed_message,
            prepared: G2Prepared::from(hashed_message.0),
        }
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
