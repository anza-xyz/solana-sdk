use {
    crate::{prepared_g2::PreparedG2, proof_of_possession::POP_DST},
    blstrs::{G2Affine, G2Projective},
};

/// Domain separation tag used for hashing messages to curve points to prevent
/// potential conflicts between different BLS implementations. This is defined
/// as the ciphersuite ID string as recommended in the
/// [standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.1).
pub const HASH_TO_POINT_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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
/// Memory note: each `PreparedHashedMessage` owns a heap-allocated pairing
/// preparation table (19,584 bytes for a nonidentity point), in addition to
/// the hashed point. Cloning duplicates the table.
#[derive(Clone, Debug)]
pub struct PreparedHashedMessage {
    pub(crate) hashed_message: HashedMessage,
    pub(crate) prepared: PreparedG2,
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
            prepared: PreparedG2::from(hashed_message.0),
        }
    }
}

/// A pre-hashed Proof-of-Possession (G2 point) for optimized verification.
/// For certain applications, re-using hash-to-curve operation can be used as a form of
/// optimization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashedPoPPayload(pub(crate) G2Affine);

impl HashedPoPPayload {
    /// Hash a payload bound to a specific public key for proof-of-possession checks.
    pub fn new(payload: &[u8], pubkey_bytes: &[u8]) -> Self {
        let point = hash_bound_pop_to_projective(payload, pubkey_bytes);
        Self(point.into())
    }
}

pub(crate) fn hash_message_to_projective(message: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
}

#[cfg(test)]
pub(crate) fn hash_pop_to_projective(payload: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(payload, POP_DST, &[])
}

pub(crate) fn hash_bound_pop_to_projective(payload: &[u8], pubkey_bytes: &[u8]) -> G2Projective {
    // blst hashes augmentation before the message, preserving
    // H(payload || pubkey_bytes) under POP_DST without a temporary buffer.
    G2Projective::hash_to_curve(pubkey_bytes, POP_DST, payload)
}

#[cfg(test)]
mod tests {
    use {super::*, alloc::vec::Vec};

    #[test]
    fn test_pop_hash_matches_concatenated_input() {
        for payload_len in [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1024] {
            let payload: Vec<u8> = [0x00, 0x7f, 0x80, 0xff]
                .into_iter()
                .cycle()
                .take(payload_len)
                .collect();
            for pubkey_len in [0, 1, 48, 96] {
                let pubkey_bytes: Vec<u8> = [0xa5, 0x00, 0xff, 0x19]
                    .into_iter()
                    .cycle()
                    .take(pubkey_len)
                    .collect();

                // Reproduce the old input construction independently.
                let mut joined = payload.clone();
                joined.extend_from_slice(&pubkey_bytes);
                let expected = G2Projective::hash_to_curve(&joined, POP_DST, &[]);
                let actual = HashedPoPPayload::new(&payload, &pubkey_bytes);
                assert_eq!(
                    actual.0,
                    G2Affine::from(expected),
                    "payload_len={payload_len}, pubkey_len={pubkey_len}"
                );
            }
        }
    }
}
