use {crate::proof_of_possession::POP_DST, blstrs::G2Projective};

/// Domain separation tag used for hashing messages to curve points to prevent
/// potential conflicts between different BLS implementations. This is defined
/// as the ciphersuite ID string as recommended in the
/// [standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.1).
pub const HASH_TO_POINT_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Hash a message to a G2 point for signature generation and verification
pub fn hash_signature_message_to_point(message: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
}

/// Hash a message to a G2 point for proof-of-possession generation and verification
pub(crate) fn hash_pop_payload_to_point(payload: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(payload, POP_DST, &[])
}
