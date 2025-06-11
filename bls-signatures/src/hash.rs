use {
    crate::{proof_of_possession::POP_DST, pubkey::PubkeyProjective},
    blstrs::G2Projective,
};

/// Domain separation tag used for hashing messages to curve points to prevent
/// potential conflicts between different BLS implementations. This is defined
/// as the ciphersuite ID string as recommended in the standard
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.1.
pub const HASH_TO_POINT_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Hash a message to a G2 point
pub fn hash_message_to_point(message: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
}

/// Hash a pubkey to a G2 point
pub(crate) fn hash_pubkey_to_g2(public_key: &PubkeyProjective) -> G2Projective {
    let pubkey_bytes = public_key.0.to_compressed();
    G2Projective::hash_to_curve(&pubkey_bytes, POP_DST, &[])
}
