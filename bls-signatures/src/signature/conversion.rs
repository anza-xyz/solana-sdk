#[cfg(not(target_os = "solana"))]
use {
    crate::signature::{
        bytes::{
            Signature, SignatureCompressed, BLS_SIGNATURE_AFFINE_SIZE,
            BLS_SIGNATURE_COMPRESSED_SIZE,
        },
        points::{AsSignatureAffine, AsSignatureProjective, SignatureAffine, SignatureProjective},
    },
    blstrs::{G2Affine, G2Projective},
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    SignatureProjective,
    SignatureAffine,
    Signature,
    SignatureCompressed,
    G2Affine,
    G2Projective,
    AsSignatureProjective,
    AsSignatureAffine,
    BLS_SIGNATURE_COMPRESSED_SIZE,
    BLS_SIGNATURE_AFFINE_SIZE
);
