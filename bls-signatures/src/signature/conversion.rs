#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        signature::{
            bytes::{AsSignature, Signature, SignatureCompressed},
            points::{AsSignatureProjective, SignatureProjective},
        },
    },
    blstrs::G2Affine,
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    SignatureProjective,
    Signature,
    SignatureCompressed,
    G2Affine,
    AsSignatureProjective,
    AsSignature
);
