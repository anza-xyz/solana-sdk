#[cfg(not(target_os = "solana"))]
use {
    crate::pubkey::{
        bytes::{
            Pubkey, PubkeyCompressed, BLS_PUBLIC_KEY_AFFINE_SIZE, BLS_PUBLIC_KEY_COMPRESSED_SIZE,
        },
        points::{AsPubkeyAffine, AsPubkeyProjective, PubkeyAffine, PubkeyProjective},
    },
    blstrs::{G1Affine, G1Projective},
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    PubkeyProjective,
    PubkeyAffine,
    Pubkey,
    PubkeyCompressed,
    G1Affine,
    G1Projective,
    AsPubkeyProjective,
    AsPubkeyAffine,
    BLS_PUBLIC_KEY_COMPRESSED_SIZE,
    BLS_PUBLIC_KEY_AFFINE_SIZE
);
