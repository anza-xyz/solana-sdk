#[cfg(not(target_os = "solana"))]
use {
    crate::proof_of_possession::{
        bytes::{
            ProofOfPossession, ProofOfPossessionCompressed, BLS_PROOF_OF_POSSESSION_AFFINE_SIZE,
            BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
        },
        points::{
            AsProofOfPossessionAffine, AsProofOfPossessionProjective, ProofOfPossessionAffine,
            ProofOfPossessionProjective,
        },
    },
    blstrs::{G2Affine, G2Projective},
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    ProofOfPossessionProjective,
    ProofOfPossessionAffine,
    ProofOfPossession,
    ProofOfPossessionCompressed,
    G2Affine,
    G2Projective,
    AsProofOfPossessionProjective,
    AsProofOfPossessionAffine,
    BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
    BLS_PROOF_OF_POSSESSION_AFFINE_SIZE
);
