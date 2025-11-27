#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        proof_of_possession::{
            bytes::{AsProofOfPossession, ProofOfPossession, ProofOfPossessionCompressed},
            points::{AsProofOfPossessionProjective, ProofOfPossessionProjective},
        },
    },
    blstrs::G2Affine,
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    ProofOfPossessionProjective,
    ProofOfPossession,
    ProofOfPossessionCompressed,
    G2Affine,
    AsProofOfPossessionProjective,
    AsProofOfPossession
);
