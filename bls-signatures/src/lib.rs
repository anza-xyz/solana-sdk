#![no_std]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

#[cfg(feature = "std")]
extern crate std;
#[cfg(not(target_os = "solana"))]
pub use crate::{
    error::BlsError,
    keypair::Keypair,
    proof_of_possession::ProofOfPossessionProjective,
    pubkey::PubkeyProjective,
    secret_key::{SecretKey, BLS_SECRET_KEY_SIZE},
    signature::SignatureProjective,
};
pub use crate::{
    proof_of_possession::{
        ProofOfPossession, ProofOfPossessionCompressed, BLS_PROOF_OF_POSSESSION_AFFINE_SIZE,
        BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
    },
    pubkey::{
        Pubkey, PubkeyCompressed, BLS_PUBLIC_KEY_AFFINE_SIZE, BLS_PUBLIC_KEY_COMPRESSED_SIZE,
    },
    signature::{
        Signature, SignatureCompressed, BLS_SIGNATURE_AFFINE_SIZE, BLS_SIGNATURE_COMPRESSED_SIZE,
    },
};

// TODO: add conversion between compressed and uncompressed representation of
// signatures, pubkeys, and proof of possessions

pub mod error;
#[cfg(not(target_os = "solana"))]
pub mod keypair;
#[macro_use]
pub(crate) mod macros;
#[cfg(not(target_os = "solana"))]
pub mod hash;
pub mod proof_of_possession;
pub mod pubkey;
#[cfg(not(target_os = "solana"))]
pub mod secret_key;
pub mod signature;
