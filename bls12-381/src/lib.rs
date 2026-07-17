#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod addition;
pub(crate) mod decompression;
pub(crate) mod msm;
pub(crate) mod multiplication;
pub(crate) mod pairing;
pub(crate) mod subtraction;
pub(crate) mod validation;

/// This module should be used by Solana programs or other downstream projects.
pub mod prelude {
    pub use crate::{
        addition::*, decompression::*, msm::*, multiplication::*, pairing::*, subtraction::*,
        validation::*, Bls12381Error,
    };
}

use thiserror::Error;

/// Curve IDs defined in SIMD-0388
pub const BLS12_381_LE: u64 = 4;
pub const BLS12_381_BE: u64 = 4 | 0x80;
pub const BLS12_381_G1_LE: u64 = 5;
pub const BLS12_381_G1_BE: u64 = 5 | 0x80;
pub const BLS12_381_G2_LE: u64 = 6;
pub const BLS12_381_G2_BE: u64 = 6 | 0x80;

/// Operations for `sol_curve_group_op`
pub const ADD: u64 = 0;
pub const SUB: u64 = 1;
pub const MUL: u64 = 2;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Bls12381Error {
    #[error("The input data is invalid")]
    InvalidInputData,
    #[error("Slice data is going out of input data bounds")]
    SliceOutOfBounds,
    #[error("Unexpected error")]
    UnexpectedError,
}

impl From<u64> for Bls12381Error {
    fn from(v: u64) -> Bls12381Error {
        match v {
            1 => Bls12381Error::InvalidInputData,
            2 => Bls12381Error::SliceOutOfBounds,
            _ => Bls12381Error::UnexpectedError,
        }
    }
}

impl From<Bls12381Error> for u64 {
    fn from(v: Bls12381Error) -> u64 {
        // Note: never return 0, as it risks being confused with syscall success
        match v {
            Bls12381Error::InvalidInputData => 1,
            Bls12381Error::SliceOutOfBounds => 2,
            Bls12381Error::UnexpectedError => 3,
        }
    }
}
