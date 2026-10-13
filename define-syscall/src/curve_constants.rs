//! Constants and identifiers for Solana elliptic curve sycalls.
//!
//! This module defines the unique identifiers for supported elliptic curves,
//! encoding formats, and algebraic group operations. These constants are used
//! to dispatch syscalls such as `sol_curve_group_op` and `sol_curve_pairing_map`.

/// Curve ID for Curve25519 Edwards representation (compressed).
pub const CURVE25519_EDWARDS: u64 = 0;

/// Curve ID for Curve25519 Ristretto representation (compressed).
pub const CURVE25519_RISTRETTO: u64 = 1;

// Indices 2 and 3 are reserved.
// These slots are set aside for potential future support of affine
// representations of Curve25519 points.
//
// Reserved constants for reference:
// pub const CURVE25519_EDWARDS_AFFINE_LE: u64 = 2;
// pub const CURVE25519_EDWARDS_AFFINE_BE: u64 = 2 | 0x80;
// pub const CURVE25519_RISTRETTO_AFFINE_LE: u64 = 3;
// pub const CURVE25519_RISTRETTO_AFFINE_BE: u64 = 3 | 0x80;

/// Curve ID for BLS12-381 pairing operations
pub const BLS12_381_LE: u64 = 4;
pub const BLS12_381_BE: u64 = 4 | 0x80;

/// Curve ID for BLS12-381 G1 group operations
pub const BLS12_381_G1_LE: u64 = 5;
pub const BLS12_381_G1_BE: u64 = 5 | 0x80;

/// Curve ID for BLS12-381 G2 group operations
pub const BLS12_381_G2_LE: u64 = 6;
pub const BLS12_381_G2_BE: u64 = 6 | 0x80;

/// Curve ID for the SECP256R1 curve
pub const SECP256R1_LE: u64 = 7;
pub const SECP256R1_BE: u64 = 7 | 0x80;

/// Group operation identifier for Addition (P1 + P2).
pub const GROUP_OP_ADD: u64 = 0;
/// Group operation identifier for Subtraction (P1 - P2).
pub const GROUP_OP_SUB: u64 = 1;
/// Group operation identifier for Scalar Multiplication (S * P).
pub const GROUP_OP_MUL: u64 = 2;
