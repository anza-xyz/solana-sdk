//! BLS12-381 elliptic curve operations for Solana programs, wrapping the
//! native syscalls defined in [SIMD-0388].
//!
//! [SIMD-0388]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0388-bls12-381-syscalls.md
//!
//! # Output buffer contract
//!
//! Every `_assign` method writes into a caller-supplied
//! [`MaybeUninit`](core::mem::MaybeUninit) buffer and reports success as a
//! `bool`:
//!
//! - On `true`, the buffer is fully initialized and may be `assume_init`ed.
//! - On `false`, treat it as uninitialized, even if it held a valid value
//!   going in. A failed operation may write part of the buffer before
//!   detecting the error, so it poisons its output.
//!
//! The `true` case is a soundness requirement: reading an uninitialized byte is
//! undefined behavior. SIMD-0388 does not state that a syscall fills the buffer
//! on success.
//!
//! Nothing constrains a *failing* syscall, hence the poisoning rule above
//! rather than a guarantee that the buffer is left untouched.
//!
//! # The all-zero encoding is not the identity
//!
//! The point types implement `bytemuck::Zeroable`, so `G1Point::zeroed()`
//! compiles. All-zero is not infinity, and is not a point at all, since
//! `(0, 0)` does not satisfy `y^2 = x^3 + 4`. [`G1Point::infinity`] is the
//! identity.
//!
//! [`G1Point::infinity`]: g1::G1Point::infinity
//!
//! # Aliasing
//!
//! SIMD-0388 does not specify whether the result pointer may alias an input
//! pointer. This crate is unaffected: `_assign` methods take `&self` alongside
//! `&mut MaybeUninit<Self>`, so an aliasing call cannot be expressed in safe
//! Rust.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Error type for the operations that distinguish their failure modes.
pub mod error;
/// Points and encodings in the G1 group.
pub mod g1;
/// Points and encodings in the G2 group.
pub mod g2;
/// Pairing operations and the target group.
pub mod pairing;
/// Scalar field elements.
pub mod scalar;

pub use {error::*, g1::*, g2::*, pairing::*, scalar::*};

/// Byte order of the base field (`Fq`) elements.
///
/// Picks between the `_LE` and `_BE` curve IDs in SIMD-0388.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    /// `Fq` byte-reversed relative to [`Endianness::Big`]; `Fq2` ordered `c0`
    /// then `c1`.
    Little,
    /// The canonical Zcash/IETF encoding. `Fq2` ordered `c1` then `c0`.
    Big,
}
