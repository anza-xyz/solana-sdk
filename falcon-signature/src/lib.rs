//! Falcon-512 post-quantum signature support for Solana SDK.
//!
//! This crate provides Falcon-512 signature operations using the `oqs` crate
//! (liboqs Rust bindings) as the cryptographic backend. Falcon-512 is a
//! lattice-based post-quantum signature scheme selected by NIST for
//! standardization (FIPS 206).
//!
//! # Overview
//!
//! Falcon-512 coexists alongside Ed25519 as an additional signature option,
//! providing post-quantum security for Solana transactions. The implementation
//! follows the SIMD-0152 precompile instruction format.
//!
//! # Key Features
//!
//! - **Post-quantum security**: Resistant to attacks from quantum computers
//! - **Variable-length signatures**: upto 666 bytes (compressed format)
//! - **897-byte public keys**: Includes FIPS 206 header byte (0x09)
//! - **SIMD-0152 compliant**: Instruction format matches other precompiles
//!
//! # Example: Signing and Verification
//!
//! ```ignore
//! use solana_falcon_signature::{SecretKey, PublicKey, Signature};
//!
//! // Generate a new keypair
//! let secret_key = SecretKey::generate().expect("key generation failed");
//! let public_key = secret_key.public_key();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = secret_key.sign(message).expect("signing failed");
//!
//! // Verify the signature
//! public_key.verify(message, &signature).expect("verification failed");
//! ```
//!
//! # Example: Creating a Verification Instruction
//!
//! ```
//! use solana_falcon_signature::{
//!     Falcon512SignatureOffsets, offsets_to_falcon512_instruction,
//!     SIGNATURE_OFFSETS_SIZE, SIGNATURE_OFFSETS_START,
//! };
//!
//! // Create offsets for verification data in the current instruction
//! let offsets = Falcon512SignatureOffsets {
//!     signature_offset: 18,
//!     signature_length: 650,
//!     signature_instruction_index: u16::MAX, // current instruction
//!     public_key_offset: 668,
//!     public_key_instruction_index: u16::MAX,
//!     message_offset: 1565,
//!     message_length: 100,
//!     message_instruction_index: u16::MAX,
//! };
//!
//! // Create the verification instruction
//! let instruction = offsets_to_falcon512_instruction(&[offsets]);
//! assert_eq!(instruction.data[0], 1); // num_signatures
//! ```
//!
//! # Constants
//!
//! All size and header constants are provisional per draft FIPS 206 and may
//! change when the final standard is published:
//!
//! - [`PUBKEY_SIZE`]: 897 bytes (includes 1-byte header)
//! - [`PUBKEY_HEADER`][]: 0x09 (identifies Falcon-512 public keys)
//! - [`MIN_SIGNATURE_SIZE`]: 41 bytes minimum
//! - [`MAX_SIGNATURE_SIZE`]: 666 bytes maximum
//! - [`SIGNATURE_HEADER`][]: 0x39 (identifies Falcon-512 signatures)
//!
//! # Platform Support
//!
//! Cryptographic operations ([`SecretKey`], [`PublicKey::verify`]) are only
//! available on non-Solana targets (`cfg(not(target_os = "solana"))`).
//! Data types ([`PublicKey`], [`Signature`], [`Falcon512SignatureOffsets`])
//! are available on all platforms.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod constants;
mod error;
mod instruction;
mod offsets;
mod public_key;
#[cfg(not(target_os = "solana"))]
mod secret_key;
mod signature;

#[cfg(test)]
mod tests;

#[cfg(not(target_os = "solana"))]
pub use secret_key::SecretKey;
pub use {
    constants::{
        DATA_START, MAX_SIGNATURE_SIZE, MIN_SIGNATURE_SIZE, PUBKEY_HEADER, PUBKEY_SIZE,
        SIGNATURE_HEADER, SIGNATURE_OFFSETS_SIZE, SIGNATURE_OFFSETS_START,
    },
    error::FalconError,
    instruction::{new_falcon512_instruction_with_signature, offsets_to_falcon512_instruction},
    offsets::Falcon512SignatureOffsets,
    public_key::PublicKey,
    signature::Signature,
};
