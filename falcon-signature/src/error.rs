#[cfg(feature = "std")]
use crate::constants::{
    MAX_SIGNATURE_SIZE, MIN_SIGNATURE_SIZE, PUBKEY_HEADER, PUBKEY_SIZE, SIGNATURE_HEADER,
};

/// Errors that can occur during Falcon-512 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum FalconError {
    /// Public key has invalid size.
    #[cfg_attr(
        feature = "std",
        error("invalid public key size: expected {PUBKEY_SIZE}, got {0}")
    )]
    InvalidPublicKeySize(usize),

    /// Public key has invalid header byte.
    #[cfg_attr(
        feature = "std",
        error("invalid public key header: expected {PUBKEY_HEADER:#04x}, got {0:#04x}")
    )]
    InvalidPublicKeyHeader(u8),

    /// Signature has invalid size.
    #[cfg_attr(
        feature = "std",
        error(
            "invalid signature size: expected {MIN_SIGNATURE_SIZE}..={MAX_SIGNATURE_SIZE}, got {0}"
        )
    )]
    InvalidSignatureSize(usize),

    /// Signature has invalid header byte.
    #[cfg_attr(
        feature = "std",
        error("invalid signature header: expected {SIGNATURE_HEADER:#04x}, got {0:#04x}")
    )]
    InvalidSignatureHeader(u8),

    /// Signature verification failed.
    #[cfg_attr(feature = "std", error("signature verification failed"))]
    VerificationFailed,

    /// Key generation failed.
    #[cfg_attr(feature = "std", error("key generation failed: {0}"))]
    KeyGenerationFailed(&'static str),

    /// Signing operation failed.
    #[cfg_attr(feature = "std", error("signing failed: {0}"))]
    SigningFailed(&'static str),
}
