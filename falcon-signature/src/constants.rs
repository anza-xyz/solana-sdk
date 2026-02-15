// =============================================================================
// Provisional Constants (per draft FIPS 206 / SIMD proposal)
// Update these when final standards are published
// =============================================================================

/// Size of a Falcon-512 public key in bytes (includes 1-byte header).
pub const PUBKEY_SIZE: usize = 897;

/// Header byte for Falcon-512 public keys (0x00 + logn where logn=9).
pub const PUBKEY_HEADER: u8 = 0x09;

/// Minimum size of a Falcon-512 signature in bytes (includes 1-byte header).
pub const MIN_SIGNATURE_SIZE: usize = 41;

/// Maximum size of a Falcon-512 signature in bytes (includes 1-byte header).
pub const MAX_SIGNATURE_SIZE: usize = 666;

/// Header byte for Falcon-512 signatures (0x30 + logn where logn=9).
pub const SIGNATURE_HEADER: u8 = 0x39;

/// Size of the signature offsets structure in bytes.
pub const SIGNATURE_OFFSETS_SIZE: usize = 16;

/// Start offset for signature offsets in instruction data.
pub const SIGNATURE_OFFSETS_START: usize = 2;

/// Start offset for variable data in instruction data.
pub const DATA_START: usize = SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SIZE;
