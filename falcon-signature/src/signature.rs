use crate::{
    constants::{MAX_SIGNATURE_SIZE, MIN_SIGNATURE_SIZE, SIGNATURE_HEADER},
    error::FalconError,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A Falcon-512 signature.
///
/// Signatures are variable length (41-666 bytes), with the first byte being
/// the header (0x39).
///
/// # Example
///
/// ```
/// use solana_falcon_signature::{
///     Signature, MIN_SIGNATURE_SIZE, MAX_SIGNATURE_SIZE, SIGNATURE_HEADER, FalconError
/// };
///
/// // Create a signature with valid header and size
/// let bytes = vec![SIGNATURE_HEADER; 100];
/// let sig = Signature::new(bytes).expect("valid signature");
/// assert!(sig.len() >= MIN_SIGNATURE_SIZE && sig.len() <= MAX_SIGNATURE_SIZE);
///
/// // Too small signature is rejected
/// let small = vec![SIGNATURE_HEADER; 10];
/// assert!(matches!(Signature::new(small), Err(FalconError::InvalidSignatureSize(10))));
///
/// // Invalid header is rejected
/// let bad_header = vec![0xFF; 100];
/// assert!(matches!(Signature::new(bad_header), Err(FalconError::InvalidSignatureHeader(0xFF))));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Creates a new signature from raw bytes.
    ///
    /// Returns an error if the size is out of range or the header byte is invalid.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FalconError> {
        let len = bytes.len();
        if !(MIN_SIGNATURE_SIZE..=MAX_SIGNATURE_SIZE).contains(&len) {
            return Err(FalconError::InvalidSignatureSize(len));
        }
        if bytes[0] != SIGNATURE_HEADER {
            return Err(FalconError::InvalidSignatureHeader(bytes[0]));
        }
        Ok(Self(bytes))
    }

    /// Creates a signature from a slice.
    ///
    /// Returns an error if the size is out of range or the header byte is invalid.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FalconError> {
        let len = bytes.len();
        if !(MIN_SIGNATURE_SIZE..=MAX_SIGNATURE_SIZE).contains(&len) {
            return Err(FalconError::InvalidSignatureSize(len));
        }
        if bytes[0] != SIGNATURE_HEADER {
            return Err(FalconError::InvalidSignatureHeader(bytes[0]));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the signature as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the signature in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
