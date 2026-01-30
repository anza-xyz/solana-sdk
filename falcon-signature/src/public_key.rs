use crate::{
    constants::{PUBKEY_HEADER, PUBKEY_SIZE},
    error::FalconError,
    signature::Signature,
};

/// A Falcon-512 public key.
///
/// The public key is 897 bytes, with the first byte being the header (0x09).
///
/// # Example
///
/// ```
/// use solana_falcon_signature::{PublicKey, PUBKEY_SIZE, PUBKEY_HEADER, FalconError};
///
/// let mut bytes = [0u8; PUBKEY_SIZE];
/// bytes[0] = PUBKEY_HEADER;
/// let pk = PublicKey::new(bytes).expect("valid public key");
/// assert_eq!(pk.as_bytes()[0], PUBKEY_HEADER);
///
/// let mut bad = bytes;
/// bad[0] = 0xFF;
/// assert!(matches!(PublicKey::new(bad), Err(FalconError::InvalidPublicKeyHeader(0xFF))));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; PUBKEY_SIZE]);

impl PublicKey {
    /// Creates a new public key from a fixed-size array.
    ///
    /// Returns an error if the header byte is invalid.
    pub fn new(bytes: [u8; PUBKEY_SIZE]) -> Result<Self, FalconError> {
        if bytes[0] != PUBKEY_HEADER {
            return Err(FalconError::InvalidPublicKeyHeader(bytes[0]));
        }
        Ok(Self(bytes))
    }

    /// Creates a public key from a slice.
    ///
    /// Returns an error if the size is incorrect or the header byte is invalid.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != PUBKEY_SIZE {
            return Err(FalconError::InvalidPublicKeySize(bytes.len()));
        }
        if bytes[0] != PUBKEY_HEADER {
            return Err(FalconError::InvalidPublicKeyHeader(bytes[0]));
        }
        let mut arr = [0u8; PUBKEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Returns the public key as a byte slice.
    pub fn as_bytes(&self) -> &[u8; PUBKEY_SIZE] {
        &self.0
    }

    /// Verifies a signature over a message.
    #[cfg(not(target_os = "solana"))]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), FalconError> {
        use oqs::sig::{Algorithm, Sig};

        let sig = Sig::new(Algorithm::Falcon512).map_err(|_| FalconError::VerificationFailed)?;

        let oqs_pk = sig
            .public_key_from_bytes(&self.0)
            .ok_or(FalconError::VerificationFailed)?;

        let oqs_sig = sig
            .signature_from_bytes(signature.as_bytes())
            .ok_or(FalconError::VerificationFailed)?;

        sig.verify(message, oqs_sig, oqs_pk)
            .map_err(|_| FalconError::VerificationFailed)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
