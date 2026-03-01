use crate::{error::FalconError, public_key::PublicKey, signature::Signature};

/// A Falcon-512 secret key.
///
/// This type is only available on non-Solana targets as cryptographic
/// operations require the liboqs library.
pub struct SecretKey {
    inner: oqs::sig::SecretKey,
    public_key: PublicKey,
}

impl SecretKey {
    /// Generates a new random keypair.
    pub fn generate() -> Result<Self, FalconError> {
        use oqs::sig::{Algorithm, Sig};

        let sig = Sig::new(Algorithm::Falcon512)
            .map_err(|_| FalconError::KeyGenerationFailed("failed to initialize Falcon512"))?;

        let (pk, sk) = sig
            .keypair()
            .map_err(|_| FalconError::KeyGenerationFailed("keypair generation failed"))?;

        let pk_bytes = pk.as_ref();
        let public_key = PublicKey::from_slice(pk_bytes)?;

        Ok(Self {
            inner: sk,
            public_key,
        })
    }

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Signs a message with this secret key.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, FalconError> {
        use oqs::sig::{Algorithm, Sig};

        let sig = Sig::new(Algorithm::Falcon512)
            .map_err(|_| FalconError::SigningFailed("failed to initialize Falcon512"))?;

        let oqs_sig = sig
            .sign(message, &self.inner)
            .map_err(|_| FalconError::SigningFailed("signing operation failed"))?;

        Signature::new(oqs_sig.as_ref().to_vec())
    }
}
