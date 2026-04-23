use {
    crate::{
        error::BlsError,
        hash::{hash_message_to_projective, hash_pop_to_projective},
        proof_of_possession::ProofOfPossessionProjective,
        pubkey::PubkeyProjective,
        signature::SignatureProjective,
    },
    blst::{blst_keygen, blst_scalar},
    blstrs::Scalar,
    core::{ptr, sync::atomic},
    ff::Field,
    rand::rngs::OsRng,
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
};
#[cfg(feature = "solana-signer-derive")]
use {
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
    subtle::ConstantTimeEq,
};

/// Size of BLS secret key in bytes
pub const BLS_SECRET_KEY_SIZE: usize = 32;

/// A BLS secret key
#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey(pub(crate) Scalar);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey(<hidden>)")
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(&mut self.0, Scalar::ZERO);
        }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Parses a canonical, non-zero secret scalar from little-endian bytes.
    fn parse_scalar(bytes: &Zeroizing<[u8; BLS_SECRET_KEY_SIZE]>) -> Result<Scalar, BlsError> {
        let scalar: Option<Scalar> = Scalar::from_bytes_le(bytes).into();
        let scalar = scalar.ok_or(BlsError::FieldDecode)?;
        if bool::from(scalar.is_zero()) {
            return Err(BlsError::FieldDecode);
        }
        Ok(scalar)
    }

    /// Constructs a new, random `BlsSecretKey` using `OsRng`
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self(Scalar::random(&mut rng))
    }

    /// Derive a `BlsSecretKey` from a seed (input key material)
    pub fn derive(ikm: &[u8]) -> Result<Self, BlsError> {
        if ikm.len() < 32 {
            return Err(BlsError::KeyDerivation);
        }
        let mut scalar = Zeroizing::new(blst_scalar::default());
        unsafe {
            blst_keygen(
                &mut *scalar as *mut blst_scalar,
                ikm.as_ptr(),
                ikm.len(),
                ptr::null(),
                0,
            );
        }
        let bytes = Zeroizing::new(scalar.b);
        Self::parse_scalar(&bytes).map(Self)
    }

    /// Derive a `BlsSecretKey` from a Solana signer
    #[cfg(feature = "solana-signer-derive")]
    pub fn derive_from_signer(signer: &dyn Signer, public_seed: &[u8]) -> Result<Self, BlsError> {
        let message = [b"bls-key-derive-", public_seed].concat();
        let signature = Zeroizing::new(<[u8; SIGNATURE_BYTES]>::from(
            signer
                .try_sign_message(&message)
                .map_err(|_| BlsError::KeyDerivation)?,
        ));

        // Some `Signer` implementations return the default signature, which is not suitable for
        // use as key material
        if bool::from(signature.as_slice().ct_eq(Signature::default().as_ref())) {
            return Err(BlsError::KeyDerivation);
        }

        Self::derive(signature.as_slice())
    }

    /// Generate a proof of possession for the corresponding pubkey
    #[allow(clippy::arithmetic_side_effects)]
    #[allow(clippy::op_ref)]
    pub fn proof_of_possession(&self, payload: Option<&[u8]>) -> ProofOfPossessionProjective {
        let hashed_point = if let Some(bytes) = payload {
            hash_pop_to_projective(bytes)
        } else {
            let pubkey = PubkeyProjective::from_secret(self);
            let pubkey_bytes = pubkey.to_bytes_compressed();
            hash_pop_to_projective(&pubkey_bytes)
        };
        ProofOfPossessionProjective(hashed_point * &self.0)
    }

    /// Sign a message using the provided secret key
    #[allow(clippy::arithmetic_side_effects)]
    #[allow(clippy::op_ref)]
    pub fn sign(&self, message: &[u8]) -> SignatureProjective {
        let hashed_message = hash_message_to_projective(message);
        SignatureProjective(hashed_message * &self.0)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_SECRET_KEY_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        let bytes = Zeroizing::new(<[u8; BLS_SECRET_KEY_SIZE]>::try_from(bytes).unwrap());
        Self::parse_scalar(&bytes).map(Self)
    }
}

impl From<&SecretKey> for [u8; BLS_SECRET_KEY_SIZE] {
    fn from(secret_key: &SecretKey) -> Self {
        // WARNING: The returned buffer contains raw secret-key bytes. Callers should zeroize it
        // as soon as they are done using it.
        secret_key.0.to_bytes_le()
    }
}

impl From<&SecretKey> for Zeroizing<[u8; BLS_SECRET_KEY_SIZE]> {
    fn from(secret_key: &SecretKey) -> Self {
        Zeroizing::new(secret_key.0.to_bytes_le())
    }
}
