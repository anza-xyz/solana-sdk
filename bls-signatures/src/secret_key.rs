use {
    crate::{
        error::BlsError,
        hash::{hash_message_to_point, hash_pubkey_to_g2},
        proof_of_possession::ProofOfPossessionProjective,
        pubkey::PubkeyProjective,
        signature::SignatureProjective,
    },
    blst::{blst_keygen, blst_scalar},
    blstrs::Scalar,
    core::ptr,
    ff::Field,
    rand::rngs::OsRng,
};
#[cfg(feature = "solana-signer-derive")]
use {solana_signature::Signature, solana_signer::Signer, subtle::ConstantTimeEq};

/// Size of BLS secret key in bytes
pub const BLS_SECRET_KEY_SIZE: usize = 32;

/// A BLS secret key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey(pub(crate) Scalar);

impl SecretKey {
    /// Constructs a new, random `BlsSecretKey` using `OsRng`
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self(Scalar::random(&mut rng))
    }

    /// Derive a `BlsSecretKey` from a seed (input key material)
    pub fn derive(ikm: &[u8]) -> Result<Self, BlsError> {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_keygen(
                &mut scalar as *mut blst_scalar,
                ikm.as_ptr(),
                ikm.len(),
                ptr::null(),
                0,
            );
        }
        scalar
            .try_into()
            .map(Self)
            .map_err(|_| BlsError::FieldDecode)
    }

    /// Derive a `BlsSecretKey` from a Solana signer
    #[cfg(feature = "solana-signer-derive")]
    pub fn derive_from_signer(signer: &dyn Signer, public_seed: &[u8]) -> Result<Self, BlsError> {
        let message = [b"bls-key-derive-", public_seed].concat();
        let signature = signer
            .try_sign_message(&message)
            .map_err(|_| BlsError::KeyDerivation)?;

        // Some `Signer` implementations return the default signature, which is not suitable for
        // use as key material
        if bool::from(signature.as_ref().ct_eq(Signature::default().as_ref())) {
            return Err(BlsError::KeyDerivation);
        }

        Self::derive(signature.as_ref())
    }

    /// Generate a proof of possession for the corresponding pubkey
    #[allow(clippy::arithmetic_side_effects)]
    pub fn proof_of_possession(&self) -> ProofOfPossessionProjective {
        let pubkey = PubkeyProjective::from_secret(self);
        let hashed_pubkey_bytes = hash_pubkey_to_g2(&pubkey);
        ProofOfPossessionProjective(hashed_pubkey_bytes * self.0)
    }

    /// Sign a message using the provided secret key
    #[allow(clippy::arithmetic_side_effects)]
    pub fn sign(&self, message: &[u8]) -> SignatureProjective {
        let hashed_message = hash_message_to_point(message);
        SignatureProjective(hashed_message * self.0)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_SECRET_KEY_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        // unwrap safe due to the length check above
        let scalar: Option<Scalar> = Scalar::from_bytes_le(bytes.try_into().unwrap()).into();
        scalar.ok_or(BlsError::FieldDecode).map(Self)
    }
}

impl From<&SecretKey> for [u8; BLS_SECRET_KEY_SIZE] {
    fn from(secret_key: &SecretKey) -> Self {
        secret_key.0.to_bytes_le()
    }
}
