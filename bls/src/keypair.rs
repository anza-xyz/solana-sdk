#[cfg(feature = "std")]
use std::{
    boxed::Box,
    error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    string::String,
    vec::Vec,
};
use {
    crate::{
        error::BlsError,
        pod::{Pubkey, BLS_PUBLIC_KEY_AFFINE_SIZE},
        proof_of_possession::ProofOfPossessionProjective,
        signature::SignatureProjective,
        Bls,
    },
    blst::{blst_keygen, blst_scalar},
    blstrs::{G1Affine, G1Projective, Scalar},
    core::ptr,
    ff::Field,
    group::Group,
    rand::rngs::OsRng,
};
#[cfg(feature = "solana-signer-derive")]
use {solana_signature::Signature, solana_signer::Signer, subtle::ConstantTimeEq};

/// Size of BLS secret key in bytes
pub const BLS_SECRET_KEY_SIZE: usize = 32;

/// Size of BLS keypair in bytes
pub const BLS_KEYPAIR_SIZE: usize = BLS_SECRET_KEY_SIZE + BLS_PUBLIC_KEY_AFFINE_SIZE;

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
    pub fn proof_of_possession(&self) -> ProofOfPossessionProjective {
        let pubkey = PubkeyProjective::from_secret(self);
        Bls::generate_proof_of_possession(self, &pubkey)
    }

    /// Sign a message using the provided secret key
    pub fn sign(&self, message: &[u8]) -> SignatureProjective {
        Bls::sign(self, message)
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

/// A BLS public key in a projective point representation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeyProjective(pub(crate) G1Projective);

impl Default for PubkeyProjective {
    fn default() -> Self {
        Self(G1Projective::identity())
    }
}

impl PubkeyProjective {
    /// Construct a corresponding `BlsPubkey` for a `BlsSecretKey`
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_secret(secret: &SecretKey) -> Self {
        Self(G1Projective::generator() * secret.0)
    }

    /// Verify a signature against a message and a public key
    pub fn verify(&self, signature: &SignatureProjective, message: &[u8]) -> bool {
        Bls::verify(self, signature, message)
    }

    /// Verify a proof of possession against a public key
    pub fn verify_proof_of_possession(&self, proof: &ProofOfPossessionProjective) -> bool {
        Bls::verify_proof_of_possession(self, proof)
    }

    /// Aggregate a list of public keys into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, I>(&mut self, pubkeys: I)
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
    {
        self.0 = pubkeys.into_iter().fold(self.0, |mut acc, pubkey| {
            acc += &pubkey.0;
            acc
        });
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, I>(pubkeys: I) -> Result<PubkeyProjective, BlsError>
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
    {
        let mut iter = pubkeys.into_iter();
        if let Some(acc) = iter.next() {
            let aggregate_point = iter.fold(acc.0, |mut acc, pubkey| {
                acc += &pubkey.0;
                acc
            });
            Ok(Self(aggregate_point))
        } else {
            Err(BlsError::EmptyAggregation)
        }
    }
}

impl From<PubkeyProjective> for Pubkey {
    fn from(proof: PubkeyProjective) -> Self {
        Self(proof.0.to_uncompressed())
    }
}

impl TryFrom<Pubkey> for PubkeyProjective {
    type Error = BlsError;

    fn try_from(proof: Pubkey) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

impl TryFrom<&Pubkey> for PubkeyProjective {
    type Error = BlsError;

    fn try_from(proof: &Pubkey) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G1Affine> = G1Affine::from_uncompressed(&proof.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}

impl TryFrom<&[u8]> for PubkeyProjective {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_PUBLIC_KEY_AFFINE_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        // unwrap safe due to the length check above
        let public_affine = Pubkey(bytes.try_into().unwrap());

        public_affine.try_into()
    }
}

impl From<&PubkeyProjective> for [u8; BLS_PUBLIC_KEY_AFFINE_SIZE] {
    fn from(pubkey: &PubkeyProjective) -> Self {
        let pubkey_affine: Pubkey = (*pubkey).into();
        pubkey_affine.0
    }
}

/// A BLS keypair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PubkeyProjective,
}

impl Keypair {
    /// Constructs a new, random `Keypair` using `OsRng`
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let secret = SecretKey::new();
        let public = PubkeyProjective::from_secret(&secret);
        Self { secret, public }
    }

    /// Derive a `Keypair` from a seed (input key material)
    pub fn derive(ikm: &[u8]) -> Result<Self, BlsError> {
        let secret = SecretKey::derive(ikm)?;
        let public = PubkeyProjective::from_secret(&secret);
        Ok(Self { secret, public })
    }

    /// Derive a `BlsSecretKey` from a Solana signer
    #[cfg(feature = "solana-signer-derive")]
    pub fn derive_from_signer(signer: &dyn Signer, public_seed: &[u8]) -> Result<Self, BlsError> {
        let secret = SecretKey::derive_from_signer(signer, public_seed)?;
        let public = PubkeyProjective::from_secret(&secret);
        Ok(Self { secret, public })
    }

    /// Generate a proof of possession for the given keypair
    pub fn proof_of_possession(&self) -> ProofOfPossessionProjective {
        Bls::generate_proof_of_possession(&self.secret, &self.public)
    }

    /// Sign a message using the provided secret key
    pub fn sign(&self, message: &[u8]) -> SignatureProjective {
        Bls::sign(&self.secret, message)
    }

    /// Verify a signature against a message and a public key
    pub fn verify(&self, signature: &SignatureProjective, message: &[u8]) -> bool {
        Bls::verify(&self.public, signature, message)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_KEYPAIR_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        Ok(Self {
            secret: SecretKey::try_from(&bytes[..BLS_SECRET_KEY_SIZE])?,
            public: PubkeyProjective::try_from(&bytes[BLS_SECRET_KEY_SIZE..])?,
        })
    }
}

impl From<&Keypair> for [u8; BLS_KEYPAIR_SIZE] {
    fn from(keypair: &Keypair) -> Self {
        let mut bytes = [0u8; BLS_KEYPAIR_SIZE];
        bytes[..BLS_SECRET_KEY_SIZE]
            .copy_from_slice(&Into::<[u8; BLS_SECRET_KEY_SIZE]>::into(&keypair.secret));
        bytes[BLS_SECRET_KEY_SIZE..].copy_from_slice(
            &Into::<[u8; BLS_PUBLIC_KEY_AFFINE_SIZE]>::into(&keypair.public),
        );
        bytes
    }
}

#[cfg(feature = "std")]
impl Keypair {
    pub fn read_json<R: Read>(reader: &mut R) -> Result<Self, Box<dyn error::Error>> {
        let bytes: Vec<u8> = serde_json::from_reader(reader)?;
        Self::try_from(bytes.as_slice())
            .ok()
            .ok_or_else(|| std::io::Error::other("Invalid BLS keypair").into())
    }

    pub fn read_json_file<F: AsRef<Path>>(path: F) -> Result<Self, Box<dyn error::Error>> {
        let mut file = File::open(path.as_ref())?;
        Self::read_json(&mut file)
    }

    pub fn write_json<W: Write>(&self, writer: &mut W) -> Result<String, Box<dyn error::Error>> {
        let json = serde_json::to_string(&Into::<[u8; BLS_KEYPAIR_SIZE]>::into(self).as_slice())?;
        writer.write_all(&json.clone().into_bytes())?;
        Ok(json)
    }

    pub fn write_json_file<F: AsRef<Path>>(
        &self,
        outfile: F,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let outfile = outfile.as_ref();

        if let Some(outdir) = outfile.parent() {
            fs::create_dir_all(outdir)?;
        }

        let mut f = {
            #[cfg(not(unix))]
            {
                OpenOptions::new()
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new().mode(0o600)
            }
        }
        .write(true)
        .truncate(true)
        .create(true)
        .open(outfile)?;

        self.write_json(&mut f)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, tempfile::NamedTempFile};

    #[test]
    fn test_keygen_derive() {
        let ikm = b"test_ikm";
        let secret = SecretKey::derive(ikm).unwrap();
        let public = PubkeyProjective::from_secret(&secret);
        let keypair = Keypair::derive(ikm).unwrap();
        assert_eq!(keypair.secret, secret);
        assert_eq!(keypair.public, public);
    }

    #[test]
    #[cfg(feature = "solana-signer-derive")]
    fn test_keygen_derive_from_signer() {
        let solana_keypair = solana_keypair::Keypair::new();
        let secret = SecretKey::derive_from_signer(&solana_keypair, b"alpenglow-vote").unwrap();
        let public = PubkeyProjective::from_secret(&secret);
        let keypair = Keypair::derive_from_signer(&solana_keypair, b"alpenglow-vote").unwrap();

        assert_eq!(keypair.secret, secret);
        assert_eq!(keypair.public, public);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_keypair_file() {
        let temp_keypair_file = NamedTempFile::new().unwrap();
        let original_keypair = Keypair::new();
        original_keypair
            .write_json_file(&temp_keypair_file)
            .unwrap();
        let read_keypair = Keypair::read_json_file(&temp_keypair_file).unwrap();
        assert_eq!(original_keypair, read_keypair);
    }
}
