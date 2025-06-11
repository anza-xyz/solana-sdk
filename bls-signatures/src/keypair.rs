use crate::{
    error::BlsError,
    proof_of_possession::ProofOfPossessionProjective,
    pubkey::{PubkeyProjective, BLS_PUBLIC_KEY_AFFINE_SIZE},
    secret_key::{SecretKey, BLS_SECRET_KEY_SIZE},
    signature::SignatureProjective,
};
#[cfg(feature = "solana-signer-derive")]
use solana_signer::Signer;
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

/// Size of BLS keypair in bytes
pub const BLS_KEYPAIR_SIZE: usize = BLS_SECRET_KEY_SIZE + BLS_PUBLIC_KEY_AFFINE_SIZE;

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
        self.secret.proof_of_possession()
    }

    /// Sign a message using the provided secret key
    pub fn sign(&self, message: &[u8]) -> SignatureProjective {
        self.secret.sign(message)
    }

    /// Verify a signature against a message and a public key
    pub fn verify(&self, signature: &SignatureProjective, message: &[u8]) -> bool {
        self.public.verify(signature, message)
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
