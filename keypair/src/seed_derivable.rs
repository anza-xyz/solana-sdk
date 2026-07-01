//! Implementation of the SeedDerivable trait for Keypair

use {
    crate::{keypair_from_seed, keypair_from_seed_phrase_and_passphrase, Keypair},
    hmac::{Hmac, Mac},
    sha2::Sha512,
    solana_derivation_path::DerivationPath,
    solana_seed_derivable::SeedDerivable,
    std::error,
};

const ED25519_BIP32_NAME: &[u8] = b"ed25519 seed";
type HmacSha512 = Hmac<Sha512>;

fn new_hmac_sha512(key: &[u8]) -> Result<HmacSha512, Box<dyn error::Error>> {
    HmacSha512::new_from_slice(key).map_err(|err| err.to_string().into())
}

impl SeedDerivable for Keypair {
    fn from_seed(seed: &[u8]) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed(seed)
    }

    fn from_seed_and_derivation_path(
        seed: &[u8],
        derivation_path: Option<DerivationPath>,
    ) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed_and_derivation_path(seed, derivation_path)
    }

    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed_phrase_and_passphrase(seed_phrase, passphrase)
    }
}

/// Generates a Keypair using Bip32 Hierarchical Derivation if derivation-path is provided;
/// otherwise generates the base Bip44 Solana keypair from the seed
pub fn keypair_from_seed_and_derivation_path(
    seed: &[u8],
    derivation_path: Option<DerivationPath>,
) -> Result<Keypair, Box<dyn error::Error>> {
    let derivation_path = derivation_path.unwrap_or_default();
    bip32_derived_keypair(seed, derivation_path)
}

/// Generates a Keypair using Bip32 Hierarchical Derivation
fn bip32_derived_keypair(
    seed: &[u8],
    derivation_path: DerivationPath,
) -> Result<Keypair, Box<dyn error::Error>> {
    let mut mac = new_hmac_sha512(ED25519_BIP32_NAME)?;
    mac.update(seed);
    let bytes = mac.finalize().into_bytes();

    let mut secret_key = [0u8; Keypair::SECRET_KEY_LENGTH];
    secret_key.copy_from_slice(&bytes[..Keypair::SECRET_KEY_LENGTH]);

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&bytes[Keypair::SECRET_KEY_LENGTH..]);

    for index in derivation_path.as_ref() {
        if index.is_normal() {
            return Err(format!("expected hardened child index: {index}").into());
        }

        let mut mac = new_hmac_sha512(&chain_code)?;
        mac.update(&[0u8]);
        mac.update(&secret_key);
        mac.update(&index.to_bits().to_be_bytes());
        let bytes = mac.finalize().into_bytes();

        secret_key.copy_from_slice(&bytes[..Keypair::SECRET_KEY_LENGTH]);
        chain_code.copy_from_slice(&bytes[Keypair::SECRET_KEY_LENGTH..]);
    }

    Ok(Keypair::new_from_array(secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_derivation_vector() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::from_absolute_path_str("m/0'/1'/2'/2'/1000000000'")
            .expect("valid derivation path");
        let keypair = keypair_from_seed_and_derivation_path(&seed, Some(path)).unwrap();
        let keypair_bytes = keypair.to_bytes();
        let expected_secret_key = [
            0x8f, 0x94, 0xd3, 0x94, 0xa8, 0xe8, 0xfd, 0x6b, 0x1b, 0xc2, 0xf3, 0xf4, 0x9f, 0x5c,
            0x47, 0xe3, 0x85, 0x28, 0x1d, 0x5c, 0x17, 0xe6, 0x53, 0x24, 0xb0, 0xf6, 0x24, 0x83,
            0xe3, 0x7e, 0x87, 0x93,
        ];
        let expected_public_key = [
            0x3c, 0x24, 0xda, 0x04, 0x94, 0x51, 0x55, 0x5d, 0x51, 0xa7, 0x01, 0x4a, 0x37, 0x33,
            0x7a, 0xa4, 0xe1, 0x2d, 0x41, 0xe4, 0x85, 0xab, 0xcc, 0xfa, 0x46, 0xb4, 0x7d, 0xfb,
            0x2a, 0xf5, 0x4b, 0x7a,
        ];

        assert_eq!(
            &keypair_bytes[..Keypair::SECRET_KEY_LENGTH],
            expected_secret_key.as_slice()
        );
        assert_eq!(
            &keypair_bytes[Keypair::SECRET_KEY_LENGTH..],
            expected_public_key.as_slice()
        );
    }
}
