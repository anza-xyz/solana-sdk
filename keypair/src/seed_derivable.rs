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

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut bytes = [0u8; N];
        for (byte, chunk) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let high = hex_value(chunk[0]);
            let low = hex_value(chunk[1]);
            *byte = (high << 4) | low;
        }
        bytes
    }

    fn hex_value(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex byte"),
        }
    }

    #[test]
    fn test_bip32_derivation_vector() {
        let seed = hex_to_bytes::<16>("000102030405060708090a0b0c0d0e0f");
        let path = DerivationPath::from_absolute_path_str("m/0'/1'/2'/2'/1000000000'")
            .expect("valid derivation path");
        let keypair = keypair_from_seed_and_derivation_path(&seed, Some(path)).unwrap();
        let keypair_bytes = keypair.to_bytes();

        assert_eq!(
            &keypair_bytes[..Keypair::SECRET_KEY_LENGTH],
            hex_to_bytes::<32>("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793")
        );
        assert_eq!(
            &keypair_bytes[Keypair::SECRET_KEY_LENGTH..],
            hex_to_bytes::<32>("3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a")
        );
    }
}
