//! Functions for generating keypairs from seed phrases.
#![cfg_attr(docsrs, feature(doc_cfg))]
use hmac::Hmac;

/// Derives a 64-byte seed from the raw UTF-8 mnemonic and passphrase.
///
/// This function does not apply BIP-39's Unicode NFKD normalization. When both
/// inputs are already in NFKD form, such as an English mnemonic with an ASCII
/// passphrase, the seed matches BIP-39. Normalizing non-NFKD inputs can change
/// the seed, so preserve the original input bytes when recovering existing keys.
pub fn generate_seed_from_seed_phrase_and_passphrase(
    seed_phrase: &str,
    passphrase: &str,
) -> Vec<u8> {
    const PBKDF2_ROUNDS: u32 = 2048;
    const PBKDF2_BYTES: usize = 64;

    let salt = format!("mnemonic{passphrase}");

    let mut seed = vec![0u8; PBKDF2_BYTES];
    pbkdf2::pbkdf2::<Hmac<sha2::Sha512>>(
        seed_phrase.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ROUNDS,
        &mut seed,
    );
    seed
}
