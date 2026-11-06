//! Functions for generating keypairs from seed phrases.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {hmac::Hmac, unicode_normalization::UnicodeNormalization};

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

/// Derives a 64-byte seed after Unicode NFKD normalization of both inputs.
///
/// This does not validate the mnemonic's words or checksum.
/// This can produce a different seed from the legacy
/// [`generate_seed_from_seed_phrase_and_passphrase`] for non-NFKD inputs.
///
/// After normalization, mnemonic words must be separated by single spaces, with
/// no leading or trailing whitespace, to match other BIP-39 implementations.
/// This function does not trim or collapse whitespace; extra whitespace changes
/// the seed.
pub fn generate_seed_with_unicode_normalization(seed_phrase: &str, passphrase: &str) -> Vec<u8> {
    let seed_phrase = seed_phrase.nfkd().collect::<String>();
    let passphrase = passphrase.nfkd().collect::<String>();
    generate_seed_from_seed_phrase_and_passphrase(&seed_phrase, &passphrase)
}
