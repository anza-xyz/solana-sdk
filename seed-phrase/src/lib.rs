//! Functions for generating keypairs from seed phrases.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {hmac::Hmac, unicode_normalization::UnicodeNormalization};

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

/// Derives a 64-byte BIP-39 seed without validating the mnemonic.
///
/// Both inputs are normalized using Unicode NFKD, as required by BIP-39.
/// This can produce a different seed from the legacy
/// [`generate_seed_from_seed_phrase_and_passphrase`] for non-NFKD inputs.
///
/// After normalization, mnemonic words must be separated by single spaces, with
/// no leading or trailing whitespace, to match other BIP-39 implementations.
/// This function does not trim or collapse whitespace; extra whitespace changes
/// the seed.
pub fn generate_seed_from_bip39_mnemonic(seed_phrase: &str, passphrase: &str) -> Vec<u8> {
    let seed_phrase = seed_phrase.nfkd().collect::<String>();
    let passphrase = passphrase.nfkd().collect::<String>();
    generate_seed_from_seed_phrase_and_passphrase(&seed_phrase, &passphrase)
}
