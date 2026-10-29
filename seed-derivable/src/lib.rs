//! The interface by which keys are derived.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {solana_derivation_path::DerivationPath, std::error};

/// The `SeedDerivable` trait defines the interface by which cryptographic keys/keypairs are
/// derived from byte seeds, derivation paths, and passphrases.
pub trait SeedDerivable: Sized {
    fn from_seed(seed: &[u8]) -> Result<Self, Box<dyn error::Error>>;
    fn from_seed_and_derivation_path(
        seed: &[u8],
        derivation_path: Option<DerivationPath>,
    ) -> Result<Self, Box<dyn error::Error>>;
    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>>;

    /// Derives a key from the BIP-39 seed of `seed_phrase` and `passphrase`,
    /// after NFKD-normalizing both inputs.
    ///
    /// This does not validate the mnemonic's words or checksum.
    /// After normalization, mnemonic words must be separated by single spaces,
    /// with no leading or trailing whitespace, to match other BIP-39
    /// implementations. Extra whitespace is preserved and changes the seed.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::from_seed`] rejects the derived seed.
    fn from_bip39_mnemonic(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>> {
        Self::from_seed(&solana_seed_phrase::generate_seed_from_bip39_mnemonic(
            seed_phrase,
            passphrase,
        ))
    }
}
