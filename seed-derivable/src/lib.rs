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
    /// Derives a key from a seed phrase and passphrase.
    ///
    /// Solana implementations pass the seed from
    /// `solana_seed_phrase::generate_seed_from_seed_phrase_and_passphrase` to
    /// [`Self::from_seed`]. This uses the raw UTF-8 inputs without BIP-39's Unicode
    /// NFKD normalization. When both inputs are already in NFKD form, such as an
    /// English mnemonic with an ASCII passphrase, the seed matches BIP-39.
    /// Normalizing non-NFKD inputs can change the key, so preserve the original
    /// input bytes when recovering existing keys.
    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>>;
}
