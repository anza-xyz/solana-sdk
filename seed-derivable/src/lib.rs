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
    /// Implementations of this function make no guarantees about NFKD normalization.
    /// Be sure to normalize inputs prior to calling if needed.
    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>>;
}
