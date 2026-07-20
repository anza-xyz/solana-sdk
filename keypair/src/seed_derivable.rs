//! Implementation of the SeedDerivable trait for Keypair

use {
    crate::{keypair_from_seed, keypair_from_seed_phrase_and_passphrase, Keypair},
    solana_derivation_path::DerivationPath,
    solana_ed25519::ed_sigs::{Bip32DerivationError, ExtendedSigningKey},
    solana_seed_derivable::SeedDerivable,
    std::error,
};

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
    bip32_derived_keypair(seed, derivation_path).map_err(|err| err.to_string().into())
}

/// Generates a Keypair using Bip32 Hierarchical Derivation
fn bip32_derived_keypair(
    seed: &[u8],
    derivation_path: DerivationPath,
) -> Result<Keypair, Bip32DerivationError> {
    // Ed25519 BIP32 derivation only supports hardened child indexes; each
    // `ChildIndex` is encoded to its BIP32 `u32` (with the hardened bit set).
    let extended = ExtendedSigningKey::from_seed(seed)
        .derive_path(derivation_path.into_iter().map(|child| child.to_bits()))?;
    Ok(Keypair(extended.into_signing_key()))
}
