//! Collection of all runtime features.
//!
//! Steps to add a new feature are outlined below. Note that these steps only cover
//! the process of getting a feature into the core Solana code.
//! - For features that are unambiguously good (ie bug fixes), these steps are sufficient.
//! - For features that should go up for community vote (ie fee structure changes), more
//!   information on the additional steps to follow can be found at:
//!   <https://spl.solana.com/feature-proposal#feature-proposal-life-cycle>
//!
//! 1. Generate a new keypair with `solana-keygen new --outfile feature.json --no-passphrase`
//!    - Keypairs should be held by core contributors only. If you're a non-core contributor going
//!      through these steps, the PR process will facilitate a keypair holder being picked. That
//!      person will generate the keypair, provide pubkey for PR, and ultimately enable the feature.
//! 2. Add a public module for the feature, specifying keypair pubkey as the id with
//!    `solana_pubkey::declare_id!()` within the module.
//!    Additionally, add an entry to `FEATURE_NAMES` map.
//! 3. Add desired logic to check for and switch on feature availability.
//!
//! For more information on how features are picked up, see comments for `Feature`.
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

use {
    ahash::{AHashMap, AHashSet},
    solana_pubkey::Pubkey,
};

/// `FeatureSet` holds the set of currently active/inactive runtime features
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FeatureSet {
    pub active: AHashMap<Pubkey, u64>,
    pub inactive: AHashSet<Pubkey>,
}

impl FeatureSet {
    pub fn is_active(&self, feature_id: &Pubkey) -> bool {
        self.active.contains_key(feature_id)
    }

    pub fn activated_slot(&self, feature_id: &Pubkey) -> Option<u64> {
        self.active.get(feature_id).copied()
    }

    /// Activate a feature
    pub fn activate(&mut self, feature_id: &Pubkey, slot: u64) {
        self.inactive.remove(feature_id);
        self.active.insert(*feature_id, slot);
    }

    /// Deactivate a feature
    pub fn deactivate(&mut self, feature_id: &Pubkey) {
        self.active.remove(feature_id);
        self.inactive.insert(*feature_id);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_feature_set_activate_deactivate() {
        let mut feature_set = FeatureSet {
            active: AHashMap::new(),
            inactive: AHashSet::new(),
        };

        let feature = Pubkey::new_unique();
        assert!(!feature_set.is_active(&feature));
        feature_set.activate(&feature, 0);
        assert!(feature_set.is_active(&feature));
        feature_set.deactivate(&feature);
        assert!(!feature_set.is_active(&feature));
    }
}
