#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![deprecated(
    since = "4.0.1",
    note = "DO NOT USE. Crates that need to break consensus should expose their own minimal configuration type"
)]

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
