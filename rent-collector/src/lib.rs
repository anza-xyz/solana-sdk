//! Calculate and collect rent from accounts.
//!
//! The `RentCollector` type is only used for its `rent` field by Agave, but
//! it's still part of snapshots, so any modifications to fields must be done
//! carefully.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

use {
    solana_clock::Epoch, solana_epoch_schedule::EpochSchedule,
    solana_genesis_config::GenesisConfig, solana_rent::Rent,
};

#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Clone, Debug, PartialEq)]
pub struct RentCollector {
    pub epoch: Epoch,
    pub epoch_schedule: EpochSchedule,
    pub slots_per_year: f64,
    pub rent: Rent,
}

impl Default for RentCollector {
    fn default() -> Self {
        Self {
            epoch: Epoch::default(),
            epoch_schedule: EpochSchedule::default(),
            // derive default value using GenesisConfig::default()
            slots_per_year: GenesisConfig::default().slots_per_year(),
            rent: Rent::default(),
        }
    }
}

impl RentCollector {
    pub fn new(
        epoch: Epoch,
        epoch_schedule: EpochSchedule,
        slots_per_year: f64,
        rent: Rent,
    ) -> Self {
        Self {
            epoch,
            epoch_schedule,
            slots_per_year,
            rent,
        }
    }
    pub fn clone_with_epoch(&self, epoch: Epoch) -> Self {
        Self {
            epoch,
            ..self.clone()
        }
    }
}
