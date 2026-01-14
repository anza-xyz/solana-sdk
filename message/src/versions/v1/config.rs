//! Transaction configuration types for V1 messages.

#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
use std::mem::size_of;

/// Bitmask indicating which configuration values are present in a V1 transaction.
///
/// Each bit (or bit pair) corresponds to a specific configuration field.
/// The config values array contains entries only for fields whose bits are set.
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransactionConfigMask(pub u32);

impl TransactionConfigMask {
    /// Bits 0-1: Priority fee (requires both bits set, 8 bytes as u64 LE).
    pub const PRIORITY_FEE_BITS: u32 = 0b11;

    /// Bit 2: Compute unit limit (4 bytes as u32 LE).
    pub const COMPUTE_UNIT_LIMIT_BIT: u32 = 0b100;

    /// Bit 3: Loaded accounts data size limit (4 bytes as u32 LE).
    pub const LOADED_ACCOUNTS_DATA_SIZE_BIT: u32 = 0b1000;

    /// Bit 4: Requested heap size (4 bytes as u32 LE).
    pub const HEAP_SIZE_BIT: u32 = 0b10000;

    /// Mask of all known/supported bits (bits 0-4).
    pub const KNOWN_BITS_MASK: u32 = 0b11111;

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns true if any unknown bits are set (bits 5-31).
    ///
    /// Unknown bits indicate a config field the parser doesn't recognize.
    /// Since config values are packed sequentially and the parser doesn't
    /// know the byte size of unknown fields, it cannot skip them correctly.
    /// Attempting to parse would read subsequent fields from wrong offsets.
    pub const fn has_unknown_bits(&self) -> bool {
        (self.0 & !Self::KNOWN_BITS_MASK) != 0
    }

    pub const fn has_priority_fee(&self) -> bool {
        (self.0 & Self::PRIORITY_FEE_BITS) == Self::PRIORITY_FEE_BITS
    }

    /// Returns true if only one of the two priority fee bits is set (invalid).
    pub const fn has_invalid_priority_fee_bits(&self) -> bool {
        let bits = self.0 & Self::PRIORITY_FEE_BITS;
        bits != 0 && bits != Self::PRIORITY_FEE_BITS
    }

    pub const fn has_compute_unit_limit(&self) -> bool {
        (self.0 & Self::COMPUTE_UNIT_LIMIT_BIT) != 0
    }

    pub const fn has_loaded_accounts_data_size(&self) -> bool {
        (self.0 & Self::LOADED_ACCOUNTS_DATA_SIZE_BIT) != 0
    }

    pub const fn has_heap_size(&self) -> bool {
        (self.0 & Self::HEAP_SIZE_BIT) != 0
    }

    /// Total size in bytes of config values indicated by this mask.
    pub const fn config_values_size(&self) -> usize {
        let mut size: usize = 0;
        if self.has_priority_fee() {
            size = size.saturating_add(size_of::<u64>());
        }
        if self.has_compute_unit_limit() {
            size = size.saturating_add(size_of::<u32>());
        }
        if self.has_loaded_accounts_data_size() {
            size = size.saturating_add(size_of::<u32>());
        }
        if self.has_heap_size() {
            size = size.saturating_add(size_of::<u32>());
        }
        size
    }

    pub const fn from_config(config: &TransactionConfig) -> Self {
        let mut mask = 0u32;
        if config.priority_fee.is_some() {
            mask |= Self::PRIORITY_FEE_BITS;
        }
        if config.compute_unit_limit.is_some() {
            mask |= Self::COMPUTE_UNIT_LIMIT_BIT;
        }
        if config.loaded_accounts_data_size_limit.is_some() {
            mask |= Self::LOADED_ACCOUNTS_DATA_SIZE_BIT;
        }
        if config.heap_size.is_some() {
            mask |= Self::HEAP_SIZE_BIT;
        }
        Self(mask)
    }
}

/// Compute budget configuration for V1 transactions.
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransactionConfig {
    /// Priority fee in lamports.
    pub priority_fee: Option<u64>,

    /// Maximum compute units. None means use runtime default.
    pub compute_unit_limit: Option<u32>,

    /// Maximum bytes of account data that may be loaded. None means use runtime default.
    pub loaded_accounts_data_size_limit: Option<u32>,

    /// Heap size in bytes. Must be multiple of 1024. `None` = 32KB.
    pub heap_size: Option<u32>,
}

impl TransactionConfig {
    pub const fn new() -> Self {
        Self {
            priority_fee: None,
            compute_unit_limit: None,
            loaded_accounts_data_size_limit: None,
            heap_size: None,
        }
    }

    #[must_use]
    pub const fn with_priority_fee(mut self, fee: u64) -> Self {
        self.priority_fee = Some(fee);
        self
    }

    #[must_use]
    pub const fn with_compute_unit_limit(mut self, limit: u32) -> Self {
        self.compute_unit_limit = Some(limit);
        self
    }

    #[must_use]
    pub const fn with_loaded_accounts_data_size_limit(mut self, limit: u32) -> Self {
        self.loaded_accounts_data_size_limit = Some(limit);
        self
    }

    /// Heap size must be a multiple of 1024. Validated during deserialization.
    #[must_use]
    pub const fn with_heap_size(mut self, size: u32) -> Self {
        self.heap_size = Some(size);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_unknown_bits_detects_unsupported_bits() {
        assert!(!TransactionConfigMask::new(0).has_unknown_bits());
        assert!(!TransactionConfigMask::new(0b11111).has_unknown_bits());
        assert!(TransactionConfigMask::new(0b100000).has_unknown_bits());
        assert!(TransactionConfigMask::new(0x80000000).has_unknown_bits());
        assert!(TransactionConfigMask::new(0b111111).has_unknown_bits());
    }

    #[test]
    fn has_priority_fee_requires_both_bits() {
        assert!(!TransactionConfigMask::new(0).has_priority_fee());
        assert!(!TransactionConfigMask::new(0b01).has_priority_fee());
        assert!(!TransactionConfigMask::new(0b10).has_priority_fee());
        assert!(TransactionConfigMask::new(0b11).has_priority_fee());
    }

    #[test]
    fn has_invalid_priority_fee_bits_detects_partial() {
        assert!(!TransactionConfigMask::new(0).has_invalid_priority_fee_bits());
        assert!(TransactionConfigMask::new(0b01).has_invalid_priority_fee_bits());
        assert!(TransactionConfigMask::new(0b10).has_invalid_priority_fee_bits());
        assert!(!TransactionConfigMask::new(0b11).has_invalid_priority_fee_bits());
    }

    #[test]
    fn has_field_methods_check_individual_bits() {
        let mask = TransactionConfigMask::new(0b11100);
        assert!(mask.has_compute_unit_limit());
        assert!(mask.has_loaded_accounts_data_size());
        assert!(mask.has_heap_size());

        let mask = TransactionConfigMask::new(0);
        assert!(!mask.has_compute_unit_limit());
        assert!(!mask.has_loaded_accounts_data_size());
        assert!(!mask.has_heap_size());
    }

    #[test]
    fn config_values_size_sums_field_sizes() {
        assert_eq!(TransactionConfigMask::new(0).config_values_size(), 0);
        assert_eq!(TransactionConfigMask::new(0b11).config_values_size(), 8);
        assert_eq!(TransactionConfigMask::new(0b100).config_values_size(), 4);
        assert_eq!(TransactionConfigMask::new(0b11111).config_values_size(), 20);
    }

    #[test]
    fn from_config_sets_correct_bits() {
        let config = TransactionConfig::new()
            .with_priority_fee(1000)
            .with_compute_unit_limit(200_000);

        let mask = TransactionConfigMask::from_config(&config);
        assert!(mask.has_priority_fee());
        assert!(mask.has_compute_unit_limit());
        assert!(!mask.has_loaded_accounts_data_size());
        assert!(!mask.has_heap_size());
    }

    #[test]
    fn mask_invariants_hold_for_all_known_bit_patterns() {
        for raw in 0u32..(1u32 << 5) {
            let mask = TransactionConfigMask::new(raw);

            assert!(!mask.has_unknown_bits());

            if mask.has_priority_fee() {
                assert!(!mask.has_invalid_priority_fee_bits());
            }

            let mut expected_size = 0;
            if mask.has_priority_fee() {
                expected_size += size_of::<u64>();
            }
            if mask.has_compute_unit_limit() {
                expected_size += size_of::<u32>();
            }
            if mask.has_loaded_accounts_data_size() {
                expected_size += size_of::<u32>();
            }
            if mask.has_heap_size() {
                expected_size += size_of::<u32>();
            }
            assert_eq!(mask.config_values_size(), expected_size);
        }
    }

    #[test]
    fn builder_sets_all_fields() {
        let config = TransactionConfig::new()
            .with_priority_fee(1000)
            .with_compute_unit_limit(200_000)
            .with_loaded_accounts_data_size_limit(64 * 1024)
            .with_heap_size(64 * 1024);

        assert_eq!(config.priority_fee, Some(1000));
        assert_eq!(config.compute_unit_limit, Some(200_000));
        assert_eq!(config.loaded_accounts_data_size_limit, Some(64 * 1024));
        assert_eq!(config.heap_size, Some(64 * 1024));
    }
}
