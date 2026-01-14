//! Runtime wrapper for V1 messages with cached writability.

use {super::Message, crate::AccountKeys, solana_address::Address, std::collections::HashSet};

/// Wrapper that precomputes account writability for efficient runtime access.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct V1Message {
    message: Message,
    writability: Vec<bool>,
}

impl V1Message {
    pub fn new(message: Message, reserved_account_keys: &HashSet<Address>) -> Self {
        let writability = (0..message.account_keys.len())
            .map(|i| message.is_maybe_writable(i, Some(reserved_account_keys)))
            .collect();
        Self {
            message,
            writability,
        }
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn has_duplicates(&self) -> bool {
        let unique: HashSet<_> = self.message.account_keys.iter().collect();
        unique.len() != self.message.account_keys.len()
    }

    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        self.message.is_key_called_as_program(key_index)
    }

    pub fn is_upgradeable_loader_present(&self) -> bool {
        self.message.is_upgradeable_loader_present()
    }

    pub fn account_keys(&self) -> AccountKeys<'_> {
        AccountKeys::new(&self.message.account_keys, None)
    }

    pub fn is_writable(&self, index: usize) -> bool {
        *self.writability.get(index).unwrap_or(&false)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{compiled_instruction::CompiledInstruction, MessageHeader},
        proptest::prelude::*,
        solana_hash::Hash,
    };

    fn create_test_message() -> Message {
        Message::builder()
            .num_required_signatures(2)
            .num_readonly_signed_accounts(1)
            .num_readonly_unsigned_accounts(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(), // 0: writable signer (fee payer)
                Address::new_unique(), // 1: readonly signer
                Address::new_unique(), // 2: writable unsigned
                Address::new_unique(), // 3: readonly unsigned
            ])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1, 3],
                data: vec![1, 2, 3],
            })
            .build()
            .unwrap()
    }

    #[test]
    fn cache_matches_underlying() {
        let message = create_test_message();
        let reserved = HashSet::new();
        let v1_msg = V1Message::new(message.clone(), &reserved);

        for i in 0..message.account_keys.len() {
            assert_eq!(
                v1_msg.is_writable(i),
                message.is_maybe_writable(i, Some(&reserved))
            );
        }
        assert!(!v1_msg.is_writable(message.account_keys.len()));
    }

    #[test]
    fn clone_preserves_writability_cache() {
        let message = create_test_message();
        let v1_msg = V1Message::new(message, &HashSet::new());
        let cloned = v1_msg.clone();

        for i in 0..4 {
            assert_eq!(v1_msg.is_writable(i), cloned.is_writable(i));
        }
    }

    fn valid_header_strategy() -> impl Strategy<Value = (usize, MessageHeader)> {
        // Start at 2 to ensure room for fee payer + at least one program
        (2usize..=10).prop_flat_map(|num_keys| {
            (1u8..=(num_keys as u8)).prop_flat_map(move |num_req_sigs| {
                let max_ro_signed = num_req_sigs.saturating_sub(1);
                let num_unsigned = num_keys.saturating_sub(num_req_sigs as usize);
                (0u8..=max_ro_signed).prop_flat_map(move |num_ro_signed| {
                    (0u8..=(num_unsigned as u8)).prop_map(move |num_ro_unsigned| {
                        (
                            num_keys,
                            MessageHeader {
                                num_required_signatures: num_req_sigs,
                                num_readonly_signed_accounts: num_ro_signed,
                                num_readonly_unsigned_accounts: num_ro_unsigned,
                            },
                        )
                    })
                })
            })
        })
    }

    proptest! {
        #[test]
        fn cache_matches_underlying_randomized(
            (num_keys, header) in valid_header_strategy(),
            // Start at 1 to avoid fee payer as program (invalid per sanitize)
            program_idx in proptest::option::of(1usize..10),
            // Only 10 bits needed since num_keys maxes at 10
            reserved_mask in 0u16..=0x03FF,
            // Test with upgradeable loader present (affects program writability)
            include_loader in proptest::bool::ANY,
        ) {
            let mut account_keys: Vec<_> = (0..num_keys).map(|_| Address::new_unique()).collect();

            // Optionally add upgradeable loader to test program writability preservation
            if include_loader {
                account_keys.push(solana_sdk_ids::bpf_loader_upgradeable::id());
            }

            let reserved: HashSet<_> = account_keys
                .iter()
                .enumerate()
                .filter(|(i, _)| reserved_mask & (1u16 << i) != 0)
                .map(|(_, k)| *k)
                .collect();

            let instructions = match program_idx {
                Some(idx) if idx < num_keys => vec![CompiledInstruction {
                    program_id_index: idx as u8,
                    accounts: vec![0],
                    data: vec![],
                }],
                _ => vec![],
            };

            let message = Message::builder()
                .num_required_signatures(header.num_required_signatures)
                .num_readonly_signed_accounts(header.num_readonly_signed_accounts)
                .num_readonly_unsigned_accounts(header.num_readonly_unsigned_accounts)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(account_keys)
                .instructions(instructions)
                .build()
                .unwrap();

            let v1_msg = V1Message::new(message.clone(), &reserved);

            for i in 0..message.account_keys.len() {
                prop_assert_eq!(
                    v1_msg.is_writable(i),
                    message.is_maybe_writable(i, Some(&reserved))
                );
            }
            prop_assert!(!v1_msg.is_writable(message.account_keys.len()));
            prop_assert!(!v1_msg.is_writable(999));
        }
    }

    #[test]
    fn has_duplicates_detects_adjacent() {
        let mut message = create_test_message();
        let v1_msg = V1Message::new(message.clone(), &HashSet::new());
        assert!(!v1_msg.has_duplicates());

        let dup = message.account_keys[0];
        message.account_keys[1] = dup;
        let v1_msg = V1Message::new(message, &HashSet::new());
        assert!(v1_msg.has_duplicates());
    }

    #[test]
    fn has_duplicates_detects_non_adjacent() {
        let dup_key = Address::new_unique();
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                dup_key,
                Address::new_unique(),
                Address::new_unique(),
                dup_key,
            ])
            .build()
            .unwrap();
        let v1_msg = V1Message::new(message, &HashSet::new());
        assert!(v1_msg.has_duplicates());
    }

    #[test]
    fn is_key_called_as_program_delegates_to_message() {
        let message = create_test_message();
        let v1_msg = V1Message::new(message, &HashSet::new());

        assert!(v1_msg.is_key_called_as_program(2));
        assert!(!v1_msg.is_key_called_as_program(0));
        assert!(!v1_msg.is_key_called_as_program(1));
        assert!(!v1_msg.is_key_called_as_program(3));
    }

    #[test]
    fn is_upgradeable_loader_present_delegates_to_message() {
        let message = create_test_message();
        let v1_msg = V1Message::new(message.clone(), &HashSet::new());

        assert_eq!(
            v1_msg.is_upgradeable_loader_present(),
            message.is_upgradeable_loader_present()
        );
    }

    #[test]
    fn account_keys_returns_correct_length() {
        let message = create_test_message();
        let expected_len = message.account_keys.len();
        let v1_msg = V1Message::new(message, &HashSet::new());

        assert_eq!(v1_msg.account_keys().len(), expected_len);
    }

    #[test]
    fn account_keys_returns_correct_content() {
        let message = create_test_message();
        let v1_msg = V1Message::new(message.clone(), &HashSet::new());

        let keys = v1_msg.account_keys();
        assert_eq!(keys.len(), message.account_keys.len());
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(*key, message.account_keys[i]);
        }
    }

    #[test]
    fn is_writable_uses_cached_values() {
        let message = create_test_message();
        let v1_msg = V1Message::new(message, &HashSet::new());

        assert!(v1_msg.is_writable(0));
        assert!(!v1_msg.is_writable(1));
        assert!(!v1_msg.is_writable(2));
        assert!(!v1_msg.is_writable(3));
        assert!(!v1_msg.is_writable(99));
    }

    #[test]
    fn is_writable_demotes_programs() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
            ])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();
        let v1_msg = V1Message::new(message, &HashSet::new());

        assert!(v1_msg.is_writable(0));
        assert!(!v1_msg.is_writable(1));
        assert!(!v1_msg.is_writable(2));
    }

    #[test]
    fn is_writable_demotes_reserved_fee_payer() {
        let message = create_test_message();
        let fee_payer = message.account_keys[0];

        let v1_msg = V1Message::new(message.clone(), &HashSet::new());
        assert!(v1_msg.is_writable(0));

        let reserved = HashSet::from([fee_payer]);
        let v1_msg = V1Message::new(message, &reserved);
        assert!(!v1_msg.is_writable(0));
    }

    #[test]
    fn is_writable_demotes_reserved_non_signer() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .build()
            .unwrap();
        let writable_key = message.account_keys[1];

        let v1_msg = V1Message::new(message.clone(), &HashSet::new());
        assert!(v1_msg.is_writable(1));

        let reserved = HashSet::from([writable_key]);
        let v1_msg = V1Message::new(message, &reserved);
        assert!(!v1_msg.is_writable(1));
    }

    #[test]
    fn is_writable_ignores_reserved_for_readonly() {
        let message = create_test_message();
        let readonly_key = message.account_keys[3];

        let v1_msg = V1Message::new(message.clone(), &HashSet::new());
        assert!(!v1_msg.is_writable(3));

        let reserved = HashSet::from([readonly_key]);
        let v1_msg = V1Message::new(message, &reserved);
        assert!(!v1_msg.is_writable(3));
    }

    #[test]
    fn is_writable_handles_single_account_message() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_key(Address::new_unique())
            .build()
            .unwrap();
        let v1_msg = V1Message::new(message, &HashSet::new());

        assert!(v1_msg.is_writable(0));
        assert!(!v1_msg.is_writable(1));
    }
}
