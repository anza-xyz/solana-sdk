//! Core Message type for V1 transactions (SIMD-0385).

#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
use {
    super::{
        ComputeBudgetConfig, ComputeBudgetConfigMask, MAX_ADDRESSES, MAX_INSTRUCTIONS,
        MAX_SIGNATURES, MAX_TRANSACTION_SIZE,
    },
    crate::{compiled_instruction::CompiledInstruction, MessageHeader},
    solana_address::Address,
    solana_hash::Hash,
    solana_sanitize::{Sanitize, SanitizeError},
    solana_sdk_ids::bpf_loader_upgradeable,
    std::collections::HashSet,
};

/// A V1 transaction message (SIMD-0385) supporting 4KB transactions with inline compute budget.
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    /// The message header describing signer/readonly account counts.
    pub header: MessageHeader,

    /// Compute budget configuration embedded in the message header.
    /// Replaces separate ComputeBudget program instructions.
    pub config: ComputeBudgetConfig,

    /// The lifetime specifier (blockhash) that determines when this transaction expires.
    pub lifetime_specifier: Hash,

    /// All account addresses referenced by this message.
    /// Unlike V0, V1 does not support address lookup tables.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    pub account_keys: Vec<Address>,

    /// Program instructions to execute.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Returns the fee payer address (first account key).
    pub fn fee_payer(&self) -> Option<&Address> {
        self.account_keys.first()
    }

    /// Account keys are ordered with signers first: `[signers..., non-signers...]`.
    /// An index falls in the signer region if it's less than `num_required_signatures`.
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header.num_required_signatures)
    }

    /// Returns true if the account at this index is both a signer and writable.
    pub fn is_signer_writable(&self, index: usize) -> bool {
        if !self.is_signer(index) {
            return false;
        }
        // Within the signer region, the first (num_required_signatures - num_readonly_signed)
        // accounts are writable signers.
        let num_writable_signers = usize::from(self.header.num_required_signatures)
            .saturating_sub(usize::from(self.header.num_readonly_signed_accounts));
        index < num_writable_signers
    }

    /// Returns true if any instruction invokes the account at this index as a program.
    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions
                .iter()
                .any(|ix| ix.program_id_index == key_index)
        } else {
            false
        }
    }

    /// Returns true if the account at the specified index was requested as writable.
    ///
    /// Account keys are ordered: `[writable signers][readonly signers][writable non-signers][readonly non-signers]`.
    /// This checks which region the index falls into based on the header counts.
    fn is_writable_index(&self, key_index: usize) -> bool {
        let num_account_keys = self.account_keys.len();
        let num_signed_accounts = usize::from(self.header.num_required_signatures);

        if key_index >= num_account_keys {
            return false;
        }

        if key_index >= num_signed_accounts {
            // Non-signer region
            let num_unsigned_accounts = num_account_keys.saturating_sub(num_signed_accounts);
            let num_writable_unsigned_accounts = num_unsigned_accounts
                .saturating_sub(usize::from(self.header.num_readonly_unsigned_accounts));
            let unsigned_account_index = key_index.saturating_sub(num_signed_accounts);
            unsigned_account_index < num_writable_unsigned_accounts
        } else {
            // Signer region
            let num_writable_signed_accounts = num_signed_accounts
                .saturating_sub(usize::from(self.header.num_readonly_signed_accounts));
            key_index < num_writable_signed_accounts
        }
    }

    /// Returns true if the BPF upgradeable loader is present in the account keys.
    pub fn is_upgradeable_loader_present(&self) -> bool {
        self.account_keys
            .iter()
            .any(|&key| key == bpf_loader_upgradeable::id())
    }

    /// Returns true if the account at the specified index was requested as writable.
    ///
    /// The `reserved_account_keys` parameter allows demoting reserved accounts to readonly.
    pub fn is_maybe_writable(
        &self,
        key_index: usize,
        reserved_account_keys: Option<&HashSet<Address>>,
    ) -> bool {
        if !self.is_writable_index(key_index) {
            return false;
        }

        // Check if reserved
        if let Some(reserved) = reserved_account_keys {
            if let Some(key) = self.account_keys.get(key_index) {
                if reserved.contains(key) {
                    return false;
                }
            }
        }

        // Demote program IDs, unless the upgradeable loader is present
        // (upgradeable programs need to be writable for upgrades)
        if self.is_key_called_as_program(key_index) && !self.is_upgradeable_loader_present() {
            return false;
        }

        true
    }

    /// Create a new builder for constructing V1 messages.
    pub fn builder() -> super::MessageBuilder {
        super::MessageBuilder::new()
    }
}

impl Sanitize for Message {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        // Transaction size (message + signatures) must fit in 4096 bytes
        if self.transaction_size() > MAX_TRANSACTION_SIZE {
            return Err(SanitizeError::InvalidValue);
        }

        // Must have at least one signer (the fee payer)
        if self.header.num_required_signatures == 0 {
            return Err(SanitizeError::InvalidValue);
        }

        // num_required_signatures <= 12
        if self.header.num_required_signatures > MAX_SIGNATURES {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // Lifetime specifier must not be zero
        if self.lifetime_specifier == Hash::default() {
            return Err(SanitizeError::InvalidValue);
        }

        let num_account_keys = self.account_keys.len();

        // num_addresses <= 64
        if num_account_keys > MAX_ADDRESSES as usize {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // num_instructions <= 64
        if self.instructions.len() > MAX_INSTRUCTIONS as usize {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // num_addresses >= num_required_signatures + num_readonly_unsigned_accounts
        let min_accounts = usize::from(self.header.num_required_signatures)
            .saturating_add(usize::from(self.header.num_readonly_unsigned_accounts));
        if num_account_keys < min_accounts {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // Must have at least 1 RW fee-payer (num_readonly_signed < num_required_signatures)
        if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
            return Err(SanitizeError::InvalidValue);
        }

        // No duplicate addresses
        let unique_keys: HashSet<_> = self.account_keys.iter().collect();
        if unique_keys.len() != num_account_keys {
            return Err(SanitizeError::InvalidValue);
        }

        // Validate config mask (2-bit fields must have both bits set or neither)
        let mask = ComputeBudgetConfigMask::from_config(&self.config);
        if mask.has_invalid_priority_fee_bits() {
            return Err(SanitizeError::InvalidValue);
        }

        // Heap size must be a multiple of 1024
        if let Some(heap_size) = self.config.heap_size {
            if heap_size % 1024 != 0 {
                return Err(SanitizeError::InvalidValue);
            }
        }

        // Instruction account indices must be < num_addresses
        let max_account_index = num_account_keys
            .checked_sub(1)
            .ok_or(SanitizeError::InvalidValue)?;

        for instruction in &self.instructions {
            // Program ID must be in static accounts
            if usize::from(instruction.program_id_index) > max_account_index {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            // Program cannot be fee payer
            if instruction.program_id_index == 0 {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            // Instruction accounts count must fit in u8
            if instruction.accounts.len() > u8::MAX as usize {
                return Err(SanitizeError::InvalidValue);
            }

            // Instruction data length must fit in u16
            if instruction.data.len() > u16::MAX as usize {
                return Err(SanitizeError::InvalidValue);
            }

            // All account indices must be valid
            for &account_index in &instruction.accounts {
                if usize::from(account_index) > max_account_index {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_message() -> Message {
        Message::builder()
            .num_required_signatures(1)
            .num_readonly_unsigned_accounts(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(), // fee payer
                Address::new_unique(), // program
                Address::new_unique(), // readonly account
            ])
            .compute_unit_limit(200_000)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0, 2],
                data: vec![1, 2, 3, 4],
            })
            .build()
            .unwrap()
    }

    #[test]
    fn fee_payer_returns_first_account() {
        let fee_payer = Address::new_unique();
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![fee_payer, Address::new_unique()])
            .build()
            .unwrap();

        assert_eq!(message.fee_payer(), Some(&fee_payer));
    }

    #[test]
    fn fee_payer_returns_none_for_empty_accounts() {
        // Direct construction to bypass builder validation
        let message = Message {
            header: MessageHeader::default(),
            config: ComputeBudgetConfig::default(),
            lifetime_specifier: Hash::new_unique(),
            account_keys: vec![],
            instructions: vec![],
        };

        assert_eq!(message.fee_payer(), None);
    }

    #[test]
    fn is_signer_checks_signature_requirement() {
        let message = create_test_message();
        assert!(message.is_signer(0)); // Fee payer is signer
        assert!(!message.is_signer(1)); // Program is not signer
        assert!(!message.is_signer(2)); // Readonly account is not signer
    }

    #[test]
    fn is_signer_writable_identifies_writable_signers() {
        let message = Message::builder()
            .num_required_signatures(3)
            .num_readonly_signed_accounts(1) // Last signer is readonly
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(), // 0: writable signer
                Address::new_unique(), // 1: writable signer
                Address::new_unique(), // 2: readonly signer
                Address::new_unique(), // 3: non-signer
            ])
            .build()
            .unwrap();

        // Writable signers
        assert!(message.is_signer_writable(0));
        assert!(message.is_signer_writable(1));
        // Readonly signer
        assert!(!message.is_signer_writable(2));
        // Non-signers
        assert!(!message.is_signer_writable(3));
        assert!(!message.is_signer_writable(100));
    }

    #[test]
    fn is_signer_writable_all_writable_when_no_readonly() {
        let message = Message::builder()
            .num_required_signatures(2)
            .num_readonly_signed_accounts(0) // All signers are writable
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
            ])
            .build()
            .unwrap();

        assert!(message.is_signer_writable(0));
        assert!(message.is_signer_writable(1));
        assert!(!message.is_signer_writable(2)); // Not a signer
    }

    #[test]
    fn is_key_called_as_program_detects_program_indices() {
        let message = create_test_message();
        // program_id_index = 1 in create_test_message
        assert!(message.is_key_called_as_program(1));
        assert!(!message.is_key_called_as_program(0));
        assert!(!message.is_key_called_as_program(2));
        // Index > u8::MAX can't match any program_id_index
        assert!(!message.is_key_called_as_program(256));
        assert!(!message.is_key_called_as_program(10_000));
    }

    #[test]
    fn is_upgradeable_loader_present_detects_loader() {
        let message = create_test_message();
        assert!(!message.is_upgradeable_loader_present());

        let mut message_with_loader = create_test_message();
        message_with_loader
            .account_keys
            .push(bpf_loader_upgradeable::id());
        assert!(message_with_loader.is_upgradeable_loader_present());
    }

    #[test]
    fn is_writable_index_respects_header_layout() {
        let message = create_test_message();
        // Account layout: [writable signer (fee payer), writable unsigned (program), readonly unsigned]
        assert!(message.is_writable_index(0)); // Fee payer is writable
        assert!(message.is_writable_index(1)); // Program position is writable unsigned
        assert!(!message.is_writable_index(2)); // Last account is readonly
    }

    #[test]
    fn is_writable_index_handles_mixed_signer_permissions() {
        let mut message = create_test_message();
        // 2 signers: first writable, second readonly
        message.header.num_required_signatures = 2;
        message.header.num_readonly_signed_accounts = 1;
        message.header.num_readonly_unsigned_accounts = 1;
        message.account_keys = vec![
            Address::new_unique(), // writable signer
            Address::new_unique(), // readonly signer
            Address::new_unique(), // readonly unsigned
        ];
        message.instructions[0].program_id_index = 2;
        message.instructions[0].accounts = vec![0, 1];

        assert!(message.sanitize().is_ok());
        assert!(message.is_writable_index(0)); // writable signer
        assert!(!message.is_writable_index(1)); // readonly signer
        assert!(!message.is_writable_index(2)); // readonly unsigned
        assert!(!message.is_writable_index(999)); // out of bounds
    }

    #[test]
    fn is_maybe_writable_returns_false_for_readonly_index() {
        let message = create_test_message();
        // Index 2 is readonly unsigned
        assert!(!message.is_writable_index(2));
        assert!(!message.is_maybe_writable(2, None));
        // Even with empty reserved set
        assert!(!message.is_maybe_writable(2, Some(&HashSet::new())));
    }

    #[test]
    fn is_maybe_writable_demotes_reserved_accounts() {
        let message = create_test_message();
        let reserved = HashSet::from([message.account_keys[0]]);
        // Fee payer is writable by index, but reserved → demoted
        assert!(message.is_writable_index(0));
        assert!(!message.is_maybe_writable(0, Some(&reserved)));
    }

    #[test]
    fn is_maybe_writable_demotes_programs_without_upgradeable_loader() {
        let message = create_test_message();
        // Index 1 is writable unsigned, called as program, no upgradeable loader
        assert!(message.is_writable_index(1));
        assert!(message.is_key_called_as_program(1));
        assert!(!message.is_upgradeable_loader_present());
        assert!(!message.is_maybe_writable(1, None));
    }

    #[test]
    fn is_maybe_writable_preserves_programs_with_upgradeable_loader() {
        let mut message = create_test_message();
        // Add upgradeable loader to account keys
        message.account_keys.push(bpf_loader_upgradeable::id());

        assert!(message.sanitize().is_ok());
        assert!(message.is_writable_index(1));
        assert!(message.is_key_called_as_program(1));
        assert!(message.is_upgradeable_loader_present());
        // Program not demoted because upgradeable loader is present
        assert!(message.is_maybe_writable(1, None));
    }

    #[test]
    fn sanitize_accepts_valid_message() {
        let message = create_test_message();
        assert!(message.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_oversized_transaction() {
        let mut message = create_test_message();
        // Inflate instruction data to exceed MAX_TRANSACTION_SIZE (4096)
        message.instructions[0].data = vec![0u8; MAX_TRANSACTION_SIZE];
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_zero_signers() {
        let mut message = create_test_message();
        message.header.num_required_signatures = 0;
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_over_12_signatures() {
        let mut message = create_test_message();
        message.header.num_required_signatures = MAX_SIGNATURES + 1;
        message.account_keys = (0..MAX_SIGNATURES + 1)
            .map(|_| Address::new_unique())
            .collect();
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_zero_lifetime_specifier() {
        let mut message = create_test_message();
        message.lifetime_specifier = Hash::default();
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_over_64_addresses() {
        let mut message = create_test_message();
        message.account_keys = (0..65).map(|_| Address::new_unique()).collect();
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_over_64_instructions() {
        let mut message = create_test_message();
        message.instructions = (0..65) // exceeds 64 max
            .map(|_| CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .collect();
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_insufficient_accounts_for_header() {
        let mut message = create_test_message();
        // min_accounts = num_required_signatures + num_readonly_unsigned_accounts
        // Set readonly_unsigned high so min_accounts > account_keys.len()
        message.header.num_readonly_unsigned_accounts = 10;
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_all_signers_readonly() {
        let mut message = create_test_message();
        message.header.num_readonly_signed_accounts = 1; // All signers readonly
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_duplicate_addresses() {
        let mut message = create_test_message();
        let dup = message.account_keys[0];
        message.account_keys[1] = dup;
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_unaligned_heap_size() {
        let mut message = create_test_message();
        message.config.heap_size = Some(1025); // Not a multiple of 1024
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_accepts_aligned_heap_size() {
        let mut message = create_test_message();
        message.config.heap_size = Some(65536); // 64KB, valid
        assert!(message.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_invalid_program_id_index() {
        let mut message = create_test_message();
        message.instructions[0].program_id_index = 99;
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_fee_payer_as_program() {
        let mut message = create_test_message();
        message.instructions[0].program_id_index = 0;
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_instruction_with_too_many_accounts() {
        let mut message = create_test_message();
        message.instructions[0].accounts = vec![0u8; (u8::MAX as usize) + 1];
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }

    #[test]
    fn sanitize_rejects_invalid_instruction_account_index() {
        let mut message = create_test_message();
        message.instructions[0].accounts = vec![0, 99]; // 99 is out of bounds
        assert_eq!(message.sanitize(), Err(SanitizeError::IndexOutOfBounds));
    }

    #[test]
    fn sanitize_accepts_64_addresses() {
        let mut message = create_test_message();
        message.account_keys = (0..MAX_ADDRESSES).map(|_| Address::new_unique()).collect();
        message.header.num_required_signatures = 1;
        message.header.num_readonly_signed_accounts = 0;
        message.header.num_readonly_unsigned_accounts = 1;
        message.instructions[0].program_id_index = 1;
        message.instructions[0].accounts = vec![0, 2];
        assert!(message.sanitize().is_ok());
    }

    #[test]
    fn sanitize_accepts_64_instructions() {
        let mut message = create_test_message();
        message.instructions = (0..MAX_INSTRUCTIONS)
            .map(|_| CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0, 2],
                data: vec![1, 2, 3],
            })
            .collect();
        assert!(message.sanitize().is_ok());
    }

    #[test]
    fn sanitize_accepts_transaction_at_exactly_4096_bytes() {
        let mut message = create_test_message();
        // Calculate current size and pad to exactly 4096
        let current_size = message.transaction_size();
        let padding_needed = MAX_TRANSACTION_SIZE.saturating_sub(current_size);
        message.instructions[0].data =
            vec![0u8; message.instructions[0].data.len() + padding_needed];
        assert_eq!(message.transaction_size(), MAX_TRANSACTION_SIZE);
        assert!(message.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_transaction_at_4097_bytes() {
        let mut message = create_test_message();
        // Pad to exactly 4096, then add one more byte
        let current_size = message.transaction_size();
        let padding_needed = MAX_TRANSACTION_SIZE.saturating_sub(current_size) + 1;
        message.instructions[0].data =
            vec![0u8; message.instructions[0].data.len() + padding_needed];
        assert_eq!(message.transaction_size(), MAX_TRANSACTION_SIZE + 1);
        assert_eq!(message.sanitize(), Err(SanitizeError::InvalidValue));
    }
}
