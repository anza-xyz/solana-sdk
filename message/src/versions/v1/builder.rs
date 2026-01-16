//! Builder pattern for constructing V1 messages.

use {
    super::{
        Message, MessageError, TransactionConfig, TransactionConfigMask, MAX_ADDRESSES,
        MAX_INSTRUCTIONS, MAX_SIGNATURES, MAX_TRANSACTION_SIZE,
    },
    crate::{compiled_instruction::CompiledInstruction, MessageHeader},
    solana_address::Address,
    solana_hash::Hash,
};

/// Builder for constructing V1 messages.
#[derive(Debug, Clone, Default)]
pub struct MessageBuilder {
    header: MessageHeader,
    config: TransactionConfig,
    lifetime_specifier: Option<Hash>,
    account_keys: Vec<Address>,
    instructions: Vec<CompiledInstruction>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn num_required_signatures(mut self, count: u8) -> Self {
        self.header.num_required_signatures = count;
        self
    }

    #[must_use]
    pub fn num_readonly_signed_accounts(mut self, count: u8) -> Self {
        self.header.num_readonly_signed_accounts = count;
        self
    }

    #[must_use]
    pub fn num_readonly_unsigned_accounts(mut self, count: u8) -> Self {
        self.header.num_readonly_unsigned_accounts = count;
        self
    }

    #[must_use]
    pub fn lifetime_specifier(mut self, hash: Hash) -> Self {
        self.lifetime_specifier = Some(hash);
        self
    }

    #[must_use]
    pub fn config(mut self, config: TransactionConfig) -> Self {
        self.config = config;
        self
    }

    #[must_use]
    pub fn priority_fee(mut self, fee: u64) -> Self {
        self.config.priority_fee = Some(fee);
        self
    }

    #[must_use]
    pub fn compute_unit_limit(mut self, limit: u32) -> Self {
        self.config.compute_unit_limit = Some(limit);
        self
    }

    #[must_use]
    pub fn loaded_accounts_data_size_limit(mut self, limit: u32) -> Self {
        self.config.loaded_accounts_data_size_limit = Some(limit);
        self
    }

    #[must_use]
    pub fn heap_size(mut self, size: u32) -> Self {
        self.config.heap_size = Some(size);
        self
    }

    #[must_use]
    pub fn account_key(mut self, key: Address) -> Self {
        self.account_keys.push(key);
        self
    }

    #[must_use]
    pub fn account_keys(mut self, keys: Vec<Address>) -> Self {
        self.account_keys = keys;
        self
    }

    #[must_use]
    pub fn instruction(mut self, instruction: CompiledInstruction) -> Self {
        self.instructions.push(instruction);
        self
    }

    #[must_use]
    pub fn instructions(mut self, instructions: Vec<CompiledInstruction>) -> Self {
        self.instructions = instructions;
        self
    }

    /// Build the message, validating all constraints.
    pub fn build(self) -> Result<Message, MessageError> {
        let lifetime_specifier = self
            .lifetime_specifier
            .ok_or(MessageError::MissingLifetimeSpecifier)?;

        // Validate signer count
        if self.header.num_required_signatures == 0 {
            return Err(MessageError::ZeroSigners);
        }
        if self.header.num_required_signatures > MAX_SIGNATURES {
            return Err(MessageError::TooManySignatures);
        }

        // Validate address count
        if self.account_keys.len() > MAX_ADDRESSES as usize {
            return Err(MessageError::TooManyAddresses);
        }
        if (self.header.num_required_signatures as usize) > self.account_keys.len() {
            return Err(MessageError::NotEnoughAddressesForSignatures);
        }

        // Validate instruction count
        if self.instructions.len() > MAX_INSTRUCTIONS as usize {
            return Err(MessageError::TooManyInstructions);
        }

        // Validate config mask (priority fee bits must be both set or both unset)
        let mask = TransactionConfigMask::from_config(&self.config);
        if mask.has_invalid_priority_fee_bits() {
            return Err(MessageError::InvalidConfigMask);
        }

        // Validate heap size alignment
        if let Some(heap_size) = self.config.heap_size {
            if heap_size % 1024 != 0 {
                return Err(MessageError::InvalidHeapSize);
            }
        }

        // Validate instruction constraints
        for ix in &self.instructions {
            if ix.accounts.len() > u8::MAX as usize {
                return Err(MessageError::InstructionAccountsTooLarge);
            }
            if ix.data.len() > u16::MAX as usize {
                return Err(MessageError::InstructionDataTooLarge);
            }
        }

        let message = Message {
            header: self.header,
            config: self.config,
            lifetime_specifier,
            account_keys: self.account_keys,
            instructions: self.instructions,
        };

        // Validate transaction size (message + signatures)
        if message.transaction_size() > MAX_TRANSACTION_SIZE {
            return Err(MessageError::TransactionTooLarge);
        }

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{FIXED_HEADER_SIZE, INSTRUCTION_HEADER_SIZE, SIGNATURE_SIZE},
            *,
        },
        solana_address::ADDRESS_BYTES,
    };

    #[test]
    fn builder_requires_lifetime_specifier() {
        let result = MessageBuilder::new()
            .num_required_signatures(1)
            .account_key(Address::new_unique())
            .build();

        assert_eq!(result, Err(MessageError::MissingLifetimeSpecifier));
    }

    #[test]
    fn builder_rejects_zero_signers() {
        let result = MessageBuilder::new()
            .num_required_signatures(0)
            .lifetime_specifier(Hash::new_unique())
            .account_key(Address::new_unique())
            .build();

        assert_eq!(result, Err(MessageError::ZeroSigners));
    }

    #[test]
    fn builder_rejects_too_many_signatures() {
        let result = MessageBuilder::new()
            .num_required_signatures(MAX_SIGNATURES + 1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys((0..20).map(|_| Address::new_unique()).collect())
            .build();

        assert_eq!(result, Err(MessageError::TooManySignatures));
    }

    #[test]
    fn builder_rejects_too_many_addresses() {
        let result = MessageBuilder::new()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys((0..65).map(|_| Address::new_unique()).collect())
            .build();

        assert_eq!(result, Err(MessageError::TooManyAddresses));
    }

    #[test]
    fn builder_rejects_not_enough_addresses() {
        let result = MessageBuilder::new()
            .num_required_signatures(5)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .build();

        assert_eq!(result, Err(MessageError::NotEnoughAddressesForSignatures));
    }

    #[test]
    fn builder_rejects_too_many_instructions() {
        let result = MessageBuilder::new()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instructions(
                (0..129)
                    .map(|_| CompiledInstruction {
                        program_id_index: 1,
                        accounts: vec![],
                        data: vec![],
                    })
                    .collect(),
            )
            .build();

        assert_eq!(result, Err(MessageError::TooManyInstructions));
    }

    #[test]
    fn builder_rejects_unaligned_heap_size() {
        let result = MessageBuilder::new()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_key(Address::new_unique())
            .heap_size(1025)
            .build();

        assert_eq!(result, Err(MessageError::InvalidHeapSize));
    }

    #[test]
    fn builder_accepts_valid_heap_sizes() {
        for size in [1024, 32768, 65536, 256 * 1024] {
            let result = MessageBuilder::new()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_key(Address::new_unique())
                .heap_size(size)
                .build();

            assert!(result.is_ok(), "heap_size {size} should be valid");
        }
    }

    #[test]
    fn builder_rejects_instruction_with_too_many_accounts() {
        let result = MessageBuilder::new()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0; 256], // Max is 255
                data: vec![],
            })
            .build();

        assert_eq!(result, Err(MessageError::InstructionAccountsTooLarge));
    }

    #[test]
    fn builder_creates_valid_message() {
        let fee_payer = Address::new_unique();
        let program = Address::new_unique();
        let blockhash = Hash::new_unique();

        let message = MessageBuilder::new()
            .num_required_signatures(1)
            .num_readonly_unsigned_accounts(0)
            .lifetime_specifier(blockhash)
            .account_keys(vec![fee_payer, program])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3],
            })
            .compute_unit_limit(200_000)
            .build()
            .unwrap();

        assert_eq!(message.header.num_required_signatures, 1);
        assert_eq!(message.lifetime_specifier, blockhash);
        assert_eq!(message.account_keys.len(), 2);
        assert_eq!(message.config.compute_unit_limit, Some(200_000));
    }

    #[test]
    fn builder_sets_all_config_fields() {
        let message = MessageBuilder::new()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_key(Address::new_unique())
            .priority_fee(1000)
            .compute_unit_limit(200_000)
            .loaded_accounts_data_size_limit(64 * 1024)
            .heap_size(64 * 1024)
            .build()
            .unwrap();

        assert_eq!(message.config.priority_fee, Some(1000));
        assert_eq!(message.config.compute_unit_limit, Some(200_000));
        assert_eq!(
            message.config.loaded_accounts_data_size_limit,
            Some(64 * 1024)
        );
        assert_eq!(message.config.heap_size, Some(64 * 1024));
    }

    #[test]
    fn builder_rejects_transaction_too_large() {
        // Create a message that would exceed 4096 bytes when serialized as a transaction.
        // With 12 signatures (64 bytes each) = 768 bytes for signatures
        // Plus message overhead, we can use large instruction data to exceed the limit.
        let large_data = vec![0u8; 3500]; // Large instruction data

        let result = MessageBuilder::new()
            .num_required_signatures(MAX_SIGNATURES) // 12 signatures = 768 bytes
            .lifetime_specifier(Hash::new_unique())
            .account_keys(
                (0..MAX_SIGNATURES as usize)
                    .map(|_| Address::new_unique())
                    .collect(),
            )
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: large_data,
            })
            .build();

        assert_eq!(result, Err(MessageError::TransactionTooLarge));
    }

    #[test]
    fn builder_accepts_transaction_at_max_size() {
        // Calculate exact max data size for a transaction at the limit:
        // - 1 signature
        // - Fixed header (version + MessageHeader + config mask + lifetime + num_ix + num_addr)
        // - 2 addresses
        // - No config values (mask = 0)
        // - 1 instruction header
        // - 1 account index in instruction
        const NUM_SIGNATURES: usize = 1;
        const NUM_ADDRESSES: usize = 2;
        const NUM_INSTRUCTION_ACCOUNTS: usize = 1;

        let overhead = (NUM_SIGNATURES * SIGNATURE_SIZE)
            + FIXED_HEADER_SIZE
            + (NUM_ADDRESSES * ADDRESS_BYTES)
            + INSTRUCTION_HEADER_SIZE
            + NUM_INSTRUCTION_ACCOUNTS;

        let max_data_size = MAX_TRANSACTION_SIZE - overhead;
        let data = vec![0u8; max_data_size];

        let result = MessageBuilder::new()
            .num_required_signatures(NUM_SIGNATURES as u8)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data,
            })
            .build();

        assert!(result.is_ok(), "Expected message to build successfully");
        let message = result.unwrap();
        assert_eq!(
            message.transaction_size(),
            MAX_TRANSACTION_SIZE,
            "Transaction should be exactly at max size"
        );
    }
}
