//! Builder pattern for constructing V1 messages.

use {
    super::{Message, TransactionConfig},
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

    pub fn build(self) -> Result<Message, &'static str> {
        let lifetime_specifier = self
            .lifetime_specifier
            .ok_or("lifetime_specifier (blockhash) is required")?;

        Ok(Message {
            header: self.header,
            config: self.config,
            lifetime_specifier,
            account_keys: self.account_keys,
            instructions: self.instructions,
        })
    }
}
