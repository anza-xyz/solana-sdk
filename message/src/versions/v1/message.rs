//! Core Message type for V1 transactions (SIMD-0385).
//!
//! A new transaction format that is designed to enable larger transactions
//! sizes while not having the address lookup table features introduced in
//! v0 transactions. The v1 transaction format also does not require compute
//! budget instructions to be present within the transaction.
//!
//! # Binary Format
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │ * LegacyHeader (3 x u8)                                │
//! │                                                        │
//! │ * TransactionConfigMask (u32, little-endian)           │
//! │                                                        │
//! │ * LifetimeSpecifier [u8; 32] (blockhash)               │
//! │                                                        │
//! │ * NumInstructions (u8, max 64)                         │
//! │                                                        │
//! │ * NumAddresses (u8, max 64)                            │
//! │                                                        │
//! │ * Addresses [[u8; 32] x NumAddresses]                  │
//! │                                                        │
//! │ * ConfigValues ([[u8; 4] * variable based on mask])    │
//! │                                                        │
//! │ * InstructionHeaders [(u8, u8, u16) x NumInstructions] │
//! │                                                        │
//! │ * InstructionPayloads (variable based on headers)      │
//! │    └─ Per NumInstructions:                             │
//! │         +- [u8] account indices                        │
//! │         └─ [u8] instruction data                       │
//! └────────────────────────────────────────────────────────┘
//! ```

// Re-export for convenient access to the message builder in tests.
#[cfg(test)]
pub use self::tests::MessageBuilder;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
#[cfg(feature = "wincode")]
use {
    crate::v1::MAX_TRANSACTION_SIZE,
    wincode::{
        config::ConfigCore,
        error::invalid_tag_encoding,
        io::{Reader, Writer},
        ReadResult, SchemaRead, SchemaWrite, WriteResult,
    },
};
use {
    crate::{
        compiled_instruction::CompiledInstruction,
        compiled_keys::CompiledKeys,
        v1::{
            InstructionHeader, MessageError, TransactionConfig, TransactionConfigMask,
            FIXED_HEADER_SIZE, MAX_ADDRESSES, MAX_INSTRUCTIONS, MAX_SIGNATURES,
        },
        AccountKeys, CompileError, MessageHeader,
    },
    core::{mem::size_of, ptr::copy_nonoverlapping},
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_sanitize::{Sanitize, SanitizeError},
    std::{collections::HashSet, mem::MaybeUninit},
};

/// A V1 transaction message (SIMD-0385) supporting 4KB transactions with inline compute budget.
///
/// # Important
///
/// This message format does not support bincode binary serialization. Use the provided
/// `serialize` and `deserialize` functions for binary encoding/decoding.
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

    /// Configuration for transaction parameters.
    pub config: TransactionConfig,

    /// The lifetime specifier (blockhash) that determines when this transaction expires.
    pub lifetime_specifier: Hash,

    /// All account addresses referenced by this message.
    ///
    /// The length should be specified as an `u8`. Unlike V0, V1 does not support
    /// address lookup tables. The ordering of the addresses is unchanged from prior
    /// transaction formats:
    ///
    ///   - `num_required_signatures-num_readonly_signed_accounts` additional addresses
    ///     for which the transaction contains signatures and are loaded as writable, of
    ///     which the first is the fee payer.
    ///
    ///   - `num_readonly_signed_accounts` addresses for which the transaction contains
    ///     signatures and are loaded as readonly.
    ///
    ///   - `num_addresses-num_required_signatures-num_readonly_unsigned_accounts` addresses
    ///     for which the transaction does not contain signatures and are loaded as writable.
    ///
    ///   - `num_readonly_unsigned_accounts` addresses for which the transaction does not
    ///     contain signatures and are loaded as readonly.
    pub account_keys: Vec<Address>,

    /// Program instructions to execute.
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Create a new V1 message.
    pub fn new(
        header: MessageHeader,
        config: TransactionConfig,
        lifetime_specifier: Hash,
        account_keys: Vec<Address>,
        instructions: Vec<CompiledInstruction>,
    ) -> Self {
        Self {
            header,
            config,
            lifetime_specifier,
            account_keys,
            instructions,
        }
    }

    /// Create a signable transaction message from a `payer` public key,
    /// `recent_blockhash`, list of `instructions` and a transaction `config`.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`], [`solana_account`], and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`solana_account`]: https://docs.rs/solana-account
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_example_mocks::{
    /// #     solana_rpc_client,
    /// #     solana_account,
    /// #     solana_signer,
    /// #     solana_keypair,
    /// # };
    /// # use std::borrow::Cow;
    /// # use solana_account::Account;
    /// use anyhow::Result;
    /// use solana_instruction::{AccountMeta, Instruction};
    /// use solana_keypair::Keypair;
    /// use solana_message::{VersionedMessage, v1};
    /// use solana_address::Address;
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_signer::Signer;
    /// # mod solana_transaction {
    /// #     pub mod versioned {
    /// #         use solana_example_mocks::{solana_keypair::Keypair, solana_signer::SignerError};
    /// #         use solana_message::VersionedMessage;
    /// #         pub struct VersionedTransaction {
    /// #             pub message: solana_message::VersionedMessage,
    /// #         }
    /// #         impl VersionedTransaction {
    /// #             pub fn try_new(
    /// #                 message: VersionedMessage,
    /// #                 _keypairs: &[&Keypair],
    /// #             ) -> std::result::Result<Self, solana_example_mocks::solana_signer::SignerError> {
    /// #                 Ok(VersionedTransaction {
    /// #                     message,
    /// #                 })
    /// #             }
    /// #         }
    /// #     }
    /// # }
    /// use solana_transaction::versioned::VersionedTransaction;
    ///
    /// fn create_v1_tx(
    ///     client: &RpcClient,
    ///     instruction: Instruction,
    ///     payer: &Keypair,
    /// ) -> Result<VersionedTransaction> {
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     let tx = VersionedTransaction::try_new(
    ///         VersionedMessage::V1(v1::Message::try_compile(
    ///             &payer.pubkey(),
    ///             &[instruction],
    ///             blockhash,
    ///         )?),
    ///         &[payer],
    ///     )?;
    ///
    ///     Ok(tx)
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let payer = Keypair::new();
    /// # let instruction = Instruction::new_with_bincode(Address::new_unique(), &(), vec![
    /// #   AccountMeta::new(Address::new_unique(), false),
    /// # ]);
    /// # create_v1_tx(&client, instruction, &payer)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn try_compile(
        payer: &Address,
        instructions: &[Instruction],
        recent_blockhash: Hash,
    ) -> Result<Self, CompileError> {
        Self::try_compile_with_config(
            payer,
            instructions,
            recent_blockhash,
            TransactionConfig::empty(),
        )
    }

    /// Create a signable transaction message from a `payer` public key,
    /// `recent_blockhash`, list of `instructions` and a transaction `config`.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`], [`solana_account`], and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`solana_account`]: https://docs.rs/solana-account
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_example_mocks::{
    /// #     solana_rpc_client,
    /// #     solana_account,
    /// #     solana_signer,
    /// #     solana_keypair,
    /// # };
    /// # use std::borrow::Cow;
    /// # use solana_account::Account;
    /// use anyhow::Result;
    /// use solana_instruction::{AccountMeta, Instruction};
    /// use solana_keypair::Keypair;
    /// use solana_message::{VersionedMessage, v1, v1::TransactionConfig};
    /// use solana_address::Address;
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_signer::Signer;
    /// # mod solana_transaction {
    /// #     pub mod versioned {
    /// #         use solana_example_mocks::{solana_keypair::Keypair, solana_signer::SignerError};
    /// #         use solana_message::VersionedMessage;
    /// #         pub struct VersionedTransaction {
    /// #             pub message: solana_message::VersionedMessage,
    /// #         }
    /// #         impl VersionedTransaction {
    /// #             pub fn try_new(
    /// #                 message: VersionedMessage,
    /// #                 _keypairs: &[&Keypair],
    /// #             ) -> std::result::Result<Self, solana_example_mocks::solana_signer::SignerError> {
    /// #                 Ok(VersionedTransaction {
    /// #                     message,
    /// #                 })
    /// #             }
    /// #         }
    /// #     }
    /// # }
    /// use solana_transaction::versioned::VersionedTransaction;
    ///
    /// fn create_v1_tx(
    ///     client: &RpcClient,
    ///     instruction: Instruction,
    ///     payer: &Keypair,
    /// ) -> Result<VersionedTransaction> {
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     let tx = VersionedTransaction::try_new(
    ///         VersionedMessage::V1(v1::Message::try_compile_with_config(
    ///             &payer.pubkey(),
    ///             &[instruction],
    ///             blockhash,
    ///             TransactionConfig::empty().with_compute_unit_limit(100),
    ///         )?),
    ///         &[payer],
    ///     )?;
    ///
    ///     Ok(tx)
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let payer = Keypair::new();
    /// # let instruction = Instruction::new_with_bincode(Address::new_unique(), &(), vec![
    /// #   AccountMeta::new(Address::new_unique(), false),
    /// # ]);
    /// # create_v1_tx(&client, instruction, &payer)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn try_compile_with_config(
        payer: &Address,
        instructions: &[Instruction],
        recent_blockhash: Hash,
        config: TransactionConfig,
    ) -> Result<Self, CompileError> {
        let compiled_keys = CompiledKeys::compile(instructions, Some(*payer));
        let (header, static_keys) = compiled_keys.try_into_message_components()?;

        let account_keys = AccountKeys::new(&static_keys, None);
        let instructions = account_keys.try_compile_instructions(instructions)?;

        Ok(Self {
            header,
            config,
            lifetime_specifier: recent_blockhash,
            account_keys: static_keys,
            instructions,
        })
    }

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
        crate::is_key_called_as_program(&self.instructions, key_index)
    }

    /// Returns `true` if the account at the specified index was requested to be
    /// writable.
    ///
    /// This method should not be used directly.
    #[inline(always)]
    pub(crate) fn is_writable_index(&self, i: usize) -> bool {
        crate::is_writable_index(i, self.header, &self.account_keys)
    }

    /// Returns true if the BPF upgradeable loader is present in the account keys.
    pub fn is_upgradeable_loader_present(&self) -> bool {
        crate::is_upgradeable_loader_present(&self.account_keys)
    }

    /// Returns `true` if the account at the specified index was requested as
    /// writable.
    ///
    ///
    /// # Important
    ///
    /// Before loading addresses, we can't demote write locks properly so this should
    /// not be used by the runtime. The `reserved_account_keys` parameter is optional
    /// to allow clients to approximate writability without requiring fetching the latest
    /// set of reserved account keys.
    ///
    /// Program accounts are demoted from writable to readonly, unless the upgradeable
    /// loader is present in which case they are left as writable since upgradeable
    /// programs need to be writable for upgrades.
    pub fn is_maybe_writable(
        &self,
        key_index: usize,
        reserved_account_keys: Option<&HashSet<Address>>,
    ) -> bool {
        crate::is_maybe_writable(
            key_index,
            self.header,
            &self.account_keys,
            &self.instructions,
            reserved_account_keys,
        )
    }

    pub fn demote_program_id(&self, i: usize) -> bool {
        crate::is_program_id_write_demoted(i, &self.account_keys, &self.instructions)
    }

    /// Calculate the serialized size of the message in bytes.
    #[allow(clippy::arithmetic_side_effects)]
    #[inline(always)]
    pub fn size(&self) -> usize {
        size_of::<MessageHeader>()                           // legacy header
            + size_of::<TransactionConfigMask>()             // config mask
            + size_of::<Hash>()                              // lifetime specifier
            + size_of::<u8>()                                // number of instructions
            + size_of::<u8>()                                // number of addresses
            + self.account_keys.len() * size_of::<Address>() // addresses
            + self.config.size()                             // config values
            + self.instructions.len()
                * (
                    size_of::<u8>()
                    + size_of::<u8>()
                    + size_of::<u16>()
                )                                            // instruction headers
            + self
                .instructions
                .iter()
                .map(|ix| {
                    (ix.accounts.len() * size_of::<u8>())
                    + ix.data.len()
                })
                .sum::<usize>() // instruction payloads
    }

    pub fn validate(&self) -> Result<(), MessageError> {
        // `num_required_signatures` <= 12
        if self.header.num_required_signatures > MAX_SIGNATURES {
            return Err(MessageError::TooManySignatures);
        }

        // `num_instructions` <= 64
        if self.instructions.len() > MAX_INSTRUCTIONS as usize {
            return Err(MessageError::TooManyInstructions);
        }

        let num_account_keys = self.account_keys.len();

        // `num_addresses` <= 64
        if num_account_keys > MAX_ADDRESSES as usize {
            return Err(MessageError::TooManyAddresses);
        }

        // `num_addresses` >= `num_required_signatures` + `num_readonly_unsigned_accounts`
        let min_accounts = usize::from(self.header.num_required_signatures)
            .saturating_add(usize::from(self.header.num_readonly_unsigned_accounts));

        if num_account_keys < min_accounts {
            return Err(MessageError::NotEnoughAddressesForSignatures);
        }

        // must have at least 1 RW fee-payer (`num_readonly_signed` < `num_required_signatures`)
        if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
            return Err(MessageError::ZeroSigners);
        }

        // no duplicate addresses
        let unique_keys: HashSet<_> = self.account_keys.iter().collect();
        if unique_keys.len() != num_account_keys {
            return Err(MessageError::DuplicateAddresses);
        }

        // validate config mask (2-bit fields must have both bits set or neither)
        let mask: TransactionConfigMask = self.config.into();

        if mask.has_invalid_priority_fee_bits() {
            return Err(MessageError::InvalidConfigMask);
        }

        // heap size must be a multiple of 1024
        if let Some(heap_size) = self.config.heap_size {
            if heap_size % 1024 != 0 {
                return Err(MessageError::InvalidHeapSize);
            }
        }

        // instruction account indices must be < `num_addresses`
        let max_account_index = num_account_keys
            .checked_sub(1)
            .ok_or(MessageError::NotEnoughAccountKeys)?;

        for instruction in &self.instructions {
            // program id must be in static accounts
            if usize::from(instruction.program_id_index) > max_account_index {
                return Err(MessageError::InvalidInstructionAccountIndex);
            }

            // program cannot be fee payer
            if instruction.program_id_index == 0 {
                return Err(MessageError::InvalidInstructionAccountIndex);
            }

            // instruction accounts count must fit in u8
            if instruction.accounts.len() > u8::MAX as usize {
                return Err(MessageError::InstructionAccountsTooLarge);
            }

            // instruction data length must fit in u16
            if instruction.data.len() > u16::MAX as usize {
                return Err(MessageError::InstructionDataTooLarge);
            }

            // all account indices must be valid
            for &account_index in &instruction.accounts {
                if usize::from(account_index) > max_account_index {
                    return Err(MessageError::InvalidInstructionAccountIndex);
                }
            }
        }

        Ok(())
    }
}

impl Sanitize for Message {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        Ok(self.validate()?)
    }
}

#[cfg(feature = "wincode")]
unsafe impl<C: ConfigCore> SchemaWrite<C> for Message {
    type Src = Self;

    #[allow(clippy::arithmetic_side_effects)]
    #[inline(always)]
    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        Ok(src.size())
    }

    // V0 and V1 add +1 for message version prefix
    #[inline(always)]
    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        // SAFETY: Serializing a slice of `[u8]`.
        unsafe {
            writer
                .write_slice_t(&serialize(src))
                .map_err(wincode::WriteError::Io)
        }
    }
}

#[cfg(feature = "wincode")]
unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for Message {
    type Dst = Self;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let bytes = reader.fill_buf(MAX_TRANSACTION_SIZE)?;
        let (message, consumed) = deserialize(bytes).map_err(|_| invalid_tag_encoding(1))?;

        // SAFETY: `deserialize` validates that we read `consumed` bytes.
        unsafe { reader.consume_unchecked(consumed) };

        dst.write(message);

        Ok(())
    }
}

/// Serialize the message.
pub fn serialize(message: &Message) -> Vec<u8> {
    let total = message.size();
    let mut buffer = Vec::<u8>::with_capacity(total);

    // SAFETY: `buffer` has sufficient capacity for serialization.
    unsafe {
        serialize_into(message, buffer.as_mut_ptr());
        buffer.set_len(total);
    }

    buffer
}

/// Serialize the message into the provided buffer.
///
/// # Safety
///
/// The caller must ensure that the provided `dst` pointer has at least
/// `message.size()` bytes of capacity.
pub(crate) unsafe fn serialize_into(message: &Message, mut dst: *mut u8) {
    // header
    dst.write(message.header.num_required_signatures);
    dst = dst.add(1);
    dst.write(message.header.num_readonly_signed_accounts);
    dst = dst.add(1);
    dst.write(message.header.num_readonly_unsigned_accounts);
    dst = dst.add(1);

    // config mask
    let mask = TransactionConfigMask::from(&message.config).0.to_le_bytes();
    copy_nonoverlapping(mask.as_ptr(), dst, mask.len());
    dst = dst.add(mask.len());

    // lifetime specifier
    let lifetime = message.lifetime_specifier.as_ref();
    copy_nonoverlapping(lifetime.as_ptr(), dst, lifetime.len());
    dst = dst.add(lifetime.len());

    // counts
    dst.write(message.instructions.len() as u8);
    dst = dst.add(1);
    dst.write(message.account_keys.len() as u8);
    dst = dst.add(1);

    // addresses
    for addr in &message.account_keys {
        let a = addr.as_ref();
        copy_nonoverlapping(a.as_ptr(), dst, a.len());
        dst = dst.add(a.len());
    }

    // config values
    if let Some(value) = message.config.priority_fee {
        let bytes = value.to_le_bytes();
        copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        dst = dst.add(bytes.len());
    }
    if let Some(value) = message.config.compute_unit_limit {
        let bytes = value.to_le_bytes();
        copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        dst = dst.add(bytes.len());
    }
    if let Some(value) = message.config.loaded_accounts_data_size_limit {
        let bytes = value.to_le_bytes();
        copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        dst = dst.add(bytes.len());
    }
    if let Some(value) = message.config.heap_size {
        let bytes = value.to_le_bytes();
        copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        dst = dst.add(bytes.len());
    }

    // instruction headers
    for ix in &message.instructions {
        dst.write(ix.program_id_index);
        dst = dst.add(1);
        dst.write(ix.accounts.len() as u8);
        dst = dst.add(1);

        let len = (ix.data.len() as u16).to_le_bytes();
        copy_nonoverlapping(len.as_ptr(), dst, 2);
        dst = dst.add(2);
    }

    // instruction payloads
    for ix in &message.instructions {
        copy_nonoverlapping(ix.accounts.as_ptr(), dst, ix.accounts.len());
        dst = dst.add(ix.accounts.len());

        copy_nonoverlapping(ix.data.as_ptr(), dst, ix.data.len());
        dst = dst.add(ix.data.len());
    }
}

/// Deserialize the message from the provided input buffer, returning the message and
/// the number of bytes read.
#[allow(clippy::arithmetic_side_effects)]
pub fn deserialize(input: &[u8]) -> Result<(Message, usize), MessageError> {
    if input.len() < FIXED_HEADER_SIZE {
        return Err(MessageError::BufferTooSmall);
    }

    let mut input_ptr = input.as_ptr();

    // SAFETY: input length has been checked against `FIXED_HEADER_SIZE`.
    let header = unsafe {
        let mut header = MaybeUninit::<MessageHeader>::uninit();
        let dst = header.as_mut_ptr() as *mut u8;

        // num_required_signatures
        dst.write(input_ptr.read());
        // num_readonly_signed_accounts
        dst.add(1).write(input_ptr.add(1).read());
        // num_readonly_unsigned_accounts
        dst.add(2).write(input_ptr.add(2).read());

        // Advance input pointer past header.
        input_ptr = input_ptr.add(3);

        header.assume_init()
    };

    // config mask
    //
    // SAFETY: input length has been checked against `FIXED_HEADER_SIZE`.
    let config_mask = unsafe {
        let mask = TransactionConfigMask(u32::from_le_bytes(*(input_ptr as *const [u8; 4])));
        input_ptr = input_ptr.add(4);

        mask
    };

    // lifetime specifier
    //
    // SAFETY: input length has been checked against `FIXED_HEADER_SIZE`.
    let lifetime_specifier = unsafe {
        let specifier = Hash::new_from_array(*(input_ptr as *const [u8; 32]));
        input_ptr = input_ptr.add(32);

        specifier
    };

    // counts
    //
    // SAFETY: input length has been checked against `FIXED_HEADER_SIZE`.
    let num_instructions = unsafe {
        let num_instructions = input_ptr.read() as usize;
        input_ptr = input_ptr.add(1);

        num_instructions
    };
    // SAFETY: input length has been checked against `FIXED_HEADER_SIZE`.
    let num_addresses = unsafe {
        let num_addresses = input_ptr.read() as usize;
        input_ptr = input_ptr.add(1);

        num_addresses
    };

    // Track the offset for input. This is the value returned to indicate
    // how many bytes were read.
    let mut offset = FIXED_HEADER_SIZE + num_addresses * size_of::<Address>();

    // addresses

    if input.len() < offset {
        return Err(MessageError::BufferTooSmall);
    }

    let mut account_keys = Vec::with_capacity(num_addresses);
    // SAFETY: input length has been checked against the required size
    // for the addresses.
    unsafe {
        let dst = account_keys.as_mut_ptr();
        copy_nonoverlapping(input_ptr as *const Address, dst, num_addresses);
        account_keys.set_len(num_addresses);
        input_ptr = input_ptr.add(num_addresses * size_of::<Address>());
    }

    // config values
    offset += config_mask.size_of_config();

    if input.len() < offset {
        return Err(MessageError::BufferTooSmall);
    }

    let mut config = TransactionConfig::empty();

    if config_mask.has_priority_fee() {
        // SAFETY: input length has been checked against the required size
        // for the config.
        let value = unsafe { u64::from_le_bytes(*(input_ptr as *const [u8; 8])) };
        config = config.with_priority_fee(value);
        input_ptr = unsafe { input_ptr.add(size_of::<u64>()) };
    }

    if config_mask.has_compute_unit_limit() {
        // SAFETY: input length has been checked against the required size
        // for the config.
        let value = unsafe { u32::from_le_bytes(*(input_ptr as *const [u8; 4])) };
        config = config.with_compute_unit_limit(value);
        input_ptr = unsafe { input_ptr.add(size_of::<u32>()) };
    }

    if config_mask.has_loaded_accounts_data_size() {
        // SAFETY: input length has been checked against the required size
        // for the config.
        let value = unsafe { u32::from_le_bytes(*(input_ptr as *const [u8; 4])) };
        config = config.with_loaded_accounts_data_size_limit(value);
        input_ptr = unsafe { input_ptr.add(size_of::<u32>()) };
    }

    if config_mask.has_heap_size() {
        // SAFETY: input length has been checked against the required size
        // for the config.
        let value = unsafe { u32::from_le_bytes(*(input_ptr as *const [u8; 4])) };
        config = config.with_heap_size(value);
        input_ptr = unsafe { input_ptr.add(size_of::<u32>()) };
    }

    // instruction headers

    offset += num_instructions * size_of::<InstructionHeader>();

    if input.len() < offset {
        return Err(MessageError::BufferTooSmall);
    }

    // SAFETY: input length has been checked against the required size
    // for the instruction headers.
    let instruction_headers: &[InstructionHeader] = unsafe {
        core::slice::from_raw_parts(input_ptr as *const InstructionHeader, num_instructions)
    };

    input_ptr = unsafe { input_ptr.add(num_instructions * size_of::<InstructionHeader>()) };

    // instruction payloads

    let mut instructions = Vec::with_capacity(num_instructions);

    for header in instruction_headers {
        let program_id_index = header.0;
        let num_accounts = header.1 as usize;
        let data_len = u16::from_le_bytes(header.2) as usize;

        offset += num_accounts + data_len;

        if input.len() < offset {
            return Err(MessageError::BufferTooSmall);
        }

        // SAFETY: input length has been checked against the required size
        // for the instruction payload.
        let accounts = unsafe { core::slice::from_raw_parts(input_ptr, num_accounts).to_vec() };

        let data = unsafe {
            input_ptr = input_ptr.add(num_accounts);
            core::slice::from_raw_parts(input_ptr, data_len).to_vec()
        };

        input_ptr = unsafe { input_ptr.add(data_len) };

        instructions.push(CompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }

    Ok((
        Message {
            header,
            config,
            lifetime_specifier,
            account_keys,
            instructions,
        },
        offset,
    ))
}

#[cfg(test)]
mod tests {
    use {super::*, solana_sdk_ids::bpf_loader_upgradeable};

    /// Builder for constructing V1 messages.
    ///
    /// This is used in tests to simplify message construction and validation. For
    /// client code, users should construct messages using `try_compile` or
    /// `try_compile_with_config`.
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
        pub fn required_signatures(mut self, count: u8) -> Self {
            self.header.num_required_signatures = count;
            self
        }

        #[must_use]
        pub fn readonly_signed_accounts(mut self, count: u8) -> Self {
            self.header.num_readonly_signed_accounts = count;
            self
        }

        #[must_use]
        pub fn readonly_unsigned_accounts(mut self, count: u8) -> Self {
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
        pub fn account(mut self, key: Address) -> Self {
            self.account_keys.push(key);
            self
        }

        #[must_use]
        pub fn accounts(mut self, keys: Vec<Address>) -> Self {
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

            let message = Message::new(
                self.header,
                self.config,
                lifetime_specifier,
                self.account_keys,
                self.instructions,
            );

            message.validate()?;

            Ok(message)
        }
    }

    fn create_test_message() -> Message {
        MessageBuilder::new()
            .required_signatures(1)
            .readonly_unsigned_accounts(1)
            .lifetime_specifier(Hash::new_unique())
            .accounts(vec![
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
        let message = MessageBuilder::new()
            .required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .accounts(vec![fee_payer, Address::new_unique()])
            .build()
            .unwrap();

        assert_eq!(message.fee_payer(), Some(&fee_payer));
    }

    #[test]
    fn fee_payer_returns_none_for_empty_accounts() {
        // Direct construction to bypass builder validation
        let message = Message::new(
            MessageHeader::default(),
            TransactionConfig::default(),
            Hash::new_unique(),
            vec![],
            vec![],
        );

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
        let message = MessageBuilder::new()
            .required_signatures(3)
            .readonly_signed_accounts(1) // Last signer is readonly
            .lifetime_specifier(Hash::new_unique())
            .accounts(vec![
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
        let message = MessageBuilder::new()
            .required_signatures(2)
            .readonly_signed_accounts(0) // All signers are writable
            .lifetime_specifier(Hash::new_unique())
            .accounts(vec![
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
    fn size_matches_serialized_length() {
        let test_cases = [
            // Minimal message
            MessageBuilder::new()
                .required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .accounts(vec![Address::new_unique()])
                .build()
                .unwrap(),
            // With config
            MessageBuilder::new()
                .required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .accounts(vec![Address::new_unique(), Address::new_unique()])
                .priority_fee(1000)
                .compute_unit_limit(200_000)
                .instruction(CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![1, 2, 3, 4],
                })
                .build()
                .unwrap(),
            // Multiple instructions with varying data
            MessageBuilder::new()
                .required_signatures(2)
                .readonly_signed_accounts(1)
                .readonly_unsigned_accounts(1)
                .lifetime_specifier(Hash::new_unique())
                .accounts(vec![
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                ])
                .heap_size(65536)
                .instructions(vec![
                    CompiledInstruction {
                        program_id_index: 2,
                        accounts: vec![0, 1],
                        data: vec![],
                    },
                    CompiledInstruction {
                        program_id_index: 3,
                        accounts: vec![0, 1, 2],
                        data: vec![0xAA; 100],
                    },
                ])
                .build()
                .unwrap(),
        ];

        for message in &test_cases {
            assert_eq!(message.size(), serialize(message).len());
        }
    }

    #[test]
    fn byte_layout_without_config() {
        let fee_payer = Address::new_from_array([1u8; 32]);
        let program = Address::new_from_array([2u8; 32]);
        let blockhash = Hash::new_from_array([0xAB; 32]);

        let message = MessageBuilder::new()
            .required_signatures(1)
            .lifetime_specifier(blockhash)
            .accounts(vec![fee_payer, program])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0xDE, 0xAD],
            })
            .build()
            .unwrap();

        let bytes = serialize(&message);

        // Build expected bytes manually per SIMD-0385
        //
        // num_required_signatures
        // num_readonly_signed_accounts
        // num_readonly_unsigned_accounts
        let mut expected = vec![1, 0, 0];
        expected.extend_from_slice(&0u32.to_le_bytes()); // ConfigMask = 0
        expected.extend_from_slice(&[0xAB; 32]); // LifetimeSpecifier
        expected.push(1); // NumInstructions
        expected.push(2); // NumAddresses
        expected.extend_from_slice(&[1u8; 32]); // fee_payer
        expected.extend_from_slice(&[2u8; 32]); // program
                                                // ConfigValues: none
        expected.push(1); // program_id_index
        expected.push(1); // num_accounts
        expected.extend_from_slice(&2u16.to_le_bytes()); // data_len
        expected.push(0); // account index 0
        expected.extend_from_slice(&[0xDE, 0xAD]); // data
        assert_eq!(bytes, expected);
    }

    #[test]
    fn byte_layout_with_config() {
        let fee_payer = Address::new_from_array([1u8; 32]);
        let program = Address::new_from_array([2u8; 32]);
        let blockhash = Hash::new_from_array([0xBB; 32]);

        let message = MessageBuilder::new()
            .required_signatures(1)
            .lifetime_specifier(blockhash)
            .accounts(vec![fee_payer, program])
            .priority_fee(0x0102030405060708u64)
            .compute_unit_limit(0x11223344u32)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            })
            .build()
            .unwrap();

        let bytes = serialize(&message);

        let mut expected = vec![1, 0, 0];
        // ConfigMask: priority fee (bits 0,1) + CU limit (bit 2) = 0b111 = 7
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&[0xBB; 32]);
        expected.push(1);
        expected.push(2);
        expected.extend_from_slice(&[1u8; 32]);
        expected.extend_from_slice(&[2u8; 32]);
        // Priority fee as u64 LE
        expected.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        // Compute unit limit as u32 LE
        expected.extend_from_slice(&0x11223344u32.to_le_bytes());
        expected.push(1); // program_id_index
        expected.push(0); // num_accounts
        expected.extend_from_slice(&0u16.to_le_bytes()); // data_len

        assert_eq!(bytes, expected);
    }

    #[test]
    fn roundtrip_preserves_all_config_fields() {
        let message = MessageBuilder::new()
            .required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .accounts(vec![Address::new_unique(), Address::new_unique()])
            .priority_fee(1000)
            .compute_unit_limit(200_000)
            .loaded_accounts_data_size_limit(1_000_000)
            .heap_size(65536)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();

        let serialized = serialize(&message);
        let (deserialized, _) = deserialize(&serialized).unwrap();
        assert_eq!(message.config, deserialized.config);
    }
}
