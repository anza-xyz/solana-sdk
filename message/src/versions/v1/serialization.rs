//! Serialization and deserialization for V1 messages.
//!
//! This module implements the SIMD-0385 binary format for V1 messages.
//!
//! # Binary Format
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │ Version (u8 = 0x81)                                    │
//! │ LegacyHeader (3 x u8)                                  │
//! │ TransactionConfigMask (u32, little-endian)             │
//! │ LifetimeSpecifier [u8; 32] (blockhash)                 │
//! │ NumInstructions (u8, max 64)                           │
//! │ NumAddresses (u8, max 64)                              │
//! │ Addresses [[u8; 32] x NumAddresses]                    │
//! │ ConfigValues (variable based on mask)                  │
//! │ InstructionHeaders [(u8, u8, u16) x NumInstructions]   │
//! │ InstructionPayloads (concatenated accounts + data)     │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! Note: Signatures are not part of the message. They appear at the end of the
//! full transaction and are handled by `VersionedTransaction`.

use {
    super::{
        Message, MessageError, TransactionConfig, TransactionConfigMask, FIXED_HEADER_SIZE,
        INSTRUCTION_HEADER_SIZE, MAX_ADDRESSES, MAX_INSTRUCTIONS, MAX_SIGNATURES, SIGNATURE_SIZE,
        V1_VERSION_BYTE,
    },
    crate::{compiled_instruction::CompiledInstruction, MessageHeader},
    solana_address::Address,
    solana_hash::Hash,
    std::mem::size_of,
};

/// Read a fixed-size array from a byte slice at the given offset.
fn read_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], MessageError> {
    let end = offset.checked_add(N).ok_or(MessageError::BufferTooSmall)?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(MessageError::BufferTooSmall)
}

impl Message {
    /// Calculate the size of this message in bytes.
    pub fn size(&self) -> usize {
        let addresses_size = self.account_keys.len().saturating_mul(size_of::<Address>());
        let config_size = TransactionConfigMask::from_config(&self.config).config_values_size();
        let instruction_headers_size = self
            .instructions
            .len()
            .saturating_mul(INSTRUCTION_HEADER_SIZE);
        let instruction_payloads_size: usize = self
            .instructions
            .iter()
            .map(|ix| ix.accounts.len().saturating_add(ix.data.len()))
            .fold(0usize, |acc, x| acc.saturating_add(x));

        FIXED_HEADER_SIZE
            .saturating_add(addresses_size)
            .saturating_add(config_size)
            .saturating_add(instruction_headers_size)
            .saturating_add(instruction_payloads_size)
    }

    /// Calculate the total transaction size including signatures.
    pub fn transaction_size(&self) -> usize {
        let signatures_size =
            (self.header.num_required_signatures as usize).saturating_mul(SIGNATURE_SIZE);
        self.size().saturating_add(signatures_size)
    }

    /// Serialize this V1 message to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if self.instructions.len() > MAX_INSTRUCTIONS as usize {
            return Err(MessageError::TooManyInstructions);
        }
        if self.account_keys.len() > MAX_ADDRESSES as usize {
            return Err(MessageError::TooManyAddresses);
        }
        for ix in &self.instructions {
            if ix.accounts.len() > u8::MAX as usize {
                return Err(MessageError::InstructionAccountsTooLarge);
            }
            if ix.data.len() > u16::MAX as usize {
                return Err(MessageError::InstructionDataTooLarge);
            }
        }

        let total_size = self.size();
        let mut bytes = Vec::with_capacity(total_size);
        let config_mask = TransactionConfigMask::from_config(&self.config);

        // Fixed header
        bytes.push(V1_VERSION_BYTE);
        bytes.push(self.header.num_required_signatures);
        bytes.push(self.header.num_readonly_signed_accounts);
        bytes.push(self.header.num_readonly_unsigned_accounts);
        bytes.extend_from_slice(&config_mask.0.to_le_bytes());
        bytes.extend_from_slice(self.lifetime_specifier.as_ref());
        bytes.push(self.instructions.len() as u8);
        bytes.push(self.account_keys.len() as u8);

        // Addresses
        for key in &self.account_keys {
            bytes.extend_from_slice(key.as_ref());
        }

        // Config values (order must match mask bit order)
        if let Some(fee) = self.config.priority_fee {
            bytes.extend_from_slice(&fee.to_le_bytes());
        }
        if let Some(limit) = self.config.compute_unit_limit {
            bytes.extend_from_slice(&limit.to_le_bytes());
        }
        if let Some(limit) = self.config.loaded_accounts_data_size_limit {
            bytes.extend_from_slice(&limit.to_le_bytes());
        }
        if let Some(size) = self.config.heap_size {
            bytes.extend_from_slice(&size.to_le_bytes());
        }

        // Instruction headers (program_id_index, num_accounts, data_len)
        for ix in &self.instructions {
            bytes.push(ix.program_id_index);
            bytes.push(ix.accounts.len() as u8);
            bytes.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        }

        // Instruction payloads (accounts then data, concatenated)
        for ix in &self.instructions {
            bytes.extend_from_slice(&ix.accounts);
            bytes.extend_from_slice(&ix.data);
        }

        Ok(bytes)
    }

    /// Deserialize a V1 message from bytes.
    ///
    /// Use this when parsing a standalone message buffer. Returns an error if
    /// there are unexpected bytes after the message. The input must start with the version byte (0x81).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        let (message, bytes_consumed) = Self::from_bytes_partial(bytes)?;
        if bytes_consumed != bytes.len() {
            return Err(MessageError::TrailingData);
        }
        Ok(message)
    }

    /// Deserialize a V1 message from a byte slice, returning bytes consumed.
    ///
    /// Use this when the message is embedded in a larger buffer, such as when
    /// parsing a V1 transaction where signatures follow the message. The returned
    /// `usize` indicates where the message ends, so you can parse subsequent data.
    /// The input must start with the version byte (0x81).
    pub fn from_bytes_partial(bytes: &[u8]) -> Result<(Self, usize), MessageError> {
        if bytes.len() < FIXED_HEADER_SIZE {
            return Err(MessageError::BufferTooSmall);
        }

        // Track position as we parse each field sequentially.
        // We use saturating_add for offset advances. Overflow produces usize::MAX
        // which will fail the next bounds check with BufferTooSmall.
        let mut offset = 0;

        // Version byte
        if bytes[offset] != V1_VERSION_BYTE {
            return Err(MessageError::InvalidVersion);
        }
        offset = offset.saturating_add(size_of::<u8>());

        // Message header (3 bytes) - bounds already checked via FIXED_HEADER_SIZE
        let header = MessageHeader {
            num_required_signatures: bytes[offset],
            num_readonly_signed_accounts: bytes
                .get(offset.saturating_add(1))
                .copied()
                .ok_or(MessageError::BufferTooSmall)?,
            num_readonly_unsigned_accounts: bytes
                .get(offset.saturating_add(2))
                .copied()
                .ok_or(MessageError::BufferTooSmall)?,
        };
        offset = offset.saturating_add(size_of::<MessageHeader>());

        if header.num_required_signatures > MAX_SIGNATURES {
            return Err(MessageError::TooManySignatures);
        }

        let config_mask = TransactionConfigMask::new(u32::from_le_bytes(read_at(bytes, offset)?));
        offset = offset.saturating_add(size_of::<TransactionConfigMask>());

        if config_mask.has_unknown_bits() || config_mask.has_invalid_priority_fee_bits() {
            return Err(MessageError::InvalidConfigMask);
        }

        let lifetime_specifier = Hash::new_from_array(read_at(bytes, offset)?);
        offset = offset.saturating_add(size_of::<Hash>());

        let num_instructions = *bytes.get(offset).ok_or(MessageError::BufferTooSmall)?;
        offset = offset.saturating_add(size_of::<u8>());
        if num_instructions > MAX_INSTRUCTIONS {
            return Err(MessageError::TooManyInstructions);
        }

        let num_addresses = *bytes.get(offset).ok_or(MessageError::BufferTooSmall)?;
        offset = offset.saturating_add(size_of::<u8>());
        if num_addresses > MAX_ADDRESSES {
            return Err(MessageError::TooManyAddresses);
        }

        // Validate that we have enough addresses for all required signatures
        if header.num_required_signatures > num_addresses {
            return Err(MessageError::NotEnoughAddressesForSignatures);
        }

        // Addresses - use checked_mul for untrusted count, saturating for offset
        let addresses_size = (num_addresses as usize)
            .checked_mul(size_of::<Address>())
            .ok_or(MessageError::BufferTooSmall)?;
        if bytes.len() < offset.saturating_add(addresses_size) {
            return Err(MessageError::BufferTooSmall);
        }

        let mut account_keys = Vec::with_capacity(num_addresses as usize);
        for _ in 0..num_addresses {
            account_keys.push(Address::new_from_array(read_at(bytes, offset)?));
            offset = offset.saturating_add(size_of::<Address>());
        }

        // Config values - parsed in bit order per SIMD-0385 wire format
        let config_size = config_mask.config_values_size();
        if bytes.len() < offset.saturating_add(config_size) {
            return Err(MessageError::BufferTooSmall);
        }

        let mut config = TransactionConfig::default();
        if config_mask.has_priority_fee() {
            config.priority_fee = Some(u64::from_le_bytes(read_at(bytes, offset)?));
            offset = offset.saturating_add(size_of::<u64>());
        }
        if config_mask.has_compute_unit_limit() {
            config.compute_unit_limit = Some(u32::from_le_bytes(read_at(bytes, offset)?));
            offset = offset.saturating_add(size_of::<u32>());
        }
        if config_mask.has_loaded_accounts_data_size() {
            config.loaded_accounts_data_size_limit =
                Some(u32::from_le_bytes(read_at(bytes, offset)?));
            offset = offset.saturating_add(size_of::<u32>());
        }
        if config_mask.has_heap_size() {
            let heap_size = u32::from_le_bytes(read_at(bytes, offset)?);
            if heap_size % 1024 != 0 {
                return Err(MessageError::InvalidHeapSize);
            }
            config.heap_size = Some(heap_size);
            offset = offset.saturating_add(size_of::<u32>());
        }

        // Instruction headers: (program_id_index: u8, num_accounts: u8, data_len: u16)
        let instruction_headers_size = (num_instructions as usize)
            .checked_mul(INSTRUCTION_HEADER_SIZE)
            .ok_or(MessageError::BufferTooSmall)?;
        if bytes.len() < offset.saturating_add(instruction_headers_size) {
            return Err(MessageError::BufferTooSmall);
        }

        let mut instruction_headers = Vec::with_capacity(num_instructions as usize);
        for _ in 0..num_instructions {
            let program_id_index = *bytes.get(offset).ok_or(MessageError::BufferTooSmall)?;
            // Validate program_id_index: must be < num_addresses and != 0 (fee payer)
            if program_id_index == 0 || program_id_index >= num_addresses {
                return Err(MessageError::InvalidProgramIdIndex);
            }
            let num_accounts = *bytes
                .get(offset.saturating_add(1))
                .ok_or(MessageError::BufferTooSmall)?;
            let num_data_bytes = u16::from_le_bytes(read_at(bytes, offset.saturating_add(2))?);
            instruction_headers.push((program_id_index, num_accounts, num_data_bytes));
            offset = offset.saturating_add(INSTRUCTION_HEADER_SIZE);
        }

        // Instruction payloads
        let mut instructions = Vec::with_capacity(num_instructions as usize);
        for (program_id_index, num_accounts, num_data_bytes) in instruction_headers {
            let accounts_size = num_accounts as usize;
            let data_size = num_data_bytes as usize;
            let payload_size = accounts_size.saturating_add(data_size);

            if bytes.len() < offset.saturating_add(payload_size) {
                return Err(MessageError::BufferTooSmall);
            }

            let accounts_end = offset.saturating_add(accounts_size);
            let accounts = bytes[offset..accounts_end].to_vec();
            // Validate all account indices are < num_addresses
            for &account_index in &accounts {
                if account_index >= num_addresses {
                    return Err(MessageError::InvalidInstructionAccountIndex);
                }
            }
            offset = accounts_end;

            let data_end = offset.saturating_add(data_size);
            let data = bytes[offset..data_end].to_vec();
            offset = data_end;

            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data,
            });
        }

        Ok((
            Self {
                header,
                lifetime_specifier,
                account_keys,
                config,
                instructions,
            },
            offset,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::vec_init_then_push)]
mod tests {
    use {
        super::*,
        proptest::prelude::*,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash as StdHash, Hasher},
        },
    };

    #[test]
    fn size_matches_serialized_length() {
        let test_cases = [
            // Minimal message
            Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![Address::new_unique()])
                .build()
                .unwrap(),
            // With config
            Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![Address::new_unique(), Address::new_unique()])
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
            Message::builder()
                .num_required_signatures(2)
                .num_readonly_signed_accounts(1)
                .num_readonly_unsigned_accounts(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![
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
            assert_eq!(message.size(), message.to_bytes().unwrap().len());
        }
    }

    #[test]
    fn transaction_size_includes_signatures() {
        // Note: num_sigs must be >= 1 (fee payer required)
        for num_sigs in [1u8, 2, 5, 12] {
            let message = Message::builder()
                .num_required_signatures(num_sigs)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(
                    (0..num_sigs as usize)
                        .map(|_| Address::new_unique())
                        .collect(),
                )
                .build()
                .unwrap();

            let expected = message.size() + (num_sigs as usize * 64);
            assert_eq!(message.transaction_size(), expected);
        }
    }

    #[test]
    fn byte_layout_without_config() {
        let fee_payer = Address::new_from_array([1u8; 32]);
        let program = Address::new_from_array([2u8; 32]);
        let blockhash = Hash::new_from_array([0xAB; 32]);

        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(blockhash)
            .account_keys(vec![fee_payer, program])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0xDE, 0xAD],
            })
            .build()
            .unwrap();

        let bytes = message.to_bytes().unwrap();

        // Build expected bytes manually per SIMD-0385
        let mut expected = Vec::new();
        expected.push(0x81); // Version
        expected.push(1); // num_required_signatures
        expected.push(0); // num_readonly_signed_accounts
        expected.push(0); // num_readonly_unsigned_accounts
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

        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(blockhash)
            .account_keys(vec![fee_payer, program])
            .priority_fee(0x0102030405060708u64)
            .compute_unit_limit(0x11223344u32)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            })
            .build()
            .unwrap();

        let bytes = message.to_bytes().unwrap();

        let mut expected = Vec::new();
        expected.push(0x81);
        expected.push(1);
        expected.push(0);
        expected.push(0);
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
    fn byte_layout_with_multiple_instructions() {
        let fee_payer = Address::new_from_array([1u8; 32]);
        let program1 = Address::new_from_array([2u8; 32]);
        let program2 = Address::new_from_array([3u8; 32]);
        let blockhash = Hash::new_from_array([0xCC; 32]);

        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(blockhash)
            .account_keys(vec![fee_payer, program1, program2])
            .instructions(vec![
                CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![0xAA],
                },
                CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![0, 1],
                    data: vec![0xBB, 0xCC, 0xDD],
                },
            ])
            .build()
            .unwrap();

        let bytes = message.to_bytes().unwrap();

        let mut expected = Vec::new();
        expected.push(0x81);
        expected.push(1);
        expected.push(0);
        expected.push(0);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&[0xCC; 32]);
        expected.push(2); // NumInstructions
        expected.push(3); // NumAddresses
        expected.extend_from_slice(&[1u8; 32]);
        expected.extend_from_slice(&[2u8; 32]);
        expected.extend_from_slice(&[3u8; 32]);
        // Instruction headers
        expected.push(1);
        expected.push(1);
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.push(2);
        expected.push(2);
        expected.extend_from_slice(&3u16.to_le_bytes());
        // Instruction payloads
        expected.push(0);
        expected.push(0xAA);
        expected.push(0);
        expected.push(1);
        expected.extend_from_slice(&[0xBB, 0xCC, 0xDD]);

        assert_eq!(bytes, expected);
    }

    #[test]
    fn from_bytes_rejects_empty_buffer() {
        assert_eq!(Message::from_bytes(&[]), Err(MessageError::BufferTooSmall));
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_from_array([0xAB; 32]))
            .account_keys(vec![
                Address::new_from_array([1u8; 32]),
                Address::new_from_array([2u8; 32]),
            ])
            .compute_unit_limit(200_000)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0xDE, 0xAD],
            })
            .build()
            .unwrap();

        let bytes = message.to_bytes().unwrap();

        for i in 0..bytes.len() {
            let truncated = &bytes[..i];
            let err = Message::from_bytes(truncated).unwrap_err();
            assert!(matches!(
                err,
                MessageError::BufferTooSmall | MessageError::InvalidVersion
            ));
        }

        assert!(Message::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn from_bytes_rejects_invalid_version() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .build()
            .unwrap();

        let mut bytes = message.to_bytes().unwrap();

        for bad_version in [0x00, 0x80, 0x82, 0xFF] {
            bytes[0] = bad_version;
            assert_eq!(
                Message::from_bytes(&bytes),
                Err(MessageError::InvalidVersion)
            );
        }
    }

    #[test]
    fn from_bytes_rejects_over_12_signatures() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(MAX_SIGNATURES + 1); // too many
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // config mask
        bytes.extend_from_slice(&[0u8; 32]); // lifetime_specifier
        bytes.push(0); // num_instructions
        bytes.push(1); // num_addresses

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::TooManySignatures)
        );
    }

    #[test]
    fn from_bytes_rejects_invalid_priority_fee_mask() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&1u32.to_le_bytes()); // INVALID: only bit 0
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(1);
        bytes.push(2);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(1);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidConfigMask)
        );

        // Also test only bit 1 set
        bytes[4] = 2;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 0;
        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidConfigMask)
        );
    }

    #[test]
    fn from_bytes_rejects_unknown_config_mask_bits() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0x00010000u32.to_le_bytes()); // Unknown high bit
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(0);
        bytes.push(1);
        bytes.extend_from_slice(&[1u8; 32]);

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidConfigMask)
        );
    }

    #[test]
    fn from_bytes_rejects_over_64_instructions() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(MAX_INSTRUCTIONS + 1); // too many (65)
        bytes.push(1);
        bytes.extend_from_slice(&[1u8; 32]);

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::TooManyInstructions)
        );
    }

    #[test]
    fn from_bytes_rejects_over_64_addresses() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(0);
        bytes.push(MAX_ADDRESSES + 1); // too many

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::TooManyAddresses)
        );
    }

    #[test]
    fn from_bytes_rejects_not_enough_addresses_for_signatures() {
        // Build bytes manually: claims 5 signers but only has 2 addresses
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(5); // num_required_signatures = 5
        bytes.push(0); // num_readonly_signed
        bytes.push(0); // num_readonly_unsigned
        bytes.extend_from_slice(&0u32.to_le_bytes()); // config mask
        bytes.extend_from_slice(&[0xAB; 32]); // lifetime_specifier
        bytes.push(0); // num_instructions
        bytes.push(2); // num_addresses = 2 (less than 5!)
        bytes.extend_from_slice(&[1u8; 32]); // address 1
        bytes.extend_from_slice(&[2u8; 32]); // address 2

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::NotEnoughAddressesForSignatures)
        );
    }

    #[test]
    fn from_bytes_rejects_unaligned_heap_size() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1); // num_required_signatures
        bytes.push(0); // num_readonly_signed
        bytes.push(0); // num_readonly_unsigned
        bytes.extend_from_slice(&TransactionConfigMask::HEAP_SIZE_BIT.to_le_bytes());
        bytes.extend_from_slice(&[1u8; 32]); // lifetime_specifier
        bytes.push(0); // num_instructions
        bytes.push(1); // num_addresses
        bytes.extend_from_slice(&[1u8; 32]); // one address
        bytes.extend_from_slice(&1025u32.to_le_bytes()); // heap_size not multiple of 1024

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidHeapSize)
        );
    }

    #[test]
    fn from_bytes_rejects_program_id_index_zero() {
        // program_id_index == 0 means fee payer is program, which is invalid
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1); // 1 signer
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no config
        bytes.extend_from_slice(&[0xAB; 32]); // blockhash
        bytes.push(1); // 1 instruction
        bytes.push(2); // 2 addresses
        bytes.extend_from_slice(&[1u8; 32]); // fee_payer
        bytes.extend_from_slice(&[2u8; 32]); // program
        bytes.push(0); // INVALID: program_id_index = 0 (fee payer)
        bytes.push(0); // num_accounts
        bytes.extend_from_slice(&0u16.to_le_bytes()); // data_len

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidProgramIdIndex)
        );
    }

    #[test]
    fn from_bytes_rejects_program_id_index_out_of_bounds() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 32]);
        bytes.push(1); // 1 instruction
        bytes.push(2); // 2 addresses
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.push(5); // INVALID: program_id_index = 5 >= num_addresses (2)
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidProgramIdIndex)
        );
    }

    #[test]
    fn from_bytes_rejects_instruction_account_index_out_of_bounds() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 32]);
        bytes.push(1); // 1 instruction
        bytes.push(2); // 2 addresses
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.push(1); // valid program_id_index
        bytes.push(1); // 1 account
        bytes.extend_from_slice(&0u16.to_le_bytes()); // 0 data bytes
        bytes.push(10); // INVALID: account index 10 >= num_addresses (2)

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::InvalidInstructionAccountIndex)
        );
    }

    #[test]
    fn from_bytes_rejects_trailing_data() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_from_array([0xAB; 32]))
            .account_keys(vec![
                Address::new_from_array([1u8; 32]),
                Address::new_from_array([2u8; 32]),
            ])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            })
            .build()
            .unwrap();

        let bytes = message.to_bytes().unwrap();
        assert!(Message::from_bytes(&bytes).is_ok());

        let mut with_trailing = bytes.clone();
        with_trailing.push(0xFF);
        assert_eq!(
            Message::from_bytes(&with_trailing),
            Err(MessageError::TrailingData)
        );
    }

    #[test]
    fn from_bytes_accepts_64_instructions() {
        // Build a valid message with 64 instructions (max per SIMD-0385)
        let num_instructions: u8 = MAX_INSTRUCTIONS;
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1); // num_required_signatures
        bytes.push(0); // num_readonly_signed
        bytes.push(0); // num_readonly_unsigned
        bytes.extend_from_slice(&0u32.to_le_bytes()); // config mask
        bytes.extend_from_slice(&[0xAB; 32]); // lifetime_specifier
        bytes.push(num_instructions); // num_instructions = 64
        bytes.push(2); // num_addresses
        bytes.extend_from_slice(&[1u8; 32]); // fee_payer
        bytes.extend_from_slice(&[2u8; 32]); // program

        // Instruction headers: all point to program (index 1), zero accounts, zero data
        for _ in 0..num_instructions {
            bytes.push(1); // program_id_index
            bytes.push(0); // num_accounts
            bytes.extend_from_slice(&0u16.to_le_bytes()); // data_len
        }
        // No instruction payloads needed (all have 0 accounts and 0 data)

        let result = Message::from_bytes(&bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().instructions.len(), 64);
    }

    #[test]
    fn from_bytes_rejects_65_instructions() {
        let mut bytes = Vec::new();
        bytes.push(V1_VERSION_BYTE);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 32]);
        bytes.push(65); // num_instructions = 65 (exceeds max 64 per SIMD-0385)
        bytes.push(2);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);

        assert_eq!(
            Message::from_bytes(&bytes),
            Err(MessageError::TooManyInstructions)
        );
    }

    #[test]
    fn roundtrip_preserves_message() {
        let message = Message::builder()
            .num_required_signatures(1)
            .num_readonly_unsigned_accounts(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
            ])
            .compute_unit_limit(200_000)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0, 2],
                data: vec![1, 2, 3, 4],
            })
            .build()
            .unwrap();
        let serialized = message.to_bytes().unwrap();
        let deserialized = Message::from_bytes(&serialized).unwrap();

        assert_eq!(message.header, deserialized.header);
        assert_eq!(message.lifetime_specifier, deserialized.lifetime_specifier);
        assert_eq!(message.account_keys, deserialized.account_keys);
        assert_eq!(message.config, deserialized.config);
        assert_eq!(message.instructions, deserialized.instructions);
    }

    #[test]
    fn roundtrip_preserves_all_config_fields() {
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
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

        let serialized = message.to_bytes().unwrap();
        let deserialized = Message::from_bytes(&serialized).unwrap();
        assert_eq!(message.config, deserialized.config);
    }

    #[test]
    fn roundtrip_preserves_sparse_config() {
        // Test each config field individually
        let configs = [
            TransactionConfig::new().with_priority_fee(1000),
            TransactionConfig::new().with_compute_unit_limit(200_000),
            TransactionConfig::new().with_loaded_accounts_data_size_limit(1_000_000),
            TransactionConfig::new().with_heap_size(65536),
        ];

        for config in configs {
            let message = Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![Address::new_unique(), Address::new_unique()])
                .config(config)
                .instruction(CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![],
                    data: vec![],
                })
                .build()
                .unwrap();

            let bytes = message.to_bytes().unwrap();
            let parsed = Message::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.config, config);
        }

        // Test gap combinations (skipping fields)
        let gap_configs = [
            TransactionConfig::new()
                .with_compute_unit_limit(200_000)
                .with_heap_size(65536),
            TransactionConfig::new()
                .with_priority_fee(5000)
                .with_loaded_accounts_data_size_limit(500_000),
            TransactionConfig::new()
                .with_priority_fee(1000)
                .with_heap_size(32768),
        ];

        for config in gap_configs {
            let message = Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![Address::new_unique(), Address::new_unique()])
                .config(config)
                .instruction(CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![],
                    data: vec![],
                })
                .build()
                .unwrap();

            let bytes = message.to_bytes().unwrap();
            let parsed = Message::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.config, config);
        }
    }

    #[test]
    fn roundtrip_handles_empty_instructions() {
        // Zero instructions, minimal addresses
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique()])
            .build()
            .unwrap();
        let bytes = message.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert!(parsed.instructions.is_empty());

        // Instruction with zero accounts and zero data
        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            })
            .build()
            .unwrap();
        let bytes = message.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert!(parsed.instructions[0].accounts.is_empty());
        assert!(parsed.instructions[0].data.is_empty());
    }

    #[test]
    fn from_bytes_partial_returns_bytes_consumed() {
        let message = Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();

        let message_bytes = message.to_bytes().unwrap();
        let message_len = message_bytes.len();

        // Append fake signatures (64 bytes each)
        let mut buf = message_bytes.clone();
        buf.extend_from_slice(&[0xAA; 64]);
        buf.extend_from_slice(&[0xBB; 64]);

        // from_bytes should reject trailing data
        assert_eq!(Message::from_bytes(&buf), Err(MessageError::TrailingData));

        // from_bytes_partial should succeed
        let (parsed, bytes_consumed) = Message::from_bytes_partial(&buf).unwrap();
        assert_eq!(bytes_consumed, message_len);
        assert_eq!(parsed.header, message.header);
        assert_eq!(parsed.account_keys, message.account_keys);

        // Verify we can locate signatures after the message
        assert_eq!(&buf[bytes_consumed..bytes_consumed + 64], &[0xAA; 64]);
        assert_eq!(&buf[bytes_consumed + 64..bytes_consumed + 128], &[0xBB; 64]);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1000)) {
            // Parser should never panic on arbitrary input
            let _ = Message::from_bytes(&bytes);
        }

        #[test]
        fn arbitrary_bytes_with_valid_prefix_never_panic(
            rest in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            // Even with valid version byte, parser should handle garbage gracefully
            let mut bytes = vec![V1_VERSION_BYTE];
            bytes.extend(rest);
            let _ = Message::from_bytes(&bytes);
        }

        #[test]
        fn roundtrip_preserves_valid_messages(
            num_keys in 2usize..=10,
            num_instructions in 0usize..=5,
            seed in any::<u64>(),
        ) {
            // Use seed to generate deterministic but varied data
            let mut hasher = DefaultHasher::new();
            seed.hash(&mut hasher);
            let hash_val = hasher.finish();

            let account_keys: Vec<Address> = (0..num_keys)
                .map(|i| {
                    let mut addr = [0u8; 32];
                    addr[0..8].copy_from_slice(&(hash_val.wrapping_add(i as u64)).to_le_bytes());
                    addr[8] = i as u8;
                    Address::new_from_array(addr)
                })
                .collect();

            let instructions: Vec<CompiledInstruction> = (0..num_instructions)
                .map(|i| CompiledInstruction {
                    program_id_index: 1, // Always use index 1 as program
                    accounts: vec![0], // Fee payer
                    data: vec![(i % 256) as u8; i % 100], // Varied data
                })
                .collect();

            let message = Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_from_array([hash_val as u8; 32]))
                .account_keys(account_keys)
                .instructions(instructions)
                .build()
                .unwrap();

            let bytes = message.to_bytes().unwrap();
            let parsed = Message::from_bytes(&bytes).unwrap();

            prop_assert_eq!(message.header, parsed.header);
            prop_assert_eq!(message.lifetime_specifier, parsed.lifetime_specifier);
            prop_assert_eq!(message.account_keys, parsed.account_keys);
            prop_assert_eq!(message.config, parsed.config);
            prop_assert_eq!(message.instructions, parsed.instructions);
        }

        #[test]
        fn truncated_valid_message_fails(
            truncate_at in 1usize..200
        ) {
            // Create a valid message
            let message = Message::builder()
                .num_required_signatures(2)
                .lifetime_specifier(Hash::new_from_array([0xCC; 32]))
                .account_keys(vec![
                    Address::new_from_array([1u8; 32]),
                    Address::new_from_array([2u8; 32]),
                    Address::new_from_array([3u8; 32]),
                ])
                .priority_fee(1000)
                .compute_unit_limit(200_000)
                .instruction(CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![0, 1],
                    data: vec![0xAA; 50],
                })
                .build()
                .unwrap();

            let bytes = message.to_bytes().unwrap();
            let truncate_pos = truncate_at.min(bytes.len().saturating_sub(1));

            if truncate_pos < bytes.len() {
                let truncated = &bytes[..truncate_pos];
                let result = Message::from_bytes(truncated);
                // Should fail, not panic
                prop_assert!(result.is_err());
            }
        }
    }
}
