#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiEnumVisitor, AbiExample};
use {
    crate::{
        compiled_instruction::CompiledInstruction, legacy::Message as LegacyMessage,
        v0::MessageAddressTableLookup, MessageHeader,
    },
    solana_address::Address,
    solana_hash::Hash,
    solana_sanitize::{Sanitize, SanitizeError},
    std::collections::HashSet,
};
#[cfg(feature = "wincode")]
use {
    crate::{
        legacy::MessageUninitBuilder as LegacyMessageUninitBuilder,
        v1::{deserialize, serialize_into},
        MessageHeaderUninitBuilder,
    },
    core::mem::MaybeUninit,
    wincode::{
        config::Config,
        io::{Reader, Writer},
        ReadResult, SchemaRead, SchemaWrite, WriteResult,
    },
};
#[cfg(feature = "serde")]
use {
    serde::{
        de::{self, Deserializer, SeqAccess, Unexpected, Visitor},
        ser::{SerializeTuple, Serializer},
    },
    serde_derive::{Deserialize, Serialize},
    std::fmt,
};

mod sanitized;
pub mod v0;
pub mod v1;

pub use sanitized::*;

/// Bit mask that indicates whether a serialized message is versioned.
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

/// Either a legacy message, v0 or a v1 message.
///
/// # Serialization
///
/// If the first bit is set, the remaining 7 bits will be used to determine
/// which message version is serialized starting from version `0`. If the first
/// is bit is not set, all bytes are used to encode the legacy `Message`
/// format.
#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "6CoVPUxkUvDrAvAkfyVXwVDHCSf77aufm7DEZy5mBVeX"),
    derive(AbiEnumVisitor, AbiExample)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VersionedMessage {
    Legacy(LegacyMessage),
    V0(v0::Message),
    V1(v1::Message),
}

impl VersionedMessage {
    pub fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            Self::Legacy(message) => message.sanitize(),
            Self::V0(message) => message.sanitize(),
            Self::V1(message) => message.sanitize(),
        }
    }

    pub fn header(&self) -> &MessageHeader {
        match self {
            Self::Legacy(message) => &message.header,
            Self::V0(message) => &message.header,
            Self::V1(message) => &message.header,
        }
    }

    pub fn static_account_keys(&self) -> &[Address] {
        match self {
            Self::Legacy(message) => &message.account_keys,
            Self::V0(message) => &message.account_keys,
            Self::V1(message) => &message.account_keys,
        }
    }

    pub fn address_table_lookups(&self) -> Option<&[MessageAddressTableLookup]> {
        match self {
            Self::Legacy(_) => None,
            Self::V0(message) => Some(&message.address_table_lookups),
            Self::V1(_) => None,
        }
    }

    /// Returns true if the account at the specified index signed this
    /// message.
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header().num_required_signatures)
    }

    /// Returns true if the account at the specified index is writable by the
    /// instructions in this message. Since dynamically loaded addresses can't
    /// have write locks demoted without loading addresses, this shouldn't be
    /// used in the runtime.
    pub fn is_maybe_writable(
        &self,
        index: usize,
        reserved_account_keys: Option<&HashSet<Address>>,
    ) -> bool {
        match self {
            Self::Legacy(message) => message.is_maybe_writable(index, reserved_account_keys),
            Self::V0(message) => message.is_maybe_writable(index, reserved_account_keys),
            Self::V1(message) => message.is_maybe_writable(index, reserved_account_keys),
        }
    }

    /// Returns true if the account at the specified index is an input to some
    /// program instruction in this message.
    fn is_instruction_account(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions()
                .iter()
                .any(|ix| ix.accounts.contains(&key_index))
        } else {
            false
        }
    }

    pub fn is_invoked(&self, key_index: usize) -> bool {
        match self {
            Self::Legacy(message) => message.is_key_called_as_program(key_index),
            Self::V0(message) => message.is_key_called_as_program(key_index),
            Self::V1(message) => message.is_key_called_as_program(key_index),
        }
    }

    /// Returns true if the account at the specified index is not invoked as a
    /// program or, if invoked, is passed to a program.
    pub fn is_non_loader_key(&self, key_index: usize) -> bool {
        !self.is_invoked(key_index) || self.is_instruction_account(key_index)
    }

    pub fn recent_blockhash(&self) -> &Hash {
        match self {
            Self::Legacy(message) => &message.recent_blockhash,
            Self::V0(message) => &message.recent_blockhash,
            Self::V1(message) => &message.lifetime_specifier,
        }
    }

    pub fn set_recent_blockhash(&mut self, recent_blockhash: Hash) {
        match self {
            Self::Legacy(message) => message.recent_blockhash = recent_blockhash,
            Self::V0(message) => message.recent_blockhash = recent_blockhash,
            Self::V1(message) => message.lifetime_specifier = recent_blockhash,
        }
    }

    /// Program instructions that will be executed in sequence and committed in
    /// one atomic transaction if all succeed.
    #[inline(always)]
    pub fn instructions(&self) -> &[CompiledInstruction] {
        match self {
            Self::Legacy(message) => &message.instructions,
            Self::V0(message) => &message.instructions,
            Self::V1(message) => &message.instructions,
        }
    }

    #[cfg(feature = "wincode")]
    pub fn serialize(&self) -> Vec<u8> {
        wincode::serialize(self).unwrap()
    }

    #[cfg(all(feature = "wincode", feature = "blake3"))]
    /// Compute the blake3 hash of this transaction's message
    pub fn hash(&self) -> Hash {
        let message_bytes = self.serialize();
        Self::hash_raw_message(&message_bytes)
    }

    #[cfg(feature = "blake3")]
    /// Compute the blake3 hash of a raw transaction message
    pub fn hash_raw_message(message_bytes: &[u8]) -> Hash {
        use blake3::traits::digest::Digest;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"solana-tx-message-v1");
        hasher.update(message_bytes);
        let hash_bytes: [u8; solana_hash::HASH_BYTES] = hasher.finalize().into();
        hash_bytes.into()
    }
}

impl Default for VersionedMessage {
    fn default() -> Self {
        Self::Legacy(LegacyMessage::default())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for VersionedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Legacy(message) => {
                let mut seq = serializer.serialize_tuple(1)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::V0(message) => {
                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&MESSAGE_VERSION_PREFIX)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::V1(message) => {
                // Note that this format does not match the wire format per SIMD-0385.

                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&crate::v1::V1_PREFIX)?;
                seq.serialize_element(message)?;
                seq.end()
            }
        }
    }
}

#[cfg(feature = "serde")]
enum MessagePrefix {
    Legacy(u8),
    Versioned(u8),
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MessagePrefix {
    fn deserialize<D>(deserializer: D) -> Result<MessagePrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrefixVisitor;

        impl Visitor<'_> for PrefixVisitor {
            type Value = MessagePrefix;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message prefix byte")
            }

            // Serde's integer visitors bubble up to u64 so check the prefix
            // with this function instead of visit_u8. This approach is
            // necessary because serde_json directly calls visit_u64 for
            // unsigned integers.
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<MessagePrefix, E> {
                if value > u8::MAX as u64 {
                    Err(de::Error::invalid_type(Unexpected::Unsigned(value), &self))?;
                }

                let byte = value as u8;
                if byte & MESSAGE_VERSION_PREFIX != 0 {
                    Ok(MessagePrefix::Versioned(byte & !MESSAGE_VERSION_PREFIX))
                } else {
                    Ok(MessagePrefix::Legacy(byte))
                }
            }
        }

        deserializer.deserialize_u8(PrefixVisitor)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for VersionedMessage {
    fn deserialize<D>(deserializer: D) -> Result<VersionedMessage, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = VersionedMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<VersionedMessage, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let prefix: MessagePrefix = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match prefix {
                    MessagePrefix::Legacy(num_required_signatures) => {
                        // The remaining fields of the legacy Message struct after the first byte.
                        #[derive(Serialize, Deserialize)]
                        struct RemainingLegacyMessage {
                            pub num_readonly_signed_accounts: u8,
                            pub num_readonly_unsigned_accounts: u8,
                            #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
                            pub account_keys: Vec<Address>,
                            pub recent_blockhash: Hash,
                            #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
                            pub instructions: Vec<CompiledInstruction>,
                        }

                        let message: RemainingLegacyMessage =
                            seq.next_element()?.ok_or_else(|| {
                                // will never happen since tuple length is always 2
                                de::Error::invalid_length(1, &self)
                            })?;

                        Ok(VersionedMessage::Legacy(LegacyMessage {
                            header: MessageHeader {
                                num_required_signatures,
                                num_readonly_signed_accounts: message.num_readonly_signed_accounts,
                                num_readonly_unsigned_accounts: message
                                    .num_readonly_unsigned_accounts,
                            },
                            account_keys: message.account_keys,
                            recent_blockhash: message.recent_blockhash,
                            instructions: message.instructions,
                        }))
                    }
                    MessagePrefix::Versioned(version) => {
                        match version {
                            0 => {
                                Ok(VersionedMessage::V0(seq.next_element()?.ok_or_else(
                                    || {
                                        // will never happen since tuple length is always 2
                                        de::Error::invalid_length(1, &self)
                                    },
                                )?))
                            }
                            1 => {
                                Ok(VersionedMessage::V1(seq.next_element()?.ok_or_else(
                                    || {
                                        // will never happen since tuple length is always 2
                                        de::Error::invalid_length(1, &self)
                                    },
                                )?))
                            }
                            127 => {
                                // 0xff is used as the first byte of the off-chain messages
                                // which corresponds to version 127 of the versioned messages.
                                // This explicit check is added to prevent the usage of version 127
                                // in the runtime as a valid transaction.
                                Err(de::Error::custom("off-chain messages are not accepted"))
                            }
                            _ => Err(de::Error::invalid_value(
                                de::Unexpected::Unsigned(version as u64),
                                &"a valid transaction message version",
                            )),
                        }
                    }
                }
            }
        }

        deserializer.deserialize_tuple(2, MessageVisitor)
    }
}

#[cfg(feature = "wincode")]
unsafe impl<C: Config> SchemaWrite<C> for VersionedMessage {
    type Src = Self;

    // V0 and V1 add +1 for message version prefix
    #[allow(clippy::arithmetic_side_effects)]
    #[inline(always)]
    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        match src {
            VersionedMessage::Legacy(message) => {
                <LegacyMessage as SchemaWrite<C>>::size_of(message)
            }
            VersionedMessage::V0(message) => {
                Ok(1 + <v0::Message as SchemaWrite<C>>::size_of(message)?)
            }
            VersionedMessage::V1(message) => Ok(1 + message.size()),
        }
    }

    // V0 and V1 add +1 for message version prefix
    #[allow(clippy::arithmetic_side_effects)]
    #[inline(always)]
    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        match src {
            VersionedMessage::Legacy(message) => {
                <LegacyMessage as SchemaWrite<C>>::write(writer, message)
            }
            VersionedMessage::V0(message) => {
                <u8 as SchemaWrite<C>>::write(&mut writer, &MESSAGE_VERSION_PREFIX)?;
                <v0::Message as SchemaWrite<C>>::write(writer, message)
            }
            VersionedMessage::V1(message) => {
                let total = message.size();
                let mut buffer: Vec<u8> = Vec::with_capacity(1 + total);
                // SAFETY: buffer has sufficient capacity for serialization.
                unsafe {
                    let ptr = buffer.as_mut_ptr();
                    ptr.write(crate::v1::V1_PREFIX);
                    serialize_into(message, ptr.add(1));
                    buffer.set_len(1 + total);

                    writer
                        .write_slice_t(&buffer)
                        .map_err(wincode::WriteError::Io)
                }
            }
        }
    }
}

#[cfg(feature = "wincode")]
unsafe impl<'de, C: Config> SchemaRead<'de, C> for VersionedMessage {
    type Dst = Self;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        // If the first bit is set, the remaining 7 bits will be used to determine
        // which message version is serialized starting from version `0`. If the first
        // is bit is not set, all bytes are used to encode the legacy `Message`
        // format.
        let variant = <u8 as SchemaRead<C>>::get(&mut reader)?;

        if variant & MESSAGE_VERSION_PREFIX != 0 {
            use wincode::error::invalid_tag_encoding;

            let version = variant & !MESSAGE_VERSION_PREFIX;
            return match version {
                0 => {
                    let msg = <v0::Message as SchemaRead<C>>::get(reader)?;
                    dst.write(VersionedMessage::V0(msg));
                    Ok(())
                }
                1 => {
                    // -1 for already-read variant byte
                    let bytes = reader.fill_buf(v1::MAX_TRANSACTION_SIZE - 1)?;
                    let (message, consumed) =
                        deserialize(bytes).map_err(|_| invalid_tag_encoding(1))?;

                    // SAFETY: `deserialize` validates that we read `consumed` bytes.
                    unsafe { reader.consume_unchecked(consumed) };

                    dst.write(VersionedMessage::V1(message));

                    Ok(())
                }
                _ => Err(invalid_tag_encoding(version as usize)),
            };
        }

        let mut msg = MaybeUninit::<LegacyMessage>::uninit();
        let mut msg_builder = LegacyMessageUninitBuilder::<C>::from_maybe_uninit_mut(&mut msg);
        // We've already read the variant byte which, in the legacy case, represents
        // the `num_required_signatures` field.
        // As such, we need to write the remaining fields into the message manually,
        // as calling `LegacyMessage::read` will miss the first field.
        let mut header_builder =
            MessageHeaderUninitBuilder::<C>::from_maybe_uninit_mut(msg_builder.uninit_header_mut());
        header_builder.write_num_required_signatures(variant);
        header_builder.read_num_readonly_signed_accounts(&mut reader)?;
        header_builder.read_num_readonly_unsigned_accounts(&mut reader)?;
        header_builder.finish();
        unsafe { msg_builder.assume_init_header() };

        msg_builder.read_account_keys(&mut reader)?;
        msg_builder.read_recent_blockhash(&mut reader)?;
        msg_builder.read_instructions(reader)?;
        msg_builder.finish();

        let msg = unsafe { msg.assume_init() };
        dst.write(VersionedMessage::Legacy(msg));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{v0::MessageAddressTableLookup, v1::V1_PREFIX},
        proptest::{
            collection::vec,
            option::of,
            prelude::{any, Just},
            prop_compose, proptest,
            strategy::Strategy,
        },
        solana_instruction::{AccountMeta, Instruction},
    };

    #[derive(Clone, Debug)]
    struct TestMessageData {
        required_signatures: u8,
        lifetime: [u8; 32],
        accounts: Vec<[u8; 32]>,
        priority_fee: Option<u64>,
        compute_unit_limit: Option<u32>,
        loaded_accounts_data_size_limit: Option<u32>,
        heap_size: Option<u32>,
        program_id_index: u8,
        instr_accounts: Vec<u8>,
        data: Vec<u8>,
    }

    #[test]
    fn test_legacy_message_serialization() {
        let program_id0 = Address::new_unique();
        let program_id1 = Address::new_unique();
        let id0 = Address::new_unique();
        let id1 = Address::new_unique();
        let id2 = Address::new_unique();
        let id3 = Address::new_unique();
        let instructions = vec![
            Instruction::new_with_bincode(program_id0, &0, vec![AccountMeta::new(id0, false)]),
            Instruction::new_with_bincode(program_id0, &0, vec![AccountMeta::new(id1, true)]),
            Instruction::new_with_bincode(
                program_id1,
                &0,
                vec![AccountMeta::new_readonly(id2, false)],
            ),
            Instruction::new_with_bincode(
                program_id1,
                &0,
                vec![AccountMeta::new_readonly(id3, true)],
            ),
        ];

        let mut message = LegacyMessage::new(&instructions, Some(&id1));
        message.recent_blockhash = Hash::new_unique();
        let wrapped_message = VersionedMessage::Legacy(message.clone());

        // bincode
        {
            let bytes = bincode::serialize(&message).unwrap();
            assert_eq!(bytes, bincode::serialize(&wrapped_message).unwrap());

            let message_from_bytes: LegacyMessage = bincode::deserialize(&bytes).unwrap();
            let wrapped_message_from_bytes: VersionedMessage =
                bincode::deserialize(&bytes).unwrap();

            assert_eq!(message, message_from_bytes);
            assert_eq!(wrapped_message, wrapped_message_from_bytes);
        }

        // serde_json
        {
            let string = serde_json::to_string(&message).unwrap();
            let message_from_string: LegacyMessage = serde_json::from_str(&string).unwrap();
            assert_eq!(message, message_from_string);
        }
    }

    #[test]
    fn test_versioned_message_serialization() {
        let message = VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            recent_blockhash: Hash::new_unique(),
            account_keys: vec![Address::new_unique()],
            address_table_lookups: vec![
                MessageAddressTableLookup {
                    account_key: Address::new_unique(),
                    writable_indexes: vec![1],
                    readonly_indexes: vec![0],
                },
                MessageAddressTableLookup {
                    account_key: Address::new_unique(),
                    writable_indexes: vec![0],
                    readonly_indexes: vec![1],
                },
            ],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0, 2, 3, 4],
                data: vec![],
            }],
        });

        let bytes = bincode::serialize(&message).unwrap();
        let message_from_bytes: VersionedMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(message, message_from_bytes);

        let string = serde_json::to_string(&message).unwrap();
        let message_from_string: VersionedMessage = serde_json::from_str(&string).unwrap();
        assert_eq!(message, message_from_string);
    }

    prop_compose! {
        fn generate_message_data()
            (
                // Generate between 12 and 64 accounts since we need at least the
                // amount of `required_signatures`.
                accounts in vec(any::<[u8; 32]>(), 12..=64),
                lifetime in any::<[u8; 32]>(),
                priority_fee in of(any::<u64>()),
                compute_unit_limit in of(0..=1_400_000u32),
                loaded_accounts_data_size_limit in of(0..=20_480u32),
                heap_size in of((0..=32u32).prop_map(|n| n.saturating_mul(1024))),
                required_signatures in 1..=12u8,
            )
            (
                // The `program_id_index` cannot be 0 (payer).
                program_id_index in 1u8..accounts.len() as u8,
                // we need to have at least `required_signatures` accounts.
                instr_accounts in vec(
                    0u8..accounts.len() as u8,
                    (required_signatures as usize)..=accounts.len(),
                ),
                // Keep instruction data relatively small to avoid hitting the maximum
                // transaction size when combined with the accounts.
                data in vec(any::<u8>(), 0..=2048),
                accounts in Just(accounts),
                lifetime in Just(lifetime),
                priority_fee in Just(priority_fee),
                compute_unit_limit in Just(compute_unit_limit),
                loaded_accounts_data_size_limit in Just(loaded_accounts_data_size_limit),
                heap_size in Just(heap_size),
                required_signatures in Just(required_signatures),
            ) -> TestMessageData
        {
            TestMessageData {
                required_signatures,
                lifetime,
                accounts,
                priority_fee,
                compute_unit_limit,
                loaded_accounts_data_size_limit,
                heap_size,
                program_id_index,
                instr_accounts,
                data,
            }
        }
    }

    proptest! {
        #[test]
        fn test_v1_message_raw_bytes_roundtrip(test_data in generate_message_data()) {
            let accounts: Vec<Address> = test_data.accounts.into_iter()
                .map(Address::new_from_array).collect();
            let lifetime = Hash::new_from_array(test_data.lifetime);

            let mut builder = v1::MessageBuilder::new()
                .required_signatures(test_data.required_signatures)
                .lifetime_specifier(lifetime)
                .accounts(accounts)
                .instruction(CompiledInstruction {
                    program_id_index: test_data.program_id_index,
                    accounts: test_data.instr_accounts,
                    data: test_data.data,
                });

            // config values.
            if let Some(priority_fee) = test_data.priority_fee {
                builder = builder.priority_fee(priority_fee);
            }
            if let Some(compute_unit_limit) = test_data.compute_unit_limit {
                builder = builder.compute_unit_limit(compute_unit_limit);
            }
            if let Some(loaded_accounts_data_size_limit) = test_data.loaded_accounts_data_size_limit {
                builder = builder.loaded_accounts_data_size_limit(loaded_accounts_data_size_limit);
            }
            if let Some(heap_size) = test_data.heap_size {
                builder = builder.heap_size(heap_size);
            }

            let message = builder.build().unwrap();

            // Serialize V1 to raw bytes.
            let bytes = v1::serialize(&message);
            // Deserialize from raw bytes.
            let (parsed, _) = v1::deserialize(&bytes).unwrap();

            // Messages should match.
            assert_eq!(message, parsed);

            // Wrap in VersionedMessage and test `serialize()`.
            let versioned = VersionedMessage::V1(message);
            let serialized = versioned.serialize();

            // Assert that everything worked:
            // - serialized message is not empty.
            // - first byte is the version prefix with the correct version.
            // - remaining bytes match the original serialized message.
            assert!(!serialized.is_empty());
            assert_eq!(serialized[0], V1_PREFIX);
            assert_eq!(&serialized[1..], bytes.as_slice());
        }
    }

    #[test]
    fn test_v1_versioned_message_json_roundtrip() {
        let msg = v1::MessageBuilder::new()
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
            .unwrap();

        let vm = VersionedMessage::V1(msg);
        let s = serde_json::to_string(&vm).unwrap();
        let back: VersionedMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(vm, back);
    }

    #[cfg(feature = "wincode")]
    #[test]
    fn test_v1_wincode_roundtrip() {
        let test_messages = [
            // Minimal message
            v1::MessageBuilder::new()
                .required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .accounts(vec![Address::new_unique(), Address::new_unique()])
                .instruction(CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![],
                })
                .build()
                .unwrap(),
            // With config
            v1::MessageBuilder::new()
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
            // Multiple instructions
            v1::MessageBuilder::new()
                .required_signatures(2)
                .lifetime_specifier(Hash::new_unique())
                .accounts(vec![
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                ])
                .heap_size(65536)
                .instructions(vec![
                    CompiledInstruction {
                        program_id_index: 2,
                        accounts: vec![0, 1],
                        data: vec![0xAA, 0xBB],
                    },
                    CompiledInstruction {
                        program_id_index: 2,
                        accounts: vec![1],
                        data: vec![0xCC],
                    },
                ])
                .build()
                .unwrap(),
        ];

        for message in test_messages {
            let versioned = VersionedMessage::V1(message.clone());

            // Wincode roundtrip
            let bytes = wincode::serialize(&versioned).expect("Wincode serialize failed");
            let deserialized: VersionedMessage =
                wincode::deserialize(&bytes).expect("Wincode deserialize failed");

            match deserialized {
                VersionedMessage::V1(parsed) => assert_eq!(parsed, message),
                _ => panic!("Expected V1 message"),
            }
        }
    }
}
