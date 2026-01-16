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
        legacy::MessageUninitBuilder as LegacyMessageUninitBuilder, MessageHeaderUninitBuilder,
    },
    core::mem::MaybeUninit,
    wincode::{
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

/// Either a legacy message, v0 message, or v1 message.
///
/// # Serialization
///
/// If the first bit is set, the remaining 7 bits will be used to determine
/// which message version is serialized starting from version `0`. If the first
/// is bit is not set, all bytes are used to encode the legacy `Message`
/// format.
#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "3FVVnsLRS9Ue7MwhQPLxod48B1HxvDuX4nt4UhKV4jcs"),
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
    pub fn instructions(&self) -> &[CompiledInstruction] {
        match self {
            Self::Legacy(message) => &message.instructions,
            Self::V0(message) => &message.instructions,
            Self::V1(message) => &message.instructions,
        }
    }

    #[cfg(feature = "bincode")]
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Legacy(_) | Self::V0(_) => bincode::serialize(self).unwrap(),
            Self::V1(message) => message
                .to_bytes()
                .expect("V1 message exceeds serialization limits"),
        }
    }

    #[cfg(all(feature = "bincode", feature = "blake3"))]
    /// Compute the blake3 hash of this transaction's message
    pub fn hash(&self) -> Hash {
        let message_bytes = self.serialize();
        Self::hash_raw_message(&message_bytes)
    }

    #[cfg(feature = "blake3")]
    /// Compute the blake3 hash of a raw transaction message
    ///
    /// Automatically detects the message version from the first byte and
    /// applies the appropriate domain separator:
    /// - Legacy (first byte < 0x80): no domain prefix
    /// - V0 (first byte == 0x80): `solana-tx-message-v0`
    /// - V1 (first byte == 0x81): `solana-tx-message-v1`
    pub fn hash_raw_message(message_bytes: &[u8]) -> Hash {
        use blake3::traits::digest::Digest;

        let mut hasher = blake3::Hasher::new();

        if let Some(&first_byte) = message_bytes.first() {
            if first_byte & MESSAGE_VERSION_PREFIX != 0 {
                let version = first_byte & !MESSAGE_VERSION_PREFIX;
                match version {
                    0 => hasher.update(b"solana-tx-message-v0"),
                    1 => hasher.update(b"solana-tx-message-v1"),
                    // Unknown versioned message - use version number in prefix
                    v => hasher.update(format!("solana-tx-message-v{v}").as_bytes()),
                };
            }
            // Legacy messages (first byte < 0x80) get no domain prefix
        }

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
                if serializer.is_human_readable() {
                    // JSON: encode as (0x81, { ...message fields... })
                    let mut seq = serializer.serialize_tuple(2)?;
                    seq.serialize_element(&(MESSAGE_VERSION_PREFIX | 1))?;
                    seq.serialize_element(message)?;
                    seq.end()
                } else {
                    // Binary formats like bincode: V1 messages cannot be serialized via bincode
                    // because the wire format (per SIMD-0385) is incompatible with bincode's
                    // data model. Use `VersionedMessage::serialize()` to get the correct wire bytes.
                    Err(serde::ser::Error::custom(
                        "V1 messages cannot be serialized via bincode. Use VersionedMessage::serialize() for wire bytes.",
                    ))
                }
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
        struct MessageVisitor {
            human_readable: bool,
        }

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
                                if self.human_readable {
                                    Ok(VersionedMessage::V1(
                                        seq.next_element()?
                                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                                    ))
                                } else {
                                    // V1 messages cannot be deserialized via bincode
                                    // because the wire format (per SIMD-0385) is incompatible.
                                    // Use `v1::Message::from_bytes()` to parse wire-format bytes.
                                    Err(de::Error::custom(
                                        "V1 messages cannot be serialized via bincode. Use VersionedMessage::serialize() for wire bytes.",
                                    ))
                                }
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

        let human_readable = deserializer.is_human_readable();
        deserializer.deserialize_tuple(2, MessageVisitor { human_readable })
    }
}

#[cfg(feature = "wincode")]
impl SchemaWrite for VersionedMessage {
    type Src = Self;

    #[inline(always)]
    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        match src {
            VersionedMessage::Legacy(message) => LegacyMessage::size_of(message),
            // +1 for message version prefix
            #[expect(clippy::arithmetic_side_effects)]
            VersionedMessage::V0(message) => Ok(1 + v0::Message::size_of(message)?),
            // V1 uses custom binary format (no bincode dependency)
            VersionedMessage::V1(message) => Ok(message
                .to_bytes()
                .expect("V1 message exceeds serialization limits")
                .len()),
        }
    }

    #[inline(always)]
    fn write(writer: &mut impl Writer, src: &Self::Src) -> WriteResult<()> {
        match src {
            VersionedMessage::Legacy(message) => LegacyMessage::write(writer, message),
            VersionedMessage::V0(message) => {
                u8::write(writer, &MESSAGE_VERSION_PREFIX)?;
                v0::Message::write(writer, message)
            }
            // V1 uses custom binary format (no bincode dependency)
            VersionedMessage::V1(message) => {
                for byte in message
                    .to_bytes()
                    .expect("V1 message exceeds serialization limits")
                {
                    u8::write(writer, &byte)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "wincode")]
impl<'de> SchemaRead<'de> for VersionedMessage {
    type Dst = Self;

    fn read(reader: &mut impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        // If the first bit is set, the remaining 7 bits will be used to determine
        // which message version is serialized starting from version `0`. If the first
        // is bit is not set, all bytes are used to encode the legacy `Message`
        // format.
        let variant = u8::get(reader)?;

        if variant & MESSAGE_VERSION_PREFIX != 0 {
            use wincode::error::invalid_tag_encoding;

            let version = variant & !MESSAGE_VERSION_PREFIX;
            return match version {
                0 => {
                    let msg = v0::Message::get(reader)?;
                    dst.write(VersionedMessage::V0(msg));
                    Ok(())
                }
                1 => {
                    // V1 uses a custom binary format. Peek available bytes,
                    // prepend version byte, and delegate to from_bytes_partial
                    // which handles all parsing and returns bytes consumed.
                    use v1::MAX_TRANSACTION_SIZE;

                    // Peek up to max message size (minus version byte already read)
                    let mut bytes = vec![variant]; // 0x81 version byte
                    bytes.extend_from_slice(reader.fill_buf(MAX_TRANSACTION_SIZE - 1)?);

                    // Parse - from_bytes_partial tells us actual consumed size
                    let (msg, consumed) = v1::Message::from_bytes_partial(&bytes)
                        .map_err(|_| invalid_tag_encoding(1))?;

                    // Advance reader by message size (minus version byte)
                    reader.consume(consumed.saturating_sub(1))?;
                    dst.write(VersionedMessage::V1(msg));
                    Ok(())
                }
                _ => Err(invalid_tag_encoding(version as usize)),
            };
        }

        let mut msg = MaybeUninit::<LegacyMessage>::uninit();
        let mut msg_builder = LegacyMessageUninitBuilder::from_maybe_uninit_mut(&mut msg);
        // We've already read the variant byte which, in the legacy case, represents
        // the `num_required_signatures` field.
        // As such, we need to write the remaining fields into the message manually,
        // as calling `LegacyMessage::read` will miss the first field.
        let mut header_builder =
            MessageHeaderUninitBuilder::from_maybe_uninit_mut(msg_builder.uninit_header_mut());
        header_builder.write_num_required_signatures(variant);
        header_builder.read_num_readonly_signed_accounts(reader)?;
        header_builder.read_num_readonly_unsigned_accounts(reader)?;
        header_builder.finish();
        unsafe { msg_builder.assume_init_header() };

        msg_builder.read_account_keys(reader)?;
        msg_builder.read_recent_blockhash(reader)?;
        msg_builder.read_instructions(reader)?;
        msg_builder.finish();

        let msg = unsafe { msg.assume_init() };
        dst.write(VersionedMessage::Legacy(msg));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "blake3")]
    use blake3::traits::digest::Digest;
    use {
        super::*,
        crate::v0::MessageAddressTableLookup,
        solana_instruction::{AccountMeta, Instruction},
    };

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

    #[test]
    fn test_v1_message_raw_bytes_roundtrip() {
        let message = v1::Message::builder()
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
            .unwrap();

        // Serialize V1 to raw bytes
        let bytes = message.to_bytes().unwrap();

        // Deserialize from raw bytes
        let parsed = v1::Message::from_bytes(&bytes).unwrap();
        assert_eq!(message, parsed);

        // Wrap in VersionedMessage and test serialize()
        let versioned = VersionedMessage::V1(message.clone());
        let serialized = versioned.serialize();
        assert_eq!(serialized, bytes);
    }

    #[test]
    fn test_v1_versioned_message_json_roundtrip() {
        let msg = v1::Message::builder()
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
            .unwrap();

        let vm = VersionedMessage::V1(msg);
        let s = serde_json::to_string(&vm).unwrap();
        let back: VersionedMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(vm, back);
    }

    #[test]
    fn test_v1_versioned_message_bincode_blocked() {
        let msg = v1::Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();

        let vm = VersionedMessage::V1(msg);

        // bincode serialization should fail
        let result = bincode::serialize(&vm);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot be serialized via bincode"));
    }

    #[cfg(feature = "wincode")]
    #[test]
    fn test_v1_wincode_roundtrip() {
        let test_messages = [
            // Minimal message
            v1::Message::builder()
                .num_required_signatures(1)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![Address::new_unique(), Address::new_unique()])
                .instruction(CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![],
                })
                .build()
                .unwrap(),
            // With config
            v1::Message::builder()
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
            // Multiple instructions
            v1::Message::builder()
                .num_required_signatures(2)
                .lifetime_specifier(Hash::new_unique())
                .account_keys(vec![
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
                VersionedMessage::V1(parsed) => {
                    assert_eq!(parsed.header, message.header);
                    assert_eq!(parsed.lifetime_specifier, message.lifetime_specifier);
                    assert_eq!(parsed.account_keys, message.account_keys);
                    assert_eq!(parsed.config, message.config);
                    assert_eq!(parsed.instructions, message.instructions);
                }
                _ => panic!("Expected V1 message"),
            }
        }
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn test_hash_raw_message_uses_version_specific_prefix() {
        // Test V1 message (0x81 prefix)
        let v1_bytes = &[0x81, 0x01, 0x02, 0x03];
        let v1_hash = VersionedMessage::hash_raw_message(v1_bytes);

        // Manually compute expected hash with v1 prefix
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"solana-tx-message-v1");
        expected_hasher.update(v1_bytes);
        let expected_v1: [u8; 32] = expected_hasher.finalize().into();
        assert_eq!(v1_hash.as_ref(), &expected_v1);

        // Test V0 message (0x80 prefix)
        let v0_bytes = &[0x80, 0x01, 0x02, 0x03];
        let v0_hash = VersionedMessage::hash_raw_message(v0_bytes);

        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"solana-tx-message-v0");
        expected_hasher.update(v0_bytes);
        let expected_v0: [u8; 32] = expected_hasher.finalize().into();
        assert_eq!(v0_hash.as_ref(), &expected_v0);

        // Test Legacy message (first byte < 0x80, no prefix)
        let legacy_bytes = &[0x01, 0x02, 0x03, 0x04];
        let legacy_hash = VersionedMessage::hash_raw_message(legacy_bytes);

        let mut expected_hasher = blake3::Hasher::new();
        // No prefix for legacy
        expected_hasher.update(legacy_bytes);
        let expected_legacy: [u8; 32] = expected_hasher.finalize().into();
        assert_eq!(legacy_hash.as_ref(), &expected_legacy);

        // Verify all three hashes are different
        assert_ne!(v1_hash, v0_hash);
        assert_ne!(v1_hash, legacy_hash);
        assert_ne!(v0_hash, legacy_hash);
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn test_hash_domain_separation_prevents_collision() {
        // Same payload bytes but different version prefixes must produce different hashes
        let payload = &[0x01, 0x02, 0x03, 0x04, 0x05];

        // Create messages with same payload but different versions
        let mut legacy_bytes = vec![0x7F]; // Legacy (< 0x80)
        legacy_bytes.extend_from_slice(payload);

        let mut v0_bytes = vec![0x80]; // V0
        v0_bytes.extend_from_slice(payload);

        let mut v1_bytes = vec![0x81]; // V1
        v1_bytes.extend_from_slice(payload);

        let legacy_hash = VersionedMessage::hash_raw_message(&legacy_bytes);
        let v0_hash = VersionedMessage::hash_raw_message(&v0_bytes);
        let v1_hash = VersionedMessage::hash_raw_message(&v1_bytes);

        // All hashes must be different despite similar content
        assert_ne!(legacy_hash, v0_hash, "Legacy and V0 hashes should differ");
        assert_ne!(legacy_hash, v1_hash, "Legacy and V1 hashes should differ");
        assert_ne!(v0_hash, v1_hash, "V0 and V1 hashes should differ");
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn test_hash_empty_message_edge_case() {
        // Empty message edge case
        let empty_hash = VersionedMessage::hash_raw_message(&[]);

        // Empty input should just hash empty bytes (no version prefix)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(empty_hash.as_ref(), &expected);
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn test_hash_unknown_version_uses_dynamic_prefix() {
        // Test unknown version byte (e.g., 0x85 = version 5)
        let future_bytes = &[0x85, 0x01, 0x02, 0x03];
        let future_hash = VersionedMessage::hash_raw_message(future_bytes);

        // Should use dynamic prefix "solana-tx-message-v5"
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"solana-tx-message-v5");
        expected_hasher.update(future_bytes);
        let expected: [u8; 32] = expected_hasher.finalize().into();
        assert_eq!(future_hash.as_ref(), &expected);
    }

    #[cfg(all(feature = "blake3", feature = "bincode"))]
    #[test]
    fn test_hash_real_v1_message() {
        let message = v1::Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_from_array([0xAB; 32]))
            .account_keys(vec![
                Address::new_from_array([1u8; 32]),
                Address::new_from_array([2u8; 32]),
            ])
            .priority_fee(1000)
            .compute_unit_limit(200_000)
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3, 4],
            })
            .build()
            .unwrap();

        let versioned = VersionedMessage::V1(message);
        let bytes = versioned.serialize();

        // Verify first byte is V1 version
        assert_eq!(bytes[0], 0x81);

        let hash = versioned.hash();

        // Hash via raw bytes should match
        let hash_from_raw = VersionedMessage::hash_raw_message(&bytes);
        assert_eq!(hash, hash_from_raw);

        // Manually verify the domain separation
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"solana-tx-message-v1");
        hasher.update(&bytes);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash.as_ref(), &expected);
    }
}
