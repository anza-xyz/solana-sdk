//! Defines a transaction which supports multiple versions of messages.

use {
    crate::Transaction,
    solana_message::{inline_nonce::is_advance_nonce_instruction_data, VersionedMessage},
    solana_sanitize::SanitizeError,
    solana_sdk_ids::system_program,
    solana_signature::Signature,
    std::cmp::Ordering,
};
#[cfg(feature = "wincode")]
use {
    core::{
        mem::MaybeUninit,
        ptr::{addr_of_mut, copy_nonoverlapping},
    },
    solana_message::v1::SIGNATURE_SIZE,
    solana_message::MESSAGE_VERSION_PREFIX,
    solana_signer::{signers::Signers, SignerError},
    wincode::{
        config::Config,
        containers,
        io::{Reader, Writer},
        len::ShortU16,
        ReadError, ReadResult, SchemaRead, SchemaWrite, WriteResult,
    },
};
#[cfg(feature = "serde")]
use {
    serde_derive::{Deserialize, Serialize},
    solana_short_vec as short_vec,
};

pub mod sanitized;

/// Type that serializes to the string "legacy"
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Legacy {
    Legacy,
}

#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(rename_all = "camelCase", untagged)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionVersion {
    Legacy(Legacy),
    Number(u8),
}

impl TransactionVersion {
    pub const LEGACY: Self = Self::Legacy(Legacy::Legacy);
}

// NOTE: Serialization-related changes must be paired with the direct read at sigverify.
/// An atomic transaction
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Default, Eq, Clone)]
pub struct VersionedTransaction {
    /// List of signatures
    #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
    pub signatures: Vec<Signature>,
    /// Message to sign.
    pub message: VersionedMessage,
}

impl From<Transaction> for VersionedTransaction {
    fn from(transaction: Transaction) -> Self {
        Self {
            signatures: transaction.signatures,
            message: VersionedMessage::Legacy(transaction.message),
        }
    }
}

impl VersionedTransaction {
    /// Signs a versioned message and if successful, returns a signed
    /// transaction.
    #[cfg(feature = "wincode")]
    pub fn try_new<T: Signers + ?Sized>(
        message: VersionedMessage,
        keypairs: &T,
    ) -> std::result::Result<Self, SignerError> {
        let static_account_keys = message.static_account_keys();
        if static_account_keys.len() < message.header().num_required_signatures as usize {
            return Err(SignerError::InvalidInput("invalid message".to_string()));
        }

        let signer_keys = keypairs.try_pubkeys()?;
        let expected_signer_keys =
            &static_account_keys[0..message.header().num_required_signatures as usize];

        match signer_keys.len().cmp(&expected_signer_keys.len()) {
            Ordering::Greater => Err(SignerError::TooManySigners),
            Ordering::Less => Err(SignerError::NotEnoughSigners),
            Ordering::Equal => Ok(()),
        }?;

        let message_data = message.serialize();
        let signature_indexes: Vec<usize> = expected_signer_keys
            .iter()
            .map(|signer_key| {
                signer_keys
                    .iter()
                    .position(|key| key == signer_key)
                    .ok_or(SignerError::KeypairPubkeyMismatch)
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        let unordered_signatures = keypairs.try_sign_message(&message_data)?;
        let signatures: Vec<Signature> = signature_indexes
            .into_iter()
            .map(|index| {
                unordered_signatures
                    .get(index)
                    .copied()
                    .ok_or_else(|| SignerError::InvalidInput("invalid keypairs".to_string()))
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        Ok(Self {
            signatures,
            message,
        })
    }

    pub fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        self.message.sanitize()?;
        self.sanitize_signatures()?;
        Ok(())
    }

    pub(crate) fn sanitize_signatures(&self) -> std::result::Result<(), SanitizeError> {
        Self::sanitize_signatures_inner(
            usize::from(self.message.header().num_required_signatures),
            self.message.static_account_keys().len(),
            self.signatures.len(),
        )
    }

    pub(crate) fn sanitize_signatures_inner(
        num_required_signatures: usize,
        num_static_account_keys: usize,
        num_signatures: usize,
    ) -> std::result::Result<(), SanitizeError> {
        match num_required_signatures.cmp(&num_signatures) {
            Ordering::Greater => Err(SanitizeError::IndexOutOfBounds),
            Ordering::Less => Err(SanitizeError::InvalidValue),
            Ordering::Equal => Ok(()),
        }?;

        // Signatures are verified before message keys are loaded so all signers
        // must correspond to static account keys.
        if num_signatures > num_static_account_keys {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        Ok(())
    }

    /// Returns the version of the transaction
    pub fn version(&self) -> TransactionVersion {
        match self.message {
            VersionedMessage::Legacy(_) => TransactionVersion::LEGACY,
            VersionedMessage::V0(_) => TransactionVersion::Number(0),
            VersionedMessage::V1(_) => TransactionVersion::Number(1),
        }
    }

    /// Returns a legacy transaction if the transaction message is legacy.
    pub fn into_legacy_transaction(self) -> Option<Transaction> {
        match self.message {
            VersionedMessage::Legacy(message) => Some(Transaction {
                signatures: self.signatures,
                message,
            }),
            _ => None,
        }
    }

    #[cfg(feature = "verify")]
    /// Verify the transaction and hash its message
    pub fn verify_and_hash_message(
        &self,
    ) -> solana_transaction_error::TransactionResult<solana_hash::Hash> {
        let message_bytes = self.message.serialize();
        if !self
            ._verify_with_results(&message_bytes)
            .iter()
            .all(|verify_result| *verify_result)
        {
            Err(solana_transaction_error::TransactionError::SignatureFailure)
        } else {
            Ok(VersionedMessage::hash_raw_message(&message_bytes))
        }
    }

    #[cfg(feature = "verify")]
    /// Verify the transaction and return a list of verification results
    pub fn verify_with_results(&self) -> Vec<bool> {
        let message_bytes = self.message.serialize();
        self._verify_with_results(&message_bytes)
    }

    #[cfg(feature = "verify")]
    fn _verify_with_results(&self, message_bytes: &[u8]) -> Vec<bool> {
        self.signatures
            .iter()
            .zip(self.message.static_account_keys().iter())
            .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), message_bytes))
            .collect()
    }

    /// Returns true if transaction begins with an advance nonce instruction.
    pub fn uses_durable_nonce(&self) -> bool {
        let message = &self.message;
        message
            .instructions()
            .get(crate::NONCED_TX_MARKER_IX_INDEX as usize)
            .filter(|instruction| {
                // Is system program
                matches!(
                    message.static_account_keys().get(instruction.program_id_index as usize),
                    Some(program_id) if system_program::check_id(program_id)
                ) && is_advance_nonce_instruction_data(&instruction.data)
            })
            .is_some()
    }
}

#[cfg(feature = "wincode")]
unsafe impl<C: Config> SchemaWrite<C> for VersionedTransaction {
    type Src = Self;

    #[allow(clippy::arithmetic_side_effects)]
    #[inline]
    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        match src.message {
            VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => {
                Ok(
                    <containers::Vec<Signature, ShortU16> as SchemaWrite<C>>::size_of(
                        &src.signatures,
                    )? + <VersionedMessage as SchemaWrite<C>>::size_of(&src.message)?,
                )
            }
            VersionedMessage::V1(_) => Ok(
                // V1 transasction signatures are written as a fixed length array
                // without a length prefix.
                <VersionedMessage as SchemaWrite<C>>::size_of(&src.message)?
                    + src.signatures.len() * SIGNATURE_SIZE,
            ),
        }
    }

    #[inline]
    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        match src.message {
            VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => {
                // `signatures` are written with `ShortU16Len` length prefix.
                <containers::Vec<Signature, ShortU16> as SchemaWrite<C>>::write(
                    &mut writer,
                    &src.signatures,
                )?;
                <VersionedMessage as SchemaWrite<C>>::write(writer, &src.message)
            }
            VersionedMessage::V1(_) => {
                <VersionedMessage as SchemaWrite<C>>::write(&mut writer, &src.message)?;
                unsafe {
                    writer
                        .write_slice_t(&src.signatures)
                        .map_err(wincode::WriteError::Io)
                }
            }
        }
    }
}

#[cfg(feature = "wincode")]
unsafe impl<'de, C: Config> SchemaRead<'de, C> for VersionedTransaction {
    type Dst = Self;

    #[inline]
    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        // Peek the discriminator to decide how to read the transaction data.
        //
        // - For `Legacy` and `V0` messages, the first byte is part of the `short_vec` length
        //   prefix for the `signatures` field. Since `signatures < 128` is always true, if
        //   the top bit is `0`, we expect the message to be either `Legacy` or `V0`.
        //
        // - For `V1` messages, the first byte is the message version byte, which is always
        //   `> 128` and the top bit is always `1`.

        use solana_message::v1::V1_PREFIX;
        let discriminator = reader.peek()?;

        if discriminator & MESSAGE_VERSION_PREFIX == 0 {
            // Legacy or V0 transaction

            let dst_ptr = dst.as_mut_ptr();

            <containers::Vec<Signature, ShortU16> as SchemaRead<'de, C>>::read(
                &mut reader,
                unsafe {
                    &mut *(addr_of_mut!((*dst_ptr).signatures))
                        .cast::<MaybeUninit<Vec<Signature>>>()
                },
            )?;

            <VersionedMessage as SchemaRead<'de, C>>::read(reader, unsafe {
                &mut *(addr_of_mut!((*dst_ptr).message)).cast::<MaybeUninit<_>>()
            })?;
        } else if *discriminator == V1_PREFIX {
            // V1 transaction

            let message = <VersionedMessage as SchemaRead<'de, C>>::get(&mut reader)?;

            let expected_signatures_len = message.header().num_required_signatures as usize;

            let bytes =
                reader.fill_exact(expected_signatures_len.saturating_mul(SIGNATURE_SIZE))?;
            let mut signatures = Vec::with_capacity(expected_signatures_len);

            // SAFETY: signatures vector is allocated with enough capacity to hold
            // `expected_signatures_len` signatures and `bytes` contains exactly that
            // many signatures read from the reader.
            unsafe {
                let signatures_ptr = signatures.as_mut_ptr();
                copy_nonoverlapping(
                    bytes.as_ptr() as *const Signature,
                    signatures_ptr,
                    expected_signatures_len,
                );
                signatures.set_len(expected_signatures_len);
            }

            dst.write(Self {
                message,
                signatures,
            });
        } else {
            return Err(ReadError::Custom("invalid transaction discriminator"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_address::{Address, ADDRESS_BYTES},
        solana_hash::Hash,
        solana_instruction::{AccountMeta, Instruction},
        solana_keypair::Keypair,
        solana_message::{
            compiled_instruction::CompiledInstruction,
            v0::Message as MessageV0,
            v1::{
                InstructionHeader, Message, TransactionConfig, FIXED_HEADER_SIZE,
                MAX_TRANSACTION_SIZE, SIGNATURE_SIZE,
            },
            Message as LegacyMessage, MessageHeader,
        },
        solana_pubkey::Pubkey,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        test_case::test_case,
    };

    #[test]
    fn test_try_new() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let message = VersionedMessage::Legacy(LegacyMessage::new(
            &[Instruction::new_with_bytes(
                Pubkey::new_unique(),
                &[],
                vec![
                    AccountMeta::new_readonly(keypair1.pubkey(), true),
                    AccountMeta::new_readonly(keypair2.pubkey(), false),
                ],
            )],
            Some(&keypair0.pubkey()),
        ));

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair0]),
            Err(SignerError::NotEnoughSigners)
        );

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair0, &keypair0]),
            Err(SignerError::KeypairPubkeyMismatch)
        );

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair1, &keypair2]),
            Err(SignerError::KeypairPubkeyMismatch)
        );

        match VersionedTransaction::try_new(message.clone(), &[&keypair0, &keypair1]) {
            Ok(tx) => assert_eq!(tx.verify_with_results(), vec![true; 2]),
            Err(err) => assert_eq!(Some(err), None),
        }

        match VersionedTransaction::try_new(message, &[&keypair1, &keypair0]) {
            Ok(tx) => assert_eq!(tx.verify_with_results(), vec![true; 2]),
            Err(err) => assert_eq!(Some(err), None),
        }
    }

    fn nonced_transfer_tx() -> (Pubkey, Pubkey, VersionedTransaction) {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::advance_nonce_account(&nonce_pubkey, &nonce_pubkey),
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
        ];
        let message = LegacyMessage::new(&instructions, Some(&nonce_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        (from_pubkey, nonce_pubkey, tx.into())
    }

    #[test]
    fn tx_uses_nonce_ok() {
        let (_, _, tx) = nonced_transfer_tx();
        assert!(tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_empty_ix_fail() {
        let tx = VersionedTransaction {
            message: VersionedMessage::V0(MessageV0::default()),
            signatures: vec![],
        };
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_bad_prog_id_idx_fail() {
        let (_, _, mut tx) = nonced_transfer_tx();
        match &mut tx.message {
            VersionedMessage::Legacy(message) => {
                message.instructions.get_mut(0).unwrap().program_id_index = 255u8;
            }
            _ => unreachable!(),
        };
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_first_prog_id_not_nonce_fail() {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
            system_instruction::advance_nonce_account(&nonce_pubkey, &nonce_pubkey),
        ];
        let message = LegacyMessage::new(&instructions, Some(&from_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        let tx = VersionedTransaction::from(tx);
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_wrong_first_nonce_ix_fail() {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::withdraw_nonce_account(
                &nonce_pubkey,
                &nonce_pubkey,
                &from_pubkey,
                42,
            ),
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
        ];
        let message = LegacyMessage::new(&instructions, Some(&nonce_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        let tx = VersionedTransaction::from(tx);
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn test_sanitize_signatures_inner() {
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 0),
            Err(SanitizeError::IndexOutOfBounds)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 2),
            Err(SanitizeError::InvalidValue)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(2, 1, 2),
            Err(SanitizeError::IndexOutOfBounds)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 1),
            Ok(())
        );
    }

    #[test]
    fn versioned_transaction_wincode_bincode_roundtrip() {
        use {
            super::*,
            proptest::prelude::*,
            solana_address::{Address, ADDRESS_BYTES},
            solana_hash::{Hash, HASH_BYTES},
            solana_message::{
                compiled_instruction::CompiledInstruction,
                v0::{self, MessageAddressTableLookup},
                Message as LegacyMessage, MessageHeader,
            },
            solana_signature::SIGNATURE_BYTES,
        };

        // Bincode version of VersionedTransaction for cross-checking serialization
        // with wincode. This only applies to legacy/v0 transactions since v1
        // transaction format is not compatible with bincode.
        #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
        #[derive(Debug, PartialEq, Default, Eq, Clone)]
        struct BincodeVersionedTransaction {
            /// List of signatures
            #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
            pub signatures: Vec<Signature>,
            /// Message to sign.
            pub message: VersionedMessage,
        }

        fn strat_byte_vec(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
            proptest::collection::vec(any::<u8>(), 0..=max_len)
        }

        fn strat_signature() -> impl Strategy<Value = Signature> {
            any::<[u8; SIGNATURE_BYTES]>().prop_map(Signature::from)
        }

        fn strat_address() -> impl Strategy<Value = Address> {
            any::<[u8; ADDRESS_BYTES]>().prop_map(Address::new_from_array)
        }

        fn strat_hash() -> impl Strategy<Value = Hash> {
            any::<[u8; HASH_BYTES]>().prop_map(Hash::new_from_array)
        }

        fn strat_message_header() -> impl Strategy<Value = MessageHeader> {
            (0u8..128, any::<u8>(), any::<u8>()).prop_map(|(a, b, c)| MessageHeader {
                num_required_signatures: a,
                num_readonly_signed_accounts: b,
                num_readonly_unsigned_accounts: c,
            })
        }

        fn strat_compiled_instruction() -> impl Strategy<Value = CompiledInstruction> {
            (any::<u8>(), strat_byte_vec(128), strat_byte_vec(128)).prop_map(
                |(program_id_index, accounts, data)| {
                    CompiledInstruction::new_from_raw_parts(program_id_index, accounts, data)
                },
            )
        }

        fn strat_address_table_lookup() -> impl Strategy<Value = MessageAddressTableLookup> {
            (strat_address(), strat_byte_vec(128), strat_byte_vec(128)).prop_map(
                |(account_key, writable_indexes, readonly_indexes)| MessageAddressTableLookup {
                    account_key,
                    writable_indexes,
                    readonly_indexes,
                },
            )
        }

        fn strat_legacy_message() -> impl Strategy<Value = LegacyMessage> {
            (
                strat_message_header(),
                proptest::collection::vec(strat_address(), 0..=8),
                strat_hash(),
                proptest::collection::vec(strat_compiled_instruction(), 0..=8),
            )
                .prop_map(|(header, account_keys, recent_blockhash, instructions)| {
                    LegacyMessage {
                        header,
                        account_keys,
                        recent_blockhash,
                        instructions,
                    }
                })
        }

        fn strat_v0_message() -> impl Strategy<Value = v0::Message> {
            (
                strat_message_header(),
                proptest::collection::vec(strat_address(), 0..=8),
                strat_hash(),
                proptest::collection::vec(strat_compiled_instruction(), 0..=4),
                proptest::collection::vec(strat_address_table_lookup(), 0..=4),
            )
                .prop_map(
                    |(
                        header,
                        account_keys,
                        recent_blockhash,
                        instructions,
                        address_table_lookups,
                    )| {
                        v0::Message {
                            header,
                            account_keys,
                            recent_blockhash,
                            instructions,
                            address_table_lookups,
                        }
                    },
                )
        }

        fn strat_versioned_message() -> impl Strategy<Value = VersionedMessage> {
            prop_oneof![
                strat_legacy_message().prop_map(VersionedMessage::Legacy),
                strat_v0_message().prop_map(VersionedMessage::V0),
            ]
        }

        fn strat_versioned_transaction(
        ) -> impl Strategy<Value = (VersionedTransaction, BincodeVersionedTransaction)> {
            (
                proptest::collection::vec(strat_signature(), 0..=8),
                strat_versioned_message(),
            )
                .prop_map(|(signatures, message)| {
                    (
                        VersionedTransaction {
                            message: message.clone(),
                            signatures: signatures.clone(),
                        },
                        BincodeVersionedTransaction {
                            message: message.clone(),
                            signatures: signatures.clone(),
                        },
                    )
                })
        }

        proptest!(|(tx in strat_versioned_transaction())| {
            let wincode_serialized = wincode::serialize(&tx.0).unwrap();
            let bincode_serialized = bincode::serialize(&tx.1).unwrap();

            assert_eq!(bincode_serialized, wincode_serialized);

            let bincode_deserialized: BincodeVersionedTransaction = bincode::deserialize(&bincode_serialized).unwrap();
            let wincode_deserialized: VersionedTransaction = wincode::deserialize(&wincode_serialized).unwrap();

            assert_eq!(&bincode_deserialized.message, &wincode_deserialized.message);
            assert_eq!(&bincode_deserialized.signatures, &wincode_deserialized.signatures);

            assert_eq!(wincode_deserialized, tx.0);
        });
    }

    #[test_case(0 ; "at max size")]
    #[test_case(1 ; "over by one")]
    #[allow(clippy::arithmetic_side_effects)]
    fn v1_transaction_serialization(delta: usize) {
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

        let overhead = 1 // version byte
            + (NUM_SIGNATURES * SIGNATURE_SIZE)
            + FIXED_HEADER_SIZE
            + (NUM_ADDRESSES * ADDRESS_BYTES)
            + size_of::<InstructionHeader>()
            + NUM_INSTRUCTION_ACCOUNTS;

        // adds `delta` bytes to the instruction data to test both at max size
        // and over by one byte scenarios.
        let max_data_size = MAX_TRANSACTION_SIZE - overhead + delta;
        let data = vec![0u8; max_data_size];

        let message = Message {
            header: MessageHeader {
                num_required_signatures: NUM_SIGNATURES as u8,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            config: TransactionConfig::default(),
            account_keys: vec![Address::new_unique(), Address::new_unique()],
            lifetime_specifier: Hash::new_unique(),
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data,
            }],
        };

        let v1_tx = VersionedTransaction {
            message: VersionedMessage::V1(message),
            signatures: vec![Signature::default()],
        };

        let serialized = wincode::serialize(&v1_tx).unwrap();

        match delta {
            0 => assert_eq!(
                serialized.len(),
                MAX_TRANSACTION_SIZE,
                "Transaction should be exactly at max size"
            ),
            d => assert_eq!(
                serialized.len(),
                MAX_TRANSACTION_SIZE + d,
                "Transaction should be over by {d} byte(s)"
            ),
        }

        let deserialized = wincode::deserialize(&serialized).unwrap();

        assert_eq!(
            v1_tx, deserialized,
            "Deserialized payload should match original"
        );
    }
}
