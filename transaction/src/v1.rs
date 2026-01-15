//! V1 transaction format per SIMD-0385.
//!
//! V1 transactions use a different wire format than Legacy/V0:
//! - Message bytes come first
//! - Signatures come last with NO length prefix
//! - Signature count is determined by `num_required_signatures` in the message header
//!
//! This format is incompatible with serde/bincode, so V1Transaction only supports
//! raw byte serialization via [`V1Transaction::serialize`] and [`V1Transaction::from_bytes`].

use {
    crate::versioned::VersionedTransaction,

    solana_message::{
        v1::{Message, V1MessageError},
        VersionedMessage,
    },
    solana_sanitize::{Sanitize, SanitizeError},
    solana_signature::{Signature, SIGNATURE_BYTES},
};
#[cfg(feature = "bincode")]
use {
    solana_signer::{signers::Signers, SignerError},
    std::cmp::Ordering,
};

/// Errors that can occur when working with V1 transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1TransactionError {
    /// Message parsing or serialization failed.
    MessageError(V1MessageError),
    /// Not enough account keys for the required number of signatures.
    NotEnoughAccountKeys,
    /// Not enough bytes for the expected number of signatures.
    NotEnoughSignatureBytes,
    /// Size calculation overflowed.
    Overflow,
    /// Signature count doesn't match num_required_signatures.
    SignatureCountMismatch {
        /// Expected number of signatures from message header.
        expected: usize,
        /// Actual number of signatures provided.
        actual: usize,
    },
    /// Unexpected trailing data after transaction.
    TrailingData,
}

impl std::fmt::Display for V1TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageError(e) => write!(f, "message error: {e}"),
            Self::NotEnoughAccountKeys => {
                write!(f, "not enough account keys for required signatures")
            }
            Self::NotEnoughSignatureBytes => write!(f, "not enough bytes for signatures"),
            Self::Overflow => write!(f, "size calculation overflow"),
            Self::SignatureCountMismatch { expected, actual } => {
                write!(
                    f,
                    "signature count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::TrailingData => write!(f, "unexpected trailing data after transaction"),
        }
    }
}

impl std::error::Error for V1TransactionError {}

impl From<V1MessageError> for V1TransactionError {
    fn from(err: V1MessageError) -> Self {
        Self::MessageError(err)
    }
}

/// A V1 transaction per SIMD-0385.
///
/// Wire format: `[message bytes][signatures]`
/// - Message bytes include version byte (0x81) through instruction payloads
/// - Signatures are appended directly with NO length prefix
/// - Signature count is determined by `num_required_signatures` from the message header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Transaction {
    /// The V1 message containing instructions and accounts.
    pub message: Message,
    /// Transaction signatures, one per required signer.
    /// Order matches the first `num_required_signatures` accounts in the message.
    pub signatures: Vec<Signature>,
}

impl V1Transaction {
    /// Create a V1 transaction from a message and existing signatures.
    ///
    /// Returns an error if the signature count doesn't match `num_required_signatures`.
    pub fn from_signatures(
        message: Message,
        signatures: Vec<Signature>,
    ) -> Result<Self, V1TransactionError> {
        let expected = message.header.num_required_signatures as usize;
        if signatures.len() != expected {
            return Err(V1TransactionError::SignatureCountMismatch {
                expected,
                actual: signatures.len(),
            });
        }
        Ok(Self {
            message,
            signatures,
        })
    }

    /// Sign a V1 message and create a transaction.
    ///
    /// Keypairs can be provided in any order; they will be matched to the
    /// expected signers (first `num_required_signatures` accounts in the message)
    /// by public key.
    #[cfg(feature = "bincode")]
    pub fn try_sign<T: Signers + ?Sized>(
        message: Message,
        keypairs: &T,
    ) -> Result<Self, SignerError> {
        let num_required_signatures = message.header.num_required_signatures as usize;

        if message.account_keys.len() < num_required_signatures {
            return Err(SignerError::InvalidInput("invalid message".to_string()));
        }

        let signer_keys = keypairs.try_pubkeys()?;
        let expected_signer_keys = &message.account_keys[0..num_required_signatures];

        match signer_keys.len().cmp(&expected_signer_keys.len()) {
            Ordering::Greater => Err(SignerError::TooManySigners),
            Ordering::Less => Err(SignerError::NotEnoughSigners),
            Ordering::Equal => Ok(()),
        }?;

        // Get message bytes for signing
        let message_data = message
            .to_bytes()
            .map_err(|e| SignerError::InvalidInput(e.to_string()))?;

        // Map expected signers to provided keypair positions
        let signature_indexes: Vec<usize> = expected_signer_keys
            .iter()
            .map(|signer_key| {
                signer_keys
                    .iter()
                    .position(|key| key.as_ref() == signer_key.as_ref())
                    .ok_or(SignerError::KeypairPubkeyMismatch)
            })
            .collect::<Result<_, SignerError>>()?;

        // Sign and reorder signatures to match expected order
        let unordered_signatures = keypairs.try_sign_message(&message_data)?;
        let signatures: Vec<Signature> = signature_indexes
            .into_iter()
            .map(|index| unordered_signatures[index])
            .collect();

        Ok(Self {
            message,
            signatures,
        })
    }

    /// Serialize the transaction to wire format per SIMD-0385.
    ///
    /// Wire format: `[message bytes][signatures]`
    /// - No length prefix on signatures
    /// - Signature count determined by `num_required_signatures` in message header
    pub fn serialize(&self) -> Result<Vec<u8>, V1TransactionError> {
        let mut out = self.message.to_bytes()?;
        let signature_bytes = self
            .signatures
            .len()
            .checked_mul(SIGNATURE_BYTES)
            .ok_or(V1TransactionError::Overflow)?;
        out.reserve(signature_bytes);
        for sig in &self.signatures {
            out.extend_from_slice(sig.as_ref());
        }
        Ok(out)
    }

    /// Parse a V1 transaction from wire format bytes.
    ///
    /// Expects format: `[message bytes][signatures]`
    /// Returns an error if there is trailing data after the transaction.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, V1TransactionError> {
        let (tx, consumed) = Self::from_bytes_partial(bytes)?;
        if consumed != bytes.len() {
            return Err(V1TransactionError::TrailingData);
        }
        Ok(tx)
    }

    /// Parse a V1 transaction from wire format, returning bytes consumed.
    ///
    /// Useful when transaction bytes are followed by other data.
    pub fn from_bytes_partial(bytes: &[u8]) -> Result<(Self, usize), V1TransactionError> {
        // Parse message first
        let (message, message_len) = Message::from_bytes_partial(bytes)?;

        // Calculate expected signature bytes with overflow checks
        let num_signatures = message.header.num_required_signatures as usize;
        let signatures_len = num_signatures
            .checked_mul(SIGNATURE_BYTES)
            .ok_or(V1TransactionError::Overflow)?;
        let total_len = message_len
            .checked_add(signatures_len)
            .ok_or(V1TransactionError::Overflow)?;

        if bytes.len() < total_len {
            return Err(V1TransactionError::NotEnoughSignatureBytes);
        }

        // Extract signatures (chunks_exact guarantees exactly SIGNATURE_BYTES per chunk)
        let sig_bytes = &bytes[message_len..total_len];
        let signatures: Vec<Signature> = sig_bytes
            .chunks_exact(SIGNATURE_BYTES)
            .map(|chunk| Signature::from(<[u8; SIGNATURE_BYTES]>::try_from(chunk).unwrap()))
            .collect();

        Ok((
            Self {
                message,
                signatures,
            },
            total_len,
        ))
    }

    /// Verify all signatures against the message.
    ///
    /// Returns `true` if all signatures are valid, `false` if any is invalid.
    /// Returns `Err` if the transaction is malformed or cannot be serialized.
    #[cfg(feature = "verify")]
    pub fn verify(&self) -> Result<bool, V1TransactionError> {
        Ok(self.verify_with_results()?.iter().all(|&valid| valid))
    }

    /// Verify each signature and return individual results.
    ///
    /// Returns a vector of booleans, one per signature, indicating whether
    /// each signature is valid. Returns `Err` if the transaction is malformed
    /// or the message cannot be serialized.
    #[cfg(feature = "verify")]
    pub fn verify_with_results(&self) -> Result<Vec<bool>, V1TransactionError> {
        let required = self.message.header.num_required_signatures as usize;

        // Ensure we verify exactly the signer region, not a subset
        if self.signatures.len() != required {
            return Err(V1TransactionError::SignatureCountMismatch {
                expected: required,
                actual: self.signatures.len(),
            });
        }
        if self.message.account_keys.len() < required {
            return Err(V1TransactionError::NotEnoughAccountKeys);
        }

        let message_bytes = self.message.to_bytes()?;

        Ok(self
            .signatures
            .iter()
            .zip(self.message.account_keys[..required].iter())
            .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), &message_bytes))
            .collect())
    }

    /// Calculate the size of this transaction when serialized.
    pub fn size(&self) -> usize {
        self.message.transaction_size()
    }
}

impl Sanitize for V1Transaction {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        // Verify signature count matches header
        let expected = self.message.header.num_required_signatures as usize;
        if self.signatures.len() != expected {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        self.message.sanitize()?;

        Ok(())
    }
}

/// Convert a V1Transaction into a VersionedTransaction.
impl From<V1Transaction> for VersionedTransaction {
    fn from(tx: V1Transaction) -> Self {
        Self {
            signatures: tx.signatures,
            message: VersionedMessage::V1(tx.message),
        }
    }
}

/// Try to convert a VersionedTransaction into a V1Transaction.
///
/// Returns `Err` with the original transaction if the message is not V1
/// or if the signature count doesn't match `num_required_signatures`.
impl TryFrom<VersionedTransaction> for V1Transaction {
    type Error = VersionedTransaction;

    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        match tx.message {
            VersionedMessage::V1(message) => {
                let expected = message.header.num_required_signatures as usize;
                if tx.signatures.len() != expected {
                    return Err(VersionedTransaction {
                        signatures: tx.signatures,
                        message: VersionedMessage::V1(message),
                    });
                }
                Ok(Self {
                    message,
                    signatures: tx.signatures,
                })
            }
            _ => Err(tx),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_address::Address,
        solana_hash::Hash,
        solana_message::compiled_instruction::CompiledInstruction,
    };

    /// Create a deterministic test signature from a seed byte.
    fn test_signature(seed: u8) -> Signature {
        let mut bytes = [seed; 64];
        bytes[63] = seed.wrapping_add(1);
        Signature::from(bytes)
    }

    fn create_test_message() -> Message {
        Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![Address::new_unique(), Address::new_unique()])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3, 4],
            })
            .build()
            .unwrap()
    }

    fn create_two_signer_message() -> Message {
        Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
            ])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![],
            })
            .build()
            .unwrap()
    }

    #[test]
    fn error_display_formats_correctly() {
        assert_eq!(
            V1TransactionError::MessageError(V1MessageError::BufferTooSmall).to_string(),
            "message error: buffer too small"
        );
        assert_eq!(
            V1TransactionError::NotEnoughAccountKeys.to_string(),
            "not enough account keys for required signatures"
        );
        assert_eq!(
            V1TransactionError::NotEnoughSignatureBytes.to_string(),
            "not enough bytes for signatures"
        );
        assert_eq!(
            V1TransactionError::Overflow.to_string(),
            "size calculation overflow"
        );
        assert_eq!(
            V1TransactionError::SignatureCountMismatch {
                expected: 2,
                actual: 1
            }
            .to_string(),
            "signature count mismatch: expected 2, got 1"
        );
        assert_eq!(
            V1TransactionError::TrailingData.to_string(),
            "unexpected trailing data after transaction"
        );
    }

    #[test]
    fn clone_and_eq_work() {
        let message = create_test_message();
        let tx = V1Transaction::from_signatures(message, vec![test_signature(0x01)]).unwrap();

        let cloned = tx.clone();
        assert_eq!(tx, cloned);

        // Different signature should not be equal
        let message2 = create_test_message();
        let tx2 = V1Transaction::from_signatures(message2, vec![test_signature(0x02)]).unwrap();
        assert_ne!(tx, tx2);
    }

    #[test]
    fn destructuring_works() {
        let message = create_test_message();
        let sig = test_signature(0x99);
        let tx = V1Transaction::from_signatures(message.clone(), vec![sig]).unwrap();

        let V1Transaction {
            message: returned_message,
            signatures: returned_sigs,
        } = tx;
        assert_eq!(returned_message, message);
        assert_eq!(returned_sigs, vec![sig]);
    }

    #[test]
    fn from_signatures_rejects_too_few_signatures() {
        let message = create_test_message(); // requires 1 signature

        assert_eq!(
            V1Transaction::from_signatures(message, vec![]),
            Err(V1TransactionError::SignatureCountMismatch {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn from_signatures_rejects_too_many_signatures() {
        let message = create_test_message(); // requires 1 signature

        assert_eq!(
            V1Transaction::from_signatures(
                message,
                vec![test_signature(0x01), test_signature(0x02)]
            ),
            Err(V1TransactionError::SignatureCountMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn try_sign_rejects_too_many_signers() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let program_id = Address::new_unique();

        // Message expects 2 signers
        let message = Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair0.pubkey(), keypair1.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![],
            })
            .build()
            .unwrap();

        // Provide 3 signers
        let result = V1Transaction::try_sign(message, &[&keypair0, &keypair1, &keypair2]);
        assert!(matches!(result, Err(SignerError::TooManySigners)));
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn try_sign_rejects_not_enough_signers() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let program_id = Address::new_unique();

        // Message expects 2 signers
        let message = Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair0.pubkey(), keypair1.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![],
            })
            .build()
            .unwrap();

        // Only provide 1 signer
        let result = V1Transaction::try_sign(message, &[&keypair0]);
        assert!(matches!(result, Err(SignerError::NotEnoughSigners)));
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn try_sign_rejects_wrong_keypairs() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair0 = Keypair::new();
        let wrong_keypair = Keypair::new(); // Not in message
        let program_id = Address::new_unique();

        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair0.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();

        let result = V1Transaction::try_sign(message, &[&wrong_keypair]);
        assert!(matches!(result, Err(SignerError::KeypairPubkeyMismatch)));
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn try_sign_signs_correctly() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair = Keypair::new();
        let program_id = Address::new_unique();

        let message = Message::builder()
            .num_required_signatures(1)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![],
            })
            .build()
            .unwrap();

        let tx = V1Transaction::try_sign(message, &[&keypair]).unwrap();

        assert_eq!(tx.signatures.len(), 1);

        #[cfg(feature = "verify")]
        assert!(tx.verify().unwrap());
    }

    #[cfg(all(feature = "bincode", feature = "verify"))]
    #[test]
    fn try_sign_with_multiple_signers() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let program_id = Address::new_unique();

        let message = Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair0.pubkey(), keypair1.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![],
            })
            .build()
            .unwrap();

        let tx = V1Transaction::try_sign(message, &[&keypair0, &keypair1]).unwrap();

        assert_eq!(tx.signatures.len(), 2);
        assert!(tx.verify().unwrap());
    }

    #[cfg(all(feature = "bincode", feature = "verify"))]
    #[test]
    fn try_sign_reorders_keypairs_correctly() {
        use {solana_keypair::Keypair, solana_signer::Signer};

        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let program_id = Address::new_unique();

        // Message expects keypair0 first, then keypair1
        let message = Message::builder()
            .num_required_signatures(2)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![keypair0.pubkey(), keypair1.pubkey(), program_id])
            .instruction(CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![],
            })
            .build()
            .unwrap();

        // Provide keypairs in REVERSE order
        let tx = V1Transaction::try_sign(message, &[&keypair1, &keypair0]).unwrap();

        // Should still verify because signatures are reordered to match account_keys
        assert!(tx.verify().unwrap());
        assert_eq!(tx.signatures.len(), 2);
    }

    #[test]
    fn serialize_produces_correct_wire_format() {
        let message = create_test_message();
        let sig = test_signature(0xAA);
        let tx = V1Transaction::from_signatures(message.clone(), vec![sig]).unwrap();

        let bytes = tx.serialize().unwrap();

        // Verify format: [message bytes][signatures]
        let message_bytes = message.to_bytes().unwrap();
        assert_eq!(&bytes[..message_bytes.len()], &message_bytes[..]);
        assert_eq!(&bytes[message_bytes.len()..], sig.as_ref());

        // No length prefix before signatures
        assert_eq!(bytes.len(), message_bytes.len() + 64);
    }

    #[test]
    fn from_bytes_rejects_invalid_message() {
        // Empty bytes - fails at message parsing
        let result = V1Transaction::from_bytes(&[]);
        assert!(matches!(result, Err(V1TransactionError::MessageError(_))));

        // Invalid version byte - fails at message parsing
        let result = V1Transaction::from_bytes(&[0x00]);
        assert!(matches!(result, Err(V1TransactionError::MessageError(_))));
    }

    #[test]
    fn from_bytes_rejects_truncated_signatures() {
        let message = create_test_message();
        let sig = test_signature(0xCC);
        let tx = V1Transaction::from_signatures(message, vec![sig]).unwrap();

        let mut bytes = tx.serialize().unwrap();
        bytes.truncate(bytes.len() - 10); // Remove part of signature

        assert_eq!(
            V1Transaction::from_bytes(&bytes),
            Err(V1TransactionError::NotEnoughSignatureBytes)
        );
    }

    #[test]
    fn from_bytes_rejects_trailing_data() {
        let message = create_test_message();
        let sig = test_signature(0xDD);
        let tx = V1Transaction::from_signatures(message, vec![sig]).unwrap();

        let mut bytes = tx.serialize().unwrap();
        bytes.push(0xFF); // Extra byte

        assert_eq!(
            V1Transaction::from_bytes(&bytes),
            Err(V1TransactionError::TrailingData)
        );
    }

    #[test]
    fn from_bytes_roundtrip_single_signature() {
        let message = create_test_message();
        let sig = test_signature(0xBB);
        let tx = V1Transaction::from_signatures(message, vec![sig]).unwrap();

        let bytes = tx.serialize().unwrap();
        let parsed = V1Transaction::from_bytes(&bytes).unwrap();

        assert_eq!(tx.message, parsed.message);
        assert_eq!(tx.signatures, parsed.signatures);
    }

    #[test]
    fn from_bytes_roundtrip_multiple_signatures() {
        let message = Message::builder()
            .num_required_signatures(3)
            .lifetime_specifier(Hash::new_unique())
            .account_keys(vec![
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
                Address::new_unique(),
            ])
            .instruction(CompiledInstruction {
                program_id_index: 3,
                accounts: vec![0, 1, 2],
                data: vec![],
            })
            .build()
            .unwrap();

        // Use distinct signatures to verify order is preserved
        let signatures = vec![
            test_signature(0x11),
            test_signature(0x22),
            test_signature(0x33),
        ];
        let tx = V1Transaction::from_signatures(message, signatures.clone()).unwrap();

        let bytes = tx.serialize().unwrap();
        let parsed = V1Transaction::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.signatures.len(), 3);
        assert_eq!(parsed.signatures[0], signatures[0]);
        assert_eq!(parsed.signatures[1], signatures[1]);
        assert_eq!(parsed.signatures[2], signatures[2]);
    }

    #[test]
    fn from_bytes_partial_returns_consumed() {
        let message = create_test_message();
        let sig = test_signature(0xEE);
        let tx = V1Transaction::from_signatures(message, vec![sig]).unwrap();

        let mut bytes = tx.serialize().unwrap();
        let expected_len = bytes.len();
        bytes.extend_from_slice(&[0xAA; 100]); // Append extra data

        let (parsed, consumed) = V1Transaction::from_bytes_partial(&bytes).unwrap();
        assert_eq!(consumed, expected_len);
        assert_eq!(parsed.message, tx.message);
        assert_eq!(parsed.signatures, tx.signatures);
    }

    #[test]
    fn sanitize_rejects_too_few_signatures() {
        // Create a malformed transaction by bypassing the constructor
        let tx = V1Transaction {
            message: create_test_message(), // requires 1 signature
            signatures: vec![],             // but has 0
        };

        assert_eq!(tx.sanitize(), Err(SanitizeError::ValueOutOfBounds));
    }

    #[test]
    fn sanitize_rejects_too_many_signatures() {
        let tx = V1Transaction {
            message: create_test_message(), // requires 1 signature
            signatures: vec![test_signature(0x01), test_signature(0x02)], // but has 2
        };

        assert_eq!(tx.sanitize(), Err(SanitizeError::ValueOutOfBounds));
    }

    #[test]
    fn sanitize_accepts_valid_transaction() {
        let message = create_test_message();
        let tx = V1Transaction::from_signatures(message, vec![test_signature(0xFF)]).unwrap();
        assert!(tx.sanitize().is_ok());
    }

    #[cfg(feature = "verify")]
    #[test]
    fn verify_returns_false_for_invalid_signature() {
        let message = create_test_message();
        // Transaction with a bogus signature (not signed by the actual key)
        let tx = V1Transaction::from_signatures(message, vec![test_signature(0x00)]).unwrap();

        assert!(!tx.verify().unwrap());
    }

    #[cfg(feature = "verify")]
    #[test]
    fn verify_rejects_zero_signatures() {
        // Create a malformed transaction by bypassing the constructor
        // (message requires 1 signature, but we provide 0)
        let tx = V1Transaction {
            message: create_test_message(),
            signatures: vec![],
        };

        assert_eq!(
            tx.verify_with_results(),
            Err(V1TransactionError::SignatureCountMismatch {
                expected: 1,
                actual: 0
            })
        );
    }

    #[cfg(feature = "verify")]
    #[test]
    fn verify_rejects_too_many_signatures() {
        // Create a malformed transaction with extra signatures
        let tx = V1Transaction {
            message: create_test_message(), // requires 1 signature
            signatures: vec![test_signature(0x01), test_signature(0x02)], // but has 2
        };

        let result = tx.verify_with_results();
        assert_eq!(
            result,
            Err(V1TransactionError::SignatureCountMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    #[cfg(feature = "verify")]
    #[test]
    fn verify_rejects_not_enough_account_keys() {
        use solana_message::{v1::TransactionConfig, MessageHeader};

        // Create a malformed message where header claims more signers than account_keys
        let malformed_message = Message {
            header: MessageHeader {
                num_required_signatures: 3, // Claims 3 signers
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            config: TransactionConfig::default(),
            lifetime_specifier: Hash::new_unique(),
            account_keys: vec![Address::new_unique()], // But only 1 account
            instructions: vec![],
        };

        // Transaction has matching signature count (3) but not enough account_keys
        let tx = V1Transaction {
            message: malformed_message,
            signatures: vec![
                test_signature(0x01),
                test_signature(0x02),
                test_signature(0x03),
            ],
        };

        let result = tx.verify_with_results();
        assert_eq!(result, Err(V1TransactionError::NotEnoughAccountKeys));
    }

    #[cfg(feature = "verify")]
    #[test]
    fn verify_with_results_returns_per_signature_status() {
        let message = create_two_signer_message();

        // Both signatures are bogus
        let tx = V1Transaction::from_signatures(
            message,
            vec![test_signature(0x01), test_signature(0x02)],
        )
        .unwrap();

        let results = tx.verify_with_results().unwrap();
        assert_eq!(results.len(), 2);
        // Both should be false since we didn't actually sign
        assert!(!results[0]);
        assert!(!results[1]);
    }

    #[test]
    fn conversion_to_versioned_transaction() {
        let message = create_test_message();
        let sig = test_signature(0x77);
        let tx = V1Transaction::from_signatures(message.clone(), vec![sig]).unwrap();

        let versioned: VersionedTransaction = tx.into();

        assert_eq!(versioned.signatures, vec![sig]);
        match versioned.message {
            VersionedMessage::V1(m) => assert_eq!(m, message),
            _ => panic!("Expected V1 message"),
        }
    }

    #[test]
    fn conversion_from_versioned_v1_rejects_signature_count_mismatch() {
        // Create a message requiring 2 signatures
        let message = create_two_signer_message();

        // But only provide 1 signature
        let versioned = VersionedTransaction {
            signatures: vec![test_signature(0x01)],
            message: VersionedMessage::V1(message),
        };

        // TryFrom should reject this
        let result = V1Transaction::try_from(versioned);
        assert!(result.is_err());

        // The error should return the original transaction
        let returned_tx = result.unwrap_err();
        assert_eq!(returned_tx.signatures.len(), 1);
    }

    #[test]
    fn conversion_from_versioned_v1_succeeds() {
        let message = create_test_message();
        let sig = test_signature(0x88);

        let versioned = VersionedTransaction {
            signatures: vec![sig],
            message: VersionedMessage::V1(message.clone()),
        };

        let tx = V1Transaction::try_from(versioned).unwrap();
        assert_eq!(tx.message, message);
        assert_eq!(tx.signatures, vec![sig]);
    }

    #[test]
    fn conversion_from_versioned_legacy_fails() {
        let versioned = VersionedTransaction::default();

        let result = V1Transaction::try_from(versioned);
        assert!(result.is_err());
    }

    #[test]
    fn conversion_from_versioned_v0_fails() {
        let v0_message = solana_message::v0::Message {
            header: solana_message::MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![Address::new_unique(), Address::new_unique()],
            recent_blockhash: Hash::new_unique(),
            instructions: vec![],
            address_table_lookups: vec![],
        };

        let versioned = VersionedTransaction {
            signatures: vec![test_signature(0x01)],
            message: VersionedMessage::V0(v0_message),
        };

        let result = V1Transaction::try_from(versioned);
        assert!(result.is_err());
    }
}
