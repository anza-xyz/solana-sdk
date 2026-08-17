#[cfg(feature = "verify")]
use solana_transaction_error::{TransactionError, TransactionResult};
use {
    crate::versioned::VersionedTransaction, alloc::vec::Vec,
    solana_message::SanitizedVersionedMessage, solana_sanitize::SanitizeError,
    solana_signature::Signature,
};

/// Wraps a sanitized `VersionedTransaction` to provide a safe API
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedTransaction {
    /// List of signatures
    pub(crate) signatures: Vec<Signature>,
    /// Message to sign.
    pub(crate) message: SanitizedVersionedMessage,
}

impl TryFrom<VersionedTransaction> for SanitizedVersionedTransaction {
    type Error = SanitizeError;
    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        Self::try_new(tx)
    }
}

impl SanitizedVersionedTransaction {
    pub fn try_new(tx: VersionedTransaction) -> Result<Self, SanitizeError> {
        tx.sanitize_signatures()?;
        Ok(Self {
            signatures: tx.signatures,
            message: SanitizedVersionedMessage::try_from(tx.message)?,
        })
    }

    pub fn get_message(&self) -> &SanitizedVersionedMessage {
        &self.message
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Verifies that all signers have signed the message and returns its hash.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::SignatureFailure`] if any signature is invalid.
    #[cfg(feature = "verify")]
    pub fn verify_and_hash_message(&self) -> TransactionResult<solana_hash::Hash> {
        let message_bytes = self.message.message.serialize();
        if self
            .signatures
            .iter()
            .zip(self.message.message.static_account_keys())
            .any(|(signature, pubkey)| !signature.verify(pubkey.as_ref(), &message_bytes))
        {
            Err(TransactionError::SignatureFailure)
        } else {
            Ok(solana_message::VersionedMessage::hash_raw_message(
                &message_bytes,
            ))
        }
    }

    /// Consumes the SanitizedVersionedTransaction, returning the fields individually.
    pub fn destruct(self) -> (Vec<Signature>, SanitizedVersionedMessage) {
        (self.signatures, self.message)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        alloc::vec,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_message::{v0, VersionedMessage},
        solana_pubkey::Pubkey,
        solana_signer::Signer,
    };

    #[test]
    fn test_try_new_with_invalid_signatures() {
        let tx = VersionedTransaction {
            signatures: vec![],
            message: VersionedMessage::V0(
                v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap(),
            ),
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::IndexOutOfBounds)
        );
    }

    #[test]
    fn test_try_new() {
        let mut message =
            v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap();
        message.header.num_readonly_signed_accounts += 1;

        let tx = VersionedTransaction {
            signatures: vec![Signature::default()],
            message: VersionedMessage::V0(message),
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::InvalidValue)
        );
    }

    #[cfg(feature = "verify")]
    #[test]
    fn test_verify_and_hash_message() {
        let keypair = Keypair::new();
        let message = VersionedMessage::V0(
            v0::Message::try_compile(&keypair.pubkey(), &[], &[], Hash::default()).unwrap(),
        );
        let tx = VersionedTransaction::try_new(message, &[&keypair]).unwrap();
        let mut tx = SanitizedVersionedTransaction::try_new(tx).unwrap();

        let message_bytes = tx.message.message.serialize();
        assert_eq!(
            tx.verify_and_hash_message(),
            Ok(VersionedMessage::hash_raw_message(&message_bytes))
        );

        tx.signatures[0] = Signature::default();
        assert_eq!(
            tx.verify_and_hash_message(),
            Err(TransactionError::SignatureFailure)
        );
    }
}
