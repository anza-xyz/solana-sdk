//! Envelope for off-chain messages with multiple signatures.
//! Matches the format from the specification at:
//! https://github.com/anza-xyz/agave/blob/master/docs/src/proposals/off-chain-message-signing.md).

use {
    crate::OffchainMessage,
    solana_sanitize::SanitizeError,
    solana_serialize_utils::{append_slice, append_u8, read_slice, read_u8},
    solana_signature::Signature,
    solana_signer::Signer,
};

/// Envelope for off-chain messages with multiple signatures.
/// All signers listed in the message must provide signatures.
/// This implements the envelope format from the spec:
/// | Field | Start offset | Length (bytes) | Description |
/// | Signature Count | 0x00 | 1 | Number of signatures |
/// | Signatures | 0x01 | `SIG_COUNT` * 64 | ed25519 signatures |
/// | Message Preamble | 0x01 + `SIG_COUNT` * 64 | variable | The message preamble |
/// | Message Body | varies | variable | The message content |
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Envelope {
    pub signatures: Vec<Signature>,
    pub message: OffchainMessage,
}

impl Envelope {
    /// Extract the signer list from a message
    fn message_signers(message: &OffchainMessage) -> &[[u8; 32]] {
        match message {
            crate::OffchainMessage::V0(msg) => &msg.signers,
        }
    }

    /// Create a new envelope by signing with all provided signers
    /// All signers must match the signers list in the message, in order
    pub fn new(message: OffchainMessage, signers: &[&dyn Signer]) -> Result<Self, SanitizeError> {
        let message_signers = Self::message_signers(&message);

        // Verify signer count and validate each signer's pubkey in one pass
        if signers.len() != message_signers.len() {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        for (signer, expected_pubkey) in signers.iter().zip(message_signers.iter()) {
            if signer.pubkey().to_bytes() != *expected_pubkey {
                return Err(SanitizeError::InvalidValue);
            }
        }
        // Serialize the message once for all signatures
        let message_bytes = message.serialize()?;
        let signatures: Vec<_> = signers
            .iter()
            .map(|s| s.sign_message(&message_bytes))
            .collect();
        Ok(Self {
            signatures,
            message,
        })
    }

    /// Verify all signatures in the envelope and message compliance
    pub fn verify_all(&self) -> Result<bool, SanitizeError> {
        let message_signers = Self::message_signers(&self.message);
        if self.signatures.len() != message_signers.len() {
            return Ok(false);
        }
        let message_bytes = self.message.serialize()?;
        let signers = message_signers;
        // Verify each signature matches the corresponding pubkey
        for (signature, signer_bytes) in self.signatures.iter().zip(signers.iter()) {
            let pubkey = ::solana_pubkey::Pubkey::try_from(signer_bytes.as_slice())
                .map_err(|_| SanitizeError::InvalidValue)?;
            if !signature.verify(pubkey.as_ref(), &message_bytes) {
                return Ok(false);
            }
        }
        // Post-verification: re-deserialize to ensure message compliance
        let _verified_message = OffchainMessage::deserialize(&message_bytes)?;
        Ok(true)
    }

    /// Serialize the complete envelope (signatures + message)
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let message_bytes = self.message.serialize()?;
        let mut data = Vec::with_capacity(
            1_usize
                .saturating_add(self.signatures.len().saturating_mul(64))
                .saturating_add(message_bytes.len()),
        );
        // Signature count (1 byte)
        append_u8(&mut data, self.signatures.len() as u8);
        // Signatures (64 bytes each)
        for signature in &self.signatures {
            append_slice(&mut data, signature.as_ref());
        }
        // Message preamble and body
        append_slice(&mut data, &message_bytes);
        Ok(data)
    }

    /// Deserialize an envelope from bytes with full verification
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        if data.is_empty() {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        let mut offset = 0;
        // Parse signature count
        let sig_count =
            read_u8(&mut offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)? as usize;
        if sig_count == 0 {
            return Err(SanitizeError::InvalidValue);
        }
        // Parse signatures
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let signature_bytes =
                read_slice(&mut offset, data, 64).map_err(|_| SanitizeError::ValueOutOfBounds)?;
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| SanitizeError::ValueOutOfBounds)?;
            signatures.push(Signature::from(signature_array));
        }

        // Parse message
        let message_data = &data[offset..];
        let message = OffchainMessage::deserialize(message_data)?;
        // Verify signature count matches message signer count
        let message_signers = Self::message_signers(&message);
        if signatures.len() != message_signers.len() {
            return Err(SanitizeError::InvalidValue);
        }
        let envelope = Self {
            signatures,
            message,
        };

        if !envelope.verify_all()? {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::OffchainMessage, solana_keypair::Keypair, solana_signer::Signer};

    #[test]
    fn test_envelope_functionality() {
        // Create 3 keypairs for a 3-party multi-signer message (all must sign)
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();
        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();
        // Create message with all 3 signers listed
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let application_domain = [0x42u8; 32];
        let message = OffchainMessage::new_with_params(
            0,
            application_domain,
            &signers_in_message,
            b"3-party multi-signer test",
        )
        .unwrap();
        // envelope with all 3 signers
        let signing_keypairs: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];
        let envelope = Envelope::new(message.clone(), &signing_keypairs).unwrap();
        assert_eq!(envelope.signatures.len(), 3);
        assert_eq!(envelope.message, message);
        assert!(
            matches!(envelope.message, crate::OffchainMessage::V0(ref msg) if msg.signers.len() == 3)
        );

        // Test serialization/deserialization and verification
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
        assert!(envelope.verify_all().unwrap());
    }

    #[test]
    fn test_envelope_validation_failures() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();
        let wrong_keypair = Keypair::new();
        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();
        // Test 1: Wrong signer count (too many signers)
        let message_2_signers =
            OffchainMessage::new_with_params(0, [0x42u8; 32], &[pubkey1, pubkey2], b"count test")
                .unwrap();
        let too_many_signers: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];
        assert!(matches!(
            Envelope::new(message_2_signers, &too_many_signers).unwrap_err(),
            SanitizeError::ValueOutOfBounds
        ));
        // Test 2: Wrong signer identity
        let message_3_signers = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &[pubkey1, pubkey2, pubkey3],
            b"identity test",
        )
        .unwrap();
        let wrong_identity: [&dyn Signer; 3] = [&keypair1, &keypair2, &wrong_keypair];
        assert!(matches!(
            Envelope::new(message_3_signers.clone(), &wrong_identity).unwrap_err(),
            SanitizeError::InvalidValue
        ));
        // Test 3: Wrong signer order
        let wrong_order: [&dyn Signer; 3] = [&keypair2, &keypair1, &keypair3];
        assert!(matches!(
            Envelope::new(message_3_signers, &wrong_order).unwrap_err(),
            SanitizeError::InvalidValue
        ));
    }
}
