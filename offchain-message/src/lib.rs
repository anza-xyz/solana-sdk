//! Off-chain message container for non-transaction messages.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
    solana_signer::Signer,
};

pub mod envelope;
pub mod serialization;
pub use envelope::Envelope;

#[cfg(test)]
static_assertions::const_assert_eq!(OffchainMessage::HEADER_LEN, 17);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN, 65482);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN_LEDGER, 1179);

/// Check if given bytes contain only printable ASCII characters
pub fn is_printable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&c| (0x20..=0x7e).contains(&c))
}

/// Check if given bytes contain valid UTF8 string
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

/// Hardware-wallet safe limit (from spec: formats 0 and 1 are limited to 1232 bytes total)
pub const PREAMBLE_AND_BODY_MAX_LEDGER: usize = 1232;

/// Extended format hard limit (u16::MAX total message size)
pub const PREAMBLE_AND_BODY_MAX_EXTENDED: usize = u16::MAX as usize;
pub const fn total_message_size(signer_count: usize, message_len: usize) -> usize {
    OffchainMessage::SIGNING_DOMAIN
        .len()
        .saturating_add(37) // version + app_domain + format + signer_count + msg_len
        .saturating_add(signer_count.saturating_mul(32))
        .saturating_add(message_len)
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
pub enum MessageFormat {
    RestrictedAscii,
    LimitedUtf8,
    ExtendedUtf8,
}

#[allow(clippy::arithmetic_side_effects)]
pub mod v0 {
    use {
        super::{serialization, MessageFormat, OffchainMessage as Base},
        solana_hash::Hash,
        solana_packet::PACKET_DATA_SIZE,
        solana_sanitize::SanitizeError,
        solana_sha256_hasher::Hasher,
    };

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        pub application_domain: [u8; 32],
        pub format: MessageFormat,
        pub signers: Vec<[u8; 32]>,
        pub message: Vec<u8>,
    }

    impl OffchainMessage {
        pub const HEADER_LEN: usize = 36;
        pub const MAX_LEN: usize = u16::MAX as usize - Base::HEADER_LEN - Self::HEADER_LEN;
        pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE - Base::HEADER_LEN - Self::HEADER_LEN;

        /// Construct a new OffchainMessage object from the given message
        #[deprecated(
            since = "3.0.0",
            note = "Use `new_with_domain` or `new_with_params` instead"
        )]
        pub fn new(message: &[u8]) -> Result<Self, SanitizeError> {
            Self::new_with_params([0u8; 32], &[[0u8; 32]], message)
        }

        /// Construct a new OffchainMessage object with all parameters. This
        /// must be used for multi-signer messages (where multiple parties must sign).
        pub fn new_with_params(
            application_domain: [u8; 32],
            signers: &[[u8; 32]],
            message: &[u8],
        ) -> Result<Self, SanitizeError> {
            let (application_domain, format, signers, message) =
                serialization::new_v0_with_params(application_domain, signers, message)?;
            Ok(Self {
                application_domain,
                format,
                signers,
                message,
            })
        }

        /// Serialize the message to bytes, including the full header.
        pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
            serialization::serialize_v0(
                &self.application_domain,
                self.format,
                &self.signers,
                &self.message,
                data,
            )
        }

        /// Deserialize the message from bytes that include a full header.
        pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
            let (application_domain, format, signers, message) =
                serialization::deserialize_v0(data)?;
            Ok(Self {
                application_domain,
                format,
                signers,
                message,
            })
        }

        /// Compute the SHA256 hash of the serialized off-chain message.
        pub fn hash(serialized_message: &[u8]) -> Result<Hash, SanitizeError> {
            let mut hasher = Hasher::default();
            hasher.hash(serialized_message);
            Ok(hasher.result())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OffchainMessage {
    V0(v0::OffchainMessage),
}

impl OffchainMessage {
    pub const SIGNING_DOMAIN: &'static [u8] = b"\xffsolana offchain";
    // Header Length = Signing Domain (16) + Header Version (1)
    pub const HEADER_LEN: usize = Self::SIGNING_DOMAIN.len() + 1;

    /// Construct a new OffchainMessage object from the given version and message.
    #[deprecated(
        since = "3.0.0",
        note = "Use `new_with_domain` or `new_with_params` instead"
    )]
    pub fn new(version: u8, message: &[u8]) -> Result<Self, SanitizeError> {
        #[allow(deprecated)]
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new(message)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Construct a new OffchainMessage object with custom application domain.
    /// Signer information is filled when `sign()` is called. This can only
    /// be used for single-signer messages; otherwise, use `new_with_params()`.
    pub fn new_with_domain(
        version: u8,
        application_domain: [u8; 32],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        // Use dummy signer that will be replaced during signing
        Self::new_with_params(version, application_domain, &[[0u8; 32]], message)
    }

    /// Construct a new OffchainMessage object with all parameters from the spec
    ///
    /// # Usage Patterns:
    /// - **Single-signer with custom domain**: Pass `&[[0u8; 32]]` for signers,
    ///   actual signer will be filled in when `sign()` is called
    /// - **Multi-signer predefined**: Pass real signer pubkeys, all signers must provide signatures
    pub fn new_with_params(
        version: u8,
        application_domain: [u8; 32],
        signers: &[[u8; 32]],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new_with_params(
                application_domain,
                signers,
                message,
            )?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Serialize the off-chain message to bytes including full header.
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let mut data = Self::SIGNING_DOMAIN.to_vec();
        match self {
            Self::V0(msg) => {
                data.push(0);
                msg.serialize(&mut data)?;
            }
        }
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header.
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        if data.len() <= Self::HEADER_LEN {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        let version = data[Self::SIGNING_DOMAIN.len()];
        let data = &data[Self::SIGNING_DOMAIN.len().saturating_add(1)..];
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::deserialize(data)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Compute the hash of the off-chain message.
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        match self {
            Self::V0(_) => v0::OffchainMessage::hash(&self.serialize()?),
        }
    }

    pub fn get_version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
        }
    }

    /// Sign the message with provided keypair.
    /// If message was created with dummy signer, update it with actual signer.
    /// For spec compliance, verify signer matches expected pubkey in message.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        let signer_pubkey = signer.pubkey().to_bytes();
        let message_signers = match self {
            Self::V0(msg) => &msg.signers,
        };
        if Self::is_single_dummy_signer_message(message_signers) {
            return Self::sign_with_rebuilt_message(self, signer, signer_pubkey);
        }
        Self::verify_signer_authorized(message_signers, &signer_pubkey)?;
        Ok(signer.sign_message(&self.serialize()?))
    }

    /// Check if message has single dummy/default signer.
    fn is_single_dummy_signer_message(signers: &[[u8; 32]]) -> bool {
        signers.len() == 1 && signers[0] == [0u8; 32]
    }

    /// Create proper message with actual signer and sign it.
    fn sign_with_rebuilt_message(
        original: &Self,
        signer: &dyn Signer,
        signer_pubkey: [u8; 32],
    ) -> Result<Signature, SanitizeError> {
        let (application_domain, message) = match original {
            Self::V0(msg) => (msg.application_domain, &msg.message),
        };
        let proper_message = Self::new_with_params(
            original.get_version(),
            application_domain,
            &[signer_pubkey],
            message,
        )?;
        Ok(signer.sign_message(&proper_message.serialize()?))
    }

    /// Verify that the signer is authorized to sign this message.
    fn verify_signer_authorized(
        message_signers: &[[u8; 32]],
        signer_pubkey: &[u8; 32],
    ) -> Result<(), SanitizeError> {
        if message_signers.contains(signer_pubkey) {
            Ok(())
        } else {
            Err(SanitizeError::InvalidValue)
        }
    }

    /// Verify that the message signature is valid for the given public key.
    pub fn verify(
        &self,
        signer: &solana_pubkey::Pubkey,
        signature: &Signature,
    ) -> Result<bool, SanitizeError> {
        Ok(signature.verify(signer.as_ref(), &self.serialize()?))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair};

    #[test]
    fn test_offchain_message_ascii() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, b"Test Message").unwrap();
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::RestrictedAscii)
        );
        assert!(matches!(message, OffchainMessage::V0(ref msg) if msg.message == b"Test Message"));
    }

    #[test]
    fn test_offchain_message_utf8() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes()).unwrap();
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::LimitedUtf8)
        );
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.message == "Тестовое сообщение".as_bytes())
        );
        let hash = message.hash().unwrap();
        assert_eq!(
            hash.to_string(),
            "E5tkTdEzcYTe5deSvw5jqzwPUEVBT83P4aHCYxjtzEW8"
        );
    }

    #[test]
    fn test_deprecated_new_then_sign_and_verify() {
        use solana_signer::Signer;
        let keypair = Keypair::new();
        let message_text = "Test Message";
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, message_text.as_bytes()).unwrap();
        let signature = message.sign(&keypair).unwrap();
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.message == message_text.as_bytes())
        );
        let expected_signed_message = OffchainMessage::new_with_params(
            0,
            [0u8; 32],
            &[keypair.pubkey().to_bytes()],
            message_text.as_bytes(),
        )
        .unwrap();
        assert!(expected_signed_message
            .verify(&keypair.pubkey(), &signature)
            .unwrap());
    }

    #[test]
    fn test_new_with_domain() {
        let keypair = Keypair::new();
        let custom_domain = [0x42u8; 32];
        let message = OffchainMessage::new_with_domain(0, custom_domain, b"Domain test").unwrap();
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.application_domain == custom_domain)
        );
        let signature = message.sign(&keypair).unwrap();
        let expected_message = OffchainMessage::new_with_params(
            0,
            custom_domain,
            &[keypair.pubkey().to_bytes()],
            b"Domain test",
        )
        .unwrap();
        assert!(expected_message
            .verify(&keypair.pubkey(), &signature)
            .unwrap());
    }
}
