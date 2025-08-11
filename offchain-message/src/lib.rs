//! Off-chain message container for non-transaction messages.
//! Follows the format from the specification at:
//! <https://github.com/anza-xyz/agave/blob/master/docs/src/proposals/off-chain-message-signing.md>.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
    solana_sha256_hasher::Hasher,
    solana_signature::Signature,
    solana_signer::Signer,
};

pub mod serialization;

// Assertions to prevent accidental drift
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN, 65482);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN_LEDGER, 1179);

/// Hardware-wallet safe limit (from spec: formats 0 and 1 are limited to 1232 bytes total)
pub const TOTAL_MAX_LEDGER: usize = 1232;
/// Extended format hard limit (u16::MAX total message size)
pub const TOTAL_MAX_EXTENDED: usize = u16::MAX as usize;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
pub enum MessageFormat {
    RestrictedAscii,
    LimitedUtf8,
    ExtendedUtf8,
}

/// Check if given bytes contain only printable ASCII characters
pub fn is_printable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&c| (0x20..=0x7e).contains(&c))
}

/// Check if given bytes contain valid UTF8 string
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

#[allow(clippy::arithmetic_side_effects)]
pub mod v0 {
    use {
        super::{MessageFormat, OffchainMessage as Base},
        crate::v0::serialization::V0MessageComponents,
        solana_packet::PACKET_DATA_SIZE,
    };

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        pub(crate) application_domain: [u8; 32],
        pub(crate) format: MessageFormat,
        pub(crate) signers: Vec<[u8; 32]>,
        pub(crate) message: Vec<u8>,
    }

    impl OffchainMessage {
        pub const PREAMBLE_LEN: usize = 36;
        pub const MAX_LEN: usize = u16::MAX as usize - Base::HEADER_LEN - Self::PREAMBLE_LEN;
        pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE - Base::HEADER_LEN - Self::PREAMBLE_LEN;

        pub fn get_format(&self) -> MessageFormat {
            self.format
        }

        pub fn get_message(&self) -> &[u8] {
            &self.message
        }
    }

    impl From<V0MessageComponents> for OffchainMessage {
        fn from(components: V0MessageComponents) -> Self {
            let (application_domain, format, signers, message) = components;
            Self {
                application_domain,
                format,
                signers,
                message,
            }
        }
    }

    // Smooth out nonsense like v0::serialization::v0::serialize
    pub(crate) use crate::serialization::v0 as serialization;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OffchainMessage {
    V0(v0::OffchainMessage),
}

impl OffchainMessage {
    pub const SIGNING_DOMAIN: &'static [u8] = b"\xffsolana offchain";
    // Header length = Signing Domain (16) + Header Version (1)
    pub const HEADER_LEN: usize = Self::SIGNING_DOMAIN.len() + 1;

    /// Construct a new OffchainMessage object from the given version and message.
    #[deprecated(
        since = "3.0.0",
        note = "Use `new_with_domain` or `new_with_params` instead"
    )]
    pub fn new(version: u8, message: &[u8]) -> Result<Self, SanitizeError> {
        // Default values for backwards compatibility
        Self::new_with_params(version, [0u8; 32], &[[0u8; 32]], message)
    }

    /// Construct a new single-signer OffchainMessage with custom application domain.
    /// The actual signer will be determined when `sign()` is called.
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
    /// - **Single-signer with custom domain**: You may pass`&[[0u8; 32]]` for signers,
    ///   in which case actual signer will be filled in when `sign()` is called
    /// - **Multi-signer predefined**: Pass real signer pubkeys, all signers must provide signatures
    pub fn new_with_params(
        version: u8,
        application_domain: [u8; 32],
        signers: &[[u8; 32]],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        match version {
            0 => {
                let components =
                    v0::serialization::new_with_params(application_domain, signers, message)?;
                Ok(Self::V0(components.into()))
            }
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Serialize the off-chain message to bytes including full header.
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let mut data = Self::SIGNING_DOMAIN.to_vec();
        match self {
            Self::V0(msg) => {
                data.push(0);
                v0::serialization::serialize(
                    &msg.application_domain,
                    msg.format,
                    &msg.signers,
                    &msg.message,
                    &mut data,
                )?;
            }
        }
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header.
    /// Fails if data does not start with the signing domain.
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        let domain_len = Self::SIGNING_DOMAIN.len();
        match data.get(..domain_len) {
            Some(prefix) if prefix == Self::SIGNING_DOMAIN => {}
            Some(_) => return Err(SanitizeError::InvalidValue),
            None => return Err(SanitizeError::ValueOutOfBounds),
        }
        let version = data
            .get(domain_len)
            .copied()
            .ok_or(SanitizeError::ValueOutOfBounds)?;
        let payload = data
            .get(domain_len.saturating_add(1)..)
            .ok_or(SanitizeError::ValueOutOfBounds)?;
        match version {
            0 => {
                let components = v0::serialization::deserialize(payload)?;
                Ok(Self::V0(components.into()))
            }
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Compute the hash of the off-chain message.
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        let mut hasher = Hasher::default();
        hasher.hash(&self.serialize()?);
        Ok(hasher.result())
    }

    /// Sign the message with provided keypair.
    /// If message was created with dummy signer, update it with actual signer.
    /// For spec compliance, verify signer matches expected pubkey in message.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        let signer_pubkey = signer.pubkey().to_bytes();
        let message_signers = match self {
            Self::V0(msg) => &msg.signers,
        };
        if message_signers.len() == 1 && message_signers[0] == [0u8; 32] {
            let (application_domain, message) = match self {
                Self::V0(msg) => (msg.application_domain, &msg.message),
            };
            let rebuilt_message =
                Self::new_with_params(0, application_domain, &[signer_pubkey], message)?;
            return Ok(signer.sign_message(&rebuilt_message.serialize()?));
        }
        if !message_signers.contains(&signer_pubkey) {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(signer.sign_message(&self.serialize()?))
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
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::RestrictedAscii)
        );
        assert!(matches!(message, OffchainMessage::V0(ref msg) if msg.message == b"Test Message"));
    }

    #[test]
    fn test_offchain_message_utf8() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes()).unwrap();
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
