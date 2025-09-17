//! Off-chain message container for non-transaction messages.
//! Follows the format from the specification at:
//! <https://github.com/anza-xyz/agave/blob/master/docs/src/proposals/off-chain-message-signing.md>.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
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

impl MessageFormat {
    /// Returns true if `self` format can represent all messages that `required` can.
    ///
    /// This avoids relying on enum discriminant ordering in case new formats
    /// are introduced in the future that are not strict supersets of prior ones.
    pub fn includes(self, required: MessageFormat) -> bool {
        use MessageFormat::*;
        match self {
            RestrictedAscii => required == RestrictedAscii,
            LimitedUtf8 => matches!(required, RestrictedAscii | LimitedUtf8),
            ExtendedUtf8 => true,
        }
    }
}

/// Check if given bytes contain only printable ASCII characters
pub fn is_printable_ascii(data: &[u8], allow_newline: bool) -> bool {
    data.iter()
        .all(|&c| (0x20..=0x7e).contains(&c) || (allow_newline && c == 0x0a))
}

/// Check if given bytes contain valid UTF8 string
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

#[allow(clippy::arithmetic_side_effects)]
pub mod v0 {
    use {
        super::{MessageFormat, OffchainMessage as Base},
        solana_hash::Hash,
        solana_packet::PACKET_DATA_SIZE,
        solana_sanitize::SanitizeError,
        solana_sha256_hasher::Hasher,
    };

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        pub(crate) application_domain: [u8; 32],
        pub(crate) format: MessageFormat,
        pub(crate) signers: Vec<[u8; 32]>,
        pub(crate) message: Vec<u8>,
    }

    impl OffchainMessage {
        /// Encoded byte length for the application domain, format, number of signers, and message length
        pub const HEADER_LEN: usize = crate::serialization::core::PREAMBLE_LEN;
        /// Maximum number of bytes available to the core v0 payload (signers + message)
        pub const MAX_LEN: usize = u16::MAX as usize - Base::HEADER_LEN - Self::HEADER_LEN;
        /// Maximum number of bytes available to the core v0 payload (signers + message) for Ledger
        /// hardware wallets
        pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE - Base::HEADER_LEN - Self::HEADER_LEN;

        /// Compute the SHA256 hash of the serialized off-chain message
        pub fn hash(serialized_message: &[u8]) -> Result<Hash, SanitizeError> {
            let mut hasher = Hasher::default();
            hasher.hash(serialized_message);
            Ok(hasher.result())
        }

        pub fn get_format(&self) -> MessageFormat {
            self.format
        }

        pub fn get_message(&self) -> &Vec<u8> {
            &self.message
        }

        /// Application domain (32 bytes) identifying the domain of the message
        pub fn application_domain(&self) -> &[u8; 32] {
            &self.application_domain
        }

        /// Signers committing to the message (as declared in the preamble)
        pub fn signers(&self) -> &[[u8; 32]] {
            &self.signers
        }
    }
}

/// OffchainMessage is a wrapper around the v0 and v1 OffchainMessage types.
/// v0::OffchainMessage is kept for backwards compatibility.
/// Full off-chain message including signing domain and header version.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OffchainMessage {
    V0(v0::OffchainMessage),
    V1(v0::OffchainMessage),
}

impl OffchainMessage {
    pub const SIGNING_DOMAIN: &'static [u8] = b"\xffsolana offchain";
    // Header Length = Signing Domain (16) + Header Version (1)
    pub const HEADER_LEN: usize = Self::SIGNING_DOMAIN.len() + 1;

    /// Construct a new OffchainMessage object from the given version and message
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
                serialization::validate_components(signers, message)?;
                let total_size =
                    serialization::core::preamble_and_body_size(signers.len(), message.len());
                let format = serialization::detect_implied_format_for::<serialization::V0>(
                    total_size, message,
                )?;
                Ok(Self::V0(v0::OffchainMessage {
                    application_domain,
                    format,
                    signers: signers.to_vec(),
                    message: message.to_vec(),
                }))
            }
            1 => {
                serialization::validate_components(signers, message)?;
                let total_size =
                    serialization::core::preamble_and_body_size(signers.len(), message.len());
                let format = serialization::detect_implied_format_for::<serialization::V1>(
                    total_size, message,
                )?;
                Ok(Self::V1(v0::OffchainMessage {
                    application_domain,
                    format,
                    signers: signers.to_vec(),
                    message: message.to_vec(),
                }))
            }
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Serialize the off-chain message to bytes including full header
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let mut data = Self::SIGNING_DOMAIN.to_vec();
        let (version, msg) = match self {
            Self::V0(msg) => (0u8, msg),
            Self::V1(msg) => (1u8, msg),
        };
        data.push(version);
        serialization::serialize(
            &msg.application_domain,
            msg.format,
            &msg.signers,
            &msg.message,
            &mut data,
        )?;
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header
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
            0 => Ok(Self::V0(
                serialization::deserialize_for::<serialization::V0>(payload)?,
            )),
            1 => Ok(Self::V1(
                serialization::deserialize_for::<serialization::V1>(payload)?,
            )),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Compute the hash of the off-chain message
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        v0::OffchainMessage::hash(&self.serialize()?)
    }

    pub fn get_version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
            Self::V1(_) => 1,
        }
    }

    pub fn get_format(&self) -> MessageFormat {
        match self {
            Self::V0(msg) | Self::V1(msg) => msg.get_format(),
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match self {
            Self::V0(msg) | Self::V1(msg) => msg.get_message(),
        }
    }

    /// Sign the message with provided keypair
    /// If message was created with dummy signer, update it with actual signer.
    /// For spec compliance, verify signer matches expected pubkey in message.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        let signer_pubkey = signer.pubkey().to_bytes();
        let message_signers = match self {
            Self::V0(msg) | Self::V1(msg) => &msg.signers,
        };
        if message_signers.len() == 1 && message_signers[0] == [0u8; 32] {
            let (application_domain, message) = match self {
                Self::V0(msg) | Self::V1(msg) => (msg.application_domain, &msg.message),
            };
            let rebuilt_message = Self::new_with_params(
                self.get_version(),
                application_domain,
                &[signer_pubkey],
                message,
            )?;
            return Ok(signer.sign_message(&rebuilt_message.serialize()?));
        }
        if !message_signers.contains(&signer_pubkey) {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(signer.sign_message(&self.serialize()?))
    }

    /// Verify that the message signature is valid for the given public key
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
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_format() == MessageFormat::RestrictedAscii)
        );
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_message() == b"Test Message")
        );
    }

    #[test]
    fn test_offchain_message_utf8() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes()).unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::LimitedUtf8);
        assert_eq!(message.get_message(), "Тестовое сообщение".as_bytes());
        let hash = message.hash().unwrap();
        assert_eq!(
            hash.to_string(),
            "E5tkTdEzcYTe5deSvw5jqzwPUEVBT83P4aHCYxjtzEW8"
        );
    }

    #[test]
    fn test_offchain_message_v1_accepts_newline_as_ascii() {
        let msg = b"Hello\nWorld";
        let message = OffchainMessage::new_with_params(1, [0u8; 32], &[[0u8; 32]], msg).unwrap();
        assert_eq!(message.get_version(), 1);
        assert_eq!(message.get_format(), MessageFormat::RestrictedAscii);
        assert_eq!(message.get_message(), &msg);
        // round trip
        let ser = message.serialize().unwrap();
        let de = OffchainMessage::deserialize(&ser).unwrap();
        assert_eq!(de.get_version(), 1);
        assert_eq!(de.get_format(), MessageFormat::RestrictedAscii);
        assert_eq!(de.get_message(), &msg);
    }

    #[test]
    fn test_offchain_message_v0_newline_not_ascii() {
        let msg = b"Hello\nWorld";
        let message = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], msg).unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::LimitedUtf8);
        assert_eq!(message.get_message(), &msg);
        // round trip
        let ser = message.serialize().unwrap();
        let de = OffchainMessage::deserialize(&ser).unwrap();
        assert_eq!(de.get_version(), 0);
        assert_eq!(de.get_format(), MessageFormat::LimitedUtf8);
        assert_eq!(de.get_message(), &msg);
    }

    #[test]
    fn test_header_prefix_and_version_bytes() {
        let msg = b"Hdr";
        let m0 = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], msg).unwrap();
        let m1 = OffchainMessage::new_with_params(1, [0u8; 32], &[[0u8; 32]], msg).unwrap();
        let s0 = m0.serialize().unwrap();
        let s1 = m1.serialize().unwrap();
        assert_eq!(
            &s0[..OffchainMessage::SIGNING_DOMAIN.len()],
            OffchainMessage::SIGNING_DOMAIN
        );
        assert_eq!(s0[OffchainMessage::SIGNING_DOMAIN.len()], 0);
        assert_eq!(
            &s1[..OffchainMessage::SIGNING_DOMAIN.len()],
            OffchainMessage::SIGNING_DOMAIN
        );
        assert_eq!(s1[OffchainMessage::SIGNING_DOMAIN.len()], 1);
    }

    #[test]
    fn test_deserialize_rejects_wrong_prefix() {
        let msg = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], b"X").unwrap();
        let mut data = msg.serialize().unwrap();
        data[0] = 0u8; // break the 0xff domain prefix
        assert!(OffchainMessage::deserialize(&data).is_err());
    }

    #[test]
    fn test_deserialize_unknown_version_rejected() {
        // Build minimal valid body and then set an unknown version byte
        let msg = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], b"X").unwrap();
        let mut data = msg.serialize().unwrap();
        let domain_len = OffchainMessage::SIGNING_DOMAIN.len();
        data[domain_len] = 2; // unsupported version
        assert!(matches!(
            OffchainMessage::deserialize(&data),
            Err(SanitizeError::ValueOutOfBounds)
        ));
    }

    #[test]
    fn test_new_with_params_zero_signers_and_zero_message_errors() {
        assert!(matches!(
            OffchainMessage::new_with_params(0, [0u8; 32], &[], b"hi"),
            Err(SanitizeError::ValueOutOfBounds)
        ));
        assert!(matches!(
            OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], &[]),
            Err(SanitizeError::InvalidValue)
        ));
    }

    #[test]
    fn test_ascii_boundary_size_selection() {
        // total_size = PREAMBLE(36) + 1 signer (32) + msg_len
        let max_total = crate::TOTAL_MAX_LEDGER; // spec combined size for formats 0/1
        let boundary_len = max_total.saturating_sub(36 + 32);
        let msg_boundary = vec![b'a'; boundary_len];
        let msg_exceed = vec![b'a'; boundary_len + 1];

        let m_ok = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], &msg_boundary)
            .expect("boundary ascii should be allowed");
        assert_eq!(m_ok.get_format(), MessageFormat::RestrictedAscii);

        let m_big = OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], &msg_exceed)
            .expect("oversized ascii should map to ExtendedUtf8");
        assert_eq!(m_big.get_format(), MessageFormat::ExtendedUtf8);
    }

    #[test]
    fn test_invalid_utf8_rejected_for_small_sizes() {
        // 0xFF 0xFE 0xFD is invalid UTF-8 and not printable ascii
        let bad = vec![0xFF, 0xFE, 0xFD];
        assert!(matches!(
            OffchainMessage::new_with_params(0, [0u8; 32], &[[0u8; 32]], &bad),
            Err(SanitizeError::InvalidValue)
        ));
    }

    #[test]
    fn test_zero_pubkey_in_multi_signer_rejected() {
        // Multi-signer list must not contain zero pubkey
        let signers = [[0u8; 32], [1u8; 32]];
        assert!(matches!(
            OffchainMessage::new_with_params(0, [0u8; 32], &signers, b"abc"),
            Err(SanitizeError::InvalidValue)
        ));
    }

    #[test]
    fn test_signer_count_overflow_rejected() {
        // 256 signers exceeds u8::MAX, should be ValueOutOfBounds
        let signers = vec![[1u8; 32]; 256];
        assert!(matches!(
            OffchainMessage::new_with_params(0, [0u8; 32], &signers, b"abc"),
            Err(SanitizeError::ValueOutOfBounds)
        ));
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
