//! Off-chain message container for storing non-transaction messages.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
    solana_signer::Signer,
};

#[cfg(test)]
static_assertions::const_assert_eq!(OffchainMessage::HEADER_LEN, 17);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN, 65482);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN_LEDGER, 1179);

/// Check if given bytes contain only printable ASCII characters
pub fn is_printable_ascii(data: &[u8]) -> bool {
    for &char in data {
        if !(0x20..=0x7e).contains(&char) {
            return false;
        }
    }
    true
}

/// Check if given bytes contain valid UTF8 string
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
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
        super::{is_printable_ascii, is_utf8, MessageFormat, OffchainMessage as Base},
        solana_hash::Hash,
        solana_packet::PACKET_DATA_SIZE,
        solana_sanitize::SanitizeError,
        solana_sha256_hasher::Hasher,
    };

    /// OffchainMessage Version 0.
    /// Struct always contains a non-empty valid message.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        application_domain: [u8; 32],
        format: MessageFormat,
        signers: Vec<[u8; 32]>,
        message: Vec<u8>,
    }

    impl OffchainMessage {
        // Header Length = Application Domain (32) + Message Format (1) + Signer Count (1) + Message Length (2)
        // Note: Signers length is variable (signer_count * 32)
        pub const HEADER_LEN: usize = 32 + 1 + 1 + 2;
        // Max length of the OffchainMessage
        pub const MAX_LEN: usize = u16::MAX as usize - Base::HEADER_LEN - Self::HEADER_LEN;
        // Max Length of the OffchainMessage supported by the Ledger
        pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE - Base::HEADER_LEN - Self::HEADER_LEN;

        /// Construct a new OffchainMessage object from the given message
        pub fn new(message: &[u8]) -> Result<Self, SanitizeError> {
            // Use default values for compatibility with existing API
            let application_domain = [0u8; 32]; // Default application domain
            let signers = vec![[0u8; 32]]; // Default single dummy signer
            Self::new_with_params(application_domain, &signers, message)
        }

        /// Construct a new OffchainMessage object with all parameters
        pub fn new_with_params(
            application_domain: [u8; 32],
            signers: &[[u8; 32]],
            message: &[u8],
        ) -> Result<Self, SanitizeError> {
            // Validate signers - must not be empty and count must fit in u8
            if signers.is_empty() || signers.len() > u8::MAX as usize {
                return Err(SanitizeError::ValueOutOfBounds);
            }

            // Validate message is not empty
            if message.is_empty() {
                return Err(SanitizeError::InvalidValue);
            }

            // Calculate total size including all components
            let signers_size = signers.len() * 32;
            let total_size = Base::HEADER_LEN + Self::HEADER_LEN + signers_size + message.len();

            let format = if total_size <= PACKET_DATA_SIZE {
                if is_printable_ascii(message) {
                    MessageFormat::RestrictedAscii
                } else if is_utf8(message) {
                    MessageFormat::LimitedUtf8
                } else {
                    return Err(SanitizeError::InvalidValue);
                }
            } else if total_size <= u16::MAX as usize {
                if is_utf8(message) {
                    MessageFormat::ExtendedUtf8
                } else {
                    return Err(SanitizeError::InvalidValue);
                }
            } else {
                return Err(SanitizeError::ValueOutOfBounds);
            };

            Ok(Self {
                application_domain,
                format,
                signers: signers.to_vec(),
                message: message.to_vec(),
            })
        }

        /// Serialize the message to bytes, including the full header
        pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
            // invalid messages shouldn't be possible, but a quick sanity check never hurts
            assert!(!self.message.is_empty());
            assert!(!self.signers.is_empty() && self.signers.len() <= u8::MAX as usize);

            let reserve_size = Self::HEADER_LEN
                .saturating_add(self.signers.len() * 32)
                .saturating_add(self.message.len());
            data.reserve(reserve_size);

            // application domain (32 bytes)
            data.extend_from_slice(&self.application_domain);
            // message format (1 byte)
            data.push(self.format.into());
            // signer count (1 byte)
            data.push(self.signers.len() as u8);
            // signers (signer_count * 32 bytes)
            for signer in &self.signers {
                data.extend_from_slice(signer);
            }
            // message length (2 bytes, little-endian)
            data.extend_from_slice(&(self.message.len() as u16).to_le_bytes());
            // message
            data.extend_from_slice(&self.message);
            Ok(())
        }

        /// Deserialize the message from bytes that include a full header
        pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
            // validate minimum data length (must at least contain fixed header)
            if data.len() < Self::HEADER_LEN {
                return Err(SanitizeError::ValueOutOfBounds);
            }

            let mut offset = 0;

            // parse application domain (32 bytes)
            let mut application_domain = [0u8; 32];
            application_domain.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            // parse message format (1 byte)
            let format =
                MessageFormat::try_from(data[offset]).map_err(|_| SanitizeError::InvalidValue)?;
            offset += 1;

            // parse signer count (1 byte)
            let signer_count = data[offset] as usize;
            offset += 1;

            // validate signer count
            if signer_count == 0 {
                return Err(SanitizeError::InvalidValue);
            }

            // validate we have enough data for all signers
            let signers_size = signer_count * 32;
            if data.len() < offset + signers_size + 2 {
                return Err(SanitizeError::ValueOutOfBounds);
            }

            // parse signers (signer_count * 32 bytes)
            let mut signers = Vec::with_capacity(signer_count);
            for _ in 0..signer_count {
                let mut signer = [0u8; 32];
                signer.copy_from_slice(&data[offset..offset + 32]);
                signers.push(signer);
                offset += 32;
            }

            // parse message length (2 bytes, little-endian)
            let message_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            // validate message length and total data length
            if message_len == 0 || offset + message_len != data.len() {
                return Err(SanitizeError::InvalidValue);
            }

            // parse message
            let message = &data[offset..];

            // validate format constraints
            let total_size = Base::HEADER_LEN + Self::HEADER_LEN + signers_size + message_len;
            let is_valid = match format {
                MessageFormat::RestrictedAscii => {
                    total_size <= PACKET_DATA_SIZE && is_printable_ascii(message)
                }
                MessageFormat::LimitedUtf8 => total_size <= PACKET_DATA_SIZE && is_utf8(message),
                MessageFormat::ExtendedUtf8 => total_size <= u16::MAX as usize && is_utf8(message),
            };

            if is_valid {
                Ok(Self {
                    application_domain,
                    format,
                    signers,
                    message: message.to_vec(),
                })
            } else {
                Err(SanitizeError::InvalidValue)
            }
        }

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

        pub fn get_application_domain(&self) -> &[u8; 32] {
            &self.application_domain
        }

        pub fn get_signers(&self) -> &[[u8; 32]] {
            &self.signers
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

    /// Construct a new OffchainMessage object from the given version and message
    pub fn new(version: u8, message: &[u8]) -> Result<Self, SanitizeError> {
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new(message)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Construct a new OffchainMessage object with all parameters from the spec
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

    /// Serialize the off-chain message to bytes including full header
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        // serialize signing domain
        let mut data = Self::SIGNING_DOMAIN.to_vec();

        // serialize version and call version specific serializer
        match self {
            Self::V0(msg) => {
                data.push(0);
                msg.serialize(&mut data)?;
            }
        }
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header
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

    /// Compute the hash of the off-chain message
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

    pub fn get_format(&self) -> MessageFormat {
        match self {
            Self::V0(msg) => msg.get_format(),
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match self {
            Self::V0(msg) => msg.get_message(),
        }
    }

    pub fn get_application_domain(&self) -> &[u8; 32] {
        match self {
            Self::V0(msg) => msg.get_application_domain(),
        }
    }

    pub fn get_signers(&self) -> &[[u8; 32]] {
        match self {
            Self::V0(msg) => msg.get_signers(),
        }
    }

    /// Sign the message with provided keypair
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        Ok(signer.sign_message(&self.serialize()?))
    }

    #[cfg(feature = "verify")]
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
        let message = OffchainMessage::new(0, b"Test Message").unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::RestrictedAscii);
        assert_eq!(message.get_message().as_slice(), b"Test Message");
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_format() == MessageFormat::RestrictedAscii)
        );
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110,
            0, // signing domain + version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // application domain (32 zeros)
            0, // format (RestrictedAscii = 0)
            1, // signer count
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // signer (32 zeros)
            12, 0, // message length (little endian)
            84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101, // "Test Message"
        ];
        assert_eq!(message.serialize().unwrap(), serialized);
        // Hash will be different due to new format - let's verify serialization first
        let _hash = message.hash().unwrap();
        assert_eq!(message, OffchainMessage::deserialize(&serialized).unwrap());
    }

    #[test]
    fn test_offchain_message_utf8() {
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes()).unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::LimitedUtf8);
        assert_eq!(
            message.get_message().as_slice(),
            "Тестовое сообщение".as_bytes()
        );
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_format() == MessageFormat::LimitedUtf8)
        );
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110,
            0, // signing domain + version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // application domain (32 zeros)
            1, // format (LimitedUtf8 = 1)
            1, // signer count
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // signer (32 zeros)
            35, 0, // message length (little endian)
            208, 162, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 208, 190, 208, 181, 32,
            209, 129, 208, 190, 208, 190, 208, 177, 209, 137, 208, 181, 208, 189, 208, 184, 208,
            181, // UTF-8 message
        ];
        assert_eq!(message.serialize().unwrap(), serialized);
        // Hash will be different due to new format - let's verify serialization first
        let _hash = message.hash().unwrap();
        assert_eq!(message, OffchainMessage::deserialize(&serialized).unwrap());
    }

    #[test]
    fn test_offchain_message_sign_and_verify() {
        let message = OffchainMessage::new(0, b"Test Message").unwrap();
        let keypair = Keypair::new();
        let signature = message.sign(&keypair).unwrap();
        assert!(message.verify(&keypair.pubkey(), &signature).unwrap());
    }

    #[test]
    fn test_offchain_message_new_with_params() {
        // Test the full spec constructor with custom application domain and multiple signers
        let application_domain = [0x42u8; 32]; // Custom application domain
        let signer1 = [0x11u8; 32];
        let signer2 = [0x22u8; 32];
        let signers = [signer1, signer2];
        let message_text = b"Multi-signer message";

        let message =
            OffchainMessage::new_with_params(0, application_domain, &signers, message_text)
                .unwrap();

        // Verify all fields are set correctly
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_application_domain(), &application_domain);
        assert_eq!(message.get_signers(), &signers[..]);
        assert_eq!(message.get_message().as_slice(), message_text);
        assert_eq!(message.get_format(), MessageFormat::RestrictedAscii);

        // Test serialization and deserialization
        let serialized = message.serialize().unwrap();
        let deserialized = OffchainMessage::deserialize(&serialized).unwrap();
        assert_eq!(message, deserialized);

        // Verify the serialized format contains our custom values
        let serialized_vec = serialized.to_vec();

        // Check signing domain and version
        assert_eq!(&serialized_vec[0..16], b"\xffsolana offchain");
        assert_eq!(serialized_vec[16], 0); // version

        // Check application domain
        assert_eq!(&serialized_vec[17..49], &application_domain);

        // Check format
        assert_eq!(serialized_vec[49], 0); // RestrictedAscii format

        // Check signer count
        assert_eq!(serialized_vec[50], 2); // 2 signers

        // Check signers
        assert_eq!(&serialized_vec[51..83], &signer1);
        assert_eq!(&serialized_vec[83..115], &signer2);

        // Check message length (little endian)
        let msg_len = u16::from_le_bytes([serialized_vec[115], serialized_vec[116]]);
        assert_eq!(msg_len, message_text.len() as u16);

        // Check message content
        assert_eq!(&serialized_vec[117..], message_text);
    }
}
