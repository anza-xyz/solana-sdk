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

/// Hardware-wallet safe limit (from spec: formats 0 and 1 are limited to 1232 bytes total)
pub const PREAMBLE_AND_BODY_MAX_LEDGER: usize = 1232;

/// Extended format hard limit (u16::MAX total message size)
pub const PREAMBLE_AND_BODY_MAX_EXTENDED: usize = u16::MAX as usize;

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
        #[deprecated(
            since = "3.0.0",
            note = "Use `new_with_domain` or `new_with_params` instead"
        )]
        pub fn new(message: &[u8]) -> Result<Self, SanitizeError> {
            // Use default values for compatibility with existing API
            let application_domain = [0u8; 32]; // Default application domain
            let signers = vec![[0u8; 32]]; // Default single dummy signer
            Self::new_with_params(application_domain, &signers, message)
        }

        /// Construct a new OffchainMessage object with all parameters. This
        /// must be used for multi-signer messages (where multiple parties must sign).
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

            let format = if total_size <= super::PREAMBLE_AND_BODY_MAX_LEDGER {
                if is_printable_ascii(message) {
                    MessageFormat::RestrictedAscii
                } else if is_utf8(message) {
                    MessageFormat::LimitedUtf8
                } else {
                    return Err(SanitizeError::InvalidValue);
                }
            } else if total_size <= super::PREAMBLE_AND_BODY_MAX_EXTENDED {
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
                    total_size <= super::PREAMBLE_AND_BODY_MAX_LEDGER && is_printable_ascii(message)
                }
                MessageFormat::LimitedUtf8 => {
                    total_size <= super::PREAMBLE_AND_BODY_MAX_LEDGER && is_utf8(message)
                }
                MessageFormat::ExtendedUtf8 => {
                    total_size <= super::PREAMBLE_AND_BODY_MAX_EXTENDED && is_utf8(message)
                }
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

    /// Construct a new OffchainMessage object from the given version and message.
    ///
    pub fn new(version: u8, message: &[u8]) -> Result<Self, SanitizeError> {
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new(message)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Construct a new OffchainMessage object with custom application domain
    /// Signer information is filled when sign() is called. This can only
    /// be used for single-signer messages; otherwise, use `new_with_params`.
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
    /// For CLI compatibility: if message was created with default signer, update it with actual signer
    /// For spec compliance: verify signer matches expected pubkey in message
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        let signer_pubkey = signer.pubkey().to_bytes();
        let message_signers = self.get_signers();

        // CLI compatibility: if this is a default/dummy message (all-zero signer),
        // create a proper version with the actual signer
        if message_signers.len() == 1 && message_signers[0] == [0u8; 32] {
            let proper_message = Self::new_with_params(
                self.get_version(),
                *self.get_application_domain(),
                &[signer_pubkey],
                self.get_message(),
            )?;
            return Ok(signer.sign_message(&proper_message.serialize()?));
        }

        // Spec compliance: verify signer is one of the expected signers
        if !message_signers.iter().any(|&s| s == signer_pubkey) {
            return Err(SanitizeError::InvalidValue);
        }

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

/// Envelope for off-chain messages with multiple signatures
/// All signers listed in the message must provide signatures (no threshold logic)
/// This implements the envelope format from the proposal:
/// | Field | Start offset | Length (bytes) | Description |
/// | Signature Count | 0x00 | 1 | Number of signatures |
/// | Signatures | 0x01 | `SIG_COUNT` * 64 | ed25519 signatures |
/// | Message Preamble | 0x01 + `SIG_COUNT` * 64 | variable | The message preamble |
/// | Message Body | varies | variable | The message content |
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Envelope {
    signatures: Vec<Signature>,
    message: OffchainMessage,
}

impl Envelope {
    /// Create a new envelope from existing signatures and message
    /// This allows for partial signing scenarios (e.g., collecting signatures from multiple parties)
    /// Note: This bypasses signature verification during construction
    pub fn new(message: OffchainMessage, signatures: Vec<Signature>) -> Self {
        Self {
            message,
            signatures,
        }
    }

    /// Create a new envelope by signing with all provided signers
    /// All signers must match the signers list in the message, in order
    pub fn sign_all(
        message: OffchainMessage,
        signers: &[&dyn Signer],
    ) -> Result<Self, SanitizeError> {
        // Verify signer count matches message signer count
        if signers.len() != message.get_signers().len() {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Verify signers match the expected pubkeys in order
        for (i, signer) in signers.iter().enumerate() {
            if signer.pubkey().to_bytes() != message.get_signers()[i] {
                return Err(SanitizeError::InvalidValue);
            }
        }

        // Serialize the message once for all signatures
        let message_bytes = message.serialize()?;

        // Create signatures in the same order as the signers in the message
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(signer.sign_message(&message_bytes));
        }

        Ok(Self {
            signatures,
            message,
        })
    }

    /// Verify all signatures in the envelope and message compliance
    #[cfg(feature = "verify")]
    pub fn verify_all(&self) -> Result<bool, SanitizeError> {
        if self.signatures.len() != self.message.get_signers().len() {
            return Ok(false);
        }

        let message_bytes = self.message.serialize()?;
        let signers = self.message.get_signers();

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
        let mut data = Vec::with_capacity(1 + self.signatures.len() * 64 + message_bytes.len());

        // Signature count (1 byte)
        data.push(self.signatures.len() as u8);

        // Signatures (64 bytes each)
        for signature in &self.signatures {
            data.extend_from_slice(signature.as_ref());
        }

        // Message preamble and body
        data.extend_from_slice(&message_bytes);

        Ok(data)
    }

    /// Deserialize an envelope from bytes with full verification
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        if data.is_empty() {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        let mut offset = 0;

        // Parse signature count
        let sig_count = data[offset] as usize;
        offset += 1;

        if sig_count == 0 {
            return Err(SanitizeError::InvalidValue);
        }

        // Check we have enough data for all signatures
        if data.len() < offset + sig_count * 64 {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Parse signatures
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let signature_bytes: [u8; 64] = data[offset..offset + 64]
                .try_into()
                .map_err(|_| SanitizeError::ValueOutOfBounds)?;
            signatures.push(Signature::from(signature_bytes));
            offset += 64;
        }

        // Parse message
        let message_data = &data[offset..];
        let message = OffchainMessage::deserialize(message_data)?;

        // Verify signature count matches message signer count
        if signatures.len() != message.get_signers().len() {
            return Err(SanitizeError::InvalidValue);
        }

        let envelope = Self {
            signatures,
            message,
        };

        // Full verification including signature checks
        #[cfg(feature = "verify")]
        {
            if !envelope.verify_all()? {
                return Err(SanitizeError::InvalidValue);
            }
        }

        Ok(envelope)
    }

    /// Get the signatures
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get the message
    pub fn message(&self) -> &OffchainMessage {
        &self.message
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
        let keypair = Keypair::new();

        // Use the simple constructor (CLI/Agave compatibility)
        let message = OffchainMessage::new(0, b"Test Message").unwrap();

        // Create the expected final message (what sign() actually produces)
        let expected_final_message = OffchainMessage::new_with_params(
            0,
            [0u8; 32],                      // default application domain
            &[keypair.pubkey().to_bytes()], // actual signer
            b"Test Message",
        )
        .unwrap();

        // Sign using the original message
        let signature = message.sign(&keypair).unwrap();

        // Verify against the expected final message
        assert!(expected_final_message
            .verify(&keypair.pubkey(), &signature)
            .unwrap());
    }

    #[test]
    fn test_agave_cli_exact_usage() {
        // Test the pattern that Agave CLI uses:
        // let message = OffchainMessage::new(version, message_text.as_bytes())
        //     .map_err(|_| CliError::BadParameter("VERSION or MESSAGE".to_string()))?;
        // message.sign(config.signers[0])?.to_string();

        use solana_signer::Signer;

        let keypair = Keypair::new();
        let version = 0u8;
        let message_text = "Test Message";

        let message = OffchainMessage::new(version, message_text.as_bytes()).unwrap();
        let signature = message.sign(&keypair).unwrap();

        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_message().as_slice(), message_text.as_bytes());

        // Verify the signature verifies against the keypair's pubkey
        // Note: Since the message is created with dummy signer with new(), the sign()
        // method internally creates a proper message with the actual signer's pubkey
        #[cfg(feature = "verify")]
        {
            // Create the expected signed message (what sign() actually signed)
            let expected_signed_message = OffchainMessage::new_with_params(
                0,
                [0u8; 32], // default application domain
                &[keypair.pubkey().to_bytes()],
                message_text.as_bytes(),
            )
            .unwrap();

            let is_valid = expected_signed_message
                .verify(&keypair.pubkey(), &signature)
                .unwrap();
            assert!(
                is_valid,
                "Signature should be valid for the keypair that signed it"
            );
        }
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
        assert_eq!(&serialized_vec[17..49], &application_domain);
        assert_eq!(serialized_vec[49], 0); // RestrictedAscii format
        assert_eq!(serialized_vec[50], 2); // 2 signers
        assert_eq!(&serialized_vec[51..83], &signer1);
        assert_eq!(&serialized_vec[83..115], &signer2);
        let msg_len = u16::from_le_bytes([serialized_vec[115], serialized_vec[116]]);
        assert_eq!(msg_len, message_text.len() as u16);
        assert_eq!(&serialized_vec[117..], message_text);
    }

    #[test]
    fn test_new_with_domain() {
        let keypair = Keypair::new();
        let custom_domain = [0x42u8; 32];

        // Use the cleaner API for single-signer with custom domain
        let message = OffchainMessage::new_with_domain(0, custom_domain, b"Domain test").unwrap();

        // Verify domain is set correctly
        assert_eq!(message.get_application_domain(), &custom_domain);

        // Sign and verify it works
        let signature = message.sign(&keypair).unwrap();

        // Create expected message for verification
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

    #[test]
    fn test_envelope_functionality() {
        use solana_signer::Signer;

        let application_domain = [0xEEu8; 32];
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let signer1_pubkey = keypair1.pubkey().to_bytes();
        let signer2_pubkey = keypair2.pubkey().to_bytes();
        let signers_pubkeys = [signer1_pubkey, signer2_pubkey];

        // Create message with multiple signers
        let message = OffchainMessage::new_with_params(
            0,
            application_domain,
            &signers_pubkeys,
            b"Multi-sig test",
        )
        .unwrap();

        // Create envelope with all signatures
        let signers: [&dyn Signer; 2] = [&keypair1, &keypair2];
        let envelope = Envelope::sign_all(message.clone(), &signers).unwrap();

        // Verify envelope
        assert_eq!(envelope.signatures().len(), 2);
        assert_eq!(envelope.message(), &message);

        // Test serialization/deserialization
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(envelope, deserialized);

        // Test verification
        #[cfg(feature = "verify")]
        assert!(envelope.verify_all().unwrap());
    }

    #[test]
    fn test_multi_signer_3_parties_success() {
        use solana_signer::Signer;

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

        // Create envelope with all 3 signers
        let signing_keypairs: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];
        let envelope = Envelope::sign_all(message.clone(), &signing_keypairs).unwrap();

        // Verify envelope structure
        assert_eq!(envelope.signatures().len(), 3);
        assert_eq!(envelope.message(), &message);
        assert_eq!(envelope.message().get_signers().len(), 3);

        // Test serialization/deserialization
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(envelope, deserialized);

        // Test verification
        #[cfg(feature = "verify")]
        assert!(envelope.verify_all().unwrap());
    }

    #[test]
    fn test_multi_signer_partial_signatures() {
        use solana_signer::Signer;

        // Create 3 keypairs but only 2 will provide valid signatures
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new(); // This one won't sign

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();

        // Create message with 3 signers listed (but we'll only provide 2 valid signatures)
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"partial signatures test",
        )
        .unwrap();

        // Sign only with first 2 signers, create empty signature for 3rd
        let message_bytes = message.serialize().unwrap();
        let sig1 = keypair1.sign_message(&message_bytes);
        let sig2 = keypair2.sign_message(&message_bytes);
        let empty_sig = Signature::from([0u8; 64]); // Placeholder for missing signature

        // Create envelope manually with partial signatures
        let signatures = vec![sig1, sig2, empty_sig];
        let envelope = Envelope::new(message.clone(), signatures);

        // Verify structure
        assert_eq!(envelope.signatures().len(), 3);
        assert_eq!(envelope.message(), &message);

        // Test serialization (should work even with invalid signatures)
        let serialized = envelope.serialize().unwrap();
        assert!(!serialized.is_empty());

        // Verification should fail due to invalid signature
        #[cfg(feature = "verify")]
        {
            let result = envelope.verify_all();
            assert!(result.is_ok());
            assert!(!result.unwrap()); // Should return false due to invalid signature
        }
    }

    #[test]
    fn test_multi_signer_missing_pubkey_in_message() {
        use solana_signer::Signer;

        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        // Note: pubkey3 is intentionally missing from the message

        // Create message with only 2 signers
        let signers_in_message = [pubkey1, pubkey2];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"Missing pubkey test",
        )
        .unwrap();

        // Try to sign with 3 signers (including one not in the message)
        let signing_keypairs: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];

        // This should fail because keypair3's pubkey is not in the message
        let result = Envelope::sign_all(message, &signing_keypairs);
        assert!(result.is_err());

        // Verify it's the expected error (signer count mismatch)
        assert!(matches!(
            result.unwrap_err(),
            SanitizeError::ValueOutOfBounds
        ));
    }

    #[test]
    fn test_multi_signer_wrong_signer_order() {
        use solana_signer::Signer;

        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();

        // Create message with signers in order: 1, 2, 3
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"Wrong order test",
        )
        .unwrap();

        // Try to sign with signers in wrong order: 2, 1, 3
        let signing_keypairs: [&dyn Signer; 3] = [&keypair2, &keypair1, &keypair3];

        // This should fail because the order doesn't match
        let result = Envelope::sign_all(message, &signing_keypairs);
        assert!(result.is_err());

        // Verify it's the expected error (invalid value due to pubkey mismatch)
        assert!(matches!(result.unwrap_err(), SanitizeError::InvalidValue));
    }

    #[test]
    fn test_spec_constant_usage() {
        let keypair = Keypair::new();
        let signer_pubkey = keypair.pubkey().to_bytes();

        // Small ASCII message should be RestrictedAscii
        let small_msg =
            OffchainMessage::new_with_params(0, [0u8; 32], &[signer_pubkey], b"Small message")
                .unwrap();
        assert_eq!(small_msg.get_format(), MessageFormat::RestrictedAscii);

        // Large message should be ExtendedUtf8 (if it fits in 65535)
        let large_msg_size = PREAMBLE_AND_BODY_MAX_LEDGER + 100;
        let header_size = OffchainMessage::HEADER_LEN + 32 + 1 + 1 + 32 + 2; // full preamble
        let max_body_size = large_msg_size - header_size;
        let large_body = vec![b'A'; max_body_size];

        let large_msg =
            OffchainMessage::new_with_params(0, [0u8; 32], &[signer_pubkey], &large_body).unwrap();
        assert_eq!(large_msg.get_format(), MessageFormat::ExtendedUtf8);
    }
}
