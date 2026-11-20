//! Off-chain message container for storing non-transaction messages.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_address::Address,
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
    solana_signer::Signer,
};

mod offspec;

pub use offspec::{v0, OffchainMessage};

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

pub mod with_signers {
    pub mod v0 {
        use {
            crate::{is_printable_ascii, is_utf8, MessageFormat, OffchainMessageWithSigners},
            solana_address::{Address, ADDRESS_BYTES},
            solana_hash::Hash,
            solana_packet::PACKET_DATA_SIZE,
            solana_sanitize::SanitizeError,
            solana_sha256_hasher::Hasher,
        };

        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct OffchainMessage {
            application_domain: [u8; 32],
            format: MessageFormat,
            signers: Vec<Address>,
            message: Vec<u8>,
        }

        impl OffchainMessage {
            // Header Length = Application Domain (32) + Message Format (1) + Signer Count (1)
            pub const HEADER_LEN: usize = 34;
            const MESSAGE_LENGTH_LEN: usize = 2;
            // Max length of the OffchainMessage, including the preamble
            pub const MAX_LEN: usize = u16::MAX as usize;
            // Max Length of the OffchainMessage supported by the Ledger
            pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE;

            /// Construct a new OffchainMessage object from the given message
            pub fn new(
                format: MessageFormat,
                application_domain: [u8; 32],
                signers: &[Address],
                message: &[u8],
            ) -> Result<Self, SanitizeError> {
                Self::check(format, signers.len(), message)?;
                Ok(Self {
                    application_domain,
                    format,
                    signers: signers.to_vec(),
                    message: message.to_vec(),
                })
            }

            fn preamble_len(signer_count: usize) -> usize {
                OffchainMessageWithSigners::HEADER_LEN
                    .saturating_add(Self::HEADER_LEN)
                    .saturating_add(signer_count.saturating_mul(ADDRESS_BYTES))
                    .saturating_add(Self::MESSAGE_LENGTH_LEN)
            }

            fn check(
                format: MessageFormat,
                signer_count: usize,
                message: &[u8],
            ) -> Result<(), SanitizeError> {
                if signer_count == 0 || message.is_empty() {
                    return Err(SanitizeError::InvalidValue);
                }
                if signer_count > u8::MAX as usize {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                let (max_len, is_valid) = match format {
                    MessageFormat::RestrictedAscii => {
                        (Self::MAX_LEN_LEDGER, is_printable_ascii(message))
                    }
                    MessageFormat::LimitedUtf8 => (Self::MAX_LEN_LEDGER, is_utf8(message)),
                    MessageFormat::ExtendedUtf8 => (Self::MAX_LEN, is_utf8(message)),
                };
                if Self::preamble_len(signer_count).saturating_add(message.len()) > max_len {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                if !is_valid {
                    return Err(SanitizeError::InvalidValue);
                }
                Ok(())
            }

            /// Serialize the message to bytes
            pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
                assert!(!self.message.is_empty() && self.message.len() <= u16::MAX as usize);
                assert!(!self.signers.is_empty() && self.signers.len() <= u8::MAX as usize);
                data.reserve(
                    Self::preamble_len(self.signers.len())
                        .saturating_sub(OffchainMessageWithSigners::HEADER_LEN)
                        .saturating_add(self.message.len()),
                );
                data.extend_from_slice(&self.application_domain);
                data.push(self.format.into());
                data.push(self.signers.len() as u8);
                for signer in &self.signers {
                    data.extend_from_slice(signer.as_ref());
                }
                data.extend_from_slice(&(self.message.len() as u16).to_le_bytes());
                data.extend_from_slice(&self.message);
                Ok(())
            }

            /// Deserialize the message from bytes that include a full header
            pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
                // validate data length
                if data.len() < Self::HEADER_LEN {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                // decode header
                let application_domain =
                    <[u8; 32]>::try_from(&data[..32]).map_err(|_| SanitizeError::InvalidValue)?;
                let format =
                    MessageFormat::try_from(data[32]).map_err(|_| SanitizeError::InvalidValue)?;
                let signer_count = data[33] as usize;
                let signers_end =
                    Self::HEADER_LEN.saturating_add(signer_count.saturating_mul(ADDRESS_BYTES));
                let message_start = signers_end.saturating_add(Self::MESSAGE_LENGTH_LEN);
                // check header
                if data.len() < message_start {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                // signers
                let signers = data[Self::HEADER_LEN..signers_end]
                    .chunks_exact(ADDRESS_BYTES)
                    .map(|bytes| Address::try_from(bytes).map_err(|_| SanitizeError::InvalidValue))
                    .collect::<Result<Vec<_>, _>>()?;
                // message length
                let message_len =
                    u16::from_le_bytes([data[signers_end], data[signers_end.saturating_add(1)]])
                        as usize;
                let message = &data[message_start..];
                if message.len() != message_len {
                    return Err(SanitizeError::InvalidValue);
                }
                // check format
                Self::check(format, signers.len(), message)?;
                Ok(Self {
                    application_domain,
                    format,
                    signers,
                    message: message.to_vec(),
                })
            }

            /// Compute the SHA256 hash of the serialized off-chain message
            pub fn hash(serialized_message: &[u8]) -> Result<Hash, SanitizeError> {
                let mut hasher = Hasher::default();
                hasher.hash(serialized_message);
                Ok(hasher.result())
            }

            pub fn get_application_domain(&self) -> &[u8; 32] {
                &self.application_domain
            }

            pub fn get_format(&self) -> MessageFormat {
                self.format
            }

            pub fn get_message(&self) -> &Vec<u8> {
                &self.message
            }

            pub fn get_signers(&self) -> &[Address] {
                &self.signers
            }
        }
    }

    pub mod v1 {
        use {
            crate::{is_utf8, MessageFormat},
            solana_address::{Address, ADDRESS_BYTES},
            solana_hash::Hash,
            solana_sanitize::SanitizeError,
            solana_sha256_hasher::Hasher,
        };

        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct OffchainMessage {
            message: Vec<u8>,
            signers: Vec<Address>,
        }

        impl OffchainMessage {
            // Header Length = Signer Count (1)
            pub const HEADER_LEN: usize = 1;

            /// Construct a new OffchainMessage object from the given message
            pub fn new(message: &[u8], signers: &[Address]) -> Result<Self, SanitizeError> {
                if message.is_empty() || !is_utf8(message) {
                    return Err(SanitizeError::InvalidValue);
                }
                let mut signers = signers.to_vec();
                signers.sort_unstable();
                signers.dedup();
                if signers.is_empty() {
                    return Err(SanitizeError::InvalidValue);
                }
                if signers.len() > u8::MAX as usize {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                Ok(Self {
                    message: message.to_vec(),
                    signers,
                })
            }

            /// Serialize the message to bytes
            pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
                assert!(!self.message.is_empty());
                assert!(!self.signers.is_empty() && self.signers.len() <= u8::MAX as usize);
                data.reserve(
                    Self::HEADER_LEN
                        .saturating_add(self.signers.len().saturating_mul(ADDRESS_BYTES))
                        .saturating_add(self.message.len()),
                );
                // signer count
                data.push(self.signers.len() as u8);
                for signer in &self.signers {
                    data.extend_from_slice(signer.as_ref());
                }
                // message
                data.extend_from_slice(&self.message);
                Ok(())
            }

            /// Deserialize the message from bytes that include a full header
            pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
                // validate data length
                if data.len() <= Self::HEADER_LEN {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                // decode header
                let signer_count = data[0] as usize;
                if signer_count == 0 {
                    return Err(SanitizeError::InvalidValue);
                }
                let header_len =
                    Self::HEADER_LEN.saturating_add(signer_count.saturating_mul(ADDRESS_BYTES));
                // check header
                if data.len() <= header_len {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                let signers = data[Self::HEADER_LEN..header_len]
                    .chunks_exact(ADDRESS_BYTES)
                    .map(|bytes| Address::try_from(bytes).map_err(|_| SanitizeError::InvalidValue))
                    .collect::<Result<Vec<_>, _>>()?;
                if !signers.windows(2).all(|pair| pair[0] < pair[1]) {
                    return Err(SanitizeError::InvalidValue);
                }
                let message = &data[header_len..];
                if is_utf8(message) {
                    Ok(Self {
                        message: message.to_vec(),
                        signers,
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

            pub fn get_message(&self) -> &Vec<u8> {
                &self.message
            }

            pub fn get_format(&self) -> MessageFormat {
                MessageFormat::ExtendedUtf8
            }

            pub fn get_signers(&self) -> &[Address] {
                &self.signers
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum VersionInput {
    V0 {
        format: MessageFormat,
        application_domain: [u8; 32],
    },
    V1,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum OffchainMessageWithSigners {
    V0(with_signers::v0::OffchainMessage),
    V1(with_signers::v1::OffchainMessage),
}

impl OffchainMessageWithSigners {
    pub const SIGNING_DOMAIN: &'static [u8] = b"\xffsolana offchain";
    // Header Length = Signing Domain (16) + Header Version (1)
    pub const HEADER_LEN: usize = Self::SIGNING_DOMAIN.len() + 1;

    /// Construct a new OffchainMessageWithSigners object from the given version input, signers
    /// and message
    pub fn new(
        input: VersionInput,
        signers: &[Address],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        match input {
            VersionInput::V0 {
                format,
                application_domain,
            } => Ok(Self::V0(with_signers::v0::OffchainMessage::new(
                format,
                application_domain,
                signers,
                message,
            )?)),
            VersionInput::V1 => Ok(Self::V1(with_signers::v1::OffchainMessage::new(
                message, signers,
            )?)),
        }
    }

    /// Serialize the off-chain message to bytes including full header
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let mut data = Self::SIGNING_DOMAIN.to_vec();
        match self {
            Self::V0(msg) => {
                data.push(0);
                msg.serialize(&mut data)?;
            }
            Self::V1(msg) => {
                data.push(1);
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
        if !data.starts_with(Self::SIGNING_DOMAIN) {
            return Err(SanitizeError::InvalidValue);
        }
        let version = data[Self::SIGNING_DOMAIN.len()];
        let data = &data[Self::HEADER_LEN..];
        match version {
            0 => Ok(Self::V0(with_signers::v0::OffchainMessage::deserialize(
                data,
            )?)),
            1 => Ok(Self::V1(with_signers::v1::OffchainMessage::deserialize(
                data,
            )?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Compute the hash of the off-chain message
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        match self {
            Self::V0(_) => with_signers::v0::OffchainMessage::hash(&self.serialize()?),
            Self::V1(_) => with_signers::v1::OffchainMessage::hash(&self.serialize()?),
        }
    }

    pub fn get_version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
            Self::V1(_) => 1,
        }
    }

    pub fn get_format(&self) -> MessageFormat {
        match self {
            Self::V0(msg) => msg.get_format(),
            Self::V1(msg) => msg.get_format(),
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match self {
            Self::V0(msg) => msg.get_message(),
            Self::V1(msg) => msg.get_message(),
        }
    }

    pub fn get_signers(&self) -> &[Address] {
        match self {
            Self::V0(msg) => msg.get_signers(),
            Self::V1(msg) => msg.get_signers(),
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
        if !self.get_signers().contains(signer) {
            return Ok(false);
        }
        Ok(signature.verify(signer.as_ref(), &self.serialize()?))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair, std::str::FromStr};

    // V0 message from @solana/kit 8.6.0 `getOffchainMessageV0Encoder`, 130 bytes:
    //   [0..16)    signing domain     b"\xffsolana offchain"
    //   [16]       version            0
    //   [17..49)   application domain GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse (secret key [3; 32])
    //   [49]       message format     0 (restricted ASCII)
    //   [50]       signer count       2
    //   [51..83)   signer 1           AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9 (secret key [1; 32])
    //   [83..115)  signer 2           9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu (secret key [2; 32])
    //   [115..117) message length     13 (u16 LE)
    //   [117..130) content            b"Hello, world!"
    const KIT_V0_SERIALIZED: [u8; 130] = [
        255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 0, 237, 73, 40,
        198, 40, 209, 194, 198, 234, 233, 3, 56, 144, 89, 149, 97, 41, 89, 39, 58, 92, 99, 249, 54,
        54, 193, 70, 20, 172, 135, 55, 209, 0, 2, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82,
        219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15,
        111, 92, 129, 57, 119, 14, 168, 125, 23, 95, 86, 163, 84, 102, 195, 76, 126, 204, 203, 141,
        138, 145, 180, 238, 55, 162, 93, 246, 15, 91, 143, 201, 179, 148, 13, 0, 72, 101, 108, 108,
        111, 44, 32, 119, 111, 114, 108, 100, 33,
    ];

    #[test]
    fn test_offchain_message_rejects_kit_v0_with_signers() {
        // The first application domain byte (237) is read as the message format.
        assert_eq!(
            OffchainMessage::deserialize(&KIT_V0_SERIALIZED),
            Err(SanitizeError::InvalidValue),
        );
    }

    #[test]
    fn test_offchain_message_kit_v0_parity() {
        let signer_1 = Keypair::new_from_array([1; 32]).pubkey();
        let signer_2 = Keypair::new_from_array([2; 32]).pubkey();
        let application_domain = Keypair::new_from_array([3; 32]).pubkey().to_bytes();

        let message = OffchainMessageWithSigners::deserialize(&KIT_V0_SERIALIZED).unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::RestrictedAscii);
        assert_eq!(message.get_message().as_slice(), b"Hello, world!");
        assert_eq!(message.get_signers(), [signer_1, signer_2].as_slice());
        assert!(
            matches!(message, OffchainMessageWithSigners::V0(ref msg) if *msg.get_application_domain() == application_domain)
        );

        let built = OffchainMessageWithSigners::new(
            VersionInput::V0 {
                format: MessageFormat::RestrictedAscii,
                application_domain,
            },
            &[signer_1, signer_2],
            b"Hello, world!",
        )
        .unwrap();
        assert_eq!(built.serialize().unwrap(), KIT_V0_SERIALIZED);
        assert_eq!(built, message);
    }

    #[test]
    fn test_offchain_message_v0_format_mismatch() {
        let input = |format| VersionInput::V0 {
            format,
            application_domain: [0; 32],
        };
        let signers = [Address::new_from_array([1; 32])];
        assert_eq!(
            OffchainMessageWithSigners::new(
                input(MessageFormat::RestrictedAscii),
                &signers,
                "Тестовое сообщение".as_bytes()
            ),
            Err(SanitizeError::InvalidValue),
        );
        assert_eq!(
            OffchainMessageWithSigners::new(input(MessageFormat::LimitedUtf8), &signers, &[0xff]),
            Err(SanitizeError::InvalidValue),
        );
        assert!(OffchainMessageWithSigners::new(
            input(MessageFormat::LimitedUtf8),
            &signers,
            b"Test Message"
        )
        .is_ok());
    }

    #[test]
    fn test_offchain_message_v0_ledger_length() {
        let input = VersionInput::V0 {
            format: MessageFormat::RestrictedAscii,
            application_domain: [0; 32],
        };
        let signers = [Address::new_from_array([1; 32])];
        // 1232 - 85 byte preamble for one signer
        let max_message = [b'a'; 1147];
        let message = OffchainMessageWithSigners::new(input, &signers, &max_message).unwrap();
        assert_eq!(message.serialize().unwrap().len(), 1232);
        assert_eq!(
            OffchainMessageWithSigners::new(input, &signers, &[b'a'; 1148]),
            Err(SanitizeError::ValueOutOfBounds),
        );
    }

    #[test]
    fn test_offchain_message_sign_and_verify_v0() {
        let keypair = Keypair::new();
        let message = OffchainMessageWithSigners::new(
            VersionInput::V0 {
                format: MessageFormat::RestrictedAscii,
                application_domain: [0; 32],
            },
            &[keypair.pubkey()],
            b"Test Message",
        )
        .unwrap();
        let signature = message.sign(&keypair).unwrap();
        assert!(message.verify(&keypair.pubkey(), &signature).unwrap());

        // valid signature from a key that is not in the signer list
        let other = Keypair::new();
        let other_signature = message.sign(&other).unwrap();
        assert!(!message.verify(&other.pubkey(), &other_signature).unwrap());
    }

    #[test]
    fn test_offchain_message_rejects_invalid_signing_domain_v1() {
        let message = OffchainMessageWithSigners::new(
            VersionInput::V1,
            &[Address::new_from_array([1; 32])],
            b"Test Message",
        )
        .unwrap();
        let serialized = message.serialize().unwrap();

        for index in 0..OffchainMessageWithSigners::SIGNING_DOMAIN.len() {
            let mut altered = serialized.clone();
            altered[index] ^= 1;

            assert_eq!(
                OffchainMessageWithSigners::deserialize(&altered),
                Err(SanitizeError::InvalidValue),
            );
        }
    }

    #[test]
    fn test_offchain_message_ascii_v1() {
        let signers = [Address::new_from_array([1; 32])];
        let message =
            OffchainMessageWithSigners::new(VersionInput::V1, &signers, b"Test Message").unwrap();
        assert_eq!(message.get_version(), 1);
        assert_eq!(message.get_format(), MessageFormat::ExtendedUtf8);
        assert_eq!(message.get_message().as_slice(), b"Test Message");
        assert_eq!(message.get_signers(), signers.as_slice());
        // from @solana/kit 8.6.0 `getOffchainMessageV1Encoder`
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101,
        ];
        let hash = Hash::from_str("5GurJvMAsqBHwjSf2AqkvZ4kGYdbS78waeUcoZ2NYUKB").unwrap();
        assert_eq!(message.serialize().unwrap(), serialized);
        assert_eq!(message.hash().unwrap(), hash);
        assert_eq!(
            message,
            OffchainMessageWithSigners::deserialize(&serialized).unwrap()
        );
    }

    #[test]
    fn test_offchain_message_utf8_v1() {
        let signers = [Address::new_from_array([1; 32])];
        let message = OffchainMessageWithSigners::new(
            VersionInput::V1,
            &signers,
            "Тестовое сообщение".as_bytes(),
        )
        .unwrap();
        assert_eq!(message.get_version(), 1);
        assert_eq!(message.get_format(), MessageFormat::ExtendedUtf8);
        assert_eq!(
            message.get_message().as_slice(),
            "Тестовое сообщение".as_bytes()
        );
        assert_eq!(message.get_signers(), signers.as_slice());
        // from @solana/kit 8.6.0 `getOffchainMessageV1Encoder`
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 208, 162, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 208, 190, 208, 181, 32,
            209, 129, 208, 190, 208, 190, 208, 177, 209, 137, 208, 181, 208, 189, 208, 184, 208,
            181,
        ];
        let hash = Hash::from_str("2XLKTFA8Kwb6vPLSGMpbKJrv9disEWisxLsCo77NXgtk").unwrap();
        assert_eq!(message.serialize().unwrap(), serialized);
        assert_eq!(message.hash().unwrap(), hash);
        assert_eq!(
            message,
            OffchainMessageWithSigners::deserialize(&serialized).unwrap()
        );
    }

    #[test]
    fn test_offchain_message_sign_and_verify_v1() {
        let keypair = Keypair::new();
        let message =
            OffchainMessageWithSigners::new(VersionInput::V1, &[keypair.pubkey()], b"Test Message")
                .unwrap();
        let signature = message.sign(&keypair).unwrap();
        assert!(message.verify(&keypair.pubkey(), &signature).unwrap());

        // valid signature from a key that is not in the signer list
        let other = Keypair::new();
        let other_signature = message.sign(&other).unwrap();
        assert!(!message.verify(&other.pubkey(), &other_signature).unwrap());
    }

    #[test]
    fn test_offchain_message_kit_v1_parity() {
        // V1 message from @solana/kit 8.6.0 `getOffchainMessageV1Encoder`, 95 bytes:
        //   [0..16)  signing domain b"\xffsolana offchain"
        //   [16]     version        1
        //   [17]     signer count   2
        //   [18..50) signer 1       9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu (secret key [2; 32])
        //   [50..82) signer 2       AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9 (secret key [1; 32])
        //   [82..95) content        b"Hello, world!"
        let kit_serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 1, 2, 129,
            57, 119, 14, 168, 125, 23, 95, 86, 163, 84, 102, 195, 76, 126, 204, 203, 141, 138, 145,
            180, 238, 55, 162, 93, 246, 15, 91, 143, 201, 179, 148, 138, 136, 227, 221, 116, 9,
            241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243,
            116, 136, 1, 180, 15, 111, 92, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100,
            33,
        ];
        let signer_1 = Keypair::new_from_array([1; 32]).pubkey();
        let signer_2 = Keypair::new_from_array([2; 32]).pubkey();

        let message = OffchainMessageWithSigners::deserialize(&kit_serialized).unwrap();
        assert_eq!(message.get_version(), 1);
        assert_eq!(message.get_message().as_slice(), b"Hello, world!");
        assert_eq!(message.get_signers(), [signer_2, signer_1].as_slice());

        let built = OffchainMessageWithSigners::new(
            VersionInput::V1,
            &[signer_1, signer_2],
            b"Hello, world!",
        )
        .unwrap();
        assert_eq!(built.serialize().unwrap(), kit_serialized);
        assert_eq!(built, message);
    }

    #[test]
    fn test_offchain_message_with_signers_rejects_offspec_v0() {
        let offspec_serialized = OffchainMessage::new(0, b"Test Message")
            .unwrap()
            .serialize()
            .unwrap();
        // 15 bytes after the version byte, shorter than the v0 header
        assert_eq!(
            OffchainMessageWithSigners::deserialize(&offspec_serialized),
            Err(SanitizeError::ValueOutOfBounds),
        );
        // The off-spec v0 message format byte (0) is read as the signer count.
        assert_eq!(
            with_signers::v1::OffchainMessage::deserialize(
                &offspec_serialized[OffchainMessage::HEADER_LEN..]
            ),
            Err(SanitizeError::InvalidValue),
        );
    }

    #[test]
    fn test_offchain_message_v1_rejects_v0() {
        // The first application domain byte (237) is read as the signer count.
        assert_eq!(
            with_signers::v1::OffchainMessage::deserialize(
                &KIT_V0_SERIALIZED[OffchainMessageWithSigners::HEADER_LEN..]
            ),
            Err(SanitizeError::ValueOutOfBounds),
        );
    }
}
