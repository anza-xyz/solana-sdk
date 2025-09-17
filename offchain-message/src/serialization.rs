//! Serialization, deserialization, validation, and parsing logic for off-chain messages.

use {
    super::{MessageFormat, TOTAL_MAX_EXTENDED, TOTAL_MAX_LEDGER},
    crate::v0::OffchainMessage as V0OffchainMessage,
    solana_sanitize::SanitizeError,
};

pub(crate) fn reject_zero_pubkey_in_multi_signer(
    signers: &[[u8; 32]],
) -> Result<(), SanitizeError> {
    if signers.len() > 1 && signers.iter().any(|s| s == &[0u8; 32]) {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(())
}

/// Validate message components
pub(crate) fn validate_components(
    signers: &[[u8; 32]],
    message: &[u8],
) -> Result<(), SanitizeError> {
    if signers.is_empty() || signers.len() > u8::MAX as usize {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    reject_zero_pubkey_in_multi_signer(signers)?;
    if message.is_empty() {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(())
}

pub trait Spec {
    const VERSION: u8;
    const ALLOW_NEWLINE: bool;
}

pub struct V0;
impl Spec for V0 {
    const VERSION: u8 = 0;
    const ALLOW_NEWLINE: bool = false;
}

pub struct V1;
impl Spec for V1 {
    const VERSION: u8 = 1;
    const ALLOW_NEWLINE: bool = true;
}

/// Version-neutral parsing and serialization helpers
pub(crate) mod core {
    use super::{reject_zero_pubkey_in_multi_signer, MessageFormat, SanitizeError};
    use solana_serialize_utils::{
        append_slice, append_u16, append_u8, read_slice, read_u16, read_u8,
    };

    pub(crate) const APPLICATION_DOMAIN_LEN: usize = 32;
    pub(crate) const FORMAT_LEN: usize = 1;
    pub(crate) const SIGNER_COUNT_LEN: usize = 1;
    pub(crate) const MESSAGE_LENGTH_LEN: usize = 2;
    pub(crate) const PREAMBLE_LEN: usize =
        APPLICATION_DOMAIN_LEN + FORMAT_LEN + SIGNER_COUNT_LEN + MESSAGE_LENGTH_LEN;
    pub(crate) const PUBKEY_LEN: usize = 32;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub(crate) struct ParsedBody {
        pub(crate) application_domain: [u8; 32],
        pub(crate) declared_format: MessageFormat,
        pub(crate) signers: Vec<[u8; 32]>,
        pub(crate) message: Vec<u8>,
    }

    #[inline]
    pub(crate) const fn preamble_and_body_size(signer_count: usize, message_len: usize) -> usize {
        PREAMBLE_LEN
            .saturating_add(signer_count.saturating_mul(PUBKEY_LEN))
            .saturating_add(message_len)
    }

    pub(crate) fn parse_application_domain(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<[u8; 32], SanitizeError> {
        let domain_bytes = read_slice(offset, data, APPLICATION_DOMAIN_LEN)
            .map_err(|_| SanitizeError::ValueOutOfBounds)?;
        let mut application_domain = [0u8; 32];
        application_domain.copy_from_slice(&domain_bytes);
        Ok(application_domain)
    }

    pub(crate) fn parse_message_format(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<MessageFormat, SanitizeError> {
        let format_byte = read_u8(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)?;
        MessageFormat::try_from(format_byte).map_err(|_| SanitizeError::InvalidValue)
    }

    pub(crate) fn parse_signer_count(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<usize, SanitizeError> {
        let signer_count =
            read_u8(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)? as usize;
        if signer_count == 0 {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(signer_count)
    }

    pub(crate) fn parse_signers(
        data: &[u8],
        offset: &mut usize,
        signer_count: usize,
    ) -> Result<Vec<[u8; 32]>, SanitizeError> {
        let mut signers = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            let signer_bytes = read_slice(offset, data, PUBKEY_LEN)
                .map_err(|_| SanitizeError::ValueOutOfBounds)?;
            let mut signer = [0u8; 32];
            signer.copy_from_slice(&signer_bytes);
            signers.push(signer);
        }
        Ok(signers)
    }

    pub(crate) fn parse_message_length(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<usize, SanitizeError> {
        let message_len =
            read_u16(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)? as usize;
        if message_len == 0 {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(message_len)
    }

    pub(crate) fn parse_message_body(
        data: &[u8],
        offset: &mut usize,
        expected_len: usize,
    ) -> Result<Vec<u8>, SanitizeError> {
        let remaining = data.len().saturating_sub(*offset);
        if remaining != expected_len {
            return Err(SanitizeError::InvalidValue);
        }
        read_slice(offset, data, expected_len).map_err(|_| SanitizeError::ValueOutOfBounds)
    }

    pub(crate) fn parse_preamble_and_body(data: &[u8]) -> Result<ParsedBody, SanitizeError> {
        if data.len() < PREAMBLE_LEN {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        let mut offset = 0;
        let application_domain = parse_application_domain(data, &mut offset)?;
        let declared_format = parse_message_format(data, &mut offset)?;
        let signer_count = parse_signer_count(data, &mut offset)?;
        let signers = parse_signers(data, &mut offset, signer_count)?;
        reject_zero_pubkey_in_multi_signer(&signers)?;
        let message_len = parse_message_length(data, &mut offset)?;
        let message = parse_message_body(data, &mut offset, message_len)?;

        Ok(ParsedBody {
            application_domain,
            declared_format,
            signers,
            message,
        })
    }

    pub(crate) fn serialize(
        application_domain: &[u8; 32],
        format: MessageFormat,
        signers: &[[u8; 32]],
        message: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), SanitizeError> {
        let reserve_size = PREAMBLE_LEN
            .saturating_add(signers.len().saturating_mul(PUBKEY_LEN))
            .saturating_add(message.len());
        data.reserve(reserve_size);

        append_slice(data, application_domain);
        append_u8(data, format.into());
        append_u8(data, signers.len() as u8);
        for signer in signers {
            append_slice(data, signer);
        }
        append_u16(data, message.len() as u16);
        append_slice(data, message);
        Ok(())
    }
}

pub(crate) fn detect_implied_format_for<S: Spec>(
    total_size: usize,
    message: &[u8],
) -> Result<MessageFormat, SanitizeError> {
    if total_size <= TOTAL_MAX_LEDGER {
        if super::is_printable_ascii(message, S::ALLOW_NEWLINE) {
            Ok(MessageFormat::RestrictedAscii)
        } else if super::is_utf8(message) {
            Ok(MessageFormat::LimitedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else if total_size <= TOTAL_MAX_EXTENDED {
        if super::is_utf8(message) {
            Ok(MessageFormat::ExtendedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else {
        Err(SanitizeError::ValueOutOfBounds)
    }
}

pub(crate) fn deserialize_body_for<S: Spec>(
    data: &[u8],
) -> Result<V0OffchainMessage, SanitizeError> {
    let parsed = core::parse_preamble_and_body(data)?;
    let total_size = core::preamble_and_body_size(parsed.signers.len(), parsed.message.len());
    let implied_format = detect_implied_format_for::<S>(total_size, &parsed.message)?;
    if !parsed.declared_format.includes(implied_format) {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(V0OffchainMessage {
        application_domain: parsed.application_domain,
        format: parsed.declared_format,
        signers: parsed.signers,
        message: parsed.message,
    })
}

/// Serialize the preamble+body
pub(crate) fn serialize(
    application_domain: &[u8; 32],
    format: MessageFormat,
    signers: &[[u8; 32]],
    message: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), SanitizeError> {
    validate_components(signers, message)?;
    core::serialize(application_domain, format, signers, message, data)
}

/// Deserialize the preamble+body using version S
pub(crate) fn deserialize_for<S: Spec>(data: &[u8]) -> Result<V0OffchainMessage, SanitizeError> {
    deserialize_body_for::<S>(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_functions() {
        assert_eq!(
            validate_components(&[], b"msg"),
            Err(SanitizeError::ValueOutOfBounds)
        );
        assert_eq!(
            validate_components(&vec![[0u8; 32]; 256], b"msg"),
            Err(SanitizeError::ValueOutOfBounds)
        );
        assert_eq!(
            validate_components(&[[1u8; 32]], &[]),
            Err(SanitizeError::InvalidValue)
        );
        assert!(validate_components(&[[1u8; 32], [2u8; 32]], b"msg").is_ok());
    }

    #[test]
    fn test_detect_format() {
        assert_eq!(
            detect_implied_format_for::<V0>(100, b"Hello World!"),
            Ok(MessageFormat::RestrictedAscii)
        );
        assert_eq!(
            detect_implied_format_for::<V0>(100, "Привет мир!".as_bytes()),
            Ok(MessageFormat::LimitedUtf8)
        );
        assert_eq!(
            detect_implied_format_for::<V0>(TOTAL_MAX_LEDGER + 100, b"Hello World!"),
            Ok(MessageFormat::ExtendedUtf8)
        );
        assert_eq!(
            detect_implied_format_for::<V0>(100, &[0xff, 0xfe, 0xfd]),
            Err(SanitizeError::InvalidValue)
        );
        assert_eq!(
            detect_implied_format_for::<V0>(TOTAL_MAX_EXTENDED + 1, b"Hello"),
            Err(SanitizeError::ValueOutOfBounds)
        );
    }

    #[test]
    fn test_parsing_functions() {
        let mut data = vec![];
        data.extend_from_slice(&[0x42u8; 32]); // domain
        data.extend_from_slice(&[0, 1]); // format, signer count
        data.extend_from_slice(&[0x11u8; 32]); // signer
        data.extend_from_slice(&[5u8, 0]); // message length
        data.extend_from_slice(b"Hello"); // message

        let mut offset = 0;
        let domain = core::parse_application_domain(&data, &mut offset).unwrap();
        let format = core::parse_message_format(&data, &mut offset).unwrap();
        let signer_count = core::parse_signer_count(&data, &mut offset).unwrap();
        let signers = core::parse_signers(&data, &mut offset, signer_count).unwrap();
        let message_len = core::parse_message_length(&data, &mut offset).unwrap();
        let message = core::parse_message_body(&data, &mut offset, message_len).unwrap();

        assert_eq!(domain, [0x42u8; 32]);
        assert_eq!(format, MessageFormat::RestrictedAscii);
        assert_eq!(signers, vec![[0x11u8; 32]]);
        assert_eq!(message, b"Hello");
    }

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let application_domain = [0x42u8; 32];
        let signers = vec![[0x11u8; 32], [0x22u8; 32]];
        let message = b"Test message".to_vec();
        let format = MessageFormat::RestrictedAscii;

        let mut serialized = Vec::new();
        serialize(
            &application_domain,
            format,
            &signers,
            &message,
            &mut serialized,
        )
        .unwrap();
        let parsed = deserialize_for::<V0>(&serialized).unwrap();

        assert_eq!(parsed.application_domain, application_domain);
        assert_eq!(parsed.format, format);
        assert_eq!(parsed.signers, signers);
        assert_eq!(parsed.message, message);
    }

    // Minimal helpers for compact tests
    fn bytes_for(format: MessageFormat, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let domain = [0xAAu8; 32];
        let signers = [[0x11u8; 32]];
        serialize(&domain, format, &signers, msg, &mut out).unwrap();
        out
    }

    #[test]
    fn test_accept_ascii_declared_higher() {
        let msg = b"Hello";
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::LimitedUtf8, msg)).is_ok());
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::ExtendedUtf8, msg)).is_ok());
    }

    #[test]
    fn test_accept_utf8_declared_extended() {
        let msg = "Привет".as_bytes();
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::ExtendedUtf8, msg)).is_ok());
    }

    #[test]
    fn test_reject_extended_size_declared_ascii_or_limited() {
        let msg = vec![b'a'; TOTAL_MAX_LEDGER]; // forces minimal ExtendedUtf8
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::RestrictedAscii, &msg)).is_err());
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::LimitedUtf8, &msg)).is_err());
    }

    #[test]
    fn test_reject_non_utf8_even_if_declared_extended() {
        let msg = vec![0xFF, 0xFE, 0xFD];
        assert!(deserialize_for::<V0>(&bytes_for(MessageFormat::ExtendedUtf8, &msg)).is_err());
    }
}
