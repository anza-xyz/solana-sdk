//! Serialization, deserialization, validation, and parsing logic for off-chain messages.

use {
    super::{MessageFormat, PREAMBLE_AND_BODY_MAX_EXTENDED, PREAMBLE_AND_BODY_MAX_LEDGER},
    crate::total_message_size,
    solana_sanitize::SanitizeError,
    solana_serialize_utils::{append_slice, append_u16, append_u8, read_slice, read_u16, read_u8},
};

/// Components of a v0 message: (application_domain, format, signers, message)
pub type V0MessageComponents = ([u8; 32], MessageFormat, Vec<[u8; 32]>, Vec<u8>);

/// Validate message components
pub fn validate_components(signers: &[[u8; 32]], message: &[u8]) -> Result<(), SanitizeError> {
    if signers.is_empty() || signers.len() > u8::MAX as usize {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    if message.is_empty() {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(())
}

/// Detect appropriate message format based on size and content
pub fn detect_format(total_size: usize, message: &[u8]) -> Result<MessageFormat, SanitizeError> {
    if total_size <= PREAMBLE_AND_BODY_MAX_LEDGER {
        if super::is_printable_ascii(message) {
            Ok(MessageFormat::RestrictedAscii)
        } else if super::is_utf8(message) {
            Ok(MessageFormat::LimitedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else if total_size <= PREAMBLE_AND_BODY_MAX_EXTENDED {
        if super::is_utf8(message) {
            Ok(MessageFormat::ExtendedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else {
        Err(SanitizeError::ValueOutOfBounds)
    }
}

/// Parse application domain from data at given offset
pub fn parse_application_domain(
    data: &[u8],
    offset: &mut usize,
) -> Result<[u8; 32], SanitizeError> {
    let domain_bytes = read_slice(offset, data, 32).map_err(|_| SanitizeError::ValueOutOfBounds)?;
    let mut application_domain = [0u8; 32];
    application_domain.copy_from_slice(&domain_bytes);
    Ok(application_domain)
}

/// Parse message format from data at given offset
pub fn parse_message_format(
    data: &[u8],
    offset: &mut usize,
) -> Result<MessageFormat, SanitizeError> {
    let format_byte = read_u8(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)?;
    MessageFormat::try_from(format_byte).map_err(|_| SanitizeError::InvalidValue)
}

/// Parse signer count from data at given offset
pub fn parse_signer_count(data: &[u8], offset: &mut usize) -> Result<usize, SanitizeError> {
    let signer_count = read_u8(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)? as usize;
    if signer_count == 0 {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(signer_count)
}

/// Parse signers from data at given offset
pub fn parse_signers(
    data: &[u8],
    offset: &mut usize,
    signer_count: usize,
) -> Result<Vec<[u8; 32]>, SanitizeError> {
    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let signer_bytes =
            read_slice(offset, data, 32).map_err(|_| SanitizeError::ValueOutOfBounds)?;
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&signer_bytes);
        signers.push(signer);
    }
    Ok(signers)
}

/// Parse message length from data at given offset
pub fn parse_message_length(data: &[u8], offset: &mut usize) -> Result<usize, SanitizeError> {
    let message_len = read_u16(offset, data).map_err(|_| SanitizeError::ValueOutOfBounds)? as usize;
    if message_len == 0 {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(message_len)
}

/// Parse message body from data at given offset
pub fn parse_message_body(
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

/// Validate format constraints against parsed data
pub fn validate_format_constraints(
    format: MessageFormat,
    total_size: usize,
    message: &[u8],
) -> Result<(), SanitizeError> {
    let is_valid = match format {
        MessageFormat::RestrictedAscii => {
            total_size <= PREAMBLE_AND_BODY_MAX_LEDGER && super::is_printable_ascii(message)
        }
        MessageFormat::LimitedUtf8 => {
            total_size <= PREAMBLE_AND_BODY_MAX_LEDGER && super::is_utf8(message)
        }
        MessageFormat::ExtendedUtf8 => {
            total_size <= PREAMBLE_AND_BODY_MAX_EXTENDED && super::is_utf8(message)
        }
    };

    is_valid.then_some(()).ok_or(SanitizeError::InvalidValue)
}

/// Serialize a v0 message to bytes, including the full header
pub fn serialize_v0(
    application_domain: &[u8; 32],
    format: MessageFormat,
    signers: &[[u8; 32]],
    message: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), SanitizeError> {
    assert!(!message.is_empty());
    assert!(!signers.is_empty() && signers.len() <= u8::MAX as usize);

    let reserve_size = super::v0::OffchainMessage::HEADER_LEN
        .saturating_add(signers.len().saturating_mul(32))
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

/// Deserialize a v0 message from bytes that include a full header
pub fn deserialize_v0(data: &[u8]) -> Result<V0MessageComponents, SanitizeError> {
    if data.len() < super::v0::OffchainMessage::HEADER_LEN {
        return Err(SanitizeError::ValueOutOfBounds);
    }

    let mut offset = 0;
    let application_domain = parse_application_domain(data, &mut offset)?;
    let format = parse_message_format(data, &mut offset)?;
    let signer_count = parse_signer_count(data, &mut offset)?;
    let signers = parse_signers(data, &mut offset, signer_count)?;
    let message_len = parse_message_length(data, &mut offset)?;
    let message = parse_message_body(data, &mut offset, message_len)?;

    let total_size = total_message_size(signers.len(), message_len);
    validate_format_constraints(format, total_size, &message)?;

    Ok((application_domain, format, signers, message))
}

/// Construct a new v0 message with validation
pub fn new_v0_with_params(
    application_domain: [u8; 32],
    signers: &[[u8; 32]],
    message: &[u8],
) -> Result<V0MessageComponents, SanitizeError> {
    validate_components(signers, message)?;
    let total_size = total_message_size(signers.len(), message.len());
    let format = detect_format(total_size, message)?;

    Ok((
        application_domain,
        format,
        signers.to_vec(),
        message.to_vec(),
    ))
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
            detect_format(100, b"Hello World!"),
            Ok(MessageFormat::RestrictedAscii)
        );
        assert_eq!(
            detect_format(100, "Привет мир!".as_bytes()),
            Ok(MessageFormat::LimitedUtf8)
        );
        assert_eq!(
            detect_format(PREAMBLE_AND_BODY_MAX_LEDGER + 100, b"Hello World!"),
            Ok(MessageFormat::ExtendedUtf8)
        );
        assert_eq!(
            detect_format(100, &[0xff, 0xfe, 0xfd]),
            Err(SanitizeError::InvalidValue)
        );
        assert_eq!(
            detect_format(PREAMBLE_AND_BODY_MAX_EXTENDED + 1, b"Hello"),
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
        let domain = parse_application_domain(&data, &mut offset).unwrap();
        let format = parse_message_format(&data, &mut offset).unwrap();
        let signer_count = parse_signer_count(&data, &mut offset).unwrap();
        let signers = parse_signers(&data, &mut offset, signer_count).unwrap();
        let message_len = parse_message_length(&data, &mut offset).unwrap();
        let message = parse_message_body(&data, &mut offset, message_len).unwrap();

        assert_eq!(domain, [0x42u8; 32]);
        assert_eq!(format, MessageFormat::RestrictedAscii);
        assert_eq!(signers, vec![[0x11u8; 32]]);
        assert_eq!(message, b"Hello");

        assert!(parse_application_domain(&[0u8; 16], &mut 0).is_err());
        assert!(parse_message_format(&[255], &mut 0).is_err());
        assert!(parse_signer_count(&[0], &mut 0).is_err());
        assert!(parse_signers(&[0u8; 16], &mut 0, 2).is_err());
        assert!(parse_message_length(&[0, 0], &mut 0).is_err());
        assert!(parse_message_body(b"Hi", &mut 0, 10).is_err());
    }

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let application_domain = [0x42u8; 32];
        let signers = vec![[0x11u8; 32], [0x22u8; 32]];
        let message = b"Test message".to_vec();
        let format = MessageFormat::RestrictedAscii;

        let mut serialized = Vec::new();
        serialize_v0(
            &application_domain,
            format,
            &signers,
            &message,
            &mut serialized,
        )
        .unwrap();
        let (parsed_domain, parsed_format, parsed_signers, parsed_message) =
            deserialize_v0(&serialized).unwrap();

        assert_eq!(parsed_domain, application_domain);
        assert_eq!(parsed_format, format);
        assert_eq!(parsed_signers, signers);
        assert_eq!(parsed_message, message);
    }

    #[test]
    fn test_new_v0_with_params() {
        let application_domain = [0x42u8; 32];
        let signers = [[0x11u8; 32]];
        let message = b"Hello World!";
        let (domain, format, parsed_signers, parsed_message) =
            new_v0_with_params(application_domain, &signers, message).unwrap();
        assert_eq!(domain, application_domain);
        assert_eq!(format, MessageFormat::RestrictedAscii);
        assert_eq!(parsed_signers, signers);
        assert_eq!(parsed_message, message);
        assert_eq!(
            new_v0_with_params(application_domain, &[], b"Hello World!"),
            Err(SanitizeError::ValueOutOfBounds)
        ); // empty signers
        assert_eq!(
            new_v0_with_params(application_domain, &[[0x11u8; 32]], b""),
            Err(SanitizeError::InvalidValue)
        ); // empty message
    }
}
