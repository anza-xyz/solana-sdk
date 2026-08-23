use {core::convert::Infallible, thiserror::Error};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum BlsError {
    #[error("Field decode failed")]
    FieldDecode,
    #[error("Empty aggregation attempted")]
    EmptyAggregation,
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Point representation conversion failed")]
    PointConversion, // TODO: could be more specific here
    #[error("Failed to parse from string")]
    ParseFromString, // TODO: update after more precise error handling
    #[error("Failed to parse from bytes")]
    ParseFromBytes,
    #[error("Failed to decode base64 string")]
    InvalidBase64,
    #[error("Base64 string length exceeded: max {max}, got {actual}")]
    StringLengthExceeded { max: usize, actual: usize },
    #[error("Invalid encoded length: expected {expected}, got {actual}")]
    InvalidEncodedLength { expected: usize, actual: usize },
    #[error("Invalid encoded length: expected {expected_compressed} or {expected_uncompressed}, got {actual}")]
    InvalidLengthMultiple {
        expected_compressed: usize,
        expected_uncompressed: usize,
        actual: usize,
    },
    #[error("Invalid point encoding")]
    InvalidPointEncoding,
    #[error("Identity point rejected")]
    IdentityPointRejected,
    #[error("The length of inputs do not match")]
    InputLengthMismatch,
    #[error("Cryptographic verification failed")]
    VerificationFailed,
}

impl From<Infallible> for BlsError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
