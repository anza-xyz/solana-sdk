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
    PointConversion,
    #[error("Failed to parse from string")]
    ParseFromString,
    #[error("Failed to parse from bytes")]
    ParseFromBytes,
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
