use thiserror::Error;

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
}
