use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Bls12381Error {
    #[error("The input data is invalid")]
    InvalidInputData,
    #[error("Slice data is going out of input data bounds")]
    SliceOutOfBounds,
    #[error("Unexpected error")]
    UnexpectedError,
}
