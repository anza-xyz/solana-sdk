use core::fmt;

/// Errors returned by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bls12381Error {
    /// The G1 and G2 slices were different lengths.
    LengthMismatch,
    /// The batch exceeded 8 pairs.
    TooManyPairs,
    /// The pairing batch was empty.
    EmptyBatch,
    /// The syscall rejected the operation.
    InvalidInput,
    /// The pairing check ran and the product was not the identity.
    VerificationFailed,
}

impl fmt::Display for Bls12381Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::LengthMismatch => "G1 and G2 batches have different lengths",
            Self::TooManyPairs => "pairing batch exceeds the maximum length",
            Self::EmptyBatch => "pairing batch is empty",
            Self::InvalidInput => "the syscall rejected the operation",
            Self::VerificationFailed => "pairing product is not the identity",
        };
        f.write_str(message)
    }
}

impl core::error::Error for Bls12381Error {}
