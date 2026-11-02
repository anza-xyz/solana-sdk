//! Vote program errors

use {
    core::fmt,
    num_derive::{FromPrimitive, ToPrimitive},
};

/// Reasons the vote might have had an error
///
/// The discriminants are the on-chain `InstructionError::Custom` codes. Codes
/// 0-4, 6-17 and 20 belonged to the tower vote instructions removed after the
/// Alpenglow migration and must not be reused.
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[non_exhaustive]
pub enum VoteError {
    TooSoonToReauthorize = 5,
    ActiveVoteAccountClose = 18,
    CommissionUpdateTooLate = 19,
}

impl core::error::Error for VoteError {}

impl fmt::Display for VoteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::TooSoonToReauthorize => "authorized voter has already been changed this epoch",
            Self::ActiveVoteAccountClose => {
                "Cannot close vote account unless it stopped voting at least one full epoch ago"
            }
            Self::CommissionUpdateTooLate => "Cannot update commission at this point in the epoch",
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        num_traits::{FromPrimitive, ToPrimitive},
    };

    #[test]
    fn test_vote_error_codes() {
        for (error, code) in [
            (VoteError::TooSoonToReauthorize, 5),
            (VoteError::ActiveVoteAccountClose, 18),
            (VoteError::CommissionUpdateTooLate, 19),
        ] {
            assert_eq!(error.to_u32(), Some(code));
            assert_eq!(VoteError::from_u32(code), Some(error));
        }

        // Codes of the removed tower vote errors no longer decode.
        for code in (0..=4).chain(6..=17).chain([20]) {
            assert_eq!(VoteError::from_u32(code), None);
        }
    }
}
