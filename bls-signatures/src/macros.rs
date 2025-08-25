macro_rules! impl_from_str {
    (TYPE = $type:ident, BYTES_LEN = $bytes_len:expr, BASE64_LEN = $base64_len:expr) => {
        impl core::str::FromStr for $type {
            type Err = crate::error::BlsError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use base64::Engine;

                if s.len() > $base64_len {
                    return Err(Self::Err::ParseFromString);
                }
                let mut bytes = [0u8; $bytes_len];
                let decoded_len = base64::prelude::BASE64_STANDARD
                    .decode_slice(s, &mut bytes)
                    .map_err(|_| Self::Err::ParseFromString)?;
                if decoded_len != $bytes_len {
                    Err(Self::Err::ParseFromString)
                } else {
                    Ok($type(bytes))
                }
            }
        }
    };
}

/// A macro to implement the standard set of conversions between BLS projective,
/// affine, and compressed point representations.
///
/// # Arguments
///
/// * `$projective`: The identifier for the projective representation struct (e.g., `PubkeyProjective`).
/// * `$affine`: The identifier for the affine (uncompressed) representation struct (e.g., `Pubkey`).
/// * `$compressed`: The identifier for the compressed representation struct (e.g., `PubkeyCompressed`).
/// * `$point_type`: The underlying `blstrs` affine point type (e.g., `G1Affine` or `G2Affine`).
/// * `$as_projective_trait`: The identifier for the custom projective conversion trait (e.g.,`AsPubkeyProjective`).
/// * `$as_affine_trait`: The identifier for the custom affine conversion trait (e.g., `AsPubkey`).
#[cfg(not(target_os = "solana"))]
macro_rules! impl_bls_conversions {
    (
        $projective:ident,
        $affine:ident,
        $compressed:ident,
        $point_type:ty,
        $as_projective_trait:ident,
        $as_affine_trait:ident
    ) => {
        // ---
        // infallible conversions from the projective type.
        // ---
        impl From<&$projective> for $affine {
            fn from(projective: &$projective) -> Self {
                Self(projective.0.to_uncompressed())
            }
        }

        impl From<$projective> for $affine {
            fn from(projective: $projective) -> Self {
                (&projective).into()
            }
        }

        // ---
        // Fallible conversions from serialized types (affine, compressed)
        // back to the projective type.
        // ---
        impl TryFrom<&$affine> for $projective {
            type Error = crate::error::BlsError;

            fn try_from(affine: &$affine) -> Result<Self, Self::Error> {
                let maybe_point: Option<$point_type> =
                    <$point_type>::from_uncompressed(&affine.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point.into()))
            }
        }

        impl TryFrom<$affine> for $projective {
            type Error = crate::error::BlsError;

            fn try_from(affine: $affine) -> Result<Self, Self::Error> {
                Self::try_from(&affine)
            }
        }

        impl TryFrom<&$compressed> for $projective {
            type Error = crate::error::BlsError;

            fn try_from(compressed: &$compressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$point_type> =
                    <$point_type>::from_compressed(&compressed.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point.into()))
            }
        }

        impl TryFrom<$compressed> for $projective {
            type Error = crate::error::BlsError;

            fn try_from(compressed: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&compressed)
            }
        }

        // ---
        // Fallible conversions between the two serialized formats (affine and compressed).
        // ---
        impl TryFrom<&$affine> for $compressed {
            type Error = crate::error::BlsError;

            fn try_from(affine: &$affine) -> Result<Self, Self::Error> {
                let maybe_point: Option<$point_type> =
                    <$point_type>::from_uncompressed(&affine.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point.to_compressed()))
            }
        }

        impl TryFrom<$affine> for $compressed {
            type Error = crate::error::BlsError;

            fn try_from(affine: $affine) -> Result<Self, Self::Error> {
                Self::try_from(&affine)
            }
        }

        impl TryFrom<&$compressed> for $affine {
            type Error = crate::error::BlsError;

            fn try_from(compressed: &$compressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$point_type> =
                    <$point_type>::from_compressed(&compressed.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point.to_uncompressed()))
            }
        }

        impl TryFrom<$compressed> for $affine {
            type Error = crate::error::BlsError;

            fn try_from(compressed: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&compressed)
            }
        }

        impl $as_projective_trait for $projective {
            fn try_as_projective(&self) -> Result<$projective, BlsError> {
                Ok(*self)
            }
        }

        impl $as_projective_trait for $affine {
            fn try_as_projective(&self) -> Result<$projective, BlsError> {
                $projective::try_from(self)
            }
        }

        impl $as_projective_trait for $compressed {
            fn try_as_projective(&self) -> Result<$projective, BlsError> {
                $projective::try_from(self)
            }
        }

        impl $as_affine_trait for $projective {
            fn try_as_affine(&self) -> Result<$affine, BlsError> {
                // Uses the `From<&$projective>` for `$affine` conversion defined above.
                Ok(self.into())
            }
        }

        impl $as_affine_trait for $affine {
            fn try_as_affine(&self) -> Result<$affine, BlsError> {
                // Trivial case: already in the correct format.
                Ok(*self)
            }
        }

        impl $as_affine_trait for $compressed {
            fn try_as_affine(&self) -> Result<$affine, BlsError> {
                // Uses the `TryFrom<&$compressed>` for `$affine` conversion defined above.
                $affine::try_from(self)
            }
        }
    };
}
