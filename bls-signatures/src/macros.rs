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
/// affine (point), uncompressed (bytes), and compressed (bytes) representations.
#[cfg(not(target_os = "solana"))]
macro_rules! impl_bls_conversions {
    (
        $projective:ident,       // e.g. PubkeyProjective
        $affine:ident,           // e.g. PubkeyAffine
        $uncompressed:ident,     // e.g. Pubkey (Bytes)
        $compressed:ident,       // e.g. PubkeyCompressed (Bytes)
        $blstrs_affine:ty,       // e.g. blstrs::G1Affine
        $blstrs_projective:ty,   // e.g. blstrs::G1Projective
        $as_projective_trait:ident, // e.g. AsPubkeyProjective
        $as_affine_trait:ident,     // e.g. AsPubkeyAffine
        $compressed_size:ident,     // e.g. BLS_PUBLIC_KEY_COMPRESSED_SIZE
        $uncompressed_size:ident    // e.g. BLS_PUBLIC_KEY_AFFINE_SIZE
    ) => {
        // Math Conversions (Projective <-> Affine)
        impl From<&$projective> for $affine {
            fn from(p: &$projective) -> Self {
                $affine(<$blstrs_affine>::from(p.0))
            }
        }

        impl From<$projective> for $affine {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        impl From<&$affine> for $projective {
            fn from(p: &$affine) -> Self {
                Self(<$blstrs_projective>::from(p.0))
            }
        }

        impl From<$affine> for $projective {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Serialization (Affine Point <-> Bytes)
        // Affine Point -> Uncompressed Bytes
        impl From<&$affine> for $uncompressed {
            fn from(p: &$affine) -> Self {
                Self(p.0.to_uncompressed())
            }
        }
        impl From<$affine> for $uncompressed {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Affine Point -> Compressed Bytes
        impl From<&$affine> for $compressed {
            fn from(p: &$affine) -> Self {
                Self(p.0.to_compressed())
            }
        }
        impl From<$affine> for $compressed {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Projective -> Uncompressed Bytes (Delegates to Affine)
        impl From<&$projective> for $uncompressed {
            fn from(p: &$projective) -> Self {
                let affine = $affine::from(p);
                affine.into()
            }
        }
        impl From<$projective> for $uncompressed {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        // Projective -> Compressed Bytes (Delegates to Affine)
        impl From<&$projective> for $compressed {
            fn from(p: &$projective) -> Self {
                let affine = $affine::from(p);
                affine.into()
            }
        }
        impl From<$projective> for $compressed {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        // Uncompressed Bytes -> Affine Point
        impl TryFrom<&$uncompressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$blstrs_affine> =
                    <$blstrs_affine>::from_uncompressed(&bytes.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }
        impl TryFrom<$uncompressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Compressed Bytes -> Affine Point
        impl TryFrom<&$compressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$blstrs_affine> =
                    <$blstrs_affine>::from_compressed(&bytes.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }
        impl TryFrom<$compressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Transit Conversions (Projective <-> Bytes via Affine)
        impl TryFrom<&$uncompressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed) -> Result<Self, Self::Error> {
                let affine = $affine::try_from(bytes)?;
                Ok(affine.into())
            }
        }
        impl TryFrom<$uncompressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        impl TryFrom<&$compressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed) -> Result<Self, Self::Error> {
                let affine = $affine::try_from(bytes)?;
                Ok(affine.into())
            }
        }
        impl TryFrom<$compressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Raw Byte Array Conversions ([u8; N] -> Types)
        // Raw Uncompressed ([u8; 96]) -> All Types
        impl TryFrom<&[u8; $uncompressed_size]> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $uncompressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $uncompressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        impl TryFrom<&[u8; $uncompressed_size]> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $uncompressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $uncompressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        // Raw Compressed ([u8; 48]) -> All Types
        impl TryFrom<&[u8; $compressed_size]> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $compressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $compressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        impl TryFrom<&[u8; $compressed_size]> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $compressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $compressed(*bytes);
                Self::try_from(&wrapper)
            }
        }

        // Bytes <-> Bytes Conversions (Transit via Affine)

        // Uncompressed Bytes -> Compressed Bytes
        impl TryFrom<&$uncompressed> for $compressed {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed) -> Result<Self, Self::Error> {
                // transit via Affine point: Bytes -> Affine -> Compressed
                let point = $affine::try_from(bytes)?;
                Ok(point.into())
            }
        }
        impl TryFrom<$uncompressed> for $compressed {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Compressed Bytes -> Uncompressed Bytes
        impl TryFrom<&$compressed> for $uncompressed {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed) -> Result<Self, Self::Error> {
                // transit via Affine point: Compressed -> Affine -> Uncompressed
                let point = $affine::try_from(bytes)?;
                Ok(point.into())
            }
        }
        impl TryFrom<$compressed> for $uncompressed {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Trait Implementations (AsProjective / AsAffine)
        // AsProjective
        impl $as_projective_trait for $projective {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                Ok(*self)
            }
        }
        impl $as_projective_trait for $affine {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                Ok(self.into())
            }
        }
        impl $as_projective_trait for $uncompressed {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                $projective::try_from(self)
            }
        }
        impl $as_projective_trait for $compressed {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                $projective::try_from(self)
            }
        }
        impl $as_projective_trait for [u8; $uncompressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                let wrapper = $uncompressed(*self);
                $projective::try_from(&wrapper)
            }
        }
        impl $as_projective_trait for [u8; $compressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                let wrapper = $compressed(*self);
                $projective::try_from(&wrapper)
            }
        }

        impl $as_projective_trait for &[u8; $uncompressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                // self is &&[u8; N], so **self gets [u8; N]
                let wrapper = $uncompressed(**self);
                $projective::try_from(&wrapper)
            }
        }

        impl $as_projective_trait for &[u8; $compressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                // self is &&[u8; N], so **self gets [u8; N]
                let wrapper = $compressed(**self);
                $projective::try_from(&wrapper)
            }
        }

        // AsAffine
        impl $as_affine_trait for $affine {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                Ok(*self)
            }
        }
        impl $as_affine_trait for $projective {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                Ok(self.into())
            }
        }
        impl $as_affine_trait for $uncompressed {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                $affine::try_from(self)
            }
        }
        impl $as_affine_trait for $compressed {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                $affine::try_from(self)
            }
        }
        impl $as_affine_trait for [u8; $uncompressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $uncompressed(*self);
                $affine::try_from(&wrapper)
            }
        }
        impl $as_affine_trait for [u8; $compressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $compressed(*self);
                $affine::try_from(&wrapper)
            }
        }

        impl $as_affine_trait for &[u8; $uncompressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $uncompressed(**self);
                $affine::try_from(&wrapper)
            }
        }

        impl $as_affine_trait for &[u8; $compressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $compressed(**self);
                $affine::try_from(&wrapper)
            }
        }

        impl $projective {
            pub fn to_bytes_compressed(&self) -> [u8; $compressed_size] {
                self.0.to_compressed()
            }

            pub fn to_bytes_uncompressed(&self) -> [u8; $uncompressed_size] {
                self.0.to_uncompressed()
            }
        }

        impl $affine {
            pub fn to_bytes_compressed(&self) -> [u8; $compressed_size] {
                self.0.to_compressed()
            }

            pub fn to_bytes_uncompressed(&self) -> [u8; $uncompressed_size] {
                self.0.to_uncompressed()
            }
        }

        impl $uncompressed {
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl $compressed {
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $projective {
            type Error = crate::error::BlsError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() == $uncompressed_size {
                    let array: [u8; $uncompressed_size] = bytes
                        .try_into()
                        .map_err(|_| crate::error::BlsError::ParseFromBytes)?;
                    let wrapper = $uncompressed(array);
                    Self::try_from(&wrapper)
                } else if bytes.len() == $compressed_size {
                    let array: [u8; $compressed_size] = bytes
                        .try_into()
                        .map_err(|_| crate::error::BlsError::ParseFromBytes)?;
                    let wrapper = $compressed(array);
                    Self::try_from(&wrapper)
                } else {
                    Err(crate::error::BlsError::ParseFromBytes)
                }
            }
        }

        impl TryFrom<&[u8]> for $affine {
            type Error = crate::error::BlsError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() == $uncompressed_size {
                    let array: [u8; $uncompressed_size] = bytes
                        .try_into()
                        .map_err(|_| crate::error::BlsError::ParseFromBytes)?;
                    let wrapper = $uncompressed(array);
                    Self::try_from(&wrapper)
                } else if bytes.len() == $compressed_size {
                    let array: [u8; $compressed_size] = bytes
                        .try_into()
                        .map_err(|_| crate::error::BlsError::ParseFromBytes)?;
                    let wrapper = $compressed(array);
                    Self::try_from(&wrapper)
                } else {
                    Err(crate::error::BlsError::ParseFromBytes)
                }
            }
        }
    };
}

#[cfg(not(target_os = "solana"))]
macro_rules! impl_add_to_accumulator {
    ($trait_name:ident, $accumulator_type:ident, $type:ty, affine) => {
        impl $trait_name for $type {
            #[allow(clippy::arithmetic_side_effects)]
            fn add_to_accumulator(
                &self,
                acc: &mut $accumulator_type,
            ) -> Result<(), crate::error::BlsError> {
                // Efficient mixed addition (Projective += Affine)
                acc.0 += self.0;
                Ok(())
            }
        }
    };
    ($trait_name:ident, $accumulator_type:ident, $type:ty, projective) => {
        impl $trait_name for $type {
            #[allow(clippy::arithmetic_side_effects)]
            fn add_to_accumulator(
                &self,
                acc: &mut $accumulator_type,
            ) -> Result<(), crate::error::BlsError> {
                // Projective += Projective
                acc.0 += self.0;
                Ok(())
            }
        }
    };
    ($trait_name:ident, $accumulator_type:ident, $type:ty, convert) => {
        impl $trait_name for $type {
            #[allow(clippy::arithmetic_side_effects)]
            fn add_to_accumulator(
                &self,
                acc: &mut $accumulator_type,
            ) -> Result<(), crate::error::BlsError> {
                // Convert bytes to Affine first, then use mixed addition
                let affine = self.try_as_affine()?;
                acc.0 += affine.0;
                Ok(())
            }
        }
    };
}

macro_rules! impl_unchecked_conversions {
    (
        $unchecked_type:ident,     // e.g. SignatureAffineUnchecked
        $validated_type:ident,     // e.g. SignatureAffine
        $projective_type:ident,    // e.g. SignatureProjective
        $compressed_type:ident,    // e.g. SignatureCompressed
        $uncompressed_type:ident,  // e.g. Signature
        $internal_type:ty          // e.g. G2Affine
    ) => {
        // Conversion from Compressed Bytes (Unchecked)
        #[cfg(not(target_os = "solana"))]
        impl TryFrom<$compressed_type> for $unchecked_type {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed_type) -> Result<Self, Self::Error> {
                let point = Option::from(<$internal_type>::from_compressed_unchecked(&bytes.0))
                    .ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }

        #[cfg(not(target_os = "solana"))]
        impl TryFrom<&$compressed_type> for $unchecked_type {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed_type) -> Result<Self, Self::Error> {
                Self::try_from(*bytes)
            }
        }

        // Conversion from Uncompressed Bytes (Unchecked)
        #[cfg(not(target_os = "solana"))]
        impl TryFrom<$uncompressed_type> for $unchecked_type {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed_type) -> Result<Self, Self::Error> {
                let point = Option::from(<$internal_type>::from_uncompressed_unchecked(&bytes.0))
                    .ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }

        #[cfg(not(target_os = "solana"))]
        impl TryFrom<&$uncompressed_type> for $unchecked_type {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed_type) -> Result<Self, Self::Error> {
                Self::try_from(*bytes)
            }
        }

        // Conversion from Validated Affine (Always safe)
        #[cfg(not(target_os = "solana"))]
        impl From<$validated_type> for $unchecked_type {
            fn from(item: $validated_type) -> Self {
                Self(item.0)
            }
        }

        #[cfg(not(target_os = "solana"))]
        impl From<&$validated_type> for $unchecked_type {
            fn from(item: &$validated_type) -> Self {
                Self(item.0)
            }
        }

        // Conversion from Projective
        #[cfg(not(target_os = "solana"))]
        impl From<$projective_type> for $unchecked_type {
            fn from(item: $projective_type) -> Self {
                Self(<$internal_type>::from(item.0))
            }
        }

        #[cfg(not(target_os = "solana"))]
        impl From<&$projective_type> for $unchecked_type {
            fn from(item: &$projective_type) -> Self {
                Self(<$internal_type>::from(item.0))
            }
        }
    };
}
