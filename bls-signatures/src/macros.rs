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
