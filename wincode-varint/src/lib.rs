//! Wincode schemas for LEB128 variable-length integer encoding.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {
    std::mem::MaybeUninit,
    wincode::{
        config::ConfigCore,
        io::{Reader, Writer},
        ReadError, ReadResult, SchemaRead, SchemaWrite, WriteResult,
    },
};

/// Wincode schema that encodes an integer using unsigned LEB128 (Little-Endian Base-128).
///
/// Each byte stores 7 bits of the value. The most significant bit is a continuation
/// flag: `1` means more bytes follow, `0` marks the last byte. Produces the same
/// bytes as `solana-serde-varint`, so wincode and bincode are wire-compatible.
///
/// Supported types: `u16`, `u32`, `u64`.
///
/// # Example
///
/// ```
/// use solana_wincode_varint::Leb128Int;
///
/// #[derive(wincode::SchemaRead, wincode::SchemaWrite)]
/// struct StructInts {
///     #[wincode(with = "Leb128Int<u32>")]
///     index: u32,
///     #[wincode(with = "Leb128Int<u64>")]
///     value: u64,
/// }
/// ```
pub struct Leb128Int<T>(pub T);

macro_rules! impl_schema_read {
    ($type:ty) => {
        unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for Leb128Int<$type> {
            type Dst = $type;

            fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<$type>) -> ReadResult<()> {
                let mut out: $type = 0;
                let mut shift = 0u32;
                while shift < <$type>::BITS {
                    let byte = reader.take_byte()?;
                    out |= ((byte & 0x7F) as $type) << shift;
                    if byte & 0x80 == 0 {
                        // Last byte should not have been truncated when it was
                        // shifted to the left above.
                        if (out >> shift) as u8 != byte {
                            return Err(ReadError::Custom("Last Byte Truncated"));
                        }
                        // Last byte can be zero only if there was only one
                        // byte and the output is also zero.
                        if byte == 0u8 && (shift != 0 || out != 0) {
                            return Err(ReadError::Custom("Invalid Trailing Zeros"));
                        }
                        dst.write(out);
                        return Ok(());
                    }
                    shift = shift.wrapping_add(7);
                }
                Err(ReadError::Custom("Left Shift Overflows"))
            }
        }
    };
}

macro_rules! impl_schema_write {
    ($type:ty) => {
        unsafe impl<C: ConfigCore> SchemaWrite<C> for Leb128Int<$type> {
            type Src = $type;

            fn size_of(src: &$type) -> WriteResult<usize> {
                let bits = <$type>::BITS.wrapping_sub(src.leading_zeros());
                Ok(bits.div_ceil(7).max(1) as usize)
            }

            fn write(mut writer: impl Writer, src: &$type) -> WriteResult<()> {
                let mut value = *src;
                while value >= 0x80 {
                    let byte = ((value & 0x7F) | 0x80) as u8;
                    writer.write(&[byte])?;
                    value >>= 7;
                }
                Ok(writer.write(&[value as u8])?)
            }
        }
    };
}

impl_schema_read!(u16);
impl_schema_read!(u32);
impl_schema_read!(u64);

impl_schema_write!(u16);
impl_schema_write!(u32);
impl_schema_write!(u64);

#[cfg(test)]
mod tests {
    use {
        rand::Rng,
        serde_derive::{Deserialize, Serialize},
    };

    // Max encoded size: ceil(16/7) + ceil(32/7) + ceil(64/7) = 3 + 5 + 10 = 18 bytes.
    #[derive(
        Debug, Eq, PartialEq, Serialize, Deserialize, wincode::SchemaRead, wincode::SchemaWrite,
    )]
    struct Dummy {
        #[serde(with = "solana_serde_varint")]
        #[wincode(with = "crate::Leb128Int<u16>")]
        a: u16,
        #[serde(with = "solana_serde_varint")]
        #[wincode(with = "crate::Leb128Int<u32>")]
        b: u32,
        #[serde(with = "solana_serde_varint")]
        #[wincode(with = "crate::Leb128Int<u64>")]
        c: u64,
    }

    fn check(dummy: &Dummy) {
        let wincode_bytes = wincode::serialize(dummy).unwrap();
        let bincode_bytes = bincode::serialize(dummy).unwrap();
        assert_eq!(wincode_bytes, bincode_bytes);
        assert_eq!(
            &wincode::deserialize::<Dummy>(&wincode_bytes).unwrap(),
            dummy
        );
        assert_eq!(
            &bincode::deserialize::<Dummy>(&bincode_bytes).unwrap(),
            dummy
        );
    }

    #[test]
    fn edge_cases() {
        let cases = [
            Dummy { a: 0, b: 0, c: 0 },
            Dummy { a: 1, b: 1, c: 1 },
            Dummy {
                a: 0x7F,
                b: 0x7F,
                c: 0x7F,
            },
            Dummy {
                a: 0x80,
                b: 0x80,
                c: 0x80,
            },
            Dummy {
                a: 0x3FFF,
                b: 0x3FFF,
                c: 0x3FFF,
            },
            Dummy {
                a: 0x4000,
                b: 0x4000,
                c: 0x4000,
            },
            Dummy {
                a: u16::MAX,
                b: u32::MAX,
                c: u64::MAX,
            },
        ];
        for dummy in &cases {
            check(dummy);
        }
    }

    #[test]
    fn random() {
        let mut rng = rand::rng();
        for _ in 0..100_000 {
            check(&Dummy {
                a: rng.random::<u16>() >> rng.random_range(0..u16::BITS),
                b: rng.random::<u32>() >> rng.random_range(0..u32::BITS),
                c: rng.random::<u64>() >> rng.random_range(0..u64::BITS),
            });
        }
    }

    #[test]
    fn trailing_zeros() {
        let buf = [0x80u8, 0x00];
        let r = wincode::deserialize::<Dummy>(&buf);
        assert!(matches!(
            r,
            Err(wincode::ReadError::Custom("Invalid Trailing Zeros"))
        ));
        assert!(bincode::deserialize::<Dummy>(&buf).is_err());
    }

    #[test]
    fn last_byte_truncated() {
        let buf = [0x01u8, 0xe4, 0xd7, 0x88, 0xf6, 0x6f];
        let r = wincode::deserialize::<Dummy>(&buf);
        assert!(matches!(
            r,
            Err(wincode::ReadError::Custom("Last Byte Truncated"))
        ));
        assert!(bincode::deserialize::<Dummy>(&buf).is_err());
    }

    #[test]
    fn shift_overflow() {
        let buf = [0x80u8, 0x80, 0x80];
        let r = wincode::deserialize::<Dummy>(&buf);
        assert!(matches!(
            r,
            Err(wincode::ReadError::Custom("Left Shift Overflows"))
        ));
        assert!(bincode::deserialize::<Dummy>(&buf).is_err());
    }

    #[test]
    fn short_buffer() {
        let buf = [0x80u8];
        let r = wincode::deserialize::<Dummy>(&buf);
        assert!(matches!(r, Err(wincode::ReadError::Io(_))));
        assert!(bincode::deserialize::<Dummy>(&buf).is_err());

        let r = wincode::deserialize::<Dummy>(&[]);
        assert!(matches!(r, Err(wincode::ReadError::Io(_))));
        assert!(bincode::deserialize::<Dummy>(&[]).is_err());
    }
}
