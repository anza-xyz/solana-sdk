use {
    crate::ShortU16,
    core::mem::MaybeUninit,
    wincode::{
        config::ConfigCore,
        error::write_length_encoding_overflow,
        io::{Reader, Writer},
        len::SeqLen,
        ReadError, ReadResult, SchemaRead, SchemaReadContext, SchemaWrite, WriteResult,
    },
};

/// Deserializes a [`ShortU16`] from its compact 1–3 byte encoding.
///
/// # Examples
///
/// ```
/// use solana_short_vec::ShortU16;
/// let ShortU16(val) = wincode::deserialize(&[0x7f]).unwrap();
/// assert_eq!(val, 127);
/// ```
///
/// ```
/// use solana_short_vec::ShortU16;
/// let ShortU16(val) = wincode::deserialize(&[0x80, 0x01]).unwrap();
/// assert_eq!(val, 128);
/// ```
///
/// ```
/// use solana_short_vec::ShortU16;
/// let ShortU16(val) = wincode::deserialize(&[0x80, 0x80, 0x01]).unwrap();
/// assert_eq!(val, 16384);
/// ```
unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for ShortU16 {
    type Dst = Self;

    #[inline]
    fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let len = decode_short_u16_from_reader(reader)?;
        // SAFETY: `dst` is a valid pointer to a `MaybeUninit<ShortU16>`.
        let slot = unsafe { &mut *(&raw mut (*dst.as_mut_ptr()).0).cast::<MaybeUninit<u16>>() };
        slot.write(len);
        Ok(())
    }
}

/// Decode a `ShortU16` from a prefetched byte prefix and a [`Reader`].
///
/// Bytes are taken from `ctx` first. If the prefix does not contain a complete
/// `ShortU16`, decoding continues by consuming the remaining bytes from `reader`.
/// The reader is left untouched when `ctx` already contains a valid encoding.
#[inline]
fn decode_short_u16_with_ctx<'de, const N: usize>(
    ctx: [u8; N],
    reader: impl Reader<'de>,
) -> ReadResult<u16> {
    /// Hybrid reader that combines a context array and a reader.
    ///
    /// This reader first reads from the context array, then falls back to the reader
    /// once indices exceed the context array size.
    struct Read<const N: usize, R> {
        ctx: [u8; N],
        reader: R,
    }

    impl<'a, const N: usize, R> Read<N, R>
    where
        R: Reader<'a>,
    {
        /// Copy a byte from the context array at `I` if `I < N`, otherwise consume
        /// from the reader.
        #[inline(always)]
        fn take_byte<const I: usize>(&mut self) -> ReadResult<u8> {
            if I < N {
                Ok(self.ctx[I])
            } else {
                Ok(self.reader.take_byte()?)
            }
        }
    }

    let mut reader = Read { ctx, reader };

    let b0 = reader.take_byte::<0>()?;
    if b0 < 0x80 {
        return Ok(b0 as u16);
    }

    let b1 = reader.take_byte::<1>()?;
    if b1 == 0 {
        return Err(non_canonical_err());
    }
    if b1 < 0x80 {
        return Ok(((b0 & 0x7f) as u16) | ((b1 as u16) << 7));
    }

    let b2 = reader.take_byte::<2>()?;
    if b2 == 0 {
        return Err(non_canonical_err());
    }
    if b2 > 3 {
        return Err(overflow_err());
    }

    Ok(((b0 & 0x7f) as u16) | (((b1 & 0x7f) as u16) << 7) | ((b2 as u16) << 14))
}

unsafe impl<'de, const N: usize, C: ConfigCore> SchemaReadContext<'de, C, [u8; N]> for ShortU16 {
    type Dst = Self;

    #[inline]
    fn read_with_context(
        ctx: [u8; N],
        reader: impl Reader<'de>,
        dst: &mut MaybeUninit<Self::Dst>,
    ) -> ReadResult<()> {
        let len = decode_short_u16_with_ctx(ctx, reader)?;
        dst.write(ShortU16(len));
        Ok(())
    }
}

unsafe impl<C: ConfigCore> SchemaWrite<C> for ShortU16 {
    type Src = Self;

    #[inline]
    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        Ok(short_u16_bytes_needed(src.0))
    }

    #[inline]
    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        let mut buf = [MaybeUninit::<u8>::uninit(); 3];
        let bytes = encode_short_u16(&mut buf, src.0);
        writer.write(bytes)?;
        Ok(())
    }
}

/// Branchless computation of the number of bytes needed to encode a short u16.
///
/// See [`solana_short_vec::ShortU16`] for more details.
#[inline(always)]
#[allow(clippy::arithmetic_side_effects)]
fn short_u16_bytes_needed(len: u16) -> usize {
    1 + (len >= 0x80) as usize + (len >= 0x4000) as usize
}

#[inline(always)]
fn try_short_u16_bytes_needed<T: TryInto<u16>>(len: T) -> WriteResult<usize> {
    match len.try_into() {
        Ok(len) => Ok(short_u16_bytes_needed(len)),
        Err(_) => Err(write_length_encoding_overflow("u16::MAX")),
    }
}

/// Encode a short u16 into the given buffer.
///
/// See [`solana_short_vec::ShortU16`] for more details.
#[inline(always)]
fn encode_short_u16(dst: &mut [MaybeUninit<u8>], len: u16) -> &[u8] {
    use core::slice::from_raw_parts;

    // From `solana_short_vec`:
    //
    // u16 serialized with 1 to 3 bytes. If the value is above
    // 0x7f, the top bit is set and the remaining value is stored in the next
    // bytes. Each byte follows the same pattern until the 3rd byte. The 3rd
    // byte may only have the 2 least-significant bits set, otherwise the encoded
    // value will overflow the u16.
    let written = match len {
        0..=0x7f => {
            dst[0].write(len as u8);
            1
        }
        0x80..=0x3fff => {
            dst[0].write(((len & 0x7f) as u8) | 0x80);
            dst[1].write((len >> 7) as u8);
            2
        }
        _ => {
            dst[0].write(((len & 0x7f) as u8) | 0x80);
            dst[1].write((((len >> 7) & 0x7f) as u8) | 0x80);
            dst[2].write((len >> 14) as u8);
            3
        }
    };

    // SAFETY: We wrote exactly `written` bytes.
    unsafe { from_raw_parts(dst.as_ptr().cast(), written) }
}

#[cold]
const fn overflow_err() -> ReadError {
    ReadError::LengthEncodingOverflow("u16::MAX")
}

#[cold]
const fn non_canonical_err() -> ReadError {
    ReadError::InvalidValue("short u16: non-canonical encoding")
}

#[inline(always)]
fn decode_short_u16_from_reader<'de>(reader: impl Reader<'de>) -> ReadResult<u16> {
    decode_short_u16_with_ctx([], reader)
}

unsafe impl<C: ConfigCore> SeqLen<C> for ShortU16 {
    #[inline(always)]
    fn read<'de>(reader: impl Reader<'de>) -> ReadResult<usize> {
        Ok(decode_short_u16_from_reader(reader)? as usize)
    }

    #[inline(always)]
    fn write(writer: impl Writer, len: usize) -> WriteResult<()> {
        if len > u16::MAX as usize {
            return Err(write_length_encoding_overflow("u16::MAX"));
        }

        <ShortU16 as SchemaWrite<C>>::write(writer, &ShortU16(len as u16))
    }

    #[inline(always)]
    fn write_bytes_needed(len: usize) -> WriteResult<usize> {
        try_short_u16_bytes_needed(len)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::ShortU16,
        proptest::prelude::*,
        serde_derive::{Deserialize, Serialize},
        wincode::{containers, io::Cursor},
    };

    fn our_short_u16_encode(len: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3);
        let bytes = encode_short_u16(buf.spare_capacity_mut(), len);
        let written = bytes.len();
        unsafe { buf.set_len(written) }
        buf
    }

    #[derive(
        Serialize, Deserialize, Debug, PartialEq, Eq, wincode::SchemaWrite, wincode::SchemaRead,
    )]
    struct ShortVecStruct {
        #[serde(with = "crate")]
        #[wincode(with = "containers::Vec<u8, ShortU16>")]
        bytes: Vec<u8>,
        #[serde(with = "crate")]
        #[wincode(with = "containers::Vec<[u8; 32], ShortU16>")]
        ar: Vec<[u8; 32]>,
    }

    #[derive(wincode::SchemaWrite, wincode::SchemaRead, Serialize, Deserialize)]
    struct ShortVecAsSchema {
        short_u16: ShortU16,
    }

    fn strat_short_vec_struct() -> impl Strategy<Value = ShortVecStruct> {
        (
            proptest::collection::vec(any::<u8>(), 0..=100),
            proptest::collection::vec(any::<[u8; 32]>(), 0..=16),
        )
            .prop_map(|(bytes, ar)| ShortVecStruct { bytes, ar })
    }

    #[test]
    fn decode_short_u16_with_ctx_uses_only_ctx_when_complete() {
        let mut reader = Cursor::new(&[0xff][..]);

        let decoded = decode_short_u16_with_ctx([0x80, 0x80, 0x01], &mut reader).unwrap();

        assert_eq!(decoded, 0x4000);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn decode_short_u16_with_ctx_uses_only_ctx_for_one_byte_encoding() {
        let mut reader = Cursor::new(&[0xff][..]);

        let decoded = decode_short_u16_with_ctx([0x7f], &mut reader).unwrap();

        assert_eq!(decoded, 0x7f);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn decode_short_u16_with_ctx_uses_only_ctx_for_two_byte_encoding() {
        let mut reader = Cursor::new(&[0xff][..]);

        let decoded = decode_short_u16_with_ctx([0x80, 0x01], &mut reader).unwrap();

        assert_eq!(decoded, 0x80);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn decode_short_u16_with_ctx_stops_after_second_byte_from_reader() {
        let mut reader = Cursor::new(&[0x01, 0xff][..]);

        let decoded = decode_short_u16_with_ctx([0x80], &mut reader).unwrap();

        assert_eq!(decoded, 0x80);
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn decode_short_u16_with_ctx_reads_remaining_bytes_from_reader() {
        let mut reader = Cursor::new(&[0x80, 0x01, 0xff][..]);

        let decoded = decode_short_u16_with_ctx([0x80], &mut reader).unwrap();

        assert_eq!(decoded, 0x4000);
        assert_eq!(reader.position(), 2);
    }

    #[test]
    fn decode_short_u16_with_ctx_non_canonical_second_byte_from_reader() {
        let mut reader = Cursor::new(&[0x00][..]);

        let err = decode_short_u16_with_ctx([0x80], &mut reader).unwrap_err();

        assert!(matches!(
            err,
            ReadError::InvalidValue("short u16: non-canonical encoding")
        ));
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn decode_short_u16_with_ctx_incomplete_second_byte_from_reader() {
        let mut reader = Cursor::new(&[][..]);

        let err = decode_short_u16_with_ctx([0x80], &mut reader).unwrap_err();

        assert!(matches!(
            err,
            ReadError::Io(wincode::io::ReadError::ReadSizeLimit(1))
        ));
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn decode_short_u16_with_ctx_non_canonical_third_byte_from_reader() {
        let mut reader = Cursor::new(&[0x00][..]);

        let err = decode_short_u16_with_ctx([0x80, 0x80], &mut reader).unwrap_err();

        assert!(matches!(
            err,
            ReadError::InvalidValue("short u16: non-canonical encoding")
        ));
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn decode_short_u16_with_ctx_incomplete_third_byte_from_reader() {
        let mut reader = Cursor::new(&[][..]);

        let err = decode_short_u16_with_ctx([0x80, 0x80], &mut reader).unwrap_err();

        assert!(matches!(
            err,
            ReadError::Io(wincode::io::ReadError::ReadSizeLimit(1))
        ));
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn decode_short_u16_with_ctx_overflow_third_byte_from_reader() {
        let mut reader = Cursor::new(&[0x04][..]);

        let err = decode_short_u16_with_ctx([0x80, 0x80], &mut reader).unwrap_err();

        assert!(matches!(err, ReadError::LengthEncodingOverflow("u16::MAX")));
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn decode_short_u16_with_ctx_non_canonical_second_byte_in_ctx() {
        let mut reader = Cursor::new(&[0xff][..]);

        let err = decode_short_u16_with_ctx([0x80, 0x00], &mut reader).unwrap_err();

        assert!(matches!(
            err,
            ReadError::InvalidValue("short u16: non-canonical encoding")
        ));
        assert_eq!(reader.position(), 0);
    }

    proptest! {
        #[test]
        fn encode_u16_equivalence(len in 0..=u16::MAX) {
            let our = our_short_u16_encode(len);
            let bincode = bincode::serialize(&ShortU16(len)).unwrap();
            prop_assert_eq!(our, bincode);
        }

        #[test]
        fn test_short_vec_struct(short_vec_struct in strat_short_vec_struct()) {
            let bincode_serialized = bincode::serialize(&short_vec_struct).unwrap();
            let wincode_serialized = wincode::serialize(&short_vec_struct).unwrap();
            prop_assert_eq!(&bincode_serialized, &wincode_serialized);
            let bincode_deserialized: ShortVecStruct = bincode::deserialize(&bincode_serialized).unwrap();
            let wincode_deserialized: ShortVecStruct = wincode::deserialize(&wincode_serialized).unwrap();
            prop_assert_eq!(&short_vec_struct, &bincode_deserialized);
            prop_assert_eq!(short_vec_struct, wincode_deserialized);
        }

        #[test]
        fn encode_decode_short_u16_roundtrip(len in 0..=u16::MAX) {
            let our = our_short_u16_encode(len);
            let ShortU16(decoded_len) = wincode::deserialize::<ShortU16>(&our).unwrap();
            let (sdk_decoded_len, sdk_read) = crate::decode_shortu16_len(&our).unwrap();
            let sdk_decoded_len = sdk_decoded_len as u16;
            prop_assert_eq!(len, decoded_len);
            prop_assert_eq!(len, sdk_decoded_len);
            prop_assert_eq!(our.len(), sdk_read);
        }

        #[test]
        fn decode_short_u16_err_equivalence(bytes in prop::collection::vec(any::<u8>(), 0..=3)) {
            let wincode_decode = wincode::deserialize::<ShortU16>(&bytes);
            let sdk_decode = crate::decode_shortu16_len(&bytes);
            prop_assert_eq!(wincode_decode.is_err(), sdk_decode.is_err());
            prop_assert_eq!(wincode_decode.is_ok(), sdk_decode.is_ok());
        }

        #[test]
        fn test_short_vec_as_schema(sv in any::<u16>()) {
            let val = ShortVecAsSchema { short_u16: ShortU16(sv) };
            let bincode_serialized = bincode::serialize(&val).unwrap();
            let wincode_serialized = wincode::serialize(&val).unwrap();
            prop_assert_eq!(&bincode_serialized, &wincode_serialized);
            let bincode_deserialized: ShortVecAsSchema = bincode::deserialize(&bincode_serialized).unwrap();
            let wincode_deserialized: ShortVecAsSchema = wincode::deserialize(&wincode_serialized).unwrap();
            prop_assert_eq!(val.short_u16.0, bincode_deserialized.short_u16.0);
            prop_assert_eq!(val.short_u16.0, wincode_deserialized.short_u16.0);
        }
    }
}
