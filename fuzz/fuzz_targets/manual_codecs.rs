#![no_main]

//! Reduced variant of `sdk_types`, restricted to the types whose wincode
//! encoding or decoding goes through a hand-written schema somewhere in the
//! solana-sdk workspace (directly, or via a `#[wincode(with = ...)]` field):
//!
//! - `ShortU16` (`short-vec/src/wincode.rs`), and every `ShortU16`-prefixed
//!   container in the message and transaction types.
//! - `VersionedMessage`, v1 `Message`, `VersionedTransaction`, and the legacy
//!   `Message` read-with-context path (`message/`, `transaction/`).
//! - `LenPrefixedByteArray<N>` and `PodPacketFlags` (`packet/src/lib.rs`).
//!
//! The checks are the same as in `sdk_types`: when `deserialize_exact::<T>`
//! accepts the input, `serialize(value) == input` and
//! `deserialize(serialize(value)) == value`.

use {
    libfuzzer_sys::fuzz_target,
    solana_message::{
        compiled_instruction::CompiledInstruction,
        v0::{Message as V0Message, MessageAddressTableLookup},
        v1::Message as V1Message,
        Message as LegacyMessage, VersionedMessage,
    },
    solana_packet::{Meta as PacketMeta, Packet},
    solana_short_vec::ShortU16,
    solana_transaction::{versioned::VersionedTransaction, Transaction},
    wincode::{containers, SchemaRead, SchemaWrite},
};

/// Exercise `ShortU16` as a `SeqLen`, the way the message and transaction types use it.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
struct ShortVecU8(#[wincode(with = "containers::Vec<_, ShortU16>")] Vec<u8>);
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
struct ShortVecU64(#[wincode(with = "containers::Vec<_, ShortU16>")] Vec<u64>);

/// Exact round trip: decode -> encode must reproduce the input byte for byte,
/// and encode -> decode must reproduce the value.
macro_rules! fuzz_roundtrip {
    ($data:expr, $ty:ty) => {
        if let Ok(value) = wincode::deserialize_exact::<$ty>($data) {
            let serialized = wincode::serialize(&value).expect("serialize should succeed");
            assert_eq!(
                $data,
                serialized.as_slice(),
                "deserialize -> serialize != original data for type {}\nserialized {:?}\noriginal   {:?}",
                stringify!($ty),
                serialized,
                $data,
            );
            let roundtrip: $ty =
                wincode::deserialize(&serialized).expect("roundtrip deserialize should succeed");
            assert_eq!(value, roundtrip, "roundtrip failed for {}", stringify!($ty));
        }
    };
}

/// `ShortU16` has no `Debug`/`PartialEq`; compare through the inner `u16`.
fn fuzz_roundtrip_short_u16(data: &[u8]) {
    if let Ok(value) = wincode::deserialize_exact::<ShortU16>(data) {
        let serialized = wincode::serialize(&value).expect("serialize should succeed");
        assert_eq!(
            data,
            serialized.as_slice(),
            "deserialize -> serialize != original data for type ShortU16\nserialized {:?}\noriginal   {:?}",
            serialized,
            data,
        );
        let roundtrip: ShortU16 =
            wincode::deserialize(&serialized).expect("roundtrip deserialize should succeed");
        assert_eq!(value.0, roundtrip.0, "roundtrip failed for ShortU16");
    }
}

fuzz_target!(|data: &[u8]| {
    // Length encodings.
    fuzz_roundtrip_short_u16(data);
    fuzz_roundtrip!(data, ShortVecU8);
    fuzz_roundtrip!(data, ShortVecU64);

    // Messages and transactions.
    fuzz_roundtrip!(data, CompiledInstruction);
    fuzz_roundtrip!(data, MessageAddressTableLookup);
    fuzz_roundtrip!(data, LegacyMessage);
    fuzz_roundtrip!(data, V0Message);
    fuzz_roundtrip!(data, V1Message);
    fuzz_roundtrip!(data, VersionedMessage);
    fuzz_roundtrip!(data, Transaction);
    fuzz_roundtrip!(data, VersionedTransaction);

    // Packets.
    fuzz_roundtrip!(data, PacketMeta);
    fuzz_roundtrip!(data, Packet);
});
