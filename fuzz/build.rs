//! Generates the seed corpus for `fuzz_targets/manual_codecs.rs`.
//!
//! Mirrors `fuzz/build.rs` in the wincode repository: every seed is a value
//! serialized with `wincode::serialize` and written to `corpus/<target>/`,
//! which is the directory `cargo fuzz run <target>` uses by default.

use {
    solana_address::Address,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
    solana_message::{
        compiled_instruction::CompiledInstruction,
        v0::{Message as V0Message, MessageAddressTableLookup},
        v1::{Message as V1Message, TransactionConfig, MAX_HEAP_SIZE},
        Message as LegacyMessage, MessageHeader, VersionedMessage,
    },
    solana_packet::{Meta as PacketMeta, Packet, PacketFlags, PACKET_DATA_SIZE},
    solana_short_vec::ShortU16,
    solana_signature::Signature,
    solana_system_interface::instruction as system_instruction,
    solana_transaction::{versioned::VersionedTransaction, Transaction},
    std::{
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::Path,
    },
    wincode::{containers, SchemaWrite},
};

/// Same wrappers as in the fuzz target: `ShortU16` used as a `SeqLen`.
#[derive(SchemaWrite)]
struct ShortVecU8(#[wincode(with = "containers::Vec<_, ShortU16>")] Vec<u8>);
#[derive(SchemaWrite)]
struct ShortVecU64(#[wincode(with = "containers::Vec<_, ShortU16>")] Vec<u64>);

fn write_seed(corpus_dir: &Path, name: &str, data: &[u8]) {
    let path = corpus_dir.join(name);
    fs::write(&path, data).unwrap_or_else(|e| panic!("failed to write seed {name}: {e}"));
}

macro_rules! seed {
    ($corpus_dir:expr, $name:expr, $value:expr) => {
        let bytes = wincode::serialize(&$value)
            .expect(concat!("failed to serialize seed: ", stringify!($name)));
        write_seed($corpus_dir, $name, &bytes);
    };
}

/// Deterministic, recognizable byte pattern: `start, start+1, ...` (wrapping).
fn pattern<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = start.wrapping_add(i as u8);
    }
    out
}

fn address(start: u8) -> Address {
    Address::new_from_array(pattern(start))
}

fn hash(start: u8) -> Hash {
    Hash::new_from_array(pattern(start))
}

fn signature(start: u8) -> Signature {
    Signature::from(pattern::<64>(start))
}

fn header(signed: u8, ro_signed: u8, ro_unsigned: u8) -> MessageHeader {
    MessageHeader {
        num_required_signatures: signed,
        num_readonly_signed_accounts: ro_signed,
        num_readonly_unsigned_accounts: ro_unsigned,
    }
}

fn compiled_transfer() -> CompiledInstruction {
    // System program at index 2, from = 0, to = 1, Transfer { lamports: 1_000_000 }.
    CompiledInstruction::new_from_raw_parts(
        2,
        [2u32.to_le_bytes().as_slice(), &1_000_000u64.to_le_bytes()].concat(),
        vec![0, 1],
    )
}

/// SPL token `Transfer` without pulling in the token crate.
fn token_transfer(
    source: Address,
    destination: Address,
    owner: Address,
    amount: u64,
) -> Instruction {
    const TOKEN_PROGRAM: Address =
        Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    Instruction::new_with_bytes(
        TOKEN_PROGRAM,
        &[&[3u8][..], &amount.to_le_bytes()].concat(),
        vec![
            AccountMeta::new(source, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(owner, true),
        ],
    )
}

/// Legacy message with a single system transfer from `payer` (address 0xad) to 0xd2.
fn legacy_transfer() -> LegacyMessage {
    let payer = address(0xad);
    let mut message = LegacyMessage::new(
        &[system_instruction::transfer(
            &payer,
            &address(0xd2),
            1_000_000,
        )],
        Some(&payer),
    );
    message.recent_blockhash = hash(0xf7);
    message
}

/// Legacy message with a durable nonce, compute-budget instructions, and a token transfer.
fn legacy_multi_ix_nonce() -> LegacyMessage {
    let payer = address(0x1c);
    let mut message = LegacyMessage::new_with_nonce(
        vec![
            ComputeBudgetInstruction::set_compute_unit_limit(200_000),
            ComputeBudgetInstruction::set_compute_unit_price(1),
            token_transfer(address(0x41), address(0x8b), payer, 1_000_000),
        ],
        Some(&payer),
        &address(0x66),
        &payer,
    );
    message.recent_blockhash = hash(0xd5);
    message
}

fn v0_from_legacy(message: LegacyMessage) -> V0Message {
    V0Message {
        header: message.header,
        account_keys: message.account_keys,
        recent_blockhash: message.recent_blockhash,
        instructions: message.instructions,
        address_table_lookups: vec![],
    }
}

fn lookup_populated() -> MessageAddressTableLookup {
    MessageAddressTableLookup {
        account_key: address(0x8e),
        writable_indexes: vec![0, 1],
        readonly_indexes: vec![2],
    }
}

/// v0 message whose instruction addresses two keys loaded from lookup tables.
fn v0_with_lookup() -> V0Message {
    V0Message {
        header: header(1, 0, 1),
        account_keys: vec![address(0x1f), address(0x44), address(0x69)],
        recent_blockhash: hash(0xb3),
        instructions: vec![
            CompiledInstruction::new_from_raw_parts(2, vec![3, 4, 5], vec![0, 1]),
            CompiledInstruction::new_from_raw_parts(
                3,
                [&[3u8][..], &1_000_000u64.to_le_bytes()].concat(),
                vec![4, 5, 0],
            ),
        ],
        address_table_lookups: vec![
            lookup_populated(),
            MessageAddressTableLookup {
                account_key: address(0xb3),
                writable_indexes: vec![],
                readonly_indexes: vec![0xff, 0, 7],
            },
        ],
    }
}

fn v1_from_legacy(message: LegacyMessage, config: TransactionConfig) -> V1Message {
    V1Message {
        header: message.header,
        config,
        lifetime_specifier: message.recent_blockhash,
        account_keys: message.account_keys,
        instructions: message.instructions,
    }
}

fn v1_full_config() -> V1Message {
    v1_from_legacy(
        legacy_multi_ix_nonce(),
        TransactionConfig::empty()
            .with_priority_fee(u64::MAX)
            .with_compute_unit_limit(1_400_000)
            .with_loaded_accounts_data_size_limit(64 * 1024 * 1024)
            .with_heap_size(MAX_HEAP_SIZE),
    )
}

fn v1_partial_config_big_ix() -> V1Message {
    let mut message = v1_from_legacy(
        legacy_transfer(),
        TransactionConfig::empty().with_compute_unit_limit(200_000),
    );
    message
        .instructions
        .push(CompiledInstruction::new_from_raw_parts(
            2,
            vec![0xee; 300],
            vec![0],
        ));
    message
}

fn signed(signatures: usize, message: VersionedMessage) -> VersionedTransaction {
    VersionedTransaction {
        signatures: (0..signatures)
            .map(|i| signature(0x03u8.wrapping_add(i as u8)))
            .collect(),
        message,
    }
}

fn packet_meta(
    size: usize,
    addr: SocketAddr,
    flags: PacketFlags,
    remote: Option<Address>,
) -> PacketMeta {
    let mut meta = PacketMeta::default();
    meta.size = size;
    meta.flags = flags;
    meta.set_socket_addr(&addr);
    if let Some(remote) = remote {
        meta.set_remote_pubkey(remote);
    }
    meta
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let corpus_dir = Path::new(&manifest_dir)
        .join("corpus")
        .join("manual_codecs");
    fs::create_dir_all(&corpus_dir).expect("failed to create corpus directory");

    // ShortU16: every boundary of the 1/2/3-byte encoding.
    seed!(&corpus_dir, "seed-short_u16-zero", ShortU16(0));
    seed!(&corpus_dir, "seed-short_u16-127", ShortU16(127));
    seed!(&corpus_dir, "seed-short_u16-128", ShortU16(128));
    seed!(&corpus_dir, "seed-short_u16-255", ShortU16(255));
    seed!(&corpus_dir, "seed-short_u16-256", ShortU16(256));
    seed!(&corpus_dir, "seed-short_u16-16383", ShortU16(16383));
    seed!(&corpus_dir, "seed-short_u16-16384", ShortU16(16384));
    seed!(&corpus_dir, "seed-short_u16-32767", ShortU16(32767));
    seed!(&corpus_dir, "seed-short_u16-max", ShortU16(u16::MAX));

    // ShortU16-prefixed vectors.
    seed!(&corpus_dir, "seed-short_vec_u8-empty", ShortVecU8(vec![]));
    for len in [1usize, 127, 128, 16383, 16384] {
        seed!(
            &corpus_dir,
            &format!("seed-short_vec_u8-len_{len}"),
            ShortVecU8((0..len).map(|i| i as u8).collect())
        );
    }
    seed!(&corpus_dir, "seed-short_vec_u64-empty", ShortVecU64(vec![]));
    for len in [1usize, 3, 127, 128] {
        seed!(
            &corpus_dir,
            &format!("seed-short_vec_u64-len_{len}"),
            ShortVecU64((0..len).map(|i| u64::from_le_bytes([i as u8; 8])).collect())
        );
    }

    // Compiled instructions.
    seed!(
        &corpus_dir,
        "seed-compiled_instruction-transfer",
        compiled_transfer()
    );
    seed!(
        &corpus_dir,
        "seed-compiled_instruction-128_accounts",
        CompiledInstruction::new_from_raw_parts(u8::MAX, vec![0; 128], (0..128u8).collect(),)
    );

    // Address table lookups.
    seed!(
        &corpus_dir,
        "seed-address_table_lookup-empty",
        MessageAddressTableLookup {
            account_key: address(0xd8),
            writable_indexes: vec![],
            readonly_indexes: vec![],
        }
    );
    seed!(
        &corpus_dir,
        "seed-address_table_lookup-populated",
        lookup_populated()
    );

    // Legacy messages.
    seed!(
        &corpus_dir,
        "seed-legacy_message-default",
        LegacyMessage::default()
    );
    seed!(
        &corpus_dir,
        "seed-legacy_message-transfer",
        legacy_transfer()
    );
    seed!(
        &corpus_dir,
        "seed-legacy_message-multi_ix_nonce",
        legacy_multi_ix_nonce()
    );

    // v0 messages.
    seed!(&corpus_dir, "seed-v0_message-default", V0Message::default());
    seed!(
        &corpus_dir,
        "seed-v0_message-no_lookup",
        v0_from_legacy(legacy_transfer())
    );
    seed!(&corpus_dir, "seed-v0_message-with_lookup", v0_with_lookup());

    // v1 messages.
    seed!(
        &corpus_dir,
        "seed-v1_message-no_keys",
        V1Message {
            header: header(0, 0, 0),
            config: TransactionConfig::empty().with_heap_size(32 * 1024),
            lifetime_specifier: Hash::default(),
            account_keys: vec![],
            instructions: vec![],
        }
    );
    seed!(
        &corpus_dir,
        "seed-v1_message-empty_config",
        v1_from_legacy(legacy_transfer(), TransactionConfig::empty())
    );
    seed!(&corpus_dir, "seed-v1_message-full_config", v1_full_config());
    seed!(
        &corpus_dir,
        "seed-v1_message-partial_config_big_ix",
        v1_partial_config_big_ix()
    );

    // Versioned messages.
    seed!(
        &corpus_dir,
        "seed-versioned_message-legacy",
        VersionedMessage::Legacy(legacy_transfer())
    );
    seed!(
        &corpus_dir,
        "seed-versioned_message-v0",
        VersionedMessage::V0(v0_from_legacy(legacy_transfer()))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_message-v0_with_lookup",
        VersionedMessage::V0(v0_with_lookup())
    );
    seed!(
        &corpus_dir,
        "seed-versioned_message-v1",
        VersionedMessage::V1(v1_from_legacy(
            legacy_transfer(),
            TransactionConfig::empty()
        ))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_message-v1_full_config",
        VersionedMessage::V1(v1_full_config())
    );

    // Legacy transactions.
    seed!(
        &corpus_dir,
        "seed-transaction-unsigned_transfer",
        Transaction::new_unsigned(legacy_transfer())
    );
    seed!(
        &corpus_dir,
        "seed-transaction-signed_transfer",
        Transaction {
            signatures: vec![signature(0x91)],
            message: legacy_transfer(),
        }
    );
    seed!(
        &corpus_dir,
        "seed-transaction-multi_ix_nonce",
        Transaction {
            signatures: vec![signature(0xb6), signature(0xdb)],
            message: legacy_multi_ix_nonce(),
        }
    );
    seed!(
        &corpus_dir,
        "seed-transaction-128_signatures",
        Transaction {
            signatures: (0..128u8).map(|i| signature(i + 1)).collect(),
            message: legacy_transfer(),
        }
    );

    // Versioned transactions.
    seed!(
        &corpus_dir,
        "seed-versioned_tx-legacy",
        signed(1, VersionedMessage::Legacy(legacy_transfer()))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v0",
        signed(1, VersionedMessage::V0(v0_from_legacy(legacy_transfer())))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v0_unsigned",
        signed(0, VersionedMessage::V0(v0_with_lookup()))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v0_with_lookup",
        signed(1, VersionedMessage::V0(v0_with_lookup()))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v1",
        signed(
            1,
            VersionedMessage::V1(v1_from_legacy(
                legacy_transfer(),
                TransactionConfig::empty()
            ))
        )
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v1_full_config",
        signed(2, VersionedMessage::V1(v1_full_config()))
    );
    seed!(
        &corpus_dir,
        "seed-versioned_tx-v1_partial_config",
        signed(1, VersionedMessage::V1(v1_partial_config_big_ix()))
    );

    // Packet metadata.
    seed!(
        &corpus_dir,
        "seed-packet_meta-default",
        PacketMeta::default()
    );
    seed!(
        &corpus_dir,
        "seed-packet_meta-ipv4",
        packet_meta(
            215,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8001),
            PacketFlags::FROM_STAKED_NODE,
            Some(address(0xe7)),
        )
    );
    seed!(
        &corpus_dir,
        "seed-packet_meta-ipv6_all_flags",
        packet_meta(
            PACKET_DATA_SIZE,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                u16::MAX,
            ),
            PacketFlags::all(),
            None,
        )
    );

    // Packets.
    seed!(&corpus_dir, "seed-packet-default", Packet::default());
    seed!(
        &corpus_dir,
        "seed-packet-full_ipv6",
        Packet::new(
            [0xa5; PACKET_DATA_SIZE],
            packet_meta(
                PACKET_DATA_SIZE,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), u16::MAX),
                PacketFlags::all(),
                None,
            ),
        )
    );
    {
        let tx = wincode::serialize(&signed(1, VersionedMessage::V0(v0_with_lookup())))
            .expect("failed to serialize seed: seed-packet-with_v0_tx");
        let mut buffer = [0u8; PACKET_DATA_SIZE];
        buffer[..tx.len()].copy_from_slice(&tx);
        seed!(
            &corpus_dir,
            "seed-packet-with_v0_tx",
            Packet::new(
                buffer,
                packet_meta(
                    tx.len(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000),
                    PacketFlags::empty(),
                    None,
                ),
            )
        );
    }
}
