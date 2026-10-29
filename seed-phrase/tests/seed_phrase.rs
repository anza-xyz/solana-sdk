use solana_seed_phrase::{
    generate_seed_from_bip39_mnemonic, generate_seed_from_seed_phrase_and_passphrase,
};

const ENGLISH_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// BIP-39 reference vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
#[test]
fn bip39_reference_vectors() {
    let vectors = [
        (
            ENGLISH_MNEMONIC,
            "TREZOR",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
            "TREZOR",
            "5a6c23b5abdd5c3e1f7d77ad25ecd715647bdafb44dab324c730a76a45d7421daccee1a4ff0739715a2c56a8a9f1e527a5e3496224d91293bfcd9b5393bfff83",
        ),
        // Both inputs need normalization:
        // https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        ),
    ];

    for (mnemonic, passphrase, expected) in vectors {
        let seed = generate_seed_from_bip39_mnemonic(mnemonic, passphrase);
        assert_eq!(hex::encode(seed), expected, "mnemonic {mnemonic:?}");
    }
}

#[test]
fn passphrase_is_nfkd_normalized() {
    for (passphrase, normalized) in [("café", "cafe\u{301}"), ("Ⅳ", "IV")] {
        assert_eq!(
            generate_seed_from_bip39_mnemonic(ENGLISH_MNEMONIC, passphrase),
            generate_seed_from_bip39_mnemonic(ENGLISH_MNEMONIC, normalized),
            "passphrase {passphrase:?}"
        );
    }
}

#[test]
fn mnemonic_is_nfkd_normalized() {
    for (mnemonic, normalized) in [("académie", "acade\u{301}mie"), ("Ⅳ", "IV")] {
        assert_eq!(
            generate_seed_from_bip39_mnemonic(mnemonic, ""),
            generate_seed_from_bip39_mnemonic(normalized, ""),
            "mnemonic {mnemonic:?}"
        );
    }
}

#[test]
fn legacy_derivation_matches_nfkd_inputs() {
    for passphrase in ["TREZOR", "cafe\u{301}"] {
        assert_eq!(
            generate_seed_from_seed_phrase_and_passphrase(ENGLISH_MNEMONIC, passphrase),
            generate_seed_from_bip39_mnemonic(ENGLISH_MNEMONIC, passphrase),
            "passphrase {passphrase:?}"
        );
    }
}

#[test]
fn mnemonic_whitespace_is_preserved() {
    let canonical_seed = generate_seed_from_bip39_mnemonic(ENGLISH_MNEMONIC, "TREZOR");
    for mnemonic in [
        format!(" {ENGLISH_MNEMONIC}"),
        format!("{ENGLISH_MNEMONIC}\n"),
        ENGLISH_MNEMONIC.replacen(' ', "  ", 1),
    ] {
        let seed = generate_seed_from_bip39_mnemonic(&mnemonic, "TREZOR");
        assert_ne!(seed, canonical_seed, "mnemonic {mnemonic:?}");
        assert_eq!(
            seed,
            generate_seed_from_seed_phrase_and_passphrase(&mnemonic, "TREZOR"),
            "mnemonic {mnemonic:?}"
        );
    }
}

#[test]
fn legacy_derivation_preserves_raw_utf8() {
    let seed = generate_seed_from_seed_phrase_and_passphrase(ENGLISH_MNEMONIC, "café");
    assert_eq!(
        hex::encode(&seed),
        "3f71749629d237c8505c83d334e9a05d9430650ee41a5da768cb4bfe1ebd0882d4ee4fe800aed9a22d8769a9bd404eedec49dcdb80b4e07e624312de775e995e"
    );
    assert_ne!(
        seed,
        generate_seed_from_bip39_mnemonic(ENGLISH_MNEMONIC, "café")
    );
}
