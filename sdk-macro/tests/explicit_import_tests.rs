mod test_default {
    use solana_sdk_macro::declare_id;

    // Test default behavior (solana_pubkey)
    declare_id!("ZkTokenProof1111111111111111111111111111111");

    #[test]
    fn test_default_import() {
        assert_eq!(
            ID.to_string(),
            "ZkTokenProof1111111111111111111111111111111"
        );
        assert!(check_id(&ID));
        assert_eq!(id(), ID);
    }
}

mod test_explicit_solana_pubkey {
    use solana_sdk_macro::declare_id;

    // Test explicit solana_pubkey import
    declare_id!(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        solana_pubkey = "solana_pubkey"
    );

    #[test]
    fn test_explicit_solana_pubkey_import() {
        assert_eq!(
            ID.to_string(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert!(check_id(&ID));
        assert_eq!(id(), ID);
    }
}

mod test_explicit_solana_sdk {
    use solana_sdk_macro::declare_id;

    // Test explicit solana_sdk import
    declare_id!(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        solana_pubkey = "solana_sdk::pubkey"
    );

    #[test]
    fn test_explicit_solana_sdk_import() {
        assert_eq!(
            ID.to_string(),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        );
        assert!(check_id(&ID));
        assert_eq!(id(), ID);
    }
}

mod test_explicit_solana_program {
    use solana_sdk_macro::declare_id;

    // Test explicit solana_program import
    declare_id!(
        "So11111111111111111111111111111111111111112",
        solana_pubkey = "solana_program::pubkey"
    );

    #[test]
    fn test_explicit_solana_program_import() {
        assert_eq!(
            ID.to_string(),
            "So11111111111111111111111111111111111111112"
        );
        assert!(check_id(&ID));
        assert_eq!(id(), ID);
    }
}
