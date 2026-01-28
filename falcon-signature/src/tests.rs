use {super::*, base64::Engine};

// ============================================================================
// Pre-computed test vectors (generated once, used for testing without sign())
// ============================================================================
// These test vectors allow verification testing without requiring the sign()
// function to be implemented or available. The vectors were generated using
// the `generate_test_vectors_for_hardcoding` test below.
//
// Note: Known Answer Tests (KAT) for Falcon-512 are performed in liboqs itself,
// so we skip them in this repository. Our tests focus on the SDK wrapper layer:
// serialization, deserialization, instruction building, and integration with
// the Solana runtime.

const TEST_MESSAGE: &[u8] = b"test message for pre-computed verification";

// Public key (897 bytes)
const TEST_PUBKEY_BASE64: &str = "CV6ZIYJ17ttDNY6BY2L8laqhQqEQT0hhvZsBqe1NNeUj+c7ULeEiVl3FZwC0xqYFDh9uAJxQyM1eGQ3MeH9TzRTuCQiF0W21vlwR0R/Rt3ClEYJaopd4q5fnosNXxfOmS4pgBxLB2wgT7KLct2MOp+s1RClmOynIr54jA5YIrE0w/juE1Xmp3Yc3igsaJumDqBCUthmKQLaVa6+wKNNnAFtaNbHbuGhIQaC9edrcknM4dBlJzWp8YDIqxOHs3aou3+ljgHZjmGW3VYcgcf2TK8SRtVmQVHiCkQa2woZ204kRkXUIOuMRUmb8B+K53kALVjDJ2ZvTuKIukFqO0idUMmFzyO+K0vDBlMysF9yDGZ/Um1US+Hk6hyqpyFyz4J+hYhaD0vtK7Qf0UGsVU3GEcOLB9MWUCuxEkmQttxU4SbEFVtWy1M/BvU2AoPl0N8KlQbm5+IvrEA86UFfHHykhGBUYIpPdxiOmlvM5hlce6Q3UgB+dCuy61uUYD3yI3+Z/RSEaBWBQ92MCt9ImtyCVjiRNWaM53hlTSF+7t0AlVay5G/Lf0UOyEScNSaVe4GJTv9vxnxyaFL9c+4k03abAVFC9prS5lCDLGpnUqvGQGUemP9hG7eY3PWOqgB+DEHhVmkIU4ybJAHbPFL0BxubCO2MxW+mf+pyi2CQK7ypAH30ZtpQ3/Z2La45d6voM2n9s9hddXm1wjXnh5EXWv7mCKoXK2IExRbshnnAp+pJ5jEVYsFKB6IqRo4i+YRKuyU4EEXDVZSB9URRpkm6pMTlULvPmYMojEMAkVRt4Y7ZoyQNQIT5gs2hGUZ2+8jwT2KW7t7k1MhjeWC5uRmdrgyYGNfN609MlkQi7IIDgrwpF+8WrzemR5vcmySSVo3Hk9WjjrrnI3UjvLKSylRrJdgG9WMD3NE8RCjGRwWQoXzK4kPuBs1NnvX2ywDxhhYFwpKOQ338UcTg4lhhNpzzGmOGP3LXuxrCK5AGf+erwsJETJhWu5TcihpzmY/bgw76Vei9S7WVWqx0opviNhQbmzboQwQRxBX2Wewgmvz2I86pKfXgyJfQ7gOae0MrrGmDnkQ3W9ENhwrJ1G7fmofMrnnzFOVqbZJq9Wz2fnYmSY2c0URS9FmxUC5fGI5Kx01cZnyh6AxSGBnxATi/FR1lhKvx+NdsCM2pEIHC5ypFIiazAqIEC";

// Signature (655 bytes)
const TEST_SIGNATURE_BASE64: &str = "OSCJBLuOJh5ASZPOMj7hL6Wvqs4nmwXV+xEGkRUkLiXgHaXqBjaayVwEYSQ6SDYKA5oi1aWzmx5uULs0Xw/l7+VsG58jhGL5NfkO0PPK9dH/R6HBhGamGPOqTW9Ye/0PeWUydbcRQ8XKWEV7IazO0+pmahhul7gSWcvZnJVbVf14e/UITCvmsXWnr1wQk0tMscaDPGwLvsr1MevbAzxUZlZ3SZ80D9YEyI1dQ5O6NrnpZlifJfgszEHXuRjtV6iCmNLBojckK0GCe/55ddEHKz/uLREPyXav5qM5jczwdjMq43qp50UshSHJzLtCY9LWfNpvp882VkCrXLEC/oQ0elIO2bXbhSYX+sev1t0qS0pNMtkmCFi/sHpNIUqr8Cazw7+MiZzUsTxHTRRjIKjhsdrEh6Oe0vi96h2d86iyGxo5TGZtNYg729HQnPRCFCEy1OHTPl6NL3s8VbyX7Ak/hqg2SDzy7pDofHSz9YNd4ftr5x9Cia+K3rVJZxm3M16c2NvNusblH5xpvGHUVKnJUZNlArhU3r3kW2eQZzqOoj5jOFC65kNxJm2yZUoA05Fq//oCT+sw1TDLrtJjKupDIIbhs4o1iIQCDMKVmFs1OiG5g/Kf5zMQE4f4huuiSn4dTsk9PArlGpvpnOLRiY+DUSRgHeKB7twZORI+qBoI2SnTwPhT+DE6WyM3VC13+i3VBVbNv9HNe3/rnBEa6ZtzZMtPnmQs2eZ26L83mcDONoxwvm/rsfKxNEoO7ivdBG3l52URskV5lbgbLNnfldnfn7eFkiCHikUl1m3INgiTiB83KnRauvYW4FWaDhs2xvX8qL7upp3mFnuH6cnGenXVFjFVcG5t0vm6YW/ObDyIkA==";

/// Helper function to decode base64 test vectors
fn decode_test_pubkey() -> PublicKey {
    let b64 = base64::engine::general_purpose::STANDARD;
    let bytes = b64.decode(TEST_PUBKEY_BASE64).expect("valid base64");
    PublicKey::from_slice(&bytes).expect("valid public key")
}

/// Helper function to decode base64 test vectors
fn decode_test_signature() -> Signature {
    let b64 = base64::engine::general_purpose::STANDARD;
    let bytes = b64.decode(TEST_SIGNATURE_BASE64).expect("valid base64");
    Signature::from_slice(&bytes).expect("valid signature")
}

// ============================================================================
// Tests using pre-computed test vectors (no sign() required)
// ============================================================================

/// Test that pre-computed public key bytes can be deserialized correctly.
#[test]
fn test_precomputed_pubkey_deserialization() {
    let pk = decode_test_pubkey();

    assert_eq!(pk.as_bytes().len(), PUBKEY_SIZE);
    assert_eq!(pk.as_bytes()[0], PUBKEY_HEADER);
}

/// Test that pre-computed signature bytes can be deserialized correctly.
#[test]
fn test_precomputed_signature_deserialization() {
    let sig = decode_test_signature();

    assert!(sig.len() >= MIN_SIGNATURE_SIZE);
    assert!(sig.len() <= MAX_SIGNATURE_SIZE);
    assert_eq!(sig.as_bytes()[0], SIGNATURE_HEADER);
}

/// Test verification with pre-computed test vectors.
/// This test validates the verify() function without requiring sign().
#[test]
fn test_precomputed_verification_succeeds() {
    let pk = decode_test_pubkey();
    let sig = decode_test_signature();

    pk.verify(TEST_MESSAGE, &sig)
        .expect("verification with pre-computed test vectors should succeed");
}

/// Test that verification fails with wrong message using pre-computed vectors.
#[test]
fn test_precomputed_verification_wrong_message_fails() {
    let pk = decode_test_pubkey();
    let sig = decode_test_signature();

    let wrong_message = b"wrong message";
    let result = pk.verify(wrong_message, &sig);
    assert!(
        result.is_err(),
        "verification should fail with wrong message"
    );
}

/// Test that verification fails with corrupted signature.
#[test]
fn test_precomputed_verification_corrupted_signature_fails() {
    let pk = decode_test_pubkey();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut sig_bytes = b64.decode(TEST_SIGNATURE_BASE64).expect("valid base64");

    // Corrupt a byte in the middle of the signature (not the header)
    sig_bytes[100] ^= 0xFF;

    let corrupted_sig = Signature::from_slice(&sig_bytes).expect("still valid format");
    let result = pk.verify(TEST_MESSAGE, &corrupted_sig);
    assert!(
        result.is_err(),
        "verification should fail with corrupted signature"
    );
}

/// Test that verification fails with corrupted public key.
#[test]
fn test_precomputed_verification_corrupted_pubkey_fails() {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut pk_bytes: [u8; PUBKEY_SIZE] = b64
        .decode(TEST_PUBKEY_BASE64)
        .expect("valid base64")
        .try_into()
        .expect("correct size");

    // Corrupt a byte in the middle of the public key (not the header)
    pk_bytes[100] ^= 0xFF;

    let corrupted_pk = PublicKey::new(pk_bytes).expect("still valid format");
    let sig = decode_test_signature();

    let result = corrupted_pk.verify(TEST_MESSAGE, &sig);
    assert!(
        result.is_err(),
        "verification should fail with corrupted public key"
    );
}

/// Test instruction creation with pre-computed test vectors.
#[test]
fn test_precomputed_instruction_creation() {
    let pk = decode_test_pubkey();
    let sig = decode_test_signature();

    let instruction = new_falcon512_instruction_with_signature(TEST_MESSAGE, &sig, &pk);

    // Verify program ID
    assert_eq!(
        instruction.program_id,
        solana_sdk_ids::falcon512_program::id()
    );

    // Verify expected data length
    let expected_len = DATA_START + PUBKEY_SIZE + sig.len() + TEST_MESSAGE.len();
    assert_eq!(instruction.data.len(), expected_len);

    // Verify public key is at expected offset
    let pk_start = DATA_START;
    let pk_end = pk_start + PUBKEY_SIZE;
    assert_eq!(&instruction.data[pk_start..pk_end], pk.as_bytes());

    // Verify signature is at expected offset
    let sig_start = pk_end;
    let sig_end = sig_start + sig.len();
    assert_eq!(&instruction.data[sig_start..sig_end], sig.as_bytes());

    // Verify message is at expected offset
    let msg_start = sig_end;
    assert_eq!(&instruction.data[msg_start..], TEST_MESSAGE);
}

/// Test round-trip: verify instruction offsets point to correct data with pre-computed vectors.
#[test]
fn test_precomputed_instruction_offsets_roundtrip() {
    let pk = decode_test_pubkey();
    let sig = decode_test_signature();

    let instruction = new_falcon512_instruction_with_signature(TEST_MESSAGE, &sig, &pk);

    // Parse offsets from instruction data
    let offsets_bytes = &instruction.data[SIGNATURE_OFFSETS_START..DATA_START];
    let offsets: &Falcon512SignatureOffsets = bytemuck::from_bytes(offsets_bytes);

    // Extract data using offsets
    let extracted_sig_start = offsets.signature_offset as usize;
    let extracted_sig_end = extracted_sig_start + offsets.signature_length as usize;
    let extracted_sig_bytes = &instruction.data[extracted_sig_start..extracted_sig_end];

    let extracted_pk_start = offsets.public_key_offset as usize;
    let extracted_pk_end = extracted_pk_start + PUBKEY_SIZE;
    let extracted_pk_bytes = &instruction.data[extracted_pk_start..extracted_pk_end];

    let extracted_msg_start = offsets.message_offset as usize;
    let extracted_msg_end = extracted_msg_start + offsets.message_length as usize;
    let extracted_msg_bytes = &instruction.data[extracted_msg_start..extracted_msg_end];

    // Reconstruct types from extracted bytes
    let extracted_pk = PublicKey::from_slice(extracted_pk_bytes).expect("valid public key");
    let extracted_sig = Signature::from_slice(extracted_sig_bytes).expect("valid signature");

    // Verify the extracted data matches originals
    assert_eq!(extracted_pk.as_bytes(), pk.as_bytes());
    assert_eq!(extracted_sig.as_bytes(), sig.as_bytes());
    assert_eq!(extracted_msg_bytes, TEST_MESSAGE);

    // Verify the extracted components can be used for verification
    extracted_pk
        .verify(extracted_msg_bytes, &extracted_sig)
        .expect("verification with extracted components should succeed");
}

#[test]
#[ignore] // Only run manually to generate new test vectors
fn generate_test_vectors_for_hardcoding() {
    let b64 = base64::engine::general_purpose::STANDARD;

    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    let message = b"test message for pre-computed verification";
    let signature = sk.sign(message).expect("signing should succeed");

    println!("\n=== TEST VECTORS ===");
    println!(
        "const TEST_MESSAGE: &[u8] = b\"{}\";",
        std::str::from_utf8(message).unwrap()
    );
    println!();
    println!("// Public key ({} bytes)", pk.as_bytes().len());
    println!(
        "const TEST_PUBKEY_BASE64: &str = \"{}\";",
        b64.encode(pk.as_bytes())
    );
    println!();
    println!("// Signature ({} bytes)", signature.len());
    println!(
        "const TEST_SIGNATURE_BASE64: &str = \"{}\";",
        b64.encode(signature.as_bytes())
    );
    println!("=== END TEST VECTORS ===\n");
}

// ============================================================================
// Normal tests
// ============================================================================

/// Verify oqs output format matches FIPS 206 expectations.
///
/// This executable test verifies that oqs returns public keys and signatures
/// with the expected header bytes and sizes. If these tests fail, the wrapper
/// implementation must adapt to add/strip headers.
#[test]
fn test_oqs_output_format() {
    // Generate a keypair
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    // oqs PublicKey::as_ref() returns exactly PUBKEY_SIZE bytes
    let pk_bytes = pk.as_bytes();
    assert_eq!(
        pk_bytes.len(),
        PUBKEY_SIZE,
        "oqs public key should be {PUBKEY_SIZE} bytes"
    );

    // oqs PublicKey::as_ref()[0] equals PUBKEY_HEADER
    assert_eq!(
        pk_bytes[0], PUBKEY_HEADER,
        "oqs public key first byte should be {PUBKEY_HEADER:#04x}, got {:#04x}",
        pk_bytes[0]
    );

    // Sign a test message
    let message = b"test message for format verification";
    let sig = sk.sign(message).expect("signing should succeed");
    let sig_bytes = sig.as_bytes();

    // oqs signature length is within MIN_SIGNATURE_SIZE..=MAX_SIGNATURE_SIZE
    assert!(
        sig_bytes.len() >= MIN_SIGNATURE_SIZE && sig_bytes.len() <= MAX_SIGNATURE_SIZE,
        "oqs signature size {} should be in range {}..={}",
        sig_bytes.len(),
        MIN_SIGNATURE_SIZE,
        MAX_SIGNATURE_SIZE
    );

    // oqs Signature::as_ref()[0] equals SIGNATURE_HEADER
    assert_eq!(
        sig_bytes[0], SIGNATURE_HEADER,
        "oqs signature first byte should be {SIGNATURE_HEADER:#04x}, got {:#04x}",
        sig_bytes[0]
    );
}

#[test]
fn test_keypair_generation() {
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    assert_eq!(pk.as_bytes().len(), PUBKEY_SIZE);
    assert_eq!(pk.as_bytes()[0], PUBKEY_HEADER);
}

/// Self-signed verification: sign with key A, verify with key A succeeds.
#[test]
fn test_self_signed_verification() {
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    let message = b"Hello, Falcon-512!";
    let signature = sk.sign(message).expect("signing should succeed");

    assert!(signature.len() >= MIN_SIGNATURE_SIZE);
    assert!(signature.len() <= MAX_SIGNATURE_SIZE);
    assert_eq!(signature.as_bytes()[0], SIGNATURE_HEADER);

    pk.verify(message, &signature)
        .expect("self-signed verification should succeed");
}

/// Cross-key verification: sign with key A, verify with key B fails (proves keys are distinct).
#[test]
fn test_cross_key_verification_fails() {
    let sk_a = SecretKey::generate().expect("key generation should succeed");
    let sk_b = SecretKey::generate().expect("key generation should succeed");

    // Ensure keys are distinct
    assert_ne!(
        sk_a.public_key().as_bytes(),
        sk_b.public_key().as_bytes(),
        "generated keys should be distinct"
    );

    let message = b"Test message for cross-key verification";
    let signature = sk_a.sign(message).expect("signing should succeed");

    // Verification with different key should fail
    let result = sk_b.public_key().verify(message, &signature);
    assert!(
        result.is_err(),
        "cross-key verification should fail (signature from key A, verified with key B)"
    );
}

#[test]
fn test_verify_wrong_message() {
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    let message = b"Original message";
    let signature = sk.sign(message).expect("signing should succeed");

    let wrong_message = b"Wrong message";
    let result = pk.verify(wrong_message, &signature);
    assert!(
        result.is_err(),
        "verification with wrong message should fail"
    );
}

#[test]
fn test_invalid_public_key_size() {
    let bytes = vec![0u8; 100]; // Wrong size
    let result = PublicKey::from_slice(&bytes);
    assert!(matches!(
        result,
        Err(FalconError::InvalidPublicKeySize(100))
    ));
}

#[test]
fn test_invalid_public_key_header() {
    let mut bytes = [0u8; PUBKEY_SIZE];
    bytes[0] = 0xFF; // Wrong header
    let result = PublicKey::new(bytes);
    assert!(matches!(
        result,
        Err(FalconError::InvalidPublicKeyHeader(0xFF))
    ));
}

#[test]
fn test_invalid_signature_size_too_small() {
    let bytes = vec![SIGNATURE_HEADER; 10]; // Too small
    let result = Signature::new(bytes);
    assert!(matches!(result, Err(FalconError::InvalidSignatureSize(10))));
}

#[test]
fn test_invalid_signature_size_too_large() {
    let bytes = vec![SIGNATURE_HEADER; 1000]; // Too large
    let result = Signature::new(bytes);
    assert!(matches!(
        result,
        Err(FalconError::InvalidSignatureSize(1000))
    ));
}

#[test]
fn test_invalid_signature_header() {
    let mut bytes = vec![0u8; 100];
    bytes[0] = 0xFF; // Wrong header
    let result = Signature::new(bytes);
    assert!(matches!(
        result,
        Err(FalconError::InvalidSignatureHeader(0xFF))
    ));
}

#[test]
fn test_signature_offsets_size() {
    assert_eq!(
        core::mem::size_of::<Falcon512SignatureOffsets>(),
        SIGNATURE_OFFSETS_SIZE,
        "Falcon512SignatureOffsets should be exactly {SIGNATURE_OFFSETS_SIZE} bytes"
    );
}

#[test]
fn test_offsets_bytemuck_serialization() {
    let offsets = Falcon512SignatureOffsets {
        signature_offset: 100,
        signature_length: 650,
        signature_instruction_index: u16::MAX,
        public_key_offset: 200,
        public_key_instruction_index: u16::MAX,
        message_offset: 300,
        message_length: 32,
        message_instruction_index: u16::MAX,
    };

    let bytes = bytemuck::bytes_of(&offsets);
    assert_eq!(bytes.len(), SIGNATURE_OFFSETS_SIZE);

    // Verify little-endian encoding
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 100); // signature_offset
    assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 650); // signature_length
}

#[test]
fn test_offsets_to_falcon512_instruction() {
    let offsets = vec![Falcon512SignatureOffsets {
        signature_offset: 18,
        signature_length: 650,
        signature_instruction_index: u16::MAX,
        public_key_offset: 668,
        public_key_instruction_index: u16::MAX,
        message_offset: 1565,
        message_length: 100,
        message_instruction_index: u16::MAX,
    }];

    let instruction = offsets_to_falcon512_instruction(&offsets);

    // Verify program ID
    assert_eq!(
        instruction.program_id,
        solana_sdk_ids::falcon512_program::id()
    );

    // Verify no accounts required
    assert!(instruction.accounts.is_empty());

    // Verify instruction data layout
    assert_eq!(instruction.data[0], 1); // num_signatures
    assert_eq!(instruction.data[1], 0); // padding
    assert_eq!(
        instruction.data.len(),
        SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SIZE
    );
}

#[test]
fn test_new_falcon512_instruction_with_signature() {
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();
    let message = b"Test message for instruction";
    let signature = sk.sign(message).expect("signing should succeed");

    let instruction = new_falcon512_instruction_with_signature(message, &signature, pk);

    // Verify program ID
    assert_eq!(
        instruction.program_id,
        solana_sdk_ids::falcon512_program::id()
    );

    // Verify no accounts required
    assert!(instruction.accounts.is_empty());

    // Verify instruction data layout
    assert_eq!(instruction.data[0], 1); // num_signatures
    assert_eq!(instruction.data[1], 0); // padding

    // Verify expected data length
    let expected_len = DATA_START + PUBKEY_SIZE + signature.len() + message.len();
    assert_eq!(instruction.data.len(), expected_len);

    // Verify public key is at expected offset
    let pk_start = DATA_START;
    let pk_end = pk_start + PUBKEY_SIZE;
    assert_eq!(&instruction.data[pk_start..pk_end], pk.as_bytes());

    // Verify signature is at expected offset
    let sig_start = pk_end;
    let sig_end = sig_start + signature.len();
    assert_eq!(&instruction.data[sig_start..sig_end], signature.as_bytes());

    // Verify message is at expected offset
    let msg_start = sig_end;
    assert_eq!(&instruction.data[msg_start..], message);
}

#[test]
fn test_instruction_offsets_match_data_layout() {
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();
    let message = b"Verify offsets match actual data positions";
    let signature = sk.sign(message).expect("signing should succeed");

    let instruction = new_falcon512_instruction_with_signature(message, &signature, pk);

    // Parse offsets from instruction data
    let offsets_bytes = &instruction.data[SIGNATURE_OFFSETS_START..DATA_START];
    let offsets: &Falcon512SignatureOffsets = bytemuck::from_bytes(offsets_bytes);

    // Verify offsets point to correct data
    let sig_start = offsets.signature_offset as usize;
    let sig_end = sig_start + offsets.signature_length as usize;
    assert_eq!(
        &instruction.data[sig_start..sig_end],
        signature.as_bytes(),
        "signature offset should point to signature data"
    );

    let pk_start = offsets.public_key_offset as usize;
    let pk_end = pk_start + PUBKEY_SIZE;
    assert_eq!(
        &instruction.data[pk_start..pk_end],
        pk.as_bytes(),
        "public key offset should point to public key data"
    );

    let msg_start = offsets.message_offset as usize;
    let msg_end = msg_start + offsets.message_length as usize;
    assert_eq!(
        &instruction.data[msg_start..msg_end],
        message,
        "message offset should point to message data"
    );

    // Verify instruction indices are set to current instruction
    assert_eq!(offsets.signature_instruction_index, u16::MAX);
    assert_eq!(offsets.public_key_instruction_index, u16::MAX);
    assert_eq!(offsets.message_instruction_index, u16::MAX);
}
