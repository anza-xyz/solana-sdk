use super::*;

/// AC-1.0: Verify oqs output format matches FIPS 206 expectations.
///
/// This executable test verifies that oqs returns public keys and signatures
/// with the expected header bytes and sizes. If these tests fail, the wrapper
/// implementation must adapt to add/strip headers.
#[test]
fn test_oqs_output_format() {
    // Generate a keypair
    let sk = SecretKey::generate().expect("key generation should succeed");
    let pk = sk.public_key();

    // AC-1.0: oqs PublicKey::as_ref() returns exactly PUBKEY_SIZE bytes
    let pk_bytes = pk.as_bytes();
    assert_eq!(
        pk_bytes.len(),
        PUBKEY_SIZE,
        "oqs public key should be {PUBKEY_SIZE} bytes"
    );

    // AC-1.0: oqs PublicKey::as_ref()[0] equals PUBKEY_HEADER
    assert_eq!(
        pk_bytes[0], PUBKEY_HEADER,
        "oqs public key first byte should be {PUBKEY_HEADER:#04x}, got {:#04x}",
        pk_bytes[0]
    );

    // Sign a test message
    let message = b"test message for format verification";
    let sig = sk.sign(message).expect("signing should succeed");
    let sig_bytes = sig.as_bytes();

    // AC-1.0: oqs signature length is within MIN_SIGNATURE_SIZE..=MAX_SIGNATURE_SIZE
    assert!(
        sig_bytes.len() >= MIN_SIGNATURE_SIZE && sig_bytes.len() <= MAX_SIGNATURE_SIZE,
        "oqs signature size {} should be in range {}..={}",
        sig_bytes.len(),
        MIN_SIGNATURE_SIZE,
        MAX_SIGNATURE_SIZE
    );

    // AC-1.0: oqs Signature::as_ref()[0] equals SIGNATURE_HEADER
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
