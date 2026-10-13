#![cfg(not(target_os = "solana"))]

use solana_bls_signatures::{
    error::BlsError,
    hash::{HashedMessage, PreparedHashedMessage},
    keypair::Keypair,
    pubkey::VerifySignature,
    signature::{SignatureAffine, SignatureCompressed, SignatureProjective},
};

#[test]
fn reused_and_cloned_preparations_match_direct_verification() {
    let keypairs = [
        Keypair::derive(&[42u8; 32]).unwrap(),
        Keypair::derive(&[43u8; 32]).unwrap(),
    ];
    let messages: [&[u8]; 3] = [
        b"",
        b"prepared verification regression",
        b"\x00\xff\x80\x00",
    ];
    let hashes = messages.map(HashedMessage::new);

    let originals: Vec<_> = hashes
        .iter()
        .map(PreparedHashedMessage::from_hashed_message)
        .collect();
    let preparations = originals.clone();
    drop(originals);

    // Reuse each surviving clone across different keys and signatures.
    for (signer_index, signer) in keypairs.iter().enumerate() {
        for (signed_index, message) in messages.iter().enumerate() {
            let encoded: SignatureCompressed = signer.sign(message).into();
            let affine = SignatureAffine::try_from(&encoded).unwrap();

            for (verifier_index, verifier) in keypairs.iter().enumerate() {
                for (checked_index, hashed) in hashes.iter().enumerate() {
                    let expected =
                        if signer_index == verifier_index && signed_index == checked_index {
                            Ok(())
                        } else {
                            Err(BlsError::VerificationFailed)
                        };

                    assert_eq!(
                        verifier
                            .public
                            .verify_signature_pre_hashed(&encoded, hashed),
                        expected,
                        "direct verification",
                    );
                    assert_eq!(
                        verifier
                            .public
                            .verify_signature_prepared(&encoded, &preparations[checked_index],),
                        expected,
                        "prepared verification with compressed signature",
                    );
                    assert_eq!(
                        verifier
                            .public
                            .verify_signature_prepared(&affine, &preparations[checked_index],),
                        expected,
                        "prepared verification with affine signature",
                    );
                }
            }
        }
    }
}

#[test]
fn prepared_verification_preserves_signature_errors() {
    let keypair = Keypair::derive(&[44u8; 32]).unwrap();
    let hashed = HashedMessage::new(b"signature error regression");
    let prepared = PreparedHashedMessage::from_hashed_message(&hashed);

    let identity: SignatureCompressed = SignatureProjective::identity().into();
    SignatureAffine::try_from(&identity).expect("identity signatures must remain decodable");

    let malformed = SignatureCompressed([0u8; 96]);
    let malformed_error = SignatureAffine::try_from(&malformed)
        .expect_err("all-zero bytes must not decode as a signature");

    for (label, signature, error) in [
        ("identity", identity, BlsError::VerificationFailed),
        ("malformed", malformed, malformed_error),
    ] {
        let expected = Err(error);

        assert_eq!(
            keypair
                .public
                .verify_signature_pre_hashed(&signature, &hashed),
            expected,
            "{label}: direct verification",
        );
        assert_eq!(
            keypair
                .public
                .verify_signature_prepared(&signature, &prepared),
            expected,
            "{label}: prepared verification",
        );
        assert_eq!(
            SignatureProjective::verify_distinct_aggregated_pre_hashed(
                core::iter::once(&keypair.public),
                &signature,
                core::iter::once(&hashed),
            ),
            expected,
            "{label}: pre-hashed aggregate screening",
        );
        assert_eq!(
            SignatureProjective::verify_distinct_aggregated_prepared(
                core::iter::once(&keypair.public),
                &signature,
                core::iter::once(&prepared),
            ),
            expected,
            "{label}: prepared aggregate screening",
        );
        #[cfg(feature = "parallel")]
        assert_eq!(
            SignatureProjective::par_verify_distinct_aggregated_prepared(
                core::slice::from_ref(&keypair.public),
                &signature,
                core::slice::from_ref(&prepared),
            ),
            expected,
            "{label}: parallel prepared aggregate screening",
        );
    }
}

#[test]
fn prepared_screening_preserves_duplicate_message_grouping() {
    let keypairs = [
        Keypair::derive(&[45u8; 32]).unwrap(),
        Keypair::derive(&[46u8; 32]).unwrap(),
        Keypair::derive(&[47u8; 32]).unwrap(),
    ];
    let public_keys = [keypairs[0].public, keypairs[1].public, keypairs[2].public];

    // Equal messages deliberately occupy nonadjacent positions.
    let messages: [&[u8]; 3] = [b"shared", b"unique", b"shared"];
    let signatures = [
        keypairs[0].sign(messages[0]),
        keypairs[1].sign(messages[1]),
        keypairs[2].sign(messages[2]),
    ];
    let aggregate_signature = SignatureProjective::aggregate(signatures.iter()).unwrap();

    let wrong_messages: [&[u8]; 3] = [b"shared", b"unique", b"wrong"];
    for (checked_messages, expected) in [
        (messages, Ok(())),
        (wrong_messages, Err(BlsError::VerificationFailed)),
    ] {
        let hashes = checked_messages.map(HashedMessage::new);
        let preparations: Vec<_> = hashes
            .iter()
            .map(PreparedHashedMessage::from_hashed_message)
            .collect();

        assert_eq!(
            SignatureProjective::verify_distinct_aggregated_pre_hashed(
                public_keys.iter(),
                &aggregate_signature,
                hashes.iter(),
            ),
            expected,
            "pre-hashed aggregate screening",
        );
        assert_eq!(
            SignatureProjective::verify_distinct_aggregated_prepared(
                public_keys.iter(),
                &aggregate_signature,
                preparations.iter(),
            ),
            expected,
            "prepared aggregate screening",
        );
        #[cfg(feature = "parallel")]
        {
            assert_eq!(
                SignatureProjective::par_verify_distinct_aggregated_prepared(
                    &public_keys,
                    &aggregate_signature,
                    &preparations,
                ),
                expected,
                "parallel prepared aggregate screening",
            );
            assert_eq!(
                SignatureProjective::par_verify_distinct_prepared(
                    &public_keys,
                    &signatures,
                    &preparations,
                ),
                expected,
                "parallel prepared screening with signature aggregation",
            );
        }
    }
}

#[cfg(feature = "parallel")]
#[test]
fn parallel_distinct_screening_preserves_public_key_errors() {
    use solana_bls_signatures::pubkey::{
        AsPubkeyAffine, PopVerified, PubkeyAffine, PubkeyCompressed, PubkeyProjective,
    };

    let keypair = Keypair::derive(&[48u8; 32]).unwrap();
    let messages: [&[u8]; 3] = [b"first", b"second", b"third"];
    let hashes = messages.map(HashedMessage::new);
    let preparations: Vec<_> = hashes
        .iter()
        .map(PreparedHashedMessage::from_hashed_message)
        .collect();
    let signatures = messages.map(|message| keypair.sign(message));
    let aggregate_signature = SignatureProjective::aggregate(signatures.iter()).unwrap();

    let malformed = PubkeyCompressed([0u8; 48]);
    let decode_error = malformed
        .try_as_affine()
        .expect_err("all-zero bytes must not decode as a public key");
    let compressed = PubkeyCompressed::from(*keypair.public);
    // The keypair already supplies a PoP-verified key.
    let valid_keys = [unsafe { PopVerified::new_unchecked(compressed) }; 3];
    assert_eq!(
        SignatureProjective::par_verify_distinct_aggregated_prepared(
            &valid_keys,
            &aggregate_signature,
            &preparations,
        ),
        Ok(()),
    );

    for bad_index in 0..valid_keys.len() {
        let mut public_keys = valid_keys;
        // Deliberately bypass PoP validation to exercise malformed-key rejection.
        public_keys[bad_index] = unsafe { PopVerified::new_unchecked(malformed) };
        assert_eq!(
            SignatureProjective::par_verify_distinct_aggregated_prepared(
                &public_keys,
                &aggregate_signature,
                &preparations,
            ),
            Err(decode_error.clone()),
            "prepared screening: malformed key at {bad_index}",
        );
    }

    let identity = PubkeyAffine::from(PubkeyProjective::identity());
    let malformed_signature = SignatureCompressed([0u8; 96]);
    for bad_index in 0..valid_keys.len() {
        let mut public_keys = [keypair.public; 3];
        // An invalid key must be rejected before decoding the aggregate signature.
        public_keys[bad_index] = unsafe { PopVerified::new_unchecked(identity) };
        assert_eq!(
            SignatureProjective::par_verify_distinct_aggregated_prepared(
                &public_keys,
                &malformed_signature,
                &preparations,
            ),
            Err(BlsError::VerificationFailed),
            "prepared screening: identity key at {bad_index} precedes signature decoding",
        );
    }
}
