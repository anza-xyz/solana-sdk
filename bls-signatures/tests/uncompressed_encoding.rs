#![cfg(not(target_os = "solana"))]

use solana_bls_signatures::{
    proof_of_possession::ProofOfPossessionProjective,
    pubkey::{PubkeyAffine, PubkeyAffineUnchecked, PubkeyProjective},
    signature::{SignatureAffine, SignatureAffineUnchecked, SignatureProjective},
    BlsError, Keypair, ProofOfPossession, Pubkey, PubkeyCompressed, Signature, SignatureCompressed,
    BLS_PUBLIC_KEY_AFFINE_SIZE, BLS_SIGNATURE_AFFINE_SIZE,
};

#[test]
fn canonical_uncompressed_points_roundtrip() {
    let keypair = Keypair::derive(&[42; 32]).unwrap();

    // Include identity signatures to check that the infinity flag remains allowed.
    for point in [
        keypair.sign(b"uncompressed encoding"),
        SignatureProjective::identity(),
    ] {
        let bytes = Signature::from(point);
        assert_eq!(SignatureProjective::try_from(bytes).unwrap(), point);
        assert_eq!(
            SignatureAffineUnchecked::try_from(bytes)
                .unwrap()
                .verify_subgroup()
                .unwrap(),
            SignatureAffine::from(point),
        );
    }

    let pubkey = Pubkey::from(*keypair.public);
    assert_eq!(PubkeyAffine::try_from(pubkey).unwrap(), *keypair.public);
    assert_eq!(
        PubkeyAffineUnchecked::try_from(pubkey)
            .unwrap()
            .verify_subgroup()
            .unwrap(),
        *keypair.public,
    );

    let proof = keypair.proof_of_possession(None);
    let bytes = ProofOfPossession::from(proof);
    assert_eq!(ProofOfPossessionProjective::try_from(bytes).unwrap(), proof);
}

#[test]
fn padded_compressed_points_are_rejected() {
    let keypair = Keypair::derive(&[42; 32]).unwrap();

    let point = keypair.sign(b"uncompressed encoding");
    let compressed = SignatureCompressed::from(point);
    assert_eq!(SignatureProjective::try_from(compressed).unwrap(), point);
    let mut padded = Signature([0; BLS_SIGNATURE_AFFINE_SIZE]);
    padded.0[..compressed.0.len()].copy_from_slice(&compressed.0);
    assert_eq!(
        SignatureAffine::try_from(padded),
        Err(BlsError::PointConversion),
    );
    assert_eq!(
        SignatureAffineUnchecked::try_from(padded),
        Err(BlsError::PointConversion),
    );

    let compressed = PubkeyCompressed::from(*keypair.public);
    assert_eq!(PubkeyAffine::try_from(compressed).unwrap(), *keypair.public);
    let mut padded = Pubkey([0; BLS_PUBLIC_KEY_AFFINE_SIZE]);
    padded.0[..compressed.0.len()].copy_from_slice(&compressed.0);
    assert_eq!(
        PubkeyAffine::try_from(padded),
        Err(BlsError::PointConversion),
    );
    assert_eq!(
        PubkeyAffineUnchecked::try_from(padded),
        Err(BlsError::PointConversion),
    );
}

#[test]
fn identity_public_keys_are_rejected() {
    let identity = PubkeyProjective::identity();
    let uncompressed = Pubkey::from(identity);
    let compressed = PubkeyCompressed::from(identity);

    assert_eq!(
        PubkeyAffine::try_from(uncompressed),
        Err(BlsError::PointConversion),
    );
    assert_eq!(
        PubkeyAffineUnchecked::try_from(uncompressed),
        Err(BlsError::PointConversion),
    );
    assert_eq!(
        PubkeyAffine::try_from(compressed),
        Err(BlsError::PointConversion),
    );
    assert_eq!(
        PubkeyAffineUnchecked::try_from(compressed),
        Err(BlsError::PointConversion),
    );

    // An aggregation identity can still enter through the infallible point conversions.
    assert_eq!(
        PubkeyAffineUnchecked::from(identity).verify_subgroup(),
        Err(BlsError::VerificationFailed),
    );
    assert_eq!(
        PubkeyAffineUnchecked::from(PubkeyAffine::from(identity)).verify_subgroup(),
        Err(BlsError::VerificationFailed),
    );
}

#[cfg(feature = "wincode")]
#[test]
fn wincode_preserves_raw_signature_bytes() {
    // Raw byte wrappers remain serializable; validation belongs to point conversion.
    let signature = Signature([0xFF; BLS_SIGNATURE_AFFINE_SIZE]);
    let bytes = wincode::serialize(&signature).unwrap();
    assert_eq!(bytes, signature.0);
    assert_eq!(
        wincode::deserialize::<Signature>(&bytes).unwrap(),
        signature
    );
    assert_eq!(
        SignatureAffine::try_from(signature),
        Err(BlsError::PointConversion),
    );
}
