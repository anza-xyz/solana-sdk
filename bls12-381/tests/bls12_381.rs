use {
    core::mem::MaybeUninit,
    solana_bls12_381::{
        pairing, pairing_assign, pairing_check, pairing_map, Endianness, G1Point, G2Point,
        GtElement, G1_UNCOMPRESSED_POINT_SIZE,
    },
};

#[test]
fn test_zero_copy_and_constructors() {
    let raw_g1 = [0u8; 96];
    let point_ref: &G1Point = bytemuck::cast_ref(&raw_g1);

    // Verify it perfectly matches the owned 'from_bytes' constructor.
    let point_owned = G1Point::from_bytes(raw_g1);
    assert_eq!(point_ref, &point_owned);
    assert_eq!(point_ref.to_bytes(), raw_g1);
}

#[test]
fn test_validated_arithmetic_routing() {
    // Generate valid infinity points for math operations.
    let p1 = G1Point::infinity(Endianness::Little);
    let p2 = G1Point::infinity(Endianness::Little);

    // Test the returning validated wrapper.
    let sum = p1.add(&p2, Endianness::Little);
    assert!(sum.is_some());

    // Test the in-place validated wrapper to save CUs.
    let mut out = MaybeUninit::uninit();
    let success = p1.add_assign(&p2, &mut out, Endianness::Little);
    assert!(success);

    // SAFETY: `add_assign` returned `true`, so every byte of `out` was written.
    let out = unsafe { out.assume_init() };

    // Verify both methods yielded the exact same underlying bytes.
    assert_eq!(sum.unwrap().to_bytes(), out.to_bytes());
}

#[test]
fn test_assign_leaves_out_untouched_on_failure() {
    let sentinel = G1Point::infinity(Endianness::Little);
    let mut out = MaybeUninit::new(sentinel);

    // An all-ones encoding is not a valid field element, so validation must
    // reject it before the operation writes anything.
    let valid = G1Point::infinity(Endianness::Little);
    let invalid = G1Point::from_bytes([0xFF; G1_UNCOMPRESSED_POINT_SIZE]);

    let success = valid.add_assign(&invalid, &mut out, Endianness::Little);
    assert!(!success);

    // SAFETY: `out` was initialized by `MaybeUninit::new`, and `add_assign`
    // returned `false`, which guarantees it was left untouched.
    assert_eq!(unsafe { out.assume_init() }, sentinel);
}

#[test]
fn test_pairing_ergonomics_and_limits() {
    let g1 = G1Point::infinity(Endianness::Little);
    let g2 = G2Point::infinity(Endianness::Little);

    // Test Single Pairing Wrapper (Returning)
    let gt_owned = pairing(&g1, &g2, Endianness::Little);
    assert!(gt_owned.is_some());

    // Test Single Pairing Wrapper (In-Place)
    let mut gt_out = MaybeUninit::uninit();
    let success = pairing_assign(&g1, &g2, &mut gt_out, Endianness::Little);
    assert!(success);

    // SAFETY: `pairing_assign` returned `true`, so `gt_out` is initialized.
    let gt_out = unsafe { gt_out.assume_init() };
    assert_eq!(gt_owned.unwrap().0, gt_out.0);

    // Test Max Pairing Limit (SIMD-0388 restricts batch to 8 pairs)
    let g1_batch_ok = vec![g1; 8];
    let g2_batch_ok = vec![g2; 8];
    assert!(pairing_check(&g1_batch_ok, &g2_batch_ok, Endianness::Little).is_some());

    let g1_batch_fail = vec![g1; 9];
    let g2_batch_fail = vec![g2; 9];
    assert!(pairing_check(&g1_batch_fail, &g2_batch_fail, Endianness::Little).is_none());
}

#[test]
fn test_pairing_check_identity() {
    let g1 = G1Point::infinity(Endianness::Little);
    let g2 = G2Point::infinity(Endianness::Little);

    // Pairing two infinity points should result in the multiplicative identity.
    // pairing_check safely evaluates this without exposing the GtElement.
    let is_identity =
        pairing_check(&[g1], &[g2], Endianness::Little).expect("Pairing execution failed");

    assert!(is_identity);
}

#[test]
fn test_empty_batch() {
    for endianness in [Endianness::Little, Endianness::Big] {
        // `pairing_map` mirrors the syscall: the empty product is the identity.
        let gt = pairing_map(&[], &[], endianness).expect("empty batch must succeed");
        assert_eq!(gt, GtElement::identity(endianness));

        // `pairing_check` refuses to succeed vacuously.
        assert_eq!(pairing_check(&[], &[], endianness), None);
    }
}
