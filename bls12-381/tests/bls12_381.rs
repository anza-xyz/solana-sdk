use solana_bls12_381::{
    pairing, pairing_assign, pairing_check, Endianness, G1Point, G2Point, GtElement,
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

    // Test the returning safe wrapper.
    let sum = p1.add(&p2, Endianness::Little);
    assert!(sum.is_some());

    // Test the in-place safe wrapper to save CUs.
    let mut out = G1Point::infinity(Endianness::Little);
    let success = p1.add_assign(&p2, &mut out, Endianness::Little);
    assert!(success);

    // Verify both methods yielded the exact same underlying bytes.
    assert_eq!(sum.unwrap().to_bytes(), out.to_bytes());
}

#[test]
fn test_pairing_ergonomics_and_limits() {
    let g1 = G1Point::infinity(Endianness::Little);
    let g2 = G2Point::infinity(Endianness::Little);

    // Test Single Pairing Wrapper (Returning)
    let gt_owned = pairing(&g1, &g2, Endianness::Little);
    assert!(gt_owned.is_some());

    // Test Single Pairing Wrapper (In-Place)
    let mut gt_out = GtElement([0u8; 576]);
    let success = pairing_assign(&g1, &g2, &mut gt_out, Endianness::Little);
    assert!(success);
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
