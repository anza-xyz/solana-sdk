use {
    core::mem::MaybeUninit,
    solana_bls12_381::{
        pairing, pairing_assign, pairing_check, pairing_map, Bls12381Error, Endianness,
        G1Compressed, G1Point, G2Compressed, G2Point, GtElement, Scalar,
        G1_UNCOMPRESSED_POINT_SIZE, MAX_PAIRING_LENGTH,
    },
};

/// Builds a value of `T` with every byte set to `byte`.
fn filled<T: bytemuck::Pod>(byte: u8) -> T {
    let mut value = T::zeroed();
    bytemuck::bytes_of_mut(&mut value).fill(byte);
    value
}

/// Asserts that a successful operation writes every byte of its output buffer.
///
/// Runs `op` into two buffers with different prior contents. If any byte were
/// left unwritten, that byte's fill value would carry through and the two
/// results would differ.
///
/// This does not require knowing the expected output, which is what makes it
/// usable as a blanket check across every operation.
fn assert_full_write<T, F>(context: &str, mut op: F)
where
    T: bytemuck::Pod + PartialEq + core::fmt::Debug,
    F: FnMut(&mut MaybeUninit<T>) -> bool,
{
    let mut a = MaybeUninit::new(filled::<T>(0x00));
    let mut b = MaybeUninit::new(filled::<T>(0xFF));

    assert!(op(&mut a), "{context}: operation unexpectedly failed");
    assert!(op(&mut b), "{context}: operation unexpectedly failed");

    // SAFETY: both calls returned `true`, so both buffers are fully
    // initialized. Both were additionally initialized by `MaybeUninit::new`
    // beforehand, so these reads are sound even if the property under test does
    // not hold — a partial write produces a failed assertion rather than
    // undefined behavior.
    let (a, b) = unsafe { (a.assume_init(), b.assume_init()) };

    assert_eq!(
        a, b,
        "{context}: prior buffer contents leaked into the result"
    );
}

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

    // SAFETY: `add_assign` returned `true`, so `out` is fully initialized.
    let out = unsafe { out.assume_init() };

    // Verify both methods yielded the exact same underlying bytes.
    assert_eq!(sum.unwrap().to_bytes(), out.to_bytes());
}

/// The `_assign` contract permits `assume_init` only on a `true` return, which
/// is sound only if the operation wrote every byte of the buffer. Reading even
/// one uninitialized byte is undefined behavior, so this is a soundness
/// property rather than a correctness nicety.
///
/// SIMD-0388 does not state the guarantee, so pin it here rather than assuming
/// it. See the "Output buffer contract" section in the crate documentation.
#[test]
fn test_success_writes_full_buffer() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g1 = G1Point::infinity(endianness);
        let g2 = G2Point::infinity(endianness);
        // Zero is a canonical scalar, so multiplication succeeds.
        let scalar = Scalar([0u8; 32]);

        assert_full_write::<G1Point, _>("g1 add", |out| g1.add_assign(&g1, out, endianness));
        assert_full_write::<G1Point, _>("g1 add_unchecked", |out| {
            g1.add_assign_unchecked(&g1, out, endianness)
        });
        assert_full_write::<G1Point, _>("g1 sub", |out| g1.sub_assign(&g1, out, endianness));
        assert_full_write::<G1Point, _>("g1 mul", |out| g1.mul_assign(&scalar, out, endianness));
        assert_full_write::<G1Point, _>("g1 decompress", |out| {
            G1Compressed::infinity(endianness).decompress_assign(out, endianness)
        });

        assert_full_write::<G2Point, _>("g2 add", |out| g2.add_assign(&g2, out, endianness));
        assert_full_write::<G2Point, _>("g2 add_unchecked", |out| {
            g2.add_assign_unchecked(&g2, out, endianness)
        });
        assert_full_write::<G2Point, _>("g2 sub", |out| g2.sub_assign(&g2, out, endianness));
        assert_full_write::<G2Point, _>("g2 mul", |out| g2.mul_assign(&scalar, out, endianness));
        assert_full_write::<G2Point, _>("g2 decompress", |out| {
            G2Compressed::infinity(endianness).decompress_assign(out, endianness)
        });

        // The 576-byte Gt buffer is the one most likely to be partially written
        // by an implementation that assembles the result coefficient by
        // coefficient.
        assert_full_write::<GtElement, _>("pairing", |out| {
            pairing_assign(&g1, &g2, out, endianness).is_ok()
        });
    }
}

/// On failure the output buffer is poisoned: the contract gives the caller no
/// way to read it, so there is nothing to assert about its contents here.
#[test]
fn test_assign_reports_failure_and_poisons_out() {
    let valid = G1Point::infinity(Endianness::Little);
    // An all-ones encoding is not a valid field element.
    let invalid = G1Point::from_bytes([0xFF; G1_UNCOMPRESSED_POINT_SIZE]);

    let mut out = MaybeUninit::uninit();
    assert!(!valid.add_assign(&invalid, &mut out, Endianness::Little));
    // Deliberately no `assume_init` on `out`.

    // The same contract holds when the failure originates in the syscall
    // rather than in the crate's own `validate` call: `add_assign` rejects
    // `invalid` before the group op runs, `add_assign_unchecked` carries it
    // through to the syscall, and both must report `false`.
    let mut out_unchecked = MaybeUninit::uninit();
    assert!(!valid.add_assign_unchecked(&invalid, &mut out_unchecked, Endianness::Little));

    // The allocating wrapper surfaces the same failure as `None`.
    assert!(valid.add(&invalid, Endianness::Little).is_none());
}

/// Pins current runtime behavior: a failing operation does not write the output
/// buffer.
///
/// This is NOT part of the public contract — the documentation treats `out` as
/// poisoned on failure, and callers must not rely on this. The test exists so
/// that a change in behavior is noticed rather than discovered in production.
#[test]
fn test_failure_leaves_buffer_unwritten() {
    let valid = G1Point::infinity(Endianness::Little);
    let invalid = G1Point::from_bytes([0xFF; G1_UNCOMPRESSED_POINT_SIZE]);

    let fill = G1Point::from_bytes([0xAB; G1_UNCOMPRESSED_POINT_SIZE]);
    let mut out = MaybeUninit::new(fill);

    // Unchecked deliberately: `add_assign` would reject `invalid` in its own
    // `validate` call and return before the group op ever runs, which would pin
    // an early return in this crate rather than what the syscall does to `out`
    // on failure. The unchecked variant skips only the subgroup check — an
    // all-ones encoding is still not a field element, so the syscall itself
    // fails and the buffer is the syscall's to write or leave alone.
    assert!(!valid.add_assign_unchecked(&invalid, &mut out, Endianness::Little));

    // SAFETY: `out` was initialized by `MaybeUninit::new`. This read is sound
    // regardless of what the syscall did; the assertion is about behavior, not
    // safety.
    assert_eq!(unsafe { out.assume_init() }, fill);
}

#[test]
fn test_pairing_ergonomics_and_limits() {
    let g1 = G1Point::infinity(Endianness::Little);
    let g2 = G2Point::infinity(Endianness::Little);

    // Test Single Pairing Wrapper (Returning)
    let gt_owned = pairing(&g1, &g2, Endianness::Little).expect("pairing must succeed");

    // Test Single Pairing Wrapper (In-Place)
    let mut gt_out = MaybeUninit::uninit();
    pairing_assign(&g1, &g2, &mut gt_out, Endianness::Little).expect("pairing must succeed");

    // SAFETY: `pairing_assign` returned `Ok`, so `gt_out` is fully initialized.
    let gt_out = unsafe { gt_out.assume_init() };
    assert_eq!(gt_owned.0, gt_out.0);
}

/// Pins `MAX_PAIRING_LENGTH` against the limit the syscall enforces
/// independently. The constant is duplicated between this crate and
/// `solana-bls12-381-syscall`, where it is private, so drift would otherwise go
/// unnoticed until a batch of the wrong size reached the runtime.
#[test]
fn test_pairing_batch_limit() {
    let g1 = G1Point::infinity(Endianness::Little);
    let g2 = G2Point::infinity(Endianness::Little);

    let g1_ok = vec![g1; MAX_PAIRING_LENGTH];
    let g2_ok = vec![g2; MAX_PAIRING_LENGTH];
    assert!(pairing_check(&g1_ok, &g2_ok, Endianness::Little).is_ok());

    let g1_over = vec![g1; MAX_PAIRING_LENGTH + 1];
    let g2_over = vec![g2; MAX_PAIRING_LENGTH + 1];
    assert_eq!(
        pairing_check(&g1_over, &g2_over, Endianness::Little),
        Err(Bls12381Error::TooManyPairs),
    );

    // A mismatched batch is distinguishable from an over-long one.
    assert_eq!(
        pairing_check(&g1_ok, &g2_ok[..1], Endianness::Little),
        Err(Bls12381Error::LengthMismatch),
    );
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

/// `pairing_map` and `pairing_check` deliberately diverge on an empty batch,
/// and a half-empty batch is a length mismatch rather than either.
#[test]
fn test_empty_batch() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g1 = G1Point::infinity(endianness);
        let g2 = G2Point::infinity(endianness);

        // `pairing_map` mirrors the syscall: the empty product is the identity.
        let gt = pairing_map(&[], &[], endianness).expect("empty batch must succeed");
        assert_eq!(gt, GtElement::identity(endianness));

        // `pairing_check` refuses to succeed vacuously: a zero-length batch
        // asserts nothing, and reporting `Ok(true)` would be a verification
        // bypass for any caller building its batch from instruction data. The
        // dedicated variant distinguishes this programmer error from a failed
        // verification.
        assert_eq!(
            pairing_check(&[], &[], endianness),
            Err(Bls12381Error::EmptyBatch),
        );

        // `EmptyBatch` means empty on both sides. One empty slice is a length
        // mismatch whichever side it is on — the check that makes this true is
        // the length comparison ahead of the empty check in `pairing_check`,
        // without which the second assertion would report `EmptyBatch`.
        assert_eq!(
            pairing_check(&[g1], &[], endianness),
            Err(Bls12381Error::LengthMismatch),
        );
        assert_eq!(
            pairing_check(&[], &[g2], endianness),
            Err(Bls12381Error::LengthMismatch),
        );
    }
}

/// Reverses each 48-byte `Fq` coefficient, converting between the LE and BE
/// encodings of a G1 point.
fn swap_fq(bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(48) {
        chunk.reverse();
    }
}

/// Swaps the `c0` and `c1` halves of each 96-byte `Fq2` coordinate.
fn swap_c0_c1(bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(96) {
        let (c0, c1) = chunk.split_at_mut(48);
        c0.swap_with_slice(c1);
    }
}

/// Pins the G1 generator constants.
///
/// Fails on the all-zero placeholders shipped in `src/g1.rs`; run
/// `cargo run --example gen_constants` and paste the output there.
///
/// Between them these assertions make a transcription error essentially
/// impossible to miss: a corrupted byte puts the point off the curve, and a
/// corrupted byte in only one of the two encodings breaks parity.
#[test]
fn test_g1_generator_is_canonical() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g = G1Point::generator(endianness);

        assert!(
            g.validate(endianness),
            "G1 generator is not a valid point — did you paste the output of \
             `cargo run --example gen_constants` into src/g1.rs?"
        );
        assert!(
            !g.is_infinity(endianness),
            "G1 generator must not be infinity"
        );

        // g * 1 == g
        assert_eq!(
            g.mul(&Scalar::one(endianness), endianness),
            Some(g),
            "G1 generator failed identity multiplication"
        );

        // g * 0 == infinity
        assert_eq!(
            g.mul(&Scalar::zero(), endianness),
            Some(G1Point::infinity(endianness)),
            "G1 generator times zero must be infinity"
        );

        // g + (-g) == infinity
        let neg = g.neg(endianness).expect("negation must succeed");
        assert_eq!(
            g.add(&neg, endianness),
            Some(G1Point::infinity(endianness)),
            "G1 generator plus its negation must be infinity"
        );
    }

    // The two encodings must describe the same point.
    let mut converted = G1Point::generator(Endianness::Big).to_bytes();
    swap_fq(&mut converted);
    assert_eq!(
        converted,
        G1Point::generator(Endianness::Little).to_bytes(),
        "G1 generator LE and BE constants disagree"
    );
}

/// Pins the G2 generator constants. See `test_g1_generator_is_canonical`.
#[test]
fn test_g2_generator_is_canonical() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g = G2Point::generator(endianness);

        assert!(
            g.validate(endianness),
            "G2 generator is not a valid point — did you paste the output of \
             `cargo run --example gen_constants` into src/g2.rs?"
        );
        assert!(
            !g.is_infinity(endianness),
            "G2 generator must not be infinity"
        );

        assert_eq!(
            g.mul(&Scalar::one(endianness), endianness),
            Some(g),
            "G2 generator failed identity multiplication"
        );
        assert_eq!(
            g.mul(&Scalar::zero(), endianness),
            Some(G2Point::infinity(endianness)),
            "G2 generator times zero must be infinity"
        );

        let neg = g.neg(endianness).expect("negation must succeed");
        assert_eq!(
            g.add(&neg, endianness),
            Some(G2Point::infinity(endianness)),
            "G2 generator plus its negation must be infinity"
        );
    }

    let mut converted = G2Point::generator(Endianness::Big).to_bytes();
    swap_c0_c1(&mut converted);
    swap_fq(&mut converted);
    assert_eq!(
        converted,
        G2Point::generator(Endianness::Little).to_bytes(),
        "G2 generator LE and BE constants disagree"
    );
}

/// `e(G1, G2)` generates the target group, so it is not the identity. A
/// `Ok(true)` here would mean the generators or the pairing are wrong.
#[test]
fn test_generator_pairing_is_not_identity() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g1 = G1Point::generator(endianness);
        let g2 = G2Point::generator(endianness);

        assert_eq!(
            pairing_check(&[g1], &[g2], endianness),
            Ok(false),
            "e(G1, G2) must not be the target group identity"
        );
    }
}

/// Bilinearity, expressed without target group arithmetic:
/// `e(aP, bQ) * e(-(ab)P, Q) == 1`.
#[test]
fn test_pairing_bilinearity() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g1 = G1Point::generator(endianness);
        let g2 = G2Point::generator(endianness);

        let (a, b) = (7u64, 11u64);
        let scalar_a = Scalar::from_u64(a, endianness);
        let scalar_b = Scalar::from_u64(b, endianness);
        let scalar_ab = Scalar::from_u64(a * b, endianness);

        let ap = g1.mul(&scalar_a, endianness).expect("aP");
        let bq = g2.mul(&scalar_b, endianness).expect("bQ");
        let abp = g1.mul(&scalar_ab, endianness).expect("abP");
        let neg_abp = abp.neg(endianness).expect("-abP");

        assert_eq!(
            pairing_check(&[ap, neg_abp], &[bq, g2], endianness),
            Ok(true),
            "bilinearity check failed"
        );
    }
}

#[test]
fn test_is_infinity_and_is_identity() {
    for endianness in [Endianness::Little, Endianness::Big] {
        assert!(G1Point::infinity(endianness).is_infinity(endianness));
        assert!(G2Point::infinity(endianness).is_infinity(endianness));
        assert!(!G1Point::generator(endianness).is_infinity(endianness));
        assert!(!G2Point::generator(endianness).is_infinity(endianness));

        // The all-zero encoding is NOT infinity: `bytemuck::Zeroable` produces
        // an invalid point, not the identity.
        assert!(!G1Point::from_bytes([0u8; G1_UNCOMPRESSED_POINT_SIZE]).is_infinity(endianness));

        assert!(GtElement::identity(endianness).is_identity(endianness));
        assert!(!GtElement::from_bytes([0u8; 576]).is_identity(endianness));

        // The compressed infinity constructors must round-trip through
        // decompression, which pins their control-bit encoding.
        assert_eq!(
            G1Compressed::infinity(endianness).decompress(endianness),
            Some(G1Point::infinity(endianness)),
        );
        assert_eq!(
            G2Compressed::infinity(endianness).decompress(endianness),
            Some(G2Point::infinity(endianness)),
        );
        assert!(G1Compressed::infinity(endianness).validate(endianness));
        assert!(G2Compressed::infinity(endianness).validate(endianness));
    }
}

#[test]
fn test_scalar_constructors() {
    for endianness in [Endianness::Little, Endianness::Big] {
        assert!(Scalar::zero().is_zero());
        assert!(!Scalar::one(endianness).is_zero());
        assert_eq!(Scalar::one(endianness), Scalar::from_u64(1, endianness));

        // `from_u64` places the value at the correct end for each encoding.
        let s = Scalar::from_u64(0x0102_0304_0506_0708, endianness);
        match endianness {
            Endianness::Little => assert_eq!(s.as_bytes()[0], 0x08),
            Endianness::Big => assert_eq!(s.as_bytes()[31], 0x08),
        }

        // Borrowing accessors agree with the copying ones.
        let g = G1Point::generator(endianness);
        assert_eq!(g.as_bytes(), &g.to_bytes());
        assert_eq!(G1Point::from_bytes_ref(g.as_bytes()), &g);
    }
}
