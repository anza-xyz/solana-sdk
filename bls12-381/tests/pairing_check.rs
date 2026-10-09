pub mod common;

use solana_bls12_381::{
    pairing, pairing_check, Bls12381Error, Endianness, G1Point, G2Point, Scalar,
};

#[test]
fn single_pair_matches_full_pairing() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let g1 = G1Point::generator(endianness);
        let g2 = G2Point::generator(endianness);
        let scalar = Scalar::from_u64(7, endianness);
        let g1_points = [
            g1,
            g1.mul(&scalar, endianness).unwrap(),
            g1.neg(endianness).unwrap(),
            G1Point::infinity(endianness),
        ];
        let g2_points = [
            g2,
            g2.mul(&scalar, endianness).unwrap(),
            g2.neg(endianness).unwrap(),
            G2Point::infinity(endianness),
        ];
        for p in g1_points {
            for q in g2_points {
                let expected = pairing(&p, &q, endianness).map(|gt| gt.is_identity(endianness));
                assert_eq!(pairing_check(&[p], &[q], endianness), expected);
            }
        }
    }
}

fn assert_invalid_pair(p: G1Point, q: G2Point, endianness: Endianness) {
    assert_eq!(
        pairing(&p, &q, endianness),
        Err(Bls12381Error::InvalidInput),
        "the full pairing must reject the fixture"
    );
    assert_eq!(
        pairing_check(&[p], &[q], endianness),
        Err(Bls12381Error::InvalidInput)
    );
}

#[test]
fn single_pair_rejects_invalid_points_even_with_infinity() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let inf1 = G1Point::infinity(endianness);
        let inf2 = G2Point::infinity(endianness);
        // Retain the infinity flag, but make the coordinates nonzero.
        let mut malformed_inf1 = inf1;
        malformed_inf1.0[95] = 1;
        let mut malformed_inf2 = inf2;
        malformed_inf2.0[191] = 1;
        let invalid_g1 = [G1Point([0; 96]), G1Point([0xff; 96]), malformed_inf1];
        let invalid_g2 = [G2Point([0; 192]), G2Point([0xff; 192]), malformed_inf2];
        for p in invalid_g1 {
            for q in [G2Point::generator(endianness), inf2] {
                assert_invalid_pair(p, q, endianness);
            }
        }
        for q in invalid_g2 {
            for p in [G1Point::generator(endianness), inf1] {
                assert_invalid_pair(p, q, endianness);
            }
        }
        assert_invalid_pair(invalid_g1[0], invalid_g2[0], endianness);
    }
}

#[test]
fn single_pair_rejects_points_outside_prime_order_subgroups() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let p = common::g1_torsion(endianness);
        let q = common::g2_torsion(endianness);
        let inf1 = G1Point::infinity(endianness);
        let inf2 = G2Point::infinity(endianness);
        assert_eq!(p.add_unchecked(&inf1, endianness), Some(p));
        assert_eq!(q.add_unchecked(&inf2, endianness), Some(q));
        assert!(!p.validate(endianness));
        assert!(!q.validate(endianness));
        assert_invalid_pair(p, G2Point::generator(endianness), endianness);
        assert_invalid_pair(G1Point::generator(endianness), q, endianness);
        assert_invalid_pair(p, inf2, endianness);
        assert_invalid_pair(inf1, q, endianness);
        assert_invalid_pair(p, q, endianness);
    }
}
