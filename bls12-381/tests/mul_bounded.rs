pub mod common;

use solana_bls12_381::{Endianness, G1Point, G2Point, Scalar};

macro_rules! group_tests {
    ($test:ident, $point:ident, $size:expr, $torsion:ident) => {
        #[test]
        fn $test() {
            for e in [Endianness::Little, Endianness::Big] {
                let p = $point::generator(e);
                // Dense and sparse scalars exercise both sides of each group's
                // chain budget, as well as the 32-bit classification boundary.
                let mut values: Vec<u32> = (0..=256).collect();
                for bit in 1..32 {
                    values.extend([1 << bit, (1 << bit) - 1, (1 << bit) + 1]);
                }
                values.extend([u32::MAX, 0x55555555, 0xaaaaaaaa]);
                for value in values {
                    let scalar = Scalar::from_u64(u64::from(value), e);
                    assert_eq!(p.mul_bounded(&scalar, e), p.mul(&scalar, e), "{value}");
                }
                for value in [0, 1, 2, 7, 1023, 16383, 65535, 1 << 32, 1 << 63, u64::MAX] {
                    let scalar = Scalar::from_u64(value, e);
                    for point in [p.neg(e).unwrap(), $point::infinity(e)] {
                        assert_eq!(point.mul_bounded(&scalar, e), point.mul(&scalar, e));
                    }
                }

                let mut malformed = $point::infinity(e);
                malformed.0[$size - 1] |= 1;
                for bad in [
                    $point([0; $size]),
                    $point([255; $size]),
                    malformed,
                    common::$torsion(e),
                ] {
                    for value in [0, 1, 2, 7, 65535, 1 << 32] {
                        assert!(bad.mul_bounded(&Scalar::from_u64(value, e), e).is_none());
                    }
                }

                let mut order = common::scalar_field_order();
                let mut order_minus_one = order;
                order_minus_one[31] = 0;
                if e == Endianness::Little {
                    order.reverse();
                    order_minus_one.reverse();
                }
                assert_eq!(p.mul_bounded(&Scalar(order_minus_one), e), p.neg(e));
                for scalar in [Scalar(order), Scalar([255; 32])] {
                    for point in [p, $point::infinity(e)] {
                        assert!(point.mul_bounded(&scalar, e).is_none());
                    }
                }
            }
        }
    };
}

group_tests!(g1_bounded_mul, G1Point, 96, g1_torsion);
group_tests!(g2_bounded_mul, G2Point, 192, g2_torsion);
