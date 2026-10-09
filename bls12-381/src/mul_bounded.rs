use {
    crate::{Endianness, G1Point, G2Point, Scalar},
    core::mem::MaybeUninit,
};

/// Returns the scalar value if its encoding fits in 32 bits.
#[inline]
fn value_u32(scalar: &Scalar, endianness: Endianness) -> Option<u32> {
    let b = scalar.as_bytes();
    match endianness {
        Endianness::Little if b[4..] == [0; 28] => {
            Some(u32::from_le_bytes(b[..4].try_into().unwrap()))
        }
        Endianness::Big if b[..28] == [0; 28] => {
            Some(u32::from_be_bytes(b[28..].try_into().unwrap()))
        }
        _ => None,
    }
}

/// Returns a mask of the bits below the leading one of `value`, one bit per
/// doubling, if the binary addition chain fits within `limit` group operations.
#[inline]
fn chain_mask(value: u32, limit: u32) -> Option<u32> {
    if value < 2 {
        return Some(0);
    }
    // SBF has no instructions for `ilog2` or `count_ones`. Every bit below the
    // leading one costs a doubling, so once the leading bit reaches `limit`,
    // only `2^limit` itself fits and nothing needs to be counted.
    if value >> limit != 0 {
        return (value == 1 << limit).then_some(value.wrapping_sub(1));
    }
    let mut below = value >> 1;
    below |= below >> 1;
    below |= below >> 2;
    below |= below >> 4;
    below |= below >> 8;
    below |= below >> 16;
    // Each bit of `below` is a doubling and each bit of `value` after the
    // leading one is an addition, so a single 64-bit count covers the chain.
    // `value >= 2`, so the count is at least two.
    let operations = ((u64::from(below) << 32) | u64::from(value))
        .count_ones()
        .wrapping_sub(1);
    (operations <= limit).then_some(below)
}

macro_rules! impl_mul_bounded {
    ($point:ty, $limit:expr) => {
        impl $point {
            /// Multiplies using a short binary addition chain when selected,
            /// otherwise using native multiplication.
            ///
            /// Only scalars fitting in 32 bits are considered for a chain.
            /// Both inputs use `endianness`. The point is validated even
            /// for scalars zero and one; the fallback relies on the native
            /// syscall's validation without a separate validation call.
            ///
            /// Control flow depends on the scalar, so use this with public
            /// scalars. Classification adds overhead when falling back; callers
            /// expecting general scalars can use [`Self::mul`] directly.
            /// The crossover depends on the compiler and runtime cost schedule.
            #[doc = concat!("The chain budget is ", stringify!($limit), " group additions, including doublings.")]
            #[inline]
            pub fn mul_bounded(&self, scalar: &Scalar, endianness: Endianness) -> Option<Self> {
                match Self::mul_bounded_value(scalar, endianness) {
                    Some((value, mask)) => self.mul_bounded_u32(value, mask, endianness),
                    None => self.mul(scalar, endianness),
                }
            }

            #[inline]
            fn mul_bounded_value(scalar: &Scalar, endianness: Endianness) -> Option<(u32, u32)> {
                let value = value_u32(scalar, endianness)?;
                chain_mask(value, $limit).map(|mask| (value, mask))
            }

            #[inline]
            fn mul_bounded_u32(
                &self,
                value: u32,
                mask: u32,
                endianness: Endianness,
            ) -> Option<Self> {
                if !self.validate(endianness) {
                    return None;
                }
                if value == 0 {
                    return Some(Self::infinity(endianness));
                }
                if value == 1 {
                    return Some(*self);
                }
                let mut a = MaybeUninit::<Self>::uninit();
                let mut b = MaybeUninit::<Self>::uninit();
                // Borrow the input for the first doubling instead of copying it.
                if !self.add_assign_unchecked(self, &mut a, endianness) {
                    return None;
                }
                let (mut current, mut scratch) = (&mut a, &mut b);
                // The first doubling is done, so continue from the highest bit
                // of `mask`, which is the bit below the leading one of `value`.
                let mut bit = mask ^ (mask >> 1);
                if value & bit != 0 {
                    // SAFETY: `add_assign_unchecked` returned `true`, so
                    // `current` is fully initialized.
                    if !unsafe { current.assume_init_ref() }
                        .add_assign_unchecked(self, scratch, endianness)
                    {
                        return None;
                    }
                    core::mem::swap(&mut current, &mut scratch);
                }
                bit >>= 1;
                while bit != 0 {
                    // SAFETY: `add_assign_unchecked` returned `true`, so
                    // `current` is fully initialized.
                    let acc = unsafe { current.assume_init_ref() };
                    if !acc.add_assign_unchecked(acc, scratch, endianness) {
                        return None;
                    }
                    core::mem::swap(&mut current, &mut scratch);
                    if value & bit != 0 {
                        // SAFETY: `add_assign_unchecked` returned `true`, so
                        // `current` is fully initialized after the swap.
                        if !unsafe { current.assume_init_ref() }
                            .add_assign_unchecked(self, scratch, endianness)
                        {
                            return None;
                        }
                        core::mem::swap(&mut current, &mut scratch);
                    }
                    bit >>= 1;
                }
                // SAFETY: `add_assign_unchecked` returned `true` before
                // each swap, so `current` is fully initialized.
                Some(unsafe { *current.assume_init_ref() })
            }
        }
    };
}

impl_mul_bounded!(G1Point, 19);
impl_mul_bounded!(G2Point, 27);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_doublings_within_budget() {
        for (value, limit, expected) in [
            (0, 18, Some(0)),
            (1, 18, Some(0)),
            (2, 18, Some(1)),
            (7, 18, Some(2)),
            (1 << 17, 18, Some(17)),
            (1 << 18, 18, Some(18)),
            ((1 << 18) + 1, 18, None),
            (1 << 19, 18, None),
            (1023, 18, Some(9)),
            (1535, 18, None),
            (1 << 26, 26, Some(26)),
            (1 << 27, 26, None),
            (16383, 26, Some(13)),
            (24575, 26, None),
            (u32::MAX, 26, None),
            (1 << 31, 31, Some(31)),
            (u32::MAX, 31, None),
        ] {
            let doublings = chain_mask(value, limit).map(u32::count_ones);
            assert_eq!(doublings, expected, "{value}, {limit}");
        }
    }

    #[test]
    fn chain_selection() {
        for e in [Endianness::Little, Endianness::Big] {
            for (value, g1, g2) in [
                (0, true, true),
                (1, true, true),
                (7, true, true),
                (1 << 19, true, true),
                (1 << 20, false, true),
                (1535, true, true),
                (2047, false, true),
                (1 << 27, false, true),
                (1 << 28, false, false),
                (24575, false, true),
                (32767, false, false),
                (u32::MAX, false, false),
            ] {
                let scalar = Scalar::from_u64(u64::from(value), e);
                let g1_value = G1Point::mul_bounded_value(&scalar, e).map(|(value, _)| value);
                let g2_value = G2Point::mul_bounded_value(&scalar, e).map(|(value, _)| value);
                assert_eq!(g1_value, g1.then_some(value));
                assert_eq!(g2_value, g2.then_some(value));
            }
            for scalar in [Scalar::from_u64(1 << 32, e), Scalar([255; 32])] {
                assert_eq!(G1Point::mul_bounded_value(&scalar, e), None);
                assert_eq!(G2Point::mul_bounded_value(&scalar, e), None);
            }
        }
    }
}
