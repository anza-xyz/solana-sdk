//! G2 pairing preparation owned by this crate.

use {
    alloc::vec::Vec,
    blst::{blst_fp12, blst_fp6, blst_miller_loop_lines, blst_precompute_lines},
    blstrs::{G1Affine, G2Affine},
    group::prime::PrimeCurveAffine,
};

// The buffer length required by blst_precompute_lines and blst_miller_loop_lines.
const MILLER_LOOP_LINES: usize = 68;

#[derive(Clone, Debug)]
pub(crate) struct PreparedG2 {
    // Empty for the identity; otherwise exactly 68 initialized coefficients.
    lines: Vec<blst_fp6>,
}

impl From<G2Affine> for PreparedG2 {
    fn from(affine: G2Affine) -> Self {
        if bool::from(affine.is_identity()) {
            return Self { lines: Vec::new() };
        }

        let mut lines = Vec::<blst_fp6>::with_capacity(MILLER_LOOP_LINES);
        // SAFETY: The allocation has space for all 68 coefficients.
        // blst_precompute_lines initializes every coefficient without reading
        // the previous contents. Both buffers remain valid for the call,
        // and blst retains neither pointer. Set the length only after
        // the entire table has been initialized.
        unsafe {
            blst_precompute_lines(lines.as_mut_ptr(), affine.as_ref());
            lines.set_len(MILLER_LOOP_LINES);
        }
        Self { lines }
    }
}

impl PreparedG2 {
    pub(crate) fn miller_loop(&self, point: &G1Affine) -> blst_fp12 {
        let mut result = blst_fp12::default();
        if self.lines.is_empty() || bool::from(point.is_identity()) {
            return result;
        }

        // SAFETY: Nonempty storage contains all 68 initialized coefficients
        // from blst_precompute_lines. The inputs remain valid and immutable,
        // and result is a separate writable blst_fp12.
        unsafe {
            blst_miller_loop_lines(&mut result, self.lines.as_ptr(), point.as_ref());
        }
        result
    }
}

#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn multi_miller_loop<'a, 'b>(
    terms: impl IntoIterator<Item = (&'a G1Affine, &'b PreparedG2)>,
) -> blst_fp12 {
    let mut result = blst_fp12::default();
    for (index, (point, prepared)) in terms.into_iter().enumerate() {
        let term = prepared.miller_loop(point);
        if index == 0 {
            result = term;
        } else {
            result *= term;
        }
    }
    result
}
