//! Thin, allocation-free wrappers over the `blst` pairing primitives.
//!
//! `blstrs` only exposes pairings through `MultiMillerLoop`, which requires a
//! `G2Prepared` (a heap-allocated 19 KiB line table) for every G2 input, and
//! keeps the raw `blst_fp12` inside `MillerLoopResult` private. A G2 input that
//! is used exactly once (a signature, a proof, a message that was not
//! pre-prepared) gains nothing from line precomputation, so this module calls
//! `blst` directly on affine points instead.
//!
//! The only crossing from `blstrs` types into `blst` types is through the
//! public `AsRef<blst_p1_affine>` / `AsRef<blst_p2_affine>` impls on
//! `G1Affine` / `G2Affine`; callers do that at the call site. No layout
//! assumptions are made about any `blstrs` type.
//!
//! `blst` never heap-allocates (it uses stack scratch space only), so every
//! function here is allocation-free.

use blst::{
    blst_fp12, blst_fp12_finalverify, blst_miller_loop, blst_p1_affine, blst_p1_affine_generator,
    blst_p2_affine,
};

/// Computes the Miller loop `ML(g1, g2)`.
///
/// If either point is the identity the result is the multiplicative identity
/// of `Fp12`, matching the convention of `blstrs::Bls12::multi_miller_loop`
/// and `blstrs::pairing` (pairing with zero is one).
pub(crate) fn miller_loop(g1: &blst_p1_affine, g2: &blst_p2_affine) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: `out` is a valid, writable `blst_fp12`, and `g1`/`g2` are valid
    // affine points for the duration of the call. `blst_miller_loop` is
    // `miller_loop_n(ret, Q, P, 1)`: it reads `Q` and `P`, fully writes `ret`
    // (including the infinity special case, which writes the identity), and
    // retains none of the pointers. Its argument order is `(ret, Q: G2, P: G1)`,
    // hence `g2` before `g1` below; the distinct pointer types make a mix-up a
    // compile error.
    unsafe { blst_miller_loop(&mut out, g2, g1) };
    out
}

/// Returns whether `a` and `b` are equal after final exponentiation, i.e.
/// whether `final_exp(a) == final_exp(b)`.
///
/// Costs one final exponentiation: `blst` computes `final_exp(conj(a) * b)`
/// and compares it with one.
pub(crate) fn final_verify(a: &blst_fp12, b: &blst_fp12) -> bool {
    // SAFETY: both pointers come from live shared references; `blst` only reads
    // through them and retains neither.
    unsafe { blst_fp12_finalverify(a, b) }
}

/// The G1 generator as a raw affine point.
pub(crate) fn g1_generator() -> &'static blst_p1_affine {
    // SAFETY: `blst_p1_affine_generator` returns a pointer to `BLS12_381_G1`, a
    // `const` static inside `blst`. It is never null, is never mutated, and
    // lives for the whole program, so a `'static` shared reference to it is
    // valid.
    unsafe { &*blst_p1_affine_generator() }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar},
        ff::Field,
        group::{prime::PrimeCurveAffine, Group},
        rand::rngs::OsRng,
    };

    fn random_pair() -> (G1Affine, G2Affine) {
        (
            G1Projective::random(&mut OsRng).into(),
            G2Projective::random(&mut OsRng).into(),
        )
    }

    #[test]
    fn g1_generator_matches_blstrs() {
        assert_eq!(G1Affine::generator().as_ref(), g1_generator());
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn miller_loop_is_bilinear_under_final_verify() {
        let (p, q) = random_pair();
        let a = Scalar::random(&mut OsRng);
        let ap: G1Affine = (p * a).into();
        let aq: G2Affine = (q * a).into();

        // e([a]P, Q) == e(P, [a]Q), and neither equals e(P, Q).
        let lhs = miller_loop(ap.as_ref(), q.as_ref());
        let rhs = miller_loop(p.as_ref(), aq.as_ref());
        let base = miller_loop(p.as_ref(), q.as_ref());
        assert!(final_verify(&lhs, &rhs));
        assert!(!final_verify(&lhs, &base));
        assert!(!final_verify(&rhs, &base));
    }

    #[test]
    fn identity_input_yields_one() {
        let (p, q) = random_pair();
        // `blst`'s `Default` for `blst_fp12` is the multiplicative identity.
        let one = blst_fp12::default();
        assert_eq!(miller_loop(p.as_ref(), G2Affine::identity().as_ref()), one);
        assert_eq!(miller_loop(G1Affine::identity().as_ref(), q.as_ref()), one);
        assert_ne!(miller_loop(p.as_ref(), q.as_ref()), one);
    }
}
