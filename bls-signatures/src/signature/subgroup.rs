//! Batched subgroup verification for G2 points.
//!
//! Algorithm for a batch of `k` unchecked G2 elements `g_1, ..., g_k`:
//!
//! 1. Precompute, once per input point, the table
//!    `[0]g_i, [1]g_i, [2]g_i, ..., [12]g_i`.
//! 2. Repeat the following `t = 35` times, since `13^35 > 2^128`:
//!    sample independent random coefficients `c_1, ..., c_k` uniformly from
//!    `{0, 1, ..., 12}` and form
//!    `h = [c_1]g_1 + [c_2]g_2 + ... + [c_k]g_k`
//!    by table lookup plus point addition.
//! 3. Check whether each sampled `h` is in the G2 prime-order subgroup.
//!    If any round fails, reject the whole batch.
//! 4. If all rounds pass, accept every input point as subgroup-validated.
//!
//! This is a probabilistic batch check with soundness error below `2^-128`.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        signature::points::{SignatureAffine, SignatureAffineUnchecked},
    },
    alloc::vec::Vec,
    blst::{blst_p2, blst_p2_affine, blst_p2_in_g2, blst_p2s_to_affine},
    blstrs::{G2Affine, G2Projective},
    core::ptr,
    group::{prime::PrimeCurveAffine, Group},
    rand::{rngs::OsRng, Rng},
};

#[cfg(not(target_os = "solana"))]
const BATCH_SUBGROUP_CHECK_MODULUS: u8 = 13;
#[cfg(not(target_os = "solana"))]
const BATCH_SUBGROUP_CHECK_ROUNDS: usize = 35;
#[cfg(not(target_os = "solana"))]
const PRECOMPUTED_MULTIPLES: usize = BATCH_SUBGROUP_CHECK_MODULUS as usize;

#[cfg(not(target_os = "solana"))]
type G2LookupTable = [G2Projective; PRECOMPUTED_MULTIPLES];

#[cfg(not(target_os = "solana"))]
fn build_lookup_table(point: &SignatureAffineUnchecked) -> G2LookupTable {
    let mut table = [G2Projective::identity(); PRECOMPUTED_MULTIPLES];
    let mut multiple = G2Projective::identity();

    for entry in table.iter_mut().skip(1) {
        multiple += &point.0;
        *entry = multiple;
    }

    table
}

#[cfg(not(target_os = "solana"))]
fn sample_coefficients<R: Rng + ?Sized>(num_points: usize, rng: &mut R) -> Vec<u8> {
    let mut coefficients = Vec::with_capacity(BATCH_SUBGROUP_CHECK_ROUNDS * num_points);

    for _ in 0..BATCH_SUBGROUP_CHECK_ROUNDS * num_points {
        coefficients.push(rng.gen_range(0..BATCH_SUBGROUP_CHECK_MODULUS));
    }

    coefficients
}

#[cfg(not(target_os = "solana"))]
fn build_selected_affine_table(tables: &[G2LookupTable], coefficients: &[u8]) -> Vec<G2Affine> {
    let mut selected_projective = Vec::with_capacity(coefficients.len());

    for round_coefficients in coefficients.chunks_exact(tables.len()) {
        for (table, &coefficient) in tables.iter().zip(round_coefficients) {
            selected_projective.push(table[coefficient as usize]);
        }
    }

    // `blstrs` does not override `group::Curve::batch_normalize`, so that API
    // would just loop over `to_affine()`. Call `blst` directly to get the real
    // batch inversion-based projective-to-affine conversion.
    let mut selected_affine: Vec<G2Affine> = Vec::with_capacity(selected_projective.len());
    unsafe { selected_affine.set_len(selected_projective.len()) };

    let mut point_ptrs = Vec::with_capacity(selected_projective.len() + 1);
    for point in &selected_projective {
        point_ptrs.push(point.as_ref() as *const blst_p2);
    }
    point_ptrs.push(ptr::null());

    unsafe {
        blst_p2s_to_affine(
            selected_affine.as_mut_ptr().cast::<blst_p2_affine>(),
            point_ptrs.as_ptr(),
            selected_projective.len(),
        );
    }

    selected_affine
}

#[cfg(not(target_os = "solana"))]
fn check_selected_affine_table(
    selected_points: &[G2Affine],
    points_per_round: usize,
) -> Result<(), BlsError> {
    for round_points in selected_points.chunks_exact(points_per_round) {
        let mut combination = G2Projective::identity();

        for point in round_points {
            if !bool::from(point.is_identity()) {
                combination = combination.add_mixed(point);
            }
        }

        check_combination_in_subgroup(&combination)?;
    }

    Ok(())
}

#[cfg(not(target_os = "solana"))]
fn check_combination_in_subgroup(combination: &G2Projective) -> Result<(), BlsError> {
    if unsafe { blst_p2_in_g2(combination.as_ref()) } {
        Ok(())
    } else {
        Err(BlsError::VerificationFailed)
    }
}

/// Probabilistically verifies that every unchecked G2 point lies in the prime-order subgroup.
///
/// The algorithm precomputes `[0]P, [1]P, ..., [12]P` for each input point once, then runs
/// 35 rounds where every point receives an independent random coefficient in `F_13`. This yields
/// a soundness error below `2^-128` because `13^35 > 2^128`.
#[cfg(not(target_os = "solana"))]
pub fn verify_signature_subgroup_batch(
    points: &[SignatureAffineUnchecked],
) -> Result<Vec<SignatureAffine>, BlsError> {
    let mut rng = OsRng;
    verify_signature_subgroup_batch_with_rng(points, &mut rng)
}

#[cfg(not(target_os = "solana"))]
fn verify_signature_subgroup_batch_with_rng<R: Rng + ?Sized>(
    points: &[SignatureAffineUnchecked],
    rng: &mut R,
) -> Result<Vec<SignatureAffine>, BlsError> {
    if points.is_empty() {
        return Ok(Vec::new());
    }

    let tables = points.iter().map(build_lookup_table).collect::<Vec<_>>();
    let coefficients = sample_coefficients(points.len(), rng);
    let selected_points = build_selected_affine_table(&tables, &coefficients);

    check_selected_affine_table(&selected_points, points.len())?;

    Ok(points
        .iter()
        .map(|point| SignatureAffine(point.0))
        .collect())
}

#[cfg(test)]
mod tests {
    use {
        super::{
            build_lookup_table, build_selected_affine_table, check_selected_affine_table,
            verify_signature_subgroup_batch_with_rng, BATCH_SUBGROUP_CHECK_ROUNDS,
        },
        crate::{
            keypair::Keypair,
            signature::{points::SignatureAffineUnchecked, SignatureCompressed},
        },
        rand::{rngs::StdRng, SeedableRng},
        std::{format, vec, vec::Vec},
    };

    fn invalid_subgroup_point() -> SignatureAffineUnchecked {
        let point = SignatureAffineUnchecked::try_from(&SignatureCompressed([
            161, 88, 176, 8, 60, 0, 4, 98, 114, 169, 182, 53, 131, 150, 63, 255, 7, 225, 71, 243,
            249, 230, 226, 65, 116, 50, 138, 216, 188, 42, 161, 80, 41, 143, 49, 137, 169, 207,
            110, 214, 38, 244, 97, 233, 68, 187, 211, 209, 23, 118, 42, 59, 145, 8, 196, 167, 74,
            21, 27, 115, 42, 96, 117, 191, 33, 153, 188, 25, 196, 140, 57, 61, 76, 235, 146, 208,
            167, 96, 87, 190, 2, 240, 133, 64, 119, 15, 171, 214, 2, 98, 206, 167, 62, 161, 144,
            108,
        ]))
        .expect("fixture should deserialize as an unchecked affine point");
        assert!(!bool::from(point.0.is_torsion_free()));
        point
    }

    #[test]
    fn test_verify_signature_subgroup_batch_accepts_valid_points() {
        let keypairs = (0..8).map(|_| Keypair::new()).collect::<Vec<_>>();
        let unchecked = keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| {
                let message = format!("batch-subgroup-{i}");
                SignatureAffineUnchecked::from(keypair.sign(message.as_bytes()))
            })
            .collect::<Vec<_>>();

        let checked =
            verify_signature_subgroup_batch_with_rng(&unchecked, &mut StdRng::seed_from_u64(7))
                .expect("valid subgroup points should pass the batched check");

        assert_eq!(checked.len(), unchecked.len());
        for (checked, unchecked) in checked.iter().zip(&unchecked) {
            assert_eq!(*checked, crate::signature::SignatureAffine(unchecked.0));
        }
    }

    #[test]
    fn test_verify_signature_subgroup_batch_rejects_invalid_point() {
        let keypair = Keypair::new();
        let mut unchecked = vec![SignatureAffineUnchecked::from(keypair.sign(b"valid-point"))];
        unchecked.push(invalid_subgroup_point());

        let tables = unchecked.iter().map(build_lookup_table).collect::<Vec<_>>();
        let coefficients = vec![1u8; BATCH_SUBGROUP_CHECK_ROUNDS * unchecked.len()];
        let selected_points = build_selected_affine_table(&tables, &coefficients);
        let result = check_selected_affine_table(&selected_points, unchecked.len());
        assert!(result.is_err(), "batch should reject a non-subgroup point");
    }

    #[test]
    fn test_verify_signature_subgroup_batch_accepts_empty_input() {
        let checked =
            verify_signature_subgroup_batch_with_rng(&[], &mut StdRng::seed_from_u64(11)).unwrap();
        assert!(checked.is_empty());
    }
}
