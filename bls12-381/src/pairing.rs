#[cfg(any(
    feature = "bytemuck",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use bytemuck_derive::{Pod, Zeroable};
use {
    crate::{g1::G1Point, g2::G2Point, Endianness},
    core::mem::MaybeUninit,
};

/// Size of a target group (Gt) element in bytes.
pub const GT_ELEMENT_SIZE: usize = 576;

/// Maximum number of pairs allowed in a single batch pairing operation.
pub const MAX_PAIRING_LENGTH: usize = 8;

/// An element in the target group (Gt).
/// Represents an element in the extension field Fq12 (576 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct GtElement(pub [u8; GT_ELEMENT_SIZE]);

impl GtElement {
    /// Returns the multiplicative identity of the target group for the given
    /// endianness.
    pub const fn identity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; GT_ELEMENT_SIZE];
        match endianness {
            Endianness::Little => bytes[0] = 1,
            Endianness::Big => bytes[GT_ELEMENT_SIZE - 1] = 1,
        }
        Self(bytes)
    }
}

/// In-place product of pairings for a batch of G1 and G2 points.
///
/// Computes `e(P_1, Q_1) * ... * e(P_n, Q_n)` and writes the resulting
/// `GtElement` into `out`.
///
/// Returns `true` if and only if every byte of `out` was written, in
/// which case the caller may `assume_init` it. On `false`, `out` is
/// left untouched and must not be assumed initialized.
pub fn pairing_map_assign(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    out: &mut MaybeUninit<GtElement>,
    endianness: Endianness,
) -> bool {
    if g1_points.len() != g2_points.len() || g1_points.len() > MAX_PAIRING_LENGTH {
        return false;
    }

    if g1_points.is_empty() {
        out.write(GtElement::identity(endianness));
        return true;
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let curve_id = match endianness {
            Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_LE,
            Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_BE,
        };

        // SAFETY: the point slices are valid for reads of their respective
        // sizes and `out` is valid for writes of `GT_ELEMENT_SIZE` bytes. Per
        // SIMD-0388 the syscall writes the full output buffer whenever it
        // returns 0.
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_pairing_map(
                curve_id,
                g1_points.len() as u64,
                g1_points.as_ptr() as *const u8,
                g2_points.as_ptr() as *const u8,
                out.as_mut_ptr().cast::<u8>(),
            )
        };
        status == 0
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let g1_pods: &[solana_bls12_381_syscall::PodG1Point] = bytemuck::cast_slice(g1_points);
        let g2_pods: &[solana_bls12_381_syscall::PodG2Point] = bytemuck::cast_slice(g2_points);

        let end = match endianness {
            Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
            Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
        };

        if let Some(res) = solana_bls12_381_syscall::bls12_381_pairing_map(
            solana_bls12_381_syscall::Version::V0,
            g1_pods,
            g2_pods,
            end,
        ) {
            out.write(GtElement(res.0));
            true
        } else {
            false
        }
    }
}

/// Product of pairings returning a new allocated target group element.
pub fn pairing_map(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    endianness: Endianness,
) -> Option<GtElement> {
    let mut out = MaybeUninit::uninit();

    if pairing_map_assign(g1_points, g2_points, &mut out, endianness) {
        // SAFETY: `pairing_map_assign` returned `true`, so every byte of `out`
        // has been written.
        Some(unsafe { out.assume_init() })
    } else {
        None
    }
}

/// In-place pairing for a single G1 and G2 point pair.
/// Zero-allocation wrapper around `pairing_map_assign`.
///
/// Returns `true` if and only if every byte of `out` was written, in
/// which case the caller may `assume_init` it. On `false`, `out` is
/// left untouched and must not be assumed initialized.
pub fn pairing_assign(
    g1_point: &G1Point,
    g2_point: &G2Point,
    out: &mut MaybeUninit<GtElement>,
    endianness: Endianness,
) -> bool {
    pairing_map_assign(
        core::slice::from_ref(g1_point),
        core::slice::from_ref(g2_point),
        out,
        endianness,
    )
}

/// Single pairing returning a new allocated target group element.
pub fn pairing(
    g1_point: &G1Point,
    g2_point: &G2Point,
    endianness: Endianness,
) -> Option<GtElement> {
    pairing_map(
        core::slice::from_ref(g1_point),
        core::slice::from_ref(g2_point),
        endianness,
    )
}

/// Evaluates whether the product of pairings equals the identity element.
///
/// Returns `Some(true)` if `e(P_1, Q_1) * ... * e(P_n, Q_n) == 1`,
/// `Some(false)` if the product is some other target group element, and
/// `None` if the check could not be run at all.
///
/// # Empty batches
///
/// Unlike [`pairing_map`], this rejects an empty batch with `None` rather
/// than reporting the vacuously-true identity. `pairing_check` is a
/// verification primitive, and callers typically build these slices from
/// attacker-controlled instruction data: a zero-length batch that reports
/// `Some(true)` is a verification bypass, not a mathematical convenience.
/// If you genuinely want the empty product, call [`pairing_map`] and compare
/// against [`GtElement::identity`] yourself.
///
/// # Correct usage
///
/// `None` means "the check did not run", which is not the same as
/// "verification failed" — but both must be treated as failure:
///
/// ```ignore
/// if pairing_check(g1, g2, e) != Some(true) {
///     return Err(ProgramError::InvalidArgument);
/// }
/// ```
///
/// Never branch on `.is_some()`.
pub fn pairing_check(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    endianness: Endianness,
) -> Option<bool> {
    // A check that asserts nothing must not report success.
    if g1_points.is_empty() {
        return None;
    }

    let mut out = MaybeUninit::uninit();

    if !pairing_map_assign(g1_points, g2_points, &mut out, endianness) {
        return None;
    }

    // SAFETY: `pairing_map_assign` returned `true`, so every byte of `out`
    // has been written.
    let gt = unsafe { out.assume_init() };

    Some(gt == GtElement::identity(endianness))
}
