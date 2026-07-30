use {
    crate::{g1::G1Point, g2::G2Point, Endianness},
    bytemuck::{Pod, Zeroable},
    core::mem::MaybeUninit,
};

/// Size of a target group (Gt) element in bytes.
pub const GT_ELEMENT_SIZE: usize = 576;

/// Maximum number of pairs allowed in a single batch pairing operation.
pub const MAX_PAIRING_LENGTH: usize = 8;

/// An element in the target group (Gt).
/// Represents an element in the extension field Fq12 (576 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct GtElement(pub [u8; GT_ELEMENT_SIZE]);

/// In-place product of pairings for a batch of G1 and G2 points.
///
/// Computes `e(P_1, Q_1) * ... * e(P_n, Q_n)` and writes the resulting
/// `GtElement` to the `out` reference.
pub fn pairing_map_assign(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    out: &mut GtElement,
    endianness: Endianness,
) -> bool {
    if g1_points.len() != g2_points.len() || g1_points.len() > MAX_PAIRING_LENGTH {
        return false;
    }

    if g1_points.is_empty() {
        out.0.fill(0);
        match endianness {
            Endianness::Little => out.0[0] = 1,
            Endianness::Big => out.0[575] = 1,
        }
        return true;
    }

    #[cfg(target_os = "solana")]
    {
        let curve_id = match endianness {
            Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_LE,
            Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_BE,
        };

        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_pairing_map(
                curve_id,
                g1_points.len() as u64,
                g1_points.as_ptr() as *const u8,
                g2_points.as_ptr() as *const u8,
                out.0.as_mut_ptr(),
            )
        };
        status == 0
    }

    #[cfg(not(target_os = "solana"))]
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
            out.0.copy_from_slice(&res.0);
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
    let mut result = MaybeUninit::<GtElement>::uninit();

    let success = pairing_map_assign(
        g1_points,
        g2_points,
        unsafe { result.assume_init_mut() },
        endianness,
    );

    if success {
        Some(unsafe { result.assume_init() })
    } else {
        None
    }
}

/// In-place pairing for a single G1 and G2 point pair.
/// Zero-allocation wrapper around `pairing_map_assign`.
pub fn pairing_assign(
    g1_point: &G1Point,
    g2_point: &G2Point,
    out: &mut GtElement,
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

/// Evaluates if the product of pairings equals the identity element.
///
/// Highly efficient for ZK verifiers (e.g., Groth16) as it avoids returning
/// the raw 576-byte `GtElement` to the caller.
pub fn pairing_check(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    endianness: Endianness,
) -> Option<bool> {
    let mut result = MaybeUninit::<GtElement>::uninit();

    let success = pairing_map_assign(
        g1_points,
        g2_points,
        unsafe { result.assume_init_mut() },
        endianness,
    );

    if !success {
        return None;
    }

    let gt = unsafe { result.assume_init() };
    let mut identity = [0u8; GT_ELEMENT_SIZE];

    match endianness {
        Endianness::Little => identity[0] = 1,
        Endianness::Big => identity[575] = 1,
    }

    Some(gt.0 == identity)
}
