use {
    crate::{g1::G1Point, g2::G2Point, Endianness},
    bytemuck::{Pod, Zeroable},
    core::mem::MaybeUninit,
};

pub const GT_ELEMENT_SIZE: usize = 576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct GtElement(pub [u8; GT_ELEMENT_SIZE]);

pub const MAX_PAIRING_LENGTH: usize = 8;

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
