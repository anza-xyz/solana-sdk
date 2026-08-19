#[cfg(any(
    feature = "bytemuck",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use bytemuck_derive::{Pod, Zeroable};
use {
    crate::{error::Bls12381Error, g1::G1Point, g2::G2Point, Endianness},
    core::mem::MaybeUninit,
};

/// Size of a target group (Gt) element in bytes.
pub const GT_ELEMENT_SIZE: usize = 576;

/// Maximum number of pairs in a single batch pairing.
pub const MAX_PAIRING_LENGTH: usize = 8;

/// A target group (Gt) element — a point in Fq12, 576 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct GtElement(
    /// The raw encoding, in whichever [`Endianness`] produced it.
    pub [u8; GT_ELEMENT_SIZE],
);

impl GtElement {
    /// The multiplicative identity, in the given encoding.
    pub const fn identity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; GT_ELEMENT_SIZE];
        match endianness {
            Endianness::Little => bytes[0] = 1,
            Endianness::Big => bytes[GT_ELEMENT_SIZE - 1] = 1,
        }
        Self(bytes)
    }

    /// Whether this is the multiplicative identity.
    ///
    /// Evaluated locally, and cheaper than `== identity()`, which constructs a
    /// 576-byte value solely for the comparison.
    pub const fn is_identity(&self, endianness: Endianness) -> bool {
        let one_index = match endianness {
            Endianness::Little => 0,
            Endianness::Big => GT_ELEMENT_SIZE - 1,
        };
        if self.0[one_index] != 1 {
            return false;
        }
        let mut i = 0;
        while i < GT_ELEMENT_SIZE {
            if i != one_index && self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Copies a byte array into a target group element.
    pub const fn from_bytes(bytes: [u8; GT_ELEMENT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Reinterprets a byte array as a target group element, without copying.
    ///
    /// Available under `default-features = false`.
    pub const fn from_bytes_ref(bytes: &[u8; GT_ELEMENT_SIZE]) -> &Self {
        // SAFETY: `GtElement` is `#[repr(transparent)]` over
        // `[u8; GT_ELEMENT_SIZE]`, so the two have identical layout and a
        // reference to one may be reinterpreted as a reference to the other.
        unsafe { &*(bytes as *const [u8; GT_ELEMENT_SIZE] as *const Self) }
    }

    /// Copies out the raw 576-byte encoding. [`Self::as_bytes`] borrows
    /// instead.
    pub const fn to_bytes(&self) -> [u8; GT_ELEMENT_SIZE] {
        self.0
    }

    /// Borrows the raw encoding.
    pub const fn as_bytes(&self) -> &[u8; GT_ELEMENT_SIZE] {
        &self.0
    }
}

/// Writes `e(P_1, Q_1) * ... * e(P_n, Q_n)` into `out`.
///
/// An empty batch is the empty product and yields the identity, as SIMD-0388
/// requires of the syscall. [`pairing_check`] deliberately differs; see its
/// documentation.
///
/// # Errors
///
/// [`Bls12381Error::LengthMismatch`] if the slices differ in length,
/// [`Bls12381Error::TooManyPairs`] if the batch exceeds [`MAX_PAIRING_LENGTH`],
/// and [`Bls12381Error::InvalidInput`] if the syscall rejects a point.
///
/// On `Ok`, `out` is initialized and may be `assume_init`ed; on `Err` it is
/// poisoned. See [Output buffer contract](crate#output-buffer-contract).
pub fn pairing_map_assign(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    out: &mut MaybeUninit<GtElement>,
    endianness: Endianness,
) -> Result<(), Bls12381Error> {
    if g1_points.len() != g2_points.len() {
        return Err(Bls12381Error::LengthMismatch);
    }
    if g1_points.len() > MAX_PAIRING_LENGTH {
        return Err(Bls12381Error::TooManyPairs);
    }

    if g1_points.is_empty() {
        out.write(GtElement::identity(endianness));
        return Ok(());
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let curve_id = match endianness {
            Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_LE,
            Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_BE,
        };

        // SAFETY: the point slices are valid for reads of their respective
        // sizes and `out` is valid for writes of `GT_ELEMENT_SIZE` bytes. The
        // syscall writes every byte of `out` whenever it returns 0; see the
        // "Output buffer contract" section in the crate documentation for why
        // this holds despite not being stated in SIMD-0388.
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_pairing_map(
                curve_id,
                g1_points.len() as u64,
                g1_points.as_ptr() as *const u8,
                g2_points.as_ptr() as *const u8,
                out.as_mut_ptr().cast::<u8>(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(Bls12381Error::InvalidInput)
        }
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
            Ok(())
        } else {
            Err(Bls12381Error::InvalidInput)
        }
    }
}

/// Allocating form of [`pairing_map_assign`].
pub fn pairing_map(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    endianness: Endianness,
) -> Result<GtElement, Bls12381Error> {
    let mut out = MaybeUninit::uninit();

    pairing_map_assign(g1_points, g2_points, &mut out, endianness)?;

    // SAFETY: `pairing_map_assign` returned `Ok`, so `out` is initialized.
    Ok(unsafe { out.assume_init() })
}

/// Single-pair form of [`pairing_map_assign`].
///
/// # Errors
///
/// [`Bls12381Error::InvalidInput`] if the syscall rejects either point.
///
/// On `Ok`, `out` is initialized and may be `assume_init`ed; on `Err` it is
/// poisoned. See [Output buffer contract](crate#output-buffer-contract).
pub fn pairing_assign(
    g1_point: &G1Point,
    g2_point: &G2Point,
    out: &mut MaybeUninit<GtElement>,
    endianness: Endianness,
) -> Result<(), Bls12381Error> {
    pairing_map_assign(
        core::slice::from_ref(g1_point),
        core::slice::from_ref(g2_point),
        out,
        endianness,
    )
}

/// Allocating form of [`pairing_assign`].
pub fn pairing(
    g1_point: &G1Point,
    g2_point: &G2Point,
    endianness: Endianness,
) -> Result<GtElement, Bls12381Error> {
    pairing_map(
        core::slice::from_ref(g1_point),
        core::slice::from_ref(g2_point),
        endianness,
    )
}

/// Whether the product of pairings is the identity.
///
/// Returns `Ok(true)` if `e(P_1, Q_1) * ... * e(P_n, Q_n) == 1`, `Ok(false)` if
/// the product is any other Gt element, and `Err` if the check never ran. Keeps
/// the 576-byte [`GtElement`] off the caller's stack, which suits a Groth16
/// verifier that would only discard it.
///
/// # Errors
///
/// [`Bls12381Error::LengthMismatch`], [`Bls12381Error::TooManyPairs`], and
/// [`Bls12381Error::EmptyBatch`] indicate a bug in the calling program.
/// [`Bls12381Error::InvalidInput`] means the syscall rejected a point.
///
/// # Empty batches
///
/// [`pairing_map`] returns the identity for an empty batch; this returns
/// [`Bls12381Error::EmptyBatch`] instead.
///
/// # Examples
///
/// `Err` means the check did not run, which is not the same as verification
/// failing — but both are failures:
///
/// ```ignore
/// if pairing_check(g1_points, g2_points, endianness) != Ok(true) {
///     return Err(ProgramError::InvalidArgument);
/// }
/// ```
///
/// Do not branch on `.is_ok()`: it reports whether the check *ran*, not whether
/// it passed, and the difference is a signature forgery.
pub fn pairing_check(
    g1_points: &[G1Point],
    g2_points: &[G2Point],
    endianness: Endianness,
) -> Result<bool, Bls12381Error> {
    // A check that asserts nothing must not report success. Testing `g1_points`
    // alone is enough — a mismatched (empty, non-empty) pair already trips the
    // length check in `pairing_map_assign`.
    if g1_points.is_empty() {
        return Err(Bls12381Error::EmptyBatch);
    }

    let mut out = MaybeUninit::uninit();
    pairing_map_assign(g1_points, g2_points, &mut out, endianness)?;

    // SAFETY: `pairing_map_assign` returned `Ok`, so `out` is initialized.
    let gt = unsafe { out.assume_init() };

    Ok(gt.is_identity(endianness))
}
