//! Benchmarks for the host-side work performed by the curve25519 syscalls
//! (`sol_curve_validate_point`, `sol_curve_group_op` and
//! `sol_curve_multiscalar_mul`).
//!
//! Every operation is measured twice over the exact same inputs:
//!
//! * `impl=solana-ed25519`: this crate's functions, which is what the syscall
//!   handlers call after translating their arguments.
//! * `impl=curve25519-dalek`: the same work spelled out against
//!   `curve25519-dalek`, which is what this crate used before, kept here so a
//!   compute unit repricing can be compared against both backends.

// the `curve25519-dalek` path mirrors this crate's own operators verbatim
#![allow(clippy::op_ref)]

use {
    criterion::{
        black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup,
        Criterion,
    },
    solana_ed25519::{edwards::EdwardsPoint, ristretto::RistrettoPoint, scalar::Scalar},
};

/// Current compute unit costs, from `ExecutionCost::default()` in
/// agave's `program-runtime/src/execution_budget.rs`.
const EDWARDS_VALIDATE_POINT_CU: u64 = 159;
const EDWARDS_ADD_CU: u64 = 473;
const EDWARDS_SUBTRACT_CU: u64 = 475;
const EDWARDS_MULTIPLY_CU: u64 = 2_177;
const EDWARDS_MSM_BASE_CU: u64 = 2_273;
const EDWARDS_MSM_INCREMENTAL_CU: u64 = 758;
const RISTRETTO_VALIDATE_POINT_CU: u64 = 169;
const RISTRETTO_ADD_CU: u64 = 521;
const RISTRETTO_SUBTRACT_CU: u64 = 519;
const RISTRETTO_MULTIPLY_CU: u64 = 2_208;
const RISTRETTO_MSM_BASE_CU: u64 = 2_303;
const RISTRETTO_MSM_INCREMENTAL_CU: u64 = 788;

/// The syscall rejects longer inputs, see `SyscallCurveMultiscalarMultiplication`.
const MSM_MAX_POINTS_LEN: usize = 512;

const MSM_POINTS_LENS: [usize; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 384, MSM_MAX_POINTS_LEN];

type PointBytes = [u8; 32];
type ScalarBytes = [u8; 32];

/// The work one syscall performs, for a single curve and a single backend.
struct CurveOps {
    validate_point: fn(&PointBytes) -> bool,
    add: fn(&PointBytes, &PointBytes) -> Option<PointBytes>,
    subtract: fn(&PointBytes, &PointBytes) -> Option<PointBytes>,
    multiply: fn(&ScalarBytes, &PointBytes) -> Option<PointBytes>,
    multiscalar_multiply: fn(&[ScalarBytes], &[PointBytes]) -> Option<PointBytes>,
}

/// This crate's functions, backed by `solana-ed25519`.
mod solana_ed25519_ops {
    use {
        super::{PointBytes, ScalarBytes},
        solana_curve25519::scalar::PodScalar,
    };

    fn pod_scalars(scalars: &[ScalarBytes]) -> &[PodScalar] {
        bytemuck::cast_slice(scalars)
    }

    pub mod edwards_ops {
        use {
            super::{pod_scalars, PointBytes, ScalarBytes},
            solana_curve25519::{
                edwards::{
                    add_edwards, multiply_edwards, multiscalar_multiply_edwards, subtract_edwards,
                    validate_edwards, PodEdwardsPoint,
                },
                scalar::PodScalar,
            },
        };

        pub fn validate_point(point: &PointBytes) -> bool {
            validate_edwards(&PodEdwardsPoint(*point))
        }

        pub fn add(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            add_edwards(&PodEdwardsPoint(*left), &PodEdwardsPoint(*right)).map(|point| point.0)
        }

        pub fn subtract(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            subtract_edwards(&PodEdwardsPoint(*left), &PodEdwardsPoint(*right)).map(|point| point.0)
        }

        pub fn multiply(scalar: &ScalarBytes, point: &PointBytes) -> Option<PointBytes> {
            multiply_edwards(&PodScalar(*scalar), &PodEdwardsPoint(*point)).map(|point| point.0)
        }

        pub fn multiscalar_multiply(
            scalars: &[ScalarBytes],
            points: &[PointBytes],
        ) -> Option<PointBytes> {
            multiscalar_multiply_edwards(pod_scalars(scalars), bytemuck::cast_slice(points))
                .map(|point| point.0)
        }
    }

    pub mod ristretto_ops {
        use {
            super::{pod_scalars, PointBytes, ScalarBytes},
            solana_curve25519::{
                ristretto::{
                    add_ristretto, multiply_ristretto, multiscalar_multiply_ristretto,
                    subtract_ristretto, validate_ristretto, PodRistrettoPoint,
                },
                scalar::PodScalar,
            },
        };

        pub fn validate_point(point: &PointBytes) -> bool {
            validate_ristretto(&PodRistrettoPoint(*point))
        }

        pub fn add(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            add_ristretto(&PodRistrettoPoint(*left), &PodRistrettoPoint(*right))
                .map(|point| point.0)
        }

        pub fn subtract(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            subtract_ristretto(&PodRistrettoPoint(*left), &PodRistrettoPoint(*right))
                .map(|point| point.0)
        }

        pub fn multiply(scalar: &ScalarBytes, point: &PointBytes) -> Option<PointBytes> {
            multiply_ristretto(&PodScalar(*scalar), &PodRistrettoPoint(*point)).map(|point| point.0)
        }

        pub fn multiscalar_multiply(
            scalars: &[ScalarBytes],
            points: &[PointBytes],
        ) -> Option<PointBytes> {
            multiscalar_multiply_ristretto(pod_scalars(scalars), bytemuck::cast_slice(points))
                .map(|point| point.0)
        }
    }
}

/// The same work spelled out against `curve25519-dalek`, the backend this crate
/// used before switching to `solana-ed25519`.
mod curve25519_dalek_ops {
    use {
        super::{PointBytes, ScalarBytes},
        curve25519_dalek::scalar::Scalar,
    };

    fn scalar(bytes: &ScalarBytes) -> Option<Scalar> {
        Option::from(Scalar::from_canonical_bytes(*bytes))
    }

    fn scalars(bytes: &[ScalarBytes]) -> Option<Vec<Scalar>> {
        bytes.iter().map(scalar).collect()
    }

    pub mod edwards_ops {
        use {
            super::{scalar, scalars, PointBytes, ScalarBytes},
            curve25519_dalek::{
                edwards::{CompressedEdwardsY, EdwardsPoint},
                traits::VartimeMultiscalarMul,
            },
        };

        fn decompress(point: &PointBytes) -> Option<EdwardsPoint> {
            CompressedEdwardsY::from_slice(point).ok()?.decompress()
        }

        pub fn validate_point(point: &PointBytes) -> bool {
            decompress(point).is_some()
        }

        pub fn add(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            let result = &decompress(left)? + &decompress(right)?;
            Some(result.compress().to_bytes())
        }

        pub fn subtract(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            let result = &decompress(left)? - &decompress(right)?;
            Some(result.compress().to_bytes())
        }

        pub fn multiply(scalar_bytes: &ScalarBytes, point: &PointBytes) -> Option<PointBytes> {
            let result = &scalar(scalar_bytes)? * &decompress(point)?;
            Some(result.compress().to_bytes())
        }

        pub fn multiscalar_multiply(
            scalar_bytes: &[ScalarBytes],
            points: &[PointBytes],
        ) -> Option<PointBytes> {
            EdwardsPoint::optional_multiscalar_mul(
                scalars(scalar_bytes)?,
                points.iter().map(decompress),
            )
            .map(|result| result.compress().to_bytes())
        }
    }

    pub mod ristretto_ops {
        use {
            super::{scalar, scalars, PointBytes, ScalarBytes},
            curve25519_dalek::{
                ristretto::{CompressedRistretto, RistrettoPoint},
                traits::VartimeMultiscalarMul,
            },
        };

        fn decompress(point: &PointBytes) -> Option<RistrettoPoint> {
            CompressedRistretto::from_slice(point).ok()?.decompress()
        }

        pub fn validate_point(point: &PointBytes) -> bool {
            decompress(point).is_some()
        }

        pub fn add(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            let result = &decompress(left)? + &decompress(right)?;
            Some(result.compress().to_bytes())
        }

        pub fn subtract(left: &PointBytes, right: &PointBytes) -> Option<PointBytes> {
            let result = &decompress(left)? - &decompress(right)?;
            Some(result.compress().to_bytes())
        }

        pub fn multiply(scalar_bytes: &ScalarBytes, point: &PointBytes) -> Option<PointBytes> {
            let result = &scalar(scalar_bytes)? * &decompress(point)?;
            Some(result.compress().to_bytes())
        }

        pub fn multiscalar_multiply(
            scalar_bytes: &[ScalarBytes],
            points: &[PointBytes],
        ) -> Option<PointBytes> {
            RistrettoPoint::optional_multiscalar_mul(
                scalars(scalar_bytes)?,
                points.iter().map(decompress),
            )
            .map(|result| result.compress().to_bytes())
        }
    }
}

const SOLANA_ED25519_EDWARDS: CurveOps = CurveOps {
    validate_point: solana_ed25519_ops::edwards_ops::validate_point,
    add: solana_ed25519_ops::edwards_ops::add,
    subtract: solana_ed25519_ops::edwards_ops::subtract,
    multiply: solana_ed25519_ops::edwards_ops::multiply,
    multiscalar_multiply: solana_ed25519_ops::edwards_ops::multiscalar_multiply,
};

const SOLANA_ED25519_RISTRETTO: CurveOps = CurveOps {
    validate_point: solana_ed25519_ops::ristretto_ops::validate_point,
    add: solana_ed25519_ops::ristretto_ops::add,
    subtract: solana_ed25519_ops::ristretto_ops::subtract,
    multiply: solana_ed25519_ops::ristretto_ops::multiply,
    multiscalar_multiply: solana_ed25519_ops::ristretto_ops::multiscalar_multiply,
};

const CURVE25519_DALEK_EDWARDS: CurveOps = CurveOps {
    validate_point: curve25519_dalek_ops::edwards_ops::validate_point,
    add: curve25519_dalek_ops::edwards_ops::add,
    subtract: curve25519_dalek_ops::edwards_ops::subtract,
    multiply: curve25519_dalek_ops::edwards_ops::multiply,
    multiscalar_multiply: curve25519_dalek_ops::edwards_ops::multiscalar_multiply,
};

const CURVE25519_DALEK_RISTRETTO: CurveOps = CurveOps {
    validate_point: curve25519_dalek_ops::ristretto_ops::validate_point,
    add: curve25519_dalek_ops::ristretto_ops::add,
    subtract: curve25519_dalek_ops::ristretto_ops::subtract,
    multiply: curve25519_dalek_ops::ristretto_ops::multiply,
    multiscalar_multiply: curve25519_dalek_ops::ristretto_ops::multiscalar_multiply,
};

/// Deterministic scalars, so that every run benchmarks the same inputs.
fn deterministic_scalar_bytes(seed: u64) -> ScalarBytes {
    let mut state = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 56) as u8;
    }
    // Reduce so that the bytes are a canonical scalar encoding, which is what
    // both backends require.
    Scalar::from_bytes_mod_order(bytes).to_bytes()
}

fn deterministic_scalar(seed: u64) -> Scalar {
    Scalar::from_canonical_bytes(deterministic_scalar_bytes(seed))
        .into_option()
        .expect("scalar bytes are reduced")
}

/// Point encodings are identical for both backends, so the same bytes feed both.
fn edwards_point_bytes(seed: u64) -> PointBytes {
    EdwardsPoint::mul_base(&deterministic_scalar(seed))
        .compress()
        .to_bytes()
}

fn ristretto_point_bytes(seed: u64) -> PointBytes {
    RistrettoPoint::mul_base(&deterministic_scalar(seed))
        .compress()
        .to_bytes()
}

fn msm_cu(base_cu: u64, incremental_cu: u64, points_len: usize) -> u64 {
    base_cu.saturating_add(incremental_cu.saturating_mul(points_len as u64 - 1))
}

struct CurveBench {
    curve_name: &'static str,
    points: Vec<PointBytes>,
    scalars: Vec<ScalarBytes>,
    validate_point_cu: u64,
    add_cu: u64,
    subtract_cu: u64,
    multiply_cu: u64,
    msm_base_cu: u64,
    msm_incremental_cu: u64,
}

impl CurveBench {
    fn run(&self, group: &mut BenchmarkGroup<'_, WallTime>, impl_name: &str, ops: &CurveOps) {
        let CurveBench {
            curve_name,
            points,
            scalars,
            ..
        } = self;
        let left_point = points[0];
        let right_point = points[1];
        let scalar = scalars[0];

        let label =
            |op: &str, cu: u64| format!("{curve_name}/{op}/impl={impl_name}/current_cu={cu}");

        group.bench_function(label("validate_point", self.validate_point_cu), |b| {
            b.iter(|| black_box((ops.validate_point)(black_box(&left_point))))
        });
        group.bench_function(label("add", self.add_cu), |b| {
            b.iter(|| black_box((ops.add)(black_box(&left_point), black_box(&right_point))))
        });
        group.bench_function(label("subtract", self.subtract_cu), |b| {
            b.iter(|| {
                black_box((ops.subtract)(
                    black_box(&left_point),
                    black_box(&right_point),
                ))
            })
        });
        group.bench_function(label("multiply", self.multiply_cu), |b| {
            b.iter(|| black_box((ops.multiply)(black_box(&scalar), black_box(&left_point))))
        });

        for points_len in MSM_POINTS_LENS {
            let current_cu = msm_cu(self.msm_base_cu, self.msm_incremental_cu, points_len);
            group.bench_function(
                label(&format!("msm/points_len={points_len}"), current_cu),
                |b| {
                    b.iter(|| {
                        black_box((ops.multiscalar_multiply)(
                            black_box(&scalars[..points_len]),
                            black_box(&points[..points_len]),
                        ))
                    })
                },
            );
        }
    }
}

fn edwards_bench() -> CurveBench {
    CurveBench {
        curve_name: "edwards",
        points: (0..MSM_MAX_POINTS_LEN)
            .map(|index| edwards_point_bytes(0xed2551 ^ index as u64))
            .collect(),
        scalars: (0..MSM_MAX_POINTS_LEN)
            .map(|index| deterministic_scalar_bytes(0x5ca1a4 ^ index as u64))
            .collect(),
        validate_point_cu: EDWARDS_VALIDATE_POINT_CU,
        add_cu: EDWARDS_ADD_CU,
        subtract_cu: EDWARDS_SUBTRACT_CU,
        multiply_cu: EDWARDS_MULTIPLY_CU,
        msm_base_cu: EDWARDS_MSM_BASE_CU,
        msm_incremental_cu: EDWARDS_MSM_INCREMENTAL_CU,
    }
}

fn ristretto_bench() -> CurveBench {
    CurveBench {
        curve_name: "ristretto",
        points: (0..MSM_MAX_POINTS_LEN)
            .map(|index| ristretto_point_bytes(0x415751 ^ index as u64))
            .collect(),
        scalars: (0..MSM_MAX_POINTS_LEN)
            .map(|index| deterministic_scalar_bytes(0x5ca1a4 ^ index as u64))
            .collect(),
        validate_point_cu: RISTRETTO_VALIDATE_POINT_CU,
        add_cu: RISTRETTO_ADD_CU,
        subtract_cu: RISTRETTO_SUBTRACT_CU,
        multiply_cu: RISTRETTO_MULTIPLY_CU,
        msm_base_cu: RISTRETTO_MSM_BASE_CU,
        msm_incremental_cu: RISTRETTO_MSM_INCREMENTAL_CU,
    }
}

/// Both backends must agree on every result, otherwise the comparison is
/// meaningless.
fn assert_backends_agree(bench: &CurveBench, left: &CurveOps, right: &CurveOps) {
    let (point_a, point_b) = (bench.points[0], bench.points[1]);
    let scalar = bench.scalars[0];

    assert_eq!(
        (left.validate_point)(&point_a),
        (right.validate_point)(&point_a),
        "{} validate_point disagrees",
        bench.curve_name
    );
    assert_eq!(
        (left.add)(&point_a, &point_b),
        (right.add)(&point_a, &point_b),
        "{} add disagrees",
        bench.curve_name
    );
    assert_eq!(
        (left.subtract)(&point_a, &point_b),
        (right.subtract)(&point_a, &point_b),
        "{} subtract disagrees",
        bench.curve_name
    );
    assert_eq!(
        (left.multiply)(&scalar, &point_a),
        (right.multiply)(&scalar, &point_a),
        "{} multiply disagrees",
        bench.curve_name
    );
    for points_len in MSM_POINTS_LENS {
        assert_eq!(
            (left.multiscalar_multiply)(&bench.scalars[..points_len], &bench.points[..points_len]),
            (right.multiscalar_multiply)(&bench.scalars[..points_len], &bench.points[..points_len]),
            "{} msm disagrees at points_len={points_len}",
            bench.curve_name
        );
    }
}

fn all_benches(c: &mut Criterion) {
    let edwards = edwards_bench();
    let ristretto = ristretto_bench();

    assert_backends_agree(&edwards, &SOLANA_ED25519_EDWARDS, &CURVE25519_DALEK_EDWARDS);
    assert_backends_agree(
        &ristretto,
        &SOLANA_ED25519_RISTRETTO,
        &CURVE25519_DALEK_RISTRETTO,
    );

    let mut group = c.benchmark_group("curve25519 syscalls");
    edwards.run(&mut group, "solana-ed25519", &SOLANA_ED25519_EDWARDS);
    edwards.run(&mut group, "curve25519-dalek", &CURVE25519_DALEK_EDWARDS);
    ristretto.run(&mut group, "solana-ed25519", &SOLANA_ED25519_RISTRETTO);
    ristretto.run(&mut group, "curve25519-dalek", &CURVE25519_DALEK_RISTRETTO);
    group.finish();
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
