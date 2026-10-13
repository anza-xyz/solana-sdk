//! Consistency checks against Ethereum's EIP-2537 BLS12-381 precompile
//! vectors, as shipped by go-ethereum and `ethereum/execution-spec-tests`.
//!
//! The two ecosystems agree on the curve arithmetic and on which points are
//! acceptable, but encode inputs differently:
//!
//! - EIP-2537 left-pads every base field element to 64 bytes and encodes the
//!   point at infinity as all zeros. SIMD-0388 uses the 48-byte Zcash/IETF
//!   encoding, with the infinity flag in the top byte, and for `Fq2` orders
//!   `c1` before `c0` in big-endian mode.
//! - EIP-2537 accepts any 256-bit scalar and reduces it modulo the group
//!   order. SIMD-0388 rejects non-canonical scalars, so those vectors are
//!   checked twice: the raw scalar must be rejected and the reduced scalar
//!   must reproduce Ethereum's result.
//! - EIP-2537 has no upper bound on the number of pairs in a pairing check;
//!   SIMD-0388 caps a batch at [`MAX_PAIRING_LENGTH`], and the larger
//!   Ethereum vectors must be rejected for that reason.
//! - Vectors that fail on Ethereum because of the byte layout alone
//!   (a wrong input length or non-zero padding bytes) have no Solana
//!   counterpart and are skipped.
//!
//! Every vector is run through both the big-endian and the little-endian
//! Solana encodings. See `tests/data/README.md` for the provenance of the
//! vector files.

use {
    core::cmp::Ordering,
    serde_derive::Deserialize,
    solana_bls12_381::{
        pairing_check, Bls12381Error, Endianness, G1Compressed, G1Point, G2Compressed, G2Point,
        Scalar, G1_COMPRESSED_POINT_SIZE, G1_UNCOMPRESSED_POINT_SIZE, G2_COMPRESSED_POINT_SIZE,
        G2_UNCOMPRESSED_POINT_SIZE, MAX_PAIRING_LENGTH, SCALAR_SIZE,
    },
};

/// Size of a base field element in the Zcash/IETF encoding.
const FQ_SIZE: usize = 48;
/// Size of a base field element in the EIP-2537 encoding.
const EIP_FP_SIZE: usize = 64;
/// Number of zero bytes EIP-2537 prepends to every base field element.
const EIP_FP_PADDING: usize = EIP_FP_SIZE - FQ_SIZE;
/// Size of a G1 point in the EIP-2537 encoding: `x`, `y`.
const EIP_G1_SIZE: usize = 2 * EIP_FP_SIZE;
/// Size of a G2 point in the EIP-2537 encoding: `x_c0`, `x_c1`, `y_c0`, `y_c1`.
const EIP_G2_SIZE: usize = 4 * EIP_FP_SIZE;
/// Size of the EIP-2537 pairing check output.
const EIP_PAIRING_OUTPUT_SIZE: usize = 32;

const ENDIANNESS: [Endianness; 2] = [Endianness::Big, Endianness::Little];

/// A successful vector in the go-ethereum / execution-spec-tests format.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Vector {
    name: String,
    input: String,
    expected: String,
}

/// A vector the Ethereum precompile rejects.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FailVector {
    name: String,
    input: String,
    expected_error: String,
}

fn load(sources: &[&str]) -> Vec<Vector> {
    let vectors: Vec<Vector> = sources
        .iter()
        .flat_map(|json| serde_json::from_str::<Vec<Vector>>(json).unwrap())
        .collect();
    assert!(!vectors.is_empty());
    vectors
}

/// Loads failing vectors, dropping the ones whose failure is a property of
/// the EIP-2537 byte layout rather than of the point: a wrong input length,
/// or non-zero padding bytes. Neither can be expressed in the Solana
/// encoding.
fn load_fail(sources: &[&str]) -> Vec<FailVector> {
    let vectors: Vec<FailVector> = sources
        .iter()
        .flat_map(|json| serde_json::from_str::<Vec<FailVector>>(json).unwrap())
        .filter(|vector| {
            !matches!(
                vector.expected_error.as_str(),
                "invalid input length" | "invalid field element top bytes"
            )
        })
        .collect();
    assert!(!vectors.is_empty());
    vectors
}

fn hex2bytes(hex: &str) -> Vec<u8> {
    array_bytes::hex2bytes_unchecked(hex)
}

/// The scalar field order `r`, big-endian.
fn scalar_field_order() -> [u8; SCALAR_SIZE] {
    hex2bytes("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
        .try_into()
        .unwrap()
}

/// `(p - 1) / 2`, big-endian: a `y` coordinate above this has the
/// lexicographically larger sign in the Zcash compressed encoding.
fn fq_half() -> [u8; FQ_SIZE] {
    hex2bytes("0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555")
        .try_into()
        .unwrap()
}

// ---------------------------------------------------------------------------
// EIP-2537 -> SIMD-0388 big-endian conversion
// ---------------------------------------------------------------------------

/// Strips the EIP-2537 padding from a base field element. `None` when the
/// padding is not zero, which Ethereum reports as a separate error.
fn fq_from_eip(fp: &[u8]) -> Option<[u8; FQ_SIZE]> {
    assert_eq!(fp.len(), EIP_FP_SIZE);
    let (padding, fq) = fp.split_at(EIP_FP_PADDING);
    padding
        .iter()
        .all(|&byte| byte == 0)
        .then(|| fq.try_into().unwrap())
}

fn g1_from_eip(bytes: &[u8]) -> Option<G1Point> {
    assert_eq!(bytes.len(), EIP_G1_SIZE);
    if bytes.iter().all(|&byte| byte == 0) {
        return Some(G1Point::infinity(Endianness::Big));
    }
    let mut point = [0u8; G1_UNCOMPRESSED_POINT_SIZE];
    point[..FQ_SIZE].copy_from_slice(&fq_from_eip(&bytes[..EIP_FP_SIZE])?);
    point[FQ_SIZE..].copy_from_slice(&fq_from_eip(&bytes[EIP_FP_SIZE..])?);
    Some(G1Point(point))
}

fn g2_from_eip(bytes: &[u8]) -> Option<G2Point> {
    assert_eq!(bytes.len(), EIP_G2_SIZE);
    if bytes.iter().all(|&byte| byte == 0) {
        return Some(G2Point::infinity(Endianness::Big));
    }
    let mut coordinates = bytes.chunks_exact(EIP_FP_SIZE);
    let mut next = || fq_from_eip(coordinates.next().unwrap());
    let (x_c0, x_c1, y_c0, y_c1) = (next()?, next()?, next()?, next()?);
    // EIP-2537 orders the coordinates `x_c0, x_c1, y_c0, y_c1`; the Zcash
    // big-endian encoding orders them `x_c1, x_c0, y_c1, y_c0`.
    let mut point = [0u8; G2_UNCOMPRESSED_POINT_SIZE];
    point[..FQ_SIZE].copy_from_slice(&x_c1);
    point[FQ_SIZE..2 * FQ_SIZE].copy_from_slice(&x_c0);
    point[2 * FQ_SIZE..3 * FQ_SIZE].copy_from_slice(&y_c1);
    point[3 * FQ_SIZE..].copy_from_slice(&y_c0);
    Some(G2Point(point))
}

fn scalar_from_eip(bytes: &[u8]) -> Scalar {
    Scalar(bytes.try_into().unwrap())
}

/// Reduces a big-endian scalar modulo `r`, as EIP-2537 does implicitly.
fn reduce_scalar(scalar: &Scalar) -> Scalar {
    let order = scalar_field_order();
    let mut value = scalar.0;
    // Equal-length big-endian arrays compare like the integers they encode.
    while value.cmp(&order) != Ordering::Less {
        let mut borrow = 0u8;
        for (value_byte, order_byte) in value.iter_mut().zip(order.iter()).rev() {
            let (difference, underflow_a) = value_byte.overflowing_sub(*order_byte);
            let (difference, underflow_b) = difference.overflowing_sub(borrow);
            *value_byte = difference;
            borrow = u8::from(underflow_a || underflow_b);
        }
        assert_eq!(borrow, 0);
    }
    Scalar(value)
}

// ---------------------------------------------------------------------------
// Big-endian -> little-endian SIMD-0388 conversion
// ---------------------------------------------------------------------------

fn reverse_fq_chunks(bytes: &mut [u8]) {
    for fq in bytes.chunks_mut(FQ_SIZE) {
        fq.reverse();
    }
}

fn swap_fq2_halves(bytes: &mut [u8]) {
    for fq2 in bytes.chunks_mut(2 * FQ_SIZE) {
        let (c1, c0) = fq2.split_at_mut(FQ_SIZE);
        c1.swap_with_slice(c0);
    }
}

/// Re-encodes a big-endian G1 point for `endianness`.
fn g1_in(point: &G1Point, endianness: Endianness) -> G1Point {
    let mut bytes = point.0;
    if endianness == Endianness::Little {
        reverse_fq_chunks(&mut bytes);
    }
    G1Point(bytes)
}

/// Re-encodes a big-endian G2 point for `endianness`.
fn g2_in(point: &G2Point, endianness: Endianness) -> G2Point {
    let mut bytes = point.0;
    if endianness == Endianness::Little {
        swap_fq2_halves(&mut bytes);
        reverse_fq_chunks(&mut bytes);
    }
    G2Point(bytes)
}

fn g1_compressed_in(point: &G1Compressed, endianness: Endianness) -> G1Compressed {
    let mut bytes = point.0;
    if endianness == Endianness::Little {
        reverse_fq_chunks(&mut bytes);
    }
    G1Compressed(bytes)
}

fn g2_compressed_in(point: &G2Compressed, endianness: Endianness) -> G2Compressed {
    let mut bytes = point.0;
    if endianness == Endianness::Little {
        swap_fq2_halves(&mut bytes);
        reverse_fq_chunks(&mut bytes);
    }
    G2Compressed(bytes)
}

/// Re-encodes a big-endian scalar for `endianness`.
fn scalar_in(scalar: &Scalar, endianness: Endianness) -> Scalar {
    let mut bytes = scalar.0;
    if endianness == Endianness::Little {
        bytes.reverse();
    }
    Scalar(bytes)
}

// ---------------------------------------------------------------------------
// Zcash compression of big-endian points
// ---------------------------------------------------------------------------

/// Whether `y > (p - 1) / 2`, i.e. whether `y` is the lexicographically
/// larger of the two square roots.
fn fq_is_large(y: &[u8]) -> bool {
    y > &fq_half()[..]
}

const COMPRESSION_FLAG: u8 = 0x80;
const SIGN_FLAG: u8 = 0x20;

fn compress_g1(point: &G1Point) -> G1Compressed {
    if point.is_infinity(Endianness::Big) {
        return G1Compressed::infinity(Endianness::Big);
    }
    let (x, y) = point.0.split_at(FQ_SIZE);
    let mut bytes = [0u8; G1_COMPRESSED_POINT_SIZE];
    bytes.copy_from_slice(x);
    bytes[0] |= COMPRESSION_FLAG;
    if fq_is_large(y) {
        bytes[0] |= SIGN_FLAG;
    }
    G1Compressed(bytes)
}

fn compress_g2(point: &G2Point) -> G2Compressed {
    if point.is_infinity(Endianness::Big) {
        return G2Compressed::infinity(Endianness::Big);
    }
    let (x, y) = point.0.split_at(2 * FQ_SIZE);
    let (y_c1, y_c0) = y.split_at(FQ_SIZE);
    let mut bytes = [0u8; G2_COMPRESSED_POINT_SIZE];
    bytes.copy_from_slice(x);
    bytes[0] |= COMPRESSION_FLAG;
    // The sign is taken from `c1`, falling back to `c0` when `c1` is zero.
    let large = if y_c1.iter().all(|&byte| byte == 0) {
        fq_is_large(y_c0)
    } else {
        fq_is_large(y_c1)
    };
    if large {
        bytes[0] |= SIGN_FLAG;
    }
    G2Compressed(bytes)
}

// ---------------------------------------------------------------------------
// G1ADD / G2ADD
// ---------------------------------------------------------------------------

#[test]
fn eip2537_g1_add() {
    for vector in load(&[
        include_str!("data/geth/blsG1Add.json"),
        include_str!("data/eest/add_G1_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, q) = input.split_at(EIP_G1_SIZE);
        let p = g1_from_eip(p).unwrap();
        let q = g1_from_eip(q).unwrap();
        let expected = g1_from_eip(&hex2bytes(&vector.expected)).unwrap();

        for endianness in ENDIANNESS {
            let (p, q, expected) = (
                g1_in(&p, endianness),
                g1_in(&q, endianness),
                g1_in(&expected, endianness),
            );
            // G1ADD does not require subgroup membership; neither does the
            // unchecked Solana entry point.
            assert_eq!(
                p.add_unchecked(&q, endianness),
                Some(expected),
                "{}: add_unchecked, {endianness:?}",
                vector.name
            );
            if p.validate(endianness) && q.validate(endianness) {
                assert_eq!(
                    p.add(&q, endianness),
                    Some(expected),
                    "{}: add, {endianness:?}",
                    vector.name
                );
            }
            // Ethereum has no subtraction precompile, but its sum pins ours:
            // (P + Q) - Q must give back P.
            assert_eq!(
                expected.sub_unchecked(&q, endianness),
                Some(p),
                "{}: sub_unchecked, {endianness:?}",
                vector.name
            );
        }
    }
}

#[test]
fn eip2537_g1_add_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG1Add.json"),
        include_str!("data/eest/fail-add_G1_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, q) = input.split_at(EIP_G1_SIZE);
        let p = g1_from_eip(p).unwrap();
        let q = g1_from_eip(q).unwrap();

        for endianness in ENDIANNESS {
            let (p, q) = (g1_in(&p, endianness), g1_in(&q, endianness));
            assert_eq!(
                p.add_unchecked(&q, endianness),
                None,
                "{} ({}): add_unchecked, {endianness:?}",
                vector.name,
                vector.expected_error
            );
            assert_eq!(
                p.add(&q, endianness),
                None,
                "{} ({}): add, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

#[test]
fn eip2537_g2_add() {
    for vector in load(&[
        include_str!("data/geth/blsG2Add.json"),
        include_str!("data/eest/add_G2_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, q) = input.split_at(EIP_G2_SIZE);
        let p = g2_from_eip(p).unwrap();
        let q = g2_from_eip(q).unwrap();
        let expected = g2_from_eip(&hex2bytes(&vector.expected)).unwrap();

        for endianness in ENDIANNESS {
            let (p, q, expected) = (
                g2_in(&p, endianness),
                g2_in(&q, endianness),
                g2_in(&expected, endianness),
            );
            assert_eq!(
                p.add_unchecked(&q, endianness),
                Some(expected),
                "{}: add_unchecked, {endianness:?}",
                vector.name
            );
            if p.validate(endianness) && q.validate(endianness) {
                assert_eq!(
                    p.add(&q, endianness),
                    Some(expected),
                    "{}: add, {endianness:?}",
                    vector.name
                );
            }
            assert_eq!(
                expected.sub_unchecked(&q, endianness),
                Some(p),
                "{}: sub_unchecked, {endianness:?}",
                vector.name
            );
        }
    }
}

#[test]
fn eip2537_g2_add_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG2Add.json"),
        include_str!("data/eest/fail-add_G2_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, q) = input.split_at(EIP_G2_SIZE);
        let p = g2_from_eip(p).unwrap();
        let q = g2_from_eip(q).unwrap();

        for endianness in ENDIANNESS {
            let (p, q) = (g2_in(&p, endianness), g2_in(&q, endianness));
            assert_eq!(
                p.add_unchecked(&q, endianness),
                None,
                "{} ({}): add_unchecked, {endianness:?}",
                vector.name,
                vector.expected_error
            );
            assert_eq!(
                p.add(&q, endianness),
                None,
                "{} ({}): add, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

// ---------------------------------------------------------------------------
// G1MUL / G2MUL
// ---------------------------------------------------------------------------

/// Checks `k * P == expected`, where `k` is an arbitrary 256-bit EIP-2537
/// scalar. Solana rejects a non-canonical `k`; the reduced scalar must then
/// reproduce Ethereum's result.
fn check_g1_mul(name: &str, p: &G1Point, k: &Scalar, expected: &G1Point) {
    let reduced = reduce_scalar(k);
    for endianness in ENDIANNESS {
        let (p, expected) = (g1_in(p, endianness), g1_in(expected, endianness));
        if reduced != *k {
            assert_eq!(
                p.mul(&scalar_in(k, endianness), endianness),
                None,
                "{name}: non-canonical scalar must be rejected, {endianness:?}"
            );
        }
        assert_eq!(
            p.mul(&scalar_in(&reduced, endianness), endianness),
            Some(expected),
            "{name}: mul, {endianness:?}"
        );
    }
}

fn check_g2_mul(name: &str, p: &G2Point, k: &Scalar, expected: &G2Point) {
    let reduced = reduce_scalar(k);
    for endianness in ENDIANNESS {
        let (p, expected) = (g2_in(p, endianness), g2_in(expected, endianness));
        if reduced != *k {
            assert_eq!(
                p.mul(&scalar_in(k, endianness), endianness),
                None,
                "{name}: non-canonical scalar must be rejected, {endianness:?}"
            );
        }
        assert_eq!(
            p.mul(&scalar_in(&reduced, endianness), endianness),
            Some(expected),
            "{name}: mul, {endianness:?}"
        );
    }
}

#[test]
fn eip2537_g1_mul() {
    for vector in load(&[
        include_str!("data/geth/blsG1Mul.json"),
        include_str!("data/eest/mul_G1_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, k) = input.split_at(EIP_G1_SIZE);
        let expected = g1_from_eip(&hex2bytes(&vector.expected)).unwrap();
        check_g1_mul(
            &vector.name,
            &g1_from_eip(p).unwrap(),
            &scalar_from_eip(k),
            &expected,
        );
    }
}

#[test]
fn eip2537_g1_mul_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG1Mul.json"),
        include_str!("data/eest/fail-mul_G1_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, k) = input.split_at(EIP_G1_SIZE);
        let p = g1_from_eip(p).unwrap();
        let k = reduce_scalar(&scalar_from_eip(k));
        for endianness in ENDIANNESS {
            assert_eq!(
                g1_in(&p, endianness).mul(&scalar_in(&k, endianness), endianness),
                None,
                "{} ({}): mul, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

#[test]
fn eip2537_g2_mul() {
    for vector in load(&[
        include_str!("data/geth/blsG2Mul.json"),
        include_str!("data/eest/mul_G2_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, k) = input.split_at(EIP_G2_SIZE);
        let expected = g2_from_eip(&hex2bytes(&vector.expected)).unwrap();
        check_g2_mul(
            &vector.name,
            &g2_from_eip(p).unwrap(),
            &scalar_from_eip(k),
            &expected,
        );
    }
}

#[test]
fn eip2537_g2_mul_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG2Mul.json"),
        include_str!("data/eest/fail-mul_G2_bls.json"),
    ]) {
        let input = hex2bytes(&vector.input);
        let (p, k) = input.split_at(EIP_G2_SIZE);
        let p = g2_from_eip(p).unwrap();
        let k = reduce_scalar(&scalar_from_eip(k));
        for endianness in ENDIANNESS {
            assert_eq!(
                g2_in(&p, endianness).mul(&scalar_in(&k, endianness), endianness),
                None,
                "{} ({}): mul, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

// ---------------------------------------------------------------------------
// G1MSM / G2MSM
// ---------------------------------------------------------------------------
//
// SIMD-0388 has no multi-scalar multiplication syscall, so the Ethereum
// vectors are evaluated as a sum of scalar multiplications. Like the
// precompile, every point must pass the full validation performed by `mul`.

fn parse_g1_msm(input: &[u8]) -> Vec<(G1Point, Scalar)> {
    input
        .chunks_exact(EIP_G1_SIZE + SCALAR_SIZE)
        .map(|pair| {
            let (p, k) = pair.split_at(EIP_G1_SIZE);
            (g1_from_eip(p).unwrap(), scalar_from_eip(k))
        })
        .collect()
}

fn parse_g2_msm(input: &[u8]) -> Vec<(G2Point, Scalar)> {
    input
        .chunks_exact(EIP_G2_SIZE + SCALAR_SIZE)
        .map(|pair| {
            let (p, k) = pair.split_at(EIP_G2_SIZE);
            (g2_from_eip(p).unwrap(), scalar_from_eip(k))
        })
        .collect()
}

fn g1_msm(pairs: &[(G1Point, Scalar)], endianness: Endianness) -> Option<G1Point> {
    let mut acc = G1Point::infinity(endianness);
    for (p, k) in pairs {
        let k = scalar_in(&reduce_scalar(k), endianness);
        let term = g1_in(p, endianness).mul(&k, endianness)?;
        acc = acc.add_unchecked(&term, endianness)?;
    }
    Some(acc)
}

fn g2_msm(pairs: &[(G2Point, Scalar)], endianness: Endianness) -> Option<G2Point> {
    let mut acc = G2Point::infinity(endianness);
    for (p, k) in pairs {
        let k = scalar_in(&reduce_scalar(k), endianness);
        let term = g2_in(p, endianness).mul(&k, endianness)?;
        acc = acc.add_unchecked(&term, endianness)?;
    }
    Some(acc)
}

#[test]
fn eip2537_g1_msm() {
    for vector in load(&[include_str!("data/eest/msm_G1_bls.json")]) {
        let pairs = parse_g1_msm(&hex2bytes(&vector.input));
        let expected = g1_from_eip(&hex2bytes(&vector.expected)).unwrap();
        for endianness in ENDIANNESS {
            assert_eq!(
                g1_msm(&pairs, endianness),
                Some(g1_in(&expected, endianness)),
                "{}: msm, {endianness:?}",
                vector.name
            );
        }
    }
}

#[test]
fn eip2537_g1_msm_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG1MultiExp.json"),
        include_str!("data/eest/fail-msm_G1_bls.json"),
    ]) {
        let pairs = parse_g1_msm(&hex2bytes(&vector.input));
        for endianness in ENDIANNESS {
            assert_eq!(
                g1_msm(&pairs, endianness),
                None,
                "{} ({}): msm, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

#[test]
fn eip2537_g2_msm() {
    for vector in load(&[include_str!("data/eest/msm_G2_bls.json")]) {
        let pairs = parse_g2_msm(&hex2bytes(&vector.input));
        let expected = g2_from_eip(&hex2bytes(&vector.expected)).unwrap();
        for endianness in ENDIANNESS {
            assert_eq!(
                g2_msm(&pairs, endianness),
                Some(g2_in(&expected, endianness)),
                "{}: msm, {endianness:?}",
                vector.name
            );
        }
    }
}

#[test]
fn eip2537_g2_msm_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsG2MultiExp.json"),
        include_str!("data/eest/fail-msm_G2_bls.json"),
    ]) {
        let pairs = parse_g2_msm(&hex2bytes(&vector.input));
        for endianness in ENDIANNESS {
            assert_eq!(
                g2_msm(&pairs, endianness),
                None,
                "{} ({}): msm, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}

// ---------------------------------------------------------------------------
// MAP_FP_TO_G1 / MAP_FP2_TO_G2
// ---------------------------------------------------------------------------
//
// SIMD-0388 has no hash-to-curve syscall, so the inputs cannot be replayed.
// The outputs are prime-order subgroup points produced by an independent
// implementation, which makes them known-good inputs for the validation and
// decompression syscalls.

#[test]
fn eip2537_map_fp_to_g1_outputs_validate_and_decompress() {
    for vector in load(&[
        include_str!("data/geth/blsMapG1.json"),
        include_str!("data/eest/map_fp_to_G1_bls.json"),
    ]) {
        let point = g1_from_eip(&hex2bytes(&vector.expected)).unwrap();
        let compressed = compress_g1(&point);
        for endianness in ENDIANNESS {
            let point = g1_in(&point, endianness);
            assert!(
                point.validate(endianness),
                "{}: validate, {endianness:?}",
                vector.name
            );
            assert_eq!(
                g1_compressed_in(&compressed, endianness).decompress(endianness),
                Some(point),
                "{}: decompress, {endianness:?}",
                vector.name
            );
        }
    }
}

#[test]
fn eip2537_map_fp2_to_g2_outputs_validate_and_decompress() {
    for vector in load(&[
        include_str!("data/geth/blsMapG2.json"),
        include_str!("data/eest/map_fp2_to_G2_bls.json"),
    ]) {
        let point = g2_from_eip(&hex2bytes(&vector.expected)).unwrap();
        let compressed = compress_g2(&point);
        for endianness in ENDIANNESS {
            let point = g2_in(&point, endianness);
            assert!(
                point.validate(endianness),
                "{}: validate, {endianness:?}",
                vector.name
            );
            assert_eq!(
                g2_compressed_in(&compressed, endianness).decompress(endianness),
                Some(point),
                "{}: decompress, {endianness:?}",
                vector.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// PAIRING
// ---------------------------------------------------------------------------

fn parse_pairing(input: &[u8]) -> (Vec<G1Point>, Vec<G2Point>) {
    input
        .chunks_exact(EIP_G1_SIZE + EIP_G2_SIZE)
        .map(|pair| {
            let (p, q) = pair.split_at(EIP_G1_SIZE);
            (g1_from_eip(p).unwrap(), g2_from_eip(q).unwrap())
        })
        .unzip()
}

#[test]
fn eip2537_pairing() {
    for vector in load(&[
        include_str!("data/geth/blsPairing.json"),
        include_str!("data/eest/pairing_check_bls.json"),
    ]) {
        let (g1, g2) = parse_pairing(&hex2bytes(&vector.input));
        let expected = hex2bytes(&vector.expected);
        assert_eq!(expected.len(), EIP_PAIRING_OUTPUT_SIZE);
        let (zeros, last) = expected.split_at(EIP_PAIRING_OUTPUT_SIZE - 1);
        assert!(zeros.iter().all(|&byte| byte == 0));
        let expected = match last[0] {
            0 => false,
            1 => true,
            other => panic!("{}: unexpected pairing output {other}", vector.name),
        };

        for endianness in ENDIANNESS {
            let g1: Vec<G1Point> = g1.iter().map(|p| g1_in(p, endianness)).collect();
            let g2: Vec<G2Point> = g2.iter().map(|q| g2_in(q, endianness)).collect();
            let result = pairing_check(&g1, &g2, endianness);
            if g1.len() > MAX_PAIRING_LENGTH {
                // Ethereum has no batch limit; Solana caps the batch size.
                assert_eq!(
                    result,
                    Err(Bls12381Error::TooManyPairs),
                    "{}: {} pairs, {endianness:?}",
                    vector.name,
                    g1.len()
                );
            } else {
                assert_eq!(
                    result,
                    Ok(expected),
                    "{}: pairing_check, {endianness:?}",
                    vector.name
                );
            }
        }
    }
}

#[test]
fn eip2537_pairing_rejects_invalid_points() {
    for vector in load_fail(&[
        include_str!("data/geth/fail-blsPairing.json"),
        include_str!("data/eest/fail-pairing_check_bls.json"),
    ]) {
        let (g1, g2) = parse_pairing(&hex2bytes(&vector.input));
        assert!(!g1.is_empty() && g1.len() <= MAX_PAIRING_LENGTH);
        for endianness in ENDIANNESS {
            let g1: Vec<G1Point> = g1.iter().map(|p| g1_in(p, endianness)).collect();
            let g2: Vec<G2Point> = g2.iter().map(|q| g2_in(q, endianness)).collect();
            assert_eq!(
                pairing_check(&g1, &g2, endianness),
                Err(Bls12381Error::InvalidInput),
                "{} ({}): pairing_check, {endianness:?}",
                vector.name,
                vector.expected_error
            );
        }
    }
}
