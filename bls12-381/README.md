# solana-bls12-381

A Rust library for BLS12-381 elliptic curve operations
on Solana, wrapping the native syscalls defined in
[SIMD-0388](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0388-bls12-381-syscalls.md).

This crate provides the standard interface for Solana program
developers to perform pairing-based cryptography, such as BLS signature
verification and zero-knowledge proof (e.g., Groth16) validation.

## Features

- **Zero-Copy Deserialization:** Types are `#[repr(transparent)]` and implement
  `bytemuck::Pod`. Developers can cast transaction instruction data directly
  into curve points without heap allocations.
- **CU-Optimized Mutations:** Provides `_assign` variants for all group
  operations (e.g., `add_assign`), allowing in-place memory mutations
  to strictly control Compute Unit (CU) consumption.
- **Safe & Unchecked APIs:** Exposes both fully validated group
  operations and `_unchecked` variants that skip subgroup checks for cheaper
  point accumulation.
- **Ergonomic Pairings:** Includes `pairing_check` for evaluating if the
  product of multiple pairings equals the identity element, avoiding costly
  target group (`Gt`) allocations in ZK verifiers.
- **Dual Endianness:** Full support for both Big-Endian (canonical Zcash/IETF
  standard) and Little-Endian memory layouts.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
solana-bls12-381 = "0.1.0"
```

### Zero-Copy Point Addition

```rust
use solana_bls12_381::{G1Point, Endianness};
use bytemuck;

// 1. Cast raw byte slices directly to G1Point references (Zero-Copy)
let p1: &G1Point = bytemuck::cast_ref(raw_bytes_1);
let p2: &G1Point = bytemuck::cast_ref(raw_bytes_2);

// 2. Allocate output buffer
let mut out = G1Point::infinity(Endianness::Little);

// 3. Perform safe, in-place addition
let success = p1.add_assign(p2, &mut out, Endianness::Little);
assert!(success);
```

### Multi-Pairing Check (e.g., BLS Signatures or ZK Proofs)

```rust
use solana_bls12_381::{G1Point, G2Point, pairing_check, Endianness};

let g1_points: &[G1Point] = get_g1_batch();
let g2_points: &[G2Point] = get_g2_batch();

// Evaluates e(P_1, Q_1) * ... * e(P_n, Q_n) == 1
let is_valid = pairing_check(g1_points, g2_points, Endianness::Big)
    .expect("Pairing execution failed");

assert!(is_valid);
```

### Security & Validation

All operations except the `_unchecked` variants
inherently perform full point validation. This includes checking that the
coordinates represent valid field elements, satisfy the curve equation, and
exist within the correct prime-order subgroup.
