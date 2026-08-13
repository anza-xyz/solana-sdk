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
  operations (e.g., `add_assign`), which write into a caller-supplied
  `MaybeUninit` buffer to strictly control Compute Unit (CU) consumption.
- **Validated & Unchecked APIs:** Group operations validate their operands by
  default, with `_unchecked` variants that skip subgroup checks for cheaper
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
use core::mem::MaybeUninit;
use bytemuck;

// 1. Cast raw byte slices directly to G1Point references (Zero-Copy)
let p1: &G1Point = bytemuck::cast_ref(raw_bytes_1);
let p2: &G1Point = bytemuck::cast_ref(raw_bytes_2);

// 2. Reserve an output buffer. It is never read before being written, so it
//    does not need to be initialized.
let mut out = MaybeUninit::uninit();

// 3. Perform validated, in-place addition
let success = p1.add_assign(p2, &mut out, Endianness::Little);
assert!(success);

// SAFETY: `add_assign` returned `true`, so every byte of `out` was written.
let sum = unsafe { out.assume_init() };
```

Every `_assign` method follows the same contract: on `true` the output buffer
is fully initialized and may be `assume_init`ed; on `false` it is left
untouched and must not be assumed initialized.

To recycle buffers across a loop, keep the accumulator in a `MaybeUninit` and
swap the two buffers each iteration:

```rust
use solana_bls12_381::{G1Point, Endianness};
use core::mem::MaybeUninit;

let e = Endianness::Little;
let mut acc = MaybeUninit::new(G1Point::infinity(e));
let mut scratch = MaybeUninit::uninit();

for p in points {
    // SAFETY: `acc` is initialized, by `new` above and by the swap below.
    let lhs = unsafe { acc.assume_init_ref() };
    if !lhs.add_assign_unchecked(p, &mut scratch, e) {
        return Err(ProgramError::InvalidArgument);
    }
    core::mem::swap(&mut acc, &mut scratch);
}

// SAFETY: `acc` was initialized before the loop and stays initialized.
let total = unsafe { acc.assume_init() };
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

All group operations except the `_unchecked` variants, along with
multiplication and decompression, inherently perform full point validation.
This includes checking that the coordinates represent valid field elements,
satisfy the curve equation, and exist within the correct prime-order subgroup.
