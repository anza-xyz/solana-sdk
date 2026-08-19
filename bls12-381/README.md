# solana-bls12-381

BLS12-381 elliptic curve operations for Solana programs, wrapping the native
syscalls defined in
[SIMD-0388](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0388-bls12-381-syscalls.md).

Intended for on-chain pairing-based cryptography: BLS signature verification
and zero-knowledge proof (e.g. Groth16) validation.

## Features

- **Zero-copy deserialization.** Types are `#[repr(transparent)]` and implement
  `bytemuck::Pod`, so instruction data can be cast directly into curve points
  without allocation.
- **In-place operations.** Every group operation has an `_assign` variant that
  writes into a caller-supplied `MaybeUninit` buffer, bounding compute unit
  consumption.
- **Validated and unchecked APIs.** Group operations validate their operands by
  default; `_unchecked` variants skip the subgroup check for cheaper
  accumulation.
- **Pairing checks.** `pairing_check` tests whether a product of pairings is the
  identity without materializing a 576-byte `Gt` element.
- **Dual endianness.** Big-endian (the canonical Zcash/IETF encoding) and
  little-endian layouts.

## Usage

```toml
[dependencies]
solana-bls12-381 = "0.1.0"
```

The `bytemuck` feature is enabled by default and provides the `Pod` and
`Zeroable` implementations used for zero-copy casting. On-chain builds that do
not need them can set `default-features = false`. Off-chain builds always
include them, since the host implementation depends on them internally.

### Zero-copy point addition

```rust
use solana_bls12_381::{G1Point, Endianness};
use core::mem::MaybeUninit;

// Cast raw instruction data directly to `G1Point` references.
let p1: &G1Point = bytemuck::cast_ref(raw_bytes_1);
let p2: &G1Point = bytemuck::cast_ref(raw_bytes_2);

// The output buffer is never read before it is written, so it does not need
// to be initialized.
let mut out = MaybeUninit::uninit();

let success = p1.add_assign(p2, &mut out, Endianness::Little);
assert!(success);

// SAFETY: `add_assign` returned `true`, so `out` is fully initialized.
let sum = unsafe { out.assume_init() };
```

### Output buffer contract

Every `_assign` method follows the same contract:

- On `true`, the output buffer is fully initialized and may be `assume_init`ed.
- On `false`, it must be treated as uninitialized and must not be read, **even
  if it held a valid value before the call**. A failed operation may write part
  of the buffer before detecting the error, so any prior contents are no longer
  guaranteed to be valid.

Permitting `assume_init` on `true` requires that the syscall wrote every byte of
the buffer, since reading an uninitialized byte is undefined behavior.
SIMD-0388 does not state this. The guarantee instead follows from consensus: the
result buffer is observable to the program — its contents can be logged,
returned, or fed into a later syscall — so an implementation that left a byte
unwritten would produce a different program result from Agave and fork the
network. `test_success_writes_full_buffer` pins the property.

Nothing constrains what a _failing_ syscall leaves in the buffer, hence the
poisoning rule above rather than a guarantee that the buffer is left untouched.

To reuse buffers across a loop, keep the accumulator in a `MaybeUninit` and swap
the two buffers each iteration:

```rust
use solana_bls12_381::{G1Point, Endianness};
use core::mem::MaybeUninit;

let e = Endianness::Little;
let mut acc = MaybeUninit::new(G1Point::infinity(e));
let mut scratch = MaybeUninit::uninit();

for p in points {
    // SAFETY: `acc` is initialized, by `new` above and by the swap below.
    let lhs = unsafe { acc.assume_init_ref() };
    // The early return is load-bearing: on failure `scratch` is poisoned and
    // must not be swapped into `acc` or read afterwards.
    if !lhs.add_assign_unchecked(p, &mut scratch, e) {
        return Err(ProgramError::InvalidArgument);
    }
    core::mem::swap(&mut acc, &mut scratch);
}

// SAFETY: `acc` was initialized before the loop and stays initialized.
let total = unsafe { acc.assume_init() };
```

### Multi-pairing check (BLS signatures, ZK proofs)

```rust
use solana_bls12_381::{G1Point, G2Point, pairing_check, Endianness};

let g1_points: &[G1Point] = get_g1_batch();
let g2_points: &[G2Point] = get_g2_batch();

// Evaluates e(P_1, Q_1) * ... * e(P_n, Q_n) == 1
if pairing_check(g1_points, g2_points, Endianness::Big) != Ok(true) {
    return Err(ProgramError::InvalidArgument);
}
```

`pairing_check` returns `Err` when the check could not be run at all —
mismatched or over-long batches, an empty batch, or an invalid point. `Err` is
not the same as "verification failed", but both must be treated as failure.
Compare against `Ok(true)` as above; never branch on `.is_ok()`.

`pairing_check` rejects an empty batch, while `pairing_map` returns the identity
for one as the syscall requires. The divergence is deliberate: `pairing_check` is
a verification primitive whose inputs are typically built from
attacker-controlled instruction data, and a zero-length batch that reported
`Ok(true)` would be a verification bypass. For the empty product, call
`pairing_map` and compare against `GtElement::identity`.

### Validation

Group operations validate both operands by default: the coordinates are checked
to be field elements, the point to satisfy the curve equation, and the point to
lie in the prime-order subgroup. The `_unchecked` variants skip these checks.
Multiplication and decompression are validated by the syscall itself and have no
`_unchecked` variant.

The subgroup check dominates the cost. Since the subgroup is closed under
addition, an accumulator built from validated points remains valid: validate at
the trust boundary and accumulate with `add_assign_unchecked`.

### Aliasing

SIMD-0388 does not specify whether the result pointer of a syscall may alias an
input pointer. This crate is unaffected either way: every `_assign` method takes
`&self` alongside `&mut MaybeUninit<Self>`, so an aliasing call cannot be
expressed in safe Rust.
