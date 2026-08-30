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
  writes into a caller-supplied `MaybeUninit` buffer, saving ~36 CU per call
  and keeping large results off the 4KB stack.
- **Validated and unchecked APIs.** Group operations validate their operands by
  default; `_unchecked` variants skip the subgroup check for cheaper
  accumulation.
- **Pairing checks.** `pairing_check` tests whether a product of pairings is the
  identity without materializing a 576-byte `Gt` element, and refuses to
  succeed on an empty batch.
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

To reuse buffers across a loop, keep two `MaybeUninit` buffers and alternate
which one is the accumulator:

```rust
use solana_bls12_381::{G1Point, Endianness};
use core::mem::MaybeUninit;

let e = Endianness::Little;
let mut a = MaybeUninit::new(points[0]);
let mut b = MaybeUninit::uninit();

// Two additions per iteration, so the result lands back in `a` and no buffer
// ever has to move. The early returns are load-bearing: on failure the
// destination is poisoned and must not be read afterwards.
for pair in points[1..].chunks_exact(2) {
    // SAFETY: `a` is initialized, by `new` above and by the second add below.
    if !unsafe { a.assume_init_ref() }.add_assign_unchecked(&pair[0], &mut b, e) {
        return Err(ProgramError::InvalidArgument);
    }
    // SAFETY: the add above returned `true`, so `b` is initialized.
    if !unsafe { b.assume_init_ref() }.add_assign_unchecked(&pair[1], &mut a, e) {
        return Err(ProgramError::InvalidArgument);
    }
}

// SAFETY: `a` was initialized before the loop and stays initialized.
let total = unsafe { a.assume_init() };
```

Do **not** `core::mem::swap` the two buffers instead. Swapping two 96-byte
`G1Point`s is three `sol_memcpy_` syscalls, ~53 CU per iteration; over an
eight-point sum that is 374 CU on top of 988 CU of actual additions. Alternating
between two fixed buffers moves nothing. Handle an odd number of points with one
extra add after the loop, in whichever direction leaves the total where you want
it.

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

### Compute unit costs

The syscalls themselves are charged by the runtime, at the `bls12_381_*` rates
in `solana-program-runtime`'s execution budget. What this crate adds on top is
small, and depends only on how a result is returned:

| Wrapper                                                                                   | Added CU |
| ----------------------------------------------------------------------------------------- | -------- |
| `validate` — returns `bool`                                                               | 11       |
| `_assign` forms — write into a caller's `MaybeUninit`                                     | 14–16    |
| `pairing_map_assign`                                                                      | 16       |
| `pairing_check` — includes the `is_identity` comparison                                   | 69       |
| Allocating forms — `add_unchecked`, `sub_unchecked`, `neg_unchecked`, `mul`, `decompress` | 36–38    |

The allocating figure is the `Option<Self>` construction, not the byte copy: it
is the same whether the output is a 96-byte G1 point or a 576-byte `Gt`
element. Choosing an `_assign` form over its allocating counterpart therefore
saves ~36 CU per operation, whatever the type.

Purely local operations issue no syscall, so these figures are the whole cost:

| Local operation                                                       | CU |
| --------------------------------------------------------------------- | -- |
| Borrow from instruction data — `from_bytes_ref`, `bytemuck::cast_ref` | 2  |
| Copy — `from_bytes`                                                   | 18 |
| `Scalar::is_zero`                                                     | 13 |
| `is_infinity` — G1 / G2                                               | 29 / 28 |
| `GtElement::is_identity`                                              | 28 |

Array equality lowers to the `sol_memcmp_` syscall, whose charge does not depend
on the length. That is why comparing a 576-byte `Gt` element costs the same as
comparing a 96-byte point, and why folding those bytes into 64-bit words in the
VM instead is not faster.

For budgeting, the measured totals — runtime charge plus this crate's
overhead — of the operations most likely to dominate an instruction:

| Operation                                                    | CU                                  |
| ------------------------------------------------------------ | ----------------------------------- |
| `validate` — G1 / G2                                         | 1,576 / 1,977                       |
| `add_assign_unchecked` — G1 / G2                             | 144 / 219                           |
| `add_unchecked` (allocating) — G1                            | 180                                 |
| `add_assign` (validated) — G1                                | 3,300                               |
| `neg_assign_unchecked` — G1                                  | 143                                 |
| `mul_assign` — G1                                            | 4,642                               |
| `decompress_assign` — G1 / G2                                | 2,114 / 3,063                       |
| `pairing_check` — 1 / 2 / 3 / 8 pairs                        | 25,514 / 38,536 / 51,559 / 116,675  |
| Sum of 8 untrusted G1 points, validated once, in place       | 13,586                              |
| Sum of 8 untrusted G2 points, validated once, in place       | 17,335                              |

These are net of a no-op instruction, so add your own entrypoint and
instruction parsing on top. Everything here fits inside the 200,000 CU default
instruction limit: a three-pair Groth16 check leaves ~148,000 CU for the rest
of the instruction, and even an eight-pair batch leaves ~83,000.

#### Designing around the costs

**Do not `validate` a point you are about to multiply or pair.** The
multiplication and pairing syscalls run the full field, curve-equation and
subgroup check on every input themselves, so a `validate` beforehand buys
nothing and costs 1,576 CU per G1 point and 1,977 per G2 point. Validating a
point before `mul_assign` measures 6,219 CU against 4,642 for the multiplication
alone; validating two G1 and two G2 points before a two-pair `pairing_check`
measures 45,643 against 38,536. `add_assign_unchecked` and
`sub_assign_unchecked` are the exception — those check the field and the curve
equation but skip the subgroup check, which is exactly what `validate` adds.

**Batch your pairings.** Only the first pair in a batch is charged at
`bls12_381_one_pair_cost`; every additional pair is charged at
`bls12_381_additional_pair_cost`, roughly half as much. A three-pair check
issued as one batch measures 51,559 CU against 76,539 as three separate calls —
24,980 CU saved.

**Validate at the trust boundary, not in the loop.** The validation syscall is
charged at roughly twelve times the addition syscall it guards. Summing eight
points with `add_assign` re-validates the accumulator every iteration: 23,397 CU
against 13,586 for validating the eight inputs once and accumulating with
`add_assign_unchecked`. The fraction grows with batch size.

**Alternate two buffers instead of swapping them.** `core::mem::swap` on two
`MaybeUninit<G1Point>`s is three `sol_memcpy_` syscalls. Over an eight-point sum
the swapping loop measures 1,362 CU against 988 for the alternating loop shown
above — 374 CU, 27% of the accumulation.

**Prefer the `_assign` forms in loops.** Each call avoids the ~36 CU the
allocating form spends constructing its `Option<Self>`.

**Take points uncompressed when you can afford the bytes.** Decompression
validates, so it replaces rather than adds to a `validate` — but it costs 2,114
CU against 1,576. Eight uncompressed points cost 13,586 CU to validate and sum;
the same eight compressed cost 17,830. That is 4,244 CU for 384 bytes of
instruction data.

**Put the many-element side of the protocol in G1.** Every G1 operation is
cheaper than its G2 counterpart: 1,576 against 1,977 to validate, 144 against
219 to add, 2,114 against 3,063 to decompress. Aggregating eight points costs
13,586 CU in G1 and 17,335 in G2.

**Endianness is free.** The runtime charges the same for the `_LE` and `_BE`
curve IDs, and selecting between them costs nothing measurable in the wrapper.
Pick whichever matches your data.

Borrowing a point out of instruction data costs 2 CU and copying one costs 18.
Neither is worth optimizing against a 128 CU addition syscall, let alone a
25,445 CU pairing.

### Validation

Group operations validate both operands by default: the coordinates are checked
to be field elements, the point to satisfy the curve equation, and the point to
lie in the prime-order subgroup. The `_unchecked` variants skip these checks.
Multiplication, decompression and the pairing operations are validated by the
syscall itself and have no `_unchecked` variant — calling `validate` before one
of them pays for the same work twice.

More precisely, of the checks `validate` performs:

| Operation                                | Field | Curve equation | Subgroup |
| ---------------------------------------- | ----- | -------------- | -------- |
| `validate`                               | yes   | yes            | yes      |
| `add_assign_unchecked`, `sub_*_unchecked`| yes   | yes            | no       |
| `mul_assign`                             | yes   | yes            | yes      |
| `decompress_assign`                      | yes   | yes            | yes      |
| `pairing_map_assign`, `pairing_check`    | yes   | yes            | yes      |

So the only thing `validate` adds over an `_unchecked` group operation is the
subgroup check — and that is the expensive part.

The subgroup check dominates the cost: the validation syscall is charged at
roughly twelve times the addition syscall it guards. Since the subgroup is closed under
addition, an accumulator built from validated points remains valid: validate at
the trust boundary and accumulate with `add_assign_unchecked`.

### Aliasing

SIMD-0388 does not specify whether the result pointer of a syscall may alias an
input pointer. This crate is unaffected either way: every `_assign` method takes
`&self` alongside `&mut MaybeUninit<Self>`, so an aliasing call cannot be
expressed in safe Rust.
