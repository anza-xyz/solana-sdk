# BLS12-381 test vectors

Known-answer tests for the EIP-2537 BLS12-381 precompiles, used by
`bls12-381/tests/ethereum_vectors.rs` to check the SIMD-0388 syscalls against
Ethereum. Ethereum's byte layout differs from Solana's (64-byte padded field
elements, all-zero infinity, `c0` before `c1` in `Fq2`), so the test converts
each vector at run time rather than storing a Solana-specific copy. It also
derives the little-endian Solana encoding from the big-endian one.

Every file is a byte-for-byte copy of its upstream counterpart, except the
two MSM files noted below. Keep them that way so they can be re-synchronised
with a plain copy.

## `geth/`

`core/vm/testdata/precompiles/` from go-ethereum `v1.17.5`.

| Positive | Failing |
| --- | --- |
| `blsG1Add.json`, `blsG2Add.json` | `fail-blsG1Add.json`, `fail-blsG2Add.json` |
| `blsG1Mul.json`, `blsG2Mul.json` | `fail-blsG1Mul.json`, `fail-blsG2Mul.json` |
| | `fail-blsG1MultiExp.json`, `fail-blsG2MultiExp.json` |
| `blsMapG1.json`, `blsMapG2.json` | `fail-blsMapG1.json`, `fail-blsMapG2.json` |
| `blsPairing.json` | `fail-blsPairing.json` |

The positive MSM files (`blsG1MultiExp.json`, `blsG2MultiExp.json`) are not
included; at several megabytes each they are dominated by vectors with
hundreds or thousands of pairs. The execution-spec-tests MSM vectors below
cover the same operation.

## `eest/`

`tests/prague/eip2537_bls_12_381_precompiles/vectors/` from
`ethereum/execution-spec-tests` at commit
`10eaa63d5da2f50b63d4359968f36542212f9f50`.

| Positive | Failing |
| --- | --- |
| `add_G1_bls.json`, `add_G2_bls.json` | `fail-add_G1_bls.json`, `fail-add_G2_bls.json` |
| `mul_G1_bls.json`, `mul_G2_bls.json` | `fail-mul_G1_bls.json`, `fail-mul_G2_bls.json` |
| `msm_G1_bls.json`, `msm_G2_bls.json` (filtered) | `fail-msm_G1_bls.json`, `fail-msm_G2_bls.json` |
| `map_fp_to_G1_bls.json`, `map_fp2_to_G2_bls.json` | `fail-map_fp_to_G1_bls.json`, `fail-map_fp2_to_G2_bls.json` |
| `pairing_check_bls.json` | `fail-pairing_check_bls.json` |

`msm_G1_bls.json` and `msm_G2_bls.json` keep only the upstream vectors with at
most eight pairs (22 of 163 and 23 of 164 respectively); the rest are gas
discount-table vectors that grow to 149 pairs. The failing files are
supersets of go-ethereum's for most operations, and both are exercised.

## What the tests skip

- Failing vectors whose `ExpectedError` is `invalid input length` or
  `invalid field element top bytes`. Both describe the EIP-2537 byte layout and
  cannot be expressed in the Solana encoding.
- The inputs of the `map_fp_to_G1` / `map_fp2_to_G2` vectors: SIMD-0388 has no
  hash-to-curve syscall. Their outputs are used as known-good subgroup points
  for the validation and decompression syscalls.
- Pairing vectors with more than eight pairs are only checked to be rejected
  with `TooManyPairs`.

## Deliberate divergences exercised by the tests

- EIP-2537 reduces scalars modulo the group order; SIMD-0388 rejects a scalar
  at or above it. The `*_unnormalized_scalar` vectors check both behaviours.
- EIP-2537 has no upper bound on the number of pairs in a pairing check;
  SIMD-0388 allows at most eight.
