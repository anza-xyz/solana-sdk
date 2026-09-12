# BN254 test vectors

Known-answer tests used by the integration tests in `bn254/tests/`. All of
the G1 and pairing vectors come from Ethereum, whose `alt_bn128` precompiles
(EIP-196 `ecadd`/`ecmul`, EIP-197 `ecpairing`) share their input and output
encodings with the big-endian Solana syscalls. The tests derive the
little-endian inputs from the big-endian ones.

## go-ethereum precompile vectors

| File | Upstream file (`core/vm/testdata/precompiles/`) |
| --- | --- |
| `addition_cases.json` | `bn256Add.json` |
| `multiplication_cases.json` | `bn256ScalarMul.json` |
| `pairing_cases.json` | `bn256Pairing.json` |

Verbatim copies of go-ethereum `v1.17.5` (the files were last changed upstream
in commit `a3cd8a040a4ffe04a7b455f11a6c049a9b29b1c5`). Keep them byte-for-byte
identical to upstream so that they can be re-synchronised with a plain copy.

Several `bn256Add.json` vectors (`cdetrio5`, `cdetrio7`, `cdetrio10`,
`cdetrio12`, `cdetrio14`) have 192-byte inputs. Ethereum ignores the bytes
beyond the nominal 128, Solana rejects them; the test helpers in
`tests/common/mod.rs` assert the rejection and then check the arithmetic on
the truncated input.

## Ethereum state test vectors

| File | Source tests |
| --- | --- |
| `eth_state_addition_cases.json` | `stZeroKnowledge2/ecadd_*` |
| `eth_state_multiplication_cases.json` | `stZeroKnowledge/ecmul_*`, `stZeroKnowledge2/ecmul_*` |
| `eth_state_pairing_cases.json` | `stZeroKnowledge/ecpairing_*` |

Derived from the `GeneralStateTests/stZeroKnowledge*` fillers of
`ethereum/tests`, which now live in `ethereum/execution-spec-tests` under
`tests/static/state_tests/` (taken at commit
`10eaa63d5da2f50b63d4359968f36542212f9f50`). These are the only Ethereum
vectors that cover *rejected* inputs: points off the curve, unreduced field
elements, G2 points outside the prime-order subgroup and bad input lengths.

Each state test calls the precompile from a helper contract with the input
taken from the transaction data and stores `keccak256(output)` in storage
slot 0; if the precompile fails the transaction reverts. The JSON rows were
produced as follows:

1. The precompile input was decoded from the ABI-encoded transaction data.
   Tests that differ only in the gas supplied (`_21000_` vs `_25000_`/`_28000_`
   variants) collapse to a single row named after the `_21000_` variant.
2. The input was run through go-ethereum `v1.17.5` and through `revm-precompile`
   `43.0.2`; both clients agreed on every input.
3. Wherever the state test pins the result, the client output was checked
   against it: a successful vector must hash to the stored value and a
   failed vector must leave storage unchanged.

A row's `Expected` is the hex-encoded precompile output, or `null` when the
Ethereum precompile fails on the input. Vectors with inputs longer than the
nominal size (`ecadd_*_192`, `ecmul_*_128`) are handled like the go-ethereum
ones above.

The `pointAdd*`, `pointMulAdd*` and `pairingTest` state tests use different
helper contracts and are not included.

## G2 vectors

`addition_g2_cases.json` and `multiplication_g2_cases.json` are Solana-only
vectors: Ethereum has no G2 precompiles for this curve.
