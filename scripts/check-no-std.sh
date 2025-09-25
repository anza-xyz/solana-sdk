#!/usr/bin/env bash

set -eo pipefail

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"

cd "${src_root}"

no_std_crates=(
  -p solana-address
  -p solana-account-view
  -p solana-blake3-hasher
  -p solana-clock
  -p solana-cluster-type
  -p solana-commitment-config
  -p solana-define-syscall
  -p solana-epoch-info
  -p solana-epoch-rewards
  -p solana-epoch-schedule
  -p solana-epoch-stake
  -p solana-fee-calculator
  -p solana-hash
  -p solana-keccak-hasher
  -p solana-msg
  -p solana-program-error
  -p solana-program-log
  -p solana-program-log-macro
  -p solana-program-memory
  -p solana-pubkey
  -p solana-rent
  -p solana-sanitize
  -p solana-sdk-ids
  -p solana-sha256-hasher
  -p solana-signature
  -p solana-sysvar-id
  -p solana-system-interface
)
# Use the upstream BPF target, which doesn't support std, to make sure that our
# no_std support really works.
target="bpfel-unknown-none"

# These features require alloc
exclude_features_no_alloc="alloc,borsh,curve25519,serde"
# These features never work on upstream BPF
exclude_features="atomic,bincode,default,dev-context-only-utils,frozen-abi,rand,std,verify"

./cargo nightly hack check \
  -Zbuild-std=core \
  "--target=$target" \
  "--exclude-features=${exclude_features},${exclude_features_no_alloc}" \
  --each-feature \
  "${no_std_crates[@]}"

# Check that all crates with features that work with no_std + alloc still work!
./cargo nightly hack check \
  -Zbuild-std=alloc,core \
  "--target=${target}" \
  "--exclude-features=${exclude_features}" \
  --each-feature \
  "${no_std_crates[@]}"
