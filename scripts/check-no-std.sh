#!/usr/bin/env bash

set -eo pipefail

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"

cd "${src_root}"

# Crates have a major version specified to avoid conflicts with
# re-exported crates.
no_std_crates=(
  -p solana-address@1
  -p solana-clock
  -p solana-commitment-config
  -p solana-define-syscall@3
  -p solana-epoch-info
  -p solana-fee-calculator
  -p solana-msg
  -p solana-program-error
  -p solana-program-log
  -p solana-program-log-macro
  -p solana-program-memory
  -p solana-rent
  -p solana-sanitize
  -p solana-sdk-ids
  -p solana-signature
  -p solana-sysvar-id
  -p solana-system-interface
)
# Use the upstream BPF target, which doesn't support std, to make sure that our
# no_std support really works.
target="bpfel-unknown-none"

./cargo nightly check -Zbuild-std=core \
  "--target=$target" \
  --no-default-features \
  "${no_std_crates[@]}"

# Check that all crates with features that work with no_std + alloc still work!
./cargo nightly check -Zbuild-std=alloc,core \
  "--target=${target}" \
  --no-default-features \
  --features "decode, error, sanitize, syscalls, borsh, serde, bytemuck, alloc" \
  "${no_std_crates[@]}"
