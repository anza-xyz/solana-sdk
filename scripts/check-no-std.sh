#!/usr/bin/env bash

set -eo pipefail

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"

cd "${src_root}"

no_std_crates=(
  -p solana-address
  -p solana-clock
  -p solana-commitment-config
  -p solana-define-syscall
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
