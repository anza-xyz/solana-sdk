#!/usr/bin/env bash

set -eo pipefail

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"

cd "${src_root}"

no_std_crates=(
  -p solana-address
  -p solana-clock
  -p solana-define-syscall
  -p solana-fee-calculator
  -p solana-program-error
  -p solana-program-memory
  -p solana-rent
  -p solana-sanitize
  -p solana-signature
)
# Use the upstream BPF target, which doesn't support std, to make sure that our
# no_std support really works.
target="bpfel-unknown-none"

./cargo nightly check -Zbuild-std=core \
  "--target=$target" \
  --no-default-features \
  "${no_std_crates[@]}"
