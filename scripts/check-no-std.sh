#!/usr/bin/env bash

set -eo pipefail

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"

cd "${src_root}"

no_std_crates=(
  -p solana-hash
  -p solana-sanitize
)
# Use the upstream BPF target, which doesn't support std, to make sure that our
# no_std support really works.
target="bpfel-unknown-none"

# pacify shellcheck: cannot follow dynamic path
# shellcheck disable=SC1090,SC1091
source "$here"/rust-version.sh nightly
# pacify shellcheck: cannot follow sourced variables
# shellcheck disable=SC2154
rustup component add rust-src "--toolchain=$rust_nightly"
./cargo nightly check -Zbuild-std=core \
  "--target=$target" \
  --no-default-features \
  "${no_std_crates[@]}"
