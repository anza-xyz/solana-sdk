#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

./cargo nightly hack --features frozen-abi --ignore-unknown-features test --lib -- test_abi_digest --nocapture
./cargo nightly hack --features frozen-abi --ignore-unknown-features test --lib -- test_api_digest --nocapture

# `stable-abi` trades the api digester for building on stable Rust
./cargo stable test -p solana-frozen-abi --features stable-abi --lib
./cargo stable test -p solana-frozen-abi-macro --no-default-features --features stable-abi --lib
