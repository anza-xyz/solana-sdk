#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

build_sbf_excludes=(
  --exclude solana-client-traits
  --exclude solana-ed25519-program
  --exclude solana-example-mocks
  --exclude solana-file-download
  --exclude solana-genesis-config
  --exclude solana-keypair
  --exclude solana-offchain-message
  --exclude solana-presigner
  --exclude solana-sdk-wasm-js
  --exclude solana-sdk-wasm-js-tests
  --exclude solana-secp256k1-program
  --exclude solana-secp256r1-program
  --exclude solana-system-transaction
  --exclude solana-system-wasm-js
  --exclude solana-transaction
  --exclude solana-sdk
)

./cargo nightly hack --workspace "${build_sbf_excludes[@]}" build-sbf

# This can be added back in once the SDK upgrades to v2.3 of Agave tools
#./cargo nightly build-sbf --manifest-path sdk/Cargo.toml --no-default-features
