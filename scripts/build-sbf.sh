#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

exclude_list=(
  ".github"
  "scripts"
  "client-traits"
  "ed25519-program"
  "example-mocks"
  "file-download"
  "genesis-config"
  "keypair"
  "logger"
  "offchain-message"
  "presigner"
  "quic-definitions"
  "rent-collector"
  "sdk-wasm-js"
  "secp256k1-program"
  "secp256r1-program"
  "system-transaction"
  "transaction"
)

for dir in $(git ls-tree -d --name-only HEAD .); do
  if [[ ! " ${exclude_list[*]} " =~ [[:space:]]${dir}[[:space:]] ]]; then
    (cd "$dir" && RUSTFLAGS="-Dwarnings" cargo build-sbf)
  fi
done
