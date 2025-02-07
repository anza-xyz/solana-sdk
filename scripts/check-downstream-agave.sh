#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

rm -rf ./target/downstream/agave
mkdir -p ./target/downstream
cd ./target/downstream
git clone --depth 1 https://github.com/anza-xyz/agave.git --single-branch --branch=master
cd ./agave

../../../scripts/patch-crates-no-header.sh . ../../..
cargo check
