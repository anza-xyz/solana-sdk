#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

export RUSTDOCFLAGS="-D warnings"
./cargo nightly hack doc --all-features --no-deps
