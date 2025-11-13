#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

./cargo nightly hack --features frozen-abi --ignore-unknown-features test --lib -- test_abi_ --nocapture
