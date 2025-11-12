#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

packages=$(./cargo nightly metadata --no-deps --format-version=1 | jq -r '.packages[] | select(.features | has("frozen-abi")) | .name')
for package in $packages; do
  echo "::group::./cargo nightly test -p $package --features frozen-abi --lib -- test_abi_ --nocapture"
  ./cargo nightly test -p "$package" --features frozen-abi --lib -- test_abi_ --nocapture
  echo "::endgroup::"
done
