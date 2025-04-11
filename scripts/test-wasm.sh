#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

for dir in program-wasm sdk ; do
  (
    cd "$dir"
    npm install
    npm test
  )
done
