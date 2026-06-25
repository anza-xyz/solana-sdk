#!/usr/bin/env bash
#
# example: FUZZ_DIR=/tmp/fuzz-test MAX_INPUT_LEN=16 FUZZ_TIME=1s ./scripts/fuzz-frozen-abi.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

duration="${FUZZ_TIME:-30s}"
fuzz_root="${FUZZ_DIR:-__fuzz__}"
package="${PACKAGE:-solana-frozen-abi}"
max_input_len="${MAX_INPUT_LEN:-${MAX_LEN:-}}"

bolero_args=(
  --package "$package"
  --features fuzz-bolero
  --rustc-bootstrap
)

targets=()
if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  echo "listing fuzz targets from $package" >&2
  mapfile -t targets < <(
    cargo bolero list "${bolero_args[@]}" |
      sed -nE 's/.*"test":"([^"]*_frozen_abi_fuzzer::test_fuzzer_[^"]+)".*/\1/p'
  )
fi

if ((${#targets[@]} == 0)); then
  echo "no fuzzer targets found for $package" >&2
  exit 1
fi

echo "found ${#targets[@]} fuzz targets" >&2

for target in "${targets[@]}"; do
  target_dir="${target//::/__}"
  work_dir="$fuzz_root/$package/$target_dir"

  bolero_test_args=(
    "${bolero_args[@]}"
    --corpus-dir "$work_dir/corpus"
    --crashes-dir "$work_dir/crashes"
  )

  if [[ -n "$max_input_len" ]]; then
    bolero_test_args+=(--max-input-length "$max_input_len")
  fi

  echo "fuzzing $package::$target for $duration${max_input_len:+ max_input_len=$max_input_len}"

  cargo bolero test "$target" "${bolero_test_args[@]}" -T "$duration"
done
