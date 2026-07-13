#!/usr/bin/env bash
#
# Runs Bolero fuzzers for targets enabled thru frozen abi with fuzzing strategy set.
#
# Usage:
#   scripts/fuzz-frozen-abi.sh [target ...]
#
# Positional arguments:
#   target          Optional cargo-bolero test target name. When omitted, the
#                   script discovers all *_frozen_abi_fuzzer::test_fuzzer_*
#                   targets in PACKAGE and splits FUZZ_TIME across them.
#
# Environment variables:
#   FUZZ_TIME       Total fuzzing time in seconds, optionally suffixed with "s"
#                   (default: 240s). Build/preparation time is not counted.
#   FUZZ_DIR        Root directory for generated corpus and crashes
#                   (default: __fuzz__).
#   PACKAGE         Cargo package to scan and fuzz
#                   (default: solana-frozen-abi).
#   MAX_INPUT_LEN   Value passed to --max-input-length (default: MAX_LEN or
#                   2048).
#   RUST_MIN_STACK  Rust stack size used by fuzz runs (default: 16777216).
#   ASAN_OPTIONS    AddressSanitizer options (default: detect_leaks=0).
#   LSAN_OPTIONS    LeakSanitizer options (default: detect_leaks=0).
#
set -euo pipefail
cd "$(dirname "$0")/.."

export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

# FUZZ_TIME controls total fuzzing time, split across selected targets.
# Compilation and preparation runs are not counted.
duration="${FUZZ_TIME:-240s}"

fuzz_root="${FUZZ_DIR:-__fuzz__}"
package="${PACKAGE:-solana-frozen-abi}"
max_input_len="${MAX_INPUT_LEN:-${MAX_LEN:-2048}}"

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

remaining_duration="$((10#${duration%s}))"
remaining_targets="${#targets[@]}"

echo "found ${#targets[@]} fuzz targets" >&2

for target in "${targets[@]}"; do
  if ((remaining_duration == 0)); then
    echo "skipping $package::$target (fuzz time exhausted)"
    remaining_targets="$((remaining_targets - 1))"
    continue
  fi

  duration="$(((remaining_duration + remaining_targets - 1) / remaining_targets))s"
  remaining_duration="$((remaining_duration - ${duration%s}))"
  remaining_targets="$((remaining_targets - 1))"

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

  echo "preparing $package::$target"
  cargo bolero test "$target" "${bolero_test_args[@]}" --runs 0

  echo "fuzzing $package::$target for $duration${max_input_len:+ max_input_len=$max_input_len}"

  if timeout "$duration" cargo bolero test "$target" "${bolero_test_args[@]}" -T "$duration"; then
    :
  else
    status="$?"
    if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
      echo "fuzzing $package::$target reached $duration"
    else
      exit "$status"
    fi
  fi
done
