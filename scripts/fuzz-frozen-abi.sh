#!/usr/bin/env bash
#
# Runs Bolero fuzzers for frozen abi targets with specified strategy `fuzz-bolero`.
#
# Usage:
#   scripts/fuzz-frozen-abi.sh [target ...] [-- cargo-bolero-arg ...]
#
# When no target is given, the script finds all
# *_frozen_abi_fuzzer::test_fuzzer_* targets in the workspace and splits
# TOTAL_FUZZ_TIME between them.

# Example:
#
# RUST_MIN_STACK=16777216 TOTAL_FUZZ_TIME=60s scripts/fuzz-frozen-abi.sh \
#   'stable_abi::impls::tests::bolero_fuzzer::TestFuzzerFeed_frozen_abi_fuzzer::test_fuzzer_wincode' \
#   -- --package solana-frozen-abi \
#      --max-input-length 64 \
#      --corpus-dir __fuzz__/corpus \
#      --crashes-dir __fuzz__/crashes
#
# Environment variables:
#   TOTAL_FUZZ_TIME  Total fuzzing time in seconds, optionally suffixed with "s"
#                    (default: 120s). Build/preparation time is not counted.
#   RUST_MIN_STACK   Rust stack size used by fuzz runs (default: 16777216).
#
set -euo pipefail
cd "$(dirname "$0")/.."

export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"

duration="${TOTAL_FUZZ_TIME:-120s}"

bolero_common_args=(
  --features fuzz-bolero
  --rustc-bootstrap
)

targets=()
bolero_extra_args=()

while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    bolero_extra_args=("$@")
    break
  fi
  targets+=("$1")
  shift
done

if ((${#targets[@]} == 0)); then
  echo "listing fuzz targets from workspace" >&2
  mapfile -t targets < <(
    cargo bolero list --workspace "${bolero_common_args[@]}" |
      sed -nE 's/.*"test":"([^"]*_frozen_abi_fuzzer::test_fuzzer_[^"]+)".*/\1/p'
  )
fi

if ((${#targets[@]} == 0)); then
  echo "no fuzzer targets found" >&2
  exit 1
fi

remaining_duration="$((10#${duration%s}))"
remaining_targets="${#targets[@]}"

echo "found ${#targets[@]} fuzz targets" >&2

for target in "${targets[@]}"; do
  if ((remaining_duration == 0)); then
    echo "skipping $target (fuzz time exhausted)"
    remaining_targets="$((remaining_targets - 1))"
    continue
  fi

  duration="$(((remaining_duration + remaining_targets - 1) / remaining_targets))s"
  remaining_duration="$((remaining_duration - ${duration%s}))"
  remaining_targets="$((remaining_targets - 1))"

  bolero_test_args=(
    "${bolero_common_args[@]}"
  )

  if ((${#bolero_extra_args[@]} > 0)); then
    bolero_test_args+=("${bolero_extra_args[@]}")
  fi

  echo "preparing $target"
  prepare_command=(cargo bolero test "${bolero_test_args[@]}" --runs 0 "$target")
  "${prepare_command[@]}"

  echo "fuzzing $target for $duration"

  fuzz_command=(cargo bolero test "${bolero_test_args[@]}" -T "$duration" "$target")

  if timeout "$duration" "${fuzz_command[@]}"; then
    :
  else
    status="$?"
    if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
      echo "fuzzing $target reached $duration"
    else
      exit "$status"
    fi
  fi
done
