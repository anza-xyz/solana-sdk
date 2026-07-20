#!/usr/bin/env bash
#
# Environment variables:
#   TOTAL_FUZZ_TIME  Total fuzzing time in seconds, optionally suffixed with "s"
#                    (default: 120s). Build/preparation time is not counted.
#   RUST_MIN_STACK   Rust stack size used by fuzz runs (default: 16777216).
#
# Usage:
#   scripts/fuzz-frozen-abi.sh [target ...] [-- cargo-bolero-arg ...]
#
# With no target arguments, the script lists all
# *_frozen_abi_fuzzer::test_fuzzer_* targets in the workspace and splits
# TOTAL_FUZZ_TIME across them.
#
# The script runs bolero fuzzing to explore new inputs. If inputs are saved in
# a corpus or crashes directory, pass the same `--corpus-dir` and
# `--crashes-dir` arguments to use them again.
#
# Example:
#   RUST_MIN_STACK=16777216 TOTAL_FUZZ_TIME=60s scripts/fuzz-frozen-abi.sh \
#     'stable_abi::impls::tests::bolero_fuzzer::TestFuzzerFeed_frozen_abi_fuzzer::test_fuzzer_wincode' \
#     -- --package solana-frozen-abi \
#        --max-input-length 64 \
#        --corpus-dir __fuzz__/corpus \
#        --crashes-dir __fuzz__/crashes
#
# Reproduce the intentionally skipped serialization bug target:
#     TOTAL_FUZZ_TIME=1s scripts/fuzz-frozen-abi.sh \
#     'stable_abi::impls::tests::bolero_repro::TestFuzzerBreakSerializationAboveN_frozen_abi_fuzzer::test_fuzzer_wincode' \
#     -- --package solana-frozen-abi \
#        --features fuzz-bolero-repro \
#        --corpus-dir frozen-abi/src/stable_abi/__fuzz__/stable_abi__impls__tests__bolero_repro__TestFuzzerBreakSerializationAboveN_frozen_abi_fuzzer__fuzzer_wincode/corpus \
#        --crashes-dir frozen-abi/src/stable_abi/__fuzz__/stable_abi__impls__tests__bolero_repro__TestFuzzerBreakSerializationAboveN_frozen_abi_fuzzer__fuzzer_wincode/crashes
#
# Output:
#
# INFO: Running with entropic power schedule (0xFF, 100).
# INFO: Seed: 404653315
# INFO: Loaded 1 modules   (40652 inline 8-bit counters): 40652 [0x5884c28935b0, 0x5884c289d47c), 
# INFO: Loaded 1 PC tables (40652 PCs): 40652 [0x5884c289d480,0x5884c293c140), 
# INFO:        1 files found in frozen-abi/src/stable_abi/__fuzz__/stable_abi__impls__tests__bolero_repro__TestFuzzerBreakSerializationAboveN_frozen_abi_fuzzer__fuzzer_wincode/corpus
# INFO:        0 files found in frozen-abi/src/stable_abi/__fuzz__/stable_abi__impls__tests__bolero_repro__TestFuzzerBreakSerializationAboveN_frozen_abi_fuzzer__fuzzer_wincode/crashes
# INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
# INFO: seed corpus: files: 1 min: 1b max: 1b total: 1b rss: 36Mb
# test failed; shrinking input...

# ======================== Test Failure ========================

# Input: 
# Length: 1 (0x1) bytes
# 0000:   11
#
set -euo pipefail
cd "$(dirname "$0")/.."

export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"

duration="${TOTAL_FUZZ_TIME:-120s}"

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

bolero_common_args=(
  --rustc-bootstrap
)

uses_custom_features=false
for arg in "${bolero_extra_args[@]}"; do
  case "$arg" in
    --features|--features=*|--all-features)
      uses_custom_features=true
      ;;
  esac
done

if [[ "$uses_custom_features" == false ]]; then
  bolero_common_args+=(--features fuzz-bolero)
fi

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
