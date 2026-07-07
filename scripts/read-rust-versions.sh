#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

source "./scripts/read-cargo-variable.sh"

minimum_versions=()
workspace_minimum=$(readCargoVariable rust-version "Cargo.toml")

for cargo_toml in $(git ls-files -- '**/Cargo.toml'); do
  # Read the MSRV from the crate
  minimum_version=$(readCargoVariable rust-version "$cargo_toml" 2>/dev/null)
  # If the crate does not specify a rust-version, or delegates to the
  # workspace, fall back to the workspace MSRV
  if [[ -z "$minimum_version" || "$minimum_version" == "{"* ]]; then
    minimum_version="$workspace_minimum"
  fi

  minimum_versions+=("$minimum_version")
done

# Get unique versions
printf '%s\n' "${minimum_versions[@]}" | sort -u
