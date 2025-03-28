#!/usr/bin/env bash

set -e
base="$(dirname "${BASH_SOURCE[0]}")"
# pacify shellcheck: cannot follow dynamic path
# shellcheck disable=SC1090,SC1091
source "$base/read-cargo-variable.sh"
cd "$base/.."

if [[ -z $1 ]]; then
  echo 'A package manifest path — e.g. "program" — must be provided.'
  exit 1
fi
PACKAGE_PATH=$1
if [[ -z $2 ]]; then
  echo 'A version level — e.g. "patch" — must be provided.'
  exit 1
fi
LEVEL=$2
DRY_RUN=$3

# Go to the directory
cd "${PACKAGE_PATH}"

# Get the old version, used with git-cliff
old_version=$(readCargoVariable version "Cargo.toml")
package_name=$(readCargoVariable name "Cargo.toml")
tag_name="${package_name//solana-/}"

# Publish the new version, commit the repo change, tag it, and push it all.
if [[ -n ${DRY_RUN} ]]; then
  cargo release "${LEVEL}"
else
  cargo release "${LEVEL}" --tag-name "${tag_name}@v{{version}}" --no-confirm --execute --dependent-version fix
fi

# Stop here if this is a dry run.
if [[ -n $DRY_RUN ]]; then
  exit 0
fi

# Get the new version.
new_version=$(readCargoVariable version "Cargo.toml")
new_git_tag="${tag_name}@v${new_version}"
old_git_tag="${tag_name}@v${old_version}"

# Expose the new version to CI if needed.
if [[ -n $CI ]]; then
  echo "new_git_tag=${new_git_tag}" >> "$GITHUB_OUTPUT"
  echo "old_git_tag=${old_git_tag}" >> "$GITHUB_OUTPUT"
fi
