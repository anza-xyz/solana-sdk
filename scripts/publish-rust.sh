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
DEPENDENT_VERSION=$3
DRY_RUN=$4

# Go to the directory
cd "${PACKAGE_PATH}"

# Get the old version, used with git-cliff
old_version=$(readCargoVariable version "Cargo.toml")
package_name=$(readCargoVariable name "Cargo.toml")
tag_name="${package_name//solana-/}"

# Publishing to crates.io is irreversible, so it is done last. If the tag push
# loses a race with a concurrent release, the run fails before anything is
# published and can simply be re-run; the worst residual state is a tag without
# a crate, recoverable by re-publishing.
if [[ -n ${DRY_RUN} ]]; then
  cargo release "${LEVEL}"
else
  cargo release "${LEVEL}" --tag-name "${tag_name}@v{{version}}" --no-confirm --execute --no-publish --no-push --dependent-version "${DEPENDENT_VERSION}"
fi

# Stop here if this is a dry run.
if [[ -n $DRY_RUN ]]; then
  exit 0
fi

# Get the new version.
new_version=$(readCargoVariable version "Cargo.toml")
new_git_tag="${tag_name}@v${new_version}"
old_git_tag="${tag_name}@v${old_version}"

# Verify the crate builds before we tag and publish it.
cargo package

# Push the tag first; a concurrent-release race is rejected non-fast-forward and
# stops us here, before publishing.
branch=$(git rev-parse --abbrev-ref HEAD)
git push --atomic origin "HEAD:${branch}" "refs/tags/${new_git_tag}"

# Publish last, now that the tag is on master. cargo package already verified
# this tree, so skip the redundant verify build.
cargo publish --no-verify

# Expose the new version to CI if needed.
if [[ -n $CI ]]; then
  echo "new_git_tag=${new_git_tag}" >> "$GITHUB_OUTPUT"
  echo "old_git_tag=${old_git_tag}" >> "$GITHUB_OUTPUT"
fi
