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

# Publish the new version and commit + tag the repo change locally.
# The push is deliberately deferred (--no-push) so it can be retried against a
# freshly synced master below; a concurrent publish of another crate may move
# master forward between our rebase and our push, which would otherwise reject
# the push non-fast-forward *after* the crate is already live on crates.io.
if [[ -n ${DRY_RUN} ]]; then
  cargo release "${LEVEL}"
else
  cargo release "${LEVEL}" --tag-name "${tag_name}@v{{version}}" --no-confirm --execute --no-push --dependent-version "${DEPENDENT_VERSION}"
fi

# Stop here if this is a dry run.
if [[ -n $DRY_RUN ]]; then
  exit 0
fi

# Get the new version.
new_version=$(readCargoVariable version "Cargo.toml")
new_git_tag="${tag_name}@v${new_version}"
old_git_tag="${tag_name}@v${old_version}"

# The crate is already on crates.io; all that remains is landing the version
# bump commit + tag in git. Retry the push, rebasing onto the latest master
# between attempts so concurrent publishes of other crates don't fail us.
branch=$(git rev-parse --abbrev-ref HEAD)
attempts=5
for ((attempt = 1; attempt <= attempts; attempt++)); do
  if git push --atomic origin "HEAD:${branch}" "refs/tags/${new_git_tag}"; then
    break
  fi
  if [[ $attempt -eq $attempts ]]; then
    echo "Failed to push ${branch} and tag ${new_git_tag} after ${attempts} attempts" >&2
    exit 1
  fi
  echo "Push rejected (attempt ${attempt}/${attempts}); rebasing onto origin/${branch} and retrying"
  git pull --rebase origin "${branch}"
  # Re-point the tag onto the rebased commit so it stays on master's history.
  git tag -f "${new_git_tag}" HEAD
done

# Expose the new version to CI if needed.
if [[ -n $CI ]]; then
  echo "new_git_tag=${new_git_tag}" >> "$GITHUB_OUTPUT"
  echo "old_git_tag=${old_git_tag}" >> "$GITHUB_OUTPUT"
fi
