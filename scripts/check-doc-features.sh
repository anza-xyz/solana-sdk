#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

err=0
# Get all Cargo.toml files that don't have [package.metadata.docs.rs] specified
files=$(comm -23 <(git ls-files -- '**/Cargo.toml' | sort) <(git grep -l "^\[package.metadata.docs.rs\]" | sort))
if [[ -n $files ]]; then
  echo "Files found without [package.metadata.docs.rs]:"
  echo "$files"
  err=1
fi

# Get all lib.rs files that don't have #![cfg_attr(docsrs, feature(doc_cfg))]
files=$(comm -23 <(git ls-files -- '**/lib.rs' | sort) <(git grep -lE '^#!\[cfg_attr\(docsrs, feature\(doc_cfg\)\)\]' | sort))
if [[ -n $files ]]; then
  echo "Files found without #![cfg_attr(docsrs, feature(doc_cfg))]"
  echo "$files"
  err=1
fi
exit $err
