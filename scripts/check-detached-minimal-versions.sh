#!/usr/bin/env bash

set -eo pipefail
base="$(dirname "${BASH_SOURCE[0]}")"
# pacify shellcheck: cannot follow dynamic path
# shellcheck disable=SC1090,SC1091
source "$base/read-cargo-variable.sh"

here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

dir=$1

# backup toml file before messing with it
cargo_toml="./Cargo.toml"
cp ${cargo_toml} ${cargo_toml}.bak

# Remove all other members
toml set ${cargo_toml}.bak workspace.members '' > ${cargo_toml}
sed -i'' "s/members.*/members = [\"$dir\"]/" ${cargo_toml}

# Remove paths from deps
sed -i'' "s/ path = .*, v/ v/" ${cargo_toml}

# Remove patches
sed -i'' "s/solana-.* path.*}//" ${cargo_toml}

# Add it back for the one to test
sed -i'' "s/solana-$dir = {/solana-$dir = { path = \"$dir\",/" ${cargo_toml}

# Run test
set +e
bash ./scripts/check-minimal-versions.sh
status=$?

# Restore toml file
mv ${cargo_toml}.bak ${cargo_toml}

exit $status
