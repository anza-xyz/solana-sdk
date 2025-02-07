# source this file

base="$(dirname "${BASH_SOURCE[0]}")"
# pacify shellcheck: cannot follow dynamic path
# shellcheck disable=SC1090,SC1091
source "$base/read-cargo-variable.sh"

crate_dirs=(
  account
  account-info
  address-lookup-table-interface
  atomic-u64
  big-mod-exp
  bincode
  blake3-hasher
  bn254
  borsh
  client-traits
  clock
  cluster-type
  commitment-config
  compute-budget-interface
  cpi
  decode-error
  define-syscall
  derivation-path
  ed25519-program
  epoch-info
  epoch-rewards
  epoch-rewards-hasher
  epoch-schedule
  example-mocks
  feature-gate-interface
  feature-set
  fee-calculator
  fee-structure
  file-download
  frozen-abi
  frozen-abi-macro
  genesis-config
  hard-forks
  hash
  inflation
  instruction
  instructions-sysvar
  keccak-hasher
  keypair
  last-restart-slot
  loader-v2-interface
  loader-v3-interface
  loader-v4-interface
  logger
  message
  msg
  native-token
  nonce
  nonce-account
  offchain-message
  package-metadata
  package-metadata-macro
  packet
  poh-config
  precompile-error
  precompiles
  presigner
  program
  program-entrypoint
  program-error
  program-memory
  program-option
  program-pack
  pubkey
  quic-definitions
  rent
  rent-collector
  rent-debits
  reserved-account-keys
  reward-info
  sanitize
  scripts
  sdk
  sdk-ids
  sdk-macro
  secp256k1-program
  secp256k1-recover
  secp256r1-program
  seed-derivable
  seed-phrase
  serde
  serde-varint
  serialize-utils
  sha256-hasher
  short-vec
  shred-version
  signature
  signer
  slot-hashes
  slot-history
  stable-layout
  system-transaction
  sysvar
  sysvar-id
  target
  time-utils
  transaction
  transaction-context
  transaction-error
  validator-exit
  vote-interface
)

update_solana_sdk_dependencies() {
  declare project_root="$1"
  declare solana_sdk_dir="$2"
  declare tomls=()
  while IFS='' read -r line; do tomls+=("$line"); done < <(find "$project_root" -name Cargo.toml)

  set -x
  for crate_dir in "${crate_dirs[@]}"; do
    full_path="$solana_sdk_dir/$crate_dir"
    crate_version=$(readCargoVariable version "$full_path/Cargo.toml")
    sed -E -i'' -e "s:(solana-${crate_dir} = \")([=<>]*)[0-9.]+([^\"]*)\".*:\1\2${crate_version}\3\":" "${tomls[@]}"
    sed -E -i'' -e "s:(solana-${crate_dir} = \{ version = \")([=<>]*)[0-9.]+([^\"]*)(\".*):\1\2${crate_version}\3\4:" "${tomls[@]}"
  done
}

patch_crates_io_solana_sdk() {
  declare Cargo_toml="$1"
  declare solana_sdk_dir="$2"
  cat >> "$Cargo_toml" <<EOF
[patch.crates-io]
EOF
  patch_crates_io_solana_sdk_no_header "$Cargo_toml" "$solana_sdk_dir"
}

patch_crates_io_solana_sdk_no_header() {
  declare Cargo_toml="$1"
  declare solana_sdk_dir="$2"

  full_path_solana_sdk_dir="$(cd "$solana_sdk_dir" && pwd -P)"
  patch_crates=()
  for crate_dir in "${crate_dirs[@]}"; do
    full_path="$full_path_solana_sdk_dir/$crate_dir"
    if [[ -r "$full_path/Cargo.toml" ]]; then
      patch_crates+=("solana-${crate_dir} = { path = \"$full_path\" }")
    fi
  done

  echo "Patching in crates from $solana_sdk_dir"
  echo
  if grep -q "# The following entries are auto-generated by $0" "$Cargo_toml"; then
    echo "$Cargo_toml is already patched"
  else
    if ! grep -q '\[patch.crates-io\]' "$Cargo_toml"; then
      echo "[patch.crates-io]" >> "$Cargo_toml"
    fi
    cat >> "$Cargo_toml" <<PATCH
# The following entries are auto-generated by $0
$(printf "%s\n" "${patch_crates[@]}")
PATCH
  fi
}
