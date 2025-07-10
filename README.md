[![Solana crate](https://img.shields.io/crates/v/solana-sdk.svg)](https://crates.io/crates/solana-sdk)
[![Solana documentation](https://docs.rs/solana-sdk/badge.svg)](https://docs.rs/solana-sdk)

# solana-sdk

Rust SDK for the Solana blockchain, used by on-chain programs and the Agave
validator.

## Upgrading from v2 to v3

### solana-sdk

The following modules have been removed, please use their component crates
directly:

* [`address_lookup_table`](https://docs.rs/solana-sdk/latest/solana_sdk/address_lookup_table) -> [`solana_address_lookup_table_interface`](https://docs.rs/solana-address-lookup-table-interface/latest/solana_address_lookup_table_interface/)
* [`alt_bn128`](https://docs.rs/solana-sdk/latest/solana_sdk/alt_bn128) -> [`solana_bn254`](https://docs.rs/solana-bn254/latest/solana_bn254)
* [`bpf_loader_upgradeable`](https://docs.rs/solana-sdk/latest/solana_sdk/bpf_loader_upgradeable) -> [`solana_loader_v3_interface`](https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface)
* [`client`](https://docs.rs/solana-sdk/latest/solana_sdk/client) -> [`solana_client_traits`](https://docs.rs/solana-client-traits/latest/solana_client_traits)
* [`commitment_config`](https://docs.rs/solana-sdk/latest/solana_sdk/commitment_config) -> [`solana_commitment_config`](https://docs.rs/solana-commitment-config/latest/solana_commitment_config)
* [`compute_budget`](https://docs.rs/solana-sdk/latest/solana_sdk/compute_budget) -> [`solana_compute_budget_interface`](https://docs.rs/solana-compute-budget-interface/latest/solana_compute_budget_interface)
* [`decode_error`](https://docs.rs/solana-sdk/latest/solana_sdk/decode_error) -> [`solana_decode_error`](https://docs.rs/solana-decode-error/latest/solana_decode_error)
* [`derivation_path`](https://docs.rs/solana-sdk/latest/solana_sdk/derivation_path) -> [`solana_derivation_path`](https://docs.rs/solana-derivation-path/latest/solana_derivation_path)
* [`ed25519_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/ed25519_instruction) -> [`solana_ed25519_program`](https://docs.rs/solana-ed25519-program/latest/solana_ed25519_program)
* [`exit`](https://docs.rs/solana-sdk/latest/solana_sdk/exit) -> [`solana_validator_exit`](https://docs.rs/solana-validator-exit/latest/solana_validator_exit)
* [`feature_set`](https://docs.rs/solana-sdk/latest/solana_sdk/feature_set) -> [`agave_feature_set`](https://docs.rs/agave-feature-set/latest/agave_feature_set)
* [`feature`](https://docs.rs/solana-sdk/latest/solana_sdk/feature) -> [`solana_feature_gate_interface`](https://docs.rs/solana-feature-gate-interface/latest/solana_feature_gate_interface)
* [`genesis_config`](https://docs.rs/solana-sdk/latest/solana_sdk/genesis_config) -> [`solana_genesis_config`](https://docs.rs/solana-genesis-config/latest/solana_genesis_config)
* [`hard_forks`](https://docs.rs/solana-sdk/latest/solana_sdk/hard_forks) -> [`solana_hard_forks`](https://docs.rs/solana-hard-forks/latest/solana_hard_forks)
* [`loader_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/loader_instruction) -> [`solana_loader_v2_interface`](https://docs.rs/solana-loader-v2-interface/latest/solana_loader_v2_interface)
* [`loader_upgradeable_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/loader_upgradeable_instruction) -> [`solana_loader_v3_interface::instruction`](https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface/instruction)
* [`loader_v4`](https://docs.rs/solana-sdk/latest/solana_sdk/loader_v4) -> [`solana_loader_v4_interface`](https://docs.rs/solana-loader-v4-interface/latest/solana_loader_v4_interface)
* [`loader_v4_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/loader_v4_instruction) -> [`solana_loader_v4_interface::instruction`](https://docs.rs/solana-loader-v4-interface/latest/solana_loader_v4_interface/instruction)
* [`nonce`](https://docs.rs/solana-sdk/latest/solana_sdk/nonce) -> [`solana_nonce`](https://docs.rs/solana-nonce/latest/solana_nonce)
* [`nonce_account`](https://docs.rs/solana-sdk/latest/solana_sdk/nonce_account) -> [`solana_nonce_account`](https://docs.rs/solana-nonce-account/latest/solana_nonce_account)
* [`packet`](https://docs.rs/solana-sdk/latest/solana_sdk/packet) -> [`solana_packet`](https://docs.rs/solana-packet/latest/solana_packet)
* [`poh_config`](https://docs.rs/solana-sdk/latest/solana_sdk/poh_config) -> [`solana_poh_config`](https://docs.rs/solana-poh-config/latest/solana_poh_config)
* [`precompiles`](https://docs.rs/solana-sdk/latest/solana_sdk/precompiles) -> [`agave_precompiles`](https://docs.rs/agave-precompiles/latest/agave_precompiles)
* [`program_utils`](https://docs.rs/solana-sdk/latest/solana_sdk/program_utils) -> [`solana_bincode::limited_deserialize`](https://docs.rs/solana-bincode/latest/solana_bincode)
* [`quic`](https://docs.rs/solana-sdk/latest/solana_sdk/quic) -> [`solana_quic_definitions`](https://docs.rs/solana-quic-definitions/latest/solana_quic_definitions)
* [`rent_collector`](https://docs.rs/solana-sdk/latest/solana_sdk/rent_collector) -> [`solana_rent_collector`](https://docs.rs/solana-rent-collector/latest/solana_rent_collector)
* [`rent_debits`](https://docs.rs/solana-sdk/latest/solana_sdk/rent_debits) -> [`solana_rent_debits`](https://docs.rs/solana-rent-debits/latest/solana_rent_debits)
* [`reserved_account_keys`](https://docs.rs/solana-sdk/latest/solana_sdk/reserved_account_keys) -> [`agave_reserved_account_keys`](https://docs.rs/agave-reserved-account-keys/latest/agave_reserved_account_keys)
* [`reward_info`](https://docs.rs/solana-sdk/latest/solana_sdk/reward_info) -> [`solana_reward_info`](https://docs.rs/solana-reward-info/latest/solana_reward_info)
* [`reward_type`](https://docs.rs/solana-sdk/latest/solana_sdk/reward_type) -> [`solana_reward_info`](https://docs.rs/solana-reward-info/latest/solana_reward_info)
* [`sdk_ids`](https://docs.rs/solana-sdk/latest/solana_sdk/sdk_ids) -> [`solana_sdk_ids`](https://docs.rs/solana-sdk-ids/latest/solana_sdk_ids)
* [`secp256k1_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/secp256k1_instruction) -> [`solana_secp256k1_program`](https://docs.rs/solana-secp256k1-program/latest/solana_secp256k1_program)
* [`secp256k1_recover`](https://docs.rs/solana-sdk/latest/solana_sdk/secp256k1_recover) -> [`solana_secp256k1_recover`](https://docs.rs/solana-secp256k1-recover/latest/solana_secp256k1_recover)
* [`stake`](https://docs.rs/solana-sdk/latest/solana_sdk/stake) -> [`solana_stake_interface`](https://docs.rs/solana-stake-interface/latest/solana_stake_interface)
* [`stake_history`](https://docs.rs/solana-sdk/latest/solana_sdk/stake_history) -> [`solana_stake_interface::stake_history`](https://docs.rs/solana-stake-interface/latest/solana_stake_interface/stake_history)
* [`system_instruction`](https://docs.rs/solana-sdk/latest/solana_sdk/system_instruction) -> [`solana_system_interface::instruction`](https://docs.rs/solana-system-interface/latest/solana_system_interface/instruction)
* [`system_program`](https://docs.rs/solana-sdk/latest/solana_sdk/system_program) -> [`solana_system_interface::program`](https://docs.rs/solana-system-interface/latest/solana_system_interface/program)
* [`system_transaction`](https://docs.rs/solana-sdk/latest/solana_sdk/system_transaction) -> [`solana_system_transaction`](https://docs.rs/solana-system-transaction/latest/solana_system_transaction)
* [`transaction_context`](https://docs.rs/solana-sdk/latest/solana_sdk/transaction_context) -> [`solana_transaction_context`](https://docs.rs/solana-transaction-context/latest/solana_transaction_context)
* [`vote`](https://docs.rs/solana-sdk/latest/solana_sdk/vote) -> [`solana_vote_interface`](https://docs.rs/solana-vote-interface/latest/solana_vote_interface)

### solana-program

The following modules have been removed, please use their component crates
directly:

* [`address_lookup_table`](https://docs.rs/solana-program/latest/solana_program/address_lookup_table) -> [`solana_address_lookup_table_interface`](https://docs.rs/solana-address-lookup-table-interface/latest/solana_address_lookup_table_interface/)
* [`bpf_loader_upgradeable`](https://docs.rs/solana-program/latest/solana_program/bpf_loader_upgradeable) -> [`solana_loader_v3_interface`](https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface)
* [`decode_error`](https://docs.rs/solana-program/latest/solana_program/decode_error) -> [`solana_decode_error`](https://docs.rs/solana-decode-error/latest/solana_decode_error)
* [`feature`](https://docs.rs/solana-program/latest/solana_program/feature) -> [`solana_feature_gate_interface`](https://docs.rs/solana-feature-gate-interface/latest/solana_feature_gate_interface)
* [`loader_instruction`](https://docs.rs/solana-program/latest/solana_program/loader_instruction) -> [`solana_loader_v2_interface`](https://docs.rs/solana-loader-v2-interface/latest/solana_loader_v2_interface)
* [`loader_upgradeable_instruction`](https://docs.rs/solana-program/latest/solana_program/loader_upgradeable_instruction) -> [`solana_loader_v3_interface::instruction`](https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface/instruction)
* [`loader_v4`](https://docs.rs/solana-program/latest/solana_program/loader_v4) -> [`solana_loader_v4_interface`](https://docs.rs/solana-loader-v4-interface/latest/solana_loader_v4_interface)
* [`loader_v4_instruction`](https://docs.rs/solana-program/latest/solana_program/loader_v4_instruction) -> [`solana_loader_v4_interface::instruction`](https://docs.rs/solana-loader-v4-interface/latest/solana_loader_v4_interface/instruction)
* [`message`](https://docs.rs/solana-program/latest/solana_program/message) -> [`solana_message`](https://docs.rs/solana-message/latest/solana_message)
* [`nonce`](https://docs.rs/solana-program/latest/solana_program/nonce) -> [`solana_nonce`](https://docs.rs/solana-nonce/latest/solana_nonce)
* [`program_utils`](https://docs.rs/solana-program/latest/solana_program/program_utils) -> [`solana_bincode::limited_deserialize`](https://docs.rs/solana-bincode/latest/solana_bincode)
* [`sanitize`](https://docs.rs/solana-program/latest/solana_program/sanitize) -> [`solana_sanitize`](https://docs.rs/solana-sanitize/latest/solana_sanitize)
* [`sdk_ids`](https://docs.rs/solana-program/latest/solana_program/sdk_ids) -> [`solana_sdk_ids`](https://docs.rs/solana-sdk-ids/latest/solana_sdk_ids)
* [`stake`](https://docs.rs/solana-program/latest/solana_program/stake) -> [`solana_stake_interface`](https://docs.rs/solana-stake-interface/latest/solana_stake_interface)
* [`stake_history`](https://docs.rs/solana-program/latest/solana_program/stake_history) -> [`solana_stake_interface::stake_history`](https://docs.rs/solana-stake-interface/latest/solana_stake_interface/stake_history)
* [`system_instruction`](https://docs.rs/solana-program/latest/solana_program/system_instruction) -> [`solana_system_interface::instruction`](https://docs.rs/solana-system-interface/latest/solana_system_interface/instruction)
* [`system_program`](https://docs.rs/solana-program/latest/solana_program/system_program) -> [`solana_system_interface::program`](https://docs.rs/solana-system-interface/latest/solana_system_interface/program)
* [`vote`](https://docs.rs/solana-program/latest/solana_program/vote) -> [`solana_vote_interface`](https://docs.rs/solana-vote-interface/latest/solana_vote_interface)

## Building

### **1. Install rustc, cargo and rustfmt.**

```console
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup component add rustfmt
```

### **2. Download the source code.**

```console
git clone https://github.com/anza-xyz/solana-sdk.git
cd solana-sdk
```

When building the master branch, please make sure you are using the version
specified in the repo's `rust-toolchain.toml` by running:

```console
rustup show
```

This command will download the toolchain if it is missing in the system.

### **3. Test.**

```console
cargo test
```

## For Agave Developers

### Patching a local solana-sdk repository

If your change to Agave also entails changes to the SDK, you will need to patch
your Agave repo to use a local checkout of solana-sdk crates.

To patch all of the crates in this repo for Agave, just run:

```console
./scripts/patch-crates-no-header.sh <AGAVE_PATH> <SOLANA_SDK_PATH>
```

### Publishing a crate from this repository

NOTE: The repo currently contains unpublished breaking changes, so please
double-check before publishing any crates!

Unlike Agave, the solana-sdk crates are versioned independently, and published
as needed.

If you need to publish a crate, you can use the "Publish Crate" GitHub Action.
Simply type in the path to the crate directory you want to release, ie.
`program-entrypoint`, along with the kind of release, either `patch`, `minor`,
`major`, or a specific version string.

The publish job will run checks, bump the crate version, commit and tag the
bump, publish the crate to crates.io, and finally create GitHub Release with
a simple changelog of all commits to the crate since the previous release.

### Backports

If you would like to backport a pull request, simply add the appropriate label,
named `backport <BRANCH_NAME>`.

For example, to create a backport to the `maintenance/v2.x` branch, just add the
`backport maintenance/v2.x` label.

## Testing

Certain tests, such as `rustfmt` and `clippy`, require the nightly rustc
configured on the repository. To easily install it, use the `./cargo` helper
script in the root of the repository:

```console
./cargo nightly tree
```

### Basic testing

Run the test suite:

```console
cargo test
```

Alternatively, there is a helper script:

```console
./scripts/test-stable.sh
```

### Formatting

Format code for rustfmt check:

```console
./cargo nightly fmt --all
```

The check can be run with a helper script:

```console
./scripts/check-fmt.sh
```

### Clippy / Linting

To check the clippy lints:

```console
./scripts/check-clippy.sh
```

### Benchmarking

Run the benchmarks:

```console
./scripts/test-bench.sh
```

### Code coverage

To generate code coverage statistics:

```console
./scripts/test-coverage.sh
$ open target/cov/lcov-local/index.html
```

Code coverage requires `llvm-tools-preview` for the configured nightly
toolchain. To install the component, run the command output by the script if it
fails to find the component:

```console
rustup component add llvm-tools-preview --toolchain=<NIGHTLY_TOOLCHAIN>
```
