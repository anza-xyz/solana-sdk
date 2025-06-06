[![Solana crate](https://img.shields.io/crates/v/solana-sdk.svg)](https://crates.io/crates/solana-sdk)
[![Solana documentation](https://docs.rs/solana-sdk/badge.svg)](https://docs.rs/solana-sdk)

# solana-sdk

Rust SDK for the Solana blockchain, used by on-chain programs and the Agave
validator.

## Upgrading from v2 to v3

### solana-sdk

The following modules have been removed, please use their component crates
directly:

* `address_lookup_table` -> `solana_address_lookup_table_interface`
* `alt_bn128` -> `solana_bn254`
* `bpf_loader_upgradeable` -> `solana_loader_v3_interface`
* `client` -> `solana_client_traits`
* `commitment_config` -> `solana_commitment_config`
* `compute_budget` -> `solana_compute_budget_interface`
* `decode_error` -> `solana_decode_error`
* `derivation_path` -> `solana_derivation_path`
* `ed25519_instruction` -> `solana_ed25519_program`
* `exit` -> `solana_validator_exit`
* `feature_set` -> `agave_feature_set`
* `feature` -> `solana_feature_gate_interface`
* `genesis_config` -> `solana_genesis_config`
* `hard_forks` -> `solana_hard_forks`
* `loader_instruction` -> `solana_loader_v2_interface`
* `loader_upgradeble_instruction` -> `solana_loader_v3_interface::instruction`
* `loader_v4` -> `solana_loader_v4_interface`
* `loader_v4_instruction` -> `solana_loader_v4_interface::instruction`
* `nonce` -> `solana_nonce`
* `nonce_account` -> `solana_nonce_account`
* `packet` -> `solana_packet`
* `poh_config` -> `solana_poh_config`
* `precompiles` -> `agave_precompiles`
* `program_utils` -> `solana_bincode::limited_deserialize`
* `quic` -> `solana_quic_definitions`
* `rent_collector` -> `solana_rent_collector`
* `rent_debits` -> `solana_rent_debits`
* `reserved_account_keys` -> `agave_reserved_account_keys`
* `reward_info` -> `solana_reward_info`
* `reward_type` -> `solana_reward_info`
* `sdk_ids` -> `solana_sdk_ids`
* `secp256k1_instruction` -> `solana_secp256k1_program`
* `secp256k1_recover` -> `solana_secp256k1_recover`
* `stake` -> `solana_stake_interface`
* `stake_history` -> `solana_stake_interface::stake_history`
* `system_instruction` -> `solana_system_interface::instruction`
* `system_program` -> `solana_system_interface::program`
* `system_transaction` -> `solana_system_transaction`
* `transaction_context` -> `solana_transaction_context`
* `vote` -> `solana_vote_interface`

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

Unlike Agave, the solana-sdk crates are versioned independently, and published
as needed.

If you need to publish a crate, you can use the "Publish Crate" GitHub Action.
Simply type in the path to the crate directory you want to release, ie.
`program-entrypoint`, along with the kind of release, either `patch`, `minor`,
`major`, or a specific version string.

The publish job will run checks, bump the crate version, commit and tag the
bump, publish the crate to crates.io, and finally create GitHub Release with
a simple changelog of all commits to the crate since the previous release.

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
