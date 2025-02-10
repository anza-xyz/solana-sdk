[![Solana crate](https://img.shields.io/crates/v/solana-sdk.svg)](https://crates.io/crates/solana-sdk)
[![Solana documentation](https://docs.rs/solana-sdk/badge.svg)](https://docs.rs/solana-sdk)

# solana-sdk

Rust SDK for the Solana blockchain, used by on-chain programs and the Agave
validator.

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
