# solana-sdk

Rust SDK for the Solana blockchain, used by on-chain programs and the Agave
validator.

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
