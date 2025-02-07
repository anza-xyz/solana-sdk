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
