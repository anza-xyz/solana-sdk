#![no_std]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(any(feature = "stable-abi", feature = "dev-context-only-utils"))]
extern crate std;

#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "decode")]
use core::fmt;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
use solana_address::Address;
#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi, StableAbiSample};

/// A wrapper to help distinguish node identity pubkeys from other types of pubkeys.
#[cfg_attr(
    feature = "stable-abi",
    frozen_abi(
        api_digest = "GY9BmH55ArakJhPZoDy6LSkc87kEU4Nz1NPY3f2stMGx",
        abi_digest = "3Hp1Xy8AqWQryLFNWuZGtx6UyKiP5PFHeV55XFaHBMN3",
        abi_serializer = ["bincode", "wincode"]
    ),
    derive(AbiExample, StableAbi, StableAbiSample)
)]
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
#[repr(transparent)]
pub struct NodePubkey(pub Address);

#[cfg(feature = "decode")]
impl fmt::Display for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A wrapper to help distinguish vote account addresses from other types of pubkeys.
#[cfg_attr(
    feature = "stable-abi",
    frozen_abi(
        api_digest = "4VF3M7qJVuMVxLtpGpPCZyWgRA5VFWxQgRSjK9BFeZx9",
        abi_digest = "3Hp1Xy8AqWQryLFNWuZGtx6UyKiP5PFHeV55XFaHBMN3",
        abi_serializer = ["bincode", "wincode"]
    ),
    derive(AbiExample, StableAbi, StableAbiSample)
)]
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
#[repr(transparent)]
pub struct VoteAccountAddress(pub Address);

#[cfg(feature = "decode")]
impl fmt::Display for VoteAccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
