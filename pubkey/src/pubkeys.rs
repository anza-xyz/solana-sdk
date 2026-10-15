use crate::Pubkey;
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi, StableAbiSample};
#[cfg(all(feature = "std", not(target_os = "solana")))]
use std::fmt;

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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
#[repr(transparent)]
pub struct NodePubkey(pub Pubkey);

#[cfg(all(feature = "std", not(target_os = "solana")))]
impl fmt::Display for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A wrapper to help distinguish vote account pubkeys from other types of pubkeys.
#[cfg_attr(
    feature = "stable-abi",
    frozen_abi(
        api_digest = "DtqeTYVwaUjSNbCWziyDK2PAKRDNVPFKFWDUgmm5D7Su",
        abi_digest = "3Hp1Xy8AqWQryLFNWuZGtx6UyKiP5PFHeV55XFaHBMN3",
        abi_serializer = ["bincode", "wincode"]
    ),
    derive(AbiExample, StableAbi, StableAbiSample)
)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
#[repr(transparent)]
pub struct VoteAccountPubkey(pub Pubkey);

#[cfg(all(feature = "std", not(target_os = "solana")))]
impl fmt::Display for VoteAccountPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
