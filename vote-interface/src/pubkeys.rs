#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi, StableAbiSample};
use {solana_pubkey::Pubkey, std::fmt::Display};

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
/// A wrapper to help distinguish node identity pubkeys from other types of pubkeys.
pub struct NodePubkey(pub Pubkey);

impl Display for NodePubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
/// A wrapper to help distinguish vote account pubkeys from other types of pubkeys.
pub struct VoteAccountPubkey(pub Pubkey);

impl Display for VoteAccountPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
