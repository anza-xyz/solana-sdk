#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{StableAbi, StableAbiSample};
use {
    crate::state::{BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE, BLS_PUBLIC_KEY_COMPRESSED_SIZE},
    solana_pubkey::Pubkey,
};
#[cfg(feature = "serde")]
use {
    serde_derive::{Deserialize, Serialize},
    serde_with::serde_as,
};

#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInit {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInitV2 {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")
    )]
    pub authorized_voter_bls_pubkey: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]")
    )]
    pub authorized_voter_bls_proof_of_possession: [u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
    pub authorized_withdrawer: Pubkey,
    pub inflation_rewards_commission_bps: u16,
    pub block_revenue_commission_bps: u16,
}

impl Default for VoteInitV2 {
    fn default() -> Self {
        Self {
            node_pubkey: Pubkey::default(),
            authorized_voter: Pubkey::default(),
            authorized_voter_bls_pubkey: [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
            authorized_voter_bls_proof_of_possession: [0u8;
                BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
            authorized_withdrawer: Pubkey::default(),
            inflation_rewards_commission_bps: 0,
            block_revenue_commission_bps: 0,
        }
    }
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoterWithBLSArgs {
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")
    )]
    pub bls_pubkey: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]")
    )]
    pub bls_proof_of_possession: [u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
}

impl Default for VoterWithBLSArgs {
    fn default() -> Self {
        Self {
            bls_pubkey: [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
            bls_proof_of_possession: [0u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
        }
    }
}

#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VoteAuthorize {
    Voter,
    Withdrawer,
    VoterWithBLS(VoterWithBLSArgs),
}

#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
    pub new_authority: Pubkey,
}

#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeCheckedWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
}
