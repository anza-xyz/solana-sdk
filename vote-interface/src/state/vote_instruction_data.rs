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

// The message size is fixed:
// "ALPENGLOW" (9) + Vote Pubkey (32) = 41 bytes
// Note: The BLS Pubkey (48 bytes) is appended dynamically by the
// solana-bls-signatures crate.
const POP_MESSAGE_SIZE: usize = 9 + size_of::<Pubkey>();

/// Create a proof of possession message for the vote account address
///
/// Can be used with a vote account's BLS keypair to generate a proof of
/// possession, or to verify an existing proof of possession
pub fn generate_pop_message(vote_account_pubkey: &Pubkey) -> [u8; POP_MESSAGE_SIZE] {
    const LABEL_LEN: usize = 9;
    const PUBKEY_LEN: usize = size_of::<Pubkey>();

    const LABEL_START: usize = 0;
    const LABEL_END: usize = LABEL_START + LABEL_LEN;

    const PUBKEY_START: usize = LABEL_END;
    const PUBKEY_END: usize = PUBKEY_START + PUBKEY_LEN;

    // Make sure POP_MESSAGE_SIZE matches the layout at compile time
    const _: () = assert!(PUBKEY_END == POP_MESSAGE_SIZE);

    let mut message = [0u8; POP_MESSAGE_SIZE];

    message[LABEL_START..LABEL_END].copy_from_slice(b"ALPENGLOW");
    message[PUBKEY_START..PUBKEY_END].copy_from_slice(vote_account_pubkey.as_ref());

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_message_bytes() {
        let address_bytes = [101; 32];
        let vote_account_address = Pubkey::new_from_array(address_bytes);
        let message = generate_pop_message(&vote_account_address);
        let expected_message = "ALPENGLOW"
            .bytes()
            .chain(vote_account_address.to_bytes())
            .collect::<Vec<_>>();
        assert_eq!(message.as_slice(), expected_message);
    }
}
