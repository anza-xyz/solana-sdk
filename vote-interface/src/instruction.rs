//! Vote program instructions

#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{frozen_abi, StableAbi, StableAbiSample};
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};
#[cfg(any(feature = "bincode", feature = "wincode"))]
use {
    crate::program::id,
    solana_instruction::{AccountMeta, Instruction},
    solana_sdk_ids::{system_program, sysvar},
};
use {
    crate::state::{
        VoteAuthorize, VoteAuthorizeCheckedWithSeedArgs, VoteAuthorizeWithSeedArgs, VoteInit,
        VoteInitV2, VoteStateV4,
    },
    solana_pubkey::Pubkey,
};

#[repr(u8)]
#[cfg_attr(feature = "stable-abi", derive(StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CommissionKind {
    InflationRewards = 0,
    BlockRevenue = 1,
}

#[cfg_attr(
    feature = "stable-abi",
    frozen_abi(
        abi_digest = "Gfrj3vdfCYcrnQsTh3HawAmQREneuREg7VbYcrjQhGvT",
        abi_serializer = ["bincode", "wincode"]
    ),
    derive(StableAbi, StableAbiSample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VoteInstruction {
    /// Initialize a vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` New validator identity (node_pubkey)
    ///
    /// This instruction MUST be included within the same Transaction as the
    /// system program's `CreateAccount` instruction that creates the account
    /// being initialized. Otherwise another party can acquire ownership of the
    /// uninitialized account.
    InitializeAccount(VoteInit),

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    ///
    /// When SIMD-0387 is enabled, the `VoteAuthorize::Voter` variant is
    /// disallowed for any vote accounts whose BLS pubkey is set to `Some`.
    Authorize(Pubkey, VoteAuthorize),

    /// Formerly `Vote`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedVote,

    /// Withdraw some amount of funds
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to withdraw from
    ///   1. `[WRITE]` Recipient account
    ///   2. `[SIGNER]` Withdraw authority
    Withdraw(u64),

    /// Update the vote account's validator identity (node_pubkey)
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the given authority public key
    ///   1. `[SIGNER]` New validator identity (node_pubkey)
    ///   2. `[SIGNER]` Withdraw authority
    UpdateValidatorIdentity,

    /// Update the commission for the vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated
    ///   1. `[SIGNER]` Withdraw authority
    UpdateCommission(u8),

    /// Formerly `VoteSwitch`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedVoteSwitch,

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new vote
    /// or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    ///   3. `[SIGNER]` New vote or withdraw authority
    ///
    /// When SIMD-0387 is enabled, the `VoteAuthorize::Voter` variant is
    /// disallowed for any vote accounts whose BLS pubkey is set to `Some`.
    AuthorizeChecked(VoteAuthorize),

    /// Formerly `UpdateVoteState`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedUpdateVoteState,

    /// Formerly `UpdateVoteStateSwitch`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedUpdateVoteStateSwitch,

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    ///
    /// When SIMD-0387 is enabled, the `VoteAuthorize::Voter` variant in
    /// `authorization_type` is disallowed for any vote accounts whose BLS
    /// pubkey is set to `Some`.
    AuthorizeWithSeed(VoteAuthorizeWithSeedArgs),

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement
    /// that the new vote or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    ///   3. `[SIGNER]` New vote or withdraw authority
    ///
    /// When SIMD-0387 is enabled, the `VoteAuthorize::Voter` variant in
    /// `authorization_type` is disallowed for any vote accounts whose BLS
    /// pubkey is set to `Some`.
    AuthorizeCheckedWithSeed(VoteAuthorizeCheckedWithSeedArgs),

    /// Formerly `CompactUpdateVoteState`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedCompactUpdateVoteState,

    /// Formerly `CompactUpdateVoteStateSwitch`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedCompactUpdateVoteStateSwitch,

    /// Formerly `TowerSync`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedTowerSync,

    /// Formerly `TowerSyncSwitch`; removed after the Alpenglow migration.
    /// Retained so later variants keep their wire index.
    #[doc(hidden)]
    RemovedTowerSyncSwitch,

    /// Initialize a vote account with all vote state v4 fields, including
    /// BLS public key and collector accounts.
    ///
    /// The vote program performs BLS proof-of-possession verification on the
    /// submitted BLS public key (per SIMD-0387). For each collector account
    /// (indices 2 and 3), the program performs the same validation as
    /// `UpdateCommissionCollector` (per SIMD-0232): if the collector is not
    /// the vote account itself, it must be system-program owned, rent-exempt,
    /// and writable (not a reserved account).
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[SIGNER]` New validator identity (node_pubkey)
    ///   2. `[WRITE]` Inflation rewards collector
    ///   3. `[WRITE]` Block revenue collector
    ///
    /// This instruction MUST be included within the same Transaction as the
    /// system program's `CreateAccount` instruction that creates the account
    /// being initialized. Otherwise another party can acquire ownership of the
    /// uninitialized account.
    InitializeAccountV2(VoteInitV2),

    /// Update the commission collector for the vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the new collector public key
    ///   1. `[WRITE]` New collector account. Must be set to the vote account or
    ///      a system program owned account. Must be writable to ensure the
    ///      account is not reserved.
    ///   2. `[SIGNER]` Vote account withdraw authority
    UpdateCommissionCollector(CommissionKind),

    /// Update the commission rate in basis points for the specified commission
    /// rate kind in a vote account.
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the new commission
    ///   1. `[SIGNER]` Vote account withdraw authority
    UpdateCommissionBps {
        commission_bps: u16,
        kind: CommissionKind,
    },

    /// Deposit lamports for distribution to stake delegators
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the deposit
    ///   1. `[SIGNER, WRITE]` Source account for deposit funds
    ///   2. `[]` System program, used to transfer the deposit
    DepositDelegatorRewards { deposit: u64 },
}

#[cfg(all(feature = "bincode", not(feature = "wincode")))]
#[inline(always)]
fn create_instruction(
    program_id: Pubkey,
    data: &VoteInstruction,
    accounts: Vec<AccountMeta>,
) -> Instruction {
    Instruction::new_with_bincode(program_id, data, accounts)
}

#[cfg(feature = "wincode")]
#[inline(always)]
fn create_instruction(
    program_id: Pubkey,
    data: &VoteInstruction,
    accounts: Vec<AccountMeta>,
) -> Instruction {
    Instruction::new_with_wincode(program_id, data, accounts)
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
fn initialize_account(vote_pubkey: &Pubkey, vote_init: &VoteInit) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(vote_init.node_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::InitializeAccount(*vote_init),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
fn initialize_account_v2(
    vote_pubkey: &Pubkey,
    vote_init: &VoteInitV2,
    inflation_rewards_collector: &Pubkey,
    block_revenue_collector: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(vote_init.node_pubkey, true),
        AccountMeta::new(*inflation_rewards_collector, false),
        AccountMeta::new(*block_revenue_collector, false),
    ];

    create_instruction(
        id(),
        &VoteInstruction::InitializeAccountV2(*vote_init),
        account_metas,
    )
}

pub struct CreateVoteAccountConfig<'a> {
    pub space: u64,
    pub with_seed: Option<(&'a Pubkey, &'a str)>,
}

impl Default for CreateVoteAccountConfig<'_> {
    fn default() -> Self {
        Self {
            // Create new vote accounts with size for V4.
            space: VoteStateV4::size_of() as u64,
            with_seed: None,
        }
    }
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn create_account_with_config(
    from_pubkey: &Pubkey,
    vote_pubkey: &Pubkey,
    vote_init: &VoteInit,
    lamports: u64,
    config: CreateVoteAccountConfig,
) -> Vec<Instruction> {
    let create_ix = if let Some((base, seed)) = config.with_seed {
        solana_system_interface::instruction::create_account_with_seed(
            from_pubkey,
            vote_pubkey,
            base,
            seed,
            lamports,
            config.space,
            &id(),
        )
    } else {
        solana_system_interface::instruction::create_account(
            from_pubkey,
            vote_pubkey,
            lamports,
            config.space,
            &id(),
        )
    };
    let init_ix = initialize_account(vote_pubkey, vote_init);
    vec![create_ix, init_ix]
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn create_account_with_config_v2(
    from_pubkey: &Pubkey,
    vote_pubkey: &Pubkey,
    vote_init: &VoteInitV2,
    inflation_rewards_collector: &Pubkey,
    block_revenue_collector: &Pubkey,
    lamports: u64,
    config: CreateVoteAccountConfig,
) -> Vec<Instruction> {
    let create_ix = if let Some((base, seed)) = config.with_seed {
        solana_system_interface::instruction::create_account_with_seed(
            from_pubkey,
            vote_pubkey,
            base,
            seed,
            lamports,
            config.space,
            &id(),
        )
    } else {
        solana_system_interface::instruction::create_account(
            from_pubkey,
            vote_pubkey,
            lamports,
            config.space,
            &id(),
        )
    };
    let init_ix = initialize_account_v2(
        vote_pubkey,
        vote_init,
        inflation_rewards_collector,
        block_revenue_collector,
    );
    vec![create_ix, init_ix]
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn authorize(
    vote_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey, // currently authorized
    new_authorized_pubkey: &Pubkey,
    vote_authorize: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::Authorize(*new_authorized_pubkey, vote_authorize),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn authorize_checked(
    vote_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey, // currently authorized
    new_authorized_pubkey: &Pubkey,
    vote_authorize: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
        AccountMeta::new_readonly(*new_authorized_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::AuthorizeChecked(vote_authorize),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn authorize_with_seed(
    vote_pubkey: &Pubkey,
    current_authority_base_key: &Pubkey,
    current_authority_derived_key_owner: &Pubkey,
    current_authority_derived_key_seed: &str,
    new_authority: &Pubkey,
    authorization_type: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*current_authority_base_key, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::AuthorizeWithSeed(VoteAuthorizeWithSeedArgs {
            authorization_type,
            current_authority_derived_key_owner: *current_authority_derived_key_owner,
            current_authority_derived_key_seed: current_authority_derived_key_seed.to_string(),
            new_authority: *new_authority,
        }),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn authorize_checked_with_seed(
    vote_pubkey: &Pubkey,
    current_authority_base_key: &Pubkey,
    current_authority_derived_key_owner: &Pubkey,
    current_authority_derived_key_seed: &str,
    new_authority: &Pubkey,
    authorization_type: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*current_authority_base_key, true),
        AccountMeta::new_readonly(*new_authority, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::AuthorizeCheckedWithSeed(VoteAuthorizeCheckedWithSeedArgs {
            authorization_type,
            current_authority_derived_key_owner: *current_authority_derived_key_owner,
            current_authority_derived_key_seed: current_authority_derived_key_seed.to_string(),
        }),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn update_validator_identity(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    node_pubkey: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(*node_pubkey, true),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::UpdateValidatorIdentity,
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn update_commission(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    commission: u8,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::UpdateCommission(commission),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn update_commission_collector(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    new_collector_pubkey: &Pubkey,
    kind: CommissionKind,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new(*new_collector_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::UpdateCommissionCollector(kind),
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn update_commission_bps(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    kind: CommissionKind,
    commission_bps: u16,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    create_instruction(
        id(),
        &VoteInstruction::UpdateCommissionBps {
            kind,
            commission_bps,
        },
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn deposit_delegator_rewards(
    vote_pubkey: &Pubkey,
    source_pubkey: &Pubkey,
    deposit: u64,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new(*source_pubkey, true),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    create_instruction(
        id(),
        &VoteInstruction::DepositDelegatorRewards { deposit },
        account_metas,
    )
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn withdraw(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    lamports: u64,
    to_pubkey: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new(*to_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    create_instruction(id(), &VoteInstruction::Withdraw(lamports), account_metas)
}

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use super::*;

    #[test]
    fn test_wire_indexes() {
        let authorize_with_seed_args = VoteAuthorizeWithSeedArgs {
            authorization_type: VoteAuthorize::Voter,
            current_authority_derived_key_owner: Pubkey::default(),
            current_authority_derived_key_seed: String::new(),
            new_authority: Pubkey::default(),
        };
        let authorize_checked_with_seed_args = VoteAuthorizeCheckedWithSeedArgs {
            authorization_type: VoteAuthorize::Voter,
            current_authority_derived_key_owner: Pubkey::default(),
            current_authority_derived_key_seed: String::new(),
        };

        // Indexes 2, 6, 8, 9 and 12-15 are held by placeholders for the
        // removed tower vote instructions.
        for (ix, expected_index) in [
            (VoteInstruction::InitializeAccount(VoteInit::default()), 0),
            (
                VoteInstruction::Authorize(Pubkey::default(), VoteAuthorize::Voter),
                1,
            ),
            (VoteInstruction::RemovedVote, 2),
            (VoteInstruction::Withdraw(0), 3),
            (VoteInstruction::UpdateValidatorIdentity, 4),
            (VoteInstruction::UpdateCommission(0), 5),
            (VoteInstruction::RemovedVoteSwitch, 6),
            (VoteInstruction::AuthorizeChecked(VoteAuthorize::Voter), 7),
            (VoteInstruction::RemovedUpdateVoteState, 8),
            (VoteInstruction::RemovedUpdateVoteStateSwitch, 9),
            (
                VoteInstruction::AuthorizeWithSeed(authorize_with_seed_args),
                10,
            ),
            (
                VoteInstruction::AuthorizeCheckedWithSeed(authorize_checked_with_seed_args),
                11,
            ),
            (VoteInstruction::RemovedCompactUpdateVoteState, 12),
            (VoteInstruction::RemovedCompactUpdateVoteStateSwitch, 13),
            (VoteInstruction::RemovedTowerSync, 14),
            (VoteInstruction::RemovedTowerSyncSwitch, 15),
            (
                VoteInstruction::InitializeAccountV2(VoteInitV2::default()),
                16,
            ),
            (
                VoteInstruction::UpdateCommissionCollector(CommissionKind::InflationRewards),
                17,
            ),
            (
                VoteInstruction::UpdateCommissionBps {
                    commission_bps: 0,
                    kind: CommissionKind::BlockRevenue,
                },
                18,
            ),
            (VoteInstruction::DepositDelegatorRewards { deposit: 0 }, 19),
        ] {
            let bytes = bincode::serialize(&ix).unwrap();
            assert_eq!(
                u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                expected_index
            );
            #[cfg(feature = "wincode")]
            assert_eq!(wincode::serialize(&ix).unwrap(), bytes);
        }
    }

    #[test]
    fn test_deposit_delegator_rewards_includes_system_program() {
        let vote_pubkey = Pubkey::new_unique();
        let source_pubkey = Pubkey::new_unique();

        let instruction = deposit_delegator_rewards(&vote_pubkey, &source_pubkey, 100_000);

        assert_eq!(instruction.program_id, id());
        assert_eq!(instruction.accounts.len(), 3);

        let vote_meta = &instruction.accounts[0];
        assert_eq!(vote_meta.pubkey, vote_pubkey);
        assert!(!vote_meta.is_signer);
        assert!(vote_meta.is_writable);

        let source_meta = &instruction.accounts[1];
        assert_eq!(source_meta.pubkey, source_pubkey);
        assert!(source_meta.is_signer);
        assert!(source_meta.is_writable);

        // The vote program transfers the deposit by invoking the System program,
        // which the runtime only resolves if it is one of the instruction's accounts.
        let system_program_meta = &instruction.accounts[2];
        assert_eq!(system_program_meta.pubkey, system_program::id());
        assert!(!system_program_meta.is_signer);
        assert!(!system_program_meta.is_writable);
    }

    #[test]
    fn test_builders_match_bincode_encoding() {
        let vote_pubkey = Pubkey::new_unique();
        let voter_pubkey = Pubkey::new_unique();
        let recipient_pubkey = Pubkey::new_unique();
        let vote_init = VoteInit {
            node_pubkey: Pubkey::new_unique(),
            authorized_voter: voter_pubkey,
            authorized_withdrawer: Pubkey::new_unique(),
            commission: 7,
        };

        for (ix, expected) in [
            (
                withdraw(&vote_pubkey, &voter_pubkey, 42, &recipient_pubkey),
                VoteInstruction::Withdraw(42),
            ),
            (
                authorize_with_seed(
                    &vote_pubkey,
                    &voter_pubkey,
                    &vote_pubkey,
                    "seed",
                    &voter_pubkey,
                    VoteAuthorize::Withdrawer,
                ),
                VoteInstruction::AuthorizeWithSeed(VoteAuthorizeWithSeedArgs {
                    authorization_type: VoteAuthorize::Withdrawer,
                    current_authority_derived_key_owner: vote_pubkey,
                    current_authority_derived_key_seed: "seed".to_string(),
                    new_authority: voter_pubkey,
                }),
            ),
            (
                create_account_with_config(
                    &voter_pubkey,
                    &vote_pubkey,
                    &vote_init,
                    42,
                    CreateVoteAccountConfig::default(),
                )
                .pop()
                .unwrap(),
                VoteInstruction::InitializeAccount(vote_init),
            ),
        ] {
            assert_eq!(ix.data, bincode::serialize(&expected).unwrap());
        }
    }
}
