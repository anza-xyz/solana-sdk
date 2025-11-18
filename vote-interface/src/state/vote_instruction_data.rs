#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
use {
    crate::state::{
        Lockout, BLS_PUBLIC_KEY_COMPRESSED_SIZE, BLS_SIGNATURE_COMPRESSED_SIZE, MAX_LOCKOUT_HISTORY,
    },
    solana_clock::{Slot, UnixTimestamp},
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    std::{collections::VecDeque, fmt::Debug},
};
#[cfg(feature = "serde")]
use {
    serde_derive::{Deserialize, Serialize},
    serde_with::serde_as,
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "GvUzgtcxhKVVxPAjSntXGPqjLZK5ovgZzCiUP1tDpB9q"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Vote {
    /// A stack of votes starting with the oldest vote
    pub slots: Vec<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl Vote {
    pub fn new(slots: Vec<Slot>, hash: Hash) -> Self {
        Self {
            slots,
            hash,
            timestamp: None,
        }
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.slots.last().copied()
    }
}

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "CxyuwbaEdzP7jDCZyxjgQvLGXadBUZF3LoUvbSpQ6tYN"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct VoteStateUpdate {
    /// The proposed tower
    pub lockouts: VecDeque<Lockout>,
    /// The proposed root
    pub root: Option<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl From<Vec<(Slot, u32)>> for VoteStateUpdate {
    fn from(recent_slots: Vec<(Slot, u32)>) -> Self {
        let lockouts: VecDeque<Lockout> = recent_slots
            .into_iter()
            .map(|(slot, confirmation_count)| {
                Lockout::new_with_confirmation_count(slot, confirmation_count)
            })
            .collect();
        Self {
            lockouts,
            root: None,
            hash: Hash::default(),
            timestamp: None,
        }
    }
}

impl VoteStateUpdate {
    pub fn new(lockouts: VecDeque<Lockout>, root: Option<Slot>, hash: Hash) -> Self {
        Self {
            lockouts,
            root,
            hash,
            timestamp: None,
        }
    }

    pub fn slots(&self) -> Vec<Slot> {
        self.lockouts.iter().map(|lockout| lockout.slot()).collect()
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.lockouts.back().map(|l| l.slot())
    }
}

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "6UDiQMH4wbNwkMHosPMtekMYu2Qa6CHPZ2ymK4mc6FGu"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct TowerSync {
    /// The proposed tower
    pub lockouts: VecDeque<Lockout>,
    /// The proposed root
    pub root: Option<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
    /// the unique identifier for the chain up to and
    /// including this block. Does not require replaying
    /// in order to compute.
    pub block_id: Hash,
}

impl From<Vec<(Slot, u32)>> for TowerSync {
    fn from(recent_slots: Vec<(Slot, u32)>) -> Self {
        let lockouts: VecDeque<Lockout> = recent_slots
            .into_iter()
            .map(|(slot, confirmation_count)| {
                Lockout::new_with_confirmation_count(slot, confirmation_count)
            })
            .collect();
        Self {
            lockouts,
            root: None,
            hash: Hash::default(),
            timestamp: None,
            block_id: Hash::default(),
        }
    }
}

impl TowerSync {
    pub fn new(
        lockouts: VecDeque<Lockout>,
        root: Option<Slot>,
        hash: Hash,
        block_id: Hash,
    ) -> Self {
        Self {
            lockouts,
            root,
            hash,
            timestamp: None,
            block_id,
        }
    }

    /// Creates a tower with consecutive votes for `slot - MAX_LOCKOUT_HISTORY + 1` to `slot` inclusive.
    /// If `slot >= MAX_LOCKOUT_HISTORY`, sets the root to `(slot - MAX_LOCKOUT_HISTORY)`
    /// Sets the hash to `hash` and leaves `block_id` unset.
    pub fn new_from_slot(slot: Slot, hash: Hash) -> Self {
        let lowest_slot = slot
            .saturating_add(1)
            .saturating_sub(MAX_LOCKOUT_HISTORY as u64);
        let slots: Vec<_> = (lowest_slot..slot.saturating_add(1)).collect();
        Self::new_from_slots(
            slots,
            hash,
            (lowest_slot > 0).then(|| lowest_slot.saturating_sub(1)),
        )
    }

    /// Creates a tower with consecutive confirmation for `slots`
    pub fn new_from_slots(slots: Vec<Slot>, hash: Hash, root: Option<Slot>) -> Self {
        let lockouts: VecDeque<Lockout> = slots
            .into_iter()
            .rev()
            .enumerate()
            .map(|(cc, s)| Lockout::new_with_confirmation_count(s, cc.saturating_add(1) as u32))
            .rev()
            .collect();
        Self {
            lockouts,
            hash,
            root,
            timestamp: None,
            block_id: Hash::default(),
        }
    }

    pub fn slots(&self) -> Vec<Slot> {
        self.lockouts.iter().map(|lockout| lockout.slot()).collect()
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.lockouts.back().map(|l| l.slot())
    }
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInit {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInitV2 {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")
    )]
    pub authorized_voter_bls_pubkey: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_COMPRESSED_SIZE]"))]
    pub authorized_voter_bls_proof_of_possession: [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
    pub authorized_withdrawer: Pubkey,
    pub inflation_rewards_commission_bps: u16,
    pub inflation_rewards_collector: Pubkey,
    pub block_revenue_commission_bps: u16,
    pub block_revenue_collector: Pubkey,
}

impl Default for VoteInitV2 {
    fn default() -> Self {
        Self {
            node_pubkey: Pubkey::default(),
            authorized_voter: Pubkey::default(),
            authorized_voter_bls_pubkey: [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
            authorized_voter_bls_proof_of_possession: [0u8; BLS_SIGNATURE_COMPRESSED_SIZE],
            authorized_withdrawer: Pubkey::default(),
            inflation_rewards_commission_bps: 0,
            inflation_rewards_collector: Pubkey::default(),
            block_revenue_commission_bps: 0,
            block_revenue_collector: Pubkey::default(),
        }
    }
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoterWithBLSArgs {
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")
    )]
    pub bls_pub_key: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_COMPRESSED_SIZE]"))]
    pub bls_proof_of_possession: [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
}

impl Default for VoterWithBLSArgs {
    fn default() -> Self {
        Self {
            bls_pub_key: [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
            bls_proof_of_possession: [0u8; BLS_SIGNATURE_COMPRESSED_SIZE],
        }
    }
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VoteAuthorize {
    Voter,
    Withdrawer,
    VoterWithBLS(VoterWithBLSArgs),
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
    pub new_authority: Pubkey,
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeCheckedWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
}
