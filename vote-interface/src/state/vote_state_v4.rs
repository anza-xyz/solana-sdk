#[cfg(feature = "bincode")]
use super::VoteStateVersions;
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
#[cfg(any(target_os = "solana", feature = "bincode"))]
use solana_instruction::error::InstructionError;
use {
    super::{BlockTimestamp, LandedVote, Lockout, BLS_PUBKEY_COMPRESSED_BYTES},
    crate::authorized_voters::AuthorizedVoters,
    solana_clock::{Epoch, Slot},
    solana_pubkey::Pubkey,
    std::{collections::VecDeque, fmt::Debug},
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "6wQjgsg3yTmdwi5SLBzRhGXrGnNMCD8rwxmUSR8mPEe6"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct VoteStateV4 {
    /// The node that votes in this account.
    pub node_pubkey: Pubkey,
    /// The signer for withdrawals.
    pub authorized_withdrawer: Pubkey,

    /// The collector account for inflation rewards.
    pub inflation_rewards_collector: Pubkey,
    /// The collector account for block revenue.
    pub block_revenue_collector: Pubkey,

    /// Basis points (0-10,000) that represent how much of the inflation
    /// rewards should be given to this vote account.
    pub inflation_rewards_commission_bps: u16,
    /// Basis points (0-10,000) that represent how much of the block revenue
    /// should be given to this vote account.
    pub block_revenue_commission_bps: u16,

    /// Reward amount pending distribution to stake delegators.
    pub pending_delegator_rewards: u64,

    /// Compressed BLS pubkey for Alpenglow.
    #[cfg_attr(feature = "serde", serde(with = "serde_bls_pubkey_compressed"))]
    pub bls_pubkey_compressed: Option<[u8; BLS_PUBKEY_COMPRESSED_BYTES]>,

    pub votes: VecDeque<LandedVote>,
    pub root_slot: Option<Slot>,

    /// The signer for vote transactions.
    /// Contains entries for the current epoch and the previous epoch.
    pub authorized_voters: AuthorizedVoters,

    /// History of credits earned by the end of each epoch.
    /// Each tuple is (Epoch, credits, prev_credits).
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// Most recent timestamp submitted with a vote.
    pub last_timestamp: BlockTimestamp,
}

impl VoteStateV4 {
    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // Same size as V3 to avoid account resizing
    }

    pub fn new_rand_for_tests(node_pubkey: Pubkey, root_slot: Slot) -> Self {
        let votes = (1..32)
            .map(|x| LandedVote {
                latency: 0,
                lockout: Lockout::new_with_confirmation_count(
                    u64::from(x).saturating_add(root_slot),
                    32_u32.saturating_sub(x),
                ),
            })
            .collect();
        Self {
            node_pubkey,
            root_slot: Some(root_slot),
            votes,
            ..VoteStateV4::default()
        }
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8], vote_pubkey: &Pubkey) -> Result<Self, InstructionError> {
        #[cfg(not(target_os = "solana"))]
        {
            bincode::deserialize::<VoteStateVersions>(input)
                .map_err(|_| InstructionError::InvalidAccountData)
                .and_then(|versioned| versioned.try_convert_to_v4(vote_pubkey))
        }
        #[cfg(target_os = "solana")]
        {
            let mut vote_state = Self::default();
            Self::deserialize_into(input, &mut vote_state, vote_pubkey)?;
            Ok(vote_state)
        }
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided `VoteStateV4`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` reflects the state of the input data. On failure, `vote_state` is
    /// reset to `VoteStateV4::default()`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into(
        input: &[u8],
        vote_state: &mut VoteStateV4,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize;
        vote_state_deserialize::deserialize_into(input, vote_state, |input, vote_state| {
            Self::deserialize_into_ptr(input, vote_state, vote_pubkey)
        })
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided
    /// `MaybeUninit<VoteStateV4>`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` is fully initialized and can be converted to `VoteStateV4` using
    /// [MaybeUninit::assume_init]. On failure, `vote_state` may still be uninitialized and must not
    /// be converted to `VoteStateV4`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into_uninit(
        input: &[u8],
        vote_state: &mut std::mem::MaybeUninit<VoteStateV4>,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        Self::deserialize_into_ptr(input, vote_state.as_mut_ptr(), vote_pubkey)
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    fn deserialize_into_ptr(
        input: &[u8],
        vote_state: *mut VoteStateV4,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize::{deserialize_vote_state_into_v4, SourceVersion};

        let mut cursor = std::io::Cursor::new(input);

        let variant = solana_serialize_utils::cursor::read_u32(&mut cursor)?;
        match variant {
            // V0_23_5. not supported for bpf targets; these should not exist on mainnet
            // supported for non-bpf targets for backwards compatibility.
            // **Same pattern as v3 for this variant**.
            0 => {
                #[cfg(not(target_os = "solana"))]
                {
                    // Safety: vote_state is valid as it comes from `&mut MaybeUninit<VoteStateV4>` or
                    // `&mut VoteStateV4`. In the first case, the value is uninitialized so we write()
                    // to avoid dropping invalid data; in the latter case, we `drop_in_place()`
                    // before writing so the value has already been dropped and we just write a new
                    // one in place.
                    unsafe {
                        vote_state.write(
                            bincode::deserialize::<VoteStateVersions>(input)
                                .map_err(|_| InstructionError::InvalidAccountData)
                                .and_then(|versioned| versioned.try_convert_to_v4(vote_pubkey))?,
                        );
                    }
                    Ok(())
                }
                #[cfg(target_os = "solana")]
                Err(InstructionError::InvalidAccountData)
            }
            // V1_14_11
            1 => deserialize_vote_state_into_v4(
                &mut cursor,
                vote_state,
                SourceVersion::V1_14_11 { vote_pubkey },
            ),
            // V3
            2 => deserialize_vote_state_into_v4(
                &mut cursor,
                vote_state,
                SourceVersion::V3 { vote_pubkey },
            ),
            // V4
            3 => deserialize_vote_state_into_v4(&mut cursor, vote_state, SourceVersion::V4),
            _ => Err(InstructionError::InvalidAccountData),
        }?;

        Ok(())
    }

    #[cfg(feature = "bincode")]
    pub fn serialize(
        versioned: &VoteStateVersions,
        output: &mut [u8],
    ) -> Result<(), InstructionError> {
        bincode::serialize_into(output, versioned).map_err(|err| match *err {
            bincode::ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        data.len() == VoteStateV4::size_of() && data[..4] == [3, 0, 0, 0] // little-endian 3u32
                                                                          // Always initialized
    }

    #[cfg(test)]
    pub(crate) fn get_max_sized_vote_state() -> Self {
        use {
            super::{MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY},
            solana_epoch_schedule::MAX_LEADER_SCHEDULE_EPOCH_OFFSET,
        };

        let mut authorized_voters = AuthorizedVoters::default();
        for i in 0..=MAX_LEADER_SCHEDULE_EPOCH_OFFSET {
            authorized_voters.insert(i, Pubkey::new_unique());
        }

        Self {
            votes: VecDeque::from(vec![LandedVote::default(); MAX_LOCKOUT_HISTORY]),
            root_slot: Some(u64::MAX),
            epoch_credits: vec![(0, 0, 0); MAX_EPOCH_CREDITS_HISTORY],
            authorized_voters,
            ..Self::default()
        }
    }
}

// Based off of serde's array impls. See:
// https://github.com/serde-rs/serde/blob/babafa54d283fb087fa94f50a2cf82fa9e582a7c/serde/src/de/impls.rs#L1268
#[cfg(feature = "serde")]
mod serde_bls_pubkey_compressed {
    #[cfg(feature = "frozen-abi")]
    use solana_frozen_abi_macro::AbiExample;
    use {
        super::BLS_PUBKEY_COMPRESSED_BYTES,
        serde::{
            de::{Error, SeqAccess, Visitor},
            ser::SerializeTuple,
            Deserializer, Serialize, Serializer,
        },
        std::fmt,
    };

    pub fn serialize<S>(
        value: &Option<[u8; BLS_PUBKEY_COMPRESSED_BYTES]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(array) => serializer.serialize_some(&ArrayWrapper(array)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<[u8; BLS_PUBKEY_COMPRESSED_BYTES]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(BLSPubkeyVisitor)
    }

    #[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
    struct ArrayWrapper<'a>(&'a [u8; BLS_PUBKEY_COMPRESSED_BYTES]);

    impl<'a> Serialize for ArrayWrapper<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_tuple(BLS_PUBKEY_COMPRESSED_BYTES)?;
            for element in self.0.iter() {
                seq.serialize_element(element)?;
            }
            seq.end()
        }
    }

    struct BLSPubkeyVisitor;

    impl<'de> Visitor<'de> for BLSPubkeyVisitor {
        type Value = Option<[u8; BLS_PUBKEY_COMPRESSED_BYTES]>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an optional BLS pubkey")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer
                .deserialize_tuple(BLS_PUBKEY_COMPRESSED_BYTES, ArrayVisitor)
                .map(Some)
        }
    }

    struct ArrayVisitor;

    impl<'de> Visitor<'de> for ArrayVisitor {
        type Value = [u8; BLS_PUBKEY_COMPRESSED_BYTES];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str(&format!("an array of {BLS_PUBKEY_COMPRESSED_BYTES} bytes"))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut array = [0u8; BLS_PUBKEY_COMPRESSED_BYTES];
            for (i, element) in array.iter_mut().enumerate() {
                *element = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(i, &self))?;
            }
            Ok(array)
        }
    }
}
