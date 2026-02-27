#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
use {solana_clock::Epoch, solana_pubkey::Pubkey, std::collections::BTreeMap};

/// Epoch-keyed map of authorized vote signers.
///
/// An authorized voter set at a given epoch remains in effect for all
/// subsequent epochs until explicitly overridden by a new entry ("carry-
/// forward" semantics). The map must never be empty — an empty map is the
/// sentinel for an uninitialized vote state.
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct AuthorizedVoters {
    authorized_voters: BTreeMap<Epoch, Pubkey>,
}

impl AuthorizedVoters {
    /// Creates a new `AuthorizedVoters` with a single entry mapping `epoch`
    /// to `pubkey`.
    pub fn new(epoch: Epoch, pubkey: Pubkey) -> Self {
        let mut authorized_voters = BTreeMap::new();
        authorized_voters.insert(epoch, pubkey);
        Self { authorized_voters }
    }

    /// Returns the authorized voter for the given `epoch`.
    ///
    /// If an exact entry exists for `epoch`, that voter is returned. Otherwise
    /// the voter from the highest epoch *before* the requested one is carried
    /// forward (the authorized voter is assumed unchanged until explicitly
    /// overridden). Returns `None` when `epoch` is earlier than all entries
    /// (i.e. the relevant history has already been purged).
    pub fn get_authorized_voter(&self, epoch: Epoch) -> Option<Pubkey> {
        self.get_or_calculate_authorized_voter_for_epoch(epoch)
            .map(|(pubkey, _)| pubkey)
    }

    /// Like [`get_authorized_voter`](Self::get_authorized_voter), but when the
    /// result is *calculated* (carried forward from a prior epoch rather than
    /// found as an exact entry) the mapping is inserted into the map so that
    /// future lookups for the same epoch are direct hits.
    pub fn get_and_cache_authorized_voter_for_epoch(&mut self, epoch: Epoch) -> Option<Pubkey> {
        let res = self.get_or_calculate_authorized_voter_for_epoch(epoch);

        res.map(|(pubkey, existed)| {
            if !existed {
                self.authorized_voters.insert(epoch, pubkey);
            }
            pubkey
        })
    }

    /// Inserts or overwrites the authorized voter for the given `epoch`.
    pub fn insert(&mut self, epoch: Epoch, authorized_voter: Pubkey) {
        self.authorized_voters.insert(epoch, authorized_voter);
    }

    /// Removes all entries with epoch strictly less than `current_epoch`.
    ///
    /// # Panics
    ///
    /// Panics if purging would leave the map empty. The map must always
    /// contain at least one entry because:
    /// 1. An empty map is the sentinel for an uninitialized vote state.
    /// 2. The carry-forward lookup relies on at least one entry existing.
    pub fn purge_authorized_voters(&mut self, current_epoch: Epoch) -> bool {
        // Iterate through the keys in order, filtering out the ones
        // less than the current epoch
        let expired_keys: Vec<_> = self
            .authorized_voters
            .range(0..current_epoch)
            .map(|(authorized_epoch, _)| *authorized_epoch)
            .collect();

        for key in expired_keys {
            self.authorized_voters.remove(&key);
        }

        // Have to uphold this invariant b/c this is
        // 1) The check for whether the vote state is initialized
        // 2) How future authorized voters for uninitialized epochs are set
        //    by this function
        assert!(!self.authorized_voters.is_empty());
        true
    }

    pub fn is_empty(&self) -> bool {
        self.authorized_voters.is_empty()
    }

    pub fn first(&self) -> Option<(&u64, &Pubkey)> {
        self.authorized_voters.iter().next()
    }

    pub fn last(&self) -> Option<(&u64, &Pubkey)> {
        self.authorized_voters.iter().next_back()
    }

    pub fn len(&self) -> usize {
        self.authorized_voters.len()
    }

    pub fn contains(&self, epoch: Epoch) -> bool {
        self.authorized_voters.contains_key(&epoch)
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, Epoch, Pubkey> {
        self.authorized_voters.iter()
    }

    /// Returns `(pubkey, existed)` for the given `epoch`, where `existed`
    /// indicates whether the entry was an exact map hit (`true`) or was
    /// carried forward from the nearest prior epoch (`false`). Returns
    /// `None` when `epoch` precedes all entries in the map.
    fn get_or_calculate_authorized_voter_for_epoch(&self, epoch: Epoch) -> Option<(Pubkey, bool)> {
        let res = self.authorized_voters.get(&epoch);
        if res.is_none() {
            // If no authorized voter has been set yet for this epoch,
            // this must mean the authorized voter remains unchanged
            // from the latest epoch before this one
            let res = self.authorized_voters.range(0..epoch).next_back();

            /*
            if res.is_none() {
                warn!(
                    "Tried to query for the authorized voter of an epoch earlier
                    than the current epoch. Earlier epochs have been purged"
                );
            }
            */

            res.map(|(_, pubkey)| (*pubkey, false))
        } else {
            res.map(|pubkey| (*pubkey, true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let pubkey = Pubkey::new_unique();
        let voters = AuthorizedVoters::new(10, pubkey);
        assert_eq!(voters.len(), 1);
        assert_eq!(voters.first(), Some((&10, &pubkey)));
    }

    #[test]
    fn test_get_authorized_voter_exact_match() {
        let pubkey = Pubkey::new_unique();
        let voters = AuthorizedVoters::new(5, pubkey);
        assert_eq!(voters.get_authorized_voter(5), Some(pubkey));
    }

    #[test]
    fn test_get_authorized_voter_carries_forward() {
        let pubkey = Pubkey::new_unique();
        let voters = AuthorizedVoters::new(5, pubkey);
        // No entry at epoch 10, so the voter from epoch 5 carries forward.
        assert_eq!(voters.get_authorized_voter(10), Some(pubkey));
    }

    #[test]
    fn test_get_authorized_voter_returns_none_before_first_entry() {
        let voters = AuthorizedVoters::new(5, Pubkey::new_unique());
        // Epoch 3 is before the only entry (epoch 5), so there is nothing
        // to carry forward and the result is None.
        assert_eq!(voters.get_authorized_voter(3), None);
    }

    #[test]
    fn test_get_authorized_voter_returns_none_on_empty() {
        let voters = AuthorizedVoters::default();
        assert_eq!(voters.get_authorized_voter(0), None);
    }

    #[test]
    fn test_get_authorized_voter_multiple_entries() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pk_a);
        voters.insert(10, pk_b);
        voters.insert(15, pk_c);

        // Before any entry.
        assert_eq!(voters.get_authorized_voter(3), None);
        // Exact matches.
        assert_eq!(voters.get_authorized_voter(5), Some(pk_a));
        assert_eq!(voters.get_authorized_voter(10), Some(pk_b));
        assert_eq!(voters.get_authorized_voter(15), Some(pk_c));
        // Carry-forward from the nearest prior entry.
        assert_eq!(voters.get_authorized_voter(7), Some(pk_a));
        assert_eq!(voters.get_authorized_voter(12), Some(pk_b));
        assert_eq!(voters.get_authorized_voter(20), Some(pk_c));
    }

    #[test]
    fn test_get_and_cache_exact_hit_does_not_duplicate() {
        let pubkey = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pubkey);
        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(5),
            Some(pubkey)
        );
        // Map should still contain exactly one entry.
        assert_eq!(voters.len(), 1);
    }

    #[test]
    fn test_get_and_cache_inserts_calculated_entry() {
        let pubkey = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pubkey);
        assert!(!voters.contains(10));

        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(10),
            Some(pubkey)
        );
        // The carried-forward result should now be cached.
        assert!(voters.contains(10));
        assert_eq!(voters.len(), 2);
    }

    #[test]
    fn test_get_and_cache_returns_none_before_first_entry() {
        let mut voters = AuthorizedVoters::new(5, Pubkey::new_unique());
        assert_eq!(voters.get_and_cache_authorized_voter_for_epoch(3), None);
        // Nothing should have been inserted.
        assert_eq!(voters.len(), 1);
    }

    #[test]
    fn test_insert() {
        let mut voters = AuthorizedVoters::default();
        let pk = Pubkey::new_unique();
        voters.insert(7, pk);
        assert!(voters.contains(7));
        assert_eq!(voters.get_authorized_voter(7), Some(pk));
    }

    #[test]
    fn test_insert_overwrites() {
        let pk_old = Pubkey::new_unique();
        let pk_new = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pk_old);
        voters.insert(5, pk_new);
        assert_eq!(voters.len(), 1);
        assert_eq!(voters.get_authorized_voter(5), Some(pk_new));
    }

    #[test]
    fn test_purge_removes_old_entries() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pk_a);
        voters.insert(10, pk_b);
        voters.insert(15, pk_c);

        voters.purge_authorized_voters(10);
        // Epoch 5 should be removed (5 < 10); epochs 10 and 15 remain.
        assert!(!voters.contains(5));
        assert!(voters.contains(10));
        assert!(voters.contains(15));
        assert_eq!(voters.len(), 2);
    }

    #[test]
    fn test_purge_keeps_current_epoch_entry() {
        let pk = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(10, pk);
        voters.purge_authorized_voters(10);
        // Epoch 10 is not < 10, so it survives.
        assert_eq!(voters.len(), 1);
        assert!(voters.contains(10));
    }

    #[test]
    fn test_purge_at_epoch_zero_removes_nothing() {
        let mut voters = AuthorizedVoters::new(0, Pubkey::new_unique());
        voters.purge_authorized_voters(0);
        assert_eq!(voters.len(), 1);
    }

    #[test]
    #[should_panic(expected = "authorized_voters.is_empty()")]
    fn test_purge_panics_when_all_entries_expired() {
        let mut voters = AuthorizedVoters::new(5, Pubkey::new_unique());
        // current_epoch = 10 means epoch 5 is expired, leaving the map
        // empty — which violates the invariant and triggers the assert.
        voters.purge_authorized_voters(10);
    }

    #[test]
    fn test_purge_returns_true() {
        let mut voters = AuthorizedVoters::new(5, Pubkey::new_unique());
        voters.insert(10, Pubkey::new_unique());
        assert!(voters.purge_authorized_voters(10));
    }

    #[test]
    fn test_is_empty() {
        let voters = AuthorizedVoters::default();
        assert!(voters.is_empty());

        let voters = AuthorizedVoters::new(0, Pubkey::new_unique());
        assert!(!voters.is_empty());
    }

    #[test]
    fn test_first_and_last_single_entry() {
        let pk = Pubkey::new_unique();
        let voters = AuthorizedVoters::new(5, pk);
        assert_eq!(voters.first(), Some((&5, &pk)));
        assert_eq!(voters.last(), Some((&5, &pk)));
    }

    #[test]
    fn test_first_and_last_multiple_entries() {
        let pk_a = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pk_a);
        voters.insert(10, Pubkey::new_unique());
        voters.insert(15, pk_c);
        assert_eq!(voters.first(), Some((&5, &pk_a)));
        assert_eq!(voters.last(), Some((&15, &pk_c)));
    }

    #[test]
    fn test_first_and_last_empty() {
        let voters = AuthorizedVoters::default();
        assert_eq!(voters.first(), None);
        assert_eq!(voters.last(), None);
    }

    #[test]
    fn test_len() {
        let mut voters = AuthorizedVoters::default();
        assert_eq!(voters.len(), 0);
        voters.insert(1, Pubkey::new_unique());
        assert_eq!(voters.len(), 1);
        voters.insert(2, Pubkey::new_unique());
        assert_eq!(voters.len(), 2);
    }

    #[test]
    fn test_contains() {
        let mut voters = AuthorizedVoters::new(5, Pubkey::new_unique());
        assert!(voters.contains(5));
        assert!(!voters.contains(6));
        voters.insert(6, Pubkey::new_unique());
        assert!(voters.contains(6));
    }

    #[test]
    fn test_iter() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(5, pk_a);
        voters.insert(10, pk_b);

        let entries: Vec<_> = voters.iter().collect();
        // BTreeMap iterates in key order.
        assert_eq!(entries, vec![(&5, &pk_a), (&10, &pk_b)]);
    }

    #[test]
    fn test_iter_empty() {
        let voters = AuthorizedVoters::default();
        assert_eq!(voters.iter().count(), 0);
    }

    #[test]
    fn test_cache_then_purge_retains_current_epoch() {
        let pk = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk);

        // Simulate advancing to epoch 5: cache the carried-forward
        // voter, then purge everything before epoch 5.
        let got = voters.get_and_cache_authorized_voter_for_epoch(5);
        assert_eq!(got, Some(pk));

        voters.purge_authorized_voters(5);
        // The cached epoch-5 entry must survive the purge.
        assert_eq!(voters.len(), 1);
        assert!(voters.contains(5));
        assert_eq!(voters.get_authorized_voter(5), Some(pk));
    }

    #[test]
    fn test_cache_then_purge_across_voter_change() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk_a);

        // A new voter is scheduled for epoch 7.
        voters.insert(7, pk_b);

        // Epoch 5: still the original voter. Cache + purge.
        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(5),
            Some(pk_a)
        );
        voters.purge_authorized_voters(5);
        // Epoch 0 purged; epochs 5 and 7 remain.
        assert_eq!(voters.len(), 2);
        assert!(!voters.contains(0));
        assert!(voters.contains(5));
        assert!(voters.contains(7));

        // Epoch 6: still the original voter (carried from 5). Cache + purge.
        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(6),
            Some(pk_a)
        );
        voters.purge_authorized_voters(6);
        // Epoch 5 purged; epochs 6 and 7 remain.
        assert_eq!(voters.len(), 2);
        assert!(voters.contains(6));
        assert!(voters.contains(7));

        // Epoch 7: the new voter takes effect. Cache + purge.
        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(7),
            Some(pk_b)
        );
        voters.purge_authorized_voters(7);
        // Epoch 6 purged; only epoch 7 remains.
        assert_eq!(voters.len(), 1);
        assert!(voters.contains(7));
        assert_eq!(voters.get_authorized_voter(7), Some(pk_b));
    }

    #[test]
    fn test_cache_then_purge_with_v4_offset() {
        // VoteStateV4 purges at current_epoch - 1 instead of current_epoch,
        // retaining one extra epoch of history.
        let pk = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk);

        // Epoch 5: cache, then purge at epoch 4 (v4-style).
        assert_eq!(voters.get_and_cache_authorized_voter_for_epoch(5), Some(pk));
        voters.purge_authorized_voters(4);
        // Epoch 0 purged; epochs 4 was never cached so only 5 remains.
        assert_eq!(voters.len(), 1);
        assert!(!voters.contains(4));
        assert!(voters.contains(5));

        // Now let's also cache epoch 4 to see both retained.
        let mut voters = AuthorizedVoters::new(0, pk);
        assert_eq!(voters.get_and_cache_authorized_voter_for_epoch(4), Some(pk));
        assert_eq!(voters.get_and_cache_authorized_voter_for_epoch(5), Some(pk));
        voters.purge_authorized_voters(4);
        // Epoch 0 purged; epochs 4 and 5 survive.
        assert_eq!(voters.len(), 2);
        assert!(voters.contains(4));
        assert!(voters.contains(5));
    }

    #[test]
    fn test_cache_then_purge_repeated_epochs() {
        // Repeatedly calling cache + purge for the same epoch should be
        // idempotent — the entry is already an exact hit on the second call.
        let pk = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk);

        for _ in 0..3 {
            assert_eq!(voters.get_and_cache_authorized_voter_for_epoch(5), Some(pk));
            voters.purge_authorized_voters(5);
            assert_eq!(voters.len(), 1);
            assert!(voters.contains(5));
        }
    }

    #[test]
    fn test_cache_then_purge_skipping_epochs() {
        // Jumping from epoch 0 straight to epoch 100 — a large gap should
        // work the same as a small one.
        let pk = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk);

        assert_eq!(
            voters.get_and_cache_authorized_voter_for_epoch(100),
            Some(pk)
        );
        voters.purge_authorized_voters(100);
        assert_eq!(voters.len(), 1);
        assert!(voters.contains(100));
        assert_eq!(voters.get_authorized_voter(100), Some(pk));
    }

    #[test]
    fn test_set_then_cache_then_purge_multiple_changes() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let mut voters = AuthorizedVoters::new(0, pk_a);
        voters.insert(5, pk_b);
        voters.insert(10, pk_c);

        // Walk forward epoch-by-epoch through the transitions.
        let expected: &[(Epoch, Pubkey)] = &[
            (3, pk_a),
            (4, pk_a),
            (5, pk_b),
            (6, pk_b),
            (9, pk_b),
            (10, pk_c),
            (11, pk_c),
            (15, pk_c),
        ];

        for &(epoch, expected_pk) in expected {
            let got = voters
                .get_and_cache_authorized_voter_for_epoch(epoch)
                .unwrap();
            assert_eq!(got, expected_pk, "mismatch at epoch {epoch}");
            voters.purge_authorized_voters(epoch);
            // The entry we just cached must survive.
            assert!(voters.contains(epoch));
        }
    }
}
