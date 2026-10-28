use {
    super::BLS_PUBLIC_KEY_COMPRESSED_SIZE,
    bytemuck::{Pod, Zeroable},
    solana_clock::{Epoch, Slot},
    solana_pubkey::Pubkey,
    std::mem::{offset_of, size_of},
};

const VOTE_ACCOUNT_V5_DISCRIMINANT: u32 = 4;
const VOTE_ACCOUNT_V5_SIZE: usize = 3762;
const MAX_COMMISSION_CHANGES: usize = 4;
const MAX_AUTHORIZED_VOTERS: usize = 4;
const MAX_ACCUMULATED_LAMPORTS: usize = 5;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct VoteAccountV5 {
    discriminant: u32,
    pub node_pubkey: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub inflation_rewards_collector: Pubkey,
    pub block_revenue_collector: Pubkey,
    pub location: Location,
    pub pending_delegator_rewards: u64,
    inflation_rewards_commission_bps_len: u32,
    block_revenue_commission_bps_len: u32,
    inflation_rewards_commission_bps_epochs: [Epoch; MAX_COMMISSION_CHANGES],
    inflation_rewards_commission_bps: [u16; MAX_COMMISSION_CHANGES],
    block_revenue_commission_bps_epochs: [Epoch; MAX_COMMISSION_CHANGES],
    block_revenue_commission_bps: [u16; MAX_COMMISSION_CHANGES],
    pub bls_pubkey_compressed: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    latest_vote: Slot,
    root_slot: Slot,
    authorized_voters_len: u32,
    accumulated_lamports_len: u32,
    authorized_voters: [AuthorizedVoter; MAX_AUTHORIZED_VOTERS],
    accumulated_lamports: [AccumulatedLamports; MAX_ACCUMULATED_LAMPORTS],
    pub last_timestamp: BlockTimestamp,
}

impl VoteAccountV5 {
    /// Returns a mutable view.
    pub fn try_new_mut(data: &mut [u8]) -> Option<&mut Self> {
        Self::try_new(data)?;
        // SAFETY: try_new checked the size and alignment.
        Some(unsafe { &mut *data.as_mut_ptr().cast::<Self>() })
    }

    /// Returns an immutable view.
    pub fn try_new(data: &[u8]) -> Option<&Self> {
        let ptr = data.as_ptr().cast::<Self>();
        if data.len() != VOTE_ACCOUNT_V5_SIZE || !ptr.is_aligned() {
            return None;
        }
        // SAFETY: data contains at least size_of::<Self>() initialized bytes,
        // ptr is aligned, and all fields (integers, byte arrays, and structs of
        // those types) accept all bit patterns. The reference borrows data.
        let state = unsafe { &*ptr };
        state.validate(&data[size_of::<Self>()..]).then_some(state)
    }

    /// Returns an owned copy.  Can be used if data is not aligned.
    pub fn try_new_unaligned(data: &[u8]) -> Option<Self> {
        if data.len() != VOTE_ACCOUNT_V5_SIZE {
            return None;
        }
        // SAFETY: data contains at least size_of::<Self>() initialized bytes,
        // and every field accepts all bit patterns. read_unaligned copies the
        // value without creating a reference or requiring an aligned pointer.
        let state = unsafe { data.as_ptr().cast::<Self>().read_unaligned() };
        state.validate(&data[size_of::<Self>()..]).then_some(state)
    }

    pub fn latest_vote(&self) -> Option<Slot> {
        (self.latest_vote == u64::MAX).then_some(self.latest_vote)
    }

    pub fn set_latest_vote(&mut self, slot: Slot) {
        self.latest_vote = slot;
    }

    pub fn root_slot(&self) -> Option<Slot> {
        (self.root_slot == u64::MAX).then_some(self.root_slot)
    }

    pub fn set_root_slot(&mut self, slot: Slot) {
        self.root_slot = slot;
    }

    pub fn inflation_rewards_commission(&self) -> Commission<'_> {
        Commission {
            epochs: &self.inflation_rewards_commission_bps_epochs
                [..self.inflation_rewards_commission_bps_len as usize],
            bps: &self.inflation_rewards_commission_bps
                [..self.inflation_rewards_commission_bps_len as usize],
        }
    }

    pub fn set_inflation_rewards_commission(&mut self, commission: Commission<'_>) {
        let Commission { epochs, bps } = commission;
        let mut epochs_buffer = [0; MAX_COMMISSION_CHANGES];
        epochs_buffer[..epochs.len()].copy_from_slice(epochs);
        let mut bps_buffer = [0; MAX_COMMISSION_CHANGES];
        bps_buffer[..bps.len()].copy_from_slice(bps);
        self.inflation_rewards_commission_bps_len = epochs.len() as u32;
        self.inflation_rewards_commission_bps_epochs = epochs_buffer;
        self.inflation_rewards_commission_bps = bps_buffer;
    }

    pub fn block_revenue_commission(&self) -> Commission<'_> {
        Commission {
            epochs: &self.block_revenue_commission_bps_epochs
                [..self.block_revenue_commission_bps_len as usize],
            bps: &self.block_revenue_commission_bps
                [..self.block_revenue_commission_bps_len as usize],
        }
    }

    pub fn set_block_revenue_commission(&mut self, commission: Commission<'_>) {
        let Commission { epochs, bps } = commission;
        let mut epochs_buffer = [0; MAX_COMMISSION_CHANGES];
        epochs_buffer[..epochs.len()].copy_from_slice(epochs);
        let mut bps_buffer = [0; MAX_COMMISSION_CHANGES];
        bps_buffer[..bps.len()].copy_from_slice(bps);
        self.block_revenue_commission_bps_len = epochs.len() as u32;
        self.block_revenue_commission_bps_epochs = epochs_buffer;
        self.block_revenue_commission_bps = bps_buffer;
    }

    pub fn authorized_voters(&self) -> AuthorizedVoters<'_> {
        AuthorizedVoters(&self.authorized_voters[..(self.authorized_voters_len as usize)])
    }

    pub fn set_authorized_voters(&mut self, voters: AuthorizedVoters) {
        let mut entries = [AuthorizedVoter::zeroed(); MAX_AUTHORIZED_VOTERS];
        entries[..voters.0.len()].copy_from_slice(voters.0);
        self.authorized_voters = entries;
        self.authorized_voters_len = voters.0.len() as u32;
    }

    pub fn accumulated_lamports(&self) -> AccumulatedLamportsList<'_> {
        AccumulatedLamportsList(
            &self.accumulated_lamports[..(self.accumulated_lamports_len as usize)],
        )
    }

    pub fn set_accumulated_lamports(&mut self, values: AccumulatedLamportsList) {
        let mut entries = [AccumulatedLamports::zeroed(); MAX_ACCUMULATED_LAMPORTS];
        entries[..values.0.len()].copy_from_slice(values.0);
        self.accumulated_lamports = entries;
        self.accumulated_lamports_len = values.0.len() as u32;
    }

    #[must_use]
    fn commission_is_valid(len: u32, epochs: &[u64], bps: &[u16]) -> bool {
        let len = len as usize;
        len <= MAX_COMMISSION_CHANGES
            && Commission::is_valid(&epochs[..len], &bps[..len])
            && is_zero(&epochs[len..])
            && is_zero(&bps[len..])
    }

    #[must_use]
    fn authorized_votes_is_valid(len: u32, data: &[AuthorizedVoter]) -> bool {
        let len = len as usize;
        len <= MAX_AUTHORIZED_VOTERS
            && AuthorizedVoters::validate(&data[..len])
            && is_zero(&data[len..])
    }

    #[must_use]
    fn accumulated_lamports_is_valid(len: u32, data: &[AccumulatedLamports]) -> bool {
        let len = len as usize;
        len <= MAX_ACCUMULATED_LAMPORTS
            && AccumulatedLamportsList::validate(&data[..len])
            && is_zero(&data[len..])
    }

    #[must_use]
    fn validate(&self, zeroed: &[u8]) -> bool {
        self.discriminant == VOTE_ACCOUNT_V5_DISCRIMINANT
            && Location::is_valid(self.location.x, self.location.y, self.location.z)
            && Self::commission_is_valid(
                self.inflation_rewards_commission_bps_len,
                &self.inflation_rewards_commission_bps_epochs,
                &self.inflation_rewards_commission_bps,
            )
            && Self::commission_is_valid(
                self.block_revenue_commission_bps_len,
                &self.block_revenue_commission_bps_epochs,
                &self.block_revenue_commission_bps,
            )
            && Self::authorized_votes_is_valid(self.authorized_voters_len, &self.authorized_voters)
            && Self::accumulated_lamports_is_valid(
                self.accumulated_lamports_len,
                &self.accumulated_lamports,
            )
            && is_zero(zeroed)
    }
}

const COORD_MAX: i32 = 6_378_138;
const SURFACE_DIST2: u64 = 40_680_631_590_769;
const FLATTENING_CORRECTION: u64 = 442;
const SURFACE_TOLERANCE: u64 = 12_756_274_000;

const _: () = {
    assert!(size_of::<VoteAccountV5>() == 608);
    assert!(offset_of!(VoteAccountV5, location) == 132);
    assert!(offset_of!(VoteAccountV5, pending_delegator_rewards) == 144);
    assert!(offset_of!(VoteAccountV5, block_revenue_commission_bps_len) == 156);
    assert!(offset_of!(VoteAccountV5, inflation_rewards_commission_bps_epochs) == 160);
    assert!(offset_of!(VoteAccountV5, block_revenue_commission_bps_epochs) == 200);
    assert!(offset_of!(VoteAccountV5, bls_pubkey_compressed) == 240);
    assert!(offset_of!(VoteAccountV5, accumulated_lamports_len) == 308);
    assert!(offset_of!(VoteAccountV5, authorized_voters) == 312);
    assert!(offset_of!(VoteAccountV5, accumulated_lamports) == 472);
    assert!(offset_of!(VoteAccountV5, last_timestamp) == 592);
};

#[must_use]
fn is_zero<T: Pod>(items: &[T]) -> bool {
    bytemuck::cast_slice::<T, u8>(items).iter().all(|&b| b == 0)
}

pub struct Commission<'a> {
    epochs: &'a [Epoch],
    bps: &'a [u16],
}

impl<'a> Commission<'a> {
    pub fn try_new(epochs: &'a [Epoch], bps: &'a [u16]) -> Option<Self> {
        Self::is_valid(epochs, bps).then_some(Self { epochs, bps })
    }

    pub fn len(&self) -> u32 {
        self.epochs.len() as u32
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }

    pub fn epochs(&self) -> &[Epoch] {
        self.epochs
    }

    pub fn bps(&self) -> &[u16] {
        self.bps
    }

    #[must_use]
    fn is_valid(epochs: &'a [Epoch], bps: &'a [u16]) -> bool {
        epochs.len() == bps.len() && !epochs.is_empty() && epochs.len() <= MAX_COMMISSION_CHANGES
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    x: i32,
    y: i32,
    z: i32,
}

impl Location {
    pub fn x(&self) -> i32 {
        self.x
    }

    pub fn y(&self) -> i32 {
        self.y
    }

    pub fn z(&self) -> i32 {
        self.z
    }

    pub fn try_new(x: i32, y: i32, z: i32) -> Option<Self> {
        Self::is_valid(x, y, z).then_some(Self { x, y, z })
    }

    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    fn is_valid(x: i32, y: i32, z: i32) -> bool {
        let in_range = |c: i32| (-COORD_MAX..=COORD_MAX).contains(&c);
        if !(in_range(x) && in_range(y) && in_range(z)) {
            return false;
        }
        let sqare = |c: i32| (c as i64 * c as i64) as u64;
        let z2 = sqare(z);
        let dist2 = sqare(x) + sqare(y) + z2 + ((FLATTENING_CORRECTION * z2) >> 16);
        (SURFACE_DIST2 - SURFACE_TOLERANCE..=SURFACE_DIST2 + SURFACE_TOLERANCE).contains(&dist2)
    }
}

pub struct AccumulatedLamportsList<'a>(&'a [AccumulatedLamports]);

impl<'a> AccumulatedLamportsList<'a> {
    pub fn try_new(data: &'a [AccumulatedLamports]) -> Option<Self> {
        Self::validate(data).then_some(Self(data))
    }

    pub fn get(&self) -> &[AccumulatedLamports] {
        self.0
    }

    #[must_use]
    fn validate(data: &'a [AccumulatedLamports]) -> bool {
        data.len() <= MAX_ACCUMULATED_LAMPORTS
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct AccumulatedLamports {
    pub epoch: u64,
    pub lamports: u64,
    pub prev_lamports: u64,
}

pub struct AuthorizedVoters<'a>(&'a [AuthorizedVoter]);

impl<'a> AuthorizedVoters<'a> {
    pub fn try_new(data: &'a [AuthorizedVoter]) -> Option<Self> {
        Self::validate(data).then_some(Self(data))
    }

    pub fn get(&self) -> &[AuthorizedVoter] {
        self.0
    }

    #[must_use]
    fn validate(data: &'a [AuthorizedVoter]) -> bool {
        data.len() <= MAX_AUTHORIZED_VOTERS && data.windows(2).all(|w| w[0].epoch < w[1].epoch)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct AuthorizedVoter {
    pub epoch: u64,
    pub pubkey: Pubkey,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct BlockTimestamp {
    pub slot: u64,
    pub timestamp: i64,
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[repr(C, align(8))]
    struct Aligned([u8; VOTE_ACCOUNT_V5_SIZE + 8]);

    fn put<T: Pod>(buf: &mut [u8], off: usize, v: T) {
        buf[off..off + size_of::<T>()].copy_from_slice(bytemuck::bytes_of(&v));
    }

    fn sample(buf: &mut [u8]) {
        buf.fill(0);
        put(
            buf,
            offset_of!(VoteAccountV5, discriminant),
            VOTE_ACCOUNT_V5_DISCRIMINANT,
        );
        put(buf, offset_of!(VoteAccountV5, node_pubkey), [0x11u8; 32]);
        put(
            buf,
            offset_of!(VoteAccountV5, location),
            [4051542i32, 618526, 4870645],
        );
        put(
            buf,
            offset_of!(VoteAccountV5, pending_delegator_rewards),
            999u64,
        );
        put(
            buf,
            offset_of!(VoteAccountV5, inflation_rewards_commission_bps_len),
            2u32,
        );
        put(
            buf,
            offset_of!(VoteAccountV5, block_revenue_commission_bps_len),
            1u32,
        );
        put(
            buf,
            offset_of!(VoteAccountV5, inflation_rewards_commission_bps_epochs),
            [5u64, 12],
        );
        put(
            buf,
            offset_of!(VoteAccountV5, inflation_rewards_commission_bps),
            [1234u16, 4321],
        );
        put(
            buf,
            offset_of!(VoteAccountV5, block_revenue_commission_bps_epochs),
            5u64,
        );
        put(
            buf,
            offset_of!(VoteAccountV5, block_revenue_commission_bps),
            5678u16,
        );
        put(buf, offset_of!(VoteAccountV5, authorized_voters_len), 2u32);
        put(
            buf,
            offset_of!(VoteAccountV5, accumulated_lamports_len),
            3u32,
        );
        put(
            buf,
            offset_of!(VoteAccountV5, authorized_voters),
            [10, 11].map(|epoch| AuthorizedVoter {
                epoch,
                pubkey: Pubkey::default(),
            }),
        );
        put(
            buf,
            offset_of!(VoteAccountV5, accumulated_lamports),
            AccumulatedLamports {
                epoch: 7,
                lamports: 0,
                prev_lamports: 0,
            },
        );
        put(
            buf,
            offset_of!(VoteAccountV5, last_timestamp),
            BlockTimestamp {
                slot: 4242,
                timestamp: 0,
            },
        );
    }

    #[test]
    fn commission_constructor_validates_slice_lengths() {
        assert!(Commission::try_new(&[], &[]).is_none());
        assert!(Commission::try_new(&[1], &[]).is_none());
        assert!(Commission::try_new(&[], &[1]).is_none());
        assert!(Commission::try_new(&[1, 2], &[3]).is_none());
        assert!(Commission::try_new(&[1], &[2, 3]).is_none());
        assert!(Commission::try_new(
            &[1; MAX_COMMISSION_CHANGES + 1],
            &[2; MAX_COMMISSION_CHANGES + 1],
        )
        .is_none());
        let epochs = [5, 12, 20, 30];
        let bps = [1, 2, 3, 4];
        for len in 1..=MAX_COMMISSION_CHANGES {
            let commission = Commission::try_new(&epochs[..len], &bps[..len]).unwrap();
            assert_eq!(commission.len(), len as u32);
            assert_eq!(commission.epochs(), &epochs[..len]);
            assert_eq!(commission.bps(), &bps[..len]);
            assert!(Commission::try_new(
                &[0; MAX_COMMISSION_CHANGES][..len],
                &[0; MAX_COMMISSION_CHANGES][..len]
            )
            .is_some());
        }
    }

    #[test]
    fn commission_setters_round_trip_and_preserve_account_invariants() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_ACCOUNT_V5_SIZE];
        sample(buf);
        for len in (1..=MAX_COMMISSION_CHANGES).rev() {
            let epochs = [20, 21, 22, 23];
            let bps = [100, 101, 102, 103];
            let s = VoteAccountV5::try_new_mut(buf).unwrap();
            let block_revenue = s.block_revenue_commission();
            let previous_epochs = block_revenue.epochs().to_vec();
            let previous_bps = block_revenue.bps().to_vec();
            s.set_inflation_rewards_commission(
                Commission::try_new(&epochs[..len], &bps[..len]).unwrap(),
            );
            let s = VoteAccountV5::try_new(buf).unwrap();
            let inflation = s.inflation_rewards_commission();
            assert_eq!(inflation.len(), len as u32);
            assert_eq!(inflation.epochs(), &epochs[..len]);
            assert_eq!(inflation.bps(), &bps[..len]);
            assert!(is_zero(&s.inflation_rewards_commission_bps_epochs[len..]));
            assert!(is_zero(&s.inflation_rewards_commission_bps[len..]));
            assert_eq!(s.block_revenue_commission().epochs(), previous_epochs);
            assert_eq!(s.block_revenue_commission().bps(), previous_bps);

            let block_bps = [200; MAX_COMMISSION_CHANGES];
            VoteAccountV5::try_new_mut(buf)
                .unwrap()
                .set_block_revenue_commission(
                    Commission::try_new(&epochs[..len], &block_bps[..len]).unwrap(),
                );
            let s = VoteAccountV5::try_new(buf).unwrap();
            let block_revenue = s.block_revenue_commission();
            assert_eq!(block_revenue.len(), len as u32);
            assert_eq!(block_revenue.epochs(), &epochs[..len]);
            assert_eq!(block_revenue.bps(), &block_bps[..len]);
            assert!(is_zero(&s.block_revenue_commission_bps_epochs[len..]));
            assert!(is_zero(&s.block_revenue_commission_bps[len..]));
            assert_eq!(s.inflation_rewards_commission().epochs(), &epochs[..len]);
            assert_eq!(s.inflation_rewards_commission().bps(), &bps[..len]);
        }
    }

    #[test]
    fn round_trip() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_ACCOUNT_V5_SIZE];
        sample(buf);
        let s = VoteAccountV5::try_new(buf).unwrap();
        assert_eq!(s.discriminant, VOTE_ACCOUNT_V5_DISCRIMINANT);
        assert_eq!(s.pending_delegator_rewards, 999);
        assert_eq!(s.inflation_rewards_commission().bps(), &[1234, 4321]);
        assert_eq!(s.block_revenue_commission().bps(), &[5678]);
        assert_eq!(s.authorized_voters().get()[1].epoch, 11);
        assert_eq!(s.last_timestamp.slot, 4242);

        let s = VoteAccountV5::try_new_mut(buf).unwrap();
        s.pending_delegator_rewards += 1;
        let location = Location::try_new(-4051542, 618526, 4870645).unwrap();
        s.location = location;
        assert_eq!(VoteAccountV5::try_new(buf).unwrap().location, location);
        assert_eq!(u64::from_le_bytes(buf[144..152].try_into().unwrap()), 1000);
    }

    #[test]
    fn authorized_voters_constructor_validates_length_and_epoch_order() {
        let voters = [0, 1, 2, u64::MAX].map(|epoch| AuthorizedVoter {
            epoch,
            pubkey: Pubkey::new_unique(),
        });
        for len in 0..=MAX_AUTHORIZED_VOTERS {
            let authorized = AuthorizedVoters::try_new(&voters[..len]).unwrap();
            assert_eq!(authorized.get(), &voters[..len]);
        }
        let oversized = [0, 1, 2, 3, 4].map(|epoch| AuthorizedVoter {
            epoch,
            pubkey: Pubkey::default(),
        });
        assert!(AuthorizedVoters::try_new(&oversized).is_none());
        assert!(AuthorizedVoters::try_new(&[voters[0], voters[0]]).is_none());
        assert!(AuthorizedVoters::try_new(&[voters[1], voters[0]]).is_none());
        assert!(AuthorizedVoters::try_new(&[voters[0], voters[2], voters[1]]).is_none());
    }

    #[test]
    fn accumulated_lamports_list_constructor_validates_length() {
        let entries =
            std::array::from_fn::<_, MAX_ACCUMULATED_LAMPORTS, _>(|i| AccumulatedLamports {
                epoch: i as Epoch,
                lamports: i as u64 + 100,
                prev_lamports: i as u64 + 50,
            });
        for len in 0..=MAX_ACCUMULATED_LAMPORTS {
            let list = AccumulatedLamportsList::try_new(&entries[..len]).unwrap();
            assert_eq!(list.get(), &entries[..len]);
        }
        assert!(AccumulatedLamportsList::try_new(
            &[AccumulatedLamports::zeroed(); MAX_ACCUMULATED_LAMPORTS + 1]
        )
        .is_none());
    }

    #[test]
    fn field_setters_preserve_account_invariants() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_ACCOUNT_V5_SIZE];
        sample(buf);
        let updates: &[fn(&mut VoteAccountV5)] = &[
            |s| {
                s.set_inflation_rewards_commission(
                    Commission::try_new(&[5, 12, 20, 30], &[1, 2, 3, 4]).unwrap(),
                );
            },
            |s| {
                s.set_inflation_rewards_commission(Commission::try_new(&[5, 12], &[1, 2]).unwrap());
            },
            |s| {
                s.set_block_revenue_commission(
                    Commission::try_new(&[5, 12, 20, 30], &[1, 2, 3, 4]).unwrap(),
                );
            },
            |s| {
                s.set_block_revenue_commission(Commission::try_new(&[5], &[1]).unwrap());
            },
            |s| {
                s.set_authorized_voters(AuthorizedVoters::try_new(&[]).unwrap());
            },
        ];
        for update in updates {
            update(VoteAccountV5::try_new_mut(buf).unwrap());
            assert!(VoteAccountV5::try_new(buf).is_some());
        }
    }

    #[test]
    fn collection_setters_resize_and_clear_unused_entries() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_ACCOUNT_V5_SIZE];
        sample(buf);
        let s = VoteAccountV5::try_new_mut(buf).unwrap();
        let voters = [10, 11, 12, 13].map(|epoch| AuthorizedVoter {
            epoch,
            pubkey: Pubkey::default(),
        });
        s.set_authorized_voters(AuthorizedVoters::try_new(&voters).unwrap());
        assert_eq!(s.authorized_voters().get(), &voters);
        s.set_authorized_voters(AuthorizedVoters::try_new(&voters[..1]).unwrap());
        assert_eq!(s.authorized_voters().get(), &voters[..1]);
        assert!(is_zero(&s.authorized_voters[1..]));
        s.set_authorized_voters(AuthorizedVoters::try_new(&[]).unwrap());
        assert!(s.authorized_voters().get().is_empty());
        assert!(is_zero(&s.authorized_voters));

        let lamports = [AccumulatedLamports {
            epoch: 10,
            lamports: 123,
            prev_lamports: 100,
        }; MAX_ACCUMULATED_LAMPORTS];
        s.set_accumulated_lamports(AccumulatedLamportsList::try_new(&lamports).unwrap());
        assert_eq!(s.accumulated_lamports().get(), &lamports);
        s.set_accumulated_lamports(AccumulatedLamportsList::try_new(&lamports[..1]).unwrap());
        assert_eq!(s.accumulated_lamports().get(), &lamports[..1]);
        assert!(is_zero(&s.accumulated_lamports[1..]));
        s.set_accumulated_lamports(AccumulatedLamportsList::try_new(&[]).unwrap());
        assert!(s.accumulated_lamports().get().is_empty());
        assert!(is_zero(&s.accumulated_lamports));

        s.set_inflation_rewards_commission(
            Commission::try_new(&[5, 12, 20, 30], &[1, 2, 3, 4]).unwrap(),
        );
        let commission = s.inflation_rewards_commission();
        let epochs = commission.epochs().to_vec();
        let mut bps = commission.bps().to_vec();
        bps[commission.len() as usize - 1] = 99;
        s.set_inflation_rewards_commission(Commission::try_new(&epochs, &bps).unwrap());
        assert_eq!(s.inflation_rewards_commission().bps()[3], 99);
        assert_eq!(&s.inflation_rewards_commission().bps()[..3], &[1, 2, 3]);
        s.set_inflation_rewards_commission(Commission::try_new(&[40], &[5]).unwrap());
        assert_eq!(s.inflation_rewards_commission().len(), 1);
        assert_eq!(s.inflation_rewards_commission().epochs(), &[40]);
        assert_eq!(s.inflation_rewards_commission().bps(), &[5]);

        s.set_block_revenue_commission(Commission::try_new(&[5, 12], &[6, 7]).unwrap());
        let commission = s.block_revenue_commission();
        let epochs = commission.epochs().to_vec();
        let mut bps = commission.bps().to_vec();
        bps[commission.len() as usize - 1] = 88;
        s.set_block_revenue_commission(Commission::try_new(&epochs, &bps).unwrap());
        assert_eq!(s.block_revenue_commission().bps()[1], 88);
        assert_eq!(s.block_revenue_commission().bps(), &[6, 88]);
        s.set_block_revenue_commission(Commission::try_new(&[20], &[8]).unwrap());
        assert_eq!(s.block_revenue_commission().len(), 1);
        assert_eq!(s.block_revenue_commission().epochs(), &[20]);
        assert_eq!(s.block_revenue_commission().bps(), &[8]);
        assert!(VoteAccountV5::try_new(buf).is_some());
    }

    #[test]
    fn misaligned() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[4..4 + VOTE_ACCOUNT_V5_SIZE];
        sample(buf);
        assert!(VoteAccountV5::try_new(buf).is_none());
        assert!(VoteAccountV5::try_new_mut(buf).is_none());
    }

    #[test]
    fn unaligned_constructor_returns_independent_owned_copy() {
        // Exercise aligned data and every possible misalignment.
        for offset in 0..std::mem::align_of::<VoteAccountV5>() {
            let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
            let buf = &mut storage.0[offset..offset + VOTE_ACCOUNT_V5_SIZE];
            sample(buf);
            let mut state = VoteAccountV5::try_new_unaligned(buf).unwrap();
            assert_eq!(state.discriminant, VOTE_ACCOUNT_V5_DISCRIMINANT);
            assert_eq!(state.pending_delegator_rewards, 999);
            assert_eq!(state.inflation_rewards_commission().bps(), &[1234, 4321]);
            assert_eq!(state.block_revenue_commission().bps(), &[5678]);
            assert_eq!(state.authorized_voters().get()[1].epoch, 11);
            assert_eq!(state.last_timestamp.slot, 4242);
            state.pending_delegator_rewards = 1000;
            assert_eq!(u64::from_le_bytes(buf[144..152].try_into().unwrap()), 999);
            buf.fill(0);
            assert_eq!(state.pending_delegator_rewards, 1000);
        }
    }

    #[test]
    fn rejects() {
        let mut storage = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_ACCOUNT_V5_SIZE];
        let cases: &[fn(&mut [u8])] = &[
            |b| put(b, 0, 3u32),
            |b| put(b, 140, 0i32),
            |b| put(b, 152, 0u32),
            |b| put(b, 156, 5u32),
            |b| put(b, 176, 13u64),
            |b| put(b, 196, 1u16),
            |b| put(b, 304, 5u32),
            |b| put(b, 352, 10u64),
            |b| b[312 + 3 * 40] = 1,
            |b| put(b, 308, MAX_ACCUMULATED_LAMPORTS as u32 + 1),
            |b| b[472 + 3 * size_of::<AccumulatedLamports>()] = 1,
            |b| b[3761] = 1,
        ];
        for mutate in cases {
            sample(buf);
            assert!(VoteAccountV5::try_new(buf).is_some());
            mutate(buf);
            assert!(VoteAccountV5::try_new(buf).is_none());
            assert!(VoteAccountV5::try_new_mut(buf).is_none());
            assert!(VoteAccountV5::try_new_unaligned(buf).is_none());
            // Validate the same malformed data at a misaligned address.
            let mut unaligned = Aligned([0; VOTE_ACCOUNT_V5_SIZE + 8]);
            unaligned.0[1..1 + VOTE_ACCOUNT_V5_SIZE].copy_from_slice(buf);
            assert!(
                VoteAccountV5::try_new_unaligned(&unaligned.0[1..1 + VOTE_ACCOUNT_V5_SIZE])
                    .is_none()
            );
        }
        for len in [0, size_of::<VoteAccountV5>() - 1, VOTE_ACCOUNT_V5_SIZE - 1] {
            assert!(VoteAccountV5::try_new(&buf[..len]).is_none());
            assert!(VoteAccountV5::try_new_unaligned(&buf[..len]).is_none());
            assert!(VoteAccountV5::try_new_mut(&mut buf[..len]).is_none());
        }
        assert!(VoteAccountV5::try_new(&storage.0).is_none());
        assert!(VoteAccountV5::try_new_unaligned(&storage.0).is_none());
        assert!(VoteAccountV5::try_new_mut(&mut storage.0).is_none());
    }
}
