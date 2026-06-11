use {
    crate::stable_abi::{
        context::{impl_with_context_via, SequenceLenMax, SequenceLenRange},
        StableAbi,
    },
    core::{array, marker::PhantomData, num::NonZero},
    rand::{Rng, RngCore},
    std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
        hash::{BuildHasher, Hash},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        rc::Rc,
        sync::Arc,
    },
};

pub(crate) const DEFAULT_COLLECTION_MAX_SAMPLE_LEN: usize = 5;
const DEFAULT_COLLECTION_MAX_SAMPLE_LEN_NON_DETERMINISTIC_ORDER: usize = 1;

macro_rules! impl_stable_abi_via_standard_uniform {
    ($($t:ty),* $(,)?) => {
        $(
            impl StableAbi for $t {
                fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
                    rng.random()
                }
            }
        )*
    };
}

macro_rules! impl_stable_abi_via_size_of_from_bytes {
    ($from_bytes:ident, $($t:ty),* $(,)?) => {
        $(
            impl StableAbi for $t {
                fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
                    Self::$from_bytes(rng.random())
                }
            }
        )*
    };
}

macro_rules! impl_stable_abi_for_tuples {
    ($(($($t:ident),+ $(,)?)),* $(,)?) => {
        $(
            impl<$($t),+> StableAbi for ($($t,)+)
            where
                $($t: StableAbi),+,
            {
                fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
                    ($($t::random(rng),)+)
                }
            }
        )*
    };
}

impl_stable_abi_via_standard_uniform!(
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    f32,
    f64,
    bool,
    char,
    NonZero<u8>,
    NonZero<u16>,
    NonZero<u32>,
    NonZero<u64>,
    NonZero<u128>,
    NonZero<i8>,
    NonZero<i16>,
    NonZero<i32>,
    NonZero<i64>,
    NonZero<i128>,
);
impl_stable_abi_via_size_of_from_bytes!(from_le_bytes, usize);
impl_stable_abi_via_size_of_from_bytes!(from_le_bytes, isize);
impl_stable_abi_for_tuples!(
    (A),
    (A, B),
    (A, B, C),
    (A, B, C, D),
    (A, B, C, D, E),
    (A, B, C, D, E, F),
    (A, B, C, D, E, F, G),
    (A, B, C, D, E, F, G, H),
    (A, B, C, D, E, F, G, H, I),
    (A, B, C, D, E, F, G, H, I, J),
    (A, B, C, D, E, F, G, H, I, J, K),
    (A, B, C, D, E, F, G, H, I, J, K, L),
);

impl<T, const N: usize> StableAbi for [T; N]
where
    T: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        array::from_fn(|_| T::random(rng))
    }
}

impl<T> StableAbi for Option<T>
where
    T: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        rng.random::<bool>().then(|| T::random(rng))
    }
}

// keep at most one element to mitigate iteration order differences
impl_with_context_via! {
    impl<K, V, S> StableAbi<()> for HashMap<K, V, S>
    where { K: StableAbi + Eq + Hash, V: StableAbi, S: BuildHasher + Default },
    |_| SequenceLenRange::new(0..=DEFAULT_COLLECTION_MAX_SAMPLE_LEN_NON_DETERMINISTIC_ORDER),
}

impl<K, V, S> StableAbi<SequenceLenRange> for HashMap<K, V, S>
where
    K: StableAbi + Eq + Hash,
    V: StableAbi,
    S: BuildHasher + Default,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| (K::random(rng), V::random(rng))).collect()
    }
}

impl_with_context_via! {
    impl<K, V, S> StableAbi<SequenceLenMax> for HashMap<K, V, S>
    where { K: StableAbi + Eq + Hash, V: StableAbi, S: BuildHasher + Default },
    |ctx| SequenceLenRange::from(ctx),
}

// keep at most one element to mitigate iteration order differences
impl_with_context_via! {
    impl<T, S> StableAbi<()> for HashSet<T, S>
    where { T: StableAbi + Eq + Hash, S: BuildHasher + Default },
    |_| SequenceLenRange::new(0..=DEFAULT_COLLECTION_MAX_SAMPLE_LEN_NON_DETERMINISTIC_ORDER),
}

impl<T, S> StableAbi<SequenceLenRange> for HashSet<T, S>
where
    T: StableAbi + Eq + Hash,
    S: BuildHasher + Default,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| T::random(rng)).collect()
    }
}

impl_with_context_via! {
    impl<T, S> StableAbi<SequenceLenMax> for HashSet<T, S>
    where { T: StableAbi + Eq + Hash, S: BuildHasher + Default },
    |ctx| SequenceLenRange::from(ctx),
}

impl_with_context_via! {
    impl<T> StableAbi<()> for Vec<T>
    where { T: StableAbi },
    |_| SequenceLenRange::new(0..=DEFAULT_COLLECTION_MAX_SAMPLE_LEN),
}

impl<T> StableAbi<SequenceLenRange> for Vec<T>
where
    T: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| T::random(rng)).collect()
    }
}

impl_with_context_via! {
    impl<T> StableAbi<SequenceLenMax> for Vec<T>
    where { T: StableAbi },
    |ctx| SequenceLenRange::from(ctx),
}

impl_with_context_via! {
    impl<T> StableAbi<()> for VecDeque<T>
    where { T: StableAbi },
    |_| SequenceLenRange::new(0..=DEFAULT_COLLECTION_MAX_SAMPLE_LEN),
}

impl<T> StableAbi<SequenceLenRange> for VecDeque<T>
where
    T: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| T::random(rng)).collect()
    }
}

impl_with_context_via! {
    impl<T> StableAbi<SequenceLenMax> for VecDeque<T>
    where { T: StableAbi },
    |ctx| SequenceLenRange::from(ctx),
}

impl_with_context_via! {
    impl<K, V> StableAbi<()> for BTreeMap<K, V>
    where { K: StableAbi + Ord, V: StableAbi },
    |_| SequenceLenRange::new(0..DEFAULT_COLLECTION_MAX_SAMPLE_LEN),
}

impl<K, V> StableAbi<SequenceLenRange> for BTreeMap<K, V>
where
    K: StableAbi + Ord,
    V: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| (K::random(rng), V::random(rng))).collect()
    }
}

impl_with_context_via! {
    impl<K, V> StableAbi<SequenceLenMax> for BTreeMap<K, V>
    where { K: StableAbi + Ord, V: StableAbi },
    |ctx| SequenceLenRange::from(ctx),
}

impl_with_context_via! {
    impl<T> StableAbi<()> for BTreeSet<T>
    where { T: StableAbi + Ord },
    |_| SequenceLenRange::new(0..=DEFAULT_COLLECTION_MAX_SAMPLE_LEN),
}

impl<T> StableAbi<SequenceLenRange> for BTreeSet<T>
where
    T: StableAbi + Ord,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: SequenceLenRange) -> Self {
        let len = rng.random_range(ctx.min..=ctx.max);
        (0..len).map(|_| T::random(rng)).collect()
    }
}

impl_with_context_via! {
    impl<T> StableAbi<SequenceLenMax> for BTreeSet<T>
    where { T: StableAbi + Ord },
    |ctx| SequenceLenRange::from(ctx),
}

impl StableAbi for () {
    fn random_with_context(_rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {}
}

impl<T> StableAbi for PhantomData<T> {
    fn random_with_context(_rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        PhantomData
    }
}

// Smart pointers serialize transparently as their pointee, so forward the
// context to the inner type and wrap the result.
macro_rules! impl_stable_abi_for_pointer {
    ($($ptr:ident),* $(,)?) => {
        $(
            impl<Ctx, T> StableAbi<Ctx> for $ptr<T>
            where
                T: StableAbi<Ctx>,
            {
                fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: Ctx) -> Self {
                    $ptr::new(T::random_with_context(rng, ctx))
                }
            }
        )*
    };
}
impl_stable_abi_for_pointer!(Box, Rc, Arc);

impl<T, E> StableAbi for Result<T, E>
where
    T: StableAbi,
    E: StableAbi,
{
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        if rng.random::<bool>() {
            Ok(T::random(rng))
        } else {
            Err(E::random(rng))
        }
    }
}

impl StableAbi for Ipv4Addr {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        Ipv4Addr::from(rng.random::<u32>())
    }
}

impl StableAbi for Ipv6Addr {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        Ipv6Addr::from(rng.random::<u128>())
    }
}

impl StableAbi for IpAddr {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        if rng.random::<bool>() {
            IpAddr::V4(Ipv4Addr::random(rng))
        } else {
            IpAddr::V6(Ipv6Addr::random(rng))
        }
    }
}

impl StableAbi for SocketAddrV4 {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        SocketAddrV4::new(Ipv4Addr::random(rng), rng.random())
    }
}

impl StableAbi for SocketAddrV6 {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        // `flowinfo` and `scope_id` are not part of the serialized form, so we
        // leave them at their default (`0`) instead of sampling them. This keeps
        // the sampled value round-trip stable (`deserialize(serialize(x)) == x`),
        // which is what lets `test_roundtrip` cover this type.
        SocketAddrV6::new(Ipv6Addr::random(rng), rng.random(), 0, 0)
    }
}

impl StableAbi for SocketAddr {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), _ctx: ()) -> Self {
        if rng.random::<bool>() {
            SocketAddr::V4(SocketAddrV4::random(rng))
        } else {
            SocketAddr::V6(SocketAddrV6::random(rng))
        }
    }
}

#[cfg(all(test, feature = "frozen-abi"))]
mod tests {
    use {
        crate::stable_abi::context::{SequenceLenMax, SequenceLenRange},
        core::num::NonZero,
        std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, LinkedList, VecDeque},
    };

    const ABI_SHARED_WINCODE_VS_BINCODE: &str = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY";
    const API_SHARED_SERIALIZERS: &str = "CKtY7bQJ1TMwbRQA93kKfaUMA3FjHSnvyWiuRQTvfhRh";
    // A single type whose ABI is digested with both `bincode` and `wincode`,
    // which must agree on the shared digest. Each serializer gets its own
    // generated test (`test_abi_digest_bincode` / `test_abi_digest_wincode`).
    #[derive(
        PartialEq,
        serde_derive::Deserialize,
        serde_derive::Serialize,
        wincode::SchemaRead,
        wincode::SchemaWrite,
    )]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::AbiExample,
            solana_frozen_abi_macro::StableAbi
        ),
        solana_frozen_abi_macro::frozen_abi(
            api_digest = API_SHARED_SERIALIZERS,
            abi_digest = ABI_SHARED_WINCODE_VS_BINCODE,
            abi_serializer = ["bincode", "wincode"],
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestStructSharedSerializers {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    impl crate::rand::distr::Distribution<TestStructSharedSerializers>
        for crate::rand::distr::StandardUniform
    {
        fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStructSharedSerializers {
            TestStructSharedSerializers {
                a: rng.random(),
                b: rng.random(),
                c: rng.random(),
                d: rng.random(),
            }
        }
    }

    // Verify abi_digest-only: no API digest, should still run ABI test.
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestStructAbiDigestOnly {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    impl crate::rand::distr::Distribution<TestStructAbiDigestOnly>
        for crate::rand::distr::StandardUniform
    {
        fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStructAbiDigestOnly {
            TestStructAbiDigestOnly {
                a: rng.random(),
                b: rng.random(),
                c: rng.random(),
                d: rng.random(),
            }
        }
    }

    // Verify stable abi sample derive (all fields with rand distribution)
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestStableAbiSampleSimple {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "CuEDjcfdYbKAoxSV9QeQDv9K71mKgitE28CwvB4PAM3S",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    enum TestStableAbiSampleEnumSimple {
        A,
        B(u64),
        C(u8, u16, u32, u64),
        D(f64),
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "2XwyJT2T6oDWtStC8n9EfDMk8wHBExsX4AoBS5uRf74u",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    enum TestStableAbiSampleEnumNamed {
        A,
        B { a: u64, b: bool },
    }

    // Verify stable abi sample derive (fields mixed, mostly without implementation of rand distribution)
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "Da7uAdhapexEgWf4xxKLrYXhnYU9g6CKpRSbrzFWDg6a",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestStableAbiSampleOverride {
        #[stable_abi_sample(
            with = "(0..rng.random::<u8>() % 4).map(|_| rng.random::<bool>()).collect()"
        )]
        a: Vec<bool>,
        // Keep a single entry so HashMap iteration order cannot affect the digest.
        #[stable_abi_sample(with = "HashMap::from_iter([(rng.random(), rng.random())])")]
        b: std::collections::HashMap<u64, bool>,
        #[stable_abi_sample(with = "rng.random::<u64>()")]
        c: u64,
        d: u16,
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "DTzLXmgVsieme1R1gFBF3NBckeeXfqR7hrkiMyWXUK7M",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    enum TestStableAbiSampleEnumOverride {
        A,
        B(u64),
        C(#[stable_abi_sample(with = "rng.random::<[bool; 4]>().to_vec()")] Vec<bool>),
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "NDiMpkrAEM4QN3GkELuBzxdCwCtVz6gp3pjFuiGtTWD",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    enum TestStableAbiSampleEnumNamedOverride {
        A,
        B {
            a: u64,
            b: bool,
        },
        C {
            #[stable_abi_sample(with = "rng.random::<[bool; 4]>().to_vec()")]
            a: Vec<bool>,
            b: u16,
        },
    }

    const ABI_DIGEST_EQUIVALENT_FIELD_STRUCTURES: &str =
        "G7kuFGzwY6HwSytv6UsjWVEAbhrfv2n2gmchE27mSRiM";
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_FIELD_STRUCTURES,
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentWincodeStruct {
        a: u8,
        b: u64,
        c: (u8, [u8; 3]),
    }

    #[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_FIELD_STRUCTURES,
            abi_serializer = "bincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentBincodeTuple(u8, u64, u8, [u8; 3]);

    const ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES: &str =
        "14qLvWX4UebbLBaKi6v31A8xDfXU8ifX8DqCGbpAwjtD";
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES,
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentCollectionsWincode {
        #[stable_abi_sample(
            with = "(0..rng.random::<u8>() % 4).map(|_| rng.random::<u8>()).collect()"
        )]
        a: Vec<u8>,
        b: bool,
    }

    #[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES,
            abi_serializer = "bincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentCollectionsBincode(
        #[stable_abi_sample(
            with = "(0..rng.random::<u8>() % 4).map(|_| rng.random::<u8>()).collect()"
        )]
        VecDeque<u8>,
        bool,
    );

    const ABI_DIGEST_EQUIVALENT_KEY_VALUE_SEQUENCES: &str =
        "9pGP5GGD2HxDRCQeDv3rPGTfVH9SzkZCXMSGHpZnzz4G";
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_KEY_VALUE_SEQUENCES,
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentBTreeMapVsVecWincode {
        #[stable_abi_sample(
            with = "(0..rng.random::<u16>() % 4).map(|i| (u16::from_be_bytes([i as u8, rng.random()]), rng.random())).collect()"
        )]
        a: BTreeMap<u16, u8>,
        b: bool,
    }

    #[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_KEY_VALUE_SEQUENCES,
            abi_serializer = "bincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestEquivalentBTreeMapVsVecBincode {
        #[stable_abi_sample(
            with = "(0..rng.random::<u16>() % 4).map(|i| (u16::from_be_bytes([i as u8, rng.random()]), rng.random())).collect()"
        )]
        a: Vec<(u16, u8)>,
        b: bool,
    }

    type AliasUsize = usize;
    type AliasIsize = isize;

    // do not remove the constraint as the expected abi_digest was calculated 64 bit little endian
    #[cfg(target_pointer_width = "64")]
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "Yfy4agydqEFuudgHJ497PHPNjbSmEDywbjRuQExv8mV",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestPlatformDependent {
        a: usize,
        b: AliasUsize,
        c: Option<usize>,
        d: Option<AliasUsize>,
        e: isize,
        f: AliasIsize,
        g: Option<AliasIsize>,
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "B4hSLevsio8KgQrkzAiQefJ181pYLbKS8qdvtjhy6LGz",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestTuples {
        a: u8,
        b: (u8, u8),
        c: (u8, u8, u8),
        d: (u8, u8, u8, u8),
        e: (u8, u8, u8, u8, u8),
        f: (u8, u8, u8, u8, u8, u8),
        g: (u8, u8, u8, u8, u8, u8, u8),
        h: (u8, u8, u8, u8, u8, u8, u8, u8),
        i: (u8, u8, u8, u8, u8, u8, u8, u8, u8),
        j: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8),
        k: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8),
        l: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8),
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "58FbcqrJoX4TQC3i9eMUxc6fqPBqbzwxZ5ZkNyUYQYzR",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestNonZero {
        a: NonZero<u32>,
        b: Option<NonZero<u8>>,
        c: NonZero<i16>,
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "2Qrf3xihSoFBSv49eVXhw2vkHDmfDfwfTKArszJuhKmz",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestWrapContainers {
        a: Box<u64>,
        b: std::rc::Rc<u32>,
        c: std::sync::Arc<(u8, u16)>,
        d: std::marker::PhantomData<u64>,
        e: Result<u64, bool>,
    }
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "BpX6LYJMYg5tvkZpvPmfwfU2mvzoQgXqyYzcXS2HXz7S",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestNet {
        a: std::net::Ipv4Addr,
        b: std::net::Ipv6Addr,
        c: std::net::IpAddr,
        d: std::net::SocketAddrV4,
        e: std::net::SocketAddrV6,
        f: std::net::SocketAddr,
    }
    macro_rules! mk_stable_abi_sample_with_from_macro_rules {
        ({ $($body:tt)* }) => {
            #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
            #[cfg_attr(
                feature = "frozen-abi",
                derive(
                    solana_frozen_abi_macro::StableAbi,
                    solana_frozen_abi_macro::StableAbiSample
                ),
                solana_frozen_abi_macro::frozen_abi(
                    abi_digest = "33q22jGb8M6yo7fWeZvMoSUJBAoBEf4w2VQpjwXuHVXM",
                    abi_serializer = "wincode",
                    test_roundtrip = "eq_and_wire",
                )
            )]
            struct TestStableAbiSampleWithFromMacroRules {
                $($body)*
            }
        };
    }
    mk_stable_abi_sample_with_from_macro_rules!({
        #[stable_abi_sample(with = "rng.random::<u8>()")]
        a: u8,
    });

    type AliasVec = Vec<(u8, u16, u32, u64)>;
    type AliasHashMap = HashMap<u8, u128>;
    type AliasVecDeque = VecDeque<i16>;

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "hsD1Hmwbrwnfw4rdiBospgofHtJTftbN9vHUGXf7N2t",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestCollectionsDerive {
        a: Vec<u8>,
        b: Option<Vec<u8>>,
        c: AliasVec,
        d: HashMap<u8, char>,
        e: AliasHashMap,
        f: Option<HashMap<u16, i64>>,
        g: VecDeque<char>,
        h: Option<VecDeque<bool>>,
        i: AliasVecDeque,
    }

    macro_rules! impl_sequence_sample_test_types {
        (
            digests = [$(
                $abi_digest:expr => [$(
                    struct $struct_name:ident { $($body:tt)* }
                ),+ $(,)?]
            ),+ $(,)?]
        ) => {
            mod sequence_sample_test_types {
                macro_rules! test_types {
                    ($derives:tt, $serializer:literal) => {
                        $($(
                            #[derive $derives]
                            #[cfg_attr(
                                feature = "frozen-abi",
                                derive(
                                    solana_frozen_abi_macro::StableAbi,
                                    solana_frozen_abi_macro::StableAbiSample
                                ),
                                solana_frozen_abi_macro::frozen_abi(
                                    abi_digest = $abi_digest,
                                    abi_serializer = $serializer,
                                    test_roundtrip = "eq_and_wire",
                                )
                            )]
                            struct $struct_name { $($body)* }
                        )+)+
                    };
                }
                mod wincode {use super::super::*; test_types!((PartialEq, wincode::SchemaWrite, wincode::SchemaRead), "wincode");}
                mod bincode {use super::super::*; test_types!((PartialEq, serde_derive::Serialize, serde_derive::Deserialize), "bincode");}
            }
        };
    }

    impl_sequence_sample_test_types!(
        digests = [
            "762V1KB6NRDroyHo31bjg7gwX9nx8QqHCP9EJ3Y7nLGE" => [
                struct MultiElementsWith {
                    #[stable_abi_sample(
                        with = "(0..rng.random_range(0..=5)).map(|_| rng.random()).collect()"
                    )]
                    a: Vec<u8>,
                },
                struct MultiElementsVec {
                    #[stable_abi_sample(ctx = SequenceLenMax(5))]
                    a: Vec<u8>,
                },
                struct MultiElementsVecDefault {
                    a: Vec<u8>,
                },
                struct MultiElementsVecDeque {
                    #[stable_abi_sample(ctx = SequenceLenMax(5))]
                    a: VecDeque<u8>,
                },
                // `LinkedList` has no dedicated `StableAbi` impl; exercise the
                // sampling helpers on it as an arbitrary `FromIterator` collection.
                struct MultiElementsLinkedListDefault {
                    #[stable_abi_sample(with = "crate::stable_abi::sample_collection(rng)")]
                    a: LinkedList<u8>,
                },
                struct MultiElementsLinkedListSized {
                    #[stable_abi_sample(
                        with = "crate::stable_abi::sample_collection_sized(rng, SequenceLenMax(5))"
                    )]
                    a: LinkedList<u8>,
                },
            ],
            "7dXyMka1Z72sENE9vva8vmE65F7y6kXZKQ2DHu9aTWyz" => [
                struct UpToOneElementWith {
                    #[stable_abi_sample(
                        with = "(0..rng.random_range(0..=1)).map(|_| rng.random()).collect()"
                    )]
                    a: Vec<u8>,
                },
                struct UpToOneElementVec {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: Vec<u8>,
                },
                struct UpToOneElementBTreeSet {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: BTreeSet<u8>,
                },
                struct UpToOneElementHashMap {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: HashMap<u8, ()>,
                },
                struct UpToOneElementHashMapDefault {
                    a: HashMap<u8, ()>,
                },
                struct UpToOneElementHashSet {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: HashSet<u8>,
                },
                struct UpToOneElementHashSetDefault {
                    a: HashSet<u8>,
                },
                struct UpToOneElementBTreeMap {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: BTreeMap<u8, ()>,
                },
                struct UpToOneElementLinkedListSized {
                    #[stable_abi_sample(
                        with = "crate::stable_abi::sample_collection_sized(rng, SequenceLenMax(1))"
                    )]
                    a: LinkedList<u8>,
                },
            ],
            "Du8dTBApdeSxYTQVprkbMGvc5dLgCfUKKZ2z63qqr5Bj" => [
                struct UpToOneKeyValueHashMapWith {
                    #[stable_abi_sample(
                        with = "(0..rng.random_range(0..=1)).map(|_| (rng.random(), rng.random())).collect()"
                    )]
                    a: HashMap<u8, u16>,
                },
                struct UpToOneKeyValueVec {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: Vec<(u8, u16)>,
                },
                struct UpToOneKeyValueHashMap {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: HashMap<u8, u16>,
                },
                struct UpToOneKeyValueBTreeMap {
                    #[stable_abi_sample(ctx = SequenceLenMax(1))]
                    a: BTreeMap<u8, u16>,
                },
                struct UpToOneKeyValueLinkedListSized {
                    #[stable_abi_sample(
                        with = "crate::stable_abi::sample_collection_sized(rng, SequenceLenMax(1))"
                    )]
                    a: LinkedList<(u8, u16)>,
                },
            ],
            "57dywdByMU7XcWbsfnXY5ChZdqne57zjJCn7uEjDKGNc" => [
                struct UpToOneKeyValueHashMapWithRange {
                    #[stable_abi_sample(
                        with = "(0..rng.random_range(1..=1)).map(|_| (rng.random(), rng.random())).collect()"
                    )]
                    a: HashMap<u8, u16>,
                },
                struct UpToOneKeyValueVecRange {
                    #[stable_abi_sample(ctx = SequenceLenRange::new(1..=1))]
                    a: Vec<(u8, u16)>,
                },
                struct UpToOneKeyValueHashMapRange {
                    #[stable_abi_sample(ctx = SequenceLenRange::new(1..=1))]
                    a: HashMap<u8, u16>,
                },
                struct UpToOneKeyValueBTreeMapRange {
                    #[stable_abi_sample(ctx = SequenceLenRange::new(1..=1))]
                    a: BTreeMap<u8, u16>,
                },
                struct UpToOneKeyValueLinkedListRange {
                    #[stable_abi_sample(
                        with = "crate::stable_abi::sample_collection_sized(rng, SequenceLenRange::new(1..=1))"
                    )]
                    a: LinkedList<(u8, u16)>,
                },
            ],
        ]
    );

    const ARRAY_LEN: usize = 1;
    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        )
    )]
    pub struct TestGenericArrayWrapper<I> {
        a: [I; ARRAY_LEN],
    }

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        )
    )]
    pub struct TestGenericArrayWrapperMore<I, T> {
        a: [I; ARRAY_LEN],
        b: [T; ARRAY_LEN],
        c: Option<(I, T)>,
    }

    type More = (bool, u64, usize, Option<usize>);

    #[derive(PartialEq, wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "z3Tk2mbrbe6j266gAp6Eo9D9Z5NgvxFQRVHvyJEubrv",
            abi_serializer = "wincode",
            test_roundtrip = "eq_and_wire",
        )
    )]
    struct TestNestedGenericBounds {
        a: TestGenericArrayWrapper<([u8; 32], u64, u64)>,
        b: TestGenericArrayWrapperMore<([u8; 32], u64, u64), More>,
    }

    // do not add missing wincode::SchemaRead to this type
    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "ErVp1LhW4wAyXr8KudiFF9DpT3ZuGx8mWBeT5mXnCn8m",
            abi_serializer = "wincode",
            test_roundtrip = "no",
        )
    )]
    struct TestRoundtripSkip {
        a: u8,
        b: bool,
        c: Option<Vec<u16>>,
    }

    #[derive(wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "ErVp1LhW4wAyXr8KudiFF9DpT3ZuGx8mWBeT5mXnCn8m",
            abi_serializer = "wincode",
            test_roundtrip = "wire_only",
        )
    )]
    struct TestRoundtripWireOnly {
        a: u8,
        b: bool,
        c: Option<Vec<u16>>,
    }

    #[derive(wincode::SchemaWrite, wincode::SchemaRead)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "ErVp1LhW4wAyXr8KudiFF9DpT3ZuGx8mWBeT5mXnCn8m",
            abi_serializer = "wincode",
        )
    )]
    struct TestRoundtripWireOnlyByDefault {
        a: u8,
        b: bool,
        c: Option<Vec<u16>>,
    }
}
