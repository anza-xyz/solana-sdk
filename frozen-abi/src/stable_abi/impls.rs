use {
    crate::stable_abi::{
        context::{impl_with_context_via, SequenceLenMax, SequenceLenRange},
        StableAbi,
    },
    core::{array, num::NonZero},
    rand::{Rng, RngCore},
    std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
        hash::{BuildHasher, Hash},
    },
};

const DEFAULT_COLLECTION_MAX_SAMPLE_LEN: usize = 5;
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

#[cfg(all(test, feature = "frozen-abi"))]
mod tests {
    use {
        crate::stable_abi::context::{SequenceLenMax, SequenceLenRange},
        core::num::NonZero,
        std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    };

    const ABI_SHARED_WINCODE_VS_BINCODE: &str = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY";
    const API_WINCODE: &str = "2cJjhqi4hsJ3Y5HeT8fYE6YzDPdWnKAmbVHcw75rG1ky";
    const API_BINCODE: &str = "ARDLdidYVUVVNNHgHx1Uf8Ec2dDdDyYAzNsAtm4oB494";
    #[derive(Debug, serde_derive::Serialize, wincode::SchemaWrite)]
    #[cfg_attr(
                feature = "frozen-abi",
                derive(
                    solana_frozen_abi_macro::AbiExample,
                    solana_frozen_abi_macro::StableAbi
                ),
                solana_frozen_abi_macro::frozen_abi(
                    api_digest = API_WINCODE,
                    abi_digest = ABI_SHARED_WINCODE_VS_BINCODE,
                    abi_serializer = "wincode",
                )
            )]
    struct TestStructWincode {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    impl crate::rand::distr::Distribution<TestStructWincode> for crate::rand::distr::StandardUniform {
        fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStructWincode {
            TestStructWincode {
                a: rng.random(),
                b: rng.random(),
                c: rng.random(),
                d: rng.random(),
            }
        }
    }

    #[derive(Debug, serde_derive::Serialize)]
    #[cfg_attr(
                feature = "frozen-abi",
                derive(
                    solana_frozen_abi_macro::AbiExample,
                    solana_frozen_abi_macro::StableAbi
                ),
                solana_frozen_abi_macro::frozen_abi(
                    api_digest = API_BINCODE,
                    abi_digest = ABI_SHARED_WINCODE_VS_BINCODE,
                    abi_serializer = "bincode",
                )
            )]
    struct TestStructBincode {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    impl crate::rand::distr::Distribution<TestStructBincode> for crate::rand::distr::StandardUniform {
        fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStructBincode {
            TestStructBincode {
                a: rng.random(),
                b: rng.random(),
                c: rng.random(),
                d: rng.random(),
            }
        }
    }

    // Verify abi_digest-only: no API digest, should still run ABI test.
    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
            abi_serializer = "wincode"
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
    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
            abi_serializer = "wincode",
        )
    )]
    struct TestStableAbiSampleSimple {
        a: u64,
        b: bool,
        c: [u8; 32],
        d: (u8, u8),
    }

    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "CuEDjcfdYbKAoxSV9QeQDv9K71mKgitE28CwvB4PAM3S",
            abi_serializer = "wincode",
        )
    )]
    enum TestStableAbiSampleEnumSimple {
        A,
        B(u64),
        C(u8, u16, u32, u64),
        D(f64),
    }

    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "2XwyJT2T6oDWtStC8n9EfDMk8wHBExsX4AoBS5uRf74u",
            abi_serializer = "wincode",
        )
    )]
    enum TestStableAbiSampleEnumNamed {
        A,
        B { a: u64, b: bool },
    }

    // Verify stable abi sample derive (fields mixed, mostly without implementation of rand distribution)
    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "Da7uAdhapexEgWf4xxKLrYXhnYU9g6CKpRSbrzFWDg6a",
            abi_serializer = "wincode",
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

    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "DTzLXmgVsieme1R1gFBF3NBckeeXfqR7hrkiMyWXUK7M",
            abi_serializer = "wincode",
        )
    )]
    enum TestStableAbiSampleEnumOverride {
        A,
        B(u64),
        C(#[stable_abi_sample(with = "rng.random::<[bool; 4]>().to_vec()")] Vec<bool>),
    }

    #[derive(wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "NDiMpkrAEM4QN3GkELuBzxdCwCtVz6gp3pjFuiGtTWD",
            abi_serializer = "wincode",
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
    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_FIELD_STRUCTURES,
            abi_serializer = "wincode",
        )
    )]
    struct TestEquivalentWincodeStruct {
        a: u8,
        b: u64,
        c: (u8, [u8; 3]),
    }

    #[derive(Debug, serde_derive::Serialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_FIELD_STRUCTURES,
            abi_serializer = "bincode",
        )
    )]
    struct TestEquivalentBincodeTuple(u8, u64, u8, [u8; 3]);

    const ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES: &str =
        "14qLvWX4UebbLBaKi6v31A8xDfXU8ifX8DqCGbpAwjtD";
    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES,
            abi_serializer = "wincode",
        )
    )]
    struct TestEquivalentCollectionsWincode {
        #[stable_abi_sample(
            with = "(0..rng.random::<u8>() % 4).map(|_| rng.random::<u8>()).collect()"
        )]
        a: Vec<u8>,
        b: bool,
    }

    #[derive(Debug, serde_derive::Serialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_BYTE_SEQUENCES,
            abi_serializer = "bincode",
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
    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_KEY_VALUE_SEQUENCES,
            abi_serializer = "wincode",
        )
    )]
    struct TestEquivalentBTreeMapVsVecWincode {
        #[stable_abi_sample(
            with = "(0..rng.random::<u16>() % 4).map(|i| (u16::from_be_bytes([i as u8, rng.random()]), rng.random())).collect()"
        )]
        a: BTreeMap<u16, u8>,
        b: bool,
    }

    #[derive(Debug, serde_derive::Serialize)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(solana_frozen_abi_macro::StableAbi, solana_frozen_abi_macro::StableAbiSample),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = ABI_DIGEST_EQUIVALENT_KEY_VALUE_SEQUENCES,
            abi_serializer = "bincode",
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
    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "Yfy4agydqEFuudgHJ497PHPNjbSmEDywbjRuQExv8mV",
            abi_serializer = "wincode",
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

    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "B4hSLevsio8KgQrkzAiQefJ181pYLbKS8qdvtjhy6LGz",
            abi_serializer = "wincode",
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

    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "58FbcqrJoX4TQC3i9eMUxc6fqPBqbzwxZ5ZkNyUYQYzR",
            abi_serializer = "wincode",
        )
    )]
    struct TestNonZero {
        a: NonZero<u32>,
        b: Option<NonZero<u8>>,
        c: NonZero<i16>,
    }

    macro_rules! mk_stable_abi_sample_with_from_macro_rules {
        ({ $($body:tt)* }) => {
            #[derive(wincode::SchemaWrite)]
            #[cfg_attr(
                feature = "frozen-abi",
                derive(
                    solana_frozen_abi_macro::StableAbi,
                    solana_frozen_abi_macro::StableAbiSample
                ),
                solana_frozen_abi_macro::frozen_abi(
                    abi_digest = "33q22jGb8M6yo7fWeZvMoSUJBAoBEf4w2VQpjwXuHVXM",
                    abi_serializer = "wincode",
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

    #[derive(Debug, wincode::SchemaWrite)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(
            solana_frozen_abi_macro::StableAbi,
            solana_frozen_abi_macro::StableAbiSample
        ),
        solana_frozen_abi_macro::frozen_abi(
            abi_digest = "hsD1Hmwbrwnfw4rdiBospgofHtJTftbN9vHUGXf7N2t",
            abi_serializer = "wincode",
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
                    ($derive:path, $serializer:literal) => {
                        $($(
                            #[derive($derive)]
                            #[cfg_attr(
                                feature = "frozen-abi",
                                derive(
                                    solana_frozen_abi_macro::StableAbi,
                                    solana_frozen_abi_macro::StableAbiSample
                                ),
                                solana_frozen_abi_macro::frozen_abi(
                                    abi_digest = $abi_digest,
                                    abi_serializer = $serializer,
                                )
                            )]
                            struct $struct_name { $($body)* }
                        )+)+
                    };
                }
                mod wincode {use super::super::*; test_types!(wincode::SchemaWrite, "wincode");}
                mod bincode {use super::super::*; test_types!(serde_derive::Serialize, "bincode");}
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
            ],
        ]
    );
}
