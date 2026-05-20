use {
    core::{array, num::NonZero},
    rand::{Rng, RngCore},
};

pub trait StableAbi: Sized {
    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self;
}

macro_rules! impl_stable_abi_via_standard_uniform {
    ($($t:ty),* $(,)?) => {
        $(
            impl StableAbi for $t {
                fn random(rng: &mut (impl RngCore + ?Sized)) -> Self {
                    rng.random::<Self>()
                }
            }
        )*
    };
}

macro_rules! impl_stable_abi_via_size_of_from_bytes {
    ($from_bytes:ident, $($t:ty),* $(,)?) => {
        $(
            impl StableAbi for $t {
                fn random(rng: &mut (impl RngCore + ?Sized)) -> Self {
                    Self::$from_bytes(rng.random::<[u8; core::mem::size_of::<Self>()]>())
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
                $($t: StableAbi),+
            {
                fn random(rng: &mut (impl RngCore + ?Sized)) -> Self {
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
    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self {
        array::from_fn(|_| T::random(rng))
    }
}

impl<T> StableAbi for Option<T>
where
    T: StableAbi,
{
    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self {
        rng.random::<bool>().then(|| T::random(rng))
    }
}

#[cfg(all(test, feature = "frozen-abi"))]
mod tests {
    use {
        core::num::NonZero,
        std::collections::{BTreeMap, VecDeque},
    };

    // Keep the bincode and wincode test fixtures structurally identical so their
    // derived `test_abi_digest` checks enforce one shared ABI digest across serializers.
    #[rustfmt::skip]
    macro_rules! linked_stable_abi_pair {
        (
            api_digest_wincode = $api_wincode:literal,
            api_digest_bincode = $api_bincode:literal,
            abi_digest = $abi:literal,
        ) => {
            #[derive(Debug, serde_derive::Serialize, wincode::SchemaWrite)]
            #[cfg_attr(
                feature = "frozen-abi",
                derive(
                    solana_frozen_abi_macro::AbiExample,
                    solana_frozen_abi_macro::StableAbi
                ),
                solana_frozen_abi_macro::frozen_abi(
                    api_digest = $api_wincode,
                    abi_digest = $abi,
                    abi_serializer = "wincode",
                )
            )]
            struct TestStructWincode {
                a: u64,
                b: bool,
                c: [u8; 32],
                d: (u8, u8),
            }

            impl crate::rand::distr::Distribution<TestStructWincode>
                for crate::rand::distr::StandardUniform
            {
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
                    api_digest = $api_bincode,
                    abi_digest = $abi,
                    abi_serializer = "bincode",
                )
            )]
            struct TestStructBincode {
                a: u64,
                b: bool,
                c: [u8; 32],
                d: (u8, u8),
            }

            impl crate::rand::distr::Distribution<TestStructBincode>
                for crate::rand::distr::StandardUniform
            {
                fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStructBincode {
                    TestStructBincode {
                        a: rng.random(),
                        b: rng.random(),
                        c: rng.random(),
                        d: rng.random(),
                    }
                }
            }
        };
    }

    linked_stable_abi_pair!(
        api_digest_wincode = "2cJjhqi4hsJ3Y5HeT8fYE6YzDPdWnKAmbVHcw75rG1ky",
        api_digest_bincode = "ARDLdidYVUVVNNHgHx1Uf8Ec2dDdDyYAzNsAtm4oB494",
        // shared by bincode and wincode
        abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
    );

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
        #[stable_abi_sample(
            with = "std::collections::HashMap::from_iter([(rng.random(), rng.random())])"
        )]
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
            with = "(0..rng.random::<u16>() % 4).map(|i| (((i << 8) + rng.random::<u8>() as u16), rng.random())).collect()"
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
            with = "(0..rng.random::<u16>() % 4).map(|i| (((i << 8) + rng.random::<u8>() as u16), rng.random())).collect()"
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
}
