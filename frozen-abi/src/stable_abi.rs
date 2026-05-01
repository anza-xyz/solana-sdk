use rand::{distr::StandardUniform, Rng, RngCore};

pub trait StableAbi: Sized {
    fn random(rng: &mut impl RngCore) -> Self
    where
        StandardUniform: rand::distr::Distribution<Self>,
    {
        rng.random::<Self>()
    }
}

#[cfg(all(test, feature = "frozen-abi"))]
mod tests {
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
        }
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
            abi_digest = "EVb5Tgy4rZzifSr6cE8HX3K8Zy6w9PD9hamvo3G9Ue7D",
            abi_serializer = "wincode",
        )
    )]
    struct TestStableAbiSampleOverride {
        #[stable_abi_sample(with = "rng.random::<[bool; 4]>().to_vec()")]
        a: Vec<bool>,
        #[stable_abi_sample(
            with = "{ let mut m = std::collections::HashMap::new(); m.insert(rng.random(), rng.random()); m }"
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
}
