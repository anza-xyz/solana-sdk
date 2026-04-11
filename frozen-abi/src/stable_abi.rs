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
        };
    }

    linked_stable_abi_pair!(
        api_digest_wincode = "2cJjhqi4hsJ3Y5HeT8fYE6YzDPdWnKAmbVHcw75rG1ky",
        api_digest_bincode = "ARDLdidYVUVVNNHgHx1Uf8Ec2dDdDyYAzNsAtm4oB494",
        // shared by bincode and wincode
        abi_digest = "AgNkEpErnFBuy7iTAEUUAC1fbvokEkhbsfFnx4DtXAvY",
    );
}
