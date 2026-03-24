use {
    rand::{distr::StandardUniform, Rng, RngCore},
    serde::Serialize,
    wincode::{config::DefaultConfig, SchemaWrite},
};

pub trait StableAbi: Sized {
    fn random(rng: &mut impl RngCore) -> Self
    where
        StandardUniform: rand::distr::Distribution<Self>,
    {
        rng.random::<Self>()
    }

    fn serialize_for_abi(&self) -> Vec<u8>
    where
        Self: StableSerialize,
    {
        StableSerialize::serialize_for_abi(self)
    }
}

// Escape hatch for types migrating to wincode that cannot use the blanket impls,
// for example when they drop serde or need a custom schema adapter.
#[doc(hidden)]
pub trait StableSerialize {
    fn serialize_for_abi(&self) -> Vec<u8>;
}

impl<T> StableSerialize for T
where
    T: Serialize,
{
    default fn serialize_for_abi(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

impl<T> StableSerialize for T
where
    T: Serialize + SchemaWrite<DefaultConfig, Src = T>,
{
    fn serialize_for_abi(&self) -> Vec<u8> {
        wincode::serialize(self).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde_derive::Serialize)]
    struct SerdeOnly {
        value: u64,
    }

    #[derive(serde_derive::Serialize, wincode::SchemaWrite)]
    #[wincode(tag_encoding = "u8")]
    enum BothFormats {
        A,
        B,
    }

    #[derive(wincode::SchemaWrite)]
    struct ManualWincodeOnly {
        value: u64,
    }

    impl StableSerialize for ManualWincodeOnly {
        fn serialize_for_abi(&self) -> Vec<u8> {
            wincode::serialize(self).unwrap()
        }
    }

    #[test]
    fn stable_abi_falls_back_to_bincode_for_serde_types() {
        let value = SerdeOnly { value: 42 };
        assert_eq!(
            value.serialize_for_abi(),
            bincode::serialize(&value).unwrap()
        );
    }

    #[test]
    fn stable_abi_prefers_wincode_when_schema_write_is_available() {
        let value = BothFormats::B;
        let abi_bytes = value.serialize_for_abi();

        assert_eq!(abi_bytes, wincode::serialize(&value).unwrap());
        assert_ne!(abi_bytes, bincode::serialize(&value).unwrap());
    }

    #[test]
    fn stable_abi_allows_manual_wincode_serialization_for_non_serde_types() {
        let value = ManualWincodeOnly { value: 42 };
        assert_eq!(
            value.serialize_for_abi(),
            wincode::serialize(&value).unwrap()
        );
    }
}
