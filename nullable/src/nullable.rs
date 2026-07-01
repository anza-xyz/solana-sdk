/// Trait for types that can be `None`.
///
/// This trait is used to indicate that a type can reserve a specific value to
/// represent `None`.
pub trait Nullable: PartialEq + Sized {
    /// Value that represents `None` for the type.
    const NONE: Self;

    /// Indicates whether the value is `None` or not.
    fn is_none(&self) -> bool {
        self == &Self::NONE
    }

    /// Indicates whether the value is a `Some` value of type `Self` or not.
    fn is_some(&self) -> bool {
        !self.is_none()
    }
}

macro_rules! nullable_integer {
    ( $type:tt ) => {
        #[doc = concat!("Implements `Nullable` for the `", stringify!($type), "` type, reserving `0` as the `NONE` value.")]
        impl Nullable for $type {
            const NONE: Self = 0;
        }
    };
}

nullable_integer!(u8);
nullable_integer!(u16);
nullable_integer!(u32);
nullable_integer!(u64);
#[cfg(not(target_arch = "bpf"))]
nullable_integer!(u128);
