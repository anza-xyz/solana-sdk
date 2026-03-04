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
