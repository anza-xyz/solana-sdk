//! Signature error copied directly from
//! [RustCrypto's opaque signature error](https://github.com/RustCrypto/traits/tree/master/signature)

#[cfg(all(feature = "std", feature = "alloc"))]
use alloc::boxed::Box;
use core::fmt::{self, Debug, Display};

/// Signature errors.
///
/// This type is deliberately opaque as to avoid sidechannel leakage which
/// could potentially be used recover signing private keys or forge signatures
/// (e.g. [BB'06]).
///
/// When the `std` feature is enabled, it impls
/// [`std::error::Error`](https://doc.rust-lang.org/std/error/trait.Error.html).
///
/// When the `alloc` feature is enabled, it supports an optional
/// [`std::error::Error::source`](https://doc.rust-lang.org/std/error/trait.Error.html#method.source),
/// which can be used by things like remote signers (e.g. HSM, KMS) to report
/// I/O or auth errors.
///
/// [BB'06]: https://en.wikipedia.org/wiki/Daniel_Bleichenbacher
#[derive(Default)]
#[non_exhaustive]
pub struct Error {
    /// Source of the error (if applicable).
    #[cfg(all(feature = "std", feature = "alloc"))]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// Create a new error with an associated source.
    ///
    /// **NOTE:** The "source" should **NOT** be used to propagate cryptographic
    /// errors e.g. signature parsing or verification errors. The intended use
    /// cases are for propagating errors related to external signers, e.g.
    /// communication/authentication errors with HSMs, KMS, etc.
    #[cfg(all(feature = "std", feature = "alloc"))]
    pub fn from_source(
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            source: Some(source.into()),
        }
    }
}

impl Debug for Error {
    #[cfg(not(all(feature = "std", feature = "alloc")))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature::Error {}")
    }

    #[cfg(all(feature = "std", feature = "alloc"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature::Error { source: ")?;

        if let Some(source) = &self.source {
            write!(f, "Some({source})")?;
        } else {
            f.write_str("None")?;
        }

        f.write_str(" }")
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature error")
    }
}

#[cfg(all(feature = "std", feature = "alloc"))]
impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for Error {
    fn from(source: Box<dyn std::error::Error + Send + Sync + 'static>) -> Error {
        Self::from_source(source)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}
