//! Owned containers for secret-key material that clear themselves on drop.
//!
//! These stand in for `zeroize::Zeroizing` in this crate's public API. Naming
//! `Zeroizing` in a return type or trait impl would force every caller to take
//! a direct dependency on `zeroize` and keep its major version in lockstep with
//! ours; these crate-owned types wrap it privately, so the clear-on-drop
//! behavior is preserved while the dependency stays an implementation detail.

use {
    alloc::string::String,
    core::{
        fmt,
        ops::{Deref, DerefMut},
    },
    zeroize::Zeroizing,
};

/// A fixed-size buffer of secret-key material, zeroized on drop.
///
/// Dereferences to `[u8; N]`, so it can be passed anywhere the raw buffer is
/// expected. `Debug` deliberately does not print the contents.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// Takes ownership of `bytes`, clearing it when the returned value drops.
    ///
    /// `bytes` is moved rather than cleared in place, so only pass a buffer
    /// that is not retained elsewhere.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A zeroed buffer, to be filled in place via [`Self::as_mut_slice`].
    pub fn zeroed() -> Self {
        Self::new([0u8; N])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(<hidden>)")
    }
}

/// A `String` holding secret material, zeroized on drop.
///
/// Dereferences to `str`. `Debug` deliberately does not print the contents.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of `string`, clearing it when the returned value drops.
    ///
    /// `string` is moved rather than cleared in place, so only pass a value
    /// that is not retained elsewhere.
    pub fn new(string: String) -> Self {
        Self(Zeroizing::new(string))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<hidden>)")
    }
}

#[cfg(test)]
mod tests {
    use {super::*, alloc::string::ToString};

    #[test]
    fn test_secret_bytes_debug_hides_contents() {
        let bytes = SecretBytes::new([0xabu8; 4]);
        assert_eq!(alloc::format!("{bytes:?}"), "SecretBytes<4>(<hidden>)");
    }

    #[test]
    fn test_secret_bytes_fill_in_place() {
        let mut bytes = SecretBytes::<4>::zeroed();
        assert_eq!(bytes.as_slice(), &[0, 0, 0, 0]);
        bytes.as_mut_slice().copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4]);
        // Deref reaches the underlying array
        assert_eq!(*bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_string_debug_hides_contents() {
        let string = SecretString::new("hunter2".to_string());
        assert_eq!(alloc::format!("{string:?}"), "SecretString(<hidden>)");
        assert_eq!(string.as_str(), "hunter2");
        assert_eq!(string.as_bytes(), b"hunter2");
    }
}
