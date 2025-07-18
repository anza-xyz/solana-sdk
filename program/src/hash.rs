//! Hashing with the [SHA-256] hash function, and a general [`Hash`] type.
//!
//! [SHA-256]: https://en.wikipedia.org/wiki/SHA-2
//! [`Hash`]: struct@Hash

#[cfg(not(target_os = "solana"))]
pub use solana_sha256_hasher::Hasher;
pub use {
    solana_hash::{Hash, ParseHashError, HASH_BYTES},
    solana_sha256_hasher::{extend_and_hash, hash, hashv},
};
