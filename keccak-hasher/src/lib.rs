//! Hashing with the [keccak] (SHA-3) hash function.
//!
//! [keccak]: https://keccak.team/keccak.html
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

#[cfg(all(feature = "sha3", not(target_os = "solana")))]
use sha3::{Digest, Keccak256};
pub use solana_hash::{Hash, ParseHashError, HASH_BYTES, MAX_BASE58_LEN};

#[derive(Clone, Default)]
#[cfg(all(feature = "sha3", not(target_os = "solana")))]
pub struct Hasher {
    hasher: Keccak256,
}

#[cfg(all(feature = "sha3", not(target_os = "solana")))]
impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        Hash::new_from_array(self.hasher.finalize().into())
    }
}

/// Return a Keccak256 hash for the given data.
pub fn hashv(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(target_os = "solana"))]
    {
        #[cfg(feature = "sha3")]
        {
            let mut hasher = Hasher::default();
            hasher.hashv(vals);
            hasher.result()
        }
        #[cfg(not(feature = "sha3"))]
        {
            core::hint::black_box(vals);
            panic!("hashv is only available on target `solana` or with the `sha3` feature enabled on this crate")
        }
    }
    // Call via a system call to perform the calculation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; HASH_BYTES];
        unsafe {
            solana_define_syscall::definitions::sol_keccak256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

/// Return a Keccak256 hash for the given data.
pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}
