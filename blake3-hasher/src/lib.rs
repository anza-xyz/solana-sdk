//! Hashing with the [blake3] hash function.
//!
//! [blake3]: https://github.com/BLAKE3-team/BLAKE3
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

pub use solana_hash::{Hash, ParseHashError, HASH_BYTES, MAX_BASE58_LEN};

#[derive(Clone, Default)]
#[cfg(all(feature = "blake3", not(target_os = "solana")))]
pub struct Hasher {
    hasher: blake3::Hasher,
}

#[cfg(all(feature = "blake3", not(target_os = "solana")))]
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
        Hash::new_from_array(*self.hasher.finalize().as_bytes())
    }
}

/// Return a Blake3 hash for the given data.
pub fn hashv(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(target_os = "solana"))]
    {
        #[cfg(feature = "blake3")]
        {
            let mut hasher = Hasher::default();
            hasher.hashv(vals);
            hasher.result()
        }
        #[cfg(not(feature = "blake3"))]
        {
            core::hint::black_box(vals);
            panic!("hashv is only available on target `solana` or with the `blake3` feature enabled on this crate")
        }
    }
    // Call via a system call to perform the calculation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; HASH_BYTES];
        unsafe {
            solana_define_syscall::definitions::sol_blake3(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

/// Return a Blake3 hash for the given data.
pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}

#[cfg(test)]
#[cfg(feature = "blake3")]
mod tests {
    use super::*;

    #[test]
    fn test_hashv() {
        let val = "gHiljKpq";
        let val_hash = hash(val.as_bytes());

        let ext = "lM890t";
        let ext_hash = hashv(&[&val_hash.to_bytes(), ext.as_bytes()]);

        let hash_ext = [&val_hash.to_bytes(), ext.as_bytes()].concat();
        assert!(ext_hash == hash(&hash_ext));
    }
}
