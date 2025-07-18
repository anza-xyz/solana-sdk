#![no_std]
#[cfg(any(feature = "sha2", not(target_os = "solana")))]
use sha2::{Digest, Sha256};
use solana_hash::Hash;

// Only include x86_shani_single_hash_optimized if we are on x86_64 (and not on chain)
#[cfg(all(target_arch = "x86_64", not(target_os = "solana")))]
mod x86_shani_single_hash_optimized;

#[cfg(any(feature = "sha2", not(target_os = "solana")))]
#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

#[cfg(any(feature = "sha2", not(target_os = "solana")))]
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
        let bytes: [u8; solana_hash::HASH_BYTES] = self.hasher.finalize().into();
        bytes.into()
    }
}

#[cfg(target_os = "solana")]
pub use solana_define_syscall::definitions::sol_sha256;

#[inline(always)]
/// Return a Sha256 hash for the given data.
pub fn hashv(vals: &[&[u8]]) -> Hash {

    #[cfg(all(target_arch = "x86_64", not(target_os = "solana")))]
    {
        if vals.len() == 1 && vals[0].len() == 32 {
            // Since we know the array contains a single block of 32 bytes, we can use the 
            // optimized version of the hasher
            let block = unsafe { &*(vals[0].as_ptr() as *const [u8; 32]) };
            return x86_shani_single_hash_optimized::single_hash_32(block).into();
        }
    }

    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Hasher::default();
        hasher.hashv(vals);
        hasher.result()
    }
    // Call via a system call to perform the calculation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; solana_hash::HASH_BYTES];
        unsafe {
            sol_sha256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

/// Return a Sha256 hash for the given data.
pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}

/// Return the hash of the given hash extended with the given value.
pub fn extend_and_hash(id: &Hash, val: &[u8]) -> Hash {
    let mut hash_data = id.as_ref().to_vec();
    hash_data.extend_from_slice(val);
    hash(&hash_data)
}
