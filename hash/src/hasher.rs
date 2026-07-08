use {
    crate::HASH_BYTES,
    core::{
        cell::Cell,
        hash::{BuildHasher, Hasher},
        mem,
    },
    rand::{rng, Rng},
};

/// A faster, but less collision resistant hasher for hashes.
///
/// Specialized hasher that uses a random 8 bytes subslice of the
/// hash as the hash value. Should not be used when collisions
/// might be used to mount DOS attacks.
///
/// Using this results in about 4x faster lookups in a typical hashmap.
#[derive(Default)]
pub struct HashHasher {
    offset: usize,
    state: u64,
}

impl Hasher for HashHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        debug_assert_eq!(
            bytes.len(),
            HASH_BYTES,
            "This hasher is intended to be used with hashes and nothing else"
        );
        // This slice/unwrap can never panic since offset is < HASH_BYTES - mem::size_of::<u64>()
        let chunk: &[u8; mem::size_of::<u64>()] = bytes
            [self.offset..self.offset + mem::size_of::<u64>()]
            .try_into()
            .unwrap();
        self.state = u64::from_ne_bytes(*chunk);
    }
}

/// A builder for faster, but less collision resistant hasher for hashes.
///
/// Initializes `HashHasher` instances that use an 8-byte
/// slice of the hash as the hash value. Should not be used when
/// collisions might be used to mount DOS attacks.
///
/// Using this results in about 4x faster lookups in a typical hashmap.
#[derive(Clone)]
pub struct HashHasherBuilder {
    offset: usize,
}

impl HashHasherBuilder {
    /// Constructs a builder with a specific offset.
    ///
    /// Prefer `HashHasherBuilder::default()` unless deterministic results are required.
    pub fn with_offset(offset: usize) -> Self {
        HashHasherBuilder { offset }
    }

    /// Returns the offset used to construct this builder.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl Default for HashHasherBuilder {
    /// Default construct the HashHasherBuilder.
    ///
    /// The position of the slice is determined initially
    /// through random draw and then by incrementing a thread-local
    /// This way each hashmap can be expected to use a slightly different
    /// slice. This is essentially the same mechanism as what is used by
    /// `RandomState`
    fn default() -> Self {
        std::thread_local!(static OFFSET: Cell<usize>  = {
            let mut rng = rng();
            Cell::new(rng.random_range(0..HASH_BYTES - mem::size_of::<u64>()))
        });

        let offset = OFFSET.with(|offset| {
            let mut next_offset = offset.get() + 1;
            if next_offset > HASH_BYTES - mem::size_of::<u64>() {
                next_offset = 0;
            }
            offset.set(next_offset);
            next_offset
        });
        HashHasherBuilder { offset }
    }
}

impl BuildHasher for HashHasherBuilder {
    type Hasher = HashHasher;
    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        HashHasher {
            offset: self.offset,
            state: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::HashHasherBuilder,
        crate::{Hash, HASH_BYTES},
        core::hash::{BuildHasher, Hasher},
    };

    fn hash_with_bytes(bytes: u8) -> Hash {
        Hash::new_from_array([bytes; HASH_BYTES])
    }

    fn hash_with_distinct_windows() -> Hash {
        Hash::new_from_array([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
    }

    #[test]
    fn test_hash_hasher_builder() {
        let key = hash_with_distinct_windows();
        let builder = HashHasherBuilder::default();
        let mut hasher1 = builder.build_hasher();
        let mut hasher2 = builder.build_hasher();
        hasher1.write(key.as_bytes());
        hasher2.write(key.as_bytes());
        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Hashers made with same builder should be identical"
        );
        // Make sure that when we make new builders we get different slices
        // chosen for hashing
        let builder2 = HashHasherBuilder::default();
        assert_ne!(builder.offset(), builder2.offset());
        let mut hasher3 = builder2.build_hasher();
        hasher3.write(key.as_bytes());
        assert_ne!(
            hasher1.finish(),
            hasher3.finish(),
            "Hashers built with different builder should use different offsets"
        );
    }

    #[test]
    fn test_hash_hasher() {
        let key1 = hash_with_bytes(1);
        let key2 = hash_with_bytes(2);
        let builder = HashHasherBuilder::default();
        let mut hasher1 = builder.build_hasher();
        let mut hasher2 = builder.build_hasher();
        hasher1.write(key1.as_bytes());
        hasher2.write(key2.as_bytes());
        assert_ne!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_builder_with_offset() {
        let builder1 = HashHasherBuilder::default();
        let offset1 = builder1.offset();
        let builder2 = HashHasherBuilder::with_offset(offset1);
        let offset2 = builder2.offset();
        assert_eq!(offset1, offset2);
        let key = hash_with_distinct_windows();
        assert_eq!(builder1.hash_one(key), builder2.hash_one(key));
    }
}
