use {
    crate::{error::AddressError, Address, MAX_SEEDS, MAX_SEED_LEN, PDA_MARKER},
    core::{mem::MaybeUninit, slice::from_raw_parts},
    sha2_const_stable::Sha256,
    solana_sha256_hasher::hashv,
};

impl Address {
    /// Derive a [program address][pda] from the given seeds, optional bump and
    /// program id.
    ///
    /// [pda]: https://solana.com/docs/core/pda
    ///
    /// In general, the derivation uses an optional bump (byte) value to ensure a
    /// valid PDA (off-curve) is generated. Even when a program stores a bump to
    /// derive a program address, it is necessary to use the
    /// [`Address::create_program_address`] to validate the derivation. In
    /// most cases, the program has the correct seeds for the derivation, so it would
    /// be sufficient to just perform the derivation and compare it against the
    /// expected resulting address.
    ///
    /// This function avoids the cost of the `create_program_address` syscall
    /// (`1500` compute units) by directly computing the derived address
    /// calculating the hash of the seeds, bump and program id using the
    /// `sol_sha256` syscall.
    ///
    /// # Important
    ///
    /// This function differs from [`Address::create_program_address`] in that
    /// it does not perform a validation to ensure that the derived address is a valid
    /// (off-curve) program derived address. It is intended for use in cases where the
    /// seeds, bump, and program id are known to be valid, and the caller wants to derive
    /// the address without incurring the cost of the `create_program_address` syscall.
    #[inline]
    pub fn derive_address<const N: usize>(
        seeds: &[&[u8]; N],
        bump: Option<u8>,
        program_id: &Address,
    ) -> Address {
        Self::try_derive_address(seeds, bump, program_id)
            .expect("seed length must be less than or equal to MAX_SEED_LEN bytes")
    }

    /// Derive a [program address][pda] from the given seeds, optional bump and
    /// program id.
    ///
    /// [pda]: https://solana.com/docs/core/pda
    ///
    /// This function is similar to [`Address::derive_address`], but it returns a `Result`
    /// instead of panicking when any of the seeds exceed the maximum seed length.
    #[inline(always)]
    pub fn try_derive_address<const N: usize>(
        seeds: &[&[u8]; N],
        bump: Option<u8>,
        program_id: &Address,
    ) -> Result<Address, AddressError> {
        const {
            assert!(N < MAX_SEEDS, "number of seeds must be less than MAX_SEEDS");
        }

        let mut data = [const { MaybeUninit::<&[u8]>::uninit() }; MAX_SEEDS + 2];
        let mut i = 0;

        while i < N {
            // SAFETY: `data` is guaranteed to have enough space for `N` seeds,
            // so `i` will always be within bounds.
            unsafe {
                let seed = seeds.get_unchecked(i);

                if seed.len() > MAX_SEED_LEN {
                    return Err(AddressError::MaxSeedLengthExceeded);
                }

                data.get_unchecked_mut(i).write(seed);
            }
            i += 1;
        }

        // SAFETY: `data` is guaranteed to have enough space for `MAX_SEEDS + 2`
        // elements, and `MAX_SEEDS` is larger than `N`.
        unsafe {
            if bump.is_some() {
                data.get_unchecked_mut(i).write(bump.as_slice());
                i += 1;
            }
            data.get_unchecked_mut(i).write(program_id.as_ref());
            data.get_unchecked_mut(i + 1).write(PDA_MARKER.as_ref());
        }

        let hash = hashv(unsafe { from_raw_parts(data.as_ptr() as *const &[u8], i + 2) });
        Ok(Address::from(hash.to_bytes()))
    }

    /// Derive a [program address][pda] from the given seeds, optional bump and
    /// program id.
    ///
    /// [pda]: https://solana.com/docs/core/pda
    ///
    /// In general, the derivation uses an optional bump (byte) value to ensure a
    /// valid PDA (off-curve) is generated.
    ///
    /// This function is intended for use in `const` contexts - i.e., the seeds and
    /// bump are known at compile time and the program id is also a constant. It avoids
    /// the cost of the `create_program_address` syscall (`1500` compute units) by
    /// directly computing the derived address using the SHA-256 hash of the seeds,
    /// bump and program id.
    ///
    /// # Important
    ///
    /// This function differs from [`Address::create_program_address`] in that
    /// it does not perform a validation to ensure that the derived address is a valid
    /// (off-curve) program derived address. It is intended for use in cases where the
    /// seeds, bump, and program id are known to be valid, and the caller wants to derive
    /// the address without incurring the cost of the `create_program_address` syscall.
    ///
    /// This function is a compile-time constant version of [`Address::derive_address`].
    /// It has worse performance than `derive_address`, so only use this function in
    /// `const` contexts, where all parameters are known at compile-time.
    pub const fn derive_address_const<const N: usize>(
        seeds: &[&[u8]; N],
        bump: Option<u8>,
        program_id: &Address,
    ) -> Address {
        const {
            assert!(N < MAX_SEEDS, "number of seeds must be less than MAX_SEEDS");
        }

        let mut hasher = Sha256::new();
        let mut i = 0;

        while i < seeds.len() {
            assert!(
                seeds[i].len() <= MAX_SEED_LEN,
                "seed length must be less than or equal to MAX_SEED_LEN bytes"
            );

            hasher = hasher.update(seeds[i]);
            i += 1;
        }

        // TODO: replace this with `bump.as_slice()` when the MSRV is
        // upgraded to `1.84.0+`.
        Address::new_from_array(if let Some(bump) = bump {
            hasher
                .update(&[bump])
                .update(program_id.as_array())
                .update(PDA_MARKER)
                .finalize()
        } else {
            hasher
                .update(program_id.as_array())
                .update(PDA_MARKER)
                .finalize()
        })
    }

    /// Attempt to derive a valid [program derived address][pda] (PDA) and its corresponding
    /// bump seed.
    ///
    /// [pda]: https://solana.com/docs/core/cpi#program-derived-addresses
    ///
    /// The main difference between this method and [`Address::derive_address`]
    /// is that this method iterates through all possible bump seed values (starting from
    /// `255` and decrementing) until it finds a valid (off-curve) program derived address.
    ///
    /// If a valid PDA is found, it returns the PDA and the bump seed used to derive it;
    /// otherwise, it returns `None`.
    #[inline]
    pub fn derive_program_address<const N: usize>(
        seeds: &[&[u8]; N],
        program_id: &Address,
    ) -> Option<(Address, u8)> {
        // Pre-calculate the bump seeds in reverse order, so that the first bump
        // seed tried is the largest.
        const BUMP_SEEDS: [u8; u8::MAX as usize] = {
            let mut seeds = [0; u8::MAX as usize];
            let mut i = 0;
            while i < seeds.len() {
                seeds[i] = u8::MAX - i as u8;
                i += 1;
            }
            seeds
        };

        if N >= MAX_SEEDS {
            return None;
        }

        let mut data = [const { MaybeUninit::<&[u8]>::uninit() }; MAX_SEEDS + 2];
        let mut i = 0;

        while i < N {
            // SAFETY: `data` is guaranteed to have enough space for `N` seeds,
            // so `i` will always be within bounds.
            unsafe {
                let seed = seeds.get_unchecked(i);

                if seed.len() > MAX_SEED_LEN {
                    return None;
                }

                data.get_unchecked_mut(i).write(seed);
            }

            i += 1;
        }

        // SAFETY: `data` is guaranteed to have enough space for `MAX_SEEDS + 2`
        // elements, and `MAX_SEEDS` is larger than `N`.
        //
        // The bump seed will be written in the loop below, so we don't need to
        // write it here.
        unsafe {
            data.get_unchecked_mut(i + 1).write(program_id.as_ref());
            data.get_unchecked_mut(i + 2).write(PDA_MARKER.as_ref());
        }

        for bump_seed in &BUMP_SEEDS {
            let address = {
                // SAFETY: `data` is allocated with enough space for `MAX_SEEDS + 2`.
                unsafe {
                    data.get_unchecked_mut(i)
                        .write(core::slice::from_ref(bump_seed));
                }

                let hash = hashv(unsafe { from_raw_parts(data.as_ptr() as *const &[u8], i + 3) });
                Address::from(hash.to_bytes())
            };

            // Check if the derived address is a valid (off-curve)
            // program derived address.
            if !address.is_on_curve() {
                return Some((address, *bump_seed));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::AddressError, Address};

    #[test]
    fn test_derive_address() {
        let program_id = Address::new_from_array([1u8; 32]);
        let seeds: &[&[u8]; 2] = &[b"seed1", b"seed2"];
        let (address, bump) = Address::find_program_address(seeds, &program_id);

        let derived_address = Address::derive_address(seeds, Some(bump), &program_id);
        let derived_address_const = Address::derive_address_const(seeds, Some(bump), &program_id);

        assert_eq!(address, derived_address);
        assert_eq!(address, derived_address_const);

        let extended_seeds: &[&[u8]; 3] = &[b"seed1", b"seed2", &[bump]];

        let derived_address = Address::derive_address(extended_seeds, None, &program_id);
        let derived_address_const =
            Address::derive_address_const(extended_seeds, None, &program_id);

        assert_eq!(address, derived_address);
        assert_eq!(address, derived_address_const);
    }

    #[test]
    fn test_program_derive_address() {
        let program_id = Address::new_unique();
        let seeds: &[&[u8]; 3] = &[b"derived", b"programm", b"address"];

        let (address, bump) = Address::find_program_address(seeds, &program_id);

        let (derived_address, derived_bump) =
            Address::derive_program_address(seeds, &program_id).unwrap();

        assert_eq!(address, derived_address);
        assert_eq!(bump, derived_bump);
    }

    #[test]
    fn test_derive_program_address_matches_find_program_address() {
        /// Check that the derived program address and bump match the
        /// expected address from `find_program_address` for the given
        /// seeds and program id.
        fn check<const N: usize>(seeds: &[&[u8]; N], program_id: &Address) {
            let expected = Address::find_program_address(seeds, program_id);

            assert_eq!(
                Address::derive_program_address(seeds, program_id),
                Some(expected),
                "mismatch for seeds {seeds:?} and program id {program_id:?}"
            );
        }

        for value in 0..128 {
            let program_id = Address::new_from_array([value; 32]);
            let seed = [value; crate::MAX_SEED_LEN];

            check(&[], &program_id);
            check(&[b""], &program_id);
            check(&[b"derived", &seed[..1], b"", &seed], &program_id);
            check(&[seed.as_slice(); crate::MAX_SEEDS - 1], &program_id);
        }
    }

    #[test]
    fn test_derive_address_matches_create_program_address() {
        /// Check that the derived address matches the expected address
        /// from `create_program_address` for the given seeds and program id.
        fn check<const N: usize>(seeds: &[&[u8]; N], program_id: &Address) {
            for bump in [None, Some(0), Some(1), Some(127), Some(255)] {
                let derived = Address::derive_address(seeds, bump, program_id);

                let mut seeds_with_bump = seeds.to_vec();

                if let Some(ref bump) = bump {
                    seeds_with_bump.push(core::slice::from_ref(bump));
                }

                let expected = Address::create_program_address(&seeds_with_bump, program_id);

                // Derivation computes the hash without rejecting on-curve addresses.
                let actual = if derived.is_on_curve() {
                    Err(AddressError::InvalidSeeds)
                } else {
                    Ok(derived)
                };

                assert_eq!(
                    actual, expected,
                    "mismatch for seeds {seeds:?}, bump {bump:?} and program id {program_id:?}"
                );
            }
        }

        for value in 0..128 {
            let program_id = Address::new_from_array([value; 32]);
            let seed = [value; crate::MAX_SEED_LEN];

            check(&[], &program_id);
            check(&[b""], &program_id);
            check(&[b"derived", &seed[..1], b"", &seed], &program_id);
            check(&[seed.as_slice(); crate::MAX_SEEDS - 1], &program_id);
        }
    }
}
