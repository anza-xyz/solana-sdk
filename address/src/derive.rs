use {
    crate::{Address, MAX_SEEDS, PDA_MARKER},
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
    pub fn derive_address<const N: usize>(
        seeds: &[&[u8]; N],
        bump: Option<u8>,
        program_id: &Address,
    ) -> Address {
        const {
            assert!(N < MAX_SEEDS, "number of seeds must be less than MAX_SEEDS");
        }

        let mut data = [const { MaybeUninit::<&[u8]>::uninit() }; MAX_SEEDS + 2];
        let mut i = 0;

        while i < N {
            // SAFETY: `data` is guaranteed to have enough space for `N` seeds,
            // so `i` will always be within bounds.
            unsafe {
                data.get_unchecked_mut(i).write(seeds.get_unchecked(i));
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
        Address::from(hash.to_bytes())
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
}

#[cfg(test)]
mod tests {
    use crate::Address;

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
}
