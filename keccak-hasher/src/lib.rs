//! Hashing with the [keccak] (SHA-3) hash function.
//!
//! [keccak]: https://keccak.team/keccak.html
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "sha3", not(any(target_os = "solana", target_arch = "bpf"))))]
use sha3::{Digest, Keccak256};
pub use solana_hash::{Hash, ParseHashError, HASH_BYTES, MAX_BASE58_LEN};

/// Number of bytes in a Keccak-f[1600] state.
pub const KECCAK_F1600_STATE_BYTES: usize = 200;
/// Number of `u64` lanes in a Keccak-f[1600] state.
pub const KECCAK_F1600_STATE_LANES: usize = 25;
/// Number of bytes in a Keccak-f[1600] lane.
pub const KECCAK_F1600_LANE_BYTES: usize = 8;
/// Required alignment in bytes for the `sol_keccak_f1600` syscall state pointer.
pub const KECCAK_F1600_STATE_ALIGN: usize = 8;
/// Number of rounds in Keccak-f[1600].
pub const KECCAK_F1600_ROUNDS: usize = 24;

#[derive(Clone, Default)]
#[cfg(all(feature = "sha3", not(any(target_os = "solana", target_arch = "bpf"))))]
pub struct Hasher {
    hasher: Keccak256,
}

#[cfg(all(feature = "sha3", not(any(target_os = "solana", target_arch = "bpf"))))]
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
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), inline(always))]
pub fn hashv(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
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
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut hash_result = core::mem::MaybeUninit::<[u8; solana_hash::HASH_BYTES]>::uninit();
        // SAFETY: This is sound as sol_keccak256 always fills all 32 bytes of our hash
        unsafe {
            solana_define_syscall::definitions::sol_keccak256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                hash_result.as_mut_ptr() as *mut u8,
            );
            Hash::new_from_array(hash_result.assume_init())
        }
    }
}

/// Return a Keccak256 hash for the given data.
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), inline(always))]
pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}

/// Apply one full 24-round Keccak-f[1600] permutation in place.
///
/// The state is 25 `u64` lanes. Lane `state[x + 5 * y]` is Keccak lane
/// `A[x, y]`, with `0 <= x < 5` and `0 <= y < 5`.
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), inline(always))]
pub fn keccak_f(state: &mut [u64; KECCAK_F1600_STATE_LANES]) {
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        keccak_f1600_native(state);
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        // SAFETY: `state` is a valid mutable pointer to exactly 25 contiguous
        // `u64` lanes. The syscall mutates that range in place or aborts.
        unsafe {
            solana_define_syscall::definitions::sol_keccak_f1600(state.as_mut_ptr());
        }
    }
}

/// Apply one full 24-round Keccak-f[1600] permutation in place.
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), inline(always))]
pub fn keccak_f1600(state: &mut [u64; KECCAK_F1600_STATE_LANES]) {
    keccak_f(state);
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn keccak_f1600_native(state: &mut [u64; KECCAK_F1600_STATE_LANES]) {
    keccak::f1600(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_f_matches_xkcp_vectors() {
        let state_first = [
            0xf125_8f79_40e1_dde7,
            0x84d5_ccf9_33c0_478a,
            0xd598_261e_a65a_a9ee,
            0xbd15_4730_6f80_494d,
            0x8b28_4e05_6253_d057,
            0xff97_a42d_7f8e_6fd4,
            0x90fe_e5a0_a446_47c4,
            0x8c5b_da0c_d619_2e76,
            0xad30_a6f7_1b19_059c,
            0x3093_5ab7_d08f_fc64,
            0xeb5a_a93f_2317_d635,
            0xa9a6_e626_0d71_2103,
            0x81a5_7c16_dbcf_555f,
            0x43b8_31cd_0347_c826,
            0x01f2_2f1a_11a5_569f,
            0x05e5_635a_21d9_ae61,
            0x64be_fef2_8cc9_70f2,
            0x6136_7095_7bc4_6611,
            0xb87c_5a55_4fd0_0ecb,
            0x8c3e_e88a_1ccf_32c8,
            0x940c_7922_ae3a_2614,
            0x1841_f924_a2c5_09e4,
            0x16f5_3526_e704_65c2,
            0x75f6_44e9_7f30_a13b,
            0xeaf1_ff7b_5cec_a249,
        ];
        let state_second = [
            0x2d5c_954d_f96e_cb3c,
            0x6a33_2cd0_7057_b56d,
            0x093d_8d12_70d7_6b6c,
            0x8a20_d9b2_5569_d094,
            0x4f9c_4f99_e5e7_f156,
            0xf957_b9a2_da65_fb38,
            0x8577_3dae_1275_af0d,
            0xfaf4_f247_c3d8_10f7,
            0x1f1b_9ee6_f79a_8759,
            0xe4fe_cc0f_ee98_b425,
            0x68ce_61b6_b9ce_68a1,
            0xdeea_66c4_ba8f_974f,
            0x33c4_3d83_6eaf_b1f5,
            0xe006_5404_2719_dbd9,
            0x7cf8_a9f0_0983_1265,
            0xfd54_49a6_bf17_4743,
            0x97dd_ad33_d899_4b40,
            0x48ea_d5fc_5d0b_e774,
            0xe3b8_c8ee_55b7_b03c,
            0x91a0_226e_649e_42e9,
            0x900e_3129_e7ba_dd7b,
            0x202a_9ec5_faa3_cce8,
            0x5b34_0246_4e1c_3db6,
            0x609f_4e62_a44c_1059,
            0x20d0_6cd2_6a8f_bf5c,
        ];

        let mut state = [0_u64; KECCAK_F1600_STATE_LANES];
        keccak_f(&mut state);
        assert_eq!(state, state_first);

        keccak_f(&mut state);
        assert_eq!(state, state_second);
    }

    #[test]
    fn keccak_f1600_alias_matches_keccak_f() {
        let mut state =
            core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(i as u64 + 1));
        let mut alias_state = state;

        keccak_f(&mut state);
        keccak_f1600(&mut alias_state);

        assert_eq!(state, alias_state);
    }
}
