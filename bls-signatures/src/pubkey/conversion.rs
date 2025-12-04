#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        pubkey::{
            bytes::{AsPubkey, Pubkey, PubkeyCompressed, BLS_PUBLIC_KEY_AFFINE_SIZE},
            points::{AsPubkeyProjective, PubkeyProjective},
        },
    },
    blstrs::G1Affine,
};

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    PubkeyProjective,
    Pubkey,
    PubkeyCompressed,
    G1Affine,
    AsPubkeyProjective,
    AsPubkey
);

#[cfg(not(target_os = "solana"))]
impl TryFrom<&[u8]> for PubkeyProjective {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_PUBLIC_KEY_AFFINE_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        // unwrap safe due to the length check above
        let public_affine = Pubkey(bytes.try_into().unwrap());

        public_affine.try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&PubkeyProjective> for [u8; BLS_PUBLIC_KEY_AFFINE_SIZE] {
    fn from(pubkey: &PubkeyProjective) -> Self {
        let pubkey_affine: Pubkey = (*pubkey).into();
        pubkey_affine.0
    }
}
