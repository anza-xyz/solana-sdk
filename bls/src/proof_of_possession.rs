use {
    crate::{error::BlsError, keypair::PubkeyProjective, pod::ProofOfPossession, Bls},
    blstrs::{G2Affine, G2Projective},
};

/// A BLS proof of possession in a projective point representation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOfPossessionProjective(pub(crate) G2Projective);
impl ProofOfPossessionProjective {
    /// Verify a proof of possession against a public key
    pub fn verify(&self, public_key: &PubkeyProjective) -> bool {
        Bls::verify_proof_of_possession(public_key, self)
    }
}

impl From<ProofOfPossessionProjective> for ProofOfPossession {
    fn from(proof: ProofOfPossessionProjective) -> Self {
        Self(proof.0.to_uncompressed())
    }
}

impl TryFrom<ProofOfPossession> for ProofOfPossessionProjective {
    type Error = BlsError;

    fn try_from(proof: ProofOfPossession) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

impl TryFrom<&ProofOfPossession> for ProofOfPossessionProjective {
    type Error = BlsError;

    fn try_from(proof: &ProofOfPossession) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&proof.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}
