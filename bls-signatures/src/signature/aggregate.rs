#[cfg(feature = "parallel")]
use rayon::prelude::*;
use {
    crate::{
        error::BlsError,
        scalar::Scalar,
        signature::points::{AddToSignatureProjective, SignatureProjective},
    },
    blstrs::{G2Projective, Scalar as BlstrsScalar},
};

impl SignatureProjective {
    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        &mut self,
        signatures: impl Iterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        for signature in signatures {
            signature.add_to_accumulator(self)?;
        }
        Ok(())
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        signatures: impl Iterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        let mut aggregate = SignatureProjective::identity();
        let mut count = 0;
        for signature in signatures {
            signature.add_to_accumulator(&mut aggregate)?;
            count += 1;
        }
        if count == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        Ok(aggregate)
    }

    // Aggregate a list of signatures and scalar elements using MSM on these signatures
    #[deprecated(
        since = "3.5.0",
        note = "Please use `SignatureProjective::aggregate_with_weights` instead, which takes \
                `solana_bls_signatures::Scalar` rather than `blstrs::Scalar`"
    )]
    pub fn aggregate_with_scalars<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        signatures: impl ExactSizeIterator<Item = &'a S>,
        scalars: impl ExactSizeIterator<Item = &'a BlstrsScalar>,
    ) -> Result<SignatureProjective, BlsError> {
        Self::multi_exp(signatures, scalars.copied())
    }

    /// Aggregate a list of signatures, each weighted by a scalar, using MSM.
    pub fn aggregate_with_weights<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        signatures: impl ExactSizeIterator<Item = &'a S>,
        weights: impl ExactSizeIterator<Item = &'a Scalar>,
    ) -> Result<SignatureProjective, BlsError> {
        Self::multi_exp(signatures, weights.map(|weight| weight.0))
    }

    /// The multi-scalar multiplication shared by [`Self::aggregate_with_weights`]
    /// and its deprecated `blstrs`-typed counterpart.
    #[allow(clippy::arithmetic_side_effects)]
    fn multi_exp<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        signatures: impl ExactSizeIterator<Item = &'a S>,
        scalars: impl ExactSizeIterator<Item = BlstrsScalar>,
    ) -> Result<SignatureProjective, BlsError> {
        if signatures.len() != scalars.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        if signatures.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }

        let mut points = alloc::vec::Vec::with_capacity(signatures.len());
        let mut scalar_values = alloc::vec::Vec::with_capacity(scalars.len());

        for (signature, scalar) in signatures.zip(scalars) {
            let mut point = SignatureProjective::identity();
            signature.add_to_accumulator(&mut point)?;

            points.push(point.0);
            scalar_values.push(scalar);
        }

        Ok(SignatureProjective(G2Projective::multi_exp(
            &points,
            &scalar_values,
        )))
    }

    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<'a, S: AddToSignatureProjective + Sync + 'a>(
        &mut self,
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        match SignatureProjective::par_aggregate(signatures) {
            Ok(aggregate) => {
                self.0 += &aggregate.0;
                Ok(())
            }
            Err(BlsError::EmptyAggregation) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<'a, S: AddToSignatureProjective + Sync + 'a>(
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        let (aggregate, has_items) = signatures
            .into_par_iter()
            .fold(
                || Ok::<_, BlsError>((SignatureProjective::identity(), false)),
                |acc, signature| {
                    let (mut proj, _) = acc?;
                    signature.add_to_accumulator(&mut proj)?;
                    Ok((proj, true))
                },
            )
            .reduce(
                || Ok::<_, BlsError>((SignatureProjective::identity(), false)),
                |a, b| {
                    let (mut a_proj, a_has) = a?;
                    let (b_proj, b_has) = b?;
                    a_proj.0 += b_proj.0;
                    Ok((a_proj, a_has || b_has))
                },
            )?;

        if !has_items {
            return Err(BlsError::EmptyAggregation);
        }

        Ok(aggregate)
    }
}

#[cfg(test)]
mod tests {
    use crate::{keypair::Keypair, scalar::Scalar, signature::SignatureProjective};

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_aggregate_with_scalars_matches_weights() {
        let message = b"test message";
        let signatures = [
            Keypair::new().sign(message),
            Keypair::new().sign(message),
            Keypair::new().sign(message),
        ];
        let weights = [Scalar::random(), Scalar::random(), Scalar::random()];
        let blstrs_weights: alloc::vec::Vec<_> = weights.iter().map(|weight| weight.0).collect();

        let from_weights =
            SignatureProjective::aggregate_with_weights(signatures.iter(), weights.iter()).unwrap();
        let from_scalars =
            SignatureProjective::aggregate_with_scalars(signatures.iter(), blstrs_weights.iter())
                .unwrap();
        assert_eq!(from_weights, from_scalars);
    }
}
