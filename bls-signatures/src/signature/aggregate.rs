#[cfg(feature = "parallel")]
use rayon::prelude::*;
use {
    crate::{
        error::BlsError,
        signature::points::{AddToSignatureProjective, SignatureProjective},
    },
    blstrs::{G2Projective, Scalar},
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
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with_scalars<'a, S: AddToSignatureProjective + ?Sized + 'a>(
        signatures: impl ExactSizeIterator<Item = &'a S>,
        scalars: impl ExactSizeIterator<Item = &'a Scalar>,
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
            scalar_values.push(*scalar);
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
