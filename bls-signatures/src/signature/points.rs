#[cfg(all(not(target_os = "solana"), feature = "std"))]
use crate::pubkey::points::NEG_G1_GENERATOR_AFFINE;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, PreparedHashedMessage},
        pubkey::{AddToPubkeyProjective, AsPubkeyAffine, PubkeyProjective, VerifiablePubkey},
        signature::bytes::{Signature, SignatureCompressed},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar},
    group::{prime::PrimeCurveAffine, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
};
#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use {alloc::vec::Vec, rayon::prelude::*};

/// A trait for types that can be converted into a `SignatureProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureProjective {
    /// Attempt to convert the type into a `SignatureProjective`.
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError>;
}

/// A trait that provides verification methods to any convertible signature type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiableSignature: AsSignatureAffine + Sized {
    /// Verify the signature against any convertible public key type and a message.
    fn verify<P: VerifiablePubkey>(&self, pubkey: &P, message: &[u8]) -> Result<(), BlsError> {
        pubkey.verify_signature(self, message)
    }
}

/// A BLS signature in a projective point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProjective(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl SignatureProjective {
    /// Group pairing terms by message hash in `O(n log n)` time by sorting keys.
    fn group_hashed_terms(
        pairs: impl Iterator<Item = (G1Affine, HashedMessage)>,
        capacity: usize,
    ) -> (alloc::vec::Vec<G1Affine>, alloc::vec::Vec<HashedMessage>) {
        let mut entries = alloc::vec::Vec::with_capacity(capacity);
        for (pubkey_affine, hashed_message) in pairs {
            entries.push((
                hashed_message.0.to_uncompressed(),
                pubkey_affine,
                hashed_message,
            ));
        }

        #[cfg(feature = "parallel")]
        entries.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));
        #[cfg(not(feature = "parallel"))]
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut grouped_pubkeys = alloc::vec::Vec::with_capacity(entries.len());
        let mut grouped_hashed_messages = alloc::vec::Vec::with_capacity(entries.len());

        for chunk in entries.chunk_by(|a, b| a.0 == b.0) {
            let mut aggregate_pubkey = G1Projective::from(chunk[0].1);
            for item in &chunk[1..] {
                #[allow(clippy::arithmetic_side_effects)]
                {
                    aggregate_pubkey += &item.1;
                }
            }
            grouped_pubkeys.push(aggregate_pubkey);
            grouped_hashed_messages.push(chunk[0].2);
        }

        let grouped_pubkeys_affine = grouped_pubkeys.into_iter().map(Into::into).collect();
        (grouped_pubkeys_affine, grouped_hashed_messages)
    }

    /// Group pairing terms by message hash in `O(n log n)` time by sorting keys,
    /// keeping prepared G2 terms to avoid recomputation.
    fn group_prepared_terms<'b>(
        pairs: impl Iterator<Item = (G1Affine, &'b PreparedHashedMessage)>,
        capacity: usize,
    ) -> (alloc::vec::Vec<G1Affine>, alloc::vec::Vec<&'b G2Prepared>) {
        let mut entries = alloc::vec::Vec::with_capacity(capacity);
        for (pubkey_affine, prepared) in pairs {
            entries.push((
                prepared.hashed_message.0.to_uncompressed(),
                pubkey_affine,
                &prepared.prepared,
            ));
        }

        #[cfg(feature = "parallel")]
        entries.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));
        #[cfg(not(feature = "parallel"))]
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut grouped_pubkeys = alloc::vec::Vec::with_capacity(entries.len());
        let mut grouped_prepared = alloc::vec::Vec::with_capacity(entries.len());

        for chunk in entries.chunk_by(|a, b| a.0 == b.0) {
            let mut aggregate_pubkey = G1Projective::from(chunk[0].1);
            for item in &chunk[1..] {
                #[allow(clippy::arithmetic_side_effects)]
                {
                    aggregate_pubkey += &item.1;
                }
            }
            grouped_pubkeys.push(aggregate_pubkey);
            grouped_prepared.push(chunk[0].2);
        }

        let grouped_pubkeys_affine = grouped_pubkeys.into_iter().map(Into::into).collect();
        (grouped_pubkeys_affine, grouped_prepared)
    }

    /// Creates the identity element, which is the starting point for aggregation
    ///
    /// The identity element is not a valid signature and it should only be used
    /// for the purpose of aggregation
    pub fn identity() -> Self {
        Self(G2Projective::identity())
    }

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

    /// Verify a list of signatures against a message and a list of public keys
    pub fn verify_aggregate<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a P>,
        signatures: impl Iterator<Item = &'a S>,
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        Self::verify_aggregate_pre_hashed(public_keys, signatures, &hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed message and a list of
    /// public keys.
    pub fn verify_aggregate_pre_hashed<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a P>,
        signatures: impl Iterator<Item = &'a S>,
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        Self::verify_aggregate_prepared(public_keys, signatures, &prepared_hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed and prepared message and
    /// a list of public keys.
    pub fn verify_aggregate_prepared<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a P>,
        signatures: impl Iterator<Item = &'a S>,
        prepared_hashed_message: &PreparedHashedMessage,
    ) -> Result<(), BlsError> {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        aggregate_pubkey.verify_signature_prepared(&aggregate_signature, prepared_hashed_message)
    }

    /// Verifies an aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct<'a, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        let hashed_messages: alloc::vec::Vec<_> = messages.map(HashedMessage::new).collect();
        Self::verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            hashed_messages.iter(),
        )
    }

    /// Verifies an aggregated signature over a set of distinct pre-hashed
    /// messages and public keys.
    pub fn verify_distinct_pre_hashed<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        hashed_messages: impl ExactSizeIterator<Item = &'b HashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != hashed_messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            hashed_messages,
        )
    }

    /// Verifies an aggregated signature over a set of distinct pre-hashed and
    /// prepared messages and public keys.
    pub fn verify_distinct_prepared<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        prepared_hashed_messages: impl ExactSizeIterator<Item = &'b PreparedHashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != prepared_hashed_messages.len()
            || public_keys.len() != signatures.len()
        {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated_prepared(
            public_keys,
            &aggregate_signature,
            prepared_hashed_messages,
        )
    }

    /// Verifies a pre-aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct_aggregated<'a, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        aggregate_signature: &S,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let hashed_messages: alloc::vec::Vec<_> = messages.map(HashedMessage::new).collect();
        Self::verify_distinct_aggregated_pre_hashed(
            public_keys,
            aggregate_signature,
            hashed_messages.iter(),
        )
    }

    /// Verifies a pre-aggregated signature over a set of distinct pre-hashed
    /// messages and public keys.
    pub fn verify_distinct_aggregated_pre_hashed<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        aggregate_signature: &S,
        hashed_messages: impl ExactSizeIterator<Item = &'b HashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let public_keys_len = public_keys.len();
        let mut pubkeys_affine = alloc::vec::Vec::with_capacity(public_keys_len);
        let mut hashed_messages_owned = alloc::vec::Vec::with_capacity(public_keys_len);
        for (pubkey, hashed_message) in public_keys.zip(hashed_messages) {
            let g1_affine = pubkey.try_as_affine()?;
            if bool::from(g1_affine.0.is_identity()) {
                return Err(BlsError::VerificationFailed);
            }
            pubkeys_affine.push(g1_affine.0);
            hashed_messages_owned.push(*hashed_message);
        }

        let aggregate_signature_affine = aggregate_signature.try_as_affine()?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine.0);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        #[allow(clippy::arithmetic_side_effects)]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let (grouped_pubkeys_affine, grouped_hashed_messages) = Self::group_hashed_terms(
            pubkeys_affine.into_iter().zip(hashed_messages_owned),
            public_keys_len,
        );
        let grouped_prepared_hashes: alloc::vec::Vec<_> = grouped_hashed_messages
            .iter()
            .map(|hashed_message| G2Prepared::from(hashed_message.0))
            .collect();

        let mut terms =
            alloc::vec::Vec::with_capacity(grouped_pubkeys_affine.len().saturating_add(1));
        for (pubkey, prepared_hash) in grouped_pubkeys_affine
            .iter()
            .zip(grouped_prepared_hashes.iter())
        {
            terms.push((pubkey, prepared_hash));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        (miller_loop_result.final_exponentiation() == Gt::identity())
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }

    /// Verifies a pre-aggregated signature over a set of distinct pre-hashed and
    /// prepared messages and public keys.
    ///
    /// Entries with identical message hashes are merged internally by summing
    /// their public keys, reducing pairing terms.
    ///
    /// Security note: rogue-key concerns are not relevant here because keys are
    /// assumed to be PoP-validated.
    pub fn verify_distinct_aggregated_prepared<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a P>,
        aggregate_signature: &S,
        prepared_hashed_messages: impl ExactSizeIterator<Item = &'b PreparedHashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != prepared_hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let public_keys_len = public_keys.len();
        let mut pubkeys_affine = alloc::vec::Vec::with_capacity(public_keys_len);
        let mut prepared_refs = alloc::vec::Vec::with_capacity(public_keys_len);
        for (pubkey, prepared) in public_keys.zip(prepared_hashed_messages) {
            let g1_affine = pubkey.try_as_affine()?;
            if bool::from(g1_affine.0.is_identity()) {
                return Err(BlsError::VerificationFailed);
            }
            pubkeys_affine.push(g1_affine.0);
            prepared_refs.push(prepared);
        }

        let aggregate_signature_affine = aggregate_signature.try_as_affine()?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine.0);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        #[allow(clippy::arithmetic_side_effects)]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let (grouped_pubkeys_affine, grouped_prepared_hashes) = Self::group_prepared_terms(
            pubkeys_affine.into_iter().zip(prepared_refs),
            public_keys_len,
        );

        let mut terms =
            alloc::vec::Vec::with_capacity(grouped_pubkeys_affine.len().saturating_add(1));
        for (pubkey, prepared_hash) in grouped_pubkeys_affine
            .iter()
            .zip(grouped_prepared_hashes.iter())
        {
            terms.push((pubkey, *prepared_hash));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        (miller_loop_result.final_exponentiation() == Gt::identity())
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }

    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<'a, S: AddToSignatureProjective + Sync + 'a>(
        &mut self,
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        let aggregate = SignatureProjective::par_aggregate(signatures)?;
        self.0 += &aggregate.0;
        Ok(())
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<'a, S: AddToSignatureProjective + Sync + 'a>(
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        signatures
            .into_par_iter()
            .fold(
                || Ok(SignatureProjective::identity()),
                |acc, signature| {
                    let mut acc = acc?;
                    signature.add_to_accumulator(&mut acc)?;
                    Ok(acc)
                },
            )
            .reduce_with(|a, b| {
                let mut a_val = a?;
                let b_val = b?;
                a_val.0 += b_val.0;
                Ok(a_val)
            })
            .ok_or(BlsError::EmptyAggregation)?
    }

    /// Verify a list of signatures against a message and a list of public keys
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[P],
        signatures: &[S],
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        Self::par_verify_aggregate_pre_hashed(public_keys, signatures, &hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed message and a list of
    /// public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate_pre_hashed<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[P],
        signatures: &[S],
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        Self::par_verify_aggregate_prepared(public_keys, signatures, &prepared_hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed and prepared message and
    /// a list of public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate_prepared<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[P],
        signatures: &[S],
        prepared_hashed_message: &PreparedHashedMessage,
    ) -> Result<(), BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        let (aggregate_pubkey_res, aggregate_signature_res) = rayon::join(
            || PubkeyProjective::par_aggregate(public_keys.into_par_iter()),
            || SignatureProjective::par_aggregate(signatures.into_par_iter()),
        );
        let aggregate_pubkey = aggregate_pubkey_res?;
        let aggregate_signature = aggregate_signature_res?;
        aggregate_pubkey.verify_signature_prepared(&aggregate_signature, prepared_hashed_message)
    }

    /// Verifies a set of signatures over a set of distinct messages and
    /// public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct<P, S>(
        public_keys: &[P],
        signatures: &[S],
        messages: &[&[u8]],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        let hashed_messages: Vec<_> = messages
            .par_iter()
            .map(|msg| HashedMessage::new(msg))
            .collect();
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            &hashed_messages,
        )
    }

    /// Verifies a set of signatures over a set of distinct pre-hashed messages
    /// and public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_pre_hashed<P, S>(
        public_keys: &[P],
        signatures: &[S],
        hashed_messages: &[HashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != hashed_messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            hashed_messages,
        )
    }

    /// Verifies a set of signatures over a set of distinct pre-hashed and
    /// prepared messages and public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_prepared<P, S>(
        public_keys: &[P],
        signatures: &[S],
        prepared_hashed_messages: &[PreparedHashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != prepared_hashed_messages.len()
            || public_keys.len() != signatures.len()
        {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        let hashed_messages: Vec<_> = prepared_hashed_messages
            .iter()
            .map(|prepared| prepared.hashed_message)
            .collect();
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            &hashed_messages,
        )
    }

    /// In parallel, verifies a pre-aggregated signature over a set of distinct
    /// messages and public keys.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated<P, S>(
        public_keys: &[P],
        aggregate_signature: &S,
        messages: &[&[u8]],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let hashed_messages: alloc::vec::Vec<_> = messages
            .par_iter()
            .map(|msg| HashedMessage::new(msg))
            .collect();
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            aggregate_signature,
            &hashed_messages,
        )
    }

    /// In parallel, verifies a pre-aggregated signature over a set of distinct
    /// pre-hashed messages and public keys.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated_pre_hashed<P, S>(
        public_keys: &[P],
        aggregate_signature: &S,
        hashed_messages: &[HashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let pubkeys_affine: Vec<_> = public_keys
            .par_iter()
            .map(|pk| {
                let affine = pk.try_as_affine()?;
                if bool::from(affine.0.is_identity()) {
                    return Err(BlsError::VerificationFailed);
                }
                Ok::<G1Affine, BlsError>(affine.0)
            })
            .collect::<Result<_, _>>()?;

        let public_keys_len = public_keys.len();
        let (grouped_pubkeys_affine, grouped_hashed_messages) = Self::group_hashed_terms(
            pubkeys_affine
                .into_iter()
                .zip(hashed_messages.iter().copied()),
            public_keys_len,
        );
        let grouped_prepared_hashes: Vec<_> = grouped_hashed_messages
            .par_iter()
            .map(|hashed_message| G2Prepared::from(hashed_message.0))
            .collect();

        let aggregate_signature_affine = aggregate_signature.try_as_affine()?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine.0);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        #[allow(clippy::arithmetic_side_effects)]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let mut terms = alloc::vec::Vec::with_capacity(grouped_pubkeys_affine.len() + 1);
        for (pubkey, prepared_hash) in grouped_pubkeys_affine
            .iter()
            .zip(grouped_prepared_hashes.iter())
        {
            terms.push((pubkey, prepared_hash));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        (miller_loop_result.final_exponentiation() == Gt::identity())
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }

    /// In parallel, verifies a pre-aggregated signature over a set of distinct
    /// pre-hashed and prepared messages and public keys.
    ///
    /// Entries with identical message hashes are merged internally by summing
    /// their public keys, reducing pairing terms.
    ///
    /// Security note: rogue-key concerns are not relevant here because keys are
    /// assumed to be PoP-validated.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated_prepared<P, S>(
        public_keys: &[P],
        aggregate_signature: &S,
        prepared_hashed_messages: &[PreparedHashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != prepared_hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }

        let hashed_messages: Vec<_> = prepared_hashed_messages
            .iter()
            .map(|prepared| prepared.hashed_message)
            .collect();
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            aggregate_signature,
            &hashed_messages,
        )
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsSignatureAffine> VerifiableSignature for T {}

/// A trait for types that can be converted into a `SignatureAffine`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureAffine {
    /// Attempt to convert the type into a `SignatureAffine`.
    fn try_as_affine(&self) -> Result<SignatureAffine, BlsError>;
}

/// A BLS signature in an affine point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignatureAffine(pub(crate) G2Affine);

/// A trait for types that can be efficiently added to a `SignatureProjective` accumulator.
/// This enables Mixed Addition (Projective += Affine) optimization.
#[cfg(not(target_os = "solana"))]
pub trait AddToSignatureProjective {
    /// Adds itself to the accumulator
    fn add_to_accumulator(&self, acc: &mut SignatureProjective) -> Result<(), BlsError>;
}

// Fallback for trait objects to support `dyn` types
#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjective for dyn AsSignatureProjective {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_accumulator(&self, acc: &mut SignatureProjective) -> Result<(), BlsError> {
        let proj = self.try_as_projective()?;
        acc.0 += proj.0;
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureAffine,
    affine
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureProjective,
    projective
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    Signature,
    convert
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureCompressed,
    convert
);

/// A BLS signature in an affine point representation that is guaranteed to
/// be a point on the curve, but it is *not* guaranteed to be in the prime-order
/// subgroup G2.
///
/// This type allows for efficient "unchecked" deserialization. It is designed
/// to be used with aggregation functions where the expensive subgroup check
/// can be performed on the aggregate instead of each individual signature.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignatureAffineUnchecked(pub(crate) G2Affine);

#[cfg(not(target_os = "solana"))]
impl SignatureAffineUnchecked {
    /// Performs the subgroup check (coset check) on this point.
    ///
    /// This verifies that the point is on the curve and in the correct q-order subgroup G2.
    /// Returns a validated `SignatureAffine` on success.
    pub fn verify_subgroup(&self) -> Result<SignatureAffine, BlsError> {
        if bool::from(self.0.is_torsion_free()) {
            Ok(SignatureAffine(self.0))
        } else {
            Err(BlsError::VerificationFailed)
        }
    }
}

impl_unchecked_conversions!(
    SignatureAffineUnchecked,
    SignatureAffine,
    SignatureProjective,
    SignatureCompressed,
    Signature,
    G2Affine
);

#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureAffineUnchecked,
    affine
);
