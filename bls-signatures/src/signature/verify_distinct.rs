#[cfg(feature = "std")]
use crate::pubkey::verify::NEG_G1_GENERATOR_AFFINE;
use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, PreparedHashedMessage},
        pubkey::AsPubkeyAffine,
        signature::points::{AddToSignatureProjective, AsSignatureAffine, SignatureProjective},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Prepared, Gt},
    group::{prime::PrimeCurveAffine, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
};
#[cfg(feature = "parallel")]
use {alloc::vec::Vec, rayon::prelude::*};

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

    /// Verifies an aggregated signature over a set of multiple messages and
    /// public keys.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique to prevent rogue-key attacks. The messages can be
    /// identical or different.
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

    /// Verifies an aggregated signature over a set of multiple pre-hashed
    /// messages and public keys.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
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

    /// Verifies an aggregated signature over a set of multiple pre-hashed and
    /// prepared messages and public keys.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
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

    /// Verifies a pre-aggregated signature over a set of multiple messages and
    /// public keys.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
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

    /// Verifies a pre-aggregated signature over a set of multiple pre-hashed
    /// messages and public keys.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
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

    /// Verifies a pre-aggregated signature over a set of multiple pre-hashed and
    /// prepared messages and public keys.
    ///
    /// Entries with identical message hashes are merged internally by summing
    /// their public keys, reducing pairing terms.
    ///
    /// Security note: rogue-key concerns are not relevant here because keys are
    /// assumed to be PoP-validated.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
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

    /// Verifies a set of signatures over a set of multiple messages and
    /// public keys in parallel.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
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
