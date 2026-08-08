use {
    crate::svm_transaction::SVMStaticTransaction, solana_signature::Signature,
    solana_transaction::versioned::sanitized::SanitizedVersionedTransaction,
};

impl SVMStaticTransaction for SanitizedVersionedTransaction {
    fn signature(&self) -> &Signature {
        &SanitizedVersionedTransaction::signatures(self)[0]
    }

    fn signatures(&self) -> &[Signature] {
        SanitizedVersionedTransaction::signatures(self)
    }
}
