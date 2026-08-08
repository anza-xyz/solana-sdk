use {
    crate::svm_transaction::SVMStaticTransaction, solana_signature::Signature,
    solana_transaction::sanitized::SanitizedTransaction,
};

impl SVMStaticTransaction for SanitizedTransaction {
    fn signature(&self) -> &Signature {
        SanitizedTransaction::signature(self)
    }

    fn signatures(&self) -> &[Signature] {
        SanitizedTransaction::signatures(self)
    }
}
