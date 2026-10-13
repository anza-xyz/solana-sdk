use {
    crate::svm_message::{SVMMessage, SVMStaticMessage},
    solana_signature::Signature,
};

mod sanitized_transaction;
mod sanitized_versioned_transaction;

pub trait SVMStaticTransaction: SVMStaticMessage {
    /// Get the first signature of the message.
    fn signature(&self) -> &Signature;

    /// Get all the signatures of the message.
    fn signatures(&self) -> &[Signature];
}

pub trait SVMTransaction: SVMStaticTransaction + SVMMessage {}
impl<T: SVMStaticTransaction + SVMMessage> SVMTransaction for T {}
