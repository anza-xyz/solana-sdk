use {
    crate::{
        instruction::SVMInstruction, message_address_table_lookup::SVMMessageAddressTableLookup,
        svm_message::SVMStaticMessage,
    },
    solana_hash::Hash,
    solana_message::VersionedMessage,
    solana_pubkey::Pubkey,
    solana_transaction::versioned::{sanitized::SanitizedVersionedTransaction, TransactionVersion},
};

impl SVMStaticMessage for SanitizedVersionedTransaction {
    fn version(&self) -> TransactionVersion {
        match &self.get_message().message {
            VersionedMessage::Legacy(_) => TransactionVersion::LEGACY,
            VersionedMessage::V0(_) => TransactionVersion::Number(0),
            VersionedMessage::V1(_) => TransactionVersion::Number(1),
        }
    }

    fn num_transaction_signatures(&self) -> u64 {
        u64::from(self.get_message().message.header().num_required_signatures)
    }

    fn num_write_locks(&self) -> u64 {
        let message = &self.get_message().message;
        let header = message.header();
        let num_writable_loaded_addresses = message
            .address_table_lookups()
            .unwrap_or_default()
            .iter()
            .map(|lookup| lookup.writable_indexes.len())
            .sum::<usize>();
        message
            .static_account_keys()
            .len()
            .saturating_sub(usize::from(header.num_readonly_signed_accounts))
            .saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
            .saturating_add(num_writable_loaded_addresses) as u64
    }

    fn num_readonly_signed_static_accounts(&self) -> u8 {
        self.get_message()
            .message
            .header()
            .num_readonly_signed_accounts
    }

    fn num_readonly_unsigned_static_accounts(&self) -> u8 {
        self.get_message()
            .message
            .header()
            .num_readonly_unsigned_accounts
    }

    fn recent_blockhash(&self) -> &Hash {
        self.get_message().message.recent_blockhash()
    }

    fn num_instructions(&self) -> usize {
        self.get_message().instructions().len()
    }

    fn instructions_iter(&self) -> impl Iterator<Item = SVMInstruction<'_>> {
        self.get_message()
            .instructions()
            .iter()
            .map(SVMInstruction::from)
    }

    fn program_instructions_iter(
        &self,
    ) -> impl Iterator<Item = (&Pubkey, SVMInstruction<'_>)> + Clone {
        self.get_message()
            .program_instructions_iter()
            .map(|(pubkey, ix)| (pubkey, SVMInstruction::from(ix)))
    }

    fn static_account_keys(&self) -> &[Pubkey] {
        self.get_message().message.static_account_keys()
    }

    fn fee_payer(&self) -> &Pubkey {
        &self.get_message().message.static_account_keys()[0]
    }

    fn num_lookup_tables(&self) -> usize {
        self.get_message()
            .message
            .address_table_lookups()
            .unwrap_or_default()
            .len()
    }

    fn message_address_table_lookups(
        &self,
    ) -> impl Iterator<Item = SVMMessageAddressTableLookup<'_>> {
        self.get_message()
            .message
            .address_table_lookups()
            .unwrap_or_default()
            .iter()
            .map(SVMMessageAddressTableLookup::from)
    }

    fn is_signer(&self, index: usize) -> bool {
        self.get_message().message.is_signer(index)
    }

    fn is_invoked(&self, key_index: usize) -> bool {
        self.get_message().message.is_invoked(key_index)
    }
}
