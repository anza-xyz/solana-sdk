#![deprecated(
    since = "2.3.0",
    note = "Use solana-address-lookup-table-interface and solana-message instead"
)]

pub use {
    solana_address_lookup_table_interface::{error, instruction, program, state},
    solana_message::AddressLookupTableAccount,
};
