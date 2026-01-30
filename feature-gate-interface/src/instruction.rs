#[cfg(feature = "bincode")]
use {
    crate::state::Feature,
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_sdk_ids::{feature::id, incinerator, system_program},
    solana_system_interface::instruction as system_instruction,
};

/// Activate a feature
#[cfg(feature = "bincode")]
#[deprecated(
    since = "3.1.0",
    note = "Use `activate_with_lamports` with `rent.minimum_balance(Feature::size_of())` instead"
)]
pub fn activate(feature_id: &Pubkey, funding_address: &Pubkey, rent: &Rent) -> Vec<Instruction> {
    activate_with_lamports(
        feature_id,
        funding_address,
        rent.minimum_balance(Feature::size_of()),
    )
}

#[cfg(feature = "bincode")]
pub fn activate_with_lamports(
    feature_id: &Pubkey,
    funding_address: &Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    vec![
        system_instruction::transfer(funding_address, feature_id, lamports),
        system_instruction::allocate(feature_id, Feature::size_of() as u64),
        system_instruction::assign(feature_id, &id()),
    ]
}

/// Creates a 'RevokePendingActivation' instruction.
#[cfg(feature = "bincode")]
pub fn revoke_pending_activation(feature_id: &Pubkey) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*feature_id, true),
        AccountMeta::new(incinerator::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    Instruction {
        program_id: crate::id(),
        accounts,
        data: vec![0],
    }
}
