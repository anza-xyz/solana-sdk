pub use {
    crate::message::compiled_instruction::CompiledInstruction,
    solana_instruction::{
        error::InstructionError,
        syscalls::{get_processed_sibling_instruction, get_stack_height},
        AccountMeta, Instruction, ProcessedSiblingInstruction, TRANSACTION_LEVEL_STACK_HEIGHT,
    },
};

// TODO: remove this.
/// Addition that returns [`InstructionError::InsufficientFunds`] on overflow.
///
/// This is an internal utility function.
#[doc(hidden)]
pub fn checked_add(a: u64, b: u64) -> Result<u64, InstructionError> {
    a.checked_add(b).ok_or(InstructionError::InsufficientFunds)
}
