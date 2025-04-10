pub use {
    crate::message::compiled_instruction::CompiledInstruction,
    solana_instruction::{
        error::InstructionError, AccountMeta, Instruction, ProcessedSiblingInstruction,
        TRANSACTION_LEVEL_STACK_HEIGHT,
    },
};

/// Returns a sibling instruction from the processed sibling instruction list.
///
/// The processed sibling instruction list is a reverse-ordered list of
/// successfully processed sibling instructions. For example, given the call flow:
///
/// A
/// B -> C -> D
/// B -> E
/// B -> F
///
/// Then B's processed sibling instruction list is: `[A]`
/// Then F's processed sibling instruction list is: `[E, C]`
pub fn get_processed_sibling_instruction(index: usize) -> Option<Instruction> {
    #[cfg(target_os = "solana")]
    {
        solana_instruction::syscalls::get_processed_sibling_instruction(index)
    }

    #[cfg(not(target_os = "solana"))]
    {
        crate::program_stubs::sol_get_processed_sibling_instruction(index)
    }
}

/// Get the current stack height, transaction-level instructions are height
/// TRANSACTION_LEVEL_STACK_HEIGHT, fist invoked inner instruction is height
/// TRANSACTION_LEVEL_STACK_HEIGHT + 1, etc...
pub fn get_stack_height() -> usize {
    #[cfg(target_os = "solana")]
    unsafe {
        solana_instruction::syscalls::get_stack_height()
    }

    #[cfg(not(target_os = "solana"))]
    {
        crate::program_stubs::sol_get_stack_height() as usize
    }
}

// TODO: remove this.
/// Addition that returns [`InstructionError::InsufficientFunds`] on overflow.
///
/// This is an internal utility function.
#[doc(hidden)]
pub fn checked_add(a: u64, b: u64) -> Result<u64, InstructionError> {
    a.checked_add(b).ok_or(InstructionError::InsufficientFunds)
}
