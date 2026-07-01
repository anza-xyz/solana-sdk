//! Useful extras for `Account` state.

use solana_instruction_error::InstructionError;

#[cfg(feature = "bincode")]
mod bincode;

/// Convenience trait to covert serialization errors to instruction errors.
pub trait StateMut<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError>;
}
pub trait State<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&self, state: &T) -> Result<(), InstructionError>;
}
