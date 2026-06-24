//! Useful extras for `Account` state.

use solana_instruction_error::InstructionError;

#[cfg(feature = "bincode")]
mod bincode;
#[cfg(feature = "wincode")]
mod wincode;
// wincode uses its own trait (rather than `StateMut`/`State`) so the bincode and
// wincode implementations can coexist when both features are enabled.
#[cfg(feature = "wincode")]
pub use wincode::*;

/// Convenience trait to covert serialization errors to instruction errors.
pub trait StateMut<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError>;
}
pub trait State<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&self, state: &T) -> Result<(), InstructionError>;
}
