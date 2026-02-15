use bytemuck_derive::{Pod, Zeroable};

/// Offsets for locating Falcon-512 signature data within instruction data.
///
/// This structure follows the SIMD-0152 precompile pattern, allowing signatures,
/// public keys, and messages to be located either in the current instruction
/// or in other instructions within the same transaction.
///
/// The instruction index fields use `u16::MAX` to indicate the current instruction.
/// Values less than `u16::MAX` reference prior instructions in the transaction.
///
/// # Example
///
/// ```
/// use solana_falcon_signature::{Falcon512SignatureOffsets, SIGNATURE_OFFSETS_SIZE};
///
/// let offsets = Falcon512SignatureOffsets {
///     signature_offset: 18,
///     signature_length: 650,
///     signature_instruction_index: u16::MAX, // current instruction
///     public_key_offset: 668,
///     public_key_instruction_index: u16::MAX,
///     message_offset: 1565,
///     message_length: 100,
///     message_instruction_index: u16::MAX,
/// };
///
/// // Structure is exactly 16 bytes for bytemuck compatibility
/// assert_eq!(std::mem::size_of::<Falcon512SignatureOffsets>(), SIGNATURE_OFFSETS_SIZE);
/// ```
#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Falcon512SignatureOffsets {
    /// Offset to the signature within the instruction data.
    pub signature_offset: u16,
    /// Length of the signature in bytes.
    pub signature_length: u16,
    /// Instruction index containing the signature (u16::MAX = current instruction).
    pub signature_instruction_index: u16,
    /// Offset to the public key within the instruction data.
    pub public_key_offset: u16,
    /// Instruction index containing the public key (u16::MAX = current instruction).
    pub public_key_instruction_index: u16,
    /// Offset to the message within the instruction data.
    pub message_offset: u16,
    /// Length of the message in bytes.
    pub message_length: u16,
    /// Instruction index containing the message (u16::MAX = current instruction).
    pub message_instruction_index: u16,
}
