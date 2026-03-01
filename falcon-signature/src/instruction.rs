#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use {
    crate::{
        constants::{DATA_START, PUBKEY_SIZE, SIGNATURE_OFFSETS_SIZE, SIGNATURE_OFFSETS_START},
        offsets::Falcon512SignatureOffsets,
        public_key::PublicKey,
        signature::Signature,
    },
    bytemuck::bytes_of,
    solana_instruction::Instruction,
};

/// Creates a Falcon-512 verification instruction from pre-computed offsets.
///
/// This function encodes the signature offsets into instruction data, allowing
/// signatures, public keys, and messages to be located in other instructions
/// within the same transaction.
///
/// # Arguments
/// * `offsets` - Slice of offset structures specifying where to find verification data
///
/// # Returns
/// An instruction for the Falcon-512 signature verification program
pub fn offsets_to_falcon512_instruction(offsets: &[Falcon512SignatureOffsets]) -> Instruction {
    let mut instruction_data = Vec::with_capacity(
        SIGNATURE_OFFSETS_START
            .saturating_add(SIGNATURE_OFFSETS_SIZE.saturating_mul(offsets.len())),
    );

    let num_signatures = offsets.len() as u8;
    // Add num_signatures and padding byte for alignment
    instruction_data.push(num_signatures);
    instruction_data.push(0); // padding

    for offset in offsets {
        instruction_data.extend_from_slice(bytes_of(offset));
    }

    Instruction {
        program_id: solana_sdk_ids::falcon512_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

/// Creates a Falcon-512 verification instruction with embedded signature data.
///
/// This is a convenience function that creates a self-contained instruction
/// with the public key, signature, and message all embedded in the instruction data.
///
/// # Arguments
/// * `message` - The message that was signed
/// * `signature` - The Falcon-512 signature (variable length, 41-666 bytes)
/// * `pubkey` - The Falcon-512 public key (897 bytes)
///
/// # Returns
/// An instruction for the Falcon-512 signature verification program
pub fn new_falcon512_instruction_with_signature(
    message: &[u8],
    signature: &Signature,
    pubkey: &PublicKey,
) -> Instruction {
    let signature_bytes = signature.as_bytes();
    let pubkey_bytes = pubkey.as_bytes();

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(PUBKEY_SIZE)
            .saturating_add(signature_bytes.len())
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset.saturating_add(PUBKEY_SIZE);
    let message_offset = signature_offset.saturating_add(signature_bytes.len());

    // Add num_signatures and padding byte for alignment
    instruction_data.push(num_signatures);
    instruction_data.push(0); // padding

    let offsets = Falcon512SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_length: signature_bytes.len() as u16,
        signature_instruction_index: u16::MAX, // current instruction
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index: u16::MAX, // current instruction
        message_offset: message_offset as u16,
        message_length: message.len() as u16,
        message_instruction_index: u16::MAX, // current instruction
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));

    debug_assert_eq!(instruction_data.len(), public_key_offset);

    instruction_data.extend_from_slice(pubkey_bytes);

    debug_assert_eq!(instruction_data.len(), signature_offset);

    instruction_data.extend_from_slice(signature_bytes);

    debug_assert_eq!(instruction_data.len(), message_offset);

    instruction_data.extend_from_slice(message);

    Instruction {
        program_id: solana_sdk_ids::falcon512_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}
