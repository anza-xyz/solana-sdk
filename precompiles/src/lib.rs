#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    lazy_static::lazy_static, solana_feature_set_interface::PrecompileFeatureSet,
    solana_message::compiled_instruction::CompiledInstruction,
    solana_precompile_error::PrecompileError, solana_pubkey::Pubkey,
};

/// All precompiled programs must implement the `Verify` function
pub type Verify =
    fn(&[u8], &[&[u8]], &PrecompileFeatureSet) -> std::result::Result<(), PrecompileError>;

/// All precompiled programs must implement the `Enabled` function
pub type Enabled = fn(&PrecompileFeatureSet) -> bool;

/// Information on a precompiled program
pub struct Precompile {
    /// Program id
    pub program_id: Pubkey,
    /// Enabled function
    pub enabled_fn: Enabled,
    /// Verification function
    pub verify_fn: Verify,
}
impl Precompile {
    /// Creates a new `Precompile`
    pub fn new(program_id: Pubkey, enabled_fn: Enabled, verify_fn: Verify) -> Self {
        Precompile {
            program_id,
            enabled_fn,
            verify_fn,
        }
    }
    /// Check if this precompiled program is enabled
    pub fn enabled(&self, feature_set: &PrecompileFeatureSet) -> bool {
        (self.enabled_fn)(feature_set)
    }
    /// Verify this precompiled program
    pub fn verify(
        &self,
        data: &[u8],
        instruction_datas: &[&[u8]],
        feature_set: &PrecompileFeatureSet,
    ) -> std::result::Result<(), PrecompileError> {
        (self.verify_fn)(data, instruction_datas, feature_set)
    }
}

lazy_static! {
    /// The list of all precompiled programs
    static ref PRECOMPILES: Vec<Precompile> = vec![
        Precompile::new(
            solana_sdk_ids::secp256k1_program::id(),
            |_| true, // always enabled
            solana_secp256k1_program::verify,
        ),
        Precompile::new(
            solana_sdk_ids::ed25519_program::id(),
            |_| true, // always enabled
            solana_ed25519_program::verify,
        ),
        Precompile::new(
            solana_sdk_ids::secp256r1_program::id(),
            |feature_set| feature_set.secp256r1_precompile_enabled,
            solana_secp256r1_program::verify,
        )
    ];
}

/// Check if a program is a precompiled program
pub fn is_precompile<F>(program_id: &Pubkey, feature_set: &PrecompileFeatureSet) -> bool
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .any(|precompile| &precompile.program_id == program_id && precompile.enabled(feature_set))
}

/// Find an enabled precompiled program
pub fn get_precompile<'a, F>(
    program_id: &'a Pubkey,
    feature_set: &PrecompileFeatureSet,
) -> Option<&'a Precompile>
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .find(|precompile| &precompile.program_id == program_id && precompile.enabled(feature_set))
}

pub fn get_precompiles<'a>() -> &'a [Precompile] {
    &PRECOMPILES
}

/// Check that a program is precompiled and if so verify it
pub fn verify_if_precompile(
    program_id: &Pubkey,
    precompile_instruction: &CompiledInstruction,
    all_instructions: &[CompiledInstruction],
    feature_set: &PrecompileFeatureSet,
) -> Result<(), PrecompileError> {
    for precompile in PRECOMPILES.iter() {
        if &precompile.program_id == program_id && precompile.enabled(feature_set) {
            let instruction_datas: Vec<_> = all_instructions
                .iter()
                .map(|instruction| instruction.data.as_ref())
                .collect();
            return precompile.verify(
                &precompile_instruction.data,
                &instruction_datas,
                feature_set,
            );
        }
    }
    Ok(())
}
