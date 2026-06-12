use std::sync::{Arc, RwLock};

/// Off-chain stub implementation of the `sol_get_sysvar` syscall.
pub trait GetSysvarStub: Sync + Send {
    /// Write `length` bytes from the sysvar identified by `sysvar_id_addr`,
    /// starting at `offset`, into `var_addr`.
    ///
    /// Return `0` on success. Return the runtime syscall error code for
    /// unsupported sysvars or invalid ranges.
    fn sol_get_sysvar(
        &self,
        sysvar_id_addr: *const u8,
        var_addr: *mut u8,
        offset: u64,
        length: u64,
    ) -> u64;
}

static GET_SYSVAR_STUB: RwLock<Option<Arc<dyn GetSysvarStub>>> = RwLock::new(None);

/// Install the process-global `sol_get_sysvar` stub, returning the previous one.
pub fn set_get_sysvar_stub(stub: Arc<dyn GetSysvarStub>) -> Option<Arc<dyn GetSysvarStub>> {
    replace_get_sysvar_stub(Some(stub))
}

/// Clear the process-global `sol_get_sysvar` stub.
pub fn clear_get_sysvar_stub() -> Option<Arc<dyn GetSysvarStub>> {
    replace_get_sysvar_stub(None)
}

fn replace_get_sysvar_stub(stub: Option<Arc<dyn GetSysvarStub>>) -> Option<Arc<dyn GetSysvarStub>> {
    std::mem::replace(&mut *GET_SYSVAR_STUB.write().unwrap(), stub)
}

pub(crate) fn sol_get_sysvar(
    sysvar_id_addr: *const u8,
    var_addr: *mut u8,
    offset: u64,
    length: u64,
) -> u64 {
    let stub = GET_SYSVAR_STUB.read().unwrap().clone();
    match stub {
        Some(stub) => stub.sol_get_sysvar(sysvar_id_addr, var_addr, offset, length),
        None => solana_program_error::UNSUPPORTED_SYSVAR,
    }
}
