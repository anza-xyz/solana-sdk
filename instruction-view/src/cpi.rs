//! Cross-program invocation helpers.

#[cfg(feature = "slice-cpi")]
extern crate alloc;

#[cfg(feature = "slice-cpi")]
use alloc::boxed::Box;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub use solana_define_syscall::{
    define_syscall,
    definitions::{sol_get_return_data, sol_invoke_signed_c, sol_set_return_data},
};
use {
    crate::InstructionView,
    core::{marker::PhantomData, mem::MaybeUninit, ops::Deref, slice::from_raw_parts},
    solana_account_view::AccountView,
    solana_address::Address,
    solana_program_error::{ProgramError, ProgramResult},
};

/// Maximum number of accounts allowed in `invoke` and `invoke_with_bounds`
/// functions.
pub const MAX_STATIC_CPI_ACCOUNTS: usize = 64;

/// Maximum number of accounts allowed in a cross-program invocation.
//
// Note: This value will increase to 255 when SIMD-0339 is activated.
pub const MAX_CPI_ACCOUNTS: usize = 128;

/// An account for CPI invocations.
///
/// This struct contains the same information as an [`AccountView`], but has
/// the memory layout as expected by `sol_invoke_signed_c` syscall.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CpiAccount<'a> {
    /// Address of the account.
    address: *const Address,

    /// Number of lamports owned by this account.
    lamports: *const u64,

    /// Length of data in bytes.
    data_len: u64,

    /// On-chain data within this account.
    data: *const u8,

    /// Program that owns this account.
    owner: *const Address,

    /// The epoch at which this account will next owe rent.
    rent_epoch: u64,

    /// Transaction was signed by this account's key?
    is_signer: bool,

    /// Is the account writable?
    is_writable: bool,

    /// This account's data contains a loaded program (and is now read-only).
    executable: bool,

    /// The pointers to the `AccountView` data are only valid for as long as the
    /// `&'a AccountView` lives. Instead of holding a reference to the actual `AccountView`,
    /// which would increase the size of the type, we claim to hold a reference without
    /// actually holding one using a `PhantomData<&'a AccountView>`.
    _account_view: PhantomData<&'a AccountView>,
}

impl From<&AccountView> for CpiAccount<'_> {
    fn from(account: &AccountView) -> Self {
        Self {
            address: account.address(),
            // SAFETY:  Dereferencing `account.account_ptr()` to access its
            // `lamports` field.
            lamports: unsafe { &(*account.account_ptr()).lamports },
            data_len: account.data_len() as u64,
            data: account.data_ptr(),
            // SAFETY: `account.owner()` is not expected to be updated between
            // the creation of the CPI account and invocation of the program.
            owner: unsafe { account.owner() },
            // The `rent_epoch` field is not present in the `AccountView` struct,
            // since the value occurs after the variable data of the account in
            // the runtime input data.
            rent_epoch: 0,
            is_signer: account.is_signer(),
            is_writable: account.is_writable(),
            executable: account.executable(),
            _account_view: PhantomData::<&AccountView>,
        }
    }
}

/// Represents a signer seed.
///
/// This struct contains the same information as a `[u8]`, but
/// has the memory layout as expected by `sol_invoke_signed_c`
/// syscall.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Seed<'a> {
    /// Seed bytes.
    pub(crate) seed: *const u8,

    /// Length of the seed bytes.
    pub(crate) len: u64,

    /// The pointer to the seed bytes is only valid while the `&'a [u8]` lives. Instead
    /// of holding a reference to the actual `[u8]`, which would increase the size of the
    /// type, we claim to hold a reference without actually holding one using a
    /// `PhantomData<&'a [u8]>`.
    _bytes: PhantomData<&'a [u8]>,
}

impl<'a> From<&'a [u8]> for Seed<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self {
            seed: value.as_ptr(),
            len: value.len() as u64,
            _bytes: PhantomData::<&[u8]>,
        }
    }
}

impl<'a, const SIZE: usize> From<&'a [u8; SIZE]> for Seed<'a> {
    fn from(value: &'a [u8; SIZE]) -> Self {
        Self {
            seed: value.as_ptr(),
            len: value.len() as u64,
            _bytes: PhantomData::<&[u8]>,
        }
    }
}

impl Deref for Seed<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { from_raw_parts(self.seed, self.len as usize) }
    }
}

/// Represents a [program derived address][pda] (PDA) signer controlled by the
/// calling program.
///
/// [pda]: https://solana.com/docs/core/cpi#program-derived-addresses
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Signer<'a, 'b> {
    /// Signer seeds.
    pub(crate) seeds: *const Seed<'a>,

    /// Number of seeds.
    pub(crate) len: u64,

    /// The pointer to the seeds is only valid while the `&'b [Seed<'a>]` lives. Instead
    /// of holding a reference to the actual `[Seed<'a>]`, which would increase the size
    /// of the type, we claim to hold a reference without actually holding one using a
    /// `PhantomData<&'b [Seed<'a>]>`.
    _seeds: PhantomData<&'b [Seed<'a>]>,
}

impl<'a, 'b> From<&'b [Seed<'a>]> for Signer<'a, 'b> {
    fn from(value: &'b [Seed<'a>]) -> Self {
        Self {
            seeds: value.as_ptr(),
            len: value.len() as u64,
            _seeds: PhantomData::<&'b [Seed<'a>]>,
        }
    }
}

impl<'a, 'b, const SIZE: usize> From<&'b [Seed<'a>; SIZE]> for Signer<'a, 'b> {
    fn from(value: &'b [Seed<'a>; SIZE]) -> Self {
        Self {
            seeds: value.as_ptr(),
            len: value.len() as u64,
            _seeds: PhantomData::<&'b [Seed<'a>]>,
        }
    }
}

/// Convenience macro for constructing a `[Seed; N]` array from a list of seeds
/// to create a [`Signer`].
///
/// # Example
///
/// Creating seeds array and signer for a PDA with a single seed and bump value:
/// ```
/// use solana_address::Address;
/// use solana_instruction_view::{cpi::Signer, seeds};
///
/// let pda_bump = 0xffu8;
/// let pda_ref = &[pda_bump];
/// let example_key = Address::default();
/// let seeds = seeds!(b"seed", example_key.as_ref(), pda_ref);
/// let signer = Signer::from(&seeds);
/// ```
#[macro_export]
macro_rules! seeds {
    ( $($seed:expr),* ) => {
        [$(
            $crate::cpi::Seed::from($seed),
        )*]
    };
}

/// Invoke a cross-program instruction from an array of `AccountView`s.
///
/// This function is a convenience wrapper around the [`invoke_signed`] function
/// with the signers' seeds set to an empty slice.
///
/// Note that this function is inlined to avoid the overhead of a function call,
/// but uses stack memory allocation. When a large number of accounts is needed,
/// it is recommended to use the [`invoke_with_slice`] function instead to reduce
/// stack memory utilization.
///
/// # Important
///
/// The accounts on the `account_views` slice must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke<const ACCOUNTS: usize, A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A; ACCOUNTS],
) -> ProgramResult {
    invoke_signed::<ACCOUNTS, A>(instruction, account_views, &[])
}

/// Invoke a cross-program instruction from a slice of `AccountView`s.
///
/// This function is a convenience wrapper around the [`invoke_signed_with_bounds`]
/// function with the signers' seeds set to an empty slice.
///
/// The `MAX_ACCOUNTS` constant defines the maximum number of accounts expected
/// to be passed to the cross-program invocation. This provides an upper bound to
/// the number of accounts that need to be statically allocated for cases where the
/// number of instruction accounts is not known at compile time. The final number of
/// accounts passed to the cross-program invocation will be the number of accounts
/// required by the `instruction`, even if `MAX_ACCOUNTS` is greater than that. When
/// `MAX_ACCOUNTS` is lower than the number of accounts expected by the instruction,
/// this function will return a [`ProgramError::InvalidArgument`] error.
///
/// Note that this function is inlined to avoid the overhead of a function call,
/// but uses stack memory allocation. When a large number of accounts is needed,
/// it is recommended to use the [`invoke_with_slice`] function instead to reduce
/// stack memory utilization.
///
/// # Important
///
/// The accounts on the `account_views` slice must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke_with_bounds<const MAX_ACCOUNTS: usize, A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A],
) -> ProgramResult {
    invoke_signed_with_bounds::<MAX_ACCOUNTS, A>(instruction, account_views, &[])
}

#[cfg(feature = "slice-cpi")]
/// Invoke a cross-program instruction from a slice of `AccountView`s.
///
/// This function is a convenience wrapper around the [`invoke_signed_with_slice`]
/// function with the signers' seeds set to an empty slice.
///
/// Note that this function will allocate heap memory to store up to
/// `MAX_CPI_ACCOUNTS` accounts.
///
/// # Important
///
/// The accounts on the `account_views` slice must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke_with_slice<A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A],
) -> ProgramResult {
    invoke_signed_with_slice(instruction, account_views, &[])
}

/// Invoke a cross-program instruction with signatures from an array of
/// `AccountView`s.
///
/// This function performs validation of the `account_views` array to ensure that:
///   1. It has at least as many accounts as the number of accounts expected by
///      the instruction.
///   2. The accounts match the expected accounts in the instruction, i.e., their
///      `Address` matches the `address` in the `AccountView`.
///   3. The borrow state of the accounts is compatible with the mutability of the
///      instruction accounts.
///
/// This validation is done to ensure that the borrow checker rules are followed,
/// consuming CUs in the process. The [`invoke_signed_unchecked`] is an alternative
/// to this function that have lower CU consumption since it does not perform
/// any validation. This should only be used when the caller is sure that the borrow
/// checker rules are followed.
///
/// Note that this function is inlined to avoid the overhead of a function call,
/// but uses stack memory allocation. When a large number of accounts is needed,
/// it is recommended to use the [`invoke_signed_with_slice`] function instead
/// to reduce stack memory utilization.
///
/// # Important
///
/// The accounts on the `account_views` array must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke_signed<const ACCOUNTS: usize, A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A; ACCOUNTS],
    signers_seeds: &[Signer],
) -> ProgramResult {
    // Check that the number of `ACCOUNTS` provided is not greater than
    // the maximum number of accounts allowed.
    const {
        assert!(
            ACCOUNTS <= MAX_STATIC_CPI_ACCOUNTS,
            "ACCOUNTS is greater than allowed MAX_STATIC_CPI_ACCOUNTS"
        );
    }

    let mut accounts = [const { MaybeUninit::<CpiAccount>::uninit() }; ACCOUNTS];

    // SAFETY: The array of `AccountView`s will be checked to ensure that it has
    // the same number of accounts as the instruction – this indirectly validates
    // that the stack allocated account storage `ACCOUNTS` is sufficient for the
    // number of accounts expected by the instruction.
    unsafe {
        inner_invoke_signed_with_slice::<A>(
            instruction,
            account_views.as_slice(),
            accounts.as_mut_slice(),
            signers_seeds,
        )
    }
}

/// Invoke a cross-program instruction with signatures from a slice of
/// `AccountView`s.
///
/// This function performs validation of the `account_views` slice to ensure that:
///   1. It has at least as many accounts as the number of accounts expected by
///      the instruction.
///   2. The accounts match the expected accounts in the instruction, i.e., their
///      `Address` matches the `address` in the `AccountView`.
///   3. The borrow state of the accounts is compatible with the mutability of the
///      instruction accounts.
///
/// This validation is done to ensure that the borrow checker rules are followed,
/// consuming CUs in the process. The [`invoke_signed_unchecked`] is an alternative
/// to this function that has lower CU consumption since it does not perform
/// any validation. This should only be used when the caller is sure that the borrow
/// checker rules are followed.
///
/// The `MAX_ACCOUNTS` constant defines the maximum number of accounts expected
/// to be passed to the cross-program invocation. This provides an upper bound to
/// the number of accounts that need to be statically allocated for cases where the
/// number of instruction accounts is not known at compile time. The final number of
/// accounts passed to the cross-program invocation will be the number of accounts
/// required by the `instruction`, even if `MAX_ACCOUNTS` is greater than that. When
/// `MAX_ACCOUNTS` is lower than the number of accounts expected by the instruction,
/// this function will return a [`ProgramError::InvalidArgument`] error.
///
/// Note that this function is inlined to avoid the overhead of a function call,
/// but uses stack memory allocation. When a large number of accounts is needed,
/// it is recommended to use the [`invoke_signed_with_slice`] function instead to reduce
/// stack memory utilization.
///
/// # Important
///
/// The accounts on the `account_views` slice must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke_signed_with_bounds<const MAX_ACCOUNTS: usize, A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A],
    signers_seeds: &[Signer],
) -> ProgramResult {
    // Check that the number of `MAX_ACCOUNTS` provided is not greater than
    // the maximum number of static accounts allowed.
    const {
        assert!(
            MAX_ACCOUNTS <= MAX_STATIC_CPI_ACCOUNTS,
            "MAX_ACCOUNTS is greater than allowed MAX_STATIC_CPI_ACCOUNTS"
        );
    }

    // Check that the stack allocated account storage `MAX_ACCOUNTS` is sufficient
    // for the number of accounts expected by the instruction.
    if MAX_ACCOUNTS < instruction.accounts.len() {
        return Err(ProgramError::InvalidArgument);
    }

    let mut accounts = [const { MaybeUninit::<CpiAccount>::uninit() }; MAX_ACCOUNTS];

    // SAFETY: The stack allocated account storage `MAX_ACCOUNTS` was validated
    // to be sufficient for the number of accounts expected by the instruction.
    unsafe {
        inner_invoke_signed_with_slice::<A>(
            instruction,
            account_views,
            accounts.as_mut_slice(),
            signers_seeds,
        )
    }
}

#[cfg(feature = "slice-cpi")]
/// Invoke a cross-program instruction with signatures from a slice of
/// `AccountView`s.
///
/// This function performs validation of the `account_views` slice to ensure that:
///   1. It has at least as many accounts as the number of accounts expected by
///      the instruction.
///   2. The accounts match the expected accounts in the instruction, i.e., their
///      `Address` matches the `address` in the `AccountView`.
///   3. The borrow state of the accounts is compatible with the mutability of the
///      instruction accounts.
///
/// This validation is done to ensure that the borrow checker rules are followed,
/// consuming CUs in the process. The [`invoke_signed_unchecked`] is an alternative
/// to this function that have lower CU consumption since it does not perform
/// any validation. This should only be used when the caller is sure that the borrow
/// checker rules are followed.
///
/// Note that this function will allocate heap memory to store up to
/// `MAX_CPI_ACCOUNTS` accounts.
///
/// # Important
///
/// The accounts on the `account_views` slice must be in the same order as the
/// `accounts` field of the `instruction`. When the instruction has duplicated
/// accounts, it is necessary to pass a duplicated reference to the same account
/// to maintain the 1:1 relationship between accounts and instruction accounts.
#[inline(always)]
pub fn invoke_signed_with_slice<A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A],
    signers_seeds: &[Signer],
) -> ProgramResult {
    // Check that the number of instruction accounts does not exceed
    // the maximum allowed number of CPI accounts.
    if MAX_CPI_ACCOUNTS < instruction.accounts.len() {
        return Err(ProgramError::InvalidArgument);
    }

    let mut accounts = Box::<[CpiAccount]>::new_uninit_slice(instruction.accounts.len());

    // SAFETY: The allocated `accounts` slice has the same size as the expected number
    // of instruction accounts.
    unsafe {
        inner_invoke_signed_with_slice::<A>(
            instruction,
            account_views,
            &mut accounts,
            signers_seeds,
        )
    }
}

/// Internal function to invoke a cross-program instruction with signatures
/// from a slice of `AccountView`s performing borrow checking.
///
/// This function performs validation of the `account_views` slice to ensure that:
///   1. It has at least as many accounts as the number of accounts expected by
///      the instruction.
///   2. The accounts match the expected accounts in the instruction, i.e., their
///      `Address` matches the `address` in the `AccountView`.
///   3. The borrow state of the accounts is compatible with the mutability of the
///      instruction accounts.
///
/// # Safety
///
/// This function is unsafe because it does not check that `accounts` is sufficiently
/// large for the number of accounts expected by the instruction. Using an `accounts` slice
/// shorter than the number of accounts expected by the instruction will result in
/// undefined behavior.
#[inline(always)]
unsafe fn inner_invoke_signed_with_slice<A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &[A],
    accounts: &mut [MaybeUninit<CpiAccount>],
    signers_seeds: &[Signer],
) -> ProgramResult {
    // Check that the number of accounts provided is not less than
    // the number of accounts expected by the instruction.
    if account_views.len() < instruction.accounts.len() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    account_views
        .iter()
        .zip(instruction.accounts.iter())
        .zip(accounts.iter_mut())
        .try_for_each(|((account_view, instruction_account), account)| {
            // In order to check whether the borrow state is compatible
            // with the invocation, we need to check that we have the
            // correct account view and instruction account pair.
            if account_view.as_ref().address() != instruction_account.address {
                return Err(ProgramError::InvalidArgument);
            }

            // Determines the borrow state that would be invalid according
            // to their mutability on the instruction.
            let borrowed = if instruction_account.is_writable {
                // If the account is required to be writable, it cannot
                //  be currently borrowed.
                account_view.as_ref().is_borrowed()
            } else {
                // If the account is required to be read-only, it cannot
                // be currently mutably borrowed.
                account_view.as_ref().is_borrowed_mut()
            };

            if borrowed {
                return Err(ProgramError::AccountBorrowFailed);
            }

            account.write(CpiAccount::from(account_view.as_ref()));

            Ok(())
        })?;

    // SAFETY: At this point it is guaranteed that instruction accounts are
    // borrowable according to their mutability on the instruction.
    unsafe {
        invoke_signed_unchecked(
            instruction,
            from_raw_parts(accounts.as_ptr() as _, instruction.accounts.len()),
            signers_seeds,
        );
    }

    Ok(())
}

/// Invoke a cross-program instruction but don't enforce Rust's aliasing rules.
///
/// This function does not check that [`CpiAccount`]s are properly borrowable.
/// Those checks consume CUs that this function avoids.
///
/// Note that the maximum number of accounts that can be passed to a cross-program
/// invocation is defined by the `MAX_CPI_ACCOUNTS` constant. Even if the `[CpiAccount]`
/// slice has more accounts, only the number of accounts required by the `instruction`
/// will be used.
///
/// # Safety
///
/// If any of the writable accounts passed to the callee contain data that is
/// borrowed within the calling program, and that data is written to by the
/// callee, then Rust's aliasing rules will be violated and cause undefined
/// behavior.
#[inline(always)]
pub unsafe fn invoke_unchecked(instruction: &InstructionView, accounts: &[CpiAccount]) {
    invoke_signed_unchecked(instruction, accounts, &[])
}

/// Invoke a cross-program instruction with signatures but don't enforce Rust's
/// aliasing rules.
///
/// This function does not check that [`CpiAccount`]s are properly borrowable.
/// Those checks consume CUs that this function avoids.
///
/// Note that the maximum number of accounts that can be passed to a cross-program
/// invocation is defined by the `MAX_CPI_ACCOUNTS` constant. Even if the `[CpiAccount]`
/// slice has more accounts, only the number of accounts required by the `instruction`
/// will be used.
///
/// # Safety
///
/// If any of the writable accounts passed to the callee contain data that is
/// borrowed within the calling program, and that data is written to by the
/// callee, then Rust's aliasing rules will be violated and cause undefined
/// behavior.
#[inline(always)]
pub unsafe fn invoke_signed_unchecked(
    instruction: &InstructionView,
    accounts: &[CpiAccount],
    signers_seeds: &[Signer],
) {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        use crate::InstructionAccount;

        /// An `Instruction` as expected by `sol_invoke_signed_c`.
        ///
        /// DO NOT EXPOSE THIS STRUCT:
        ///
        /// To ensure pointers are valid upon use, the scope of this struct should
        /// only be limited to the stack where `sol_invoke_signed_c` happens and then
        /// discarded immediately after.
        #[repr(C)]
        struct CInstruction<'a> {
            /// Public key of the program.
            program_id: *const Address,

            /// Accounts expected by the program instruction.
            accounts: *const InstructionAccount<'a>,

            /// Number of accounts expected by the program instruction.
            accounts_len: u64,

            /// Data expected by the program instruction.
            data: *const u8,

            /// Length of the data expected by the program instruction.
            data_len: u64,
        }

        let cpi_instruction = CInstruction {
            program_id: instruction.program_id,
            accounts: instruction.accounts.as_ptr(),
            accounts_len: instruction.accounts.len() as u64,
            data: instruction.data.as_ptr(),
            data_len: instruction.data.len() as u64,
        };

        unsafe {
            sol_invoke_signed_c(
                &cpi_instruction as *const _ as *const u8,
                accounts as *const _ as *const u8,
                accounts.len() as u64,
                signers_seeds as *const _ as *const u8,
                signers_seeds.len() as u64,
            )
        };
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    core::hint::black_box((instruction, accounts, signers_seeds));
}

/// Maximum size that can be set using [`set_return_data`].
pub const MAX_RETURN_DATA: usize = 1024;

/// Set the running program's return data.
///
/// Return data is a dedicated per-transaction buffer for data passed
/// from cross-program invoked programs back to their caller.
///
/// The maximum size of return data is [`MAX_RETURN_DATA`]. Return data is
/// retrieved by the caller with [`get_return_data`].
#[inline(always)]
pub fn set_return_data(data: &[u8]) {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    unsafe {
        sol_set_return_data(data.as_ptr(), data.len() as u64)
    };

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    core::hint::black_box(data);
}

/// Get the return data from an invoked program.
///
/// For every transaction there is a single buffer with maximum length
/// [`MAX_RETURN_DATA`], paired with an [`Address`] representing the program ID of
/// the program that most recently set the return data. Thus the return data is
/// a global resource and care must be taken to ensure that it represents what
/// is expected: called programs are free to set or not set the return data; and
/// the return data may represent values set by programs multiple calls down the
/// call stack, depending on the circumstances of transaction execution.
///
/// Return data is set by the callee with [`set_return_data`].
///
/// Return data is cleared before every CPI invocation - a program that
/// has invoked no other programs can expect the return data to be `None`; if no
/// return data was set by the previous CPI invocation, then this function
/// returns `None`.
///
/// Return data is not cleared after returning from CPI invocations. A
/// program that has called another program may retrieve return data that was
/// not set by the called program, but instead set by a program further down the
/// call stack; or, if a program calls itself recursively, it is possible that
/// the return data was not set by the immediate call to that program, but by a
/// subsequent recursive call to that program. Likewise, an external RPC caller
/// may see return data that was not set by the program it is directly calling,
/// but by a program that program called.
///
/// For more about return data see the [documentation for the return data proposal][rdp].
///
/// [rdp]: https://docs.solanalabs.com/proposals/return-data
#[inline]
pub fn get_return_data() -> Option<ReturnData> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();
        let mut data = [UNINIT_BYTE; MAX_RETURN_DATA];
        let mut program_id = MaybeUninit::<Address>::uninit();

        let size = unsafe {
            sol_get_return_data(
                data.as_mut_ptr() as *mut u8,
                data.len() as u64,
                program_id.as_mut_ptr() as *mut _ as *mut u8,
            )
        };

        if size == 0 {
            None
        } else {
            Some(ReturnData {
                program_id: unsafe { program_id.assume_init() },
                data,
                size: core::cmp::min(size as usize, MAX_RETURN_DATA),
            })
        }
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    core::hint::black_box(None)
}

/// Struct to hold the return data from an invoked program.
#[derive(Debug)]
pub struct ReturnData {
    /// Program that most recently set the return data.
    program_id: Address,

    /// Return data set by the program.
    data: [MaybeUninit<u8>; MAX_RETURN_DATA],

    /// Length of the return data.
    size: usize,
}

impl ReturnData {
    /// Returns the program that most recently set the return data.
    pub fn program_id(&self) -> &Address {
        &self.program_id
    }

    /// Return the data set by the program.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self.data.as_ptr() as _, self.size) }
    }
}
