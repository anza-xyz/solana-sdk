//! Data structures to represent account information.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::arithmetic_side_effects)]

use {
    core::{
        marker::PhantomData,
        mem::{size_of, ManuallyDrop},
        ops::{Deref, DerefMut},
        ptr::{write, write_bytes, NonNull},
        slice::{from_raw_parts, from_raw_parts_mut},
    },
    solana_address::Address,
    solana_program_error::{ProgramError, ProgramResult},
};

/// Maximum number of bytes a program may add to an account during a
/// single top-level instruction.
pub const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;

/// Value to indicate that an account is not borrowed.
///
/// This value is the same as `solana_program_entrypoint::NON_DUP_MARKER`.
pub const NOT_BORROWED: u8 = u8::MAX;

/// Raw account data.
///
/// This struct is wrapped by [`AccountView`], which provides safe access
/// to account information. At runtime, the account's data is serialized
/// directly after the `Account` struct in memory, with its size specified
/// by [`RuntimeAccount::data_len`].
#[repr(C)]
#[cfg_attr(feature = "copy", derive(Copy))]
#[derive(Clone, Default)]
pub struct RuntimeAccount {
    /// Borrow state for account data.
    ///
    /// This reuses the memory reserved for the duplicate flag in the
    /// account to track data borrows. It represents the numbers of
    /// borrows available. The value `0` indicates that the account
    /// data is mutably borrowed, while values between `2` and `255`
    /// indicate the number of immutable borrows that can still be
    /// allocated. An account's data can only be mutably borrowed
    /// when there are no other active borrows, i.e., when this value
    /// is equal to [`NOT_BORROWED`].
    pub borrow_state: u8,

    /// Indicates whether the transaction was signed by this account.
    pub is_signer: u8,

    /// Indicates whether the account is writable.
    pub is_writable: u8,

    /// Indicates whether this account represents a program.
    pub executable: u8,

    /// Difference between the original data length and the current
    /// data length.
    ///
    /// This is used to track the original data length of the account
    /// when the account is resized. The runtime guarantees that this
    /// value is zero at the start of the instruction.
    pub resize_delta: i32,

    /// Address of the account.
    pub address: Address,

    /// Program that owns this account. Modifiable by programs.
    pub owner: Address,

    /// The lamports in the account. Modifiable by programs.
    pub lamports: u64,

    /// Length of the data. Modifiable by programs.
    pub data_len: u64,
}

/// Wrapper struct for a `RuntimeAccount`.
///
/// This struct provides safe access to the data in a `RuntimeAccount`.
/// It is also used to track borrows of the account data, given that
/// an account can be "shared" across multiple `AccountView` instances.
///
/// # Invariants
///
/// - The `raw` pointer must be valid and point to memory containing a
///   `RuntimeAccount` struct, immediately followed by the account's data
///   region.
/// - The length of the account data must exactly match the value stored in
///   `RuntimeAccount::data_len`.
///
/// These conditions must always hold for any `AccountView` created from
/// a raw pointer.
#[repr(C)]
#[cfg_attr(feature = "copy", derive(Copy))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountView {
    /// Raw (pointer to) account data.
    ///
    /// Note that this is a pointer can be shared across multiple `AccountView`.
    raw: *mut RuntimeAccount,
}

impl AccountView {
    /// Creates a new [`AccountView`] for a given raw account pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `raw` pointer is valid and points
    /// to memory containing a `RuntimeAccount` struct, immediately followed by
    /// the account's data region.
    #[inline(always)]
    pub unsafe fn new_unchecked(raw: *mut RuntimeAccount) -> Self {
        Self { raw }
    }

    /// Address of the account.
    #[inline(always)]
    pub fn address(&self) -> &Address {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { &(*self.raw).address }
    }

    /// Return a reference to the address of the program that owns this account.
    ///
    /// For ownership checks, use the safe `owned_by` method instead.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it returns a reference to the owner field,
    /// which can be modified by `assign` and `close` methods. It is undefined
    /// behavior to use this reference after the account owner has been modified.
    #[inline(always)]
    pub unsafe fn owner(&self) -> &Address {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { &(*self.raw).owner }
    }

    /// Indicate whether the transaction was signed by this account.
    #[inline(always)]
    pub fn is_signer(&self) -> bool {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).is_signer != 0 }
    }

    /// Indicate whether the account is writable or not.
    #[inline(always)]
    pub fn is_writable(&self) -> bool {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).is_writable != 0 }
    }

    /// Indicate whether this account represents an executable program
    /// or not.
    #[inline(always)]
    pub fn executable(&self) -> bool {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).executable != 0 }
    }

    /// Return the size of the account data.
    #[inline(always)]
    pub fn data_len(&self) -> usize {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).data_len as usize }
    }

    /// Return the delta between the original data length and the current
    /// data length.
    ///
    /// This value will be different than zero if the account has been
    /// resized during the current instruction.
    #[inline(always)]
    pub fn resize_delta(&self) -> i32 {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).resize_delta }
    }

    /// Return the lamports in the account.
    #[inline(always)]
    pub fn lamports(&self) -> u64 {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (*self.raw).lamports }
    }

    /// Set the lamports in the account.
    #[inline(always)]
    pub fn set_lamports(&self, lamports: u64) {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe {
            (*self.raw).lamports = lamports;
        }
    }

    /// Indicates whether the account data is empty or not.
    ///
    /// An account is considered empty if the data length is zero.
    #[inline(always)]
    pub fn is_data_empty(&self) -> bool {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        self.data_len() == 0
    }

    /// Checks if the account is owned by the given program.
    #[inline(always)]
    pub fn owned_by(&self, program: &Address) -> bool {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { self.owner() == program }
    }

    /// Changes the owner of the account.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to use this method while there is an active reference
    /// to the `owner` returned by [`Self::owner`].
    #[allow(clippy::clone_on_copy)]
    #[inline(always)]
    pub unsafe fn assign(&self, new_owner: &Address) {
        write(&mut (*self.raw).owner, new_owner.clone());
    }

    /// Return `true` if the account data is borrowed in any form.
    #[inline(always)]
    pub fn is_borrowed(&self) -> bool {
        unsafe { (*self.raw).borrow_state != NOT_BORROWED }
    }

    /// Return `true` if the account data is mutably borrowed.
    #[inline(always)]
    pub fn is_borrowed_mut(&self) -> bool {
        unsafe { (*self.raw).borrow_state == 0 }
    }

    /// Returns an immutable reference to the data in the account.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not return a `Ref`, thus leaving the borrow
    /// flag untouched. Useful when an instruction has verified non-duplicate accounts.
    #[inline(always)]
    pub unsafe fn borrow_unchecked(&self) -> &[u8] {
        from_raw_parts(self.data_ptr(), self.data_len())
    }

    /// Returns a mutable reference to the data in the account.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not return a `RefMut`, thus leaving the borrow
    /// flag untouched. Useful when an instruction has verified non-duplicate accounts.
    #[allow(clippy::mut_from_ref)]
    #[inline(always)]
    pub unsafe fn borrow_unchecked_mut(&self) -> &mut [u8] {
        from_raw_parts_mut(self.data_ptr(), self.data_len())
    }

    /// Tries to get an immutable reference to the account data, failing if the account
    /// is already mutably borrowed.
    pub fn try_borrow(&self) -> Result<Ref<'_, [u8]>, ProgramError> {
        // check if the account data can be borrowed
        self.check_borrow()?;

        let borrow_state = self.raw as *mut u8;
        // Use one immutable borrow for data by subtracting `1` from the data
        // borrow counter bits; we are guaranteed that there is at least one
        // immutable borrow available.
        //
        // SAFETY: The `borrow_state` is a mutable pointer to the borrow state
        // of the account, which is guaranteed to be valid.
        unsafe { *borrow_state -= 1 };

        // return the reference to data
        Ok(Ref {
            value: unsafe { NonNull::from(from_raw_parts(self.data_ptr(), self.data_len())) },
            state: unsafe { NonNull::new_unchecked(borrow_state) },
            marker: PhantomData,
        })
    }

    /// Tries to get a mutable reference to the account data, failing if the account
    /// is already borrowed in any form.
    pub fn try_borrow_mut(&self) -> Result<RefMut<'_, [u8]>, ProgramError> {
        // check if the account data can be mutably borrowed
        self.check_borrow_mut()?;

        let borrow_state = self.raw as *mut u8;
        // Set the mutable data borrow bit to `0`; we are guaranteed that account
        // data is not already borrowed in any form.
        //
        // SAFETY: The `borrow_state` is a mutable pointer to the borrow state
        // of the account, which is guaranteed to be valid.
        unsafe { *borrow_state = 0 };

        // return the mutable reference to data
        Ok(RefMut {
            value: unsafe { NonNull::from(from_raw_parts_mut(self.data_ptr(), self.data_len())) },
            state: unsafe { NonNull::new_unchecked(borrow_state) },
            marker: PhantomData,
        })
    }

    /// Check if it is possible to get an immutable reference to the account data,
    /// failing if the account is already mutably borrowed or there are not enough
    /// immutable borrows available.
    #[inline(always)]
    pub fn check_borrow(&self) -> Result<(), ProgramError> {
        // There must be at least one immutable borrow available.
        //
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        if unsafe { (*self.raw).borrow_state } < 2 {
            return Err(ProgramError::AccountBorrowFailed);
        }

        Ok(())
    }

    /// Checks if it is possible to get a mutable reference to the account data,
    /// failing if the account is already borrowed in any form.
    #[inline(always)]
    pub fn check_borrow_mut(&self) -> Result<(), ProgramError> {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        if unsafe { (*self.raw).borrow_state } != NOT_BORROWED {
            return Err(ProgramError::AccountBorrowFailed);
        }

        Ok(())
    }

    /// Resize (either truncating or zero extending) the account's data.
    ///
    /// The account data can be increased by up to [`MAX_PERMITTED_DATA_INCREASE`] bytes
    /// within an instruction.
    ///
    /// # Important
    ///
    /// This method makes assumptions about the layout and location of memory
    /// referenced by `RuntimeAccount` fields. It should only be called for
    /// instances of `AccountView` that were created by the runtime and received
    /// in the `process_instruction` entrypoint of a program.
    #[inline]
    pub fn resize(&self, new_len: usize) -> Result<(), ProgramError> {
        // Check whether the account data is already borrowed.
        self.check_borrow_mut()?;

        // SAFETY: We are checking if the account data is already borrowed, so
        // we are safe to call.
        unsafe { self.resize_unchecked(new_len) }
    }

    /// Resize (either truncating or zero extending) the account's data.
    ///
    /// The account data can be increased by up to [`MAX_PERMITTED_DATA_INCREASE`] bytes
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not check if the account data is already
    /// borrowed. The caller must guarantee that there are no active borrows to the account
    /// data.
    #[inline(always)]
    pub unsafe fn resize_unchecked(&self, new_len: usize) -> Result<(), ProgramError> {
        // Account length is always `< i32::MAX`...
        let current_len = self.data_len() as i32;
        // ...so the new length must fit in an `i32`.
        let new_len = i32::try_from(new_len).map_err(|_| ProgramError::InvalidRealloc)?;

        // Return early if length hasn't changed.
        if new_len == current_len {
            return Ok(());
        }

        let difference = new_len - current_len;
        let accumulated_resize_delta = self.resize_delta() + difference;

        // Return an error when the length increase from the original serialized data
        // length is too large and would result in an out of bounds allocation
        if accumulated_resize_delta > MAX_PERMITTED_DATA_INCREASE as i32 {
            return Err(ProgramError::InvalidRealloc);
        }

        unsafe {
            (*self.raw).data_len = new_len as u64;
            (*self.raw).resize_delta = accumulated_resize_delta;
        }

        if difference > 0 {
            unsafe {
                write_bytes(
                    self.data_ptr().add(current_len as usize),
                    0,
                    difference as usize,
                );
            }
        }

        Ok(())
    }

    /// Zero out the the account's data length, lamports and owner fields, effectively
    /// closing the account.
    ///
    /// Note: This does not zero the account data. The account data will be zeroed by
    /// the runtime at the end of the instruction where the account was closed or at the
    /// next CPI call.
    ///
    /// # Important
    ///
    /// The lamports must be moved from the account prior to closing it to prevent
    /// an unbalanced instruction error. Any existing reference to the account owner
    /// will be invalidated after calling this method.
    #[inline]
    pub fn close(&self) -> ProgramResult {
        // Make sure the account is not borrowed since we are about to
        // resize the data to zero.
        if self.is_borrowed() {
            return Err(ProgramError::AccountBorrowFailed);
        }

        // SAFETY: The are no active borrows on the account data or lamports.
        unsafe {
            // Update the resize delta since closing an account will set its data length
            // to zero (account length is always `< i32::MAX`).
            (*self.raw).resize_delta = self.resize_delta() - self.data_len() as i32;

            self.close_unchecked();
        }

        Ok(())
    }

    /// Zero out the the account's data length, lamports and owner fields, effectively
    /// closing the account.
    ///
    /// Note: This does not zero the account data. The account data will be zeroed by
    /// the runtime at the end of the instruction where the account was closed or at the
    /// next CPI call.
    ///
    /// # Important
    ///
    /// The lamports must be moved from the account prior to closing it to prevent
    /// an unbalanced instruction error.
    ///
    /// If [`Self::resize`] is called after closing the account, it might incorrectly
    /// return an error for going over the limit if the account previously had space
    /// allocated since this method does not update the [`Self::resize_delta`] value.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not check if the account data is already
    /// borrowed. It should only be called when the account is not being used.
    ///
    /// It also makes assumptions about the layout and location of memory
    /// referenced by `RuntimeAccount` fields. It should only be called for
    /// instances of `AccountView` that were created by the runtime and received
    /// in the `process_instruction` entrypoint of a program.
    #[inline(always)]
    pub unsafe fn close_unchecked(&self) {
        // We take advantage that the 48 bytes before the account data are:
        // - 32 bytes for the owner
        // - 8 bytes for the lamports
        // - 8 bytes for the data_len
        //
        // So we can zero out them directly.
        write_bytes(self.data_ptr().sub(48), 0, 48);
    }

    /// Returns the raw pointer to the `Account` struct.
    pub const fn account_ptr(&self) -> *const RuntimeAccount {
        self.raw
    }

    /// Returns the memory address of the account data.
    ///
    /// # Important
    ///
    /// Obtaining the raw pointer itself is safe, but de-referencing it requires
    /// the caller to uphold Rust's aliasing rules. It is undefined behavior to
    /// de-reference the pointer or write through it while any safe reference
    /// (e.g., from any of `borrow` or `borrow_mut` methods) to the same data
    /// is still alive.
    #[inline(always)]
    pub fn data_ptr(&self) -> *mut u8 {
        // SAFETY: The `raw` pointer is guaranteed to be valid.
        unsafe { (self.raw as *mut u8).add(size_of::<RuntimeAccount>()) }
    }
}

/// Reference to account data with checked borrow rules.
#[derive(Debug)]
pub struct Ref<'a, T: ?Sized> {
    value: NonNull<T>,
    state: NonNull<u8>,
    /// The `value` raw pointer is only valid while the `&'a T` lives so we claim
    /// to hold a reference to it.
    marker: PhantomData<&'a T>,
}

impl<'a, T: ?Sized> Ref<'a, T> {
    /// Maps a reference to a new type.
    #[inline]
    pub fn map<U: ?Sized, F>(orig: Ref<'a, T>, f: F) -> Ref<'a, U>
    where
        F: FnOnce(&T) -> &U,
    {
        // Avoid decrementing the borrow flag on drop.
        let orig = ManuallyDrop::new(orig);
        Ref {
            value: NonNull::from(f(&*orig)),
            state: orig.state,
            marker: PhantomData,
        }
    }

    /// Tries to makes a new `Ref` for a component of the borrowed data.
    ///
    /// On failure, the original guard is returned alongside with the error
    /// returned by the closure.
    #[inline]
    pub fn try_map<U: ?Sized, E>(
        orig: Ref<'a, T>,
        f: impl FnOnce(&T) -> Result<&U, E>,
    ) -> Result<Ref<'a, U>, (Self, E)> {
        // Avoid decrementing the borrow flag on Drop.
        let orig = ManuallyDrop::new(orig);
        match f(&*orig) {
            Ok(value) => Ok(Ref {
                value: NonNull::from(value),
                state: orig.state,
                marker: PhantomData,
            }),
            Err(e) => Err((ManuallyDrop::into_inner(orig), e)),
        }
    }

    /// Filters and maps a reference to a new type.
    ///
    /// On failure, the original guard is returned.
    #[inline]
    pub fn filter_map<U: ?Sized, F>(orig: Ref<'a, T>, f: F) -> Result<Ref<'a, U>, Self>
    where
        F: FnOnce(&T) -> Option<&U>,
    {
        // Avoid decrementing the borrow flag on drop.
        let orig = ManuallyDrop::new(orig);

        match f(&*orig) {
            Some(value) => Ok(Ref {
                value: NonNull::from(value),
                state: orig.state,
                marker: PhantomData,
            }),
            None => Err(ManuallyDrop::into_inner(orig)),
        }
    }
}

impl<T: ?Sized> Deref for Ref<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        // Increment the available borrow count.
        unsafe { *self.state.as_mut() += 1 };
    }
}

/// Mutable reference to account data with checked borrow rules.
#[derive(Debug)]
pub struct RefMut<'a, T: ?Sized> {
    value: NonNull<T>,
    state: NonNull<u8>,
    /// The `value` raw pointer is only valid while the `&'a T` lives so we claim
    /// to hold a reference to it.
    marker: PhantomData<&'a mut T>,
}

impl<'a, T: ?Sized> RefMut<'a, T> {
    /// Maps a mutable reference to a new type.
    #[inline]
    pub fn map<U: ?Sized, F>(orig: RefMut<'a, T>, f: F) -> RefMut<'a, U>
    where
        F: FnOnce(&mut T) -> &mut U,
    {
        // Avoid decrementing the borrow flag on Drop.
        let mut orig = ManuallyDrop::new(orig);
        RefMut {
            value: NonNull::from(f(&mut *orig)),
            state: orig.state,
            marker: PhantomData,
        }
    }

    /// Tries to makes a new `RefMut` for a component of the borrowed data.
    ///
    /// On failure, the original guard is returned alongside with the error
    /// returned by the closure.
    #[inline]
    pub fn try_map<U: ?Sized, E>(
        orig: RefMut<'a, T>,
        f: impl FnOnce(&mut T) -> Result<&mut U, E>,
    ) -> Result<RefMut<'a, U>, (Self, E)> {
        // Avoid decrementing the borrow flag on Drop.
        let mut orig = ManuallyDrop::new(orig);
        match f(&mut *orig) {
            Ok(value) => Ok(RefMut {
                value: NonNull::from(value),
                state: orig.state,
                marker: PhantomData,
            }),
            Err(e) => Err((ManuallyDrop::into_inner(orig), e)),
        }
    }

    /// Filters and maps a mutable reference to a new type.
    ///
    /// On failure, the original guard is returned alongside with the error
    /// returned by the closure.
    #[inline]
    pub fn filter_map<U: ?Sized, F>(orig: RefMut<'a, T>, f: F) -> Result<RefMut<'a, U>, Self>
    where
        F: FnOnce(&mut T) -> Option<&mut U>,
    {
        // Avoid decrementing the mutable borrow flag on Drop.
        let mut orig = ManuallyDrop::new(orig);
        match f(&mut *orig) {
            Some(value) => Ok(RefMut {
                value: NonNull::from(value),
                state: orig.state,
                marker: PhantomData,
            }),
            None => Err(ManuallyDrop::into_inner(orig)),
        }
    }
}

impl<T: ?Sized> Deref for RefMut<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { self.value.as_ref() }
    }
}
impl<T: ?Sized> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut <Self as core::ops::Deref>::Target {
        unsafe { self.value.as_mut() }
    }
}

impl<T: ?Sized> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        // Reset the borrow state.
        unsafe { *self.state.as_mut() = NOT_BORROWED };
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        core::mem::{size_of, MaybeUninit},
    };

    #[test]
    fn test_ref() {
        let data: [u8; 4] = [0, 1, 2, 3];
        let mut state = NOT_BORROWED - 1;

        let ref_data = Ref {
            value: NonNull::from(&data),
            // borrow state must be a mutable reference
            state: NonNull::from(&mut state),
            marker: PhantomData,
        };

        let new_ref = Ref::map(ref_data, |data| &data[1]);

        assert_eq!(state, NOT_BORROWED - 1);
        assert_eq!(*new_ref, 1);

        let Ok(new_ref) = Ref::filter_map(new_ref, |_| Some(&3)) else {
            unreachable!()
        };

        assert_eq!(state, NOT_BORROWED - 1);
        assert_eq!(*new_ref, 3);

        let Ok(new_ref) = Ref::try_map::<_, u8>(new_ref, |_| Ok(&4)) else {
            unreachable!()
        };

        assert_eq!(state, NOT_BORROWED - 1);
        assert_eq!(*new_ref, 4);

        let (new_ref, err) = Ref::try_map::<u8, u8>(new_ref, |_| Err(5)).unwrap_err();
        assert_eq!(state, NOT_BORROWED - 1);
        assert_eq!(err, 5);
        // Unchanged
        assert_eq!(*new_ref, 4);

        let new_ref = Ref::filter_map(new_ref, |_| Option::<&u8>::None);

        assert_eq!(state, NOT_BORROWED - 1);
        assert!(new_ref.is_err());

        drop(new_ref);

        assert_eq!(state, NOT_BORROWED);
    }

    #[test]
    fn test_ref_mut() {
        let mut data: [u8; 4] = [0, 1, 2, 3];
        let mut state = 0;

        let ref_data = RefMut {
            value: NonNull::from(&mut data),
            // borrow state must be a mutable reference
            state: NonNull::from(&mut state),
            marker: PhantomData,
        };

        let Ok(mut new_ref) = RefMut::filter_map(ref_data, |data| data.get_mut(0)) else {
            unreachable!()
        };

        *new_ref = 4;

        assert_eq!(state, 0);
        assert_eq!(*new_ref, 4);

        drop(new_ref);

        assert_eq!(data, [4, 1, 2, 3]);
        assert_eq!(state, NOT_BORROWED);
    }

    #[test]
    fn test_borrow() {
        // 8-bytes aligned account data + 8 bytes of trailing data.
        let mut data = [0u64; size_of::<RuntimeAccount>() / size_of::<u64>() + 1];
        data[0] = NOT_BORROWED as u64;

        let account = data.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*account).data_len = 8 };

        let account_view = AccountView { raw: account };

        // Check that we can borrow data and lamports.
        assert!(account_view.check_borrow().is_ok());
        assert!(account_view.check_borrow_mut().is_ok());

        // It should be sound to mutate the data through the data pointer
        // while no other borrows exist.
        let data_ptr = account_view.data_ptr();
        unsafe {
            // There are 8 bytes of trailing data.
            let data = from_raw_parts_mut(data_ptr, 8);
            data[0] = 1;
        }

        // Borrow multiple immutable data references (254 immutable borrows
        // available).
        const ACCOUNT_REF: MaybeUninit<Ref<[u8]>> = MaybeUninit::<Ref<[u8]>>::uninit();
        let mut refs = [ACCOUNT_REF; (NOT_BORROWED as usize) - 1];

        refs.iter_mut().for_each(|r| {
            let Ok(data_ref) = account_view.try_borrow() else {
                panic!("Failed to borrow data");
            };
            // Sanity check: the data pointer should see the change.
            assert!(data_ref[0] == 1);
            r.write(data_ref);
        });

        // Check that we cannot borrow the data anymore.
        assert!(account_view.check_borrow().is_err());
        assert!(account_view.try_borrow().is_err());
        assert!(account_view.check_borrow_mut().is_err());
        assert!(account_view.try_borrow_mut().is_err());

        // Drop the immutable borrows.
        refs.iter_mut().for_each(|r| {
            let r = unsafe { r.assume_init_read() };
            drop(r);
        });

        // We should be able to borrow the data again.
        assert!(account_view.check_borrow().is_ok());
        assert!(account_view.check_borrow_mut().is_ok());

        // Borrow mutable data.
        let ref_mut = account_view.try_borrow_mut().unwrap();
        // It should be sound to get the data pointer while the data is borrowed
        // as long as we don't use it.
        let _data_ptr = account_view.data_ptr();

        // Check that we cannot borrow the data anymore.
        assert!(account_view.check_borrow().is_err());
        assert!(account_view.try_borrow().is_err());
        assert!(account_view.check_borrow_mut().is_err());
        assert!(account_view.try_borrow_mut().is_err());

        drop(ref_mut);

        // We should be able to borrow the data again.
        assert!(account_view.check_borrow().is_ok());
        assert!(account_view.check_borrow_mut().is_ok());

        let borrow_state = unsafe { (*account_view.raw).borrow_state };
        assert!(borrow_state == NOT_BORROWED);
    }

    #[test]
    fn test_resize() {
        // 8-bytes aligned account data.
        let mut data = [0u64; 100 * size_of::<u64>()];

        // Set the borrow state.
        data[0] = NOT_BORROWED as u64;
        // Set the initial data length to 100.
        //   - index `10` is equal to offset `10 * size_of::<u64>() = 80` bytes.
        data[10] = 100;

        let account = AccountView {
            raw: data.as_mut_ptr() as *const _ as *mut RuntimeAccount,
        };

        assert_eq!(account.data_len(), 100);
        assert_eq!(account.resize_delta(), 0);

        // We should be able to get the data pointer whenever as long as we don't use it while the data is borrowed
        let data_ptr_before = account.data_ptr();

        // increase the size.

        account.resize(200).unwrap();

        let data_ptr_after = account.data_ptr();
        // The data pointer should point to the same address regardless of the reallocation
        assert_eq!(data_ptr_before, data_ptr_after);

        assert_eq!(account.data_len(), 200);
        assert_eq!(account.resize_delta(), 100);

        // decrease the size.

        account.resize(0).unwrap();

        assert_eq!(account.data_len(), 0);
        assert_eq!(account.resize_delta(), -100);

        // Invalid reallocation.

        let invalid_realloc = account.resize(10_000_000_001);
        assert!(invalid_realloc.is_err());

        // Reset to its original size.

        account.resize(100).unwrap();

        assert_eq!(account.data_len(), 100);
        assert_eq!(account.resize_delta(), 0);

        // Consecutive resizes.

        account.resize(200).unwrap();
        account.resize(50).unwrap();
        account.resize(500).unwrap();

        assert_eq!(account.data_len(), 500);
        assert_eq!(account.resize_delta(), 400);

        let data = account.try_borrow().unwrap();
        assert_eq!(data.len(), 500);
    }
}
