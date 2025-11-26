#![allow(unused)]

use core::{
    mem,
    ops::{Deref, DerefMut},
    ptr::addr_of_mut,
};

use symcrypt_sys::{SIZE_T, SYMCRYPT_GCM_EXPANDED_KEY, SYMCRYPT_GCM_STATE, SymCryptWipe};

pub unsafe trait SecureZeroable: Sized {
    fn zero_memory(&mut self) {
        unsafe {
            SymCryptWipe(self as *mut _ as *mut _, size_of::<Self>() as SIZE_T);
        }
    }
}

///
/// This type represents a handle to an initialized GcmStream that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
/// 3. Zero the underlying storage when dropped.
///
pub struct Initialized<'a, T: SecureZeroable>(&'a mut T);

impl<'a, T: SecureZeroable> Initialized<'a, T> {
    //
    // `new` creates a new handle to an initialized type.
    //
    // # Safety
    //
    // The caller must ensure that the underlying storage has been initialized.
    //
    #[inline(always)]
    pub unsafe fn new(inner: &'a mut T) -> Self {
        Self(inner)
    }

    #[inline(always)]
    pub fn as_ref<'b>(&'b self) -> InitializedRef<'b, T> {
        InitializedRef(self.0)
    }

    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> InitializedRefMut<'b, T> {
        InitializedRefMut(self.0)
    }

    #[inline(always)]
    pub fn drop_without_zero(self) {
        mem::forget(self);
    }

    #[inline(always)]
    pub fn get_state_ptr(&self) -> *const T {
        self.0
    }

    #[inline(always)]
    pub fn get_state_ptr_mut(&mut self) -> *mut T {
        self.0
    }
}

impl<'a, T: SecureZeroable> Drop for Initialized<'a, T> {
    fn drop(&mut self) {
        self.0.zero_memory();
    }
}

///
/// This type represents a borrowed handle to an initialized type that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
///
/// This type does not zero the underlying storage when dropped.
///
#[derive(Clone, Copy)]
pub struct InitializedRef<'a, T>(&'a T);

impl<'a, T> InitializedRef<'a, T> {
    //
    // `new` creates a new handle to an initialized type.
    //
    // # Safety
    //
    // The caller must ensure that the underlying storage has been initialized.
    //
    #[inline(always)]
    pub unsafe fn new(inner: &'a T) -> Self {
        Self(inner)
    }

    #[inline(always)]
    pub fn as_ref<'b>(&'b self) -> InitializedRef<'b, T> {
        InitializedRef(self.0)
    }

    #[inline(always)]
    pub fn get_state_ptr(&self) -> *const T {
        self.0
    }
}

///
/// This type represents a borrowed mutable handle to an initialized type that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
///
/// This type does not zero the underlying storage when dropped.
///
pub struct InitializedRefMut<'a, T>(&'a mut T);

impl<'a, T> InitializedRefMut<'a, T> {
    #[inline(always)]
    pub fn as_ref<'b>(&'b self) -> InitializedRef<'b, T> {
        InitializedRef(self.0)
    }

    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> InitializedRefMut<'b, T> {
        InitializedRefMut(self.0)
    }

    #[inline(always)]
    pub fn get_state_ptr(&self) -> *const T {
        self.0
    }

    #[inline(always)]
    pub fn get_state_ptr_mut(&mut self) -> *mut T {
        self.0
    }
}
