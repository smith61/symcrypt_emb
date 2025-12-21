use core::ptr;
use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
};

use paste::paste;

use crate::{
    SymCryptError, Zeroable,
    ptr::{OwningPointer, SharedPointer, UniquePointer},
    symcrypt_init, symcrypt_wipe,
};

pub trait HmacAlgorithm {
    type ExpandedKey: Zeroable + Default;
    type StreamState: Zeroable + Default;
    type Result;

    unsafe fn expand_key(
        expanded_key: *mut Self::ExpandedKey,
        key_data: &[u8],
    ) -> Result<(), SymCryptError>;

    unsafe fn hmac(expanded_key: *const Self::ExpandedKey, data: &[u8], result: &mut Self::Result);

    unsafe fn stream_init(
        stream_state: *mut Self::StreamState,
        expanded_key: *const Self::ExpandedKey,
    );
    unsafe fn stream_append(stream_state: *mut Self::StreamState, data: &[u8]);
    unsafe fn stream_result(stream_state: *mut Self::StreamState, result: &mut Self::Result);
}

///
/// This type represents an uninitialized key.
///
#[derive(Default)]
pub struct HmacUninitializedKey<T: HmacAlgorithm>(T::ExpandedKey);

///
/// This type represents a handle to an initialized key.
///
pub struct HmacExpandedKey<T: HmacAlgorithm, P: OwningPointer<Target = HmacUninitializedKey<T>>>(P);

impl<T: HmacAlgorithm, P: OwningPointer<Target = HmacUninitializedKey<T>>> Drop
    for HmacExpandedKey<T, P>
{
    fn drop(&mut self) {
        if let Some(initialized_key) = self.0.try_get_mut() {
            symcrypt_wipe(&mut initialized_key.0);
        }
    }
}

impl<T: HmacAlgorithm, P: SharedPointer<Target = HmacUninitializedKey<T>>> Clone
    for HmacExpandedKey<T, P>
{
    fn clone(&self) -> Self {
        Self(Clone::clone(&self.0))
    }
}

impl<T: HmacAlgorithm, P: OwningPointer<Target = HmacUninitializedKey<T>>> HmacExpandedKey<T, P> {
    //
    // SAFETY: The caller must ensure that the pointed to key is initialized.
    //
    #[inline(always)]
    unsafe fn new(initialized_key: P) -> Self {
        Self(initialized_key)
    }

    #[inline(always)]
    fn get_key_ptr(&self) -> *const T::ExpandedKey {
        ptr::addr_of!(self.0.0)
    }

    ///
    /// `expand_key` initialized the pointed to key using the provided key data.
    ///
    /// `uninitialized_key` is a pointer to an uninitialized hmac key to initialize.
    ///
    /// `key_data` is a &[u8] the contains key information.
    ///
    pub fn expand_key(mut uninitialized_key: P, key_data: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        unsafe {
            T::expand_key(
                ptr::addr_of_mut!(uninitialized_key.try_get_mut().unwrap().0),
                key_data,
            )?;

            Ok(Self::new(uninitialized_key))
        }
    }

    ///
    /// `as_ref` returns a non-mutable reference to the underlying initialized key.
    ///
    pub fn as_ref<'b>(&'b self) -> HmacExpandedKey<T, &'b HmacUninitializedKey<T>> {
        //
        // SAFETY: The contained key is guaranteed to be initialized by the caller
        // to `HmacExpandedKey::new`
        //
        unsafe { HmacExpandedKey::new(self.0.deref()) }
    }

    ///
    /// `hmac` computes the MAC value for the provided data using the contained key.
    ///
    /// `data` supplies a &[u8] to calculate the MAC value of.
    ///
    /// `result` supplies a mutable reference in which to write the calculated MAC.
    ///
    pub fn hmac(&self, data: &[u8], result: &mut T::Result) {
        unsafe {
            T::hmac(self.get_key_ptr(), data, result);
        }
    }
}

///
/// This type represents an uninitialized HMAC stream.
///
pub struct HmacUninitializedStream<
    T: HmacAlgorithm,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
> {
    stream_state: T::StreamState,
    key_pointer: MaybeUninit<HmacExpandedKey<T, KP>>,
}

impl<T: HmacAlgorithm, KP: OwningPointer<Target = HmacUninitializedKey<T>>> Default
    for HmacUninitializedStream<T, KP>
{
    fn default() -> Self {
        Self {
            stream_state: Default::default(),
            key_pointer: MaybeUninit::uninit(),
        }
    }
}

//
// This type represents a handle to an initialized HMAC stream.
//
struct HmacInitializedStream<
    T: HmacAlgorithm,
    P: UniquePointer<Target = HmacUninitializedStream<T, KP>>,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
>(P, PhantomData<KP>);

impl<
    T: HmacAlgorithm,
    P: UniquePointer<Target = HmacUninitializedStream<T, KP>>,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
> Drop for HmacInitializedStream<T, P, KP>
{
    fn drop(&mut self) {
        //
        // SAFETY: The key_pointer is initialized in `HmacInitializedStream::initialize`
        //
        unsafe { self.0.key_pointer.assume_init_drop() }
        symcrypt_wipe(&mut self.0.stream_state);
    }
}

impl<
    T: HmacAlgorithm,
    P: UniquePointer<Target = HmacUninitializedStream<T, KP>>,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
> HmacInitializedStream<T, P, KP>
{
    fn initialize(mut uninitialized_stream: P, expanded_key: HmacExpandedKey<T, KP>) -> Self {
        unsafe {
            T::stream_init(
                ptr::addr_of_mut!(uninitialized_stream.stream_state),
                expanded_key.get_key_ptr(),
            );
        }

        uninitialized_stream.key_pointer.write(expanded_key);
        Self(uninitialized_stream, PhantomData)
    }

    fn drop_without_zero(mut self) {
        unsafe { self.0.key_pointer.assume_init_drop() }
        mem::forget(self);
    }

    fn as_ref_mut<'a>(&'a mut self) -> HmacInitializedStreamRefMut<'a, T> {
        HmacInitializedStreamRefMut(&mut self.0.stream_state)
    }

    fn get_state_ptr_mut(&mut self) -> *mut T::StreamState {
        ptr::addr_of_mut!(self.0.stream_state)
    }
}

//
// This type represents a mutable reference to an initialized HMAC stream.
//
struct HmacInitializedStreamRefMut<'a, T: HmacAlgorithm>(&'a mut T::StreamState);

impl<T: HmacAlgorithm> HmacInitializedStreamRefMut<'_, T> {
    fn as_ref_mut<'a>(&'a mut self) -> HmacInitializedStreamRefMut<'a, T> {
        HmacInitializedStreamRefMut(self.0)
    }

    fn get_state_ptr_mut(&mut self) -> *mut T::StreamState {
        self.0 as *mut _
    }
}

///
/// This type represents an initialized HMAC stream.
///
pub struct HmacStream<
    T: HmacAlgorithm,
    P: UniquePointer<Target = HmacUninitializedStream<T, KP>>,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
>(HmacInitializedStream<T, P, KP>);

impl<
    T: HmacAlgorithm,
    P: UniquePointer<Target = HmacUninitializedStream<T, KP>>,
    KP: OwningPointer<Target = HmacUninitializedKey<T>>,
> HmacStream<T, P, KP>
{
    ///
    /// `new` initialized a new HMAC stream at the provided location using the provided
    /// HMAC expanded key.
    ///
    /// `uninitialized_stream` is a pointer to an uninitialized HMAC stream to initialize.
    ///
    /// `expanded_key` is a handle to an initialized HMAC key to use for calculating the MAC.
    ///
    pub fn new(uninitialized_stream: P, expanded_key: HmacExpandedKey<T, KP>) -> Self {
        Self(HmacInitializedStream::initialize(
            uninitialized_stream,
            expanded_key,
        ))
    }

    ///
    /// `as_ref_mut` gets a mutable reference to the initialized HMAC stream.
    ///
    pub fn as_ref_mut<'a>(&'a mut self) -> HmacStreamRefMut<'a, T> {
        HmacStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `append` appends the provided data to the HMAC stream.
    ///
    pub fn append(&mut self, data: &[u8]) {
        self.as_ref_mut().append(data);
    }

    ///
    /// `result` finalizes the HMAC stream and calculates the resulting MAC.
    ///
    pub fn result(mut self, result: &mut T::Result) {
        //
        // SAFETY: The underlying HMAC stream is guaranteed to be initialized by the
        // caller of `HmacInitializedStream::initialize`.
        //
        unsafe {
            T::stream_result(self.0.get_state_ptr_mut(), result);
        }

        self.0.drop_without_zero();
    }
}

///
/// This type represents a mutable reference to an initialized HMAC stream.
///
pub struct HmacStreamRefMut<'a, T: HmacAlgorithm>(HmacInitializedStreamRefMut<'a, T>);

impl<T: HmacAlgorithm> HmacStreamRefMut<'_, T> {
    ///
    /// `as_ref_mut` gets a mutable reference to the initialized HMAC stream.
    ///
    pub fn as_ref_mut<'a>(&'a mut self) -> HmacStreamRefMut<'a, T> {
        HmacStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `append` appends the provided data to the HMAC stream.
    ///
    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            T::stream_append(self.0.get_state_ptr_mut(), data);
        }
    }
}

macro_rules! define_mac_algorithm {
    ($lc: ident, $uc: ident) => {
        paste! {

            #[derive(Clone, Copy, Default)]
            pub struct [<$lc HmacAlgorithm>];

            pub type [<$lc HmacUninitializedKey>] = HmacUninitializedKey<[<$lc HmacAlgorithm>]>;
            pub type [<$lc HmacExpandedKey>]<P> = HmacExpandedKey<[<$lc HmacAlgorithm>], P>;
            pub type [<$lc HmacUninitializedStream>]<KP> = HmacUninitializedStream<[<$lc HmacAlgorithm>], KP>;
            pub type [<$lc HmacStream>]<P, KP> = HmacStream<[<$lc HmacAlgorithm>], P, KP>;
            pub type [<$lc HmacStreamRefMut>]<'a> = HmacStreamRefMut<'a, [<$lc HmacAlgorithm>]>;
            pub type [<$lc HmacResult>] = [u8; symcrypt_sys::[<SYMCRYPT_ $uc _RESULT_SIZE>] as usize];

            //
            // SAFETY: C FFI structs are always safe to zero
            //
            unsafe impl Zeroable for symcrypt_sys::[<SYMCRYPT_HMAC_ $uc _EXPANDED_KEY>] {}
            unsafe impl Zeroable for symcrypt_sys::[<SYMCRYPT_HMAC_ $uc _STATE>] {}

            //
            // SAFETY: The uninitialized structure wrappers are safe to be sent
            // across threads since they contain no state. Only when initialized
            // behind some pointer will they contain state and Send/Sync properties
            // are needed for those handles.
            //
            unsafe impl Send for HmacUninitializedKey<[<$lc HmacAlgorithm>]> { }
            unsafe impl Sync for HmacUninitializedKey<[<$lc HmacAlgorithm>]> { }
            unsafe impl<KP: OwningPointer<Target = [<$lc HmacUninitializedKey>]>> Send for HmacUninitializedStream<[<$lc HmacAlgorithm>], KP> { }
            unsafe impl<KP: OwningPointer<Target = [<$lc HmacUninitializedKey>]>> Sync for HmacUninitializedStream<[<$lc HmacAlgorithm>], KP> { }

            //
            // SAFETY: A mutable reference to an initialized SYMCRYPT_HMAC_*_STATE is
            // safe to be shared/sent with other threads.
            //
            unsafe impl Send for HmacInitializedStreamRefMut<'_, [<$lc HmacAlgorithm>]> { }
            unsafe impl Sync for HmacInitializedStreamRefMut<'_, [<$lc HmacAlgorithm>]> { }

            impl HmacAlgorithm for [<$lc HmacAlgorithm>] {
                type ExpandedKey = symcrypt_sys::[<SYMCRYPT_HMAC_ $uc _EXPANDED_KEY>];
                type StreamState = symcrypt_sys::[<SYMCRYPT_HMAC_ $uc _STATE>];
                type Result = [<$lc HmacResult>];

                unsafe fn expand_key(
                    expanded_key: *mut Self::ExpandedKey,
                    key_data: &[u8],
                ) -> Result<(), SymCryptError> {
                    unsafe {
                        let result = symcrypt_sys::[<SymCryptHmac $lc ExpandKey>](
                            expanded_key,
                            key_data.as_ptr(),
                            key_data.len() as symcrypt_sys::SIZE_T
                        );

                        match result {
                            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                            error => Err(error.into()),
                        }
                    }
                }

                unsafe fn hmac(expanded_key: *const Self::ExpandedKey, data: &[u8], result: &mut Self::Result) {
                    unsafe {
                        symcrypt_sys::[<SymCryptHmac $lc>](
                            expanded_key,
                            data.as_ptr(),
                            data.len() as symcrypt_sys::SIZE_T,
                            result.as_mut_ptr()
                        );
                    }
                }

                unsafe fn stream_init(stream_state: *mut Self::StreamState, expanded_key: *const Self::ExpandedKey) {
                    unsafe {
                        symcrypt_sys::[<SymCryptHmac $lc Init>](
                            stream_state,
                            expanded_key
                        );
                    }
                }

                unsafe fn stream_append(stream_state: *mut Self::StreamState, data: &[u8]) {
                    unsafe {
                        symcrypt_sys::[<SymCryptHmac $lc Append>](
                            stream_state,
                            data.as_ptr(),
                            data.len() as symcrypt_sys::SIZE_T
                        );
                    }
                }

                unsafe fn stream_result(stream_state: *mut Self::StreamState, result: &mut Self::Result) {
                    unsafe {
                        symcrypt_sys::[<SymCryptHmac $lc Result>](
                            stream_state,
                            result.as_mut_ptr()
                        );
                    }
                }
            }
        }
    };
}

define_mac_algorithm!(Md5, MD5);
define_mac_algorithm!(Sha1, SHA1);
define_mac_algorithm!(Sha256, SHA256);
define_mac_algorithm!(Sha384, SHA384);
define_mac_algorithm!(Sha512, SHA512);
