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
    type ExpandedKey: Zeroable;
    type StreamState: Zeroable;
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
pub struct HmacUninitializedKey<T: HmacAlgorithm>(T::ExpandedKey);

impl<T: HmacAlgorithm> Default for HmacUninitializedKey<T>
where
    T::ExpandedKey: Default,
{
    fn default() -> Self {
        Self(T::ExpandedKey::default())
    }
}

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
where
    T::StreamState: Default,
{
    fn default() -> Self {
        Self {
            stream_state: T::StreamState::default(),
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

            pub struct [<$lc HmacAlgorithm>];

            pub type [<$lc HmacResult>] = [u8; symcrypt_sys::[<SYMCRYPT_ $uc _RESULT_SIZE>] as usize];
            pub type [<$lc HmacUninitializedKey>] = HmacUninitializedKey<[<$lc HmacAlgorithm>]>;
            pub type [<$lc HmacExpandedKey>]<P> = HmacExpandedKey<[<$lc HmacAlgorithm>], P>;
            pub type [<$lc HmacUninitializedStream>]<KP> = HmacUninitializedStream<[<$lc HmacAlgorithm>], KP>;
            pub type [<$lc HmacStream>]<P, KP> = HmacStream<[<$lc HmacAlgorithm>], P, KP>;
            pub type [<$lc HmacStreamRefMut>]<'a> = HmacStreamRefMut<'a, [<$lc HmacAlgorithm>]>;

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

#[cfg(test)]
mod test {
    use crate::{
        SymCryptError,
        hmac::{
            Md5HmacExpandedKey, Md5HmacStream, Md5HmacUninitializedKey, Md5HmacUninitializedStream,
            Sha1HmacExpandedKey, Sha1HmacStream, Sha1HmacUninitializedKey,
            Sha1HmacUninitializedStream, Sha256HmacExpandedKey, Sha256HmacStream,
            Sha256HmacUninitializedKey, Sha256HmacUninitializedStream, Sha384HmacExpandedKey,
            Sha384HmacStream, Sha384HmacUninitializedKey, Sha384HmacUninitializedStream,
            Sha512HmacExpandedKey, Sha512HmacStream, Sha512HmacUninitializedKey,
            Sha512HmacUninitializedStream,
        },
    };

    static KEY: &'static str = "feffe9928665731c6d6a8f9467308308";
    static LOREM_IPSUM: &'static str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed dapibus consequat nisi nec dictum. Duis a tempor diam. Suspendisse a justo neque. Nullam laoreet bibendum lectus. Morbi at dapibus odio. Phasellus gravida lacus non tortor cursus, quis aliquam turpis mollis. Ut et dui tristique, blandit erat in, aliquam mauris.";

    #[test]
    fn test_md5() -> Result<(), SymCryptError> {
        let expected_result = "7053FBF41DB128711D63E38305DCBAA6";
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut key = Md5HmacUninitializedKey::default();
        let key = Md5HmacExpandedKey::expand_key(&mut key, &hex::decode(&KEY).unwrap())?;

        let mut result = [0; _];
        key.hmac(as_bytes, &mut result);
        assert_eq!(hex::encode_upper(&result), expected_result);

        let mut stream_storage = Md5HmacUninitializedStream::default();
        for chunk_size in 1..as_bytes.len() {
            let mut stream = Md5HmacStream::new(&mut stream_storage, key.as_ref());
            for chunk in as_bytes.chunks(chunk_size) {
                stream.append(chunk);
            }

            stream.result(&mut result);
            assert_eq!(hex::encode_upper(&result), expected_result);
        }

        Ok(())
    }

    #[test]
    fn test_sha1() -> Result<(), SymCryptError> {
        let expected_result = "AEF07DAA7F4955C2A0FB26F66CE481A20EC3627C";
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut key = Sha1HmacUninitializedKey::default();
        let key = Sha1HmacExpandedKey::expand_key(&mut key, &hex::decode(&KEY).unwrap())?;

        let mut result = [0; _];
        key.hmac(as_bytes, &mut result);
        assert_eq!(hex::encode_upper(&result), expected_result);

        let mut stream_storage = Sha1HmacUninitializedStream::default();
        for chunk_size in 1..as_bytes.len() {
            let mut stream = Sha1HmacStream::new(&mut stream_storage, key.as_ref());
            for chunk in as_bytes.chunks(chunk_size) {
                stream.append(chunk);
            }

            stream.result(&mut result);
            assert_eq!(hex::encode_upper(&result), expected_result);
        }

        Ok(())
    }

    #[test]
    fn test_sha256() -> Result<(), SymCryptError> {
        let expected_result = "9A3ADF1664696458D66495C6756CFB5A532DB519259E1938132163B1471507F5";
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut key = Sha256HmacUninitializedKey::default();
        let key = Sha256HmacExpandedKey::expand_key(&mut key, &hex::decode(&KEY).unwrap())?;

        let mut result = [0; _];
        key.hmac(as_bytes, &mut result);
        assert_eq!(hex::encode_upper(&result), expected_result);

        let mut stream_storage = Sha256HmacUninitializedStream::default();
        for chunk_size in 1..as_bytes.len() {
            let mut stream = Sha256HmacStream::new(&mut stream_storage, key.as_ref());
            for chunk in as_bytes.chunks(chunk_size) {
                stream.append(chunk);
            }

            stream.result(&mut result);
            assert_eq!(hex::encode_upper(&result), expected_result);
        }

        Ok(())
    }

    #[test]
    fn test_sha384() -> Result<(), SymCryptError> {
        let expected_result = "DD9862B33D71119C9FD878ED5FE2ACC559CB361C7E2DAC42B0D78071946EA3B50727EC426833E0E28DC916A6B6ADBEE0";
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut key = Sha384HmacUninitializedKey::default();
        let key = Sha384HmacExpandedKey::expand_key(&mut key, &hex::decode(&KEY).unwrap())?;

        let mut result = [0; _];
        key.hmac(as_bytes, &mut result);
        assert_eq!(hex::encode_upper(&result), expected_result);

        let mut stream_storage = Sha384HmacUninitializedStream::default();
        for chunk_size in 1..as_bytes.len() {
            let mut stream = Sha384HmacStream::new(&mut stream_storage, key.as_ref());
            for chunk in as_bytes.chunks(chunk_size) {
                stream.append(chunk);
            }

            stream.result(&mut result);
            assert_eq!(hex::encode_upper(&result), expected_result);
        }

        Ok(())
    }

    #[test]
    fn test_sha512() -> Result<(), SymCryptError> {
        let expected_result = "A89B0CCD2D386D41D029173E8766FA1749BE3C14F7AAC3CCB78882F60719AF93CB322856474EB8ECE5AB3CAB1329DDA657ECBA741E1EC032A8FC2FCAA0A3614C";
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut key = Sha512HmacUninitializedKey::default();
        let key = Sha512HmacExpandedKey::expand_key(&mut key, &hex::decode(&KEY).unwrap())?;

        let mut result = [0; _];
        key.hmac(as_bytes, &mut result);
        assert_eq!(hex::encode_upper(&result), expected_result);

        let mut stream_storage = Sha512HmacUninitializedStream::default();
        for chunk_size in 1..as_bytes.len() {
            let mut stream = Sha512HmacStream::new(&mut stream_storage, key.as_ref());
            for chunk in as_bytes.chunks(chunk_size) {
                stream.append(chunk);
            }

            stream.result(&mut result);
            assert_eq!(hex::encode_upper(&result), expected_result);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod std_test {
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::{rc::Rc, sync::Arc};

    use crate::hmac::{
        HmacInitializedStream, HmacInitializedStreamRefMut, Md5HmacAlgorithm, Md5HmacExpandedKey,
    };

    #[test]
    fn test_auto_traits() {
        assert_impl_all!(Md5HmacExpandedKey<&'static _>: Send, Sync);
        assert_impl_all!(Md5HmacExpandedKey<&'static mut _>: Send, Sync);
        assert_impl_all!(Md5HmacExpandedKey<Box<_>>: Send, Sync);
        assert_not_impl_any!(Md5HmacExpandedKey<Rc<_>>: Send, Sync);
        assert_impl_all!(Md5HmacExpandedKey<Arc<_>>: Send, Sync);

        assert_impl_all!(HmacInitializedStream<Md5HmacAlgorithm, &'static mut _, &'static _>: Send, Sync);
        assert_not_impl_any!(HmacInitializedStream<Md5HmacAlgorithm, &'static mut _, Rc<_>>: Send, Sync);
        assert_impl_all!(HmacInitializedStream<Md5HmacAlgorithm, Box<_>, &'static _>: Send, Sync);
        assert_not_impl_any!(HmacInitializedStream<Md5HmacAlgorithm, Box<_>, Rc<_>>: Send, Sync);

        assert_impl_all!(HmacInitializedStreamRefMut<'static, Md5HmacAlgorithm>: Send, Sync);
    }
}
