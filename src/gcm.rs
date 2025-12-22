use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ptr,
};

use symcrypt_sys::{
    SIZE_T, SYMCRYPT_BLOCKCIPHER, SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR, SYMCRYPT_GCM_EXPANDED_KEY,
    SYMCRYPT_GCM_STATE, SymCryptGcmAuthPart, SymCryptGcmDecrypt, SymCryptGcmDecryptFinal,
    SymCryptGcmDecryptPart, SymCryptGcmEncrypt, SymCryptGcmEncryptFinal, SymCryptGcmEncryptPart,
    SymCryptGcmExpandKey, SymCryptGcmInit,
};

use crate::{
    SymCryptError, Zeroable,
    ptr::{OwningPointer, SharedPointer, UniquePointer},
    symcrypt_init, symcrypt_wipe,
};

///
/// `BlockCipherType` is an enum that enumerates all possible block ciphers that are supported.
/// Currently the only supported type is `AesBlock`.
///
#[derive(Clone, Copy, Debug)]
pub enum BlockCipherType {
    AesBlock,
}

impl Into<*const SYMCRYPT_BLOCKCIPHER> for BlockCipherType {
    fn into(self) -> *const SYMCRYPT_BLOCKCIPHER {
        //
        // SAFETY: Accessing a static AES block cipher is safe.
        //
        match self {
            BlockCipherType::AesBlock => unsafe { symcrypt_sys::SymCryptAesBlockCipher },
        }
    }
}

///
/// `GcmUninitializedKey` represents an uninitialized SYMCRYPT_GCM_EXPANDED_KEY.
///
#[repr(transparent)]
#[derive(Default)]
pub struct GcmUninitializedKey(SYMCRYPT_GCM_EXPANDED_KEY);

//
// SAFETY: An uninitialized key is allowed to be sent/shared between
// threads as it contains no state.
//

unsafe impl Send for GcmUninitializedKey {}
unsafe impl Sync for GcmUninitializedKey {}

///
/// `GcmExpandedKey` represents a pointer to an initialized SYMCRYPT_GCM_EXPANDED_KEY.
///
pub struct GcmExpandedKey<P: OwningPointer<Target = GcmUninitializedKey>>(P);

impl<P: OwningPointer<Target = GcmUninitializedKey>> Drop for GcmExpandedKey<P> {
    fn drop(&mut self) {
        if let Some(initialized_key) = self.0.try_get_mut() {
            symcrypt_wipe(&mut initialized_key.0);
        }
    }
}

impl<P: SharedPointer<Target = GcmUninitializedKey>> Clone for GcmExpandedKey<P> {
    fn clone(&self) -> Self {
        Self(Clone::clone(&self.0))
    }
}

impl<P: OwningPointer<Target = GcmUninitializedKey>> GcmExpandedKey<P> {
    //
    // SAFETY: The caller must ensure that the pointed to key is initialized.
    //
    #[inline(always)]
    unsafe fn new(initialized_key: P) -> Self {
        Self(initialized_key)
    }

    #[inline(always)]
    fn get_key_ptr(&self) -> *const SYMCRYPT_GCM_EXPANDED_KEY {
        ptr::addr_of!(self.0.0)
    }

    #[inline(always)]
    pub fn expand_key(
        mut uninitialized_key: P,
        cipher_type: BlockCipherType,
        key_data: &[u8],
    ) -> Result<Self, SymCryptError> {
        symcrypt_init();

        //
        // SAFETY: FFI call to initialize the SYMCRYPT_GCM_EXPANDED_KEY. The contract for
        // OwningPointer guarantees that the underlying storage won't be moved.
        //
        unsafe {
            let result = SymCryptGcmExpandKey(
                ptr::addr_of_mut!(uninitialized_key.try_get_mut().unwrap().0),
                cipher_type.into(),
                key_data.as_ptr(),
                key_data.len() as SIZE_T,
            );

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(Self::new(uninitialized_key)),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `as_ref` returns a `GcmExpandedKey` that provides a borrowed reference to the underlying key.
    ///
    #[inline(always)]
    pub fn as_ref<'b>(&'b self) -> GcmExpandedKey<&'b GcmUninitializedKey> {
        //
        // SAFETY: The underlying key is guaranteed to be initialized by the caller
        // to `GcmExpandedKey::new`.
        //
        unsafe { GcmExpandedKey::new(self.0.deref()) }
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    #[inline(always)]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        assert_eq!(source.len(), destination.len());
        assert!(tag.len() >= 12 && tag.len() <= 16);

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            let result = SymCryptGcmDecrypt(
                self.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as SIZE_T,
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as SIZE_T,
                tag.as_ptr(),
                tag.len() as SIZE_T,
            );

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed. This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the cipher text data to be decrypted. After the decryption has been completed,
    /// `buffer` will be over-written to contain the plain text data.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    #[inline(always)]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        assert!(tag.len() >= 12 && tag.len() <= 16);
        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new`.
        //

        unsafe {
            let result = SymCryptGcmDecrypt(
                self.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as SIZE_T,
                tag.as_ptr(),
                tag.len() as SIZE_T,
            );

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    /// This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &mut [u8],
    ) {
        assert_eq!(source.len(), destination.len());
        assert!(tag.len() >= 12 && tag.len() <= 16);

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as SIZE_T,
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as SIZE_T,
            );
        }
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed. This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        assert!(tag.len() >= 12 && tag.len() <= 16);
        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new`.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as SIZE_T,
            );
        }
    }
}

impl<'a, P: OwningPointer<Target = GcmUninitializedKey>> From<&'a GcmExpandedKey<P>>
    for GcmExpandedKey<&'a GcmUninitializedKey>
{
    fn from(value: &'a GcmExpandedKey<P>) -> Self {
        value.as_ref()
    }
}

///
/// This type represents an uninitialized SYMCRYPT_GCM_STATE.
///
pub struct GcmUnitializedStream<KP: OwningPointer<Target = GcmUninitializedKey>> {
    stream_state: SYMCRYPT_GCM_STATE,
    key_pointer: MaybeUninit<GcmExpandedKey<KP>>,
}

//
// SAFETY: An uninitialized key is allowed to be sent/shared between
// threads even if the key_pointer is not as the key_pointer is
// only used by `GcmInitializedStream` which is Send/Sync based on KP.
//

unsafe impl<KP: OwningPointer<Target = GcmUninitializedKey>> Send for GcmUnitializedStream<KP> {}
unsafe impl<KP: OwningPointer<Target = GcmUninitializedKey>> Sync for GcmUnitializedStream<KP> {}

impl<KP: OwningPointer<Target = GcmUninitializedKey>> Default for GcmUnitializedStream<KP> {
    fn default() -> Self {
        Self {
            stream_state: Default::default(),
            key_pointer: MaybeUninit::uninit(),
        }
    }
}

//
// This type represents a handle to an initialized SYMCRYPT_GCM_STATE.
//
struct GcmInitializedStream<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
>(P, PhantomData<GcmExpandedKey<KP>>);

impl<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> Drop for GcmInitializedStream<P, KP>
{
    fn drop(&mut self) {
        //
        // SAFETY: The key pointer is initialized in `GcmInitializedStream::initialize`.
        //
        unsafe {
            self.0.key_pointer.assume_init_drop();
        }
        symcrypt_wipe(&mut self.0.stream_state)
    }
}

impl<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> GcmInitializedStream<P, KP>
{
    fn initialize(
        mut uninitialized_stream: P,
        expanded_key: GcmExpandedKey<KP>,
        nonce: &[u8; 12],
    ) -> Self {
        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //
        unsafe {
            SymCryptGcmInit(
                ptr::addr_of_mut!(uninitialized_stream.stream_state),
                expanded_key.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
            );
        }

        uninitialized_stream.key_pointer.write(expanded_key);
        Self(uninitialized_stream, PhantomData::default())
    }

    fn drop_without_zero(mut self) {
        //
        // SAFETY: The key pointer is initialized by `GcmInitializedStream::initialize`.
        //
        unsafe {
            self.0.key_pointer.assume_init_drop();
        }
        mem::forget(self);
    }

    fn as_ref_mut<'a>(&'a mut self) -> GcmInitializedStreamRefMut<'a> {
        GcmInitializedStreamRefMut(&mut self.0.stream_state)
    }

    fn get_state_ptr_mut(&mut self) -> *mut SYMCRYPT_GCM_STATE {
        ptr::addr_of_mut!(self.0.stream_state)
    }
}

//
// This type represents a mutable reference to an initialized SYMCRYPT_GCM_STATE.
//
struct GcmInitializedStreamRefMut<'a>(&'a mut SYMCRYPT_GCM_STATE);

impl GcmInitializedStreamRefMut<'_> {
    fn as_ref_mut<'a>(&'a mut self) -> GcmInitializedStreamRefMut<'a> {
        GcmInitializedStreamRefMut(self.0)
    }

    fn get_state_ptr_mut(&mut self) -> *mut SYMCRYPT_GCM_STATE {
        self.0 as *mut _
    }
}

//
// SAFETY: A mutable reference to an initialized SYMCRYPT_GCM_STATE is
// safe to be shared/sent with other threads.
//

unsafe impl Send for GcmInitializedStreamRefMut<'_> {}
unsafe impl Sync for GcmInitializedStreamRefMut<'_> {}

///
/// This type represents a handle to an initialized GcmStream that can be used to authenticate,
/// but not encrypt or decrypt, data. It can later be converted to a GcmDecryptionStream or
/// GcmEncryptionStream.
///
pub struct GcmAuthStream<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
>(GcmInitializedStream<P, KP>);

impl<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> GcmAuthStream<P, KP>
{
    pub fn new(
        uninitialized_stream: P,
        expanded_key: GcmExpandedKey<KP>,
        nonce: &[u8; 12],
    ) -> Self {
        Self(GcmInitializedStream::initialize(
            uninitialized_stream,
            expanded_key,
            nonce,
        ))
    }

    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> GcmAuthStreamRefMut<'b> {
        GcmAuthStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `authenticate` authenticates, but does not otherwise encrypt or decrypt, the provided data.
    ///
    /// `data` is a `&[u8]` that contains the data to authenticate.
    ///
    #[inline(always)]
    pub fn authenticate(&mut self, data: &[u8]) {
        self.as_ref_mut().authenticate(data);
    }

    ///
    /// `to_decryption_stream` converts this GcmAuthStream into a GcmDecryptionStream
    ///
    #[inline(always)]
    pub fn to_decryption_stream(self) -> GcmDecryptionStream<P, KP> {
        GcmDecryptionStream(self.0)
    }

    ///
    /// `to_encryption_stream` converts this GcmAuthStream into a GcmEncryptionStream
    ///
    #[inline(always)]
    pub fn to_encryption_stream(self) -> GcmEncryptionStream<P, KP> {
        GcmEncryptionStream(self.0)
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// authenticate, but not encrypt or decrypt, data.
///
pub struct GcmAuthStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl GcmAuthStreamRefMut<'_> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> GcmAuthStreamRefMut<'b> {
        GcmAuthStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `authenticate` authenticates, but does not otherwise encrypt or decrypt, the provided data.
    ///
    /// `data` is a `&[u8]` that contains the data to authenticate.
    ///
    #[inline(always)]
    pub fn authenticate(&mut self, data: &[u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            SymCryptGcmAuthPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.len() as SIZE_T,
            );
        }
    }
}

impl<
    'a,
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> From<&'a mut GcmAuthStream<P, KP>> for GcmAuthStreamRefMut<'a>
{
    fn from(value: &'a mut GcmAuthStream<P, KP>) -> Self {
        value.as_ref_mut()
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to decrypt data.
///
pub struct GcmDecryptionStream<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
>(GcmInitializedStream<P, KP>);

impl<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> GcmDecryptionStream<P, KP>
{
    pub fn new(
        uninitialized_stream: P,
        expanded_key: GcmExpandedKey<KP>,
        nonce: &[u8; 12],
    ) -> Self {
        Self(GcmInitializedStream::initialize(
            uninitialized_stream,
            expanded_key,
            nonce,
        ))
    }

    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'a>(&'a mut self) -> GcmDecryptionStreamRefMut<'a> {
        GcmDecryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `complete` finishes this decryption stream and validates that the provided tag matches
    /// the generated tag.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption.
    /// This is used to verify the integrity of the cipher text.
    ///
    #[inline(always)]
    pub fn complete(mut self, tag: &[u8]) -> Result<(), SymCryptError> {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        let result = unsafe {
            SymCryptGcmDecryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_ptr(),
                tag.len() as SIZE_T,
            )
        };

        self.0.drop_without_zero();
        match result {
            SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            error => Err(error.into()),
        }
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        self.as_ref_mut().decrypt(source, destination);
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.as_ref_mut().decrypt_in_place(data);
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// decrypt data.
///
pub struct GcmDecryptionStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl GcmDecryptionStreamRefMut<'_> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> GcmDecryptionStreamRefMut<'b> {
        GcmDecryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive and we've asserted that the source and destination buffers
        // are the same length.
        //

        unsafe {
            SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as SIZE_T,
            );
        }
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as SIZE_T,
            );
        }
    }
}

impl<
    'a,
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> From<&'a mut GcmDecryptionStream<P, KP>> for GcmDecryptionStreamRefMut<'a>
{
    fn from(value: &'a mut GcmDecryptionStream<P, KP>) -> Self {
        value.as_ref_mut()
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to
/// encrypt data.
///
pub struct GcmEncryptionStream<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
>(GcmInitializedStream<P, KP>);

impl<
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> GcmEncryptionStream<P, KP>
{
    pub fn new(
        uninitialized_stream: P,
        expanded_key: GcmExpandedKey<KP>,
        nonce: &[u8; 12],
    ) -> Self {
        Self(GcmInitializedStream::initialize(
            uninitialized_stream,
            expanded_key,
            nonce,
        ))
    }

    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'a>(&'a mut self) -> GcmEncryptionStreamRefMut<'a> {
        GcmEncryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `complete` finishes this encryption stream and returns the generated tag for validating
    /// decryption.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to.
    /// Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn complete(mut self, tag: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            SymCryptGcmEncryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_mut_ptr(),
                tag.len() as SIZE_T,
            );
        }

        self.0.drop_without_zero();
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    ///
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn encrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        self.as_ref_mut().encrypt(source, destination);
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    #[inline(always)]
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.as_ref_mut().encrypt_in_place(data);
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// encrypt data.
///
pub struct GcmEncryptionStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl GcmEncryptionStreamRefMut<'_> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut<'b>(&'b mut self) -> GcmEncryptionStreamRefMut<'b> {
        GcmEncryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    ///
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn encrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive and we've asserted that the source and destination buffers
        // are the same length.
        //

        unsafe {
            SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as SIZE_T,
            );
        }
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    #[inline(always)]
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as SIZE_T,
            );
        }
    }
}

impl<
    'a,
    P: UniquePointer<Target = GcmUnitializedStream<KP>>,
    KP: OwningPointer<Target = GcmUninitializedKey>,
> From<&'a mut GcmEncryptionStream<P, KP>> for GcmEncryptionStreamRefMut<'a>
{
    fn from(value: &'a mut GcmEncryptionStream<P, KP>) -> Self {
        value.as_ref_mut()
    }
}

//
// SAFETY: C FFI structs are always safe to zero
//
unsafe impl Zeroable for SYMCRYPT_GCM_EXPANDED_KEY {}
unsafe impl Zeroable for SYMCRYPT_GCM_STATE {}

#[cfg(test)]
mod test {
    use crate::{
        SymCryptError,
        gcm::{
            BlockCipherType, GcmDecryptionStream, GcmEncryptionStream, GcmExpandedKey,
            GcmUninitializedKey, GcmUnitializedStream,
        },
    };

    #[test]
    fn test_encrypt_decrypt_part() -> Result<(), SymCryptError> {
        let mut key = GcmUninitializedKey::default();
        let key = GcmExpandedKey::expand_key(
            &mut key,
            BlockCipherType::AesBlock,
            &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap(),
        )?;

        let mut nonce = [0; 12];
        rand::fill(&mut nonce);

        let mut orig_data = [0; 1024];
        rand::fill(&mut orig_data);

        let (expected_encrypted, expected_tag) = {
            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];

            key.encrypt_in_place(&nonce, &[], &mut encrypted_data, &mut tag);
            (encrypted_data, tag)
        };

        let mut gcm_stream = GcmUnitializedStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream =
                GcmEncryptionStream::new(&mut gcm_stream, key.as_ref(), &nonce);

            let mut encrypted_data = [0; 1024];
            let mut tag = [0; 16];
            for (source, destination) in orig_data
                .chunks(chunk_size)
                .zip(encrypted_data.chunks_mut(chunk_size))
            {
                encryption_stream.encrypt(source, destination);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream =
                GcmDecryptionStream::new(&mut gcm_stream, key.as_ref(), &nonce);

            let mut decrypted_data = [0; 1024];
            for (source, destination) in expected_encrypted
                .chunks(chunk_size)
                .zip(decrypted_data.chunks_mut(chunk_size))
            {
                decryption_stream.decrypt(source, destination);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_part_inplace() -> Result<(), SymCryptError> {
        let mut key = GcmUninitializedKey::default();
        let key = GcmExpandedKey::expand_key(
            &mut key,
            BlockCipherType::AesBlock,
            &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap(),
        )?;

        let mut nonce = [0; 12];
        rand::fill(&mut nonce);

        let mut orig_data = [0; 1024];
        rand::fill(&mut orig_data);

        let (expected_encrypted, expected_tag) = {
            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            key.encrypt_in_place(&nonce, &[], &mut encrypted_data, &mut tag);
            (encrypted_data, tag)
        };

        let mut gcm_stream = GcmUnitializedStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream =
                GcmEncryptionStream::new(&mut gcm_stream, key.as_ref(), &nonce);

            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            for window in encrypted_data.chunks_mut(chunk_size) {
                encryption_stream.encrypt_in_place(window);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream =
                GcmDecryptionStream::new(&mut gcm_stream, key.as_ref(), &nonce);

            let mut decrypted_data = expected_encrypted;
            for window in decrypted_data.chunks_mut(chunk_size) {
                decryption_stream.decrypt_in_place(window);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod std_test {
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::{rc::Rc, sync::Arc};

    use crate::{
        SymCryptError,
        gcm::{
            BlockCipherType, GcmDecryptionStream, GcmEncryptionStream, GcmExpandedKey,
            GcmInitializedStream, GcmInitializedStreamRefMut,
        },
    };

    #[test]
    fn test_auto_traits() {
        assert_impl_all!(GcmExpandedKey<&'static _>: Send, Sync);
        assert_impl_all!(GcmExpandedKey<&'static mut _>: Send, Sync);
        assert_impl_all!(GcmExpandedKey<Box<_>>: Send, Sync);
        assert_not_impl_any!(GcmExpandedKey<Rc<_>>: Send, Sync);
        assert_impl_all!(GcmExpandedKey<Arc<_>>: Send, Sync);

        assert_impl_all!(GcmInitializedStream<&'static mut _, &'static _>: Send, Sync);
        assert_not_impl_any!(GcmInitializedStream<&'static mut _, Rc<_>>: Send, Sync);
        assert_impl_all!(GcmInitializedStream<Box<_>, &'static _>: Send, Sync);
        assert_not_impl_any!(GcmInitializedStream<Box<_>, Rc<_>>: Send, Sync);

        assert_impl_all!(GcmInitializedStreamRefMut<'static>: Send, Sync);
    }

    #[test]
    fn test_owned_key() -> Result<(), SymCryptError> {
        let key = GcmExpandedKey::expand_key(
            Rc::default(),
            BlockCipherType::AesBlock,
            &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap(),
        )?;

        let mut nonce = [0; 12];
        rand::fill(&mut nonce);

        let mut orig_data = [0; 1024];
        rand::fill(&mut orig_data);

        let (expected_encrypted, expected_tag) = {
            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            key.encrypt_in_place(&nonce, &[], &mut encrypted_data, &mut tag);
            (encrypted_data, tag)
        };

        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream =
                GcmEncryptionStream::new(Box::default(), key.clone(), &nonce);

            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            for window in encrypted_data.chunks_mut(chunk_size) {
                encryption_stream.encrypt_in_place(window);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream =
                GcmDecryptionStream::new(Box::default(), key.clone(), &nonce);

            let mut decrypted_data = expected_encrypted;
            for window in decrypted_data.chunks_mut(chunk_size) {
                decryption_stream.decrypt_in_place(window);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }
}
