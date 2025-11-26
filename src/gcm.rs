use core::{
    mem::offset_of,
    ptr::{self, addr_of_mut},
};

use symcrypt_sys::{
    PCSYMCRYPT_GCM_EXPANDED_KEY, PSYMCRYPT_GCM_EXPANDED_KEY, SIZE_T, SYMCRYPT_BLOCKCIPHER,
    SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR, SYMCRYPT_GCM_EXPANDED_KEY, SYMCRYPT_GCM_STATE,
    SymCryptGcmAuthPart, SymCryptGcmDecrypt, SymCryptGcmDecryptFinal, SymCryptGcmDecryptPart,
    SymCryptGcmEncrypt, SymCryptGcmEncryptFinal, SymCryptGcmEncryptPart, SymCryptGcmExpandKey,
    SymCryptGcmInit, SymCryptWipe,
};

use crate::{
    SymCryptError,
    ptr::{OwningPointer, SharedPointer},
    refs::{self, SecureZeroable},
    symcrypt_init,
};

unsafe extern "C" {
    fn SymCryptGcmKeyCopy(pSrc: PCSYMCRYPT_GCM_EXPANDED_KEY, pDst: PSYMCRYPT_GCM_EXPANDED_KEY);
}

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

//
// SAFETY: SYMCRYPT_GCM_EXPANDED_KEY can be securely zeroed.
//
unsafe impl SecureZeroable for SYMCRYPT_GCM_EXPANDED_KEY {}

///
/// `GcmUninitializedKey` represents an uninitialized SYMCRYPT_GCM_EXPANDED_KEY.
///
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct GcmUninitializedKey(SYMCRYPT_GCM_EXPANDED_KEY);

impl GcmUninitializedKey {
    ///
    /// `expand_key` will initialize this SYMCRYPT_GCM_EXPANDED_KEY using the provided
    /// cipher type and key.
    ///
    /// `cipher_type` is a `BlockCipherType` that determines the cipher to use for this key.
    /// The only supported cipher type is [`BlockCipherType::AesBlock`]
    ///
    /// `key_data` is a `&[u8]` that contains the key to initialize with.
    ///
    #[inline(always)]
    pub fn expand_key<'a>(
        &'a mut self,
        cipher_type: BlockCipherType,
        key_data: &[u8],
    ) -> Result<GcmExpandedKey<'a>, SymCryptError> {
        symcrypt_init();

        //
        // SAFETY: FFI call to initialize the SYMCRYPT_GCM_EXPANDED_KEY. The mutable borrow
        // in refs::Initialized ensures that the underlying storage can not be moved
        // until it is dropped.
        //
        unsafe {
            let result = SymCryptGcmExpandKey(
                addr_of_mut!(self.0) as *mut _,
                cipher_type.into(),
                key_data.as_ptr(),
                key_data.len() as SIZE_T,
            );

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    Ok(GcmExpandedKey(refs::Initialized::new(&mut self.0)))
                }
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `copy_from` will copy the contents of `other` into this uninitialized key.
    ///
    #[inline(always)]
    pub fn copy_from<'a>(&'a mut self, other: GcmExpandedKeyRef<'a>) -> GcmExpandedKey<'a> {
        //
        // SAFETY: FFI call to initialize the SYMCRYPT_GCM_EXPANDED_KEY. The GcmExpandedKeyRef
        // ensures that the other key has been properly initialized for this call and the mutable
        // borrow in refs::Initialized ensures that the underlying storage can not be moved
        // until it is dropped.
        //
        unsafe {
            SymCryptGcmKeyCopy(other.0.get_state_ptr(), addr_of_mut!(self.0) as *mut _);

            GcmExpandedKey(refs::Initialized::new(&mut self.0))
        }
    }
}

///
/// `GcmExpandedKey` represents an initialized SYMCRYPT_GCM_EXPANDED_KEY.
///
pub struct GcmExpandedKey<'a>(refs::Initialized<'a, SYMCRYPT_GCM_EXPANDED_KEY>);

impl<'a> GcmExpandedKey<'a> {
    ///
    /// `as_ref` returns a `GcmExpandedKeyRef` that provides a borrowed reference to the underlying key.
    ///
    #[inline(always)]
    pub fn as_ref<'b>(&'b self) -> GcmExpandedKeyRef<'b> {
        GcmExpandedKeyRef(self.0.as_ref())
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
        self.as_ref()
            .decrypt(nonce, auth_data, source, destination, tag)
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
        self.as_ref()
            .decrypt_in_place(nonce, auth_data, buffer, tag)
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
        self.as_ref()
            .encrypt(nonce, auth_data, source, destination, tag);
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
        self.as_ref()
            .encrypt_in_place(nonce, auth_data, buffer, tag);
    }
}

///
/// `OwningGcmExpandedKey` represents an owned pointer to an initialized SYMCRYPT_GCM_EXPANDED_KEY.
///
/// If T is a SharedPointer, then multiple OwningGcmExpandedKey instances can share ownership of
/// the same underlying key and will be zeroed and freed when the last owner is dropped.
///
pub struct OwningGcmExpandedKey<T: OwningPointer<Target = GcmUninitializedKey>>(Option<T>);

impl<T: OwningPointer<Target = GcmUninitializedKey>> Drop for OwningGcmExpandedKey<T> {
    fn drop(&mut self) {
        if let Some(mut key_storage) = self.0.take() {
            if let Some(key_storage) = key_storage.try_get_mut() {
                //
                // SAFETY: SYMCRYPT_GCM_EXPANDED_KEY can be securely zeroed.
                //
                unsafe {
                    SymCryptWipe(
                        addr_of_mut!(key_storage.0) as *mut _,
                        size_of::<SYMCRYPT_GCM_EXPANDED_KEY>() as SIZE_T,
                    );
                }
            }
        }
    }
}

impl<T: SharedPointer<Target = GcmUninitializedKey>> Clone for OwningGcmExpandedKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: OwningPointer<Target = GcmUninitializedKey>> OwningGcmExpandedKey<T> {
    ///
    /// `expand_key` will initialize the uninitialized key specified by `key_storage` using
    /// the provided cipher type and key.
    ///
    /// `key_storage` is an OwningPointer to a GcmUnitializedKey. This must be the only
    /// owner of the key storage at the time of this call.
    ///
    /// `cipher_type` is a `BlockCipherType` that determines the cipher to use for this key.
    /// The only supported cipher type is [`BlockCipherType::AesBlock`]
    ///
    /// `key_data` is a `&[u8]` that contains the key to initialize with.
    ///
    #[inline(always)]
    pub fn expand_key(
        mut key_storage: T,
        cipher_type: BlockCipherType,
        key_data: &[u8],
    ) -> Result<Self, SymCryptError> {
        symcrypt_init();

        //
        // SAFETY: FFI call to initialize the SYMCRYPT_GCM_EXPANDED_KEY. The contact for
        // OwningPointer ensures that the underlying storage can not be moved.
        //
        unsafe {
            let result = SymCryptGcmExpandKey(
                addr_of_mut!(key_storage.try_get_mut().unwrap().0),
                cipher_type.into(),
                key_data.as_ptr(),
                key_data.len() as SIZE_T,
            );

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(Self(Some(key_storage))),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `copy_from` will copy the contents of `other` into the uninitialized key
    /// specified by `key_storage`.
    ///
    #[inline(always)]
    pub fn copy_from(mut key_storage: T, other: GcmExpandedKeyRef) -> Self {
        //
        // SAFETY: FFI call to initialize the SYMCRYPT_GCM_EXPANDED_KEY. The GcmExpandedKeyRef
        // ensures that the other key has been properly initialized for this call and the
        // contact for OwningPointer ensures that the underlying storage can not be moved.
        //
        unsafe {
            SymCryptGcmKeyCopy(
                other.0.get_state_ptr(),
                addr_of_mut!(key_storage.try_get_mut().unwrap().0),
            );

            Self(Some(key_storage))
        }
    }

    ///
    /// `as_ref` returns a `GcmExpandedKeyRef` that provides a borrowed reference to the underlying key.
    ///
    #[inline(always)]
    pub fn as_ref<'a>(&'a self) -> GcmExpandedKeyRef<'a> {
        //
        // SAFETY: The contact for OwningPointer ensures that the underlying storage can not be moved
        // and self must contain a valid initialized key.
        //
        unsafe { GcmExpandedKeyRef(refs::InitializedRef::new(&self.0.as_deref().unwrap().0)) }
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
        self.as_ref()
            .decrypt(nonce, auth_data, source, destination, tag)
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
        self.as_ref()
            .decrypt_in_place(nonce, auth_data, buffer, tag)
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
        self.as_ref()
            .encrypt(nonce, auth_data, source, destination, tag);
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
        self.as_ref()
            .encrypt_in_place(nonce, auth_data, buffer, tag);
    }
}

///
/// `GcmExpandedKeyRef` provides a borrowed reference to an initialized SYMCRYPT_GCM_EXPANDED_KEY.
///
#[derive(Clone, Copy)]
pub struct GcmExpandedKeyRef<'a>(refs::InitializedRef<'a, SYMCRYPT_GCM_EXPANDED_KEY>);

impl<'a, 'b> From<&'a GcmExpandedKey<'b>> for GcmExpandedKeyRef<'a> {
    fn from(value: &'a GcmExpandedKey<'b>) -> Self {
        value.as_ref()
    }
}

impl<'a, T: OwningPointer<Target = GcmUninitializedKey>> From<&'a OwningGcmExpandedKey<T>>
    for GcmExpandedKeyRef<'a>
{
    fn from(value: &'a OwningGcmExpandedKey<T>) -> Self {
        value.as_ref()
    }
}

impl<'a> GcmExpandedKeyRef<'a> {
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
        // by the caller of `refs::Initialized::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            let result = SymCryptGcmDecrypt(
                self.0.get_state_ptr(),
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
        // by the caller of `refs::Initialized::new`.
        //

        unsafe {
            let result = SymCryptGcmDecrypt(
                self.0.get_state_ptr(),
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
        // by the caller of `refs::Initialized::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.0.get_state_ptr(),
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
        // by the caller of `refs::Initialized::new`.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.0.get_state_ptr(),
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

unsafe impl SecureZeroable for SYMCRYPT_GCM_STATE {
    fn zero_memory(&mut self) {
        //
        // SAFETY: SYMCRYPT_GCM_STATE can be securely zeroed and
        // SYMCRYPT_GCM_STATE is only contained within a GcmStream.
        //
        unsafe {
            GcmStream::get_destructor(self as *const _)();
            SymCryptWipe(
                self as *mut _ as *mut _,
                size_of::<SYMCRYPT_GCM_STATE>() as SIZE_T,
            );
        }
    }
}

///
/// This type represents an uninitialized SYMCRYPT_GCM_STATE.
///
#[derive(Clone, Copy)]
pub struct GcmStream {
    stream_state: SYMCRYPT_GCM_STATE,
    destructor: unsafe fn(*const GcmUninitializedKey),
}

impl Default for GcmStream {
    fn default() -> Self {
        Self {
            stream_state: Default::default(),
            destructor: |_| {},
        }
    }
}

impl GcmStream {
    //
    // `initialize` initializes the underlying `SYMCRYPT_GCM_STATE` with the provided key and nonce.
    //
    // `expanded_key` provides a borrowed reference to an initialized `SYMCRYPT_GCM_EXPANDED_KEY`
    //
    // `nonce` is a `&[u8; 12]` that is used as the nonce.
    //
    #[inline(always)]
    fn initialize<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> refs::Initialized<'a, SYMCRYPT_GCM_STATE> {
        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //

        unsafe {
            SymCryptGcmInit(
                ptr::addr_of_mut!(self.stream_state),
                expanded_key.0.get_state_ptr(),
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
            );

            self.destructor = |_| {};
            refs::Initialized::new(&mut self.stream_state)
        }
    }

    //
    // `initialize` initializes the underlying `SYMCRYPT_GCM_STATE` with the provided key and nonce.
    //
    // `expanded_key` provides an owned reference to an initialized `SYMCRYPT_GCM_EXPANDED_KEY`
    //
    // `nonce` is a `&[u8; 12]` that is used as the nonce.
    //
    fn initialize_owned<'a, T: OwningPointer<Target = GcmUninitializedKey>>(
        &'a mut self,
        mut expanded_key: OwningGcmExpandedKey<T>,
        nonce: &[u8; 12],
    ) -> refs::Initialized<'a, SYMCRYPT_GCM_STATE> {
        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //

        unsafe {
            let key_storage = expanded_key.0.take().unwrap().into_raw();

            SymCryptGcmInit(
                ptr::addr_of_mut!(self.stream_state),
                key_storage as *const _,
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
            );

            self.destructor = |this| {
                OwningGcmExpandedKey(Some(T::from_raw(this)));
            };

            refs::Initialized::new(&mut self.stream_state)
        }
    }

    ///
    /// `get_destructor` retrieves the destructor function for the GcmStream.
    ///
    /// SAFETY: `this` must be a pointer to a SYMCRYPT_GCM_STATE that is part of a GcmStream.
    ///
    unsafe fn get_destructor(this: *const SYMCRYPT_GCM_STATE) -> impl FnOnce() {
        //
        // SAFETY: The caller has ensures that `this` is a valid pointer to a SYMCRYPT_GCM_STATE
        // that is part of a GcmStream.
        //
        let (p_key, destructor) = unsafe {
            let gcm_stream_ptr =
                this.byte_sub(offset_of!(GcmStream, stream_state)) as *const GcmStream;

            (
                (*gcm_stream_ptr).stream_state.pKey,
                (*gcm_stream_ptr).destructor,
            )
        };

        move || unsafe {
            (destructor)(p_key as *const _);
        }
    }

    ///
    /// Initializes this GcmStream as a GcmAuthStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_auth_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmAuthStream<'a> {
        GcmAuthStream(self.initialize(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmAuthStream using the provided owned key, and nonce.
    ///
    /// `expanded_key` is a `OwningGcmExpandedKey` that provides a handle to the key to use
    /// for operations. It will be dropped when the resulting stream is completed or dropped.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_auth_stream_owned<'a>(
        &'a mut self,
        expanded_key: OwningGcmExpandedKey<impl OwningPointer<Target = GcmUninitializedKey>>,
        nonce: &[u8; 12],
    ) -> GcmAuthStream<'a> {
        GcmAuthStream(self.initialize_owned(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmDecryptionStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_decryption_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmDecryptionStream<'a> {
        GcmDecryptionStream(self.initialize(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmDecryptionStream using the provided owned key, and nonce.
    ///
    /// `expanded_key` is a `OwningGcmExpandedKey` that provides a handle to the key to use
    /// for operations. It will be dropped when the resulting stream is completed or dropped.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_decryption_stream_owned<'a>(
        &'a mut self,
        expanded_key: OwningGcmExpandedKey<impl OwningPointer<Target = GcmUninitializedKey>>,
        nonce: &[u8; 12],
    ) -> GcmDecryptionStream<'a> {
        GcmDecryptionStream(self.initialize_owned(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmEncryptionStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_encryption_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmEncryptionStream<'a> {
        GcmEncryptionStream(self.initialize(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmEncryptionStream using the provided owned key, and nonce.
    ///
    /// `expanded_key` is a `OwningGcmExpandedKey` that provides a handle to the key to use
    /// for operations. It will be dropped when the resulting stream is completed or dropped.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_encryption_stream_owned<'a>(
        &'a mut self,
        expanded_key: OwningGcmExpandedKey<impl OwningPointer<Target = GcmUninitializedKey>>,
        nonce: &[u8; 12],
    ) -> GcmEncryptionStream<'a> {
        GcmEncryptionStream(self.initialize_owned(expanded_key, nonce))
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to authenticate,
/// but not encrypt or decrypt, data. It can later be converted to a GcmDecryptionStream or
/// GcmEncryptionStream.
///
pub struct GcmAuthStream<'a>(refs::Initialized<'a, SYMCRYPT_GCM_STATE>);

impl<'a> GcmAuthStream<'a> {
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
    pub fn to_decryption_stream(self) -> GcmDecryptionStream<'a> {
        GcmDecryptionStream(self.0)
    }

    ///
    /// `to_encryption_stream` converts this GcmAuthStream into a GcmEncryptionStream
    ///
    #[inline(always)]
    pub fn to_encryption_stream(self) -> GcmEncryptionStream<'a> {
        GcmEncryptionStream(self.0)
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// authenticate, but not encrypt or decrypt, data.
///
pub struct GcmAuthStreamRefMut<'a>(refs::InitializedRefMut<'a, SYMCRYPT_GCM_STATE>);

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

impl<'a, 'b> From<&'a mut GcmAuthStream<'b>> for GcmAuthStreamRefMut<'a> {
    fn from(value: &'a mut GcmAuthStream<'b>) -> Self {
        value.as_ref_mut()
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to decrypt data.
///
pub struct GcmDecryptionStream<'a>(refs::Initialized<'a, SYMCRYPT_GCM_STATE>);

impl GcmDecryptionStream<'_> {
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
        let destructor = unsafe { GcmStream::get_destructor(self.0.get_state_ptr()) };

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

        destructor();
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
pub struct GcmDecryptionStreamRefMut<'a>(refs::InitializedRefMut<'a, SYMCRYPT_GCM_STATE>);

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

impl<'a, 'b> From<&'a mut GcmDecryptionStream<'b>> for GcmDecryptionStreamRefMut<'a> {
    fn from(value: &'a mut GcmDecryptionStream<'b>) -> Self {
        value.as_ref_mut()
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to
/// encrypt data.
///
pub struct GcmEncryptionStream<'a>(refs::Initialized<'a, SYMCRYPT_GCM_STATE>);

impl GcmEncryptionStream<'_> {
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
        let destructor = unsafe { GcmStream::get_destructor(self.0.get_state_ptr()) };

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

        destructor();
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
pub struct GcmEncryptionStreamRefMut<'a>(refs::InitializedRefMut<'a, SYMCRYPT_GCM_STATE>);

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

impl<'a, 'b> From<&'a mut GcmEncryptionStream<'b>> for GcmEncryptionStreamRefMut<'a> {
    fn from(value: &'a mut GcmEncryptionStream<'b>) -> Self {
        value.as_ref_mut()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        SymCryptError,
        gcm::{BlockCipherType, GcmStream, GcmUninitializedKey},
    };

    #[test]
    fn test_encrypt_decrypt_part() -> Result<(), SymCryptError> {
        let mut key = GcmUninitializedKey::default();
        let key = key.expand_key(
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

        let mut gcm_stream = GcmStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream = gcm_stream.as_encryption_stream(key.as_ref(), &nonce);

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
            let mut decryption_stream = gcm_stream.as_decryption_stream(key.as_ref(), &nonce);

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
        let key = key.expand_key(
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

        let mut gcm_stream = GcmStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream = gcm_stream.as_encryption_stream(key.as_ref(), &nonce);

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
            let mut decryption_stream = gcm_stream.as_decryption_stream(key.as_ref(), &nonce);

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
    use std::rc::Rc;

    use crate::{
        SymCryptError,
        gcm::{BlockCipherType, GcmStream, OwningGcmExpandedKey},
    };

    #[test]
    fn test_owned_key() -> Result<(), SymCryptError> {
        let key = OwningGcmExpandedKey::expand_key(
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

        let mut gcm_stream = GcmStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream = gcm_stream.as_encryption_stream_owned(key.clone(), &nonce);

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
            let mut decryption_stream = gcm_stream.as_decryption_stream_owned(key.clone(), &nonce);

            let mut decrypted_data = expected_encrypted;
            for window in decrypted_data.chunks_mut(chunk_size) {
                decryption_stream.decrypt_in_place(window);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        std::mem::drop(key);
        Ok(())
    }
}
