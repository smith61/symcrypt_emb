use symcrypt_sys::SIZE_T;

use crate::{
    Zeroable,
    ptr::{OwningPointer, SharedPointer},
    symcrypt_init, symcrypt_wipe,
};

pub trait CbcAlgorithm {
    type Key: Zeroable;
    type Block: Zeroable;

    fn get_block_size() -> usize;
    unsafe fn expand_key(key: &mut Self::Key, key_data: &[u8]);
    unsafe fn cbc_decrypt(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source: &[u8],
        destination: &mut [u8],
    );
    unsafe fn cbc_decrypt_in_place(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source_destination: &mut [u8],
    );
    unsafe fn cbc_encrypt(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source: &[u8],
        destination: &mut [u8],
    );
    unsafe fn cbc_encrypt_in_place(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source_destination: &mut [u8],
    );
}

pub struct CbcUninitializedKey<T: CbcAlgorithm>(T::Key);

impl<T: CbcAlgorithm> Default for CbcUninitializedKey<T>
where
    T::Key: Default,
{
    fn default() -> Self {
        Self(T::Key::default())
    }
}

//
// SAFETY: An uninitialized key is allowed to be sent/shared between
// threads as it contains no state.
//

unsafe impl<T: CbcAlgorithm> Send for CbcUninitializedKey<T> {}
unsafe impl<T: CbcAlgorithm> Sync for CbcUninitializedKey<T> {}

pub struct CbcExpandedKey<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>>(P);

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> Drop
    for CbcExpandedKey<T, P>
{
    fn drop(&mut self) {
        if let Some(initialized_key) = self.0.try_get_mut() {
            symcrypt_wipe(&mut initialized_key.0);
        }
    }
}

impl<T: CbcAlgorithm, P: SharedPointer<Target = CbcUninitializedKey<T>>> Clone
    for CbcExpandedKey<T, P>
{
    fn clone(&self) -> Self {
        Self(Clone::clone(&self.0))
    }
}

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> CbcExpandedKey<T, P> {
    pub fn expand_key(mut uninitialized_key: P, key_data: &[u8]) -> Self {
        symcrypt_init();
        unsafe {
            T::expand_key(&mut uninitialized_key.try_get_mut().unwrap().0, key_data);
            Self(uninitialized_key)
        }
    }

    pub fn as_ref<'a>(&'a self) -> CbcExpandedKey<T, &'a CbcUninitializedKey<T>> {
        CbcExpandedKey(self.0.deref())
    }
}

pub struct CbcEncryptionStream<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> {
    key: P,
    chaining_value: T::Block,
}

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> Drop
    for CbcEncryptionStream<T, P>
{
    fn drop(&mut self) {
        symcrypt_wipe(&mut self.chaining_value);
    }
}

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> CbcEncryptionStream<T, P> {
    pub fn new(key: P, iv: T::Block) -> Self {
        Self {
            key,
            chaining_value: iv,
        }
    }

    pub fn get_chaining_value(&self) -> &T::Block {
        &self.chaining_value
    }

    pub fn encrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        assert_eq!(source.len() % T::get_block_size(), 0);

        unsafe {
            T::cbc_encrypt(&self.key.0, &mut self.chaining_value, source, destination);
        }
    }

    pub fn encrypt_in_place(&mut self, source_destination: &mut [u8]) {
        assert_eq!(source_destination.len() % T::get_block_size(), 0);

        unsafe {
            T::cbc_encrypt_in_place(&self.key.0, &mut self.chaining_value, source_destination);
        }
    }
}

pub struct CbcDecryptionStream<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> {
    key: P,
    chaining_value: T::Block,
}

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> Drop
    for CbcDecryptionStream<T, P>
{
    fn drop(&mut self) {
        symcrypt_wipe(&mut self.chaining_value);
    }
}

impl<T: CbcAlgorithm, P: OwningPointer<Target = CbcUninitializedKey<T>>> CbcDecryptionStream<T, P> {
    pub fn new(key: P, iv: T::Block) -> Self {
        Self {
            key,
            chaining_value: iv,
        }
    }

    pub fn get_chaining_value(&self) -> &T::Block {
        &self.chaining_value
    }

    pub fn decrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        assert_eq!(source.len() % T::get_block_size(), 0);

        unsafe {
            T::cbc_decrypt(&self.key.0, &mut self.chaining_value, source, destination);
        }
    }

    pub fn decrypt_in_place(&mut self, source_destination: &mut [u8]) {
        assert_eq!(source_destination.len() % T::get_block_size(), 0);

        unsafe {
            T::cbc_decrypt_in_place(&self.key.0, &mut self.chaining_value, source_destination);
        }
    }
}

pub struct AesCbcAlgorithm;

pub type AesCbcBlock = <AesCbcAlgorithm as CbcAlgorithm>::Block;
pub type AesCbcUninitializedKey = CbcUninitializedKey<AesCbcAlgorithm>;
pub type AesCbcExpandedKey<P> = CbcExpandedKey<AesCbcAlgorithm, P>;
pub type AesCbcEncryptionStream<P> = CbcEncryptionStream<AesCbcAlgorithm, P>;
pub type AesCbcDecryptionStream<P> = CbcDecryptionStream<AesCbcAlgorithm, P>;

unsafe impl Zeroable for symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY {}

impl CbcAlgorithm for AesCbcAlgorithm {
    type Key = symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY;
    type Block = [u8; symcrypt_sys::SYMCRYPT_AES_BLOCK_SIZE as usize];

    fn get_block_size() -> usize {
        symcrypt_sys::SYMCRYPT_AES_BLOCK_SIZE as usize
    }

    unsafe fn expand_key(key: &mut Self::Key, key_data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptAesExpandKey(
                key as *mut _,
                key_data.as_ptr(),
                key_data.len() as SIZE_T,
            );
        }
    }

    unsafe fn cbc_decrypt(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source: &[u8],
        destination: &mut [u8],
    ) {
        unsafe {
            symcrypt_sys::SymCryptAesCbcDecrypt(
                key as *const _,
                chaining_value.as_mut_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                source.len() as SIZE_T,
            );
        }
    }

    unsafe fn cbc_decrypt_in_place(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source_destination: &mut [u8],
    ) {
        unsafe {
            symcrypt_sys::SymCryptAesCbcDecrypt(
                key as *const _,
                chaining_value.as_mut_ptr(),
                source_destination.as_ptr(),
                source_destination.as_mut_ptr(),
                source_destination.len() as SIZE_T,
            );
        }
    }

    unsafe fn cbc_encrypt(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source: &[u8],
        destination: &mut [u8],
    ) {
        unsafe {
            symcrypt_sys::SymCryptAesCbcEncrypt(
                key as *const _,
                chaining_value.as_mut_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                source.len() as SIZE_T,
            );
        }
    }

    unsafe fn cbc_encrypt_in_place(
        key: &Self::Key,
        chaining_value: &mut Self::Block,
        source_destination: &mut [u8],
    ) {
        unsafe {
            symcrypt_sys::SymCryptAesCbcEncrypt(
                key as *const _,
                chaining_value.as_mut_ptr(),
                source_destination.as_ptr(),
                source_destination.as_mut_ptr(),
                source_destination.len() as SIZE_T,
            );
        }
    }
}
