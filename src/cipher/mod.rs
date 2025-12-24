use symcrypt_sys::SIZE_T;

use crate::{
    Zeroable,
    ptr::{OwningPointer, SharedPointer},
    symcrypt_init, symcrypt_wipe,
};

pub mod cbc;

pub trait BlockCipherAlgorithm {
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

pub struct UninitializedKey<T: BlockCipherAlgorithm>(T::Key);

impl<T: BlockCipherAlgorithm> Default for UninitializedKey<T>
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

unsafe impl<T: BlockCipherAlgorithm> Send for UninitializedKey<T> {}
unsafe impl<T: BlockCipherAlgorithm> Sync for UninitializedKey<T> {}

pub struct ExpandedKey<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>>(P);

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>> Drop
    for ExpandedKey<T, P>
{
    fn drop(&mut self) {
        if let Some(initialized_key) = self.0.try_get_mut() {
            symcrypt_wipe(&mut initialized_key.0);
        }
    }
}

impl<T: BlockCipherAlgorithm, P: SharedPointer<Target = UninitializedKey<T>>> Clone
    for ExpandedKey<T, P>
{
    fn clone(&self) -> Self {
        Self(Clone::clone(&self.0))
    }
}

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>> ExpandedKey<T, P> {
    pub fn expand_key(mut uninitialized_key: P, key_data: &[u8]) -> Self {
        symcrypt_init();
        unsafe {
            T::expand_key(&mut uninitialized_key.try_get_mut().unwrap().0, key_data);
            Self(uninitialized_key)
        }
    }

    pub fn as_ref<'a>(&'a self) -> ExpandedKey<T, &'a UninitializedKey<T>> {
        ExpandedKey(self.0.deref())
    }

    pub fn get_block_size(&self) -> usize {
        T::get_block_size()
    }

    fn get_initialized_key_ref(&self) -> &T::Key {
        &self.0.0
    }
}

#[derive(Clone, Copy, Default)]
pub struct AesBlockCipher;

pub type AesBlock = <AesBlockCipher as BlockCipherAlgorithm>::Block;
pub type AesUninitializedKey = UninitializedKey<AesBlockCipher>;
pub type AesExpandedKey<P> = ExpandedKey<AesBlockCipher, P>;

unsafe impl Zeroable for symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY {}

impl BlockCipherAlgorithm for AesBlockCipher {
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
