use crate::{
    cipher::{AesBlockCipher, BlockCipherAlgorithm, ExpandedKey, UninitializedKey},
    ptr::OwningPointer,
    symcrypt_wipe,
};

pub struct CbcEncryptionStream<
    T: BlockCipherAlgorithm,
    P: OwningPointer<Target = UninitializedKey<T>>,
> {
    key: ExpandedKey<T, P>,
    chaining_value: T::Block,
}

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>> Drop
    for CbcEncryptionStream<T, P>
{
    fn drop(&mut self) {
        symcrypt_wipe(&mut self.chaining_value);
    }
}

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>>
    CbcEncryptionStream<T, P>
{
    pub fn new(key: ExpandedKey<T, P>, iv: T::Block) -> Self {
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
        assert_eq!(source.len() % self.key.get_block_size(), 0);
        //
        // SAFETY: Key is guaranteed to be initialized by `CbcExpandedKey::new`
        //
        unsafe {
            T::cbc_encrypt(
                &self.key.get_initialized_key_ref(),
                &mut self.chaining_value,
                source,
                destination,
            );
        }
    }

    pub fn encrypt_in_place(&mut self, source_destination: &mut [u8]) {
        assert_eq!(source_destination.len() % self.key.get_block_size(), 0);
        //
        // SAFETY: Key is guaranteed to be initialized by `CbcExpandedKey::new`
        //
        unsafe {
            T::cbc_encrypt_in_place(
                &self.key.get_initialized_key_ref(),
                &mut self.chaining_value,
                source_destination,
            );
        }
    }
}

pub struct CbcDecryptionStream<
    T: BlockCipherAlgorithm,
    P: OwningPointer<Target = UninitializedKey<T>>,
> {
    key: ExpandedKey<T, P>,
    chaining_value: T::Block,
}

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>> Drop
    for CbcDecryptionStream<T, P>
{
    fn drop(&mut self) {
        symcrypt_wipe(&mut self.chaining_value);
    }
}

impl<T: BlockCipherAlgorithm, P: OwningPointer<Target = UninitializedKey<T>>>
    CbcDecryptionStream<T, P>
{
    pub fn new(key: ExpandedKey<T, P>, iv: T::Block) -> Self {
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
        assert_eq!(source.len() % self.key.get_block_size(), 0);
        //
        // SAFETY: Key is guaranteed to be initialized by `CbcExpandedKey::new`
        //
        unsafe {
            T::cbc_decrypt(
                &self.key.get_initialized_key_ref(),
                &mut self.chaining_value,
                source,
                destination,
            );
        }
    }

    pub fn decrypt_in_place(&mut self, source_destination: &mut [u8]) {
        assert_eq!(source_destination.len() % self.key.get_block_size(), 0);
        //
        // SAFETY: Key is guaranteed to be initialized by `CbcExpandedKey::new`
        //
        unsafe {
            T::cbc_decrypt_in_place(
                &self.key.get_initialized_key_ref(),
                &mut self.chaining_value,
                source_destination,
            );
        }
    }
}

pub type AesCbcEncryptionStream<P> = CbcEncryptionStream<AesBlockCipher, P>;
pub type AesCbcDecryptionStream<P> = CbcDecryptionStream<AesBlockCipher, P>;
