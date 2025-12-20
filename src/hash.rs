use core::ptr;

use paste::paste;
use symcrypt_sys::{PCSYMCRYPT_HASH, SIZE_T};

use crate::{Zeroable, ptr::UniquePointer, symcrypt_init, symcrypt_wipe};

pub trait HashAlgorithm {
    type StreamState: Zeroable;
    type Result;

    fn get_hash_algorithm() -> PCSYMCRYPT_HASH;

    fn hash(data: &[u8], result: &mut Self::Result);

    unsafe fn stream_init(state: *mut Self::StreamState);
    unsafe fn stream_append(state: *mut Self::StreamState, data: &[u8]);
    unsafe fn stream_result(state: *mut Self::StreamState, result: &mut Self::Result);
}

///
/// This type represents an uninitialized hashing stream.
///
#[derive(Default)]
pub struct UninitializedHasher<T: HashAlgorithm>(T::StreamState);

///
/// This type represents an initialized hashing stream.
///
pub struct Hasher<T: HashAlgorithm, P: UniquePointer<Target = UninitializedHasher<T>>>(P);

impl<T: HashAlgorithm, P: UniquePointer<Target = UninitializedHasher<T>>> Drop for Hasher<T, P> {
    fn drop(&mut self) {
        symcrypt_wipe(&mut self.0.0);
    }
}

impl<T: HashAlgorithm, P: UniquePointer<Target = UninitializedHasher<T>>> Hasher<T, P> {
    ///
    /// `new` creates a new hashing stream at the provided location.
    ///
    /// `uninitialized_hasher` is a pointer to an uninitialized hashing stream
    ///
    pub fn new(mut uninitialized_hasher: P) -> Self {
        symcrypt_init();
        unsafe {
            T::stream_init(ptr::addr_of_mut!(uninitialized_hasher.0));
            Self(uninitialized_hasher)
        }
    }

    ///
    /// `as_ref_mut` gets a mutable reference to the underlying hashing stream.
    ///
    pub fn as_ref_mut<'b>(&'b mut self) -> HasherRefMut<'b, T> {
        HasherRefMut(self.0.deref_mut())
    }

    ///
    /// `hash` appends the provided data buffer to the hashing stream.
    ///
    /// `data` is an array of bytes to be hashed.
    ///
    pub fn hash(&mut self, data: &[u8]) {
        self.as_ref_mut().hash(data);
    }

    ///
    /// `complete` finishes the hashing operation and returns a newly initialized
    /// hashing stream.
    ///
    /// `result` is a reference to a location in which to write the generated hash.
    ///
    pub fn complete(mut self, result: &mut T::Result) -> Self {
        unsafe {
            T::stream_result(ptr::addr_of_mut!(self.0.0), result);
        }

        self
    }
}

///
/// This type represents a mutable reference to an initialized hashing stream.
///
pub struct HasherRefMut<'a, T: HashAlgorithm>(&'a mut UninitializedHasher<T>);

impl<'a, T: HashAlgorithm> HasherRefMut<'a, T> {
    ///
    /// `as_ref_mut` gets a mutable reference to the underlying hashing stream.
    ///
    pub fn as_ref_mut<'b>(&'b mut self) -> HasherRefMut<'b, T> {
        HasherRefMut(self.0)
    }

    ///
    /// `hash` appends the provided data buffer to the hashing stream.
    ///
    /// `data` is an array of bytes to be hashed.
    ///
    pub fn hash(&mut self, data: &[u8]) {
        unsafe {
            T::stream_append(ptr::addr_of_mut!(self.0.0), data);
        }
    }
}

macro_rules! define_hash_algorithm {
    ($lc: ident, $uc: ident) => {
        paste! {
            pub struct [<$lc HashAlgorithm>];

            pub type [<$lc HashResult>] = [u8; symcrypt_sys::[<SYMCRYPT_ $uc _RESULT_SIZE>] as usize];
            pub type [<$lc Hasher>]<P> = Hasher<[<$lc HashAlgorithm>], P>;
            pub type [<$lc HasherRefMut>]<'a> = HasherRefMut<'a, [<$lc HashAlgorithm>]>;

            //
            // SAFETY: C FFI structs are always safe to zero
            //
            unsafe impl Zeroable for symcrypt_sys::[<SYMCRYPT_ $uc _STATE>] { }

            //
            // SAFETY: The uninitialized structure wrappers are safe to be sent
            // across threads since they contain no state. Only when initialized
            // behind some pointer will they contain state and Send/Sync properties
            // are needed for those handles.
            //
            unsafe impl Send for UninitializedHasher<[<$lc HashAlgorithm>]> { }
            unsafe impl Sync for UninitializedHasher<[<$lc HashAlgorithm>]> { }

            impl HashAlgorithm for [<$lc HashAlgorithm>] {
                type StreamState = symcrypt_sys::[<SYMCRYPT_ $uc _STATE>];
                type Result = [<$lc HashResult>];

                fn get_hash_algorithm() -> PCSYMCRYPT_HASH {
                    unsafe {
                        symcrypt_sys::[<SymCrypt $lc Algorithm>]
                    }
                }

                fn hash(data: &[u8], result: &mut Self::Result) {
                    unsafe {
                        symcrypt_sys::[<SymCrypt $lc>](data.as_ptr(), data.len() as SIZE_T, result.as_mut_ptr());
                    }
                }

                unsafe fn stream_init(state: *mut Self::StreamState) {
                    unsafe {
                        symcrypt_sys::[<SymCrypt $lc Init>](state);
                    }
                }

                unsafe fn stream_append(state: *mut Self::StreamState, data: &[u8]) {
                    unsafe {
                        symcrypt_sys::[<SymCrypt $lc Append>](state, data.as_ptr(), data.len() as SIZE_T);
                    }
                }

                unsafe fn stream_result(state: *mut Self::StreamState, result: &mut Self::Result) {
                    unsafe {
                        symcrypt_sys::[<SymCrypt $lc Result>](state, result.as_mut_ptr());
                    }
                }
            }
        }
    };
}

define_hash_algorithm!(Md5, MD5);
define_hash_algorithm!(Sha1, SHA1);
define_hash_algorithm!(Sha256, SHA256);
define_hash_algorithm!(Sha384, SHA384);
define_hash_algorithm!(Sha512, SHA512);
define_hash_algorithm!(Sha3_256, SHA3_256);
define_hash_algorithm!(Sha3_384, SHA3_384);
define_hash_algorithm!(Sha3_512, SHA3_512);
