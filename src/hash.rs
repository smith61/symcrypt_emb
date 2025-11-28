use core::ptr::addr_of_mut;

use paste::paste;
use symcrypt_sys::{PCSYMCRYPT_HASH, SIZE_T};

use crate::refs::{self, SecureZeroable};

pub trait HashAlgorithm {
    type StreamState: SecureZeroable;
    type Result;

    fn get_hash_algorithm() -> PCSYMCRYPT_HASH;

    fn hash(data: &[u8], result: &mut Self::Result);

    unsafe fn stream_init(state: *mut Self::StreamState);
    unsafe fn stream_append(state: *mut Self::StreamState, data: &[u8]);
    unsafe fn stream_result(state: *mut Self::StreamState, result: &mut Self::Result);
}

pub struct UnitializedHasher<T: HashAlgorithm>(T::StreamState);

impl<T: HashAlgorithm> UnitializedHasher<T> {
    pub fn initialize<'a>(&'a mut self) -> Hasher<'a, T> {
        unsafe {
            T::stream_init(addr_of_mut!(self.0));
            Hasher(refs::Initialized::new(&mut self.0))
        }
    }
}

pub struct Hasher<'a, T: HashAlgorithm>(refs::Initialized<'a, T::StreamState>);

impl<'a, T: HashAlgorithm> Hasher<'a, T> {
    pub fn as_ref_mut<'b>(&'b mut self) -> HasherRefMut<'b, T> {
        HasherRefMut(self.0.as_ref_mut())
    }

    pub fn hash(&mut self, data: &[u8]) {
        self.as_ref_mut().hash(data);
    }

    pub fn complete(mut self, result: &mut T::Result) -> Hasher<'a, T> {
        unsafe {
            T::stream_result(self.0.get_state_ptr_mut(), result);
        }

        self
    }
}

pub struct HasherRefMut<'a, T: HashAlgorithm>(refs::InitializedRefMut<'a, T::StreamState>);

impl<'a, T: HashAlgorithm> HasherRefMut<'a, T> {
    pub fn as_ref_mut<'b>(&'b mut self) -> HasherRefMut<'b, T> {
        HasherRefMut(self.0.as_ref_mut())
    }

    pub fn hash(&mut self, data: &[u8]) {
        unsafe {
            T::stream_append(self.0.get_state_ptr_mut(), data);
        }
    }
}

macro_rules! define_hash_algorithm {
    ($lc: ident, $uc: ident) => {
        paste! {
            pub struct [<$lc HashAlgorithm>];

            pub type [<$lc HashResult>] = [u8; symcrypt_sys::[<SYMCRYPT_ $uc _RESULT_SIZE>] as usize];
            pub type [<$lc Hasher>]<'a> = Hasher<'a, [<$lc HashAlgorithm>]>;
            pub type [<$lc HasherRefMut>]<'a> = HasherRefMut<'a, [<$lc HashAlgorithm>]>;

            unsafe impl SecureZeroable for symcrypt_sys::[<SYMCRYPT_ $uc _STATE>] { }

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
