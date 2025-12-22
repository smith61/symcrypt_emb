use core::ptr;

use paste::paste;
use symcrypt_sys::{PCSYMCRYPT_HASH, SIZE_T};

use crate::{Zeroable, ptr::UniquePointer, symcrypt_init, symcrypt_wipe};

pub trait HashAlgorithm {
    type StreamState: Zeroable + Default;
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

            #[derive(Clone, Copy, Default)]
            pub struct [<$lc HashAlgorithm>];

            pub type [<$lc HashResult>] = [u8; symcrypt_sys::[<SYMCRYPT_ $uc _RESULT_SIZE>] as usize];
            pub type [<$lc UninitializedHasher>] = UninitializedHasher<[<$lc HashAlgorithm>]>;
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

#[cfg(test)]
mod test {
    use crate::hash::{
        Md5Hasher, Md5UninitializedHasher, Sha1Hasher, Sha1UninitializedHasher, Sha3_256Hasher,
        Sha3_256UninitializedHasher, Sha3_384Hasher, Sha3_384UninitializedHasher, Sha3_512Hasher,
        Sha3_512UninitializedHasher, Sha256Hasher, Sha256UninitializedHasher, Sha384Hasher,
        Sha384UninitializedHasher, Sha512Hasher, Sha512UninitializedHasher,
    };

    static LOREM_IPSUM: &'static str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed dapibus consequat nisi nec dictum. Duis a tempor diam. Suspendisse a justo neque. Nullam laoreet bibendum lectus. Morbi at dapibus odio. Phasellus gravida lacus non tortor cursus, quis aliquam turpis mollis. Ut et dui tristique, blandit erat in, aliquam mauris.";

    #[test]
    fn test_md5() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Md5UninitializedHasher::default();
        let mut hasher = Md5Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "B78AD3014B1E0FC9F75AFEF1BBBDDCD6"
            );
        }
    }

    #[test]
    fn test_sha1() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha1UninitializedHasher::default();
        let mut hasher = Sha1Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "BAE2F27CB983CDBE0FD0FBFE9674DFC7176A3C92"
            );
        }
    }

    #[test]
    fn test_sha256() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha256UninitializedHasher::default();
        let mut hasher = Sha256Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "35B7DA1BC11818280EFB28B15301121A3A71FDE0C32679BB24E2429326DAAAF4"
            );
        }
    }

    #[test]
    fn test_sha384() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha384UninitializedHasher::default();
        let mut hasher = Sha384Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "19C1A1B528B325D1678187F7134B68BA6403958142F412B3A62FDD18E7F99E1E314F164A6EA2F2E4C82DF3505C30DD1B"
            );
        }
    }

    #[test]
    fn test_sha512() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha512UninitializedHasher::default();
        let mut hasher = Sha512Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "24F48B45BE5CAB1DF306DF7FC2C7B3257BC1BE2EBD6A2DE179D616C5B60CDA8EE7B587DA2CD704BC9876A823D991F19F569A3E9D8461195E7356318D0580F000"
            );
        }
    }

    #[test]
    fn test_sha3_256() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha3_256UninitializedHasher::default();
        let mut hasher = Sha3_256Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "48C7F5CDDBEF9CBBF47093F0C214334AF1663EAF6C0BA47F932CBCD341DDFBBF"
            );
        }
    }

    #[test]
    fn test_sha3_384() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha3_384UninitializedHasher::default();
        let mut hasher = Sha3_384Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "90B0B38BAE616DC696E9A625AF2D522CA5022D9196E758CA982F4D8F07BA62334A16DC02C113B06C777A9DBBEFC9EC2A"
            );
        }
    }

    #[test]
    fn test_sha3_512() {
        let as_bytes = LOREM_IPSUM.as_bytes();
        let mut hasher_storage = Sha3_512UninitializedHasher::default();
        let mut hasher = Sha3_512Hasher::new(&mut hasher_storage);
        for chunk_size in 1..as_bytes.len() {
            for chunk in as_bytes.chunks(chunk_size) {
                hasher.hash(chunk);
            }

            let mut result = [0; _];
            hasher = hasher.complete(&mut result);

            assert_eq!(
                hex::encode_upper(&result),
                "311306FFE17D714047DAE9BBAF9A326264602B356DF5C9148DC534CBB1491EF8914418047235DFCF4041B91BFF066491291FBB860F7F62B7117AF4F01921D982"
            );
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod std_test {
    use static_assertions::assert_impl_all;

    use crate::hash::{Md5Hasher, Md5HasherRefMut};

    #[test]
    fn test_auto_traits() {
        assert_impl_all!(Md5Hasher<&'static mut _>: Send, Sync);
        assert_impl_all!(Md5Hasher<Box<_>>: Send, Sync);
        assert_impl_all!(Md5HasherRefMut<'static>: Send, Sync);
    }
}
