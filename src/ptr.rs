use core::ops::{Deref, DerefMut};

///
/// An `OwningPointer` represents a pointer type that guarantees that:
/// 1. The pointed to type does not move
/// 2. Successive calls to deref/deref_mut return the same object
///
pub unsafe trait OwningPointer: Deref {
    ///
    /// `try_get_mut` attemps to return a mutable reference to the pointed
    /// to object. It should only return a mutable reference if this pointer:
    /// 1. Is a mutable pointer
    /// 2. There are no other references to the pointed to object
    ///
    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target>;
}

///
/// A `UniquePointer` represents a unique pointer type (ex. Box).
///
pub unsafe trait UniquePointer: OwningPointer + DerefMut {}

///
/// `SharedPointer` represents a shared pointer type (ex. Rc/Arc).
///
pub unsafe trait SharedPointer: OwningPointer + Clone {}

unsafe impl<'a, T> OwningPointer for &'a T {
    fn try_get_mut<'b>(&'b mut self) -> Option<&'b mut Self::Target> {
        None
    }
}

unsafe impl<'a, T> SharedPointer for &'a T {}

unsafe impl<'a, T> OwningPointer for &'a mut T {
    fn try_get_mut<'b>(&'b mut self) -> Option<&'b mut Self::Target> {
        Some(self)
    }
}

unsafe impl<'a, T> UniquePointer for &'a mut T {}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::boxed::Box<T> {
    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        Some(self)
    }
}

#[cfg(feature = "std")]
unsafe impl<T> UniquePointer for std::boxed::Box<T> {}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::rc::Rc<T> {
    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        std::rc::Rc::get_mut(self)
    }
}

#[cfg(feature = "std")]
unsafe impl<T> SharedPointer for std::rc::Rc<T> {}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::sync::Arc<T> {
    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        std::sync::Arc::get_mut(self)
    }
}

#[cfg(feature = "std")]
unsafe impl<T> SharedPointer for std::sync::Arc<T> {}
