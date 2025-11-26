use core::ops::Deref;

pub unsafe trait OwningPointer: Deref {
    fn into_raw(self) -> *const Self::Target;
    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target>;
    unsafe fn from_raw(this: *const Self::Target) -> Self;
}

pub unsafe trait SharedPointer: OwningPointer + Clone {}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::boxed::Box<T> {
    fn into_raw(self) -> *const Self::Target {
        std::boxed::Box::leak(self) as *const Self::Target
    }

    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        Some(&mut *self)
    }

    unsafe fn from_raw(this: *const Self::Target) -> Self {
        unsafe { std::boxed::Box::from_raw(this as *mut Self::Target) }
    }
}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::rc::Rc<T> {
    fn into_raw(self) -> *const Self::Target {
        std::rc::Rc::into_raw(self)
    }

    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        std::rc::Rc::get_mut(self)
    }

    unsafe fn from_raw(this: *const Self::Target) -> Self {
        unsafe { std::rc::Rc::from_raw(this) }
    }
}

#[cfg(feature = "std")]
unsafe impl<T> SharedPointer for std::rc::Rc<T> {}

#[cfg(feature = "std")]
unsafe impl<T> OwningPointer for std::sync::Arc<T> {
    fn into_raw(self) -> *const Self::Target {
        std::sync::Arc::into_raw(self)
    }

    fn try_get_mut<'a>(&'a mut self) -> Option<&'a mut Self::Target> {
        std::sync::Arc::get_mut(self)
    }

    unsafe fn from_raw(this: *const Self::Target) -> Self {
        unsafe { std::sync::Arc::from_raw(this) }
    }
}

#[cfg(feature = "std")]
unsafe impl<T> SharedPointer for std::sync::Arc<T> {}
