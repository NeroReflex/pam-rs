use core::{
    borrow::{Borrow, BorrowMut},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    ptr::{drop_in_place, NonNull},
};

/// A pointer type for C-compatible heap allocation.
///
/// Designed with a [`Box`]-like interface.
#[derive(Debug)]
#[repr(transparent)]
pub struct CBox<T: ?Sized>(NonNull<T>);

impl<T> CBox<T> {
    pub fn new(count: usize) -> Self {
        assert!(count > 0);

        let ptr = unsafe { libc::calloc(std::mem::size_of::<T>(), count) } as *mut T;

        match NonNull::new(ptr) {
            Some(content) => Self(content),
            None => panic!("Error in calloc"),
        }
    }

    /// Tries to allocate nulled memory for `len` elements of `T` on the heap.
    ///
    /// If you can guarantee that zeroed memory is a valid representation
    /// for T, use [`assume_all_init()`][`Self::assume_all_init()`] to
    /// strip the [`MaybeUninit`][`MaybeUninit`] wrapper.
    pub fn new_zeroed_slice(len: usize) -> Option<CBox<[MaybeUninit<T>]>> {
        let size = std::cmp::max(std::mem::size_of::<T>(), 1);

        let ptr = unsafe { libc::calloc(len, size) }.cast();

        match CBox::wrap_slice(ptr, len) {
            None => return None,
            Some(result) => Some(result),
        }
    }

    /// Internal: Wraps a pointer to a slice of `len` elements of `T`
    ///
    /// Returns `None` if `raw` is null.
    fn wrap_slice(raw: *mut T, len: usize) -> Option<CBox<[T]>> {
        let slice = unsafe { std::slice::from_raw_parts_mut(raw, len) };
        CBox::wrap(slice)
    }

    /// Takes ownership of a pointer to a C array/slice.
    ///
    /// The pointer must have been allocated with `malloc` or `calloc`.
    ///
    /// # Panics
    /// Panics if `raw` is null.
    pub unsafe fn from_raw_slice(raw: *mut T, len: usize) -> CBox<[T]> {
        CBox::wrap_slice(raw, len).expect("cannot construct CBox from null pointer")
    }
}

impl<T: ?Sized> Drop for CBox<T> {
    fn drop(&mut self) {
        let ptr = self.0.as_ptr();
        unsafe {
            drop_in_place(ptr);
            libc::free(ptr.cast())
        }
    }
}

impl<T> From<T> for CBox<T> {
    fn from(value: T) -> Self {
        let res = Self::new(1);

        unsafe {
            libc::memcpy(
                res.0.as_ptr().cast(),
                (&value as *const T).cast(),
                std::mem::size_of_val(&value),
            )
        };

        res
    }
}

impl<T: ?Sized> Deref for CBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for CBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}

impl<T: ?Sized> AsMut<T> for CBox<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}

impl<T: ?Sized> AsRef<T> for CBox<T> {
    fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }
}

impl<T: ?Sized> Borrow<T> for CBox<T> {
    #[inline]
    fn borrow(&self) -> &T {
        self
    }
}

impl<T: ?Sized> BorrowMut<T> for CBox<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        self
    }
}

impl<T> CBox<T>
where
    T: ?Sized,
{
    /// Internal: Wraps a pointer to a `T`
    #[inline]
    fn wrap(raw: *mut T) -> Option<Self> {
        NonNull::new(raw).map(Self)
    }

    /// Takes ownership of a pointer
    ///
    /// The pointer must have been allocated with `malloc` or `calloc`.
    ///
    /// # Panics
    /// Panics if `raw` is null.
    pub unsafe fn from_raw(raw: *mut T) -> CBox<T> {
        Self::wrap(raw).expect("cannot construct CBox from null pointer")
    }

    /// Consumes the `CBox`, returning the wrapped raw pointer.
    ///
    /// The receiver of the pointer is responsible for the destruction and
    /// deallocation of T.
    ///
    /// The memory may be released with [`libc::free()`], but then no
    /// destructors will be called. Use [`CBox::from_raw()`] instead to put
    /// the cleanup responsibility back to `CBox`.
    pub const fn into_raw(b: CBox<T>) -> *mut T {
        let ptr: NonNull<T> = b.0;
        std::mem::forget(b);
        ptr.as_ptr()
    }
}

impl<T> CBox<[MaybeUninit<T>]> {
    /// Converts a `CBox` containing `[MaybeUninit<T>]` to `CBox<[T]>` by
    /// assuming all the elements are in an initialized state.
    ///
    /// # Safety
    /// It is up to the caller to guarantee that the `MaybeUninit<T>` elements
    /// really are in an initialized state. Calling this when the content is
    /// not yet fully initialized causes undefined behavior.
    pub const unsafe fn assume_all_init(self) -> CBox<[T]> {
        CBox::<[T]>(NonNull::new_unchecked(CBox::into_raw(self) as *mut _))
    }
}
