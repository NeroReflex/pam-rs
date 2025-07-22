use alloc::ffi::CString;

use crate::{
    c_box::CBox,
    conv::PamResponse,
    error::{PamErrorCode, PamResult},
};

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct Responses(CBox<[PamResponse]>);

impl Responses {
    /// Creates a new buffer for `len` PAM conversation responses.
    ///
    /// Fails with `Err(BUF_ERR)` if
    /// 1. `len` is non-positive,
    /// 2. `len` is so large, the total allocated memory would exceed [`isize::MAX`],
    /// 3. the memory could not be allocated.
    pub fn new(len: usize) -> PamResult<Self> {
        match len {
            1..=usize::MAX => match CBox::<PamResponse>::new_zeroed_slice(len as usize) {
                Some(result) => Ok(Self(unsafe { result.assume_all_init() })),
                None => Err(PamErrorCode::BUF_ERR),
            },
            _ => Err(PamErrorCode::BUF_ERR),
        }
    }

    /// Puts a response at the specified index slot.
    ///
    /// If the slot was already filled, the previous response will be lost.
    ///
    /// # Panics
    /// Panics if the index is out of range.
    #[inline]
    pub fn put(&mut self, index: usize, response: Option<CString>) {
        assert!(index < self.0.len());
        // Sound because of the bounds check above and because zeroed memory
        // is a valid representation for the contained structs.
        let dest = &mut self.0[index];

        // Free the old string if there was already one in this slot
        if !dest.resp.is_null() {
            unsafe { libc::free(dest.resp.cast()) };
        }

        // Copy the string into the struct, so that the resulting pointer can
        // be deallocated with `free()`. The use of `strdup` should be sound
        // here, because `CString::as_ptr()` guarantees to point to a valid
        // NULL-terminated string.
        *dest = match response {
            Some(text) => PamResponse {
                resp: unsafe { libc::strdup(text.as_ptr()) },
                resp_retcode: 0,
            },
            None => PamResponse {
                resp: std::ptr::null_mut(),
                resp_retcode: 0,
            },
        }
    }
}

/// Convert a `ResponseBuffer` into a mutable `PamResponse` array pointer.
///
/// This is mainly used for easy low-level interaction with the PAM
/// framework and the responsibility to call [`libc::free()`] on the
/// array pointer is moved to the caller!
impl From<Responses> for *mut PamResponse {
    fn from(mut buf: Responses) -> Self {
        let result = (buf.0.as_mut() as *mut [PamResponse]).cast();
        std::mem::forget(buf);
        result
    }
}
