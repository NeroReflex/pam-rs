use alloc::ffi::CString;
use core::{
    ffi::CStr,
    ptr::{self},
    slice,
};

use libc::{c_char, c_int};

use crate::{
    constants::{PamMessageStyle, PamResultCode},
    conversation::ConversationHandler,
    error::{PamErrorCode, PamResult},
    items::Item,
    responses::Responses,
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct PamMessage {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}
#[test]
fn bindgen_test_layout_pam_message() {
    const UNINIT: ::std::mem::MaybeUninit<PamMessage> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<PamMessage>(),
        16usize,
        concat!("Size of: ", stringify!(PamMessage))
    );
    assert_eq!(
        ::std::mem::align_of::<PamMessage>(),
        8usize,
        concat!("Alignment of ", stringify!(PamMessage))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg_style) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(PamMessage),
            "::",
            stringify!(msg_style)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
            "::",
            stringify!(msg)
        )
    );
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct PamResponse {
    pub(crate) resp: *mut c_char,
    pub(crate) resp_retcode: libc::c_int, // Unused - always zero
}

#[test]
fn bindgen_test_layout_pam_response() {
    const UNINIT: ::std::mem::MaybeUninit<PamResponse> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<PamResponse>(),
        16usize,
        concat!("Size of: ", stringify!(PamResponse))
    );
    assert_eq!(
        ::std::mem::align_of::<PamResponse>(),
        8usize,
        concat!("Alignment of ", stringify!(PamResponse))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(PamResponse),
            "::",
            stringify!(resp)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp_retcode) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(PamResponse),
            "::",
            stringify!(PamResponse)
        )
    );
}

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawPamConv {
    conv: unsafe extern "C" fn(
        num_msg: c_int,
        pam_message: *mut *const PamMessage,
        pam_response: *mut *mut PamResponse,
        appdata_ptr: *mut libc::c_void,
    ) -> PamResultCode,
    appdata_ptr: *mut libc::c_void,
}

impl RawPamConv {
    /// Extracts the pointer to the conversation handler of type `T`.
    ///
    /// Performs the reverse of [`into_pam_conv()`] (except for not rebuilding a `Box`).
    ///
    /// There is no check that `T` is the correct type. Unsafe code dereferencing
    /// the returned pointer must make sure that the types match.
    ///
    /// # Panics
    /// Panics on null pointers in the `pam_conv` structure.
    pub(crate) fn from_pam_conv<T>(conv: &RawPamConv) -> *mut T {
        //assert!(conv.conv.is_some());
        assert!(!conv.appdata_ptr.is_null());
        conv.appdata_ptr.cast()
    }
}

pub struct Conv<'a>(&'a RawPamConv);

impl<'a> Conv<'a> {
    /// Sends a message to the pam client.
    ///
    /// This will typically result in the user seeing a message or a prompt.
    /// There are several message styles available:
    ///
    /// - PAM_PROMPT_ECHO_OFF
    /// - PAM_PROMPT_ECHO_ON
    /// - PAM_ERROR_MSG
    /// - PAM_TEXT_INFO
    /// - PAM_RADIO_TYPE
    /// - PAM_BINARY_PROMPT
    ///
    /// Note that the user experience will depend on how the client implements
    /// these message styles - and not all applications implement all message
    /// styles.
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<&CStr>> {
        let mut resp_ptr: *mut PamResponse = ptr::null_mut();
        let msg_cstr = CString::new(msg).unwrap();

        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        let mut msg_ptr = &msg as *const PamMessage;

        let ret = unsafe {
            (self.0.conv)(
                1,
                &mut msg_ptr as *mut *const PamMessage,
                &mut resp_ptr,
                self.0.appdata_ptr,
            )
        };

        if PamResultCode::PAM_SUCCESS != ret {
            return Err(ret.into());
        }

        // PamResponse.resp is null for styles that don't return user input like
        // PAM_TEXT_INFO
        let response = unsafe { (*resp_ptr).resp };
        if response.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { CStr::from_ptr(response) }))
        }
    }
}

impl<'a> Item for Conv<'a> {
    type Raw = RawPamConv;

    fn type_id() -> crate::items::ItemType {
        crate::items::ItemType::Conv
    }

    unsafe fn from_raw(raw: *const Self::Raw) -> Self {
        Self(&*raw)
    }

    fn into_raw(self) -> *const Self::Raw {
        self.0 as _
    }
}

impl<'a> AsRef<RawPamConv> for Conv<'a> {
    fn as_ref(&self) -> &RawPamConv {
        self.0
    }
}

#[test]
fn bindgen_test_layout_pam_conv() {
    const UNINIT: ::std::mem::MaybeUninit<RawPamConv> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<RawPamConv>(),
        16usize,
        concat!("Size of: ", stringify!(RawPamConv))
    );
    assert_eq!(
        ::std::mem::align_of::<RawPamConv>(),
        8usize,
        concat!("Alignment of ", stringify!(RawPamConv))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).conv) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(RawPamConv),
            "::",
            stringify!(conv)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).appdata_ptr) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
            "::",
            stringify!(appdata_ptr)
        )
    );
}

/// Maximum supported message number
#[allow(clippy::cast_possible_wrap)]
const fn max_msg_num() -> isize {
    #[cfg(not(target_os = "solaris"))]
    {
        isize::MAX / size_of::<*const PamMessage>() as isize
    }

    #[cfg(target_os = "solaris")]
    {
        isize::MAX / size_of::<PamMessage>() as isize
    }
}

pub(crate) fn into_pam_conv<T: ConversationHandler>(callback: Box<T>) -> RawPamConv {
    RawPamConv {
        conv: pam_converse::<T>,
        appdata_ptr: Box::into_raw(callback).cast(),
    }
}

/// Conversation function C library callback.
///
/// Will be called by C code when a conversation is requested. Does sanity
/// checks, prepares a response buffer and calls the conversation function
/// identified by `T` and `appdata_ptr` for each message.
pub(crate) unsafe extern "C" fn pam_converse<T: ConversationHandler>(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> PamResultCode {
    const MAX_MSG_NUM: isize = max_msg_num();

    // Check for null pointers
    if msg.is_null()
        || out_resp.is_null()
        || appdata_ptr.is_null()
        || num_msg < 0
        || num_msg as isize > MAX_MSG_NUM
    {
        return PamResultCode::PAM_BUF_ERR;
    }

    // Extract conversation handler from `appdata_ptr`.
    // This is sound, as we did the reverse in `into_pam_conv`.
    let handler = &mut *(appdata_ptr.cast::<T>());

    // Prepare response buffer
    let mut responses = match Responses::new(num_msg as usize) {
        Ok(buf) => buf,
        Err(e) => return PamResultCode::from(e.repr()),
    };

    for (i, message) in
        unsafe { slice::from_raw_parts((*msg) as *const &PamMessage, num_msg as usize) }
            .as_ref()
            .iter()
            .enumerate()
    {
        let message_cstr = match msg.is_null() {
            true => CStr::from_bytes_with_nul_unchecked(b"\0"),
            false => CStr::from_ptr(message.msg),
        };

        let result = match message.msg_style {
            PamMessageStyle::PAM_PROMPT_ECHO_OFF => handler.prompt_echo_off(message_cstr),
            PamMessageStyle::PAM_PROMPT_ECHO_ON => handler.prompt_echo_on(message_cstr),
            PamMessageStyle::PAM_ERROR_MSG => {
                handler.error_msg(message_cstr);
                CString::new("").map_err(|_| PamErrorCode::CONV_ERR)
            }
            PamMessageStyle::PAM_TEXT_INFO => {
                handler.text_info(message_cstr);
                CString::new("").map_err(|_| PamErrorCode::CONV_ERR)
            }
            #[cfg(target_os = "linux")]
            PamMessageStyle::PAM_RADIO_TYPE => match handler.radio_prompt(message_cstr) {
                Ok(choice) => match choice {
                    true => CString::new("yes").map_err(|_| PamErrorCode::CONV_ERR),
                    false => CString::new("no").map_err(|_| PamErrorCode::CONV_ERR),
                },
                Err(err) => Err(err),
            },
            #[cfg(target_os = "linux")]
            PamMessageStyle::PAM_BINARY_PROMPT => todo!(),
        };

        // Process response and bail out on errors
        match result {
            Ok(response) => responses.put(i, Some(response)),
            Err(code) => return PamResultCode::from(code.repr()),
        }
    }

    // Transfer responses to caller and return.
    // Sound as long as the PAM modules play by the rules..
    *out_resp = responses.into();
    PamResultCode::PAM_SUCCESS
}
