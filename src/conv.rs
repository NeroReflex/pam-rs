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
    error::{ErrorCode, PamResult},
    items::Item,
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct pam_message {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}
#[test]
fn bindgen_test_layout_pam_message() {
    const UNINIT: ::std::mem::MaybeUninit<pam_message> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<pam_message>(),
        16usize,
        concat!("Size of: ", stringify!(pam_message))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_message>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_message))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg_style) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
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

pub(crate) type PamMessage = pam_message;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct pam_response {
    resp: *const c_char,
    resp_retcode: libc::c_int, // Unused - always zero
}
#[test]
fn bindgen_test_layout_pam_response() {
    const UNINIT: ::std::mem::MaybeUninit<pam_response> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<pam_response>(),
        16usize,
        concat!("Size of: ", stringify!(pam_response))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_response>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_response))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp_retcode) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp_retcode)
        )
    );
}

pub(crate) type PamResponse = pam_response;

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_conv {
    conv: unsafe extern "C" fn(
        num_msg: c_int,
        pam_message: *mut *const PamMessage,
        pam_response: *mut *mut PamResponse,
        appdata_ptr: *mut libc::c_void,
    ) -> PamResultCode,
    appdata_ptr: *mut libc::c_void,
}

impl pam_conv {
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

pub type RawPamConv = pam_conv;

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
                &mut msg_ptr as *mut *const pam_message,
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
    const UNINIT: ::std::mem::MaybeUninit<pam_conv> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<pam_conv>(),
        16usize,
        concat!("Size of: ", stringify!(pam_conv))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_conv>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_conv))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).conv) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
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
                CString::new("").map_err(|_| ErrorCode::CONV_ERR)
            }
            PamMessageStyle::PAM_TEXT_INFO => {
                handler.text_info(message_cstr);
                CString::new("").map_err(|_| ErrorCode::CONV_ERR)
            }
            #[cfg(target_os = "linux")]
            PamMessageStyle::PAM_RADIO_TYPE => match handler.radio_prompt(message_cstr) {
                Ok(choice) => match choice {
                    true => CString::new("yes").map_err(|_| ErrorCode::CONV_ERR),
                    false => CString::new("no").map_err(|_| ErrorCode::CONV_ERR),
                },
                Err(err) => Err(err),
            },
            #[cfg(target_os = "linux")]
            PamMessageStyle::PAM_BINARY_PROMPT => todo!(),
        };
    }

    /*
    // Prepare response buffer
    let mut responses = match ResponseBuffer::new(num_msg as isize) {
        Ok(buf) => buf,
        Err(e) => return e.code().repr(),
    };

    // Check preconditions for slice::from_raw_parts.
    // (the checks in `ResponseBuffer::new` are even stricter but better be
    // safe than sorry).
    if !(0..=MAX_MSG_NUM).contains(&(num_msg as isize)) {
        return ErrorCode::BUF_ERR as c_int;
    }

    let messages = msg_to_slice(&msg, num_msg);

    // Call conversation handler for each message
    for (i, message) in messages.iter().enumerate() {
        match message.msg_style as c_int {
            // Special case: experimental binary messages (Linux)
            #[cfg(target_os = "linux")]
            PamMessageStyle::PAM_BINARY_PROMPT => {
                let (type_, data) = msg_content_to_bin(&message.msg);
                let result = handler.binary_prompt(type_, data);
                match result {
                    Ok(response) => responses.put_binary(i, response.0, &response.1),
                    Err(code) => return code.repr(),
                }
            }
            // All other cases
            _ => {
                // Delegate to the correct handler method based on `msg_style`
                let result = match message.msg_style as c_int {
                    PamMessageStyle::PAM_PROMPT_ECHO_ON => {
                        let text = msg_content_as_cstr(&message.msg);
                        handler.prompt_echo_on(text).map(map_conv_string)
                    }
                    PamMessageStyle::PAM_PROMPT_ECHO_OFF => {
                        let text = msg_content_as_cstr(&message.msg);
                        handler.prompt_echo_off(text).map(map_conv_string)
                    }
                    PamMessageStyle::PAM_TEXT_INFO => {
                        let text = msg_content_as_cstr(&message.msg);
                        handler.text_info(text);
                        Ok(None)
                    }
                    PamMessageStyle::PAM_ERROR_MSG => {
                        let text = msg_content_as_cstr(&message.msg);
                        handler.error_msg(text);
                        Ok(None)
                    }
                    #[cfg(target_os = "linux")]
                    PamMessageStyle::PAM_RADIO_TYPE => {
                        let text = msg_content_to_cstr(&message.msg);
                        handler.radio_prompt(text).map(|b| {
                            if b {
                                CString::new("yes").ok()
                            } else {
                                CString::new("no").ok()
                            }
                        })
                    }
                    _ => Err(PamResultCode::PAM_CONV_ERR),
                };

                // Process response and bail out on errors
                match result {
                    Ok(response) => responses.put(i, response),
                    Err(code) => return code.repr(),
                }
            }
        }
    }

    // Transfer responses to caller and return.
    // Sound as long as the PAM modules play by the rules..
    *out_resp = responses.into();
    PamResultCode::PAM_SUCCESS

    */

    todo!()
}
