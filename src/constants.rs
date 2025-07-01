use libc::{c_int, c_uint};
use strum::Display;

// TODO: Import constants from C header file at compile time.

pub type PamFlag = c_uint;
pub type PamItemType = c_int;

// The Linux-PAM flags
// see /usr/include/security/_pam_types.h
pub const PAM_SILENT: PamFlag = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x0001;
pub const PAM_ESTABLISH_CRED: PamFlag = 0x0002;
pub const PAM_DELETE_CRED: PamFlag = 0x0004;
pub const PAM_REINITIALIZE_CRED: PamFlag = 0x0008;
pub const PAM_REFRESH_CRED: PamFlag = 0x0010;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0020;

pub const PAM_USER_PROMPT: i32 = 9;

// Message styles
#[allow(non_camel_case_types, clippy::upper_case_acronyms, dead_code)]
#[derive(Debug, Display, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PamMessageStyle {
    PAM_PROMPT_ECHO_OFF = 1,
    PAM_PROMPT_ECHO_ON = 2,
    PAM_ERROR_MSG = 3,
    PAM_TEXT_INFO = 4,

    /// yes/no/maybe conditionals
    #[cfg(target_os = "linux")]
    PAM_RADIO_TYPE = 5,

    #[cfg(target_os = "linux")]
    PAM_BINARY_PROMPT = 7,
}

// The Linux-PAM return values
// see /usr/include/security/_pam_types.h
#[allow(non_camel_case_types, clippy::upper_case_acronyms, dead_code)]
#[derive(Debug, Display, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(i32)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_CRED_INSUFFICIENT = 8,
    PAM_AUTHINFO_UNAVAIL = 9,
    PAM_USER_UNKNOWN = 10,
    PAM_MAXTRIES = 11,
    PAM_NEW_AUTHTOK_REQD = 12,
    PAM_ACCT_EXPIRED = 13,
    PAM_SESSION_ERR = 14,
    PAM_CRED_UNAVAIL = 15,
    PAM_CRED_EXPIRED = 16,
    PAM_CRED_ERR = 17,
    PAM_NO_MODULE_DATA = 18,
    PAM_CONV_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_TRY_AGAIN = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_AUTHTOK_EXPIRED = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_BAD_ITEM = 29,
    PAM_CONV_AGAIN = 30,
    PAM_INCOMPLETE = 31,
}

impl From<i32> for PamResultCode {
    fn from(value: i32) -> Self {
        unsafe { std::mem::transmute_copy(&value) }
    }
}
