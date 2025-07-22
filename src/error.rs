use core::fmt::Display;

use crate::constants::PamResultCode::{self, *};
use libc::c_int;

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(isize)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// PAM error codes
pub enum ErrorCode {
    OPEN_ERR = PAM_OPEN_ERR as isize,
    SYMBOL_ERR = PAM_SYMBOL_ERR as isize,
    SERVICE_ERR = PAM_SERVICE_ERR as isize,
    SYSTEM_ERR = PAM_SYSTEM_ERR as isize,
    BUF_ERR = PAM_BUF_ERR as isize,
    PERM_DENIED = PAM_PERM_DENIED as isize,
    AUTH_ERR = PAM_AUTH_ERR as isize,
    CRED_INSUFFICIENT = PAM_CRED_INSUFFICIENT as isize,
    AUTHINFO_UNAVAIL = PAM_AUTHINFO_UNAVAIL as isize,
    USER_UNKNOWN = PAM_USER_UNKNOWN as isize,
    MAXTRIES = PAM_MAXTRIES as isize,
    NEW_AUTHTOK_REQD = PAM_NEW_AUTHTOK_REQD as isize,
    ACCT_EXPIRED = PAM_ACCT_EXPIRED as isize,
    SESSION_ERR = PAM_SESSION_ERR as isize,
    CRED_UNAVAIL = PAM_CRED_UNAVAIL as isize,
    CRED_EXPIRED = PAM_CRED_EXPIRED as isize,
    CRED_ERR = PAM_CRED_ERR as isize,
    CONV_ERR = PAM_CONV_ERR as isize,
    AUTHTOK_ERR = PAM_AUTHTOK_ERR as isize,
    AUTHTOK_RECOVERY_ERR = PAM_AUTHTOK_RECOVERY_ERR as isize,
    AUTHTOK_LOCK_BUSY = PAM_AUTHTOK_LOCK_BUSY as isize,
    AUTHTOK_DISABLE_AGING = PAM_AUTHTOK_DISABLE_AGING as isize,
    ABORT = PAM_ABORT as isize,
    AUTHTOK_EXPIRED = PAM_AUTHTOK_EXPIRED as isize,
    MODULE_UNKNOWN = PAM_MODULE_UNKNOWN as isize,
    BAD_ITEM = PAM_BAD_ITEM as isize,
    CONV_AGAIN = PAM_CONV_AGAIN as isize,
    INCOMPLETE = PAM_INCOMPLETE as isize,
    TRY_AGAIN = PAM_TRY_AGAIN as isize,
    IGNORE = PAM_IGNORE as isize,
    NO_MODULE_DATA = PAM_NO_MODULE_DATA as isize,
}

impl ErrorCode {
    pub fn repr(&self) -> c_int {
        match self {
            ErrorCode::OPEN_ERR => PAM_OPEN_ERR as c_int,
            ErrorCode::SYMBOL_ERR => PAM_SYMBOL_ERR as c_int,
            ErrorCode::SERVICE_ERR => PAM_SERVICE_ERR as c_int,
            ErrorCode::SYSTEM_ERR => PAM_SYSTEM_ERR as c_int,
            ErrorCode::BUF_ERR => PAM_BUF_ERR as c_int,
            ErrorCode::PERM_DENIED => PAM_PERM_DENIED as c_int,
            ErrorCode::AUTH_ERR => PAM_AUTH_ERR as c_int,
            ErrorCode::CRED_INSUFFICIENT => PAM_CRED_INSUFFICIENT as c_int,
            ErrorCode::AUTHINFO_UNAVAIL => PAM_AUTHINFO_UNAVAIL as c_int,
            ErrorCode::USER_UNKNOWN => PAM_USER_UNKNOWN as c_int,
            ErrorCode::MAXTRIES => PAM_MAXTRIES as c_int,
            ErrorCode::NEW_AUTHTOK_REQD => PAM_NEW_AUTHTOK_REQD as c_int,
            ErrorCode::ACCT_EXPIRED => PAM_ACCT_EXPIRED as c_int,
            ErrorCode::SESSION_ERR => PAM_SESSION_ERR as c_int,
            ErrorCode::CRED_UNAVAIL => PAM_CRED_UNAVAIL as c_int,
            ErrorCode::CRED_EXPIRED => PAM_CRED_EXPIRED as c_int,
            ErrorCode::CRED_ERR => PAM_CRED_ERR as c_int,
            ErrorCode::CONV_ERR => PAM_CONV_ERR as c_int,
            ErrorCode::AUTHTOK_ERR => PAM_AUTHTOK_ERR as c_int,
            ErrorCode::AUTHTOK_RECOVERY_ERR => PAM_AUTHTOK_RECOVERY_ERR as c_int,
            ErrorCode::AUTHTOK_LOCK_BUSY => PAM_AUTHTOK_LOCK_BUSY as c_int,
            ErrorCode::AUTHTOK_DISABLE_AGING => PAM_AUTHTOK_DISABLE_AGING as c_int,
            ErrorCode::ABORT => PAM_ABORT as c_int,
            ErrorCode::AUTHTOK_EXPIRED => PAM_AUTHTOK_EXPIRED as c_int,
            ErrorCode::MODULE_UNKNOWN => PAM_MODULE_UNKNOWN as c_int,
            ErrorCode::BAD_ITEM => PAM_BAD_ITEM as c_int,
            ErrorCode::CONV_AGAIN => PAM_CONV_AGAIN as c_int,
            ErrorCode::INCOMPLETE => PAM_INCOMPLETE as c_int,
            ErrorCode::TRY_AGAIN => PAM_TRY_AGAIN as c_int,
            ErrorCode::IGNORE => PAM_IGNORE as c_int,
            ErrorCode::NO_MODULE_DATA => PAM_NO_MODULE_DATA as c_int,
        }
    }
}

impl From<PamResultCode> for ErrorCode {
    fn from(value: PamResultCode) -> Self {
        match value {
            PAM_OPEN_ERR => ErrorCode::OPEN_ERR,
            PAM_SYMBOL_ERR => ErrorCode::SYMBOL_ERR,
            PAM_SERVICE_ERR => ErrorCode::SERVICE_ERR,
            PAM_SYSTEM_ERR => ErrorCode::SYSTEM_ERR,
            PAM_BUF_ERR => ErrorCode::BUF_ERR,
            PAM_PERM_DENIED => ErrorCode::PERM_DENIED,
            PAM_AUTH_ERR => ErrorCode::AUTH_ERR,
            PAM_CRED_INSUFFICIENT => ErrorCode::CRED_INSUFFICIENT,
            PAM_AUTHINFO_UNAVAIL => ErrorCode::AUTHINFO_UNAVAIL,
            PAM_USER_UNKNOWN => ErrorCode::USER_UNKNOWN,
            PAM_MAXTRIES => ErrorCode::MAXTRIES,
            PAM_NEW_AUTHTOK_REQD => ErrorCode::NEW_AUTHTOK_REQD,
            PAM_ACCT_EXPIRED => ErrorCode::ACCT_EXPIRED,
            PAM_SESSION_ERR => ErrorCode::SESSION_ERR,
            PAM_CRED_UNAVAIL => ErrorCode::CRED_UNAVAIL,
            PAM_CRED_EXPIRED => ErrorCode::CRED_EXPIRED,
            PAM_CRED_ERR => ErrorCode::CRED_ERR,
            PAM_CONV_ERR => ErrorCode::CONV_ERR,
            PAM_AUTHTOK_ERR => ErrorCode::AUTHTOK_ERR,
            PAM_AUTHTOK_RECOVERY_ERR => ErrorCode::AUTHTOK_RECOVERY_ERR,
            PAM_AUTHTOK_LOCK_BUSY => ErrorCode::AUTHTOK_LOCK_BUSY,
            PAM_AUTHTOK_DISABLE_AGING => ErrorCode::AUTHTOK_DISABLE_AGING,
            PAM_ABORT => ErrorCode::ABORT,
            PAM_AUTHTOK_EXPIRED => ErrorCode::AUTHTOK_EXPIRED,
            PAM_MODULE_UNKNOWN => ErrorCode::MODULE_UNKNOWN,
            PAM_BAD_ITEM => ErrorCode::BAD_ITEM,
            PAM_CONV_AGAIN => ErrorCode::CONV_AGAIN,
            PAM_INCOMPLETE => ErrorCode::INCOMPLETE,
            PAM_SUCCESS => unreachable!("PAM_SUCCESS is not managed here"),
            _ => unreachable!("unrecognised return value: {value}"),
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorCode::OPEN_ERR => write!(f, "OPEN_ERR"),
            ErrorCode::SYMBOL_ERR => write!(f, "SYMBOL_ERR"),
            ErrorCode::SERVICE_ERR => write!(f, "SERVICE_ERR"),
            ErrorCode::SYSTEM_ERR => write!(f, "SYSTEM_ERR"),
            ErrorCode::BUF_ERR => write!(f, "BUF_ERR"),
            ErrorCode::PERM_DENIED => write!(f, "PERM_DENIED"),
            ErrorCode::AUTH_ERR => write!(f, "AUTH_ERR"),
            ErrorCode::CRED_INSUFFICIENT => write!(f, "CRED_INSUFFICIENT"),
            ErrorCode::AUTHINFO_UNAVAIL => write!(f, "AUTHINFO_UNAVAIL"),
            ErrorCode::USER_UNKNOWN => write!(f, "USER_UNKNOWN"),
            ErrorCode::MAXTRIES => write!(f, "MAXTRIES"),
            ErrorCode::NEW_AUTHTOK_REQD => write!(f, "NEW_AUTHTOK_REQD"),
            ErrorCode::ACCT_EXPIRED => write!(f, "ACCT_EXPIRED"),
            ErrorCode::SESSION_ERR => write!(f, "SESSION_ERR"),
            ErrorCode::CRED_UNAVAIL => write!(f, "CRED_UNAVAIL"),
            ErrorCode::CRED_EXPIRED => write!(f, "CRED_EXPIRED"),
            ErrorCode::CRED_ERR => write!(f, "CRED_ERR"),
            ErrorCode::CONV_ERR => write!(f, "CONV_ERR"),
            ErrorCode::AUTHTOK_ERR => write!(f, "AUTHTOK_ERR"),
            ErrorCode::AUTHTOK_RECOVERY_ERR => write!(f, "AUTHTOK_RECOVERY_ERR"),
            ErrorCode::AUTHTOK_LOCK_BUSY => write!(f, "AUTHTOK_LOCK_BUSY"),
            ErrorCode::AUTHTOK_DISABLE_AGING => write!(f, "AUTHTOK_DISABLE_AGING"),
            ErrorCode::ABORT => write!(f, "ABORT"),
            ErrorCode::AUTHTOK_EXPIRED => write!(f, "AUTHTOK_EXPIRED"),
            ErrorCode::MODULE_UNKNOWN => write!(f, "MODULE_UNKNOWN"),
            ErrorCode::BAD_ITEM => write!(f, "BAD_ITEM"),
            ErrorCode::CONV_AGAIN => write!(f, "CONV_AGAIN"),
            ErrorCode::INCOMPLETE => write!(f, "INCOMPLETE"),
            ErrorCode::TRY_AGAIN => write!(f, "TRY_AGAIN"),
            ErrorCode::IGNORE => write!(f, "IGNORE"),
            ErrorCode::NO_MODULE_DATA => write!(f, "NO_MODULE_DATA"),
        }
    }
}

/*
impl From<c_int> for ErrorCode {
    fn from(value: c_int) -> Self {
        ErrorCode::from(PamResultCode::from(value))
    }
}
*/

/// Type alias for the result of most PAM methods.
pub type PamResult<T> = std::result::Result<T, ErrorCode>;
// Type alias for the result of PAM methods that pass back a consumed struct
// on error.
//pub type ExtResult<T, P> = std::result::Result<T, ErrorWith<P>>;

impl<T> From<PamResultCode> for PamResult<T>
where
    T: Default,
{
    fn from(value: PamResultCode) -> Self {
        match value {
            PAM_SUCCESS => Ok(T::default()),
            err => Err(ErrorCode::from(err)),
        }
    }
}

impl<T> From<PamResult<T>> for PamResultCode {
    fn from(value: PamResult<T>) -> Self {
        match value {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(err) => PamResultCode::from(err as c_int),
        }
    }
}
