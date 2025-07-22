use core::fmt::Display;

use crate::constants::PamResultCode::{self, *};
use libc::c_int;

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(isize)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// PAM error codes
pub enum PamErrorCode {
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

impl PamErrorCode {
    pub fn repr(&self) -> c_int {
        match self {
            PamErrorCode::OPEN_ERR => PAM_OPEN_ERR as c_int,
            PamErrorCode::SYMBOL_ERR => PAM_SYMBOL_ERR as c_int,
            PamErrorCode::SERVICE_ERR => PAM_SERVICE_ERR as c_int,
            PamErrorCode::SYSTEM_ERR => PAM_SYSTEM_ERR as c_int,
            PamErrorCode::BUF_ERR => PAM_BUF_ERR as c_int,
            PamErrorCode::PERM_DENIED => PAM_PERM_DENIED as c_int,
            PamErrorCode::AUTH_ERR => PAM_AUTH_ERR as c_int,
            PamErrorCode::CRED_INSUFFICIENT => PAM_CRED_INSUFFICIENT as c_int,
            PamErrorCode::AUTHINFO_UNAVAIL => PAM_AUTHINFO_UNAVAIL as c_int,
            PamErrorCode::USER_UNKNOWN => PAM_USER_UNKNOWN as c_int,
            PamErrorCode::MAXTRIES => PAM_MAXTRIES as c_int,
            PamErrorCode::NEW_AUTHTOK_REQD => PAM_NEW_AUTHTOK_REQD as c_int,
            PamErrorCode::ACCT_EXPIRED => PAM_ACCT_EXPIRED as c_int,
            PamErrorCode::SESSION_ERR => PAM_SESSION_ERR as c_int,
            PamErrorCode::CRED_UNAVAIL => PAM_CRED_UNAVAIL as c_int,
            PamErrorCode::CRED_EXPIRED => PAM_CRED_EXPIRED as c_int,
            PamErrorCode::CRED_ERR => PAM_CRED_ERR as c_int,
            PamErrorCode::CONV_ERR => PAM_CONV_ERR as c_int,
            PamErrorCode::AUTHTOK_ERR => PAM_AUTHTOK_ERR as c_int,
            PamErrorCode::AUTHTOK_RECOVERY_ERR => PAM_AUTHTOK_RECOVERY_ERR as c_int,
            PamErrorCode::AUTHTOK_LOCK_BUSY => PAM_AUTHTOK_LOCK_BUSY as c_int,
            PamErrorCode::AUTHTOK_DISABLE_AGING => PAM_AUTHTOK_DISABLE_AGING as c_int,
            PamErrorCode::ABORT => PAM_ABORT as c_int,
            PamErrorCode::AUTHTOK_EXPIRED => PAM_AUTHTOK_EXPIRED as c_int,
            PamErrorCode::MODULE_UNKNOWN => PAM_MODULE_UNKNOWN as c_int,
            PamErrorCode::BAD_ITEM => PAM_BAD_ITEM as c_int,
            PamErrorCode::CONV_AGAIN => PAM_CONV_AGAIN as c_int,
            PamErrorCode::INCOMPLETE => PAM_INCOMPLETE as c_int,
            PamErrorCode::TRY_AGAIN => PAM_TRY_AGAIN as c_int,
            PamErrorCode::IGNORE => PAM_IGNORE as c_int,
            PamErrorCode::NO_MODULE_DATA => PAM_NO_MODULE_DATA as c_int,
        }
    }
}

impl From<PamResultCode> for PamErrorCode {
    fn from(value: PamResultCode) -> Self {
        match value {
            PAM_OPEN_ERR => PamErrorCode::OPEN_ERR,
            PAM_SYMBOL_ERR => PamErrorCode::SYMBOL_ERR,
            PAM_SERVICE_ERR => PamErrorCode::SERVICE_ERR,
            PAM_SYSTEM_ERR => PamErrorCode::SYSTEM_ERR,
            PAM_BUF_ERR => PamErrorCode::BUF_ERR,
            PAM_PERM_DENIED => PamErrorCode::PERM_DENIED,
            PAM_AUTH_ERR => PamErrorCode::AUTH_ERR,
            PAM_CRED_INSUFFICIENT => PamErrorCode::CRED_INSUFFICIENT,
            PAM_AUTHINFO_UNAVAIL => PamErrorCode::AUTHINFO_UNAVAIL,
            PAM_USER_UNKNOWN => PamErrorCode::USER_UNKNOWN,
            PAM_MAXTRIES => PamErrorCode::MAXTRIES,
            PAM_NEW_AUTHTOK_REQD => PamErrorCode::NEW_AUTHTOK_REQD,
            PAM_ACCT_EXPIRED => PamErrorCode::ACCT_EXPIRED,
            PAM_SESSION_ERR => PamErrorCode::SESSION_ERR,
            PAM_CRED_UNAVAIL => PamErrorCode::CRED_UNAVAIL,
            PAM_CRED_EXPIRED => PamErrorCode::CRED_EXPIRED,
            PAM_CRED_ERR => PamErrorCode::CRED_ERR,
            PAM_CONV_ERR => PamErrorCode::CONV_ERR,
            PAM_AUTHTOK_ERR => PamErrorCode::AUTHTOK_ERR,
            PAM_AUTHTOK_RECOVERY_ERR => PamErrorCode::AUTHTOK_RECOVERY_ERR,
            PAM_AUTHTOK_LOCK_BUSY => PamErrorCode::AUTHTOK_LOCK_BUSY,
            PAM_AUTHTOK_DISABLE_AGING => PamErrorCode::AUTHTOK_DISABLE_AGING,
            PAM_ABORT => PamErrorCode::ABORT,
            PAM_AUTHTOK_EXPIRED => PamErrorCode::AUTHTOK_EXPIRED,
            PAM_MODULE_UNKNOWN => PamErrorCode::MODULE_UNKNOWN,
            PAM_BAD_ITEM => PamErrorCode::BAD_ITEM,
            PAM_CONV_AGAIN => PamErrorCode::CONV_AGAIN,
            PAM_INCOMPLETE => PamErrorCode::INCOMPLETE,
            PAM_NO_MODULE_DATA => PamErrorCode::NO_MODULE_DATA,
            PAM_SUCCESS => unreachable!("PAM_SUCCESS is not managed here"),
            _ => unreachable!("unrecognised return value: {value}"),
        }
    }
}

impl Display for PamErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PamErrorCode::OPEN_ERR => write!(f, "OPEN_ERR"),
            PamErrorCode::SYMBOL_ERR => write!(f, "SYMBOL_ERR"),
            PamErrorCode::SERVICE_ERR => write!(f, "SERVICE_ERR"),
            PamErrorCode::SYSTEM_ERR => write!(f, "SYSTEM_ERR"),
            PamErrorCode::BUF_ERR => write!(f, "BUF_ERR"),
            PamErrorCode::PERM_DENIED => write!(f, "PERM_DENIED"),
            PamErrorCode::AUTH_ERR => write!(f, "AUTH_ERR"),
            PamErrorCode::CRED_INSUFFICIENT => write!(f, "CRED_INSUFFICIENT"),
            PamErrorCode::AUTHINFO_UNAVAIL => write!(f, "AUTHINFO_UNAVAIL"),
            PamErrorCode::USER_UNKNOWN => write!(f, "USER_UNKNOWN"),
            PamErrorCode::MAXTRIES => write!(f, "MAXTRIES"),
            PamErrorCode::NEW_AUTHTOK_REQD => write!(f, "NEW_AUTHTOK_REQD"),
            PamErrorCode::ACCT_EXPIRED => write!(f, "ACCT_EXPIRED"),
            PamErrorCode::SESSION_ERR => write!(f, "SESSION_ERR"),
            PamErrorCode::CRED_UNAVAIL => write!(f, "CRED_UNAVAIL"),
            PamErrorCode::CRED_EXPIRED => write!(f, "CRED_EXPIRED"),
            PamErrorCode::CRED_ERR => write!(f, "CRED_ERR"),
            PamErrorCode::CONV_ERR => write!(f, "CONV_ERR"),
            PamErrorCode::AUTHTOK_ERR => write!(f, "AUTHTOK_ERR"),
            PamErrorCode::AUTHTOK_RECOVERY_ERR => write!(f, "AUTHTOK_RECOVERY_ERR"),
            PamErrorCode::AUTHTOK_LOCK_BUSY => write!(f, "AUTHTOK_LOCK_BUSY"),
            PamErrorCode::AUTHTOK_DISABLE_AGING => write!(f, "AUTHTOK_DISABLE_AGING"),
            PamErrorCode::ABORT => write!(f, "ABORT"),
            PamErrorCode::AUTHTOK_EXPIRED => write!(f, "AUTHTOK_EXPIRED"),
            PamErrorCode::MODULE_UNKNOWN => write!(f, "MODULE_UNKNOWN"),
            PamErrorCode::BAD_ITEM => write!(f, "BAD_ITEM"),
            PamErrorCode::CONV_AGAIN => write!(f, "CONV_AGAIN"),
            PamErrorCode::INCOMPLETE => write!(f, "INCOMPLETE"),
            PamErrorCode::TRY_AGAIN => write!(f, "TRY_AGAIN"),
            PamErrorCode::IGNORE => write!(f, "IGNORE"),
            PamErrorCode::NO_MODULE_DATA => write!(f, "NO_MODULE_DATA"),
        }
    }
}

/*
impl From<c_int> for PamErrorCode {
    fn from(value: c_int) -> Self {
        PamErrorCode::from(PamResultCode::from(value))
    }
}
*/

/// Type alias for the result of most PAM methods.
pub type PamResult<T> = std::result::Result<T, PamErrorCode>;
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
            err => Err(PamErrorCode::from(err)),
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
