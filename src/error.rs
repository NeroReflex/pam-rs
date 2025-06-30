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
        }
    }
    pub fn from_repr(x: c_int) -> Option<ErrorCode> {
		match PamResultCode::from(x) {
			PAM_OPEN_ERR => Some(ErrorCode::OPEN_ERR),
			PAM_SYMBOL_ERR => Some(ErrorCode::SYMBOL_ERR),
			PAM_SERVICE_ERR => Some(ErrorCode::SERVICE_ERR),
			PAM_SYSTEM_ERR => Some(ErrorCode::SYSTEM_ERR),
			PAM_BUF_ERR => Some(ErrorCode::BUF_ERR),
			PAM_PERM_DENIED => Some(ErrorCode::PERM_DENIED),
			PAM_AUTH_ERR => Some(ErrorCode::AUTH_ERR),
			PAM_CRED_INSUFFICIENT => Some(ErrorCode::CRED_INSUFFICIENT),
			PAM_AUTHINFO_UNAVAIL => Some(ErrorCode::AUTHINFO_UNAVAIL),
			PAM_USER_UNKNOWN => Some(ErrorCode::USER_UNKNOWN),
			PAM_MAXTRIES => Some(ErrorCode::MAXTRIES),
			PAM_NEW_AUTHTOK_REQD => Some(ErrorCode::NEW_AUTHTOK_REQD),
			PAM_ACCT_EXPIRED => Some(ErrorCode::ACCT_EXPIRED),
			PAM_SESSION_ERR => Some(ErrorCode::SESSION_ERR),
			PAM_CRED_UNAVAIL => Some(ErrorCode::CRED_UNAVAIL),
			PAM_CRED_EXPIRED => Some(ErrorCode::CRED_EXPIRED),
			PAM_CRED_ERR => Some(ErrorCode::CRED_ERR),
			PAM_CONV_ERR => Some(ErrorCode::CONV_ERR),
			PAM_AUTHTOK_ERR => Some(ErrorCode::AUTHTOK_ERR),
			PAM_AUTHTOK_RECOVERY_ERR => Some(ErrorCode::AUTHTOK_RECOVERY_ERR),
			PAM_AUTHTOK_LOCK_BUSY => Some(ErrorCode::AUTHTOK_LOCK_BUSY),
			PAM_AUTHTOK_DISABLE_AGING => Some(ErrorCode::AUTHTOK_DISABLE_AGING),
			PAM_ABORT => Some(ErrorCode::ABORT),
			PAM_AUTHTOK_EXPIRED => Some(ErrorCode::AUTHTOK_EXPIRED),
			PAM_MODULE_UNKNOWN => Some(ErrorCode::MODULE_UNKNOWN),
			PAM_BAD_ITEM => Some(ErrorCode::BAD_ITEM),
			PAM_CONV_AGAIN => Some(ErrorCode::CONV_AGAIN),
			PAM_INCOMPLETE => Some(ErrorCode::INCOMPLETE),
			_ => None,
		}
    }
}

pub type Error = ErrorCode;

/// Type alias for the result of most PAM methods.
pub type Result<T> = std::result::Result<T, Error>;
// Type alias for the result of PAM methods that pass back a consumed struct
// on error.
//pub type ExtResult<T, P> = std::result::Result<T, ErrorWith<P>>;