use crate::{
    constants::PamResultCode,
    conv::{Conv, RawPamConv},
    conversation::ConversationHandler,
    error::{PamErrorCode, PamResult},
    items::Item,
    module::PamHandle,
    session::{Session, SessionToken},
};
use alloc::{borrow::Cow, collections::HashMap, ffi::CString};
use bitflags::bitflags;
use core::{ffi::CStr, ptr::null};
use std::cell::Cell;
use std::marker::PhantomData;

bitflags! {
    /// Flags for most PAM functions
    #[allow(clippy::upper_case_acronyms)]
    #[repr(transparent)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(transparent))]
    #[derive(Default, Copy, Clone, PartialEq, Eq)]
    pub struct Flag: libc::c_int {
        /// Don't generate any messages
        const SILENT = crate::constants::PAM_SILENT as libc::c_int;
        /// Fail with `AUTH_ERROR` if the user has a null authentication token.
        const DISALLOW_NULL_AUTHTOK = crate::constants::PAM_DISALLOW_NULL_AUTHTOK as libc::c_int;
        /// Only update passwords that have aged.
        const CHANGE_EXPIRED_AUTHTOK = crate::constants::PAM_CHANGE_EXPIRED_AUTHTOK as libc::c_int;
        /// Set user credentials.
        const ESTABLISH_CRED = crate::constants::PAM_ESTABLISH_CRED as libc::c_int;
        /// Delete user credentials.
        const DELETE_CRED = crate::constants::PAM_DELETE_CRED as libc::c_int;
        /// Reinitialize user credentials.
        const REINITIALIZE_CRED = crate::constants::PAM_REINITIALIZE_CRED as libc::c_int;
        /// Extend lifetime of user credentials.
        const REFRESH_CRED = crate::constants::PAM_REFRESH_CRED as libc::c_int;
    }
}

#[allow(clippy::upper_case_acronyms)]
impl Flag {
    /// No flags; use default behaviour.
    pub const NONE: Flag = Flag::empty();
}

/// Main struct for PAM interaction
///
/// Manages a PAM context holding the transaction state.
///
/// See the [crate documentation][`crate`] for examples.
pub struct Context<ConvT> {
    pub(crate) handle: PamHandle,
    last_status: Cell<PamResultCode>,
    _conversation: PhantomData<ConvT>,
}

impl<ConvT> Context<ConvT> {
    #[cfg(any(target_os = "linux"))]
    pub fn authtok_type(&self) -> PamResult<String> {
        let ptr = self
            .handle
            .raw_get_item(crate::items::ItemType::AuthTokType)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    #[cfg(any(target_os = "linux"))]
    pub fn set_authtok_type(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::AuthTokType, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::AuthTokType, cstring.as_ptr().cast())
            }
        }
    }

    pub fn rhost(&self) -> PamResult<String> {
        let ptr = self.handle.raw_get_item(crate::items::ItemType::RHost)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    pub fn set_rhost(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::RHost, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::RHost, cstring.as_ptr().cast())
            }
        }
    }

    pub fn ruser(&self) -> PamResult<String> {
        let ptr = self.handle.raw_get_item(crate::items::ItemType::RUser)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    pub fn set_ruser(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::RUser, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::RUser, cstring.as_ptr().cast())
            }
        }
    }

    pub fn tty(&self) -> PamResult<String> {
        let ptr = self.handle.raw_get_item(crate::items::ItemType::Tty)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    pub fn set_tty(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::Tty, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::Tty, cstring.as_ptr().cast())
            }
        }
    }

    pub fn user(&self) -> PamResult<String> {
        let ptr = self.handle.raw_get_item(crate::items::ItemType::User)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    pub fn set_user(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::User, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::User, cstring.as_ptr().cast())
            }
        }
    }

    pub fn user_prompt(&self) -> PamResult<String> {
        let ptr = self
            .handle
            .raw_get_item(crate::items::ItemType::UserPrompt)?;
        if ptr.is_null() {
            return Err(PamErrorCode::PERM_DENIED);
        }
        let string = unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned();
        return Ok(string);
    }

    pub fn set_user_prompt(&mut self, value: Option<&str>) -> PamResult<()> {
        match value {
            None => self
                .handle
                .raw_set_item(crate::items::ItemType::UserPrompt, null()),
            Some(string) => {
                let cstring = CString::new(string).map_err(|_| PamErrorCode::BUF_ERR)?;
                self.handle
                    .raw_set_item(crate::items::ItemType::UserPrompt, cstring.as_ptr().cast())
            }
        }
    }
}

impl<ConvT> Context<ConvT>
where
    ConvT: ConversationHandler,
{
    /// Returns a pointer to the raw conversation handler
    ///
    /// # Panics
    /// May panic if the type of the handler isn't `ConvT` or if somehow
    /// extracting the handler from the PAM handle fails.
    #[inline]
    fn conversation_raw(&self) -> *mut ConvT {
        let ptr = self
            .handle
            .get_item::<Conv>() // questo vuole un PAM_CONV
            .expect("Extracting the conversation handler should never fail")
            .unwrap();

        RawPamConv::from_pam_conv::<ConvT>(ptr.as_ref())
    }

    /// Returns a reference to the conversation handler.
    #[inline]
    pub fn conversation(&self) -> &ConvT {
        let ptr: *const ConvT = self.conversation_raw();
        // Safety: the conversation handler is only set by `from_boxed_conv()` or `replace_handler()`
        // and these maintain that the installed handler is valid and of the correct type.
        unsafe { &*ptr }
    }

    /// Returns a mutable reference to the conversation handler.
    #[inline]
    pub fn conversation_mut(&mut self) -> &mut ConvT {
        let ptr = self.conversation_raw();
        // Safety: the conversation handler is only set by `from_boxed_conv()` or `replace_handler()`
        // and these maintain that the installed handler is valid and of the correct type.
        unsafe { &mut *ptr }
    }

    /// Creates a PAM context and starts a PAM transaction.
    ///
    /// # Parameters
    /// - `service` – Name of the service. The policy for the service will be
    ///   read from the file /etc/pam.d/*service_name*, falling back to
    ///   /etc/pam.conf.
    /// - `username` – Name of the target user. If `None`, the user will be
    ///   asked through the conversation handler if neccessary.
    /// - `conversation` – A conversation handler through which the user can be
    ///   asked for his username, password, etc. Use
    ///   [`conv_cli::Conversation`][`crate::conv_cli::Conversation`] for a command line
    ///   default implementation, [`conv_mock::Conversation`][`crate::conv_mock::Conversation`]
    ///   for fixed credentials or implement the [`ConversationHandler`] trait
    ///   for custom behaviour.
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `PamErrorCode::ABORT` – General failure
    /// - `PamErrorCode::BUF_ERR` – Memory allocation failure or null byte in
    ///   parameter.
    /// - `PamErrorCode::SYSTEM_ERR` – Other system error
    #[must_use]
    #[inline]
    pub fn new(service: &str, username: Option<&str>, conversation: ConvT) -> PamResult<Self> {
        // Wrap `conversation` in a box and delegate to `from_boxed_conv`
        Self::from_boxed_conv(service, username, Box::new(conversation))
    }

    /// Returns a copy of the PAM environment in this context.
    ///
    /// The contained variables represent the contents of the regular
    /// environment variables of the authenticated user when service is
    /// granted.
    ///
    /// The returned [`EnvList`] type is designed to ease handing the
    /// environment to [`std::process::Command::envs()`] and
    /// `nix::unistd::execve()`.
    #[must_use]
    #[inline]
    pub fn envlist(&self) -> HashMap<String, String> {
        self.handle.env_list()
    }

    /// Returns the value of a PAM environment variable.
    ///
    /// See [`crate::context::Context::getenv()`].
    #[must_use]
    #[inline]
    pub fn getenv<'b>(&self, name: Cow<'b, str>) -> Option<String> {
        self.handle.env_get(name)
    }

    /// Sets or unsets a PAM environment variable.
    ///
    /// Modifies the environment list in this PAM context. The `name_value`
    /// argument can take one of the following forms:
    /// - *NAME*=*value* – Set a variable to a given value. If it was already
    ///   set it is overwritten.
    /// - *NAME*= – Set a variable to the empty value. If it was already set
    ///   it is overwritten.
    /// - *NAME* – Delete a variable, if it exists.
    #[must_use]
    #[inline]
    pub fn putenv<'b>(&mut self, name_value: Cow<'b, str>) -> PamResult<()> {
        if name_value.contains("=") {
            let components = name_value
                .split("=")
                .into_iter()
                .map(|a| String::from(a))
                .collect::<Vec<String>>();
            if components.len() > 1 && components[1].len() > 0 {
                self.handle.env_set(
                    Cow::Borrowed(components[0].as_str()),
                    Cow::Borrowed(components[1].as_str()),
                )
            } else {
                self.handle.env_reset(Cow::Borrowed(components[0].as_str()))
            }
        } else {
            self.handle.env_remove(name_value)
        }
    }

    /// Creates a PAM context and starts a PAM transaction taking a boxed
    /// conversation handler.
    ///
    /// See [`new()`][`Self::new()`] for details.
    pub fn from_boxed_conv(
        service: &str,
        username: Option<&str>,
        boxed_conv: Box<ConvT>,
    ) -> PamResult<Self> {
        match unsafe { PamHandle::start(service.into(), username.map(|a| a.into()), boxed_conv) } {
            Ok(handle) => {
                let mut result = Self {
                    handle,
                    last_status: Cell::new(PamResultCode::PAM_SUCCESS),
                    _conversation: PhantomData,
                };

                // Initialize the conversation handler
                result.conversation_mut().init(username);
                Ok(result)
            }
            Err(err) => Err(err),
        }
    }

    /// Authenticates a user.
    ///
    /// The conversation handler may be called to ask the user for their name
    /// (especially if no initial username was provided), their password and
    /// possibly other tokens if e.g. two-factor authentication is required.
    /// Conversely the conversation handler may not be called if authentication
    /// is handled by other means, e.g. a fingerprint scanner.
    ///
    /// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
    /// [`Flag::DISALLOW_NULL_AUTHTOK`] (don't authenticate empty
    /// passwords).
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `ABORT` – Serious failure; the application should exit.
    /// - `AUTH_ERR` – The user was not authenticated.
    /// - `CRED_INSUFFICIENT` – The application does not have sufficient
    ///   credentials to authenticate the user.
    /// - `AUTHINFO_UNAVAIL` – Could not retrieve authentication information
    ///   due to e.g. network failure.
    /// - `MAXTRIES` – At least one module reached its retry limit. Do not
    /// - try again.
    /// - `USER_UNKNOWN` – User not known.
    /// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
    ///   again after the asynchronous conversation finished.
    #[inline]
    pub fn authenticate(&mut self, flags: Flag) -> PamResult<()> {
        self.handle.authenticate(flags.bits())
    }

    /// Validates user account authorization.
    ///
    /// Determines if the account is valid, not expired, and verifies other
    /// access restrictions. Usually used directly after authentication.
    /// The conversation handler may be called by some PAM module.
    ///
    /// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
    /// [`Flag::DISALLOW_NULL_AUTHTOK`] (demand password change on empty
    /// passwords).
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `ACCT_EXPIRED` – Account has expired.
    /// - `AUTH_ERR` – Authentication failure.
    /// - `NEW_AUTHTOK_REQD` – Password has expired. Use [`chauthtok()`] to let
    ///   the user change their password or abort.
    /// - `PERM_DENIED` – Permission denied
    /// - `USER_UNKNOWN` – User not known
    /// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
    ///   again after the asynchronous conversation finished.
    ///
    /// [`chauthtok()`]: `Self::chauthtok`
    #[inline]
    pub fn acct_mgmt(&mut self, flags: Flag) -> PamResult<()> {
        self.handle.acct_mgmt(flags.bits())
    }

    /// Fully reinitializes the user's credentials (if established).
    ///
    /// Reinitializes credentials like Kerberos tokens for when a session
    /// is already managed by another process. This is e.g. used in
    /// lockscreen applications to refresh the credentials of the desktop
    /// session.
    ///
    /// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `BUF_ERR` – Memory allocation error
    /// - `CRED_ERR` – Setting credentials failed
    /// - `CRED_UNAVAIL` – Failed to retrieve credentials
    /// - `SYSTEM_ERR` – Other system error
    /// - `USER_UNKNOWN` – User not known
    #[inline]
    pub fn reinitialize_credentials(&mut self, flags: Flag) -> PamResult<()> {
        self.handle
            .setcred((Flag::REINITIALIZE_CRED | flags).bits())
    }

    /// Changes a users password.
    ///
    /// The conversation handler will be used to request the new password
    /// and might query for the old one.
    ///
    /// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
    /// [`Flag::CHANGE_EXPIRED_AUTHTOK`] (only initiate change for
    /// expired passwords).
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `AUTHTOK_ERR` – Unable to obtain the new password
    /// - `AUTHTOK_RECOVERY_ERR` – Unable to obtain the old password
    /// - `AUTHTOK_LOCK_BUSY` – Authentication token is currently locked
    /// - `AUTHTOK_DISABLE_AGING` – Password aging is disabled (password may
    ///   be unchangeable in at least one module)
    /// - `PERM_DENIED` – Permission denied
    /// - `TRY_AGAIN` – Not all modules were able to prepare an authentication
    ///   token update. Nothing was changed.
    /// - `USER_UNKNOWN` – User not known
    /// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
    ///   again after the asynchronous conversation finished.
    #[inline]
    pub fn chauthtok(&mut self, flags: Flag) -> PamResult<()> {
        self.handle.chauthtok(flags.bits())
    }

    /// Sets up a user session.
    ///
    /// Establishes user credentials and performs various tasks to prepare
    /// a login session, may create the home directory on first login, mount
    /// user-specific directories, log access times, etc. The application
    /// must usually have sufficient privileges to perform this task (e.g.
    /// have EUID 0). The returned [`Session`] object closes the session and
    /// deletes the established credentials on drop.
    ///
    /// The user should already be [authenticated] and [authorized] at this
    /// point, but this isn't enforced or strictly neccessary if the user
    /// was authenticated by other means. In that case the conversation
    /// handler might be called by e.g. crypt-mount modules to get a password.
    ///
    /// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `ABORT` – Serious failure; the application should exit
    /// - `BUF_ERR` – Memory allocation error
    /// - `SESSION_ERR` – Some session initialization failed
    /// - `CRED_ERR` – Setting credentials failed
    /// - `CRED_UNAVAIL` – Failed to retrieve credentials
    /// - `SYSTEM_ERR` – Other system error
    /// - `USER_UNKNOWN` – User not known
    /// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
    ///   again after the asynchronous conversation finished.
    ///
    /// [authenticated]: `Self::authenticate()`
    /// [authorized]: `Self::acct_mgmt()`
    #[inline]
    pub fn open_session(&mut self, flags: Flag) -> PamResult<Session<ConvT>> {
        let bits = flags.bits();
        self.handle.setcred((Flag::ESTABLISH_CRED | flags).bits())?;

        if let Err(e) = self.handle.open_session(bits) {
            self.handle.setcred((Flag::DELETE_CRED | flags).bits())?;
            return Err(e);
        }

        // Reinitialize credentials after session opening. With this we try
        // to circumvent different assumptions of PAM modules about when
        // `setcred` is called, as the documentations of different PAM
        // implementations differ. (OpenSSH does something similar too).
        if let Err(e) = self
            .handle
            .setcred((Flag::REINITIALIZE_CRED | flags).bits())
        {
            self.handle.close_session(bits)?;
            self.handle.setcred((Flag::DELETE_CRED | flags).bits())?;
            return Err(e);
        }

        Ok(Session::new(self, true))
    }

    /// Maintains user credentials but don't set up a full user session.
    ///
    /// Establishes user credentials and returns a [`Session`] object that
    /// deletes the credentials on drop. It doesn't open a PAM session.
    ///
    /// The user should already be [authenticated] and [authorized] at this
    /// point, but this isn't enforced or strictly neccessary.
    ///
    /// Depending on the platform this use case may not be fully supported.
    ///
    /// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `BUF_ERR` – Memory allocation error
    /// - `CRED_ERR` – Setting credentials failed
    /// - `CRED_UNAVAIL` – Failed to retrieve credentials
    /// - `SYSTEM_ERR` – Other system error
    /// - `USER_UNKNOWN` – User not known
    ///
    /// [authenticated]: Self::authenticate()
    /// [authorized]: Self::acct_mgmt()
    #[inline]
    pub fn open_pseudo_session(&mut self, flags: Flag) -> PamResult<Session<ConvT>> {
        self.handle.setcred((Flag::ESTABLISH_CRED | flags).bits())?;

        Ok(Session::new(self, false))
    }

    /// Resume a session from a [`SessionToken`].
    pub fn unleak_session(&mut self, token: SessionToken) -> Session<ConvT> {
        Session::new(self, matches!(token, SessionToken::FullSession))
    }
}

/// Destructor ending the PAM transaction and releasing the PAM context
impl<ConvT> Drop for Context<ConvT> {
    fn drop(&mut self) {
        let conv = self
            .handle
            .get_item::<Conv>()
            .expect("Extracting the conversation handler should never fail")
            .unwrap();
        unsafe { self.handle.end(self.last_status.get()) }.unwrap();
        drop(unsafe { Box::from_raw(conv.into_raw() as *mut ConvT) });
    }
}

// `Send` should be possible, as long as `ConvT` is `Send` too, as all memory
// access is bound to an unique instance of `Context` (no copy/clone) and we
// keep interior mutability bound to having a reference to the instance.
unsafe impl<ConvT> Send for Context<ConvT> where ConvT: Send {}
