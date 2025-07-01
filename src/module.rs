//! Functions for use in pam modules.

use alloc::{borrow::Cow, boxed::Box, collections::HashMap, ffi::CString, vec::Vec};
use core::{
    ffi::CStr,
    ptr::{null, null_mut, NonNull},
};

use libc::c_char;

use crate::{
    constants::{
        PamFlag,
        PamResultCode::{self, PAM_SUCCESS},
    },
    conv::{into_pam_conv, RawPamConv},
    conversation::ConversationHandler,
    error::{ErrorCode, PamResult},
    items::ItemType,
};

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[repr(C)]
pub struct RawPamHandle {
    _data: [u8; 0],
}

// Implementation detail: the discriminant values in the following enum
// corresponds to the int values of the corresponding constants in
// glibc syslog.h
//
/// Log levels as defined in the syslog(3) manual page.
/// #[cfg(target_os = "linux")]
pub enum LogLevel {
    /// system is unusable, corresponds to LOG_EMERG
    Emergency = 0,
    /// action must be taken immediately, corresponds to LOG_ALERT
    Alert = 1,
    /// critical conditions, corresponds to LOG_CRIT
    Critical = 2,
    /// error conditions, corresponds to LOG_ERR
    Error = 3,
    /// warning conditions, corresponds to LOG_WARN
    Warning = 4,
    /// normal, but significant, condition, corresponds to LOG_NOTICE
    Notice = 5,
    /// informational message, corresponds to LOG_INFO
    Info = 6,
    /// debug-level message, corresponds to LOG_DEBUG
    Debug = 7,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conversation: *const RawPamConv,
        pamh: *mut *mut RawPamHandle,
    ) -> PamResultCode;

    fn pam_start_confdir(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conversation: *const RawPamConv,
        confdir: *const libc::c_char,
        pamh: *mut *mut RawPamHandle,
    ) -> PamResultCode;

    fn pam_end(pamh: *mut RawPamHandle, pam_status: PamResultCode) -> PamResultCode;

    fn pam_authenticate(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_setcred(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_acct_mgmt(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_open_session(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_close_session(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_chauthtok(pamh: *mut RawPamHandle, flags: libc::c_int) -> PamResultCode;

    fn pam_get_data(
        pamh: *const RawPamHandle,
        module_data_name: *const c_char,
        data: &mut *const libc::c_void,
    ) -> PamResultCode;

    fn pam_set_data(
        pamh: *const RawPamHandle,
        module_data_name: *const c_char,
        data: *mut libc::c_void,
        cleanup: extern "C" fn(
            pamh: *const RawPamHandle,
            data: *mut libc::c_void,
            error_status: PamResultCode,
        ),
    ) -> PamResultCode;

    fn pam_get_item(
        pamh: *const RawPamHandle,
        item_type: ItemType,
        item: &mut *const libc::c_void,
    ) -> PamResultCode;

    fn pam_set_item(
        pamh: *mut RawPamHandle,
        item_type: ItemType,
        item: *const libc::c_void,
    ) -> PamResultCode;

    fn pam_get_user(
        pamh: *const RawPamHandle,
        user: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_get_authtok(
        pamh: *const RawPamHandle,
        item: ItemType,
        authtok: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_get_authtok_noverify(
        pamh: *const RawPamHandle,
        authtok: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_get_authtok_verify(
        pamh: *const RawPamHandle,
        authtok: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_putenv(pamh: *const RawPamHandle, name_value: *const c_char) -> PamResultCode;

    fn pam_getenv(pamh: *const RawPamHandle, name: *const libc::c_char) -> *const libc::c_char;

    fn pam_getenvlist(pamh: *const RawPamHandle) -> *mut *mut libc::c_char;

    #[cfg(target_os = "linux")]
    fn pam_syslog(pamh: *const RawPamHandle, priority: libc::c_int, format: *const c_char, ...);
}

pub extern "C" fn cleanup<T>(_: *const RawPamHandle, c_data: *mut libc::c_void, _: PamResultCode) {
    unsafe {
        drop(Box::from_raw(c_data.cast::<T>()));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PamHandle {
    handle: NonNull<RawPamHandle>,
}

/// PAM handle wrapper
impl PamHandle {
    /// Create a PAM handle from a raw handle pointer.
    ///
    /// # Safety
    /// The argument `ptr` must be a valid non-dangling PAM handle created by `pam_start`.
    #[inline]
    pub unsafe fn new(ptr: *mut RawPamHandle) -> Option<Self> {
        match NonNull::new(ptr) {
            Some(handle) => Some(Self { handle }),
            None => None,
        }
    }

    #[inline]
    pub const fn as_ptr(self) -> *mut RawPamHandle {
        self.handle.as_ptr()
    }
}

impl From<PamHandle> for *mut RawPamHandle {
    #[inline]
    fn from(handle: PamHandle) -> Self {
        handle.as_ptr()
    }
}

impl From<PamHandle> for *const RawPamHandle {
    #[inline]
    fn from(handle: PamHandle) -> Self {
        handle.as_ptr()
    }
}

impl PamHandle {
    pub unsafe fn start<'a, ConvT>(
        service: Cow<'a, str>,
        username: Option<Cow<'a, str>>,
        boxed_conv: Box<ConvT>,
    ) -> PamResult<Self>
    where
        ConvT: ConversationHandler,
    {
        let mut handle: *mut RawPamHandle = null_mut();

        // Create callback struct for C code
        let pam_conv = into_pam_conv(boxed_conv);

        let c_service = CString::new(service.to_string()).unwrap();

        // Start the PAM context
        let res = unsafe {
            pam_start(
                c_service.as_ptr(),
                match username {
                    Some(user) => CString::new(user.to_string()).unwrap().as_ptr(),
                    None => null(),
                },
                &pam_conv,
                &mut handle,
            )
        };

        if PamResultCode::PAM_SUCCESS != res {
            return Err(res.into());
        }

        match NonNull::new(handle) {
            Some(handle) => Ok(Self { handle }),
            None => Err(ErrorCode::ABORT),
        }
    }

    pub unsafe fn end(&self, pam_status: PamResultCode) -> PamResult<()> {
        unsafe { pam_end(self.handle.as_ptr(), pam_status) }.into()
    }

    /// Gets some value, identified by `key`, that has been set by the module
    /// previously.
    ///
    /// See `pam_get_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Safety
    ///
    /// The data stored under the provided key must be of type `T` otherwise the
    /// behaviour of this funtion is undefined.
    pub unsafe fn get_data<T>(&self, key: &str) -> PamResult<&T> {
        let c_key = CString::new(key).unwrap();
        let mut ptr: *const libc::c_void = core::ptr::null();
        let res = pam_get_data(self.handle.as_ptr(), c_key.as_ptr(), &mut ptr);
        if PAM_SUCCESS == res && !ptr.is_null() {
            let typed_ptr = ptr.cast::<T>();
            let data: &T = &*typed_ptr;
            Ok(data)
        } else {
            return Err(res.into());
        }
    }

    /// Stores a value that can be retrieved later with `get_data`.  The value
    /// lives as long as the current pam cycle.
    ///
    /// See `pam_set_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn set_data<T>(&self, key: &str, data: Box<T>) -> PamResult<()> {
        let c_key = CString::new(key).unwrap();
        unsafe {
            pam_set_data(
                self.handle.as_ptr(),
                c_key.as_ptr(),
                Box::into_raw(data).cast::<libc::c_void>(),
                cleanup::<T>,
            )
        }
        .into()
    }

    /// Retrieves a value that has been set, possibly by the pam client.
    /// This is particularly useful for getting a `PamConv` reference.
    ///
    /// See `pam_get_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn get_item<T: crate::items::Item>(&self) -> PamResult<Option<T>> {
        let mut ptr: *const libc::c_void = core::ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self.handle.as_ptr(), T::type_id(), &mut ptr);
            let typed_ptr = ptr.cast::<T::Raw>();
            let t = if typed_ptr.is_null() {
                None
            } else {
                Some(T::from_raw(typed_ptr))
            };
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res.into());
        }

        Ok(item)
    }

    /// Sets a value in the pam context. The value can be retrieved using
    /// `get_item`.
    ///
    /// Note that all items are strings, except `PAM_CONV` and `PAM_FAIL_DELAY`.
    ///
    /// See `pam_set_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided item key contains a nul byte
    pub fn set_item_str<T: crate::items::Item>(&mut self, item: T) -> PamResult<()> {
        unsafe {
            pam_set_item(
                self.handle.as_ptr(),
                T::type_id(),
                item.into_raw().cast::<libc::c_void>(),
            )
        }
        .into()
    }

    pub(crate) fn raw_set_item(
        &mut self,
        item_type: ItemType,
        item: *const libc::c_void,
    ) -> PamResult<()> {
        unsafe { pam_set_item(self.handle.as_ptr(), item_type, &*item) }.into()
    }

    pub(crate) fn raw_get_item(&self, item_type: ItemType) -> PamResult<*const libc::c_void> {
        let mut result: *const libc::c_void = null();
        match unsafe { pam_get_item(self.handle.as_ptr(), item_type, &mut result) } {
            PAM_SUCCESS => Ok(result),
            err => Err(err.into()),
        }
    }

    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See `pam_get_user` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided prompt string contains a nul byte
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<String>> {
        let ptr: *mut c_char = core::ptr::null_mut();
        let code = unsafe {
            pam_get_user(
                self.handle.as_ptr(),
                &ptr,
                prompt
                    .and_then(|x| CString::new(x).ok())
                    .map_or(core::ptr::null(), |x| x.as_ptr()),
            )
        };
        match code {
            PAM_SUCCESS => match ptr.is_null() {
                true => Ok(None),
                false => match unsafe { CStr::from_ptr(ptr as *const c_char).to_str() } {
                    Ok(username) => Ok(Some(username.to_string())),
                    Err(err) => Err(ErrorCode::CONV_ERR),
                },
            },
            e => Err(e.into()),
        }
    }

    pub(crate) fn authenticate(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_authenticate(self.handle.as_ptr(), flags) }.into()
    }

    pub(crate) fn setcred(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_setcred(self.handle.as_ptr(), flags) }.into()
    }

    pub(crate) fn acct_mgmt(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_acct_mgmt(self.handle.as_ptr(), flags) }.into()
    }

    pub(crate) fn open_session(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_open_session(self.handle.as_ptr(), flags) }.into()
    }

    pub(crate) fn close_session(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_close_session(self.handle.as_ptr(), flags) }.into()
    }

    pub(crate) fn chauthtok(&self, flags: libc::c_int) -> PamResult<()> {
        unsafe { pam_chauthtok(self.handle.as_ptr(), flags) }.into()
    }

    pub fn get_authtok(
        &self,
        item: ItemType,
        prompt: Option<&str>,
    ) -> PamResult<Option<Cow<'_, str>>> {
        let token: *mut c_char = core::ptr::null_mut();
        self.get_authtok_post(token, unsafe {
            pam_get_authtok(
                self.handle.as_ptr(),
                item,
                &token,
                prompt
                    .and_then(|x| CString::new(x).ok())
                    .map_or(core::ptr::null(), |x| x.as_ptr()),
            )
        })
    }

    pub fn get_authtok_verify(&self, prompt: Option<&str>) -> PamResult<Option<Cow<'_, str>>> {
        let token: *mut c_char = core::ptr::null_mut();
        self.get_authtok_post(token, unsafe {
            pam_get_authtok_verify(
                self.handle.as_ptr(),
                &token,
                prompt
                    .and_then(|x| CString::new(x).ok())
                    .map_or(core::ptr::null(), |x| x.as_ptr()),
            )
        })
    }

    pub fn get_authtok_noverify(&self, prompt: Option<&str>) -> PamResult<Option<Cow<'_, str>>> {
        let token: *mut c_char = core::ptr::null_mut();
        self.get_authtok_post(token, unsafe {
            pam_get_authtok_noverify(
                self.handle.as_ptr(),
                &token,
                prompt
                    .and_then(|x| CString::new(x).ok())
                    .map_or(core::ptr::null(), |x| x.as_ptr()),
            )
        })
    }

    fn get_authtok_post<'a>(
        &self,
        token: *mut c_char,
        code: PamResultCode,
    ) -> PamResult<Option<Cow<'a, str>>> {
        match code {
            PAM_SUCCESS if token.is_null() => Ok(None),
            PAM_SUCCESS => {
                let pass = unsafe { CStr::from_ptr(token as *const c_char).to_str() }
                    .map_err(|_| ErrorCode::CONV_ERR)?;
                Ok(if pass.trim().is_empty() {
                    None
                } else {
                    Some(pass.into())
                })
            }
            e => Err(e.into()),
        }
    }

    pub fn env_list(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();

        unsafe {
            let envlist = pam_getenvlist(self.handle.as_ptr());
            while !(*envlist).is_null() {
                let current_ptr = *envlist;
                let current_env = CStr::from_ptr(current_ptr);
                let env_var = current_env.to_string_lossy().to_string();

                let (key, val) = match env_var.find("=") {
                    Some(mid) => env_var.split_at(mid),
                    None => (env_var.as_str(), ""),
                };

                result.insert(String::from(key), String::from(val));

                libc::free(current_ptr.cast());
            }

            libc::free(envlist.cast());
        }

        result
    }

    pub fn env_get<'a>(&self, name: Cow<'a, str>) -> Option<String> {
        let name_value = format!("{}", name);
        let c_string = CString::new(name_value).unwrap();

        let result = unsafe { pam_getenv(self.handle.as_ptr(), c_string.as_ptr()).as_ref() };

        result.map(|a| {
            unsafe { CStr::from_ptr(a as *const i8) }
                .to_string_lossy()
                .to_string()
        })
    }

    pub fn env_set<'a>(&self, name: Cow<'a, str>, value: Cow<'a, str>) -> PamResult<()> {
        let name_value = format!("{}={}", name.replace("=", "_"), value);
        let c_string = CString::new(name_value).unwrap();

        unsafe { pam_putenv(self.handle.as_ptr(), c_string.as_ptr()) }.into()
    }

    pub fn env_reset<'a>(&self, name: Cow<'a, str>) -> PamResult<()> {
        let name_value = format!("{}=", name.replace("=", "_"));
        let c_string = CString::new(name_value).unwrap();

        unsafe { pam_putenv(self.handle.as_ptr(), c_string.as_ptr()) }.into()
    }

    pub fn env_remove<'a>(&self, name: Cow<'a, str>) -> PamResult<()> {
        let name_value = format!("{}", name.replace("=", "_"));
        let c_string = CString::new(name_value).unwrap();

        unsafe { pam_putenv(self.handle.as_ptr(), c_string.as_ptr()) }.into()
    }

    /// Log a message with the specified level to the syslog.
    ///
    /// This method wraps pam_syslog, which prefixes the message with a string indicating
    /// the relevant PAM context.
    #[cfg(target_os = "linux")]
    pub fn log(&self, level: LogLevel, message: String) {
        let percent_s = CString::new("%s").unwrap();
        let message = CString::new(message).unwrap();
        unsafe {
            pam_syslog(
                self.handle.as_ptr(),
                level as i32,
                percent_s.as_ptr(),
                message.as_ptr(),
            );
        }
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All of hooks are ignored by PAM dispatch by default given the default return
/// value of `PAM_IGNORE`. Override any functions that you want to handle with
/// your module. See `man pam(3)`.
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is
    /// permitted to gain access at this time. It should be understood that
    /// the user has previously been validated by an authentication module.
    /// This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function
    /// may also determine things like the expiration on passwords, and
    /// respond that the user change it before continuing.
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    /// This function is used to (re-)set the authentication token of the user.
    ///
    /// The PAM library calls this function twice in succession. The first time
    /// with `PAM_PRELIM_CHECK` and then, if the module does not return
    /// `PAM_TRY_AGAIN`, subsequently with `PAM_UPDATE_AUTHTOK`. It is only
    /// on the second call that the authorization token is (possibly)
    /// changed.
    fn sm_chauthtok(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    /// This function is called to terminate a session.
    fn sm_close_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    /// This function is called to commence a session.
    fn sm_open_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    /// This function performs the task of altering the credentials of the user
    /// with respect to the corresponding authorization scheme. Generally,
    /// an authentication module may have access to more information about a
    /// user than their authentication token. This function is used to make such
    /// information available to the application. It should only be called after
    /// the user has been authenticated but before a session has been
    /// established.
    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }
}

#[allow(unused_variables)]
pub trait PamHooksResult {
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    fn sm_chauthtok(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    fn sm_close_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    fn sm_open_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }

    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        PamResultCode::PAM_IGNORE.into()
    }
}

impl<T> PamHooks for T
where
    T: PamHooksResult,
{
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::acct_mgmt(pamh, args, flags)
    }

    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::sm_authenticate(pamh, args, flags)
    }

    fn sm_chauthtok(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::sm_chauthtok(pamh, args, flags)
    }

    fn sm_close_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::sm_close_session(pamh, args, flags)
    }

    fn sm_open_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::sm_open_session(pamh, args, flags)
    }

    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
        T::sm_setcred(pamh, args, flags)
    }
}
