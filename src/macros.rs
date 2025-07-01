/// Macro to generate the `extern "C"` entrypoint bindings needed by PAM
///
/// You can call `pam_hooks!(SomeType);` for any type that implements `PamHooks`
///
/// ## Examples:
///
/// Here is full example of a PAM module that would authenticate and authorize
/// everybody:
///
/// ```
/// #[macro_use] extern crate pam;
///
/// use std::ffi::CStr;
///
/// use pam::{
///     constants::{PamFlag, PamResultCode},
///     module::{PamHandle, PamHooks},
///     error::PamResult
/// };
///
/// # fn main() {}
/// struct MyPamModule;
/// pam_hooks!(MyPamModule);
///
/// impl PamHooks for MyPamModule {
///     fn sm_authenticate(
///         pamh: &mut PamHandle,
///         args: Vec<&CStr>,
///         flags: PamFlag,
///     ) -> PamResult<()> {
///         println!("Everybody is authenticated!");
///         Ok(())
///     }
///
///     fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResult<()> {
///         println!("Everybody is authorized!");
///         Ok(())
///     }
/// }
/// ```
#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use core::ffi::{c_char, c_int, CStr};

            use $crate::{
                constants::{PamFlag, PamResultCode},
                module::{PamHandle, PamHooks, RawPamHandle},
            };

            fn extract_argv<'a>(argc: c_int, argv: *const *const c_char) -> $crate::Vec<&'a CStr> {
                (0..argc)
                    .map(|o| unsafe { CStr::from_ptr(*argv.offset(o as isize) as *const c_char) })
                    .collect()
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::acct_mgmt(&mut handle, args, flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::sm_authenticate(&mut handle, args, flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_chauthtok(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::sm_chauthtok(&mut handle, args, flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_close_session(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::sm_close_session(&mut handle, args, flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_open_session(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::sm_open_session(&mut handle, args, flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_setcred(
                pamh: &mut RawPamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                let mut handle = unsafe { PamHandle::new(pamh) }.unwrap();
                PamResultCode::from(super::$ident::sm_setcred(&mut handle, args, flags))
            }
        }
    };
}

#[macro_export]
macro_rules! pam_try {
    ($r:expr) => {
        match $r {
            Ok(t) => t,
            Err(e) => return e,
        }
    };
    ($r:expr, $e:expr) => {
        match $r {
            Ok(t) => t,
            Err(_) => return $e,
        }
    };
}

#[cfg(test)]
pub mod test {
    use crate::module::PamHooks;

    struct Foo;
    impl PamHooks for Foo {}

    pam_hooks!(Foo);
}
