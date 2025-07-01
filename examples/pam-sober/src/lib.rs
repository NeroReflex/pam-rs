use std::{ffi::CStr, str::FromStr};

use pam::{
    constants::{PamFlag, PamMessageStyle, PamResultCode},
    conv::Conv,
    error::PamResult,
    module::{PamHandle, PamHooks},
    pam_try,
};
use rand::Rng;

struct PamSober;
pam::pam_hooks!(PamSober);

impl PamHooks for PamSober {
    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("account management");
        PamResultCode::PAM_SUCCESS.into()
    }

    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("Let's make sure you're sober enough to perform basic addition");

        // TODO: use args to change difficulty ;-)
        // let args: HashMap<&str, &str> = args.iter().map(|s| {
        // let mut parts = s.splitn(2, "=");
        // (parts.next().unwrap(), parts.next().unwrap_or(""))\
        // }).collect();

        // TODO: maybe we can change difficulty base on user?
        // let user = pam_try!(pam.get_user(None));

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => unreachable!(),
            Err(err) => {
                println!("Couldn't get pam_conv");
                return Err(err);
            }
        };

        let mut rng = rand::thread_rng();
        let a = rng.gen::<u32>() % 100;
        let b = rng.gen::<u32>() % 100;
        let math = format!("{} + {} = ", a, b);

        // This println kinda helps debugging since the test script doesn't echo
        eprintln!("[DEBUG]: {}{}", math, a + b);

        let password = conv.send(PamMessageStyle::PAM_PROMPT_ECHO_ON, &math)?;

        if let Some(password) = password {
            let password = pam_try!(password.to_str(), PamResultCode::PAM_AUTH_ERR.into());
            let answer = pam_try!(u32::from_str(password), PamResultCode::PAM_AUTH_ERR.into());
            if answer == a + b {
                PamResultCode::PAM_SUCCESS.into()
            } else {
                println!("Wrong answer provided {} + {} != {}", a, b, answer);
                PamResultCode::PAM_AUTH_ERR.into()
            }
        } else {
            println!("You failed the PAM sobriety test.");
            PamResultCode::PAM_AUTH_ERR.into()
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS.into()
    }
}
