use std::{collections::HashMap, ffi::CStr, time::Duration};

use pam::{
    constants::{PamFlag, PamMessageStyle, PamResultCode},
    conv::Conv,
    error::{ErrorCode, PamResult},
    module::{PamHandle, PamHooks},
    pam_try,
};
use reqwest::{blocking::Client, StatusCode};

struct PamHttp;
pam::pam_hooks!(PamHttp);

impl PamHooks for PamHttp {
    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("account management");
        Ok(())
    }

    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("Let's auth over HTTP");

        let args: Vec<_> = args.iter().map(|s| s.to_string_lossy()).collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let user = pamh.get_user(None)?;
        let Some(user) = user else {
            return Err(ErrorCode::AUTHINFO_UNAVAIL);
        };

        let url: &str = match args.get("url") {
            Some(url) => url,
            None => return Err(ErrorCode::AUTH_ERR),
        };

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                unreachable!("No conv available");
            }
            Err(err) => {
                println!("Couldn't get pam_conv");
                return Err(err);
            }
        };
        let password = conv.send(PamMessageStyle::PAM_PROMPT_ECHO_OFF, "Word, yo: ")?;
        let password = match password {
            Some(password) => Some(pam_try!(
                password.to_str(),
                Err(ErrorCode::AUTH_ERR)
            )),
            None => None,
        };
        println!("Got a password {:?}", password);
        let status = pam_try!(
            get_url(url, &user, password),
            Err(ErrorCode::AUTH_ERR)
        );

        if !status.is_success() {
            println!("HTTP Error: {}", status);
            return Err(ErrorCode::AUTH_ERR);
        }

        Ok(())
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        println!("set credentials");
        Ok(())
    }
}

fn get_url(url: &str, user: &str, password: Option<&str>) -> reqwest::Result<StatusCode> {
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    client
        .get(url)
        .basic_auth(user, password)
        .send()
        .map(|r| r.status())
}
