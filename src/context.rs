use bitflags::bitflags;

bitflags! {
	/// Flags for most PAM functions
	#[allow(clippy::upper_case_acronyms)]
	#[repr(transparent)]
	#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(transparent))]
	#[derive(Copy, Clone)]
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
