use alloc::borrow::Cow;
use alloc::collections::HashMap;

use crate::context::{Context, Flag};
use crate::conversation::ConversationHandler;
use crate::error::PamResult;

/// Token type to resume RAII handling of a session that was released with [`Session::leak()`].
///
/// The representation may not yet be stable, so don't rely on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub enum SessionToken {
    FullSession,
    PseudoSession,
}

/// An active PAM session or pseudo session
#[must_use]
pub struct Session<'a, ConvT> {
    context: &'a mut Context<ConvT>,
    session_active: bool,
    credentials_active: bool,
}

impl<'a, ConvT> Session<'a, ConvT>
where
    ConvT: ConversationHandler,
{
    /// Constructs a `Session` object for a PAM context.
    #[inline]
    pub(crate) fn new(context: &'a mut Context<ConvT>, real: bool) -> Session<'a, ConvT> {
        Self {
            context,
            session_active: real,
            credentials_active: true,
        }
    }

    /// Extends the lifetime of existing credentials.
    ///
    /// Might be called periodically for long running sessions to
    /// keep e.g. Kerberos tokens alive.
    ///
    /// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
    ///
    /// # Errors
    /// Expected error codes include:
    /// - `ReturnCode::BUF_ERR`: Memory allocation error
    /// - `ReturnCode::CRED_ERR`: Setting credentials failed
    /// - `ReturnCode::CRED_EXPIRED`: Credentials are expired
    /// - `ReturnCode::CRED_UNAVAIL`: Failed to retrieve credentials
    /// - `ReturnCode::SYSTEM_ERR`: Other system error
    /// - `ReturnCode::USER_UNKNOWN`: User not known
    #[inline]
    pub fn refresh_credentials(&mut self, flags: Flag) -> PamResult<()> {
        self.context
            .handle
            .setcred((Flag::REFRESH_CRED | flags).bits())
    }

    /// Fully reinitializes the user's credentials.
    ///
    /// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
    ///
    /// See [`Context::reinitialize_credentials()`] for more information.
    #[inline]
    pub fn reinitialize_credentials(&mut self, flags: Flag) -> PamResult<()> {
        self.context
            .handle
            .setcred((Flag::REINITIALIZE_CRED | flags).bits())
    }

    /// Converts the session into a [`SessionToken`] without closing it.
    ///
    /// The returned token can be used to resume handling the
    /// session with [`Context::unleak_session()`].
    ///
    /// Please note, that if the session isn't closed eventually and the
    /// established credentials aren't deleted, security problems might
    /// occur.
    ///
    /// Depending on the platform it may be possible to close the session
    /// from another context than the one that started the session. But as
    /// this behaviour cannot be safely relied upon, it is recommended to
    /// close the session within the same PAM context.
    pub fn leak(mut self) -> SessionToken {
        let result = if self.session_active {
            SessionToken::FullSession
        } else {
            SessionToken::PseudoSession
        };
        self.session_active = false;
        self.credentials_active = false;
        result
    }

    /// Returns the value of a PAM environment variable.
    ///
    /// See [`crate::context::Context::getenv()`].
    #[must_use]
    #[inline]
    pub fn getenv<'b>(&self, name: Cow<'b, str>) -> Option<String> {
        self.context.getenv(name)
    }

    /// Returns a copy of the PAM environment in this context.
    ///
    /// See [`Context::envlist()`].
    #[must_use]
    pub fn envlist(&self) -> HashMap<String, String> {
        self.context.envlist()
    }
}
