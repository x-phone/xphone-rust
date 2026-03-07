use std::collections::HashMap;

use crate::error::Result;

/// Internal interface for SIP dialog operations.
/// Production: backed by SIP UA sessions.
/// Tests: satisfied by MockDialog.
pub trait Dialog: Send + Sync {
    /// Sends a SIP response (200 OK with SDP for accept, 4xx/6xx for reject).
    fn respond(&self, code: u16, reason: &str, body: &[u8]) -> Result<()>;
    /// Terminates the dialog (BYE).
    fn send_bye(&self) -> Result<()>;
    /// Cancels a pending INVITE (pre-active calls).
    fn send_cancel(&self) -> Result<()>;
    /// Sends a re-INVITE with new SDP (hold/resume/refresh).
    fn send_reinvite(&self, sdp: &[u8]) -> Result<()>;
    /// Sends a REFER for blind transfer.
    fn send_refer(&self, target: &str) -> Result<()>;
    /// Registers a callback for NOTIFY events (REFER progress).
    fn on_notify(&self, f: Box<dyn Fn(u16) + Send + Sync>);
    /// Returns the SIP Call-ID.
    fn call_id(&self) -> String;
    /// Returns values for a SIP header (case-insensitive).
    fn header(&self, name: &str) -> Vec<String>;
    /// Returns a copy of all SIP headers.
    fn headers(&self) -> HashMap<String, Vec<String>>;
}
