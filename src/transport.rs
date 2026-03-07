use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::sip::message::Message;

/// Internal interface for SIP transport.
/// Production: implemented by SipUA (backed by sip::Client).
/// Tests: implemented by MockTransport.
pub trait SipTransport: Send + Sync {
    /// Sends a SIP request and waits for a final response.
    /// Returns the response message.
    fn send_request(
        &self,
        method: &str,
        headers: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Message>;

    /// Reads the next response for the current dialog.
    /// Used after send_request("INVITE") to consume provisional (1xx) and final (2xx) responses.
    fn read_response(&self, timeout: Duration) -> Result<Message>;

    /// Sends a NAT keepalive packet.
    fn send_keepalive(&self) -> Result<()>;

    /// Sends a SIP response to an incoming request.
    fn respond(&self, code: u16, reason: &str);

    /// Registers a callback that fires when the transport connection drops.
    fn on_drop(&self, f: Box<dyn Fn() + Send + Sync>);

    /// Registers a callback for incoming SIP requests (basic: from/to strings).
    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>);

    /// Dials a target with an SDP offer, creating an outbound dialog.
    /// Returns the dialog and the remote SDP from the 200 OK.
    fn dial(
        &self,
        _target: &str,
        _local_sdp: &[u8],
        _timeout: Duration,
    ) -> Result<(Arc<dyn Dialog>, String)> {
        Err(Error::Other("dial not supported on this transport".into()))
    }

    /// Registers a callback for incoming INVITEs with a full dialog.
    /// Args: dialog, from, to, remote_sdp
    #[allow(clippy::type_complexity)]
    fn on_dialog_invite(
        &self,
        _f: Box<dyn Fn(Arc<dyn Dialog>, String, String, String) + Send + Sync>,
    ) {
    }

    /// Registers a callback for incoming BYE requests.
    /// Arg: Call-ID of the terminated dialog.
    fn on_bye(&self, _f: Box<dyn Fn(String) + Send + Sync>) {}

    /// Closes the transport.
    fn close(&self) -> Result<()>;
}
