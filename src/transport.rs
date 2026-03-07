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

    /// Registers a callback for incoming NOTIFY requests (REFER progress).
    /// Args: Call-ID, status code parsed from sipfrag body.
    fn on_notify(&self, _f: Box<dyn Fn(String, u16) + Send + Sync>) {}

    /// Sends REGISTER with Expires: 0 to unregister.
    fn unregister(&self, _timeout: Duration) -> Result<()> {
        Ok(())
    }

    /// Returns the advertised address (routable or STUN-mapped IP + port).
    /// Used by the phone layer to set the SDP media address.
    /// Returns `None` if unknown (e.g. mock transports).
    fn advertised_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }

    /// Closes the transport.
    fn close(&self) -> Result<()>;
}
