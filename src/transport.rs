use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::sip::message::Message;

/// Result from a dial() operation.
pub struct DialResult {
    /// The dialog for the established call.
    pub dialog: Arc<dyn Dialog>,
    /// Remote SDP from the final 200 OK response.
    pub remote_sdp: String,
    /// SDP from 183 Session Progress (early media), if received.
    pub early_sdp: Option<String>,
}

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
    /// Returns a [`DialResult`] with the dialog, remote SDP, and optional early media SDP.
    fn dial(&self, _target: &str, _local_sdp: &[u8], _timeout: Duration) -> Result<DialResult> {
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

    /// Registers a callback for incoming SIP INFO DTMF requests.
    /// Args: Call-ID, digit.
    fn on_info_dtmf(&self, _f: Box<dyn Fn(String, String) + Send + Sync>) {}

    /// Sends a SIP SUBSCRIBE request to the given URI with extra headers.
    /// Returns the final response.
    fn send_subscribe(
        &self,
        _uri: &str,
        _headers: &HashMap<String, String>,
        _timeout: Duration,
    ) -> Result<Message> {
        Err(Error::Other(
            "subscribe not supported on this transport".into(),
        ))
    }

    /// Registers a callback for incoming MWI NOTIFY (message-summary body).
    fn on_mwi_notify(&self, _f: Box<dyn Fn(String) + Send + Sync>) {}

    /// Sends an out-of-dialog SIP MESSAGE to the given URI.
    fn send_message(
        &self,
        _target: &str,
        _content_type: &str,
        _body: &[u8],
        _timeout: Duration,
    ) -> Result<()> {
        Err(Error::Other(
            "message not supported on this transport".into(),
        ))
    }

    /// Registers a callback for incoming SIP MESSAGE requests.
    /// Args: from, content_type, body.
    fn on_message(&self, _f: Box<dyn Fn(String, String, String) + Send + Sync>) {}

    /// Registers a callback for incoming subscription NOTIFYs (dialog, presence, etc.).
    /// Args: event header, content_type, body, subscription_state header, from_uri.
    #[allow(clippy::type_complexity)]
    fn on_subscription_notify(
        &self,
        _f: Box<dyn Fn(String, String, String, String, String) + Send + Sync>,
    ) {
    }

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
