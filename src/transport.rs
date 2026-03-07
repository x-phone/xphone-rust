use std::collections::HashMap;
use std::time::Duration;

use crate::error::Result;
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

    /// Registers a callback for incoming SIP requests.
    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>);

    /// Closes the transport.
    fn close(&self) -> Result<()>;
}
