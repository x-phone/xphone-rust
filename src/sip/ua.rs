use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::client::{Client, ClientConfig};
use super::dialog::{build_sip_response, SipDialogUAC, SipDialogUAS};
use super::message::Message;
use crate::config::Config;
use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::transport::SipTransport;

#[allow(clippy::type_complexity)]
struct Inner {
    drop_handler: Option<Arc<dyn Fn() + Send + Sync>>,
    incoming_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    dialog_invite_handler:
        Option<Arc<dyn Fn(Arc<dyn Dialog>, String, String, String) + Send + Sync>>,
    bye_handler: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

/// Production SIP transport backed by `sip::client::Client`.
/// Implements the `SipTransport` trait for real network communication.
pub struct SipUA {
    client: Arc<Client>,
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for SipUA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipUA").finish()
    }
}

impl SipUA {
    /// Creates a new SipUA from a phone Config.
    pub fn new(cfg: &Config) -> Result<Self> {
        if cfg.host.is_empty() {
            return Err(Error::HostRequired);
        }

        let server_addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
            .parse()
            .map_err(|e| Error::Other(format!("invalid server address: {}", e)))?;

        let client_cfg = ClientConfig {
            local_addr: "0.0.0.0:0".into(),
            server_addr,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            domain: cfg.host.clone(),
        };

        let client = Arc::new(Client::new(client_cfg)?);

        let inner = Arc::new(Mutex::new(Inner {
            drop_handler: None,
            incoming_handler: None,
            dialog_invite_handler: None,
            bye_handler: None,
        }));

        // Wire up incoming SIP request handler.
        let inner_clone = Arc::clone(&inner);
        let client_clone = Arc::clone(&client);
        client.on_incoming(move |msg, addr| {
            handle_incoming_request(&inner_clone, &client_clone, &msg, addr);
        });

        Ok(Self { client, inner })
    }
}

fn handle_incoming_request(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    match msg.method.as_str() {
        "INVITE" => handle_invite(inner, client, msg, from_addr),
        "BYE" => handle_bye(inner, client, msg, from_addr),
        "ACK" => {} // ACK is handled implicitly
        "OPTIONS" => {
            // Respond 200 OK to OPTIONS keepalive probes.
            let resp = build_sip_response(msg, 200, "OK");
            let _ = client.send_raw_to(&resp.to_bytes(), from_addr);
        }
        _ => {}
    }
}

fn handle_invite(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let from = msg.header("From").to_string();
    let to = msg.header("To").to_string();
    let remote_sdp = String::from_utf8_lossy(&msg.body).to_string();

    // Send 100 Trying immediately to stop INVITE retransmissions.
    let trying = build_sip_response(msg, 100, "Trying");
    let _ = client.send_raw_to(&trying.to_bytes(), from_addr);

    // Check for dialog-based handler first.
    let dialog_handler = inner.lock().dialog_invite_handler.clone();
    if let Some(handler) = dialog_handler {
        let dlg = Arc::new(SipDialogUAS::new(
            Arc::clone(client),
            msg.clone(),
            from_addr,
        ));
        handler(dlg as Arc<dyn Dialog>, from, to, remote_sdp);
        return;
    }

    // Fall back to simple (from, to) handler for backward compatibility.
    let cb = inner.lock().incoming_handler.clone();
    if let Some(f) = cb {
        f(from, to);
    }
}

fn handle_bye(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    // Always respond 200 OK to BYE to stop retransmissions.
    let resp = build_sip_response(msg, 200, "OK");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Fire BYE handler with Call-ID.
    let call_id = msg.header("Call-ID").to_string();
    let cb = inner.lock().bye_handler.clone();
    if let Some(f) = cb {
        f(call_id);
    }
}

impl SipTransport for SipUA {
    fn send_request(
        &self,
        method: &str,
        _headers: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Message> {
        if method == "REGISTER" {
            let (code, reason) = self.client.send_register(timeout)?;
            let msg = Message::new_response(code, &reason);
            return Ok(msg);
        }

        Err(Error::Other(format!(
            "sip: method {} not supported via send_request, use dial() for INVITE",
            method
        )))
    }

    fn read_response(&self, _timeout: Duration) -> Result<Message> {
        Err(Error::Other(
            "sip: read_response not used in production transport".into(),
        ))
    }

    fn send_keepalive(&self) -> Result<()> {
        self.client.send_keepalive()
    }

    fn respond(&self, _code: u16, _reason: &str) {
        // Responses now handled via Dialog.respond() in production.
    }

    fn on_drop(&self, f: Box<dyn Fn() + Send + Sync>) {
        self.inner.lock().drop_handler = Some(Arc::from(f));
    }

    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().incoming_handler = Some(Arc::from(f));
    }

    fn dial(
        &self,
        target: &str,
        local_sdp: &[u8],
        timeout: Duration,
    ) -> Result<(Arc<dyn Dialog>, String)> {
        // Normalize target to SIP URI.
        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, self.client.domain())
        };

        let result = self.client.send_invite(&target_uri, local_sdp, timeout)?;
        let remote_sdp = String::from_utf8_lossy(&result.response.body).to_string();

        let dlg = Arc::new(SipDialogUAC::new(
            Arc::clone(&self.client),
            result.invite,
            result.response,
        ));

        Ok((dlg as Arc<dyn Dialog>, remote_sdp))
    }

    fn on_dialog_invite(
        &self,
        f: Box<dyn Fn(Arc<dyn Dialog>, String, String, String) + Send + Sync>,
    ) {
        self.inner.lock().dialog_invite_handler = Some(Arc::from(f));
    }

    fn on_bye(&self, f: Box<dyn Fn(String) + Send + Sync>) {
        self.inner.lock().bye_handler = Some(Arc::from(f));
    }

    fn close(&self) -> Result<()> {
        self.client.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_requires_host() {
        let cfg = Config::default();
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Host"));
    }

    #[test]
    fn new_with_valid_config() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15060,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        ua.close().unwrap();
    }

    #[test]
    fn close_is_idempotent() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15061,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        ua.close().unwrap();
        ua.close().unwrap();
    }

    #[test]
    fn unsupported_method_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15062,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        let result = ua.send_request("INVITE", None, Duration::from_secs(1));
        assert!(result.is_err());
        ua.close().unwrap();
    }

    #[test]
    fn keepalive_does_not_panic() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15063,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        let _ = ua.send_keepalive();
        ua.close().unwrap();
    }
}
