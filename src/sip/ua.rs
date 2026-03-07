use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::client::{Client, ClientConfig};
use super::message::Message;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::SipTransport;

struct Inner {
    drop_handler: Option<Arc<dyn Fn() + Send + Sync>>,
    incoming_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
}

/// Production SIP transport backed by `sip::client::Client`.
/// Implements the `SipTransport` trait for real network communication.
pub struct SipUA {
    client: Client,
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

        let client = Client::new(client_cfg)?;

        let inner = Arc::new(Mutex::new(Inner {
            drop_handler: None,
            incoming_handler: None,
        }));

        // Wire up incoming SIP request handler.
        let inner_clone = Arc::clone(&inner);
        client.on_incoming(move |msg, _addr| {
            handle_incoming_request(&inner_clone, &msg);
        });

        Ok(Self { client, inner })
    }
}

fn handle_incoming_request(inner: &Arc<Mutex<Inner>>, msg: &Message) {
    if msg.method == "INVITE" {
        let from = msg.header("From").to_string();
        let to = msg.header("To").to_string();

        let cb = inner.lock().incoming_handler.clone();
        if let Some(f) = cb {
            f(from, to);
        }
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

        // INVITE and other methods will go through a dialog-based path
        // once UAC/UAS dialogs are implemented.
        Err(Error::Other(format!(
            "sip: method {} not yet supported via SipUA",
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
        // Inbound responses handled via dialog layer (future).
    }

    fn on_drop(&self, f: Box<dyn Fn() + Send + Sync>) {
        self.inner.lock().drop_handler = Some(Arc::from(f));
    }

    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().incoming_handler = Some(Arc::from(f));
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
        // Keepalive sends to a non-listening port — should not error on UDP.
        let _ = ua.send_keepalive();
        ua.close().unwrap();
    }
}
