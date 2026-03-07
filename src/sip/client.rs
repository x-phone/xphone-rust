use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use super::auth::{self, Credentials};
use super::conn::Conn;
use super::message::Message;
use super::transaction::{self, TransactionManager};
use crate::error::{Error, Result};

/// Configuration for a SIP client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub local_addr: String,
    pub server_addr: SocketAddr,
    pub username: String,
    pub password: String,
    pub domain: String,
}

/// A SIP UA client that can send REGISTER and other requests,
/// and receive incoming requests (INVITE, BYE, etc.).
pub struct Client {
    tm: Mutex<TransactionManager>,
    cfg: ClientConfig,
    cseq: AtomicU32,
    call_id: String,
    conn_local_addr: SocketAddr,
    closed: Mutex<bool>,
}

impl Client {
    /// Creates a new SIP client, binding to `local_addr`.
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        let conn = Conn::listen(&cfg.local_addr)
            .map_err(|e| Error::Other(format!("sip: listen: {}", e)))?;
        let local_addr = conn
            .local_addr()
            .map_err(|e| Error::Other(format!("sip: local addr: {}", e)))?;
        let tm = TransactionManager::new(conn);
        let call_id = transaction::generate_branch();

        Ok(Self {
            tm: Mutex::new(tm),
            cfg,
            cseq: AtomicU32::new(0),
            call_id,
            conn_local_addr: local_addr,
            closed: Mutex::new(false),
        })
    }

    /// Returns the local address the client is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.conn_local_addr
    }

    /// Shuts down the client.
    pub fn close(&self) {
        *self.closed.lock() = true;
        self.tm.lock().stop();
    }

    /// Registers a callback for incoming SIP requests.
    pub fn on_incoming<F>(&self, f: F)
    where
        F: Fn(Message, SocketAddr) + Send + Sync + 'static,
    {
        self.tm.lock().on_request(f);
    }

    /// Sends a REGISTER request.
    /// Handles 401 auth challenges automatically.
    /// Returns (response_code, reason).
    pub fn send_register(&self, timeout: Duration) -> Result<(u16, String)> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let request_uri = format!("sip:{}", self.cfg.domain);
        let mut req = self.build_request("REGISTER", &request_uri, None);

        let tm = self.tm.lock();
        let resp = tm.send(&mut req, self.cfg.server_addr, timeout)?;
        let branch = req.via_branch().to_string();

        // Handle 401 auth challenge.
        if resp.status_code == 401 {
            tm.remove_tx(&branch);
            let auth_hdr = resp.header("WWW-Authenticate");
            let ch = match auth::parse_challenge(auth_hdr) {
                Ok(ch) => ch,
                Err(_) => return Ok((401, auth_hdr.to_string())),
            };
            let creds = Credentials {
                username: self.cfg.username.clone(),
                password: self.cfg.password.clone(),
            };
            let auth_val = auth::build_authorization(&ch, &creds, "REGISTER", &request_uri);

            let mut extra = HashMap::new();
            extra.insert("Authorization".to_string(), auth_val);
            let mut retry = self.build_request("REGISTER", &request_uri, Some(&extra));
            let resp = tm.send(&mut retry, self.cfg.server_addr, timeout)?;
            let retry_branch = retry.via_branch().to_string();
            tm.remove_tx(&retry_branch);
            return Ok((resp.status_code, resp.reason.clone()));
        }

        tm.remove_tx(&branch);
        Ok((resp.status_code, resp.reason.clone()))
    }

    /// Sends a CRLF NAT keepalive packet to the server.
    pub fn send_keepalive(&self) -> Result<()> {
        self.tm.lock().send_raw(b"\r\n\r\n", self.cfg.server_addr)
    }

    /// Creates a SIP request with standard headers.
    fn build_request(
        &self,
        method: &str,
        request_uri: &str,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Message {
        let seq = self.cseq.fetch_add(1, Ordering::Relaxed) + 1;
        let local = self.conn_local_addr;

        let mut msg = Message::new_request(method, request_uri);

        let from_tag = &transaction::generate_branch()[..15];
        msg.set_header(
            "From",
            &format!(
                "<sip:{}@{}>;tag={}",
                self.cfg.username, self.cfg.domain, from_tag
            ),
        );
        msg.set_header(
            "To",
            &format!("<sip:{}@{}>", self.cfg.username, self.cfg.domain),
        );
        msg.set_header("Call-ID", &self.call_id);
        msg.set_header("CSeq", &format!("{} {}", seq, method));
        msg.set_header("Contact", &format!("<sip:{}@{}>", self.cfg.username, local));
        msg.set_header("Max-Forwards", "70");
        msg.set_header("User-Agent", "xphone");

        if let Some(extra) = extra_headers {
            for (k, v) in extra {
                msg.set_header(k, v);
            }
        }

        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creates_and_closes() {
        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
        };
        let client = Client::new(cfg).unwrap();
        assert!(client.local_addr().port() > 0);
        client.close();
    }

    #[test]
    fn build_request_has_standard_headers() {
        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
        };
        let client = Client::new(cfg).unwrap();

        let req = client.build_request("REGISTER", "sip:pbx.local", None);
        assert_eq!(req.method, "REGISTER");
        assert!(!req.header("From").is_empty());
        assert!(!req.header("To").is_empty());
        assert!(!req.header("Call-ID").is_empty());
        assert_eq!(req.header("CSeq"), "1 REGISTER");
        assert_eq!(req.header("Max-Forwards"), "70");
        assert_eq!(req.header("User-Agent"), "xphone");

        client.close();
    }

    #[test]
    fn send_register_with_401_auth() {
        let server = Conn::listen("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            let mut server = server;

            // First request → 401.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "REGISTER");

            let mut resp = Message::new_response(401, "Unauthorized");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header(
                "WWW-Authenticate",
                r#"Digest realm="asterisk",nonce="abc123",algorithm=MD5"#,
            );
            server.send(&resp.to_bytes(), from).unwrap();

            // Second request (with auth) → 200.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "REGISTER");
            let auth = req.header("Authorization");
            assert!(auth.contains("Digest "), "expected Authorization header");

            let mut resp = Message::new_response(200, "OK");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            server.send(&resp.to_bytes(), from).unwrap();
        });

        let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "OK");

        client.close();
        handle.join().unwrap();
    }

    #[test]
    fn close_then_register_returns_error() {
        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
        };
        let client = Client::new(cfg).unwrap();
        client.close();

        let result = client.send_register(Duration::from_secs(1));
        assert!(result.is_err());
    }
}
