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

/// Result of a successful INVITE transaction.
pub struct InviteResult {
    /// The INVITE request that was sent.
    pub invite: Message,
    /// The final 2xx response.
    pub response: Message,
    /// Provisional responses received before the final response.
    pub provisionals: Vec<(u16, String)>,
}

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
    /// The address advertised in Via/Contact headers (routable IP + bound port).
    advertised_addr: SocketAddr,
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

        // Compute a routable IP to advertise in Via/Contact headers.
        // When bound to 0.0.0.0, the OS-reported local_addr is 0.0.0.0:PORT,
        // which is invalid for SIP peers. Use a UDP connect trick to discover
        // the actual outgoing interface IP for the server.
        let advertised_addr = if local_addr.ip().is_unspecified() {
            use std::net::UdpSocket;
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(sock) => match sock.connect(cfg.server_addr) {
                    Ok(()) => match sock.local_addr() {
                        Ok(addr) if !addr.ip().is_unspecified() => {
                            SocketAddr::new(addr.ip(), local_addr.port())
                        }
                        _ => local_addr,
                    },
                    Err(_) => local_addr,
                },
                Err(_) => local_addr,
            }
        } else {
            local_addr
        };

        Ok(Self {
            tm: Mutex::new(tm),
            cfg,
            cseq: AtomicU32::new(0),
            call_id,
            advertised_addr,
            closed: Mutex::new(false),
        })
    }

    /// Returns the advertised address (routable IP + bound port)
    /// for use in Contact/Via headers.
    pub fn local_addr(&self) -> SocketAddr {
        self.advertised_addr
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

    /// Returns the configured server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.cfg.server_addr
    }

    /// Returns the configured username.
    pub fn username(&self) -> &str {
        &self.cfg.username
    }

    /// Returns the configured domain.
    pub fn domain(&self) -> &str {
        &self.cfg.domain
    }

    /// Sends a SIP INVITE with SDP body.
    /// Handles 401/407 auth challenges, consumes provisional responses,
    /// sends ACK on 200 OK, and returns the full result.
    pub fn send_invite(
        &self,
        target_uri: &str,
        sdp: &[u8],
        timeout: Duration,
    ) -> Result<InviteResult> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let mut req = self.build_invite_request(target_uri, sdp, None);

        let (resp, branch, invite) = {
            let tm = self.tm.lock();
            let resp = tm.send(&mut req, self.cfg.server_addr, timeout)?;
            let branch = req.via_branch().to_string();

            if resp.status_code == 401 || resp.status_code == 407 {
                tm.remove_tx(&branch);
                let auth_hdr_name = if resp.status_code == 401 {
                    "WWW-Authenticate"
                } else {
                    "Proxy-Authenticate"
                };
                let auth_hdr = resp.header(auth_hdr_name);
                let ch = auth::parse_challenge(auth_hdr)
                    .map_err(|_| Error::Other("sip: auth challenge parse failed".into()))?;
                let creds = Credentials {
                    username: self.cfg.username.clone(),
                    password: self.cfg.password.clone(),
                };
                let auth_val = auth::build_authorization(&ch, &creds, "INVITE", target_uri);
                let auth_resp_hdr = if resp.status_code == 401 {
                    "Authorization"
                } else {
                    "Proxy-Authorization"
                };

                let mut extra = HashMap::new();
                extra.insert(auth_resp_hdr.to_string(), auth_val);
                let mut retry = self.build_invite_request(target_uri, sdp, Some(&extra));
                let resp = tm.send(&mut retry, self.cfg.server_addr, timeout)?;
                let branch = retry.via_branch().to_string();
                (resp, branch, retry)
            } else {
                (resp, branch, req)
            }
        };

        self.consume_invite_responses(invite, resp, &branch, timeout)
    }

    /// Consumes provisional responses and sends ACK on 200 OK.
    fn consume_invite_responses(
        &self,
        invite: Message,
        first_resp: Message,
        branch: &str,
        timeout: Duration,
    ) -> Result<InviteResult> {
        let mut provisionals = Vec::new();
        let mut resp = first_resp;

        while (100..200).contains(&resp.status_code) {
            provisionals.push((resp.status_code, resp.reason.clone()));
            let tm = self.tm.lock();
            resp = tm.read_response(branch, timeout)?;
        }

        if resp.status_code >= 200 && resp.status_code < 300 {
            // Send ACK for 2xx.
            let ack = self.build_ack(&invite, &resp);
            {
                let tm = self.tm.lock();
                tm.remove_tx(branch);
                tm.send_raw(&ack.to_bytes(), self.cfg.server_addr)?;
            }
            Ok(InviteResult {
                invite,
                response: resp,
                provisionals,
            })
        } else {
            self.tm.lock().remove_tx(branch);
            Err(Error::Other(format!(
                "sip: INVITE rejected: {} {}",
                resp.status_code, resp.reason
            )))
        }
    }

    /// Sends an in-dialog SIP request (BYE, REFER) and waits for response.
    pub fn send_dialog_request(&self, req: &mut Message, timeout: Duration) -> Result<Message> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }
        let tm = self.tm.lock();
        let resp = tm.send(req, self.cfg.server_addr, timeout)?;
        let branch = req.via_branch().to_string();
        tm.remove_tx(&branch);
        Ok(resp)
    }

    /// Sends an in-dialog re-INVITE, consuming provisional responses and sending ACK on 200 OK.
    pub fn send_dialog_reinvite(&self, req: &mut Message, timeout: Duration) -> Result<Message> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let invite_clone = req.clone();
        let resp = {
            let tm = self.tm.lock();
            tm.send(req, self.cfg.server_addr, timeout)?
        };
        let branch = req.via_branch().to_string();

        // Consume provisional responses.
        let mut resp = resp;
        while (100..200).contains(&resp.status_code) {
            let tm = self.tm.lock();
            resp = tm.read_response(&branch, timeout)?;
        }

        if (200..300).contains(&resp.status_code) {
            // Send ACK for 2xx.
            let ack = self.build_ack(&invite_clone, &resp);
            let tm = self.tm.lock();
            tm.remove_tx(&branch);
            tm.send_raw(&ack.to_bytes(), self.cfg.server_addr)?;
        } else {
            self.tm.lock().remove_tx(&branch);
        }

        Ok(resp)
    }

    /// Sends raw bytes to a specific address (for SIP responses, ACK).
    pub fn send_raw_to(&self, data: &[u8], dst: SocketAddr) -> Result<()> {
        self.tm.lock().send_raw(data, dst)
    }

    /// Sends a CRLF NAT keepalive packet to the server.
    pub fn send_keepalive(&self) -> Result<()> {
        self.tm.lock().send_raw(b"\r\n\r\n", self.cfg.server_addr)
    }

    /// Builds an INVITE request with SDP body.
    fn build_invite_request(
        &self,
        target_uri: &str,
        sdp: &[u8],
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Message {
        let seq = self.cseq.fetch_add(1, Ordering::Relaxed) + 1;
        let local = self.advertised_addr;
        let from_tag = &transaction::generate_branch()[..15];
        let invite_call_id = transaction::generate_branch();

        let mut msg = Message::new_request("INVITE", target_uri);

        // Pre-set Via so TransactionManager doesn't generate one with 0.0.0.0.
        let branch = transaction::generate_branch();
        msg.set_header("Via", &format!("SIP/2.0/UDP {};branch={}", local, branch));

        msg.set_header(
            "From",
            &format!(
                "<sip:{}@{}>;tag={}",
                self.cfg.username, self.cfg.domain, from_tag
            ),
        );
        msg.set_header("To", &format!("<{}>", target_uri));
        msg.set_header("Call-ID", &invite_call_id);
        msg.set_header("CSeq", &format!("{} INVITE", seq));
        msg.set_header("Contact", &format!("<sip:{}@{}>", self.cfg.username, local));
        msg.set_header("Max-Forwards", "70");
        msg.set_header("User-Agent", "xphone");
        msg.set_header("Content-Type", "application/sdp");
        msg.body = sdp.to_vec();

        if let Some(extra) = extra_headers {
            for (k, v) in extra {
                msg.set_header(k, v);
            }
        }

        msg
    }

    /// Builds an ACK for a 2xx response to INVITE.
    fn build_ack(&self, invite: &Message, response: &Message) -> Message {
        let mut ack = Message::new_request("ACK", &invite.request_uri);
        ack.set_header("Call-ID", invite.header("Call-ID"));
        ack.set_header("From", invite.header("From"));
        ack.set_header("To", response.header("To"));
        let (cseq_num, _) = invite.cseq();
        ack.set_header("CSeq", &format!("{} ACK", cseq_num));
        ack.set_header("Max-Forwards", "70");
        ack.set_header("User-Agent", "xphone");
        let branch = transaction::generate_branch();
        let via = format!("SIP/2.0/UDP {};branch={}", self.advertised_addr, branch);
        ack.set_header("Via", &via);
        ack
    }

    /// Creates a SIP request with standard headers.
    fn build_request(
        &self,
        method: &str,
        request_uri: &str,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Message {
        let seq = self.cseq.fetch_add(1, Ordering::Relaxed) + 1;
        let local = self.advertised_addr;

        let mut msg = Message::new_request(method, request_uri);

        // Pre-set Via so TransactionManager doesn't generate one with 0.0.0.0.
        let branch = transaction::generate_branch();
        msg.set_header("Via", &format!("SIP/2.0/UDP {};branch={}", local, branch));

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
