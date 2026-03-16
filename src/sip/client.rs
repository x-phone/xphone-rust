use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use tracing::{debug, info, warn};

use super::auth::{self, Credentials};
use super::conn::{self, TlsConfig};
use super::dialog::extract_uri;
use super::message::Message;
use super::transaction::{self, TransactionManager};
use crate::error::{Error, Result};

/// Maximum number of 3xx redirect hops before giving up.
const MAX_REDIRECTS: u8 = 3;

/// Result of a successful INVITE transaction.
#[derive(Debug)]
pub struct InviteResult {
    /// The INVITE request that was sent.
    pub invite: Message,
    /// The final 2xx response.
    pub response: Message,
    /// Provisional responses received before the final response.
    pub provisionals: Vec<(u16, String)>,
    /// SDP body from 183 Session Progress (early media), if any.
    pub early_sdp: Option<String>,
}

/// Internal result from consuming INVITE responses — either success or redirect.
enum ConsumeResult {
    Success(Box<InviteResult>),
    Redirect(String),
}

/// Configuration for a SIP client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub local_addr: String,
    pub server_addr: SocketAddr,
    pub username: String,
    pub password: String,
    pub domain: String,
    /// Transport protocol: "udp", "tcp", or "tls".
    pub transport: String,
    /// TLS configuration (required when transport is "tls").
    pub tls_config: Option<TlsConfig>,
    /// STUN server address (e.g. `"stun.l.google.com:19302"`).
    pub stun_server: Option<String>,
    /// Outbound proxy address for routing INVITEs (parsed from URI).
    pub outbound_proxy: Option<SocketAddr>,
    /// Username for outbound INVITE auth. Falls back to `username` if `None`.
    pub outbound_username: Option<String>,
    /// Password for outbound INVITE auth. Falls back to `password` if `None`.
    pub outbound_password: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            local_addr: "0.0.0.0:0".into(),
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            transport: "udp".into(),
            tls_config: None,
            stun_server: None,
            outbound_proxy: None,
            outbound_username: None,
            outbound_password: None,
        }
    }
}

/// A SIP UA client that can send REGISTER and other requests,
/// and receive incoming requests (INVITE, BYE, etc.).
pub struct Client {
    tm: TransactionManager,
    cfg: ClientConfig,
    cseq: AtomicU32,
    call_id: String,
    /// The address advertised in Via/Contact headers (routable IP + bound port).
    advertised_addr: SocketAddr,
    /// Via transport tag (UDP, TCP, TLS).
    via_transport: String,
    closed: Mutex<bool>,
}

impl Client {
    /// Creates a new SIP client, binding or connecting based on transport.
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        let sip_conn = conn::connect(
            &cfg.transport,
            cfg.server_addr,
            &cfg.local_addr,
            &cfg.domain,
            cfg.tls_config.as_ref(),
            Duration::from_secs(10),
        )
        .map_err(|e| Error::Other(format!("sip: connect: {}", e)))?;

        let local_addr = sip_conn
            .local_addr()
            .map_err(|e| Error::Other(format!("sip: local addr: {}", e)))?;
        let via_transport = sip_conn.transport_name().to_string();
        let tm = TransactionManager::new(sip_conn);
        let call_id = transaction::generate_branch();

        // Compute a routable IP to advertise in Via/Contact headers.
        // Priority: STUN mapped address > UDP connect heuristic > local address.
        let advertised_addr = if local_addr.ip().is_unspecified() {
            if let Some(stun_addr) = Self::try_stun(&cfg) {
                info!("STUN mapped address: {}", stun_addr);
                SocketAddr::new(stun_addr.ip(), local_addr.port())
            } else {
                // Fallback: UDP connect trick to determine local routable IP.
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
            }
        } else {
            local_addr
        };

        Ok(Self {
            tm,
            cfg,
            cseq: AtomicU32::new(0),
            call_id,
            advertised_addr,
            via_transport,
            closed: Mutex::new(false),
        })
    }

    /// Attempts a STUN Binding Request to discover the NAT-mapped address.
    /// Returns `None` if no STUN server is configured or if the request fails.
    fn try_stun(cfg: &ClientConfig) -> Option<SocketAddr> {
        let stun_server_str = cfg.stun_server.as_deref()?;
        let stun_addr = match crate::stun::resolve_stun_server(stun_server_str) {
            Ok(a) => a,
            Err(e) => {
                debug!("STUN resolve failed: {}", e);
                return None;
            }
        };

        let probe = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                debug!("STUN bind failed: {}", e);
                return None;
            }
        };

        match crate::stun::stun_mapped_address(&probe, stun_addr, Duration::from_secs(3)) {
            Ok(mapped) => Some(mapped),
            Err(e) => {
                debug!("STUN request failed: {}", e);
                None
            }
        }
    }

    /// Returns the advertised address (routable IP + bound port)
    /// for use in Contact/Via headers.
    pub fn local_addr(&self) -> SocketAddr {
        self.advertised_addr
    }

    /// Returns the Via transport tag (UDP, TCP, TLS).
    pub fn via_transport(&self) -> &str {
        &self.via_transport
    }

    /// Shuts down the client.
    pub fn close(&self) {
        *self.closed.lock() = true;
        self.tm.stop();
    }

    /// Registers a callback for incoming SIP requests.
    pub fn on_incoming<F>(&self, f: F)
    where
        F: Fn(Message, SocketAddr) + Send + Sync + 'static,
    {
        self.tm.on_request(f);
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

        debug!(method = "REGISTER", uri = %request_uri, server = %self.cfg.server_addr, "SIP >>> sending");
        let resp = self.tm.send(&mut req, self.cfg.server_addr, timeout)?;
        debug!(method = "REGISTER", status = resp.status_code, reason = %resp.reason, "SIP <<< response");
        let branch = req.via_branch().to_string();

        // Handle 401 auth challenge.
        if resp.status_code == 401 {
            self.tm.remove_tx(&branch);
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
            debug!(method = "REGISTER", "SIP >>> re-sending with auth");
            let resp = self.tm.send(&mut retry, self.cfg.server_addr, timeout)?;
            info!(method = "REGISTER", status = resp.status_code, reason = %resp.reason, "SIP <<< auth response");
            let retry_branch = retry.via_branch().to_string();
            self.tm.remove_tx(&retry_branch);
            return Ok((resp.status_code, resp.reason.clone()));
        }

        self.tm.remove_tx(&branch);
        Ok((resp.status_code, resp.reason.clone()))
    }

    /// Sends REGISTER with Expires: 0 to unregister from the server.
    pub fn send_unregister(&self, timeout: Duration) -> Result<(u16, String)> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let request_uri = format!("sip:{}", self.cfg.domain);
        let mut extra = HashMap::new();
        extra.insert("Expires".to_string(), "0".to_string());
        let mut req = self.build_request("REGISTER", &request_uri, Some(&extra));

        info!("SIP >>> REGISTER Expires=0 (unregister)");
        let resp = self.tm.send(&mut req, self.cfg.server_addr, timeout)?;
        let branch = req.via_branch().to_string();

        // Handle 401 auth challenge.
        if resp.status_code == 401 {
            self.tm.remove_tx(&branch);
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

            let mut extra2 = HashMap::new();
            extra2.insert("Authorization".to_string(), auth_val);
            extra2.insert("Expires".to_string(), "0".to_string());
            let mut retry = self.build_request("REGISTER", &request_uri, Some(&extra2));
            let resp = self.tm.send(&mut retry, self.cfg.server_addr, timeout)?;
            info!(status = resp.status_code, "SIP <<< unregister response");
            let retry_branch = retry.via_branch().to_string();
            self.tm.remove_tx(&retry_branch);
            return Ok((resp.status_code, resp.reason.clone()));
        }

        self.tm.remove_tx(&branch);
        info!(status = resp.status_code, "SIP <<< unregister response");
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

    /// Returns the INVITE destination: outbound proxy if set, otherwise registrar.
    fn outbound_dest(&self) -> SocketAddr {
        self.cfg.outbound_proxy.unwrap_or(self.cfg.server_addr)
    }

    /// Returns the username for outbound INVITE auth (falls back to main credentials).
    fn outbound_username(&self) -> &str {
        self.cfg
            .outbound_username
            .as_deref()
            .unwrap_or(&self.cfg.username)
    }

    /// Returns the password for outbound INVITE auth (falls back to main credentials).
    fn outbound_password(&self) -> &str {
        self.cfg
            .outbound_password
            .as_deref()
            .unwrap_or(&self.cfg.password)
    }

    /// Returns the configured domain.
    pub fn domain(&self) -> &str {
        &self.cfg.domain
    }

    /// Sends a SIP INVITE with SDP body.
    /// Handles 401/407 auth challenges, 3xx redirects (up to 3 hops),
    /// consumes provisional responses, sends ACK on 200 OK, and returns the full result.
    pub fn send_invite(
        &self,
        target_uri: &str,
        sdp: &[u8],
        timeout: Duration,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Result<InviteResult> {
        let mut current_target = target_uri.to_string();
        let mut redirects: u8 = 0;

        loop {
            if redirects > 0 {
                info!(hop = redirects, target = %current_target, "SIP >>> following 3xx redirect");
            }
            match self.send_invite_once(&current_target, sdp, timeout, extra_headers)? {
                ConsumeResult::Success(result) => return Ok(*result),
                ConsumeResult::Redirect(new_target) => {
                    redirects += 1;
                    if redirects >= MAX_REDIRECTS {
                        return Err(Error::Other(format!(
                            "sip: too many redirects (max {})",
                            MAX_REDIRECTS
                        )));
                    }
                    current_target = new_target;
                }
            }
        }
    }

    /// Sends a single INVITE attempt (with auth retry), returning Success or Redirect.
    fn send_invite_once(
        &self,
        target_uri: &str,
        sdp: &[u8],
        timeout: Duration,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Result<ConsumeResult> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let mut req = self.build_invite_request(target_uri, sdp, extra_headers);

        // Route to outbound proxy if configured, otherwise to registrar.
        let dest = self.outbound_dest();
        info!(method = "INVITE", target = %target_uri, server = %dest, "SIP >>> sending");
        let resp = self.tm.send(&mut req, dest, timeout)?;
        debug!(method = "INVITE", status = resp.status_code, reason = %resp.reason, "SIP <<< response");
        let branch = req.via_branch().to_string();

        let (resp, branch, invite) = if resp.status_code == 401 || resp.status_code == 407 {
            self.tm.remove_tx(&branch);
            let auth_hdr_name = if resp.status_code == 401 {
                "WWW-Authenticate"
            } else {
                "Proxy-Authenticate"
            };
            let auth_hdr = resp.header(auth_hdr_name);
            let ch = auth::parse_challenge(auth_hdr)
                .map_err(|_| Error::Other("sip: auth challenge parse failed".into()))?;
            // Use outbound credentials for INVITE auth when available.
            let creds = Credentials {
                username: self.outbound_username().to_string(),
                password: self.outbound_password().to_string(),
            };
            let auth_val = auth::build_authorization(&ch, &creds, "INVITE", target_uri);
            let auth_resp_hdr = if resp.status_code == 401 {
                "Authorization"
            } else {
                "Proxy-Authorization"
            };

            // Merge caller's extra headers first, then insert auth header
            // so the computed digest always wins (prevents accidental overwrite).
            let mut auth_extra = HashMap::new();
            if let Some(eh) = extra_headers {
                for (k, v) in eh {
                    auth_extra.insert(k.clone(), v.clone());
                }
            }
            auth_extra.insert(auth_resp_hdr.to_string(), auth_val);
            let mut retry = self.build_invite_request(target_uri, sdp, Some(&auth_extra));
            debug!(method = "INVITE", "SIP >>> re-sending with auth");
            let resp = self.tm.send(&mut retry, dest, timeout)?;
            debug!(method = "INVITE", status = resp.status_code, reason = %resp.reason, "SIP <<< auth response");
            let branch = retry.via_branch().to_string();
            (resp, branch, retry)
        } else {
            (resp, branch, req)
        };

        self.consume_invite_responses(invite, resp, &branch, timeout)
    }

    /// Consumes provisional responses and returns Success, Redirect, or error.
    fn consume_invite_responses(
        &self,
        invite: Message,
        first_resp: Message,
        branch: &str,
        timeout: Duration,
    ) -> Result<ConsumeResult> {
        let mut provisionals = Vec::new();
        let mut early_sdp = None;
        let mut resp = first_resp;

        while (100..200).contains(&resp.status_code) {
            debug!(status = resp.status_code, reason = %resp.reason, "SIP <<< provisional");
            // Capture SDP from 183 Session Progress for early media.
            if resp.status_code == 183 && !resp.body.is_empty() {
                let sdp_str = String::from_utf8_lossy(&resp.body).to_string();
                debug!(sdp_len = sdp_str.len(), "SIP <<< 183 early media SDP");
                early_sdp = Some(sdp_str);
            }
            provisionals.push((resp.status_code, resp.reason.clone()));
            resp = self.tm.read_response(branch, timeout)?;
        }

        if resp.status_code >= 200 && resp.status_code < 300 {
            info!(status = resp.status_code, reason = %resp.reason, "SIP <<< final response, sending ACK");
            // Send ACK for 2xx.
            let ack = self.build_ack(&invite, &resp);
            self.tm.remove_tx(branch);
            self.tm.send_raw(&ack.to_bytes(), self.cfg.server_addr)?;
            Ok(ConsumeResult::Success(Box::new(InviteResult {
                invite,
                response: resp,
                provisionals,
                early_sdp,
            })))
        } else if resp.status_code >= 300 && resp.status_code < 400 {
            // 3xx redirect — extract target from Contact header.
            // Send ACK for 3xx (required by RFC 3261 §17.1.1.3).
            // Non-2xx ACK reuses the INVITE's Via branch (same transaction).
            let ack = self.build_ack_non2xx(&invite, &resp, branch);
            if let Err(e) = self.tm.send_raw(&ack.to_bytes(), self.cfg.server_addr) {
                warn!(error = %e, "failed to send ACK for 3xx redirect");
            }
            self.tm.remove_tx(branch);

            let contact = resp.header("Contact");
            let new_target = extract_uri(contact).trim().to_string();
            if new_target.is_empty() {
                return Err(Error::Other(format!(
                    "sip: {} {} redirect with no Contact URI",
                    resp.status_code, resp.reason
                )));
            }
            info!(status = resp.status_code, target = %new_target, "SIP <<< redirect");
            Ok(ConsumeResult::Redirect(new_target))
        } else {
            self.tm.remove_tx(branch);
            Err(Error::Other(format!(
                "sip: INVITE rejected: {} {}",
                resp.status_code, resp.reason
            )))
        }
    }

    /// Sends a SIP SUBSCRIBE request to the given URI with extra headers.
    /// Handles 401/407 auth challenges automatically.
    pub fn send_subscribe(
        &self,
        subscribe_uri: &str,
        extra_headers: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<(u16, String)> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let mut req = self.build_request("SUBSCRIBE", subscribe_uri, Some(extra_headers));
        // Override To header to target the subscription URI.
        req.set_header("To", &format!("<{}>", subscribe_uri));

        debug!(method = "SUBSCRIBE", uri = %subscribe_uri, "SIP >>> sending");
        let resp = self.tm.send(&mut req, self.cfg.server_addr, timeout)?;
        debug!(method = "SUBSCRIBE", status = resp.status_code, reason = %resp.reason, "SIP <<< response");
        let branch = req.via_branch().to_string();

        // Handle 401/407 auth challenge.
        if resp.status_code == 401 || resp.status_code == 407 {
            self.tm.remove_tx(&branch);
            let (auth_hdr_name, auth_resp_hdr) = if resp.status_code == 401 {
                ("WWW-Authenticate", "Authorization")
            } else {
                ("Proxy-Authenticate", "Proxy-Authorization")
            };
            let auth_hdr = resp.header(auth_hdr_name);
            let ch = match auth::parse_challenge(auth_hdr) {
                Ok(ch) => ch,
                Err(_) => return Ok((resp.status_code, auth_hdr.to_string())),
            };
            let creds = Credentials {
                username: self.cfg.username.clone(),
                password: self.cfg.password.clone(),
            };
            let auth_val = auth::build_authorization(&ch, &creds, "SUBSCRIBE", subscribe_uri);

            let mut extra = extra_headers.clone();
            extra.insert(auth_resp_hdr.to_string(), auth_val);
            let mut retry = self.build_request("SUBSCRIBE", subscribe_uri, Some(&extra));
            retry.set_header("To", &format!("<{}>", subscribe_uri));
            debug!(method = "SUBSCRIBE", "SIP >>> re-sending with auth");
            let resp = self.tm.send(&mut retry, self.cfg.server_addr, timeout)?;
            info!(method = "SUBSCRIBE", status = resp.status_code, reason = %resp.reason, "SIP <<< auth response");
            let retry_branch = retry.via_branch().to_string();
            self.tm.remove_tx(&retry_branch);
            return Ok((resp.status_code, resp.reason.clone()));
        }

        self.tm.remove_tx(&branch);
        Ok((resp.status_code, resp.reason.clone()))
    }

    /// Sends an out-of-dialog SIP MESSAGE (RFC 3428).
    /// Handles 401/407 auth challenges automatically.
    pub fn send_message(
        &self,
        target_uri: &str,
        content_type: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<(u16, String)> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        let extra: HashMap<String, String> = [("Content-Type".into(), content_type.into())].into();
        let mut req = self.build_request("MESSAGE", target_uri, Some(&extra));
        req.set_header("To", &format!("<{}>", target_uri));
        req.body = body.to_vec();

        debug!(method = "MESSAGE", uri = %target_uri, "SIP >>> sending");
        let resp = self.tm.send(&mut req, self.cfg.server_addr, timeout)?;
        debug!(method = "MESSAGE", status = resp.status_code, reason = %resp.reason, "SIP <<< response");
        let branch = req.via_branch().to_string();

        // Handle 401/407 auth challenge.
        if resp.status_code == 401 || resp.status_code == 407 {
            self.tm.remove_tx(&branch);
            let (auth_hdr_name, auth_resp_hdr) = if resp.status_code == 401 {
                ("WWW-Authenticate", "Authorization")
            } else {
                ("Proxy-Authenticate", "Proxy-Authorization")
            };
            let auth_hdr = resp.header(auth_hdr_name);
            let ch = match auth::parse_challenge(auth_hdr) {
                Ok(ch) => ch,
                Err(_) => return Ok((resp.status_code, auth_hdr.to_string())),
            };
            let creds = Credentials {
                username: self.cfg.username.clone(),
                password: self.cfg.password.clone(),
            };
            let auth_val = auth::build_authorization(&ch, &creds, "MESSAGE", target_uri);

            let mut extra_auth = extra.clone();
            extra_auth.insert(auth_resp_hdr.to_string(), auth_val);
            let mut retry = self.build_request("MESSAGE", target_uri, Some(&extra_auth));
            retry.set_header("To", &format!("<{}>", target_uri));
            retry.body = body.to_vec();
            debug!(method = "MESSAGE", "SIP >>> re-sending with auth");
            let resp = self.tm.send(&mut retry, self.cfg.server_addr, timeout)?;
            info!(method = "MESSAGE", status = resp.status_code, reason = %resp.reason, "SIP <<< auth response");
            let retry_branch = retry.via_branch().to_string();
            self.tm.remove_tx(&retry_branch);
            return Ok((resp.status_code, resp.reason.clone()));
        }

        self.tm.remove_tx(&branch);
        Ok((resp.status_code, resp.reason.clone()))
    }

    /// Sends an in-dialog SIP request (BYE, REFER) and waits for response.
    pub fn send_dialog_request(&self, req: &mut Message, timeout: Duration) -> Result<Message> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }
        debug!(method = %req.method, "SIP >>> in-dialog request");
        let resp = self.tm.send(req, self.cfg.server_addr, timeout)?;
        debug!(method = %req.method, status = resp.status_code, reason = %resp.reason, "SIP <<< in-dialog response");
        let branch = req.via_branch().to_string();
        self.tm.remove_tx(&branch);
        Ok(resp)
    }

    /// Sends an in-dialog re-INVITE, consuming provisional responses and sending ACK on 200 OK.
    pub fn send_dialog_reinvite(&self, req: &mut Message, timeout: Duration) -> Result<Message> {
        if *self.closed.lock() {
            return Err(Error::Other("sip: client closed".into()));
        }

        debug!(method = "re-INVITE", "SIP >>> in-dialog re-INVITE");
        let invite_clone = req.clone();
        let resp = self.tm.send(req, self.cfg.server_addr, timeout)?;
        let branch = req.via_branch().to_string();

        // Consume provisional responses.
        let mut resp = resp;
        while (100..200).contains(&resp.status_code) {
            resp = self.tm.read_response(&branch, timeout)?;
        }

        if (200..300).contains(&resp.status_code) {
            // Send ACK for 2xx.
            let ack = self.build_ack(&invite_clone, &resp);
            self.tm.remove_tx(&branch);
            self.tm.send_raw(&ack.to_bytes(), self.cfg.server_addr)?;
        } else {
            self.tm.remove_tx(&branch);
        }

        Ok(resp)
    }

    /// Sends raw bytes to a specific address (for SIP responses, ACK).
    pub fn send_raw_to(&self, data: &[u8], dst: SocketAddr) -> Result<()> {
        self.tm.send_raw(data, dst)
    }

    /// Sends a CRLF NAT keepalive packet to the server.
    pub fn send_keepalive(&self) -> Result<()> {
        self.tm.send_raw(b"\r\n\r\n", self.cfg.server_addr)
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
        msg.set_header(
            "Via",
            &format!("SIP/2.0/{} {};branch={}", self.via_transport, local, branch),
        );

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
    /// Per RFC 3261, 2xx ACK is a new transaction with its own branch.
    fn build_ack(&self, invite: &Message, response: &Message) -> Message {
        let branch = transaction::generate_branch();
        self.build_ack_inner(invite, response, &branch)
    }

    /// Builds an ACK for a non-2xx (3xx-6xx) response to INVITE.
    /// Per RFC 3261 §17.1.1.3, the ACK reuses the INVITE's Via branch
    /// because it belongs to the same transaction.
    fn build_ack_non2xx(
        &self,
        invite: &Message,
        response: &Message,
        invite_branch: &str,
    ) -> Message {
        self.build_ack_inner(invite, response, invite_branch)
    }

    fn build_ack_inner(&self, invite: &Message, response: &Message, branch: &str) -> Message {
        let mut ack = Message::new_request("ACK", &invite.request_uri);
        ack.set_header("Call-ID", invite.header("Call-ID"));
        ack.set_header("From", invite.header("From"));
        ack.set_header("To", response.header("To"));
        let (cseq_num, _) = invite.cseq();
        ack.set_header("CSeq", &format!("{} ACK", cseq_num));
        ack.set_header("Max-Forwards", "70");
        ack.set_header("User-Agent", "xphone");
        let via = format!(
            "SIP/2.0/{} {};branch={}",
            self.via_transport, self.advertised_addr, branch
        );
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
        msg.set_header(
            "Via",
            &format!("SIP/2.0/{} {};branch={}", self.via_transport, local, branch),
        );

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
    use super::super::conn::{SipConnection, UdpConn};
    use super::*;

    fn test_config(port: u16) -> ClientConfig {
        ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        }
    }

    #[test]
    fn client_creates_and_closes() {
        let client = Client::new(test_config(5060)).unwrap();
        assert!(client.local_addr().port() > 0);
        assert_eq!(client.via_transport(), "UDP");
        client.close();
    }

    #[test]
    fn build_request_has_standard_headers() {
        let client = Client::new(test_config(5060)).unwrap();

        let req = client.build_request("REGISTER", "sip:pbx.local", None);
        assert_eq!(req.method, "REGISTER");
        assert!(!req.header("From").is_empty());
        assert!(!req.header("To").is_empty());
        assert!(!req.header("Call-ID").is_empty());
        assert_eq!(req.header("CSeq"), "1 REGISTER");
        assert_eq!(req.header("Max-Forwards"), "70");
        assert_eq!(req.header("User-Agent"), "xphone");
        // Via should contain the correct transport.
        assert!(req.header("Via").contains("SIP/2.0/UDP"));

        client.close();
    }

    #[test]
    fn send_register_with_401_auth() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
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
        let client = Client::new(test_config(5060)).unwrap();
        client.close();

        let result = client.send_register(Duration::from_secs(1));
        assert!(result.is_err());
    }

    #[test]
    fn send_invite_follows_302_redirect() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            // First INVITE → 302 redirect.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");
            assert!(req.request_uri.contains("1002"));

            let mut resp = Message::new_response(302, "Moved Temporarily");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", req.header("To"));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            server.send(&resp.to_bytes(), from).unwrap();

            // Client should send ACK for 302.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");

            // Second INVITE → to redirect target → 200 OK.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");
            assert_eq!(req.request_uri, "sip:1003@redirect.local");

            let mut resp = Message::new_response(200, "OK");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", &format!("{};tag=abc123", req.header("To")));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            resp.body = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec();
            server.send(&resp.to_bytes(), from).unwrap();

            // ACK for 200.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");
        });

        let sdp = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let result = client
            .send_invite("sip:1002@pbx.local", sdp, Duration::from_secs(5), None)
            .unwrap();

        // Should have followed redirect to 1003.
        assert_eq!(result.response.status_code, 200);
        assert!(result.invite.request_uri.contains("1003"));

        client.close();
        handle.join().unwrap();
    }

    #[test]
    fn send_invite_302_no_contact_returns_error() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();

            // 302 with no Contact header.
            let mut resp = Message::new_response(302, "Moved Temporarily");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", req.header("To"));
            server.send(&resp.to_bytes(), from).unwrap();

            // Consume ACK.
            let _ = server.receive(Duration::from_secs(2));
        });

        let sdp = b"v=0\r\n";
        let result = client.send_invite("sip:1002@pbx.local", sdp, Duration::from_secs(5), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no Contact URI"));

        client.close();
        handle.join().unwrap();
    }

    #[test]
    fn send_invite_too_many_redirects() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            // Respond with 302 for every INVITE (1 original + MAX_REDIRECTS - 1 followed redirects + 1 that triggers error).
            for i in 0..MAX_REDIRECTS {
                let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
                let req = super::super::message::parse(&data).unwrap();
                assert_eq!(req.method, "INVITE");

                let mut resp = Message::new_response(302, "Moved Temporarily");
                resp.set_header("Via", req.header("Via"));
                resp.set_header("Call-ID", req.header("Call-ID"));
                resp.set_header("CSeq", req.header("CSeq"));
                resp.set_header("From", req.header("From"));
                resp.set_header("To", req.header("To"));
                resp.set_header("Contact", &format!("<sip:loop{}@pbx.local>", i));
                server.send(&resp.to_bytes(), from).unwrap();

                // Consume ACK.
                let _ = server.receive(Duration::from_secs(2));
            }
        });

        let sdp = b"v=0\r\n";
        let result = client.send_invite("sip:1002@pbx.local", sdp, Duration::from_secs(5), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many redirects"));

        client.close();
        handle.join().unwrap();
    }

    #[test]
    fn send_invite_302_then_auth_challenge() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            // First INVITE → 302 redirect.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");

            let mut resp = Message::new_response(302, "Moved Temporarily");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", req.header("To"));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            server.send(&resp.to_bytes(), from).unwrap();

            // ACK for 302.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");

            // Second INVITE (to redirect target) → 401 auth challenge.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");
            assert_eq!(req.request_uri, "sip:1003@redirect.local");

            let mut resp = Message::new_response(401, "Unauthorized");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", req.header("To"));
            resp.set_header(
                "WWW-Authenticate",
                r#"Digest realm="asterisk",nonce="xyz789",algorithm=MD5"#,
            );
            server.send(&resp.to_bytes(), from).unwrap();

            // Third INVITE (with auth) → 200 OK.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");
            let auth = req.header("Authorization");
            assert!(auth.contains("Digest "), "expected Authorization header");

            let mut resp = Message::new_response(200, "OK");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", &format!("{};tag=xyz789", req.header("To")));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            resp.body = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec();
            server.send(&resp.to_bytes(), from).unwrap();

            // ACK for 200.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");
        });

        let sdp = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let result = client
            .send_invite("sip:1002@pbx.local", sdp, Duration::from_secs(5), None)
            .unwrap();

        assert_eq!(result.response.status_code, 200);
        assert!(result.invite.request_uri.contains("1003"));

        client.close();
        handle.join().unwrap();
    }

    #[test]
    fn send_invite_provisional_then_302() {
        let server = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr,
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
            ..Default::default()
        };
        let client = Client::new(cfg).unwrap();

        let handle = std::thread::spawn(move || {
            // First INVITE → 100 Trying → 302 redirect.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");

            // Send 100 Trying.
            let mut trying = Message::new_response(100, "Trying");
            trying.set_header("Via", req.header("Via"));
            trying.set_header("Call-ID", req.header("Call-ID"));
            trying.set_header("CSeq", req.header("CSeq"));
            trying.set_header("From", req.header("From"));
            trying.set_header("To", req.header("To"));
            server.send(&trying.to_bytes(), from).unwrap();

            // Then 302.
            let mut resp = Message::new_response(302, "Moved Temporarily");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", req.header("To"));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            server.send(&resp.to_bytes(), from).unwrap();

            // ACK for 302.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");

            // Second INVITE → 200 OK.
            let (data, from) = server.receive(Duration::from_secs(2)).unwrap();
            let req = super::super::message::parse(&data).unwrap();
            assert_eq!(req.method, "INVITE");
            assert_eq!(req.request_uri, "sip:1003@redirect.local");

            let mut resp = Message::new_response(200, "OK");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));
            resp.set_header("From", req.header("From"));
            resp.set_header("To", &format!("{};tag=abc999", req.header("To")));
            resp.set_header("Contact", "<sip:1003@redirect.local>");
            resp.body = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec();
            server.send(&resp.to_bytes(), from).unwrap();

            // ACK for 200.
            let (data, _) = server.receive(Duration::from_secs(2)).unwrap();
            let ack = super::super::message::parse(&data).unwrap();
            assert_eq!(ack.method, "ACK");
        });

        let sdp = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let result = client
            .send_invite("sip:1002@pbx.local", sdp, Duration::from_secs(5), None)
            .unwrap();

        assert_eq!(result.response.status_code, 200);
        assert!(result.invite.request_uri.contains("1003"));

        client.close();
        handle.join().unwrap();
    }
}
