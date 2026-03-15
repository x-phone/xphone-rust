use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

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
    notify_handler: Option<Arc<dyn Fn(String, u16) + Send + Sync>>,
    info_dtmf_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    mwi_notify_handler: Option<Arc<dyn Fn(String) + Send + Sync>>,
    message_handler: Option<Arc<dyn Fn(String, String, String) + Send + Sync>>,
    #[allow(clippy::type_complexity)]
    #[allow(clippy::type_complexity)]
    subscription_notify_handler:
        Option<Arc<dyn Fn(String, String, String, String, String) + Send + Sync>>,
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

        // Validate transport.
        let transport = cfg.transport.to_lowercase();
        match transport.as_str() {
            "udp" | "tcp" | "tls" => {}
            other => {
                return Err(Error::Other(format!(
                    "xphone: unsupported transport: {}",
                    other
                )));
            }
        }

        if transport == "tls" && cfg.tls_config.is_none() {
            return Err(Error::TlsConfigRequired);
        }

        let server_addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
            .parse()
            .map_err(|e| Error::Other(format!("invalid server address: {}", e)))?;

        // Parse outbound proxy URI to SocketAddr if configured.
        let outbound_proxy = cfg.outbound_proxy.as_ref().and_then(|uri| {
            parse_proxy_uri(uri).or_else(|| {
                warn!("invalid outbound_proxy URI: {uri}");
                None
            })
        });

        let client_cfg = ClientConfig {
            local_addr: "0.0.0.0:0".into(),
            server_addr,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            domain: cfg.host.clone(),
            transport: transport.clone(),
            tls_config: cfg.tls_config.clone(),
            stun_server: cfg.stun_server.clone(),
            outbound_proxy,
            outbound_username: cfg.outbound_username.clone(),
            outbound_password: cfg.outbound_password.clone(),
        };

        let client = Arc::new(Client::new(client_cfg)?);

        let inner = Arc::new(Mutex::new(Inner {
            drop_handler: None,
            incoming_handler: None,
            dialog_invite_handler: None,
            bye_handler: None,
            notify_handler: None,
            info_dtmf_handler: None,
            mwi_notify_handler: None,
            message_handler: None,
            subscription_notify_handler: None,
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
    debug!(method = %msg.method, from = %from_addr, "SIP <<< incoming request");
    match msg.method.as_str() {
        "INVITE" => handle_invite(inner, client, msg, from_addr),
        "BYE" => handle_bye(inner, client, msg, from_addr),
        "CANCEL" => handle_cancel(inner, client, msg, from_addr),
        "ACK" => {
            debug!("SIP <<< ACK received");
        }
        "NOTIFY" => handle_notify(inner, client, msg, from_addr),
        "INFO" => handle_info(inner, client, msg, from_addr),
        "MESSAGE" => handle_message(inner, client, msg, from_addr),
        "OPTIONS" => {
            debug!("SIP <<< OPTIONS keepalive, responding 200 OK");
            let resp = build_sip_response(msg, 200, "OK");
            let _ = client.send_raw_to(&resp.to_bytes(), from_addr);
        }
        other => {
            debug!(method = other, "SIP <<< unhandled request");
        }
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

    info!(from = %from, to = %to, call_id = %msg.header("Call-ID"), "SIP <<< incoming INVITE");

    // Send 100 Trying immediately to stop INVITE retransmissions.
    let trying = build_sip_response(msg, 100, "Trying");
    debug!("SIP >>> 100 Trying");
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
    let call_id = msg.header("Call-ID").to_string();
    info!(call_id = %call_id, "SIP <<< BYE received");

    // Always respond 200 OK to BYE to stop retransmissions.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (BYE)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Fire BYE handler with Call-ID.
    let cb = inner.lock().bye_handler.clone();
    if let Some(f) = cb {
        f(call_id);
    }
}

fn handle_cancel(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    info!(call_id = %call_id, "SIP <<< CANCEL received");

    // Respond 200 OK to CANCEL to stop retransmissions.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (CANCEL)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Also send 487 Request Terminated for the original INVITE.
    let mut terminated = build_sip_response(msg, 487, "Request Terminated");
    // The 487 should use the original INVITE's CSeq, not the CANCEL's.
    // Since CANCEL has the same Call-ID, branch, and CSeq method=INVITE,
    // we can reconstruct it.
    let (cseq_num, _) = msg.cseq();
    terminated.set_header("CSeq", &format!("{} INVITE", cseq_num));
    debug!("SIP >>> 487 Request Terminated");
    let _ = client.send_raw_to(&terminated.to_bytes(), from_addr);

    // Fire BYE handler with Call-ID to terminate the ringing call.
    let cb = inner.lock().bye_handler.clone();
    if let Some(f) = cb {
        f(call_id);
    }
}

fn handle_notify(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    let event = msg.header("Event").to_string();
    info!(call_id = %call_id, event = %event, "SIP <<< NOTIFY received");

    // Always respond 200 OK to NOTIFY.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (NOTIFY)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    let content_type = msg.header("Content-Type").to_string();
    let body = String::from_utf8_lossy(&msg.body).to_string();
    let sub_state = msg.header("Subscription-State").to_string();

    // Dispatch by Event header (RFC 6665).
    let event_base = event.split(';').next().unwrap_or("").trim();
    if event_base.eq_ignore_ascii_case("message-summary") {
        // MWI NOTIFY (RFC 3842).
        let cb = inner.lock().mwi_notify_handler.clone();
        if let Some(f) = cb {
            f(body);
        }
        return;
    }

    // Subscription NOTIFYs (dialog, presence, etc.) — dispatch to subscription manager.
    if !event_base.is_empty() && !event_base.eq_ignore_ascii_case("refer") {
        let from_uri = msg.header("From").to_string();
        let cb = inner.lock().subscription_notify_handler.clone();
        if let Some(f) = cb {
            f(event, content_type, body, sub_state, from_uri);
        }
        return;
    }

    // Fallback: REFER progress (sipfrag body) or legacy Content-Type based dispatch.
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("application/simple-message-summary") {
        let cb = inner.lock().mwi_notify_handler.clone();
        if let Some(f) = cb {
            f(body);
        }
        return;
    }

    let status_code = parse_sipfrag_status(&body);
    if let Some(code) = status_code {
        let cb = inner.lock().notify_handler.clone();
        if let Some(f) = cb {
            f(call_id, code);
        }
    }
}

fn handle_info(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    debug!(call_id = %call_id, "SIP <<< INFO received");

    // Always respond 200 OK to INFO.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (INFO)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Only process application/dtmf-relay bodies.
    let content_type = msg.header("Content-Type");
    if !content_type
        .to_ascii_lowercase()
        .contains("application/dtmf-relay")
    {
        debug!(content_type = %content_type, "INFO: ignoring non-dtmf-relay body");
        return;
    }

    let body = String::from_utf8_lossy(&msg.body);
    if let Some(digit) = parse_dtmf_relay(&body) {
        // Normalize lowercase a-d to uppercase for RFC 4733 compatibility.
        let digit = digit.to_ascii_uppercase();
        // Validate the digit before passing to callbacks.
        if crate::dtmf::digit_to_code(&digit).is_none() {
            debug!(digit = %digit, "INFO: ignoring invalid DTMF digit");
            return;
        }
        info!(call_id = %call_id, digit = %digit, "SIP <<< INFO DTMF");
        let cb = inner.lock().info_dtmf_handler.clone();
        if let Some(f) = cb {
            f(call_id, digit);
        }
    }
}

fn handle_message(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    info!("SIP <<< MESSAGE received");

    // Always respond 200 OK to MESSAGE.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (MESSAGE)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    let from = msg.header("From").to_string();
    let content_type = msg.header("Content-Type").to_string();
    let body = String::from_utf8_lossy(&msg.body).to_string();

    let cb = inner.lock().message_handler.clone();
    if let Some(f) = cb {
        f(from, content_type, body);
    }
}

/// Parses the Signal value from an `application/dtmf-relay` body.
/// Case-insensitive key matching for PBX interop.
/// Example body: "Signal=5\r\nDuration=160\r\n" → Some("5")
fn parse_dtmf_relay(body: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            if key.eq_ignore_ascii_case("signal") {
                let val = line[eq_pos + 1..].trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Parses the status code from a message/sipfrag body.
/// Example: "SIP/2.0 200 OK" → Some(200)
fn parse_sipfrag_status(body: &str) -> Option<u16> {
    let line = body.lines().next()?.trim();
    if line.starts_with("SIP/") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    None
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
        opts: &crate::config::DialOptions,
    ) -> Result<crate::transport::DialResult> {
        // Normalize target to SIP URI.
        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, self.client.domain())
        };

        info!(target = %target_uri, "SIP >>> dialing");

        // Build extra headers from DialOptions (caller_id, custom_headers).
        let mut extra = HashMap::new();
        if let Some(ref cid) = opts.caller_id {
            extra.insert(
                "P-Asserted-Identity".to_string(),
                format!("<sip:{}@{}>", cid, self.client.domain()),
            );
        }
        for (k, v) in &opts.custom_headers {
            extra.insert(k.clone(), v.clone());
        }
        let extra_ref = if extra.is_empty() { None } else { Some(&extra) };

        let result = self
            .client
            .send_invite(&target_uri, local_sdp, timeout, extra_ref)?;
        let remote_sdp = String::from_utf8_lossy(&result.response.body).to_string();
        info!(
            status = result.response.status_code,
            "SIP <<< INVITE final response"
        );

        let dlg = Arc::new(SipDialogUAC::new(
            Arc::clone(&self.client),
            result.invite,
            result.response,
        ));

        Ok(crate::transport::DialResult {
            dialog: dlg as Arc<dyn Dialog>,
            remote_sdp,
            early_sdp: result.early_sdp,
        })
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

    fn on_notify(&self, f: Box<dyn Fn(String, u16) + Send + Sync>) {
        self.inner.lock().notify_handler = Some(Arc::from(f));
    }

    fn on_info_dtmf(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().info_dtmf_handler = Some(Arc::from(f));
    }

    fn send_subscribe(
        &self,
        uri: &str,
        headers: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<Message> {
        let (code, reason) = self.client.send_subscribe(uri, headers, timeout)?;
        let msg = Message::new_response(code, &reason);
        Ok(msg)
    }

    fn on_mwi_notify(&self, f: Box<dyn Fn(String) + Send + Sync>) {
        self.inner.lock().mwi_notify_handler = Some(Arc::from(f));
    }

    fn send_message(
        &self,
        target: &str,
        content_type: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<()> {
        // Normalize target to SIP URI.
        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, self.client.domain())
        };

        let (code, reason) = self
            .client
            .send_message(&target_uri, content_type, body, timeout)?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(Error::Other(format!(
                "MESSAGE rejected: {} {}",
                code, reason
            )))
        }
    }

    fn on_message(&self, f: Box<dyn Fn(String, String, String) + Send + Sync>) {
        self.inner.lock().message_handler = Some(Arc::from(f));
    }

    fn on_subscription_notify(
        &self,
        f: Box<dyn Fn(String, String, String, String, String) + Send + Sync>,
    ) {
        self.inner.lock().subscription_notify_handler = Some(Arc::from(f));
    }

    fn unregister(&self, timeout: Duration) -> Result<()> {
        let _ = self.client.send_unregister(timeout)?;
        Ok(())
    }

    fn advertised_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.client.local_addr())
    }

    fn close(&self) -> Result<()> {
        self.client.close();
        Ok(())
    }
}

/// Parse a SIP proxy URI (`"sip:proxy.example.com:5060"`) to a `SocketAddr`.
/// Supports `sip:host:port`, `sip:host`, and bare `host:port` formats.
fn parse_proxy_uri(uri: &str) -> Option<SocketAddr> {
    let host_part = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);
    // Try as SocketAddr directly.
    if let Ok(addr) = host_part.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Try as IP with default SIP port.
    if let Ok(ip) = host_part.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, 5060));
    }
    // Try DNS resolution.
    use std::net::ToSocketAddrs;
    let with_port = if host_part.contains(':') {
        host_part.to_string()
    } else {
        format!("{host_part}:5060")
    };
    with_port.to_socket_addrs().ok()?.next()
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
    fn unsupported_transport_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15064,
            transport: "sctp".into(),
            ..Config::default()
        };
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn tls_without_config_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15065,
            transport: "tls".into(),
            tls_config: None,
            ..Config::default()
        };
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TLS"));
    }

    #[test]
    fn tcp_transport_accepted() {
        // TCP connect will fail (no server), but we validate the transport string is accepted.
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15066,
            transport: "tcp".into(),
            ..Config::default()
        };
        // TCP connect will fail since no server is listening,
        // but the transport validation should pass.
        let result = SipUA::new(&cfg);
        assert!(result.is_err()); // connection refused, not "unsupported transport"
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("unsupported"),
            "should not be unsupported transport error: {}",
            err
        );
    }

    #[test]
    fn parse_dtmf_relay_signal_digit() {
        assert_eq!(
            parse_dtmf_relay("Signal=5\r\nDuration=160\r\n"),
            Some("5".into())
        );
    }

    #[test]
    fn parse_dtmf_relay_star_and_hash() {
        assert_eq!(parse_dtmf_relay("Signal=*\r\n"), Some("*".into()));
        assert_eq!(parse_dtmf_relay("Signal=#\r\n"), Some("#".into()));
    }

    #[test]
    fn parse_dtmf_relay_with_spaces() {
        assert_eq!(
            parse_dtmf_relay("Signal = 9\r\nDuration = 250\r\n"),
            Some("9".into())
        );
    }

    #[test]
    fn parse_dtmf_relay_empty_body() {
        assert_eq!(parse_dtmf_relay(""), None);
    }

    #[test]
    fn parse_dtmf_relay_no_signal_line() {
        assert_eq!(parse_dtmf_relay("Duration=160\r\n"), None);
    }

    #[test]
    fn parse_dtmf_relay_case_insensitive() {
        assert_eq!(parse_dtmf_relay("signal=3\r\n"), Some("3".into()));
        assert_eq!(parse_dtmf_relay("SIGNAL=0\r\n"), Some("0".into()));
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
