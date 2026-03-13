//! `Dialog` implementation backed by trunk SIP transport.
//!
//! Bridges xphone's synchronous `Dialog` trait to the trunk server's async UDP
//! socket by queuing outgoing SIP messages through a bounded channel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::sip::message::Message;
use crate::trunk::util::{append_tag, extract_tag, extract_uri, generate_branch};

/// An outgoing SIP datagram to be sent by the server's send task.
pub struct SipOutgoing {
    pub data: Vec<u8>,
    pub addr: SocketAddr,
}

/// Dialog role — determines From/To handling in outgoing SIP requests.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DialogRole {
    /// UAS (inbound): we received the INVITE, swap From/To in outgoing requests.
    Uas,
    /// UAC (outbound): we originated the INVITE, keep From/To as-is.
    Uac,
}

/// `Dialog` implementation backed by the trunk server's UDP transport.
///
/// When xphone's `Call` calls `respond()`, `send_bye()`, etc., this impl builds
/// the SIP message and enqueues it for async delivery by the server's send task.
pub struct TrunkDialog {
    role: DialogRole,
    tx: mpsc::Sender<SipOutgoing>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    sip_call_id: String,
    remote_tag: Mutex<String>,
    /// Pre-computed From header with local tag appended.
    local_from_tagged: String,
    remote_to: String,
    /// Original INVITE Via headers (UAS uses for responses — all must be preserved).
    invite_vias: Vec<String>,
    invite_cseq_num: u32,
    /// Request-URI for in-dialog requests (BYE, re-INVITE, etc.).
    contact_uri: Mutex<String>,
    /// Headers from the INVITE (for `header()`/`headers()` methods).
    invite_headers: HashMap<String, Vec<String>>,
    /// CSeq counter for outgoing requests.
    cseq_counter: AtomicU32,
    #[allow(clippy::type_complexity)]
    on_notify_fn: Mutex<Option<Arc<dyn Fn(u16) + Send + Sync>>>,
}

impl TrunkDialog {
    /// Create a UAS dialog from an incoming INVITE.
    pub(crate) fn new(
        tx: mpsc::Sender<SipOutgoing>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        invite: &Message,
        local_tag: String,
    ) -> Self {
        // Build headers map (lowercase keys for case-insensitive lookup).
        let mut headers = HashMap::with_capacity(6);
        for name in &["From", "To", "Call-ID", "Via", "Contact", "CSeq"] {
            let vals: Vec<String> = invite
                .header_values(name)
                .into_iter()
                .map(|v| v.to_string())
                .collect();
            if !vals.is_empty() {
                headers.insert(name.to_lowercase(), vals);
            }
        }

        let (cseq_num, _) = invite.cseq();

        // Derive contact URI from the INVITE's Contact header or request URI.
        let contact = invite.header("Contact");
        let contact_uri = if !contact.is_empty() {
            extract_uri(contact).to_string()
        } else {
            invite.request_uri.clone()
        };

        // UAS: our From is the INVITE's To (we're the callee).
        let local_from = invite.header("To").to_string();
        let local_from_tagged = if local_from.contains("tag=") {
            local_from
        } else {
            format!("{};tag={}", local_from, local_tag)
        };

        Self {
            role: DialogRole::Uas,
            tx,
            remote_addr,
            local_addr,
            sip_call_id: invite.header("Call-ID").to_string(),
            remote_tag: Mutex::new(String::new()),
            local_from_tagged,
            remote_to: invite.header("From").to_string(),
            invite_vias: invite
                .header_values("Via")
                .into_iter()
                .map(|v| v.to_string())
                .collect(),
            invite_cseq_num: cseq_num,
            contact_uri: Mutex::new(contact_uri),
            invite_headers: headers,
            cseq_counter: AtomicU32::new(cseq_num),
            on_notify_fn: Mutex::new(None),
        }
    }

    /// Create a UAC dialog for an outbound call to a peer.
    pub(crate) fn new_outbound(
        tx: mpsc::Sender<SipOutgoing>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        sip_call_id: String,
        local_tag: String,
        from_header: String,
        to_header: String,
    ) -> Self {
        let contact_uri = format!("sip:{}@{}", extract_uri(&to_header), remote_addr);

        let mut headers = HashMap::with_capacity(3);
        headers.insert("from".into(), vec![from_header.clone()]);
        headers.insert("to".into(), vec![to_header.clone()]);
        headers.insert("call-id".into(), vec![sip_call_id.clone()]);

        // Pre-compute tagged From header.
        let local_from_tagged = if from_header.contains("tag=") {
            from_header
        } else {
            format!("{};tag={}", from_header, local_tag)
        };

        Self {
            role: DialogRole::Uac,
            tx,
            remote_addr,
            local_addr,
            sip_call_id,
            remote_tag: Mutex::new(String::new()),
            local_from_tagged,
            remote_to: to_header,
            invite_vias: Vec::new(),
            invite_cseq_num: 1,
            contact_uri: Mutex::new(contact_uri),
            invite_headers: headers,
            cseq_counter: AtomicU32::new(1),
            on_notify_fn: Mutex::new(None),
        }
    }

    /// Update dialog state from a received SIP response (for UAC).
    /// Captures the remote tag and Contact URI from 1xx/2xx responses.
    pub(crate) fn update_from_response(&self, resp: &Message) {
        let to = resp.header("To");
        if let Some(tag) = extract_tag(to) {
            let mut remote_tag = self.remote_tag.lock();
            if remote_tag.is_empty() {
                *remote_tag = tag.to_string();
            }
        }
        let contact = resp.header("Contact");
        if !contact.is_empty() {
            *self.contact_uri.lock() = extract_uri(contact).to_string();
        }
    }

    /// Build and enqueue a SIP response (UAS only).
    fn send_response(&self, code: u16, reason: &str, body: &[u8]) -> Result<()> {
        if self.role == DialogRole::Uac {
            return Ok(());
        }
        let mut resp = Message::new_response(code, reason);
        for via in &self.invite_vias {
            resp.add_header("Via", via);
        }
        // UAS response: From = INVITE's From (remote), To = INVITE's To (us) + our tag.
        resp.set_header("From", &self.remote_to);
        resp.set_header("To", self.local_from_with_tag());
        resp.set_header("Call-ID", &self.sip_call_id);
        resp.set_header("CSeq", &format!("{} INVITE", self.invite_cseq_num));
        resp.set_header("Contact", &format!("<sip:xphone@{}>", self.local_addr));
        if !body.is_empty() {
            resp.set_header("Content-Type", "application/sdp");
            resp.body = body.to_vec();
        }
        self.enqueue(resp)
    }

    /// Build and enqueue a SIP request (BYE, re-INVITE, REFER, INFO).
    fn send_sip_request(
        &self,
        method: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<()> {
        let branch = generate_branch();
        let cseq = self.next_cseq();
        let contact_uri = self.contact_uri.lock().clone();

        // For UAS (inbound) calls, the INVITE's Contact may contain an internal
        // proxy IP (e.g. Twilio 172.x.x.x) that's unreachable. Use the edge
        // proxy address (remote_addr) in the Request-URI so the BYE routes
        // through the same path as the INVITE.
        let request_uri = if self.role == DialogRole::Uas {
            rewrite_uri_host(&contact_uri, &self.remote_addr)
        } else {
            contact_uri
        };
        let mut req = Message::new_request(method, &request_uri);
        req.set_header(
            "Via",
            &format!("SIP/2.0/UDP {};branch={}", self.local_addr, branch),
        );

        let remote_tag = self.remote_tag.lock().clone();
        req.set_header("From", self.local_from_with_tag());
        req.set_header("To", &append_tag(&self.remote_to, &remote_tag));

        req.set_header("Call-ID", &self.sip_call_id);
        req.set_header("CSeq", &format!("{} {}", cseq, method));
        req.set_header("Contact", &format!("<sip:xphone@{}>", self.local_addr));
        for (name, value) in extra_headers {
            req.set_header(name, value);
        }
        if !body.is_empty() {
            req.body = body.to_vec();
        }
        self.enqueue(req)
    }

    fn enqueue(&self, msg: Message) -> Result<()> {
        let data = msg.to_bytes();
        self.tx
            .try_send(SipOutgoing {
                data,
                addr: self.remote_addr,
            })
            .map_err(|_| Error::Other("trunk send channel full or closed".into()))
    }

    /// Our From header with local tag (pre-computed in constructor).
    fn local_from_with_tag(&self) -> &str {
        &self.local_from_tagged
    }

    fn next_cseq(&self) -> u32 {
        self.cseq_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl Dialog for TrunkDialog {
    fn respond(&self, code: u16, reason: &str, body: &[u8]) -> Result<()> {
        self.send_response(code, reason, body)
    }

    fn send_bye(&self) -> Result<()> {
        self.send_sip_request("BYE", &[], &[])
    }

    fn send_cancel(&self) -> Result<()> {
        if self.role == DialogRole::Uas {
            return Err(Error::InvalidState);
        }
        self.send_sip_request("CANCEL", &[], &[])
    }

    fn send_reinvite(&self, sdp: &[u8]) -> Result<()> {
        self.send_sip_request("INVITE", sdp, &[("Content-Type", "application/sdp")])
    }

    fn send_refer(&self, target: &str) -> Result<()> {
        self.send_sip_request("REFER", &[], &[("Refer-To", target)])
    }

    fn send_info_dtmf(&self, digit: &str, duration_ms: u32) -> Result<()> {
        let body = format!("Signal={}\r\nDuration={}\r\n", digit, duration_ms);
        self.send_sip_request(
            "INFO",
            body.as_bytes(),
            &[("Content-Type", "application/dtmf-relay")],
        )
    }

    fn on_notify(&self, f: Box<dyn Fn(u16) + Send + Sync>) {
        *self.on_notify_fn.lock() = Some(Arc::from(f));
    }

    fn fire_notify(&self, code: u16) {
        let cb = self.on_notify_fn.lock().clone();
        if let Some(f) = cb {
            f(code);
        }
    }

    fn call_id(&self) -> String {
        self.sip_call_id.clone()
    }

    fn header(&self, name: &str) -> Vec<String> {
        self.invite_headers
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    fn headers(&self) -> HashMap<String, Vec<String>> {
        self.invite_headers.clone()
    }
}

/// Rewrite the host:port in a SIP URI to use the given address.
/// `sip:+19085679691@172.25.62.99:5060;transport=udp` + `54.172.60.0:5060`
/// -> `sip:+19085679691@54.172.60.0:5060;transport=udp`
fn rewrite_uri_host(uri: &str, addr: &SocketAddr) -> String {
    if let Some((user_part, host_part)) = uri.split_once('@') {
        let params = if let Some(semi) = host_part.find(';') {
            &host_part[semi..]
        } else {
            ""
        };
        format!("{user_part}@{addr}{params}")
    } else {
        uri.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invite() -> Message {
        let mut msg = Message::new_request("INVITE", "sip:1002@xphone:5080");
        msg.add_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        msg.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        msg.set_header("To", "<sip:1002@xphone:5080>");
        msg.set_header("Call-ID", "testcall@host");
        msg.set_header("CSeq", "1 INVITE");
        msg.set_header("Contact", "<sip:1001@10.0.0.1:5060>");
        msg
    }

    fn make_dialog() -> (TrunkDialog, mpsc::Receiver<SipOutgoing>) {
        let (tx, rx) = mpsc::channel(64);
        let invite = sample_invite();
        let dialog = TrunkDialog::new(
            tx,
            "127.0.0.1:5080".parse().unwrap(),
            "10.0.0.1:5060".parse().unwrap(),
            &invite,
            "localtag123".into(),
        );
        (dialog, rx)
    }

    fn make_uac_dialog() -> (TrunkDialog, mpsc::Receiver<SipOutgoing>) {
        let (tx, rx) = mpsc::channel(64);
        let dialog = TrunkDialog::new_outbound(
            tx,
            "127.0.0.1:5080".parse().unwrap(),
            "10.0.0.1:5060".parse().unwrap(),
            "outbound-call-id@xphone".into(),
            "uactag456".into(),
            "<sip:1001@127.0.0.1:5080>".into(),
            "<sip:1002@10.0.0.1:5060>".into(),
        );
        (dialog, rx)
    }

    fn parse_outgoing(rx: &mut mpsc::Receiver<SipOutgoing>) -> Message {
        let outgoing = rx.try_recv().unwrap();
        crate::sip::message::parse(&outgoing.data).unwrap()
    }

    // ── UAS (inbound) tests ──

    #[test]
    fn respond_builds_valid_sip_response() {
        let (dialog, mut rx) = make_dialog();
        dialog.respond(200, "OK", b"v=0\r\n").unwrap();

        let outgoing = rx.try_recv().unwrap();
        let msg = crate::sip::message::parse(&outgoing.data).unwrap();

        assert!(msg.is_response());
        assert_eq!(msg.status_code, 200);
        assert_eq!(msg.header("Call-ID"), "testcall@host");
        assert!(msg.header("To").contains("tag=localtag123"));
        assert_eq!(msg.header("Content-Type"), "application/sdp");
        assert_eq!(String::from_utf8_lossy(&msg.body), "v=0\r\n");
        assert_eq!(
            outgoing.addr,
            "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn respond_preserves_all_via_headers() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut invite = sample_invite();
        invite.add_header(
            "Via",
            "SIP/2.0/UDP 172.18.65.254:5060;rport=5060;branch=z9hG4bK222",
        );
        let dialog = TrunkDialog::new(
            tx,
            "127.0.0.1:5080".parse().unwrap(),
            "10.0.0.1:5060".parse().unwrap(),
            &invite,
            "localtag123".into(),
        );
        dialog.respond(200, "OK", b"v=0\r\n").unwrap();

        let msg = parse_outgoing(&mut rx);
        let vias = msg.header_values("Via");
        assert_eq!(
            vias.len(),
            2,
            "200 OK must preserve all Via headers from INVITE"
        );
    }

    #[test]
    fn respond_without_body_has_no_content_type() {
        let (dialog, mut rx) = make_dialog();
        dialog.respond(486, "Busy Here", &[]).unwrap();
        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.status_code, 486);
        assert_eq!(msg.header("Content-Type"), "");
    }

    #[test]
    fn to_tag_is_stable_across_responses() {
        let (dialog, mut rx) = make_dialog();
        dialog.respond(180, "Ringing", &[]).unwrap();
        dialog.respond(200, "OK", &[]).unwrap();

        let msg1 = parse_outgoing(&mut rx);
        let msg2 = parse_outgoing(&mut rx);
        assert!(msg1.header("To").contains("tag=localtag123"));
        assert!(msg2.header("To").contains("tag=localtag123"));
    }

    #[test]
    fn send_bye_builds_valid_request() {
        let (dialog, mut rx) = make_dialog();
        dialog.send_bye().unwrap();

        let msg = parse_outgoing(&mut rx);
        assert!(!msg.is_response());
        assert_eq!(msg.method, "BYE");
        // UAS: Request-URI uses remote_addr (Twilio fix)
        assert_eq!(msg.request_uri, "sip:1001@10.0.0.1:5060");
        assert_eq!(msg.header("Call-ID"), "testcall@host");
        assert!(msg.header("From").contains("tag=localtag123"));
        assert!(msg.header("To").contains("from1"));
        let (seq, method) = msg.cseq();
        assert_eq!(seq, 2);
        assert_eq!(method, "BYE");
    }

    #[test]
    fn send_cancel_returns_invalid_state() {
        let (dialog, _rx) = make_dialog();
        assert!(dialog.send_cancel().is_err());
    }

    #[test]
    fn send_reinvite_includes_sdp() {
        let (dialog, mut rx) = make_dialog();
        let sdp = b"v=0\r\no=- 0 0 IN IP4 10.0.0.2\r\n";
        dialog.send_reinvite(sdp).unwrap();

        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.method, "INVITE");
        assert_eq!(msg.header("Content-Type"), "application/sdp");
        assert_eq!(msg.body, sdp);
    }

    #[test]
    fn send_refer_includes_refer_to() {
        let (dialog, mut rx) = make_dialog();
        dialog.send_refer("sip:1003@pbx.local").unwrap();

        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.method, "REFER");
        assert_eq!(msg.header("Refer-To"), "sip:1003@pbx.local");
    }

    #[test]
    fn send_info_dtmf_format() {
        let (dialog, mut rx) = make_dialog();
        dialog.send_info_dtmf("5", 250).unwrap();

        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.method, "INFO");
        assert_eq!(msg.header("Content-Type"), "application/dtmf-relay");
        let body = String::from_utf8_lossy(&msg.body);
        assert!(body.contains("Signal=5"));
        assert!(body.contains("Duration=250"));
    }

    #[test]
    fn cseq_increments() {
        let (dialog, mut rx) = make_dialog();
        dialog.send_bye().unwrap();
        let _ = dialog.send_sip_request("INFO", &[], &[]);

        let msg1 = parse_outgoing(&mut rx);
        let msg2 = parse_outgoing(&mut rx);
        let (seq1, _) = msg1.cseq();
        let (seq2, _) = msg2.cseq();
        assert_eq!(seq2, seq1 + 1);
    }

    #[test]
    fn call_id_returns_sip_call_id() {
        let (dialog, _rx) = make_dialog();
        assert_eq!(dialog.call_id(), "testcall@host");
    }

    #[test]
    fn header_returns_invite_headers() {
        let (dialog, _rx) = make_dialog();
        let from = dialog.header("From");
        assert_eq!(from.len(), 1);
        assert!(from[0].contains("1001@pbx.local"));
    }

    #[test]
    fn header_case_insensitive() {
        let (dialog, _rx) = make_dialog();
        assert_eq!(dialog.header("call-id"), dialog.header("Call-ID"));
    }

    #[test]
    fn header_missing_returns_empty() {
        let (dialog, _rx) = make_dialog();
        assert!(dialog.header("X-Nonexistent").is_empty());
    }

    #[test]
    fn headers_returns_all() {
        let (dialog, _rx) = make_dialog();
        let all = dialog.headers();
        assert!(all.contains_key("from"));
        assert!(all.contains_key("to"));
        assert!(all.contains_key("call-id"));
    }

    #[test]
    fn on_notify_fires_callback() {
        let (dialog, _rx) = make_dialog();
        let received = Arc::new(Mutex::new(None));
        let r = received.clone();
        dialog.on_notify(Box::new(move |code| {
            *r.lock() = Some(code);
        }));
        dialog.fire_notify(200);
        assert_eq!(*received.lock(), Some(200));
    }

    // ── UAC (outbound) tests ──

    #[test]
    fn uac_respond_is_noop() {
        let (dialog, mut rx) = make_uac_dialog();
        dialog.respond(200, "OK", b"v=0\r\n").unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn uac_send_bye_no_swap() {
        let (dialog, mut rx) = make_uac_dialog();
        dialog.send_bye().unwrap();

        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.method, "BYE");
        assert_eq!(msg.header("Call-ID"), "outbound-call-id@xphone");
        assert!(msg.header("From").contains("1001@127.0.0.1:5080"));
        assert!(msg.header("From").contains("tag=uactag456"));
        assert!(msg.header("To").contains("1002@10.0.0.1:5060"));
    }

    #[test]
    fn uac_send_cancel_works() {
        let (dialog, mut rx) = make_uac_dialog();
        dialog.send_cancel().unwrap();

        let msg = parse_outgoing(&mut rx);
        assert_eq!(msg.method, "CANCEL");
        assert_eq!(msg.header("Call-ID"), "outbound-call-id@xphone");
    }

    #[test]
    fn uac_update_from_response_captures_remote_tag() {
        let (dialog, mut rx) = make_uac_dialog();

        let mut resp = Message::new_response(200, "OK");
        resp.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=remotetag789");
        resp.set_header("Contact", "<sip:1002@10.0.0.1:5060>");
        dialog.update_from_response(&resp);

        dialog.send_bye().unwrap();
        let msg = parse_outgoing(&mut rx);
        assert!(msg.header("To").contains("tag=remotetag789"));
    }

    #[test]
    fn uac_update_does_not_overwrite_remote_tag() {
        let (dialog, _rx) = make_uac_dialog();

        let mut resp1 = Message::new_response(180, "Ringing");
        resp1.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=first");
        dialog.update_from_response(&resp1);

        let mut resp2 = Message::new_response(200, "OK");
        resp2.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=second");
        resp2.set_header("Contact", "<sip:1002@10.0.0.1:5060>");
        dialog.update_from_response(&resp2);

        assert_eq!(*dialog.remote_tag.lock(), "first");
    }

    #[test]
    fn uac_update_captures_contact_uri() {
        let (dialog, _rx) = make_uac_dialog();

        let mut resp = Message::new_response(200, "OK");
        resp.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=t1");
        resp.set_header("Contact", "<sip:1002@192.168.1.100:5060>");
        dialog.update_from_response(&resp);

        assert_eq!(*dialog.contact_uri.lock(), "sip:1002@192.168.1.100:5060");
    }

    // ── URI rewriting ──

    #[test]
    fn rewrite_uri_host_basic() {
        let result = rewrite_uri_host(
            "sip:+19085679691@172.25.62.99:5060",
            &"54.172.60.0:5060".parse().unwrap(),
        );
        assert_eq!(result, "sip:+19085679691@54.172.60.0:5060");
    }

    #[test]
    fn rewrite_uri_host_with_params() {
        let result = rewrite_uri_host(
            "sip:+19085679691@172.25.62.99:5060;transport=udp",
            &"54.172.60.0:5060".parse().unwrap(),
        );
        assert_eq!(result, "sip:+19085679691@54.172.60.0:5060;transport=udp");
    }

    #[test]
    fn rewrite_uri_host_no_at_sign() {
        let result = rewrite_uri_host(
            "sip:172.25.62.99:5060",
            &"54.172.60.0:5060".parse().unwrap(),
        );
        assert_eq!(result, "sip:172.25.62.99:5060");
    }
}
