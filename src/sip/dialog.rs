use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::client::Client;
use super::message::Message;
use super::transaction::generate_branch;
use crate::dialog::Dialog;
use crate::error::{Error, Result};

const SIP_TIMEOUT: Duration = Duration::from_secs(5);

/// Extracts the URI from a Contact/From/To header value.
/// e.g. `<sip:1001@10.0.0.1:5060>` -> `sip:1001@10.0.0.1:5060`
fn extract_uri(header_val: &str) -> String {
    if let (Some(start), Some(end)) = (header_val.find('<'), header_val.find('>')) {
        if end > start {
            return header_val[start + 1..end].to_string();
        }
    }
    header_val.to_string()
}

/// Builds a SIP response echoing the Via, From, To, Call-ID, CSeq from a request.
pub(crate) fn build_sip_response(req: &Message, code: u16, reason: &str) -> Message {
    let mut resp = Message::new_response(code, reason);
    for via in req.header_values("Via") {
        resp.add_header("Via", via);
    }
    resp.set_header("From", req.header("From"));
    resp.set_header("To", req.header("To"));
    resp.set_header("Call-ID", req.header("Call-ID"));
    resp.set_header("CSeq", req.header("CSeq"));
    resp
}

// ---------------------------------------------------------------------------
// UAC Dialog (outbound calls)
// ---------------------------------------------------------------------------

/// Production Dialog for outbound calls (UAC side).
/// Created after a successful INVITE + 200 OK exchange.
type NotifyCallback = Arc<dyn Fn(u16) + Send + Sync>;

pub struct SipDialogUAC {
    client: Arc<Client>,
    call_id: String,
    from_hdr: String,
    to_hdr: String,
    remote_target: String,
    route_set: Vec<String>,
    cseq: AtomicU32,
    invite: Message,
    response: Mutex<Option<Message>>,
    on_notify_fn: Mutex<Option<NotifyCallback>>,
}

impl std::fmt::Debug for SipDialogUAC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipDialogUAC")
            .field("call_id", &self.call_id)
            .finish()
    }
}

impl SipDialogUAC {
    /// Creates a UAC dialog from the sent INVITE and the 200 OK response.
    pub fn new(client: Arc<Client>, invite: Message, response: Message) -> Self {
        let call_id = invite.header("Call-ID").to_string();
        let from_hdr = invite.header("From").to_string();
        let to_hdr = response.header("To").to_string();
        let remote_target = extract_uri(response.header("Contact"));

        let mut route_set: Vec<String> = response
            .header_values("Record-Route")
            .iter()
            .map(|s| s.to_string())
            .collect();
        route_set.reverse();

        let (cseq_num, _) = invite.cseq();

        Self {
            client,
            call_id,
            from_hdr,
            to_hdr,
            remote_target,
            route_set,
            cseq: AtomicU32::new(cseq_num),
            invite,
            response: Mutex::new(Some(response)),
            on_notify_fn: Mutex::new(None),
        }
    }

    fn build_request(&self, method: &str) -> Message {
        let cseq = self.cseq.fetch_add(1, Ordering::Relaxed) + 1;
        let target = if self.remote_target.is_empty() {
            self.invite.request_uri.clone()
        } else {
            self.remote_target.clone()
        };
        let mut req = Message::new_request(method, &target);

        // Pre-set Via with advertised address so TransactionManager doesn't use 0.0.0.0.
        let branch = generate_branch();
        req.set_header(
            "Via",
            &format!("SIP/2.0/UDP {};branch={}", self.client.local_addr(), branch),
        );

        req.set_header("Call-ID", &self.call_id);
        req.set_header("From", &self.from_hdr);
        req.set_header("To", &self.to_hdr);
        req.set_header("CSeq", &format!("{} {}", cseq, method));
        req.set_header(
            "Contact",
            &format!(
                "<sip:{}@{}>",
                self.client.username(),
                self.client.local_addr()
            ),
        );
        req.set_header("Max-Forwards", "70");
        req.set_header("User-Agent", "xphone");
        for route in &self.route_set {
            req.add_header("Route", route);
        }
        req
    }
}

impl Dialog for SipDialogUAC {
    fn respond(&self, _code: u16, _reason: &str, _body: &[u8]) -> Result<()> {
        Err(Error::InvalidState) // UAC cannot respond to INVITE
    }

    fn send_bye(&self) -> Result<()> {
        let mut req = self.build_request("BYE");
        let _ = self.client.send_dialog_request(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn send_cancel(&self) -> Result<()> {
        Err(Error::Other("cancel not yet implemented".into()))
    }

    fn send_reinvite(&self, sdp: &[u8]) -> Result<()> {
        let mut req = self.build_request("INVITE");
        req.set_header("Content-Type", "application/sdp");
        req.body = sdp.to_vec();
        let _ = self.client.send_dialog_reinvite(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn send_refer(&self, target: &str) -> Result<()> {
        let mut req = self.build_request("REFER");
        req.set_header("Refer-To", target);
        let _ = self.client.send_dialog_request(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn on_notify(&self, f: Box<dyn Fn(u16) + Send + Sync>) {
        *self.on_notify_fn.lock() = Some(Arc::from(f));
    }

    fn call_id(&self) -> String {
        self.call_id.clone()
    }

    fn header(&self, name: &str) -> Vec<String> {
        // Response headers take precedence over INVITE headers.
        if let Some(ref resp) = *self.response.lock() {
            let val = resp.header(name);
            if !val.is_empty() {
                return vec![val.to_string()];
            }
        }
        let val = self.invite.header(name);
        if !val.is_empty() {
            vec![val.to_string()]
        } else {
            Vec::new()
        }
    }

    fn headers(&self) -> HashMap<String, Vec<String>> {
        let mut result = HashMap::new();
        result.insert("Call-ID".to_string(), vec![self.call_id.clone()]);
        result.insert("From".to_string(), vec![self.from_hdr.clone()]);
        result.insert("To".to_string(), vec![self.to_hdr.clone()]);
        result
    }
}

// ---------------------------------------------------------------------------
// UAS Dialog (inbound calls)
// ---------------------------------------------------------------------------

/// Production Dialog for inbound calls (UAS side).
/// Created when an INVITE is received.
pub struct SipDialogUAS {
    client: Arc<Client>,
    call_id: String,
    local_tag: String,
    from_hdr: String,
    to_hdr: String,
    remote_target: String,
    route_set: Vec<String>,
    cseq: AtomicU32,
    invite: Message,
    remote_addr: SocketAddr,
    response: Mutex<Option<Message>>,
    on_notify_fn: Mutex<Option<NotifyCallback>>,
}

impl std::fmt::Debug for SipDialogUAS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipDialogUAS")
            .field("call_id", &self.call_id)
            .finish()
    }
}

impl SipDialogUAS {
    /// Creates a UAS dialog from an incoming INVITE.
    pub fn new(client: Arc<Client>, invite: Message, remote_addr: SocketAddr) -> Self {
        let call_id = invite.header("Call-ID").to_string();
        let local_tag = generate_branch()[..15].to_string();
        let remote_target = extract_uri(invite.header("Contact"));

        let route_set: Vec<String> = invite
            .header_values("Record-Route")
            .iter()
            .map(|s| s.to_string())
            .collect();

        let (cseq_num, _) = invite.cseq();

        // For UAS: From/To are swapped relative to the INVITE.
        // When we send in-dialog requests (BYE, re-INVITE):
        //   Our From = INVITE's To (us) + our tag
        //   Our To   = INVITE's From (them, with their tag)
        let invite_to = invite.header("To").to_string();
        let invite_from = invite.header("From").to_string();

        Self {
            client,
            call_id,
            local_tag,
            from_hdr: invite_from,
            to_hdr: invite_to,
            remote_target,
            route_set,
            cseq: AtomicU32::new(cseq_num),
            invite,
            remote_addr,
            response: Mutex::new(None),
            on_notify_fn: Mutex::new(None),
        }
    }

    fn build_request(&self, method: &str) -> Message {
        let cseq = self.cseq.fetch_add(1, Ordering::Relaxed) + 1;
        let target = if self.remote_target.is_empty() {
            extract_uri(&self.from_hdr)
        } else {
            self.remote_target.clone()
        };
        let mut req = Message::new_request(method, &target);

        // Pre-set Via with advertised address so TransactionManager doesn't use 0.0.0.0.
        let branch = generate_branch();
        req.set_header(
            "Via",
            &format!("SIP/2.0/UDP {};branch={}", self.client.local_addr(), branch),
        );

        req.set_header("Call-ID", &self.call_id);
        // For UAS sending requests: From = us (INVITE's To + our tag), To = them (INVITE's From)
        let our_from = if self.to_hdr.contains("tag=") {
            self.to_hdr.clone()
        } else {
            format!("{};tag={}", self.to_hdr, self.local_tag)
        };
        req.set_header("From", &our_from);
        req.set_header("To", &self.from_hdr);
        req.set_header("CSeq", &format!("{} {}", cseq, method));
        req.set_header(
            "Contact",
            &format!(
                "<sip:{}@{}>",
                self.client.username(),
                self.client.local_addr()
            ),
        );
        req.set_header("Max-Forwards", "70");
        req.set_header("User-Agent", "xphone");
        for route in &self.route_set {
            req.add_header("Route", route);
        }
        req
    }
}

impl Dialog for SipDialogUAS {
    fn respond(&self, code: u16, reason: &str, body: &[u8]) -> Result<()> {
        let mut resp = build_sip_response(&self.invite, code, reason);

        // Add our tag to To header.
        let to = self.invite.header("To");
        if !to.contains("tag=") {
            resp.set_header("To", &format!("{};tag={}", to, self.local_tag));
        }

        // Add Contact header.
        resp.set_header(
            "Contact",
            &format!(
                "<sip:{}@{}>",
                self.client.username(),
                self.client.local_addr()
            ),
        );

        if !body.is_empty() {
            resp.set_header("Content-Type", "application/sdp");
            resp.body = body.to_vec();
        }

        self.client
            .send_raw_to(&resp.to_bytes(), self.remote_addr)?;

        if (200..300).contains(&code) {
            *self.response.lock() = Some(resp);
        }

        Ok(())
    }

    fn send_bye(&self) -> Result<()> {
        let mut req = self.build_request("BYE");
        let _ = self.client.send_dialog_request(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn send_cancel(&self) -> Result<()> {
        Err(Error::InvalidState) // UAS cannot send CANCEL
    }

    fn send_reinvite(&self, sdp: &[u8]) -> Result<()> {
        let mut req = self.build_request("INVITE");
        req.set_header("Content-Type", "application/sdp");
        req.body = sdp.to_vec();
        let _ = self.client.send_dialog_reinvite(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn send_refer(&self, target: &str) -> Result<()> {
        let mut req = self.build_request("REFER");
        req.set_header("Refer-To", target);
        let _ = self.client.send_dialog_request(&mut req, SIP_TIMEOUT)?;
        Ok(())
    }

    fn on_notify(&self, f: Box<dyn Fn(u16) + Send + Sync>) {
        *self.on_notify_fn.lock() = Some(Arc::from(f));
    }

    fn call_id(&self) -> String {
        self.call_id.clone()
    }

    fn header(&self, name: &str) -> Vec<String> {
        // Response headers take precedence.
        if let Some(ref resp) = *self.response.lock() {
            let val = resp.header(name);
            if !val.is_empty() {
                return vec![val.to_string()];
            }
        }
        let val = self.invite.header(name);
        if !val.is_empty() {
            vec![val.to_string()]
        } else {
            Vec::new()
        }
    }

    fn headers(&self) -> HashMap<String, Vec<String>> {
        let mut result = HashMap::new();
        result.insert("Call-ID".to_string(), vec![self.call_id.clone()]);
        result.insert("From".to_string(), vec![self.from_hdr.clone()]);
        result.insert("To".to_string(), vec![self.to_hdr.clone()]);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::client::ClientConfig;
    use crate::sip::message;

    fn test_client() -> Arc<Client> {
        let cfg = ClientConfig {
            local_addr: "127.0.0.1:0".into(),
            server_addr: "127.0.0.1:15070".parse().unwrap(),
            username: "1001".into(),
            password: "test".into(),
            domain: "pbx.local".into(),
        };
        Arc::new(Client::new(cfg).unwrap())
    }

    fn sample_invite() -> Message {
        let sdp = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0 8\r\n";
        let raw = format!(
            "INVITE sip:1002@pbx.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKinv1\r\n\
             From: <sip:1001@pbx.local>;tag=from1\r\n\
             To: <sip:1002@pbx.local>\r\n\
             Call-ID: test-call-id-123\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:1001@10.0.0.1:5060>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            sdp.len(),
            sdp
        );
        message::parse(raw.as_bytes()).unwrap()
    }

    fn sample_200ok() -> Message {
        let sdp = "v=0\r\no=- 0 0 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0 8\r\n";
        let raw = format!(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKinv1\r\n\
             From: <sip:1001@pbx.local>;tag=from1\r\n\
             To: <sip:1002@pbx.local>;tag=to2\r\n\
             Call-ID: test-call-id-123\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:1002@10.0.0.2:5060>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            sdp.len(),
            sdp
        );
        message::parse(raw.as_bytes()).unwrap()
    }

    // --- UAC Dialog tests ---

    #[test]
    fn uac_call_id() {
        let client = test_client();
        let dlg = SipDialogUAC::new(client, sample_invite(), sample_200ok());
        assert_eq!(dlg.call_id(), "test-call-id-123");
        dlg.client.close();
    }

    #[test]
    fn uac_headers() {
        let client = test_client();
        let dlg = SipDialogUAC::new(client, sample_invite(), sample_200ok());
        let from = dlg.header("From");
        assert_eq!(from.len(), 1);
        assert!(from[0].contains("1001"));
        let to = dlg.header("To");
        assert!(to[0].contains("tag=to2"));
        dlg.client.close();
    }

    #[test]
    fn uac_respond_returns_error() {
        let client = test_client();
        let dlg = SipDialogUAC::new(client, sample_invite(), sample_200ok());
        let result = dlg.respond(200, "OK", b"");
        assert!(result.is_err());
        dlg.client.close();
    }

    // --- UAS Dialog tests ---

    #[test]
    fn uas_call_id() {
        let client = test_client();
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let dlg = SipDialogUAS::new(client, sample_invite(), addr);
        assert_eq!(dlg.call_id(), "test-call-id-123");
        dlg.client.close();
    }

    #[test]
    fn uas_cancel_returns_error() {
        let client = test_client();
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let dlg = SipDialogUAS::new(client, sample_invite(), addr);
        let result = dlg.send_cancel();
        assert!(result.is_err());
        dlg.client.close();
    }

    #[test]
    fn uas_header_from_invite() {
        let client = test_client();
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let dlg = SipDialogUAS::new(client, sample_invite(), addr);
        let from = dlg.header("From");
        assert_eq!(from.len(), 1);
        assert!(from[0].contains("1001"));
        dlg.client.close();
    }

    // --- build_sip_response tests ---

    #[test]
    fn build_response_echoes_headers() {
        let invite = sample_invite();
        let resp = build_sip_response(&invite, 100, "Trying");
        assert_eq!(resp.status_code, 100);
        assert_eq!(resp.reason, "Trying");
        assert_eq!(resp.header("Call-ID"), "test-call-id-123");
        assert_eq!(resp.header("CSeq"), "1 INVITE");
        assert!(!resp.header("Via").is_empty());
    }

    #[test]
    fn extract_uri_from_contact() {
        assert_eq!(
            extract_uri("<sip:1001@10.0.0.1:5060>"),
            "sip:1001@10.0.0.1:5060"
        );
        assert_eq!(
            extract_uri("\"Alice\" <sip:alice@host>;tag=abc"),
            "sip:alice@host"
        );
        assert_eq!(extract_uri("sip:plain@host"), "sip:plain@host");
    }
}
