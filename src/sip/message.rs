use std::fmt::Write;

use crate::error::{Error, Result};

/// A SIP header (name-value pair).
#[derive(Debug, Clone)]
struct Header {
    name: String,
    value: String,
}

/// A SIP request or response message.
///
/// For requests: `method` and `request_uri` are set, `status_code` is 0.
/// For responses: `status_code` and `reason` are set, `method` is empty.
#[derive(Debug, Clone)]
pub struct Message {
    pub method: String,
    pub request_uri: String,
    pub status_code: u16,
    pub reason: String,
    headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl Message {
    /// Create a new empty request message.
    pub fn new_request(method: &str, request_uri: &str) -> Self {
        Self {
            method: method.into(),
            request_uri: request_uri.into(),
            status_code: 0,
            reason: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Create a new empty response message.
    pub fn new_response(status_code: u16, reason: &str) -> Self {
        Self {
            method: String::new(),
            request_uri: String::new(),
            status_code,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Returns true if this message is a SIP response.
    pub fn is_response(&self) -> bool {
        self.status_code > 0
    }

    /// Returns the first value for the named header (case-insensitive).
    pub fn header(&self, name: &str) -> &str {
        for h in &self.headers {
            if h.name.eq_ignore_ascii_case(name) {
                return &h.value;
            }
        }
        ""
    }

    /// Returns all values for the named header (case-insensitive).
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Sets a header, replacing any existing values with the same name.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let mut found = false;
        let mut i = 0;
        while i < self.headers.len() {
            if self.headers[i].name.eq_ignore_ascii_case(name) {
                if !found {
                    self.headers[i].value = value.into();
                    found = true;
                    i += 1;
                } else {
                    self.headers.remove(i);
                }
            } else {
                i += 1;
            }
        }
        if !found {
            self.headers.push(Header {
                name: name.into(),
                value: value.into(),
            });
        }
    }

    /// Appends a header value (does not replace existing).
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.push(Header {
            name: name.into(),
            value: value.into(),
        });
    }

    /// Returns the branch parameter from the top Via header.
    pub fn via_branch(&self) -> &str {
        let via = self.header("Via");
        if via.is_empty() {
            return "";
        }
        param_value(via, "branch")
    }

    /// Parses the CSeq header into (sequence number, method).
    pub fn cseq(&self) -> (u32, &str) {
        let val = self.header("CSeq");
        if val.is_empty() {
            return (0, "");
        }
        let val = val.trim();
        if let Some(space) = val.find(' ') {
            if let Ok(n) = val[..space].parse() {
                return (n, &val[space + 1..]);
            }
        }
        (0, "")
    }

    /// Returns the tag parameter from the From header.
    pub fn from_tag(&self) -> &str {
        param_value(self.header("From"), "tag")
    }

    /// Returns the tag parameter from the To header.
    pub fn to_tag(&self) -> &str {
        param_value(self.header("To"), "tag")
    }

    /// Serializes the message to wire format.
    /// Content-Length is computed automatically.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = String::new();

        // Start line.
        if self.is_response() {
            let _ = write!(buf, "SIP/2.0 {} {}\r\n", self.status_code, self.reason);
        } else {
            let _ = write!(buf, "{} {} SIP/2.0\r\n", self.method, self.request_uri);
        }

        // Headers (skip any caller-set Content-Length — we compute it).
        for h in &self.headers {
            if h.name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            let _ = write!(buf, "{}: {}\r\n", h.name, h.value);
        }

        // Write computed Content-Length.
        let _ = write!(buf, "Content-Length: {}\r\n", self.body.len());

        // Blank line separating headers from body.
        buf.push_str("\r\n");

        let mut bytes = buf.into_bytes();
        if !self.body.is_empty() {
            bytes.extend_from_slice(&self.body);
        }
        bytes
    }
}

/// Parse a raw SIP message (request or response).
pub fn parse(data: &[u8]) -> Result<Message> {
    if data.is_empty() {
        return Err(Error::Other("sip: empty message".into()));
    }

    // Split into head and body at the blank line.
    let head_end = find_subsequence(data, b"\r\n\r\n");
    let (head, body) = match head_end {
        Some(pos) => (&data[..pos], &data[pos + 4..]),
        None => (data, &[] as &[u8]),
    };

    // Split head into lines.
    let head_str = std::str::from_utf8(head)
        .map_err(|_| Error::Other("sip: invalid utf-8 in headers".into()))?;
    let mut lines = head_str.split("\r\n");

    let start_line = lines
        .next()
        .ok_or_else(|| Error::Other("sip: no start line".into()))?;
    if start_line.is_empty() {
        return Err(Error::Other("sip: empty start line".into()));
    }

    let mut msg = Message {
        method: String::new(),
        request_uri: String::new(),
        status_code: 0,
        reason: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };

    if let Some(rest) = start_line.strip_prefix("SIP/2.0 ") {
        // Response: "SIP/2.0 200 OK"
        let space = rest
            .find(' ')
            .ok_or_else(|| Error::Other("sip: malformed status line".into()))?;
        let code: u16 = rest[..space]
            .parse()
            .map_err(|_| Error::Other("sip: invalid status code".into()))?;
        msg.status_code = code;
        msg.reason = rest[space + 1..].into();
    } else {
        // Request: "INVITE sip:1002@pbx.local SIP/2.0"
        let parts: Vec<&str> = start_line.splitn(3, ' ').collect();
        if parts.len() < 3 || parts[2] != "SIP/2.0" {
            return Err(Error::Other("sip: malformed request line".into()));
        }
        msg.method = parts[0].into();
        msg.request_uri = parts[1].into();
    }

    // Parse headers.
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(colon) = line.find(':') {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            msg.headers.push(Header {
                name: name.into(),
                value: value.into(),
            });
        }
    }

    // Body: use Content-Length if present, otherwise use remaining data.
    if head_end.is_some() && !body.is_empty() {
        let cl_str = msg.header("Content-Length");
        if !cl_str.is_empty() {
            if let Ok(cl) = cl_str.parse::<usize>() {
                if cl > 0 && cl <= body.len() {
                    msg.body = body[..cl].to_vec();
                } else if cl > body.len() {
                    // Truncated: use whatever data we have (matches Go behavior).
                    msg.body = body.to_vec();
                }
                // cl == 0 means explicit zero-length body
            } else {
                msg.body = body.to_vec();
            }
        } else {
            msg.body = body.to_vec();
        }
    }

    Ok(msg)
}

/// Extract a parameter value from a SIP header value string.
/// Example: `param_value("SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK123;rport", "branch")` => `"z9hG4bK123"`
fn param_value<'a>(header_val: &'a str, param: &str) -> &'a str {
    // Split on ';' and find the matching param (case-insensitive ASCII).
    let search = format!("{}=", param);
    for part in header_val.split(';') {
        let trimmed = part.trim();
        if trimmed.len() >= search.len() && trimmed[..search.len()].eq_ignore_ascii_case(&search) {
            let val = &trimmed[search.len()..];
            let end = val.find([',', ' ', '\t', '>']);
            return match end {
                Some(e) => &val[..e],
                None => val,
            };
        }
    }
    ""
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Parsing SIP Responses ---

    #[test]
    fn parse_response_200ok() {
        let raw = "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n\
            From: <sip:1001@pbx.example.com>;tag=1928301774\r\n\
            To: <sip:1001@pbx.example.com>;tag=a6c85cf\r\n\
            Call-ID: a84b4c76e66710@192.168.1.100\r\n\
            CSeq: 314159 REGISTER\r\n\
            Contact: <sip:1001@192.168.1.100:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.status_code, 200);
        assert_eq!(msg.reason, "OK");
        assert_eq!(msg.header("Call-ID"), "a84b4c76e66710@192.168.1.100");
        assert_eq!(msg.header("CSeq"), "314159 REGISTER");
    }

    #[test]
    fn parse_response_401_challenge() {
        let raw = "SIP/2.0 401 Unauthorized\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1234\r\n\
            From: <sip:1001@pbx.local>;tag=abc\r\n\
            To: <sip:1001@pbx.local>;tag=def\r\n\
            Call-ID: call123@10.0.0.1\r\n\
            CSeq: 1 REGISTER\r\n\
            WWW-Authenticate: Digest realm=\"asterisk\",nonce=\"abc123def\",algorithm=MD5\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.status_code, 401);
        assert_eq!(msg.reason, "Unauthorized");
        let auth = msg.header("WWW-Authenticate");
        assert!(!auth.is_empty());
        // Case-insensitive lookup.
        assert_eq!(msg.header("www-authenticate"), auth);
    }

    #[test]
    fn parse_response_180_ringing() {
        let raw = "SIP/2.0 180 Ringing\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK5678\r\n\
            From: <sip:1001@pbx.local>;tag=aaa\r\n\
            To: <sip:1002@pbx.local>;tag=bbb\r\n\
            Call-ID: inv001@10.0.0.1\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.status_code, 180);
        assert_eq!(msg.reason, "Ringing");
    }

    #[test]
    fn parse_response_multi_word_reason() {
        let raw = "SIP/2.0 486 Busy Here\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKxyz\r\n\
            Call-ID: call@host\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.status_code, 486);
        assert_eq!(msg.reason, "Busy Here");
    }

    // --- Parsing SIP Requests ---

    #[test]
    fn parse_request_invite() {
        let sdp_body = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let raw = format!(
            "INVITE sip:1002@pbx.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKinv1\r\n\
            From: <sip:1001@pbx.local>;tag=from1\r\n\
            To: <sip:1002@pbx.local>\r\n\
            Call-ID: invite001@10.0.0.1\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:1001@10.0.0.1:5060>\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: {}\r\n\
            \r\n\
            {}",
            sdp_body.len(),
            sdp_body
        );

        let msg = parse(raw.as_bytes()).unwrap();
        assert!(!msg.is_response());
        assert_eq!(msg.method, "INVITE");
        assert_eq!(msg.request_uri, "sip:1002@pbx.local");
        assert_eq!(String::from_utf8_lossy(&msg.body), sdp_body);
    }

    #[test]
    fn parse_request_register() {
        let raw = "REGISTER sip:pbx.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKreg1\r\n\
            From: <sip:1001@pbx.local>;tag=reg1\r\n\
            To: <sip:1001@pbx.local>\r\n\
            Call-ID: reg001@10.0.0.1\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:1001@10.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.method, "REGISTER");
        assert_eq!(msg.request_uri, "sip:pbx.local");
        assert_eq!(msg.header("Expires"), "3600");
    }

    #[test]
    fn parse_request_bye() {
        let raw = "BYE sip:1001@10.0.0.1:5060 SIP/2.0\r\n\
            Via: SIP/2.0/UDP pbx.local:5060;branch=z9hG4bKbye1\r\n\
            From: <sip:1002@pbx.local>;tag=from2\r\n\
            To: <sip:1001@pbx.local>;tag=to2\r\n\
            Call-ID: invite001@10.0.0.1\r\n\
            CSeq: 2 BYE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.method, "BYE");
    }

    // --- Header Access ---

    #[test]
    fn header_case_insensitive() {
        let raw = "SIP/2.0 200 OK\r\n\
            call-id: lower@host\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        for name in &["Call-ID", "call-id", "CALL-ID", "Call-Id"] {
            assert_eq!(msg.header(name), "lower@host");
        }
    }

    #[test]
    fn header_missing() {
        let raw = "SIP/2.0 200 OK\r\n\
            Call-ID: x@y\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.header("X-Nonexistent"), "");
    }

    #[test]
    fn header_values_multiple() {
        let raw = "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111\r\n\
            Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK222\r\n\
            Call-ID: multi@host\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        let vias = msg.header_values("Via");
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0], "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        assert_eq!(vias[1], "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK222");
    }

    // --- Building SIP Messages ---

    #[test]
    fn build_request_register() {
        let mut msg = Message::new_request("REGISTER", "sip:pbx.local");
        msg.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKtest1");
        msg.set_header("From", "<sip:1001@pbx.local>;tag=t1");
        msg.set_header("To", "<sip:1001@pbx.local>");
        msg.set_header("Call-ID", "build-test@10.0.0.1");
        msg.set_header("CSeq", "1 REGISTER");
        msg.set_header("Contact", "<sip:1001@10.0.0.1:5060>");

        let data = msg.to_bytes();
        let got = String::from_utf8_lossy(&data);
        assert!(got.starts_with("REGISTER sip:pbx.local SIP/2.0\r\n"));

        // Round-trip.
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.method, "REGISTER");
        assert_eq!(parsed.header("Call-ID"), "build-test@10.0.0.1");
    }

    #[test]
    fn build_request_invite_with_body() {
        let sdp_body = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\n";
        let mut msg = Message::new_request("INVITE", "sip:1002@pbx.local");
        msg.body = sdp_body.as_bytes().to_vec();
        msg.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKinv1");
        msg.set_header("From", "<sip:1001@pbx.local>;tag=f1");
        msg.set_header("To", "<sip:1002@pbx.local>");
        msg.set_header("Call-ID", "inv-build@10.0.0.1");
        msg.set_header("CSeq", "1 INVITE");
        msg.set_header("Content-Type", "application/sdp");

        let data = msg.to_bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.method, "INVITE");
        assert_eq!(String::from_utf8_lossy(&parsed.body), sdp_body);
        assert_eq!(
            parsed.header("Content-Length"),
            sdp_body.len().to_string().as_str()
        );
    }

    #[test]
    fn build_response() {
        let mut msg = Message::new_response(200, "OK");
        msg.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKtest1");
        msg.set_header("From", "<sip:1001@pbx.local>;tag=t1");
        msg.set_header("To", "<sip:1001@pbx.local>;tag=t2");
        msg.set_header("Call-ID", "resp-test@10.0.0.1");
        msg.set_header("CSeq", "1 REGISTER");

        let data = msg.to_bytes();
        let got = String::from_utf8_lossy(&data);
        assert!(got.starts_with("SIP/2.0 200 OK\r\n"));

        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.reason, "OK");
    }

    // --- Via Branch ---

    #[test]
    fn via_branch() {
        let raw = "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKmybranch;rport\r\n\
            Call-ID: via@host\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.via_branch(), "z9hG4bKmybranch");
    }

    #[test]
    fn via_branch_missing() {
        let raw = "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060\r\n\
            Call-ID: via2@host\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.via_branch(), "");
    }

    // --- CSeq Parsing ---

    #[test]
    fn cseq_method() {
        let raw = "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKx\r\n\
            Call-ID: cseq@host\r\n\
            CSeq: 42 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        let (seq, method) = msg.cseq();
        assert_eq!(seq, 42);
        assert_eq!(method, "INVITE");
    }

    // --- From/To Tag ---

    #[test]
    fn from_to_tag() {
        let raw = "SIP/2.0 200 OK\r\n\
            From: <sip:1001@pbx.local>;tag=fromtag123\r\n\
            To: <sip:1002@pbx.local>;tag=totag456\r\n\
            Call-ID: tag@host\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.from_tag(), "fromtag123");
        assert_eq!(msg.to_tag(), "totag456");
    }

    // --- Error Cases ---

    #[test]
    fn parse_empty() {
        assert!(parse(b"").is_err());
    }

    #[test]
    fn parse_garbage() {
        assert!(parse(b"this is not a SIP message").is_err());
    }

    #[test]
    fn parse_truncated_status_line() {
        assert!(parse(b"SIP/2.0\r\n\r\n").is_err());
    }

    #[test]
    fn parse_invalid_status_code() {
        assert!(parse(b"SIP/2.0 abc OK\r\n\r\n").is_err());
    }

    #[test]
    fn parse_no_headers() {
        let raw = "SIP/2.0 200 OK\r\n\r\n";
        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(msg.status_code, 200);
    }

    // --- Body Handling ---

    #[test]
    fn parse_body_by_content_length() {
        let body = "v=0\r\no=test\r\n";
        let raw = format!(
            "INVITE sip:1002@pbx.local SIP/2.0\r\n\
            Content-Length: {}\r\n\
            Content-Type: application/sdp\r\n\
            \r\n\
            {}",
            body.len(),
            body
        );

        let msg = parse(raw.as_bytes()).unwrap();
        assert_eq!(String::from_utf8_lossy(&msg.body), body);
    }

    #[test]
    fn parse_no_body() {
        let raw = "BYE sip:1001@10.0.0.1 SIP/2.0\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let msg = parse(raw.as_bytes()).unwrap();
        assert!(msg.body.is_empty());
    }

    // --- AddHeader ---

    #[test]
    fn add_header_multiple() {
        let mut msg = Message::new_response(200, "OK");
        msg.add_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        msg.add_header("Via", "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK222");

        let vias = msg.header_values("Via");
        assert_eq!(vias.len(), 2);
    }

    // --- Bytes auto-sets Content-Length ---

    #[test]
    fn bytes_auto_content_length() {
        let mut msg = Message::new_request("INVITE", "sip:1002@pbx.local");
        msg.body = b"testbody".to_vec();
        msg.set_header("Call-ID", "auto-cl@host");
        msg.set_header("CSeq", "1 INVITE");

        let parsed = parse(&msg.to_bytes()).unwrap();
        assert_eq!(parsed.header("Content-Length"), "8");
    }

    #[test]
    fn bytes_zero_content_length() {
        let mut msg = Message::new_request("BYE", "sip:1001@10.0.0.1");
        msg.set_header("Call-ID", "bye-cl@host");
        msg.set_header("CSeq", "2 BYE");

        let parsed = parse(&msg.to_bytes()).unwrap();
        assert_eq!(parsed.header("Content-Length"), "0");
    }

    // --- SetHeader replaces existing ---

    #[test]
    fn set_header_replaces() {
        let mut msg = Message::new_request("REGISTER", "sip:pbx.local");
        msg.set_header("Call-ID", "first");
        msg.set_header("Call-ID", "second");
        assert_eq!(msg.header("Call-ID"), "second");
        assert_eq!(msg.header_values("Call-ID").len(), 1);
    }
}
