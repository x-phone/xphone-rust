//! ICE-Lite implementation (RFC 8445 §2.2).
//!
//! Gathers host, server-reflexive (STUN), and relay (TURN) candidates,
//! encodes them in SDP, and responds to incoming STUN connectivity checks
//! on the media socket.
//!
//! ICE-Lite only responds to checks — it never initiates connectivity
//! checks. This is sufficient for SIP telephony where the remote peer
//! (PBX, trunk, or WebRTC gateway) is typically the controlling agent.

use std::fmt;
use std::net::SocketAddr;

use parking_lot::Mutex;
use tracing::debug;

use crate::stun;

/// ICE candidate type per RFC 8445 §4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    /// Local address on a network interface.
    Host,
    /// NAT-mapped address discovered via STUN.
    ServerReflexive,
    /// Address on a TURN relay server.
    Relay,
}

impl CandidateType {
    /// Type preference for priority calculation (RFC 8445 §5.1.2.1).
    fn type_preference(self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::Relay => "relay",
        }
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single ICE candidate.
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Foundation string (unique per base address + candidate type).
    pub foundation: String,
    /// Component ID: 1 = RTP, 2 = RTCP.
    pub component: u32,
    /// Transport protocol (always "UDP").
    pub transport: String,
    /// Candidate priority (computed per RFC 8445 §5.1.2).
    pub priority: u32,
    /// Candidate address.
    pub addr: SocketAddr,
    /// Candidate type.
    pub cand_type: CandidateType,
    /// Related address (base for srflx, srflx for relay). None for host.
    pub rel_addr: Option<SocketAddr>,
}

impl IceCandidate {
    /// Formats this candidate as an SDP `a=candidate:` line (without the
    /// `a=candidate:` prefix — that's added by the SDP builder).
    pub fn to_sdp_value(&self) -> String {
        let mut s = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.addr.ip(),
            self.addr.port(),
            self.cand_type,
        );
        if let Some(rel) = self.rel_addr {
            s.push_str(&format!(" raddr {} rport {}", rel.ip(), rel.port()));
        }
        s
    }
}

/// ICE credentials (ice-ufrag and ice-pwd).
#[derive(Debug, Clone)]
pub struct IceCredentials {
    /// Username fragment (4+ characters).
    pub ufrag: String,
    /// Password (22+ characters / 128+ bits).
    pub pwd: String,
}

/// Generates random ICE credentials.
pub fn generate_credentials() -> IceCredentials {
    let ufrag = random_ice_string(8);
    let pwd = random_ice_string(24);
    IceCredentials { ufrag, pwd }
}

/// ICE parameters for SDP encoding.
pub struct IceSdpParams {
    pub ufrag: String,
    pub pwd: String,
    pub candidates: Vec<IceCandidate>,
    pub ice_lite: bool,
}

/// ICE-Lite agent: stores local credentials, candidates, and responds
/// to incoming STUN Binding Requests.
pub struct IceAgent {
    pub local_creds: IceCredentials,
    pub remote_creds: Mutex<Option<IceCredentials>>,
    pub candidates: Vec<IceCandidate>,
    pub nominated_addr: Mutex<Option<SocketAddr>>,
    /// Pre-computed "ufrag:" prefix for Binding Request validation.
    ufrag_prefix: String,
}

impl IceAgent {
    /// Creates a new ICE-Lite agent with the given credentials and candidates.
    pub fn new(creds: IceCredentials, candidates: Vec<IceCandidate>) -> Self {
        let prefix = format!("{}:", creds.ufrag);
        Self {
            local_creds: creds,
            remote_creds: Mutex::new(None),
            candidates,
            nominated_addr: Mutex::new(None),
            ufrag_prefix: prefix,
        }
    }

    /// Sets the remote ICE credentials (parsed from remote SDP).
    pub fn set_remote_credentials(&self, creds: IceCredentials) {
        *self.remote_creds.lock() = Some(creds);
    }

    /// Handles an incoming STUN Binding Request on the media socket.
    /// Returns the response bytes to send back, or `None` if invalid.
    pub fn handle_binding_request(&self, data: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        if !stun::is_stun_message(data) {
            return None;
        }

        let msg_type = stun::extract_msg_type(data)?;
        if msg_type != stun::BINDING_REQUEST {
            return None;
        }

        let txn_id = stun::extract_txn_id(data)?;

        // Parse attributes to validate USERNAME and MESSAGE-INTEGRITY.
        let attrs = stun::parse_stun_attrs(&data[stun::HEADER_SIZE..]);

        // Extract USERNAME attribute: should be "local_ufrag:remote_ufrag".
        let username = attrs
            .iter()
            .find(|(t, _)| *t == stun::ATTR_USERNAME)
            .and_then(|(_, v)| String::from_utf8(v.clone()).ok())?;

        if !username.starts_with(&self.ufrag_prefix) {
            debug!(
                username = %username,
                expected = %self.ufrag_prefix,
                "ICE: Binding Request username mismatch"
            );
            return None;
        }

        // Verify MESSAGE-INTEGRITY using local password as key.
        let mi_offset = find_attr_offset(data, stun::ATTR_MESSAGE_INTEGRITY)?;
        if !stun::verify_message_integrity(data, mi_offset, self.local_creds.pwd.as_bytes()) {
            debug!("ICE: MESSAGE-INTEGRITY verification failed");
            return None;
        }

        // Check for USE-CANDIDATE (nomination).
        let use_candidate = attrs.iter().any(|(t, _)| *t == stun::ATTR_USE_CANDIDATE);
        if use_candidate {
            *self.nominated_addr.lock() = Some(from);
            debug!(peer = %from, "ICE: nominated by remote");
        }

        // Build Binding Response with XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY.
        let resp =
            stun::build_binding_response_integrity(&txn_id, from, self.local_creds.pwd.as_bytes());

        debug!(peer = %from, "ICE: Binding Response sent");
        Some(resp)
    }
}

// ─── Candidate gathering ───────────────────────────────────────────────

/// Computes ICE candidate priority per RFC 8445 §5.1.2.
pub fn compute_priority(cand_type: CandidateType, component: u32, local_pref: u32) -> u32 {
    (1 << 24) * cand_type.type_preference() + (1 << 8) * local_pref + (256 - component)
}

/// Gathers ICE candidates from the given addresses.
pub fn gather_candidates(
    local_addr: SocketAddr,
    srflx_addr: Option<SocketAddr>,
    relay_addr: Option<SocketAddr>,
    component: u32,
) -> Vec<IceCandidate> {
    let mut candidates = Vec::with_capacity(3);

    // Host candidate.
    candidates.push(IceCandidate {
        foundation: "1".into(),
        component,
        transport: "UDP".into(),
        priority: compute_priority(CandidateType::Host, component, 65535),
        addr: local_addr,
        cand_type: CandidateType::Host,
        rel_addr: None,
    });

    // Server-reflexive candidate.
    if let Some(srflx) = srflx_addr {
        candidates.push(IceCandidate {
            foundation: "2".into(),
            component,
            transport: "UDP".into(),
            priority: compute_priority(CandidateType::ServerReflexive, component, 65535),
            addr: srflx,
            cand_type: CandidateType::ServerReflexive,
            rel_addr: Some(local_addr),
        });
    }

    // Relay candidate.
    if let Some(relay) = relay_addr {
        candidates.push(IceCandidate {
            foundation: "3".into(),
            component,
            transport: "UDP".into(),
            priority: compute_priority(CandidateType::Relay, component, 65535),
            addr: relay,
            cand_type: CandidateType::Relay,
            rel_addr: srflx_addr.or(Some(local_addr)),
        });
    }

    candidates
}

// ─── SDP parsing ───────────────────────────────────────────────────────

/// Parses an `a=candidate:` line value into an `IceCandidate`.
pub fn parse_sdp_candidate(line: &str) -> Option<IceCandidate> {
    // Format: foundation component transport priority addr port typ type [raddr X rport Y]
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    let foundation = parts[0].to_string();
    let component = parts[1].parse().ok()?;
    let transport = parts[2].to_string();
    let priority = parts[3].parse().ok()?;
    let ip = parts[4];
    let port: u16 = parts[5].parse().ok()?;
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;

    // "typ" keyword at index 6
    if parts[6] != "typ" {
        return None;
    }
    let cand_type = match parts[7] {
        "host" => CandidateType::Host,
        "srflx" => CandidateType::ServerReflexive,
        "relay" => CandidateType::Relay,
        _ => return None,
    };

    // Optional raddr/rport
    let mut rel_addr = None;
    if parts.len() >= 12 && parts[8] == "raddr" && parts[10] == "rport" {
        let rip = parts[9];
        let rport: u16 = parts[11].parse().ok()?;
        rel_addr = format!("{}:{}", rip, rport).parse().ok();
    }

    Some(IceCandidate {
        foundation,
        component,
        transport,
        priority,
        addr,
        cand_type,
        rel_addr,
    })
}

/// Extracts `a=ice-ufrag` and `a=ice-pwd` from an SDP string.
pub fn parse_ice_credentials(sdp: &str) -> Option<IceCredentials> {
    let mut ufrag = None;
    let mut pwd = None;

    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(val) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("a=ice-pwd:") {
            pwd = Some(val.to_string());
        }
    }

    match (ufrag, pwd) {
        (Some(u), Some(p)) => Some(IceCredentials { ufrag: u, pwd: p }),
        _ => None,
    }
}

/// Returns `true` if the SDP contains `a=ice-lite`.
pub fn is_ice_lite(sdp: &str) -> bool {
    sdp.lines()
        .any(|l| l.trim_end_matches('\r') == "a=ice-lite")
}

// ─── Internal ──────────────────────────────────────────────────────────

/// Generates a random ICE string of the given length using alphanumeric chars.
fn random_ice_string(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
        .iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect()
}

/// Finds the byte offset of a specific attribute within a STUN message.
fn find_attr_offset(msg: &[u8], target_type: u16) -> Option<usize> {
    if msg.len() < stun::HEADER_SIZE {
        return None;
    }
    let mut offset = stun::HEADER_SIZE;
    while offset + 4 <= msg.len() {
        let attr_type = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let attr_len = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]) as usize;
        if attr_type == target_type {
            return Some(offset);
        }
        let padded = (attr_len + 3) & !3;
        offset += 4 + padded;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_host_highest() {
        let host = compute_priority(CandidateType::Host, 1, 65535);
        let srflx = compute_priority(CandidateType::ServerReflexive, 1, 65535);
        let relay = compute_priority(CandidateType::Relay, 1, 65535);
        assert!(host > srflx);
        assert!(srflx > relay);
    }

    #[test]
    fn priority_component_1_higher_than_2() {
        let p1 = compute_priority(CandidateType::Host, 1, 65535);
        let p2 = compute_priority(CandidateType::Host, 2, 65535);
        assert!(p1 > p2);
    }

    #[test]
    fn credentials_generation() {
        let c1 = generate_credentials();
        let c2 = generate_credentials();
        assert_eq!(c1.ufrag.len(), 8);
        assert_eq!(c1.pwd.len(), 24);
        assert_ne!(c1.ufrag, c2.ufrag);
        assert_ne!(c1.pwd, c2.pwd);
    }

    #[test]
    fn candidate_to_sdp_host() {
        let c = IceCandidate {
            foundation: "1".into(),
            component: 1,
            transport: "UDP".into(),
            priority: 2130706431,
            addr: "192.168.1.100:5004".parse().unwrap(),
            cand_type: CandidateType::Host,
            rel_addr: None,
        };
        let sdp = c.to_sdp_value();
        assert!(sdp.contains("192.168.1.100"));
        assert!(sdp.contains("5004"));
        assert!(sdp.contains("typ host"));
        assert!(!sdp.contains("raddr"));
    }

    #[test]
    fn candidate_to_sdp_srflx() {
        let c = IceCandidate {
            foundation: "2".into(),
            component: 1,
            transport: "UDP".into(),
            priority: 1694498815,
            addr: "203.0.113.42:12345".parse().unwrap(),
            cand_type: CandidateType::ServerReflexive,
            rel_addr: Some("192.168.1.100:5004".parse().unwrap()),
        };
        let sdp = c.to_sdp_value();
        assert!(sdp.contains("typ srflx"));
        assert!(sdp.contains("raddr 192.168.1.100 rport 5004"));
    }

    #[test]
    fn candidate_to_sdp_relay() {
        let c = IceCandidate {
            foundation: "3".into(),
            component: 1,
            transport: "UDP".into(),
            priority: 16777215,
            addr: "10.0.0.1:50000".parse().unwrap(),
            cand_type: CandidateType::Relay,
            rel_addr: Some("203.0.113.42:12345".parse().unwrap()),
        };
        let sdp = c.to_sdp_value();
        assert!(sdp.contains("typ relay"));
        assert!(sdp.contains("raddr 203.0.113.42"));
    }

    #[test]
    fn parse_sdp_candidate_host() {
        let line = "1 1 UDP 2130706431 192.168.1.100 5004 typ host";
        let c = parse_sdp_candidate(line).unwrap();
        assert_eq!(c.foundation, "1");
        assert_eq!(c.component, 1);
        assert_eq!(c.priority, 2130706431);
        assert_eq!(c.addr, "192.168.1.100:5004".parse::<SocketAddr>().unwrap());
        assert_eq!(c.cand_type, CandidateType::Host);
        assert!(c.rel_addr.is_none());
    }

    #[test]
    fn parse_sdp_candidate_srflx_with_raddr() {
        let line = "2 1 UDP 1694498815 203.0.113.42 12345 typ srflx raddr 192.168.1.100 rport 5004";
        let c = parse_sdp_candidate(line).unwrap();
        assert_eq!(c.cand_type, CandidateType::ServerReflexive);
        assert_eq!(
            c.rel_addr.unwrap(),
            "192.168.1.100:5004".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_sdp_candidate_round_trip() {
        let original = IceCandidate {
            foundation: "2".into(),
            component: 1,
            transport: "UDP".into(),
            priority: 1694498815,
            addr: "203.0.113.42:12345".parse().unwrap(),
            cand_type: CandidateType::ServerReflexive,
            rel_addr: Some("192.168.1.100:5004".parse().unwrap()),
        };
        let sdp_val = original.to_sdp_value();
        let parsed = parse_sdp_candidate(&sdp_val).unwrap();
        assert_eq!(parsed.foundation, original.foundation);
        assert_eq!(parsed.component, original.component);
        assert_eq!(parsed.priority, original.priority);
        assert_eq!(parsed.addr, original.addr);
        assert_eq!(parsed.cand_type, original.cand_type);
        assert_eq!(parsed.rel_addr, original.rel_addr);
    }

    #[test]
    fn parse_sdp_candidate_invalid() {
        assert!(parse_sdp_candidate("").is_none());
        assert!(parse_sdp_candidate("too short").is_none());
        assert!(parse_sdp_candidate("1 1 UDP 100 1.2.3.4 5 nottyp host").is_none());
    }

    #[test]
    fn parse_ice_credentials_from_sdp() {
        let sdp = "v=0\r\na=ice-ufrag:abcd1234\r\na=ice-pwd:longpasswordstringhere123\r\nm=audio 5004 RTP/AVP 0\r\n";
        let creds = parse_ice_credentials(sdp).unwrap();
        assert_eq!(creds.ufrag, "abcd1234");
        assert_eq!(creds.pwd, "longpasswordstringhere123");
    }

    #[test]
    fn parse_ice_credentials_missing() {
        assert!(parse_ice_credentials("v=0\r\n").is_none());
        assert!(parse_ice_credentials("a=ice-ufrag:foo\r\n").is_none());
    }

    #[test]
    fn is_ice_lite_detection() {
        assert!(is_ice_lite(
            "v=0\r\na=ice-lite\r\nm=audio 5004 RTP/AVP 0\r\n"
        ));
        assert!(!is_ice_lite("v=0\r\nm=audio 5004 RTP/AVP 0\r\n"));
    }

    #[test]
    fn gather_candidates_host_only() {
        let local: SocketAddr = "192.168.1.100:5004".parse().unwrap();
        let cands = gather_candidates(local, None, None, 1);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].cand_type, CandidateType::Host);
        assert_eq!(cands[0].addr, local);
    }

    #[test]
    fn gather_candidates_all_three() {
        let local: SocketAddr = "192.168.1.100:5004".parse().unwrap();
        let srflx: SocketAddr = "203.0.113.42:12345".parse().unwrap();
        let relay: SocketAddr = "10.0.0.1:50000".parse().unwrap();
        let cands = gather_candidates(local, Some(srflx), Some(relay), 1);
        assert_eq!(cands.len(), 3);
        assert_eq!(cands[0].cand_type, CandidateType::Host);
        assert_eq!(cands[1].cand_type, CandidateType::ServerReflexive);
        assert_eq!(cands[2].cand_type, CandidateType::Relay);
        // Host has highest priority.
        assert!(cands[0].priority > cands[1].priority);
        assert!(cands[1].priority > cands[2].priority);
    }

    #[test]
    fn ice_agent_binding_request_response() {
        let local_creds = IceCredentials {
            ufrag: "localufrag".into(),
            pwd: "localpassword1234567890".into(),
        };
        let remote_creds = IceCredentials {
            ufrag: "remoteufrag".into(),
            pwd: "remotepassword1234567890".into(),
        };

        let agent = IceAgent::new(local_creds.clone(), vec![]);
        agent.set_remote_credentials(remote_creds.clone());

        // Build a STUN Binding Request with USERNAME and MESSAGE-INTEGRITY.
        let txn_id = stun::generate_txn_id();
        let username = format!("{}:{}", local_creds.ufrag, remote_creds.ufrag);
        let mut req = stun::build_stun_message(
            stun::BINDING_REQUEST,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_USERNAME,
                    value: username.as_bytes().to_vec(),
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_PRIORITY,
                    value: 100u32.to_be_bytes().to_vec(),
                },
            ],
        );
        stun::append_message_integrity(&mut req, local_creds.pwd.as_bytes());

        let from: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let resp = agent.handle_binding_request(&req, from).unwrap();

        // Verify response is a valid STUN message.
        assert!(stun::is_stun_message(&resp));
        assert_eq!(
            stun::extract_msg_type(&resp).unwrap(),
            stun::BINDING_RESPONSE
        );
        assert_eq!(stun::extract_txn_id(&resp).unwrap(), txn_id);
    }

    #[test]
    fn ice_agent_rejects_wrong_username() {
        let local_creds = IceCredentials {
            ufrag: "localufrag".into(),
            pwd: "localpassword1234567890".into(),
        };
        let agent = IceAgent::new(local_creds.clone(), vec![]);

        let txn_id = stun::generate_txn_id();
        let mut req = stun::build_stun_message(
            stun::BINDING_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_USERNAME,
                value: b"wrongufrag:remote".to_vec(),
            }],
        );
        stun::append_message_integrity(&mut req, local_creds.pwd.as_bytes());

        let from: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert!(agent.handle_binding_request(&req, from).is_none());
    }

    #[test]
    fn ice_agent_rejects_bad_integrity() {
        let local_creds = IceCredentials {
            ufrag: "localufrag".into(),
            pwd: "localpassword1234567890".into(),
        };
        let agent = IceAgent::new(local_creds.clone(), vec![]);

        let txn_id = stun::generate_txn_id();
        let username = format!("{}:remote", local_creds.ufrag);
        let mut req = stun::build_stun_message(
            stun::BINDING_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_USERNAME,
                value: username.as_bytes().to_vec(),
            }],
        );
        stun::append_message_integrity(&mut req, b"wrong-password");

        let from: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert!(agent.handle_binding_request(&req, from).is_none());
    }

    #[test]
    fn ice_agent_nomination() {
        let local_creds = IceCredentials {
            ufrag: "localufrag".into(),
            pwd: "localpassword1234567890".into(),
        };
        let agent = IceAgent::new(local_creds.clone(), vec![]);

        let txn_id = stun::generate_txn_id();
        let username = format!("{}:remote", local_creds.ufrag);
        let mut req = stun::build_stun_message(
            stun::BINDING_REQUEST,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_USERNAME,
                    value: username.as_bytes().to_vec(),
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_USE_CANDIDATE,
                    value: vec![],
                },
            ],
        );
        stun::append_message_integrity(&mut req, local_creds.pwd.as_bytes());

        let from: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let resp = agent.handle_binding_request(&req, from);
        assert!(resp.is_some());
        assert_eq!(agent.nominated_addr.lock().unwrap(), from);
    }

    #[test]
    fn candidate_type_display() {
        assert_eq!(CandidateType::Host.to_string(), "host");
        assert_eq!(CandidateType::ServerReflexive.to_string(), "srflx");
        assert_eq!(CandidateType::Relay.to_string(), "relay");
    }

    #[test]
    fn find_attr_offset_works() {
        let txn_id = [0xAA; 12];
        let mut msg = stun::build_stun_message(
            stun::BINDING_REQUEST,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_USERNAME,
                    value: b"test".to_vec(),
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_PRIORITY,
                    value: 100u32.to_be_bytes().to_vec(),
                },
            ],
        );
        stun::append_message_integrity(&mut msg, b"key");

        let offset = find_attr_offset(&msg, stun::ATTR_MESSAGE_INTEGRITY);
        assert!(offset.is_some());

        let offset = find_attr_offset(&msg, 0x9999);
        assert!(offset.is_none());
    }
}
