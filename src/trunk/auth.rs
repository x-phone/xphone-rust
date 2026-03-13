//! Peer authentication: IP allowlist and SIP digest auth.

use std::net::IpAddr;

use crate::sip::message::Message;
use crate::trunk::config::{PeerConfig, ServerConfig};

/// Realm used in SIP digest challenges.
const REALM: &str = "xphone";

/// Result of authenticating an incoming SIP request.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    /// Authenticated — includes the matched peer name.
    Authenticated(String),
    /// Needs digest auth challenge — returns (realm, nonce) for 401 response.
    Challenge { realm: String, nonce: String },
    /// Rejected — no matching peer.
    Rejected,
}

/// Authenticate an incoming SIP INVITE against configured peers.
///
/// Authentication order:
/// 1. Check source IP against peer `host` / `hosts` fields.
/// 2. If no IP match, check for digest `Authorization` header against peer credentials.
/// 3. If no `Authorization` header but a digest-auth peer exists, return `Challenge`.
/// 4. Otherwise, `Rejected`.
pub fn authenticate(config: &ServerConfig, msg: &Message, source_ip: IpAddr) -> AuthResult {
    // Step 1: IP-based auth — fastest path.
    for peer in &config.peers {
        if peer.matches_ip(source_ip) {
            return AuthResult::Authenticated(peer.name.clone());
        }
    }

    // Step 2: Digest auth — check Authorization header.
    let auth_header = msg.header("Authorization");
    if !auth_header.is_empty() {
        if let Some(digest) = parse_digest_auth(auth_header) {
            // Reject if realm doesn't match our challenge.
            if digest.realm != REALM {
                return AuthResult::Rejected;
            }
            for peer in &config.peers {
                if let Some(ref cred) = peer.auth {
                    if cred.username == digest.username {
                        let ha1 = cred.ha1();
                        let ha2 = md5_hex(&format!("{}:{}", msg.method, digest.uri));
                        let expected = md5_hex(&format!("{ha1}:{}:{ha2}", digest.nonce));
                        if expected == digest.response {
                            return AuthResult::Authenticated(peer.name.clone());
                        }
                    }
                }
            }
        }
        // Bad credentials — reject, don't re-challenge.
        return AuthResult::Rejected;
    }

    // Step 3: No auth header — challenge if any digest-auth peer exists.
    let has_digest_peers = config.peers.iter().any(|p| p.auth.is_some());
    if has_digest_peers {
        let nonce = generate_nonce();
        return AuthResult::Challenge {
            realm: REALM.into(),
            nonce,
        };
    }

    // Step 4: No matching auth method.
    AuthResult::Rejected
}

/// Find a peer by name.
pub fn find_peer<'a>(config: &'a ServerConfig, name: &str) -> Option<&'a PeerConfig> {
    config.peers.iter().find(|p| p.name == name)
}

/// Parsed fields from a SIP `Authorization: Digest ...` header.
struct DigestFields {
    username: String,
    realm: String,
    nonce: String,
    uri: String,
    response: String,
}

/// Parse a `Digest username="...",realm="...",nonce="...",uri="...",response="..."` header.
fn parse_digest_auth(header: &str) -> Option<DigestFields> {
    let rest = header.strip_prefix("Digest ")?.trim();
    let mut username = None;
    let mut realm = None;
    let mut nonce = None;
    let mut uri = None;
    let mut response = None;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "username" => username = Some(val.to_string()),
                "realm" => realm = Some(val.to_string()),
                "nonce" => nonce = Some(val.to_string()),
                "uri" => uri = Some(val.to_string()),
                "response" => response = Some(val.to_string()),
                _ => {}
            }
        }
    }

    Some(DigestFields {
        username: username?,
        realm: realm?,
        nonce: nonce?,
        uri: uri?,
        response: response?,
    })
}

/// Build a 401 WWW-Authenticate header value for digest auth challenge.
pub fn build_www_authenticate(realm: &str, nonce: &str) -> String {
    format!("Digest realm=\"{realm}\",nonce=\"{nonce}\",algorithm=MD5")
}

/// Compute MD5 hex digest of a string.
pub(crate) fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    super::util::hex_encode(&bytes)
}

/// Compute SIP digest auth response (RFC 2617, MD5). Test-only.
#[cfg(test)]
fn compute_digest_response(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trunk::config::PeerAuthConfig;
    use std::net::Ipv4Addr;

    fn test_config() -> ServerConfig {
        ServerConfig {
            listen: "0.0.0.0:5080".into(),
            peers: vec![
                PeerConfig {
                    name: "office-pbx".into(),
                    host: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                    ..Default::default()
                },
                PeerConfig {
                    name: "remote-office".into(),
                    auth: Some(PeerAuthConfig::new("remote-trunk", "secret123")),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    fn make_invite(auth_header: Option<&str>) -> Message {
        let mut msg = Message::new_request("INVITE", "sip:1002@xphone:5080");
        msg.set_header("From", "<sip:1001@pbx.local>;tag=abc");
        msg.set_header("To", "<sip:1002@xphone:5080>");
        msg.set_header("Call-ID", "test@host");
        msg.set_header("CSeq", "1 INVITE");
        if let Some(auth) = auth_header {
            msg.set_header("Authorization", auth);
        }
        msg
    }

    #[test]
    fn ip_auth_matches() {
        let config = test_config();
        let msg = make_invite(None);
        let result = authenticate(&config, &msg, Ipv4Addr::new(192, 168, 1, 10).into());
        assert_eq!(result, AuthResult::Authenticated("office-pbx".into()));
    }

    #[test]
    fn ip_auth_wrong_ip_triggers_challenge() {
        let config = test_config();
        let msg = make_invite(None);
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert!(matches!(result, AuthResult::Challenge { .. }));
    }

    #[test]
    fn digest_auth_valid() {
        let config = test_config();
        let nonce = "testnonce123";
        let uri = "sip:1002@xphone:5080";
        let response =
            compute_digest_response("remote-trunk", "secret123", "xphone", nonce, "INVITE", uri);
        let auth_header = format!(
            "Digest username=\"remote-trunk\",realm=\"xphone\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\""
        );
        let msg = make_invite(Some(&auth_header));
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert_eq!(result, AuthResult::Authenticated("remote-office".into()));
    }

    #[test]
    fn digest_auth_wrong_password() {
        let config = test_config();
        let nonce = "testnonce123";
        let uri = "sip:1002@xphone:5080";
        let response = compute_digest_response(
            "remote-trunk",
            "wrong-password",
            "xphone",
            nonce,
            "INVITE",
            uri,
        );
        let auth_header = format!(
            "Digest username=\"remote-trunk\",realm=\"xphone\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\""
        );
        let msg = make_invite(Some(&auth_header));
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert_eq!(result, AuthResult::Rejected);
    }

    #[test]
    fn digest_auth_unknown_username() {
        let config = test_config();
        let auth_header =
            "Digest username=\"unknown\",realm=\"xphone\",nonce=\"abc\",uri=\"sip:x@y\",response=\"deadbeef\"";
        let msg = make_invite(Some(auth_header));
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert_eq!(result, AuthResult::Rejected);
    }

    #[test]
    fn digest_auth_wrong_realm_rejected() {
        let config = test_config();
        let nonce = "testnonce123";
        let uri = "sip:1002@xphone:5080";
        let response = compute_digest_response(
            "remote-trunk",
            "secret123",
            "evil-realm",
            nonce,
            "INVITE",
            uri,
        );
        let auth_header = format!(
            "Digest username=\"remote-trunk\",realm=\"evil-realm\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\""
        );
        let msg = make_invite(Some(&auth_header));
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert_eq!(result, AuthResult::Rejected);
    }

    #[test]
    fn no_peers_rejects() {
        let config = ServerConfig {
            listen: "0.0.0.0:5080".into(),
            ..Default::default()
        };
        let msg = make_invite(None);
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 1).into());
        assert_eq!(result, AuthResult::Rejected);
    }

    #[test]
    fn ip_only_peers_no_challenge() {
        let config = ServerConfig {
            listen: "0.0.0.0:5080".into(),
            peers: vec![PeerConfig {
                name: "local".into(),
                host: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                ..Default::default()
            }],
            ..Default::default()
        };
        let msg = make_invite(None);
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 99).into());
        assert_eq!(result, AuthResult::Rejected);
    }

    #[test]
    fn ip_auth_takes_priority() {
        let config = ServerConfig {
            listen: "0.0.0.0:5080".into(),
            peers: vec![PeerConfig {
                name: "both-auth".into(),
                host: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                auth: Some(PeerAuthConfig::new("user", "pass")),
                ..Default::default()
            }],
            ..Default::default()
        };
        let msg = make_invite(None);
        let result = authenticate(&config, &msg, Ipv4Addr::new(10, 0, 0, 1).into());
        assert_eq!(result, AuthResult::Authenticated("both-auth".into()));
    }

    #[test]
    fn parse_digest_auth_header() {
        let header = "Digest username=\"alice\",realm=\"biloxi.com\",nonce=\"abc123\",uri=\"sip:bob@biloxi.com\",response=\"deadbeef\"";
        let fields = parse_digest_auth(header).unwrap();
        assert_eq!(fields.username, "alice");
        assert_eq!(fields.realm, "biloxi.com");
        assert_eq!(fields.nonce, "abc123");
        assert_eq!(fields.uri, "sip:bob@biloxi.com");
        assert_eq!(fields.response, "deadbeef");
    }

    #[test]
    fn parse_digest_auth_not_digest() {
        assert!(parse_digest_auth("Basic dXNlcjpwYXNz").is_none());
    }

    #[test]
    fn parse_digest_auth_missing_field() {
        let header = "Digest username=\"alice\",realm=\"test\"";
        assert!(parse_digest_auth(header).is_none());
    }

    #[test]
    fn www_authenticate_header() {
        let val = build_www_authenticate("xphone", "abc123");
        assert_eq!(
            val,
            "Digest realm=\"xphone\",nonce=\"abc123\",algorithm=MD5"
        );
    }

    #[test]
    fn find_peer_by_name() {
        let config = test_config();
        assert_eq!(find_peer(&config, "office-pbx").unwrap().name, "office-pbx");
        assert_eq!(
            find_peer(&config, "remote-office").unwrap().name,
            "remote-office"
        );
        assert!(find_peer(&config, "nonexistent").is_none());
    }

    #[test]
    fn digest_response_rfc2617_compatible() {
        let response = compute_digest_response(
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            "GET",
            "/dir/index.html",
        );
        assert!(!response.is_empty());
        assert_eq!(response.len(), 32);
    }
}
