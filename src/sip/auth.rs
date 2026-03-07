use crate::error::{Error, Result};

/// A parsed WWW-Authenticate or Proxy-Authenticate header.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub algorithm: String,
    pub qop: String,
    pub opaque: String,
}

/// SIP authentication credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Parses a WWW-Authenticate header value.
/// Example: `Digest realm="asterisk",nonce="abc123",algorithm=MD5`
pub fn parse_challenge(header: &str) -> Result<Challenge> {
    if header.is_empty() {
        return Err(Error::Other("sip: empty challenge header".into()));
    }
    let params = header.strip_prefix("Digest ").ok_or_else(|| {
        Error::Other("sip: unsupported auth scheme (only Digest supported)".into())
    })?;

    let mut ch = Challenge {
        realm: String::new(),
        nonce: String::new(),
        algorithm: String::new(),
        qop: String::new(),
        opaque: String::new(),
    };

    for part in split_params(params) {
        let part = part.trim();
        let eq_idx = match part.find('=') {
            Some(i) => i,
            None => continue,
        };
        let key = part[..eq_idx].trim().to_lowercase();
        let val = part[eq_idx + 1..].trim().trim_matches('"');
        match key.as_str() {
            "realm" => ch.realm = val.into(),
            "nonce" => ch.nonce = val.into(),
            "algorithm" => ch.algorithm = val.into(),
            "qop" => ch.qop = val.into(),
            "opaque" => ch.opaque = val.into(),
            _ => {}
        }
    }

    Ok(ch)
}

/// Computes the digest response hash per RFC 2617.
/// HA1 = MD5(username:realm:password)
/// HA2 = MD5(method:digest_uri)
/// response = MD5(HA1:nonce:HA2)
pub fn digest_response(
    ch: &Challenge,
    creds: &Credentials,
    method: &str,
    digest_uri: &str,
) -> String {
    let ha1 = md5_hex(&format!(
        "{}:{}:{}",
        creds.username, ch.realm, creds.password
    ));
    let ha2 = md5_hex(&format!("{}:{}", method, digest_uri));
    md5_hex(&format!("{}:{}:{}", ha1, ch.nonce, ha2))
}

/// Builds a complete Authorization header value.
pub fn build_authorization(
    ch: &Challenge,
    creds: &Credentials,
    method: &str,
    digest_uri: &str,
) -> String {
    let resp = digest_response(ch, creds, method, digest_uri);
    let mut s = format!(
        "Digest username=\"{}\",realm=\"{}\",nonce=\"{}\",uri=\"{}\",response=\"{}\",algorithm=MD5",
        creds.username, ch.realm, ch.nonce, digest_uri, resp
    );
    if !ch.opaque.is_empty() {
        s.push_str(&format!(",opaque=\"{}\"", ch.opaque));
    }
    s
}

/// Splits a parameter string on commas, respecting quoted values.
fn split_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        parts.push(&s[start..]);
    }
    parts
}

fn md5_hex(s: &str) -> String {
    use std::fmt::Write;
    let digest = md5::compute(s.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in digest.iter() {
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_challenge_basic() {
        let hdr = r#"Digest realm="asterisk",nonce="abc123",algorithm=MD5"#;
        let ch = parse_challenge(hdr).unwrap();
        assert_eq!(ch.realm, "asterisk");
        assert_eq!(ch.nonce, "abc123");
        assert_eq!(ch.algorithm, "MD5");
    }

    #[test]
    fn parse_challenge_with_qop() {
        let hdr = r#"Digest realm="sip.example.com",nonce="dcd98b",qop="auth",algorithm=MD5"#;
        let ch = parse_challenge(hdr).unwrap();
        assert_eq!(ch.realm, "sip.example.com");
        assert_eq!(ch.nonce, "dcd98b");
        assert_eq!(ch.qop, "auth");
    }

    #[test]
    fn parse_challenge_with_opaque() {
        let hdr = r#"Digest realm="test",nonce="n1",opaque="op1",algorithm=MD5"#;
        let ch = parse_challenge(hdr).unwrap();
        assert_eq!(ch.opaque, "op1");
    }

    #[test]
    fn parse_challenge_qop_with_comma() {
        let hdr = r#"Digest realm="test",nonce="n1",qop="auth,auth-int",algorithm=MD5"#;
        let ch = parse_challenge(hdr).unwrap();
        assert_eq!(ch.qop, "auth,auth-int");
        assert_eq!(ch.algorithm, "MD5");
    }

    #[test]
    fn parse_challenge_not_digest() {
        let err = parse_challenge(r#"Basic realm="test""#);
        assert!(err.is_err());
    }

    #[test]
    fn parse_challenge_empty() {
        assert!(parse_challenge("").is_err());
    }

    #[test]
    fn digest_response_rfc2617() {
        let ch = Challenge {
            realm: "asterisk".into(),
            nonce: "abc123".into(),
            algorithm: "MD5".into(),
            qop: String::new(),
            opaque: String::new(),
        };
        let creds = Credentials {
            username: "1001".into(),
            password: "test".into(),
        };
        let resp = digest_response(&ch, &creds, "REGISTER", "sip:pbx.local");
        assert!(!resp.is_empty());
        assert_eq!(resp.len(), 32);

        // Deterministic.
        let resp2 = digest_response(&ch, &creds, "REGISTER", "sip:pbx.local");
        assert_eq!(resp, resp2);
    }

    #[test]
    fn digest_response_different_method() {
        let ch = Challenge {
            realm: "asterisk".into(),
            nonce: "abc123".into(),
            algorithm: String::new(),
            qop: String::new(),
            opaque: String::new(),
        };
        let creds = Credentials {
            username: "1001".into(),
            password: "test".into(),
        };
        let reg = digest_response(&ch, &creds, "REGISTER", "sip:pbx.local");
        let inv = digest_response(&ch, &creds, "INVITE", "sip:pbx.local");
        assert_ne!(reg, inv);
    }

    #[test]
    fn build_authorization_header() {
        let ch = Challenge {
            realm: "asterisk".into(),
            nonce: "abc123".into(),
            algorithm: String::new(),
            qop: String::new(),
            opaque: String::new(),
        };
        let creds = Credentials {
            username: "1001".into(),
            password: "test".into(),
        };
        let hdr = build_authorization(&ch, &creds, "REGISTER", "sip:pbx.local");
        assert!(hdr.starts_with("Digest "));
        for want in &["username=", "realm=", "nonce=", "uri=", "response="] {
            assert!(hdr.contains(want), "missing {}", want);
        }
    }

    #[test]
    fn build_authorization_with_opaque() {
        let ch = Challenge {
            realm: "asterisk".into(),
            nonce: "abc123".into(),
            algorithm: String::new(),
            qop: String::new(),
            opaque: "opaque-val".into(),
        };
        let creds = Credentials {
            username: "1001".into(),
            password: "test".into(),
        };
        let hdr = build_authorization(&ch, &creds, "REGISTER", "sip:pbx.local");
        assert!(hdr.contains("opaque="));
    }
}
