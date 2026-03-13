use std::fmt::Write;

/// Encode bytes as lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Generate cryptographically random bytes.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

/// Generate a random SIP tag (16 hex chars).
pub(crate) fn generate_tag() -> String {
    hex_encode(&random_bytes::<8>())
}

/// Generate a random SIP branch with the RFC 3261 magic cookie prefix.
pub(crate) fn generate_branch() -> String {
    format!("z9hG4bK{}", hex_encode(&random_bytes::<12>()))
}

/// Generate a random UUID v4 string (for Call-ID generation).
pub(crate) fn uuid_v4() -> String {
    let bytes = random_bytes::<16>();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0FFF,
        (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3FFF) | 0x8000,
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
    )
}

/// Add a to-tag to a SIP To header if missing (for non-100 responses).
pub(crate) fn ensure_to_tag(to: &str, status_code: u16) -> String {
    if status_code > 100 && !to.contains("tag=") {
        format!("{to};tag={}", generate_tag())
    } else {
        to.to_string()
    }
}

/// Extract a bare SIP URI from a header value.
/// `<sip:1001@10.0.0.1:5060>` -> `sip:1001@10.0.0.1:5060`
pub(crate) fn extract_uri(header_val: &str) -> &str {
    if let Some(start) = header_val.find('<') {
        if let Some(end) = header_val[start..].find('>') {
            return &header_val[start + 1..start + end];
        }
    }
    header_val.trim()
}

/// Extract the user part from a SIP URI in a From/To header.
/// `<sip:1001@pbx.local>;tag=abc` -> `1001`
pub(crate) fn extract_uri_user(header_val: &str) -> &str {
    let uri = extract_uri(header_val);
    let after_scheme = if let Some(pos) = uri.find("sip:") {
        &uri[pos + 4..]
    } else if let Some(pos) = uri.find("sips:") {
        &uri[pos + 5..]
    } else {
        uri
    };
    after_scheme.split('@').next().unwrap_or(after_scheme)
}

/// Extract the tag value from a From/To header.
/// `<sip:1001@pbx.local>;tag=abc123` -> `Some("abc123")`
pub(crate) fn extract_tag(header_val: &str) -> Option<&str> {
    let tag_start = header_val.find("tag=")?;
    let val = &header_val[tag_start + 4..];
    Some(
        val.split(|c: char| c == ';' || c == ',' || c.is_whitespace())
            .next()
            .unwrap_or(val),
    )
}

/// Append a tag to a From/To header if not already present and tag is non-empty.
pub(crate) fn append_tag(header_val: &str, tag: &str) -> String {
    if tag.is_empty() || header_val.contains("tag=") {
        header_val.to_string()
    } else {
        format!("{};tag={}", header_val, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0x0a, 0xff, 0x00]), "0aff00");
    }

    #[test]
    fn tag_format() {
        let tag = generate_tag();
        assert_eq!(tag.len(), 16);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn branch_format() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert_eq!(branch.len(), 7 + 24);
    }

    #[test]
    fn uuid_format() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(id.chars().nth(14), Some('4'));
    }

    #[test]
    fn ensure_to_tag_adds_for_200() {
        let result = ensure_to_tag("<sip:1002@pbx>", 200);
        assert!(result.contains("tag="));
    }

    #[test]
    fn ensure_to_tag_skips_for_100() {
        let result = ensure_to_tag("<sip:1002@pbx>", 100);
        assert!(!result.contains("tag="));
    }

    #[test]
    fn ensure_to_tag_preserves_existing() {
        let result = ensure_to_tag("<sip:1002@pbx>;tag=existing", 200);
        assert!(result.contains("tag=existing"));
        assert_eq!(result.matches("tag=").count(), 1);
    }

    #[test]
    fn extract_uri_angle_brackets() {
        assert_eq!(
            extract_uri("<sip:1001@10.0.0.1:5060>"),
            "sip:1001@10.0.0.1:5060"
        );
    }

    #[test]
    fn extract_uri_bare() {
        assert_eq!(extract_uri("sip:1001@10.0.0.1"), "sip:1001@10.0.0.1");
    }

    #[test]
    fn extract_uri_with_display_name() {
        assert_eq!(
            extract_uri("\"Alice\" <sip:1001@10.0.0.1:5060>;transport=udp"),
            "sip:1001@10.0.0.1:5060"
        );
    }

    #[test]
    fn extract_uri_user_from_header() {
        assert_eq!(extract_uri_user("<sip:1001@pbx.local>;tag=abc"), "1001");
    }

    #[test]
    fn extract_uri_user_plus_number() {
        assert_eq!(
            extract_uri_user("<sip:+15551234567@10.0.0.1:5060>"),
            "+15551234567"
        );
    }

    #[test]
    fn extract_uri_user_bare() {
        assert_eq!(extract_uri_user("sip:user@host"), "user");
    }

    #[test]
    fn extract_tag_present() {
        assert_eq!(
            extract_tag("<sip:1001@pbx.local>;tag=abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_tag_absent() {
        assert_eq!(extract_tag("<sip:1001@pbx.local>"), None);
    }

    #[test]
    fn extract_tag_with_params() {
        assert_eq!(
            extract_tag("<sip:1001@pbx.local>;tag=abc;param=x"),
            Some("abc")
        );
    }

    #[test]
    fn append_tag_to_header() {
        assert_eq!(
            append_tag("<sip:1001@pbx.local>", "newtag"),
            "<sip:1001@pbx.local>;tag=newtag"
        );
    }

    #[test]
    fn append_tag_preserves_existing() {
        assert_eq!(
            append_tag("<sip:1001@pbx.local>;tag=existing", "newtag"),
            "<sip:1001@pbx.local>;tag=existing"
        );
    }

    #[test]
    fn append_tag_empty_is_noop() {
        assert_eq!(
            append_tag("<sip:1001@pbx.local>", ""),
            "<sip:1001@pbx.local>"
        );
    }
}
