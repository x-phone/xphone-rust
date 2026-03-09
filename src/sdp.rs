use crate::error::Error;
use crate::ice::IceSdpParams;

/// SDP direction: send and receive.
pub const DIR_SEND_RECV: &str = "sendrecv";
/// SDP direction: send only.
pub const DIR_SEND_ONLY: &str = "sendonly";
/// SDP direction: receive only.
pub const DIR_RECV_ONLY: &str = "recvonly";
/// SDP direction: inactive (neither send nor receive).
pub const DIR_INACTIVE: &str = "inactive";

/// A parsed SDP session description.
#[derive(Debug, Clone)]
pub struct Session {
    /// The `o=` origin line value.
    pub origin: String,
    /// The IP address from the `c=` connection line.
    pub connection: String,
    /// Media descriptions parsed from `m=` lines.
    pub media: Vec<MediaDesc>,
    /// The original raw SDP text.
    pub raw: String,
    /// ICE username fragment from `a=ice-ufrag:`.
    pub ice_ufrag: Option<String>,
    /// ICE password from `a=ice-pwd:`.
    pub ice_pwd: Option<String>,
    /// Whether `a=ice-lite` is present.
    pub ice_lite: bool,
}

/// A single media description from an SDP m= line.
#[derive(Debug, Clone)]
pub struct MediaDesc {
    /// Media port number.
    pub port: i32,
    /// RTP payload type numbers offered/answered.
    pub codecs: Vec<i32>,
    /// Stream direction (e.g., "sendrecv", "sendonly").
    pub direction: String,
    /// RTP profile: "RTP/AVP" or "RTP/SAVP".
    pub profile: String,
    /// SRTP crypto attributes parsed from `a=crypto:` lines.
    pub crypto: Vec<CryptoAttr>,
    /// Raw `a=candidate:` lines.
    pub candidates: Vec<String>,
}

/// Parsed SRTP crypto attribute from an `a=crypto:` SDP line.
#[derive(Debug, Clone)]
pub struct CryptoAttr {
    /// Crypto tag number (e.g., 1).
    pub tag: u32,
    /// Cipher suite name (e.g., "AES_CM_128_HMAC_SHA1_80").
    pub suite: String,
    /// Key parameter (e.g., "inline:base64key...").
    pub key_params: String,
}

impl Session {
    /// Returns the first payload type from the first m= line, or -1 if none.
    pub fn first_codec(&self) -> i32 {
        self.media
            .first()
            .and_then(|m| m.codecs.first().copied())
            .unwrap_or(-1)
    }

    /// Returns the media direction, defaulting to sendrecv.
    pub fn dir(&self) -> &str {
        self.media
            .first()
            .map(|m| {
                if m.direction.is_empty() {
                    DIR_SEND_RECV
                } else {
                    m.direction.as_str()
                }
            })
            .unwrap_or(DIR_SEND_RECV)
    }

    /// Returns true if the first media line uses RTP/SAVP (SRTP).
    pub fn is_srtp(&self) -> bool {
        self.media
            .first()
            .map(|m| m.profile == "RTP/SAVP")
            .unwrap_or(false)
    }

    /// Returns the first crypto attribute from the first media line, if any.
    pub fn first_crypto(&self) -> Option<&CryptoAttr> {
        self.media.first().and_then(|m| m.crypto.first())
    }
}

fn codec_name(pt: i32) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU/8000"),
        8 => Some("PCMA/8000"),
        9 => Some("G722/8000"),
        101 => Some("telephone-event/8000"),
        111 => Some("opus/48000/2"),
        _ => None,
    }
}

fn codec_fmtp(pt: i32) -> Option<&'static str> {
    match pt {
        101 => Some("0-16"),
        111 => Some("minptime=20;useinbandfec=0"),
        _ => None,
    }
}

/// Parses a raw SDP string into a [`Session`].
pub fn parse(raw: &str) -> crate::error::Result<Session> {
    let mut session = Session {
        origin: String::new(),
        connection: String::new(),
        media: Vec::new(),
        raw: raw.to_string(),
        ice_ufrag: None,
        ice_pwd: None,
        ice_lite: false,
    };
    let mut has_version = false;
    let mut cur_media_idx: Option<usize> = None;

    for line in raw.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            continue;
        }
        let key = line.as_bytes()[0];
        let val = &line[2..];

        match key {
            b'v' => has_version = true,
            b'o' => session.origin = val.to_string(),
            b'c' => {
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 3 {
                    session.connection = parts[2].to_string();
                }
            }
            b'm' => {
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 3 {
                    let port = parts[1].parse::<i32>().unwrap_or(0);
                    let profile = parts[2].to_string();
                    let codecs: Vec<i32> = parts[3..]
                        .iter()
                        .filter_map(|s| s.parse::<i32>().ok())
                        .collect();
                    session.media.push(MediaDesc {
                        port,
                        codecs,
                        direction: String::new(),
                        profile,
                        crypto: Vec::new(),
                        candidates: Vec::new(),
                    });
                    cur_media_idx = Some(session.media.len() - 1);
                }
            }
            b'a' => match val {
                DIR_SEND_RECV | DIR_SEND_ONLY | DIR_RECV_ONLY | DIR_INACTIVE => {
                    if let Some(idx) = cur_media_idx {
                        session.media[idx].direction = val.to_string();
                    }
                }
                _ => {
                    if let Some(crypto_val) = val.strip_prefix("crypto:") {
                        if let Some(idx) = cur_media_idx {
                            if let Some(attr) = parse_crypto_val(crypto_val) {
                                session.media[idx].crypto.push(attr);
                            }
                        }
                    } else if let Some(ufrag) = val.strip_prefix("ice-ufrag:") {
                        session.ice_ufrag = Some(ufrag.to_string());
                    } else if let Some(pwd) = val.strip_prefix("ice-pwd:") {
                        session.ice_pwd = Some(pwd.to_string());
                    } else if val == "ice-lite" {
                        session.ice_lite = true;
                    } else if let Some(cand_val) = val.strip_prefix("candidate:") {
                        if let Some(idx) = cur_media_idx {
                            session.media[idx].candidates.push(cand_val.to_string());
                        }
                    }
                }
            },
            _ => {}
        }
    }

    if !has_version {
        return Err(Error::Sdp("no v= line found".into()));
    }
    Ok(session)
}

fn build_offer_inner(
    ip: &str,
    port: i32,
    codecs: &[i32],
    direction: &str,
    profile: &str,
    crypto_inline_key: Option<&str>,
    ice: Option<&IceSdpParams>,
) -> String {
    let mut b = String::new();
    b.push_str("v=0\r\n");
    b.push_str("o=xphone 0 0 IN IP4 ");
    b.push_str(ip);
    b.push_str("\r\n");
    b.push_str("s=xphone\r\n");
    b.push_str("c=IN IP4 ");
    b.push_str(ip);
    b.push_str("\r\n");
    b.push_str("t=0 0\r\n");
    // ICE-Lite is a session-level attribute.
    if let Some(ice_params) = ice {
        if ice_params.ice_lite {
            b.push_str("a=ice-lite\r\n");
        }
    }
    b.push_str(&format!("m=audio {} {}", port, profile));
    for c in codecs {
        b.push_str(&format!(" {}", c));
    }
    b.push_str("\r\n");
    for &c in codecs {
        if let Some(name) = codec_name(c) {
            b.push_str(&format!("a=rtpmap:{} {}\r\n", c, name));
            if let Some(fmtp) = codec_fmtp(c) {
                b.push_str(&format!("a=fmtp:{} {}\r\n", c, fmtp));
            }
        }
    }
    if let Some(key) = crypto_inline_key {
        b.push_str(&format!(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
            key
        ));
    }
    // ICE attributes (media-level).
    if let Some(ice_params) = ice {
        b.push_str(&format!("a=ice-ufrag:{}\r\n", ice_params.ufrag));
        b.push_str(&format!("a=ice-pwd:{}\r\n", ice_params.pwd));
        for cand in &ice_params.candidates {
            b.push_str(&format!("a=candidate:{}\r\n", cand.to_sdp_value()));
        }
    }
    b.push_str("a=");
    b.push_str(direction);
    b.push_str("\r\n");
    b
}

/// Creates an SDP offer string.
pub fn build_offer(ip: &str, port: i32, codecs: &[i32], direction: &str) -> String {
    build_offer_inner(ip, port, codecs, direction, "RTP/AVP", None, None)
}

/// Creates an SDP offer with ICE attributes.
pub fn build_offer_ice(
    ip: &str,
    port: i32,
    codecs: &[i32],
    direction: &str,
    ice: &IceSdpParams,
) -> String {
    build_offer_inner(ip, port, codecs, direction, "RTP/AVP", None, Some(ice))
}

/// Creates an SDP answer that only includes codecs present in both
/// `local_prefs` and `remote_offer` (in local preference order).
pub fn build_answer(
    ip: &str,
    port: i32,
    local_prefs: &[i32],
    remote_offer: &[i32],
    direction: &str,
) -> String {
    let mut common = intersect_codecs(local_prefs, remote_offer);
    if common.is_empty() {
        common = local_prefs.to_vec();
    }
    build_offer(ip, port, &common, direction)
}

/// Finds the first common codec between local preferences and remote offer.
/// Returns -1 if no common codec found.
pub fn negotiate_codec(local_prefs: &[i32], remote_offer: &[i32]) -> i32 {
    let common = intersect_codecs(local_prefs, remote_offer);
    common.first().copied().unwrap_or(-1)
}

/// Creates an SDP offer with SRTP support (RTP/SAVP + a=crypto line).
pub fn build_offer_srtp(
    ip: &str,
    port: i32,
    codecs: &[i32],
    direction: &str,
    crypto_inline_key: &str,
) -> String {
    build_offer_inner(
        ip,
        port,
        codecs,
        direction,
        "RTP/SAVP",
        Some(crypto_inline_key),
        None,
    )
}

/// Creates an SDP offer with SRTP and ICE attributes.
pub fn build_offer_srtp_ice(
    ip: &str,
    port: i32,
    codecs: &[i32],
    direction: &str,
    crypto_inline_key: &str,
    ice: &IceSdpParams,
) -> String {
    build_offer_inner(
        ip,
        port,
        codecs,
        direction,
        "RTP/SAVP",
        Some(crypto_inline_key),
        Some(ice),
    )
}

/// Creates an SDP answer with SRTP support.
pub fn build_answer_srtp(
    ip: &str,
    port: i32,
    local_prefs: &[i32],
    remote_offer: &[i32],
    direction: &str,
    crypto_inline_key: &str,
) -> String {
    let mut common = intersect_codecs(local_prefs, remote_offer);
    if common.is_empty() {
        common = local_prefs.to_vec();
    }
    build_offer_srtp(ip, port, &common, direction, crypto_inline_key)
}

/// Parses the value portion of `a=crypto:<value>`.
fn parse_crypto_val(val: &str) -> Option<CryptoAttr> {
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let tag = parts[0].parse::<u32>().ok()?;
    Some(CryptoAttr {
        tag,
        suite: parts[1].to_string(),
        key_params: parts[2].to_string(),
    })
}

fn intersect_codecs(local_prefs: &[i32], remote: &[i32]) -> Vec<i32> {
    let set: std::collections::HashSet<i32> = remote.iter().copied().collect();
    local_prefs
        .iter()
        .copied()
        .filter(|c| set.contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sdp(ip: &str, port: i32, dir: &str, codecs: &[i32]) -> String {
        build_offer(ip, port, codecs, dir)
    }

    #[test]
    fn build_offer_single_codec() {
        let sdp = build_offer("192.168.1.100", 5004, &[0], "sendrecv");
        assert!(sdp.contains("m=audio"));
        assert!(sdp.contains("PCMU/8000"));
    }

    #[test]
    fn build_offer_multiple_codecs() {
        let sdp = build_offer("192.168.1.100", 5004, &[0, 8, 9], "sendrecv");
        assert!(sdp.contains("m=audio 5004 RTP/AVP 0 8 9"));
    }

    #[test]
    fn build_offer_connection_line() {
        let sdp = build_offer("10.0.0.1", 5004, &[0], "sendrecv");
        assert!(sdp.contains("c=IN IP4 10.0.0.1"));
    }

    #[test]
    fn build_offer_media_line() {
        let sdp = build_offer("192.168.1.100", 6000, &[0], "sendrecv");
        assert!(sdp.contains("m=audio 6000 RTP/AVP"));
    }

    #[test]
    fn build_offer_direction_sendonly() {
        let sdp = build_offer("192.168.1.100", 5004, &[0], "sendonly");
        assert!(sdp.contains("a=sendonly"));
    }

    #[test]
    fn build_offer_direction_sendrecv() {
        let sdp = build_offer("192.168.1.100", 5004, &[0], "sendrecv");
        assert!(sdp.contains("a=sendrecv"));
    }

    #[test]
    fn parse_extracts_codec() {
        let raw = sample_sdp("192.168.1.100", 5004, "sendrecv", &[0, 8]);
        let s = parse(&raw).unwrap();
        assert_eq!(s.first_codec(), 0);
    }

    #[test]
    fn parse_extracts_address() {
        let raw = sample_sdp("10.0.0.42", 5004, "sendrecv", &[0]);
        let s = parse(&raw).unwrap();
        assert_eq!(s.connection, "10.0.0.42");
    }

    #[test]
    fn parse_extracts_port() {
        let raw = sample_sdp("192.168.1.100", 7000, "sendrecv", &[0]);
        let s = parse(&raw).unwrap();
        assert!(!s.media.is_empty());
        assert_eq!(s.media[0].port, 7000);
    }

    #[test]
    fn parse_direction() {
        let raw = sample_sdp("192.168.1.100", 5004, "sendonly", &[0]);
        let s = parse(&raw).unwrap();
        assert_eq!(s.dir(), "sendonly");
    }

    #[test]
    fn parse_default_direction_is_sendrecv() {
        let raw = "v=0\r\no=xphone 0 0 IN IP4 192.168.1.100\r\ns=xphone\r\nc=IN IP4 192.168.1.100\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let s = parse(raw).unwrap();
        assert_eq!(s.dir(), "sendrecv");
    }

    #[test]
    fn parse_invalid_returns_error() {
        let result = parse("this is not valid SDP");
        assert!(result.is_err());
    }

    #[test]
    fn parse_round_trip() {
        let offer = build_offer("192.168.1.100", 5004, &[0, 8], "sendrecv");
        let s = parse(&offer).unwrap();
        assert_eq!(s.connection, "192.168.1.100");
        assert!(!s.media.is_empty());
        assert_eq!(s.media[0].port, 5004);
        assert_eq!(s.first_codec(), 0);
    }

    #[test]
    fn test_negotiate_codec() {
        // local prefers [0,8], remote offers [8,0] -> first local pref found in remote = 0
        assert_eq!(negotiate_codec(&[0, 8], &[8, 0]), 0);
        // no common codec
        assert_eq!(negotiate_codec(&[0], &[9]), -1);
    }

    #[test]
    fn build_offer_srtp_has_savp() {
        let sdp = build_offer_srtp("10.0.0.1", 5004, &[0], "sendrecv", "dGVzdGtleQ==");
        assert!(sdp.contains("RTP/SAVP"));
        assert!(!sdp.contains("RTP/AVP "));
    }

    #[test]
    fn build_offer_srtp_has_crypto_line() {
        let sdp = build_offer_srtp("10.0.0.1", 5004, &[0], "sendrecv", "dGVzdGtleQ==");
        assert!(sdp.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dGVzdGtleQ=="));
    }

    #[test]
    fn parse_srtp_sdp() {
        let sdp = build_offer_srtp("10.0.0.1", 5004, &[0, 8], "sendrecv", "dGVzdGtleQ==");
        let s = parse(&sdp).unwrap();
        assert!(s.is_srtp());
        assert!(!s.media.is_empty());
        assert_eq!(s.media[0].profile, "RTP/SAVP");

        let crypto = s.first_crypto().unwrap();
        assert_eq!(crypto.tag, 1);
        assert_eq!(crypto.suite, "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(crypto.key_params, "inline:dGVzdGtleQ==");
    }

    #[test]
    fn parse_avp_not_srtp() {
        let sdp = build_offer("10.0.0.1", 5004, &[0], "sendrecv");
        let s = parse(&sdp).unwrap();
        assert!(!s.is_srtp());
        assert!(s.first_crypto().is_none());
        assert_eq!(s.media[0].profile, "RTP/AVP");
    }

    #[test]
    fn build_answer_srtp_intersects() {
        let sdp = build_answer_srtp("10.0.0.1", 5004, &[0, 8], &[8, 9], "sendrecv", "a2V5");
        assert!(sdp.contains("RTP/SAVP"));
        assert!(sdp.contains("a=crypto:"));
        let s = parse(&sdp).unwrap();
        // Only codec 8 is common.
        assert_eq!(s.media[0].codecs, vec![8]);
    }

    // --- ICE SDP tests ---

    #[test]
    fn build_offer_ice_has_candidates() {
        use crate::ice::{self, IceSdpParams};
        let cands = ice::gather_candidates(
            "192.168.1.100:5004".parse().unwrap(),
            Some("203.0.113.42:12345".parse().unwrap()),
            None,
            1,
        );
        let ice_params = IceSdpParams {
            ufrag: "abcd1234".into(),
            pwd: "longpasswordstring12345".into(),
            candidates: cands,
            ice_lite: true,
        };
        let sdp = build_offer_ice("192.168.1.100", 5004, &[0], "sendrecv", &ice_params);
        assert!(sdp.contains("a=ice-lite"));
        assert!(sdp.contains("a=ice-ufrag:abcd1234"));
        assert!(sdp.contains("a=ice-pwd:longpasswordstring12345"));
        assert!(sdp.contains("a=candidate:1"));
        assert!(sdp.contains("typ host"));
        assert!(sdp.contains("a=candidate:2"));
        assert!(sdp.contains("typ srflx"));
    }

    #[test]
    fn build_offer_srtp_ice_has_both() {
        use crate::ice::{self, IceSdpParams};
        let cands = ice::gather_candidates("10.0.0.1:5004".parse().unwrap(), None, None, 1);
        let ice_params = IceSdpParams {
            ufrag: "ufrag".into(),
            pwd: "password".into(),
            candidates: cands,
            ice_lite: false,
        };
        let sdp = build_offer_srtp_ice("10.0.0.1", 5004, &[0], "sendrecv", "key123", &ice_params);
        assert!(sdp.contains("RTP/SAVP"));
        assert!(sdp.contains("a=crypto:"));
        assert!(sdp.contains("a=ice-ufrag:ufrag"));
        assert!(sdp.contains("a=candidate:1"));
        assert!(!sdp.contains("a=ice-lite"));
    }

    #[test]
    fn parse_sdp_with_ice_attrs() {
        use crate::ice::{self, IceSdpParams};
        let cands = ice::gather_candidates(
            "192.168.1.100:5004".parse().unwrap(),
            Some("203.0.113.42:12345".parse().unwrap()),
            None,
            1,
        );
        let ice_params = IceSdpParams {
            ufrag: "testufrag".into(),
            pwd: "testpassword".into(),
            candidates: cands,
            ice_lite: true,
        };
        let sdp = build_offer_ice("192.168.1.100", 5004, &[0], "sendrecv", &ice_params);
        let s = parse(&sdp).unwrap();

        assert!(s.ice_lite);
        assert_eq!(s.ice_ufrag.as_deref(), Some("testufrag"));
        assert_eq!(s.ice_pwd.as_deref(), Some("testpassword"));
        assert_eq!(s.media[0].candidates.len(), 2);
    }

    #[test]
    fn parse_sdp_without_ice() {
        let sdp = build_offer("10.0.0.1", 5004, &[0], "sendrecv");
        let s = parse(&sdp).unwrap();
        assert!(!s.ice_lite);
        assert!(s.ice_ufrag.is_none());
        assert!(s.ice_pwd.is_none());
        assert!(s.media[0].candidates.is_empty());
    }
}
