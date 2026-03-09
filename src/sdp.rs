use crate::error::Error;
use crate::ice::IceSdpParams;
use crate::types::VideoCodec;

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
    /// Media type: `"audio"` or `"video"`.
    pub media_type: String,
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
    /// `a=rtpmap:` entries: `(payload_type, encoding_name)`.
    pub rtpmap: Vec<(i32, String)>,
    /// `a=fmtp:` entries: `(payload_type, params)`.
    pub fmtp: Vec<(i32, String)>,
    /// `a=rtcp-fb:` entries: `(payload_type, feedback_type)`.
    pub rtcp_fb: Vec<(i32, String)>,
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

    /// Returns the first audio media description, if any.
    pub fn audio_media(&self) -> Option<&MediaDesc> {
        self.media.iter().find(|m| m.media_type == "audio")
    }

    /// Returns the first video media description, if any.
    pub fn video_media(&self) -> Option<&MediaDesc> {
        self.media.iter().find(|m| m.media_type == "video")
    }

    /// Returns true if this SDP includes a video m= line.
    pub fn has_video(&self) -> bool {
        self.video_media().is_some()
    }

    /// Identifies the negotiated video codec from the video m= line's rtpmap.
    pub fn video_codec(&self) -> Option<VideoCodec> {
        let vm = self.video_media()?;
        let pt = *vm.codecs.first()?;
        vm.rtpmap
            .iter()
            .find(|(p, _)| *p == pt)
            .and_then(|(_, name)| VideoCodec::from_rtpmap_name(name))
    }
}

fn codec_name(pt: i32) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU/8000"),
        8 => Some("PCMA/8000"),
        9 => Some("G722/8000"),
        18 => Some("G729/8000"),
        101 => Some("telephone-event/8000"),
        111 => Some("opus/48000/2"),
        _ => None,
    }
}

fn codec_fmtp(pt: i32) -> Option<&'static str> {
    match pt {
        18 => Some("annexb=no"),
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
                    let media_type = parts[0].to_string();
                    let port = parts[1].parse::<i32>().unwrap_or(0);
                    let profile = parts[2].to_string();
                    let codecs: Vec<i32> = parts[3..]
                        .iter()
                        .filter_map(|s| s.parse::<i32>().ok())
                        .collect();
                    session.media.push(MediaDesc {
                        media_type,
                        port,
                        codecs,
                        direction: String::new(),
                        profile,
                        crypto: Vec::new(),
                        candidates: Vec::new(),
                        rtpmap: Vec::new(),
                        fmtp: Vec::new(),
                        rtcp_fb: Vec::new(),
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
                    if let Some(rtpmap_val) = val.strip_prefix("rtpmap:") {
                        if let Some(idx) = cur_media_idx {
                            if let Some(pair) = parse_pt_value(rtpmap_val) {
                                session.media[idx].rtpmap.push(pair);
                            }
                        }
                    } else if let Some(fmtp_val) = val.strip_prefix("fmtp:") {
                        if let Some(idx) = cur_media_idx {
                            if let Some(pair) = parse_pt_value(fmtp_val) {
                                session.media[idx].fmtp.push(pair);
                            }
                        }
                    } else if let Some(fb_val) = val.strip_prefix("rtcp-fb:") {
                        if let Some(idx) = cur_media_idx {
                            if let Some(pair) = parse_pt_value(fb_val) {
                                session.media[idx].rtcp_fb.push(pair);
                            }
                        }
                    } else if let Some(crypto_val) = val.strip_prefix("crypto:") {
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

/// Appends media-level crypto, ICE, and direction attributes.
fn write_media_attrs(
    b: &mut String,
    direction: &str,
    crypto_inline_key: Option<&str>,
    ice: Option<&IceSdpParams>,
) {
    if let Some(key) = crypto_inline_key {
        b.push_str(&format!(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
            key
        ));
    }
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
    write_media_attrs(&mut b, direction, crypto_inline_key, ice);
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

/// Parses `"<PT> <value>"` → `(PT, value)`.
/// Used for `a=rtpmap:`, `a=fmtp:`, and `a=rtcp-fb:` lines.
fn parse_pt_value(val: &str) -> Option<(i32, String)> {
    let (pt_str, rest) = val.split_once(' ')?;
    let pt = pt_str.trim().parse::<i32>().ok()?;
    Some((pt, rest.trim().to_string()))
}

/// Builds a video m= section (without session-level headers).
/// `codecs` is a list of `(VideoCodec, payload_type)` pairs.
/// For offers, use `default_payload_type()`. For answers, use the remote's PT.
fn build_video_section(
    port: i32,
    codecs: &[(VideoCodec, u8)],
    direction: &str,
    profile: &str,
    crypto_inline_key: Option<&str>,
    ice: Option<&IceSdpParams>,
) -> String {
    let mut b = String::new();
    b.push_str(&format!("m=video {} {}", port, profile));
    for (_, pt) in codecs {
        b.push_str(&format!(" {}", pt));
    }
    b.push_str("\r\n");
    for (vc, pt) in codecs {
        b.push_str(&format!("a=rtpmap:{} {}\r\n", pt, vc.rtpmap_name()));
        if let Some(fmtp) = vc.fmtp() {
            b.push_str(&format!("a=fmtp:{} {}\r\n", pt, fmtp));
        }
        for fb in vc.rtcp_fb() {
            b.push_str(&format!("a=rtcp-fb:{} {}\r\n", pt, fb));
        }
    }
    write_media_attrs(&mut b, direction, crypto_inline_key, ice);
    b
}

/// Converts a slice of VideoCodec to (codec, default_pt) pairs for offers.
fn default_video_pts(codecs: &[VideoCodec]) -> Vec<(VideoCodec, u8)> {
    codecs
        .iter()
        .map(|vc| (*vc, vc.default_payload_type()))
        .collect()
}

/// Creates an SDP offer with audio and video media sections.
pub fn build_offer_video(
    ip: &str,
    audio_port: i32,
    audio_codecs: &[i32],
    video_port: i32,
    video_codecs: &[VideoCodec],
    direction: &str,
) -> String {
    let mut sdp = build_offer_inner(
        ip,
        audio_port,
        audio_codecs,
        direction,
        "RTP/AVP",
        None,
        None,
    );
    let pts = default_video_pts(video_codecs);
    sdp.push_str(&build_video_section(
        video_port, &pts, direction, "RTP/AVP", None, None,
    ));
    sdp
}

/// Creates an SDP offer with audio + video and SRTP.
#[allow(clippy::too_many_arguments)]
pub fn build_offer_video_srtp(
    ip: &str,
    audio_port: i32,
    audio_codecs: &[i32],
    video_port: i32,
    video_codecs: &[VideoCodec],
    direction: &str,
    audio_crypto_key: &str,
    video_crypto_key: &str,
) -> String {
    let mut sdp = build_offer_inner(
        ip,
        audio_port,
        audio_codecs,
        direction,
        "RTP/SAVP",
        Some(audio_crypto_key),
        None,
    );
    let pts = default_video_pts(video_codecs);
    sdp.push_str(&build_video_section(
        video_port,
        &pts,
        direction,
        "RTP/SAVP",
        Some(video_crypto_key),
        None,
    ));
    sdp
}

/// Creates an SDP offer with audio + video and ICE.
#[allow(clippy::too_many_arguments)]
pub fn build_offer_video_ice(
    ip: &str,
    audio_port: i32,
    audio_codecs: &[i32],
    video_port: i32,
    video_codecs: &[VideoCodec],
    direction: &str,
    audio_ice: &IceSdpParams,
    video_ice: &IceSdpParams,
) -> String {
    let mut sdp = build_offer_inner(
        ip,
        audio_port,
        audio_codecs,
        direction,
        "RTP/AVP",
        None,
        Some(audio_ice),
    );
    let pts = default_video_pts(video_codecs);
    sdp.push_str(&build_video_section(
        video_port,
        &pts,
        direction,
        "RTP/AVP",
        None,
        Some(video_ice),
    ));
    sdp
}

/// Creates an SDP answer with audio + video (intersects codecs).
///
/// Per RFC 3264: the answer uses the remote's payload types, and includes
/// a rejected `m=video 0` line if no common video codec is found (to preserve
/// m= line count/order).
#[allow(clippy::too_many_arguments)]
pub fn build_answer_video(
    ip: &str,
    audio_port: i32,
    local_audio_prefs: &[i32],
    remote_audio: &[i32],
    video_port: i32,
    local_video: &[VideoCodec],
    remote_video_rtpmap: &[(i32, String)],
    direction: &str,
) -> String {
    // Audio: intersect as usual.
    let mut audio_common = intersect_codecs(local_audio_prefs, remote_audio);
    if audio_common.is_empty() {
        audio_common = local_audio_prefs.to_vec();
    }
    // Video: intersect by matching local VideoCodec against remote rtpmap names.
    // Use the remote's PT (RFC 3264 §6.1: answer mirrors offer's dynamic PT).
    let video_common: Vec<(VideoCodec, u8)> = local_video
        .iter()
        .filter_map(|vc| {
            remote_video_rtpmap
                .iter()
                .find(|(_, name)| VideoCodec::from_rtpmap_name(name) == Some(*vc))
                .map(|(pt, _)| (*vc, *pt as u8))
        })
        .collect();
    let mut sdp = build_offer(ip, audio_port, &audio_common, direction);
    if video_common.is_empty() {
        // RFC 3264: reject unsupported media with port 0.
        sdp.push_str("m=video 0 RTP/AVP 0\r\n");
    } else {
        sdp.push_str(&build_video_section(
            video_port,
            &video_common,
            direction,
            "RTP/AVP",
            None,
            None,
        ));
    }
    sdp
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

    // --- Video SDP tests ---

    #[test]
    fn build_offer_video_has_two_m_lines() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0, 8],
            5006,
            &[VideoCodec::H264, VideoCodec::VP8],
            "sendrecv",
        );
        assert!(sdp.contains("m=audio 5004 RTP/AVP 0 8"));
        assert!(sdp.contains("m=video 5006 RTP/AVP 96 97"));
    }

    #[test]
    fn build_offer_video_h264_rtpmap_fmtp() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
        );
        assert!(sdp.contains("a=rtpmap:96 H264/90000"));
        assert!(sdp.contains("a=fmtp:96 profile-level-id=42e01f;packetization-mode=1"));
    }

    #[test]
    fn build_offer_video_vp8_no_fmtp() {
        let sdp = build_offer_video("10.0.0.1", 5004, &[0], 5006, &[VideoCodec::VP8], "sendrecv");
        assert!(sdp.contains("a=rtpmap:97 VP8/90000"));
        // VP8 has no fmtp
        assert!(!sdp.contains("a=fmtp:97"));
    }

    #[test]
    fn build_offer_video_rtcp_fb() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
        );
        assert!(sdp.contains("a=rtcp-fb:96 nack\r\n"));
        assert!(sdp.contains("a=rtcp-fb:96 nack pli"));
        assert!(sdp.contains("a=rtcp-fb:96 ccm fir"));
    }

    #[test]
    fn build_offer_video_direction() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendonly",
        );
        // Both audio and video sections should have the direction
        let sendonly_count = sdp.matches("a=sendonly").count();
        assert_eq!(sendonly_count, 2);
    }

    #[test]
    fn parse_video_offer_two_m_lines() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0, 8],
            5006,
            &[VideoCodec::H264, VideoCodec::VP8],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.media[0].media_type, "audio");
        assert_eq!(s.media[0].port, 5004);
        assert_eq!(s.media[1].media_type, "video");
        assert_eq!(s.media[1].port, 5006);
    }

    #[test]
    fn parse_video_offer_rtpmap() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264, VideoCodec::VP8],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        let video = s.video_media().unwrap();
        assert_eq!(video.codecs, vec![96, 97]);
        assert!(video
            .rtpmap
            .iter()
            .any(|(pt, n)| *pt == 96 && n == "H264/90000"));
        assert!(video
            .rtpmap
            .iter()
            .any(|(pt, n)| *pt == 97 && n == "VP8/90000"));
    }

    #[test]
    fn parse_video_offer_fmtp() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        let video = s.video_media().unwrap();
        assert!(video
            .fmtp
            .iter()
            .any(|(pt, p)| *pt == 96 && p.contains("profile-level-id")));
    }

    #[test]
    fn parse_video_offer_rtcp_fb() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        let video = s.video_media().unwrap();
        assert!(video
            .rtcp_fb
            .iter()
            .any(|(pt, fb)| *pt == 96 && fb == "nack"));
        assert!(video
            .rtcp_fb
            .iter()
            .any(|(pt, fb)| *pt == 96 && fb == "nack pli"));
        assert!(video
            .rtcp_fb
            .iter()
            .any(|(pt, fb)| *pt == 96 && fb == "ccm fir"));
    }

    #[test]
    fn session_has_video() {
        let sdp = build_offer_video(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        assert!(s.has_video());
        assert_eq!(s.video_codec(), Some(VideoCodec::H264));
    }

    #[test]
    fn session_audio_only_no_video() {
        let sdp = build_offer("10.0.0.1", 5004, &[0], "sendrecv");
        let s = parse(&sdp).unwrap();
        assert!(!s.has_video());
        assert_eq!(s.video_codec(), None);
        assert!(s.audio_media().is_some());
        assert_eq!(s.audio_media().unwrap().media_type, "audio");
    }

    #[test]
    fn audio_only_backwards_compat() {
        // Existing audio-only functions still work unchanged.
        let sdp = build_offer("192.168.1.100", 5004, &[0, 8], "sendrecv");
        let s = parse(&sdp).unwrap();
        assert_eq!(s.media.len(), 1);
        assert_eq!(s.media[0].media_type, "audio");
        assert_eq!(s.first_codec(), 0);
        assert_eq!(s.dir(), "sendrecv");
        assert!(!s.has_video());
    }

    #[test]
    fn parse_pt_value_rtpmap() {
        let (pt, name) = parse_pt_value("96 H264/90000").unwrap();
        assert_eq!(pt, 96);
        assert_eq!(name, "H264/90000");
    }

    #[test]
    fn parse_pt_value_fmtp() {
        let (pt, params) = parse_pt_value("96 profile-level-id=42e01f").unwrap();
        assert_eq!(pt, 96);
        assert_eq!(params, "profile-level-id=42e01f");
    }

    #[test]
    fn parse_pt_value_rtcp_fb() {
        let (pt, fb) = parse_pt_value("96 nack pli").unwrap();
        assert_eq!(pt, 96);
        assert_eq!(fb, "nack pli");
    }

    #[test]
    fn parse_pt_value_invalid() {
        assert!(parse_pt_value("").is_none());
        assert!(parse_pt_value("notanumber foo").is_none());
    }

    #[test]
    fn build_offer_video_srtp_has_savp() {
        let sdp = build_offer_video_srtp(
            "10.0.0.1",
            5004,
            &[0],
            5006,
            &[VideoCodec::H264],
            "sendrecv",
            "audiokey123",
            "videokey456",
        );
        assert!(sdp.contains("m=audio 5004 RTP/SAVP"));
        assert!(sdp.contains("m=video 5006 RTP/SAVP"));
        assert!(sdp.contains("inline:audiokey123"));
        assert!(sdp.contains("inline:videokey456"));
    }

    #[test]
    fn build_answer_video_intersects() {
        // Remote offers H264(96) + VP8(97), local prefers [VP8, H264].
        // Answer should include both in local preference order, using remote's PTs.
        let sdp = build_answer_video(
            "10.0.0.1",
            5004,
            &[0, 8],
            &[0, 8, 9],
            5006,
            &[VideoCodec::VP8, VideoCodec::H264],
            &[(96, "H264/90000".into()), (97, "VP8/90000".into())],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        assert!(s.has_video());
        let video = s.video_media().unwrap();
        // VP8 first (local preference), then H264 — using remote's PTs
        assert_eq!(video.codecs[0], 97); // VP8 at remote's PT 97
        assert_eq!(video.codecs[1], 96); // H264 at remote's PT 96
    }

    #[test]
    fn build_answer_video_uses_remote_pt() {
        // Remote offers H264 at PT 120 (non-default). Answer must mirror PT 120.
        let sdp = build_answer_video(
            "10.0.0.1",
            5004,
            &[0],
            &[0],
            5006,
            &[VideoCodec::H264],
            &[(120, "H264/90000".into())],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        assert!(s.has_video());
        let video = s.video_media().unwrap();
        assert_eq!(video.codecs, vec![120]); // Remote's PT, not default 96
        assert!(video
            .rtpmap
            .iter()
            .any(|(pt, n)| *pt == 120 && n == "H264/90000"));
    }

    #[test]
    fn build_answer_video_no_common_rejects_with_port_zero() {
        // Remote offers only H264, local only supports VP8.
        // RFC 3264: must include m= line with port 0 to reject.
        let sdp = build_answer_video(
            "10.0.0.1",
            5004,
            &[0],
            &[0],
            5006,
            &[VideoCodec::VP8],
            &[(96, "H264/90000".into())],
            "sendrecv",
        );
        let s = parse(&sdp).unwrap();
        // Video rejected but m= line preserved with port 0.
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.media[1].media_type, "video");
        assert_eq!(s.media[1].port, 0);
    }

    #[test]
    fn parse_external_video_sdp() {
        // Simulate parsing an SDP from a remote endpoint.
        let raw = "v=0\r\n\
            o=remote 123 456 IN IP4 203.0.113.1\r\n\
            s=-\r\n\
            c=IN IP4 203.0.113.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0 8\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=sendrecv\r\n\
            m=video 20002 RTP/AVP 96\r\n\
            a=rtpmap:96 H264/90000\r\n\
            a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n\
            a=rtcp-fb:96 nack\r\n\
            a=rtcp-fb:96 nack pli\r\n\
            a=rtcp-fb:96 ccm fir\r\n\
            a=sendrecv\r\n";
        let s = parse(raw).unwrap();
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.media[0].media_type, "audio");
        assert_eq!(s.media[0].port, 20000);
        assert_eq!(s.media[1].media_type, "video");
        assert_eq!(s.media[1].port, 20002);
        assert!(s.has_video());
        assert_eq!(s.video_codec(), Some(VideoCodec::H264));

        let video = s.video_media().unwrap();
        assert_eq!(video.codecs, vec![96]);
        assert_eq!(video.rtpmap.len(), 1);
        assert_eq!(video.fmtp.len(), 1);
        assert_eq!(video.rtcp_fb.len(), 3);
    }

    #[test]
    fn parse_audio_rtpmap_stored() {
        // Verify rtpmap is also parsed for audio m= lines.
        let sdp = build_offer("10.0.0.1", 5004, &[0, 8], "sendrecv");
        let s = parse(&sdp).unwrap();
        let audio = s.audio_media().unwrap();
        assert!(audio
            .rtpmap
            .iter()
            .any(|(pt, n)| *pt == 0 && n == "PCMU/8000"));
        assert!(audio
            .rtpmap
            .iter()
            .any(|(pt, n)| *pt == 8 && n == "PCMA/8000"));
    }
}
