use std::fmt;

/// Current state of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallState {
    /// No active call.
    Idle,
    /// Inbound: INVITE received, not yet accepted.
    Ringing,
    /// Outbound: INVITE sent, no response yet.
    Dialing,
    /// Outbound: 180 Ringing received from remote.
    RemoteRinging,
    /// Outbound: 183 Session Progress received with early media.
    EarlyMedia,
    /// Call established, RTP flowing.
    Active,
    /// Local hold via re-INVITE with `a=sendonly` or `a=inactive`.
    OnHold,
    /// Terminal state; see [`EndReason`] for cause.
    Ended,
}

impl fmt::Display for CallState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallState::Idle => write!(f, "Idle"),
            CallState::Ringing => write!(f, "Ringing"),
            CallState::Dialing => write!(f, "Dialing"),
            CallState::RemoteRinging => write!(f, "RemoteRinging"),
            CallState::EarlyMedia => write!(f, "EarlyMedia"),
            CallState::Active => write!(f, "Active"),
            CallState::OnHold => write!(f, "OnHold"),
            CallState::Ended => write!(f, "Ended"),
        }
    }
}

/// Registration state of the phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhoneState {
    /// Not connected to the SIP server.
    Disconnected,
    /// REGISTER request in flight.
    Registering,
    /// Successfully registered with the SIP server.
    Registered,
    /// Un-REGISTER request in flight.
    Unregistering,
    /// Registration attempt failed.
    RegistrationFailed,
}

impl fmt::Display for PhoneState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneState::Disconnected => write!(f, "Disconnected"),
            PhoneState::Registering => write!(f, "Registering"),
            PhoneState::Registered => write!(f, "Registered"),
            PhoneState::Unregistering => write!(f, "Unregistering"),
            PhoneState::RegistrationFailed => write!(f, "RegistrationFailed"),
        }
    }
}

/// Reason why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndReason {
    /// Local hangup while call was active or on hold.
    Local,
    /// Remote party sent BYE.
    Remote,
    /// RTP media timeout exceeded.
    Timeout,
    /// Internal or transport error.
    Error,
    /// Call ended after successful REFER transfer.
    Transfer,
    /// Inbound call rejected by local party.
    Rejected,
    /// Outbound call cancelled before receiving 200 OK.
    Cancelled,
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndReason::Local => write!(f, "Local"),
            EndReason::Remote => write!(f, "Remote"),
            EndReason::Timeout => write!(f, "Timeout"),
            EndReason::Error => write!(f, "Error"),
            EndReason::Transfer => write!(f, "Transfer"),
            EndReason::Rejected => write!(f, "Rejected"),
            EndReason::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Direction of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Call received from a remote party.
    Inbound,
    /// Call initiated by the local party.
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => write!(f, "Inbound"),
            Direction::Outbound => write!(f, "Outbound"),
        }
    }
}

/// Fixed portion of an RTP packet header (no CSRC or extensions).
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    /// RTP version, typically `2`.
    pub version: u8,
    /// Marker bit, often used to signal the start of a talkspurt.
    pub marker: bool,
    /// Payload type identifying the codec (e.g., 0 = PCMU).
    pub payload_type: u8,
    /// Monotonically increasing packet sequence number.
    pub sequence_number: u16,
    /// Sampling-clock timestamp of the first octet in the payload.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
}

/// An RTP packet consisting of a header and a media payload.
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// Parsed RTP header fields.
    pub header: RtpHeader,
    /// Raw media payload bytes (codec-encoded audio).
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Minimum RTP header size (no CSRC, no extensions).
    const MIN_HEADER_SIZE: usize = 12;

    /// Parses an RTP packet from raw bytes. Returns None if too short.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return None;
        }
        let version = (data[0] >> 6) & 0x03;
        let cc = (data[0] & 0x0F) as usize;
        let marker = (data[1] & 0x80) != 0;
        let payload_type = data[1] & 0x7F;
        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let header_len = Self::MIN_HEADER_SIZE + cc * 4;
        if data.len() < header_len {
            return None;
        }

        Some(RtpPacket {
            header: RtpHeader {
                version,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
            },
            payload: data[header_len..].to_vec(),
        })
    }

    /// Serializes the RTP packet to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MIN_HEADER_SIZE + self.payload.len());
        buf.push((self.header.version << 6) & 0xC0); // V=2, P=0, X=0, CC=0
        let mut byte1 = self.header.payload_type & 0x7F;
        if self.header.marker {
            byte1 |= 0x80;
        }
        buf.push(byte1);
        buf.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.header.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.header.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// Voicemail (MWI) status from a `message-summary` NOTIFY (RFC 3842).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VoicemailStatus {
    /// Whether new messages are waiting.
    pub messages_waiting: bool,
    /// Optional message account URI (e.g. `sip:*97@pbx.local`).
    pub account: String,
    /// `(new, old)` voice message counts. `(0, 0)` if not reported.
    pub voice: (u32, u32),
}

impl fmt::Display for VoicemailStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MWI: waiting={}, voice={}/{}",
            self.messages_waiting, self.voice.0, self.voice.1
        )
    }
}

/// An instant message received or sent via SIP MESSAGE (RFC 3428).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipMessage {
    /// SIP URI of the sender (from the From header).
    pub from: String,
    /// SIP URI of the recipient (from the To header).
    pub to: String,
    /// MIME content type (e.g. "text/plain").
    pub content_type: String,
    /// The message body.
    pub body: String,
}

impl fmt::Display for SipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MESSAGE from={} body={}", self.from, self.body)
    }
}

/// State of a monitored extension (BLF / dialog event package).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ExtensionState {
    /// Extension is idle and available.
    Available,
    /// Extension is ringing (incoming call).
    Ringing,
    /// Extension is on an active call.
    OnThePhone,
    /// Extension is not registered / unreachable.
    Offline,
    /// State cannot be determined.
    #[default]
    Unknown,
}

impl fmt::Display for ExtensionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtensionState::Available => write!(f, "Available"),
            ExtensionState::Ringing => write!(f, "Ringing"),
            ExtensionState::OnThePhone => write!(f, "OnThePhone"),
            ExtensionState::Offline => write!(f, "Offline"),
            ExtensionState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Status of a watched extension, passed to BLF callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionStatus {
    /// The extension identifier (e.g. "1001").
    pub extension: String,
    /// Current state of the extension.
    pub state: ExtensionState,
}

impl fmt::Display for ExtensionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.extension, self.state)
    }
}

/// Raw NOTIFY event for generic subscription callbacks.
#[derive(Debug, Clone)]
pub struct NotifyEvent {
    /// SIP Event header value (e.g. "dialog", "presence").
    pub event: String,
    /// Content-Type of the NOTIFY body.
    pub content_type: String,
    /// Body of the NOTIFY.
    pub body: String,
    /// Parsed Subscription-State header.
    pub subscription_state: SubState,
}

/// Subscription-State from a NOTIFY (RFC 6665 section 4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubState {
    /// Subscription is pending authorization.
    Pending,
    /// Subscription is active with a remaining lifetime.
    Active {
        /// Server-granted remaining seconds.
        expires: u32,
    },
    /// Subscription has been terminated.
    Terminated {
        /// Reason for termination (e.g. "deactivated", "timeout", "rejected").
        reason: String,
    },
}

impl fmt::Display for SubState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubState::Pending => write!(f, "pending"),
            SubState::Active { expires } => write!(f, "active;expires={}", expires),
            SubState::Terminated { reason } => write!(f, "terminated;reason={}", reason),
        }
    }
}

/// Parses a Subscription-State header value (RFC 6665).
///
/// Examples: `"active;expires=600"`, `"terminated;reason=deactivated"`, `"pending"`
pub fn parse_subscription_state(header: &str) -> SubState {
    let header = header.trim();
    let (state, params) = match header.find(';') {
        Some(pos) => (header[..pos].trim(), &header[pos + 1..]),
        None => (header, ""),
    };

    match state.to_lowercase().as_str() {
        "pending" => SubState::Pending,
        "active" => {
            let expires = parse_param(params, "expires")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600);
            SubState::Active { expires }
        }
        "terminated" => {
            let reason = parse_param(params, "reason").unwrap_or_default();
            SubState::Terminated { reason }
        }
        _ => SubState::Terminated {
            reason: "unknown".into(),
        },
    }
}

/// Extracts a named parameter value from a semicolon-separated param string.
fn parse_param(params: &str, name: &str) -> Option<String> {
    for part in params.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim();
            if key.eq_ignore_ascii_case(name) {
                return Some(part[eq + 1..].trim().to_string());
            }
        }
    }
    None
}

/// Video codec for SDP negotiation and RTP packetization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    /// H.264 / AVC (RFC 6184).
    H264,
    /// VP8 (RFC 7741).
    VP8,
}

impl VideoCodec {
    /// Default dynamic RTP payload type used in SDP offers.
    pub fn default_payload_type(self) -> u8 {
        match self {
            VideoCodec::H264 => 96,
            VideoCodec::VP8 => 97,
        }
    }

    /// RTP clock rate (always 90 kHz for video).
    pub fn clock_rate(self) -> u32 {
        90000
    }

    /// SDP rtpmap encoding name (e.g. `"H264/90000"`).
    pub fn rtpmap_name(self) -> &'static str {
        match self {
            VideoCodec::H264 => "H264/90000",
            VideoCodec::VP8 => "VP8/90000",
        }
    }

    /// SDP fmtp parameters, if any.
    pub fn fmtp(self) -> Option<&'static str> {
        match self {
            VideoCodec::H264 => Some("profile-level-id=42e01f;packetization-mode=1"),
            VideoCodec::VP8 => None,
        }
    }

    /// RTCP feedback types for this codec.
    pub fn rtcp_fb(self) -> &'static [&'static str] {
        match self {
            VideoCodec::H264 | VideoCodec::VP8 => &["nack", "nack pli", "ccm fir"],
        }
    }

    /// Attempts to identify a video codec from an rtpmap encoding name.
    pub fn from_rtpmap_name(name: &str) -> Option<VideoCodec> {
        let codec_part = name.split('/').next()?;
        if codec_part.eq_ignore_ascii_case("H264") {
            Some(VideoCodec::H264)
        } else if codec_part.eq_ignore_ascii_case("VP8") {
            Some(VideoCodec::VP8)
        } else {
            None
        }
    }
}

impl fmt::Display for VideoCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VideoCodec::H264 => write!(f, "H264"),
            VideoCodec::VP8 => write!(f, "VP8"),
        }
    }
}

/// Audio codec identified by RTP payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// G.711 mu-law (payload type 0).
    PCMU = 0,
    /// G.711 A-law (payload type 8).
    PCMA = 8,
    /// G.722 (payload type 9).
    G722 = 9,
    /// G.729 (payload type 18).
    G729 = 18,
    /// Opus (payload type 111).
    Opus = 111,
}

impl Codec {
    /// Returns the RTP payload type number.
    pub fn payload_type(self) -> i32 {
        self as i32
    }

    /// Creates a Codec from an RTP payload type number.
    pub fn from_payload_type(pt: i32) -> Option<Codec> {
        match pt {
            0 => Some(Codec::PCMU),
            8 => Some(Codec::PCMA),
            9 => Some(Codec::G722),
            18 => Some(Codec::G729),
            111 => Some(Codec::Opus),
            _ => None,
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Codec::PCMU => write!(f, "PCMU"),
            Codec::PCMA => write!(f, "PCMA"),
            Codec::G722 => write!(f, "G722"),
            Codec::G729 => write!(f, "G729"),
            Codec::Opus => write!(f, "Opus"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_state_display() {
        assert_eq!(CallState::Idle.to_string(), "Idle");
        assert_eq!(CallState::Active.to_string(), "Active");
        assert_eq!(CallState::Ended.to_string(), "Ended");
    }

    #[test]
    fn phone_state_display() {
        assert_eq!(PhoneState::Disconnected.to_string(), "Disconnected");
        assert_eq!(PhoneState::Registered.to_string(), "Registered");
    }

    #[test]
    fn end_reason_display() {
        assert_eq!(EndReason::Local.to_string(), "Local");
        assert_eq!(EndReason::Remote.to_string(), "Remote");
        assert_eq!(EndReason::Cancelled.to_string(), "Cancelled");
    }

    #[test]
    fn direction_display() {
        assert_eq!(Direction::Inbound.to_string(), "Inbound");
        assert_eq!(Direction::Outbound.to_string(), "Outbound");
    }

    #[test]
    fn codec_payload_type() {
        assert_eq!(Codec::PCMU.payload_type(), 0);
        assert_eq!(Codec::PCMA.payload_type(), 8);
        assert_eq!(Codec::G722.payload_type(), 9);
        assert_eq!(Codec::G729.payload_type(), 18);
        assert_eq!(Codec::Opus.payload_type(), 111);
    }

    #[test]
    fn codec_from_payload_type() {
        assert_eq!(Codec::from_payload_type(0), Some(Codec::PCMU));
        assert_eq!(Codec::from_payload_type(8), Some(Codec::PCMA));
        assert_eq!(Codec::from_payload_type(9), Some(Codec::G722));
        assert_eq!(Codec::from_payload_type(18), Some(Codec::G729));
        assert_eq!(Codec::from_payload_type(111), Some(Codec::Opus));
        assert_eq!(Codec::from_payload_type(99), None);
    }

    #[test]
    fn codec_display() {
        assert_eq!(Codec::PCMU.to_string(), "PCMU");
        assert_eq!(Codec::G722.to_string(), "G722");
        assert_eq!(Codec::G729.to_string(), "G729");
    }

    #[test]
    fn rtp_packet_round_trip() {
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: true,
                payload_type: 0,
                sequence_number: 1234,
                timestamp: 56789,
                ssrc: 0xDEADBEEF,
            },
            payload: vec![1, 2, 3, 4],
        };
        let bytes = pkt.to_bytes();
        let parsed = RtpPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.header.version, 2);
        assert!(parsed.header.marker);
        assert_eq!(parsed.header.payload_type, 0);
        assert_eq!(parsed.header.sequence_number, 1234);
        assert_eq!(parsed.header.timestamp, 56789);
        assert_eq!(parsed.header.ssrc, 0xDEADBEEF);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn rtp_parse_too_short() {
        assert!(RtpPacket::parse(&[0; 11]).is_none());
        assert!(RtpPacket::parse(&[]).is_none());
    }

    #[test]
    fn rtp_parse_header_only() {
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 8,
                sequence_number: 42,
                timestamp: 320,
                ssrc: 100,
            },
            payload: vec![],
        };
        let bytes = pkt.to_bytes();
        assert_eq!(bytes.len(), 12);
        let parsed = RtpPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.header.payload_type, 8);
        assert!(!parsed.header.marker);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn sip_message_default() {
        let msg = SipMessage::default();
        assert!(msg.from.is_empty());
        assert!(msg.body.is_empty());
        assert!(msg.content_type.is_empty());
    }

    #[test]
    fn sip_message_display() {
        let msg = SipMessage {
            from: "sip:1001@pbx.local".into(),
            to: String::new(),
            content_type: "text/plain".into(),
            body: "Hello".into(),
        };
        let s = msg.to_string();
        assert!(s.contains("1001@pbx.local"));
        assert!(s.contains("Hello"));
    }

    #[test]
    fn extension_state_default_is_unknown() {
        assert_eq!(ExtensionState::default(), ExtensionState::Unknown);
    }

    #[test]
    fn extension_state_display() {
        assert_eq!(ExtensionState::Available.to_string(), "Available");
        assert_eq!(ExtensionState::OnThePhone.to_string(), "OnThePhone");
        assert_eq!(ExtensionState::Offline.to_string(), "Offline");
    }

    #[test]
    fn extension_status_display() {
        let s = ExtensionStatus {
            extension: "1001".into(),
            state: ExtensionState::OnThePhone,
        };
        assert_eq!(s.to_string(), "1001: OnThePhone");
    }

    #[test]
    fn parse_subscription_state_active_with_expires() {
        let s = parse_subscription_state("active;expires=600");
        assert_eq!(s, SubState::Active { expires: 600 });
    }

    #[test]
    fn parse_subscription_state_active_no_expires() {
        let s = parse_subscription_state("active");
        assert_eq!(s, SubState::Active { expires: 3600 });
    }

    #[test]
    fn parse_subscription_state_terminated_deactivated() {
        let s = parse_subscription_state("terminated;reason=deactivated");
        assert_eq!(
            s,
            SubState::Terminated {
                reason: "deactivated".into()
            }
        );
    }

    #[test]
    fn parse_subscription_state_terminated_rejected() {
        let s = parse_subscription_state("terminated;reason=rejected");
        assert_eq!(
            s,
            SubState::Terminated {
                reason: "rejected".into()
            }
        );
    }

    #[test]
    fn parse_subscription_state_pending() {
        assert_eq!(parse_subscription_state("pending"), SubState::Pending);
    }

    #[test]
    fn parse_subscription_state_case_insensitive() {
        let s = parse_subscription_state("Active;Expires=300");
        assert_eq!(s, SubState::Active { expires: 300 });
    }

    #[test]
    fn parse_subscription_state_whitespace() {
        let s = parse_subscription_state("  active ; expires = 120  ");
        assert_eq!(s, SubState::Active { expires: 120 });
    }

    #[test]
    fn sub_state_display() {
        assert_eq!(SubState::Pending.to_string(), "pending");
        assert_eq!(
            SubState::Active { expires: 600 }.to_string(),
            "active;expires=600"
        );
        assert_eq!(
            SubState::Terminated {
                reason: "timeout".into()
            }
            .to_string(),
            "terminated;reason=timeout"
        );
    }

    #[test]
    fn video_codec_display() {
        assert_eq!(VideoCodec::H264.to_string(), "H264");
        assert_eq!(VideoCodec::VP8.to_string(), "VP8");
    }

    #[test]
    fn video_codec_default_payload_type() {
        assert_eq!(VideoCodec::H264.default_payload_type(), 96);
        assert_eq!(VideoCodec::VP8.default_payload_type(), 97);
    }

    #[test]
    fn video_codec_clock_rate() {
        assert_eq!(VideoCodec::H264.clock_rate(), 90000);
        assert_eq!(VideoCodec::VP8.clock_rate(), 90000);
    }

    #[test]
    fn video_codec_rtpmap_name() {
        assert_eq!(VideoCodec::H264.rtpmap_name(), "H264/90000");
        assert_eq!(VideoCodec::VP8.rtpmap_name(), "VP8/90000");
    }

    #[test]
    fn video_codec_fmtp() {
        assert!(VideoCodec::H264
            .fmtp()
            .unwrap()
            .contains("profile-level-id"));
        assert!(VideoCodec::H264
            .fmtp()
            .unwrap()
            .contains("packetization-mode=1"));
        assert!(VideoCodec::VP8.fmtp().is_none());
    }

    #[test]
    fn video_codec_rtcp_fb() {
        let fb = VideoCodec::H264.rtcp_fb();
        assert!(fb.contains(&"nack"));
        assert!(fb.contains(&"nack pli"));
        assert!(fb.contains(&"ccm fir"));
    }

    #[test]
    fn video_codec_from_rtpmap_name() {
        assert_eq!(
            VideoCodec::from_rtpmap_name("H264/90000"),
            Some(VideoCodec::H264)
        );
        assert_eq!(
            VideoCodec::from_rtpmap_name("VP8/90000"),
            Some(VideoCodec::VP8)
        );
        assert_eq!(
            VideoCodec::from_rtpmap_name("h264/90000"),
            Some(VideoCodec::H264)
        );
        assert_eq!(VideoCodec::from_rtpmap_name("PCMU/8000"), None);
    }

    #[test]
    fn enums_are_copy_clone_eq() {
        let s1 = CallState::Active;
        let s2 = s1;
        assert_eq!(s1, s2);

        let d1 = Direction::Inbound;
        let d2 = d1;
        assert_eq!(d1, d2);
    }
}
