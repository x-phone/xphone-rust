use std::time::Duration;

use crate::sip::conn::TlsConfig;
use crate::types::{Codec, VideoCodec};

/// Selects how DTMF digits are sent and received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtmfMode {
    /// RFC 4733 RTP telephone-event packets (default).
    Rfc4733,
    /// SIP INFO with `application/dtmf-relay` body (RFC 2976).
    SipInfo,
    /// Send via RFC 4733; also accept incoming SIP INFO.
    Both,
}

/// Configuration for a [`Phone`](crate::phone::Phone) instance.
///
/// Use [`PhoneBuilder`] for ergonomic construction with defaults.
#[derive(Debug, Clone)]
pub struct Config {
    /// SIP username / extension.
    pub username: String,
    /// SIP password for digest authentication.
    pub password: String,
    /// SIP server hostname or IP address.
    pub host: String,
    /// SIP server port (default `5060`).
    pub port: u16,
    /// Transport protocol: `"udp"`, `"tcp"`, or `"tls"`.
    pub transport: String,
    /// TLS configuration. Required when `transport` is `"tls"`.
    pub tls_config: Option<TlsConfig>,

    /// REGISTER expiry duration advertised to the server.
    pub register_expiry: Duration,
    /// Delay between registration retry attempts.
    pub register_retry: Duration,
    /// Maximum number of consecutive registration retries.
    pub register_max_retry: u32,

    /// Interval for NAT keep-alive packets. `None` disables keep-alive.
    pub nat_keepalive_interval: Option<Duration>,

    /// Override the local IP advertised in SDP/Via/Contact.
    /// If empty, the address is auto-detected.
    pub local_ip: String,
    /// Minimum port in the RTP port range (0 = OS-assigned).
    ///
    /// Each concurrent call requires one RTP port (even-numbered). The maximum
    /// number of concurrent calls is `(rtp_port_max - rtp_port_min) / 2`.
    ///
    /// **Production recommendation:** `10000–20000` (5,000 concurrent calls).
    /// The default (0) lets the OS assign ports, which works for development
    /// but gives no control over firewall rules or concurrency limits.
    pub rtp_port_min: u16,
    /// Maximum port in the RTP port range (0 = OS-assigned).
    pub rtp_port_max: u16,
    /// Preferred codecs in priority order.
    pub codec_prefs: Vec<Codec>,
    /// Jitter buffer depth for inbound RTP.
    pub jitter_buffer: Duration,
    /// Duration of RTP silence before a media timeout is raised.
    pub media_timeout: Duration,
    /// PCM frame size in samples. 0 uses the codec default.
    pub pcm_frame_size: usize,
    /// PCM sample rate in Hz (default `8000`).
    pub pcm_rate: u32,
    /// Enable SRTP (SDES-SRTP with AES_CM_128_HMAC_SHA1_80).
    pub srtp: bool,
    /// STUN server address (e.g. `"stun.l.google.com:19302"`).
    /// When set, a STUN Binding Request is used to discover the
    /// NAT-mapped address for SIP and RTP instead of the local-IP heuristic.
    pub stun_server: Option<String>,
    /// DTMF transport mode (default: RFC 4733 RTP telephone-events).
    pub dtmf_mode: DtmfMode,
    /// Voicemail server URI for MWI SUBSCRIBE (RFC 3842).
    /// When set, the phone subscribes to `message-summary` events after registration.
    /// Example: `"sip:*97@pbx.local"` or left empty to default to user's AOR.
    pub voicemail_uri: Option<String>,
    /// TURN server address (e.g. `"turn.example.com:3478"`).
    /// When set, a TURN relay is allocated for media NAT traversal.
    pub turn_server: Option<String>,
    /// TURN username for long-term credentials.
    pub turn_username: Option<String>,
    /// TURN password for long-term credentials.
    pub turn_password: Option<String>,
    /// Enable ICE-Lite candidate gathering and STUN responder.
    /// Requires `stun_server` and/or `turn_server` to produce useful candidates.
    pub ice: bool,

    /// Outbound proxy URI for routing INVITEs (e.g. `"sip:proxy.example.com:5060"`).
    /// When set, outbound INVITEs are sent to this proxy instead of the registrar.
    /// Registration traffic still goes to `host:port`.
    pub outbound_proxy: Option<String>,
    /// Username for outbound INVITE authentication. Falls back to `username` if unset.
    pub outbound_username: Option<String>,
    /// Password for outbound INVITE authentication. Falls back to `password` if unset.
    pub outbound_password: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            username: String::new(),
            password: String::new(),
            host: String::new(),
            port: 5060,
            transport: "udp".into(),
            tls_config: None,
            register_expiry: Duration::from_secs(60),
            register_retry: Duration::from_secs(1),
            register_max_retry: 3,
            nat_keepalive_interval: None,
            local_ip: String::new(),
            rtp_port_min: 0,
            rtp_port_max: 0,
            codec_prefs: Vec::new(),
            jitter_buffer: Duration::from_millis(50),
            media_timeout: Duration::from_secs(30),
            pcm_frame_size: 0,
            pcm_rate: 8000,
            srtp: false,
            stun_server: None,
            dtmf_mode: DtmfMode::Rfc4733,
            voicemail_uri: None,
            turn_server: None,
            turn_username: None,
            turn_password: None,
            ice: false,
            outbound_proxy: None,
            outbound_username: None,
            outbound_password: None,
        }
    }
}

impl Config {
    /// Extracts an embedded port from `host` (e.g. `"10.0.0.1:5060"`) into
    /// the separate `port` field. Only applies if `port` is still at the
    /// default value (5060) — an explicit `.port()` call takes precedence.
    ///
    /// Called once from [`Phone::new()`](crate::phone::Phone::new).
    pub(crate) fn normalize_host(&mut self) {
        if self.host.is_empty() {
            return;
        }
        if let Some((host, port)) = split_host_port(&self.host) {
            // Only apply embedded port if port hasn't been explicitly set.
            if self.port == 5060 {
                self.port = port;
            }
            self.host = host.to_string();
        }
    }
}

/// Split a `host:port` string. Returns `None` if no port is present.
/// Handles `[::1]:5060` (IPv6 bracket notation) and `10.0.0.1:5060`.
fn split_host_port(s: &str) -> Option<(&str, u16)> {
    // IPv6 bracket notation: [::1]:5060
    if let Some(bracket_end) = s.find(']') {
        let after = &s[bracket_end + 1..];
        if let Some(port_str) = after.strip_prefix(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((&s[..bracket_end + 1], port));
            }
        }
        return None;
    }
    // Only split on the last colon, and only if there's exactly one
    // (multiple colons without brackets = bare IPv6, don't split).
    if s.matches(':').count() == 1 {
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host, port));
            }
        }
    }
    None
}

/// Builder for constructing a [`Config`] using chained method calls.
pub struct PhoneBuilder {
    config: Config,
}

impl PhoneBuilder {
    /// Creates a new builder with default configuration values.
    pub fn new() -> Self {
        PhoneBuilder {
            config: Config::default(),
        }
    }

    /// Sets SIP username, password, and server host.
    ///
    /// The `host` parameter accepts `"hostname"`, `"hostname:port"`, or
    /// `"ip:port"` formats. If a port is embedded, it is extracted and
    /// applied when the `Config` is consumed by [`Phone::new()`](crate::phone::Phone::new).
    /// An explicit [`.port()`](Self::port) call always takes precedence.
    pub fn credentials(mut self, username: &str, password: &str, host: &str) -> Self {
        self.config.username = username.into();
        self.config.password = password.into();
        self.config.host = host.into();
        self
    }

    /// Sets the transport protocol (`"udp"`, `"tcp"`, or `"tls"`).
    pub fn transport(mut self, protocol: &str) -> Self {
        self.config.transport = protocol.into();
        self
    }

    /// Sets TLS configuration. Required when transport is `"tls"`.
    pub fn tls_config(mut self, tls: TlsConfig) -> Self {
        self.config.tls_config = Some(tls);
        self
    }

    /// Sets the SIP server port.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Sets the RTP port range for media sockets.
    ///
    /// Each concurrent call needs one even-numbered RTP port.
    /// Max concurrent calls = `(max - min) / 2`.
    ///
    /// ```rust
    /// # use xphone::PhoneBuilder;
    /// let cfg = PhoneBuilder::new()
    ///     .credentials("alice", "secret", "sip.example.com")
    ///     .rtp_ports(10000, 20000) // 5,000 concurrent calls
    ///     .build();
    /// ```
    pub fn rtp_ports(mut self, min: u16, max: u16) -> Self {
        self.config.rtp_port_min = min;
        self.config.rtp_port_max = max;
        self
    }

    /// Sets the preferred codec list in priority order.
    pub fn codecs(mut self, codecs: Vec<Codec>) -> Self {
        self.config.codec_prefs = codecs;
        self
    }

    /// Sets the jitter buffer depth for inbound RTP.
    pub fn jitter_buffer(mut self, d: Duration) -> Self {
        self.config.jitter_buffer = d;
        self
    }

    /// Sets the media timeout duration.
    pub fn media_timeout(mut self, d: Duration) -> Self {
        self.config.media_timeout = d;
        self
    }

    /// Enables NAT keep-alive with the given interval.
    pub fn nat_keepalive(mut self, d: Duration) -> Self {
        self.config.nat_keepalive_interval = Some(d);
        self
    }

    /// Sets the PCM sample rate in Hz.
    pub fn pcm_rate(mut self, rate: u32) -> Self {
        self.config.pcm_rate = rate;
        self
    }

    /// Sets the REGISTER expiry duration.
    pub fn register_expiry(mut self, d: Duration) -> Self {
        self.config.register_expiry = d;
        self
    }

    /// Sets the delay between registration retry attempts.
    pub fn register_retry(mut self, d: Duration) -> Self {
        self.config.register_retry = d;
        self
    }

    /// Sets the maximum number of registration retries.
    pub fn register_max_retry(mut self, n: u32) -> Self {
        self.config.register_max_retry = n;
        self
    }

    /// Enables SRTP (SDES-SRTP with AES_CM_128_HMAC_SHA1_80).
    pub fn srtp(mut self, enabled: bool) -> Self {
        self.config.srtp = enabled;
        self
    }

    /// Sets the STUN server for NAT-mapped address discovery.
    pub fn stun_server(mut self, server: &str) -> Self {
        self.config.stun_server = Some(server.into());
        self
    }

    /// Sets the DTMF transport mode.
    pub fn dtmf_mode(mut self, mode: DtmfMode) -> Self {
        self.config.dtmf_mode = mode;
        self
    }

    /// Sets the voicemail server URI for MWI SUBSCRIBE (RFC 3842).
    pub fn voicemail_uri(mut self, uri: &str) -> Self {
        self.config.voicemail_uri = Some(uri.into());
        self
    }

    /// Sets the TURN server for NAT relay allocation.
    pub fn turn_server(mut self, server: &str) -> Self {
        self.config.turn_server = Some(server.into());
        self
    }

    /// Sets TURN long-term credentials.
    pub fn turn_credentials(mut self, username: &str, password: &str) -> Self {
        self.config.turn_username = Some(username.into());
        self.config.turn_password = Some(password.into());
        self
    }

    /// Enables ICE-Lite candidate gathering and STUN responder.
    pub fn ice(mut self, enabled: bool) -> Self {
        self.config.ice = enabled;
        self
    }

    /// Sets an outbound proxy for routing INVITEs (e.g. `"sip:proxy.example.com:5060"`).
    /// Registration traffic still goes to the configured host.
    pub fn outbound_proxy(mut self, proxy: &str) -> Self {
        self.config.outbound_proxy = Some(proxy.into());
        self
    }

    /// Sets separate credentials for outbound INVITE authentication.
    /// Falls back to the main credentials if unset.
    pub fn outbound_credentials(mut self, username: &str, password: &str) -> Self {
        self.config.outbound_username = Some(username.into());
        self.config.outbound_password = Some(password.into());
        self
    }

    /// Consumes the builder and returns the finished [`Config`].
    pub fn build(self) -> Config {
        self.config
    }
}

impl Default for PhoneBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for an outbound call.
///
/// Use [`DialOptionsBuilder`] for ergonomic construction with defaults.
#[derive(Debug, Clone)]
pub struct DialOptions {
    /// Caller-ID string to place in the From header. `None` uses the default.
    pub caller_id: Option<String>,
    /// Extra SIP headers to include in the INVITE.
    pub custom_headers: std::collections::HashMap<String, String>,
    /// Whether to accept early media (183 Session Progress).
    pub early_media: bool,
    /// Maximum time to wait for the callee to answer.
    pub timeout: Duration,
    /// Codec list that overrides the phone-level preferences for this call.
    pub codec_override: Vec<Codec>,
    /// Enable video in the SDP offer.
    pub video: bool,
    /// Video codecs in preference order. Defaults to `[H264, VP8]` when
    /// `video` is enabled. Only used when `video` is `true`.
    pub video_codecs: Vec<VideoCodec>,
}

impl Default for DialOptions {
    fn default() -> Self {
        DialOptions {
            caller_id: None,
            custom_headers: std::collections::HashMap::new(),
            early_media: false,
            timeout: Duration::from_secs(30),
            codec_override: Vec::new(),
            video: false,
            video_codecs: Vec::new(),
        }
    }
}

/// Builder for constructing [`DialOptions`].
pub struct DialOptionsBuilder {
    opts: DialOptions,
}

impl DialOptionsBuilder {
    /// Creates a new builder with default dial options.
    pub fn new() -> Self {
        DialOptionsBuilder {
            opts: DialOptions::default(),
        }
    }

    /// Sets the caller-ID string for the From header.
    pub fn caller_id(mut self, id: &str) -> Self {
        self.opts.caller_id = Some(id.into());
        self
    }

    /// Adds a custom SIP header to the INVITE.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.opts.custom_headers.insert(name.into(), value.into());
        self
    }

    /// Enables early media (183 Session Progress).
    pub fn early_media(mut self) -> Self {
        self.opts.early_media = true;
        self
    }

    /// Sets the dial timeout.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.opts.timeout = d;
        self
    }

    /// Overrides the phone-level codec preferences for this call.
    pub fn codec_override(mut self, codecs: Vec<Codec>) -> Self {
        self.opts.codec_override = codecs;
        self
    }

    /// Enables video in the SDP offer. Also sets default video codecs
    /// `[H264, VP8]` if none were explicitly set.
    pub fn video(mut self) -> Self {
        self.opts.video = true;
        if self.opts.video_codecs.is_empty() {
            self.opts.video_codecs = vec![VideoCodec::H264, VideoCodec::VP8];
        }
        self
    }

    /// Sets the preferred video codecs (default: `[H264, VP8]`).
    pub fn video_codecs(mut self, codecs: Vec<VideoCodec>) -> Self {
        self.opts.video_codecs = codecs;
        self
    }

    /// Consumes the builder and returns the finished [`DialOptions`].
    pub fn build(self) -> DialOptions {
        self.opts
    }
}

impl Default for DialOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── host:port parsing ──

    #[test]
    fn normalize_splits_host_port() {
        let mut cfg = Config {
            host: "10.0.0.7:5061".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "10.0.0.7");
        assert_eq!(cfg.port, 5061);
    }

    #[test]
    fn normalize_host_only() {
        let mut cfg = Config {
            host: "10.0.0.7".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "10.0.0.7");
        assert_eq!(cfg.port, 5060); // default
    }

    #[test]
    fn normalize_hostname_with_port() {
        let mut cfg = Config {
            host: "sip.example.com:5080".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "sip.example.com");
        assert_eq!(cfg.port, 5080);
    }

    #[test]
    fn normalize_ipv6_bracket_with_port() {
        let mut cfg = Config {
            host: "[::1]:5060".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "[::1]");
        assert_eq!(cfg.port, 5060);
    }

    #[test]
    fn normalize_bare_ipv6_no_split() {
        let mut cfg = Config {
            host: "::1".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 5060);
    }

    #[test]
    fn normalize_host_direct_config() {
        let mut cfg = Config {
            host: "10.0.0.7:5061".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        assert_eq!(cfg.host, "10.0.0.7");
        assert_eq!(cfg.port, 5061);
    }

    #[test]
    fn normalize_host_invalid_port_ignored() {
        let mut cfg = Config {
            host: "10.0.0.7:notaport".into(),
            ..Config::default()
        };
        cfg.normalize_host();
        // Invalid port — host unchanged.
        assert_eq!(cfg.host, "10.0.0.7:notaport");
        assert_eq!(cfg.port, 5060);
    }

    #[test]
    fn builder_explicit_port_wins_over_default() {
        // If .port() is called after .credentials(), it should take precedence.
        let cfg = PhoneBuilder::new()
            .credentials("1001", "secret", "10.0.0.7")
            .port(5061)
            .build();
        assert_eq!(cfg.host, "10.0.0.7");
        assert_eq!(cfg.port, 5061);
    }

    #[test]
    fn explicit_port_wins_over_embedded() {
        // Explicit .port() takes precedence over embedded port in host.
        let mut cfg = PhoneBuilder::new()
            .credentials("1001", "secret", "10.0.0.7:5080")
            .port(9999)
            .build();
        cfg.normalize_host();
        assert_eq!(cfg.host, "10.0.0.7"); // host part still stripped
        assert_eq!(cfg.port, 9999); // explicit port preserved
    }

    // ── existing tests ──

    #[test]
    fn config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.transport, "udp");
        assert_eq!(cfg.port, 5060);
        assert_eq!(cfg.register_expiry, Duration::from_secs(60));
        assert_eq!(cfg.register_retry, Duration::from_secs(1));
        assert_eq!(cfg.register_max_retry, 3);
        assert_eq!(cfg.media_timeout, Duration::from_secs(30));
        assert_eq!(cfg.jitter_buffer, Duration::from_millis(50));
        assert_eq!(cfg.pcm_rate, 8000);
    }

    #[test]
    fn phone_builder() {
        let cfg = PhoneBuilder::new()
            .credentials("alice", "secret", "sip.example.com")
            .transport("tcp")
            .port(5061)
            .rtp_ports(10000, 20000)
            .codecs(vec![Codec::PCMU, Codec::PCMA])
            .jitter_buffer(Duration::from_millis(100))
            .media_timeout(Duration::from_secs(60))
            .nat_keepalive(Duration::from_secs(30))
            .pcm_rate(16000)
            .build();

        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.password, "secret");
        assert_eq!(cfg.host, "sip.example.com");
        assert_eq!(cfg.transport, "tcp");
        assert_eq!(cfg.port, 5061);
        assert_eq!(cfg.rtp_port_min, 10000);
        assert_eq!(cfg.rtp_port_max, 20000);
        assert_eq!(cfg.codec_prefs, vec![Codec::PCMU, Codec::PCMA]);
        assert_eq!(cfg.jitter_buffer, Duration::from_millis(100));
        assert_eq!(cfg.media_timeout, Duration::from_secs(60));
        assert_eq!(cfg.nat_keepalive_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.pcm_rate, 16000);
    }

    #[test]
    fn dial_options_defaults() {
        let opts = DialOptions::default();
        assert_eq!(opts.timeout, Duration::from_secs(30));
        assert!(!opts.early_media);
        assert!(opts.caller_id.is_none());
        assert!(opts.custom_headers.is_empty());
        assert!(opts.codec_override.is_empty());
    }

    #[test]
    fn dtmf_mode_default_is_rfc4733() {
        let cfg = Config::default();
        assert_eq!(cfg.dtmf_mode, DtmfMode::Rfc4733);
    }

    #[test]
    fn phone_builder_dtmf_mode() {
        let cfg = PhoneBuilder::new()
            .credentials("alice", "secret", "sip.example.com")
            .dtmf_mode(DtmfMode::SipInfo)
            .build();
        assert_eq!(cfg.dtmf_mode, DtmfMode::SipInfo);

        let cfg2 = PhoneBuilder::new()
            .credentials("alice", "secret", "sip.example.com")
            .dtmf_mode(DtmfMode::Both)
            .build();
        assert_eq!(cfg2.dtmf_mode, DtmfMode::Both);
    }

    #[test]
    fn dial_options_builder() {
        let opts = DialOptionsBuilder::new()
            .caller_id("Bob")
            .header("X-Custom", "value")
            .early_media()
            .timeout(Duration::from_secs(60))
            .codec_override(vec![Codec::G722])
            .build();

        assert_eq!(opts.caller_id, Some("Bob".into()));
        assert_eq!(opts.custom_headers.get("X-Custom"), Some(&"value".into()));
        assert!(opts.early_media);
        assert_eq!(opts.timeout, Duration::from_secs(60));
        assert_eq!(opts.codec_override, vec![Codec::G722]);
    }

    #[test]
    fn dial_options_video_default_off() {
        let opts = DialOptions::default();
        assert!(!opts.video);
        assert!(opts.video_codecs.is_empty());
    }

    #[test]
    fn dial_options_builder_video() {
        let opts = DialOptionsBuilder::new()
            .video()
            .video_codecs(vec![VideoCodec::H264, VideoCodec::VP8])
            .build();
        assert!(opts.video);
        assert_eq!(opts.video_codecs, vec![VideoCodec::H264, VideoCodec::VP8]);
    }

    #[test]
    fn dial_options_builder_video_default_codecs() {
        // .video() without .video_codecs() should default to [H264, VP8].
        let opts = DialOptionsBuilder::new().video().build();
        assert!(opts.video);
        assert_eq!(opts.video_codecs, vec![VideoCodec::H264, VideoCodec::VP8]);
    }

    #[test]
    fn dial_options_builder_video_h264_only() {
        // Explicit .video_codecs() before .video() is preserved.
        let opts = DialOptionsBuilder::new()
            .video_codecs(vec![VideoCodec::H264])
            .video()
            .build();
        assert!(opts.video);
        assert_eq!(opts.video_codecs, vec![VideoCodec::H264]);
    }
}
