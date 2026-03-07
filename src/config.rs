use std::time::Duration;

use crate::sip::conn::TlsConfig;
use crate::types::Codec;

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
        }
    }
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

    /// Sets the RTP port range.
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
}

impl Default for DialOptions {
    fn default() -> Self {
        DialOptions {
            caller_id: None,
            custom_headers: std::collections::HashMap::new(),
            early_media: false,
            timeout: Duration::from_secs(30),
            codec_override: Vec::new(),
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
}
