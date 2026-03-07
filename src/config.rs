use std::time::Duration;

use crate::types::Codec;

/// Configuration for a Phone instance.
#[derive(Debug, Clone)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub transport: String,

    pub register_expiry: Duration,
    pub register_retry: Duration,
    pub register_max_retry: u32,

    pub nat_keepalive_interval: Option<Duration>,

    /// Override the local IP advertised in SDP. If empty, auto-detected.
    pub local_ip: String,
    pub rtp_port_min: u16,
    pub rtp_port_max: u16,
    pub codec_prefs: Vec<Codec>,
    pub jitter_buffer: Duration,
    pub media_timeout: Duration,
    pub pcm_frame_size: usize,
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
    pub fn new() -> Self {
        PhoneBuilder {
            config: Config::default(),
        }
    }

    pub fn credentials(mut self, username: &str, password: &str, host: &str) -> Self {
        self.config.username = username.into();
        self.config.password = password.into();
        self.config.host = host.into();
        self
    }

    pub fn transport(mut self, protocol: &str) -> Self {
        self.config.transport = protocol.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn rtp_ports(mut self, min: u16, max: u16) -> Self {
        self.config.rtp_port_min = min;
        self.config.rtp_port_max = max;
        self
    }

    pub fn codecs(mut self, codecs: Vec<Codec>) -> Self {
        self.config.codec_prefs = codecs;
        self
    }

    pub fn jitter_buffer(mut self, d: Duration) -> Self {
        self.config.jitter_buffer = d;
        self
    }

    pub fn media_timeout(mut self, d: Duration) -> Self {
        self.config.media_timeout = d;
        self
    }

    pub fn nat_keepalive(mut self, d: Duration) -> Self {
        self.config.nat_keepalive_interval = Some(d);
        self
    }

    pub fn pcm_rate(mut self, rate: u32) -> Self {
        self.config.pcm_rate = rate;
        self
    }

    pub fn register_expiry(mut self, d: Duration) -> Self {
        self.config.register_expiry = d;
        self
    }

    pub fn register_retry(mut self, d: Duration) -> Self {
        self.config.register_retry = d;
        self
    }

    pub fn register_max_retry(mut self, n: u32) -> Self {
        self.config.register_max_retry = n;
        self
    }

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
#[derive(Debug, Clone)]
pub struct DialOptions {
    pub caller_id: Option<String>,
    pub custom_headers: std::collections::HashMap<String, String>,
    pub early_media: bool,
    pub timeout: Duration,
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
    pub fn new() -> Self {
        DialOptionsBuilder {
            opts: DialOptions::default(),
        }
    }

    pub fn caller_id(mut self, id: &str) -> Self {
        self.opts.caller_id = Some(id.into());
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.opts.custom_headers.insert(name.into(), value.into());
        self
    }

    pub fn early_media(mut self) -> Self {
        self.opts.early_media = true;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.opts.timeout = d;
        self
    }

    pub fn codec_override(mut self, codecs: Vec<Codec>) -> Self {
        self.opts.codec_override = codecs;
        self
    }

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
