use std::net::IpAddr;

/// Configuration for the SIP trunk host server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to listen on (e.g., `"0.0.0.0:5080"`).
    pub listen: String,
    /// Configured peers that are allowed to connect.
    pub peers: Vec<PeerConfig>,
    /// Minimum RTP port for media allocation. 0 = OS-assigned.
    pub rtp_port_min: u16,
    /// Maximum RTP port for media allocation. 0 = OS-assigned.
    pub rtp_port_max: u16,
    /// IP address advertised in SDP for RTP media. When the server listens on
    /// `0.0.0.0`, this must be set to the reachable IP (e.g. a container IP).
    pub rtp_address: Option<IpAddr>,
    /// Append `;rport` (RFC 3581) to outgoing Via headers. Trunk servers are
    /// UDP-only by construction, so unlike [`Config::nat`](crate::Config::nat)
    /// this flag is not gated on transport. Opt-in; default `false`.
    pub nat: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:5080".into(),
            peers: Vec::new(),
            rtp_port_min: 0,
            rtp_port_max: 0,
            rtp_address: None,
            nat: false,
        }
    }
}

/// A known SIP peer (PBX system or trunk provider) that can send/receive calls.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Human-readable name for this peer (e.g., `"office-pbx"`).
    pub name: String,
    /// Single IP address for IP-based authentication (simple case).
    pub host: Option<IpAddr>,
    /// Multiple IPs or CIDR ranges for IP-based authentication.
    /// Supports exact IPs (`"54.172.60.1"`) and CIDRs (`"54.172.60.0/22"`).
    pub hosts: Vec<String>,
    /// SIP port for outbound calls to this peer. Defaults to 5060.
    pub port: u16,
    /// Digest authentication credentials. If set, INVITEs are challenged with 401.
    pub auth: Option<PeerAuthConfig>,
    /// Allowed codecs (e.g., `["ulaw", "alaw"]`). Empty means accept any.
    pub codecs: Vec<String>,
    /// Per-peer RTP address override. If set, SDP for calls from this peer
    /// uses this address instead of the server-level `rtp_address`.
    pub rtp_address: Option<IpAddr>,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: None,
            hosts: Vec::new(),
            port: 5060,
            auth: None,
            codecs: Vec::new(),
            rtp_address: None,
        }
    }
}

impl PeerConfig {
    /// Returns true if this peer has at least one auth method configured.
    pub fn has_auth(&self) -> bool {
        self.host.is_some() || !self.hosts.is_empty() || self.auth.is_some()
    }

    /// Returns true if the given IP matches this peer's `host` or any entry in `hosts`.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        if self.host == Some(ip) {
            return true;
        }
        self.hosts.iter().any(|entry| cidr_matches(entry, ip))
    }
}

/// Digest auth credentials for a peer.
#[derive(Debug, Clone)]
pub struct PeerAuthConfig {
    pub username: String,
    pub password: String,
    /// Cached HA1 = MD5(username:xphone:password), lazily computed on first use.
    ha1_cache: std::sync::OnceLock<String>,
}

impl PeerAuthConfig {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            ha1_cache: std::sync::OnceLock::new(),
        }
    }

    /// Returns pre-computed HA1 = MD5(username:xphone:password).
    pub(crate) fn ha1(&self) -> &str {
        self.ha1_cache.get_or_init(|| {
            let input = format!("{}:xphone:{}", self.username, self.password);
            super::auth::md5_hex(&input)
        })
    }
}

/// Check if an IP matches a CIDR string (`"10.0.0.0/8"`) or exact IP string (`"10.0.0.1"`).
fn cidr_matches(entry: &str, ip: IpAddr) -> bool {
    if let Some((net_str, prefix_str)) = entry.split_once('/') {
        let Ok(net_ip) = net_str.parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix_len) = prefix_str.parse::<u32>() else {
            return false;
        };
        match (net_ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if prefix_len > 32 {
                    return false;
                }
                if prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix_len);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if prefix_len > 128 {
                    return false;
                }
                if prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - prefix_len);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    } else {
        entry.parse::<IpAddr>().ok() == Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn peer_has_auth_ip_only() {
        let peer = PeerConfig {
            name: "test".into(),
            host: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ..Default::default()
        };
        assert!(peer.has_auth());
    }

    #[test]
    fn peer_has_auth_digest_only() {
        let peer = PeerConfig {
            name: "test".into(),
            auth: Some(PeerAuthConfig::new("user", "pass")),
            ..Default::default()
        };
        assert!(peer.has_auth());
    }

    #[test]
    fn peer_has_auth_hosts() {
        let peer = PeerConfig {
            name: "test".into(),
            hosts: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        assert!(peer.has_auth());
    }

    #[test]
    fn peer_has_auth_none() {
        let peer = PeerConfig {
            name: "test".into(),
            ..Default::default()
        };
        assert!(!peer.has_auth());
    }

    #[test]
    fn matches_ip_host() {
        let peer = PeerConfig {
            name: "test".into(),
            host: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            ..Default::default()
        };
        assert!(peer.matches_ip(Ipv4Addr::new(192, 168, 1, 10).into()));
        assert!(!peer.matches_ip(Ipv4Addr::new(192, 168, 1, 11).into()));
    }

    #[test]
    fn matches_ip_cidr() {
        let peer = PeerConfig {
            name: "test".into(),
            hosts: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        assert!(peer.matches_ip(Ipv4Addr::new(10, 255, 255, 255).into()));
        assert!(!peer.matches_ip(Ipv4Addr::new(11, 0, 0, 1).into()));
    }

    #[test]
    fn matches_ip_exact_string() {
        let peer = PeerConfig {
            name: "test".into(),
            hosts: vec!["192.168.1.100".into()],
            ..Default::default()
        };
        assert!(peer.matches_ip(Ipv4Addr::new(192, 168, 1, 100).into()));
        assert!(!peer.matches_ip(Ipv4Addr::new(192, 168, 1, 101).into()));
    }

    #[test]
    fn cidr_matches_v4() {
        assert!(cidr_matches(
            "10.0.0.0/8",
            Ipv4Addr::new(10, 1, 2, 3).into()
        ));
        assert!(!cidr_matches(
            "10.0.0.0/8",
            Ipv4Addr::new(11, 0, 0, 1).into()
        ));
        assert!(cidr_matches(
            "192.168.1.0/24",
            Ipv4Addr::new(192, 168, 1, 100).into()
        ));
        assert!(!cidr_matches(
            "192.168.1.0/24",
            Ipv4Addr::new(192, 168, 2, 1).into()
        ));
    }

    #[test]
    fn cidr_matches_v6() {
        assert!(cidr_matches(
            "fe80::/10",
            "fe80::1".parse::<IpAddr>().unwrap()
        ));
        assert!(!cidr_matches(
            "fe80::/10",
            "2001:db8::1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn cidr_matches_prefix_zero() {
        // /0 matches everything.
        assert!(cidr_matches("0.0.0.0/0", Ipv4Addr::new(1, 2, 3, 4).into()));
    }

    #[test]
    fn cidr_matches_prefix_32() {
        // /32 = exact match.
        assert!(cidr_matches(
            "10.0.0.1/32",
            Ipv4Addr::new(10, 0, 0, 1).into()
        ));
        assert!(!cidr_matches(
            "10.0.0.1/32",
            Ipv4Addr::new(10, 0, 0, 2).into()
        ));
    }

    #[test]
    fn cidr_matches_invalid() {
        assert!(!cidr_matches(
            "invalid/24",
            Ipv4Addr::new(10, 0, 0, 1).into()
        ));
        assert!(!cidr_matches(
            "10.0.0.0/abc",
            Ipv4Addr::new(10, 0, 0, 1).into()
        ));
        assert!(!cidr_matches(
            "10.0.0.0/33",
            Ipv4Addr::new(10, 0, 0, 1).into()
        ));
    }

    #[test]
    fn ha1_precomputed() {
        let cred = PeerAuthConfig::new("user", "pass");
        let expected = super::super::auth::md5_hex("user:xphone:pass");
        assert_eq!(cred.ha1(), expected);
        // Second call returns same cached value.
        assert_eq!(cred.ha1(), expected);
    }
}
