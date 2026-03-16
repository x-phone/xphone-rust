pub mod auth;
pub mod client;
pub mod conn;
pub mod dialog;
pub mod message;
pub mod transaction;
pub mod ua;

use std::net::SocketAddr;

/// Resolve a SIP host string to a `SocketAddr`.
///
/// Accepts bare `host:port`, `host` (uses `default_port`), or IP addresses.
/// Strips URI parameters (`;transport=udp`, etc.) before parsing.
/// Falls back to DNS resolution for hostnames.
///
/// Used by both the outbound proxy URI parser and the trunk server's
/// SIP URI address extractor.
pub(crate) fn resolve_host(host: &str, default_port: u16) -> Option<SocketAddr> {
    // Strip URI parameters.
    let host = host.split(';').next().unwrap_or(host);
    // Try as SocketAddr (e.g. "10.0.0.1:5060").
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Try as bare IP (e.g. "10.0.0.1") with default port.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    // Try DNS resolution for hostnames.
    use std::net::ToSocketAddrs;
    let with_port = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:{default_port}")
    };
    with_port.to_socket_addrs().ok()?.next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_host_ip_port() {
        assert_eq!(
            resolve_host("10.0.0.1:5060", 5060),
            Some("10.0.0.1:5060".parse().unwrap())
        );
    }

    #[test]
    fn resolve_host_ip_only() {
        assert_eq!(
            resolve_host("10.0.0.1", 5060),
            Some("10.0.0.1:5060".parse().unwrap())
        );
    }

    #[test]
    fn resolve_host_ip_custom_port() {
        assert_eq!(
            resolve_host("10.0.0.1", 5061),
            Some("10.0.0.1:5061".parse().unwrap())
        );
    }

    #[test]
    fn resolve_host_with_params() {
        assert_eq!(
            resolve_host("10.0.0.1:5060;transport=udp", 5060),
            Some("10.0.0.1:5060".parse().unwrap())
        );
    }

    #[test]
    fn resolve_host_localhost() {
        let result = resolve_host("localhost", 5060);
        assert!(result.is_some());
        assert_eq!(result.unwrap().port(), 5060);
    }

    #[test]
    fn resolve_host_empty() {
        assert!(resolve_host("", 5060).is_none());
    }

    #[test]
    fn resolve_host_nonsense() {
        assert!(resolve_host("not a valid host!!!", 5060).is_none());
    }
}
