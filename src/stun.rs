//! STUN Binding client (RFC 5389).
//!
//! Sends a STUN Binding Request to a public STUN server and parses the
//! response to discover the NAT-mapped (server-reflexive) address.
//! Only the bare minimum of RFC 5389 is implemented — no authentication,
//! no FINGERPRINT, no long-term credentials. This covers the common case
//! of discovering a mapped address for SIP/RTP NAT traversal.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::error::{Error, Result};

// STUN message types (RFC 5389 §6).
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

// Magic cookie (RFC 5389 §6).
const MAGIC_COOKIE: u32 = 0x2112_A442;

// STUN header size.
const HEADER_SIZE: usize = 20;

// Attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// Address families.
const FAMILY_IPV4: u8 = 0x01;

/// Default STUN server (Google's public STUN server).
pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

/// Sends a STUN Binding Request from `socket` to `stun_server` and returns
/// the server-reflexive (NAT-mapped) address.
///
/// The socket is not consumed — it can be used for SIP/RTP traffic afterward.
/// This is a blocking call with `timeout` applied via `set_read_timeout`.
pub fn stun_mapped_address(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {
    let txn_id = generate_txn_id();
    let request = build_binding_request(&txn_id);

    socket
        .send_to(&request, stun_server)
        .map_err(|e| Error::Other(format!("stun: send: {}", e)))?;

    // Save and restore the original read timeout.
    let orig_timeout = socket.read_timeout().unwrap_or(None);
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::Other(format!("stun: set timeout: {}", e)))?;

    let mut buf = [0u8; 576]; // RFC 5389 §7.1: responses fit in 576 bytes
    let result = socket.recv_from(&mut buf);

    // Restore original timeout.
    let _ = socket.set_read_timeout(orig_timeout);

    let (n, from) = result.map_err(|e| Error::Other(format!("stun: recv: {}", e)))?;

    // Validate source address (RFC 5389 §7.3.1).
    if from.ip() != stun_server.ip() {
        return Err(Error::Other(format!(
            "stun: response from unexpected source: {} (expected {})",
            from, stun_server
        )));
    }

    parse_binding_response(&buf[..n], &txn_id)
}

/// Resolves a STUN server address string (host:port) to a `SocketAddr`.
/// Prefers IPv4 addresses to match the typical `0.0.0.0` SIP/RTP bind.
pub fn resolve_stun_server(server: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = server
        .to_socket_addrs()
        .map_err(|e| Error::Other(format!("stun: resolve {}: {}", server, e)))?
        .collect();

    // Prefer IPv4.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| Error::Other(format!("stun: no addresses for {}", server)))
}

// ─── Internal ────────────────────────────────────────────────────────────

fn generate_txn_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    getrandom::getrandom(&mut id).expect("getrandom failed");
    id
}

fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);

    // Message type: Binding Request
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    buf.extend_from_slice(txn_id);

    buf
}

fn parse_binding_response(data: &[u8], expected_txn_id: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < HEADER_SIZE {
        return Err(Error::Other("stun: response too short".into()));
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(Error::Other(format!(
            "stun: unexpected message type: 0x{:04x}",
            msg_type
        )));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(Error::Other("stun: bad magic cookie".into()));
    }

    // Verify transaction ID.
    if data[8..20] != expected_txn_id[..] {
        return Err(Error::Other("stun: transaction ID mismatch".into()));
    }

    if data.len() < HEADER_SIZE + msg_len {
        return Err(Error::Other("stun: truncated response".into()));
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS.
    let attrs = &data[HEADER_SIZE..HEADER_SIZE + msg_len];
    let mut mapped: Option<SocketAddr> = None;

    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let attr_start = offset + 4;

        if attr_start + attr_len > attrs.len() {
            return Err(Error::Other("stun: truncated attribute".into()));
        }

        let attr_data = &attrs[attr_start..attr_start + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                // XOR-MAPPED-ADDRESS is preferred — return immediately.
                return parse_xor_mapped_address(attr_data);
            }
            ATTR_MAPPED_ADDRESS => {
                // Fall back to MAPPED-ADDRESS if no XOR variant found.
                if let Ok(addr) = parse_mapped_address(attr_data) {
                    mapped = Some(addr);
                }
            }
            t if t < 0x8000 => {
                // Unknown comprehension-required attribute (RFC 5389 §15).
                return Err(Error::Other(format!(
                    "stun: unknown comprehension-required attribute: 0x{:04x}",
                    t
                )));
            }
            _ => {} // Skip comprehension-optional attributes.
        }

        // Attributes are padded to 4-byte boundaries (RFC 5389 §15).
        let padded_len = (attr_len + 3) & !3;
        offset = attr_start + padded_len;
    }

    mapped.ok_or_else(|| Error::Other("stun: no mapped address in response".into()))
}

fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    // Format: 1 byte reserved, 1 byte family, 2 bytes port, 4/16 bytes address
    if data.len() < 8 {
        return Err(Error::Other("stun: XOR-MAPPED-ADDRESS too short".into()));
    }

    let family = data[1];
    if family != FAMILY_IPV4 {
        return Err(Error::Other(format!(
            "stun: unsupported address family: {}",
            family
        )));
    }

    // Port is XOR'd with top 16 bits of magic cookie.
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    // IPv4 address is XOR'd with the magic cookie.
    let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ip = xor_ip ^ MAGIC_COOKIE;
    let addr = std::net::Ipv4Addr::from(ip);

    Ok(SocketAddr::new(std::net::IpAddr::V4(addr), port))
}

fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(Error::Other("stun: MAPPED-ADDRESS too short".into()));
    }

    let family = data[1];
    if family != FAMILY_IPV4 {
        return Err(Error::Other(format!(
            "stun: unsupported address family: {}",
            family
        )));
    }

    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);

    Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_format() {
        let txn_id = [1u8; 12];
        let req = build_binding_request(&txn_id);

        assert_eq!(req.len(), HEADER_SIZE);
        // Binding Request
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        // Length = 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        // Transaction ID
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // Build a synthetic Binding Response with XOR-MAPPED-ADDRESS.
        let txn_id = [0xAA; 12];
        let mapped_ip: u32 = u32::from(std::net::Ipv4Addr::new(203, 0, 113, 42));
        let mapped_port: u16 = 12345;

        let xor_port = mapped_port ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = mapped_ip ^ MAGIC_COOKIE;

        // Attribute: XOR-MAPPED-ADDRESS
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes()); // type
        attr.extend_from_slice(&8u16.to_be_bytes()); // length
        attr.push(0x00); // reserved
        attr.push(FAMILY_IPV4); // family
        attr.extend_from_slice(&xor_port.to_be_bytes());
        attr.extend_from_slice(&xor_ip.to_be_bytes());

        // Full response
        let msg_len = attr.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attr);

        let addr = parse_binding_response(&resp, &txn_id).unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(203, 0, 113, 42));
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn parse_mapped_address_fallback() {
        // Response with only MAPPED-ADDRESS (no XOR variant).
        let txn_id = [0xBB; 12];

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00); // reserved
        attr.push(FAMILY_IPV4);
        attr.extend_from_slice(&54321u16.to_be_bytes());
        attr.extend_from_slice(&std::net::Ipv4Addr::new(198, 51, 100, 7).octets());

        let msg_len = attr.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attr);

        let addr = parse_binding_response(&resp, &txn_id).unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(addr.port(), 54321);
    }

    #[test]
    fn reject_wrong_txn_id() {
        let txn_id = [0xCC; 12];
        let wrong_id = [0xDD; 12];

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&wrong_id);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(err.to_string().contains("transaction ID mismatch"));
    }

    #[test]
    fn reject_wrong_message_type() {
        let txn_id = [0xEE; 12];

        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0111u16.to_be_bytes()); // Binding Error Response
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(err.to_string().contains("unexpected message type"));
    }

    #[test]
    fn reject_truncated_response() {
        let err = parse_binding_response(&[0u8; 10], &[0; 12]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn xor_mapped_address_too_short() {
        let err = parse_xor_mapped_address(&[0u8; 4]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn multiple_attributes_prefers_xor() {
        // Response with MAPPED-ADDRESS first, then XOR-MAPPED-ADDRESS.
        let txn_id = [0xFF; 12];

        // MAPPED-ADDRESS pointing to 1.2.3.4:1111
        let mut attr1 = Vec::new();
        attr1.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr1.extend_from_slice(&8u16.to_be_bytes());
        attr1.push(0x00);
        attr1.push(FAMILY_IPV4);
        attr1.extend_from_slice(&1111u16.to_be_bytes());
        attr1.extend_from_slice(&std::net::Ipv4Addr::new(1, 2, 3, 4).octets());

        // XOR-MAPPED-ADDRESS pointing to 5.6.7.8:2222
        let xor_port = 2222u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = u32::from(std::net::Ipv4Addr::new(5, 6, 7, 8)) ^ MAGIC_COOKIE;
        let mut attr2 = Vec::new();
        attr2.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr2.extend_from_slice(&8u16.to_be_bytes());
        attr2.push(0x00);
        attr2.push(FAMILY_IPV4);
        attr2.extend_from_slice(&xor_port.to_be_bytes());
        attr2.extend_from_slice(&xor_ip.to_be_bytes());

        let mut attrs = attr1;
        attrs.extend_from_slice(&attr2);

        let msg_len = attrs.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attrs);

        let addr = parse_binding_response(&resp, &txn_id).unwrap();
        // Should prefer XOR-MAPPED-ADDRESS
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(addr.port(), 2222);
    }

    #[test]
    fn padded_attributes() {
        // Attribute with length 5 should be padded to 8 bytes.
        let txn_id = [0x11; 12];

        // Unknown attribute with 5-byte value (padded to 8).
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x8000u16.to_be_bytes()); // unknown comprehension-optional
        attrs.extend_from_slice(&5u16.to_be_bytes());
        attrs.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // 5 bytes
        attrs.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 bytes padding

        // XOR-MAPPED-ADDRESS after the padded attribute.
        let xor_port = 9999u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = u32::from(std::net::Ipv4Addr::new(10, 20, 30, 40)) ^ MAGIC_COOKIE;
        attrs.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&8u16.to_be_bytes());
        attrs.push(0x00);
        attrs.push(FAMILY_IPV4);
        attrs.extend_from_slice(&xor_port.to_be_bytes());
        attrs.extend_from_slice(&xor_ip.to_be_bytes());

        let msg_len = attrs.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attrs);

        let addr = parse_binding_response(&resp, &txn_id).unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(10, 20, 30, 40));
        assert_eq!(addr.port(), 9999);
    }

    #[test]
    fn resolve_stun_server_invalid() {
        let err = resolve_stun_server("not-a-valid-host:99999");
        assert!(err.is_err());
    }

    #[test]
    fn generate_txn_id_is_random() {
        let id1 = generate_txn_id();
        let id2 = generate_txn_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn reject_bad_magic_cookie() {
        let txn_id = [0xAA; 12];
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // wrong cookie
        resp.extend_from_slice(&txn_id);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(err.to_string().contains("bad magic cookie"));
    }

    #[test]
    fn reject_ipv6_family() {
        // XOR-MAPPED-ADDRESS with IPv6 family (0x02) should be rejected.
        let data = [0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = parse_xor_mapped_address(&data).unwrap_err();
        assert!(err.to_string().contains("unsupported address family"));

        let err = parse_mapped_address(&data).unwrap_err();
        assert!(err.to_string().contains("unsupported address family"));
    }

    #[test]
    fn reject_truncated_attribute() {
        let txn_id = [0xBB; 12];

        // Attribute header claims 100 bytes but only 4 bytes follow.
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&100u16.to_be_bytes()); // length = 100
        attrs.extend_from_slice(&[0x00; 4]); // only 4 bytes of data

        let msg_len = attrs.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attrs);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(err.to_string().contains("truncated attribute"));
    }

    #[test]
    fn reject_unknown_comprehension_required_attribute() {
        // Attribute type 0x0099 is < 0x8000 (comprehension-required) and unknown.
        let txn_id = [0xCC; 12];

        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x0099u16.to_be_bytes()); // unknown required
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.extend_from_slice(&[0x00; 4]);

        let msg_len = attrs.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attrs);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(
            err.to_string().contains("comprehension-required"),
            "expected comprehension-required error, got: {}",
            err
        );
    }

    #[test]
    fn no_mapped_address_in_response() {
        // Response with only comprehension-optional attributes, no mapped address.
        let txn_id = [0xDD; 12];

        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x8028u16.to_be_bytes()); // FINGERPRINT (optional)
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.extend_from_slice(&[0x00; 4]);

        let msg_len = attrs.len() as u16;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&attrs);

        let err = parse_binding_response(&resp, &txn_id).unwrap_err();
        assert!(err.to_string().contains("no mapped address"));
    }

    // Integration-level test: actually contacts a public STUN server.
    // Ignored by default since it requires network access.
    #[test]
    #[ignore]
    fn live_stun_binding() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let server = resolve_stun_server(DEFAULT_STUN_SERVER).unwrap();
        let addr = stun_mapped_address(&socket, server, Duration::from_secs(3)).unwrap();
        // We can't know our exact public IP, but it should be non-zero.
        assert!(!addr.ip().is_unspecified());
        assert_ne!(addr.port(), 0);
        println!("STUN mapped address: {}", addr);
    }
}
