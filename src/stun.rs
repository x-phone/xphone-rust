//! STUN Binding client (RFC 5389) and shared STUN primitives.
//!
//! Sends a STUN Binding Request to a public STUN server and parses the
//! response to discover the NAT-mapped (server-reflexive) address.
//!
//! Also provides generic STUN message building/parsing used by the TURN
//! client and ICE-Lite modules.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::error::{Error, Result};

// ─── STUN message types (RFC 5389 §6) ─────────────────────────────────

pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;

// TURN message types (RFC 5766).
pub(crate) const ALLOCATE_REQUEST: u16 = 0x0003;
pub(crate) const ALLOCATE_RESPONSE: u16 = 0x0103;
pub(crate) const ALLOCATE_ERROR: u16 = 0x0113;
pub(crate) const REFRESH_REQUEST: u16 = 0x0004;
pub(crate) const REFRESH_RESPONSE: u16 = 0x0104;
pub(crate) const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub(crate) const CREATE_PERMISSION_RESPONSE: u16 = 0x0108;
pub(crate) const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub(crate) const CHANNEL_BIND_RESPONSE: u16 = 0x0109;

// Magic cookie (RFC 5389 §6).
pub(crate) const MAGIC_COOKIE: u32 = 0x2112_A442;

// STUN header size.
pub(crate) const HEADER_SIZE: usize = 20;

// ─── Attribute types (RFC 5389 + RFC 5766) ─────────────────────────────

pub(crate) const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub(crate) const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub(crate) const ATTR_ERROR_CODE: u16 = 0x0009;
pub(crate) const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub(crate) const ATTR_LIFETIME: u16 = 0x000D;
pub(crate) const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub(crate) const ATTR_REALM: u16 = 0x0014;
pub(crate) const ATTR_NONCE: u16 = 0x0015;
pub(crate) const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub(crate) const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub(crate) const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub(crate) const ATTR_USE_CANDIDATE: u16 = 0x0025;
#[cfg(test)]
pub(crate) const ATTR_PRIORITY: u16 = 0x0024;

// Address families.
pub(crate) const FAMILY_IPV4: u8 = 0x01;

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

// ─── Shared STUN primitives ──────────────────────────────────────────────

/// Generates a random 12-byte transaction ID.
pub fn generate_txn_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    getrandom::getrandom(&mut id).expect("getrandom failed");
    id
}

/// Returns `true` if `data` looks like a STUN message (first two bits `00`,
/// magic cookie at bytes 4-7, length >= 20).
pub fn is_stun_message(data: &[u8]) -> bool {
    if data.len() < HEADER_SIZE {
        return false;
    }
    // First two bits must be 0b00 (RFC 5764 §5.1.2).
    if data[0] & 0xC0 != 0x00 {
        return false;
    }
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    cookie == MAGIC_COOKIE
}

/// A single STUN attribute (type + value).
pub struct StunAttr {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

/// Builds a STUN message with the given type, transaction ID, and attributes.
/// Handles 4-byte padding per RFC 5389 §15.
pub fn build_stun_message(msg_type: u16, txn_id: &[u8; 12], attrs: &[StunAttr]) -> Vec<u8> {
    // Compute total attribute body length.
    let body_len: usize = attrs.iter().map(|a| 4 + ((a.value.len() + 3) & !3)).sum();

    let mut buf = Vec::with_capacity(HEADER_SIZE + body_len);
    buf.extend_from_slice(&msg_type.to_be_bytes());
    buf.extend_from_slice(&(body_len as u16).to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txn_id);

    for attr in attrs {
        buf.extend_from_slice(&attr.attr_type.to_be_bytes());
        buf.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&attr.value);
        // Pad to 4-byte boundary.
        let pad = (4 - (attr.value.len() % 4)) % 4;
        buf.extend(std::iter::repeat_n(0u8, pad));
    }
    buf
}

/// Appends a MESSAGE-INTEGRITY attribute to a STUN message.
///
/// Per RFC 5389 §15.4, the message length in the header is adjusted to
/// point to the end of the MESSAGE-INTEGRITY attribute before computing
/// the HMAC-SHA1 over the entire message (including the adjusted header).
pub fn append_message_integrity(msg: &mut Vec<u8>, key: &[u8]) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // MESSAGE-INTEGRITY adds 24 bytes (4-byte attr header + 20-byte HMAC).
    let new_len = (msg.len() - HEADER_SIZE + 24) as u16;
    msg[2..4].copy_from_slice(&new_len.to_be_bytes());

    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC key length");
    mac.update(msg);
    let hmac_result = mac.finalize().into_bytes();

    msg.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&hmac_result);
}

/// Verifies a MESSAGE-INTEGRITY attribute in a STUN message.
/// Returns true if the HMAC matches. `mi_offset` is the byte offset of the
/// MESSAGE-INTEGRITY attribute within `msg`.
pub(crate) fn verify_message_integrity(msg: &[u8], mi_offset: usize, key: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    if mi_offset + 24 > msg.len() || mi_offset < HEADER_SIZE {
        return false;
    }

    // The HMAC is over bytes [0..mi_offset] with the message length adjusted.
    let mut buf = msg[..mi_offset].to_vec();
    let new_len = (mi_offset - HEADER_SIZE + 24) as u16;
    buf[2..4].copy_from_slice(&new_len.to_be_bytes());

    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC key length");
    mac.update(&buf);
    let expected = mac.finalize().into_bytes();

    // The actual HMAC value starts 4 bytes into the attribute (after type + length).
    msg[mi_offset + 4..mi_offset + 24] == expected[..]
}

/// Parses STUN attributes from the body portion of a message.
/// Returns `(attr_type, value_bytes)` pairs.
pub(crate) fn parse_stun_attrs(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let attr_start = offset + 4;
        if attr_start + attr_len > data.len() {
            break;
        }
        result.push((attr_type, data[attr_start..attr_start + attr_len].to_vec()));
        let padded_len = (attr_len + 3) & !3;
        offset = attr_start + padded_len;
    }
    result
}

/// Decodes an XOR-encoded address (used by XOR-MAPPED-ADDRESS,
/// XOR-RELAYED-ADDRESS, XOR-PEER-ADDRESS). IPv4 only.
pub(crate) fn parse_xor_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(Error::Other("stun: XOR address too short".into()));
    }
    let family = data[1];
    if family != FAMILY_IPV4 {
        return Err(Error::Other(format!(
            "stun: unsupported address family: {}",
            family
        )));
    }
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;
    let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ip = xor_ip ^ MAGIC_COOKIE;
    Ok(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::from(ip)),
        port,
    ))
}

/// Encodes a `SocketAddr` as XOR-MAPPED-ADDRESS attribute value. IPv4 only.
/// Returns an error for IPv6 addresses.
pub(crate) fn encode_xor_address(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.push(0x00); // reserved
    buf.push(FAMILY_IPV4);
    let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    buf.extend_from_slice(&xor_port.to_be_bytes());
    match addr {
        SocketAddr::V4(v4) => {
            let xor_ip = u32::from(*v4.ip()) ^ MAGIC_COOKIE;
            buf.extend_from_slice(&xor_ip.to_be_bytes());
        }
        SocketAddr::V6(_) => {
            panic!("encode_xor_address: IPv6 not supported");
        }
    }
    buf
}

/// Extracts the transaction ID from a STUN message. Returns `None` if too short.
pub(crate) fn extract_txn_id(data: &[u8]) -> Option<[u8; 12]> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&data[8..20]);
    Some(id)
}

/// Extracts the message type from a STUN message.
pub fn extract_msg_type(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([data[0], data[1]]))
}

/// Builds a STUN Binding Response with XOR-MAPPED-ADDRESS and MESSAGE-INTEGRITY.
pub(crate) fn build_binding_response_integrity(
    txn_id: &[u8; 12],
    mapped_addr: SocketAddr,
    key: &[u8],
) -> Vec<u8> {
    let xor_addr = encode_xor_address(mapped_addr);
    let mut msg = build_stun_message(
        BINDING_RESPONSE,
        txn_id,
        &[StunAttr {
            attr_type: ATTR_XOR_MAPPED_ADDRESS,
            value: xor_addr,
        }],
    );
    append_message_integrity(&mut msg, key);
    msg
}

// ─── Binding client (original API) ──────────────────────────────────────

fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    build_stun_message(BINDING_REQUEST, txn_id, &[])
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
                return parse_xor_address(attr_data);
            }
            ATTR_MAPPED_ADDRESS => {
                if let Ok(addr) = parse_mapped_address(attr_data) {
                    mapped = Some(addr);
                }
            }
            t if t < 0x8000 => {
                return Err(Error::Other(format!(
                    "stun: unknown comprehension-required attribute: 0x{:04x}",
                    t
                )));
            }
            _ => {}
        }

        let padded_len = (attr_len + 3) & !3;
        offset = attr_start + padded_len;
    }

    mapped.ok_or_else(|| Error::Other("stun: no mapped address in response".into()))
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
    let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);

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
    fn parse_xor_address_ipv4() {
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
        let err = parse_xor_address(&[0u8; 4]).unwrap_err();
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
        let err = parse_xor_address(&data).unwrap_err();
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

    // --- Shared primitives tests ---

    #[test]
    fn is_stun_message_valid() {
        let txn_id = [0xAA; 12];
        let msg = build_binding_request(&txn_id);
        assert!(is_stun_message(&msg));
    }

    #[test]
    fn is_stun_message_rtp() {
        // RTP packet (first byte 0x80 = version 2).
        let mut rtp = vec![0x80, 0x00];
        rtp.extend_from_slice(&[0u8; 18]);
        assert!(!is_stun_message(&rtp));
    }

    #[test]
    fn is_stun_message_too_short() {
        assert!(!is_stun_message(&[0u8; 10]));
    }

    #[test]
    fn build_stun_message_with_attrs() {
        let txn_id = [0x11; 12];
        let msg = build_stun_message(
            BINDING_REQUEST,
            &txn_id,
            &[StunAttr {
                attr_type: ATTR_LIFETIME,
                value: 600u32.to_be_bytes().to_vec(),
            }],
        );
        assert_eq!(msg.len(), HEADER_SIZE + 4 + 4); // header + attr_hdr + 4 bytes value
        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), BINDING_REQUEST);
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            MAGIC_COOKIE
        );
    }

    #[test]
    fn parse_stun_attrs_round_trip() {
        let txn_id = [0x22; 12];
        let msg = build_stun_message(
            BINDING_REQUEST,
            &txn_id,
            &[
                StunAttr {
                    attr_type: ATTR_LIFETIME,
                    value: 600u32.to_be_bytes().to_vec(),
                },
                StunAttr {
                    attr_type: ATTR_USERNAME,
                    value: b"alice".to_vec(),
                },
            ],
        );
        let attrs = parse_stun_attrs(&msg[HEADER_SIZE..]);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, ATTR_LIFETIME);
        assert_eq!(
            u32::from_be_bytes([attrs[0].1[0], attrs[0].1[1], attrs[0].1[2], attrs[0].1[3]]),
            600
        );
        assert_eq!(attrs[1].0, ATTR_USERNAME);
        assert_eq!(attrs[1].1, b"alice");
    }

    #[test]
    fn xor_address_round_trip() {
        let addr: SocketAddr = "203.0.113.42:12345".parse().unwrap();
        let encoded = encode_xor_address(addr);
        let decoded = parse_xor_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn message_integrity_verify() {
        let txn_id = [0x33; 12];
        let key = b"test-key";
        let mut msg = build_stun_message(
            BINDING_REQUEST,
            &txn_id,
            &[StunAttr {
                attr_type: ATTR_USERNAME,
                value: b"user".to_vec(),
            }],
        );
        let mi_offset = msg.len();
        append_message_integrity(&mut msg, key);
        assert!(verify_message_integrity(&msg, mi_offset, key));
        assert!(!verify_message_integrity(&msg, mi_offset, b"wrong-key"));
    }

    #[test]
    fn binding_response_has_xor_mapped() {
        let txn_id = [0x44; 12];
        let addr: SocketAddr = "10.20.30.40:5060".parse().unwrap();
        let resp = build_binding_response_integrity(&txn_id, addr, b"test-key");
        assert!(is_stun_message(&resp));
        let parsed = parse_binding_response(&resp, &txn_id).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn extract_txn_id_and_msg_type() {
        let txn_id = [0x55; 12];
        let msg = build_binding_request(&txn_id);
        assert_eq!(extract_txn_id(&msg).unwrap(), txn_id);
        assert_eq!(extract_msg_type(&msg).unwrap(), BINDING_REQUEST);
    }

    #[test]
    #[should_panic(expected = "IPv6 not supported")]
    fn encode_xor_address_rejects_ipv6() {
        let addr: SocketAddr = "[::1]:5060".parse().unwrap();
        encode_xor_address(addr);
    }
}
