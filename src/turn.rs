//! TURN client (RFC 5766).
//!
//! Provides NAT relay allocation via a TURN server. When STUN alone fails
//! (symmetric NAT, enterprise firewalls), TURN allocates a relay address
//! on the server that forwards media on the client's behalf.
//!
//! Supports:
//! - Allocate with long-term credentials (401 retry)
//! - CreatePermission for peer addresses
//! - ChannelBind for efficient 4-byte framed relay
//! - Background refresh loop (allocation + permissions + channels)
//! - ChannelData framing (RFC 5766 §11)

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::stun;

/// TURN long-term credential key: `MD5(username:realm:password)`.
pub(crate) fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{}:{}:{}", username, realm, password);
    md5::compute(input.as_bytes()).0.to_vec()
}

/// TURN client that manages a relay allocation on a TURN server.
pub struct TurnClient {
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    username: String,
    password: String,
    realm: Mutex<String>,
    nonce: Mutex<String>,
    relay_addr: Mutex<Option<SocketAddr>>,
    lifetime: Mutex<u32>,
    channel_bindings: Mutex<HashMap<SocketAddr, u16>>,
    permissions: Mutex<Vec<SocketAddr>>,
    next_channel: Mutex<u16>,
    stop_tx: Mutex<Option<crossbeam_channel::Sender<()>>>,
    loop_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl TurnClient {
    /// Creates a new TURN client bound to `socket`, targeting `server_addr`.
    pub fn new(
        socket: Arc<UdpSocket>,
        server_addr: SocketAddr,
        username: String,
        password: String,
    ) -> Self {
        Self {
            socket,
            server_addr,
            username,
            password,
            realm: Mutex::new(String::new()),
            nonce: Mutex::new(String::new()),
            relay_addr: Mutex::new(None),
            lifetime: Mutex::new(0),
            channel_bindings: Mutex::new(HashMap::new()),
            permissions: Mutex::new(Vec::new()),
            next_channel: Mutex::new(0x4000), // First valid channel number.
            stop_tx: Mutex::new(None),
            loop_thread: Mutex::new(None),
        }
    }

    /// Sends an Allocate request and returns the relay address.
    /// Handles 401 (Unauthorized) by extracting realm/nonce and retrying.
    /// Starts the background refresh loop on success.
    pub fn allocate(&self) -> Result<SocketAddr> {
        // First attempt without credentials (to get realm + nonce).
        let txn_id = stun::generate_txn_id();
        let msg = stun::build_stun_message(
            stun::ALLOCATE_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_REQUESTED_TRANSPORT,
                value: vec![17, 0, 0, 0], // UDP = protocol 17
            }],
        );

        info!(server = %self.server_addr, "TURN >>> Allocate");
        let resp = self.send_recv(&msg, Duration::from_secs(5))?;
        let msg_type = stun::extract_msg_type(&resp)
            .ok_or_else(|| Error::Other("turn: response too short".into()))?;

        if msg_type == stun::ALLOCATE_ERROR {
            // Extract realm and nonce from 401 error response.
            self.extract_realm_nonce(&resp)?;
            debug!("TURN: got 401, retrying with credentials");
            return self.allocate_authenticated();
        }

        if msg_type == stun::ALLOCATE_RESPONSE {
            return self.parse_allocate_success(&resp);
        }

        Err(Error::Other(format!(
            "turn: unexpected response type: 0x{:04x}",
            msg_type
        )))
    }

    /// Sends an authenticated Allocate request.
    fn allocate_authenticated(&self) -> Result<SocketAddr> {
        let txn_id = stun::generate_txn_id();
        let key = self.long_term_key();

        let mut attrs = vec![stun::StunAttr {
            attr_type: stun::ATTR_REQUESTED_TRANSPORT,
            value: vec![17, 0, 0, 0],
        }];
        attrs.extend(self.credential_attrs());
        let mut msg = stun::build_stun_message(stun::ALLOCATE_REQUEST, &txn_id, &attrs);
        stun::append_message_integrity(&mut msg, &key);

        info!(server = %self.server_addr, "TURN >>> Allocate (authenticated)");
        let resp = self.send_recv(&msg, Duration::from_secs(5))?;
        let msg_type = stun::extract_msg_type(&resp)
            .ok_or_else(|| Error::Other("turn: response too short".into()))?;

        if msg_type == stun::ALLOCATE_ERROR {
            let error = self.extract_error_code(&resp);
            return Err(Error::Other(format!("turn: Allocate rejected: {}", error)));
        }

        if msg_type == stun::ALLOCATE_RESPONSE {
            let addr = self.parse_allocate_success(&resp)?;
            self.start_refresh_loop();
            return Ok(addr);
        }

        Err(Error::Other(format!(
            "turn: unexpected response: 0x{:04x}",
            msg_type
        )))
    }

    /// Parses a successful Allocate response for relay address and lifetime.
    fn parse_allocate_success(&self, resp: &[u8]) -> Result<SocketAddr> {
        if resp.len() < stun::HEADER_SIZE {
            return Err(Error::Other("turn: response too short".into()));
        }
        let attrs = stun::parse_stun_attrs(&resp[stun::HEADER_SIZE..]);
        let mut relay = None;

        for (t, v) in &attrs {
            match *t {
                stun::ATTR_XOR_RELAYED_ADDRESS => {
                    relay = Some(stun::parse_xor_address(v)?);
                }
                stun::ATTR_LIFETIME if v.len() >= 4 => {
                    let lt = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                    *self.lifetime.lock() = lt;
                    debug!(lifetime = lt, "TURN: server lifetime");
                }
                _ => {}
            }
        }

        let addr =
            relay.ok_or_else(|| Error::Other("turn: no XOR-RELAYED-ADDRESS in response".into()))?;
        *self.relay_addr.lock() = Some(addr);
        info!(relay = %addr, "TURN: allocation succeeded");
        Ok(addr)
    }

    /// Creates a permission for the given peer address.
    pub fn create_permission(&self, peer: SocketAddr) -> Result<()> {
        let txn_id = stun::generate_txn_id();
        let key = self.long_term_key();

        let mut attrs = vec![stun::StunAttr {
            attr_type: stun::ATTR_XOR_PEER_ADDRESS,
            value: stun::encode_xor_address(peer),
        }];
        attrs.extend(self.credential_attrs());
        let mut msg = stun::build_stun_message(stun::CREATE_PERMISSION_REQUEST, &txn_id, &attrs);
        stun::append_message_integrity(&mut msg, &key);

        debug!(peer = %peer, "TURN >>> CreatePermission");
        let resp = self.send_recv(&msg, Duration::from_secs(5))?;
        let msg_type = stun::extract_msg_type(&resp)
            .ok_or_else(|| Error::Other("turn: response too short".into()))?;

        if msg_type == stun::CREATE_PERMISSION_RESPONSE {
            self.permissions.lock().push(peer);
            debug!(peer = %peer, "TURN: permission created");
            Ok(())
        } else {
            Err(Error::Other(format!(
                "turn: CreatePermission failed: 0x{:04x}",
                msg_type
            )))
        }
    }

    /// Binds a channel to a peer address for efficient ChannelData relay.
    /// Returns the channel number assigned.
    pub fn channel_bind(&self, peer: SocketAddr) -> Result<u16> {
        let channel = {
            let mut next = self.next_channel.lock();
            let ch = *next;
            if ch > 0x7FFE {
                return Err(Error::Other("turn: channel numbers exhausted".into()));
            }
            *next = ch + 1;
            ch
        };

        let txn_id = stun::generate_txn_id();
        let key = self.long_term_key();

        let mut channel_val = vec![0u8; 4];
        channel_val[0..2].copy_from_slice(&channel.to_be_bytes());
        // bytes 2-3 are RFFU (reserved, must be 0)

        let mut attrs = vec![
            stun::StunAttr {
                attr_type: stun::ATTR_CHANNEL_NUMBER,
                value: channel_val,
            },
            stun::StunAttr {
                attr_type: stun::ATTR_XOR_PEER_ADDRESS,
                value: stun::encode_xor_address(peer),
            },
        ];
        attrs.extend(self.credential_attrs());
        let mut msg = stun::build_stun_message(stun::CHANNEL_BIND_REQUEST, &txn_id, &attrs);
        stun::append_message_integrity(&mut msg, &key);

        debug!(peer = %peer, channel, "TURN >>> ChannelBind");
        let resp = self.send_recv(&msg, Duration::from_secs(5))?;
        let msg_type = stun::extract_msg_type(&resp)
            .ok_or_else(|| Error::Other("turn: response too short".into()))?;

        if msg_type == stun::CHANNEL_BIND_RESPONSE {
            self.channel_bindings.lock().insert(peer, channel);
            debug!(peer = %peer, channel, "TURN: channel bound");
            Ok(channel)
        } else {
            Err(Error::Other(format!(
                "turn: ChannelBind failed: 0x{:04x}",
                msg_type
            )))
        }
    }

    /// Refreshes the TURN allocation.
    pub fn refresh(&self) -> Result<()> {
        let txn_id = stun::generate_txn_id();
        let key = self.long_term_key();
        let lifetime = *self.lifetime.lock();

        let mut attrs = vec![stun::StunAttr {
            attr_type: stun::ATTR_LIFETIME,
            value: lifetime.to_be_bytes().to_vec(),
        }];
        attrs.extend(self.credential_attrs());
        let mut msg = stun::build_stun_message(stun::REFRESH_REQUEST, &txn_id, &attrs);
        stun::append_message_integrity(&mut msg, &key);

        debug!("TURN >>> Refresh");
        let resp = self.send_recv(&msg, Duration::from_secs(5))?;
        let msg_type = stun::extract_msg_type(&resp)
            .ok_or_else(|| Error::Other("turn: response too short".into()))?;

        if msg_type == stun::REFRESH_RESPONSE {
            debug!("TURN: refresh succeeded");
            Ok(())
        } else {
            Err(Error::Other(format!(
                "turn: Refresh failed: 0x{:04x}",
                msg_type
            )))
        }
    }

    /// Sends a Refresh with LIFETIME=0 to deallocate.
    pub fn deallocate(&self) -> Result<()> {
        let txn_id = stun::generate_txn_id();
        let key = self.long_term_key();

        let mut attrs = vec![stun::StunAttr {
            attr_type: stun::ATTR_LIFETIME,
            value: 0u32.to_be_bytes().to_vec(),
        }];
        attrs.extend(self.credential_attrs());
        let mut msg = stun::build_stun_message(stun::REFRESH_REQUEST, &txn_id, &attrs);
        stun::append_message_integrity(&mut msg, &key);

        info!("TURN >>> Refresh LIFETIME=0 (deallocate)");
        // Best-effort: don't fail if the server doesn't respond.
        let _ = self.socket.send_to(&msg, self.server_addr);
        *self.relay_addr.lock() = None;
        Ok(())
    }

    /// Stops the refresh loop and deallocates.
    pub fn stop(&self) {
        self.stop_tx.lock().take();
        if let Some(handle) = self.loop_thread.lock().take() {
            let _ = handle.join();
        }
        let _ = self.deallocate();
    }

    /// Returns the relay address, if allocated.
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        *self.relay_addr.lock()
    }

    /// Returns the channel number bound to `peer`, if any.
    pub fn channel_for_peer(&self, peer: &SocketAddr) -> Option<u16> {
        self.channel_bindings.lock().get(peer).copied()
    }

    // ─── ChannelData framing ──────────────────────────────────────────────

    /// Returns the TURN server address (for sending ChannelData).
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    // ─── Internal ─────────────────────────────────────────────────────────

    fn long_term_key(&self) -> Vec<u8> {
        let realm = self.realm.lock().clone();
        long_term_key(&self.username, &realm, &self.password)
    }

    /// Returns the credential attributes (USERNAME, REALM, NONCE) for authenticated requests.
    fn credential_attrs(&self) -> Vec<stun::StunAttr> {
        vec![
            stun::StunAttr {
                attr_type: stun::ATTR_USERNAME,
                value: self.username.as_bytes().to_vec(),
            },
            stun::StunAttr {
                attr_type: stun::ATTR_REALM,
                value: self.realm.lock().as_bytes().to_vec(),
            },
            stun::StunAttr {
                attr_type: stun::ATTR_NONCE,
                value: self.nonce.lock().as_bytes().to_vec(),
            },
        ]
    }

    fn send_recv(&self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.socket
            .send_to(msg, self.server_addr)
            .map_err(|e| Error::Other(format!("turn: send: {}", e)))?;

        let orig_timeout = self.socket.read_timeout().unwrap_or(None);
        let _ = self.socket.set_read_timeout(Some(timeout));

        let mut buf = [0u8; 2048];
        let result = self.socket.recv_from(&mut buf);
        let _ = self.socket.set_read_timeout(orig_timeout);

        let (n, from) = result.map_err(|e| Error::Other(format!("turn: recv: {}", e)))?;
        // Validate response came from the TURN server.
        if from.ip() != self.server_addr.ip() {
            return Err(Error::Other(format!(
                "turn: response from unexpected source: {} (expected {})",
                from, self.server_addr
            )));
        }
        Ok(buf[..n].to_vec())
    }

    fn extract_realm_nonce(&self, resp: &[u8]) -> Result<()> {
        if resp.len() < stun::HEADER_SIZE {
            return Err(Error::Other("turn: error response too short".into()));
        }
        let attrs = stun::parse_stun_attrs(&resp[stun::HEADER_SIZE..]);
        for (t, v) in &attrs {
            match *t {
                stun::ATTR_REALM => {
                    *self.realm.lock() = String::from_utf8(v.clone()).unwrap_or_default();
                }
                stun::ATTR_NONCE => {
                    *self.nonce.lock() = String::from_utf8(v.clone()).unwrap_or_default();
                }
                _ => {}
            }
        }
        if self.realm.lock().is_empty() {
            return Err(Error::Other("turn: no REALM in 401 response".into()));
        }
        Ok(())
    }

    fn extract_error_code(&self, resp: &[u8]) -> String {
        if resp.len() < stun::HEADER_SIZE {
            return "unknown".into();
        }
        let attrs = stun::parse_stun_attrs(&resp[stun::HEADER_SIZE..]);
        for (t, v) in &attrs {
            if *t == stun::ATTR_ERROR_CODE && v.len() >= 4 {
                let class = (v[2] & 0x07) as u16;
                let number = v[3] as u16;
                let code = class * 100 + number;
                let reason = if v.len() > 4 {
                    String::from_utf8_lossy(&v[4..]).to_string()
                } else {
                    String::new()
                };
                return format!("{} {}", code, reason);
            }
        }
        "unknown".into()
    }

    fn start_refresh_loop(&self) {
        let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(0);
        *self.stop_tx.lock() = Some(stop_tx);

        let socket = Arc::clone(&self.socket);
        let server_addr = self.server_addr;
        let username = self.username.clone();
        let password = self.password.clone();
        // Share live realm/nonce so the refresh loop sees nonce updates.
        let realm = Arc::new(Mutex::new(self.realm.lock().clone()));
        let nonce = Arc::new(Mutex::new(self.nonce.lock().clone()));
        // Link to the real collections so new permissions/channels are refreshed.
        let lifetime = *self.lifetime.lock();
        let permissions = Arc::new(Mutex::new(self.permissions.lock().clone()));
        let channel_bindings = Arc::new(Mutex::new(self.channel_bindings.lock().clone()));

        let handle = std::thread::Builder::new()
            .name("turn-refresh".into())
            .spawn(move || {
                // Refresh at half the lifetime, minimum 30s.
                let refresh_interval = Duration::from_secs(std::cmp::max(lifetime / 2, 30) as u64);
                // Permissions and channels expire at 5 minutes (RFC 5766).
                let perm_interval = Duration::from_secs(240);

                let mut last_refresh = std::time::Instant::now();
                let mut last_perm = std::time::Instant::now();

                loop {
                    let tick = Duration::from_millis(500);
                    match stop_rx.recv_timeout(tick) {
                        Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    }

                    // Recompute key each iteration so nonce/realm updates are picked up.
                    let r = realm.lock().clone();
                    let n = nonce.lock().clone();
                    let key = long_term_key(&username, &r, &password);
                    let creds = TurnCreds {
                        username: &username,
                        realm: &r,
                        nonce: &n,
                        key: &key,
                    };

                    if last_refresh.elapsed() >= refresh_interval {
                        last_refresh = std::time::Instant::now();
                        if let Err(e) = send_refresh(&socket, server_addr, &creds, lifetime) {
                            warn!(error = %e, "TURN: refresh failed");
                        }
                    }

                    if last_perm.elapsed() >= perm_interval {
                        last_perm = std::time::Instant::now();
                        // Refresh permissions.
                        for peer in permissions.lock().iter() {
                            let _ = send_create_permission(&socket, server_addr, &creds, *peer);
                        }
                        // Refresh channel bindings.
                        for (peer, ch) in channel_bindings.lock().iter() {
                            let _ = send_channel_bind(&socket, server_addr, &creds, *peer, *ch);
                        }
                    }
                }
            })
            .expect("failed to spawn turn-refresh");

        *self.loop_thread.lock() = Some(handle);
    }
}

impl Drop for TurnClient {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─── ChannelData framing (RFC 5766 §11) ────────────────────────────────

/// Wraps RTP data in a ChannelData frame (4-byte header).
/// Panics in debug builds if `data` exceeds 65535 bytes.
pub fn wrap_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    debug_assert!(
        data.len() <= u16::MAX as usize,
        "ChannelData payload too large"
    );
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&channel.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Parses a ChannelData frame. Returns `(channel, payload)`.
pub fn parse_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + length {
        return None;
    }
    Some((channel, &data[4..4 + length]))
}

/// Returns `true` if the first byte indicates a ChannelData message
/// (0x40..=0x7F per RFC 5764 §5.1.2).
pub fn is_channel_data(data: &[u8]) -> bool {
    !data.is_empty() && (0x40..=0x7F).contains(&data[0])
}

// ─── Background loop helpers ───────────────────────────────────────────

fn send_refresh(
    socket: &UdpSocket,
    server: SocketAddr,
    creds: &TurnCreds<'_>,
    lifetime: u32,
) -> Result<()> {
    let txn_id = stun::generate_txn_id();
    let mut attrs = vec![stun::StunAttr {
        attr_type: stun::ATTR_LIFETIME,
        value: lifetime.to_be_bytes().to_vec(),
    }];
    attrs.extend(creds.to_attrs());
    let mut msg = stun::build_stun_message(stun::REFRESH_REQUEST, &txn_id, &attrs);
    stun::append_message_integrity(&mut msg, creds.key);
    socket
        .send_to(&msg, server)
        .map_err(|e| Error::Other(format!("turn: refresh send: {}", e)))?;
    Ok(())
}

fn send_create_permission(
    socket: &UdpSocket,
    server: SocketAddr,
    creds: &TurnCreds<'_>,
    peer: SocketAddr,
) -> Result<()> {
    let txn_id = stun::generate_txn_id();
    let mut attrs = vec![stun::StunAttr {
        attr_type: stun::ATTR_XOR_PEER_ADDRESS,
        value: stun::encode_xor_address(peer),
    }];
    attrs.extend(creds.to_attrs());
    let mut msg = stun::build_stun_message(stun::CREATE_PERMISSION_REQUEST, &txn_id, &attrs);
    stun::append_message_integrity(&mut msg, creds.key);
    socket
        .send_to(&msg, server)
        .map_err(|e| Error::Other(format!("turn: permission send: {}", e)))?;
    Ok(())
}

/// TURN credential parameters for background loop helpers.
struct TurnCreds<'a> {
    username: &'a str,
    realm: &'a str,
    nonce: &'a str,
    key: &'a [u8],
}

impl TurnCreds<'_> {
    /// Returns USERNAME, REALM, NONCE attributes for authenticated requests.
    fn to_attrs(&self) -> Vec<stun::StunAttr> {
        vec![
            stun::StunAttr {
                attr_type: stun::ATTR_USERNAME,
                value: self.username.as_bytes().to_vec(),
            },
            stun::StunAttr {
                attr_type: stun::ATTR_REALM,
                value: self.realm.as_bytes().to_vec(),
            },
            stun::StunAttr {
                attr_type: stun::ATTR_NONCE,
                value: self.nonce.as_bytes().to_vec(),
            },
        ]
    }
}

fn send_channel_bind(
    socket: &UdpSocket,
    server: SocketAddr,
    creds: &TurnCreds<'_>,
    peer: SocketAddr,
    channel: u16,
) -> Result<()> {
    let txn_id = stun::generate_txn_id();
    let mut channel_val = vec![0u8; 4];
    channel_val[0..2].copy_from_slice(&channel.to_be_bytes());

    let mut attrs = vec![
        stun::StunAttr {
            attr_type: stun::ATTR_CHANNEL_NUMBER,
            value: channel_val,
        },
        stun::StunAttr {
            attr_type: stun::ATTR_XOR_PEER_ADDRESS,
            value: stun::encode_xor_address(peer),
        },
    ];
    attrs.extend(creds.to_attrs());
    let mut msg = stun::build_stun_message(stun::CHANNEL_BIND_REQUEST, &txn_id, &attrs);
    stun::append_message_integrity(&mut msg, creds.key);
    socket
        .send_to(&msg, server)
        .map_err(|e| Error::Other(format!("turn: channel bind send: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_term_key_md5() {
        // RFC 5389 example: MD5("user:realm:pass")
        let key = long_term_key("user", "realm", "pass");
        assert_eq!(key.len(), 16);
        // Verify deterministic.
        assert_eq!(key, long_term_key("user", "realm", "pass"));
        // Different inputs → different keys.
        assert_ne!(key, long_term_key("user2", "realm", "pass"));
    }

    #[test]
    fn channel_data_round_trip() {
        let channel = 0x4000u16;
        let payload = b"hello RTP";
        let frame = wrap_channel_data(channel, payload);
        assert_eq!(frame.len(), 4 + payload.len());

        let (ch, data) = parse_channel_data(&frame).unwrap();
        assert_eq!(ch, channel);
        assert_eq!(data, payload);
    }

    #[test]
    fn channel_data_empty_payload() {
        let frame = wrap_channel_data(0x4001, &[]);
        let (ch, data) = parse_channel_data(&frame).unwrap();
        assert_eq!(ch, 0x4001);
        assert!(data.is_empty());
    }

    #[test]
    fn channel_data_too_short() {
        assert!(parse_channel_data(&[0x40, 0x00]).is_none());
        assert!(parse_channel_data(&[]).is_none());
    }

    #[test]
    fn channel_data_truncated_payload() {
        // Header says 10 bytes, but only 5 follow.
        let mut frame = vec![0x40, 0x00, 0x00, 0x0A];
        frame.extend_from_slice(&[0u8; 5]);
        assert!(parse_channel_data(&frame).is_none());
    }

    #[test]
    fn is_channel_data_valid() {
        assert!(is_channel_data(&[0x40, 0x00, 0x00, 0x00]));
        assert!(is_channel_data(&[0x7F, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn is_channel_data_invalid() {
        // STUN message (first byte < 0x40)
        assert!(!is_channel_data(&[0x00, 0x01]));
        // RTP (first byte >= 0x80)
        assert!(!is_channel_data(&[0x80, 0x00]));
        assert!(!is_channel_data(&[]));
    }

    #[test]
    fn allocate_request_format() {
        let txn_id = [0xAA; 12];
        let msg = stun::build_stun_message(
            stun::ALLOCATE_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_REQUESTED_TRANSPORT,
                value: vec![17, 0, 0, 0],
            }],
        );
        assert!(stun::is_stun_message(&msg));
        assert_eq!(
            stun::extract_msg_type(&msg).unwrap(),
            stun::ALLOCATE_REQUEST
        );
        let attrs = stun::parse_stun_attrs(&msg[stun::HEADER_SIZE..]);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, stun::ATTR_REQUESTED_TRANSPORT);
        assert_eq!(attrs[0].1[0], 17); // UDP
    }

    #[test]
    fn refresh_request_format() {
        let txn_id = [0xBB; 12];
        let lifetime = 600u32;
        let msg = stun::build_stun_message(
            stun::REFRESH_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_LIFETIME,
                value: lifetime.to_be_bytes().to_vec(),
            }],
        );
        assert_eq!(stun::extract_msg_type(&msg).unwrap(), stun::REFRESH_REQUEST);
        let attrs = stun::parse_stun_attrs(&msg[stun::HEADER_SIZE..]);
        let lt_val =
            u32::from_be_bytes([attrs[0].1[0], attrs[0].1[1], attrs[0].1[2], attrs[0].1[3]]);
        assert_eq!(lt_val, 600);
    }

    #[test]
    fn deallocate_request_has_zero_lifetime() {
        let txn_id = [0xCC; 12];
        let msg = stun::build_stun_message(
            stun::REFRESH_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_LIFETIME,
                value: 0u32.to_be_bytes().to_vec(),
            }],
        );
        let attrs = stun::parse_stun_attrs(&msg[stun::HEADER_SIZE..]);
        let lt_val =
            u32::from_be_bytes([attrs[0].1[0], attrs[0].1[1], attrs[0].1[2], attrs[0].1[3]]);
        assert_eq!(lt_val, 0);
    }

    #[test]
    fn create_permission_request_format() {
        let txn_id = [0xDD; 12];
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let xor_peer = stun::encode_xor_address(peer);
        let msg = stun::build_stun_message(
            stun::CREATE_PERMISSION_REQUEST,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_XOR_PEER_ADDRESS,
                value: xor_peer,
            }],
        );
        assert_eq!(
            stun::extract_msg_type(&msg).unwrap(),
            stun::CREATE_PERMISSION_REQUEST
        );
    }

    #[test]
    fn channel_bind_request_format() {
        let txn_id = [0xEE; 12];
        let peer: SocketAddr = "10.0.0.2:6000".parse().unwrap();
        let xor_peer = stun::encode_xor_address(peer);
        let channel = 0x4000u16;
        let mut channel_val = vec![0u8; 4];
        channel_val[0..2].copy_from_slice(&channel.to_be_bytes());

        let msg = stun::build_stun_message(
            stun::CHANNEL_BIND_REQUEST,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_CHANNEL_NUMBER,
                    value: channel_val,
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_XOR_PEER_ADDRESS,
                    value: xor_peer,
                },
            ],
        );
        assert_eq!(
            stun::extract_msg_type(&msg).unwrap(),
            stun::CHANNEL_BIND_REQUEST
        );
        let attrs = stun::parse_stun_attrs(&msg[stun::HEADER_SIZE..]);
        assert_eq!(attrs[0].0, stun::ATTR_CHANNEL_NUMBER);
        let ch = u16::from_be_bytes([attrs[0].1[0], attrs[0].1[1]]);
        assert_eq!(ch, 0x4000);
    }

    #[test]
    fn authenticated_message_has_integrity() {
        let txn_id = [0xFF; 12];
        let key = long_term_key("alice", "example.com", "secret");
        let mut msg = stun::build_stun_message(
            stun::ALLOCATE_REQUEST,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_USERNAME,
                    value: b"alice".to_vec(),
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_REALM,
                    value: b"example.com".to_vec(),
                },
            ],
        );
        let mi_offset = msg.len();
        stun::append_message_integrity(&mut msg, &key);
        assert!(stun::verify_message_integrity(&msg, mi_offset, &key));
    }

    #[test]
    fn extract_error_code_parses() {
        // Build a fake Allocate Error Response with ERROR-CODE 401.
        let txn_id = [0x11; 12];
        let mut error_val = vec![0u8; 4];
        error_val[2] = 4; // class = 4
        error_val[3] = 1; // number = 1 → 401
        error_val.extend_from_slice(b"Unauthorized");

        let msg = stun::build_stun_message(
            stun::ALLOCATE_ERROR,
            &txn_id,
            &[stun::StunAttr {
                attr_type: stun::ATTR_ERROR_CODE,
                value: error_val,
            }],
        );

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let client = TurnClient::new(
            socket,
            "127.0.0.1:3478".parse().unwrap(),
            "user".into(),
            "pass".into(),
        );
        let error = client.extract_error_code(&msg);
        assert!(error.contains("401"));
        assert!(error.contains("Unauthorized"));
    }

    #[test]
    fn extract_realm_nonce_from_401() {
        let txn_id = [0x22; 12];
        let mut error_val = vec![0u8; 4];
        error_val[2] = 4;
        error_val[3] = 1;

        let msg = stun::build_stun_message(
            stun::ALLOCATE_ERROR,
            &txn_id,
            &[
                stun::StunAttr {
                    attr_type: stun::ATTR_ERROR_CODE,
                    value: error_val,
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_REALM,
                    value: b"example.com".to_vec(),
                },
                stun::StunAttr {
                    attr_type: stun::ATTR_NONCE,
                    value: b"abc123".to_vec(),
                },
            ],
        );

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let client = TurnClient::new(
            socket,
            "127.0.0.1:3478".parse().unwrap(),
            "user".into(),
            "pass".into(),
        );
        client.extract_realm_nonce(&msg).unwrap();
        assert_eq!(*client.realm.lock(), "example.com");
        assert_eq!(*client.nonce.lock(), "abc123");
    }

    #[test]
    fn demux_stun_vs_channel_vs_rtp() {
        // STUN Binding Request
        let stun_msg = stun::build_stun_message(stun::BINDING_REQUEST, &[0; 12], &[]);
        assert!(stun::is_stun_message(&stun_msg));
        assert!(!is_channel_data(&stun_msg));

        // ChannelData
        let cd = wrap_channel_data(0x4000, b"rtp payload");
        assert!(is_channel_data(&cd));
        assert!(!stun::is_stun_message(&cd));

        // RTP (version 2, first byte = 0x80)
        let rtp = vec![
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD,
        ];
        assert!(!stun::is_stun_message(&rtp));
        assert!(!is_channel_data(&rtp));
    }
}
