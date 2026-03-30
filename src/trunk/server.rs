//! SIP trunk host server — accepts and places calls directly with trusted SIP peers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::call::Call;
use crate::config::DialOptions;
use crate::error::{Error, Result};
use crate::sip::message::{self, Message};
use crate::trunk::auth::{self, AuthResult};
use crate::trunk::config::ServerConfig;
use crate::trunk::dialog::{SipOutgoing, TrunkDialog};
use crate::trunk::util::{
    ensure_to_tag, extract_uri, extract_uri_user, generate_branch, generate_tag, uuid_v4,
};
use crate::types::{CallState, EndReason};

type CallStateCb = Arc<dyn Fn(Arc<Call>, CallState) + Send + Sync>;
type CallEndedCb = Arc<dyn Fn(Arc<Call>, EndReason) + Send + Sync>;
type CallDtmfCb = Arc<dyn Fn(Arc<Call>, String) + Send + Sync>;

/// TTL thresholds for dialog reaping.
const SETUP_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const ACTIVE_TTL: std::time::Duration = std::time::Duration::from_secs(4 * 3600);
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Tracks an active SIP dialog in the server.
struct DialogEntry {
    call: Option<Arc<Call>>,
    dialog: Option<Arc<TrunkDialog>>,
    created_at: Instant,
}

type DialogMap = Arc<Mutex<HashMap<String, DialogEntry>>>;

struct Inner {
    sip_tx: Option<mpsc::Sender<SipOutgoing>>,
    local_addr: Option<SocketAddr>,
    dialogs: DialogMap,

    incoming_fn: Vec<Arc<dyn Fn(Arc<Call>) + Send + Sync>>,
    on_call_state_fn: Vec<CallStateCb>,
    on_call_ended_fn: Vec<CallEndedCb>,
    on_call_dtmf_fn: Vec<CallDtmfCb>,
}

/// SIP trunk host server — accept and place calls directly with trusted SIP peers.
///
/// `Server` is a second connection mode alongside [`Phone`](crate::phone::Phone).
/// While `Phone` registers to a SIP server, `Server` listens for incoming SIP
/// traffic directly from trusted peers (PBXes, trunk providers like Twilio/Telnyx).
///
/// Both modes produce the same [`Call`] object — the downstream API
/// (accept, hangup, DTMF, media, PCM access) is identical.
///
/// # Example
///
/// ```rust,no_run
/// use xphone::trunk::server::Server;
/// use xphone::trunk::config::{ServerConfig, PeerConfig};
///
/// # async fn example() -> xphone::Result<()> {
/// let config = ServerConfig {
///     listen: "0.0.0.0:5080".into(),
///     peers: vec![PeerConfig {
///         name: "office-pbx".into(),
///         host: Some("192.168.1.10".parse().unwrap()),
///         ..Default::default()
///     }],
///     ..Default::default()
/// };
///
/// let server = Server::new(config);
///
/// server.on_incoming(|call| {
///     call.accept().unwrap();
/// });
///
/// server.listen().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Server {
    config: ServerConfig,
    inner: Arc<Mutex<Inner>>,
}

impl Server {
    /// Creates a new `Server` with the given configuration.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(Inner {
                sip_tx: None,
                local_addr: None,
                dialogs: Arc::new(Mutex::new(HashMap::new())),
                incoming_fn: Vec::new(),
                on_call_state_fn: Vec::new(),
                on_call_ended_fn: Vec::new(),
                on_call_dtmf_fn: Vec::new(),
            })),
        }
    }

    /// Registers a callback for incoming calls from peers.
    ///
    /// The callback receives an `Arc<Call>` in the `Ringing` state. Call
    /// [`Call::accept()`] to answer or [`Call::reject()`] to decline.
    pub fn on_incoming<F>(&self, f: F)
    where
        F: Fn(Arc<Call>) + Send + Sync + 'static,
    {
        self.inner.lock().incoming_fn.push(Arc::new(f));
    }

    /// Registers a callback for call state changes on any call.
    /// Multiple callbacks can be registered; all will fire.
    pub fn on_call_state<F>(&self, f: F)
    where
        F: Fn(Arc<Call>, CallState) + Send + Sync + 'static,
    {
        self.inner.lock().on_call_state_fn.push(Arc::new(f));
    }

    /// Registers a callback for call ended events on any call.
    /// Multiple callbacks can be registered; all will fire.
    pub fn on_call_ended<F>(&self, f: F)
    where
        F: Fn(Arc<Call>, EndReason) + Send + Sync + 'static,
    {
        self.inner.lock().on_call_ended_fn.push(Arc::new(f));
    }

    /// Registers a callback for DTMF events on any call.
    /// Multiple callbacks can be registered; all will fire.
    pub fn on_call_dtmf<F>(&self, f: F)
    where
        F: Fn(Arc<Call>, String) + Send + Sync + 'static,
    {
        self.inner.lock().on_call_dtmf_fn.push(Arc::new(f));
    }

    /// Places an outbound call to a named peer.
    ///
    /// `peer_name` must match a configured [`PeerConfig::name`].
    /// `to` is the destination (e.g., `"+15551234567"`).
    /// `from` is the caller ID (e.g., `"+15559876543"`).
    pub fn dial(&self, peer_name: &str, to: &str, from: &str) -> Result<Arc<Call>> {
        let peer = auth::find_peer(&self.config, peer_name)
            .ok_or_else(|| Error::Other(format!("unknown peer: {peer_name}")))?;
        let remote_addr = SocketAddr::new(
            peer.host
                .ok_or_else(|| Error::Other(format!("peer '{peer_name}' has no host")))?,
            peer.port,
        );
        let rtp_address = peer.rtp_address.or(self.config.rtp_address);

        self.dial_inner(remote_addr, to, from, rtp_address)
    }

    /// Dials a SIP URI directly, bypassing peer resolution.
    ///
    /// The host:port is extracted from the URI (default port 5060).
    /// Useful for outbound trunking where the destination is dynamic.
    ///
    /// ```ignore
    /// let call = server.dial_uri("sip:+15551234567@trunk.provider.com:5060", "1001")?;
    /// ```
    pub fn dial_uri(&self, sip_uri: &str, from: &str) -> Result<Arc<Call>> {
        let remote_addr = parse_addr_from_uri(sip_uri)
            .ok_or_else(|| Error::Other(format!("cannot parse address from URI: {sip_uri}")))?;
        let to = extract_uri_user(sip_uri);
        if to.is_empty() || to.contains(':') {
            return Err(Error::Other(format!("SIP URI has no user part: {sip_uri}")));
        }

        self.dial_inner(remote_addr, to, from, self.config.rtp_address)
    }

    fn dial_inner(
        &self,
        remote_addr: SocketAddr,
        to: &str,
        from: &str,
        rtp_address: Option<std::net::IpAddr>,
    ) -> Result<Arc<Call>> {
        let inner = self.inner.lock();
        let sip_tx = inner
            .sip_tx
            .clone()
            .ok_or_else(|| Error::Other("server not listening".into()))?;
        let local_addr = inner
            .local_addr
            .ok_or_else(|| Error::Other("server not listening".into()))?;
        let dialogs = inner.dialogs.clone();
        let on_call_state_fn = inner.on_call_state_fn.clone();
        let on_call_ended_fn = inner.on_call_ended_fn.clone();
        let on_call_dtmf_fn = inner.on_call_dtmf_fn.clone();
        drop(inner);

        let local_ip = rtp_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| local_addr.ip().to_string());
        let sip_addr = match rtp_address {
            Some(ip) => SocketAddr::new(ip, local_addr.port()),
            None => local_addr,
        };

        // Allocate RTP port.
        let (rtp_socket, rtp_port) =
            crate::media::listen_rtp_port(self.config.rtp_port_min, self.config.rtp_port_max)?;

        // Create dialog and call.
        let sip_call_id = uuid_v4();
        let local_tag = generate_tag();
        let from_header = format!("<sip:{}@{}>;tag={}", from, sip_addr, local_tag);
        let to_header = format!("<sip:{}@{}>", to, remote_addr);

        let dialog = Arc::new(TrunkDialog::new_outbound(
            sip_tx.clone(),
            sip_addr,
            remote_addr,
            sip_call_id.clone(),
            local_tag.clone(),
            from_header,
            to_header,
        ));

        let call = Call::new_outbound(dialog.clone(), DialOptions::default());
        call.set_local_media(&local_ip, rtp_port as i32);
        call.set_rtp_socket(rtp_socket);

        // Build and send SDP offer.
        let codec_prefs: Vec<i32> = vec![0, 8, 101]; // PCMU, PCMA, telephone-event
        let sdp = crate::sdp::build_offer(&local_ip, rtp_port as i32, &codec_prefs, "sendrecv");

        // Register in dialog map.
        {
            let mut map = dialogs.lock();
            map.insert(
                sip_call_id.clone(),
                DialogEntry {
                    call: Some(call.clone()),
                    dialog: Some(dialog),
                    created_at: Instant::now(),
                },
            );
        }

        // Wire server-level callbacks.
        wire_call_callbacks(
            &call,
            &sip_call_id,
            &self.inner,
            &dialogs,
            on_call_state_fn,
            on_call_ended_fn,
            on_call_dtmf_fn,
        );

        // Build and send INVITE.
        build_and_send_invite(&BuildInviteParams {
            sip_tx: &sip_tx,
            local_addr: sip_addr,
            remote_addr,
            sip_call_id: &sip_call_id,
            local_tag: &local_tag,
            from,
            to,
            sdp: &sdp,
        });

        Ok(call)
    }

    /// Starts the SIP trunk server, listening for incoming SIP traffic.
    ///
    /// This method binds a UDP socket on the configured address, spawns background
    /// tasks for sending SIP messages and cleaning up stale dialogs, then enters
    /// the main receive loop.
    ///
    /// This is a blocking async call — it runs until the server encounters an
    /// unrecoverable error. To run the server in the background while calling
    /// [`dial()`](Self::dial), clone the `Server` and spawn `listen()` on a
    /// separate tokio task.
    pub async fn listen(&self) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(&self.config.listen)
                .await
                .map_err(|e| Error::Other(format!("bind failed: {e}")))?,
        );
        self.listen_inner(socket).await
    }

    /// Starts the SIP trunk server using a pre-bound UDP socket.
    ///
    /// Use this when you need control over the socket (e.g., `SO_REUSEPORT` for
    /// zero-downtime deploys). The socket must already be bound to the desired address.
    ///
    /// ```rust,ignore
    /// let std_socket = std::net::UdpSocket::bind("0.0.0.0:5080").unwrap();
    /// // set_nonblocking is called automatically by listen_with_socket
    /// let server = Server::new(config);
    /// server.listen_with_socket(std_socket).await.unwrap();
    /// ```
    pub async fn listen_with_socket(&self, socket: std::net::UdpSocket) -> Result<()> {
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::Other(format!("set_nonblocking failed: {e}")))?;
        let socket = Arc::new(
            UdpSocket::from_std(socket)
                .map_err(|e| Error::Other(format!("from_std failed: {e}")))?,
        );
        self.listen_inner(socket).await
    }

    async fn listen_inner(&self, socket: Arc<UdpSocket>) -> Result<()> {
        let local_addr = socket
            .local_addr()
            .map_err(|e| Error::Other(format!("local_addr failed: {e}")))?;
        info!("trunk server listening on {}", local_addr);

        let (sip_tx, mut sip_rx) = mpsc::channel::<SipOutgoing>(4096);

        // Store in inner for dial() access.
        let dialogs = {
            let mut inner = self.inner.lock();
            inner.sip_tx = Some(sip_tx.clone());
            inner.local_addr = Some(local_addr);
            inner.dialogs.clone()
        };

        // Spawn send task: drains outgoing SIP messages and sends via socket.
        let send_socket = socket.clone();
        tokio::spawn(async move {
            while let Some(msg) = sip_rx.recv().await {
                if let Err(e) = send_socket.send_to(&msg.data, msg.addr).await {
                    warn!("trunk SIP send error: {e}");
                }
            }
        });

        // Spawn dialog TTL reaper.
        let reaper_dialogs = dialogs.clone();
        tokio::spawn(async move {
            reap_stale_dialogs(reaper_dialogs).await;
        });

        let mut buf = vec![0u8; 65535];
        loop {
            let (len, addr) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| Error::Other(format!("recv failed: {e}")))?;

            let msg = match message::parse(&buf[..len]) {
                Ok(m) => m,
                Err(_) => {
                    debug!("ignoring unparseable SIP from {addr}");
                    continue;
                }
            };

            if msg.is_response() {
                self.handle_response(&msg, &dialogs, &sip_tx, local_addr);
                continue;
            }

            match msg.method.as_str() {
                "OPTIONS" => handle_options(&socket, addr, &msg).await,
                "INVITE" => {
                    self.handle_invite(&socket, local_addr, addr, msg, &dialogs, &sip_tx)
                        .await
                }
                "ACK" => {
                    debug!("ACK received for Call-ID={}", msg.header("Call-ID"));
                }
                "BYE" => self.handle_bye(&socket, addr, &msg, &dialogs).await,
                "CANCEL" => handle_cancel(&socket, addr, &msg, &dialogs).await,
                "NOTIFY" => handle_notify(&socket, addr, &msg, &dialogs).await,
                other => {
                    debug!("unsupported SIP method '{other}' from {addr}");
                    send_sip_response(&socket, addr, &msg, 405, "Method Not Allowed").await;
                }
            }
        }
    }

    /// Stops the server and ends all active calls.
    pub fn stop(&self) {
        let dialogs = {
            let mut inner = self.inner.lock();
            inner.sip_tx = None;
            inner.local_addr = None;
            inner.dialogs.clone()
        };
        // Drain outside inner lock; drain dialogs to release Arc<TrunkDialog>/sip_tx.
        let entries: Vec<DialogEntry> = dialogs.lock().drain().map(|(_, e)| e).collect();
        for entry in entries {
            if let Some(call) = entry.call {
                if call.state() != CallState::Ended {
                    let _ = call.end();
                }
            }
        }
    }

    /// Returns the local address the server is bound to, if listening.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().local_addr
    }

    /// Returns the number of active calls.
    pub fn call_count(&self) -> usize {
        let dialogs = self.inner.lock().dialogs.clone();
        let map = dialogs.lock();
        map.values().filter(|e| e.call.is_some()).count()
    }

    /// Returns all active calls.
    pub fn calls(&self) -> Vec<Arc<Call>> {
        let dialogs = self.inner.lock().dialogs.clone();
        let map = dialogs.lock();
        map.values().filter_map(|e| e.call.clone()).collect()
    }

    /// Finds an active call by SIP Call-ID.
    pub fn find_call(&self, call_id: &str) -> Option<Arc<Call>> {
        let dialogs = self.inner.lock().dialogs.clone();
        let map = dialogs.lock();
        map.values()
            .filter_map(|e| e.call.as_ref())
            .find(|c| c.call_id() == call_id)
            .cloned()
    }

    // ── SIP Handlers ──

    #[allow(clippy::too_many_arguments)]
    async fn handle_invite(
        &self,
        socket: &Arc<UdpSocket>,
        local_addr: SocketAddr,
        addr: SocketAddr,
        msg: Message,
        dialogs: &DialogMap,
        sip_tx: &mpsc::Sender<SipOutgoing>,
    ) {
        let source_ip = addr.ip();

        match auth::authenticate(&self.config, &msg, source_ip) {
            AuthResult::Authenticated(peer_name) => {
                info!("authenticated INVITE from peer '{peer_name}' at {addr}");

                // Send 100 Trying immediately.
                send_sip_response(socket, addr, &msg, 100, "Trying").await;

                let sip_call_id = msg.header("Call-ID").to_string();

                // Guard against re-INVITE on existing dialog.
                {
                    let map = dialogs.lock();
                    if map
                        .get(&sip_call_id)
                        .and_then(|e| e.call.as_ref())
                        .is_some()
                    {
                        debug!("re-INVITE on existing dialog Call-ID={sip_call_id}, ignoring");
                        return;
                    }
                }

                // Insert placeholder dialog entry.
                {
                    let mut map = dialogs.lock();
                    map.insert(
                        sip_call_id.clone(),
                        DialogEntry {
                            call: None,
                            dialog: None,
                            created_at: Instant::now(),
                        },
                    );
                }

                // Per-peer rtp_address takes priority over server-level.
                let rtp_address = self
                    .config
                    .peers
                    .iter()
                    .find(|p| p.name == peer_name)
                    .and_then(|p| p.rtp_address)
                    .or(self.config.rtp_address);

                let sip_addr = match rtp_address {
                    Some(ip) => SocketAddr::new(ip, local_addr.port()),
                    None => local_addr,
                };

                let rtp_port_min = self.config.rtp_port_min;
                let rtp_port_max = self.config.rtp_port_max;
                let server = self.clone();
                let sip_tx = sip_tx.clone();
                let dialogs = dialogs.clone();

                tokio::spawn(async move {
                    server.handle_incoming_call(
                        &msg,
                        peer_name,
                        sip_call_id,
                        sip_tx,
                        sip_addr,
                        addr,
                        rtp_port_min,
                        rtp_port_max,
                        rtp_address,
                        &dialogs,
                    );
                });
            }
            AuthResult::Challenge { realm, nonce } => {
                info!("challenging INVITE from {addr} (no IP match)");
                let mut resp = Message::new_response(401, "Unauthorized");
                copy_dialog_headers(&msg, &mut resp);
                resp.set_header(
                    "WWW-Authenticate",
                    &auth::build_www_authenticate(&realm, &nonce),
                );
                let data = resp.to_bytes();
                if let Err(e) = socket.send_to(&data, addr).await {
                    warn!("SIP send to {addr} failed: {e}");
                }
            }
            AuthResult::Rejected => {
                warn!("rejected INVITE from unknown source {addr}");
                send_sip_response(socket, addr, &msg, 403, "Forbidden").await;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_incoming_call(
        &self,
        invite: &Message,
        peer_name: String,
        sip_call_id: String,
        sip_tx: mpsc::Sender<SipOutgoing>,
        sip_addr: SocketAddr,
        remote_addr: SocketAddr,
        rtp_port_min: u16,
        rtp_port_max: u16,
        rtp_address: Option<std::net::IpAddr>,
        dialogs: &DialogMap,
    ) {
        let from = extract_uri_user(invite.header("From")).to_string();
        let to = extract_uri_user(invite.header("To")).to_string();
        info!("trunk incoming call from peer '{peer_name}': {from} → {to}");

        // Allocate RTP port.
        let (rtp_socket, rtp_port) = match crate::media::listen_rtp_port(rtp_port_min, rtp_port_max)
        {
            Ok(pair) => pair,
            Err(e) => {
                error!("RTP port allocation failed: {e}");
                send_reject_via_channel(&sip_tx, invite, remote_addr, 503, "Service Unavailable");
                dialogs.lock().remove(&sip_call_id);
                return;
            }
        };

        // Create TrunkDialog + Call.
        let local_tag = generate_tag();
        let dialog = Arc::new(TrunkDialog::new(
            sip_tx,
            sip_addr,
            remote_addr,
            invite,
            local_tag,
        ));

        let call = Call::new_inbound(dialog.clone());

        let local_ip = rtp_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| sip_addr.ip().to_string());

        call.set_local_media(&local_ip, rtp_port as i32);
        call.set_rtp_socket(rtp_socket);

        // Set remote SDP from INVITE body.
        if !invite.body.is_empty() {
            if let Ok(sdp_str) = std::str::from_utf8(&invite.body) {
                call.set_remote_sdp(sdp_str);
            }
        }

        // Update dialog entry with call + dialog.
        {
            let mut map = dialogs.lock();
            if let Some(entry) = map.get_mut(&sip_call_id) {
                entry.call = Some(call.clone());
                entry.dialog = Some(dialog);
            }
        }

        // Wire server-level callbacks (single lock acquisition).
        let (on_call_state_fn, on_call_ended_fn, on_call_dtmf_fn) = {
            let inner = self.inner.lock();
            (
                inner.on_call_state_fn.clone(),
                inner.on_call_ended_fn.clone(),
                inner.on_call_dtmf_fn.clone(),
            )
        };
        wire_call_callbacks(
            &call,
            &sip_call_id,
            &self.inner,
            dialogs,
            on_call_state_fn,
            on_call_ended_fn,
            on_call_dtmf_fn,
        );

        // Fire incoming callbacks.
        let incoming_fns = self.inner.lock().incoming_fn.clone();
        if incoming_fns.is_empty() {
            warn!("no on_incoming handler, rejecting call");
            if let Some(entry) = dialogs.lock().remove(&sip_call_id) {
                if let Some(c) = entry.call {
                    let _ = c.reject(480, "No handler");
                }
            }
        } else {
            for f in &incoming_fns {
                f(Arc::clone(&call));
            }
        }
    }

    async fn handle_bye(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        msg: &Message,
        dialogs: &DialogMap,
    ) {
        let sip_call_id = msg.header("Call-ID").to_string();
        debug!("BYE from {addr} for Call-ID={sip_call_id}");

        let entry = dialogs.lock().remove(&sip_call_id);
        if let Some(entry) = entry {
            if let Some(call) = entry.call {
                call.simulate_bye();
            }
        }

        send_sip_response(socket, addr, msg, 200, "OK").await;
    }

    fn handle_response(
        &self,
        msg: &Message,
        dialogs: &DialogMap,
        sip_tx: &mpsc::Sender<SipOutgoing>,
        local_addr: SocketAddr,
    ) {
        let code = msg.status_code;
        let (_, cseq_method) = msg.cseq();

        // Only handle responses to INVITE (skip BYE/CANCEL/OPTIONS responses).
        if !cseq_method.eq_ignore_ascii_case("INVITE") {
            return;
        }

        let sip_call_id = msg.header("Call-ID").to_string();
        debug!("SIP response {code} for Call-ID={sip_call_id}");

        let (call, trunk_dialog) = {
            let map = dialogs.lock();
            let entry = match map.get(&sip_call_id) {
                Some(e) => e,
                None => {
                    debug!("no dialog for response Call-ID={sip_call_id}");
                    return;
                }
            };
            (entry.call.clone(), entry.dialog.clone())
        };

        let call = match call {
            Some(c) => c,
            None => return,
        };

        match code {
            100 => {
                debug!("100 Trying for outbound Call-ID={sip_call_id}");
            }
            180 | 183 => {
                if let Some(ref dlg) = trunk_dialog {
                    dlg.update_from_response(msg);
                }
                call.simulate_response(code, &msg.reason);
            }
            200..=299 => {
                if let Some(ref dlg) = trunk_dialog {
                    dlg.update_from_response(msg);
                }
                if !msg.body.is_empty() {
                    if let Ok(sdp_str) = std::str::from_utf8(&msg.body) {
                        call.set_remote_sdp(sdp_str);
                    }
                }
                call.simulate_response(200, "OK");
                send_ack(sip_tx, msg, &sip_call_id, local_addr);
            }
            _ => {
                warn!("outbound call {sip_call_id} rejected with {code}");
                call.simulate_bye();
                dialogs.lock().remove(&sip_call_id);
            }
        }
    }
}

// ── Free functions ──

async fn handle_options(socket: &UdpSocket, addr: SocketAddr, msg: &Message) {
    debug!("OPTIONS from {addr}");
    let mut resp = Message::new_response(200, "OK");
    copy_dialog_headers(msg, &mut resp);
    resp.set_header("Allow", "INVITE,ACK,BYE,CANCEL,OPTIONS");
    let data = resp.to_bytes();
    if let Err(e) = socket.send_to(&data, addr).await {
        warn!("SIP send to {addr} failed: {e}");
    }
}

async fn handle_cancel(socket: &UdpSocket, addr: SocketAddr, msg: &Message, dialogs: &DialogMap) {
    let sip_call_id = msg.header("Call-ID").to_string();
    debug!("CANCEL from {addr} for Call-ID={sip_call_id}");

    let removed = dialogs.lock().remove(&sip_call_id);
    send_sip_response(socket, addr, msg, 200, "OK").await;

    if let Some(entry) = removed {
        if let Some(call) = entry.call {
            call.simulate_bye();
        }

        // Send 487 Request Terminated for the original INVITE.
        let mut resp = Message::new_response(487, "Request Terminated");
        copy_dialog_headers(msg, &mut resp);
        let (seq, _) = msg.cseq();
        resp.set_header("CSeq", &format!("{seq} INVITE"));
        let data = resp.to_bytes();
        if let Err(e) = socket.send_to(&data, addr).await {
            warn!("SIP send to {addr} failed: {e}");
        }
    }
}

async fn handle_notify(socket: &UdpSocket, addr: SocketAddr, msg: &Message, dialogs: &DialogMap) {
    let sip_call_id = msg.header("Call-ID").to_string();
    info!(call_id = %sip_call_id, "NOTIFY from {addr}");

    // Always respond 200 OK to NOTIFY.
    send_sip_response(socket, addr, msg, 200, "OK").await;

    // Parse sipfrag status from the NOTIFY body (e.g., "SIP/2.0 200 OK" → 200).
    let body = String::from_utf8_lossy(&msg.body);
    let status_code = body
        .lines()
        .next()
        .filter(|line| line.trim().starts_with("SIP/"))
        .and_then(|line| line.trim().split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok());

    if let Some(code) = status_code {
        let call = dialogs
            .lock()
            .get(&sip_call_id)
            .and_then(|e| e.call.clone());
        if let Some(call) = call {
            info!(call_id = %sip_call_id, code = code, "dispatching NOTIFY to call");
            call.fire_notify(code);
        } else {
            debug!(call_id = %sip_call_id, "NOTIFY for unknown dialog");
        }
    } else {
        debug!(call_id = %sip_call_id, "NOTIFY without parseable sipfrag status");
    }
}

async fn send_sip_response(
    socket: &UdpSocket,
    addr: SocketAddr,
    req: &Message,
    code: u16,
    reason: &str,
) {
    let mut resp = Message::new_response(code, reason);
    copy_dialog_headers(req, &mut resp);
    let data = resp.to_bytes();
    if let Err(e) = socket.send_to(&data, addr).await {
        warn!("SIP send to {addr} failed: {e}");
    }
}

fn copy_dialog_headers(req: &Message, resp: &mut Message) {
    for via in req.header_values("Via") {
        resp.add_header("Via", via);
    }
    resp.set_header("From", req.header("From"));
    resp.set_header("To", &ensure_to_tag(req.header("To"), resp.status_code));
    resp.set_header("Call-ID", req.header("Call-ID"));
    resp.set_header("CSeq", req.header("CSeq"));
}

fn send_reject_via_channel(
    tx: &mpsc::Sender<SipOutgoing>,
    invite: &Message,
    remote_addr: SocketAddr,
    code: u16,
    reason: &str,
) {
    let mut resp = Message::new_response(code, reason);
    copy_dialog_headers(invite, &mut resp);
    if let Err(e) = tx.try_send(SipOutgoing {
        data: resp.to_bytes(),
        addr: remote_addr,
    }) {
        warn!("failed to send SIP {code} reject to {remote_addr}: {e}");
    }
}

fn send_ack(
    tx: &mpsc::Sender<SipOutgoing>,
    ok_response: &Message,
    sip_call_id: &str,
    local_addr: SocketAddr,
) {
    let contact = ok_response.header("Contact");
    let request_uri = if !contact.is_empty() {
        extract_uri(contact).to_string()
    } else {
        let to = ok_response.header("To");
        extract_uri(to).to_string()
    };

    let dest_addr =
        parse_addr_from_uri(&request_uri).unwrap_or_else(|| "0.0.0.0:5060".parse().unwrap());

    let branch = generate_branch();
    let mut ack = Message::new_request("ACK", &request_uri);
    ack.set_header("Via", &format!("SIP/2.0/UDP {local_addr};branch={branch}"));
    ack.set_header("From", ok_response.header("From"));
    ack.set_header("To", ok_response.header("To"));
    ack.set_header("Call-ID", sip_call_id);
    let (cseq_num, _) = ok_response.cseq();
    ack.set_header("CSeq", &format!("{cseq_num} ACK"));

    if let Err(e) = tx.try_send(SipOutgoing {
        data: ack.to_bytes(),
        addr: dest_addr,
    }) {
        warn!("failed to send ACK for Call-ID={sip_call_id}: {e}");
    }
}

/// Extract a `SocketAddr` from a SIP URI (e.g. `sip:1001@10.0.0.1:5060`).
/// Strips the `user@` prefix and delegates to `sip::resolve_host`.
fn parse_addr_from_uri(uri: &str) -> Option<SocketAddr> {
    let host_part = uri.split('@').nth(1)?;
    crate::sip::resolve_host(host_part, 5060)
}

struct BuildInviteParams<'a> {
    sip_tx: &'a mpsc::Sender<SipOutgoing>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    sip_call_id: &'a str,
    local_tag: &'a str,
    from: &'a str,
    to: &'a str,
    sdp: &'a str,
}

fn build_and_send_invite(params: &BuildInviteParams<'_>) {
    let branch = generate_branch();
    let request_uri = format!("sip:{}@{}", params.to, params.remote_addr);

    let mut invite = Message::new_request("INVITE", &request_uri);
    invite.set_header(
        "Via",
        &format!("SIP/2.0/UDP {};branch={branch}", params.local_addr),
    );
    invite.set_header(
        "From",
        &format!(
            "<sip:{}@{}>;tag={}",
            params.from, params.local_addr, params.local_tag
        ),
    );
    invite.set_header("To", &format!("<sip:{}@{}>", params.to, params.remote_addr));
    invite.set_header("Call-ID", params.sip_call_id);
    invite.set_header("CSeq", "1 INVITE");
    invite.set_header("Contact", &format!("<sip:xphone@{}>", params.local_addr));
    invite.set_header("Max-Forwards", "70");
    invite.set_header("Content-Type", "application/sdp");
    invite.body = params.sdp.as_bytes().to_vec();

    if let Err(e) = params.sip_tx.try_send(SipOutgoing {
        data: invite.to_bytes(),
        addr: params.remote_addr,
    }) {
        warn!("failed to send INVITE to {}: {e}", params.remote_addr);
    }
}

/// Wire server-level callbacks to a call.
fn wire_call_callbacks(
    call: &Arc<Call>,
    sip_call_id: &str,
    _server_inner: &Arc<Mutex<Inner>>,
    dialogs: &DialogMap,
    on_call_state_fns: Vec<CallStateCb>,
    on_call_ended_fns: Vec<CallEndedCb>,
    on_call_dtmf_fns: Vec<CallDtmfCb>,
) {
    if !on_call_state_fns.is_empty() {
        let call2 = call.clone();
        call.on_state(move |state| {
            for f in &on_call_state_fns {
                f(call2.clone(), state);
            }
        });
    }

    // Always wire on_ended for cleanup; optionally invoke user callbacks.
    {
        let call2 = call.clone();
        let sip_call_id = sip_call_id.to_string();
        let dialogs = dialogs.clone();
        call.on_ended(move |reason| {
            dialogs.lock().remove(&sip_call_id);
            for f in &on_call_ended_fns {
                f(call2.clone(), reason);
            }
        });
    }

    if !on_call_dtmf_fns.is_empty() {
        let call2 = call.clone();
        call.on_dtmf(move |digit| {
            for f in &on_call_dtmf_fns {
                f(call2.clone(), digit.clone());
            }
        });
    }
}

/// Periodically scan trunk dialogs and remove entries that have exceeded their TTL.
///
/// Collects stale entries under the lock, then drops the lock before calling
/// `simulate_bye()` — which fires `on_ended` callbacks that also acquire the lock.
async fn reap_stale_dialogs(dialogs: DialogMap) {
    loop {
        tokio::time::sleep(REAP_INTERVAL).await;

        let now = Instant::now();
        let stale: Vec<Option<Arc<Call>>> = {
            let mut map = dialogs.lock();
            let mut stale = Vec::new();
            map.retain(|sip_call_id, entry| {
                let age = now.duration_since(entry.created_at);
                let ttl = if entry.call.is_some() {
                    ACTIVE_TTL
                } else {
                    SETUP_TTL
                };
                if age > ttl {
                    warn!("reaping stale dialog {sip_call_id} (age={age:.0?})");
                    stale.push(entry.call.clone());
                    false
                } else {
                    true
                }
            });
            stale
        };
        // Lock dropped — safe to call simulate_bye (which may re-acquire the lock).
        for call in stale.iter().flatten() {
            call.simulate_bye();
        }
        if !stale.is_empty() {
            info!("reaped {} stale trunk dialog(s)", stale.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_dialog_headers_preserves_via() {
        let mut req = Message::new_request("INVITE", "sip:1002@xphone:5080");
        req.add_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        req.add_header("Via", "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK222");
        req.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        req.set_header("To", "<sip:1002@xphone:5080>");
        req.set_header("Call-ID", "test@host");
        req.set_header("CSeq", "1 INVITE");

        let mut resp = Message::new_response(200, "OK");
        copy_dialog_headers(&req, &mut resp);

        assert_eq!(resp.header_values("Via").len(), 2);
        assert_eq!(resp.header("Call-ID"), "test@host");
        assert_eq!(resp.header("CSeq"), "1 INVITE");
        assert!(resp.header("From").contains("tag=from1"));
        assert!(resp.header("To").contains("tag="));
    }

    #[test]
    fn copy_dialog_headers_100_no_to_tag() {
        let mut req = Message::new_request("INVITE", "sip:1002@xphone:5080");
        req.add_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        req.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        req.set_header("To", "<sip:1002@xphone:5080>");
        req.set_header("Call-ID", "test@host");
        req.set_header("CSeq", "1 INVITE");

        let mut resp = Message::new_response(100, "Trying");
        copy_dialog_headers(&req, &mut resp);

        assert!(!resp.header("To").contains("tag="));
    }

    #[test]
    fn send_reject_via_channel_builds_response() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut invite = Message::new_request("INVITE", "sip:1002@xphone:5080");
        invite.add_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK111");
        invite.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        invite.set_header("To", "<sip:1002@xphone:5080>");
        invite.set_header("Call-ID", "test@host");
        invite.set_header("CSeq", "1 INVITE");

        send_reject_via_channel(
            &tx,
            &invite,
            "10.0.0.1:5060".parse().unwrap(),
            486,
            "Busy Here",
        );

        let outgoing = rx.try_recv().unwrap();
        let msg = message::parse(&outgoing.data).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.status_code, 486);
        assert_eq!(msg.header("Call-ID"), "test@host");
        assert_eq!(
            outgoing.addr,
            "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn send_ack_uses_contact_for_request_uri() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut ok_resp = Message::new_response(200, "OK");
        ok_resp.set_header("From", "<sip:1001@127.0.0.1:5080>;tag=local1");
        ok_resp.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=remote1");
        ok_resp.set_header("Call-ID", "ack-test@xphone");
        ok_resp.set_header("CSeq", "1 INVITE");
        ok_resp.set_header("Contact", "<sip:1002@10.0.0.1:5060>");

        send_ack(
            &tx,
            &ok_resp,
            "ack-test@xphone",
            "127.0.0.1:5080".parse().unwrap(),
        );

        let outgoing = rx.try_recv().unwrap();
        let msg = message::parse(&outgoing.data).unwrap();
        assert_eq!(msg.method, "ACK");
        assert_eq!(msg.request_uri, "sip:1002@10.0.0.1:5060");
        assert_eq!(msg.header("Call-ID"), "ack-test@xphone");
        assert_eq!(msg.header("CSeq"), "1 ACK");
        assert!(msg.header("From").contains("tag=local1"));
        assert!(msg.header("To").contains("tag=remote1"));
        assert_eq!(
            outgoing.addr,
            "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn send_ack_falls_back_to_to_header() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut ok_resp = Message::new_response(200, "OK");
        ok_resp.set_header("From", "<sip:1001@127.0.0.1:5080>;tag=local1");
        ok_resp.set_header("To", "<sip:1002@10.0.0.1:5060>;tag=remote1");
        ok_resp.set_header("Call-ID", "ack-test@xphone");
        ok_resp.set_header("CSeq", "1 INVITE");

        send_ack(
            &tx,
            &ok_resp,
            "ack-test@xphone",
            "127.0.0.1:5080".parse().unwrap(),
        );

        let outgoing = rx.try_recv().unwrap();
        let msg = message::parse(&outgoing.data).unwrap();
        assert_eq!(msg.method, "ACK");
        assert_eq!(msg.request_uri, "sip:1002@10.0.0.1:5060");
    }

    #[test]
    fn parse_addr_from_sip_uri() {
        assert_eq!(
            parse_addr_from_uri("sip:1001@10.0.0.1:5060"),
            Some("10.0.0.1:5060".parse().unwrap())
        );
        assert_eq!(
            parse_addr_from_uri("sip:1001@192.168.1.1"),
            Some("192.168.1.1:5060".parse().unwrap())
        );
        assert!(parse_addr_from_uri("sip:1001").is_none());
    }

    #[test]
    fn parse_addr_from_uri_with_params() {
        assert_eq!(
            parse_addr_from_uri("sip:1001@10.0.0.1:5060;transport=udp"),
            Some("10.0.0.1:5060".parse().unwrap())
        );
    }

    #[test]
    fn build_outbound_invite_message() {
        let (tx, mut rx) = mpsc::channel(64);
        build_and_send_invite(&BuildInviteParams {
            sip_tx: &tx,
            local_addr: "127.0.0.1:5080".parse().unwrap(),
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            sip_call_id: "test-call-id@xphone",
            local_tag: "localtag1",
            from: "1001",
            to: "1002",
            sdp: "v=0\r\n",
        });

        let outgoing = rx.try_recv().unwrap();
        let msg = message::parse(&outgoing.data).unwrap();
        assert!(!msg.is_response());
        assert_eq!(msg.method, "INVITE");
        assert_eq!(msg.request_uri, "sip:1002@10.0.0.1:5060");
        assert_eq!(msg.header("Call-ID"), "test-call-id@xphone");
        assert!(msg.header("From").contains("1001@127.0.0.1:5080"));
        assert!(msg.header("From").contains("tag=localtag1"));
        assert!(msg.header("To").contains("1002@10.0.0.1:5060"));
        assert_eq!(msg.header("CSeq"), "1 INVITE");
        assert_eq!(msg.header("Content-Type"), "application/sdp");
        assert_eq!(String::from_utf8_lossy(&msg.body), "v=0\r\n");
        assert_eq!(
            outgoing.addr,
            "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn server_new_and_callbacks() {
        let server = Server::new(ServerConfig::default());

        // Callbacks can be set before listen().
        server.on_incoming(|_call| {});
        server.on_call_state(|_call, _state| {});
        server.on_call_ended(|_call, _reason| {});
        server.on_call_dtmf(|_call, _digit| {});

        assert_eq!(server.call_count(), 0);
    }

    #[test]
    fn server_dial_without_listen_fails() {
        let server = Server::new(ServerConfig::default());
        let result = server.dial("peer", "1002", "1001");
        assert!(result.is_err());
    }

    #[test]
    fn server_dial_uri_without_listen_fails() {
        let server = Server::new(ServerConfig::default());
        let result = server.dial_uri("sip:1002@10.0.0.1:5060", "1001");
        assert!(result.is_err());
    }

    #[test]
    fn server_dial_uri_bad_uri_fails() {
        let server = Server::new(ServerConfig::default());
        let result = server.dial_uri("not-a-sip-uri", "1001");
        let err = result.err().expect("expected error");
        assert!(err.to_string().contains("cannot parse"));
    }

    #[test]
    fn server_dial_uri_no_user_part_fails() {
        let server = Server::new(ServerConfig::default());
        // No @ sign → parse_addr_from_uri fails first.
        assert!(server.dial_uri("sip:10.0.0.1:5060", "1001").is_err());
        // Empty user part → caught by user validation.
        let err = server
            .dial_uri("sip:@10.0.0.1:5060", "1001")
            .err()
            .expect("expected error");
        assert!(err.to_string().contains("no user part"));
    }

    #[test]
    fn reap_inline_removes_stale() {
        let dialogs: DialogMap = Arc::new(Mutex::new(HashMap::new()));

        // Stale entry (past TTL).
        dialogs.lock().insert(
            "stale@xphone".into(),
            DialogEntry {
                call: None,
                dialog: None,
                created_at: Instant::now() - SETUP_TTL - std::time::Duration::from_secs(1),
            },
        );

        // Fresh entry.
        dialogs.lock().insert(
            "fresh@xphone".into(),
            DialogEntry {
                call: None,
                dialog: None,
                created_at: Instant::now(),
            },
        );

        assert_eq!(dialogs.lock().len(), 2);

        // Inline reap.
        {
            let now = Instant::now();
            let mut map = dialogs.lock();
            map.retain(|_, entry| {
                let age = now.duration_since(entry.created_at);
                let ttl = if entry.call.is_some() {
                    ACTIVE_TTL
                } else {
                    SETUP_TTL
                };
                age <= ttl
            });
        }

        assert_eq!(dialogs.lock().len(), 1);
        assert!(dialogs.lock().get("stale@xphone").is_none());
        assert!(dialogs.lock().get("fresh@xphone").is_some());
    }

    #[tokio::test]
    async fn handle_notify_dispatches_sipfrag_to_call() {
        use crate::mock::dialog::MockDialog;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Create an inbound call, accept it, then start a blind transfer.
        let mock = Arc::new(MockDialog::new());
        let call = Call::new_inbound(mock.clone());
        call.accept().unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        call.on_ended(move |reason| {
            let _ = tx.send(reason);
        });
        call.blind_transfer("sip:1003@pbx.local").unwrap();

        let dialogs: DialogMap = Arc::new(Mutex::new(HashMap::new()));
        dialogs.lock().insert(
            "notify-test@xphone".into(),
            DialogEntry {
                call: Some(call),
                dialog: None,
                created_at: Instant::now(),
            },
        );

        // Build a NOTIFY with sipfrag "SIP/2.0 200 OK" body.
        let mut notify = Message::new_request("NOTIFY", "sip:xphone@127.0.0.1:5080");
        notify.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnotify1");
        notify.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        notify.set_header("To", "<sip:3004@xphone:5080>;tag=to1");
        notify.set_header("Call-ID", "notify-test@xphone");
        notify.set_header("CSeq", "1 NOTIFY");
        notify.set_header("Event", "refer");
        notify.set_header("Content-Type", "message/sipfrag");
        notify.body = b"SIP/2.0 200 OK\r\n".to_vec();

        handle_notify(&socket, addr, &notify, &dialogs).await;

        // The call should end with Transfer reason.
        let reason = rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .unwrap();
        assert_eq!(reason, EndReason::Transfer);
        // Dialog should NOT be removed by handle_notify itself.
        assert!(dialogs.lock().contains_key("notify-test@xphone"));
    }

    #[tokio::test]
    async fn handle_notify_unknown_dialog_does_not_panic() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let dialogs: DialogMap = Arc::new(Mutex::new(HashMap::new()));

        let mut notify = Message::new_request("NOTIFY", "sip:xphone@127.0.0.1:5080");
        notify.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnotify2");
        notify.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        notify.set_header("To", "<sip:3004@xphone:5080>;tag=to1");
        notify.set_header("Call-ID", "unknown@xphone");
        notify.set_header("CSeq", "1 NOTIFY");
        notify.set_header("Event", "refer");
        notify.set_header("Content-Type", "message/sipfrag");
        notify.body = b"SIP/2.0 200 OK\r\n".to_vec();

        // Should not panic — just logs debug.
        handle_notify(&socket, addr, &notify, &dialogs).await;
    }

    #[tokio::test]
    async fn handle_notify_no_sipfrag_body() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let dialogs: DialogMap = Arc::new(Mutex::new(HashMap::new()));

        let mut notify = Message::new_request("NOTIFY", "sip:xphone@127.0.0.1:5080");
        notify.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnotify3");
        notify.set_header("From", "<sip:1001@pbx.local>;tag=from1");
        notify.set_header("To", "<sip:3004@xphone:5080>;tag=to1");
        notify.set_header("Call-ID", "empty-body@xphone");
        notify.set_header("CSeq", "1 NOTIFY");
        notify.set_header("Event", "refer");

        // Empty body — should not dispatch, just log debug.
        handle_notify(&socket, addr, &notify, &dialogs).await;
    }
}
