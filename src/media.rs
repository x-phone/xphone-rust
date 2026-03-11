use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::callback_pool::spawn_callback;
use crate::codec::{self, CodecProcessor};
use crate::dtmf;
use crate::ice::IceAgent;
use crate::jitter::JitterBuffer;
use crate::rtcp::{self, RtcpStats};
use crate::srtp::SrtpContext;
use crate::stun;
use crate::turn;
use crate::types::*;

/// Default media configuration values.
const DEFAULT_MEDIA_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_JITTER_DEPTH: Duration = Duration::from_millis(50);
const DEFAULT_PCM_RATE: i32 = 8000;
const CHANNEL_CAPACITY: usize = 256;

/// Maximum number of frames held in the paced writer buffer (30 seconds at 20ms/frame).
const MAX_PACED_FRAMES: usize = 1500;

/// Deep-clone an RtpPacket so each tap is independent.
pub fn clone_packet(pkt: &RtpPacket) -> RtpPacket {
    pkt.clone()
}

/// Send a packet to a bounded channel; if full, drain one oldest entry first.
pub fn send_drop_oldest<T>(tx: &Sender<T>, rx: &Receiver<T>, item: T) {
    match tx.try_send(item) {
        Ok(()) => {}
        Err(TrySendError::Full(item)) => {
            let _ = rx.try_recv(); // drop oldest
            let _ = tx.try_send(item);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

/// Configuration for the media pipeline.
pub struct MediaConfig {
    /// How long to wait without RTP before firing a media timeout.
    pub media_timeout: Duration,
    /// Playout delay for the jitter buffer.
    pub jitter_depth: Duration,
    /// PCM sample rate in Hz (typically 8000).
    pub pcm_rate: i32,
    /// Audio codec to use for encoding/decoding.
    pub codec: Codec,
    /// SRTP context for inbound (decrypt). None = plain RTP.
    pub srtp_inbound: Option<SrtpContext>,
    /// SRTP context for outbound (encrypt). None = plain RTP.
    pub srtp_outbound: Option<SrtpContext>,
    /// Optional RTCP socket (RTP port + 1). None = no RTCP.
    pub rtcp_socket: Option<Arc<UdpSocket>>,
    /// Remote RTCP address (remote RTP port + 1).
    pub rtcp_remote_addr: Option<SocketAddr>,
    /// ICE-Lite agent for handling STUN binding requests on the media socket.
    pub ice_agent: Option<Arc<IceAgent>>,
    /// TURN channel number + server address for relayed media.
    /// When set, outbound RTP is wrapped in ChannelData and sent to the TURN server.
    pub turn_relay: Option<(u16, SocketAddr)>,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            media_timeout: DEFAULT_MEDIA_TIMEOUT,
            jitter_depth: DEFAULT_JITTER_DEPTH,
            pcm_rate: DEFAULT_PCM_RATE,
            codec: Codec::PCMU,
            srtp_inbound: None,
            srtp_outbound: None,
            rtcp_socket: None,
            rtcp_remote_addr: None,
            ice_agent: None,
            turn_relay: None,
        }
    }
}

/// A pair of sender and receiver for a bounded crossbeam channel.
#[derive(Clone)]
pub struct ChannelPair<T> {
    /// Sending half of the channel.
    pub tx: Sender<T>,
    /// Receiving half of the channel.
    pub rx: Receiver<T>,
}

impl<T> ChannelPair<T> {
    fn new() -> Self {
        let (tx, rx) = bounded(CHANNEL_CAPACITY);
        Self { tx, rx }
    }
}

/// All the channels used by the media pipeline.
pub struct MediaChannels {
    /// Inbound RTP from network → pipeline.
    pub rtp_inbound: ChannelPair<RtpPacket>,
    /// Pre-jitter-buffer fan-out (wire order).
    pub rtp_raw_reader: ChannelPair<RtpPacket>,
    /// Post-jitter-buffer (reordered).
    pub rtp_reader: ChannelPair<RtpPacket>,
    /// Outbound RTP from user (raw mode).
    pub rtp_writer: ChannelPair<RtpPacket>,
    /// Decoded PCM from inbound RTP.
    pub pcm_reader: ChannelPair<Vec<i16>>,
    /// PCM from user for encoding + sending (real-time, no pacing).
    pub pcm_writer: ChannelPair<Vec<i16>>,
    /// Paced PCM from user — accepts arbitrary-length buffers (e.g. from TTS),
    /// internally split into codec-frame-sized chunks and sent at 20ms intervals.
    pub paced_pcm_writer: ChannelPair<Vec<i16>>,
    /// Assembled video frames from inbound RTP (after depacketization).
    pub video_frame_reader: ChannelPair<VideoFrame>,
    /// Video frames from user for packetization + sending.
    pub video_frame_writer: ChannelPair<VideoFrame>,
    /// Test hook: outbound packets copied here.
    pub sent_rtp: Option<ChannelPair<RtpPacket>>,
}

impl MediaChannels {
    /// Creates a new set of media channels with no sent-RTP tap.
    pub fn new() -> Self {
        Self {
            rtp_inbound: ChannelPair::new(),
            rtp_raw_reader: ChannelPair::new(),
            rtp_reader: ChannelPair::new(),
            rtp_writer: ChannelPair::new(),
            pcm_reader: ChannelPair::new(),
            pcm_writer: ChannelPair::new(),
            paced_pcm_writer: ChannelPair::new(),
            video_frame_reader: ChannelPair::new(),
            video_frame_writer: ChannelPair::new(),
            sent_rtp: None,
        }
    }

    /// Enables the sent-RTP tap channel for testing outbound packets.
    pub fn with_sent_rtp(mut self) -> Self {
        self.sent_rtp = Some(ChannelPair::new());
        self
    }
}

impl Default for MediaChannels {
    fn default() -> Self {
        Self::new()
    }
}

type Callback<T> = Mutex<Option<Arc<dyn Fn(T) + Send + Sync>>>;

/// Shared mutable state the media thread reads from the call.
pub struct MediaSharedState {
    /// Current call state, used to suspend timeout while on hold.
    pub state: Mutex<CallState>,
    /// Callback fired when a DTMF digit is detected.
    pub on_dtmf_fn: Callback<String>,
    /// Callback fired when the call ends (e.g., media timeout).
    pub on_ended_fn: Callback<EndReason>,
    /// Callback fired on call state transitions.
    pub on_state_fn: Callback<CallState>,
}

impl MediaSharedState {
    /// Creates shared state with the given initial call state.
    pub fn new(initial_state: CallState) -> Self {
        Self {
            state: Mutex::new(initial_state),
            on_dtmf_fn: Mutex::new(None),
            on_ended_fn: Mutex::new(None),
            on_state_fn: Mutex::new(None),
        }
    }
}

/// A running media stream (audio or video) with its channels and mute flag.
///
/// Each stream owns its pipeline threads via `MediaHandle` and exposes
/// channels for reading/writing RTP and PCM data. The per-stream mute flag
/// is read by the media thread to suppress outbound packets.
pub struct MediaStream {
    handle: MediaHandle,
    /// Channels for this stream (RTP inbound/outbound, PCM, etc.).
    pub channels: Arc<MediaChannels>,
    /// Per-stream mute flag. When true, outbound packets are suppressed.
    pub muted: Arc<AtomicBool>,
}

impl MediaStream {
    /// Signals the media threads to stop and joins them.
    pub fn stop(&mut self) {
        self.handle.stop();
    }

    /// Returns true if the media pipeline threads have been joined.
    pub fn is_stopped(&self) -> bool {
        self.handle.thread.is_none()
    }
}

/// RTP transport for sending/receiving packets over UDP.
pub struct MediaTransport {
    /// The UDP socket for sending and receiving RTP.
    pub socket: Arc<UdpSocket>,
    /// Remote address to send outbound RTP to.
    pub remote_addr: Mutex<SocketAddr>,
}

impl MediaTransport {
    /// Wraps a UDP socket and remote address for RTP transport.
    pub fn new(socket: UdpSocket, remote_addr: SocketAddr) -> Self {
        socket
            .set_nonblocking(false)
            .expect("set_nonblocking failed");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set_read_timeout failed");
        Self {
            socket: Arc::new(socket),
            remote_addr: Mutex::new(remote_addr),
        }
    }
}

/// Allocates a UDP socket on an even port in [min, max].
/// Returns the socket and the allocated port.
pub fn listen_rtp_port(min: u16, max: u16) -> crate::error::Result<(UdpSocket, u16)> {
    let mut port = min;
    // Ensure we start on an even port (RTP convention).
    if !port.is_multiple_of(2) {
        port += 1;
    }
    while port <= max {
        match UdpSocket::bind(format!("0.0.0.0:{}", port)) {
            Ok(sock) => return Ok((sock, port)),
            Err(_) => port += 2, // Try next even port.
        }
    }
    Err(crate::error::Error::Other(format!(
        "RTP port exhaustion: no available port in range {}-{} (max {} concurrent calls). \
         Widen the range with rtp_ports() or check for leaked sockets.",
        min,
        max,
        (max - min) / 2
    )))
}

/// Binds a UDP socket for RTCP on the port adjacent to RTP (rtp_port + 1).
/// Returns the socket or an error if the port is unavailable.
pub fn listen_rtcp_port(rtp_port: u16) -> crate::error::Result<UdpSocket> {
    let rtcp_port = rtp_port + 1;
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", rtcp_port)).map_err(|e| {
        crate::error::Error::Other(format!("failed to bind RTCP port {}: {}", rtcp_port, e))
    })?;
    sock.set_read_timeout(Some(Duration::from_millis(10)))
        .expect("set_read_timeout failed");
    Ok(sock)
}

/// Handle to a running media pipeline. Drop to stop.
pub struct MediaHandle {
    done_tx: Sender<()>,
    reader_done_tx: Option<Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    reader_thread: Option<std::thread::JoinHandle<()>>,
}

impl MediaHandle {
    /// Signals the media threads to stop and joins them.
    pub fn stop(&mut self) {
        let _ = self.done_tx.try_send(());
        if let Some(ref tx) = self.reader_done_tx {
            let _ = tx.try_send(());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MediaHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Generate a random u32 for RTP SSRC.
fn rand_u32() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static RNG: Cell<u64> = Cell::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
                ^ 0x5DEECE66D
        );
    }
    RNG.with(|rng| {
        let mut s = rng.get();
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        rng.set(s);
        s as u32
    })
}

/// Start the media pipeline on a dedicated std::thread.
///
/// If `transport` is provided, spawns an additional reader thread that reads
/// UDP packets and pushes them into `channels.rtp_inbound`. Outbound packets
/// are sent via the transport's socket to the remote address.
///
/// Returns a [`MediaStream`] that owns the pipeline threads, channels, and mute flag.
pub fn start_media(
    config: MediaConfig,
    channels: Arc<MediaChannels>,
    shared: Arc<MediaSharedState>,
    transport: Option<Arc<MediaTransport>>,
    muted: Arc<AtomicBool>,
) -> MediaStream {
    let (done_tx, done_rx) = bounded::<()>(1);

    let timeout = if config.media_timeout == Duration::ZERO {
        DEFAULT_MEDIA_TIMEOUT
    } else {
        config.media_timeout
    };
    let jitter_depth = if config.jitter_depth == Duration::ZERO {
        DEFAULT_JITTER_DEPTH
    } else {
        config.jitter_depth
    };
    let pcm_rate = if config.pcm_rate == 0 {
        DEFAULT_PCM_RATE
    } else {
        config.pcm_rate
    };

    let codec_pt = config.codec.payload_type();
    let mut cp = codec::new_codec_processor(codec_pt, pcm_rate);

    // Move SRTP contexts into Mutex for thread safety.
    let srtp_in = config.srtp_inbound.map(|ctx| Arc::new(Mutex::new(ctx)));
    let srtp_out = config.srtp_outbound.map(|ctx| Arc::new(Mutex::new(ctx)));

    // RTCP socket and remote address.
    let rtcp_socket = config.rtcp_socket;
    let rtcp_remote_addr = config.rtcp_remote_addr;

    // Spawn an inbound UDP reader thread if transport is available.
    let (reader_done_tx, reader_done_rx) = bounded::<()>(1);
    let rtcp_socket_for_reader = rtcp_socket.as_ref().map(Arc::clone);
    // Channel for RTCP packets received by the reader thread.
    let (rtcp_recv_tx, rtcp_recv_rx) = bounded::<Vec<u8>>(16);
    let ice_agent = config.ice_agent;

    let reader_thread = transport.as_ref().map(|tr| {
        let socket = Arc::clone(&tr.socket);
        let inbound_tx = channels.rtp_inbound.tx.clone();
        let inbound_rx = channels.rtp_inbound.rx.clone();
        let done = reader_done_rx;
        let srtp_in_clone = srtp_in.clone();
        let rtcp_sock = rtcp_socket_for_reader;
        let rtcp_tx = rtcp_recv_tx;
        let ice = ice_agent;
        debug!("media: starting UDP reader thread");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut rtcp_buf = [0u8; 512];
            let mut pkt_count: u64 = 0;
            loop {
                if done.try_recv().is_ok() {
                    return;
                }
                match socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if n < 4 {
                            continue;
                        }

                        // Demux: STUN vs ChannelData vs RTP (RFC 5764 §5.1.2).
                        if stun::is_stun_message(&buf[..n]) {
                            // ICE connectivity check — respond if agent is configured.
                            if let Some(ref agent) = ice {
                                if let Some(resp) = agent.handle_binding_request(&buf[..n], src) {
                                    let _ = socket.send_to(&resp, src);
                                }
                            }
                            continue;
                        }

                        // ChannelData from TURN relay — unwrap and process as RTP.
                        let (rtp_slice, _channel_buf);
                        if turn::is_channel_data(&buf[..n]) {
                            match turn::parse_channel_data(&buf[..n]) {
                                Some((_ch, payload)) => {
                                    _channel_buf = payload.to_vec();
                                    rtp_slice = _channel_buf.as_slice();
                                }
                                None => continue,
                            }
                        } else {
                            rtp_slice = &buf[..n];
                        }

                        if rtp_slice.len() < 12 {
                            continue;
                        }

                        // SRTP decrypt if configured.
                        let rtp_data = if let Some(ref srtp) = srtp_in_clone {
                            match srtp.lock().unprotect(rtp_slice) {
                                Ok(decrypted) => decrypted,
                                Err(e) => {
                                    warn!(error = %e, "media: SRTP unprotect failed — dropping packet");
                                    continue;
                                }
                            }
                        } else {
                            rtp_slice.to_vec()
                        };
                        if let Some(pkt) = RtpPacket::parse(&rtp_data) {
                            pkt_count += 1;
                            if pkt_count <= 3 || pkt_count.is_multiple_of(500) {
                                debug!(
                                    pt = pkt.header.payload_type,
                                    seq = pkt.header.sequence_number,
                                    ssrc = pkt.header.ssrc,
                                    len = rtp_data.len(),
                                    total = pkt_count,
                                    "media: RTP recv"
                                );
                            }
                            send_drop_oldest(&inbound_tx, &inbound_rx, pkt);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => return,
                }

                // Non-blocking read from RTCP socket.
                if let Some(ref rsock) = rtcp_sock {
                    match rsock.recv_from(&mut rtcp_buf) {
                        Ok((n, _)) if n >= 8 => {
                            let rtcp_data = if let Some(ref srtp) = srtp_in_clone {
                                match srtp.lock().unprotect_rtcp(&rtcp_buf[..n]) {
                                    Ok(decrypted) => decrypted,
                                    Err(_) => continue, // Drop unauthenticated RTCP
                                }
                            } else {
                                rtcp_buf[..n].to_vec()
                            };
                            let _ = rtcp_tx.try_send(rtcp_data);
                        }
                        _ => {}
                    }
                }
            }
        })
    });

    let transport_for_thread = transport.clone();
    let srtp_out_for_thread = srtp_out;
    let rtcp_socket_for_thread = rtcp_socket;
    let turn_relay = config.turn_relay;
    let muted_for_thread = Arc::clone(&muted);
    let channels_for_thread = Arc::clone(&channels);
    let thread = std::thread::spawn(move || {
        let channels = channels_for_thread;
        let mut jb = JitterBuffer::new(jitter_depth);
        let mut out_seq: u16 = 0;
        let mut out_timestamp: u32 = 0;
        let out_ssrc = rand_u32();
        let mut rtp_writer_used = false;
        let mut paced_writer_used = false;
        let mut last_dtmf_timestamp: u32 = 0;
        let mut last_dtmf_seen = false;

        let mut last_rtp_time = Instant::now();
        let jitter_tick = crossbeam_channel::tick(Duration::from_millis(5));

        // Paced outbound PCM state. Uses VecDeque for O(1) drain from front.
        let frame_size = (pcm_rate / 50) as usize; // 160 samples for 8kHz (20ms frame)
        let mut paced_residual: VecDeque<i16> = VecDeque::new();
        let mut paced_buffer: VecDeque<Vec<i16>> = VecDeque::new();
        // 20ms tick is negligible overhead on top of the 5ms jitter tick (200/sec).
        let pacing_tick = crossbeam_channel::tick(Duration::from_millis(20));

        // RTCP state.
        let mut rtcp_stats = RtcpStats::new();
        let rtcp_tick = crossbeam_channel::tick(Duration::from_secs(rtcp::RTCP_INTERVAL_SECS));

        loop {
            crossbeam_channel::select! {
                recv(done_rx) -> _ => return,

                recv(channels.rtp_inbound.rx) -> msg => {
                    let pkt = match msg {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    // Fan out to raw reader (wire order, pre-jitter).
                    send_drop_oldest(
                        &channels.rtp_raw_reader.tx,
                        &channels.rtp_raw_reader.rx,
                        clone_packet(&pkt),
                    );

                    // DTMF intercept: PT=101 before jitter buffer.
                    if pkt.header.payload_type == dtmf::DTMF_PAYLOAD_TYPE {
                        debug!(
                            seq = pkt.header.sequence_number,
                            ts = pkt.header.timestamp,
                            payload_len = pkt.payload.len(),
                            "media: DTMF RTP packet (PT=101)"
                        );
                        if let Some(ev) = dtmf::decode_dtmf(&pkt.payload) {
                            debug!(
                                digit = %ev.digit,
                                end = ev.end,
                                duration = ev.duration,
                                "media: DTMF event decoded"
                            );
                            if ev.end && !(last_dtmf_seen && pkt.header.timestamp == last_dtmf_timestamp) {
                                last_dtmf_timestamp = pkt.header.timestamp;
                                last_dtmf_seen = true;
                                let cb = shared.on_dtmf_fn.lock().clone();
                                if let Some(f) = cb {
                                    debug!(digit = %ev.digit, "media: firing DTMF callback");
                                    let digit = ev.digit.clone();
                                    spawn_callback(move || f(digit));
                                } else {
                                    warn!(digit = %ev.digit, "media: DTMF received but no callback registered");
                                }
                            }
                        } else {
                            warn!(payload = ?pkt.payload, "media: failed to decode DTMF payload");
                        }
                        last_rtp_time = Instant::now();
                        continue;
                    }

                    rtcp_stats.record_rtp_received(&pkt, pcm_rate as u32);
                    jb.push(pkt);
                    last_rtp_time = Instant::now();
                    drain_jb_inline(&mut jb, &mut cp, &channels);
                },

                recv(jitter_tick) -> _ => {
                    drain_jb_inline(&mut jb, &mut cp, &channels);

                    // Check media timeout on each tick.
                    if last_rtp_time.elapsed() >= timeout {
                        let mut state = shared.state.lock();
                        if *state == CallState::OnHold {
                            // Suspend timeout while on hold.
                            last_rtp_time = Instant::now();
                        } else {
                            // Fire timeout.
                            warn!(elapsed_ms = last_rtp_time.elapsed().as_millis(), "media: timeout — no RTP received");
                            *state = CallState::Ended;
                            drop(state);
                            let on_state = shared.on_state_fn.lock().clone();
                            if let Some(f) = on_state {
                                spawn_callback(move || f(CallState::Ended));
                            }
                            let on_ended = shared.on_ended_fn.lock().clone();
                            if let Some(f) = on_ended {
                                spawn_callback(move || f(EndReason::Timeout));
                            }
                            return;
                        }
                    }
                },

                recv(channels.rtp_writer.rx) -> msg => {
                    let pkt = match msg {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    rtp_writer_used = true;
                    if muted_for_thread.load(Ordering::Relaxed) {
                        continue;
                    }
                    rtcp_stats.record_rtp_sent(pkt.payload.len(), pkt.header.timestamp);
                    if let Some(ref sent) = channels.sent_rtp {
                        send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&pkt));
                    }
                    if let Some(ref tr) = transport_for_thread {
                        send_rtp_to_transport(pkt.to_bytes(), &srtp_out_for_thread, tr, turn_relay);
                    }
                },

                recv(channels.pcm_writer.rx) -> msg => {
                    let pcm_frame = match msg {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if rtp_writer_used || paced_writer_used || muted_for_thread.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(ref mut proc) = cp {
                        encode_and_send_pcm(
                            &pcm_frame, proc.as_mut(), &mut out_seq, &mut out_timestamp,
                            out_ssrc, &mut rtcp_stats, &channels.sent_rtp,
                            &transport_for_thread, &srtp_out_for_thread, turn_relay,
                        );
                    }
                },

                // Paced PCM writer: accept arbitrary-length buffers, split into frames.
                recv(channels.paced_pcm_writer.rx) -> msg => {
                    let pcm_data = match msg {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if rtp_writer_used {
                        continue; // raw RTP mode active, discard paced input
                    }
                    paced_writer_used = true;
                    paced_residual.extend(pcm_data);
                    while paced_residual.len() >= frame_size {
                        let frame: Vec<i16> = paced_residual.drain(..frame_size).collect();
                        if paced_buffer.len() >= MAX_PACED_FRAMES {
                            paced_buffer.pop_front();
                        }
                        paced_buffer.push_back(frame);
                    }
                },

                // Pacing ticker: send one buffered frame every 20ms.
                // Muted frames are consumed and discarded (not paused) to keep
                // pacing aligned — resuming after unmute plays from current position.
                recv(pacing_tick) -> _ => {
                    if let Some(pcm_frame) = paced_buffer.pop_front() {
                        if rtp_writer_used {
                            paced_buffer.clear();
                            paced_residual.clear();
                            continue;
                        }
                        if muted_for_thread.load(Ordering::Relaxed) {
                            continue;
                        }
                        if let Some(ref mut proc) = cp {
                            encode_and_send_pcm(
                                &pcm_frame, proc.as_mut(), &mut out_seq, &mut out_timestamp,
                                out_ssrc, &mut rtcp_stats, &channels.sent_rtp,
                                &transport_for_thread, &srtp_out_for_thread, turn_relay,
                            );
                        }
                    }
                },

                recv(rtcp_tick) -> _ => {
                    if let Some(ref rsock) = rtcp_socket_for_thread {
                        if let Some(addr) = rtcp_remote_addr {
                            let sr = rtcp::build_sr(out_ssrc, &mut rtcp_stats);
                            let data = if let Some(ref ctx) = srtp_out_for_thread {
                                match ctx.lock().protect_rtcp(&sr) {
                                    Ok(encrypted) => encrypted,
                                    Err(e) => {
                                        warn!(error = %e, "media: SRTCP protect failed, dropping RTCP");
                                        continue;
                                    }
                                }
                            } else {
                                sr
                            };
                            let _ = rsock.send_to(&data, addr);
                        }
                    }
                },

                recv(rtcp_recv_rx) -> msg => {
                    if let Ok(data) = msg {
                        if let Some(rtcp::RtcpPacket::SenderReport { ntp_sec, ntp_frac, .. }) = rtcp::parse_rtcp(&data) {
                            rtcp_stats.process_incoming_sr(ntp_sec, ntp_frac);
                        }
                    }
                },
            }
        }
    });

    let handle = MediaHandle {
        done_tx,
        reader_done_tx: if reader_thread.is_some() {
            Some(reader_done_tx)
        } else {
            None
        },
        thread: Some(thread),
        reader_thread,
    };
    MediaStream {
        handle,
        channels,
        muted,
    }
}

/// Optionally encrypts with SRTP and sends an RTP packet via transport.
/// If `turn_relay` is set, wraps the data in ChannelData and sends to the
/// TURN server instead of the remote peer directly.
fn send_rtp_to_transport(
    raw: Vec<u8>,
    srtp: &Option<Arc<Mutex<SrtpContext>>>,
    transport: &MediaTransport,
    turn_relay: Option<(u16, SocketAddr)>,
) {
    let data = if let Some(ref ctx) = srtp {
        match ctx.lock().protect(&raw) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                warn!(error = %e, "media: SRTP protect failed");
                return;
            }
        }
    } else {
        raw
    };
    if let Some((channel, server)) = turn_relay {
        let frame = turn::wrap_channel_data(channel, &data);
        let _ = transport.socket.send_to(&frame, server);
    } else {
        let remote = *transport.remote_addr.lock();
        let _ = transport.socket.send_to(&data, remote);
    }
}

/// Encodes a PCM frame and sends it as an outbound RTP packet.
///
/// Shared between the immediate `pcm_writer` path and the paced writer's tick path.
#[inline]
#[allow(clippy::too_many_arguments)]
fn encode_and_send_pcm(
    pcm_frame: &[i16],
    proc: &mut dyn codec::CodecProcessor,
    out_seq: &mut u16,
    out_timestamp: &mut u32,
    out_ssrc: u32,
    rtcp_stats: &mut RtcpStats,
    sent_rtp: &Option<ChannelPair<RtpPacket>>,
    transport: &Option<Arc<MediaTransport>>,
    srtp_out: &Option<Arc<Mutex<SrtpContext>>>,
    turn_relay: Option<(u16, SocketAddr)>,
) {
    let encoded = proc.encode(pcm_frame);
    let out_pkt = RtpPacket {
        header: RtpHeader {
            version: 2,
            payload_type: proc.payload_type(),
            sequence_number: *out_seq,
            timestamp: *out_timestamp,
            ssrc: out_ssrc,
            marker: false,
        },
        payload: encoded,
    };
    *out_seq = out_seq.wrapping_add(1);
    *out_timestamp = out_timestamp.wrapping_add(proc.samples_per_frame());
    rtcp_stats.record_rtp_sent(out_pkt.payload.len(), out_pkt.header.timestamp);
    if let Some(ref sent) = sent_rtp {
        send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&out_pkt));
    }
    if let Some(ref tr) = transport {
        send_rtp_to_transport(out_pkt.to_bytes(), srtp_out, tr, turn_relay);
    }
}

/// Inline drain: pops from jitter buffer and fans out to readers.
fn drain_jb_inline(
    jb: &mut JitterBuffer,
    cp: &mut Option<Box<dyn CodecProcessor>>,
    channels: &MediaChannels,
) {
    loop {
        let pkt = match jb.pop() {
            Some(p) => p,
            None => return,
        };
        send_drop_oldest(
            &channels.rtp_reader.tx,
            &channels.rtp_reader.rx,
            clone_packet(&pkt),
        );
        if !pkt.payload.is_empty() {
            if let Some(ref mut proc) = cp {
                let pcm = proc.decode(&pkt.payload);
                send_drop_oldest(&channels.pcm_reader.tx, &channels.pcm_reader.rx, pcm);
            }
        }
    }
}

/// Configuration for the video media pipeline.
pub struct VideoMediaConfig {
    /// Optional SRTP context for decrypting inbound video RTP.
    pub srtp_inbound: Option<SrtpContext>,
    /// Optional SRTP context for encrypting outbound video RTP.
    pub srtp_outbound: Option<SrtpContext>,
    /// RTCP socket for sending/receiving video RTCP packets.
    pub rtcp_socket: Option<Arc<UdpSocket>>,
    /// Remote RTCP address for video.
    pub rtcp_remote_addr: Option<SocketAddr>,
    /// Negotiated video codec for frame assembly/fragmentation.
    pub video_codec: Option<VideoCodec>,
    /// RTP payload type for outbound video (from SDP negotiation).
    pub video_payload_type: u8,
}

/// Start a video media pipeline on a dedicated std::thread.
///
/// Unlike the audio pipeline, the video pipeline has no jitter buffer, no codec
/// processing, no PCM channels, and no DTMF handling. It is a simple RTP
/// passthrough: inbound packets are fanned out to readers, outbound packets are
/// sent via the transport.
pub fn start_video_media(
    config: VideoMediaConfig,
    channels: Arc<MediaChannels>,
    transport: Option<Arc<MediaTransport>>,
    muted: Arc<AtomicBool>,
) -> MediaStream {
    let (done_tx, done_rx) = bounded::<()>(1);

    let srtp_in = config.srtp_inbound.map(|ctx| Arc::new(Mutex::new(ctx)));
    let srtp_out = config.srtp_outbound.map(|ctx| Arc::new(Mutex::new(ctx)));
    let rtcp_socket = config.rtcp_socket;
    let rtcp_remote_addr = config.rtcp_remote_addr;

    // Spawn inbound UDP reader thread (identical to audio reader).
    let (reader_done_tx, reader_done_rx) = bounded::<()>(1);
    let rtcp_socket_for_reader = rtcp_socket.as_ref().map(Arc::clone);
    let (rtcp_recv_tx, rtcp_recv_rx) = bounded::<Vec<u8>>(16);

    let reader_thread = transport.as_ref().map(|tr| {
        let socket = Arc::clone(&tr.socket);
        let inbound_tx = channels.rtp_inbound.tx.clone();
        let inbound_rx = channels.rtp_inbound.rx.clone();
        let done = reader_done_rx;
        let srtp_in_clone = srtp_in.clone();
        let rtcp_sock = rtcp_socket_for_reader;
        let rtcp_tx = rtcp_recv_tx;
        debug!("video: starting UDP reader thread");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut rtcp_buf = [0u8; 512];
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .ok();
            if let Some(ref rsock) = rtcp_sock {
                rsock.set_read_timeout(Some(Duration::from_millis(1))).ok();
            }
            loop {
                if done.try_recv().is_ok() {
                    return;
                }
                if let Ok((n, _addr)) = socket.recv_from(&mut buf) {
                    if n < 12 {
                        continue;
                    }
                    let raw = &buf[..n];
                    let data = if let Some(ref ctx) = srtp_in_clone {
                        match ctx.lock().unprotect(raw) {
                            Ok(d) => d,
                            Err(_) => continue,
                        }
                    } else {
                        raw.to_vec()
                    };
                    if let Some(pkt) = crate::types::RtpPacket::parse(&data) {
                        send_drop_oldest(&inbound_tx, &inbound_rx, pkt);
                    }
                }
                // RTCP read.
                if let Some(ref rsock) = rtcp_sock {
                    if let Ok((n, _)) = rsock.recv_from(&mut rtcp_buf) {
                        let _ = rtcp_tx.try_send(rtcp_buf[..n].to_vec());
                    }
                }
            }
        })
    });

    let transport_for_thread = transport.clone();
    let srtp_out_for_thread = srtp_out;
    let rtcp_socket_for_thread = rtcp_socket;
    let muted_for_thread = Arc::clone(&muted);
    let channels_for_thread = Arc::clone(&channels);
    let video_codec = config.video_codec;
    let video_pt = config.video_payload_type;
    let thread = std::thread::spawn(move || {
        let channels = channels_for_thread;
        let out_ssrc = rand_u32();

        let mut rtcp_stats = RtcpStats::new();
        let rtcp_tick = crossbeam_channel::tick(Duration::from_secs(rtcp::RTCP_INTERVAL_SECS));

        // Create depacketizer/packetizer if a video codec is configured.
        let mut depacketizer: Option<Box<dyn crate::video::VideoDepacketizer>> =
            video_codec.map(crate::video::new_depacketizer);
        let mut packetizer: Option<Box<dyn crate::video::VideoPacketizer>> =
            video_codec.map(crate::video::new_packetizer);
        let mut out_seq: u16 = rand_u32() as u16;
        let out_pt: u8 = video_pt;

        loop {
            crossbeam_channel::select! {
                recv(done_rx) -> _ => return,

                recv(channels.rtp_inbound.rx) -> msg => {
                    let pkt = match msg {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    // Fan out to raw reader and reordered reader (no jitter buffer for video).
                    rtcp_stats.record_rtp_received(&pkt, 90000);
                    send_drop_oldest(
                        &channels.rtp_raw_reader.tx,
                        &channels.rtp_raw_reader.rx,
                        clone_packet(&pkt),
                    );

                    // Run depacketizer to produce assembled frames.
                    if let Some(ref mut depkt) = depacketizer {
                        if let Some(frame) = depkt.depacketize(&pkt) {
                            send_drop_oldest(
                                &channels.video_frame_reader.tx,
                                &channels.video_frame_reader.rx,
                                frame,
                            );
                        }
                    }

                    send_drop_oldest(
                        &channels.rtp_reader.tx,
                        &channels.rtp_reader.rx,
                        pkt,
                    );
                },

                // Raw RTP writer (bypass packetizer).
                recv(channels.rtp_writer.rx) -> msg => {
                    let pkt = match msg {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    if muted_for_thread.load(Ordering::Relaxed) {
                        continue;
                    }
                    rtcp_stats.record_rtp_sent(pkt.payload.len(), pkt.header.timestamp);
                    if let Some(ref sent) = channels.sent_rtp {
                        send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&pkt));
                    }
                    if let Some(ref tr) = transport_for_thread {
                        send_rtp_to_transport(pkt.to_bytes(), &srtp_out_for_thread, tr, None);
                    }
                },

                // VideoFrame writer → packetize → send as RTP.
                recv(channels.video_frame_writer.rx) -> msg => {
                    let frame = match msg {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if muted_for_thread.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(ref mut pktizer) = packetizer {
                        let payloads = pktizer.packetize(&frame, 1200);
                        let num = payloads.len();
                        for (i, payload) in payloads.into_iter().enumerate() {
                            let marker = i == num - 1;
                            let rtp = RtpPacket {
                                header: RtpHeader {
                                    version: 2,
                                    marker,
                                    payload_type: out_pt,
                                    sequence_number: out_seq,
                                    timestamp: frame.timestamp,
                                    ssrc: out_ssrc,
                                },
                                payload,
                            };
                            out_seq = out_seq.wrapping_add(1);
                            rtcp_stats.record_rtp_sent(rtp.payload.len(), rtp.header.timestamp);
                            if let Some(ref sent) = channels.sent_rtp {
                                send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&rtp));
                            }
                            if let Some(ref tr) = transport_for_thread {
                                send_rtp_to_transport(
                                    rtp.to_bytes(),
                                    &srtp_out_for_thread,
                                    tr,
                                    None,
                                );
                            }
                        }
                    }
                },

                recv(rtcp_tick) -> _ => {
                    if let Some(ref rsock) = rtcp_socket_for_thread {
                        if let Some(addr) = rtcp_remote_addr {
                            let sr = rtcp::build_sr(out_ssrc, &mut rtcp_stats);
                            let data = if let Some(ref ctx) = srtp_out_for_thread {
                                match ctx.lock().protect_rtcp(&sr) {
                                    Ok(encrypted) => encrypted,
                                    Err(e) => {
                                        warn!(error = %e, "video: SRTCP protect failed");
                                        continue;
                                    }
                                }
                            } else {
                                sr
                            };
                            let _ = rsock.send_to(&data, addr);
                        }
                    }
                },

                recv(rtcp_recv_rx) -> msg => {
                    if let Ok(data) = msg {
                        if let Some(rtcp::RtcpPacket::SenderReport { ntp_sec, ntp_frac, .. }) = rtcp::parse_rtcp(&data) {
                            rtcp_stats.process_incoming_sr(ntp_sec, ntp_frac);
                        }
                    }
                },
            }
        }
    });

    let handle = MediaHandle {
        done_tx,
        reader_done_tx: if reader_thread.is_some() {
            Some(reader_done_tx)
        } else {
            None
        },
        thread: Some(thread),
        reader_thread,
    };
    MediaStream {
        handle,
        channels,
        muted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_channels() -> Arc<MediaChannels> {
        Arc::new(MediaChannels::new().with_sent_rtp())
    }

    fn test_shared(state: CallState) -> Arc<MediaSharedState> {
        Arc::new(MediaSharedState::new(state))
    }

    fn test_muted() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn make_rtp(seq: u16, pt: u8, payload: Vec<u8>) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                payload_type: pt,
                sequence_number: seq,
                timestamp: seq as u32 * 160,
                ssrc: 1234,
                marker: false,
            },
            payload,
        }
    }

    fn inject(channels: &MediaChannels, pkt: RtpPacket) {
        channels.rtp_inbound.tx.send(pkt).unwrap();
    }

    fn read_pkt(rx: &Receiver<RtpPacket>, ms: u64) -> Option<RtpPacket> {
        rx.recv_timeout(Duration::from_millis(ms)).ok()
    }

    fn read_pcm(rx: &Receiver<Vec<i16>>, ms: u64) -> Option<Vec<i16>> {
        rx.recv_timeout(Duration::from_millis(ms)).ok()
    }

    fn drain_pkts(rx: &Receiver<RtpPacket>) -> Vec<RtpPacket> {
        std::thread::sleep(Duration::from_millis(30));
        let mut pkts = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            pkts.push(pkt);
        }
        pkts
    }

    // --- RTP pipeline tests ---

    #[test]
    fn rtp_raw_reader_pre_jitter() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        inject(&ch, make_rtp(1, 0, vec![0; 160]));
        inject(&ch, make_rtp(3, 0, vec![0; 160]));
        inject(&ch, make_rtp(2, 0, vec![0; 160]));

        let p1 = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();
        let p2 = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();
        let p3 = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();

        // Raw reader delivers in wire order.
        assert_eq!(p1.header.sequence_number, 1);
        assert_eq!(p2.header.sequence_number, 3);
        assert_eq!(p3.header.sequence_number, 2);

        stream.stop();
    }

    #[test]
    fn rtp_reader_post_jitter() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        inject(&ch, make_rtp(3, 0, vec![0; 160]));
        inject(&ch, make_rtp(1, 0, vec![0; 160]));
        inject(&ch, make_rtp(2, 0, vec![0; 160]));

        let p1 = read_pkt(&ch.rtp_reader.rx, 200).unwrap();
        let p2 = read_pkt(&ch.rtp_reader.rx, 200).unwrap();
        let p3 = read_pkt(&ch.rtp_reader.rx, 200).unwrap();

        // Post-jitter delivers reordered.
        assert_eq!(p1.header.sequence_number, 1);
        assert_eq!(p2.header.sequence_number, 2);
        assert_eq!(p3.header.sequence_number, 3);

        stream.stop();
    }

    #[test]
    fn tap_independence() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // PCMU payload so PCMReader also gets decoded audio.
        inject(&ch, make_rtp(42, 0, vec![0; 160]));

        let raw = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();
        let ordered = read_pkt(&ch.rtp_reader.rx, 200).unwrap();
        let pcm = read_pcm(&ch.pcm_reader.rx, 200).unwrap();

        assert_eq!(raw.header.sequence_number, 42);
        assert_eq!(ordered.header.sequence_number, 42);
        assert!(!pcm.is_empty());

        stream.stop();
    }

    #[test]
    fn rtp_writer_passthrough() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                payload_type: 111,
                sequence_number: 999,
                timestamp: 12345,
                ssrc: 9999,
                marker: false,
            },
            payload: vec![0xDE, 0xAD],
        };
        ch.rtp_writer.tx.send(pkt).unwrap();

        let sent = read_pkt(&ch.sent_rtp.as_ref().unwrap().rx, 200).unwrap();
        assert_eq!(sent.header.sequence_number, 999);
        assert_eq!(sent.header.timestamp, 12345);
        assert_eq!(sent.header.payload_type, 111);
        assert_eq!(sent.payload, vec![0xDE, 0xAD]);

        stream.stop();
    }

    #[test]
    fn outbound_mutex_rtp_writer_suppresses_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Send an RTP packet first to set rtp_writer_used.
        ch.rtp_writer.tx.send(make_rtp(1, 0, vec![])).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let _ = read_pkt(sent_rx, 200); // consume the forwarded packet

        // Now send a PCM frame — should be dropped.
        let _ = ch.pcm_writer.tx.try_send(vec![0i16; 160]);
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            sent_rx.try_recv().is_err(),
            "PCMWriter should be suppressed when RTPWriter was used"
        );

        stream.stop();
    }

    #[test]
    fn pcm_writer_encode() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Write silence PCM frame.
        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(sent.header.payload_type, 0); // PCMU
        assert_eq!(sent.payload.len(), 160);
        assert_eq!(sent.header.version, 2);

        stream.stop();
    }

    #[test]
    fn pcm_writer_seq_and_timestamp() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();
        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let p0 = read_pkt(sent_rx, 200).unwrap();
        let p1 = read_pkt(sent_rx, 200).unwrap();

        assert_eq!(p0.header.sequence_number, 0);
        assert_eq!(p1.header.sequence_number, 1);
        assert_eq!(p0.header.timestamp, 0);
        assert_eq!(p1.header.timestamp, 160);
        assert_eq!(p0.header.ssrc, p1.header.ssrc);
        assert_ne!(p0.header.ssrc, 0);

        stream.stop();
    }

    #[test]
    fn pcm_writer_pcma_payload_type() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            codec: Codec::PCMA,
            ..Default::default()
        };
        let mut stream = start_media(config, ch.clone(), shared, None, test_muted());

        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(sent.header.payload_type, 8); // PCMA
        assert_eq!(sent.payload.len(), 160);

        stream.stop();
    }

    #[test]
    fn codec_dispatch_pcmu() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // mu-law 0xFF = silence (decodes to 0).
        inject(&ch, make_rtp(1, 0, vec![0xFF; 160]));

        let pcm = read_pcm(&ch.pcm_reader.rx, 200).unwrap();
        assert_eq!(pcm.len(), 160);
        for s in &pcm {
            assert_eq!(*s, 0);
        }

        stream.stop();
    }

    #[test]
    fn codec_dispatch_pcma() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            codec: Codec::PCMA,
            ..Default::default()
        };
        let mut stream = start_media(config, ch.clone(), shared, None, test_muted());

        // A-law 0xD5 = silence (decodes near 0).
        inject(&ch, make_rtp(1, 8, vec![0xD5; 160]));

        let pcm = read_pcm(&ch.pcm_reader.rx, 200).unwrap();
        assert_eq!(pcm.len(), 160);
        for s in &pcm {
            assert!(
                s.abs() <= 8,
                "expected near-zero for A-law silence, got {}",
                s
            );
        }

        stream.stop();
    }

    #[test]
    fn channel_overflow_drop_oldest() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Saturate with 300 packets (buffer is 256).
        for i in 0..300u16 {
            inject(&ch, make_rtp(i, 0, vec![0; 160]));
        }

        let pkts = drain_pkts(&ch.rtp_raw_reader.rx);
        assert!(!pkts.is_empty());
        let last_seq = pkts.last().unwrap().header.sequence_number;
        assert_eq!(last_seq, 299, "newest packet must survive overflow");
        let first_seq = pkts.first().unwrap().header.sequence_number;
        assert!(first_seq > 0, "oldest packets should have been dropped");

        stream.stop();
    }

    #[test]
    fn media_timeout_fires() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            media_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let ended = Arc::new(Mutex::new(None::<EndReason>));
        let ended2 = ended.clone();
        *shared.on_ended_fn.lock() = Some(Arc::new(move |r| {
            *ended2.lock() = Some(r);
        }));

        let _stream = start_media(config, ch.clone(), shared, None, test_muted());

        // Don't send any RTP — timeout should fire.
        std::thread::sleep(Duration::from_millis(200));
        let reason = ended.lock().take();
        assert_eq!(reason, Some(EndReason::Timeout));
    }

    #[test]
    fn media_timeout_suspended_on_hold() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            media_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let ended = Arc::new(Mutex::new(None::<EndReason>));
        let ended2 = ended.clone();
        *shared.on_ended_fn.lock() = Some(Arc::new(move |r| {
            *ended2.lock() = Some(r);
        }));

        let _stream = start_media(config, ch.clone(), shared.clone(), None, test_muted());

        // Put on hold.
        *shared.state.lock() = CallState::OnHold;

        // Wait longer than timeout — should NOT fire while on hold.
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            ended.lock().is_none(),
            "media timeout must not fire while on hold"
        );

        // Resume — timeout should fire after timeout period with no RTP.
        *shared.state.lock() = CallState::Active;
        std::thread::sleep(Duration::from_millis(120));
        let reason = ended.lock().take();
        assert_eq!(reason, Some(EndReason::Timeout));
    }

    #[test]
    fn dtmf_inbound_fires_callback() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared.clone(),
            None,
            test_muted(),
        );

        let (tx, rx) = std::sync::mpsc::channel();
        *shared.on_dtmf_fn.lock() = Some(Arc::new(move |digit| {
            let _ = tx.send(digit);
        }));

        // Inject DTMF RTP packet (PT=101, event=5, E bit, volume=10, duration=1000).
        let payload = vec![5, 0x8A, 0x03, 0xE8];
        inject(
            &ch,
            RtpPacket {
                header: RtpHeader {
                    version: 2,
                    payload_type: 101,
                    sequence_number: 1,
                    timestamp: 1000,
                    ssrc: 1234,
                    marker: false,
                },
                payload,
            },
        );

        let digit = rx.recv_timeout(Duration::from_millis(200)).unwrap();
        assert_eq!(digit, "5");

        stream.stop();
    }

    #[test]
    fn dtmf_no_callback_no_panic() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // No callback registered — should not panic.
        let payload = vec![5, 0x8A, 0x03, 0xE8];
        inject(
            &ch,
            RtpPacket {
                header: RtpHeader {
                    version: 2,
                    payload_type: 101,
                    sequence_number: 1,
                    timestamp: 1000,
                    ssrc: 1234,
                    marker: false,
                },
                payload,
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        stream.stop();
    }

    #[test]
    fn mute_suppresses_outbound_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let muted = test_muted();
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            muted.clone(),
        );

        muted.store(true, Ordering::Relaxed);

        let _ = ch.pcm_writer.tx.try_send(vec![9999i16; 160]);
        std::thread::sleep(Duration::from_millis(50));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "PCMWriter output must be suppressed while muted"
        );

        stream.stop();
    }

    #[test]
    fn mute_suppresses_outbound_rtp_writer() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let muted = test_muted();
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            muted.clone(),
        );

        muted.store(true, Ordering::Relaxed);

        let _ = ch.rtp_writer.tx.try_send(make_rtp(42, 0, vec![]));
        std::thread::sleep(Duration::from_millis(50));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "RTPWriter output must be suppressed while muted"
        );

        stream.stop();
    }

    #[test]
    fn unmute_restores_outbound_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let muted = test_muted();
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            muted.clone(),
        );

        muted.store(true, Ordering::Relaxed);
        muted.store(false, Ordering::Relaxed);

        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200);
        assert!(
            sent.is_some(),
            "PCMWriter should produce packets after unmute"
        );

        stream.stop();
    }

    #[test]
    fn mute_inbound_still_flows() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let muted = test_muted();
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            muted.clone(),
        );

        muted.store(true, Ordering::Relaxed);

        inject(&ch, make_rtp(1, 0, vec![0; 160]));

        let raw = read_pkt(&ch.rtp_raw_reader.rx, 200);
        assert!(raw.is_some(), "inbound RTP must still flow while muted");

        stream.stop();
    }

    #[test]
    fn stop_media_terminates_thread() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(MediaConfig::default(), ch, shared, None, test_muted());

        stream.stop();
        // Thread should have joined. If not, test would hang.
        assert!(stream.is_stopped());
    }

    // --- Video pipeline tests ---

    fn start_video(ch: Arc<MediaChannels>, muted: Arc<AtomicBool>) -> MediaStream {
        let config = VideoMediaConfig {
            srtp_inbound: None,
            srtp_outbound: None,
            rtcp_socket: None,
            rtcp_remote_addr: None,
            video_codec: None, // no depacketizer/packetizer in basic tests
            video_payload_type: 96,
        };
        start_video_media(config, ch, None, muted)
    }

    #[test]
    fn video_stream_rtp_passthrough() {
        let ch = test_channels();
        let mut stream = start_video(ch.clone(), test_muted());

        inject(&ch, make_rtp(1, 96, vec![0xAB; 100]));

        let raw = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();
        assert_eq!(raw.header.sequence_number, 1);
        assert_eq!(raw.header.payload_type, 96);

        let ordered = read_pkt(&ch.rtp_reader.rx, 200).unwrap();
        assert_eq!(ordered.header.sequence_number, 1);

        stream.stop();
    }

    #[test]
    fn video_stream_rtp_writer() {
        let ch = test_channels();
        let mut stream = start_video(ch.clone(), test_muted());

        let pkt = make_rtp(42, 96, vec![0xDE; 200]);
        ch.rtp_writer.tx.send(pkt).unwrap();

        let sent = read_pkt(&ch.sent_rtp.as_ref().unwrap().rx, 200).unwrap();
        assert_eq!(sent.header.sequence_number, 42);
        assert_eq!(sent.payload.len(), 200);

        stream.stop();
    }

    #[test]
    fn video_stream_mute_suppresses_send() {
        let ch = test_channels();
        let muted = test_muted();
        let mut stream = start_video(ch.clone(), muted.clone());

        muted.store(true, Ordering::Relaxed);

        let _ = ch.rtp_writer.tx.try_send(make_rtp(1, 96, vec![0; 100]));
        std::thread::sleep(Duration::from_millis(50));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "video RTP must be suppressed while muted"
        );

        stream.stop();
    }

    #[test]
    fn video_stream_no_pcm_decode() {
        let ch = test_channels();
        let mut stream = start_video(ch.clone(), test_muted());

        // Inject video RTP — PCM reader should remain empty (no codec processing).
        inject(&ch, make_rtp(1, 96, vec![0; 100]));
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            ch.pcm_reader.rx.try_recv().is_err(),
            "video stream must not produce PCM output"
        );

        stream.stop();
    }

    #[test]
    fn video_stream_stop() {
        let ch = test_channels();
        let mut stream = start_video(ch, test_muted());
        stream.stop();
        assert!(stream.is_stopped());
    }

    // --- Paced PCM writer tests ---

    #[test]
    fn paced_pcm_writer_single_frame() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Send exactly one frame (160 samples = 20ms at 8kHz).
        ch.paced_pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        // The pacing tick fires every 20ms, so allow time for it.
        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(sent.header.payload_type, 0); // PCMU
        assert_eq!(sent.payload.len(), 160);
        assert_eq!(sent.header.version, 2);

        stream.stop();
    }

    #[test]
    fn pcm_writer_burst_sends_instantly() {
        // Documents that pcm_writer has NO pacing — all frames sent immediately.
        // Use paced_pcm_writer for TTS/burst audio sources.
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        for _ in 0..5 {
            ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();
        }

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let t0 = Instant::now();
        for _ in 0..5 {
            read_pkt(sent_rx, 200).unwrap();
        }
        let elapsed = t0.elapsed();

        // All 5 packets arrive in <5ms — no pacing.
        assert!(elapsed < Duration::from_millis(5), "elapsed: {:?}", elapsed);

        stream.stop();
    }

    #[test]
    fn paced_pcm_writer_splits_large_buffer() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Send 480 samples (3 frames worth) as a single burst.
        ch.paced_pcm_writer.tx.send(vec![0i16; 480]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let p0 = read_pkt(sent_rx, 200).unwrap();
        let p1 = read_pkt(sent_rx, 200).unwrap();
        let p2 = read_pkt(sent_rx, 200).unwrap();

        // All 3 frames should have sequential seq numbers and correct timestamps.
        assert_eq!(p0.header.sequence_number, 0);
        assert_eq!(p1.header.sequence_number, 1);
        assert_eq!(p2.header.sequence_number, 2);
        assert_eq!(p0.header.timestamp, 0);
        assert_eq!(p1.header.timestamp, 160);
        assert_eq!(p2.header.timestamp, 320);
        assert_eq!(p0.header.ssrc, p1.header.ssrc);

        stream.stop();
    }

    #[test]
    fn paced_pcm_writer_handles_partial_frames() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Send 240 samples (1.5 frames). First frame is sent, 80 samples buffered.
        ch.paced_pcm_writer.tx.send(vec![0i16; 240]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let p0 = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(p0.header.sequence_number, 0);

        // Send another 80 samples to complete the second frame.
        ch.paced_pcm_writer.tx.send(vec![0i16; 80]).unwrap();

        let p1 = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(p1.header.sequence_number, 1);
        assert_eq!(p1.header.timestamp, 160);

        stream.stop();
    }

    #[test]
    fn paced_pcm_writer_pacing_interval() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Send 5 frames as a burst.
        ch.paced_pcm_writer.tx.send(vec![0i16; 160 * 5]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;

        // Read first packet.
        let _p0 = read_pkt(sent_rx, 200).unwrap();
        let t0 = Instant::now();

        // Read second packet — should arrive ~20ms later.
        let _p1 = read_pkt(sent_rx, 200).unwrap();
        let elapsed = t0.elapsed();

        // Allow margin: at least 10ms (the tick may not be perfectly precise).
        assert!(
            elapsed >= Duration::from_millis(10),
            "pacing interval too short: {:?}",
            elapsed
        );

        stream.stop();
    }

    #[test]
    fn paced_pcm_writer_muted_suppresses_send() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let muted = test_muted();
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            muted.clone(),
        );

        muted.store(true, Ordering::Relaxed);

        ch.paced_pcm_writer.tx.send(vec![0i16; 160 * 3]).unwrap();

        // Wait long enough for all 3 frames to have been ticked.
        std::thread::sleep(Duration::from_millis(100));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "paced writer should suppress packets while muted"
        );

        stream.stop();
    }

    #[test]
    fn paced_pcm_writer_rtp_writer_suppresses() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Activate raw RTP writer mode first.
        ch.rtp_writer.tx.send(make_rtp(1, 0, vec![])).unwrap();
        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let _ = read_pkt(sent_rx, 200); // consume

        // Now send paced PCM — should be suppressed.
        ch.paced_pcm_writer.tx.send(vec![0i16; 160 * 3]).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        assert!(
            sent_rx.try_recv().is_err(),
            "paced writer should be suppressed when rtp_writer was used"
        );

        stream.stop();
    }

    #[test]
    fn paced_writer_suppresses_pcm_writer() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut stream = start_media(
            MediaConfig::default(),
            ch.clone(),
            shared,
            None,
            test_muted(),
        );

        // Activate paced writer first.
        ch.paced_pcm_writer.tx.send(vec![0i16; 160]).unwrap();
        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let _ = read_pkt(sent_rx, 200); // consume paced packet

        // Now send via regular pcm_writer — should be suppressed.
        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            sent_rx.try_recv().is_err(),
            "pcm_writer should be suppressed when paced_pcm_writer was used"
        );

        stream.stop();
    }
}
