use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex;

use crate::codec::{self, CodecProcessor};
use crate::dtmf;
use crate::jitter::JitterBuffer;
use crate::types::*;

/// Default media configuration values.
const DEFAULT_MEDIA_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_JITTER_DEPTH: Duration = Duration::from_millis(50);
const DEFAULT_PCM_RATE: i32 = 8000;
const CHANNEL_CAPACITY: usize = 256;

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
    pub media_timeout: Duration,
    pub jitter_depth: Duration,
    pub pcm_rate: i32,
    pub codec: Codec,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            media_timeout: DEFAULT_MEDIA_TIMEOUT,
            jitter_depth: DEFAULT_JITTER_DEPTH,
            pcm_rate: DEFAULT_PCM_RATE,
            codec: Codec::PCMU,
        }
    }
}

/// A pair of sender and receiver for a bounded crossbeam channel.
#[derive(Clone)]
pub struct ChannelPair<T> {
    pub tx: Sender<T>,
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
    /// PCM from user for encoding + sending.
    pub pcm_writer: ChannelPair<Vec<i16>>,
    /// Test hook: outbound packets copied here.
    pub sent_rtp: Option<ChannelPair<RtpPacket>>,
}

impl MediaChannels {
    pub fn new() -> Self {
        Self {
            rtp_inbound: ChannelPair::new(),
            rtp_raw_reader: ChannelPair::new(),
            rtp_reader: ChannelPair::new(),
            rtp_writer: ChannelPair::new(),
            pcm_reader: ChannelPair::new(),
            pcm_writer: ChannelPair::new(),
            sent_rtp: None,
        }
    }

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
    pub muted: AtomicBool,
    pub state: Mutex<CallState>,
    pub on_dtmf_fn: Callback<String>,
    pub on_ended_fn: Callback<EndReason>,
    pub on_state_fn: Callback<CallState>,
}

impl MediaSharedState {
    pub fn new(initial_state: CallState) -> Self {
        Self {
            muted: AtomicBool::new(false),
            state: Mutex::new(initial_state),
            on_dtmf_fn: Mutex::new(None),
            on_ended_fn: Mutex::new(None),
            on_state_fn: Mutex::new(None),
        }
    }
}

/// RTP transport for sending/receiving packets over UDP.
pub struct MediaTransport {
    pub socket: Arc<UdpSocket>,
    pub remote_addr: Mutex<SocketAddr>,
}

impl MediaTransport {
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
        "no available RTP port in range {}-{}",
        min, max
    )))
}

/// Handle to a running media pipeline. Drop to stop.
pub struct MediaHandle {
    done_tx: Sender<()>,
    reader_done_tx: Option<Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    reader_thread: Option<std::thread::JoinHandle<()>>,
}

impl MediaHandle {
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
/// Returns a `MediaHandle` that stops the pipeline when dropped.
pub fn start_media(
    config: MediaConfig,
    channels: Arc<MediaChannels>,
    shared: Arc<MediaSharedState>,
    transport: Option<Arc<MediaTransport>>,
) -> MediaHandle {
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

    // Spawn an inbound UDP reader thread if transport is available.
    let (reader_done_tx, reader_done_rx) = bounded::<()>(1);
    let reader_thread = transport.as_ref().map(|tr| {
        let socket = Arc::clone(&tr.socket);
        let inbound_tx = channels.rtp_inbound.tx.clone();
        let inbound_rx = channels.rtp_inbound.rx.clone();
        let done = reader_done_rx;
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                if done.try_recv().is_ok() {
                    return;
                }
                match socket.recv_from(&mut buf) {
                    Ok((n, _src)) => {
                        if n < 12 {
                            continue;
                        }
                        if let Some(pkt) = RtpPacket::parse(&buf[..n]) {
                            send_drop_oldest(&inbound_tx, &inbound_rx, pkt);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => return,
                }
            }
        })
    });

    let transport_for_thread = transport.clone();
    let thread = std::thread::spawn(move || {
        let mut jb = JitterBuffer::new(jitter_depth);
        let mut out_seq: u16 = 0;
        let mut out_timestamp: u32 = 0;
        let out_ssrc = rand_u32();
        let mut rtp_writer_used = false;
        let mut last_dtmf_timestamp: u32 = 0;
        let mut last_dtmf_seen = false;

        let mut last_rtp_time = Instant::now();
        let jitter_tick = crossbeam_channel::tick(Duration::from_millis(5));

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
                        if let Some(ev) = dtmf::decode_dtmf(&pkt.payload) {
                            if ev.end && !(last_dtmf_seen && pkt.header.timestamp == last_dtmf_timestamp) {
                                last_dtmf_timestamp = pkt.header.timestamp;
                                last_dtmf_seen = true;
                                let cb = shared.on_dtmf_fn.lock().clone();
                                if let Some(f) = cb {
                                    let digit = ev.digit.clone();
                                    std::thread::spawn(move || f(digit));
                                }
                            }
                        }
                        last_rtp_time = Instant::now();
                        continue;
                    }

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
                            *state = CallState::Ended;
                            drop(state);
                            let on_state = shared.on_state_fn.lock().clone();
                            if let Some(f) = on_state {
                                std::thread::spawn(move || f(CallState::Ended));
                            }
                            let on_ended = shared.on_ended_fn.lock().clone();
                            if let Some(f) = on_ended {
                                std::thread::spawn(move || f(EndReason::Timeout));
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
                    if shared.muted.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(ref sent) = channels.sent_rtp {
                        send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&pkt));
                    }
                    if let Some(ref tr) = transport_for_thread {
                        let remote = *tr.remote_addr.lock();
                        let _ = tr.socket.send_to(&pkt.to_bytes(), remote);
                    }
                },

                recv(channels.pcm_writer.rx) -> msg => {
                    let pcm_frame = match msg {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if rtp_writer_used || cp.is_none() {
                        continue;
                    }
                    if shared.muted.load(Ordering::Relaxed) {
                        continue;
                    }
                    let proc = cp.as_mut().unwrap();
                    let encoded = proc.encode(&pcm_frame);
                    let out_pkt = RtpPacket {
                        header: RtpHeader {
                            version: 2,
                            payload_type: proc.payload_type(),
                            sequence_number: out_seq,
                            timestamp: out_timestamp,
                            ssrc: out_ssrc,
                            marker: false,
                        },
                        payload: encoded,
                    };
                    out_seq = out_seq.wrapping_add(1);
                    out_timestamp = out_timestamp.wrapping_add(proc.samples_per_frame());
                    if let Some(ref sent) = channels.sent_rtp {
                        send_drop_oldest(&sent.tx, &sent.rx, clone_packet(&out_pkt));
                    }
                    if let Some(ref tr) = transport_for_thread {
                        let remote = *tr.remote_addr.lock();
                        let _ = tr.socket.send_to(&out_pkt.to_bytes(), remote);
                    }
                },
            }
        }
    });

    MediaHandle {
        done_tx,
        reader_done_tx: if reader_thread.is_some() {
            Some(reader_done_tx)
        } else {
            None
        },
        thread: Some(thread),
        reader_thread,
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
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn rtp_reader_post_jitter() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn tap_independence() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

        // PCMU payload so PCMReader also gets decoded audio.
        inject(&ch, make_rtp(42, 0, vec![0; 160]));

        let raw = read_pkt(&ch.rtp_raw_reader.rx, 200).unwrap();
        let ordered = read_pkt(&ch.rtp_reader.rx, 200).unwrap();
        let pcm = read_pcm(&ch.pcm_reader.rx, 200).unwrap();

        assert_eq!(raw.header.sequence_number, 42);
        assert_eq!(ordered.header.sequence_number, 42);
        assert!(!pcm.is_empty());

        handle.stop();
    }

    #[test]
    fn rtp_writer_passthrough() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn outbound_mutex_rtp_writer_suppresses_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn pcm_writer_encode() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

        // Write silence PCM frame.
        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(sent.header.payload_type, 0); // PCMU
        assert_eq!(sent.payload.len(), 160);
        assert_eq!(sent.header.version, 2);

        handle.stop();
    }

    #[test]
    fn pcm_writer_seq_and_timestamp() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn pcm_writer_pcma_payload_type() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            codec: Codec::PCMA,
            ..Default::default()
        };
        let mut handle = start_media(config, ch.clone(), shared, None);

        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200).unwrap();
        assert_eq!(sent.header.payload_type, 8); // PCMA
        assert_eq!(sent.payload.len(), 160);

        handle.stop();
    }

    #[test]
    fn codec_dispatch_pcmu() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

        // mu-law 0xFF = silence (decodes to 0).
        inject(&ch, make_rtp(1, 0, vec![0xFF; 160]));

        let pcm = read_pcm(&ch.pcm_reader.rx, 200).unwrap();
        assert_eq!(pcm.len(), 160);
        for s in &pcm {
            assert_eq!(*s, 0);
        }

        handle.stop();
    }

    #[test]
    fn codec_dispatch_pcma() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let config = MediaConfig {
            codec: Codec::PCMA,
            ..Default::default()
        };
        let mut handle = start_media(config, ch.clone(), shared, None);

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

        handle.stop();
    }

    #[test]
    fn channel_overflow_drop_oldest() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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

        handle.stop();
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

        let _handle = start_media(config, ch.clone(), shared, None);

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

        let _handle = start_media(config, ch.clone(), shared.clone(), None);

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
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared.clone(), None);

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

        handle.stop();
    }

    #[test]
    fn dtmf_no_callback_no_panic() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared, None);

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
        handle.stop();
    }

    #[test]
    fn mute_suppresses_outbound_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared.clone(), None);

        shared.muted.store(true, Ordering::Relaxed);

        let _ = ch.pcm_writer.tx.try_send(vec![9999i16; 160]);
        std::thread::sleep(Duration::from_millis(50));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "PCMWriter output must be suppressed while muted"
        );

        handle.stop();
    }

    #[test]
    fn mute_suppresses_outbound_rtp_writer() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared.clone(), None);

        shared.muted.store(true, Ordering::Relaxed);

        let _ = ch.rtp_writer.tx.try_send(make_rtp(42, 0, vec![]));
        std::thread::sleep(Duration::from_millis(50));

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        assert!(
            sent_rx.try_recv().is_err(),
            "RTPWriter output must be suppressed while muted"
        );

        handle.stop();
    }

    #[test]
    fn unmute_restores_outbound_pcm() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared.clone(), None);

        shared.muted.store(true, Ordering::Relaxed);
        shared.muted.store(false, Ordering::Relaxed);

        ch.pcm_writer.tx.send(vec![0i16; 160]).unwrap();

        let sent_rx = &ch.sent_rtp.as_ref().unwrap().rx;
        let sent = read_pkt(sent_rx, 200);
        assert!(
            sent.is_some(),
            "PCMWriter should produce packets after unmute"
        );

        handle.stop();
    }

    #[test]
    fn mute_inbound_still_flows() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch.clone(), shared.clone(), None);

        shared.muted.store(true, Ordering::Relaxed);

        inject(&ch, make_rtp(1, 0, vec![0; 160]));

        let raw = read_pkt(&ch.rtp_raw_reader.rx, 200);
        assert!(raw.is_some(), "inbound RTP must still flow while muted");

        handle.stop();
    }

    #[test]
    fn stop_media_terminates_thread() {
        let ch = test_channels();
        let shared = test_shared(CallState::Active);
        let mut handle = start_media(MediaConfig::default(), ch, shared, None);

        handle.stop();
        // Thread should have joined. If not, test would hang.
        assert!(handle.thread.is_none());
    }
}
