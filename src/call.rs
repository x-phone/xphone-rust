use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::info;

use crate::config::DialOptions;
use crate::dialog::Dialog;
use crate::dtmf;
use crate::error::{Error, Result};
use crate::media::{self, MediaChannels, MediaConfig, MediaHandle, MediaTransport};
use crate::sdp;
use crate::srtp::SrtpContext;
use crate::types::*;

/// Default codec preference order (payload types).
const DEFAULT_CODEC_PREFS: &[i32] = &[8, 0, 9, 101, 111];

fn new_call_id() -> String {
    let mut buf = [0u8; 16];
    // Use thread_rng for non-crypto random IDs.
    for b in &mut buf {
        *b = rand_byte();
    }
    format!("CA{}", hex::encode(&buf))
}

fn rand_byte() -> u8 {
    use std::cell::Cell;
    thread_local! {
        static RNG: Cell<u64> = Cell::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        );
    }
    RNG.with(|rng| {
        // Simple xorshift64
        let mut s = rng.get();
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        rng.set(s);
        s as u8
    })
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- SIP header helpers ---

/// Extracts the SIP URI from a header value.
/// e.g. `"Alice" <sip:1001@host>;tag=xyz` -> `sip:1001@host`
pub fn sip_header_uri(val: &str) -> &str {
    if let (Some(start), Some(end)) = (val.find('<'), val.find('>')) {
        if end > start {
            return &val[start + 1..end];
        }
    }
    val
}

/// Extracts the user part from a SIP header value.
/// e.g. `"Alice" <sip:+15551234567@host>;tag=xyz` -> `+15551234567`
pub fn sip_header_user(val: &str) -> &str {
    let uri = sip_header_uri(val);
    let uri = if let Some(i) = uri.find(':') {
        &uri[i + 1..]
    } else {
        uri
    };
    if let Some(i) = uri.find('@') {
        &uri[..i]
    } else {
        uri
    }
}

/// Extracts the display name from a SIP header value.
/// e.g. `"Alice" <sip:1001@host>` -> `Alice`
pub fn sip_header_display_name(val: &str) -> &str {
    let lt = match val.find('<') {
        Some(0) | None => return "",
        Some(i) => i,
    };
    let name = val[..lt].trim();
    if name.len() >= 2 && name.starts_with('"') && name.ends_with('"') {
        &name[1..name.len() - 1]
    } else {
        name
    }
}

// --- Call struct ---

struct CallInner {
    id: String,
    state: CallState,
    direction: Direction,
    opts: DialOptions,
    start_time: Option<Instant>,
    muted: bool,

    codec_prefs: Vec<i32>,
    local_ip: String,
    rtp_port: i32,
    remote_ip: String,
    remote_port: i32,

    local_sdp: String,
    remote_sdp: String,
    codec: Codec,

    media_active: bool,
    /// Whether SRTP is enabled for this call.
    srtp_enabled: bool,
    /// Local SRTP keying material (base64 inline key).
    srtp_local_key: String,
    /// Remote SRTP keying material (base64 inline key).
    srtp_remote_key: String,

    rtp_socket: Option<Arc<UdpSocket>>,
    media_handle: Option<MediaHandle>,
    media_channels: Option<Arc<MediaChannels>>,
    media_shared: Option<Arc<media::MediaSharedState>>,

    on_ended_fn: Option<Arc<dyn Fn(EndReason) + Send + Sync>>,
    on_ended_internal: Option<Arc<dyn Fn(EndReason) + Send + Sync>>,
    on_media_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_state_fn: Option<Arc<dyn Fn(CallState) + Send + Sync>>,
    on_dtmf_fn: Option<Arc<dyn Fn(String) + Send + Sync>>,
    on_hold_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_resume_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_mute_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unmute_fn: Option<Arc<dyn Fn() + Send + Sync>>,

    session_timer: Option<std::thread::JoinHandle<()>>,
    session_timer_cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
}

/// Manages a single SIP call lifecycle including state transitions, media, and callbacks.
///
/// Created via [`Call::new_inbound`] or [`Call::new_outbound`] and returned as `Arc<Call>`.
pub struct Call {
    inner: Mutex<CallInner>,
    dlg: Arc<dyn Dialog>,
}

impl Call {
    /// Creates a new inbound call in the `Ringing` state.
    pub fn new_inbound(dlg: Arc<dyn Dialog>) -> Arc<Self> {
        Arc::new(Call {
            inner: Mutex::new(CallInner {
                id: new_call_id(),
                state: CallState::Ringing,
                direction: Direction::Inbound,
                opts: DialOptions::default(),
                start_time: None,
                muted: false,
                codec_prefs: Vec::new(),
                local_ip: String::new(),
                rtp_port: 0,
                remote_ip: String::new(),
                remote_port: 0,
                local_sdp: String::new(),
                remote_sdp: String::new(),
                codec: Codec::PCMU,
                media_active: false,
                srtp_enabled: false,
                srtp_local_key: String::new(),
                srtp_remote_key: String::new(),
                rtp_socket: None,
                media_handle: None,
                media_channels: None,
                media_shared: None,
                on_ended_fn: None,
                on_ended_internal: None,
                on_media_fn: None,
                on_state_fn: None,
                on_dtmf_fn: None,
                on_hold_fn: None,
                on_resume_fn: None,
                on_mute_fn: None,
                on_unmute_fn: None,
                session_timer: None,
                session_timer_cancel: None,
            }),
            dlg,
        })
    }

    /// Creates a new outbound call in the `Dialing` state with the given dial options.
    pub fn new_outbound(dlg: Arc<dyn Dialog>, opts: DialOptions) -> Arc<Self> {
        Arc::new(Call {
            inner: Mutex::new(CallInner {
                id: new_call_id(),
                state: CallState::Dialing,
                direction: Direction::Outbound,
                opts,
                start_time: None,
                muted: false,
                codec_prefs: Vec::new(),
                local_ip: String::new(),
                rtp_port: 0,
                remote_ip: String::new(),
                remote_port: 0,
                local_sdp: String::new(),
                remote_sdp: String::new(),
                codec: Codec::PCMU,
                media_active: false,
                srtp_enabled: false,
                srtp_local_key: String::new(),
                srtp_remote_key: String::new(),
                rtp_socket: None,
                media_handle: None,
                media_channels: None,
                media_shared: None,
                on_ended_fn: None,
                on_ended_internal: None,
                on_media_fn: None,
                on_state_fn: None,
                on_dtmf_fn: None,
                on_hold_fn: None,
                on_resume_fn: None,
                on_mute_fn: None,
                on_unmute_fn: None,
                session_timer: None,
                session_timer_cancel: None,
            }),
            dlg,
        })
    }

    // --- Getters ---

    /// Returns the unique internal call identifier.
    pub fn id(&self) -> String {
        self.inner.lock().id.clone()
    }

    /// Returns the SIP Call-ID header value from the underlying dialog.
    pub fn call_id(&self) -> String {
        self.dlg.call_id()
    }

    /// Returns the call direction (inbound or outbound).
    pub fn direction(&self) -> Direction {
        self.inner.lock().direction
    }

    /// Returns the current call state (e.g., Ringing, Active, OnHold, Ended).
    pub fn state(&self) -> CallState {
        self.inner.lock().state
    }

    /// Returns the negotiated audio codec for this call.
    pub fn codec(&self) -> Codec {
        self.inner.lock().codec
    }

    /// Returns the local SDP offer or answer for this call.
    pub fn local_sdp(&self) -> String {
        self.inner.lock().local_sdp.clone()
    }

    /// Returns the remote SDP received from the far end.
    pub fn remote_sdp(&self) -> String {
        self.inner.lock().remote_sdp.clone()
    }

    /// Returns the instant the call became active, or `None` if not yet answered.
    pub fn start_time(&self) -> Option<Instant> {
        self.inner.lock().start_time
    }

    /// Returns the elapsed duration since the call became active, or zero if not yet answered.
    pub fn duration(&self) -> Duration {
        let inner = self.inner.lock();
        match inner.start_time {
            Some(t) => t.elapsed(),
            None => Duration::ZERO,
        }
    }

    /// Returns the full SIP URI of the remote party (e.g., `sip:user@host`).
    pub fn remote_uri(&self) -> String {
        let vals = self.dlg.header("From");
        vals.first()
            .map(|v| sip_header_uri(v).to_string())
            .unwrap_or_default()
    }

    /// Returns the user part of the SIP From header (e.g., `+15551234567`).
    pub fn from(&self) -> String {
        let vals = self.dlg.header("From");
        vals.first()
            .map(|v| sip_header_user(v).to_string())
            .unwrap_or_default()
    }

    /// Returns the user part of the SIP To header.
    pub fn to(&self) -> String {
        let vals = self.dlg.header("To");
        vals.first()
            .map(|v| sip_header_user(v).to_string())
            .unwrap_or_default()
    }

    /// Returns the display name from the SIP From header (e.g., `Alice`).
    pub fn from_name(&self) -> String {
        let vals = self.dlg.header("From");
        vals.first()
            .map(|v| sip_header_display_name(v).to_string())
            .unwrap_or_default()
    }

    /// Returns the remote media IP address, parsed from the remote SDP.
    pub fn remote_ip(&self) -> String {
        let inner = self.inner.lock();
        if !inner.remote_ip.is_empty() {
            return inner.remote_ip.clone();
        }
        if inner.remote_sdp.is_empty() {
            return String::new();
        }
        sdp::parse(&inner.remote_sdp)
            .map(|s| s.connection.clone())
            .unwrap_or_default()
    }

    /// Returns the remote RTP port, parsed from the remote SDP.
    pub fn remote_port(&self) -> i32 {
        let inner = self.inner.lock();
        if inner.remote_port != 0 {
            return inner.remote_port;
        }
        if inner.remote_sdp.is_empty() {
            return 0;
        }
        sdp::parse(&inner.remote_sdp)
            .map(|s| s.media.first().map(|m| m.port).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Returns the values of a specific SIP header by name.
    pub fn header(&self, name: &str) -> Vec<String> {
        self.dlg.header(name)
    }

    /// Returns all SIP headers from the underlying dialog.
    pub fn headers(&self) -> HashMap<String, Vec<String>> {
        self.dlg.headers()
    }

    /// Returns whether the media session is currently active.
    pub fn media_session_active(&self) -> bool {
        self.inner.lock().media_active
    }

    // --- Codec helpers ---

    fn resolve_codec_prefs(inner: &CallInner) -> &[i32] {
        if !inner.codec_prefs.is_empty() {
            &inner.codec_prefs
        } else {
            DEFAULT_CODEC_PREFS
        }
    }

    fn build_local_sdp(inner: &mut CallInner, direction: &str) -> String {
        if inner.local_ip.is_empty() {
            inner.local_ip = "127.0.0.1".into();
        }
        let prefs = Self::resolve_codec_prefs(inner);
        if inner.srtp_enabled && !inner.srtp_local_key.is_empty() {
            sdp::build_offer_srtp(
                &inner.local_ip,
                inner.rtp_port,
                prefs,
                direction,
                &inner.srtp_local_key,
            )
        } else {
            sdp::build_offer(&inner.local_ip, inner.rtp_port, prefs, direction)
        }
    }

    fn build_answer_sdp(inner: &mut CallInner, remote: &sdp::Session, direction: &str) -> String {
        if inner.local_ip.is_empty() {
            inner.local_ip = "127.0.0.1".into();
        }
        let remote_codecs: &[i32] = remote
            .media
            .first()
            .map(|m| m.codecs.as_slice())
            .unwrap_or(&[]);
        let prefs = Self::resolve_codec_prefs(inner);
        if inner.srtp_enabled && !inner.srtp_local_key.is_empty() {
            sdp::build_answer_srtp(
                &inner.local_ip,
                inner.rtp_port,
                prefs,
                remote_codecs,
                direction,
                &inner.srtp_local_key,
            )
        } else {
            sdp::build_answer(
                &inner.local_ip,
                inner.rtp_port,
                prefs,
                remote_codecs,
                direction,
            )
        }
    }

    fn negotiate_codec(inner: &mut CallInner, sess: &sdp::Session) {
        let remote_codecs: &[i32] = sess
            .media
            .first()
            .map(|m| m.codecs.as_slice())
            .unwrap_or(&[]);
        let prefs = Self::resolve_codec_prefs(inner);
        let pt = sdp::negotiate_codec(prefs, remote_codecs);
        if pt >= 0 {
            if let Some(c) = Codec::from_payload_type(pt) {
                inner.codec = c;
            }
        }
    }

    fn set_remote_endpoint(inner: &mut CallInner, sess: &sdp::Session) {
        inner.remote_ip = sess.connection.clone();
        if let Some(m) = sess.media.first() {
            inner.remote_port = m.port;
        }
    }

    // --- Callback dispatch (copy fn under lock, fire outside) ---

    fn fire_on_state(inner: &CallInner, state: CallState) {
        if let Some(ref f) = inner.on_state_fn {
            let f = Arc::clone(f);
            std::thread::spawn(move || f(state));
        }
    }

    fn fire_on_ended(inner: &CallInner, reason: EndReason) {
        // Stop session timer.
        if let Some(ref cancel) = inner.session_timer_cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(ref f) = inner.on_ended_internal {
            let f = Arc::clone(f);
            std::thread::spawn(move || f(reason));
        }
        if let Some(ref f) = inner.on_ended_fn {
            let f = Arc::clone(f);
            std::thread::spawn(move || f(reason));
        }
    }

    // --- Session timer ---

    fn start_session_timer(self: &Arc<Self>) {
        let vals = self.dlg.header("Session-Expires");
        if vals.is_empty() {
            return;
        }
        // Handle parameters like "1800;refresher=uac" by taking text before ';'.
        let raw = vals[0].split(';').next().unwrap_or("").trim();
        let seconds: u64 = match raw.parse() {
            Ok(s) if s > 0 => s,
            _ => return,
        };
        let interval = Duration::from_secs(seconds) / 2;
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel);
        let call = Arc::clone(self);
        let handle = std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let refresh_sdp = {
                let mut inner = call.inner.lock();
                if inner.state == CallState::Ended {
                    return;
                }
                Self::build_local_sdp(&mut inner, sdp::DIR_SEND_RECV)
            };
            let _ = call.dlg.send_reinvite(refresh_sdp.as_bytes());
        });
        let mut inner = self.inner.lock();
        inner.session_timer = Some(handle);
        inner.session_timer_cancel = Some(cancel);
    }

    // --- Actions ---

    /// Accepts an inbound call, transitioning from `Ringing` to `Active`.
    ///
    /// Sends a 200 OK with SDP, starts the media pipeline, and fires state/media callbacks.
    pub fn accept(self: &Arc<Self>) -> Result<()> {
        info!(call_id = %self.call_id(), "Call accepting");
        let on_media_fn;
        {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Ringing {
                info!(state = ?inner.state, "Call accept rejected — not in Ringing state");
                return Err(Error::InvalidState);
            }

            if !inner.remote_sdp.is_empty() {
                if let Ok(sess) = sdp::parse(&inner.remote_sdp) {
                    Self::negotiate_codec(&mut inner, &sess);
                    inner.local_sdp = Self::build_answer_sdp(&mut inner, &sess, sdp::DIR_SEND_RECV);
                    Self::set_remote_endpoint(&mut inner, &sess);
                } else {
                    inner.local_sdp = Self::build_local_sdp(&mut inner, sdp::DIR_SEND_RECV);
                }
            } else {
                inner.local_sdp = Self::build_local_sdp(&mut inner, sdp::DIR_SEND_RECV);
            }

            let _ = self.dlg.respond(200, "OK", inner.local_sdp.as_bytes());
            inner.state = CallState::Active;
            inner.start_time = Some(Instant::now());
            inner.media_active = true;
            Self::start_media_pipeline(&mut inner);
            Self::fire_on_state(&inner, CallState::Active);
            on_media_fn = inner.on_media_fn.clone();
        }

        self.start_session_timer();

        if let Some(f) = on_media_fn {
            std::thread::spawn(move || f());
        }
        Ok(())
    }

    /// Rejects an inbound call with the given SIP response code and reason.
    pub fn reject(&self, code: u16, reason: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != CallState::Ringing {
            return Err(Error::InvalidState);
        }
        let _ = self.dlg.respond(code, reason, &[]);
        inner.state = CallState::Ended;
        Self::fire_on_state(&inner, CallState::Ended);
        Self::fire_on_ended(&inner, EndReason::Rejected);
        Ok(())
    }

    /// Ends the call. Sends CANCEL if dialing, or BYE if active/on-hold.
    pub fn end(&self) -> Result<()> {
        let mut inner = self.inner.lock();
        if let Some(ref cancel) = inner.session_timer_cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        match inner.state {
            CallState::Dialing | CallState::RemoteRinging | CallState::EarlyMedia => {
                let _ = self.dlg.send_cancel();
                inner.state = CallState::Ended;
                Self::fire_on_state(&inner, CallState::Ended);
                Self::fire_on_ended(&inner, EndReason::Cancelled);
                Ok(())
            }
            CallState::Active | CallState::OnHold => {
                let _ = self.dlg.send_bye();
                inner.state = CallState::Ended;
                if let Some(ref mut h) = inner.media_handle {
                    h.stop();
                }
                Self::fire_on_state(&inner, CallState::Ended);
                Self::fire_on_ended(&inner, EndReason::Local);
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Places the call on hold by sending a re-INVITE with `sendonly` SDP.
    pub fn hold(&self) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != CallState::Active {
            return Err(Error::InvalidState);
        }
        inner.local_sdp = Self::build_local_sdp(&mut inner, sdp::DIR_SEND_ONLY);
        let _ = self.dlg.send_reinvite(inner.local_sdp.as_bytes());
        inner.state = CallState::OnHold;
        Self::fire_on_state(&inner, CallState::OnHold);
        Ok(())
    }

    /// Resumes a held call by sending a re-INVITE with `sendrecv` SDP.
    pub fn resume(&self) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != CallState::OnHold {
            return Err(Error::InvalidState);
        }
        inner.local_sdp = Self::build_local_sdp(&mut inner, sdp::DIR_SEND_RECV);
        let _ = self.dlg.send_reinvite(inner.local_sdp.as_bytes());
        inner.state = CallState::Active;
        Self::fire_on_state(&inner, CallState::Active);
        Ok(())
    }

    /// Mutes the local audio. Returns an error if already muted or not active.
    pub fn mute(&self) -> Result<()> {
        let on_mute;
        {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            if inner.muted {
                return Err(Error::AlreadyMuted);
            }
            inner.muted = true;
            on_mute = inner.on_mute_fn.clone();
        }
        if let Some(f) = on_mute {
            std::thread::spawn(move || f());
        }
        Ok(())
    }

    /// Unmutes the local audio. Returns an error if not muted or not active.
    pub fn unmute(&self) -> Result<()> {
        let on_unmute;
        {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            if !inner.muted {
                return Err(Error::NotMuted);
            }
            inner.muted = false;
            on_unmute = inner.on_unmute_fn.clone();
        }
        if let Some(f) = on_unmute {
            std::thread::spawn(move || f());
        }
        Ok(())
    }

    /// Sends a DTMF digit (e.g., `"1"`, `"#"`, `"*"`) as RFC 2833 RTP events.
    pub fn send_dtmf(&self, digit: &str) -> Result<()> {
        let (rtp_socket, remote_ip, remote_port) = {
            let inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            (
                inner.rtp_socket.clone(),
                inner.remote_ip.clone(),
                inner.remote_port,
            )
        };
        if dtmf::digit_to_code(digit).is_none() {
            return Err(Error::InvalidDtmfDigit);
        }
        let pkts = dtmf::encode_dtmf(digit, 0, 0, 0)?;
        // Send directly to UDP socket (like Go's SendDTMF).
        if let Some(sock) = rtp_socket {
            if !remote_ip.is_empty() && remote_port > 0 {
                if let Ok(addr) =
                    format!("{}:{}", remote_ip, remote_port).parse::<std::net::SocketAddr>()
                {
                    for pkt in &pkts {
                        let _ = sock.send_to(&pkt.to_bytes(), addr);
                    }
                }
            }
        }
        Ok(())
    }

    /// Initiates a blind (unattended) transfer to the given SIP target URI.
    pub fn blind_transfer(self: &Arc<Self>, target: &str) -> Result<()> {
        {
            let inner = self.inner.lock();
            if inner.state != CallState::Active && inner.state != CallState::OnHold {
                return Err(Error::InvalidState);
            }
        }
        let call = Arc::clone(self);
        self.dlg.on_notify(Box::new(move |code| {
            if code == 200 {
                let mut inner = call.inner.lock();
                if inner.state == CallState::Ended {
                    return;
                }
                inner.state = CallState::Ended;
                Self::fire_on_state(&inner, CallState::Ended);
                Self::fire_on_ended(&inner, EndReason::Transfer);
            }
        }));
        let _ = self.dlg.send_refer(target);
        Ok(())
    }

    // --- Simulation methods (for tests and incoming SIP events) ---

    /// Simulates receiving a SIP response (180, 183, 200) to drive outbound call state transitions.
    pub fn simulate_response(self: &Arc<Self>, code: u16, _reason: &str) {
        let start_timer;
        {
            let mut inner = self.inner.lock();
            start_timer = match code {
                180 => {
                    if inner.state == CallState::Dialing {
                        inner.state = CallState::RemoteRinging;
                        Self::fire_on_state(&inner, CallState::RemoteRinging);
                    }
                    false
                }
                183 => {
                    if inner.opts.early_media
                        && (inner.state == CallState::Dialing
                            || inner.state == CallState::RemoteRinging)
                    {
                        inner.state = CallState::EarlyMedia;
                        inner.media_active = true;
                        Self::fire_on_state(&inner, CallState::EarlyMedia);
                        if let Some(ref f) = inner.on_media_fn {
                            let f = Arc::clone(f);
                            std::thread::spawn(move || f());
                        }
                    }
                    false
                }
                200 => {
                    if inner.state == CallState::Dialing
                        || inner.state == CallState::RemoteRinging
                        || inner.state == CallState::EarlyMedia
                    {
                        inner.state = CallState::Active;
                        inner.start_time = Some(Instant::now());
                        inner.media_active = true;
                        Self::start_media_pipeline(&mut inner);
                        Self::fire_on_state(&inner, CallState::Active);
                        if let Some(ref f) = inner.on_media_fn {
                            let f = Arc::clone(f);
                            std::thread::spawn(move || f());
                        }
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
        }
        if start_timer {
            self.start_session_timer();
        }
    }

    /// Simulates receiving a remote BYE, ending the call.
    pub fn simulate_bye(&self) {
        let mut inner = self.inner.lock();
        if inner.state == CallState::Ended {
            return;
        }
        // If the call was still ringing (not yet accepted), treat as Cancelled.
        let reason = if inner.state == CallState::Ringing {
            info!(call_id = %self.dlg.call_id(), state = ?inner.state, "Call cancelled by remote (BYE/CANCEL while ringing)");
            EndReason::Cancelled
        } else {
            info!(call_id = %self.dlg.call_id(), state = ?inner.state, "Call ended by remote BYE");
            EndReason::Remote
        };
        inner.state = CallState::Ended;
        if let Some(ref mut h) = inner.media_handle {
            h.stop();
        }
        Self::fire_on_state(&inner, CallState::Ended);
        Self::fire_on_ended(&inner, reason);
    }

    /// Simulates receiving a remote re-INVITE, handling hold/resume based on SDP direction.
    pub fn simulate_reinvite(&self, raw_sdp: &str) {
        let mut inner = self.inner.lock();
        if inner.state == CallState::Ended {
            return;
        }

        let sess = match sdp::parse(raw_sdp) {
            Ok(s) => s,
            Err(_) => return,
        };
        inner.remote_sdp = raw_sdp.to_string();
        Self::set_remote_endpoint(&mut inner, &sess);

        let dir = sess.dir();
        let mut hold_fn = None;
        let mut resume_fn = None;
        let mut state_fn: Option<Box<dyn FnOnce() + Send>> = None;

        let is_hold_dir =
            dir == sdp::DIR_SEND_ONLY || dir == sdp::DIR_RECV_ONLY || dir == sdp::DIR_INACTIVE;
        match (is_hold_dir, inner.state) {
            (true, CallState::Active) => {
                inner.state = CallState::OnHold;
                hold_fn = inner.on_hold_fn.clone();
                if let Some(ref f) = inner.on_state_fn {
                    let f = Arc::clone(f);
                    state_fn = Some(Box::new(move || f(CallState::OnHold)));
                }
            }
            (false, CallState::OnHold) if dir == sdp::DIR_SEND_RECV => {
                inner.state = CallState::Active;
                resume_fn = inner.on_resume_fn.clone();
                if let Some(ref f) = inner.on_state_fn {
                    let f = Arc::clone(f);
                    state_fn = Some(Box::new(move || f(CallState::Active)));
                }
            }
            _ => {}
        }

        Self::negotiate_codec(&mut inner, &sess);
        drop(inner);

        if let Some(f) = state_fn {
            std::thread::spawn(f);
        }
        if let Some(f) = hold_fn {
            std::thread::spawn(move || f());
        }
        if let Some(f) = resume_fn {
            std::thread::spawn(move || f());
        }
    }

    /// Sets the remote SDP, parsing it to extract remote endpoint and codec info.
    pub fn set_remote_sdp(&self, raw_sdp: &str) {
        let mut inner = self.inner.lock();
        inner.remote_sdp = raw_sdp.to_string();
        if let Ok(sess) = sdp::parse(raw_sdp) {
            Self::set_remote_endpoint(&mut inner, &sess);
            Self::negotiate_codec(&mut inner, &sess);
            // Extract remote SRTP key if present and suite is supported.
            if sess.is_srtp() {
                if let Some(crypto) = sess.first_crypto() {
                    if crypto.suite == crate::srtp::SUPPORTED_SUITE {
                        inner.srtp_remote_key = crypto.key_params.clone();
                        inner.srtp_enabled = true;
                    } else {
                        tracing::warn!("remote offered unsupported SRTP suite: {}", crypto.suite);
                    }
                }
            }
        }
    }

    /// Sets the local media address and RTP port for this call.
    pub(crate) fn set_local_media(&self, ip: &str, port: i32) {
        let mut inner = self.inner.lock();
        inner.local_ip = ip.to_string();
        inner.rtp_port = port;
    }

    /// Stores the local SDP offer (outbound calls).
    pub(crate) fn set_local_sdp(&self, sdp: &str) {
        self.inner.lock().local_sdp = sdp.to_string();
    }

    /// Sets the RTP socket for this call (production path).
    pub(crate) fn set_rtp_socket(&self, socket: UdpSocket) {
        self.inner.lock().rtp_socket = Some(Arc::new(socket));
    }

    /// Enables SRTP and stores the local inline key.
    /// The remote key is extracted from remote SDP when available.
    pub(crate) fn set_srtp(&self, local_inline_key: &str) {
        let mut inner = self.inner.lock();
        inner.srtp_enabled = true;
        inner.srtp_local_key = local_inline_key.to_string();
    }

    /// Starts the media pipeline if an RTP socket is available and remote endpoint is known.
    fn start_media_pipeline(inner: &mut CallInner) {
        if inner.media_handle.is_some() {
            return; // already started
        }
        let socket = match inner.rtp_socket.as_ref() {
            Some(s) => Arc::clone(s),
            None => return, // no socket — test path, skip media
        };
        if inner.remote_ip.is_empty() || inner.remote_port <= 0 {
            return; // no remote endpoint yet
        }
        let remote_addr: std::net::SocketAddr =
            match format!("{}:{}", inner.remote_ip, inner.remote_port).parse() {
                Ok(a) => a,
                Err(_) => return,
            };

        let transport = Arc::new(MediaTransport::new(
            socket.try_clone().expect("failed to clone RTP socket"),
            remote_addr,
        ));
        let channels = Arc::new(MediaChannels::new());
        let shared = Arc::new(media::MediaSharedState::new(inner.state));
        // Wire callbacks from Call into the media thread's shared state.
        if let Some(ref f) = inner.on_dtmf_fn {
            *shared.on_dtmf_fn.lock() = Some(Arc::clone(f));
        }
        // Create SRTP contexts if enabled and both keys are available.
        let (srtp_in, srtp_out) = if inner.srtp_enabled
            && !inner.srtp_local_key.is_empty()
            && !inner.srtp_remote_key.is_empty()
        {
            let inbound = match SrtpContext::from_sdes_inline(&inner.srtp_remote_key) {
                Ok(ctx) => Some(ctx),
                Err(e) => {
                    tracing::error!("SRTP inbound context creation failed: {}", e);
                    return;
                }
            };
            let outbound =
                match SrtpContext::from_sdes_inline(&format!("inline:{}", inner.srtp_local_key)) {
                    Ok(ctx) => Some(ctx),
                    Err(e) => {
                        tracing::error!("SRTP outbound context creation failed: {}", e);
                        return;
                    }
                };
            (inbound, outbound)
        } else {
            (None, None)
        };
        let config = MediaConfig {
            codec: inner.codec,
            srtp_inbound: srtp_in,
            srtp_outbound: srtp_out,
            ..MediaConfig::default()
        };
        let handle = media::start_media(
            config,
            Arc::clone(&channels),
            Arc::clone(&shared),
            Some(transport),
        );
        inner.media_handle = Some(handle);
        inner.media_channels = Some(channels);
        inner.media_shared = Some(shared);
    }

    /// Sends a SIP response via the dialog (e.g., 180 Ringing for inbound calls).
    pub(crate) fn dlg_respond(&self, code: u16, reason: &str) -> Result<()> {
        self.dlg.respond(code, reason, &[])
    }

    // --- Callback setters ---

    /// Registers a callback invoked on every state transition.
    pub fn on_state(&self, f: impl Fn(CallState) + Send + Sync + 'static) {
        self.inner.lock().on_state_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when the call ends, with the reason.
    pub fn on_ended(&self, f: impl Fn(EndReason) + Send + Sync + 'static) {
        self.inner.lock().on_ended_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when the media session becomes available.
    pub fn on_media(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_media_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when a DTMF digit is received.
    pub fn on_dtmf(&self, f: impl Fn(String) + Send + Sync + 'static) {
        let cb: Arc<dyn Fn(String) + Send + Sync> = Arc::new(f);
        let mut inner = self.inner.lock();
        inner.on_dtmf_fn = Some(Arc::clone(&cb));
        // Propagate to media thread's shared state if pipeline is running.
        if let Some(ref shared) = inner.media_shared {
            *shared.on_dtmf_fn.lock() = Some(cb);
        }
    }

    /// Registers a callback invoked when the call is placed on hold.
    pub fn on_hold(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_hold_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when the call is resumed from hold.
    pub fn on_resume(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_resume_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when the call is muted.
    pub fn on_mute(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_mute_fn = Some(Arc::new(f));
    }

    /// Registers a callback invoked when the call is unmuted.
    pub fn on_unmute(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_unmute_fn = Some(Arc::new(f));
    }

    pub(crate) fn on_ended_internal(&self, f: impl Fn(EndReason) + Send + Sync + 'static) {
        self.inner.lock().on_ended_internal = Some(Arc::new(f));
    }

    // --- Media channel accessors ---

    /// Returns the RTP writer sender (for sending raw RTP packets outbound).
    pub fn rtp_writer(&self) -> Option<crossbeam_channel::Sender<RtpPacket>> {
        self.inner
            .lock()
            .media_channels
            .as_ref()
            .map(|c| c.rtp_writer.tx.clone())
    }

    /// Returns the RTP reader receiver (post-jitter-buffer, reordered).
    pub fn rtp_reader(&self) -> Option<crossbeam_channel::Receiver<RtpPacket>> {
        self.inner
            .lock()
            .media_channels
            .as_ref()
            .map(|c| c.rtp_reader.rx.clone())
    }

    /// Returns the RTP raw reader receiver (pre-jitter-buffer, wire order).
    pub fn rtp_raw_reader(&self) -> Option<crossbeam_channel::Receiver<RtpPacket>> {
        self.inner
            .lock()
            .media_channels
            .as_ref()
            .map(|c| c.rtp_raw_reader.rx.clone())
    }

    /// Returns the PCM writer sender (for sending PCM samples for encoding + sending).
    pub fn pcm_writer(&self) -> Option<crossbeam_channel::Sender<Vec<i16>>> {
        self.inner
            .lock()
            .media_channels
            .as_ref()
            .map(|c| c.pcm_writer.tx.clone())
    }

    /// Returns the PCM reader receiver (decoded PCM from inbound RTP).
    pub fn pcm_reader(&self) -> Option<crossbeam_channel::Receiver<Vec<i16>>> {
        self.inner
            .lock()
            .media_channels
            .as_ref()
            .map(|c| c.pcm_reader.rx.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::dialog::MockDialog;
    use std::sync::mpsc;
    use std::time::Duration;

    fn mock_dlg() -> Arc<MockDialog> {
        Arc::new(MockDialog::new())
    }

    fn mock_dlg_with_headers(headers: HashMap<String, Vec<String>>) -> Arc<MockDialog> {
        Arc::new(MockDialog::with_headers(headers))
    }

    fn test_sdp(ip: &str, port: i32, dir: &str, codecs: &[i32]) -> String {
        sdp::build_offer(ip, port, codecs, dir)
    }

    // --- Inbound: basic state transitions ---

    #[test]
    fn inbound_initial_state_is_ringing() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.state(), CallState::Ringing);
    }

    #[test]
    fn accept_transitions_to_active() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn accept_sends_sdp_answer() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        assert_eq!(dlg.last_response_code(), 200);
        assert!(!dlg.last_response_body().is_empty());
    }

    #[test]
    fn accept_sets_media_active() {
        let call = Call::new_inbound(mock_dlg());
        assert!(!call.media_session_active());
        call.accept().unwrap();
        assert!(call.media_session_active());
    }

    #[test]
    fn reject_sends_correct_sip_code() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.reject(486, "Busy Here").unwrap();
        assert_eq!(dlg.last_response_code(), 486);
        assert_eq!(dlg.last_response_reason(), "Busy Here");
    }

    #[test]
    fn reject_transitions_to_ended() {
        let call = Call::new_inbound(mock_dlg());
        call.reject(486, "Busy Here").unwrap();
        assert_eq!(call.state(), CallState::Ended);
    }

    #[test]
    fn reject_fires_ended_by_rejected() {
        let call = Call::new_inbound(mock_dlg());
        let (tx, rx) = mpsc::channel();
        call.on_ended(move |r| {
            let _ = tx.send(r);
        });
        call.reject(486, "Busy Here").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Rejected
        );
    }

    #[test]
    fn cannot_accept_after_rejected() {
        let call = Call::new_inbound(mock_dlg());
        call.reject(486, "Busy Here").unwrap();
        assert!(call.accept().is_err());
    }

    #[test]
    fn cannot_reject_after_accepted() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert!(call.reject(486, "Busy Here").is_err());
    }

    // --- Outbound: state transitions ---

    #[test]
    fn outbound_initial_state_is_dialing() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        assert_eq!(call.state(), CallState::Dialing);
    }

    #[test]
    fn outbound_transitions_on_remote_ringing() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(180, "Ringing");
        assert_eq!(call.state(), CallState::RemoteRinging);
    }

    #[test]
    fn outbound_transitions_to_active_on_200() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(180, "Ringing");
        call.simulate_response(200, "OK");
        assert_eq!(call.state(), CallState::Active);
    }

    // --- 183 / EarlyMedia ---

    #[test]
    fn early_media_183_transitions() {
        let opts = DialOptions {
            early_media: true,
            ..Default::default()
        };
        let call = Call::new_outbound(mock_dlg(), opts);
        call.simulate_response(183, "Session Progress");
        assert_eq!(call.state(), CallState::EarlyMedia);
    }

    #[test]
    fn no_early_media_183_stays_remote_ringing() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(180, "Ringing");
        call.simulate_response(183, "Session Progress");
        assert_eq!(call.state(), CallState::RemoteRinging);
    }

    #[test]
    fn no_early_media_183_media_not_active() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(183, "Session Progress");
        assert!(!call.media_session_active());
    }

    // --- OnMedia event ---

    #[test]
    fn on_media_fires_after_200() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        let (tx, rx) = mpsc::channel();
        call.on_media(move || {
            let _ = tx.send(());
        });
        call.simulate_response(200, "OK");
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn on_media_fires_on_183_with_early_media() {
        let opts = DialOptions {
            early_media: true,
            ..Default::default()
        };
        let call = Call::new_outbound(mock_dlg(), opts);
        let (tx, rx) = mpsc::channel();
        call.on_media(move || {
            let _ = tx.send(());
        });
        call.simulate_response(183, "Session Progress");
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn on_media_does_not_fire_on_183_without_early_media() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        let (tx, _rx) = mpsc::channel::<()>();
        call.on_media(move || {
            let _ = tx.send(());
        });
        call.simulate_response(183, "Session Progress");
        std::thread::sleep(Duration::from_millis(50));
        assert!(_rx.try_recv().is_err());
    }

    // --- End() semantics ---

    #[test]
    fn end_before_answer_sends_cancel() {
        let dlg = mock_dlg();
        let call = Call::new_outbound(dlg.clone(), DialOptions::default());
        call.simulate_response(180, "Ringing");
        call.end().unwrap();
        assert!(dlg.cancel_sent());
        assert!(!dlg.bye_sent());
    }

    #[test]
    fn end_before_answer_fires_ended_by_cancelled() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(180, "Ringing");
        let (tx, rx) = mpsc::channel();
        call.on_ended(move |r| {
            let _ = tx.send(r);
        });
        call.end().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Cancelled
        );
    }

    #[test]
    fn end_while_active_sends_bye() {
        let dlg = mock_dlg();
        let call = Call::new_outbound(dlg.clone(), DialOptions::default());
        call.simulate_response(200, "OK");
        call.end().unwrap();
        assert!(dlg.bye_sent());
        assert!(!dlg.cancel_sent());
    }

    #[test]
    fn end_while_active_fires_ended_by_local() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        call.simulate_response(200, "OK");
        let (tx, rx) = mpsc::channel();
        call.on_ended(move |r| {
            let _ = tx.send(r);
        });
        call.end().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Local
        );
    }

    #[test]
    fn end_while_on_hold_sends_bye() {
        let dlg = mock_dlg();
        let call = Call::new_outbound(dlg.clone(), DialOptions::default());
        call.simulate_response(200, "OK");
        call.hold().unwrap();
        call.end().unwrap();
        assert!(dlg.bye_sent());
    }

    #[test]
    fn remote_bye_fires_ended_by_remote() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_ended(move |r| {
            let _ = tx.send(r);
        });
        call.simulate_bye();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Remote
        );
    }

    #[test]
    fn end_on_already_ended_returns_invalid_state() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.end().unwrap();
        assert!(call.end().is_err());
    }

    #[test]
    fn simulate_bye_on_ended_is_noop() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.end().unwrap();
        // Second simulate_bye should not panic or fire duplicate events.
        call.simulate_bye();
        assert_eq!(call.state(), CallState::Ended);
    }

    // --- Hold / Resume ---

    #[test]
    fn hold_sends_reinvite_with_sendonly() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.hold().unwrap();
        assert!(dlg.last_reinvite_sdp().contains("a=sendonly"));
    }

    #[test]
    fn hold_transitions_to_on_hold() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.hold().unwrap();
        assert_eq!(call.state(), CallState::OnHold);
    }

    #[test]
    fn resume_sends_reinvite_with_sendrecv() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.hold().unwrap();
        call.resume().unwrap();
        assert!(dlg.last_reinvite_sdp().contains("a=sendrecv"));
    }

    #[test]
    fn resume_transitions_to_active() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.hold().unwrap();
        call.resume().unwrap();
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn hold_when_not_active_returns_invalid_state() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.hold().is_err());
    }

    // --- Identity & Headers ---

    #[test]
    fn id_is_unique_per_call() {
        let c1 = Call::new_inbound(mock_dlg());
        let c2 = Call::new_inbound(mock_dlg());
        assert_ne!(c1.id(), c2.id());
    }

    #[test]
    fn call_id_matches_sip_header() {
        let dlg = Arc::new(MockDialog::with_call_id("test-call-id-xyz"));
        let call = Call::new_inbound(dlg);
        assert_eq!(call.call_id(), "test-call-id-xyz");
    }

    #[test]
    fn headers_returns_copy() {
        let mut h = HashMap::new();
        h.insert("X-Custom".into(), vec!["value1".into()]);
        let dlg = mock_dlg_with_headers(h);
        let call = Call::new_inbound(dlg);
        let mut headers = call.headers();
        headers.insert("X-Custom".into(), vec!["mutated".into()]);
        assert_eq!(call.header("X-Custom"), vec!["value1"]);
    }

    #[test]
    fn header_case_insensitive() {
        let mut h = HashMap::new();
        h.insert("P-Asserted-Identity".into(), vec!["sip:1001@pbx".into()]);
        let dlg = mock_dlg_with_headers(h);
        let call = Call::new_inbound(dlg);
        assert_eq!(call.header("p-asserted-identity"), vec!["sip:1001@pbx"]);
    }

    #[test]
    fn direction_inbound() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.direction(), Direction::Inbound);
    }

    #[test]
    fn direction_outbound() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        assert_eq!(call.direction(), Direction::Outbound);
    }

    // --- Timing ---

    #[test]
    fn start_time_none_before_active() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.start_time().is_none());
    }

    #[test]
    fn start_time_set_on_active() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert!(call.start_time().is_some());
    }

    #[test]
    fn duration_zero_before_active() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.duration(), Duration::ZERO);
    }

    #[test]
    fn duration_grows_while_active() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert!(call.duration() > Duration::from_millis(20));
    }

    // --- Blind Transfer ---

    #[test]
    fn blind_transfer_sends_refer() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.blind_transfer("sip:1003@pbx").unwrap();
        assert!(dlg.refer_sent());
        assert_eq!(dlg.last_refer_target(), "sip:1003@pbx");
    }

    #[test]
    fn blind_transfer_fires_ended_by_transfer() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_ended(move |r| {
            let _ = tx.send(r);
        });
        call.blind_transfer("sip:1003@pbx").unwrap();
        dlg.simulate_notify(200);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Transfer
        );
    }

    #[test]
    fn blind_transfer_when_not_active_returns_invalid_state() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.blind_transfer("sip:1003@pbx").is_err());
    }

    // --- SDP integration ---

    #[test]
    fn local_sdp_empty_before_active() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.local_sdp(), "");
    }

    #[test]
    fn local_sdp_populated_after_accept() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert!(call.local_sdp().contains("v=0"));
    }

    #[test]
    fn codec_negotiated_from_sdp() {
        let remote_sdp = test_sdp("192.168.1.200", 5004, "sendrecv", &[0, 8]);
        let call = Call::new_inbound(mock_dlg());
        call.set_remote_sdp(&remote_sdp);
        call.accept().unwrap();
        // Default prefs are [8, 0, 9, 101, 111], so PCMA (8) wins.
        assert_eq!(call.codec(), Codec::PCMA);
    }

    #[test]
    fn hold_sends_sdp_with_sendonly() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.hold().unwrap();
        let raw = dlg.last_reinvite_sdp();
        let s = sdp::parse(&raw).unwrap();
        assert_eq!(s.dir(), "sendonly");
    }

    #[test]
    fn resume_sends_sdp_with_sendrecv() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.hold().unwrap();
        call.resume().unwrap();
        let raw = dlg.last_reinvite_sdp();
        let s = sdp::parse(&raw).unwrap();
        assert_eq!(s.dir(), "sendrecv");
    }

    // --- Re-INVITE handling ---

    #[test]
    fn inbound_reinvite_hold() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendonly", &[0]));
        assert_eq!(call.state(), CallState::OnHold);
    }

    #[test]
    fn inbound_reinvite_resume() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendonly", &[0]));
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendrecv", &[0]));
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn on_hold_callback_fires() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_hold(move || {
            let _ = tx.send(());
        });
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendonly", &[0]));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn on_resume_callback_fires() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_resume(move || {
            let _ = tx.send(());
        });
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendonly", &[0]));
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendrecv", &[0]));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn reinvite_codec_change() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendrecv", &[9]));
        assert_eq!(call.codec(), Codec::G722);
    }

    #[test]
    fn reinvite_on_ended_call_ignored() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.end().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.200", 5004, "sendonly", &[0]));
        assert_eq!(call.state(), CallState::Ended);
    }

    // --- DTMF ---

    #[test]
    fn send_dtmf_invalid_digit_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert!(call.send_dtmf("X").is_err());
    }

    #[test]
    fn send_dtmf_when_not_active_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.send_dtmf("1").is_err());
    }

    // --- Session timers ---

    #[test]
    fn session_timer_sends_refresh_reinvite() {
        let dlg = Arc::new(MockDialog::with_session_expires(1));
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        // Timer fires at 500ms (half of 1s).
        std::thread::sleep(Duration::from_millis(600));
        assert!(!dlg.last_reinvite_sdp().is_empty());
    }

    #[test]
    fn session_timer_no_header_no_timer() {
        let dlg = mock_dlg();
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(dlg.last_reinvite_sdp().is_empty());
    }

    #[test]
    fn session_timer_cancelled_on_end() {
        let dlg = Arc::new(MockDialog::with_session_expires(1));
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        call.end().unwrap();
        std::thread::sleep(Duration::from_millis(600));
        assert!(dlg.last_reinvite_sdp().is_empty());
    }

    #[test]
    fn session_timer_parses_header_with_params() {
        let mut headers = HashMap::new();
        headers.insert("Session-Expires".into(), vec!["1;refresher=uac".into()]);
        let dlg = Arc::new(MockDialog::with_headers(headers));
        let call = Call::new_inbound(dlg.clone());
        call.accept().unwrap();
        std::thread::sleep(Duration::from_millis(600));
        assert!(!dlg.last_reinvite_sdp().is_empty());
    }

    // --- re-INVITE with recvonly/inactive ---

    #[test]
    fn inbound_reinvite_recvonly_triggers_hold() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.100", 5000, "recvonly", &[0]));
        assert_eq!(call.state(), CallState::OnHold);
    }

    #[test]
    fn inbound_reinvite_inactive_triggers_hold() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.simulate_reinvite(&test_sdp("192.168.1.100", 5000, "inactive", &[0]));
        assert_eq!(call.state(), CallState::OnHold);
    }

    // --- Mute / Unmute ---

    #[test]
    fn mute_when_not_active_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.mute().is_err());
    }

    #[test]
    fn unmute_when_not_active_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        assert!(call.unmute().is_err());
    }

    #[test]
    fn mute_when_already_muted_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.mute().unwrap();
        assert!(call.mute().is_err());
    }

    #[test]
    fn unmute_when_not_muted_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        assert!(call.unmute().is_err());
    }

    #[test]
    fn mute_when_on_hold_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.hold().unwrap();
        assert!(call.mute().is_err());
    }

    #[test]
    fn unmute_when_ended_returns_error() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.end().unwrap();
        assert!(call.unmute().is_err());
    }

    #[test]
    fn on_mute_callback_fires() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_mute(move || {
            let _ = tx.send(());
        });
        call.mute().unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn on_unmute_callback_fires() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_unmute(move || {
            let _ = tx.send(());
        });
        call.mute().unwrap();
        call.unmute().unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    // --- RemoteURI / From / To / FromName ---

    #[test]
    fn remote_uri_from_dialog_header() {
        let mut h = HashMap::new();
        h.insert("From".into(), vec!["<sip:1001@pbx.example.com>".into()]);
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.remote_uri(), "sip:1001@pbx.example.com");
    }

    #[test]
    fn remote_uri_empty_when_no_from_header() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.remote_uri(), "");
    }

    #[test]
    fn remote_uri_strips_display_name() {
        let mut h = HashMap::new();
        h.insert(
            "From".into(),
            vec!["\"Alice\" <sip:alice@example.com>".into()],
        );
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.remote_uri(), "sip:alice@example.com");
    }

    #[test]
    fn from_extracts_user_part() {
        let mut h = HashMap::new();
        h.insert(
            "From".into(),
            vec!["\"Alice\" <sip:+15551234567@pbx.example.com>;tag=abc".into()],
        );
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.from(), "+15551234567");
    }

    #[test]
    fn from_extension() {
        let mut h = HashMap::new();
        h.insert("From".into(), vec!["<sip:1001@10.200.1.2>".into()]);
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.from(), "1001");
    }

    #[test]
    fn from_empty_when_no_header() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.from(), "");
    }

    #[test]
    fn to_extracts_user_part() {
        let mut h = HashMap::new();
        h.insert("To".into(), vec!["<sip:1002@pbx.example.com>".into()]);
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.to(), "1002");
    }

    #[test]
    fn to_empty_when_no_header() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.to(), "");
    }

    #[test]
    fn from_name_quoted_display_name() {
        let mut h = HashMap::new();
        h.insert(
            "From".into(),
            vec!["\"Alice Smith\" <sip:alice@example.com>".into()],
        );
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.from_name(), "Alice Smith");
    }

    #[test]
    fn from_name_unquoted_display_name() {
        let mut h = HashMap::new();
        h.insert("From".into(), vec!["Alice <sip:alice@example.com>".into()]);
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.from_name(), "Alice");
    }

    #[test]
    fn from_name_empty_when_no_display_name() {
        let mut h = HashMap::new();
        h.insert("From".into(), vec!["<sip:1001@pbx.example.com>".into()]);
        let call = Call::new_inbound(mock_dlg_with_headers(h));
        assert_eq!(call.from_name(), "");
    }

    #[test]
    fn from_name_empty_when_no_header() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.from_name(), "");
    }

    #[test]
    fn remote_ip_from_remote_sdp() {
        let call = Call::new_inbound(mock_dlg());
        call.set_remote_sdp(&test_sdp("192.168.1.200", 5004, "sendrecv", &[0]));
        assert_eq!(call.remote_ip(), "192.168.1.200");
    }

    #[test]
    fn remote_ip_empty_before_sdp() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.remote_ip(), "");
    }

    #[test]
    fn remote_port_from_remote_sdp() {
        let call = Call::new_inbound(mock_dlg());
        call.set_remote_sdp(&test_sdp("192.168.1.200", 5004, "sendrecv", &[0]));
        assert_eq!(call.remote_port(), 5004);
    }

    #[test]
    fn remote_port_zero_before_sdp() {
        let call = Call::new_inbound(mock_dlg());
        assert_eq!(call.remote_port(), 0);
    }

    #[test]
    fn remote_media_updates_after_reinvite() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.set_remote_sdp(&test_sdp("192.168.1.100", 5000, "sendrecv", &[0]));
        assert_eq!(call.remote_ip(), "192.168.1.100");
        call.simulate_reinvite(&test_sdp("10.0.0.50", 6000, "sendrecv", &[0]));
        assert_eq!(call.remote_ip(), "10.0.0.50");
        assert_eq!(call.remote_port(), 6000);
    }

    // --- OnState callback ---

    #[test]
    fn on_state_fires_on_accept() {
        let call = Call::new_inbound(mock_dlg());
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.accept().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Active
        );
    }

    #[test]
    fn on_state_fires_on_reject() {
        let call = Call::new_inbound(mock_dlg());
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.reject(486, "Busy Here").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Ended
        );
    }

    #[test]
    fn on_state_fires_on_end() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.end().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Ended
        );
    }

    #[test]
    fn on_state_fires_on_hold() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.hold().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::OnHold
        );
    }

    #[test]
    fn on_state_fires_on_resume() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        call.hold().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.resume().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Active
        );
    }

    #[test]
    fn on_state_fires_on_remote_bye() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.simulate_bye();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Ended
        );
    }

    #[test]
    fn on_state_fires_on_outbound_ringing() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.simulate_response(180, "Ringing");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::RemoteRinging
        );
    }

    #[test]
    fn on_state_fires_on_outbound_200() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.simulate_response(200, "OK");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Active
        );
    }

    #[test]
    fn on_state_fires_on_early_media() {
        let opts = DialOptions {
            early_media: true,
            ..Default::default()
        };
        let call = Call::new_outbound(mock_dlg(), opts);
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.simulate_response(183, "Session Progress");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::EarlyMedia
        );
    }

    #[test]
    fn on_state_does_not_fire_on_mute() {
        let call = Call::new_inbound(mock_dlg());
        call.accept().unwrap();
        let (tx, rx) = mpsc::channel::<CallState>();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });
        call.mute().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn on_state_tracks_full_lifecycle() {
        let call = Call::new_outbound(mock_dlg(), DialOptions::default());
        let (tx, rx) = mpsc::channel();
        call.on_state(move |s| {
            let _ = tx.send(s);
        });

        call.simulate_response(180, "Ringing");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::RemoteRinging
        );

        call.simulate_response(200, "OK");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Active
        );

        call.hold().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::OnHold
        );

        call.resume().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Active
        );

        call.end().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap(),
            CallState::Ended
        );
    }
}
