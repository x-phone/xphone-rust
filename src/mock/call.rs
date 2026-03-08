use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::error::{Error, Result};
use crate::types::*;

#[allow(clippy::type_complexity)]
struct Inner {
    id: String,
    call_id: String,
    state: CallState,
    direction: Direction,
    from: String,
    to: String,
    from_name: String,
    remote_uri: String,
    remote_ip: String,
    remote_port: i32,
    codec: Codec,
    local_sdp: String,
    remote_sdp: String,
    start_time: Option<Instant>,
    muted: bool,
    sent_dtmf: Vec<String>,
    transfer_to: String,
    headers: HashMap<String, Vec<String>>,

    on_dtmf_fn: Option<Arc<dyn Fn(String) + Send + Sync>>,
    on_hold_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_resume_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_mute_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unmute_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_media_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_state_fn: Option<Arc<dyn Fn(CallState) + Send + Sync>>,
    on_ended_fn: Option<Arc<dyn Fn(EndReason) + Send + Sync>>,
}

fn mock_call_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!("mock-{}", CTR.fetch_add(1, Ordering::Relaxed))
}

fn mock_call_call_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(1);
    format!("mock-call-{}", CTR.fetch_add(1, Ordering::Relaxed))
}

/// Mock call for testing consumer code that receives Call-like objects.
/// Provides the same API surface as `Call` but with test setters and inspection.
pub struct MockCall {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for MockCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("MockCall")
            .field("id", &inner.id)
            .field("state", &inner.state)
            .field("direction", &inner.direction)
            .finish()
    }
}

impl MockCall {
    /// Creates a new `MockCall` with default state (`Ringing`, `Inbound`).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                id: mock_call_id(),
                call_id: mock_call_call_id(),
                state: CallState::Ringing,
                direction: Direction::Inbound,
                from: String::new(),
                to: String::new(),
                from_name: String::new(),
                remote_uri: String::new(),
                remote_ip: String::new(),
                remote_port: 0,
                codec: Codec::PCMU,
                local_sdp: String::new(),
                remote_sdp: String::new(),
                start_time: None,
                muted: false,
                sent_dtmf: Vec::new(),
                transfer_to: String::new(),
                headers: HashMap::new(),
                on_dtmf_fn: None,
                on_hold_fn: None,
                on_resume_fn: None,
                on_mute_fn: None,
                on_unmute_fn: None,
                on_media_fn: None,
                on_state_fn: None,
                on_ended_fn: None,
            }),
        }
    }

    // --- Getters (mirror Call API) ---

    /// Returns the unique mock call identifier.
    pub fn id(&self) -> String {
        self.inner.lock().id.clone()
    }

    /// Returns the SIP Call-ID.
    pub fn call_id(&self) -> String {
        self.inner.lock().call_id.clone()
    }

    /// Returns the current call state.
    pub fn state(&self) -> CallState {
        self.inner.lock().state
    }

    /// Returns the call direction (inbound or outbound).
    pub fn direction(&self) -> Direction {
        self.inner.lock().direction
    }

    /// Returns the From URI.
    pub fn from(&self) -> String {
        self.inner.lock().from.clone()
    }

    /// Returns the To URI.
    pub fn to(&self) -> String {
        self.inner.lock().to.clone()
    }

    /// Returns the display name from the From header.
    pub fn from_name(&self) -> String {
        self.inner.lock().from_name.clone()
    }

    /// Returns the remote party's SIP URI.
    pub fn remote_uri(&self) -> String {
        self.inner.lock().remote_uri.clone()
    }

    /// Returns the remote party's IP address.
    pub fn remote_ip(&self) -> String {
        self.inner.lock().remote_ip.clone()
    }

    /// Returns the remote party's RTP port.
    pub fn remote_port(&self) -> i32 {
        self.inner.lock().remote_port
    }

    /// Returns the negotiated audio codec.
    pub fn codec(&self) -> Codec {
        self.inner.lock().codec
    }

    /// Returns the local SDP offer/answer.
    pub fn local_sdp(&self) -> String {
        self.inner.lock().local_sdp.clone()
    }

    /// Returns the remote SDP offer/answer.
    pub fn remote_sdp(&self) -> String {
        self.inner.lock().remote_sdp.clone()
    }

    /// Returns the time when the call became active, if any.
    pub fn start_time(&self) -> Option<Instant> {
        self.inner.lock().start_time
    }

    /// Returns how long the call has been active. Zero if not yet active.
    pub fn duration(&self) -> Duration {
        self.inner
            .lock()
            .start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Returns values for the given SIP header name (case-insensitive).
    pub fn header(&self, name: &str) -> Vec<String> {
        let inner = self.inner.lock();
        let lower = name.to_lowercase();
        for (k, v) in &inner.headers {
            if k.to_lowercase() == lower {
                return v.clone();
            }
        }
        Vec::new()
    }

    /// Returns all SIP headers as a map.
    pub fn headers(&self) -> HashMap<String, Vec<String>> {
        self.inner.lock().headers.clone()
    }

    // --- Actions (mirror Call API) ---

    /// Accepts a ringing call, transitioning it to `Active`.
    pub fn accept(&self) -> Result<()> {
        let cb = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Ringing {
                return Err(Error::InvalidState);
            }
            inner.state = CallState::Active;
            inner.start_time = Some(Instant::now());
            inner.on_state_fn.clone()
        };
        if let Some(f) = cb {
            f(CallState::Active);
        }
        Ok(())
    }

    /// Rejects a ringing call with the given SIP status code and reason.
    pub fn reject(&self, _code: u16, _reason: &str) -> Result<()> {
        let (state_cb, ended_cb) = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Ringing {
                return Err(Error::InvalidState);
            }
            inner.state = CallState::Ended;
            (inner.on_state_fn.clone(), inner.on_ended_fn.clone())
        };
        if let Some(f) = state_cb {
            f(CallState::Ended);
        }
        if let Some(f) = ended_cb {
            f(EndReason::Rejected);
        }
        Ok(())
    }

    /// Ends an active, on-hold, or dialing call.
    pub fn end(&self) -> Result<()> {
        let (reason, state_cb, ended_cb) = {
            let mut inner = self.inner.lock();
            let reason = match inner.state {
                CallState::Dialing | CallState::RemoteRinging | CallState::EarlyMedia => {
                    EndReason::Cancelled
                }
                CallState::Active | CallState::OnHold => EndReason::Local,
                _ => return Err(Error::InvalidState),
            };
            inner.state = CallState::Ended;
            (reason, inner.on_state_fn.clone(), inner.on_ended_fn.clone())
        };
        if let Some(f) = state_cb {
            f(CallState::Ended);
        }
        if let Some(f) = ended_cb {
            f(reason);
        }
        Ok(())
    }

    /// Places an active call on hold.
    pub fn hold(&self) -> Result<()> {
        let (state_cb, hold_cb) = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            inner.state = CallState::OnHold;
            (inner.on_state_fn.clone(), inner.on_hold_fn.clone())
        };
        if let Some(f) = state_cb {
            f(CallState::OnHold);
        }
        if let Some(f) = hold_cb {
            f();
        }
        Ok(())
    }

    /// Resumes a held call back to active.
    pub fn resume(&self) -> Result<()> {
        let (state_cb, resume_cb) = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::OnHold {
                return Err(Error::InvalidState);
            }
            inner.state = CallState::Active;
            (inner.on_state_fn.clone(), inner.on_resume_fn.clone())
        };
        if let Some(f) = state_cb {
            f(CallState::Active);
        }
        if let Some(f) = resume_cb {
            f();
        }
        Ok(())
    }

    /// Mutes the call's outgoing audio.
    pub fn mute(&self) -> Result<()> {
        let cb = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            if inner.muted {
                return Err(Error::AlreadyMuted);
            }
            inner.muted = true;
            inner.on_mute_fn.clone()
        };
        if let Some(f) = cb {
            f();
        }
        Ok(())
    }

    /// Unmutes the call's outgoing audio.
    pub fn unmute(&self) -> Result<()> {
        let cb = {
            let mut inner = self.inner.lock();
            if inner.state != CallState::Active {
                return Err(Error::InvalidState);
            }
            if !inner.muted {
                return Err(Error::NotMuted);
            }
            inner.muted = false;
            inner.on_unmute_fn.clone()
        };
        if let Some(f) = cb {
            f();
        }
        Ok(())
    }

    /// Sends a DTMF digit. Records it for later inspection via [`sent_dtmf`](Self::sent_dtmf).
    pub fn send_dtmf(&self, digit: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != CallState::Active {
            return Err(Error::InvalidState);
        }
        inner.sent_dtmf.push(digit.into());
        Ok(())
    }

    /// Initiates a blind transfer. Records the target for inspection via [`last_transfer_target`](Self::last_transfer_target).
    pub fn blind_transfer(&self, target: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != CallState::Active && inner.state != CallState::OnHold {
            return Err(Error::InvalidState);
        }
        inner.transfer_to = target.into();
        Ok(())
    }

    // --- Callback setters ---

    /// Registers a callback fired when a DTMF digit is received.
    pub fn on_dtmf(&self, f: impl Fn(String) + Send + Sync + 'static) {
        self.inner.lock().on_dtmf_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the call is placed on hold.
    pub fn on_hold(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_hold_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the call is resumed from hold.
    pub fn on_resume(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_resume_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the call is muted.
    pub fn on_mute(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_mute_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the call is unmuted.
    pub fn on_unmute(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_unmute_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when media starts flowing.
    pub fn on_media(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().on_media_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired on every state transition.
    pub fn on_state(&self, f: impl Fn(CallState) + Send + Sync + 'static) {
        self.inner.lock().on_state_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the call ends, with the reason.
    pub fn on_ended(&self, f: impl Fn(EndReason) + Send + Sync + 'static) {
        self.inner.lock().on_ended_fn = Some(Arc::new(f));
    }

    // --- Test setters ---

    /// Sets the call state directly (test helper).
    pub fn set_state(&self, s: CallState) {
        self.inner.lock().state = s;
    }

    /// Sets the call direction (test helper).
    pub fn set_direction(&self, d: Direction) {
        self.inner.lock().direction = d;
    }

    /// Sets the From URI (test helper).
    pub fn set_from(&self, from: &str) {
        self.inner.lock().from = from.into();
    }

    /// Sets the To URI (test helper).
    pub fn set_to(&self, to: &str) {
        self.inner.lock().to = to.into();
    }

    /// Sets the From display name (test helper).
    pub fn set_from_name(&self, name: &str) {
        self.inner.lock().from_name = name.into();
    }

    /// Sets the remote SIP URI (test helper).
    pub fn set_remote_uri(&self, uri: &str) {
        self.inner.lock().remote_uri = uri.into();
    }

    /// Sets the remote IP address (test helper).
    pub fn set_remote_ip(&self, ip: &str) {
        self.inner.lock().remote_ip = ip.into();
    }

    /// Sets the remote RTP port (test helper).
    pub fn set_remote_port(&self, port: i32) {
        self.inner.lock().remote_port = port;
    }

    /// Sets the negotiated codec (test helper).
    pub fn set_codec(&self, codec: Codec) {
        self.inner.lock().codec = codec;
    }

    /// Sets the local SDP (test helper).
    pub fn set_local_sdp(&self, sdp: &str) {
        self.inner.lock().local_sdp = sdp.into();
    }

    /// Sets the remote SDP (test helper).
    pub fn set_remote_sdp(&self, sdp: &str) {
        self.inner.lock().remote_sdp = sdp.into();
    }

    /// Sets a SIP header value (test helper).
    pub fn set_header(&self, name: &str, value: &str) {
        self.inner
            .lock()
            .headers
            .insert(name.into(), vec![value.into()]);
    }

    // --- Test inspection ---

    /// Returns whether the call is currently muted.
    pub fn muted(&self) -> bool {
        self.inner.lock().muted
    }

    /// Returns all DTMF digits sent via [`send_dtmf`](Self::send_dtmf).
    pub fn sent_dtmf(&self) -> Vec<String> {
        self.inner.lock().sent_dtmf.clone()
    }

    /// Returns the target URI from the last [`blind_transfer`](Self::blind_transfer) call.
    pub fn last_transfer_target(&self) -> String {
        self.inner.lock().transfer_to.clone()
    }

    // --- Simulation ---

    /// Simulates receiving a DTMF digit, firing the on_dtmf callback.
    pub fn simulate_dtmf(&self, digit: &str) {
        let cb = self.inner.lock().on_dtmf_fn.clone();
        if let Some(f) = cb {
            f(digit.to_string());
        }
    }
}

impl Default for MockCall {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn new_mock_call_defaults() {
        let c = MockCall::new();
        assert_eq!(c.state(), CallState::Ringing);
        assert_eq!(c.direction(), Direction::Inbound);
        assert!(c.call_id().starts_with("mock-call-"));
    }

    #[test]
    fn accept_transitions_to_active() {
        let c = MockCall::new();
        c.accept().unwrap();
        assert_eq!(c.state(), CallState::Active);
        assert!(c.start_time().is_some());
    }

    #[test]
    fn reject_transitions_to_ended() {
        let c = MockCall::new();
        c.reject(486, "Busy Here").unwrap();
        assert_eq!(c.state(), CallState::Ended);
    }

    #[test]
    fn end_active_call() {
        let c = MockCall::new();
        c.accept().unwrap();
        c.end().unwrap();
        assert_eq!(c.state(), CallState::Ended);
    }

    #[test]
    fn end_ringing_returns_error() {
        let c = MockCall::new();
        assert!(c.end().is_err());
    }

    #[test]
    fn hold_and_resume() {
        let c = MockCall::new();
        c.accept().unwrap();
        c.hold().unwrap();
        assert_eq!(c.state(), CallState::OnHold);
        c.resume().unwrap();
        assert_eq!(c.state(), CallState::Active);
    }

    #[test]
    fn mute_unmute() {
        let c = MockCall::new();
        c.accept().unwrap();
        assert!(!c.muted());
        c.mute().unwrap();
        assert!(c.muted());
        c.unmute().unwrap();
        assert!(!c.muted());
    }

    #[test]
    fn send_dtmf_records() {
        let c = MockCall::new();
        c.accept().unwrap();
        c.send_dtmf("1").unwrap();
        c.send_dtmf("2").unwrap();
        assert_eq!(c.sent_dtmf(), vec!["1", "2"]);
    }

    #[test]
    fn blind_transfer_records() {
        let c = MockCall::new();
        c.accept().unwrap();
        c.blind_transfer("sip:1003@pbx.local").unwrap();
        assert_eq!(c.last_transfer_target(), "sip:1003@pbx.local");
    }

    #[test]
    fn setters_work() {
        let c = MockCall::new();
        c.set_remote_uri("sip:1001@host");
        c.set_remote_ip("10.0.0.1");
        c.set_remote_port(5060);
        c.set_codec(Codec::PCMA);
        c.set_local_sdp("v=0...");
        c.set_remote_sdp("v=0...");
        c.set_header("From", "<sip:1001@host>");

        assert_eq!(c.remote_uri(), "sip:1001@host");
        assert_eq!(c.remote_ip(), "10.0.0.1");
        assert_eq!(c.remote_port(), 5060);
        assert_eq!(c.codec(), Codec::PCMA);
        assert_eq!(c.local_sdp(), "v=0...");
        assert_eq!(c.remote_sdp(), "v=0...");
        assert_eq!(c.header("from"), vec!["<sip:1001@host>"]);
    }

    #[test]
    fn on_state_fires() {
        let c = MockCall::new();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        c.on_state(move |s| {
            if s == CallState::Active {
                fired_clone.store(true, Ordering::Relaxed);
            }
        });
        c.accept().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn on_ended_fires() {
        let c = MockCall::new();
        c.accept().unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        c.on_ended(move |r| {
            if r == EndReason::Local {
                fired_clone.store(true, Ordering::Relaxed);
            }
        });
        c.end().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn simulate_dtmf_fires_callback() {
        let c = MockCall::new();
        let received = Arc::new(Mutex::new(String::new()));
        let received_clone = Arc::clone(&received);
        c.on_dtmf(move |d| {
            *received_clone.lock() = d;
        });
        c.simulate_dtmf("5");
        assert_eq!(*received.lock(), "5");
    }

    #[test]
    fn end_dialing_gives_cancelled() {
        let c = MockCall::new();
        c.set_state(CallState::Dialing);
        let reason = Arc::new(Mutex::new(None));
        let reason_clone = Arc::clone(&reason);
        c.on_ended(move |r| {
            *reason_clone.lock() = Some(r);
        });
        c.end().unwrap();
        assert_eq!(*reason.lock(), Some(EndReason::Cancelled));
    }

    #[test]
    fn on_hold_callback_fires() {
        let c = MockCall::new();
        c.accept().unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        c.on_hold(move || {
            fired_clone.store(true, Ordering::Relaxed);
        });
        c.hold().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn on_mute_callback_fires() {
        let c = MockCall::new();
        c.accept().unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        c.on_mute(move || {
            fired_clone.store(true, Ordering::Relaxed);
        });
        c.mute().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn duration_zero_before_active() {
        let c = MockCall::new();
        assert_eq!(c.duration(), Duration::ZERO);
    }

    #[test]
    fn duration_grows_after_accept() {
        let c = MockCall::new();
        c.accept().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(c.duration() >= Duration::from_millis(10));
    }

    #[test]
    fn callback_can_query_state() {
        let c = Arc::new(MockCall::new());
        let c2 = Arc::clone(&c);
        let state = Arc::new(Mutex::new(CallState::Ringing));
        let state_clone = Arc::clone(&state);
        c.on_state(move |_| {
            *state_clone.lock() = c2.state();
        });
        c.accept().unwrap();
        assert_eq!(*state.lock(), CallState::Active);
    }
}
