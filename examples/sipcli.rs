//! sipcli — Interactive SIP client TUI built with xphone and ratatui.
//!
//! Usage:
//!   cargo run --example sipcli --features cli -- --profile vg1002
//!   cargo run --example sipcli --features cli -- --server pbx.example.com --user 1001 --pass secret
//!
//! Profiles are loaded from ~/.sipcli.yaml. CLI flags override profile values.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use serde::Deserialize;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use xphone::{Call, CallState, EndReason, Phone};

// -- Accent colors ----------------------------------------------------------

const ACCENT: Color = Color::Rgb(100, 149, 237); // cornflower blue
const ACCENT_DIM: Color = Color::Rgb(60, 90, 150);
const GREEN: Color = Color::Rgb(80, 200, 120);
const RED: Color = Color::Rgb(220, 80, 80);
const YELLOW: Color = Color::Rgb(230, 190, 60);
const MAGENTA: Color = Color::Rgb(180, 120, 220);
const DIM: Color = Color::Rgb(100, 100, 110);
const SURFACE: Color = Color::Rgb(30, 30, 36);
const BAR_BG: Color = Color::Rgb(40, 40, 50);

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sipcli", about = "Interactive SIP client TUI")]
struct Cli {
    /// Load settings from ~/.sipcli.yaml profile
    #[arg(long)]
    profile: Option<String>,

    /// SIP server hostname or IP
    #[arg(long)]
    server: Option<String>,

    /// SIP username / extension
    #[arg(long)]
    user: Option<String>,

    /// SIP password
    #[arg(long)]
    pass: Option<String>,

    /// SIP transport (udp, tcp, tls)
    #[arg(long, default_value = "udp")]
    transport: String,

    /// SIP port
    #[arg(long, default_value_t = 5060)]
    port: u16,

    /// Override local IP advertised in SDP
    #[arg(long)]
    local_ip: Option<String>,
}

// ---------------------------------------------------------------------------
// Profile config (~/.sipcli.yaml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
struct Profile {
    server: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    transport: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct ProfileFile {
    profiles: std::collections::HashMap<String, Profile>,
}

fn load_profile(name: &str) -> Result<Profile, String> {
    let home = dirs_next::home_dir().ok_or("cannot find home directory")?;
    let path = home.join(".sipcli.yaml");
    let data =
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read ~/.sipcli.yaml: {}", e))?;
    let file: ProfileFile =
        serde_yaml::from_str(&data).map_err(|e| format!("invalid ~/.sipcli.yaml: {}", e))?;
    file.profiles.get(name).cloned().ok_or_else(|| {
        let available: Vec<_> = file.profiles.keys().collect();
        format!("profile {:?} not found (available: {:?})", name, available)
    })
}

// ---------------------------------------------------------------------------
// Shared TUI state (written by xphone callbacks, read by render loop)
// ---------------------------------------------------------------------------

struct AppState {
    reg_status: String,
    call_status: String,
    call_id: String,
    events: Vec<String>,
    debug_logs: Vec<String>,
    input: String,
    error: String,
    call: Option<Arc<Call>>,
    quitting: bool,
    echo_active: Arc<AtomicBool>,
    speaker_active: Arc<AtomicBool>,
    /// Command history (oldest first).
    history: Vec<String>,
    /// Current position in history (None = not browsing).
    history_pos: Option<usize>,
    /// Saved input when user starts browsing history.
    history_draft: String,
}

impl AppState {
    fn new() -> Self {
        AppState {
            reg_status: "disconnected".into(),
            call_status: "idle".into(),
            call_id: String::new(),
            events: Vec::new(),
            debug_logs: Vec::new(),
            input: String::new(),
            error: String::new(),
            call: None,
            quitting: false,
            echo_active: Arc::new(AtomicBool::new(false)),
            speaker_active: Arc::new(AtomicBool::new(true)),
            history: Vec::new(),
            history_pos: None,
            history_draft: String::new(),
        }
    }

    fn history_up(&mut self) {
        if self.history.is_empty() {
            return;
        }
        match self.history_pos {
            None => {
                // Start browsing — save current input.
                self.history_draft = self.input.clone();
                self.history_pos = Some(self.history.len() - 1);
                self.input = self.history[self.history.len() - 1].clone();
            }
            Some(pos) if pos > 0 => {
                self.history_pos = Some(pos - 1);
                self.input = self.history[pos - 1].clone();
            }
            _ => {}
        }
    }

    fn history_down(&mut self) {
        if let Some(pos) = self.history_pos {
            if pos + 1 < self.history.len() {
                self.history_pos = Some(pos + 1);
                self.input = self.history[pos + 1].clone();
            } else {
                self.history_pos = None;
                self.input = self.history_draft.clone();
                self.history_draft.clear();
            }
        }
    }

    fn push_event(&mut self, msg: String) {
        self.events.push(msg);
    }

    fn push_debug(&mut self, msg: String) {
        self.debug_logs.push(msg);
    }
}

type SharedState = Arc<Mutex<AppState>>;

// ---------------------------------------------------------------------------
// Tracing layer — feeds library logs into the TUI debug panel
// ---------------------------------------------------------------------------

struct TuiLayer {
    state: SharedState,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TuiLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);

        let level = *event.metadata().level();
        let prefix = match level {
            tracing::Level::ERROR => "ERR",
            tracing::Level::WARN => "WRN",
            tracing::Level::INFO => "INF",
            _ => "DBG",
        };

        let line = format!("{} {}", prefix, visitor.0);
        if let Ok(mut st) = self.state.lock() {
            st.push_debug(line);
        }
    }
}

#[derive(Default)]
struct StringVisitor(String);

impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        } else {
            self.0 = format!("{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={}", field.name(), value));
        } else {
            self.0 = format!("{}={}", field.name(), value);
        }
    }
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

fn wire_phone_events(phone: &Phone, state: &SharedState) {
    let s = Arc::clone(state);
    phone.on_registered(move || {
        let mut st = s.lock().unwrap();
        st.reg_status = "registered".into();
        st.push_event("registered with server".into());
    });

    let s = Arc::clone(state);
    phone.on_unregistered(move || {
        let mut st = s.lock().unwrap();
        st.reg_status = "unregistered".into();
        st.push_event("registration lost".into());
    });

    let s = Arc::clone(state);
    phone.on_error(move |err| {
        let mut st = s.lock().unwrap();
        st.reg_status = "error".into();
        st.push_event(format!("ERROR {}", err));
    });

    // Phone-level call callbacks — auto-wired to every call BEFORE state transitions.
    let s = Arc::clone(state);
    phone.on_call_state(move |cs| {
        let name = call_state_name(cs);
        let mut st = s.lock().unwrap();
        st.push_event(format!("call: {}", name));
        if cs == CallState::Ended {
            st.call_status = "idle".into();
            st.call_id.clear();
            st.call = None;
        } else {
            st.call_status = name;
        }
    });

    let s = Arc::clone(state);
    phone.on_call_ended(move |reason| {
        let mut st = s.lock().unwrap();
        st.push_event(format!("ended: {}", end_reason_name(reason)));
        st.call_status = "idle".into();
        st.call_id.clear();
        st.call = None;
    });

    let s = Arc::clone(state);
    phone.on_call_dtmf(move |digit| {
        let mut st = s.lock().unwrap();
        st.push_event(format!("DTMF recv: {}", digit));
    });

    let s = Arc::clone(state);
    phone.on_incoming(move |call| {
        let from = call.from();
        let from_name = call.from_name();
        let display = if from_name.is_empty() {
            from.clone()
        } else {
            format!("{} ({})", from_name, from)
        };

        // Wire hold/resume per-call (only fire after Active, no timing issue).
        wire_call_events(&call, &s);

        let mut st = s.lock().unwrap();
        let short_id = &call.id()[..call.id().len().min(10)];
        st.push_event(format!("[{}] incoming from {}", short_id, display));
        st.call_status = format!("ringing < {}", display);
        st.call_id = call.id();
        st.call = Some(call);
    });
}

/// Wire per-call callbacks that are only needed after the call is established.
fn wire_call_events(call: &Arc<Call>, state: &SharedState) {
    let s = Arc::clone(state);
    call.on_hold(move || {
        let mut st = s.lock().unwrap();
        st.push_event("held by remote".into());
    });

    let s = Arc::clone(state);
    call.on_resume(move || {
        let mut st = s.lock().unwrap();
        st.push_event("resumed by remote".into());
    });
}

// ---------------------------------------------------------------------------
// Audio: echo + speaker playback
// ---------------------------------------------------------------------------

/// Start the audio handler thread. Reads decoded PCM from the call and:
/// - If echo is on: buffers ~200ms then writes back to pcm_writer (remote hears themselves)
/// - If speaker is on: plays through default audio output device
fn start_audio_handler(
    call: &Arc<Call>,
    echo_flag: Arc<AtomicBool>,
    speaker_flag: Arc<AtomicBool>,
) {
    let pcm_rx = match call.pcm_reader() {
        Some(rx) => rx,
        None => {
            tracing::warn!("audio: no pcm_reader available — audio handler not started");
            return;
        }
    };
    let pcm_tx = call.pcm_writer();
    tracing::info!(
        has_pcm_tx = pcm_tx.is_some(),
        "audio: starting audio handler thread"
    );

    std::thread::Builder::new()
        .name("audio-handler".into())
        .spawn(move || {
            // Set up speaker output via cpal (must happen on this thread,
            // not the main thread, to avoid blocking the TUI event loop).
            let speaker_ctx = setup_speaker_stream(Arc::clone(&speaker_flag));
            tracing::info!(
                speaker_available = speaker_ctx.is_some(),
                "audio: speaker stream ready"
            );

            // Echo delay buffer: ~200ms at 20ms/frame = 10 frames.
            let echo_delay_frames = 10usize;
            let mut echo_buffer: VecDeque<Vec<i16>> = VecDeque::new();
            let mut frame_count: u64 = 0;

            loop {
                match pcm_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(frame) => {
                        frame_count += 1;
                        if frame_count <= 3 || frame_count.is_multiple_of(500) {
                            tracing::debug!(
                                frame_count,
                                frame_len = frame.len(),
                                echo = echo_flag.load(Ordering::Relaxed),
                                speaker = speaker_flag.load(Ordering::Relaxed),
                                "audio: PCM frame received"
                            );
                        }

                        // Speaker playback.
                        if speaker_flag.load(Ordering::Relaxed) {
                            if let Some((ref ring_buf, ref ratio)) = speaker_ctx {
                                let mut buf = ring_buf.lock().unwrap();
                                for &s in &frame {
                                    let f = s as f32 / 32768.0;
                                    for _ in 0..*ratio {
                                        buf.push_back(f);
                                    }
                                }
                                // Prevent unbounded growth (cap at 2s).
                                let cap = *ratio * 8000 * 2;
                                while buf.len() > cap {
                                    buf.pop_front();
                                }
                            }
                        }

                        // Echo with delay.
                        if echo_flag.load(Ordering::Relaxed) {
                            echo_buffer.push_back(frame);
                            if echo_buffer.len() > echo_delay_frames {
                                if let Some(delayed) = echo_buffer.pop_front() {
                                    if let Some(ref tx) = pcm_tx {
                                        let _ = tx.try_send(delayed);
                                    }
                                }
                            }
                        } else {
                            echo_buffer.clear();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        tracing::info!(frame_count, "audio: PCM channel disconnected, stopping");
                        return;
                    }
                }
            }
        })
        .expect("failed to spawn audio handler");
}

/// Set up cpal speaker output stream. Returns (ring_buffer, upsample_ratio)
/// and keeps the Stream alive via ownership in the returned tuple.
#[allow(clippy::type_complexity)]
fn setup_speaker_stream(active: Arc<AtomicBool>) -> Option<(Arc<Mutex<VecDeque<f32>>>, usize)> {
    let host = cpal::default_host();
    let device = host.default_output_device()?;
    let config = device.default_output_config().ok()?;
    let sample_rate = config.sample_rate().0 as usize;
    let channels = config.channels() as usize;
    let ratio = (sample_rate / 8000).max(1);

    let ring_buf: Arc<Mutex<VecDeque<f32>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(sample_rate * 2)));
    let buf_cb = Arc::clone(&ring_buf);

    let stream = device
        .build_output_stream(
            &config.into(),
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if !active.load(Ordering::Relaxed) {
                    data.fill(0.0);
                    return;
                }
                let mut buf = buf_cb.lock().unwrap();
                for frame in data.chunks_mut(channels) {
                    let sample = buf.pop_front().unwrap_or(0.0);
                    for s in frame.iter_mut() {
                        *s = sample;
                    }
                }
            },
            |_err| {},
            None,
        )
        .ok()?;
    stream.play().ok()?;

    // Leak the stream so it stays alive — it will be cleaned up on process exit
    // or when the audio handler thread returns.
    // We use Box::leak because cpal::Stream is !Send on some platforms.
    Box::leak(Box::new(stream));

    Some((ring_buf, ratio))
}

fn call_state_name(s: CallState) -> String {
    match s {
        CallState::Idle => "idle".into(),
        CallState::Ringing => "ringing".into(),
        CallState::Dialing => "dialing".into(),
        CallState::RemoteRinging => "ringing remote".into(),
        CallState::EarlyMedia => "early media".into(),
        CallState::Active => "active".into(),
        CallState::OnHold => "on hold".into(),
        CallState::Ended => "ended".into(),
    }
}

fn end_reason_name(r: EndReason) -> String {
    match r {
        EndReason::Local => "local hangup".into(),
        EndReason::Remote => "remote hangup".into(),
        EndReason::Timeout => "media timeout".into(),
        EndReason::Error => "error".into(),
        EndReason::Transfer => "transferred".into(),
        EndReason::Rejected => "rejected".into(),
        EndReason::Cancelled => "cancelled".into(),
    }
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

fn exec_command(state: &SharedState, phone: &Phone, input: &str) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }
    let cmd = parts[0].to_lowercase();
    let arg = if parts.len() > 1 {
        parts[1..].join(" ")
    } else {
        String::new()
    };

    match cmd.as_str() {
        "quit" | "q" | "exit" => {
            let mut st = state.lock().unwrap();
            if let Some(ref call) = st.call {
                let _ = call.end();
            }
            st.quitting = true;
            drop(st);
            let _ = phone.disconnect();
        }

        "dial" | "d" => {
            if arg.is_empty() {
                state.lock().unwrap().error = "usage: dial <target>".into();
                return;
            }
            {
                let st = state.lock().unwrap();
                if st.call.is_some() {
                    drop(st);
                    state.lock().unwrap().error = "already in a call -- hangup first".into();
                    return;
                }
            }
            state
                .lock()
                .unwrap()
                .push_event(format!("dialing {}...", arg));

            let phone = phone.clone();
            let s = Arc::clone(state);
            let target = arg.clone();
            let echo_flag = Arc::clone(&state.lock().unwrap().echo_active);
            let speaker_flag = Arc::clone(&state.lock().unwrap().speaker_active);
            std::thread::spawn(move || {
                let opts = xphone::DialOptions {
                    timeout: Duration::from_secs(30),
                    ..Default::default()
                };
                match phone.dial(&target, opts) {
                    Ok(call) => {
                        wire_call_events(&call, &s);
                        start_audio_handler(
                            &call,
                            Arc::clone(&echo_flag),
                            Arc::clone(&speaker_flag),
                        );
                        let mut st = s.lock().unwrap();
                        let short_id = &call.id()[..call.id().len().min(10)];
                        st.push_event(format!("[{}] connected to {}", short_id, target));
                        st.call_id = call.id();
                        st.call = Some(call);
                    }
                    Err(e) => {
                        let mut st = s.lock().unwrap();
                        st.push_event(format!("ERROR dial failed: {}", e));
                    }
                }
            });
        }

        "accept" | "a" => {
            let echo_flag = Arc::clone(&state.lock().unwrap().echo_active);
            let speaker_flag = Arc::clone(&state.lock().unwrap().speaker_active);
            call_action(state, "accept", move |c| {
                let result = c.accept();
                if result.is_ok() {
                    start_audio_handler(c, echo_flag, speaker_flag);
                }
                result
            });
        }

        "reject" => {
            call_action(state, "reject", |c| c.reject(486, "Busy Here"));
        }

        "hangup" | "h" => {
            call_action(state, "hangup", |c| c.end());
        }

        "hold" => {
            call_action(state, "hold", |c| c.hold());
        }

        "resume" => {
            call_action(state, "resume", |c| c.resume());
        }

        "mute" => {
            call_action(state, "mute", |c| c.mute());
        }

        "unmute" => {
            call_action(state, "unmute", |c| c.unmute());
        }

        "dtmf" => {
            let st = state.lock().unwrap();
            if st.call.is_none() {
                drop(st);
                state.lock().unwrap().error = "no active call".into();
                return;
            }
            if arg.is_empty() {
                drop(st);
                state.lock().unwrap().error = "usage: dtmf <digits>".into();
                return;
            }
            let call = st.call.as_ref().unwrap().clone();
            drop(st);
            for ch in arg.chars() {
                if let Err(e) = call.send_dtmf(&ch.to_string()) {
                    state.lock().unwrap().error = format!("dtmf error: {}", e);
                    return;
                }
            }
            state
                .lock()
                .unwrap()
                .push_event(format!("DTMF sent: {}", arg));
        }

        "transfer" | "xfer" => {
            if arg.is_empty() {
                state.lock().unwrap().error = "usage: transfer <target>".into();
                return;
            }
            let label = format!("transfer to {}", arg);
            let target = arg.clone();
            call_action(state, &label, move |c| c.blind_transfer(&target));
        }

        "echo" => {
            let st = state.lock().unwrap();
            let flag = Arc::clone(&st.echo_active);
            let prev = flag.load(Ordering::Relaxed);
            flag.store(!prev, Ordering::Relaxed);
            drop(st);
            let label = if !prev { "ON" } else { "OFF" };
            state.lock().unwrap().push_event(format!("echo: {}", label));
        }

        "speaker" => {
            let st = state.lock().unwrap();
            let flag = Arc::clone(&st.speaker_active);
            let prev = flag.load(Ordering::Relaxed);
            flag.store(!prev, Ordering::Relaxed);
            drop(st);
            let label = if !prev { "ON" } else { "OFF" };
            state
                .lock()
                .unwrap()
                .push_event(format!("speaker: {}", label));
        }

        _ => {
            state.lock().unwrap().error = format!("unknown command: {}", cmd);
        }
    }
}

fn call_action<F>(state: &SharedState, name: &str, action: F)
where
    F: FnOnce(&Arc<Call>) -> xphone::Result<()>,
{
    let st = state.lock().unwrap();
    if let Some(ref call) = st.call {
        let call = call.clone();
        let name = name.to_string();
        let s = Arc::clone(state);
        drop(st);
        if let Err(e) = action(&call) {
            s.lock()
                .unwrap()
                .push_event(format!("ERROR {}: {}", name, e));
        }
    } else {
        drop(st);
        state.lock().unwrap().error = "no active call".into();
    }
}

// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

fn reg_status_style(status: &str) -> (Span<'_>, Span<'_>) {
    let (indicator, color) = match status {
        "registered" => ("●", GREEN),
        "registering" => ("◌", YELLOW),
        "error" | "failed" => ("●", RED),
        _ => ("○", DIM),
    };
    (
        Span::styled(format!(" {} ", indicator), Style::default().fg(color)),
        Span::styled(
            status,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    )
}

fn call_status_style(status: &str) -> (Span<'_>, Span<'_>) {
    let color = match status {
        "active" => GREEN,
        s if s.starts_with("ringing") => YELLOW,
        "dialing" | "ringing remote" | "early media" => YELLOW,
        "on hold" => MAGENTA,
        "idle" | "ended" => DIM,
        _ => DIM,
    };
    let indicator = match status {
        "active" => "●",
        "idle" => "○",
        _ => "◌",
    };
    (
        Span::styled(format!(" {} ", indicator), Style::default().fg(color)),
        Span::styled(
            status,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    )
}

fn event_style(line: &str) -> Style {
    if line.starts_with("ERROR") {
        Style::default().fg(RED)
    } else if line.starts_with("call:") || line.starts_with("ended:") {
        Style::default().fg(ACCENT)
    } else if line.starts_with("incoming") {
        Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
    } else if line.starts_with("DTMF") {
        Style::default().fg(MAGENTA)
    } else if line.starts_with("registered") || line.starts_with("dialing") {
        Style::default().fg(GREEN)
    } else if line.starts_with("held") || line.starts_with("resumed") {
        Style::default().fg(MAGENTA)
    } else {
        Style::default().fg(Color::White)
    }
}

fn debug_style(line: &str) -> Style {
    if line.starts_with("ERR") {
        Style::default().fg(RED)
    } else if line.starts_with("WRN") {
        Style::default().fg(YELLOW)
    } else if line.starts_with("INF") {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    }
}

fn draw(f: &mut ratatui::Frame, state: &SharedState) {
    let st = state.lock().unwrap();
    let area = f.area();

    // Overall layout: status bar | panels | command box
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // status bar (bordered)
            Constraint::Min(6),    // panels
            Constraint::Length(5), // command area (bordered)
        ])
        .split(area);

    // --- Status bar (bordered block) ---
    let (reg_dot, reg_text) = reg_status_style(&st.reg_status);
    let (call_dot, call_text) = call_status_style(&st.call_status);
    let mut status_spans = vec![
        Span::styled("  REG", Style::default().fg(DIM)),
        reg_dot,
        reg_text,
        Span::styled("    CALL", Style::default().fg(DIM)),
        call_dot,
        call_text,
    ];
    if !st.call_id.is_empty() {
        let short = if st.call_id.len() > 10 {
            &st.call_id[..10]
        } else {
            &st.call_id
        };
        status_spans.push(Span::styled(
            format!("  [{}]", short),
            Style::default().fg(DIM),
        ));
    }
    let status_line = Line::from(status_spans);
    let status_block = Paragraph::new(status_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .border_style(Style::default().fg(ACCENT_DIM))
            .title(Span::styled(
                " sipcli ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(BAR_BG)),
    );
    f.render_widget(status_block, outer[0]);

    // --- Side-by-side panels ---
    let panel_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(outer[1]);

    // Events panel (left)
    let event_lines: Vec<Line> = st
        .events
        .iter()
        .map(|e| Line::from(Span::styled(e.as_str(), event_style(e))))
        .collect();

    let events_panel = Paragraph::new(event_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(border::ROUNDED)
                .border_style(Style::default().fg(ACCENT_DIM))
                .title(Span::styled(
                    " Events ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(SURFACE)),
        )
        .wrap(Wrap { trim: false })
        .scroll((
            scroll_offset(
                st.events.len(),
                panel_chunks[0].height.saturating_sub(2) as usize,
            ),
            0,
        ));
    f.render_widget(events_panel, panel_chunks[0]);

    // Debug panel (right)
    let debug_lines: Vec<Line> = st
        .debug_logs
        .iter()
        .map(|d| Line::from(Span::styled(d.as_str(), debug_style(d))))
        .collect();

    let debug_panel = Paragraph::new(debug_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(border::ROUNDED)
                .border_style(Style::default().fg(ACCENT_DIM))
                .title(Span::styled(
                    " SIP Debug ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(SURFACE)),
        )
        .wrap(Wrap { trim: false })
        .scroll((
            scroll_offset(
                st.debug_logs.len(),
                panel_chunks[1].height.saturating_sub(2) as usize,
            ),
            0,
        ));
    f.render_widget(debug_panel, panel_chunks[1]);

    // --- Command area (bordered block with input + help + error) ---
    let cmd_title = if st.error.is_empty() {
        Span::styled(
            " Command ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            format!(" Command  --  {} ", st.error),
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        )
    };

    let help_text =
        "dial(d) accept(a) reject hangup(h) hold resume mute unmute dtmf transfer(xfer) echo speaker quit(q)";

    let cmd_lines = vec![
        Line::from(vec![
            Span::styled(
                " > ",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(&st.input, Style::default().fg(Color::White)),
            Span::styled(
                "_",
                Style::default()
                    .fg(GREEN)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
        ]),
        Line::default(),
        Line::from(Span::styled(
            format!("   {}", help_text),
            Style::default().fg(DIM),
        )),
    ];

    let cmd_block = Paragraph::new(cmd_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .border_style(Style::default().fg(ACCENT_DIM))
            .title(cmd_title)
            .style(Style::default().bg(SURFACE)),
    );
    f.render_widget(cmd_block, outer[2]);
}

fn scroll_offset(total_lines: usize, visible: usize) -> u16 {
    if total_lines > visible {
        (total_lines - visible) as u16
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Resolve profile + CLI overrides.
    let mut server = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    let mut transport = cli.transport.clone();
    let mut port = cli.port;

    if let Some(ref profile_name) = cli.profile {
        let p = load_profile(profile_name)
            .map_err(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            })
            .unwrap();
        if let Some(s) = p.server {
            server = s;
        }
        if let Some(u) = p.user {
            user = u;
        }
        if let Some(pw) = p.pass {
            pass = pw;
        }
        if let Some(t) = p.transport {
            transport = t;
        }
        if let Some(pt) = p.port {
            port = pt;
        }
    }

    // CLI flags override profile values.
    if let Some(s) = cli.server {
        server = s;
    }
    if let Some(u) = cli.user {
        user = u;
    }
    if let Some(p) = cli.pass {
        pass = p;
    }

    if server.is_empty() || user.is_empty() {
        eprintln!("Usage: sipcli --profile <name>");
        eprintln!("       sipcli --server <host> --user <username> [--pass <password>] [--transport udp|tcp|tls]");
        eprintln!();
        eprintln!("Profiles are loaded from ~/.sipcli.yaml. Flags override profile values.");
        std::process::exit(1);
    }

    // Build phone config.
    let mut cfg = xphone::Config {
        username: user.clone(),
        password: pass.clone(),
        host: server.clone(),
        port,
        transport,
        rtp_port_min: 10000,
        rtp_port_max: 20000,
        ..Default::default()
    };
    if let Some(ip) = cli.local_ip {
        cfg.local_ip = ip;
    }

    let phone = Phone::new(cfg);
    let state: SharedState = Arc::new(Mutex::new(AppState::new()));

    // Install tracing subscriber that feeds library logs into the debug panel.
    let tui_layer = TuiLayer {
        state: Arc::clone(&state),
    };
    tracing_subscriber::registry().with(tui_layer).init();

    wire_phone_events(&phone, &state);

    // Enter TUI.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Connect in background thread.
    {
        let phone = phone.clone();
        let s = Arc::clone(&state);
        std::thread::spawn(move || {
            {
                let mut st = s.lock().unwrap();
                st.push_event(format!("connecting to {} as {}...", phone.host(), user));
                st.reg_status = "registering".into();
            }
            if let Err(e) = phone.connect() {
                let mut st = s.lock().unwrap();
                st.push_event(format!("ERROR connect: {}", e));
                st.reg_status = "failed".into();
            }
        });
    }

    // Main event loop.
    loop {
        terminal.draw(|f| draw(f, &state))?;

        if state.lock().unwrap().quitting {
            break;
        }

        // Poll for keyboard events with a short timeout so we can redraw.
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let mut st = state.lock().unwrap();
                        if let Some(ref call) = st.call {
                            let _ = call.end();
                        }
                        st.quitting = true;
                        drop(st);
                        let _ = phone.disconnect();
                        break;
                    }
                    KeyCode::Enter => {
                        let input = {
                            let mut st = state.lock().unwrap();
                            st.error.clear();
                            let input = st.input.trim().to_string();
                            st.input.clear();
                            st.history_pos = None;
                            st.history_draft.clear();
                            if !input.is_empty() {
                                st.history.push(input.clone());
                            }
                            input
                        };
                        if !input.is_empty() {
                            exec_command(&state, &phone, &input);
                        }
                        if state.lock().unwrap().quitting {
                            break;
                        }
                    }
                    KeyCode::Backspace => {
                        state.lock().unwrap().input.pop();
                    }
                    KeyCode::Char(c) => {
                        state.lock().unwrap().input.push(c);
                    }
                    KeyCode::Up => {
                        state.lock().unwrap().history_up();
                    }
                    KeyCode::Down => {
                        state.lock().unwrap().history_down();
                    }
                    KeyCode::Esc => {
                        state.lock().unwrap().input.clear();
                    }
                    _ => {}
                }
            }
        }
    }

    // Restore terminal.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    println!("Bye!");

    Ok(())
}
