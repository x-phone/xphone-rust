//! MWI (Message Waiting Indicator) via SIP SUBSCRIBE/NOTIFY (RFC 3842).
//!
//! Subscribes to `message-summary` events on a voicemail server and parses
//! incoming NOTIFY bodies to surface voicemail counts to the application.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::callback_pool::spawn_callback;
use crate::error::{Error, Result};
use crate::transport::SipTransport;
use crate::types::VoicemailStatus;

/// Default SUBSCRIBE Expires value in seconds.
const DEFAULT_EXPIRES: u32 = 600;

struct Inner {
    status: VoicemailStatus,
    on_voicemail: Option<Arc<dyn Fn(VoicemailStatus) + Send + Sync>>,
    stopped: bool,
}

/// Manages MWI subscription lifecycle: SUBSCRIBE, refresh, NOTIFY parsing.
pub struct MwiSubscriber {
    tr: Arc<dyn SipTransport>,
    voicemail_uri: String,
    inner: Arc<Mutex<Inner>>,
    /// Dropping this sender signals the background loop to stop.
    stop_tx: Mutex<Option<crossbeam_channel::Sender<()>>>,
    /// Handle for the background refresh thread.
    loop_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl MwiSubscriber {
    pub fn new(tr: Arc<dyn SipTransport>, voicemail_uri: String) -> Self {
        Self {
            tr,
            voicemail_uri,
            inner: Arc::new(Mutex::new(Inner {
                status: VoicemailStatus::default(),
                on_voicemail: None,
                stopped: false,
            })),
            stop_tx: Mutex::new(None),
            loop_thread: Mutex::new(None),
        }
    }

    /// Sends the initial SUBSCRIBE and starts the background refresh loop.
    pub fn start(&self) {
        // Guard against double start.
        self.stop();

        let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(0);
        *self.stop_tx.lock() = Some(stop_tx);
        self.inner.lock().stopped = false;

        // Wire up MWI NOTIFY callback on the transport.
        let inner_clone = Arc::clone(&self.inner);
        self.tr.on_mwi_notify(Box::new(move |body| {
            handle_mwi_notify(&inner_clone, &body);
        }));

        // Initial SUBSCRIBE (non-blocking, fire-and-forget).
        let uri = self.voicemail_uri.clone();
        let tr = Arc::clone(&self.tr);
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new()
            .name("mwi-loop".into())
            .spawn(move || {
                // Initial subscribe.
                if let Err(e) = do_subscribe(&tr, &uri) {
                    warn!(error = %e, "MWI initial SUBSCRIBE failed");
                }
                mwi_loop(tr, uri, inner, stop_rx);
            })
            .expect("failed to spawn mwi loop");
        *self.loop_thread.lock() = Some(handle);
    }

    /// Stops the MWI subscription and joins the background thread.
    /// Sends SUBSCRIBE Expires=0 to unsubscribe from the server.
    pub fn stop(&self) {
        {
            let mut inner = self.inner.lock();
            if inner.stopped {
                return;
            }
            inner.stopped = true;
        }

        // Best-effort unsubscribe (Expires=0).
        let _ = do_unsubscribe(&self.tr, &self.voicemail_uri);

        // Drop the sender to close the channel — wakes the loop.
        self.stop_tx.lock().take();
        // Join the background loop thread.
        if let Some(handle) = self.loop_thread.lock().take() {
            let _ = handle.join();
        }
    }

    pub fn on_voicemail<F: Fn(VoicemailStatus) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_voicemail = Some(Arc::new(f));
    }

    /// Returns the most recent voicemail status.
    pub fn status(&self) -> VoicemailStatus {
        self.inner.lock().status.clone()
    }
}

impl Drop for MwiSubscriber {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sends a SUBSCRIBE for the `message-summary` event package.
fn do_subscribe(tr: &Arc<dyn SipTransport>, uri: &str) -> Result<()> {
    let mut headers = std::collections::HashMap::new();
    headers.insert("Event".to_string(), "message-summary".to_string());
    headers.insert(
        "Accept".to_string(),
        "application/simple-message-summary".to_string(),
    );
    headers.insert("Expires".to_string(), DEFAULT_EXPIRES.to_string());

    info!(uri = %uri, "MWI >>> SUBSCRIBE");
    let msg = tr.send_subscribe(uri, &headers, Duration::from_secs(10))?;
    debug!(status = msg.status_code, "MWI <<< SUBSCRIBE response");

    if msg.status_code >= 200 && msg.status_code < 300 {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "MWI SUBSCRIBE rejected: {} {}",
            msg.status_code, msg.reason
        )))
    }
}

/// Sends a SUBSCRIBE with Expires=0 to unsubscribe from MWI events.
fn do_unsubscribe(tr: &Arc<dyn SipTransport>, uri: &str) -> Result<()> {
    let mut headers = std::collections::HashMap::new();
    headers.insert("Event".to_string(), "message-summary".to_string());
    headers.insert(
        "Accept".to_string(),
        "application/simple-message-summary".to_string(),
    );
    headers.insert("Expires".to_string(), "0".to_string());

    info!(uri = %uri, "MWI >>> SUBSCRIBE Expires=0 (unsubscribe)");
    let _ = tr.send_subscribe(uri, &headers, Duration::from_secs(5))?;
    Ok(())
}

/// Background loop: periodic SUBSCRIBE refresh.
fn mwi_loop(
    tr: Arc<dyn SipTransport>,
    uri: String,
    inner: Arc<Mutex<Inner>>,
    stop_rx: crossbeam_channel::Receiver<()>,
) {
    let refresh_interval = Duration::from_secs((DEFAULT_EXPIRES / 2) as u64);
    let mut last_refresh = std::time::Instant::now();

    loop {
        let tick = Duration::from_millis(500);
        match stop_rx.recv_timeout(tick) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }

        if inner.lock().stopped {
            return;
        }

        if last_refresh.elapsed() >= refresh_interval {
            last_refresh = std::time::Instant::now();
            if let Err(e) = do_subscribe(&tr, &uri) {
                warn!(error = %e, "MWI refresh SUBSCRIBE failed");
            }
        }
    }
}

/// Handles an incoming MWI NOTIFY body.
fn handle_mwi_notify(inner: &Arc<Mutex<Inner>>, body: &str) {
    let status = match parse_message_summary(body) {
        Some(s) => s,
        None => {
            debug!("MWI: failed to parse message-summary body");
            return;
        }
    };

    info!(
        waiting = status.messages_waiting,
        new = status.voice.0,
        old = status.voice.1,
        "MWI status update"
    );

    let cb = {
        let mut guard = inner.lock();
        guard.status = status.clone();
        guard.on_voicemail.clone()
    };

    if let Some(f) = cb {
        spawn_callback(move || f(status));
    }
}

/// Parses an `application/simple-message-summary` body (RFC 3842).
///
/// Example body:
/// ```text
/// Messages-Waiting: yes
/// Message-Account: sip:*97@pbx.local
/// Voice-Message: 2/8
/// ```
pub fn parse_message_summary(body: &str) -> Option<VoicemailStatus> {
    let mut status = VoicemailStatus::default();
    let mut found_waiting = false;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let key = line[..colon].trim();
        let val = line[colon + 1..].trim();

        if key.eq_ignore_ascii_case("Messages-Waiting") {
            status.messages_waiting = val.eq_ignore_ascii_case("yes");
            found_waiting = true;
        } else if key.eq_ignore_ascii_case("Message-Account") {
            status.account = val.to_string();
        } else if key.eq_ignore_ascii_case("Voice-Message") {
            status.voice = parse_message_counts(val);
        }
    }

    if found_waiting {
        Some(status)
    } else {
        None
    }
}

/// Parses `new/old` or `new/old (urgent_new/urgent_old)` message count format.
fn parse_message_counts(val: &str) -> (u32, u32) {
    // Strip optional urgent counts in parentheses: "2/8 (1/0)" -> "2/8"
    let base = val.split('(').next().unwrap_or(val).trim();
    let parts: Vec<&str> = base.split('/').collect();
    if parts.len() >= 2 {
        let new_count = parts[0].trim().parse().unwrap_or(0);
        let old_count = parts[1].trim().parse().unwrap_or(0);
        (new_count, old_count)
    } else {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_waiting_yes() {
        let body = "Messages-Waiting: yes\r\nVoice-Message: 2/8\r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (2, 8));
    }

    #[test]
    fn parse_basic_waiting_no() {
        let body = "Messages-Waiting: no\r\nVoice-Message: 0/5\r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(!s.messages_waiting);
        assert_eq!(s.voice, (0, 5));
    }

    #[test]
    fn parse_with_account() {
        let body =
            "Messages-Waiting: yes\r\nMessage-Account: sip:*97@pbx.local\r\nVoice-Message: 1/0\r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.account, "sip:*97@pbx.local");
        assert_eq!(s.voice, (1, 0));
    }

    #[test]
    fn parse_with_urgent_counts() {
        let body = "Messages-Waiting: yes\r\nVoice-Message: 3/10 (1/0)\r\n";
        let s = parse_message_summary(body).unwrap();
        assert_eq!(s.voice, (3, 10));
    }

    #[test]
    fn parse_case_insensitive() {
        let body = "messages-waiting: YES\r\nvoice-message: 5/2\r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (5, 2));
    }

    #[test]
    fn parse_missing_waiting_header_returns_none() {
        let body = "Voice-Message: 2/8\r\n";
        assert!(parse_message_summary(body).is_none());
    }

    #[test]
    fn parse_empty_body_returns_none() {
        assert!(parse_message_summary("").is_none());
    }

    #[test]
    fn parse_no_voice_line_defaults_to_zero() {
        let body = "Messages-Waiting: yes\r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (0, 0));
    }

    #[test]
    fn parse_extra_whitespace() {
        let body = "  Messages-Waiting :  yes  \r\n  Voice-Message :  4 / 12  \r\n";
        let s = parse_message_summary(body).unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (4, 12));
    }

    #[test]
    fn parse_unix_line_endings() {
        let body = "Messages-Waiting: no\nVoice-Message: 0/0\n";
        let s = parse_message_summary(body).unwrap();
        assert!(!s.messages_waiting);
        assert_eq!(s.voice, (0, 0));
    }

    #[test]
    fn parse_message_counts_basic() {
        assert_eq!(parse_message_counts("2/8"), (2, 8));
        assert_eq!(parse_message_counts("0/0"), (0, 0));
        assert_eq!(parse_message_counts("100/50"), (100, 50));
    }

    #[test]
    fn parse_message_counts_with_urgent() {
        assert_eq!(parse_message_counts("3/10 (1/0)"), (3, 10));
    }

    #[test]
    fn parse_message_counts_invalid() {
        assert_eq!(parse_message_counts("bad"), (0, 0));
        assert_eq!(parse_message_counts(""), (0, 0));
    }

    #[test]
    fn voicemail_status_display() {
        let s = VoicemailStatus {
            messages_waiting: true,
            account: String::new(),
            voice: (3, 7),
        };
        assert_eq!(s.to_string(), "MWI: waiting=true, voice=3/7");
    }

    #[test]
    fn voicemail_status_default() {
        let s = VoicemailStatus::default();
        assert!(!s.messages_waiting);
        assert_eq!(s.voice, (0, 0));
        assert!(s.account.is_empty());
    }

    // --- Integration tests using MockTransport ---

    use crate::mock::transport::MockTransport;

    #[test]
    fn subscriber_sends_subscribe_on_start() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // for SUBSCRIBE

        let sub = MwiSubscriber::new(
            Arc::clone(&tr) as Arc<dyn SipTransport>,
            "sip:*97@pbx.local".into(),
        );
        sub.start();

        // Give the thread time to send.
        std::thread::sleep(Duration::from_millis(200));

        assert!(
            tr.count_sent("SUBSCRIBE") >= 1,
            "expected at least 1 SUBSCRIBE, got {}",
            tr.count_sent("SUBSCRIBE")
        );

        sub.stop();
    }

    #[test]
    fn subscriber_fires_callback_on_notify() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // for SUBSCRIBE

        let sub = MwiSubscriber::new(
            Arc::clone(&tr) as Arc<dyn SipTransport>,
            "sip:*97@pbx.local".into(),
        );

        let (tx, rx) = crossbeam_channel::bounded(1);
        sub.on_voicemail(move |status| {
            let _ = tx.send(status);
        });

        sub.start();
        std::thread::sleep(Duration::from_millis(100));

        // Simulate incoming MWI NOTIFY.
        tr.simulate_mwi_notify("Messages-Waiting: yes\r\nVoice-Message: 3/5\r\n");

        let status = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(status.messages_waiting);
        assert_eq!(status.voice, (3, 5));

        sub.stop();
    }

    #[test]
    fn subscriber_tracks_status() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let sub = MwiSubscriber::new(
            Arc::clone(&tr) as Arc<dyn SipTransport>,
            "sip:*97@pbx.local".into(),
        );
        sub.start();
        std::thread::sleep(Duration::from_millis(100));

        assert!(!sub.status().messages_waiting);

        tr.simulate_mwi_notify("Messages-Waiting: yes\r\nVoice-Message: 1/0\r\n");
        std::thread::sleep(Duration::from_millis(100));

        let s = sub.status();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (1, 0));

        sub.stop();
    }

    #[test]
    fn subscriber_stop_is_idempotent() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let sub = MwiSubscriber::new(
            Arc::clone(&tr) as Arc<dyn SipTransport>,
            "sip:*97@pbx.local".into(),
        );
        sub.start();
        sub.stop();
        sub.stop(); // should not panic
    }
}
