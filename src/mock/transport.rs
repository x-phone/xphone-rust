use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;

use crate::error::{Error, Result};
use crate::sip::message::Message;
use crate::transport::SipTransport;

/// A queued response for the mock transport.
#[derive(Debug, Clone)]
pub struct Response {
    pub code: u16,
    pub reason: String,
}

impl Response {
    pub fn new(code: u16, reason: &str) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// Recorded sent SIP message for test inspection.
#[derive(Debug, Clone)]
pub struct SentMessage {
    pub method: String,
    pub headers: Option<HashMap<String, String>>,
}

struct Inner {
    responses: Vec<Response>,
    sequence: Vec<Response>,
    seq_index: usize,
    fail_remain: u32,

    sent: Vec<SentMessage>,
    keepalives: u32,
    closed: bool,
    advertised: Option<std::net::SocketAddr>,
    early_sdp: Option<String>,

    invite_func: Option<Arc<dyn Fn() + Send + Sync>>,
    drop_handler: Option<Arc<dyn Fn() + Send + Sync>>,
    incoming_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    #[allow(clippy::type_complexity)]
    dialog_invite_handler:
        Option<Arc<dyn Fn(Arc<dyn crate::dialog::Dialog>, String, String, String) + Send + Sync>>,
    info_dtmf_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    response_watchers: HashMap<u16, Vec<Sender<bool>>>,
}

/// Mock SIP transport for testing.
/// Satisfies the `SipTransport` trait and provides test helpers.
pub struct MockTransport {
    inner: Mutex<Inner>,
    response_ready_tx: Sender<()>,
    response_ready_rx: Receiver<()>,
}

impl MockTransport {
    pub fn new() -> Self {
        let (tx, rx) = bounded(1);
        Self {
            inner: Mutex::new(Inner {
                responses: Vec::new(),
                sequence: Vec::new(),
                seq_index: 0,
                fail_remain: 0,
                sent: Vec::new(),
                keepalives: 0,
                closed: false,
                advertised: None,
                early_sdp: None,
                invite_func: None,
                drop_handler: None,
                incoming_handler: None,
                dialog_invite_handler: None,
                info_dtmf_handler: None,
                response_watchers: HashMap::new(),
            }),
            response_ready_tx: tx,
            response_ready_rx: rx,
        }
    }

    /// Queues a response for the next SIP request.
    pub fn respond_with(&self, code: u16, reason: &str) {
        {
            let mut inner = self.inner.lock();
            inner.responses.push(Response::new(code, reason));
        }
        let _ = self.response_ready_tx.try_send(());
    }

    /// Queues an ordered sequence of responses.
    pub fn respond_sequence(&self, responses: Vec<Response>) {
        {
            let mut inner = self.inner.lock();
            inner.sequence.extend(responses);
            inner.seq_index = 0;
        }
        let _ = self.response_ready_tx.try_send(());
    }

    /// Causes the next `n` send attempts to fail.
    pub fn fail_next(&self, n: u32) {
        self.inner.lock().fail_remain = n;
    }

    /// Sets a callback that fires when SendRequest is called with "INVITE".
    pub fn on_invite<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().invite_func = Some(Arc::new(f));
    }

    /// Simulates a transport connection drop.
    pub fn simulate_drop(&self) {
        let handler = self.inner.lock().drop_handler.clone();
        if let Some(h) = handler {
            h();
        }
    }

    /// Simulates an incoming INVITE.
    pub fn simulate_invite(&self, from: &str, to: &str) {
        let handler = self.inner.lock().incoming_handler.clone();
        if let Some(h) = handler {
            h(from.into(), to.into());
        }
    }

    /// Simulates an incoming INVITE with a full dialog (production path).
    /// Creates a MockDialog and dispatches through the `on_dialog_invite` handler.
    pub fn simulate_dialog_invite(&self, from: &str, to: &str, remote_sdp: &str) {
        let handler = self.inner.lock().dialog_invite_handler.clone();
        if let Some(h) = handler {
            let dlg = Arc::new(crate::mock::dialog::MockDialog::new());
            h(
                dlg as Arc<dyn crate::dialog::Dialog>,
                from.into(),
                to.into(),
                remote_sdp.into(),
            );
        }
    }

    /// Simulates an incoming SIP INFO DTMF.
    pub fn simulate_info_dtmf(&self, call_id: &str, digit: &str) {
        let handler = self.inner.lock().info_dtmf_handler.clone();
        if let Some(h) = handler {
            h(call_id.into(), digit.into());
        }
    }

    /// Returns whether Close was called.
    pub fn closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// Returns the number of messages sent with the given method.
    pub fn count_sent(&self, method: &str) -> usize {
        let inner = self.inner.lock();
        inner.sent.iter().filter(|m| m.method == method).count()
    }

    /// Returns the number of keepalive messages sent.
    pub fn count_keepalives(&self) -> u32 {
        self.inner.lock().keepalives
    }

    /// Returns the last sent message with the given method.
    pub fn last_sent(&self, method: &str) -> Option<SentMessage> {
        let inner = self.inner.lock();
        inner
            .sent
            .iter()
            .rev()
            .find(|m| m.method == method)
            .cloned()
    }

    /// Returns a receiver that fires when Respond is called with the given code.
    pub fn wait_for_response(&self, code: u16, timeout: Duration) -> Receiver<bool> {
        let (tx, rx) = bounded(1);
        self.inner
            .lock()
            .response_watchers
            .entry(code)
            .or_default()
            .push(tx.clone());

        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = tx.try_send(false);
        });

        rx
    }

    /// Sets the advertised address (simulates STUN-mapped address).
    pub fn set_advertised_addr(&self, addr: std::net::SocketAddr) {
        self.inner.lock().advertised = Some(addr);
    }

    /// Sets an early media SDP that dial() will return as early_sdp.
    pub fn set_early_sdp(&self, sdp: &str) {
        self.inner.lock().early_sdp = Some(sdp.to_string());
    }

    fn await_response(&self, timeout: Duration) -> Result<(u16, String)> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let mut inner = self.inner.lock();
                // Sequence responses take priority.
                if inner.seq_index < inner.sequence.len() {
                    let resp = inner.sequence[inner.seq_index].clone();
                    inner.seq_index += 1;
                    return Ok((resp.code, resp.reason));
                }
                // Then check the general response queue.
                if !inner.responses.is_empty() {
                    let resp = inner.responses.remove(0);
                    return Ok((resp.code, resp.reason));
                }
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Other("mock: response timeout".into()));
            }

            // Wait for a response to be queued.
            let _ = self.response_ready_rx.recv_timeout(remaining);
        }
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl SipTransport for MockTransport {
    fn send_request(
        &self,
        method: &str,
        headers: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Message> {
        // Record and check for failures.
        let invite_fn = {
            let mut inner = self.inner.lock();
            inner.sent.push(SentMessage {
                method: method.into(),
                headers: headers.cloned(),
            });

            if inner.fail_remain > 0 {
                inner.fail_remain -= 1;
                return Err(Error::Other("transport error".into()));
            }

            if method == "INVITE" {
                inner.invite_func.clone()
            } else {
                None
            }
        };

        // Call invite func outside lock.
        if let Some(f) = invite_fn {
            f();
        }

        let (code, reason) = self.await_response(timeout)?;
        let mut msg = Message::new_response(code, &reason);
        msg.set_header("CSeq", &format!("1 {}", method));
        Ok(msg)
    }

    fn read_response(&self, timeout: Duration) -> Result<Message> {
        let (code, reason) = self.await_response(timeout)?;
        Ok(Message::new_response(code, &reason))
    }

    fn send_keepalive(&self) -> Result<()> {
        self.inner.lock().keepalives += 1;
        Ok(())
    }

    fn respond(&self, code: u16, _reason: &str) {
        let watchers = {
            let mut inner = self.inner.lock();
            inner.response_watchers.remove(&code).unwrap_or_default()
        };
        for ch in watchers {
            let _ = ch.try_send(true);
        }
    }

    fn on_drop(&self, f: Box<dyn Fn() + Send + Sync>) {
        self.inner.lock().drop_handler = Some(Arc::from(f));
    }

    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().incoming_handler = Some(Arc::from(f));
    }

    #[allow(clippy::type_complexity)]
    fn on_dialog_invite(
        &self,
        f: Box<dyn Fn(Arc<dyn crate::dialog::Dialog>, String, String, String) + Send + Sync>,
    ) {
        self.inner.lock().dialog_invite_handler = Some(Arc::from(f));
    }

    fn on_info_dtmf(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().info_dtmf_handler = Some(Arc::from(f));
    }

    fn dial(
        &self,
        _target: &str,
        _local_sdp: &[u8],
        timeout: Duration,
    ) -> Result<crate::transport::DialResult> {
        // Record as an INVITE send.
        {
            let mut inner = self.inner.lock();
            inner.sent.push(SentMessage {
                method: "INVITE".into(),
                headers: None,
            });

            if inner.fail_remain > 0 {
                inner.fail_remain -= 1;
                return Err(Error::Other("transport error".into()));
            }
        }

        let (code, reason) = self.await_response(timeout)?;
        if code >= 300 {
            return Err(Error::Other(format!("INVITE failed: {} {}", code, reason)));
        }

        let early_sdp = self.inner.lock().early_sdp.take();
        let dlg = Arc::new(crate::mock::dialog::MockDialog::new());
        Ok(crate::transport::DialResult {
            dialog: dlg as Arc<dyn crate::dialog::Dialog>,
            remote_sdp: String::new(),
            early_sdp,
        })
    }

    fn advertised_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.lock().advertised
    }

    fn close(&self) -> Result<()> {
        self.inner.lock().closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respond_with_returns_queued_response() {
        let tr = MockTransport::new();
        tr.respond_with(200, "OK");

        let (code, reason) = tr.await_response(Duration::from_secs(1)).unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn respond_sequence_returns_in_order() {
        let tr = MockTransport::new();
        tr.respond_sequence(vec![
            Response::new(100, "Trying"),
            Response::new(180, "Ringing"),
            Response::new(200, "OK"),
        ]);

        let (c1, _) = tr.await_response(Duration::from_secs(1)).unwrap();
        let (c2, _) = tr.await_response(Duration::from_secs(1)).unwrap();
        let (c3, _) = tr.await_response(Duration::from_secs(1)).unwrap();
        assert_eq!(c1, 100);
        assert_eq!(c2, 180);
        assert_eq!(c3, 200);
    }

    #[test]
    fn fail_next_causes_errors() {
        let tr = MockTransport::new();
        tr.fail_next(2);
        tr.respond_with(200, "OK");

        let r1 = tr.send_request("REGISTER", None, Duration::from_secs(1));
        assert!(r1.is_err());

        let r2 = tr.send_request("REGISTER", None, Duration::from_secs(1));
        assert!(r2.is_err());

        // Third attempt succeeds.
        let r3 = tr.send_request("REGISTER", None, Duration::from_secs(1));
        assert!(r3.is_ok());
    }

    #[test]
    fn count_sent_tracks_methods() {
        let tr = MockTransport::new();
        tr.respond_with(200, "OK");
        tr.respond_with(200, "OK");
        let _ = tr.send_request("REGISTER", None, Duration::from_secs(1));
        let _ = tr.send_request("INVITE", None, Duration::from_secs(1));

        assert_eq!(tr.count_sent("REGISTER"), 1);
        assert_eq!(tr.count_sent("INVITE"), 1);
    }

    #[test]
    fn simulate_drop_fires_handler() {
        let tr = Arc::new(MockTransport::new());
        let dropped = Arc::new(Mutex::new(false));
        let dropped_clone = Arc::clone(&dropped);
        tr.on_drop(Box::new(move || {
            *dropped_clone.lock() = true;
        }));

        tr.simulate_drop();
        assert!(*dropped.lock());
    }

    #[test]
    fn close_sets_flag() {
        let tr = MockTransport::new();
        assert!(!tr.closed());
        tr.close().unwrap();
        assert!(tr.closed());
    }

    #[test]
    fn send_keepalive_increments() {
        let tr = MockTransport::new();
        tr.send_keepalive().unwrap();
        tr.send_keepalive().unwrap();
        assert_eq!(tr.count_keepalives(), 2);
    }
}
