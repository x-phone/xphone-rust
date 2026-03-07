use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::call::Call;
use crate::config::{Config, DialOptions};
use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::mock::dialog::MockDialog;
use crate::registry::Registry;
use crate::transport::SipTransport;
use crate::types::PhoneState;

type CallStateCb = Arc<dyn Fn(Arc<Call>, crate::types::CallState) + Send + Sync>;
type CallEndedCb = Arc<dyn Fn(Arc<Call>, crate::types::EndReason) + Send + Sync>;
type CallDtmfCb = Arc<dyn Fn(Arc<Call>, String) + Send + Sync>;

struct Inner {
    state: PhoneState,
    tr: Option<Arc<dyn SipTransport>>,
    reg: Option<Arc<Registry>>,
    incoming: Option<Arc<dyn Fn(Arc<Call>) + Send + Sync>>,
    calls: HashMap<String, Arc<Call>>,

    on_registered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unregistered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_error_fn: Option<Arc<dyn Fn(Error) + Send + Sync>>,

    // Phone-level call callbacks — auto-wired to every new call.
    on_call_state_fn: Option<CallStateCb>,
    on_call_ended_fn: Option<CallEndedCb>,
    on_call_dtmf_fn: Option<CallDtmfCb>,
}

/// Phone orchestrates SIP registration, call tracking, and incoming/outgoing calls.
#[derive(Clone)]
pub struct Phone {
    cfg: Config,
    inner: Arc<Mutex<Inner>>,
}

impl Phone {
    /// Creates a new `Phone` with the given configuration, initially in the `Disconnected` state.
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            inner: Arc::new(Mutex::new(Inner {
                state: PhoneState::Disconnected,
                tr: None,
                reg: None,
                incoming: None,
                calls: HashMap::new(),
                on_registered_fn: None,
                on_unregistered_fn: None,
                on_error_fn: None,
                on_call_state_fn: None,
                on_call_ended_fn: None,
                on_call_dtmf_fn: None,
            })),
        }
    }

    /// Connects to the SIP server using the configured transport.
    /// Creates a real SipUA, performs registration, and wires up incoming INVITE handling.
    pub fn connect(&self) -> crate::error::Result<()> {
        info!(host = %self.cfg.host, port = self.cfg.port, user = %self.cfg.username, "Phone connecting");
        let tr = Arc::new(crate::sip::ua::SipUA::new(&self.cfg)?);
        self.connect_with_transport(tr);
        let state = self.state();
        if state == PhoneState::Registered {
            info!("Phone connected and registered");
            Ok(())
        } else {
            warn!("Phone registration failed");
            Err(crate::error::Error::RegistrationFailed)
        }
    }

    /// Connects with a provided transport (test hook).
    /// Performs registration and wires up incoming INVITE handling.
    pub fn connect_with_transport(&self, tr: Arc<dyn SipTransport>) {
        let reg = Arc::new(Registry::new(Arc::clone(&tr), self.cfg.clone()));

        // Apply buffered callbacks to the registry.
        {
            let inner = self.inner.lock();
            if let Some(ref f) = inner.on_registered_fn {
                let f = Arc::clone(f);
                reg.on_registered(move || f());
            }
            if let Some(ref f) = inner.on_unregistered_fn {
                let f = Arc::clone(f);
                reg.on_unregistered(move || f());
            }
            if let Some(ref f) = inner.on_error_fn {
                let f = Arc::clone(f);
                reg.on_error(move |e| f(e));
            }
        }

        // Perform registration.
        let reg_result = reg.start();

        // Determine the local IP for SDP media address.
        // Priority: explicit config override > STUN-mapped IP > UDP heuristic.
        let effective_ip = if !self.cfg.local_ip.is_empty() {
            self.cfg.local_ip.clone()
        } else if let Some(addr) = tr.advertised_addr() {
            addr.ip().to_string()
        } else {
            local_ip_for(&self.cfg.host)
        };

        // Wire up incoming INVITE handling (dialog-based for production, simple for mock).
        let inner_clone = Arc::clone(&self.inner);
        let incoming_ip = effective_ip.clone();
        let rtp_port_min = self.cfg.rtp_port_min;
        let rtp_port_max = self.cfg.rtp_port_max;
        tr.on_dialog_invite(Box::new(move |dlg, from, to, remote_sdp| {
            handle_dialog_incoming(
                &inner_clone,
                dlg,
                &from,
                &to,
                &remote_sdp,
                &incoming_ip,
                rtp_port_min,
                rtp_port_max,
            );
        }));

        let inner_clone = Arc::clone(&self.inner);
        tr.on_incoming(Box::new(move |from, to| {
            handle_incoming(&inner_clone, &from, &to);
        }));

        // Wire up BYE handling.
        let inner_clone = Arc::clone(&self.inner);
        tr.on_bye(Box::new(move |call_id| {
            handle_bye(&inner_clone, &call_id);
        }));

        // Wire up NOTIFY handling (REFER progress).
        let inner_clone = Arc::clone(&self.inner);
        tr.on_notify(Box::new(move |call_id, code| {
            handle_notify(&inner_clone, &call_id, code);
        }));

        let mut inner = self.inner.lock();
        inner.tr = Some(tr);
        inner.reg = Some(reg);
        if reg_result.is_ok() {
            inner.state = PhoneState::Registered;
        } else {
            inner.state = PhoneState::RegistrationFailed;
        }
    }

    /// Disconnects the phone: stops registry and closes transport.
    pub fn disconnect(&self) -> Result<()> {
        info!("Phone disconnecting");
        let (reg, tr, unreg_fn) = {
            let mut inner = self.inner.lock();
            if inner.state == PhoneState::Disconnected {
                return Err(Error::NotConnected);
            }
            let reg = inner.reg.take();
            let tr = inner.tr.take();
            let unreg_fn = inner.on_unregistered_fn.clone();
            inner.state = PhoneState::Disconnected;
            (reg, tr, unreg_fn)
        };

        if let Some(reg) = reg {
            reg.stop();
        }
        if let Some(tr) = tr {
            let _ = tr.close();
        }
        if let Some(f) = unreg_fn {
            std::thread::spawn(move || f());
        }

        Ok(())
    }

    /// Initiates an outbound call.
    pub fn dial(&self, target: &str, opts: DialOptions) -> Result<Arc<Call>> {
        info!(target = %target, "Phone dialing");
        let tr = {
            let inner = self.inner.lock();
            if inner.state != PhoneState::Registered {
                return Err(Error::NotRegistered);
            }
            inner.tr.as_ref().cloned().ok_or(Error::NotConnected)?
        };

        // Allocate RTP port and build SDP offer.
        // Use STUN-mapped IP from transport if available.
        let local_ip = if !self.cfg.local_ip.is_empty() {
            self.cfg.local_ip.clone()
        } else if let Some(addr) = tr.advertised_addr() {
            addr.ip().to_string()
        } else {
            local_ip_for(&self.cfg.host)
        };
        let (rtp_socket, rtp_port) = if self.cfg.rtp_port_min > 0 && self.cfg.rtp_port_max > 0 {
            match crate::media::listen_rtp_port(self.cfg.rtp_port_min, self.cfg.rtp_port_max) {
                Ok((sock, port)) => (Some(sock), port as i32),
                Err(_) => (None, 20000),
            }
        } else {
            (None, 20000)
        };
        // Generate SRTP keying material if enabled.
        let srtp_inline_key = if self.cfg.srtp {
            let (_material, encoded) = crate::srtp::generate_keying_material()?;
            Some(encoded)
        } else {
            None
        };

        let local_sdp = if let Some(ref key) = srtp_inline_key {
            crate::sdp::build_offer_srtp(
                &local_ip,
                rtp_port,
                &[8, 0, 9, 101],
                crate::sdp::DIR_SEND_RECV,
                key,
            )
        } else {
            crate::sdp::build_offer(
                &local_ip,
                rtp_port,
                &[8, 0, 9, 101],
                crate::sdp::DIR_SEND_RECV,
            )
        };

        // Try dialog-based dial (production SipUA path).
        let dial_result = tr.dial(target, local_sdp.as_bytes(), opts.timeout);

        let (call, responses) = match dial_result {
            Ok((dlg, remote_sdp)) => {
                // Production path: got a real dialog from SipUA.
                // tr.dial() already consumed the 200 OK, so transition to Active.
                let call = Call::new_outbound(dlg, opts);
                call.set_local_media(&local_ip, rtp_port);
                call.set_local_sdp(&local_sdp);
                if let Some(ref key) = srtp_inline_key {
                    call.set_srtp(key);
                }
                if let Some(sock) = rtp_socket {
                    call.set_rtp_socket(sock);
                }
                if !remote_sdp.is_empty() {
                    call.set_remote_sdp(&remote_sdp);
                }
                // Wire phone-level callbacks BEFORE simulate_response fires on_state.
                wire_phone_call_callbacks(&self.inner, &call);
                call.simulate_response(200, "OK");
                (call, Vec::new())
            }
            Err(e) if e.to_string().contains("not supported") => {
                // Fallback path (MockTransport): use send_request + MockDialog.
                let resp = tr.send_request("INVITE", None, opts.timeout)?;
                let mut code = resp.status_code;
                let mut responses = vec![(code, resp.reason.clone())];

                while (100..200).contains(&code) {
                    let next = tr.read_response(opts.timeout)?;
                    code = next.status_code;
                    responses.push((code, next.reason.clone()));
                }

                let dlg = Arc::new(MockDialog::new());
                let call = Call::new_outbound(dlg as Arc<dyn Dialog>, opts);
                // Wire phone-level callbacks BEFORE replay.
                wire_phone_call_callbacks(&self.inner, &call);
                (call, responses)
            }
            Err(e) => return Err(e),
        };

        // Wire up call tracking cleanup.
        let inner_clone = Arc::clone(&self.inner);
        let call_id = call.call_id();
        call.on_ended_internal(move |_| {
            inner_clone.lock().calls.remove(&call_id);
        });

        // Replay provisional responses (mock path only).
        for (c, r) in &responses {
            call.simulate_response(*c, r);
        }

        // Track the call.
        self.inner
            .lock()
            .calls
            .insert(call.call_id(), Arc::clone(&call));

        Ok(call)
    }

    /// Sets the callback for incoming calls.
    pub fn on_incoming<F: Fn(Arc<Call>) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().incoming = Some(Arc::new(f));
    }

    /// Sets the callback for successful registration.
    pub fn on_registered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(f);
        let reg = {
            let mut inner = self.inner.lock();
            inner.on_registered_fn = Some(Arc::clone(&cb));
            inner.reg.clone()
        };
        if let Some(reg) = reg {
            let cb = Arc::clone(&cb);
            reg.on_registered(move || cb());
        }
    }

    /// Sets the callback for loss of registration.
    pub fn on_unregistered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(f);
        let reg = {
            let mut inner = self.inner.lock();
            inner.on_unregistered_fn = Some(Arc::clone(&cb));
            inner.reg.clone()
        };
        if let Some(reg) = reg {
            let cb = Arc::clone(&cb);
            reg.on_unregistered(move || cb());
        }
    }

    /// Sets the callback for registration errors.
    pub fn on_error<F: Fn(Error) + Send + Sync + 'static>(&self, f: F) {
        let cb: Arc<dyn Fn(Error) + Send + Sync> = Arc::new(f);
        let reg = {
            let mut inner = self.inner.lock();
            inner.on_error_fn = Some(Arc::clone(&cb));
            inner.reg.clone()
        };
        if let Some(reg) = reg {
            let cb = Arc::clone(&cb);
            reg.on_error(move |e| cb(e));
        }
    }

    /// Returns the current phone state.
    pub fn state(&self) -> PhoneState {
        self.inner.lock().state
    }

    /// Returns the configured SIP server host.
    pub fn host(&self) -> &str {
        &self.cfg.host
    }

    /// Sets a callback that fires for every call state change (all calls).
    /// Receives `(call, state)`.
    pub fn on_call_state<F: Fn(Arc<Call>, crate::types::CallState) + Send + Sync + 'static>(
        &self,
        f: F,
    ) {
        self.inner.lock().on_call_state_fn = Some(Arc::new(f));
    }

    /// Sets a callback that fires when any call ends.
    /// Receives `(call, reason)`.
    pub fn on_call_ended<F: Fn(Arc<Call>, crate::types::EndReason) + Send + Sync + 'static>(
        &self,
        f: F,
    ) {
        self.inner.lock().on_call_ended_fn = Some(Arc::new(f));
    }

    /// Sets a callback that fires for DTMF digits received on any call.
    /// Receives `(call, digit)`.
    pub fn on_call_dtmf<F: Fn(Arc<Call>, String) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_call_dtmf_fn = Some(Arc::new(f));
    }

    /// Looks up an active call by dialog ID.
    pub fn find_call(&self, call_id: &str) -> Option<Arc<Call>> {
        self.inner.lock().calls.get(call_id).cloned()
    }
}

/// Discovers the local IP address used to reach the given host.
/// Uses a connectionless UDP dial (no packets sent).
fn local_ip_for(host: &str) -> String {
    use std::net::UdpSocket;
    let target = format!("{}:5060", host);
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => match sock.connect(&target) {
            Ok(()) => match sock.local_addr() {
                Ok(addr) if !addr.ip().is_unspecified() => addr.ip().to_string(),
                _ => "127.0.0.1".into(),
            },
            Err(_) => "127.0.0.1".into(),
        },
        Err(_) => "127.0.0.1".into(),
    }
}

/// Handles an incoming INVITE from the transport.
fn handle_incoming(inner: &Arc<Mutex<Inner>>, from: &str, to: &str) {
    let (tr, incoming_fn) = {
        let guard = inner.lock();
        (guard.tr.clone(), guard.incoming.clone())
    };

    // Send 100 Trying.
    if let Some(ref tr) = tr {
        tr.respond(100, "Trying");
    }

    // Create an inbound call with a stub dialog.
    let dlg = Arc::new(MockDialog::new());
    let call = Call::new_inbound(dlg as Arc<dyn Dialog>);

    // Wire up call tracking cleanup.
    let inner_clone = Arc::clone(inner);
    let call_id = call.call_id();
    call.on_ended_internal(move |_| {
        inner_clone.lock().calls.remove(&call_id);
    });

    // Track the call.
    inner.lock().calls.insert(call.call_id(), Arc::clone(&call));

    // Log incoming call details (suppress unused warnings).
    let _ = (from, to);

    // Fire OnIncoming callback.
    if let Some(f) = incoming_fn {
        f(call);
    }

    // Send 180 Ringing.
    if let Some(ref tr) = tr {
        tr.respond(180, "Ringing");
    }
}

/// Handles an incoming INVITE with a real SIP dialog (production path).
#[allow(clippy::too_many_arguments)]
/// Wire phone-level call callbacks onto an individual call.
fn wire_phone_call_callbacks(inner: &Arc<Mutex<Inner>>, call: &Arc<Call>) {
    let locked = inner.lock();
    if let Some(ref f) = locked.on_call_state_fn {
        let f = Arc::clone(f);
        let c = Arc::clone(call);
        call.on_state(move |s| f(Arc::clone(&c), s));
    }
    if let Some(ref f) = locked.on_call_ended_fn {
        let f = Arc::clone(f);
        let c = Arc::clone(call);
        call.on_ended(move |r| f(Arc::clone(&c), r));
    }
    if let Some(ref f) = locked.on_call_dtmf_fn {
        let f = Arc::clone(f);
        let c = Arc::clone(call);
        call.on_dtmf(move |d| f(Arc::clone(&c), d));
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_dialog_incoming(
    inner: &Arc<Mutex<Inner>>,
    dlg: Arc<dyn Dialog>,
    _from: &str,
    _to: &str,
    remote_sdp: &str,
    local_ip: &str,
    rtp_port_min: u16,
    rtp_port_max: u16,
) {
    info!(from = _from, to = _to, "Phone handling incoming INVITE");
    let incoming_fn = inner.lock().incoming.clone();

    // Allocate an RTP socket for this call.
    let (rtp_socket, actual_port) = if rtp_port_min > 0 && rtp_port_max > 0 {
        match crate::media::listen_rtp_port(rtp_port_min, rtp_port_max) {
            Ok((sock, port)) => (Some(sock), port as i32),
            Err(_) => (None, rtp_port_min as i32),
        }
    } else {
        (None, rtp_port_min as i32)
    };

    // Only use SRTP if the remote actually offers RTP/SAVP with a supported suite.
    // Local config preference alone is not enough — the remote must also offer SRTP.
    let use_srtp = if let Ok(sess) = crate::sdp::parse(remote_sdp) {
        if sess.is_srtp() {
            // Validate that the remote offers a supported cipher suite.
            if let Some(crypto) = sess.first_crypto() {
                crypto.suite == crate::srtp::SUPPORTED_SUITE
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Create an inbound call with the real dialog.
    let call = Call::new_inbound(dlg);
    call.set_local_media(local_ip, actual_port);
    if use_srtp {
        match crate::srtp::generate_keying_material() {
            Ok((_material, encoded)) => call.set_srtp(&encoded),
            Err(e) => {
                tracing::error!("failed to generate SRTP keying material: {}", e);
                return;
            }
        }
    }
    if let Some(sock) = rtp_socket {
        call.set_rtp_socket(sock);
    }
    if !remote_sdp.is_empty() {
        call.set_remote_sdp(remote_sdp);
    }

    // Wire up call tracking cleanup.
    let inner_clone = Arc::clone(inner);
    let call_id = call.call_id();
    call.on_ended_internal(move |_| {
        inner_clone.lock().calls.remove(&call_id);
    });

    // Wire phone-level callbacks before anything fires.
    wire_phone_call_callbacks(inner, &call);

    // Track the call.
    inner.lock().calls.insert(call.call_id(), Arc::clone(&call));

    // Send 180 Ringing via dialog.
    let _ = call.dlg_respond(180, "Ringing");

    // Fire OnIncoming callback.
    if let Some(f) = incoming_fn {
        f(call);
    }
}

/// Handles an incoming BYE — looks up the call by Call-ID and simulates BYE.
fn handle_bye(inner: &Arc<Mutex<Inner>>, call_id: &str) {
    info!(call_id = %call_id, "Phone handling BYE");
    let call = inner.lock().calls.get(call_id).cloned();
    if let Some(call) = call {
        call.simulate_bye();
    } else {
        debug!(call_id = %call_id, "Phone BYE for unknown call (already ended)");
    }
}

fn handle_notify(inner: &Arc<Mutex<Inner>>, call_id: &str, code: u16) {
    info!(call_id = %call_id, code = code, "Phone handling NOTIFY");
    let call = inner.lock().calls.get(call_id).cloned();
    if let Some(call) = call {
        call.fire_notify(code);
    } else {
        warn!(call_id = %call_id, "Phone NOTIFY for unknown call");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::transport::{MockTransport, Response};
    use std::time::Duration;

    fn test_cfg() -> Config {
        Config {
            register_expiry: Duration::from_secs(60),
            register_retry: Duration::from_millis(50),
            register_max_retry: 3,
            nat_keepalive_interval: None,
            ..Config::default()
        }
    }

    #[test]
    fn connect_and_state() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // for REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        assert_eq!(phone.state(), PhoneState::Registered);
        assert_eq!(tr.count_sent("REGISTER"), 1);
    }

    #[test]
    fn disconnect_sets_disconnected() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);
        phone.disconnect().unwrap();

        assert_eq!(phone.state(), PhoneState::Disconnected);
        assert!(tr.closed());
    }

    #[test]
    fn disconnect_when_not_connected_returns_error() {
        let phone = Phone::new(test_cfg());
        let result = phone.disconnect();
        assert!(result.is_err());
    }

    #[test]
    fn dial_before_connect_returns_error() {
        let phone = Phone::new(test_cfg());
        let result = phone.dial("sip:1002@pbx.local", DialOptions::default());
        assert!(result.is_err());
    }

    #[test]
    fn dial_sends_invite_and_creates_call() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Queue INVITE response.
        tr.respond_with(200, "OK");
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        assert_eq!(tr.count_sent("INVITE"), 1);
        // Call should be active after 200 OK.
        assert_eq!(call.state(), crate::types::CallState::Active);
    }

    #[test]
    fn dial_with_ringing() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Queue a sequence: 180 Ringing -> 200 OK.
        tr.respond_sequence(vec![
            Response::new(180, "Ringing"),
            Response::new(200, "OK"),
        ]);

        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        assert_eq!(call.state(), crate::types::CallState::Active);
    }

    #[test]
    fn incoming_call_fires_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_incoming(move |_call| {
            let _ = tx.send(true);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.simulate_invite("sip:1001@pbx.local", "sip:1002@pbx.local");

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);
    }

    #[test]
    fn incoming_call_sends_100_and_180() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.on_incoming(|_| {});
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Wait for 100 and 180.
        let rx100 = tr.wait_for_response(100, Duration::from_secs(2));
        let rx180 = tr.wait_for_response(180, Duration::from_secs(2));

        tr.simulate_invite("sip:1001@pbx.local", "sip:1002@pbx.local");

        assert!(rx100.recv_timeout(Duration::from_secs(2)).unwrap());
        assert!(rx180.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn on_registered_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let phone = Phone::new(test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_registered(move || {
            let _ = tx.send(true);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);
    }

    #[test]
    fn on_unregistered_fires_on_disconnect() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let phone = Phone::new(test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_unregistered(move || {
            let _ = tx.send(true);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);
        phone.disconnect().unwrap();

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);
    }

    #[test]
    fn call_tracking() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let call_id = call.call_id();

        // Call should be tracked.
        assert!(phone.find_call(&call_id).is_some());

        // End the call.
        call.end().unwrap();

        // Give the callback thread time to fire.
        std::thread::sleep(Duration::from_millis(100));

        // Call should be untracked.
        assert!(phone.find_call(&call_id).is_none());
    }

    #[test]
    fn dial_uses_advertised_addr_in_sdp() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        // Simulate a STUN-mapped address.
        let stun_ip: std::net::SocketAddr = "203.0.113.42:5060".parse().unwrap();
        tr.set_advertised_addr(stun_ip);

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        // The local SDP should contain the STUN-mapped IP, not a local IP.
        let sdp = call.local_sdp();
        assert!(
            sdp.contains("c=IN IP4 203.0.113.42"),
            "SDP should contain STUN-mapped IP, got: {}",
            sdp
        );
    }

    #[test]
    fn dial_prefers_local_ip_config_over_advertised_addr() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        // Set both advertised addr and explicit local_ip.
        let stun_ip: std::net::SocketAddr = "203.0.113.42:5060".parse().unwrap();
        tr.set_advertised_addr(stun_ip);

        let mut cfg = test_cfg();
        cfg.local_ip = "10.0.0.99".into();
        let phone = Phone::new(cfg);
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        // Explicit local_ip should take priority over STUN.
        let sdp = call.local_sdp();
        assert!(
            sdp.contains("c=IN IP4 10.0.0.99"),
            "SDP should use explicit local_ip over STUN, got: {}",
            sdp
        );
    }
}
