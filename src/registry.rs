use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::callback_pool::spawn_callback;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::SipTransport;
use crate::types::PhoneState;

struct Inner {
    state: PhoneState,
    on_registered: Vec<Arc<dyn Fn() + Send + Sync>>,
    on_unregistered: Vec<Arc<dyn Fn() + Send + Sync>>,
    on_error: Vec<Arc<dyn Fn(Error) + Send + Sync>>,
    reregistering: bool,
    stopped: bool,
    /// Handle for the re-registration thread spawned by handle_drop.
    rereg_thread: Option<std::thread::JoinHandle<()>>,
}

/// Manages SIP registration lifecycle: initial register with retries,
/// periodic refresh, NAT keepalives, and transport drop recovery.
pub struct Registry {
    tr: Arc<dyn SipTransport>,
    cfg: Config,
    inner: Arc<Mutex<Inner>>,
    /// Dropping this sender signals the background loop to stop.
    stop_tx: Mutex<Option<crossbeam_channel::Sender<()>>>,
    /// Handle for the background loop thread.
    loop_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Registry {
    pub fn new(tr: Arc<dyn SipTransport>, cfg: Config) -> Self {
        Self {
            tr,
            cfg,
            inner: Arc::new(Mutex::new(Inner {
                state: PhoneState::Disconnected,
                on_registered: Vec::new(),
                on_unregistered: Vec::new(),
                on_error: Vec::new(),
                reregistering: false,
                stopped: false,
                rereg_thread: None,
            })),
            stop_tx: Mutex::new(None),
            loop_thread: Mutex::new(None),
        }
    }

    /// Performs initial registration and starts the background refresh/keepalive loop.
    /// Blocks until the initial REGISTER succeeds or all retries are exhausted.
    pub fn start(&self) -> Result<()> {
        let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(0);

        {
            let mut inner = self.inner.lock();
            inner.state = PhoneState::Registering;
            inner.stopped = false;
        }
        *self.stop_tx.lock() = Some(stop_tx);

        // Wire up transport drop detection.
        let inner_clone = Arc::clone(&self.inner);
        let tr_clone = Arc::clone(&self.tr);
        let cfg_clone = self.cfg.clone();
        self.tr.on_drop(Box::new(move || {
            handle_drop(&inner_clone, &tr_clone, &cfg_clone);
        }));

        // Attempt initial registration with retries.
        if let Err(e) = self.register() {
            *self.stop_tx.lock() = None;
            return Err(e);
        }

        // Start background loop.
        let tr = Arc::clone(&self.tr);
        let cfg = self.cfg.clone();
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new()
            .name("registry-loop".into())
            .spawn(move || registry_loop(tr, cfg, inner, stop_rx))
            .expect("failed to spawn registry loop");
        *self.loop_thread.lock() = Some(handle);

        Ok(())
    }

    /// Stops the background loop, sends unregister, and transitions to Disconnected.
    pub fn stop(&self) {
        // Send REGISTER Expires=0 to unregister before tearing down.
        {
            let inner = self.inner.lock();
            if inner.state == PhoneState::Registered {
                drop(inner);
                info!("unregistering from server");
                if let Err(e) = self.tr.unregister(Duration::from_secs(5)) {
                    warn!(error = %e, "unregister failed");
                }
            }
        }

        let rereg_handle = {
            let mut inner = self.inner.lock();
            inner.state = PhoneState::Disconnected;
            inner.stopped = true;
            inner.rereg_thread.take()
        };
        // Drop the sender to close the channel — wakes the loop.
        self.stop_tx.lock().take();
        // Join the background loop thread.
        if let Some(handle) = self.loop_thread.lock().take() {
            let _ = handle.join();
        }
        // Join the re-registration thread if one is running.
        if let Some(handle) = rereg_handle {
            let _ = handle.join();
        }
    }

    pub fn on_registered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(f);
        let mut inner = self.inner.lock();
        let already = inner.state == PhoneState::Registered;
        inner.on_registered.push(Arc::clone(&cb));
        drop(inner);

        if already {
            spawn_callback(move || cb());
        }
    }

    pub fn on_unregistered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_unregistered.push(Arc::new(f));
    }

    pub fn on_error<F: Fn(Error) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_error.push(Arc::new(f));
    }

    pub fn state(&self) -> PhoneState {
        self.inner.lock().state
    }

    /// Sends REGISTER with retries. On success, transitions to Registered and
    /// fires OnRegistered. On exhausting retries, fires OnError with the last
    /// observed SIP status (or `code == 0` and the transport error description
    /// if no response was received).
    fn register(&self) -> Result<()> {
        let mut last_code: u16 = 0;
        let mut last_reason: String = String::new();

        for attempt in 0..self.cfg.register_max_retry {
            if attempt > 0 {
                debug!(attempt, "REGISTER retry after delay");
                if self.inner.lock().stopped {
                    return Err(Error::Other("registry stopped".into()));
                }
                std::thread::sleep(self.cfg.register_retry);
            }

            info!(attempt, "REGISTER attempt");
            let result = self
                .tr
                .send_request("REGISTER", None, self.cfg.register_expiry);
            let msg = match result {
                Ok(m) => m,
                Err(e) => {
                    warn!(attempt, error = %e, "REGISTER failed");
                    last_code = 0;
                    last_reason = format!("transport: {}", e);
                    continue;
                }
            };

            if msg.status_code == 200 {
                info!("REGISTER success — registered");
                let cbs = {
                    let mut inner = self.inner.lock();
                    inner.state = PhoneState::Registered;
                    inner.on_registered.clone()
                };
                for f in cbs {
                    spawn_callback(move || f());
                }
                return Ok(());
            }

            last_code = msg.status_code;
            last_reason = msg.reason.clone();
        }

        // All retries exhausted.
        warn!(
            max_retry = self.cfg.register_max_retry,
            last_code,
            last_reason = %last_reason,
            "REGISTER failed — all retries exhausted"
        );
        let cbs = {
            let mut inner = self.inner.lock();
            inner.state = PhoneState::RegistrationFailed;
            inner.on_error.clone()
        };
        let err = Error::RegistrationFailed {
            code: last_code,
            reason: last_reason.clone(),
        };
        for f in cbs {
            let err = err.clone();
            spawn_callback(move || f(err));
        }
        Err(err)
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Called when the transport connection drops.
fn handle_drop(inner: &Arc<Mutex<Inner>>, tr: &Arc<dyn SipTransport>, cfg: &Config) {
    warn!("transport drop detected — attempting re-registration");
    let (cbs, should_reregister) = {
        let mut guard = inner.lock();
        if guard.state == PhoneState::Disconnected || guard.reregistering || guard.stopped {
            return;
        }
        guard.state = PhoneState::Registering;
        guard.reregistering = true;
        (guard.on_unregistered.clone(), true)
    };

    for f in cbs {
        spawn_callback(move || f());
    }

    if should_reregister {
        let inner_clone = Arc::clone(inner);
        let tr = Arc::clone(tr);
        let cfg = cfg.clone();
        let handle = std::thread::spawn(move || {
            let _ = reregister(&inner_clone, &tr, &cfg);
            let mut guard = inner_clone.lock();
            guard.reregistering = false;
            guard.rereg_thread = None;
        });
        // Store the handle so stop() can join it.
        inner.lock().rereg_thread = Some(handle);
    }
}

/// Re-registration attempt after a transport drop.
fn reregister(inner: &Arc<Mutex<Inner>>, tr: &Arc<dyn SipTransport>, cfg: &Config) -> Result<()> {
    let mut last_code: u16 = 0;
    let mut last_reason: String = String::new();

    for attempt in 0..cfg.register_max_retry {
        if attempt > 0 {
            if inner.lock().stopped {
                return Err(Error::Other("registry stopped".into()));
            }
            std::thread::sleep(cfg.register_retry);
        }

        let result = tr.send_request("REGISTER", None, cfg.register_expiry);
        let msg = match result {
            Ok(m) => m,
            Err(e) => {
                last_code = 0;
                last_reason = format!("transport: {}", e);
                continue;
            }
        };

        if msg.status_code == 200 {
            let cbs = {
                let mut guard = inner.lock();
                guard.state = PhoneState::Registered;
                guard.on_registered.clone()
            };
            for f in cbs {
                spawn_callback(move || f());
            }
            return Ok(());
        }

        last_code = msg.status_code;
        last_reason = msg.reason.clone();
    }

    warn!(
        last_code,
        last_reason = %last_reason,
        "re-REGISTER failed — all retries exhausted"
    );
    let cbs = {
        let mut guard = inner.lock();
        guard.state = PhoneState::RegistrationFailed;
        guard.on_error.clone()
    };
    let err = Error::RegistrationFailed {
        code: last_code,
        reason: last_reason.clone(),
    };
    for f in cbs {
        let err = err.clone();
        spawn_callback(move || f(err));
    }
    Err(err)
}

/// Background loop: periodic refresh and NAT keepalive.
fn registry_loop(
    tr: Arc<dyn SipTransport>,
    cfg: Config,
    inner: Arc<Mutex<Inner>>,
    stop_rx: crossbeam_channel::Receiver<()>,
) {
    let refresh_interval = cfg.register_expiry / 2;
    let keepalive_interval = cfg.nat_keepalive_interval;

    let mut last_refresh = std::time::Instant::now();
    let mut last_keepalive = std::time::Instant::now();

    loop {
        // Sleep in short increments so we can check the stop signal.
        let tick = Duration::from_millis(500);
        match stop_rx.recv_timeout(tick) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }

        if inner.lock().stopped {
            return;
        }

        // Refresh timer.
        if last_refresh.elapsed() >= refresh_interval {
            last_refresh = std::time::Instant::now();
            let result = tr.send_request("REGISTER", None, cfg.register_expiry);
            match result {
                Ok(msg) if msg.status_code == 200 => {}
                _ => {
                    handle_drop(&inner, &tr, &cfg);
                }
            }
        }

        // NAT keepalive timer.
        if let Some(interval) = keepalive_interval {
            if last_keepalive.elapsed() >= interval {
                last_keepalive = std::time::Instant::now();
                let _ = tr.send_keepalive();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::transport::MockTransport;

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
    fn start_registers_successfully() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        reg.start().unwrap();

        assert_eq!(reg.state(), PhoneState::Registered);
        assert_eq!(tr.count_sent("REGISTER"), 1);

        reg.stop();
    }

    #[test]
    fn start_retries_on_failure() {
        let tr = Arc::new(MockTransport::new());
        tr.fail_next(2);
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        reg.start().unwrap();

        assert_eq!(reg.state(), PhoneState::Registered);
        // 2 failed + 1 success = 3 REGISTER attempts
        assert_eq!(tr.count_sent("REGISTER"), 3);

        reg.stop();
    }

    #[test]
    fn start_fails_after_max_retries() {
        let tr = Arc::new(MockTransport::new());
        tr.fail_next(10);

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        let result = reg.start();

        assert!(result.is_err());
        assert_eq!(reg.state(), PhoneState::RegistrationFailed);
    }

    #[test]
    fn start_surfaces_403_code_and_reason() {
        // A SIP rejection (403 Forbidden) on every attempt must surface the
        // status code and reason-phrase in the returned error.
        let tr = Arc::new(MockTransport::new());
        for _ in 0..3 {
            tr.respond_with(403, "Forbidden");
        }

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        let err = reg.start().unwrap_err();

        match err {
            Error::RegistrationFailed { code, reason } => {
                assert_eq!(code, 403);
                assert_eq!(reason, "Forbidden");
            }
            other => panic!("expected RegistrationFailed {{403, Forbidden}}, got {other:?}"),
        }
        assert_eq!(reg.state(), PhoneState::RegistrationFailed);
    }

    #[test]
    fn start_transport_failure_surfaces_code_zero() {
        // Pure transport failure (no SIP response ever received) must produce
        // code=0 with a transport-error reason-phrase.
        let tr = Arc::new(MockTransport::new());
        tr.fail_next(10);

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        let err = reg.start().unwrap_err();

        match err {
            Error::RegistrationFailed { code, reason } => {
                assert_eq!(code, 0, "transport failure must not surface a SIP code");
                assert!(
                    reason.starts_with("transport:"),
                    "reason should describe transport failure, got: {reason}"
                );
            }
            other => panic!("expected RegistrationFailed {{0, transport:...}}, got {other:?}"),
        }
    }

    #[test]
    fn start_error_callback_receives_detailed_error() {
        let tr = Arc::new(MockTransport::new());
        for _ in 0..3 {
            tr.respond_with(503, "Service Unavailable");
        }

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        let (tx, rx) = crossbeam_channel::bounded(1);
        reg.on_error(move |e| {
            let _ = tx.send(e);
        });

        let _ = reg.start();
        let received = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match received {
            Error::RegistrationFailed { code, reason } => {
                assert_eq!(code, 503);
                assert_eq!(reason, "Service Unavailable");
            }
            other => panic!("expected detailed RegistrationFailed, got {other:?}"),
        }
    }

    #[test]
    fn stop_sets_disconnected() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        reg.start().unwrap();
        reg.stop();

        assert_eq!(reg.state(), PhoneState::Disconnected);
    }

    #[test]
    fn on_registered_fires_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        reg.on_registered(move || {
            let _ = tx.send(true);
        });

        reg.start().unwrap();

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);

        reg.stop();
    }

    #[test]
    fn on_registered_fires_if_already_registered() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());
        reg.start().unwrap();

        // Set callback after already registered.
        let (tx, rx) = crossbeam_channel::bounded(1);
        reg.on_registered(move || {
            let _ = tx.send(true);
        });

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);

        reg.stop();
    }

    #[test]
    fn drop_triggers_reregistration() {
        let tr = Arc::new(MockTransport::new());
        // Initial register.
        tr.respond_with(200, "OK");

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());

        let (unreg_tx, unreg_rx) = crossbeam_channel::bounded(1);
        reg.on_unregistered(move || {
            let _ = unreg_tx.send(true);
        });

        reg.start().unwrap();
        assert_eq!(reg.state(), PhoneState::Registered);

        // Queue a response for the re-registration attempt.
        tr.respond_with(200, "OK");
        tr.simulate_drop();

        // Wait for OnUnregistered callback.
        let fired = unreg_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);

        // Wait for re-registration to complete.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(reg.state(), PhoneState::Registered);

        reg.stop();
    }

    #[test]
    fn on_error_fires_on_exhausted_retries() {
        let tr = Arc::new(MockTransport::new());
        tr.fail_next(10);

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        reg.on_error(move |_| {
            let _ = tx.send(true);
        });

        let _ = reg.start();

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);
    }

    #[test]
    fn keepalive_sent_when_configured() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");

        let mut cfg = test_cfg();
        cfg.nat_keepalive_interval = Some(Duration::from_millis(200));

        let reg = Registry::new(Arc::clone(&tr) as Arc<dyn SipTransport>, cfg);
        reg.start().unwrap();

        // The loop ticks every 500ms; with 200ms keepalive interval,
        // each tick fires a keepalive. Wait for 2+ ticks.
        std::thread::sleep(Duration::from_millis(1500));
        assert!(
            tr.count_keepalives() >= 2,
            "expected >=2 keepalives, got {}",
            tr.count_keepalives()
        );

        reg.stop();
    }
}
