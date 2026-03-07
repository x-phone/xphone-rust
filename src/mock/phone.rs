use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::DialOptions;
use crate::error::{Error, Result};
use crate::mock::call::MockCall;
use crate::types::PhoneState;

struct Inner {
    state: PhoneState,
    on_incoming_fn: Option<Arc<dyn Fn(Arc<MockCall>) + Send + Sync>>,
    on_registered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unregistered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_error_fn: Option<Arc<dyn Fn(Error) + Send + Sync>>,
    last_call: Option<Arc<MockCall>>,
}

/// Mock phone for testing consumer code without a real SIP transport.
/// Provides the same API surface as `Phone` but with test simulation methods.
pub struct MockPhone {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for MockPhone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("MockPhone")
            .field("state", &inner.state)
            .finish()
    }
}

impl MockPhone {
    /// Creates a new `MockPhone` in the `Disconnected` state.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: PhoneState::Disconnected,
                on_incoming_fn: None,
                on_registered_fn: None,
                on_unregistered_fn: None,
                on_error_fn: None,
                last_call: None,
            }),
        }
    }

    /// Connects and registers the phone. Fires the on_registered callback.
    pub fn connect(&self) -> Result<()> {
        let cb = {
            let mut inner = self.inner.lock();
            if inner.state != PhoneState::Disconnected {
                return Err(Error::AlreadyConnected);
            }
            inner.state = PhoneState::Registered;
            inner.on_registered_fn.clone()
        };
        if let Some(f) = cb {
            f();
        }
        Ok(())
    }

    /// Disconnects the phone. Fires the on_unregistered callback.
    pub fn disconnect(&self) -> Result<()> {
        let cb = {
            let mut inner = self.inner.lock();
            if inner.state == PhoneState::Disconnected {
                return Err(Error::NotConnected);
            }
            inner.state = PhoneState::Disconnected;
            inner.on_unregistered_fn.clone()
        };
        if let Some(f) = cb {
            f();
        }
        Ok(())
    }

    /// Dials a target URI, returning an outbound `MockCall` in the `Active` state.
    pub fn dial(&self, target: &str, _opts: DialOptions) -> Result<Arc<MockCall>> {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }

        let call = Arc::new(MockCall::new());
        call.set_state(crate::types::CallState::Active);
        call.set_direction(crate::types::Direction::Outbound);
        call.set_remote_uri(target);
        inner.last_call = Some(Arc::clone(&call));
        Ok(call)
    }

    /// Registers a callback fired when an incoming call arrives.
    pub fn on_incoming<F: Fn(Arc<MockCall>) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_incoming_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the phone becomes registered.
    pub fn on_registered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_registered_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired when the phone becomes unregistered.
    pub fn on_unregistered<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_unregistered_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired on errors.
    pub fn on_error<F: Fn(Error) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_error_fn = Some(Arc::new(f));
    }

    /// Returns the current phone state.
    pub fn state(&self) -> PhoneState {
        self.inner.lock().state
    }

    // --- Test simulation methods ---

    /// Creates an incoming MockCall and fires the OnIncoming callback.
    pub fn simulate_incoming(&self, from: &str) {
        let call = Arc::new(MockCall::new());
        call.set_remote_uri(from);

        let cb = {
            let mut inner = self.inner.lock();
            inner.last_call = Some(Arc::clone(&call));
            inner.on_incoming_fn.clone()
        };
        if let Some(f) = cb {
            f(call);
        }
    }

    /// Fires the OnError callback with the given error.
    pub fn simulate_error(&self, err: Error) {
        let cb = self.inner.lock().on_error_fn.clone();
        if let Some(f) = cb {
            f(err);
        }
    }

    /// Returns the most recent call (dialed or incoming).
    pub fn last_call(&self) -> Option<Arc<MockCall>> {
        self.inner.lock().last_call.clone()
    }
}

impl Default for MockPhone {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn new_mock_phone_is_disconnected() {
        let p = MockPhone::new();
        assert_eq!(p.state(), PhoneState::Disconnected);
    }

    #[test]
    fn connect_transitions_to_registered() {
        let p = MockPhone::new();
        p.connect().unwrap();
        assert_eq!(p.state(), PhoneState::Registered);
    }

    #[test]
    fn connect_when_already_connected_errors() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let err = p.connect().unwrap_err();
        assert!(matches!(err, Error::AlreadyConnected));
    }

    #[test]
    fn disconnect_transitions_to_disconnected() {
        let p = MockPhone::new();
        p.connect().unwrap();
        p.disconnect().unwrap();
        assert_eq!(p.state(), PhoneState::Disconnected);
    }

    #[test]
    fn disconnect_when_not_connected_errors() {
        let p = MockPhone::new();
        let err = p.disconnect().unwrap_err();
        assert!(matches!(err, Error::NotConnected));
    }

    #[test]
    fn dial_creates_outbound_call() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let call = p
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        assert_eq!(call.state(), crate::types::CallState::Active);
        assert_eq!(call.direction(), crate::types::Direction::Outbound);
        assert_eq!(call.remote_uri(), "sip:1002@pbx.local");
    }

    #[test]
    fn dial_before_connect_errors() {
        let p = MockPhone::new();
        let err = p
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap_err();
        assert!(matches!(err, Error::NotRegistered));
    }

    #[test]
    fn on_registered_fires_on_connect() {
        let p = MockPhone::new();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        p.on_registered(move || {
            fired_clone.store(true, Ordering::Relaxed);
        });
        p.connect().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn on_unregistered_fires_on_disconnect() {
        let p = MockPhone::new();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        p.on_unregistered(move || {
            fired_clone.store(true, Ordering::Relaxed);
        });
        p.connect().unwrap();
        p.disconnect().unwrap();
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn simulate_incoming_fires_callback() {
        let p = MockPhone::new();
        let received = Arc::new(Mutex::new(String::new()));
        let received_clone = Arc::clone(&received);
        p.on_incoming(move |call| {
            *received_clone.lock() = call.remote_uri();
        });
        p.simulate_incoming("sip:1001@pbx.local");
        assert_eq!(*received.lock(), "sip:1001@pbx.local");
    }

    #[test]
    fn simulate_incoming_without_callback() {
        let p = MockPhone::new();
        p.simulate_incoming("sip:1001@pbx.local");
        let last = p.last_call().unwrap();
        assert_eq!(last.remote_uri(), "sip:1001@pbx.local");
    }

    #[test]
    fn simulate_error_fires_callback() {
        let p = MockPhone::new();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        p.on_error(move |_| {
            fired_clone.store(true, Ordering::Relaxed);
        });
        p.simulate_error(Error::RegistrationFailed);
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn last_call_returns_most_recent() {
        let p = MockPhone::new();
        p.connect().unwrap();

        assert!(p.last_call().is_none());

        let call = p
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let last = p.last_call().unwrap();
        assert_eq!(last.remote_uri(), call.remote_uri());
    }

    #[test]
    fn last_call_updated_on_simulate_incoming() {
        let p = MockPhone::new();
        p.on_incoming(|_| {});
        p.simulate_incoming("sip:1001@pbx.local");
        let last = p.last_call().unwrap();
        assert_eq!(last.remote_uri(), "sip:1001@pbx.local");
    }

    #[test]
    fn callback_can_query_state() {
        let p = Arc::new(MockPhone::new());
        let p2 = Arc::clone(&p);
        let state = Arc::new(Mutex::new(PhoneState::Disconnected));
        let state_clone = Arc::clone(&state);
        p.on_registered(move || {
            *state_clone.lock() = p2.state();
        });
        p.connect().unwrap();
        assert_eq!(*state.lock(), PhoneState::Registered);
    }
}
