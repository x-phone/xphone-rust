use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::DialOptions;
use crate::error::{Error, Result};
use crate::mock::call::MockCall;
use crate::subscription::SubId;
use crate::types::{
    ExtensionState, ExtensionStatus, NotifyEvent, PhoneState, SipMessage, VoicemailStatus,
};

type BlfCallback = Arc<dyn Fn(ExtensionStatus, Option<ExtensionState>) + Send + Sync>;

struct Inner {
    state: PhoneState,
    on_incoming_fn: Option<Arc<dyn Fn(Arc<MockCall>) + Send + Sync>>,
    on_registered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unregistered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_error_fn: Option<Arc<dyn Fn(Error) + Send + Sync>>,
    on_voicemail_fn: Option<Arc<dyn Fn(VoicemailStatus) + Send + Sync>>,
    on_message_fn: Option<Arc<dyn Fn(SipMessage) + Send + Sync>>,
    on_subscription_error_fn: Option<Arc<dyn Fn(String, Error) + Send + Sync>>,
    last_call: Option<Arc<MockCall>>,
    calls: HashMap<String, Arc<MockCall>>,
    sent_messages: Vec<SipMessage>,
    blf_watchers: HashMap<String, (ExtensionState, BlfCallback)>,
    event_subscriptions: HashMap<SubId, Arc<dyn Fn(NotifyEvent) + Send + Sync>>,
    next_sub_id: u64,
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
                on_voicemail_fn: None,
                on_message_fn: None,
                on_subscription_error_fn: None,
                last_call: None,
                calls: HashMap::new(),
                sent_messages: Vec::new(),
                blf_watchers: HashMap::new(),
                event_subscriptions: HashMap::new(),
                next_sub_id: 1,
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

    /// Disconnects the phone. Ends all active calls and fires the on_unregistered callback.
    pub fn disconnect(&self) -> Result<()> {
        let (cb, active_calls) = {
            let mut inner = self.inner.lock();
            if inner.state == PhoneState::Disconnected {
                return Err(Error::NotConnected);
            }
            inner.state = PhoneState::Disconnected;
            inner.blf_watchers.clear();
            inner.event_subscriptions.clear();
            let calls: Vec<Arc<MockCall>> = inner.calls.drain().map(|(_, c)| c).collect();
            (inner.on_unregistered_fn.clone(), calls)
        };
        for call in active_calls {
            if call.state() != crate::types::CallState::Ended {
                call.end().ok();
            }
        }
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
        inner.calls.insert(call.call_id(), Arc::clone(&call));
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

    /// Registers a callback fired on voicemail (MWI) status updates.
    pub fn on_voicemail<F: Fn(VoicemailStatus) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_voicemail_fn = Some(Arc::new(f));
    }

    /// Registers a callback fired on incoming SIP MESSAGE.
    pub fn on_message<F: Fn(SipMessage) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_message_fn = Some(Arc::new(f));
    }

    /// Sends a SIP MESSAGE (mock: records the message for inspection).
    pub fn send_message(&self, target: &str, body: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        inner.sent_messages.push(SipMessage {
            from: String::new(),
            to: target.to_string(),
            content_type: "text/plain".to_string(),
            body: body.to_string(),
        });
        Ok(())
    }

    /// Returns all sent messages (for test assertions).
    pub fn sent_messages(&self) -> Vec<SipMessage> {
        self.inner.lock().sent_messages.clone()
    }

    /// Watches an extension's state (BLF). The callback receives the new status
    /// and the previous state (if any).
    pub fn watch<F>(&self, extension: &str, f: F) -> Result<()>
    where
        F: Fn(ExtensionStatus, Option<ExtensionState>) + Send + Sync + 'static,
    {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        inner.blf_watchers.insert(
            extension.to_string(),
            (ExtensionState::Unknown, Arc::new(f)),
        );
        Ok(())
    }

    /// Stops watching an extension's state.
    pub fn unwatch(&self, extension: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        inner.blf_watchers.remove(extension);
        Ok(())
    }

    /// Subscribes to a generic SIP event. Returns a subscription ID.
    pub fn subscribe_event<F>(&self, _uri: &str, _event: &str, _accept: &str, f: F) -> Result<SubId>
    where
        F: Fn(NotifyEvent) + Send + Sync + 'static,
    {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        let id = inner.next_sub_id;
        inner.next_sub_id += 1;
        inner.event_subscriptions.insert(id, Arc::new(f));
        Ok(id)
    }

    /// Unsubscribes from a generic SIP event by subscription ID.
    pub fn unsubscribe_event(&self, sub_id: SubId) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        inner.event_subscriptions.remove(&sub_id);
        Ok(())
    }

    /// Registers a callback fired when a subscription encounters a permanent failure.
    pub fn on_subscription_error<F>(&self, f: F)
    where
        F: Fn(String, Error) + Send + Sync + 'static,
    {
        self.inner.lock().on_subscription_error_fn = Some(Arc::new(f));
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
            inner.calls.insert(call.call_id(), Arc::clone(&call));
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

    /// Simulates an incoming SIP MESSAGE and fires the on_message callback.
    pub fn simulate_message(&self, from: &str, body: &str) {
        let cb = self.inner.lock().on_message_fn.clone();
        if let Some(f) = cb {
            f(SipMessage {
                from: from.to_string(),
                to: String::new(),
                content_type: "text/plain".to_string(),
                body: body.to_string(),
            });
        }
    }

    /// Simulates an extension state change and fires the watch callback.
    /// Implements duplicate suppression (same as Phone).
    pub fn simulate_extension_state(&self, extension: &str, state: ExtensionState) {
        let cb = {
            let mut inner = self.inner.lock();
            if let Some((prev, f)) = inner.blf_watchers.get_mut(extension) {
                if *prev == state {
                    return; // duplicate suppression
                }
                let old = *prev;
                *prev = state;
                let status = ExtensionStatus {
                    extension: extension.to_string(),
                    state,
                };
                Some((f.clone(), status, Some(old)))
            } else {
                None
            }
        };
        if let Some((f, status, prev)) = cb {
            f(status, prev);
        }
    }

    /// Simulates a generic event notification for a subscription.
    pub fn simulate_notify(&self, sub_id: SubId, event: NotifyEvent) {
        let cb = {
            let inner = self.inner.lock();
            inner.event_subscriptions.get(&sub_id).cloned()
        };
        if let Some(f) = cb {
            f(event);
        }
    }

    /// Simulates a subscription error.
    pub fn simulate_subscription_error(&self, uri: &str, err: Error) {
        let cb = self.inner.lock().on_subscription_error_fn.clone();
        if let Some(f) = cb {
            f(uri.to_string(), err);
        }
    }

    /// Returns the list of currently watched extensions.
    pub fn watched_extensions(&self) -> Vec<String> {
        self.inner.lock().blf_watchers.keys().cloned().collect()
    }

    /// Fires the OnVoicemail callback with the given status.
    pub fn simulate_mwi(&self, status: VoicemailStatus) {
        let cb = self.inner.lock().on_voicemail_fn.clone();
        if let Some(f) = cb {
            f(status);
        }
    }

    /// Returns the most recent call (dialed or incoming).
    pub fn last_call(&self) -> Option<Arc<MockCall>> {
        self.inner.lock().last_call.clone()
    }

    /// Looks up a tracked call by ID.
    pub fn find_call(&self, call_id: &str) -> Option<Arc<MockCall>> {
        self.inner.lock().calls.get(call_id).cloned()
    }

    /// Returns all tracked calls.
    pub fn calls(&self) -> Vec<Arc<MockCall>> {
        self.inner.lock().calls.values().cloned().collect()
    }

    /// Initiates an attended transfer between two mock calls.
    /// Records the transfer on `call_a` and ends both calls with `Transfer` reason.
    pub fn attended_transfer(&self, call_a: &Arc<MockCall>, call_b: &Arc<MockCall>) -> Result<()> {
        use crate::types::CallState;

        let state_a = call_a.state();
        if state_a != CallState::Active && state_a != CallState::OnHold {
            return Err(Error::InvalidState);
        }
        let state_b = call_b.state();
        if state_b != CallState::Active && state_b != CallState::OnHold {
            return Err(Error::InvalidState);
        }

        call_a.blind_transfer(&call_b.remote_uri())?;
        call_a.end_with_reason(crate::types::EndReason::Transfer);
        call_b.end_with_reason(crate::types::EndReason::Transfer);
        Ok(())
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
    use crate::types::SubState;
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
    fn find_call_returns_tracked_call() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let call = p
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let found = p.find_call(&call.call_id()).unwrap();
        assert_eq!(found.call_id(), call.call_id());
    }

    #[test]
    fn multiple_calls_tracked() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let c1 = p
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let c2 = p
            .dial("sip:1003@pbx.local", DialOptions::default())
            .unwrap();
        p.on_incoming(|_| {});
        p.simulate_incoming("sip:1004@pbx.local");

        assert_eq!(p.calls().len(), 3);
        assert!(p.find_call(&c1.call_id()).is_some());
        assert!(p.find_call(&c2.call_id()).is_some());
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

    #[test]
    fn attended_transfer_ends_both_calls() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let a = p.dial("sip:bob@pbx.local", DialOptions::default()).unwrap();
        let b = p
            .dial("sip:charlie@pbx.local", DialOptions::default())
            .unwrap();
        p.attended_transfer(&a, &b).unwrap();
        assert_eq!(a.state(), crate::types::CallState::Ended);
        assert_eq!(b.state(), crate::types::CallState::Ended);
    }

    #[test]
    fn attended_transfer_rejects_ringing_call() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let a = p.dial("sip:bob@pbx.local", DialOptions::default()).unwrap();
        let b = Arc::new(MockCall::new()); // Ringing state
        let result = p.attended_transfer(&a, &b);
        assert!(result.is_err());
    }

    #[test]
    fn simulate_mwi_fires_callback() {
        let p = MockPhone::new();
        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        p.on_voicemail(move |status| {
            *received_clone.lock() = Some(status);
        });

        p.simulate_mwi(VoicemailStatus {
            messages_waiting: true,
            account: "sip:*97@pbx.local".into(),
            voice: (3, 5),
        });

        let s = received.lock().clone().unwrap();
        assert!(s.messages_waiting);
        assert_eq!(s.voice, (3, 5));
        assert_eq!(s.account, "sip:*97@pbx.local");
    }

    #[test]
    fn simulate_mwi_without_callback() {
        let p = MockPhone::new();
        // Should not panic.
        p.simulate_mwi(VoicemailStatus::default());
    }

    #[test]
    fn send_message_before_connect_errors() {
        let p = MockPhone::new();
        let err = p.send_message("sip:1002@pbx.local", "Hello").unwrap_err();
        assert!(matches!(err, Error::NotRegistered));
    }

    #[test]
    fn send_message_records_message() {
        let p = MockPhone::new();
        p.connect().unwrap();
        p.send_message("sip:1002@pbx.local", "Hello!").unwrap();
        let msgs = p.sent_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].to, "sip:1002@pbx.local");
        assert_eq!(msgs[0].body, "Hello!");
        assert_eq!(msgs[0].content_type, "text/plain");
    }

    #[test]
    fn simulate_message_fires_callback() {
        let p = MockPhone::new();
        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        p.on_message(move |msg| {
            *received_clone.lock() = Some(msg);
        });
        p.simulate_message("sip:1001@pbx.local", "Hi there");
        let msg = received.lock().clone().unwrap();
        assert_eq!(msg.from, "sip:1001@pbx.local");
        assert_eq!(msg.body, "Hi there");
    }

    #[test]
    fn simulate_message_without_callback() {
        let p = MockPhone::new();
        // Should not panic.
        p.simulate_message("sip:1001@pbx.local", "Hello");
    }

    #[test]
    fn watch_before_connect_errors() {
        let p = MockPhone::new();
        let err = p.watch("1002", |_, _| {}).unwrap_err();
        assert!(matches!(err, Error::NotRegistered));
    }

    #[test]
    fn watch_fires_callback_on_state_change() {
        let p = MockPhone::new();
        p.connect().unwrap();

        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        p.watch("1002", move |status, prev| {
            *received_clone.lock() = Some((status, prev));
        })
        .unwrap();

        p.simulate_extension_state("1002", ExtensionState::OnThePhone);

        let (status, prev) = received.lock().clone().unwrap();
        assert_eq!(status.extension, "1002");
        assert_eq!(status.state, ExtensionState::OnThePhone);
        assert_eq!(prev, Some(ExtensionState::Unknown));
    }

    #[test]
    fn watch_duplicate_suppression() {
        let p = MockPhone::new();
        p.connect().unwrap();

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count_clone = Arc::clone(&count);
        p.watch("1002", move |_, _| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();

        p.simulate_extension_state("1002", ExtensionState::Available);
        p.simulate_extension_state("1002", ExtensionState::Available); // duplicate
        p.simulate_extension_state("1002", ExtensionState::OnThePhone);

        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn unwatch_removes_subscription() {
        let p = MockPhone::new();
        p.connect().unwrap();
        p.watch("1002", |_, _| {}).unwrap();
        assert_eq!(p.watched_extensions().len(), 1);
        p.unwatch("1002").unwrap();
        assert!(p.watched_extensions().is_empty());
    }

    #[test]
    fn subscribe_event_returns_id() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let id = p
            .subscribe_event(
                "sip:1002@pbx.local",
                "presence",
                "application/pidf+xml",
                |_| {},
            )
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn simulate_notify_fires_callback() {
        let p = MockPhone::new();
        p.connect().unwrap();

        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        let id = p
            .subscribe_event(
                "sip:1002@pbx.local",
                "dialog",
                "application/dialog-info+xml",
                move |ev| {
                    *received_clone.lock() = Some(ev);
                },
            )
            .unwrap();

        p.simulate_notify(
            id,
            NotifyEvent {
                event: "dialog".to_string(),
                content_type: "application/dialog-info+xml".to_string(),
                body: "<dialog-info/>".to_string(),
                subscription_state: SubState::Active { expires: 3600 },
            },
        );

        let ev = received.lock().clone().unwrap();
        assert_eq!(ev.event, "dialog");
    }

    #[test]
    fn unsubscribe_event_removes() {
        let p = MockPhone::new();
        p.connect().unwrap();
        let id = p
            .subscribe_event(
                "sip:1002@pbx.local",
                "presence",
                "application/pidf+xml",
                |_| {},
            )
            .unwrap();
        p.unsubscribe_event(id).unwrap();

        // simulate_notify should not panic (callback removed)
        p.simulate_notify(
            id,
            NotifyEvent {
                event: "presence".to_string(),
                content_type: "application/pidf+xml".to_string(),
                body: String::new(),
                subscription_state: SubState::Terminated {
                    reason: "noresource".to_string(),
                },
            },
        );
    }

    #[test]
    fn simulate_subscription_error_fires_callback() {
        let p = MockPhone::new();
        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        p.on_subscription_error(move |uri, _err| {
            *received_clone.lock() = Some(uri);
        });
        p.simulate_subscription_error("sip:1002@pbx.local", Error::NotConnected);
        assert_eq!(*received.lock(), Some("sip:1002@pbx.local".to_string()));
    }

    #[test]
    fn disconnect_clears_watchers() {
        let p = MockPhone::new();
        p.connect().unwrap();
        p.watch("1002", |_, _| {}).unwrap();
        p.disconnect().unwrap();
        assert!(p.watched_extensions().is_empty());
    }
}
