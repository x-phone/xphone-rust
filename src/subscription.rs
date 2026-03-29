//! Generic SUBSCRIBE/NOTIFY subscription manager (RFC 6665).
//!
//! Manages multiple concurrent SIP subscriptions from a single background thread.
//! Used by the BLF (watch/unwatch) API and the generic subscribe_event API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::transport::SipTransport;
use crate::types::{parse_subscription_state, NotifyEvent, SubState};

/// Unique subscription identifier.
pub type SubId = u64;

/// Command sent to the manager thread.
enum Command {
    Subscribe {
        id: SubId,
        uri: String,
        event: String,
        accept: String,
        callback: Arc<dyn Fn(NotifyEvent) + Send + Sync>,
    },
    Unsubscribe {
        id: SubId,
    },
    Notify {
        event: String,
        content_type: String,
        body: String,
        subscription_state: String,
        from_uri: String,
    },
    Stop,
}

/// Lifecycle state of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleState {
    Pending,
    Active,
    Terminated,
}

/// Tracked state for one active subscription.
struct Subscription {
    id: SubId,
    uri: String,
    event: String,
    accept: String,
    callback: Arc<dyn Fn(NotifyEvent) + Send + Sync>,
    expires_at: Instant,
    expires_duration: Duration,
    initial_notify_received: bool,
    subscribe_ok_at: Option<Instant>,
    last_refresh_at: Option<Instant>,
    state: LifecycleState,
}

/// Manages all active SIP subscriptions from a single background thread.
pub struct SubscriptionManager {
    cmd_tx: Sender<Command>,
    next_id: AtomicU64,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    error_cb: ErrorCallback,
}

impl SubscriptionManager {
    /// Creates a new manager and spawns the background thread.
    pub fn new(tr: Arc<dyn SipTransport>) -> Self {
        let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded();
        let error_cb: ErrorCallback = Arc::new(Mutex::new(Vec::new()));
        let error_cb_clone = Arc::clone(&error_cb);

        let handle = std::thread::Builder::new()
            .name("subscription-mgr".into())
            .spawn(move || {
                subscription_loop(tr, cmd_rx, error_cb_clone);
            })
            .expect("failed to spawn subscription manager thread");

        Self {
            cmd_tx,
            next_id: AtomicU64::new(1),
            thread: Mutex::new(Some(handle)),
            error_cb,
        }
    }

    /// Subscribe to an event package. Returns a subscription ID.
    pub fn subscribe(
        &self,
        uri: &str,
        event: &str,
        accept: &str,
        callback: Arc<dyn Fn(NotifyEvent) + Send + Sync>,
    ) -> SubId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let _ = self.cmd_tx.send(Command::Subscribe {
            id,
            uri: uri.to_string(),
            event: event.to_string(),
            accept: accept.to_string(),
            callback,
        });
        id
    }

    /// Unsubscribe by ID.
    pub fn unsubscribe(&self, id: SubId) {
        let _ = self.cmd_tx.send(Command::Unsubscribe { id });
    }

    /// Called by the transport layer when a subscription NOTIFY arrives.
    pub fn handle_notify(
        &self,
        event: String,
        content_type: String,
        body: String,
        subscription_state: String,
        from_uri: String,
    ) {
        let _ = self.cmd_tx.send(Command::Notify {
            event,
            content_type,
            body,
            subscription_state,
            from_uri,
        });
    }

    /// Sets the error callback.
    pub fn on_error<F: Fn(String, Error) + Send + Sync + 'static>(&self, f: F) {
        self.error_cb.lock().push(Arc::new(f));
    }

    /// Stops the manager thread and joins it.
    pub fn stop(&self) {
        let _ = self.cmd_tx.send(Command::Stop);
        if let Some(handle) = self.thread.lock().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SubscriptionManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Shared error callback type.
type ErrorCallback = Arc<Mutex<Vec<Arc<dyn Fn(String, Error) + Send + Sync>>>>;

/// Default SUBSCRIBE Expires value.
const DEFAULT_EXPIRES: u32 = 600;

/// Timeout for initial NOTIFY after SUBSCRIBE 200 OK.
const INITIAL_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Background thread event loop.
fn subscription_loop(
    tr: Arc<dyn SipTransport>,
    cmd_rx: Receiver<Command>,
    error_cb: ErrorCallback,
) {
    let mut subs: HashMap<SubId, Subscription> = HashMap::new();
    let tick = Duration::from_millis(500);

    loop {
        match cmd_rx.recv_timeout(tick) {
            Ok(Command::Stop) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // Unsubscribe all before exiting.
                for sub in subs.values() {
                    if sub.state == LifecycleState::Active {
                        let _ = do_unsubscribe(&tr, &sub.uri, &sub.event, &sub.accept);
                    }
                }
                return;
            }
            Ok(Command::Subscribe {
                id,
                uri,
                event,
                accept,
                callback,
            }) => {
                handle_subscribe(&tr, &error_cb, &mut subs, id, uri, event, accept, callback);
            }
            Ok(Command::Unsubscribe { id }) => {
                if let Some(sub) = subs.remove(&id) {
                    if sub.state == LifecycleState::Active {
                        let _ = do_unsubscribe(&tr, &sub.uri, &sub.event, &sub.accept);
                    }
                    info!(id = id, uri = %sub.uri, "subscription removed");
                }
            }
            Ok(Command::Notify {
                event,
                content_type,
                body,
                subscription_state,
                from_uri,
            }) => {
                handle_incoming_notify(
                    &tr,
                    &error_cb,
                    &mut subs,
                    &event,
                    &content_type,
                    &body,
                    &subscription_state,
                    &from_uri,
                );
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }

        // Periodic maintenance: refresh + initial NOTIFY timeout.
        let now = Instant::now();
        let mut to_refresh = Vec::new();
        let mut timed_out = Vec::new();

        for sub in subs.values() {
            if sub.state != LifecycleState::Active {
                continue;
            }
            // Refresh at 50% of expiry, with 30s minimum cooldown on failure.
            let half_expiry = sub.expires_duration / 2;
            let midpoint = sub.expires_at - half_expiry;
            if now >= midpoint && now < sub.expires_at {
                let cooldown_ok = sub
                    .last_refresh_at
                    .map(|t| now.duration_since(t) >= Duration::from_secs(30))
                    .unwrap_or(true);
                if cooldown_ok {
                    to_refresh.push(sub.id);
                }
            }

            // Initial NOTIFY timeout.
            if !sub.initial_notify_received {
                if let Some(ok_at) = sub.subscribe_ok_at {
                    if now.duration_since(ok_at) >= INITIAL_NOTIFY_TIMEOUT {
                        timed_out.push(sub.id);
                    }
                }
            }
        }

        for id in to_refresh {
            if let Some(sub) = subs.get_mut(&id) {
                debug!(id = id, uri = %sub.uri, "refreshing subscription");
                sub.last_refresh_at = Some(Instant::now());
                match do_subscribe(&tr, &sub.uri, &sub.event, &sub.accept, DEFAULT_EXPIRES) {
                    Ok(granted) => {
                        let dur = Duration::from_secs(granted as u64);
                        sub.expires_duration = dur;
                        sub.expires_at = Instant::now() + dur;
                    }
                    Err(e) => {
                        warn!(id = id, error = %e, "subscription refresh failed");
                    }
                }
            }
        }

        for id in timed_out {
            if let Some(sub) = subs.get_mut(&id) {
                warn!(id = id, uri = %sub.uri, "initial NOTIFY timeout — marking Unknown");
                sub.initial_notify_received = true; // Stop re-checking.
                                                    // Fire callback with empty body so consumer knows the subscription exists.
                let notify = NotifyEvent {
                    event: sub.event.clone(),
                    content_type: String::new(),
                    body: String::new(),
                    subscription_state: SubState::Active {
                        expires: sub.expires_duration.as_secs() as u32,
                    },
                };
                (sub.callback)(notify);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_subscribe(
    tr: &Arc<dyn SipTransport>,
    error_cb: &ErrorCallback,
    subs: &mut HashMap<SubId, Subscription>,
    id: SubId,
    uri: String,
    event: String,
    accept: String,
    callback: Arc<dyn Fn(NotifyEvent) + Send + Sync>,
) {
    info!(id = id, uri = %uri, event = %event, "sending SUBSCRIBE");
    match do_subscribe(tr, &uri, &event, &accept, DEFAULT_EXPIRES) {
        Ok(granted) => {
            let dur = Duration::from_secs(granted as u64);
            subs.insert(
                id,
                Subscription {
                    id,
                    uri,
                    event,
                    accept,
                    callback,
                    expires_at: Instant::now() + dur,
                    expires_duration: dur,
                    initial_notify_received: false,
                    subscribe_ok_at: Some(Instant::now()),
                    last_refresh_at: None,
                    state: LifecycleState::Active,
                },
            );
            info!(id = id, expires = granted, "subscription active");
        }
        Err(e) => {
            warn!(id = id, error = %e, "SUBSCRIBE failed");
            let cbs = error_cb.lock().clone();
            for f in &cbs {
                f(uri.clone(), e.clone());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_incoming_notify(
    tr: &Arc<dyn SipTransport>,
    error_cb: &ErrorCallback,
    subs: &mut HashMap<SubId, Subscription>,
    event: &str,
    content_type: &str,
    body: &str,
    subscription_state_header: &str,
    from_uri: &str,
) {
    let sub_state = parse_subscription_state(subscription_state_header);

    // Match to subscription by event header + URI (for multiple subs with same event).
    let event_base = event.split(';').next().unwrap_or("").trim();
    let sub = subs.values_mut().find(|s| {
        s.event.eq_ignore_ascii_case(event_base)
            && s.state != LifecycleState::Terminated
            && (from_uri.is_empty() || from_uri.contains(&s.uri))
    });

    let Some(sub) = sub else {
        debug!(event = %event, "NOTIFY for unknown subscription — ignoring");
        return;
    };

    sub.initial_notify_received = true;

    // Update subscription state based on Subscription-State header.
    match &sub_state {
        SubState::Active { expires } => {
            let dur = Duration::from_secs(*expires as u64);
            sub.expires_duration = dur;
            sub.expires_at = Instant::now() + dur;
            sub.state = LifecycleState::Active;
        }
        SubState::Pending => {
            sub.state = LifecycleState::Pending;
        }
        SubState::Terminated { reason } => {
            info!(id = sub.id, reason = %reason, "subscription terminated by server");
            sub.state = LifecycleState::Terminated;

            // Auto-re-subscribe on deactivated/timeout.
            if reason == "deactivated" || reason == "timeout" {
                let uri = sub.uri.clone();
                let event_str = sub.event.clone();
                let accept = sub.accept.clone();
                let id = sub.id;
                info!(id = id, reason = %reason, "auto-re-subscribing");
                match do_subscribe(tr, &uri, &event_str, &accept, DEFAULT_EXPIRES) {
                    Ok(granted) => {
                        let dur = Duration::from_secs(granted as u64);
                        sub.expires_at = Instant::now() + dur;
                        sub.expires_duration = dur;
                        sub.state = LifecycleState::Active;
                        sub.subscribe_ok_at = Some(Instant::now());
                        sub.initial_notify_received = false;
                    }
                    Err(e) => {
                        warn!(id = id, error = %e, "auto-re-subscribe failed");
                        let cbs = error_cb.lock().clone();
                        for f in &cbs {
                            f(uri.clone(), e.clone());
                        }
                    }
                }
                return; // Don't fire callback for the terminating NOTIFY.
            }

            // Permanent failure — fire error callback (don't fire subscription callback).
            if reason == "rejected" || reason == "noresource" {
                let cbs = error_cb.lock().clone();
                for f in &cbs {
                    f(
                        sub.uri.clone(),
                        Error::Other(format!("subscription rejected: {}", reason)),
                    );
                }
                return;
            }
        }
    }

    // Fire the subscription callback.
    let notify = NotifyEvent {
        event: event.to_string(),
        content_type: content_type.to_string(),
        body: body.to_string(),
        subscription_state: sub_state,
    };
    (sub.callback)(notify);
}

/// Sends a SUBSCRIBE and returns the server-granted Expires value.
fn do_subscribe(
    tr: &Arc<dyn SipTransport>,
    uri: &str,
    event: &str,
    accept: &str,
    expires: u32,
) -> Result<u32> {
    let mut headers = HashMap::new();
    headers.insert("Event".to_string(), event.to_string());
    headers.insert("Accept".to_string(), accept.to_string());
    headers.insert("Expires".to_string(), expires.to_string());

    let resp = tr.send_subscribe(uri, &headers, Duration::from_secs(10))?;
    if resp.status_code >= 200 && resp.status_code < 300 {
        // Parse Expires from response; fall back to our requested value.
        let granted = resp.header("Expires").parse::<u32>().unwrap_or(expires);
        Ok(granted)
    } else if resp.status_code == 489 {
        Err(Error::Other(format!(
            "Bad Event: server does not support '{}' event package",
            event
        )))
    } else {
        Err(Error::Other(format!(
            "SUBSCRIBE rejected: {} {}",
            resp.status_code, resp.reason
        )))
    }
}

/// Sends a SUBSCRIBE with Expires=0 to unsubscribe.
fn do_unsubscribe(tr: &Arc<dyn SipTransport>, uri: &str, event: &str, accept: &str) -> Result<()> {
    info!(uri = %uri, event = %event, "unsubscribing (Expires=0)");
    let mut headers = HashMap::new();
    headers.insert("Event".to_string(), event.to_string());
    headers.insert("Accept".to_string(), accept.to_string());
    headers.insert("Expires".to_string(), "0".to_string());

    let _ = tr.send_subscribe(uri, &headers, Duration::from_secs(5))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::transport::MockTransport;

    fn test_tr() -> Arc<MockTransport> {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // for SUBSCRIBE
        tr
    }

    #[test]
    fn subscribe_sends_subscribe() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );
        std::thread::sleep(Duration::from_millis(200));

        assert!(
            tr.count_sent("SUBSCRIBE") >= 1,
            "expected SUBSCRIBE, got {}",
            tr.count_sent("SUBSCRIBE")
        );
        mgr.stop();
    }

    #[test]
    fn unsubscribe_sends_expires_zero() {
        let tr = test_tr();
        tr.respond_with(200, "OK"); // for unsubscribe
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );
        std::thread::sleep(Duration::from_millis(200));

        mgr.unsubscribe(id);
        std::thread::sleep(Duration::from_millis(200));

        // Should have sent at least 2 SUBSCRIBEs (initial + unsubscribe).
        assert!(
            tr.count_sent("SUBSCRIBE") >= 2,
            "expected >= 2 SUBSCRIBEs (initial + unsubscribe), got {}",
            tr.count_sent("SUBSCRIBE")
        );
        mgr.stop();
    }

    #[test]
    fn notify_fires_callback() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (tx, rx) = crossbeam_channel::bounded(1);
        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(move |notify| {
                let _ = tx.send(notify);
            }),
        );
        std::thread::sleep(Duration::from_millis(200));

        mgr.handle_notify(
            "dialog".into(),
            "application/dialog-info+xml".into(),
            "<dialog-info/>".into(),
            "active;expires=600".into(),
            "sip:1001@pbx.local".into(),
        );

        let notify = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(notify.event, "dialog");
        assert_eq!(notify.body, "<dialog-info/>");
        assert_eq!(notify.subscription_state, SubState::Active { expires: 600 });
        mgr.stop();
    }

    #[test]
    fn terminated_deactivated_resubscribes() {
        let tr = test_tr();
        tr.respond_with(200, "OK"); // for re-subscribe
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );
        std::thread::sleep(Duration::from_millis(200));

        let initial_count = tr.count_sent("SUBSCRIBE");

        mgr.handle_notify(
            "dialog".into(),
            "application/dialog-info+xml".into(),
            "".into(),
            "terminated;reason=deactivated".into(),
            "sip:1001@pbx.local".into(),
        );
        std::thread::sleep(Duration::from_millis(300));

        // Should have sent another SUBSCRIBE for re-subscribe.
        assert!(
            tr.count_sent("SUBSCRIBE") > initial_count,
            "expected re-subscribe after deactivated"
        );
        mgr.stop();
    }

    #[test]
    fn terminated_rejected_fires_error() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (err_tx, err_rx) = crossbeam_channel::bounded(1);
        mgr.on_error(move |uri, _err| {
            let _ = err_tx.send(uri);
        });

        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );
        std::thread::sleep(Duration::from_millis(200));

        mgr.handle_notify(
            "dialog".into(),
            "".into(),
            "".into(),
            "terminated;reason=rejected".into(),
            "sip:1001@pbx.local".into(),
        );

        let uri = err_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(uri.contains("1001"));
        mgr.stop();
    }

    #[test]
    fn pending_state_keeps_subscription() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (tx, rx) = crossbeam_channel::bounded(1);
        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(move |notify| {
                let _ = tx.send(notify.subscription_state);
            }),
        );
        std::thread::sleep(Duration::from_millis(200));

        mgr.handle_notify(
            "dialog".into(),
            "".into(),
            "".into(),
            "pending".into(),
            "sip:1001@pbx.local".into(),
        );

        let state = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(state, SubState::Pending);
        mgr.stop();
    }

    #[test]
    fn stop_is_idempotent() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);
        mgr.stop();
        mgr.stop(); // should not panic
    }

    #[test]
    fn multiple_subscriptions() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");
        tr.respond_with(200, "OK");
        tr.respond_with(200, "OK");

        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (tx1, rx1) = crossbeam_channel::bounded(1);
        let (tx2, rx2) = crossbeam_channel::bounded(1);

        mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(move |n| {
                let _ = tx1.send(n.body);
            }),
        );
        mgr.subscribe(
            "sip:1002@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(move |n| {
                let _ = tx2.send(n.body);
            }),
        );
        std::thread::sleep(Duration::from_millis(300));

        // NOTIFY for 1002 — should route to second subscription.
        mgr.handle_notify(
            "dialog".into(),
            "application/dialog-info+xml".into(),
            "body-for-1002".into(),
            "active;expires=600".into(),
            "sip:1002@pbx.local".into(),
        );

        let result = rx2.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result, "body-for-1002");

        // NOTIFY for 1001 — should route to first subscription.
        mgr.handle_notify(
            "dialog".into(),
            "application/dialog-info+xml".into(),
            "body-for-1001".into(),
            "active;expires=600".into(),
            "sip:1001@pbx.local".into(),
        );

        let result = rx1.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result, "body-for-1001");

        mgr.stop();
    }

    #[test]
    fn notify_for_unknown_event_ignored() {
        let tr = test_tr();
        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );
        std::thread::sleep(Duration::from_millis(200));

        // NOTIFY for "presence" should not crash.
        mgr.handle_notify(
            "presence".into(),
            "application/pidf+xml".into(),
            "<presence/>".into(),
            "active;expires=300".into(),
            "sip:someone@pbx.local".into(),
        );
        std::thread::sleep(Duration::from_millis(100));

        mgr.stop();
    }

    #[test]
    fn subscribe_failure_fires_error() {
        // No response queued → send_subscribe will fail.
        let tr = Arc::new(MockTransport::new());
        tr.fail_next(1); // fail the SUBSCRIBE

        let mgr = SubscriptionManager::new(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (err_tx, err_rx) = crossbeam_channel::bounded(1);
        mgr.on_error(move |uri, _err| {
            let _ = err_tx.send(uri);
        });

        let _id = mgr.subscribe(
            "sip:1001@pbx.local",
            "dialog",
            "application/dialog-info+xml",
            Arc::new(|_| {}),
        );

        let uri = err_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(uri.contains("1001"));
        mgr.stop();
    }
}
