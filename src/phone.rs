use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::call::{self, Call};
use crate::config::{Config, DialOptions};
use crate::dialog::Dialog;
use crate::dialog_info::parse_dialog_info;
use crate::error::{Error, Result};
use crate::mock::dialog::MockDialog;
use crate::mwi::MwiSubscriber;
use crate::registry::Registry;
use crate::subscription::{SubId, SubscriptionManager};
use crate::transport::SipTransport;
use crate::types::{
    CallState, Direction, EndReason, ExtensionState, ExtensionStatus, NotifyEvent, PhoneState,
    SipMessage, VoicemailStatus,
};

type CallStateCb = Arc<dyn Fn(Arc<Call>, crate::types::CallState) + Send + Sync>;
type CallEndedCb = Arc<dyn Fn(Arc<Call>, crate::types::EndReason) + Send + Sync>;
type CallDtmfCb = Arc<dyn Fn(Arc<Call>, String) + Send + Sync>;

struct Inner {
    state: PhoneState,
    tr: Option<Arc<dyn SipTransport>>,
    reg: Option<Arc<Registry>>,
    mwi: Option<Arc<MwiSubscriber>>,
    incoming: Option<Arc<dyn Fn(Arc<Call>) + Send + Sync>>,
    calls: HashMap<String, Arc<Call>>,

    on_registered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_unregistered_fn: Option<Arc<dyn Fn() + Send + Sync>>,
    on_error_fn: Option<Arc<dyn Fn(Error) + Send + Sync>>,
    on_voicemail_fn: Option<Arc<dyn Fn(VoicemailStatus) + Send + Sync>>,
    on_message_fn: Option<Arc<dyn Fn(SipMessage) + Send + Sync>>,
    on_subscription_error_fn: Option<Arc<dyn Fn(String, Error) + Send + Sync>>,

    // Phone-level call callbacks — auto-wired to every new call.
    on_call_state_fn: Option<CallStateCb>,
    on_call_ended_fn: Option<CallEndedCb>,
    on_call_dtmf_fn: Option<CallDtmfCb>,

    /// DTMF mode from config, applied to every new call.
    dtmf_mode: crate::config::DtmfMode,

    /// Subscription manager for BLF and generic event subscriptions.
    subscription_mgr: Option<Arc<SubscriptionManager>>,
    /// BLF watchers: extension -> (SubId, last known state).
    blf_watchers: HashMap<String, (SubId, ExtensionState)>,
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
        let dtmf_mode = cfg.dtmf_mode;
        Self {
            cfg,
            inner: Arc::new(Mutex::new(Inner {
                state: PhoneState::Disconnected,
                tr: None,
                reg: None,
                mwi: None,
                incoming: None,
                calls: HashMap::new(),
                on_registered_fn: None,
                on_unregistered_fn: None,
                on_error_fn: None,
                on_voicemail_fn: None,
                on_message_fn: None,
                on_subscription_error_fn: None,
                on_call_state_fn: None,
                on_call_ended_fn: None,
                on_call_dtmf_fn: None,
                dtmf_mode,
                subscription_mgr: None,
                blf_watchers: HashMap::new(),
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

        // Wire up SIP INFO DTMF handling.
        let inner_clone = Arc::clone(&self.inner);
        tr.on_info_dtmf(Box::new(move |call_id, digit| {
            handle_info_dtmf(&inner_clone, &call_id, &digit);
        }));

        // Wire up SIP MESSAGE handling.
        let inner_clone = Arc::clone(&self.inner);
        tr.on_message(Box::new(move |from, content_type, body| {
            handle_message(&inner_clone, &from, &content_type, &body);
        }));

        // Create subscription manager and wire NOTIFY handler.
        let sub_mgr = Arc::new(SubscriptionManager::new(Arc::clone(&tr)));
        let sub_mgr_clone = Arc::clone(&sub_mgr);
        tr.on_subscription_notify(Box::new(move |event, ct, body, sub_state, from_uri| {
            sub_mgr_clone.handle_notify(event, ct, body, sub_state, from_uri);
        }));
        // Apply buffered on_subscription_error callback.
        if let Some(ref f) = self.inner.lock().on_subscription_error_fn {
            let f = Arc::clone(f);
            sub_mgr.on_error(move |uri, err| f(uri, err));
        }

        // Start MWI subscriber if voicemail URI is configured and registration succeeded.
        let mwi = if reg_result.is_ok() {
            if let Some(ref vm_uri) = self.cfg.voicemail_uri {
                let sub = Arc::new(MwiSubscriber::new(Arc::clone(&tr), vm_uri.clone()));
                // Apply buffered on_voicemail callback.
                if let Some(ref f) = self.inner.lock().on_voicemail_fn {
                    let f = Arc::clone(f);
                    sub.on_voicemail(move |s| f(s));
                }
                sub.start();
                Some(sub)
            } else {
                None
            }
        } else {
            None
        };

        let mut inner = self.inner.lock();
        inner.tr = Some(tr);
        inner.reg = Some(reg);
        inner.mwi = mwi;
        inner.subscription_mgr = Some(sub_mgr);
        if reg_result.is_ok() {
            inner.state = PhoneState::Registered;
        } else {
            inner.state = PhoneState::RegistrationFailed;
        }
    }

    /// Disconnects the phone: ends all active calls, stops registry, and closes transport.
    pub fn disconnect(&self) -> Result<()> {
        info!("Phone disconnecting");
        let (reg, tr, unreg_fn, active_calls, mwi, sub_mgr) = {
            let mut inner = self.inner.lock();
            if inner.state == PhoneState::Disconnected {
                return Err(Error::NotConnected);
            }
            let reg = inner.reg.take();
            let tr = inner.tr.take();
            let unreg_fn = inner.on_unregistered_fn.clone();
            let active_calls: Vec<Arc<Call>> = inner.calls.drain().map(|(_, c)| c).collect();
            let mwi = inner.mwi.take();
            let sub_mgr = inner.subscription_mgr.take();
            inner.blf_watchers.clear();
            inner.state = PhoneState::Disconnected;
            (reg, tr, unreg_fn, active_calls, mwi, sub_mgr)
        };

        // End all active calls so their resources (media, sockets, SRTP) are released.
        for call in active_calls {
            let _ = call.end();
        }

        if let Some(sub_mgr) = sub_mgr {
            sub_mgr.stop();
        }
        if let Some(mwi) = mwi {
            mwi.stop();
        }
        if let Some(reg) = reg {
            reg.stop();
        }
        if let Some(tr) = tr {
            let _ = tr.close();
        }
        if let Some(f) = unreg_fn {
            crate::callback_pool::spawn_callback(move || f());
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
        // Allocate video RTP socket if video is requested.
        let (video_rtp_socket, video_rtp_port) = if opts.video {
            if self.cfg.rtp_port_min > 0 && self.cfg.rtp_port_max > 0 {
                match crate::media::listen_rtp_port(self.cfg.rtp_port_min, self.cfg.rtp_port_max) {
                    Ok((sock, port)) => (Some(sock), port as i32),
                    Err(_) => (None, 0),
                }
            } else {
                (None, 0)
            }
        } else {
            (None, 0)
        };

        // Generate SRTP keying material if enabled.
        let srtp_inline_key = if self.cfg.srtp {
            let (_material, encoded) = crate::srtp::generate_keying_material()?;
            Some(encoded)
        } else {
            None
        };
        let video_srtp_inline_key = if self.cfg.srtp && opts.video {
            let (_material, encoded) = crate::srtp::generate_keying_material()?;
            Some(encoded)
        } else {
            None
        };

        let video_codecs = if opts.video_codecs.is_empty() {
            vec![
                crate::types::VideoCodec::H264,
                crate::types::VideoCodec::VP8,
            ]
        } else {
            opts.video_codecs.clone()
        };

        let local_sdp = if opts.video {
            match (&srtp_inline_key, &video_srtp_inline_key) {
                (Some(audio_key), Some(video_key)) => crate::sdp::build_offer_video_srtp(
                    &local_ip,
                    rtp_port,
                    &[8, 0, 9, 101],
                    video_rtp_port,
                    &video_codecs,
                    crate::sdp::DIR_SEND_RECV,
                    audio_key,
                    video_key,
                ),
                _ => crate::sdp::build_offer_video(
                    &local_ip,
                    rtp_port,
                    &[8, 0, 9, 101],
                    video_rtp_port,
                    &video_codecs,
                    crate::sdp::DIR_SEND_RECV,
                ),
            }
        } else if let Some(ref key) = srtp_inline_key {
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
            Ok(result) => {
                // Production path: got a real dialog from SipUA.
                // tr.dial() already consumed the 200 OK, so transition to Active.
                let call = Call::new_outbound(result.dialog, opts);
                call.set_local_media(&local_ip, rtp_port);
                call.set_local_sdp(&local_sdp);
                if let Some(ref key) = srtp_inline_key {
                    call.set_srtp(key);
                }
                if let Some(sock) = rtp_socket {
                    call.set_rtp_socket(sock);
                }
                // Wire video socket if allocated.
                if let Some(vsock) = video_rtp_socket {
                    call.set_video_rtp_port(video_rtp_port);
                    call.set_video_rtp_socket(vsock);
                }

                // Wire phone-level callbacks (incl. dtmf_mode) BEFORE simulate_response fires on_state.
                wire_phone_call_callbacks(&self.inner, &call);

                // Handle early media: if we got a 183 with SDP, set up media before
                // the final 200 OK so the caller hears ringback/IVR prompts.
                if let Some(ref early_sdp) = result.early_sdp {
                    call.set_remote_sdp(early_sdp);
                    call.simulate_response(183, "Session Progress");
                }

                if !result.remote_sdp.is_empty() {
                    call.set_remote_sdp(&result.remote_sdp);
                }
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
                // Wire phone-level callbacks (incl. dtmf_mode) BEFORE replay.
                wire_phone_call_callbacks(&self.inner, &call);
                (call, responses)
            }
            Err(e) => return Err(e),
        };

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
    /// The callback fires for every incoming INVITE, even during an active call (call waiting).
    /// The application decides whether to accept, reject (486 Busy), or ignore the new call.
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

    /// Sets the callback for voicemail (MWI) status updates.
    /// Fires whenever a NOTIFY with `application/simple-message-summary` is received.
    pub fn on_voicemail<F: Fn(VoicemailStatus) + Send + Sync + 'static>(&self, f: F) {
        let cb: Arc<dyn Fn(VoicemailStatus) + Send + Sync> = Arc::new(f);
        let mwi = {
            let mut inner = self.inner.lock();
            inner.on_voicemail_fn = Some(Arc::clone(&cb));
            inner.mwi.clone()
        };
        if let Some(mwi) = mwi {
            let cb = Arc::clone(&cb);
            mwi.on_voicemail(move |s| cb(s));
        }
    }

    /// Sets the callback for incoming SIP MESSAGE (instant messages, RFC 3428).
    pub fn on_message<F: Fn(SipMessage) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().on_message_fn = Some(Arc::new(f));
    }

    /// Sends a SIP MESSAGE with `text/plain` content type.
    pub fn send_message(&self, target: &str, body: &str) -> Result<()> {
        let tr = {
            let inner = self.inner.lock();
            if inner.state != PhoneState::Registered {
                return Err(Error::NotRegistered);
            }
            inner.tr.as_ref().cloned().ok_or(Error::NotConnected)?
        };
        tr.send_message(
            target,
            "text/plain",
            body.as_bytes(),
            std::time::Duration::from_secs(10),
        )
    }

    /// Sends a SIP MESSAGE with a custom content type.
    pub fn send_message_with_type(
        &self,
        target: &str,
        content_type: &str,
        body: &str,
    ) -> Result<()> {
        let tr = {
            let inner = self.inner.lock();
            if inner.state != PhoneState::Registered {
                return Err(Error::NotRegistered);
            }
            inner.tr.as_ref().cloned().ok_or(Error::NotConnected)?
        };
        tr.send_message(
            target,
            content_type,
            body.as_bytes(),
            std::time::Duration::from_secs(10),
        )
    }

    /// Returns the subscription manager, or `NotConnected` if not connected.
    fn get_sub_mgr(&self) -> Result<Arc<SubscriptionManager>> {
        let inner = self.inner.lock();
        inner
            .subscription_mgr
            .as_ref()
            .ok_or(Error::NotConnected)
            .cloned()
    }

    /// Watch an extension's state via BLF (dialog event package, RFC 4235).
    ///
    /// The callback fires with the new `ExtensionStatus` and the previous state
    /// (`None` on the first update). Duplicate states are suppressed.
    pub fn watch<F>(&self, extension: &str, f: F) -> Result<()>
    where
        F: Fn(ExtensionStatus, Option<ExtensionState>) + Send + Sync + 'static,
    {
        if self.inner.lock().state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        let sub_mgr = self.get_sub_mgr()?;

        let uri = format!("sip:{}@{}", extension, self.cfg.host);
        let ext = extension.to_string();
        let phone_inner = Arc::clone(&self.inner);
        let f = Arc::new(f);

        let sub_id = sub_mgr.subscribe(
            &uri,
            "dialog",
            "application/dialog-info+xml",
            Arc::new(move |notify: NotifyEvent| {
                let new_state = if notify.body.is_empty() {
                    ExtensionState::Unknown
                } else {
                    parse_dialog_info(&notify.body)
                };

                // Duplicate suppression + track previous state.
                // Only update the ExtensionState; preserve the SubId.
                let (prev, should_fire) = {
                    let mut inner = phone_inner.lock();
                    if let Some((_sub_id, last)) = inner.blf_watchers.get_mut(&ext) {
                        if *last == new_state {
                            return; // No change — suppress.
                        }
                        let prev = Some(*last);
                        *last = new_state; // Only update state; SubId is preserved.
                        (prev, true)
                    } else {
                        // First NOTIFY before post-subscribe storage — use 0 as placeholder.
                        inner.blf_watchers.insert(ext.clone(), (0, new_state));
                        (None, true)
                    }
                };

                if should_fire {
                    let status = ExtensionStatus {
                        extension: ext.clone(),
                        state: new_state,
                    };
                    f(status, prev);
                }
            }),
        );

        // Store the SubId for unwatch.
        self.inner
            .lock()
            .blf_watchers
            .entry(extension.to_string())
            .and_modify(|(id, _)| *id = sub_id)
            .or_insert((sub_id, ExtensionState::Unknown));

        Ok(())
    }

    /// Stop watching an extension.
    pub fn unwatch(&self, extension: &str) -> Result<()> {
        let sub_mgr = self.get_sub_mgr()?;
        let sub_id = {
            let inner = self.inner.lock();
            let (sub_id, _) = inner
                .blf_watchers
                .get(extension)
                .ok_or_else(|| Error::Other(format!("not watching {}", extension)))?;
            *sub_id
        };

        sub_mgr.unsubscribe(sub_id);
        self.inner.lock().blf_watchers.remove(extension);
        Ok(())
    }

    /// Subscribe to a generic event package (power user API).
    /// Returns a subscription ID for later unsubscribe.
    pub fn subscribe_event<F>(&self, uri: &str, event: &str, accept: &str, f: F) -> Result<SubId>
    where
        F: Fn(NotifyEvent) + Send + Sync + 'static,
    {
        if self.inner.lock().state != PhoneState::Registered {
            return Err(Error::NotRegistered);
        }
        let sub_mgr = self.get_sub_mgr()?;
        Ok(sub_mgr.subscribe(uri, event, accept, Arc::new(f)))
    }

    /// Unsubscribe from a previously subscribed event.
    pub fn unsubscribe_event(&self, sub_id: SubId) -> Result<()> {
        let sub_mgr = self.get_sub_mgr()?;
        sub_mgr.unsubscribe(sub_id);
        Ok(())
    }

    /// Register a callback for subscription errors (permanent failures).
    pub fn on_subscription_error<F>(&self, f: F)
    where
        F: Fn(String, Error) + Send + Sync + 'static,
    {
        let mut inner = self.inner.lock();
        let f: Arc<dyn Fn(String, Error) + Send + Sync> = Arc::new(f);
        inner.on_subscription_error_fn = Some(Arc::clone(&f));
        // If subscription manager already exists, wire it.
        if let Some(ref mgr) = inner.subscription_mgr {
            let f = Arc::clone(&f);
            mgr.on_error(move |uri, err| f(uri, err));
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

    /// Returns all active calls.
    /// Useful for call waiting UIs that need to display concurrent calls.
    pub fn calls(&self) -> Vec<Arc<Call>> {
        self.inner.lock().calls.values().cloned().collect()
    }

    /// Initiates an attended (consultative) transfer.
    ///
    /// Transfers `call_a` by sending REFER with a Replaces header that references
    /// `call_b`'s dialog. After the transfer succeeds (NOTIFY 200), both calls end
    /// with `EndReason::Transfer`.
    ///
    /// Both calls must be in `Active` or `OnHold` state.
    pub fn attended_transfer(&self, call_a: &Arc<Call>, call_b: &Arc<Call>) -> Result<()> {
        {
            let state_a = call_a.state();
            if state_a != CallState::Active && state_a != CallState::OnHold {
                return Err(Error::InvalidState);
            }
            let state_b = call_b.state();
            if state_b != CallState::Active && state_b != CallState::OnHold {
                return Err(Error::InvalidState);
            }
        }

        // Extract Call B's dialog identifiers for the Replaces header.
        let (b_call_id, b_local_tag, b_remote_tag) = call_b.dialog_id();
        if b_call_id.is_empty() || b_local_tag.is_empty() || b_remote_tag.is_empty() {
            return Err(Error::Other(
                "attended transfer: call B dialog missing call-id or tags".into(),
            ));
        }

        // Build the remote party's SIP URI from Call B.
        let remote_uri = match call_b.direction() {
            Direction::Outbound => {
                // Outbound: remote party is in the To header.
                call_b
                    .header("To")
                    .first()
                    .map(|v| call::sip_header_uri(v).to_string())
                    .unwrap_or_default()
            }
            Direction::Inbound => {
                // Inbound: remote party is in the From header.
                call_b
                    .header("From")
                    .first()
                    .map(|v| call::sip_header_uri(v).to_string())
                    .unwrap_or_default()
            }
        };
        if remote_uri.is_empty() {
            return Err(Error::Other(
                "attended transfer: cannot determine call B remote URI".into(),
            ));
        }

        // Build Refer-To URI with Replaces parameter (URL-encoded per RFC 3891).
        // Format: <remote_uri>?Replaces=<call-id>%3Bto-tag%3D<remote-tag>%3Bfrom-tag%3D<local-tag>
        let refer_to = format!(
            "{}?Replaces={}%3Bto-tag%3D{}%3Bfrom-tag%3D{}",
            remote_uri,
            uri_encode(&b_call_id),
            uri_encode(&b_remote_tag),
            uri_encode(&b_local_tag),
        );

        // Wire up NOTIFY handler: on 200, end both calls with Transfer reason.
        let weak_a = Arc::downgrade(call_a);
        let weak_b = Arc::downgrade(call_b);
        call_a.dlg.on_notify(Box::new(move |code| {
            if code == 200 {
                if let Some(a) = weak_a.upgrade() {
                    a.end_with_reason(EndReason::Transfer);
                }
                if let Some(b) = weak_b.upgrade() {
                    b.end_with_reason(EndReason::Transfer);
                }
            }
        }));

        // Send REFER on Call A's dialog.
        call_a.dlg.send_refer(&refer_to)?;
        Ok(())
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        // Only disconnect if this is the last clone — dropping a clone must not
        // tear down the shared registration/transport.
        if Arc::strong_count(&self.inner) == 1 {
            let _ = self.disconnect();
        }
    }
}

/// URI-encoding for SIP Replaces header values (RFC 3891).
/// Encodes URI-reserved characters that appear in Call-IDs and tag values.
fn uri_encode(val: &str) -> String {
    let mut out = String::with_capacity(val.len() * 2);
    for b in val.bytes() {
        match b {
            b'%' => out.push_str("%25"),
            b'@' => out.push_str("%40"),
            b' ' => out.push_str("%20"),
            b';' => out.push_str("%3B"),
            b'?' => out.push_str("%3F"),
            b'&' => out.push_str("%26"),
            b'=' => out.push_str("%3D"),
            b'+' => out.push_str("%2B"),
            b':' => out.push_str("%3A"),
            _ => out.push(b as char),
        }
    }
    out
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

    // Wire phone-level callbacks + call-tracking cleanup.
    wire_phone_call_callbacks(inner, &call);

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

/// Wire phone-level call callbacks onto an individual call.
fn wire_phone_call_callbacks(inner: &Arc<Mutex<Inner>>, call: &Arc<Call>) {
    // Copy callbacks and config out of Phone lock, then drop it before acquiring Call lock.
    let (state_fn, ended_fn, dtmf_fn, dtmf_mode) = {
        let locked = inner.lock();
        (
            locked.on_call_state_fn.clone(),
            locked.on_call_ended_fn.clone(),
            locked.on_call_dtmf_fn.clone(),
            locked.dtmf_mode,
        )
    };

    call.set_dtmf_mode(dtmf_mode);

    if let Some(f) = state_fn {
        let c = Arc::clone(call);
        call.on_state_internal(move |s| f(Arc::clone(&c), s));
    }

    // Combine phone-level on_ended callback with call-tracking cleanup
    // into a single on_ended_internal closure so neither overwrites the other.
    {
        let inner_clone = Arc::clone(inner);
        let call_id = call.call_id();
        let c = Arc::clone(call);
        call.on_ended_internal(move |r| {
            // Call-tracking cleanup.
            inner_clone.lock().calls.remove(&call_id);
            // Phone-level on_call_ended callback.
            if let Some(ref f) = ended_fn {
                f(Arc::clone(&c), r);
            }
        });
    }

    if let Some(f) = dtmf_fn {
        let c = Arc::clone(call);
        call.on_dtmf_internal(move |d| f(Arc::clone(&c), d));
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
    // Check if this is a re-INVITE for an existing call (same Call-ID).
    let call_id = dlg.call_id();
    let existing_call = inner.lock().calls.get(&call_id).cloned();
    if let Some(call) = existing_call {
        info!(call_id = %call_id, "Phone handling re-INVITE for existing call");
        handle_reinvite(&call, dlg, remote_sdp, rtp_port_min, rtp_port_max);
        return;
    }

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

    // Parse remote SDP once for SRTP detection and video detection.
    let parsed_sdp = crate::sdp::parse(remote_sdp).ok();

    // Only use SRTP if the remote actually offers RTP/SAVP with a supported suite.
    let use_srtp = parsed_sdp.as_ref().is_some_and(|sess| {
        sess.is_srtp()
            && sess
                .first_crypto()
                .is_some_and(|c| c.suite == crate::srtp::SUPPORTED_SUITE)
    });

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

    // Allocate video RTP socket if remote SDP offers video.
    if let Some(ref sess) = parsed_sdp {
        if sess.has_video() && rtp_port_min > 0 && rtp_port_max > 0 {
            if let Ok((vsock, vport)) = crate::media::listen_rtp_port(rtp_port_min, rtp_port_max) {
                call.set_video_rtp_port(vport as i32);
                call.set_video_rtp_socket(vsock);
            }
        }
    }

    if !remote_sdp.is_empty() {
        call.set_remote_sdp(remote_sdp);
    }

    // Wire phone-level callbacks + call-tracking cleanup before anything fires.
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

/// Handles a mid-dialog re-INVITE for an existing call (e.g., video upgrade, hold/resume).
fn handle_reinvite(
    call: &Arc<Call>,
    dlg: Arc<dyn Dialog>,
    remote_sdp: &str,
    rtp_port_min: u16,
    rtp_port_max: u16,
) {
    call.handle_reinvite(&dlg, remote_sdp, rtp_port_min, rtp_port_max);
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

/// Handles an incoming SIP INFO DTMF — looks up the call by Call-ID and fires its DTMF callback.
fn handle_info_dtmf(inner: &Arc<Mutex<Inner>>, call_id: &str, digit: &str) {
    info!(call_id = %call_id, digit = %digit, "Phone handling INFO DTMF");
    let call = inner.lock().calls.get(call_id).cloned();
    if let Some(call) = call {
        call.fire_dtmf(digit);
    } else {
        debug!(call_id = %call_id, "Phone INFO DTMF for unknown call");
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

/// Handles an incoming SIP MESSAGE — fires the on_message callback.
fn handle_message(inner: &Arc<Mutex<Inner>>, from: &str, content_type: &str, body: &str) {
    info!(from = %from, "Phone handling MESSAGE");
    let cb = inner.lock().on_message_fn.clone();
    if let Some(f) = cb {
        let msg = SipMessage {
            from: from.to_string(),
            to: String::new(),
            content_type: content_type.to_string(),
            body: body.to_string(),
        };
        crate::callback_pool::spawn_callback(move || f(msg));
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

    #[test]
    fn dial_with_early_media_transitions_through_early_media_state() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Set up early media SDP from the "remote" side.
        let early_sdp = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nm=audio 20000 RTP/AVP 8\r\n";
        tr.set_early_sdp(early_sdp);
        tr.respond_with(200, "OK"); // INVITE

        // Use a channel to detect EarlyMedia state (callbacks fire in spawned threads).
        let (em_tx, em_rx) = crossbeam_channel::bounded(1);
        phone.on_call_state(move |_call, state| {
            if state == crate::types::CallState::EarlyMedia {
                let _ = em_tx.try_send(());
            }
        });

        let opts = crate::config::DialOptions {
            early_media: true,
            ..Default::default()
        };

        let call = phone.dial("sip:1002@pbx.local", opts).unwrap();
        assert_eq!(call.state(), crate::types::CallState::Active);

        // Verify the call transitioned through EarlyMedia.
        let got_early = em_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        assert!(got_early, "should have transitioned through EarlyMedia");

        // Remote SDP should have been set from the early media SDP.
        assert!(!call.remote_sdp().is_empty());
    }

    #[test]
    fn phone_and_user_callbacks_both_fire() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());

        // Phone-level callback (wired internally).
        let (phone_tx, phone_rx) = crossbeam_channel::bounded(1);
        phone.on_call_state(move |_call, state| {
            if state == crate::types::CallState::Active {
                let _ = phone_tx.try_send(());
            }
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        // User-level callback (should NOT overwrite phone-level).
        let (user_tx, user_rx) = crossbeam_channel::bounded(1);
        call.on_state(move |state| {
            if state == crate::types::CallState::Ended {
                let _ = user_tx.try_send(());
            }
        });

        // Phone-level should have already fired for Active.
        let got_phone = phone_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        assert!(got_phone, "phone-level on_call_state should have fired");

        // End the call — user-level callback should fire.
        call.end().unwrap();
        let got_user = user_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        assert!(got_user, "user-level on_state should have fired");
    }

    #[test]
    fn info_dtmf_fires_call_dtmf_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());

        let (dtmf_tx, dtmf_rx) = crossbeam_channel::bounded(1);
        phone.on_call_dtmf(move |_call, digit| {
            let _ = dtmf_tx.send(digit);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Dial to create a call.
        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let call_id = call.call_id();

        // Simulate incoming SIP INFO DTMF.
        tr.simulate_info_dtmf(&call_id, "5");

        let digit = dtmf_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(digit, "5");
    }

    #[test]
    fn dtmf_mode_propagated_to_calls() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let mut cfg = test_cfg();
        cfg.dtmf_mode = crate::config::DtmfMode::SipInfo;
        let phone = Phone::new(cfg);
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Dial to create a call.
        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        // Verify dtmf_mode was propagated: send_dtmf("3") should use SIP INFO.
        // Detailed MockDialog inspection is in call::tests::send_dtmf_sip_info_mode.
        // Here we just verify it doesn't error (SIP INFO path doesn't need RTP socket).
        call.send_dtmf("3").unwrap();
    }

    // --- Call waiting / multi-call ---

    #[test]
    fn two_concurrent_outbound_calls() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE 1
        let call1 = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        tr.respond_with(200, "OK"); // INVITE 2
        let call2 = phone
            .dial("sip:1003@pbx.local", DialOptions::default())
            .unwrap();

        assert_ne!(call1.call_id(), call2.call_id());
        assert!(phone.find_call(&call1.call_id()).is_some());
        assert!(phone.find_call(&call2.call_id()).is_some());
        assert_eq!(phone.calls().len(), 2);
    }

    #[test]
    fn incoming_during_active_call_fires_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_incoming(move |_call| {
            let _ = tx.send(true);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Create an active outbound call.
        tr.respond_with(200, "OK"); // INVITE
        let call1 = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        assert_eq!(call1.state(), crate::types::CallState::Active);

        // Simulate an incoming INVITE while the first call is active.
        tr.simulate_invite("sip:1001@pbx.local", "sip:1003@pbx.local");

        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired);
        assert_eq!(phone.calls().len(), 2);
    }

    #[test]
    fn bye_for_one_call_leaves_other_active() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK");
        let call1 = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        tr.respond_with(200, "OK");
        let call2 = phone
            .dial("sip:1003@pbx.local", DialOptions::default())
            .unwrap();

        assert_eq!(phone.calls().len(), 2);

        // End call1 — call2 should remain active.
        call1.end().unwrap();
        std::thread::sleep(Duration::from_millis(100));

        assert!(phone.find_call(&call1.call_id()).is_none());
        assert!(phone.find_call(&call2.call_id()).is_some());
        assert_eq!(call2.state(), crate::types::CallState::Active);
        assert_eq!(phone.calls().len(), 1);
    }

    #[test]
    fn disconnect_ends_all_calls() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK");
        let call1 = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        tr.respond_with(200, "OK");
        let call2 = phone
            .dial("sip:1003@pbx.local", DialOptions::default())
            .unwrap();

        phone.disconnect().unwrap();

        assert_eq!(call1.state(), crate::types::CallState::Ended);
        assert_eq!(call2.state(), crate::types::CallState::Ended);
        assert!(phone.calls().is_empty());
    }

    #[test]
    fn calls_returns_all_active() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        assert!(phone.calls().is_empty());

        tr.respond_with(200, "OK");
        phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        assert_eq!(phone.calls().len(), 1);

        tr.respond_with(200, "OK");
        phone
            .dial("sip:1003@pbx.local", DialOptions::default())
            .unwrap();
        assert_eq!(phone.calls().len(), 2);
    }

    #[test]
    fn dialog_invite_during_active_call() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_incoming(move |call| {
            let _ = tx.send(call.call_id());
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Active outbound call.
        tr.respond_with(200, "OK");
        let call1 = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();

        // Incoming via dialog path (production path).
        let sdp = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nm=audio 20000 RTP/AVP 8\r\n";
        tr.simulate_dialog_invite("sip:1001@pbx.local", "sip:1003@pbx.local", sdp);

        let incoming_id = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_ne!(incoming_id, call1.call_id());
        assert_eq!(phone.calls().len(), 2);
    }

    #[test]
    fn call_arc_freed_after_end() {
        // Verifies circular Arc references are broken when a call ends.
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.on_call_state(|_call, _state| {});
        phone.on_call_ended(|_call, _reason| {});
        phone.on_call_dtmf(|_call, _digit| {});
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK");
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        call.end().unwrap();

        // Give callback threads time to complete.
        std::thread::sleep(Duration::from_millis(200));

        // After end, our local `call` + the on_ended spawn should be the only Arc holders.
        // Phone's HashMap should have removed it. The circular callback references
        // should have been cleared by fire_on_ended.
        assert!(phone.find_call(&call.call_id()).is_none());
        // The Arc strong count should be 1 (our local variable only).
        assert_eq!(
            Arc::strong_count(&call),
            1,
            "Call Arc should have no other holders after end + callback cleanup"
        );
    }

    // --- Attended Transfer ---

    fn mock_dlg_with_tags(
        call_id: &str,
        from: &str,
        to: &str,
    ) -> Arc<crate::mock::dialog::MockDialog> {
        let mut h = std::collections::HashMap::new();
        h.insert("From".into(), vec![from.into()]);
        h.insert("To".into(), vec![to.into()]);
        let dlg = crate::mock::dialog::MockDialog::with_headers(h);
        dlg.set_call_id(call_id);
        Arc::new(dlg)
    }

    #[test]
    fn attended_transfer_sends_refer_with_replaces() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Create Call A (outbound to Bob) with dialog tags.
        let dlg_a = mock_dlg_with_tags(
            "call-a-id",
            "<sip:1001@pbx>;tag=alice-a",
            "<sip:bob@pbx>;tag=bob-a",
        );
        let call_a = Call::new_outbound(dlg_a.clone(), DialOptions::default());
        call_a.simulate_response(200, "OK");

        // Create Call B (outbound to Charlie) with dialog tags.
        let dlg_b = mock_dlg_with_tags(
            "call-b-id@pbx.local",
            "<sip:1001@pbx>;tag=alice-b",
            "<sip:charlie@pbx>;tag=charlie-b",
        );
        let call_b = Call::new_outbound(dlg_b.clone(), DialOptions::default());
        call_b.simulate_response(200, "OK");
        call_b.hold().unwrap(); // typically call_b is active during consultation

        // Execute attended transfer.
        phone.attended_transfer(&call_a, &call_b).unwrap();

        // Verify REFER was sent on Call A's dialog.
        assert!(dlg_a.refer_sent());
        let refer_target = dlg_a.last_refer_target();

        // Refer-To should point to Charlie's URI with Replaces encoding.
        assert!(
            refer_target.starts_with("sip:charlie@pbx?Replaces="),
            "REFER target should start with Charlie's URI: {}",
            refer_target
        );
        // Call-ID should be URL-encoded (@ -> %40).
        assert!(
            refer_target.contains("call-b-id%40pbx.local"),
            "Call-ID @ should be encoded: {}",
            refer_target
        );
        // Tags should be present with URL-encoded separators.
        assert!(
            refer_target.contains("to-tag%3Dcharlie-b"),
            "remote tag (charlie) should be in to-tag: {}",
            refer_target
        );
        assert!(
            refer_target.contains("from-tag%3Dalice-b"),
            "local tag (alice) should be in from-tag: {}",
            refer_target
        );
    }

    #[test]
    fn attended_transfer_ends_both_on_notify_200() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");
        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let dlg_a = mock_dlg_with_tags("call-a", "<sip:1001@pbx>;tag=a1", "<sip:bob@pbx>;tag=b1");
        let dlg_b = mock_dlg_with_tags(
            "call-b",
            "<sip:1001@pbx>;tag=a2",
            "<sip:charlie@pbx>;tag=c2",
        );
        let call_a = Call::new_outbound(dlg_a.clone(), DialOptions::default());
        call_a.simulate_response(200, "OK");
        let call_b = Call::new_outbound(dlg_b.clone(), DialOptions::default());
        call_b.simulate_response(200, "OK");

        let (tx_a, rx_a) = crossbeam_channel::bounded(1);
        let (tx_b, rx_b) = crossbeam_channel::bounded(1);
        call_a.on_ended(move |r| {
            let _ = tx_a.send(r);
        });
        call_b.on_ended(move |r| {
            let _ = tx_b.send(r);
        });

        phone.attended_transfer(&call_a, &call_b).unwrap();

        // Simulate successful NOTIFY from Bob.
        dlg_a.simulate_notify(200);

        // Wait for callbacks.
        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(call_a.state(), CallState::Ended);
        assert_eq!(call_b.state(), CallState::Ended);
        assert_eq!(
            rx_a.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Transfer
        );
        assert_eq!(
            rx_b.recv_timeout(Duration::from_millis(200)).unwrap(),
            EndReason::Transfer
        );
    }

    #[test]
    fn attended_transfer_rejects_inactive_call_a() {
        let phone = Phone::new(test_cfg());
        let dlg_a = Arc::new(MockDialog::new());
        let dlg_b = Arc::new(MockDialog::new());
        let call_a = Call::new_inbound(dlg_a); // Ringing, not Active
        let call_b = Call::new_outbound(dlg_b, DialOptions::default());
        call_b.simulate_response(200, "OK");

        let result = phone.attended_transfer(&call_a, &call_b);
        assert!(result.is_err());
    }

    #[test]
    fn attended_transfer_rejects_inactive_call_b() {
        let phone = Phone::new(test_cfg());
        let dlg_a = Arc::new(MockDialog::new());
        let dlg_b = Arc::new(MockDialog::new());
        let call_a = Call::new_inbound(dlg_a);
        call_a.accept().unwrap();
        let call_b = Call::new_inbound(dlg_b); // Ringing, not Active

        let result = phone.attended_transfer(&call_a, &call_b);
        assert!(result.is_err());
    }

    #[test]
    fn attended_transfer_notify_non_200_keeps_calls_alive() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK");
        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let dlg_a = mock_dlg_with_tags("call-a", "<sip:1001@pbx>;tag=a1", "<sip:bob@pbx>;tag=b1");
        let dlg_b = mock_dlg_with_tags(
            "call-b",
            "<sip:1001@pbx>;tag=a2",
            "<sip:charlie@pbx>;tag=c2",
        );
        let call_a = Call::new_outbound(dlg_a.clone(), DialOptions::default());
        call_a.simulate_response(200, "OK");
        let call_b = Call::new_outbound(dlg_b.clone(), DialOptions::default());
        call_b.simulate_response(200, "OK");

        phone.attended_transfer(&call_a, &call_b).unwrap();

        // NOTIFY 100 (Trying) should NOT end the calls.
        dlg_a.simulate_notify(100);
        std::thread::sleep(Duration::from_millis(50));

        assert_eq!(call_a.state(), CallState::Active);
        assert_eq!(call_b.state(), CallState::Active);
    }

    #[test]
    fn uri_encode_encodes_special_chars() {
        assert_eq!(uri_encode("abc@host"), "abc%40host");
        assert_eq!(uri_encode("hello world"), "hello%20world");
        assert_eq!(uri_encode("100%done"), "100%25done");
        assert_eq!(uri_encode("simple"), "simple");
        assert_eq!(uri_encode("a;b=c?d&e+f"), "a%3Bb%3Dc%3Fd%26e%2Bf");
        assert_eq!(uri_encode("sip:user"), "sip%3Auser");
    }

    // --- MWI ---

    #[test]
    fn mwi_subscribes_on_connect() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE

        let mut cfg = test_cfg();
        cfg.voicemail_uri = Some("sip:*97@pbx.local".into());
        let phone = Phone::new(cfg);
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        // Give MWI thread time to send SUBSCRIBE.
        std::thread::sleep(Duration::from_millis(300));

        assert!(
            tr.count_sent("SUBSCRIBE") >= 1,
            "expected at least 1 SUBSCRIBE, got {}",
            tr.count_sent("SUBSCRIBE")
        );

        phone.disconnect().unwrap();
    }

    #[test]
    fn mwi_fires_on_voicemail_callback() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE

        let mut cfg = test_cfg();
        cfg.voicemail_uri = Some("sip:*97@pbx.local".into());
        let phone = Phone::new(cfg);

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone.on_voicemail(move |status| {
            let _ = tx.send(status);
        });

        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);
        std::thread::sleep(Duration::from_millis(200));

        // Simulate MWI NOTIFY.
        tr.simulate_mwi_notify("Messages-Waiting: yes\r\nVoice-Message: 2/4\r\n");

        let status = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(status.messages_waiting);
        assert_eq!(status.voice, (2, 4));

        phone.disconnect().unwrap();
    }

    #[test]
    fn no_mwi_without_voicemail_uri() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg()); // no voicemail_uri
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(tr.count_sent("SUBSCRIBE"), 0);

        phone.disconnect().unwrap();
    }

    #[test]
    fn send_message_before_connect_returns_error() {
        let phone = Phone::new(test_cfg());
        let result = phone.send_message("sip:1002@pbx.local", "Hello");
        assert!(result.is_err());
    }

    #[test]
    fn send_message_sends_via_transport() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // MESSAGE

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        phone.send_message("sip:1002@pbx.local", "Hello!").unwrap();
        assert_eq!(tr.count_sent("MESSAGE"), 1);

        phone.disconnect().unwrap();
    }

    #[test]
    fn on_message_fires_on_incoming() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);
        phone.on_message(move |msg| {
            *received_clone.lock() = Some(msg);
        });
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.simulate_message("sip:1001@pbx.local", "text/plain", "Hi there");
        // spawn_callback is async — give it a moment.
        std::thread::sleep(Duration::from_millis(100));

        let msg = received.lock().clone().unwrap();
        assert_eq!(msg.from, "sip:1001@pbx.local");
        assert_eq!(msg.body, "Hi there");
        assert_eq!(msg.content_type, "text/plain");

        phone.disconnect().unwrap();
    }

    #[test]
    fn watch_before_connect_errors() {
        let phone = Phone::new(test_cfg());
        let result = phone.watch("1001", |_, _| {});
        assert!(result.is_err());
    }

    #[test]
    fn watch_fires_callback_on_notify() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (tx, rx) = crossbeam_channel::bounded(1);
        phone
            .watch("1002", move |status, prev| {
                let _ = tx.send((status, prev));
            })
            .unwrap();

        // Simulate a dialog-info NOTIFY with confirmed state.
        std::thread::sleep(Duration::from_millis(300));
        tr.simulate_subscription_notify(
            "dialog",
            "application/dialog-info+xml",
            r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1002@test">
  <dialog id="d1"><state>confirmed</state></dialog>
</dialog-info>"#,
            "active;expires=600",
            "sip:1002@test",
        );

        let (status, prev) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(status.extension, "1002");
        assert_eq!(status.state, ExtensionState::OnThePhone);
        assert!(prev.is_none() || prev == Some(ExtensionState::Unknown));

        phone.disconnect().unwrap();
    }

    #[test]
    fn watch_duplicate_suppression() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let (tx, rx) = crossbeam_channel::bounded(10);
        phone
            .watch("1002", move |status, _| {
                let _ = tx.send(status.state);
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));

        let confirmed_xml = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1002@test">
  <dialog id="d1"><state>confirmed</state></dialog>
</dialog-info>"#;

        // Send same state twice.
        tr.simulate_subscription_notify(
            "dialog",
            "application/dialog-info+xml",
            confirmed_xml,
            "active;expires=600",
            "sip:1002@test",
        );
        std::thread::sleep(Duration::from_millis(100));
        tr.simulate_subscription_notify(
            "dialog",
            "application/dialog-info+xml",
            confirmed_xml,
            "active;expires=600",
            "sip:1002@test",
        );
        std::thread::sleep(Duration::from_millis(100));

        // Should only get one callback (duplicate suppressed).
        let _first = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second = rx.recv_timeout(Duration::from_millis(500));
        assert!(second.is_err(), "duplicate should be suppressed");

        phone.disconnect().unwrap();
    }

    #[test]
    fn unwatch_removes_subscription() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE
        tr.respond_with(200, "OK"); // unsubscribe

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);
        phone.watch("1002", |_, _| {}).unwrap();
        std::thread::sleep(Duration::from_millis(300));

        phone.unwatch("1002").unwrap();
        std::thread::sleep(Duration::from_millis(200));

        // Should have sent at least 2 SUBSCRIBEs (initial + unsubscribe).
        assert!(tr.count_sent("SUBSCRIBE") >= 2);

        phone.disconnect().unwrap();
    }

    #[test]
    fn subscribe_event_returns_id() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER
        tr.respond_with(200, "OK"); // SUBSCRIBE

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        let id = phone
            .subscribe_event(
                "sip:1002@test",
                "dialog",
                "application/dialog-info+xml",
                |_| {},
            )
            .unwrap();
        assert!(id > 0);
        std::thread::sleep(Duration::from_millis(200));

        phone.unsubscribe_event(id).unwrap();

        phone.disconnect().unwrap();
    }

    // --- Video ---

    #[test]
    fn dial_with_video_builds_video_sdp() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let opts = DialOptions {
            video: true,
            ..DialOptions::default()
        };
        let call = phone.dial("sip:1002@pbx.local", opts).unwrap();
        assert_eq!(call.state(), crate::types::CallState::Active);

        // The local SDP should contain a video m= line.
        let sdp = call.local_sdp();
        assert!(sdp.contains("m=video"), "SDP should contain video m= line");
        assert!(
            sdp.contains("m=audio"),
            "SDP should still contain audio m= line"
        );
    }

    #[test]
    fn dial_without_video_no_video_sdp() {
        let tr = Arc::new(MockTransport::new());
        tr.respond_with(200, "OK"); // REGISTER

        let phone = Phone::new(test_cfg());
        phone.connect_with_transport(Arc::clone(&tr) as Arc<dyn SipTransport>);

        tr.respond_with(200, "OK"); // INVITE
        let call = phone
            .dial("sip:1002@pbx.local", DialOptions::default())
            .unwrap();
        let sdp = call.local_sdp();
        assert!(
            !sdp.contains("m=video"),
            "SDP should not contain video m= line"
        );
    }
}
