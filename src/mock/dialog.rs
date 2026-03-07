use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::dialog::Dialog;
use crate::error::Result;

/// Mock SIP dialog for testing call behavior.
pub struct MockDialog {
    inner: Mutex<MockDialogInner>,
}

struct MockDialogInner {
    last_response_code: u16,
    last_response_reason: String,
    last_response_body: Vec<u8>,
    cancel_sent: bool,
    bye_sent: bool,
    last_reinvite_sdp: Vec<u8>,
    refer_sent: bool,
    last_refer_target: String,
    call_id: String,
    headers: HashMap<String, Vec<String>>,
    on_notify: Option<Arc<dyn Fn(u16) + Send + Sync>>,
}

impl MockDialog {
    pub fn new() -> Self {
        MockDialog {
            inner: Mutex::new(MockDialogInner {
                last_response_code: 0,
                last_response_reason: String::new(),
                last_response_body: Vec::new(),
                cancel_sent: false,
                bye_sent: false,
                last_reinvite_sdp: Vec::new(),
                refer_sent: false,
                last_refer_target: String::new(),
                call_id: "mock-call-id".into(),
                headers: HashMap::new(),
                on_notify: None,
            }),
        }
    }

    pub fn with_call_id(call_id: &str) -> Self {
        let d = Self::new();
        d.inner.lock().call_id = call_id.into();
        d
    }

    pub fn with_headers(headers: HashMap<String, Vec<String>>) -> Self {
        let d = Self::new();
        d.inner.lock().headers = headers;
        d
    }

    pub fn with_session_expires(seconds: u32) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Session-Expires".into(), vec![seconds.to_string()]);
        Self::with_headers(headers)
    }

    // --- Test inspection methods ---

    pub fn last_response_code(&self) -> u16 {
        self.inner.lock().last_response_code
    }

    pub fn last_response_reason(&self) -> String {
        self.inner.lock().last_response_reason.clone()
    }

    pub fn last_response_body(&self) -> Vec<u8> {
        self.inner.lock().last_response_body.clone()
    }

    pub fn bye_sent(&self) -> bool {
        self.inner.lock().bye_sent
    }

    pub fn cancel_sent(&self) -> bool {
        self.inner.lock().cancel_sent
    }

    pub fn refer_sent(&self) -> bool {
        self.inner.lock().refer_sent
    }

    pub fn last_refer_target(&self) -> String {
        self.inner.lock().last_refer_target.clone()
    }

    pub fn last_reinvite_sdp(&self) -> String {
        let inner = self.inner.lock();
        String::from_utf8_lossy(&inner.last_reinvite_sdp).to_string()
    }

    pub fn simulate_notify(&self, code: u16) {
        let f = self.inner.lock().on_notify.clone();
        if let Some(f) = f {
            f(code);
        }
    }
}

impl Default for MockDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl Dialog for MockDialog {
    fn respond(&self, code: u16, reason: &str, body: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock();
        inner.last_response_code = code;
        inner.last_response_reason = reason.into();
        inner.last_response_body = body.to_vec();
        Ok(())
    }

    fn send_bye(&self) -> Result<()> {
        self.inner.lock().bye_sent = true;
        Ok(())
    }

    fn send_cancel(&self) -> Result<()> {
        self.inner.lock().cancel_sent = true;
        Ok(())
    }

    fn send_reinvite(&self, sdp: &[u8]) -> Result<()> {
        self.inner.lock().last_reinvite_sdp = sdp.to_vec();
        Ok(())
    }

    fn send_refer(&self, target: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        inner.refer_sent = true;
        inner.last_refer_target = target.into();
        Ok(())
    }

    fn on_notify(&self, f: Box<dyn Fn(u16) + Send + Sync>) {
        self.inner.lock().on_notify = Some(Arc::from(f));
    }

    fn call_id(&self) -> String {
        self.inner.lock().call_id.clone()
    }

    fn header(&self, name: &str) -> Vec<String> {
        let inner = self.inner.lock();
        let lower = name.to_lowercase();
        for (k, v) in &inner.headers {
            if k.to_lowercase() == lower {
                return v.clone();
            }
        }
        Vec::new()
    }

    fn headers(&self) -> HashMap<String, Vec<String>> {
        let inner = self.inner.lock();
        inner.headers.clone()
    }
}
