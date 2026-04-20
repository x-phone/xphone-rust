use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;

use tracing::{debug, warn};

use super::conn::SipConnection;
use super::message::{self, Message};
use crate::error::{Error, Result};

/// Pending client transaction waiting for a response.
struct PendingTx {
    resp_tx: Sender<Message>,
    resp_rx: Receiver<Message>,
}

type RequestCallback = Arc<dyn Fn(Message, SocketAddr) + Send + Sync>;

struct Inner {
    pending: HashMap<String, PendingTx>,
    on_request: Option<RequestCallback>,
    stopped: bool,
}

/// Manages SIP client transactions.
/// Dispatches incoming responses to the correct pending transaction by Via branch,
/// and incoming requests to the OnRequest callback.
pub struct TransactionManager {
    conn: Arc<dyn SipConnection>,
    local_addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
    /// Transport name for Via headers (UDP, TCP, TLS).
    transport_name: String,
    /// Append `;rport` (RFC 3581) to auto-generated Via headers when `true`.
    nat: std::sync::atomic::AtomicBool,
    /// Dropping this sender closes the channel, signaling all receivers to stop.
    done_tx: Mutex<Option<Sender<()>>>,
    done_rx: Receiver<()>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl TransactionManager {
    /// Creates a new TransactionManager and starts its read loop.
    pub fn new(conn: Box<dyn SipConnection>) -> Self {
        let local_addr = conn.local_addr().expect("failed to get local addr");
        let transport_name = conn.transport_name().to_string();

        // Wrap in Arc so both read loop and write path share the connection.
        let conn: Arc<dyn SipConnection> = Arc::from(conn);

        let inner = Arc::new(Mutex::new(Inner {
            pending: HashMap::new(),
            on_request: None,
            stopped: false,
        }));
        let (done_tx, done_rx) = bounded::<()>(0);

        let thread = {
            let inner = Arc::clone(&inner);
            let done_rx = done_rx.clone();
            let conn_read = Arc::clone(&conn);
            std::thread::Builder::new()
                .name("sip-transaction-reader".into())
                .spawn(move || read_loop(conn_read, inner, done_rx))
                .expect("failed to spawn transaction reader thread")
        };

        Self {
            conn,
            local_addr,
            inner,
            transport_name,
            nat: std::sync::atomic::AtomicBool::new(false),
            done_tx: Mutex::new(Some(done_tx)),
            done_rx,
            thread: Mutex::new(Some(thread)),
        }
    }

    /// Returns the transport name (UDP, TCP, TLS) for Via header construction.
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    /// Enables appending `;rport` (RFC 3581) to auto-generated Via headers.
    pub fn set_nat(&self, enabled: bool) {
        self.nat
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Shuts down the read loop and cancels all pending transactions.
    pub fn stop(&self) {
        let mut inner = self.inner.lock();
        if inner.stopped {
            return;
        }
        inner.stopped = true;
        inner.pending.clear();
        drop(inner);
        // Drop the sender to close the channel — wakes all receivers.
        self.done_tx.lock().take();
        // Join the read loop thread.
        if let Some(handle) = self.thread.lock().take() {
            let _ = handle.join();
        }
    }

    /// Sends a SIP request and waits for the first response.
    /// Auto-generates a Via header with a unique branch if none is set.
    pub fn send(&self, req: &mut Message, dst: SocketAddr, timeout: Duration) -> Result<Message> {
        {
            let inner = self.inner.lock();
            if inner.stopped {
                return Err(Error::Other("sip: transaction manager stopped".into()));
            }
        }

        // Generate branch and set Via if not present.
        let mut branch = req.via_branch().to_string();
        if branch.is_empty() {
            branch = generate_branch();
            let rport = if self.nat.load(std::sync::atomic::Ordering::Relaxed) {
                ";rport"
            } else {
                ""
            };
            let via = format!(
                "SIP/2.0/{} {};branch={}{}",
                self.transport_name, self.local_addr, branch, rport
            );
            req.set_header("Via", &via);
        }

        // Register this transaction.
        let resp_rx = {
            let (resp_tx, resp_rx) = bounded(8);
            let mut inner = self.inner.lock();
            inner.pending.insert(
                branch.clone(),
                PendingTx {
                    resp_tx,
                    resp_rx: resp_rx.clone(),
                },
            );
            resp_rx
        };

        // Send the request.
        self.conn
            .send(&req.to_bytes(), dst)
            .map_err(|e| Error::Other(format!("sip: send: {}", e)))?;

        // Wait for first response, timeout, or stop.
        crossbeam_channel::select! {
            recv(resp_rx) -> msg => {
                msg.map_err(|_| Error::Other("sip: transaction manager stopped".into()))
            }
            recv(self.done_rx) -> _ => {
                self.remove_tx(&branch);
                Err(Error::Other("sip: transaction manager stopped".into()))
            }
            default(timeout) => {
                self.remove_tx(&branch);
                Err(Error::Other("sip: transaction timeout".into()))
            }
        }
    }

    /// Reads the next response for a transaction identified by its Via branch.
    pub fn read_response(&self, branch: &str, timeout: Duration) -> Result<Message> {
        let resp_rx = {
            let inner = self.inner.lock();
            let tx = inner
                .pending
                .get(branch)
                .ok_or_else(|| Error::Other("sip: no pending transaction for branch".into()))?;
            tx.resp_rx.clone()
        };

        crossbeam_channel::select! {
            recv(resp_rx) -> msg => {
                msg.map_err(|_| Error::Other("sip: transaction manager stopped".into()))
            }
            recv(self.done_rx) -> _ => {
                Err(Error::Other("sip: transaction manager stopped".into()))
            }
            default(timeout) => {
                Err(Error::Other("sip: transaction timeout".into()))
            }
        }
    }

    /// Registers a callback for incoming SIP requests (INVITE, BYE, etc.).
    pub fn on_request<F>(&self, f: F)
    where
        F: Fn(Message, SocketAddr) + Send + Sync + 'static,
    {
        self.inner.lock().on_request = Some(Arc::new(f));
    }

    /// Sends raw data (e.g., keepalive) without transaction tracking.
    pub fn send_raw(&self, data: &[u8], dst: SocketAddr) -> Result<()> {
        self.conn
            .send(data, dst)
            .map_err(|e| Error::Other(format!("sip: send_raw: {}", e)))
    }

    /// Removes a completed transaction from the pending map.
    pub fn remove_tx(&self, branch: &str) {
        self.inner.lock().pending.remove(branch);
    }
}

impl Drop for TransactionManager {
    fn drop(&mut self) {
        // Use direct field access (no lock needed since we have &mut self).
        let mut inner = self.inner.lock();
        if inner.stopped {
            return;
        }
        inner.stopped = true;
        inner.pending.clear();
        drop(inner);
        self.done_tx.get_mut().take();
        if let Some(handle) = self.thread.get_mut().take() {
            let _ = handle.join();
        }
    }
}

/// Read loop runs on a dedicated thread.
fn read_loop(conn: Arc<dyn SipConnection>, inner: Arc<Mutex<Inner>>, done_rx: Receiver<()>) {
    loop {
        // Check if stopped (channel closed).
        if done_rx.try_recv().is_ok() || done_rx.is_empty() && inner.lock().stopped {
            return;
        }

        let (data, addr) = match conn.receive(Duration::from_millis(500)) {
            Ok(pair) => pair,
            Err(_) => continue, // timeout or error — loop again
        };

        debug!(len = data.len(), from = %addr, "SIP recv raw packet");

        let msg = match message::parse(&data) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    error = %e,
                    from = %addr,
                    len = data.len(),
                    preview = %String::from_utf8_lossy(&data[..data.len().min(120)]),
                    "SIP parse failed — dropping packet"
                );
                continue;
            }
        };

        if !msg.is_response() {
            debug!(method = %msg.method, from = %addr, "SIP dispatching incoming request");
            // Dispatch incoming request to callback.
            let cb = inner.lock().on_request.clone();
            if let Some(cb) = cb {
                cb(msg, addr);
            } else {
                warn!(method = %msg.method, "SIP incoming request but no callback registered");
            }
            continue;
        }

        let branch = msg.via_branch().to_string();
        if branch.is_empty() {
            warn!(
                status = msg.status_code,
                "SIP response with empty Via branch — dropping"
            );
            continue;
        }

        debug!(status = msg.status_code, branch = %branch, "SIP dispatching response to transaction");
        let inner = inner.lock();
        if let Some(tx) = inner.pending.get(&branch) {
            let _ = tx.resp_tx.try_send(msg);
        } else {
            debug!(branch = %branch, "SIP no pending transaction for branch (stale response)");
        }
    }
}

/// Generates a unique Via branch per RFC 3261 section 8.1.1.7.
/// Branches must start with "z9hG4bK" (magic cookie).
pub fn generate_branch() -> String {
    let mut buf = [0u8; 12];
    for b in &mut buf {
        *b = rand_byte();
    }
    let mut hex = String::with_capacity(7 + 24);
    hex.push_str("z9hG4bK");
    for byte in &buf {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

fn rand_byte() -> u8 {
    use std::cell::Cell;
    thread_local! {
        static RNG: Cell<u64> = Cell::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        );
    }
    RNG.with(|cell| {
        // xorshift64
        let mut s = cell.get();
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        cell.set(s);
        s as u8
    })
}

#[cfg(test)]
mod tests {
    use super::super::conn::UdpConn;
    use super::*;

    #[test]
    fn generate_branch_format() {
        let b = generate_branch();
        assert!(b.starts_with("z9hG4bK"));
        assert!(b.len() > 7);
    }

    #[test]
    fn generate_branch_unique() {
        let b1 = generate_branch();
        let b2 = generate_branch();
        assert_ne!(b1, b2);
    }

    #[test]
    fn transaction_send_receive() {
        let server_conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server_conn.local_addr().unwrap();

        let client_conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let tm = TransactionManager::new(Box::new(client_conn));

        // Spawn a thread that reads from the server and sends a 200 OK back.
        let handle = std::thread::spawn(move || {
            let (data, from) = server_conn.receive(Duration::from_secs(2)).unwrap();
            let req = message::parse(&data).unwrap();
            assert_eq!(req.method, "REGISTER");

            let mut resp = Message::new_response(200, "OK");
            resp.set_header("Via", req.header("Via"));
            resp.set_header("Call-ID", req.header("Call-ID"));
            resp.set_header("CSeq", req.header("CSeq"));

            let resp_data = resp.to_bytes();
            server_conn.send(&resp_data, from).unwrap();
        });

        let mut req = Message::new_request("REGISTER", "sip:pbx.local");
        req.set_header("Call-ID", "test-tx@host");
        req.set_header("CSeq", "1 REGISTER");

        let resp = tm
            .send(&mut req, server_addr, Duration::from_secs(2))
            .unwrap();
        assert_eq!(resp.status_code, 200);

        tm.stop();
        handle.join().unwrap();
    }

    #[test]
    fn transaction_timeout() {
        let conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let dst: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let tm = TransactionManager::new(Box::new(conn));

        let mut req = Message::new_request("REGISTER", "sip:pbx.local");
        req.set_header("Call-ID", "timeout-test@host");
        req.set_header("CSeq", "1 REGISTER");

        let result = tm.send(&mut req, dst, Duration::from_millis(200));
        assert!(
            result.is_err(),
            "expected error when sending to unreachable destination"
        );

        tm.stop();
    }

    #[test]
    fn send_after_stop_returns_error() {
        let conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let dst: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let tm = TransactionManager::new(Box::new(conn));

        tm.stop();

        let mut req = Message::new_request("OPTIONS", "sip:pbx.local");
        req.set_header("Call-ID", "stop-test@host");
        req.set_header("CSeq", "1 OPTIONS");
        let result = tm.send(&mut req, dst, Duration::from_secs(5));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("stopped"));
    }

    #[test]
    fn on_request_callback() {
        let server_conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let server_addr = server_conn.local_addr().unwrap();

        let tm = TransactionManager::new(Box::new(server_conn));

        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);
        tm.on_request(move |msg, _addr| {
            received_clone.lock().push(msg.method.clone());
        });

        // Send a request from another socket.
        let sender = UdpConn::bind("127.0.0.1:0").unwrap();
        let mut req = Message::new_request("INVITE", "sip:1002@pbx.local");
        req.set_header("Via", "SIP/2.0/UDP 127.0.0.1:9999;branch=z9hG4bKtest");
        req.set_header("Call-ID", "incoming@host");
        req.set_header("CSeq", "1 INVITE");
        sender.send(&req.to_bytes(), server_addr).unwrap();

        // Wait for the read loop to pick it up.
        std::thread::sleep(Duration::from_millis(600));

        let methods = received.lock().clone();
        assert_eq!(methods, vec!["INVITE"]);

        tm.stop();
    }
}
