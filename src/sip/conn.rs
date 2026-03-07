use std::io::{self, BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

/// Maximum SIP message size over UDP.
const MAX_SIP_MESSAGE_SIZE: usize = 65535;

/// Returns the SIP Via transport tag for a given protocol string.
pub fn via_transport(protocol: &str) -> &'static str {
    match protocol {
        "tcp" => "TCP",
        "tls" => "TLS",
        _ => "UDP",
    }
}

// ---------------------------------------------------------------------------
// SipConnection trait
// ---------------------------------------------------------------------------

/// Abstraction over UDP, TCP, and TLS SIP transports.
///
/// Implementations must be `Send + Sync` so they can be shared between
/// the read loop thread and the write path.
pub trait SipConnection: Send + Sync {
    /// Sends raw data. For UDP, `to` specifies the destination.
    /// For TCP/TLS, `to` is ignored (connection-oriented).
    fn send(&self, data: &[u8], to: SocketAddr) -> io::Result<()>;

    /// Reads the next SIP message with a timeout.
    /// Returns the raw message data and the peer's address.
    fn receive(&self, timeout: Duration) -> io::Result<(Vec<u8>, SocketAddr)>;

    /// Returns the local address this connection is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Returns the transport protocol name (for Via headers).
    fn transport_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// UDP SIP connection.
pub struct UdpConn {
    socket: UdpSocket,
    recv_buf: Mutex<Vec<u8>>,
}

impl UdpConn {
    /// Creates a new UDP connection bound to the given address.
    pub fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            recv_buf: Mutex::new(vec![0u8; MAX_SIP_MESSAGE_SIZE]),
        })
    }

    /// Creates a clone sharing the same underlying UDP socket.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            recv_buf: Mutex::new(vec![0u8; MAX_SIP_MESSAGE_SIZE]),
        })
    }
}

impl SipConnection for UdpConn {
    fn send(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        self.socket.send_to(data, to)?;
        Ok(())
    }

    fn receive(&self, timeout: Duration) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buf = self.recv_buf.lock();
        let (n, addr) = self.socket.recv_from(&mut buf)?;
        Ok((buf[..n].to_vec(), addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn transport_name(&self) -> &str {
        "UDP"
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// TCP SIP connection.
///
/// SIP over TCP is stream-oriented. Messages are framed using the
/// `Content-Length` header (RFC 3261 §18.3). The read path buffers
/// incoming data and parses header/body boundaries.
pub struct TcpConn {
    reader: Mutex<BufReader<TcpStream>>,
    writer: Mutex<TcpStream>,
    peer_addr: SocketAddr,
    local: SocketAddr,
}

impl TcpConn {
    /// Connects to the given SIP server over TCP.
    pub fn connect(server_addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&server_addr, timeout)?;
        let local = stream.local_addr()?;
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: Mutex::new(BufReader::new(stream)),
            writer: Mutex::new(writer),
            peer_addr: server_addr,
            local,
        })
    }
}

impl SipConnection for TcpConn {
    fn send(&self, data: &[u8], _to: SocketAddr) -> io::Result<()> {
        let mut writer = self.writer.lock();
        writer.write_all(data)?;
        writer.flush()?;
        Ok(())
    }

    fn receive(&self, timeout: Duration) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut reader = self.reader.lock();
        reader.get_mut().set_read_timeout(Some(timeout))?;
        let data = read_sip_message(&mut *reader)?;
        Ok((data, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn transport_name(&self) -> &str {
        "TCP"
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// TLS SIP connection configuration.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Skip server certificate verification (insecure, useful for self-signed certs).
    pub insecure_skip_verify: bool,
}

/// TLS SIP connection.
///
/// Wraps a TCP stream with TLS encryption using `rustls`.
/// A single TLS session is shared for both reading and writing,
/// protected by a mutex.
pub struct TlsConn {
    stream: Mutex<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>,
    peer_addr: SocketAddr,
    local: SocketAddr,
}

impl TlsConn {
    /// Connects to the given SIP server over TLS.
    pub fn connect(
        server_addr: SocketAddr,
        domain: &str,
        tls_config: &TlsConfig,
        timeout: Duration,
    ) -> io::Result<Self> {
        let tcp = TcpStream::connect_timeout(&server_addr, timeout)?;
        let local = tcp.local_addr()?;

        let rustls_config = build_rustls_config(tls_config)?;
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let tls_conn = rustls::ClientConnection::new(Arc::new(rustls_config), server_name)
            .map_err(io::Error::other)?;

        let tls_stream = rustls::StreamOwned::new(tls_conn, tcp);

        Ok(Self {
            stream: Mutex::new(tls_stream),
            peer_addr: server_addr,
            local,
        })
    }
}

impl SipConnection for TlsConn {
    fn send(&self, data: &[u8], _to: SocketAddr) -> io::Result<()> {
        let mut stream = self.stream.lock();
        stream.write_all(data)?;
        stream.flush()?;
        Ok(())
    }

    fn receive(&self, timeout: Duration) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut stream = self.stream.lock();
        stream.get_ref().set_read_timeout(Some(timeout))?;
        // We need a BufReader around the stream for line-by-line reading.
        // Since we hold the lock for the entire receive, this is safe.
        let data = read_sip_message_from_tls(&mut stream)?;
        Ok((data, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn transport_name(&self) -> &str {
        "TLS"
    }
}

fn build_rustls_config(tls_config: &TlsConfig) -> io::Result<rustls::ClientConfig> {
    if tls_config.insecure_skip_verify {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
        Ok(config)
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(config)
    }
}

/// Certificate verifier that accepts any certificate (insecure).
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// SIP message framing for TCP/TLS
// ---------------------------------------------------------------------------

/// Reads a single SIP message from a buffered stream (TCP).
///
/// SIP over TCP uses Content-Length to delimit message bodies (RFC 3261 §18.3).
/// Reads header lines until `\r\n\r\n`, parses Content-Length, then reads the body.
fn read_sip_message(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut header_data = Vec::with_capacity(2048);
    let mut content_length: usize = 0;

    // Read headers line by line until empty line.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }

        // Parse Content-Length (case-insensitive, including compact form "l:").
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower
            .strip_prefix("content-length:")
            .or_else(|| lower.strip_prefix("l:"))
        {
            if let Ok(len) = rest.trim().parse::<usize>() {
                content_length = len;
            }
        }

        header_data.extend_from_slice(line.as_bytes());

        // End of headers: blank line.
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Read body if Content-Length > 0.
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        header_data.extend_from_slice(&body);
    }

    Ok(header_data)
}

/// Reads a single SIP message from a TLS stream.
///
/// Unlike TCP where we can use BufReader over a cloned TcpStream,
/// TLS streams cannot be split. We read byte by byte to find header
/// boundaries, then read the body in one shot.
fn read_sip_message_from_tls(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut header_data = Vec::with_capacity(2048);
    let mut content_length: usize = 0;

    // Read headers byte by byte until \r\n\r\n.
    let mut consecutive_crlf = 0u8;
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        header_data.push(byte[0]);

        // Track \r\n\r\n sequence.
        match byte[0] {
            b'\r' => {}
            b'\n' => {
                consecutive_crlf += 1;
                if consecutive_crlf >= 2 {
                    break;
                }
            }
            _ => {
                consecutive_crlf = 0;
            }
        }
    }

    // Parse Content-Length from headers.
    let header_str = String::from_utf8_lossy(&header_data);
    for line in header_str.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower
            .strip_prefix("content-length:")
            .or_else(|| lower.strip_prefix("l:"))
        {
            if let Ok(len) = rest.trim().parse::<usize>() {
                content_length = len;
            }
        }
    }

    // Read body if Content-Length > 0.
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body)?;
        header_data.extend_from_slice(&body);
    }

    Ok(header_data)
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Creates a SIP connection for the given transport protocol.
pub fn connect(
    transport: &str,
    server_addr: SocketAddr,
    local_addr: &str,
    domain: &str,
    tls_config: Option<&TlsConfig>,
    timeout: Duration,
) -> io::Result<Box<dyn SipConnection>> {
    match transport {
        "tcp" => {
            let conn = TcpConn::connect(server_addr, timeout)?;
            Ok(Box::new(conn))
        }
        "tls" => {
            let cfg = tls_config.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS transport requires TlsConfig",
                )
            })?;
            let conn = TlsConn::connect(server_addr, domain, cfg, timeout)?;
            Ok(Box::new(conn))
        }
        _ => {
            // UDP (default)
            let conn = UdpConn::bind(local_addr)?;
            Ok(Box::new(conn))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_listen_and_local_addr() {
        let conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let addr = conn.local_addr().unwrap();
        assert!(addr.port() > 0);
        assert_eq!(conn.transport_name(), "UDP");
    }

    #[test]
    fn udp_send_and_receive() {
        let c1 = UdpConn::bind("127.0.0.1:0").unwrap();
        let c2 = UdpConn::bind("127.0.0.1:0").unwrap();

        let addr1 = c1.local_addr().unwrap();
        let msg = b"SIP/2.0 200 OK\r\n\r\n";
        c2.send(msg, addr1).unwrap();

        let (data, from) = c1.receive(Duration::from_secs(1)).unwrap();
        assert_eq!(data, msg);
        assert_eq!(from.port(), c2.local_addr().unwrap().port());
    }

    #[test]
    fn udp_receive_timeout() {
        let conn = UdpConn::bind("127.0.0.1:0").unwrap();
        let result = conn.receive(Duration::from_millis(10));
        assert!(result.is_err());
    }

    #[test]
    fn udp_large_message() {
        let c1 = UdpConn::bind("127.0.0.1:0").unwrap();
        let c2 = UdpConn::bind("127.0.0.1:0").unwrap();

        let addr1 = c1.local_addr().unwrap();
        let body = "x".repeat(8000);
        let msg = format!(
            "SIP/2.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        c2.send(msg.as_bytes(), addr1).unwrap();

        let (data, _) = c1.receive(Duration::from_secs(1)).unwrap();
        assert_eq!(data.len(), msg.len());
    }

    #[test]
    fn udp_clone() {
        let c1 = UdpConn::bind("127.0.0.1:0").unwrap();
        let c2 = UdpConn::bind("127.0.0.1:0").unwrap();
        let wc = c2.try_clone().unwrap();

        let addr1 = c1.local_addr().unwrap();
        wc.send(b"REGISTER sip:pbx\r\n\r\n", addr1).unwrap();

        let (data, _) = c1.receive(Duration::from_secs(1)).unwrap();
        assert_eq!(data, b"REGISTER sip:pbx\r\n\r\n");
        assert_eq!(wc.local_addr().unwrap(), c2.local_addr().unwrap());
    }

    #[test]
    fn via_transport_names() {
        assert_eq!(via_transport("udp"), "UDP");
        assert_eq!(via_transport("tcp"), "TCP");
        assert_eq!(via_transport("tls"), "TLS");
        assert_eq!(via_transport("other"), "UDP");
    }

    #[test]
    fn tcp_send_receive() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server thread: accept, read a SIP message, send response.
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let data = read_sip_message(&mut reader).unwrap();
            assert!(data.starts_with(b"REGISTER"));

            let resp = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(resp).unwrap();
            stream.flush().unwrap();
        });

        let conn = TcpConn::connect(server_addr, Duration::from_secs(2)).unwrap();
        assert_eq!(conn.transport_name(), "TCP");

        let msg = b"REGISTER sip:pbx.local SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        conn.send(msg, server_addr).unwrap();

        let (data, from) = conn.receive(Duration::from_secs(2)).unwrap();
        assert!(String::from_utf8_lossy(&data).contains("200 OK"));
        assert_eq!(from, server_addr);

        handle.join().unwrap();
    }

    #[test]
    fn tcp_message_with_body() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n";
            let msg = format!(
                "SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(msg.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let conn = TcpConn::connect(server_addr, Duration::from_secs(2)).unwrap();
        let (data, _) = conn.receive(Duration::from_secs(2)).unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(text.contains("200 OK"));
        assert!(text.contains("v=0"));

        handle.join().unwrap();
    }

    #[test]
    fn read_sip_message_framing() {
        let input = b"SIP/2.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = BufReader::new(&input[..]);
        let data = read_sip_message(&mut reader).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&data),
            "SIP/2.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
    }

    #[test]
    fn read_sip_message_no_body() {
        let input = b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let data = read_sip_message(&mut reader).unwrap();
        assert!(String::from_utf8_lossy(&data).contains("100 Trying"));
    }

    #[test]
    fn read_sip_message_compact_content_length() {
        let input = b"SIP/2.0 200 OK\r\nl: 3\r\n\r\nabc";
        let mut reader = BufReader::new(&input[..]);
        let data = read_sip_message(&mut reader).unwrap();
        assert!(String::from_utf8_lossy(&data).ends_with("abc"));
    }
}
