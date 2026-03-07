use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Maximum SIP message size over UDP.
const MAX_SIP_MESSAGE_SIZE: usize = 65535;

/// Wraps a UDP socket for sending and receiving SIP messages.
pub struct Conn {
    socket: UdpSocket,
    recv_buf: Vec<u8>,
}

impl Conn {
    /// Creates a new SIP UDP connection bound to the given address.
    /// Use `"0.0.0.0:0"` for an ephemeral port.
    pub fn listen(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            recv_buf: vec![0u8; MAX_SIP_MESSAGE_SIZE],
        })
    }

    /// Sends raw data to the given address.
    pub fn send(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(data, addr)?;
        Ok(())
    }

    /// Reads the next UDP packet with a timeout.
    /// Returns a copy of the raw data and the sender's address.
    /// Not safe for concurrent calls (single reusable buffer).
    pub fn receive(&mut self, timeout: Duration) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.socket.set_read_timeout(Some(timeout))?;
        let (n, addr) = self.socket.recv_from(&mut self.recv_buf)?;
        Ok((self.recv_buf[..n].to_vec(), addr))
    }

    /// Returns the local address the connection is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Creates a write-only handle sharing the same underlying UDP socket.
    /// Used to separate read and write paths (avoids mutex contention).
    pub fn try_clone_write(&self) -> io::Result<WriteConn> {
        Ok(WriteConn {
            socket: self.socket.try_clone()?,
        })
    }
}

/// A write-only handle to a UDP socket (cloned from a Conn).
pub struct WriteConn {
    socket: UdpSocket,
}

impl WriteConn {
    /// Sends raw data to the given address.
    pub fn send(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(data, addr)?;
        Ok(())
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_and_local_addr() {
        let conn = Conn::listen("127.0.0.1:0").unwrap();
        let addr = conn.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    fn send_and_receive() {
        let mut c1 = Conn::listen("127.0.0.1:0").unwrap();
        let c2 = Conn::listen("127.0.0.1:0").unwrap();

        let addr1 = c1.local_addr().unwrap();
        let msg = b"SIP/2.0 200 OK\r\n\r\n";
        c2.send(msg, addr1).unwrap();

        let (data, from) = c1.receive(Duration::from_secs(1)).unwrap();
        assert_eq!(data, msg);
        assert_eq!(from.port(), c2.local_addr().unwrap().port());
    }

    #[test]
    fn receive_timeout() {
        let mut conn = Conn::listen("127.0.0.1:0").unwrap();
        let result = conn.receive(Duration::from_millis(10));
        assert!(result.is_err());
    }
}
