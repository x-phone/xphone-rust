use std::cmp::Ordering;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::RtpPacket;

struct JitterEntry {
    pkt: RtpPacket,
    arrival: Instant,
}

/// Compares two 16-bit RTP sequence numbers with wraparound (RFC 3550).
/// Returns true if `a` comes before `b`.
fn seq_less(a: u16, b: u16) -> bool {
    let diff = b.wrapping_sub(a);
    diff > 0 && diff < 0x8000
}

/// Wraparound-aware ordering for RTP sequence numbers.
///
/// Defines a strict order only when all compared values lie within a window
/// of less than 32768 sequence numbers — true for any sane jitter buffer
/// (telephony depths are tens of packets) but worth being explicit about
/// since [`Vec::binary_search_by`] relies on the slice being totally ordered
/// under the comparator.
fn seq_cmp(a: u16, b: u16) -> Ordering {
    if a == b {
        Ordering::Equal
    } else if seq_less(a, b) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Reorders and deduplicates incoming RTP packets.
pub struct JitterBuffer {
    inner: Mutex<JitterInner>,
}

struct JitterInner {
    depth: Duration,
    entries: Vec<JitterEntry>,
    seen: std::collections::HashSet<u16>,
}

impl JitterBuffer {
    /// Creates a JitterBuffer with the given playout depth.
    pub fn new(depth: Duration) -> Self {
        JitterBuffer {
            inner: Mutex::new(JitterInner {
                depth,
                entries: Vec::new(),
                seen: std::collections::HashSet::new(),
            }),
        }
    }

    /// Adds an RTP packet to the buffer. Duplicates are dropped.
    pub fn push(&self, pkt: RtpPacket) {
        let mut inner = self.inner.lock();
        let seq = pkt.header.sequence_number;
        if inner.seen.contains(&seq) {
            return;
        }
        inner.seen.insert(seq);
        let pos = inner
            .entries
            .binary_search_by(|e| seq_cmp(e.pkt.header.sequence_number, seq))
            .unwrap_or_else(|p| p);
        inner.entries.insert(
            pos,
            JitterEntry {
                pkt,
                arrival: Instant::now(),
            },
        );
    }

    /// Returns the next packet in sequence order if its arrival time exceeds
    /// the jitter depth, or `None` if no packet is ready.
    pub fn pop(&self) -> Option<RtpPacket> {
        let mut inner = self.inner.lock();
        if inner.entries.is_empty() {
            return None;
        }

        let now = Instant::now();
        if now.duration_since(inner.entries[0].arrival) >= inner.depth {
            let entry = inner.entries.remove(0);
            inner.seen.remove(&entry.pkt.header.sequence_number);
            Some(entry.pkt)
        } else {
            None
        }
    }

    /// Returns all buffered packets in sequence order and clears the buffer.
    pub fn flush(&self) -> Vec<RtpPacket> {
        let mut inner = self.inner.lock();
        if inner.entries.is_empty() {
            return Vec::new();
        }

        let pkts = inner.entries.drain(..).map(|e| e.pkt).collect();
        inner.seen.clear();
        pkts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RtpHeader;

    fn make_pkt(seq: u16) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 0,
                sequence_number: seq,
                timestamp: 0,
                ssrc: 0,
            },
            payload: Vec::new(),
        }
    }

    fn make_pkt_with_payload(seq: u16, payload: &[u8]) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 0,
                sequence_number: seq,
                timestamp: 0,
                ssrc: 0,
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn in_order() {
        let jb = JitterBuffer::new(Duration::from_millis(50));
        for seq in 1..=3 {
            jb.push(make_pkt(seq));
        }
        let pkts = jb.flush();
        assert_eq!(pkts.len(), 3);
        for (i, pkt) in pkts.iter().enumerate() {
            assert_eq!(pkt.header.sequence_number, (i + 1) as u16);
        }
    }

    #[test]
    fn reorder() {
        let jb = JitterBuffer::new(Duration::from_millis(50));
        jb.push(make_pkt(3));
        jb.push(make_pkt(1));
        jb.push(make_pkt(2));

        let pkts = jb.flush();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].header.sequence_number, 1);
        assert_eq!(pkts[1].header.sequence_number, 2);
        assert_eq!(pkts[2].header.sequence_number, 3);
    }

    #[test]
    fn dedup() {
        let jb = JitterBuffer::new(Duration::from_millis(50));
        jb.push(make_pkt_with_payload(1, &[0xAA]));
        jb.push(make_pkt_with_payload(1, &[0xBB])); // duplicate
        jb.push(make_pkt_with_payload(2, &[0xCC]));

        let pkts = jb.flush();
        assert_eq!(pkts.len(), 2, "duplicate seq 1 should be suppressed");
        assert_eq!(pkts[0].header.sequence_number, 1);
        assert_eq!(pkts[0].payload, vec![0xAA], "first copy must be preserved");
        assert_eq!(pkts[1].header.sequence_number, 2);
    }

    #[test]
    fn configurable_depth() {
        let short = JitterBuffer::new(Duration::from_millis(10));
        short.push(make_pkt(2));
        std::thread::sleep(Duration::from_millis(15));
        let pkt = short.pop();
        assert!(
            pkt.is_some(),
            "short depth should release packet after delay"
        );
        assert_eq!(pkt.unwrap().header.sequence_number, 2);

        let long = JitterBuffer::new(Duration::from_millis(200));
        long.push(make_pkt(3));
        let pkt = long.pop();
        assert!(
            pkt.is_none(),
            "long depth should hold packet within depth window"
        );
        std::thread::sleep(Duration::from_millis(210));
        let pkt = long.pop();
        assert!(
            pkt.is_some(),
            "long depth should release packet after delay"
        );
        assert_eq!(pkt.unwrap().header.sequence_number, 3);
    }

    #[test]
    fn sequence_wrap_around() {
        let jb = JitterBuffer::new(Duration::from_millis(50));
        jb.push(make_pkt(0));
        jb.push(make_pkt(65535));
        jb.push(make_pkt(65534));
        jb.push(make_pkt(1));

        let pkts = jb.flush();
        assert_eq!(pkts.len(), 4);
        assert_eq!(pkts[0].header.sequence_number, 65534);
        assert_eq!(pkts[1].header.sequence_number, 65535);
        assert_eq!(pkts[2].header.sequence_number, 0);
        assert_eq!(pkts[3].header.sequence_number, 1);
    }

    #[test]
    fn empty() {
        let jb = JitterBuffer::new(Duration::from_millis(50));
        let pkts = jb.flush();
        assert!(pkts.is_empty());
        let pkt = jb.pop();
        assert!(pkt.is_none());
    }
}
