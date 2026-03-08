//! Basic RTCP (RFC 3550) — Sender/Receiver Reports for trunk compatibility.
//!
//! Provides RTCP SR/RR packet building, parsing, and statistics tracking.
//! Most SIP trunks expect periodic RTCP traffic and may tear down calls
//! if none is received.

use std::time::{Instant, SystemTime};

use crate::types::RtpPacket;

/// RTCP packet type: Sender Report (RFC 3550 §6.4.1).
const RTCP_SR: u8 = 200;
/// RTCP packet type: Receiver Report (RFC 3550 §6.4.2).
const RTCP_RR: u8 = 201;
/// RTCP version (always 2, matching RTP).
const RTCP_VERSION: u8 = 2;
/// NTP epoch offset: seconds between 1900-01-01 and 1970-01-01.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
/// Minimum RTCP send interval (RFC 3550 §6.2).
pub const RTCP_INTERVAL_SECS: u64 = 5;

/// Statistics tracked for RTCP report generation.
pub struct RtcpStats {
    // --- Outbound (for SR sender info) ---
    packets_sent: u32,
    octets_sent: u32,
    last_rtp_timestamp: u32,

    // --- Inbound (for RR report block) ---
    packets_received: u32,
    remote_ssrc: u32,

    // Sequence tracking for loss calculation.
    base_seq: u16,
    max_seq: u16,
    cycles: u32,
    seq_initialized: bool,

    // Jitter calculation (RFC 3550 A.8).
    jitter: f64,
    prev_transit: i64,
    jitter_initialized: bool,
    /// Baseline instant for converting monotonic time to RTP clock units.
    baseline: Instant,

    // For loss fraction between RR intervals.
    expected_prior: u32,
    received_prior: u32,

    // For round-trip time: middle 32 bits of last received SR NTP timestamp.
    last_sr_ntp_middle: u32,
    last_sr_recv_time: Option<Instant>,
}

impl Default for RtcpStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RtcpStats {
    /// Creates a new stats tracker with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_sent: 0,
            octets_sent: 0,
            last_rtp_timestamp: 0,
            packets_received: 0,
            remote_ssrc: 0,
            base_seq: 0,
            max_seq: 0,
            cycles: 0,
            seq_initialized: false,
            jitter: 0.0,
            prev_transit: 0,
            jitter_initialized: false,
            baseline: Instant::now(),
            expected_prior: 0,
            received_prior: 0,
            last_sr_ntp_middle: 0,
            last_sr_recv_time: None,
        }
    }

    /// Records an outbound RTP packet for SR sender info.
    pub fn record_rtp_sent(&mut self, payload_len: usize, rtp_timestamp: u32) {
        self.packets_sent = self.packets_sent.wrapping_add(1);
        self.octets_sent = self.octets_sent.wrapping_add(payload_len as u32);
        self.last_rtp_timestamp = rtp_timestamp;
    }

    /// Records an inbound RTP packet for RR report block.
    pub fn record_rtp_received(&mut self, pkt: &RtpPacket, clock_rate: u32) {
        self.packets_received = self.packets_received.wrapping_add(1);
        self.remote_ssrc = pkt.header.ssrc;

        let seq = pkt.header.sequence_number;
        if !self.seq_initialized {
            self.base_seq = seq;
            self.max_seq = seq;
            self.seq_initialized = true;
        } else {
            let udelta = seq.wrapping_sub(self.max_seq);
            if udelta < 0x8000 {
                if seq < self.max_seq {
                    self.cycles = self.cycles.wrapping_add(1);
                }
                self.max_seq = seq;
            }
        }

        // Jitter calculation per RFC 3550 A.8.
        // Uses monotonic Instant to avoid per-packet syscall (only differences matter).
        if clock_rate > 0 {
            let elapsed = self.baseline.elapsed();
            let arrival = (elapsed.as_secs_f64() * clock_rate as f64) as i64;
            let transit = arrival - pkt.header.timestamp as i64;
            if self.jitter_initialized {
                let d = (transit - self.prev_transit).unsigned_abs() as f64;
                self.jitter += (d - self.jitter) / 16.0;
            }
            self.prev_transit = transit;
            self.jitter_initialized = true;
        }
    }

    /// Processes a received SR to record its NTP timestamp for RTT calculation.
    pub fn process_incoming_sr(&mut self, ntp_sec: u32, ntp_frac: u32) {
        // Middle 32 bits of NTP timestamp: low 16 of sec + high 16 of frac.
        self.last_sr_ntp_middle = ((ntp_sec & 0xFFFF) << 16) | ((ntp_frac >> 16) & 0xFFFF);
        self.last_sr_recv_time = Some(Instant::now());
    }

    /// Extended highest sequence number received (cycles << 16 | max_seq).
    fn extended_max_seq(&self) -> u32 {
        (self.cycles << 16) | self.max_seq as u32
    }

    /// Total packets expected.
    fn expected(&self) -> u32 {
        if !self.seq_initialized {
            return 0;
        }
        self.extended_max_seq() - self.base_seq as u32 + 1
    }

    /// Cumulative packets lost.
    fn cumulative_lost(&self) -> u32 {
        self.expected().saturating_sub(self.packets_received)
    }

    /// Fraction lost since last RR (0-255 scale).
    fn fraction_lost(&mut self) -> u8 {
        let expected = self.expected();
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        let received_interval = self.packets_received.wrapping_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = self.packets_received;

        if expected_interval == 0 || received_interval >= expected_interval {
            0
        } else {
            let lost_interval = expected_interval - received_interval;
            ((lost_interval * 256) / expected_interval).min(255) as u8
        }
    }

    /// Delay since last SR in 1/65536 seconds (for DLSR field).
    fn delay_since_last_sr(&self) -> u32 {
        match self.last_sr_recv_time {
            Some(t) => {
                let elapsed = t.elapsed();
                let secs = elapsed.as_secs() as u32;
                let frac = ((elapsed.subsec_nanos() as u64 * 65536) / 1_000_000_000) as u32;
                (secs << 16) | (frac & 0xFFFF)
            }
            None => 0,
        }
    }
}

/// Returns the current time as an NTP timestamp (seconds since 1900, fractional part).
pub fn ntp_now() -> (u32, u32) {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let ntp_sec = (dur.as_secs() + NTP_EPOCH_OFFSET) as u32;
    let ntp_frac = ((dur.subsec_nanos() as u64 * (1u64 << 32)) / 1_000_000_000) as u32;
    (ntp_sec, ntp_frac)
}

/// Builds an RTCP Sender Report packet (RFC 3550 §6.4.1).
///
/// Includes one RR report block if we've received at least one RTP packet.
pub fn build_sr(ssrc: u32, stats: &mut RtcpStats) -> Vec<u8> {
    let has_report = stats.seq_initialized;
    let rc: u8 = if has_report { 1 } else { 0 };

    let (ntp_sec, ntp_frac) = ntp_now();

    // Header + sender info = 28 bytes. Each report block = 24 bytes.
    let length_words = if has_report { 12 } else { 6 }; // (28+24)/4 -1 or 28/4 -1
    let total_len = (length_words + 1) * 4;

    let mut buf = Vec::with_capacity(total_len);

    // RTCP header: V=2, P=0, RC, PT=200.
    buf.push((RTCP_VERSION << 6) | rc);
    buf.push(RTCP_SR);
    buf.extend_from_slice(&(length_words as u16).to_be_bytes());

    // SSRC of sender.
    buf.extend_from_slice(&ssrc.to_be_bytes());

    // NTP timestamp.
    buf.extend_from_slice(&ntp_sec.to_be_bytes());
    buf.extend_from_slice(&ntp_frac.to_be_bytes());

    // RTP timestamp.
    buf.extend_from_slice(&stats.last_rtp_timestamp.to_be_bytes());

    // Sender's packet count & octet count.
    buf.extend_from_slice(&stats.packets_sent.to_be_bytes());
    buf.extend_from_slice(&stats.octets_sent.to_be_bytes());

    // Report block for the remote sender.
    if has_report {
        write_report_block(&mut buf, stats);
    }

    buf
}

/// Builds an RTCP Receiver Report packet (RFC 3550 §6.4.2).
pub fn build_rr(ssrc: u32, stats: &mut RtcpStats) -> Vec<u8> {
    let has_report = stats.seq_initialized;
    let rc: u8 = if has_report { 1 } else { 0 };

    let length_words: u16 = if has_report { 7 } else { 1 }; // (8+24)/4 -1 or 8/4 -1
    let total_len = (length_words as usize + 1) * 4;

    let mut buf = Vec::with_capacity(total_len);

    // RTCP header: V=2, P=0, RC, PT=201.
    buf.push((RTCP_VERSION << 6) | rc);
    buf.push(RTCP_RR);
    buf.extend_from_slice(&length_words.to_be_bytes());

    // SSRC of this receiver.
    buf.extend_from_slice(&ssrc.to_be_bytes());

    if has_report {
        write_report_block(&mut buf, stats);
    }

    buf
}

/// Writes a 24-byte report block into the buffer.
fn write_report_block(buf: &mut Vec<u8>, stats: &mut RtcpStats) {
    // SSRC_n (source being reported).
    buf.extend_from_slice(&stats.remote_ssrc.to_be_bytes());

    let fraction_lost = stats.fraction_lost();
    let cumulative_lost = stats.cumulative_lost();

    // Fraction lost (8 bits) + cumulative lost (24 bits).
    buf.push(fraction_lost);
    // Cumulative lost is a 24-bit signed integer; we clamp to 0x7FFFFF.
    let cum_24 = cumulative_lost.min(0x7FFFFF);
    buf.push(((cum_24 >> 16) & 0xFF) as u8);
    buf.push(((cum_24 >> 8) & 0xFF) as u8);
    buf.push((cum_24 & 0xFF) as u8);

    // Extended highest sequence number received.
    buf.extend_from_slice(&stats.extended_max_seq().to_be_bytes());

    // Interarrival jitter.
    buf.extend_from_slice(&(stats.jitter as u32).to_be_bytes());

    // Last SR (LSR): middle 32 bits of NTP timestamp from last received SR.
    buf.extend_from_slice(&stats.last_sr_ntp_middle.to_be_bytes());

    // Delay since last SR (DLSR).
    buf.extend_from_slice(&stats.delay_since_last_sr().to_be_bytes());
}

/// A parsed RTCP report block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: u32,
    pub highest_seq: u32,
    pub jitter: u32,
    pub last_sr: u32,
    pub delay_since_sr: u32,
}

/// A parsed RTCP packet.
#[derive(Debug, Clone)]
pub enum RtcpPacket {
    SenderReport {
        ssrc: u32,
        ntp_sec: u32,
        ntp_frac: u32,
        rtp_timestamp: u32,
        packet_count: u32,
        octet_count: u32,
        reports: Vec<ReportBlock>,
    },
    ReceiverReport {
        ssrc: u32,
        reports: Vec<ReportBlock>,
    },
}

/// Parses an RTCP packet from raw bytes. Returns `None` for unknown types or truncated data.
pub fn parse_rtcp(data: &[u8]) -> Option<RtcpPacket> {
    if data.len() < 8 {
        return None;
    }

    let version = (data[0] >> 6) & 0x03;
    if version != RTCP_VERSION {
        return None;
    }

    let rc = data[0] & 0x1F;
    let pt = data[1];
    let _length_words = u16::from_be_bytes([data[2], data[3]]) as usize;

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    match pt {
        RTCP_SR => {
            // SR header is 28 bytes + 24 per report block.
            if data.len() < 28 {
                return None;
            }
            let ntp_sec = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let ntp_frac = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
            let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

            let reports = parse_report_blocks(&data[28..], rc);

            Some(RtcpPacket::SenderReport {
                ssrc,
                ntp_sec,
                ntp_frac,
                rtp_timestamp,
                packet_count,
                octet_count,
                reports,
            })
        }
        RTCP_RR => {
            let reports = parse_report_blocks(&data[8..], rc);
            Some(RtcpPacket::ReceiverReport { ssrc, reports })
        }
        _ => None,
    }
}

/// Parses `count` report blocks from the given slice.
fn parse_report_blocks(data: &[u8], count: u8) -> Vec<ReportBlock> {
    let mut blocks = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let offset = i * 24;
        if offset + 24 > data.len() {
            break;
        }
        let b = &data[offset..offset + 24];
        blocks.push(ReportBlock {
            ssrc: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            fraction_lost: b[4],
            cumulative_lost: ((b[5] as u32) << 16) | ((b[6] as u32) << 8) | b[7] as u32,
            highest_seq: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            jitter: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            last_sr: u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
            delay_since_sr: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
        });
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RtpHeader, RtpPacket};

    #[test]
    fn ntp_timestamp_reasonable() {
        let (sec, frac) = ntp_now();
        // NTP timestamp for 2024-01-01 is ~3,913,056,000.
        assert!(sec > 3_900_000_000, "NTP sec {} too low", sec);
        // Fractional part should be < 2^32.
        let _ = frac; // just ensure it doesn't panic
    }

    #[test]
    fn build_sr_no_report_block() {
        let mut stats = RtcpStats::new();
        stats.packets_sent = 100;
        stats.octets_sent = 16000;
        stats.last_rtp_timestamp = 320000;

        let sr = build_sr(0xDEADBEEF, &mut stats);
        assert_eq!(sr.len(), 28); // No report block.

        // Version=2, RC=0, PT=200.
        assert_eq!((sr[0] >> 6) & 0x03, 2);
        assert_eq!(sr[0] & 0x1F, 0);
        assert_eq!(sr[1], 200);

        // SSRC.
        assert_eq!(u32::from_be_bytes([sr[4], sr[5], sr[6], sr[7]]), 0xDEADBEEF);

        // Packet count.
        assert_eq!(u32::from_be_bytes([sr[20], sr[21], sr[22], sr[23]]), 100);
        // Octet count.
        assert_eq!(u32::from_be_bytes([sr[24], sr[25], sr[26], sr[27]]), 16000);
    }

    #[test]
    fn build_sr_with_report_block() {
        let mut stats = RtcpStats::new();
        stats.packets_sent = 50;
        stats.octets_sent = 8000;
        stats.last_rtp_timestamp = 160000;

        // Simulate receiving some packets to populate report block.
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 0,
                sequence_number: 42,
                timestamp: 6720,
                ssrc: 0xCAFEBABE,
            },
            payload: vec![0; 160],
        };
        stats.record_rtp_received(&pkt, 8000);

        let sr = build_sr(0x12345678, &mut stats);
        assert_eq!(sr.len(), 52); // 28 + 24.

        // RC=1.
        assert_eq!(sr[0] & 0x1F, 1);

        // Report block SSRC.
        assert_eq!(
            u32::from_be_bytes([sr[28], sr[29], sr[30], sr[31]]),
            0xCAFEBABE
        );
    }

    #[test]
    fn build_rr_format() {
        let mut stats = RtcpStats::new();
        let rr = build_rr(0xABCD1234, &mut stats);
        assert_eq!(rr.len(), 8); // No report block.

        assert_eq!((rr[0] >> 6) & 0x03, 2);
        assert_eq!(rr[0] & 0x1F, 0);
        assert_eq!(rr[1], 201);
        assert_eq!(u32::from_be_bytes([rr[4], rr[5], rr[6], rr[7]]), 0xABCD1234);
    }

    #[test]
    fn build_rr_with_report_block() {
        let mut stats = RtcpStats::new();
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 0,
                sequence_number: 10,
                timestamp: 1600,
                ssrc: 0x11111111,
            },
            payload: vec![0; 160],
        };
        stats.record_rtp_received(&pkt, 8000);

        let rr = build_rr(0x22222222, &mut stats);
        assert_eq!(rr.len(), 32); // 8 + 24.
        assert_eq!(rr[0] & 0x1F, 1); // RC=1.
    }

    #[test]
    fn parse_sr() {
        let mut stats = RtcpStats::new();
        stats.packets_sent = 200;
        stats.octets_sent = 32000;
        stats.last_rtp_timestamp = 640000;

        let sr = build_sr(0xAAAAAAAA, &mut stats);
        let parsed = parse_rtcp(&sr).unwrap();

        match parsed {
            RtcpPacket::SenderReport {
                ssrc,
                packet_count,
                octet_count,
                rtp_timestamp,
                reports,
                ..
            } => {
                assert_eq!(ssrc, 0xAAAAAAAA);
                assert_eq!(packet_count, 200);
                assert_eq!(octet_count, 32000);
                assert_eq!(rtp_timestamp, 640000);
                assert!(reports.is_empty());
            }
            _ => panic!("expected SenderReport"),
        }
    }

    #[test]
    fn parse_rr() {
        let mut stats = RtcpStats::new();
        let rr = build_rr(0xBBBBBBBB, &mut stats);
        let parsed = parse_rtcp(&rr).unwrap();

        match parsed {
            RtcpPacket::ReceiverReport { ssrc, reports } => {
                assert_eq!(ssrc, 0xBBBBBBBB);
                assert!(reports.is_empty());
            }
            _ => panic!("expected ReceiverReport"),
        }
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_rtcp(&[]).is_none());
        assert!(parse_rtcp(&[0x80, 200, 0, 0]).is_none()); // Only 4 bytes.
    }

    #[test]
    fn parse_unknown_pt() {
        // Build a fake packet with PT=202 (SDES).
        let data = [0x80, 202, 0, 1, 0, 0, 0, 0];
        assert!(parse_rtcp(&data).is_none());
    }

    #[test]
    fn parse_bad_version() {
        // Version=1 instead of 2.
        let data = [
            0x40, 200, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_rtcp(&data).is_none());
    }

    #[test]
    fn record_rtp_sent() {
        let mut stats = RtcpStats::new();
        stats.record_rtp_sent(160, 0);
        stats.record_rtp_sent(160, 160);
        stats.record_rtp_sent(160, 320);

        assert_eq!(stats.packets_sent, 3);
        assert_eq!(stats.octets_sent, 480);
        assert_eq!(stats.last_rtp_timestamp, 320);
    }

    #[test]
    fn record_rtp_received_seq_tracking() {
        let mut stats = RtcpStats::new();

        // Send packets 0..5 in order.
        for seq in 0..5u16 {
            let pkt = RtpPacket {
                header: RtpHeader {
                    version: 2,
                    marker: false,
                    payload_type: 0,
                    sequence_number: seq,
                    timestamp: seq as u32 * 160,
                    ssrc: 1234,
                },
                payload: vec![0; 160],
            };
            stats.record_rtp_received(&pkt, 8000);
        }

        assert_eq!(stats.packets_received, 5);
        assert_eq!(stats.max_seq, 4);
        assert_eq!(stats.base_seq, 0);
        assert_eq!(stats.cycles, 0);
        assert_eq!(stats.extended_max_seq(), 4);
    }

    #[test]
    fn seq_wraparound() {
        let mut stats = RtcpStats::new();

        // Start near the end of u16 range.
        for seq in [65534u16, 65535, 0, 1, 2] {
            let pkt = RtpPacket {
                header: RtpHeader {
                    version: 2,
                    marker: false,
                    payload_type: 0,
                    sequence_number: seq,
                    timestamp: 0,
                    ssrc: 1234,
                },
                payload: vec![],
            };
            stats.record_rtp_received(&pkt, 0);
        }

        assert_eq!(stats.max_seq, 2);
        assert_eq!(stats.cycles, 1);
        // Extended: (1 << 16) | 2 = 65538.
        assert_eq!(stats.extended_max_seq(), 65538);
    }

    #[test]
    fn loss_fraction_calculation() {
        let mut stats = RtcpStats::new();

        // Receive packets 0, 1, 2, 4, 5 (skip 3).
        for seq in [0u16, 1, 2, 4, 5] {
            let pkt = RtpPacket {
                header: RtpHeader {
                    version: 2,
                    marker: false,
                    payload_type: 0,
                    sequence_number: seq,
                    timestamp: 0,
                    ssrc: 1234,
                },
                payload: vec![],
            };
            stats.record_rtp_received(&pkt, 0);
        }

        assert_eq!(stats.cumulative_lost(), 1);
        assert_eq!(stats.expected(), 6); // 0..=5

        // fraction_lost should be ~42 (1/6 * 256 = 42.67).
        let frac = stats.fraction_lost();
        assert_eq!(frac, 42);
    }

    #[test]
    fn sr_round_trip_build_parse() {
        let mut stats = RtcpStats::new();
        stats.packets_sent = 1000;
        stats.octets_sent = 160000;
        stats.last_rtp_timestamp = 160000;

        // Receive some packets for report block.
        for seq in 0..10u16 {
            let pkt = RtpPacket {
                header: RtpHeader {
                    version: 2,
                    marker: false,
                    payload_type: 0,
                    sequence_number: seq,
                    timestamp: seq as u32 * 160,
                    ssrc: 0xFEEDFACE,
                },
                payload: vec![0; 160],
            };
            stats.record_rtp_received(&pkt, 8000);
        }

        let sr = build_sr(0x99887766, &mut stats);
        let parsed = parse_rtcp(&sr).unwrap();

        match parsed {
            RtcpPacket::SenderReport {
                ssrc,
                packet_count,
                octet_count,
                rtp_timestamp,
                reports,
                ..
            } => {
                assert_eq!(ssrc, 0x99887766);
                assert_eq!(packet_count, 1000);
                assert_eq!(octet_count, 160000);
                assert_eq!(rtp_timestamp, 160000);
                assert_eq!(reports.len(), 1);
                assert_eq!(reports[0].ssrc, 0xFEEDFACE);
                assert_eq!(reports[0].highest_seq, 9);
            }
            _ => panic!("expected SenderReport"),
        }
    }

    #[test]
    fn process_incoming_sr_stores_ntp() {
        let mut stats = RtcpStats::new();
        stats.process_incoming_sr(0xAABBCCDD, 0x11223344);

        // Middle 32 bits: low 16 of sec (0xCCDD) << 16 | high 16 of frac (0x1122).
        assert_eq!(stats.last_sr_ntp_middle, 0xCCDD1122);
        assert!(stats.last_sr_recv_time.is_some());
    }

    #[test]
    fn delay_since_last_sr_zero_when_no_sr() {
        let stats = RtcpStats::new();
        assert_eq!(stats.delay_since_last_sr(), 0);
    }

    #[test]
    fn parse_sr_with_report_block() {
        let mut stats = RtcpStats::new();
        stats.packets_sent = 50;
        stats.octets_sent = 8000;

        // Receive a packet to generate a report block.
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: false,
                payload_type: 0,
                sequence_number: 100,
                timestamp: 16000,
                ssrc: 0x55555555,
            },
            payload: vec![0; 160],
        };
        stats.record_rtp_received(&pkt, 8000);

        let sr = build_sr(0x66666666, &mut stats);
        let parsed = parse_rtcp(&sr).unwrap();

        match parsed {
            RtcpPacket::SenderReport { reports, .. } => {
                assert_eq!(reports.len(), 1);
                assert_eq!(reports[0].ssrc, 0x55555555);
                assert_eq!(reports[0].highest_seq, 100);
                assert_eq!(reports[0].cumulative_lost, 0);
            }
            _ => panic!("expected SenderReport"),
        }
    }
}
