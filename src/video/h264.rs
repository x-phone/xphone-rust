//! H.264 RTP packetizer and depacketizer (RFC 6184).
//!
//! Supports:
//! - Single NAL Unit mode (NAL types 1-23): one NAL per RTP packet
//! - STAP-A (type 24): multiple small NALs aggregated in one RTP packet
//! - FU-A (type 28): a large NAL fragmented across multiple RTP packets
//!
//! Keyframe detection: NAL type 5 (IDR) is treated as a keyframe.
//! SPS (type 7) and PPS (type 8) are prepended to keyframes in output.

use super::{VideoDepacketizer, VideoPacketizer};
use crate::types::{RtpPacket, VideoCodec, VideoFrame};

// NAL unit type constants.
const NAL_TYPE_IDR: u8 = 5;
const NAL_TYPE_SPS: u8 = 7;
const NAL_TYPE_PPS: u8 = 8;
const NAL_TYPE_STAP_A: u8 = 24;
const NAL_TYPE_FU_A: u8 = 28;

/// Annex B start code used to delimit NAL units in output frames.
const START_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];

/// H.264 RTP depacketizer.
///
/// Reassembles RTP packets into Annex-B formatted video frames.
/// Frame boundaries are detected via RTP marker bit + timestamp change.
pub struct H264Depacketizer {
    /// NAL units accumulated for the current frame.
    nals: Vec<Vec<u8>>,
    /// Current frame's RTP timestamp.
    current_ts: u32,
    /// FU-A fragment reassembly buffer.
    fua_buf: Vec<u8>,
    /// FU-A NRI + NAL type from the first fragment.
    fua_nri: u8,
    /// Whether we are in the middle of FU-A reassembly.
    fua_active: bool,
    /// Whether any NAL in the current frame is an IDR.
    has_idr: bool,
    /// Cached SPS NAL for prepending to keyframes.
    sps: Option<Vec<u8>>,
    /// Cached PPS NAL for prepending to keyframes.
    pps: Option<Vec<u8>>,
    /// Whether we have received a first packet (to initialize timestamp).
    started: bool,
}

impl Default for H264Depacketizer {
    fn default() -> Self {
        Self::new()
    }
}

impl H264Depacketizer {
    pub fn new() -> Self {
        Self {
            nals: Vec::new(),
            current_ts: 0,
            fua_buf: Vec::new(),
            fua_nri: 0,
            fua_active: false,
            has_idr: false,
            sps: None,
            pps: None,
            started: false,
        }
    }

    fn emit_frame(&mut self) -> Option<VideoFrame> {
        if self.nals.is_empty() {
            return None;
        }
        let keyframe = self.has_idr;
        let total: usize = self.nals.iter().map(|n| START_CODE.len() + n.len()).sum();
        let mut data = Vec::with_capacity(total + 2 * (START_CODE.len() + 64));

        // Prepend SPS/PPS before IDR frames if we have them cached.
        if keyframe {
            if let Some(ref sps) = self.sps {
                data.extend_from_slice(START_CODE);
                data.extend_from_slice(sps);
            }
            if let Some(ref pps) = self.pps {
                data.extend_from_slice(START_CODE);
                data.extend_from_slice(pps);
            }
        }

        for nal in self.nals.drain(..) {
            let nal_type = nal[0] & 0x1F;
            // Skip SPS/PPS in the NAL list — already prepended above.
            if keyframe && (nal_type == NAL_TYPE_SPS || nal_type == NAL_TYPE_PPS) {
                continue;
            }
            data.extend_from_slice(START_CODE);
            data.extend_from_slice(&nal);
        }

        self.has_idr = false;

        if data.is_empty() {
            return None;
        }

        Some(VideoFrame {
            codec: VideoCodec::H264,
            keyframe,
            timestamp: self.current_ts,
            data,
        })
    }

    fn process_nal(&mut self, nal: &[u8]) {
        if nal.is_empty() {
            return;
        }
        let nal_type = nal[0] & 0x1F;
        match nal_type {
            NAL_TYPE_SPS => {
                let v = nal.to_vec();
                self.sps = Some(v.clone());
                self.nals.push(v);
            }
            NAL_TYPE_PPS => {
                let v = nal.to_vec();
                self.pps = Some(v.clone());
                self.nals.push(v);
            }
            NAL_TYPE_IDR => {
                self.has_idr = true;
                self.nals.push(nal.to_vec());
            }
            _ => {
                self.nals.push(nal.to_vec());
            }
        }
    }
}

impl VideoDepacketizer for H264Depacketizer {
    fn depacketize(&mut self, pkt: &RtpPacket) -> Option<VideoFrame> {
        if pkt.payload.is_empty() {
            return None;
        }

        // Detect timestamp change → emit buffered frame.
        let mut result = None;
        if self.started && pkt.header.timestamp != self.current_ts {
            if !self.nals.is_empty() {
                result = self.emit_frame();
            }
            // Discard incomplete FU-A reassembly from previous frame.
            if self.fua_active {
                self.fua_buf.clear();
                self.fua_active = false;
            }
        }
        self.current_ts = pkt.header.timestamp;
        self.started = true;

        let first_byte = pkt.payload[0];
        let nal_type = first_byte & 0x1F;

        match nal_type {
            1..=23 => {
                // Single NAL Unit — the entire payload is one NAL.
                self.process_nal(&pkt.payload);
            }
            NAL_TYPE_STAP_A => {
                // STAP-A: multiple NALs aggregated.
                // Format: [STAP-A byte] [2-byte size | NAL] [2-byte size | NAL] ...
                let mut offset = 1; // skip STAP-A indicator
                while offset + 2 <= pkt.payload.len() {
                    let size =
                        u16::from_be_bytes([pkt.payload[offset], pkt.payload[offset + 1]]) as usize;
                    offset += 2;
                    if size == 0 || offset + size > pkt.payload.len() {
                        break;
                    }
                    self.process_nal(&pkt.payload[offset..offset + size]);
                    offset += size;
                }
            }
            NAL_TYPE_FU_A => {
                // FU-A: fragmented NAL.
                // Format: [FU indicator] [FU header] [payload...]
                if pkt.payload.len() < 2 {
                    return result;
                }
                let fu_header = pkt.payload[1];
                let start = (fu_header & 0x80) != 0;
                let end = (fu_header & 0x40) != 0;
                let frag_type = fu_header & 0x1F;

                if start {
                    // Reconstruct the NAL header: NRI from FU indicator + type from FU header.
                    self.fua_nri = first_byte & 0xE0;
                    self.fua_buf.clear();
                    self.fua_buf.push(self.fua_nri | frag_type);
                    self.fua_buf.extend_from_slice(&pkt.payload[2..]);
                    self.fua_active = true;
                } else if self.fua_active {
                    self.fua_buf.extend_from_slice(&pkt.payload[2..]);
                }

                if end && self.fua_active {
                    self.process_nal(&self.fua_buf.clone());
                    self.fua_buf.clear(); // retain capacity for next FU-A
                    self.fua_active = false;
                }
            }
            _ => {
                // Unknown NAL type — skip.
            }
        }

        // Marker bit signals end of frame.
        if pkt.header.marker && !self.nals.is_empty() {
            return self.emit_frame().or(result);
        }

        result
    }
}

/// H.264 RTP packetizer.
///
/// Fragments Annex-B video frames into RTP payloads:
/// - NALs <= MTU: sent as Single NAL unit
/// - NALs > MTU: fragmented using FU-A
pub struct H264Packetizer;

impl Default for H264Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

impl H264Packetizer {
    pub fn new() -> Self {
        Self
    }
}

impl VideoPacketizer for H264Packetizer {
    fn packetize(&mut self, frame: &VideoFrame, mtu: usize) -> Vec<Vec<u8>> {
        if frame.data.is_empty() || mtu < 3 {
            return Vec::new();
        }

        let nals = extract_nals(&frame.data);
        let mut payloads = Vec::with_capacity(nals.len());

        for nal in &nals {
            if nal.is_empty() {
                continue;
            }
            if nal.len() <= mtu {
                // Single NAL unit — payload is just the NAL.
                payloads.push(nal.to_vec());
            } else {
                // FU-A fragmentation.
                let nri = nal[0] & 0xE0;
                let nal_type = nal[0] & 0x1F;
                let fu_indicator = nri | NAL_TYPE_FU_A;

                let frag_data = &nal[1..]; // skip original NAL header
                let max_frag = mtu - 2; // 2 bytes for FU indicator + FU header
                let mut offset = 0;
                let mut first = true;

                while offset < frag_data.len() {
                    let end_offset = (offset + max_frag).min(frag_data.len());
                    let last = end_offset == frag_data.len();

                    let mut fu_header = nal_type;
                    if first {
                        fu_header |= 0x80; // S bit
                    }
                    if last {
                        fu_header |= 0x40; // E bit
                    }

                    let mut payload = Vec::with_capacity(2 + (end_offset - offset));
                    payload.push(fu_indicator);
                    payload.push(fu_header);
                    payload.extend_from_slice(&frag_data[offset..end_offset]);

                    payloads.push(payload);
                    offset = end_offset;
                    first = false;
                }
            }
        }

        payloads
    }
}

/// Extracts individual NAL units from an Annex-B byte stream.
/// Handles both 3-byte (00 00 01) and 4-byte (00 00 00 01) start codes.
/// Returns slices borrowing from the input data to avoid allocations.
fn extract_nals(data: &[u8]) -> Vec<&[u8]> {
    let mut nals = Vec::new();
    let mut i = 0;
    let len = data.len();

    // Skip to the first start code.
    while i < len {
        if i + 3 <= len && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            i += 3;
            break;
        }
        if i + 4 <= len && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1
        {
            i += 4;
            break;
        }
        i += 1;
    }

    let mut nal_start = i;

    while i < len {
        // Look for next start code.
        if i + 3 <= len && data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                // 3-byte start code.
                if i > nal_start {
                    nals.push(&data[nal_start..i]);
                }
                i += 3;
                nal_start = i;
                continue;
            }
            if i + 4 <= len && data[i + 2] == 0 && data[i + 3] == 1 {
                // 4-byte start code.
                if i > nal_start {
                    nals.push(&data[nal_start..i]);
                }
                i += 4;
                nal_start = i;
                continue;
            }
        }
        i += 1;
    }

    // Remaining data after last start code.
    if nal_start < len {
        nals.push(&data[nal_start..len]);
    }

    nals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RtpHeader;

    fn make_rtp(payload: Vec<u8>, ts: u32, marker: bool, seq: u16) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                marker,
                payload_type: 96,
                sequence_number: seq,
                timestamp: ts,
                ssrc: 1234,
            },
            payload,
        }
    }

    // --- extract_nals ---

    #[test]
    fn extract_nals_annex_b() {
        // Two NALs with 4-byte start codes.
        let mut data = Vec::new();
        data.extend_from_slice(START_CODE);
        data.push(0x67); // SPS (NAL type 7)
        data.extend_from_slice(&[0x42, 0x00, 0x1f]);
        data.extend_from_slice(START_CODE);
        data.push(0x68); // PPS (NAL type 8)
        data.extend_from_slice(&[0xce, 0x38, 0x80]);

        let nals = extract_nals(&data);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0][0] & 0x1F, NAL_TYPE_SPS);
        assert_eq!(nals[1][0] & 0x1F, NAL_TYPE_PPS);
    }

    #[test]
    fn extract_nals_3byte_start_code() {
        let data = [0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB]; // IDR
        let nals = extract_nals(&data);
        assert_eq!(nals.len(), 1);
        assert_eq!(nals[0], vec![0x65, 0xAA, 0xBB]);
    }

    // --- Single NAL ---

    #[test]
    fn single_nal_depacketize() {
        let mut depkt = H264Depacketizer::new();
        // NAL type 1 (non-IDR slice), marker set.
        let nal = vec![0x41, 0x01, 0x02, 0x03]; // type 1
        let pkt = make_rtp(nal.clone(), 1000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(!frame.keyframe);
        assert_eq!(frame.timestamp, 1000);
        // Output should be start code + NAL.
        assert!(frame.data.starts_with(START_CODE));
        assert_eq!(&frame.data[4..], &nal[..]);
    }

    #[test]
    fn single_nal_idr_is_keyframe() {
        let mut depkt = H264Depacketizer::new();
        let nal = vec![0x65, 0xFF, 0xFE]; // NAL type 5 = IDR
        let pkt = make_rtp(nal, 2000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(frame.keyframe);
    }

    // --- STAP-A ---

    #[test]
    fn stap_a_depacketize() {
        let mut depkt = H264Depacketizer::new();
        // STAP-A containing SPS + PPS + IDR.
        let sps = vec![0x67, 0x42, 0x00, 0x1f]; // NAL type 7
        let pps = vec![0x68, 0xce, 0x38, 0x80]; // NAL type 8
        let idr = vec![0x65, 0xAA]; // NAL type 5

        let mut payload = vec![NAL_TYPE_STAP_A]; // STAP-A indicator
                                                 // SPS
        payload.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        payload.extend_from_slice(&sps);
        // PPS
        payload.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        payload.extend_from_slice(&pps);
        // IDR
        payload.extend_from_slice(&(idr.len() as u16).to_be_bytes());
        payload.extend_from_slice(&idr);

        let pkt = make_rtp(payload, 3000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp, 3000);
        // Should contain start_code + SPS + start_code + PPS + start_code + IDR.
        assert!(frame.data.len() > 12);
    }

    #[test]
    fn stap_a_zero_length_nal_does_not_loop() {
        let mut depkt = H264Depacketizer::new();
        // STAP-A with a zero-length NAL size field — must not infinite loop.
        let payload = vec![
            NAL_TYPE_STAP_A, // STAP-A indicator
            0x00,
            0x00, // NAL size = 0 (malformed)
            0x00,
            0x03, // next NAL size = 3
            0x41,
            0x01,
            0x02, // NAL data
        ];
        let pkt = make_rtp(payload, 9000, true, 1);
        // Should not hang — breaks on zero-length NAL.
        let frame = depkt.depacketize(&pkt);
        // The zero-length NAL breaks parsing, so we get no NALs from this packet.
        assert!(frame.is_none());
    }

    // --- FU-A ---

    #[test]
    fn fua_reassembly() {
        let mut depkt = H264Depacketizer::new();
        // Fragment a NAL type 5 (IDR) into 3 FU-A packets.
        let original_nal = vec![0x65, 0x01, 0x02, 0x03, 0x04, 0x05]; // IDR
        let nri = original_nal[0] & 0xE0; // 0x60
        let nal_type = original_nal[0] & 0x1F; // 5

        // Fragment 1 (start).
        let mut p1 = vec![nri | NAL_TYPE_FU_A]; // FU indicator
        p1.push(0x80 | nal_type); // FU header: S=1
        p1.extend_from_slice(&original_nal[1..3]); // first 2 bytes of body
        let pkt1 = make_rtp(p1, 4000, false, 1);

        // Fragment 2 (middle).
        let mut p2 = vec![nri | NAL_TYPE_FU_A];
        p2.push(nal_type); // FU header: S=0, E=0
        p2.extend_from_slice(&original_nal[3..5]);
        let pkt2 = make_rtp(p2, 4000, false, 2);

        // Fragment 3 (end).
        let mut p3 = vec![nri | NAL_TYPE_FU_A];
        p3.push(0x40 | nal_type); // FU header: E=1
        p3.extend_from_slice(&original_nal[5..]);
        let pkt3 = make_rtp(p3, 4000, true, 3); // marker = end of frame

        assert!(depkt.depacketize(&pkt1).is_none());
        assert!(depkt.depacketize(&pkt2).is_none());
        let frame = depkt.depacketize(&pkt3).unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp, 4000);
        // Verify reconstructed NAL.
        assert!(frame.data.starts_with(START_CODE));
    }

    // --- Packetizer ---

    #[test]
    fn packetize_small_nal() {
        let mut pkt = H264Packetizer::new();
        // Single small NAL.
        let mut data = Vec::new();
        data.extend_from_slice(START_CODE);
        data.extend_from_slice(&[0x41, 0x01, 0x02]);
        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: false,
            timestamp: 100,
            data,
        };
        let payloads = pkt.packetize(&frame, 1200);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], vec![0x41, 0x01, 0x02]);
    }

    #[test]
    fn packetize_fua_fragmentation() {
        let mut pkt = H264Packetizer::new();
        // NAL larger than MTU.
        let mut data = Vec::new();
        data.extend_from_slice(START_CODE);
        let mut nal = vec![0x65]; // IDR
        nal.extend_from_slice(&vec![0xAA; 100]); // 101 bytes total
        data.extend_from_slice(&nal);

        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: true,
            timestamp: 200,
            data,
        };
        let payloads = pkt.packetize(&frame, 50);
        assert!(payloads.len() > 1);

        // First fragment should have S bit.
        assert_eq!(payloads[0][0] & 0x1F, NAL_TYPE_FU_A);
        assert_ne!(payloads[0][1] & 0x80, 0); // S bit set

        // Last fragment should have E bit.
        let last = payloads.last().unwrap();
        assert_ne!(last[1] & 0x40, 0); // E bit set

        // Middle fragments should have neither.
        if payloads.len() > 2 {
            assert_eq!(payloads[1][1] & 0xC0, 0);
        }
    }

    // --- Round-trip ---

    #[test]
    fn packetize_depacketize_round_trip() {
        let mut packetizer = H264Packetizer::new();
        let mut depacketizer = H264Depacketizer::new();

        // Create a frame with SPS + PPS + IDR.
        let mut data = Vec::new();
        data.extend_from_slice(START_CODE);
        data.extend_from_slice(&[0x67, 0x42, 0x00, 0x1f]); // SPS
        data.extend_from_slice(START_CODE);
        data.extend_from_slice(&[0x68, 0xce, 0x38, 0x80]); // PPS
        data.extend_from_slice(START_CODE);
        let mut idr = vec![0x65]; // IDR
        idr.extend_from_slice(&vec![0xBB; 50]);
        data.extend_from_slice(&idr);

        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: true,
            timestamp: 9000,
            data: data.clone(),
        };

        let payloads = packetizer.packetize(&frame, 1200);
        assert!(!payloads.is_empty());

        // Feed all payloads as RTP packets.
        let mut result = None;
        for (i, pl) in payloads.iter().enumerate() {
            let marker = i == payloads.len() - 1;
            let pkt = make_rtp(pl.clone(), 9000, marker, i as u16);
            if let Some(f) = depacketizer.depacketize(&pkt) {
                result = Some(f);
            }
        }

        let out = result.unwrap();
        assert!(out.keyframe);
        assert_eq!(out.timestamp, 9000);
        // Output should contain SPS, PPS, IDR NALs.
        assert!(out.data.len() > 10);
    }

    #[test]
    fn packetize_depacketize_non_idr_round_trip() {
        let mut packetizer = H264Packetizer::new();
        let mut depacketizer = H264Depacketizer::new();

        let mut data = Vec::new();
        data.extend_from_slice(START_CODE);
        data.extend_from_slice(&[0x41, 0x01, 0x02, 0x03]); // non-IDR slice

        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: false,
            timestamp: 10000,
            data,
        };

        let payloads = packetizer.packetize(&frame, 1200);
        let mut result = None;
        for (i, pl) in payloads.iter().enumerate() {
            let marker = i == payloads.len() - 1;
            let pkt = make_rtp(pl.clone(), 10000, marker, i as u16);
            if let Some(f) = depacketizer.depacketize(&pkt) {
                result = Some(f);
            }
        }
        let out = result.unwrap();
        assert!(!out.keyframe);
    }

    #[test]
    fn multi_frame_depacketize() {
        let mut depkt = H264Depacketizer::new();

        // Frame 1 at ts=1000.
        let pkt1 = make_rtp(vec![0x41, 0x01], 1000, true, 1);
        let f1 = depkt.depacketize(&pkt1).unwrap();
        assert_eq!(f1.timestamp, 1000);

        // Frame 2 at ts=2000 (timestamp change triggers emit of previous).
        let pkt2 = make_rtp(vec![0x41, 0x02], 2000, true, 2);
        let f2 = depkt.depacketize(&pkt2).unwrap();
        assert_eq!(f2.timestamp, 2000);
    }

    #[test]
    fn sps_pps_cached_and_prepended() {
        let mut depkt = H264Depacketizer::new();

        // First: send SPS + PPS in a STAP-A, non-IDR.
        let sps = vec![0x67, 0x42, 0x00, 0x1f];
        let pps = vec![0x68, 0xce, 0x38];
        let mut stap = vec![NAL_TYPE_STAP_A];
        stap.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        stap.extend_from_slice(&sps);
        stap.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        stap.extend_from_slice(&pps);
        let pkt1 = make_rtp(stap, 1000, true, 1);
        let _f1 = depkt.depacketize(&pkt1);

        // Second: IDR at different timestamp — should get SPS+PPS prepended.
        let idr = vec![0x65, 0xAA, 0xBB];
        let pkt2 = make_rtp(idr, 2000, true, 2);
        let frame = depkt.depacketize(&pkt2).unwrap();
        assert!(frame.keyframe);
        // Check SPS is at the start.
        assert!(frame.data.starts_with(START_CODE));
        // Should contain SPS bytes.
        let sps_pos = frame.data.windows(4).position(|w| w == &sps[..4]);
        assert!(sps_pos.is_some());
    }

    #[test]
    fn empty_payload_ignored() {
        let mut depkt = H264Depacketizer::new();
        let pkt = make_rtp(vec![], 1000, true, 1);
        assert!(depkt.depacketize(&pkt).is_none());
    }

    #[test]
    fn packetize_empty_frame() {
        let mut pkt = H264Packetizer::new();
        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: false,
            timestamp: 0,
            data: Vec::new(),
        };
        assert!(pkt.packetize(&frame, 1200).is_empty());
    }
}
