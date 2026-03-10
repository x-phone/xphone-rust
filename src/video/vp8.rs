//! VP8 RTP packetizer and depacketizer (RFC 7741).
//!
//! VP8 RTP payload format:
//! ```text
//! [Required] 1 byte: X R N S PartID(4)
//! [Optional] 1 byte: I L T K RSV (if X=1)
//! [Optional] 1-2 bytes: PictureID (if I=1)
//! [Optional] 1 byte: TL0PICIDX (if L=1)
//! [Optional] 1 byte: TID Y KEYIDX (if T=1 or K=1)
//! [VP8 payload data]
//! ```
//!
//! Keyframe detection: VP8 frame header byte 0 bit 0 (P bit) = 0 means keyframe.

use super::{VideoDepacketizer, VideoPacketizer};
use crate::types::{RtpPacket, VideoCodec, VideoFrame};

/// VP8 RTP depacketizer.
///
/// Reassembles VP8 RTP packets into complete video frames.
/// Frame boundaries: marker bit (end) + S bit (start of new partition).
pub struct Vp8Depacketizer {
    /// Fragment buffer for the current frame.
    buf: Vec<u8>,
    /// Current frame timestamp.
    current_ts: u32,
    /// Whether the current frame is a keyframe (detected from first fragment).
    keyframe: bool,
    /// Whether we have started receiving.
    started: bool,
}

impl Default for Vp8Depacketizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Vp8Depacketizer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            current_ts: 0,
            keyframe: false,
            started: false,
        }
    }

    fn emit_frame(&mut self) -> Option<VideoFrame> {
        if self.buf.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.buf);
        Some(VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: self.keyframe,
            timestamp: self.current_ts,
            data,
        })
    }
}

impl VideoDepacketizer for Vp8Depacketizer {
    fn depacketize(&mut self, pkt: &RtpPacket) -> Option<VideoFrame> {
        if pkt.payload.is_empty() {
            return None;
        }

        // Detect timestamp change → emit buffered frame.
        let mut result = None;
        if self.started && pkt.header.timestamp != self.current_ts && !self.buf.is_empty() {
            result = self.emit_frame();
        }
        self.current_ts = pkt.header.timestamp;
        self.started = true;

        // Parse VP8 payload descriptor.
        let mut offset = 0;
        let first_byte = pkt.payload[offset];
        offset += 1;

        let x = (first_byte & 0x80) != 0; // Extension bit
        let s = (first_byte & 0x10) != 0; // Start of VP8 partition

        if x && offset < pkt.payload.len() {
            let ext_byte = pkt.payload[offset];
            offset += 1;

            let i = (ext_byte & 0x80) != 0; // PictureID present
            let l = (ext_byte & 0x40) != 0; // TL0PICIDX present
            let t_or_k = (ext_byte & 0x20) != 0 || (ext_byte & 0x10) != 0;

            // PictureID
            if i && offset < pkt.payload.len() {
                if (pkt.payload[offset] & 0x80) != 0 {
                    // 16-bit PictureID (M bit set) — need 2 bytes.
                    if offset + 2 <= pkt.payload.len() {
                        offset += 2;
                    } else {
                        return result; // truncated packet
                    }
                } else {
                    offset += 1;
                }
            }

            // TL0PICIDX
            if l {
                offset += 1;
            }

            // TID/Y/KEYIDX
            if t_or_k {
                offset += 1;
            }
        }

        if offset > pkt.payload.len() {
            return result;
        }

        let vp8_data = &pkt.payload[offset..];

        // On the first partition (S=1), detect keyframe.
        if s {
            if !vp8_data.is_empty() {
                // VP8 frame header: bit 0 of first byte = P (0=keyframe, 1=interframe).
                self.keyframe = (vp8_data[0] & 0x01) == 0;
            }
            // If we had a partial frame from a different partition, discard it.
            if !self.buf.is_empty() && result.is_none() {
                // Incomplete previous frame — discard.
                self.buf.clear();
            }
        }

        self.buf.extend_from_slice(vp8_data);

        // Marker bit signals end of frame.
        if pkt.header.marker && !self.buf.is_empty() {
            return self.emit_frame().or(result);
        }

        result
    }
}

/// VP8 RTP packetizer.
///
/// Fragments VP8 frames into MTU-sized RTP payloads with VP8 payload descriptors.
pub struct Vp8Packetizer;

impl Default for Vp8Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Vp8Packetizer {
    pub fn new() -> Self {
        Self
    }
}

impl VideoPacketizer for Vp8Packetizer {
    fn packetize(&mut self, frame: &VideoFrame, mtu: usize) -> Vec<Vec<u8>> {
        if frame.data.is_empty() || mtu < 2 {
            return Vec::new();
        }

        let num_fragments = (frame.data.len() + mtu - 2) / (mtu - 1);
        let mut payloads = Vec::with_capacity(num_fragments);
        let max_payload = mtu - 1; // 1 byte for VP8 payload descriptor
        let mut offset = 0;
        let mut first = true;

        while offset < frame.data.len() {
            let end = (offset + max_payload).min(frame.data.len());

            let mut payload = Vec::with_capacity(1 + (end - offset));

            // VP8 payload descriptor: X=0, R=0, N=0, S=first, PartID=0.
            let desc = if first { 0x10 } else { 0x00 };
            payload.push(desc);
            payload.extend_from_slice(&frame.data[offset..end]);

            payloads.push(payload);
            offset = end;
            first = false;
        }

        payloads
    }
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
                payload_type: 97,
                sequence_number: seq,
                timestamp: ts,
                ssrc: 5678,
            },
            payload,
        }
    }

    // --- Depacketizer ---

    #[test]
    fn single_packet_keyframe() {
        let mut depkt = Vp8Depacketizer::new();
        // VP8 descriptor: S=1 (start), no extensions.
        // VP8 data: first byte bit 0 = 0 → keyframe.
        let payload = vec![0x10, 0x9C, 0x01, 0x02]; // desc=0x10(S=1), data starts with 0x9C (P=0→key)
        let pkt = make_rtp(payload, 1000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp, 1000);
        assert_eq!(frame.data, vec![0x9C, 0x01, 0x02]);
    }

    #[test]
    fn single_packet_interframe() {
        let mut depkt = Vp8Depacketizer::new();
        // VP8 data: bit 0 = 1 → interframe.
        let payload = vec![0x10, 0x01, 0xAA]; // P=1 → not keyframe
        let pkt = make_rtp(payload, 2000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(!frame.keyframe);
    }

    #[test]
    fn multi_packet_frame() {
        let mut depkt = Vp8Depacketizer::new();
        // Packet 1: S=1, no marker.
        let p1 = vec![0x10, 0x9C, 0x01, 0x02];
        let pkt1 = make_rtp(p1, 3000, false, 1);
        assert!(depkt.depacketize(&pkt1).is_none());

        // Packet 2: S=0, marker.
        let p2 = vec![0x00, 0x03, 0x04];
        let pkt2 = make_rtp(p2, 3000, true, 2);
        let frame = depkt.depacketize(&pkt2).unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.data, vec![0x9C, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn extension_with_picture_id() {
        let mut depkt = Vp8Depacketizer::new();
        // X=1, I=1, 8-bit PictureID.
        let payload = vec![
            0x90, // X=1, S=1
            0x80, // I=1
            0x42, // PictureID (7-bit, M=0)
            0x9C, // VP8 data (keyframe)
            0xAA,
        ];
        let pkt = make_rtp(payload, 4000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.data, vec![0x9C, 0xAA]);
    }

    #[test]
    fn extension_with_16bit_picture_id() {
        let mut depkt = Vp8Depacketizer::new();
        // X=1, I=1, 16-bit PictureID (M=1).
        let payload = vec![
            0x90, // X=1, S=1
            0x80, // I=1
            0x80, 0x42, // PictureID 16-bit (M=1)
            0x01, // VP8 data (interframe, P=1)
            0xBB,
        ];
        let pkt = make_rtp(payload, 5000, true, 1);
        let frame = depkt.depacketize(&pkt).unwrap();
        assert!(!frame.keyframe);
        assert_eq!(frame.data, vec![0x01, 0xBB]);
    }

    // --- Packetizer ---

    #[test]
    fn packetize_small_frame() {
        let mut pkt = Vp8Packetizer::new();
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: true,
            timestamp: 100,
            data: vec![0x9C, 0x01, 0x02],
        };
        let payloads = pkt.packetize(&frame, 1200);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0][0] & 0x10, 0x10); // S bit set
        assert_eq!(&payloads[0][1..], &[0x9C, 0x01, 0x02]);
    }

    #[test]
    fn packetize_fragmentation() {
        let mut pkt = Vp8Packetizer::new();
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: false,
            timestamp: 200,
            data: vec![0x01; 100],
        };
        let payloads = pkt.packetize(&frame, 30); // max_payload = 29 bytes per fragment
        assert!(payloads.len() > 1);
        // First fragment has S=1.
        assert_eq!(payloads[0][0] & 0x10, 0x10);
        // Subsequent fragments have S=0.
        assert_eq!(payloads[1][0] & 0x10, 0x00);
    }

    // --- Round-trip ---

    #[test]
    fn packetize_depacketize_round_trip() {
        let mut packetizer = Vp8Packetizer::new();
        let mut depacketizer = Vp8Depacketizer::new();

        let original_data = vec![0x9C, 0x01, 0x02, 0x03, 0x04, 0x05];
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: true,
            timestamp: 9000,
            data: original_data.clone(),
        };

        let payloads = packetizer.packetize(&frame, 1200);
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
        assert_eq!(out.data, original_data);
    }

    #[test]
    fn packetize_depacketize_fragmented_round_trip() {
        let mut packetizer = Vp8Packetizer::new();
        let mut depacketizer = Vp8Depacketizer::new();

        // First byte must have P=1 (bit 0 set) for interframe.
        let mut original_data: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
        original_data[0] = 0x01; // P=1 → interframe
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: false,
            timestamp: 12000,
            data: original_data.clone(),
        };

        let payloads = packetizer.packetize(&frame, 50);
        assert!(payloads.len() > 1);

        let mut result = None;
        for (i, pl) in payloads.iter().enumerate() {
            let marker = i == payloads.len() - 1;
            let pkt = make_rtp(pl.clone(), 12000, marker, i as u16);
            if let Some(f) = depacketizer.depacketize(&pkt) {
                result = Some(f);
            }
        }
        let out = result.unwrap();
        assert!(!out.keyframe);
        assert_eq!(out.data, original_data);
    }

    #[test]
    fn empty_payload_ignored() {
        let mut depkt = Vp8Depacketizer::new();
        let pkt = make_rtp(vec![], 1000, true, 1);
        assert!(depkt.depacketize(&pkt).is_none());
    }

    #[test]
    fn packetize_empty_frame() {
        let mut pkt = Vp8Packetizer::new();
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: false,
            timestamp: 0,
            data: Vec::new(),
        };
        assert!(pkt.packetize(&frame, 1200).is_empty());
    }
}
