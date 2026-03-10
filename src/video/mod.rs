pub mod h264;
pub mod vp8;

use crate::types::{RtpPacket, VideoCodec, VideoFrame};

/// Reassembles incoming RTP packets into complete video frames.
pub trait VideoDepacketizer: Send {
    /// Feed an RTP packet. Returns a complete frame when all fragments have arrived.
    fn depacketize(&mut self, pkt: &RtpPacket) -> Option<VideoFrame>;
}

/// Fragments a video frame into RTP payloads suitable for transmission.
pub trait VideoPacketizer: Send {
    /// Split a frame into MTU-sized RTP payloads (without RTP header — caller adds that).
    fn packetize(&mut self, frame: &VideoFrame, mtu: usize) -> Vec<Vec<u8>>;
}

/// Creates a depacketizer for the given video codec.
pub fn new_depacketizer(codec: VideoCodec) -> Box<dyn VideoDepacketizer> {
    match codec {
        VideoCodec::H264 => Box::new(h264::H264Depacketizer::new()),
        VideoCodec::VP8 => Box::new(vp8::Vp8Depacketizer::new()),
    }
}

/// Creates a packetizer for the given video codec.
pub fn new_packetizer(codec: VideoCodec) -> Box<dyn VideoPacketizer> {
    match codec {
        VideoCodec::H264 => Box::new(h264::H264Packetizer::new()),
        VideoCodec::VP8 => Box::new(vp8::Vp8Packetizer::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_creates_h264() {
        let mut depkt = new_depacketizer(VideoCodec::H264);
        let mut pkt = new_packetizer(VideoCodec::H264);
        // Smoke test — empty frame produces no payloads.
        let frame = VideoFrame {
            codec: VideoCodec::H264,
            keyframe: false,
            timestamp: 0,
            data: Vec::new(),
        };
        assert!(pkt.packetize(&frame, 1200).is_empty());
        // Empty packet produces no frame.
        let rtp = RtpPacket::default();
        assert!(depkt.depacketize(&rtp).is_none());
    }

    #[test]
    fn factory_creates_vp8() {
        let mut depkt = new_depacketizer(VideoCodec::VP8);
        let mut pkt = new_packetizer(VideoCodec::VP8);
        let frame = VideoFrame {
            codec: VideoCodec::VP8,
            keyframe: false,
            timestamp: 0,
            data: Vec::new(),
        };
        assert!(pkt.packetize(&frame, 1200).is_empty());
        let rtp = RtpPacket::default();
        assert!(depkt.depacketize(&rtp).is_none());
    }
}
