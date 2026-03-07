pub mod pcma;
pub mod pcmu;

/// Handles encoding and decoding for a specific audio codec.
pub trait CodecProcessor: Send {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16>;
    fn encode(&mut self, samples: &[i16]) -> Vec<u8>;
    fn payload_type(&self) -> u8;
    fn clock_rate(&self) -> u32;
    fn samples_per_frame(&self) -> u32;
}

/// Returns a [`CodecProcessor`] for the given RTP payload type.
/// Returns `None` for unsupported payload types.
pub fn new_codec_processor(payload_type: i32, _pcm_rate: i32) -> Option<Box<dyn CodecProcessor>> {
    match payload_type {
        0 => Some(Box::new(pcmu::PcmuProcessor::new())),
        8 => Some(Box::new(pcma::PcmaProcessor::new())),
        // G.722 (PT 9) deferred — ship with G.711 only for now.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_processor_pcmu_interface() {
        let cp = new_codec_processor(0, 8000).unwrap();
        assert_eq!(cp.payload_type(), 0);
        assert_eq!(cp.clock_rate(), 8000);
        assert_eq!(cp.samples_per_frame(), 160);
    }

    #[test]
    fn codec_processor_pcma_interface() {
        let cp = new_codec_processor(8, 8000).unwrap();
        assert_eq!(cp.payload_type(), 8);
        assert_eq!(cp.clock_rate(), 8000);
        assert_eq!(cp.samples_per_frame(), 160);
    }

    #[test]
    fn codec_processor_unknown_returns_none() {
        assert!(new_codec_processor(99, 8000).is_none());
        assert!(new_codec_processor(111, 8000).is_none());
    }
}
