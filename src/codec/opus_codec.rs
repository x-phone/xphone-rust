// Opus codec implementation (RFC 6716, payload type 111).
//
// Uses the `opus` crate (libopus FFI) gated behind the `opus-codec` feature.
// The encoder/decoder operate at 8kHz mono to match the pipeline's PCM rate,
// but RTP timestamps use the 48kHz clock per RFC 7587.

use super::CodecProcessor;
use opus::{Application, Channels, Decoder, Encoder};

const PAYLOAD_TYPE: u8 = 111;
const CLOCK_RATE: u32 = 48000;
const PCM_RATE: u32 = 8000;
const SAMPLES_PER_FRAME: u32 = 960; // 20ms at 48kHz clock
const MAX_DECODE_SAMPLES: usize = 960; // 120ms at 8kHz — handles up to 60ms Opus frames

pub struct OpusProcessor {
    enc: Encoder,
    dec: Decoder,
}

impl OpusProcessor {
    pub fn new() -> Option<Self> {
        let enc = Encoder::new(PCM_RATE, Channels::Mono, Application::Voip).ok()?;
        let dec = Decoder::new(PCM_RATE, Channels::Mono).ok()?;
        Some(Self { enc, dec })
    }
}

impl CodecProcessor for OpusProcessor {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        let mut out = vec![0i16; MAX_DECODE_SAMPLES];
        match self.dec.decode(payload, &mut out, false) {
            Ok(n) => {
                out.truncate(n);
                out
            }
            Err(e) => {
                tracing::warn!("opus decode error: {}", e);
                Vec::new()
            }
        }
    }

    fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        match self.enc.encode_vec(samples, 4000) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("opus encode error: {}", e);
                Vec::new()
            }
        }
    }

    fn payload_type(&self) -> u8 {
        PAYLOAD_TYPE
    }

    fn clock_rate(&self) -> u32 {
        CLOCK_RATE
    }

    /// RTP timestamp increment per frame (48kHz clock per RFC 7587).
    /// The actual PCM buffer size is PCM_FRAME_SIZE (160 samples at 8kHz).
    fn samples_per_frame(&self) -> u32 {
        SAMPLES_PER_FRAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCM_FRAME_SIZE: usize = 160; // 20ms at 8kHz

    #[test]
    fn interface() {
        let p = OpusProcessor::new().unwrap();
        assert_eq!(p.payload_type(), 111);
        assert_eq!(p.clock_rate(), 48000);
        assert_eq!(p.samples_per_frame(), 960);
    }

    #[test]
    fn round_trip_silence() {
        let mut p = OpusProcessor::new().unwrap();
        let silence = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&silence);
        assert!(!encoded.is_empty());
        let decoded = p.decode(&encoded);
        assert_eq!(decoded.len(), PCM_FRAME_SIZE);
        // Silence should decode to near-zero values
        for &s in &decoded {
            assert!(s.abs() < 100, "expected near-silence, got {}", s);
        }
    }

    #[test]
    fn round_trip_tone() {
        let mut p = OpusProcessor::new().unwrap();
        let tone: Vec<i16> = (0..PCM_FRAME_SIZE)
            .map(|i| {
                let t = i as f64 / PCM_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();
        let encoded = p.encode(&tone);
        assert!(!encoded.is_empty());
        let decoded = p.decode(&encoded);
        assert_eq!(decoded.len(), PCM_FRAME_SIZE);
        // Should have non-trivial energy
        let energy: i64 = decoded.iter().map(|&s| (s as i64) * (s as i64)).sum();
        assert!(energy > 0, "decoded tone should have energy");
    }

    #[test]
    fn compression() {
        let mut p = OpusProcessor::new().unwrap();
        let pcm = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&pcm);
        // Opus compressed output should be smaller than raw PCM (320 bytes)
        assert!(
            encoded.len() < PCM_FRAME_SIZE * 2,
            "encoded {} bytes >= raw {} bytes",
            encoded.len(),
            PCM_FRAME_SIZE * 2
        );
    }

    #[test]
    fn output_size_bounded() {
        let mut p = OpusProcessor::new().unwrap();
        let tone: Vec<i16> = (0..PCM_FRAME_SIZE)
            .map(|i| ((i as f64 * 0.1).sin() * 20000.0) as i16)
            .collect();
        let encoded = p.encode(&tone);
        // Max Opus frame at 8kHz VoIP should be well under 4000 bytes
        assert!(encoded.len() < 4000);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn stateful_encoding() {
        let mut p = OpusProcessor::new().unwrap();
        let pcm = vec![1000i16; PCM_FRAME_SIZE];
        let first = p.encode(&pcm);
        let second = p.encode(&pcm);
        // Opus is stateful — second frame may differ from first
        // Both should be valid non-empty output
        assert!(!first.is_empty());
        assert!(!second.is_empty());
    }

    #[test]
    fn multi_frame_round_trip() {
        let mut p = OpusProcessor::new().unwrap();
        for i in 0..5 {
            let pcm: Vec<i16> = (0..PCM_FRAME_SIZE)
                .map(|j| ((j as f64 + i as f64 * 100.0) * 0.05).sin() as i16 * 10000)
                .collect();
            let encoded = p.encode(&pcm);
            assert!(!encoded.is_empty(), "frame {} encode failed", i);
            let decoded = p.decode(&encoded);
            assert_eq!(decoded.len(), PCM_FRAME_SIZE, "frame {} decode size", i);
        }
    }
}
