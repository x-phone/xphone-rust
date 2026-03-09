// G.729 codec implementation (ITU-T G.729, payload type 18).
//
// Uses the `g729-sys` crate (pure Rust port of bcg729) gated behind the
// `g729-codec` feature. G.729 operates on 10ms / 80-sample frames at 8kHz,
// producing 10 bytes per frame. The pipeline uses 20ms / 160-sample frames,
// so this processor splits/merges internally (transparent to pipeline).
//
// **No Annex B (VAD/CNG)**: g729-sys has VAD stubbed out. SDP advertises
// `annexb=no` to tell remote endpoints not to send SID frames.

use super::CodecProcessor;

const PAYLOAD_TYPE: u8 = 18;
const CLOCK_RATE: u32 = 8000;
const SAMPLES_PER_FRAME: u32 = 160; // 20ms at 8kHz (pipeline frame size)
const G729_FRAME_SAMPLES: usize = 80; // 10ms at 8kHz (codec native)
const G729_FRAME_BYTES: usize = 10; // 10 bytes per 10ms frame

pub struct G729Processor {
    enc: g729_sys::Encoder,
    dec: g729_sys::Decoder,
}

impl G729Processor {
    pub fn new() -> Option<Self> {
        let enc = g729_sys::Encoder::new(false).ok()?;
        let dec = g729_sys::Decoder::new().ok()?;
        Some(Self { enc, dec })
    }
}

impl CodecProcessor for G729Processor {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        // Split payload into 10-byte chunks, decode each into 80 samples.
        // Handles both 10-byte (single 10ms) and 20-byte (standard 20ms) payloads,
        // as well as any multiple. Trailing bytes < 10 are ignored.
        let num_frames = payload.len() / G729_FRAME_BYTES;
        if num_frames == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(num_frames * G729_FRAME_SAMPLES);
        for i in 0..num_frames {
            let chunk = &payload[i * G729_FRAME_BYTES..(i + 1) * G729_FRAME_BYTES];
            let samples = self.dec.decode(chunk, false, false, false);
            out.extend_from_slice(&samples);
        }
        out
    }

    fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        // Split 160 samples into 2×80, encode each into 10 bytes → 20 bytes total.
        let num_frames = samples.len() / G729_FRAME_SAMPLES;
        if num_frames == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(num_frames * G729_FRAME_BYTES);
        for i in 0..num_frames {
            let start = i * G729_FRAME_SAMPLES;
            let frame: &[i16; 80] = samples[start..start + G729_FRAME_SAMPLES]
                .try_into()
                .expect("slice is exactly 80 samples");
            let encoded = self.enc.encode(frame);
            out.extend_from_slice(&encoded);
        }
        out
    }

    fn payload_type(&self) -> u8 {
        PAYLOAD_TYPE
    }

    fn clock_rate(&self) -> u32 {
        CLOCK_RATE
    }

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
        let p = G729Processor::new().unwrap();
        assert_eq!(p.payload_type(), 18);
        assert_eq!(p.clock_rate(), 8000);
        assert_eq!(p.samples_per_frame(), 160);
    }

    #[test]
    fn round_trip_silence() {
        let mut p = G729Processor::new().unwrap();
        let silence = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&silence);
        assert!(!encoded.is_empty());
        let decoded = p.decode(&encoded);
        assert_eq!(decoded.len(), PCM_FRAME_SIZE);
        // Silence should decode to near-zero values
        for &s in &decoded {
            assert!(s.abs() < 500, "expected near-silence, got {}", s);
        }
    }

    #[test]
    fn round_trip_tone() {
        let mut p = G729Processor::new().unwrap();
        let tone: Vec<i16> = (0..PCM_FRAME_SIZE)
            .map(|i| {
                let t = i as f64 / CLOCK_RATE as f64;
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
        let mut p = G729Processor::new().unwrap();
        let pcm = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&pcm);
        // G.729 produces 20 bytes for 160 samples (320 bytes raw PCM)
        assert_eq!(encoded.len(), 20);
        assert!(
            encoded.len() < PCM_FRAME_SIZE * 2,
            "encoded {} bytes >= raw {} bytes",
            encoded.len(),
            PCM_FRAME_SIZE * 2
        );
    }

    #[test]
    fn output_size() {
        let mut p = G729Processor::new().unwrap();
        let tone: Vec<i16> = (0..PCM_FRAME_SIZE)
            .map(|i| ((i as f64 * 0.1).sin() * 20000.0) as i16)
            .collect();
        let encoded = p.encode(&tone);
        // 160 samples → 2 × 10-byte frames = 20 bytes exactly
        assert_eq!(encoded.len(), 20);
    }

    #[test]
    fn stateful_encoding() {
        let mut p = G729Processor::new().unwrap();
        let pcm = vec![1000i16; PCM_FRAME_SIZE];
        let first = p.encode(&pcm);
        let second = p.encode(&pcm);
        // G.729 is stateful — second frame may differ from first.
        // Both should be valid non-empty output.
        assert!(!first.is_empty());
        assert!(!second.is_empty());
    }

    #[test]
    fn multi_frame_round_trip() {
        let mut p = G729Processor::new().unwrap();
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

    #[test]
    fn single_10byte_decode() {
        // Remote endpoint sends a single 10ms frame (10 bytes).
        // Decoder should produce 80 samples.
        let mut p = G729Processor::new().unwrap();
        // Encode a full 160-sample frame, take only the first 10 bytes (first 10ms).
        let pcm = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&pcm);
        assert_eq!(encoded.len(), 20);
        let first_frame = &encoded[..10];
        let decoded = p.decode(first_frame);
        assert_eq!(decoded.len(), G729_FRAME_SAMPLES);
    }

    #[test]
    fn odd_payload_handling() {
        // Payloads that aren't a multiple of 10 bytes: trailing bytes are ignored.
        let mut p = G729Processor::new().unwrap();
        let pcm = vec![0i16; PCM_FRAME_SIZE];
        let encoded = p.encode(&pcm);
        // Append 3 garbage bytes
        let mut odd = encoded.clone();
        odd.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        let decoded = p.decode(&odd);
        // Should decode exactly 2 frames (20 bytes), ignoring the 3 trailing bytes
        assert_eq!(decoded.len(), PCM_FRAME_SIZE);

        // Payload shorter than one frame (e.g. 5 bytes) → empty
        let short = &encoded[..5];
        let decoded_short = p.decode(short);
        assert!(decoded_short.is_empty());
    }
}
