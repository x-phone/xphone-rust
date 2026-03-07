use super::CodecProcessor;

/// Segment boundaries for A-law encoding (13-bit domain).
const A_LAW_SEG_END: [i32; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];

/// A-law decode table: maps each A-law byte to its 16-bit linear PCM value.
static A_LAW_DECODE_TABLE: std::sync::LazyLock<[i16; 256]> = std::sync::LazyLock::new(|| {
    let mut table = [0i16; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let a = (i as u8) ^ 0x55;
        let mut t = ((a & 0x0F) as i32) << 4;
        let seg = ((a & 0x70) >> 4) as i32;
        match seg {
            0 => t += 8,
            1 => t += 0x108,
            _ => {
                t += 0x108;
                t <<= (seg - 1) as u32;
            }
        }
        if a & 0x80 != 0 {
            *entry = t as i16;
        } else {
            *entry = (-t) as i16;
        }
    }
    table
});

fn encode_a_law(sample: i16) -> u8 {
    let pcm_val = (sample as i32) >> 3; // scale 16-bit to 13-bit
    let (mask, pcm_val) = if pcm_val >= 0 {
        (0xD5u8, pcm_val)
    } else {
        (0x55u8, -pcm_val - 1)
    };

    // Find segment.
    let mut seg = 0;
    while seg < 8 {
        if pcm_val <= A_LAW_SEG_END[seg] {
            break;
        }
        seg += 1;
    }

    if seg >= 8 {
        return 0x7F ^ mask;
    }

    let aval = if seg < 2 {
        ((pcm_val >> 1) & 0x0F) as u8
    } else {
        ((pcm_val >> seg as u32) & 0x0F) as u8
    };

    ((seg as u8) << 4 | aval) ^ mask
}

/// G.711 A-law codec processor (ITU-T G.711, payload type 8).
pub struct PcmaProcessor;

impl Default for PcmaProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl PcmaProcessor {
    pub fn new() -> Self {
        let _ = &*A_LAW_DECODE_TABLE;
        PcmaProcessor
    }
}

impl CodecProcessor for PcmaProcessor {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        payload
            .iter()
            .map(|&b| A_LAW_DECODE_TABLE[b as usize])
            .collect()
    }

    fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        samples.iter().map(|&s| encode_a_law(s)).collect()
    }

    fn payload_type(&self) -> u8 {
        8
    }

    fn clock_rate(&self) -> u32 {
        8000
    }

    fn samples_per_frame(&self) -> u32 {
        160
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_values() {
        let mut cp = PcmaProcessor::new();
        // 0xD5 is A-law silence -> small value near 0
        let decoded = cp.decode(&[0xD5])[0];
        assert!(
            (decoded as f64).abs() <= 8.0,
            "A-law silence should be near zero, got {decoded}"
        );
        // Verify positive and negative sides exist.
        assert!(cp.decode(&[0x80])[0] > 0, "0x80 should be positive");
        assert!(cp.decode(&[0x00])[0] < 0, "0x00 should be negative");
    }

    #[test]
    fn encode_known_values() {
        let mut cp = PcmaProcessor::new();
        // 0 encodes to 0xD5 (A-law silence).
        assert_eq!(cp.encode(&[0])[0], 0xD5);
        // Positive and negative should produce different bytes.
        let pos_enc = cp.encode(&[1000])[0];
        let neg_enc = cp.encode(&[-1000])[0];
        assert_ne!(pos_enc, neg_enc);
    }

    #[test]
    fn round_trip() {
        let mut cp = PcmaProcessor::new();
        let test_samples: Vec<i16> = vec![0, 100, -100, 1000, -1000, 8000, -8000, 16000, -16000];
        for &sample in &test_samples {
            let encoded = cp.encode(&[sample]);
            let decoded = cp.decode(&encoded);
            let tolerance = (sample as f64).abs() * 0.02;
            let tolerance = if tolerance < 16.0 { 16.0 } else { tolerance };
            let diff = (decoded[0] as f64 - sample as f64).abs();
            assert!(
                diff <= tolerance + 1.0,
                "sample {sample}: encoded=0x{:02X} decoded={}",
                encoded[0],
                decoded[0]
            );
        }
    }

    #[test]
    fn frame_size() {
        let mut cp = PcmaProcessor::new();
        let payload = vec![0u8; 160];
        let samples = cp.decode(&payload);
        assert_eq!(samples.len(), 160);

        let pcm = vec![0i16; 160];
        let encoded = cp.encode(&pcm);
        assert_eq!(encoded.len(), 160);
    }

    #[test]
    fn silence() {
        let mut cp = PcmaProcessor::new();
        let silence = vec![0i16; 160];
        let encoded = cp.encode(&silence);
        let decoded = cp.decode(&encoded);
        for (i, &s) in decoded.iter().enumerate() {
            assert!((s as f64).abs() <= 16.0, "sample {i} not near zero: {s}");
        }
    }
}
