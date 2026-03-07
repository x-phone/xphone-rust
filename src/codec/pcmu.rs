use super::CodecProcessor;

const MU_LAW_BIAS: i32 = 0x84; // 132
const MU_LAW_CLIP: i32 = 32635;

/// Mu-law decode table: maps each mu-law byte to its 16-bit linear PCM value.
static MU_LAW_DECODE_TABLE: std::sync::LazyLock<[i16; 256]> = std::sync::LazyLock::new(|| {
    let mut table = [0i16; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let b = (i as u8) ^ 0xFF;
        let mut t = (((b & 0x0F) as i32) << 3) + MU_LAW_BIAS;
        t <<= ((b >> 4) & 7) as u32;
        if b & 0x80 != 0 {
            *entry = (MU_LAW_BIAS - t) as i16;
        } else {
            *entry = (t - MU_LAW_BIAS) as i16;
        }
    }
    table
});

/// Mu-law exponent lookup table.
static MU_LAW_EXP_LUT: std::sync::LazyLock<[i32; 256]> = std::sync::LazyLock::new(|| {
    let mut lut = [0i32; 256];
    for (i, entry) in lut.iter_mut().enumerate().skip(1) {
        let mut val = i;
        let mut exp = 0;
        while val > 1 {
            val >>= 1;
            exp += 1;
        }
        if exp > 7 {
            exp = 7;
        }
        *entry = exp;
    }
    lut
});

fn encode_mu_law(sample: i16) -> u8 {
    let s = sample as i32;
    let sign = (s >> 8) & 0x80;
    let mut s = if sign != 0 { -s } else { s };
    if s > MU_LAW_CLIP {
        s = MU_LAW_CLIP;
    }
    s += MU_LAW_BIAS;

    let exp = MU_LAW_EXP_LUT[((s >> 7) & 0xFF) as usize];
    let mantissa = (s >> (exp + 3)) & 0x0F;

    (!(sign | (exp << 4) | mantissa)) as u8
}

/// G.711 mu-law codec processor (ITU-T G.711, payload type 0).
pub struct PcmuProcessor;

impl Default for PcmuProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl PcmuProcessor {
    pub fn new() -> Self {
        // Force lazy init of tables.
        let _ = &*MU_LAW_DECODE_TABLE;
        let _ = &*MU_LAW_EXP_LUT;
        PcmuProcessor
    }
}

impl CodecProcessor for PcmuProcessor {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        payload
            .iter()
            .map(|&b| MU_LAW_DECODE_TABLE[b as usize])
            .collect()
    }

    fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        samples.iter().map(|&s| encode_mu_law(s)).collect()
    }

    fn payload_type(&self) -> u8 {
        0
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
        let mut cp = PcmuProcessor::new();
        // 0xFF is mu-law silence -> 0
        assert_eq!(cp.decode(&[0xFF])[0], 0);
        // 0x80 -> large positive
        assert!(cp.decode(&[0x80])[0] > 16000);
        // 0x00 -> large negative
        assert!(cp.decode(&[0x00])[0] < -16000);
    }

    #[test]
    fn encode_known_values() {
        let mut cp = PcmuProcessor::new();
        // 0 -> 0xFF (silence)
        assert_eq!(cp.encode(&[0])[0], 0xFF);
        // Positive and negative samples should differ.
        let pos_enc = cp.encode(&[1000])[0];
        let neg_enc = cp.encode(&[-1000])[0];
        assert_ne!(pos_enc, neg_enc);
    }

    #[test]
    fn round_trip() {
        let mut cp = PcmuProcessor::new();
        let test_samples: Vec<i16> = vec![0, 100, -100, 1000, -1000, 8000, -8000, 16000, -16000];
        for &sample in &test_samples {
            let encoded = cp.encode(&[sample]);
            let decoded = cp.decode(&encoded);
            let tolerance = (sample as f64).abs() * 0.02;
            let tolerance = if tolerance < 8.0 { 8.0 } else { tolerance };
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
        let mut cp = PcmuProcessor::new();
        // 160 bytes PCMU <-> 160 samples
        let payload = vec![0u8; 160];
        let samples = cp.decode(&payload);
        assert_eq!(samples.len(), 160);

        let pcm = vec![0i16; 160];
        let encoded = cp.encode(&pcm);
        assert_eq!(encoded.len(), 160);
    }

    #[test]
    fn silence() {
        let mut cp = PcmuProcessor::new();
        let silence = vec![0i16; 160];
        let encoded = cp.encode(&silence);
        let decoded = cp.decode(&encoded);
        for (i, &s) in decoded.iter().enumerate() {
            assert!((s as f64).abs() <= 8.0, "sample {i} not near zero: {s}");
        }
    }
}
