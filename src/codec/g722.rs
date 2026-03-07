// G.722 codec implementation (ITU-T G.722, payload type 9).
//
// Ported from the SpanDSP / libg722 public domain implementation:
//   Written by Steve Underwood <steveu@coppice.org>
//   Copyright (C) 2005 Steve Underwood
//   "I place my own contributions to this code in the public domain
//    for the benefit of all mankind."
//
// Based on the CMU G.722 codec:
//   Copyright (c) CMU 1993, Computer Science, Speech Group
//   Chengxiang Lu and Alex Hauptmann

use super::CodecProcessor;

// ---------------------------------------------------------------------------
// Core algorithm types and helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Bitrate {
    Mode64000,
}

impl Bitrate {
    fn bits_per_sample(self) -> i32 {
        match self {
            Bitrate::Mode64000 => 8,
        }
    }
}

#[derive(Clone, Default)]
struct G722Band {
    s: i32,
    sp: i32,
    sz: i32,
    r: [i32; 3],
    a: [i32; 3],
    ap: [i32; 3],
    p: [i32; 3],
    d: [i32; 7],
    b: [i32; 7],
    bp: [i32; 7],
    sg: [i32; 7],
    nb: i32,
    det: i32,
}

fn saturate(amp: i32) -> i32 {
    amp.clamp(i16::MIN as i32, i16::MAX as i32)
}

fn block4(band: &mut G722Band, d: i32) {
    // Block 4, RECONS
    band.d[0] = d;
    band.r[0] = saturate(band.s + d);

    // Block 4, PARREC
    band.p[0] = saturate(band.sz + d);

    // Block 4, UPPOL2
    for i in 0..3 {
        band.sg[i] = band.p[i] >> 15;
    }
    let wd1 = saturate(band.a[1] << 2);

    let mut wd2 = if band.sg[0] == band.sg[1] { -wd1 } else { wd1 };
    if wd2 > 32767 {
        wd2 = 32767;
    }
    let mut wd3 = (wd2 >> 7) + (if band.sg[0] == band.sg[2] { 128 } else { -128 });
    wd3 += (band.a[2] * 32512) >> 15;
    wd3 = wd3.clamp(-12288, 12288);
    band.ap[2] = wd3;

    // Block 4, UPPOL1
    band.sg[0] = band.p[0] >> 15;
    band.sg[1] = band.p[1] >> 15;
    let wd1 = if band.sg[0] == band.sg[1] { 192 } else { -192 };
    let wd2 = (band.a[1] * 32640) >> 15;

    band.ap[1] = saturate(wd1 + wd2);
    let wd3 = saturate(15360 - band.ap[2]);
    if band.ap[1] > wd3 {
        band.ap[1] = wd3;
    } else if band.ap[1] < -wd3 {
        band.ap[1] = -wd3;
    }

    // Block 4, UPZERO
    let wd1 = if d == 0 { 0 } else { 128 };
    band.sg[0] = d >> 15;
    let mut i = 1;
    while i < 7 {
        band.sg[i] = band.d[i] >> 15;
        let wd2 = if band.sg[i] == band.sg[0] { wd1 } else { -wd1 };
        let wd3 = (band.b[i] * 32640) >> 15;
        band.bp[i] = saturate(wd2 + wd3);
        i += 1;
    }

    // Block 4, DELAYA
    i = 6;
    while i > 0 {
        band.d[i] = band.d[i - 1];
        band.b[i] = band.bp[i];
        i -= 1;
    }
    i = 2;
    while i > 0 {
        band.r[i] = band.r[i - 1];
        band.p[i] = band.p[i - 1];
        band.a[i] = band.ap[i];
        i -= 1;
    }

    // Block 4, FILTEP
    let wd1 = saturate(band.r[1] + band.r[1]);
    let wd1 = (band.a[1] * wd1) >> 15;
    let wd2 = saturate(band.r[2] + band.r[2]);
    let wd2 = (band.a[2] * wd2) >> 15;
    band.sp = saturate(wd1 + wd2);

    // Block 4, FILTEZ
    band.sz = 0;
    i = 6;
    while i > 0 {
        let wd1 = saturate(band.d[i] + band.d[i]);
        band.sz += (band.b[i] * wd1) >> 15;
        i -= 1;
    }
    band.sz = saturate(band.sz);

    // Block 4, PREDIC
    band.s = saturate(band.sp + band.sz);
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

struct G722Encoder {
    eight_k: bool,
    bits_per_sample: i32,
    x: [i32; 24],
    band: [G722Band; 2],
}

impl G722Encoder {
    fn new(eight_k: bool) -> Self {
        Self {
            eight_k,
            bits_per_sample: Bitrate::Mode64000.bits_per_sample(),
            x: [0; 24],
            band: Default::default(),
        }
    }

    fn encode(&mut self, amp: &[i16]) -> Vec<u8> {
        static Q6: [i32; 32] = [
            0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858,
            940, 1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
        ];
        static ILN: [i32; 32] = [
            0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
            12, 11, 10, 9, 8, 7, 6, 5, 4, 0,
        ];
        static ILP: [i32; 32] = [
            0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41,
            40, 39, 38, 37, 36, 35, 34, 33, 32, 0,
        ];
        static WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
        static RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
        static ILB: [i32; 32] = [
            2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714,
            2774, 2834, 2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676,
            3756, 3838, 3922, 4008,
        ];
        static QM4: [i32; 16] = [
            0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240,
            2584, 1200, 0,
        ];
        static QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
        static QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];
        static IHN: [i32; 3] = [0, 1, 0];
        static IHP: [i32; 3] = [0, 3, 2];
        static WH: [i32; 3] = [0, -214, 798];
        static RH2: [i32; 4] = [2, 1, 2, 1];

        let mut out = Vec::with_capacity(amp.len());
        let mut xhigh: i32 = 0;
        let mut j: usize = 0;

        while j < amp.len() {
            let xlow: i32;

            if self.eight_k {
                xlow = amp[j] as i32 >> 1;
                j += 1;
            } else {
                // Apply the transmit QMF — shuffle the buffer down
                for i in 0..22 {
                    self.x[i] = self.x[i + 2];
                }
                self.x[22] = amp[j] as i32;
                j += 1;
                self.x[23] = amp[j] as i32;
                j += 1;

                // Discard every other QMF output
                let mut sumeven: i32 = 0;
                let mut sumodd: i32 = 0;
                for i in 0..12 {
                    sumodd += self.x[2 * i] * QMF_COEFFS[i];
                    sumeven += self.x[2 * i + 1] * QMF_COEFFS[11 - i];
                }
                xlow = (sumeven + sumodd) >> 14;
                xhigh = (sumeven - sumodd) >> 14;
            }

            // Block 1L, SUBTRA
            let el = saturate(xlow - self.band[0].s);

            // Block 1L, QUANTL
            let mut wd = if el >= 0 { el } else { -(el + 1) };

            let mut i = 1;
            while i < 30 {
                let wd1 = (Q6[i] * self.band[0].det) >> 12;
                if wd < wd1 {
                    break;
                }
                i += 1;
            }
            let ilow = if el < 0 { ILN[i] } else { ILP[i] };

            // Block 2L, INVQAL
            let ril = ilow >> 2;
            let wd2 = QM4[ril as usize];
            let dlow = (self.band[0].det * wd2) >> 15;

            // Block 3L, LOGSCL
            let il4 = RL42[ril as usize];
            wd = (self.band[0].nb * 127) >> 7;
            self.band[0].nb = wd + WL[il4 as usize];
            self.band[0].nb = self.band[0].nb.clamp(0, 18432);

            // Block 3L, SCALEL
            let wd1 = self.band[0].nb >> 6 & 31;
            let wd2 = 8 - (self.band[0].nb >> 11);
            let wd3 = if wd2 < 0 {
                ILB[wd1 as usize] << -wd2
            } else {
                ILB[wd1 as usize] >> wd2
            };
            self.band[0].det = wd3 << 2;

            block4(&mut self.band[0], dlow);

            let code: i32;
            if self.eight_k {
                // Just leave the high bits as zero
                code = ((0xc0 | ilow) >> 8) - self.bits_per_sample;
            } else {
                // Block 1H, SUBTRA
                let eh = saturate(xhigh - self.band[1].s);

                // Block 1H, QUANTH
                wd = if eh >= 0 { eh } else { -(eh + 1) };
                let wd1 = (564 * self.band[1].det) >> 12;
                let mih = if wd >= wd1 { 2 } else { 1 };
                let ihigh = if eh < 0 { IHN[mih] } else { IHP[mih] };

                // Block 2H, INVQAH
                let wd2 = QM2[ihigh as usize];
                let dhigh = (self.band[1].det * wd2) >> 15;

                // Block 3H, LOGSCH
                let ih2 = RH2[ihigh as usize];
                wd = (self.band[1].nb * 127) >> 7;
                self.band[1].nb = wd + WH[ih2 as usize];
                self.band[1].nb = self.band[1].nb.clamp(0, 22528);

                // Block 3H, SCALEH
                let wd1 = self.band[1].nb >> 6 & 31;
                let wd2 = 10 - (self.band[1].nb >> 11);
                let wd3 = if wd2 < 0 {
                    ILB[wd1 as usize] << -wd2
                } else {
                    ILB[wd1 as usize] >> wd2
                };
                self.band[1].det = wd3 << 2;

                block4(&mut self.band[1], dhigh);
                code = (ihigh << 6 | ilow) >> (8 - self.bits_per_sample);
            }

            out.push(code as u8);
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct G722Decoder {
    eight_k: bool,
    x: [i32; 24],
    band: [G722Band; 2],
}

impl G722Decoder {
    fn new(eight_k: bool) -> Self {
        Self {
            eight_k,
            x: [0; 24],
            band: Default::default(),
        }
    }

    fn decode(&mut self, g722_data: &[u8]) -> Vec<i16> {
        static WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
        static RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
        static ILB: [i32; 32] = [
            2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714,
            2774, 2834, 2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676,
            3756, 3838, 3922, 4008,
        ];
        static WH: [i32; 3] = [0, -214, 798];
        static RH2: [i32; 4] = [2, 1, 2, 1];
        static QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
        static QM4: [i32; 16] = [
            0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240,
            2584, 1200, 0,
        ];
        static QM6: [i32; 64] = [
            -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192,
            -10232, -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576,
            -3168, -2776, -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704,
            14984, 13512, 12280, 11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944,
            4464, 4008, 3576, 3168, 2776, 2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
        ];
        static QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

        let mut out = Vec::with_capacity(g722_data.len() * 2);
        let mut rhigh: i32 = 0;

        for &byte in g722_data {
            let code = byte as i32;

            // 64kbps mode: 8 bits per sample
            let mut wd1 = code & 0x3f;
            let ihigh = (code >> 6) & 0x3;
            let wd2 = QM6[wd1 as usize];
            wd1 >>= 2;

            // Block 5L, LOW BAND INVQBL
            let wd2 = (self.band[0].det * wd2) >> 15;

            // Block 5L, RECONS
            let rlow = (self.band[0].s + wd2).clamp(-16384, 16383);

            // Block 2L, INVQAL
            let wd2 = QM4[wd1 as usize];
            let dlowt = (self.band[0].det * wd2) >> 15;

            // Block 3L, LOGSCL
            let wd2 = RL42[wd1 as usize];
            let mut wd1 = (self.band[0].nb * 127) >> 7;
            wd1 += WL[wd2 as usize];
            wd1 = wd1.clamp(0, 18432);
            self.band[0].nb = wd1;

            // Block 3L, SCALEL
            let wd1 = self.band[0].nb >> 6 & 31;
            let wd2 = 8 - (self.band[0].nb >> 11);
            let wd3 = if wd2 < 0 {
                ILB[wd1 as usize] << -wd2
            } else {
                ILB[wd1 as usize] >> wd2
            };
            self.band[0].det = wd3 << 2;

            block4(&mut self.band[0], dlowt);

            if !self.eight_k {
                // Block 2H, INVQAH
                let wd2 = QM2[ihigh as usize];
                let dhigh = (self.band[1].det * wd2) >> 15;

                // Block 5H, RECONS
                rhigh = (dhigh + self.band[1].s).clamp(-16384, 16383);

                // Block 2H, INVQAH
                let wd2 = RH2[ihigh as usize];
                let mut wd1 = (self.band[1].nb * 127) >> 7;
                wd1 += WH[wd2 as usize];
                wd1 = wd1.clamp(0, 22528);
                self.band[1].nb = wd1;

                // Block 3H, SCALEH
                let wd1 = self.band[1].nb >> 6 & 31;
                let wd2 = 10 - (self.band[1].nb >> 11);
                let wd3 = if wd2 < 0 {
                    ILB[wd1 as usize] << -wd2
                } else {
                    ILB[wd1 as usize] >> wd2
                };
                self.band[1].det = wd3 << 2;

                block4(&mut self.band[1], dhigh);
            }

            if self.eight_k {
                out.push((rlow << 1) as i16);
            } else {
                // Apply the receive QMF
                for i in 0..22 {
                    self.x[i] = self.x[i + 2];
                }
                self.x[22] = rlow + rhigh;
                self.x[23] = rlow - rhigh;

                let mut xout1: i32 = 0;
                let mut xout2: i32 = 0;
                for i in 0..12 {
                    xout2 += self.x[2 * i] * QMF_COEFFS[i];
                    xout1 += self.x[2 * i + 1] * QMF_COEFFS[11 - i];
                }

                out.push(saturate(xout1 >> 11) as i16);
                out.push(saturate(xout2 >> 11) as i16);
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// CodecProcessor wrapper with 8kHz ↔ 16kHz resampling
// ---------------------------------------------------------------------------

/// G.722 codec processor (ITU-T G.722, payload type 9).
///
/// G.722 operates at 16kHz internally. When used with an 8kHz PCM pipeline
/// (the standard case), simple 2:1 resampling is applied:
/// - **Encode**: each 8kHz sample is duplicated to produce 16kHz input
/// - **Decode**: every other 16kHz sample is taken to produce 8kHz output
///
/// Per RFC 3551, the RTP clock rate for G.722 is 8000 Hz despite the
/// 16kHz sampling rate (a well-known historical quirk).
pub struct G722Processor {
    enc: G722Encoder,
    dec: G722Decoder,
    pcm_rate: u32,
}

impl Default for G722Processor {
    fn default() -> Self {
        Self::new(8000)
    }
}

impl G722Processor {
    /// Creates a new G.722 processor.
    ///
    /// `pcm_rate` is the PCM sample rate of the pipeline (typically 8000).
    /// When `pcm_rate` is 8000, 2:1 resampling is applied to bridge the
    /// 16kHz G.722 native rate.
    pub fn new(pcm_rate: u32) -> Self {
        // eight_k=true tells the encoder/decoder to skip the QMF filters
        // and work directly with sub-band samples. We set this to false
        // because we handle the 8k resampling ourselves at the PCM level.
        Self {
            enc: G722Encoder::new(false),
            dec: G722Decoder::new(false),
            pcm_rate,
        }
    }
}

impl CodecProcessor for G722Processor {
    fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        // G.722 at 64kbps: each byte decodes to 2 samples at 16kHz
        let samples = self.dec.decode(payload);

        if self.pcm_rate == 8000 {
            // Decimate 2:1: take every other sample (16kHz → 8kHz)
            samples.iter().step_by(2).copied().collect()
        } else {
            samples
        }
    }

    fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        if self.pcm_rate == 8000 {
            // Upsample 2:1: duplicate each sample (8kHz → 16kHz)
            let upsampled: Vec<i16> = samples.iter().flat_map(|&s| [s, s]).collect();
            self.enc.encode(&upsampled)
        } else {
            self.enc.encode(samples)
        }
    }

    fn payload_type(&self) -> u8 {
        9
    }

    fn clock_rate(&self) -> u32 {
        // RFC 3551 quirk: G.722 clock rate is 8000 despite 16kHz sampling
        8000
    }

    fn samples_per_frame(&self) -> u32 {
        // 20ms at 8kHz = 160 samples (matching the 8kHz PCM pipeline)
        160
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_interface() {
        let cp = G722Processor::new(8000);
        assert_eq!(cp.payload_type(), 9);
        assert_eq!(cp.clock_rate(), 8000);
        assert_eq!(cp.samples_per_frame(), 160);
    }

    #[test]
    fn encode_decode_silence() {
        let mut cp = G722Processor::new(8000);
        let silence = vec![0i16; 160];
        let encoded = cp.encode(&silence);
        // 160 samples at 8kHz → 320 samples at 16kHz → 160 bytes at 64kbps
        assert_eq!(encoded.len(), 160);
        let decoded = cp.decode(&encoded);
        // 160 bytes → 320 samples at 16kHz → 160 samples at 8kHz
        assert_eq!(decoded.len(), 160);
        for (i, &s) in decoded.iter().enumerate() {
            assert!((s as i32).abs() < 50, "sample {i} not near zero: {s}");
        }
    }

    #[test]
    fn round_trip_tone() {
        let mut cp = G722Processor::new(8000);
        // Generate a 400Hz tone at 8kHz
        let samples: Vec<i16> = (0..160)
            .map(|i| {
                let t = i as f64 / 8000.0;
                (f64::sin(2.0 * std::f64::consts::PI * 400.0 * t) * 10000.0) as i16
            })
            .collect();

        let encoded = cp.encode(&samples);
        let decoded = cp.decode(&encoded);

        assert_eq!(decoded.len(), 160);

        // G.722 is lossy but should preserve the general shape.
        // Check that energy is preserved within a reasonable tolerance.
        let orig_energy: f64 = samples.iter().map(|&s| (s as f64).powi(2)).sum();
        let dec_energy: f64 = decoded.iter().map(|&s| (s as f64).powi(2)).sum();
        let ratio = dec_energy / orig_energy;
        assert!(
            (0.3..3.0).contains(&ratio),
            "energy ratio {ratio} out of range"
        );
    }

    #[test]
    fn encode_output_size() {
        let mut cp = G722Processor::new(8000);
        // 80 samples at 8kHz → 160 at 16kHz → 80 bytes
        let samples = vec![0i16; 80];
        let encoded = cp.encode(&samples);
        assert_eq!(encoded.len(), 80);
    }

    #[test]
    fn decode_output_size() {
        let mut cp = G722Processor::new(8000);
        // 80 bytes → 160 samples at 16kHz → 80 at 8kHz
        let payload = vec![0u8; 80];
        let decoded = cp.decode(&payload);
        assert_eq!(decoded.len(), 80);
    }

    #[test]
    fn stateful_encoding() {
        // Encoding the same input twice should produce different output
        // because G.722 is a stateful ADPCM codec.
        let mut cp = G722Processor::new(8000);
        let tone: Vec<i16> = (0..160)
            .map(|i| ((i as f64 * 0.1).sin() * 5000.0) as i16)
            .collect();
        let first = cp.encode(&tone);
        let second = cp.encode(&tone);
        // After encoding the first frame, internal state has changed,
        // so the second encoding should differ.
        assert_ne!(first, second);
    }

    #[test]
    fn raw_encoder_decoder_16k() {
        // Test the raw encoder/decoder without resampling
        let mut enc = G722Encoder::new(false);
        let mut dec = G722Decoder::new(false);

        // 320 samples at 16kHz (20ms)
        let samples: Vec<i16> = (0..320)
            .map(|i| {
                let t = i as f64 / 16000.0;
                (f64::sin(2.0 * std::f64::consts::PI * 1000.0 * t) * 8000.0) as i16
            })
            .collect();

        let encoded = enc.encode(&samples);
        // 320 samples → 160 bytes (2 samples per byte)
        assert_eq!(encoded.len(), 160);

        let decoded = dec.decode(&encoded);
        // 160 bytes → 320 samples
        assert_eq!(decoded.len(), 320);
    }

    #[test]
    fn multiple_frames() {
        let mut cp = G722Processor::new(8000);
        // Encode and decode 3 consecutive frames
        for frame in 0..3 {
            let samples: Vec<i16> = (0..160)
                .map(|i| {
                    let t = (frame * 160 + i) as f64 / 8000.0;
                    (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 8000.0) as i16
                })
                .collect();
            let encoded = cp.encode(&samples);
            assert_eq!(encoded.len(), 160, "frame {frame} encode size");
            let decoded = cp.decode(&encoded);
            assert_eq!(decoded.len(), 160, "frame {frame} decode size");
        }
    }
}
