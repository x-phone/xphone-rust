//! SRTP (Secure RTP) implementation per RFC 3711 with SDES key exchange (RFC 4568).
//!
//! Supports `AES_CM_128_HMAC_SHA1_80` — the mandatory-to-implement cipher suite.
//! Operates on raw RTP byte slices: `protect()` encrypts payload + appends auth tag,
//! `unprotect()` verifies auth tag + decrypts payload.
//!
//! ## Known limitations
//!
//! - TODO: Add replay protection with a sliding window bitmask (RFC 3711 §3.3.2).
//! - TODO: Implement full ROC estimation per RFC 3711 Appendix A instead of the
//!   simplified 0x1000/0xF000 threshold heuristic (fine for sequential telephony
//!   traffic but not robust against large packet reordering).
//! - TODO: Replace inline AES-128/SHA-1/HMAC-SHA1 with audited crates (`aes`, `sha1`,
//!   `hmac`) for constant-time guarantees and hardware acceleration (AES-NI).
//! - TODO: Zeroize key material on drop (use `zeroize` crate on `SrtpContext` fields).
//! - TODO: Track per-SSRC crypto state for inbound streams (RFC 3711 §3.2.3).
//! - TODO: Cache AES expanded key schedule in `SrtpContext` instead of recomputing per block.

use std::fmt;

use crate::error::{Error, Result};

/// SRTP auth tag length for HMAC-SHA1-80 (10 bytes = 80 bits).
const AUTH_TAG_LEN: usize = 10;
/// Master key length (16 bytes = 128 bits).
const MASTER_KEY_LEN: usize = 16;
/// Master salt length (14 bytes = 112 bits).
const MASTER_SALT_LEN: usize = 14;
/// Total keying material = master key + master salt.
const KEYING_MATERIAL_LEN: usize = MASTER_KEY_LEN + MASTER_SALT_LEN;
/// AES block size.
const AES_BLOCK_SIZE: usize = 16;
/// Minimum RTP header size.
const RTP_HEADER_MIN: usize = 12;

/// SRTP key derivation labels per RFC 3711 §4.3.1.
const LABEL_CIPHER_KEY: u8 = 0x00;
const LABEL_AUTH_KEY: u8 = 0x01;
const LABEL_SALT: u8 = 0x02;

/// SRTP crypto context for a single direction (send or receive).
pub struct SrtpContext {
    /// AES-128 cipher key (16 bytes), derived from master key.
    cipher_key: [u8; 16],
    /// HMAC-SHA1 authentication key (20 bytes), derived from master key.
    auth_key: [u8; 20],
    /// Session salt (14 bytes), derived from master key.
    session_salt: [u8; 14],
    /// ROC: Rollover Counter — how many times the 16-bit seq has wrapped.
    roc: u32,
    /// Last observed sequence number (for ROC tracking on receive).
    last_seq: u16,
    /// Whether we've seen the first packet (for ROC init).
    seq_initialized: bool,
}

impl fmt::Debug for SrtpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpContext")
            .field("roc", &self.roc)
            .field("last_seq", &self.last_seq)
            .finish()
    }
}

impl SrtpContext {
    /// Creates a new SRTP context from master key (16 bytes) and master salt (14 bytes).
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Result<Self> {
        if master_key.len() != MASTER_KEY_LEN {
            return Err(Error::Other(format!(
                "srtp: master key must be {} bytes, got {}",
                MASTER_KEY_LEN,
                master_key.len()
            )));
        }
        if master_salt.len() != MASTER_SALT_LEN {
            return Err(Error::Other(format!(
                "srtp: master salt must be {} bytes, got {}",
                MASTER_SALT_LEN,
                master_salt.len()
            )));
        }

        let cipher_key = derive_session_key(master_key, master_salt, LABEL_CIPHER_KEY, 16)?;
        let auth_key = derive_session_key(master_key, master_salt, LABEL_AUTH_KEY, 20)?;
        let salt_bytes = derive_session_key(master_key, master_salt, LABEL_SALT, 14)?;

        let mut ck = [0u8; 16];
        ck.copy_from_slice(&cipher_key);
        let mut ak = [0u8; 20];
        ak.copy_from_slice(&auth_key);
        let mut ss = [0u8; 14];
        ss.copy_from_slice(&salt_bytes);

        Ok(Self {
            cipher_key: ck,
            auth_key: ak,
            session_salt: ss,
            roc: 0,
            last_seq: 0,
            seq_initialized: false,
        })
    }

    /// Creates an SRTP context from an SDES crypto attribute inline key.
    /// Format: `inline:<base64(master_key || master_salt)>`
    pub fn from_sdes_inline(inline: &str) -> Result<Self> {
        let b64 = inline.strip_prefix("inline:").unwrap_or(inline);
        let decoded = base64_decode(b64)?;
        if decoded.len() < KEYING_MATERIAL_LEN {
            return Err(Error::Other(format!(
                "srtp: SDES keying material must be {} bytes, got {}",
                KEYING_MATERIAL_LEN,
                decoded.len()
            )));
        }
        let master_key = &decoded[..MASTER_KEY_LEN];
        let master_salt = &decoded[MASTER_KEY_LEN..KEYING_MATERIAL_LEN];
        Self::new(master_key, master_salt)
    }

    /// Encrypts an RTP packet in-place and appends a 10-byte auth tag.
    /// Input: raw RTP bytes (header + payload).
    /// Output: SRTP bytes (header + encrypted_payload + auth_tag).
    pub fn protect(&mut self, rtp: &[u8]) -> Result<Vec<u8>> {
        if rtp.len() < RTP_HEADER_MIN {
            return Err(Error::Other("srtp: packet too short".into()));
        }

        let seq = u16::from_be_bytes([rtp[2], rtp[3]]);
        let ssrc = u32::from_be_bytes([rtp[8], rtp[9], rtp[10], rtp[11]]);
        let header_len = rtp_header_len(rtp)?;

        // Update ROC for sender.
        self.update_roc_sender(seq);
        let index = ((self.roc as u64) << 16) | seq as u64;

        // Encrypt the payload (header stays cleartext).
        let mut out = rtp.to_vec();
        let keystream = generate_keystream(
            &self.cipher_key,
            &self.session_salt,
            ssrc,
            index,
            out.len() - header_len,
        )?;
        for i in header_len..out.len() {
            out[i] ^= keystream[i - header_len];
        }

        // Compute and append auth tag over (SRTP_header + encrypted_payload + ROC).
        let tag = compute_auth_tag(&self.auth_key, &out, self.roc);
        out.extend_from_slice(&tag);

        Ok(out)
    }

    /// Verifies auth tag, then decrypts the SRTP packet payload.
    /// Input: SRTP bytes (header + encrypted_payload + auth_tag).
    /// Output: raw RTP bytes (header + decrypted_payload).
    pub fn unprotect(&mut self, srtp: &[u8]) -> Result<Vec<u8>> {
        if srtp.len() < RTP_HEADER_MIN + AUTH_TAG_LEN {
            return Err(Error::Other("srtp: packet too short for unprotect".into()));
        }

        let authenticated_len = srtp.len() - AUTH_TAG_LEN;
        let received_tag = &srtp[authenticated_len..];
        let authenticated_portion = &srtp[..authenticated_len];

        let seq = u16::from_be_bytes([srtp[2], srtp[3]]);
        let ssrc = u32::from_be_bytes([srtp[8], srtp[9], srtp[10], srtp[11]]);
        let header_len = rtp_header_len(srtp)?;

        // Estimate ROC for this packet.
        let estimated_roc = self.estimate_roc(seq);
        let index = ((estimated_roc as u64) << 16) | seq as u64;

        // Verify auth tag.
        let expected_tag = compute_auth_tag(&self.auth_key, authenticated_portion, estimated_roc);
        if !constant_time_eq(received_tag, &expected_tag) {
            return Err(Error::Other("srtp: authentication failed".into()));
        }

        // Auth passed — update ROC.
        self.update_roc_receiver(seq, estimated_roc);

        // Decrypt payload.
        let payload_len = authenticated_len - header_len;
        let keystream = generate_keystream(
            &self.cipher_key,
            &self.session_salt,
            ssrc,
            index,
            payload_len,
        )?;

        let mut out = authenticated_portion.to_vec();
        for i in header_len..out.len() {
            out[i] ^= keystream[i - header_len];
        }

        Ok(out)
    }

    fn update_roc_sender(&mut self, seq: u16) {
        if !self.seq_initialized {
            self.last_seq = seq;
            self.seq_initialized = true;
            return;
        }
        // If seq wrapped around (went from high to low).
        if seq < 0x1000 && self.last_seq > 0xF000 {
            self.roc += 1;
        }
        self.last_seq = seq;
    }

    fn estimate_roc(&self, seq: u16) -> u32 {
        if !self.seq_initialized {
            return 0;
        }
        if seq < 0x1000 && self.last_seq > 0xF000 {
            self.roc + 1
        } else if seq > 0xF000 && self.last_seq < 0x1000 {
            self.roc.wrapping_sub(1)
        } else {
            self.roc
        }
    }

    fn update_roc_receiver(&mut self, seq: u16, estimated_roc: u32) {
        if !self.seq_initialized {
            self.last_seq = seq;
            self.roc = estimated_roc;
            self.seq_initialized = true;
            return;
        }
        if estimated_roc > self.roc || (estimated_roc == self.roc && seq > self.last_seq) {
            self.roc = estimated_roc;
            self.last_seq = seq;
        }
    }
}

/// Derives a session key using AES-128-CM key derivation (RFC 3711 §4.3.1).
///
/// key_derivation_rate = 0 (default), so `r = index DIV key_derivation_rate = 0`.
/// `x = label || r` (7 bytes of label padded to 14 bytes) XOR salt.
/// Session key = AES-CM(master_key, x, 0) for required length.
fn derive_session_key(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
    out_len: usize,
) -> Result<Vec<u8>> {
    // Build the 14-byte x value: label at byte 7 (0-indexed), rest zero, XOR with salt.
    let mut x = [0u8; 14];
    x[7] = label;
    for i in 0..14 {
        x[i] ^= master_salt[i];
    }

    // Generate keystream using AES-CM with IV = x || 0x0000 (padded to 16 bytes).
    let blocks_needed = out_len.div_ceil(AES_BLOCK_SIZE);
    let mut result = Vec::with_capacity(blocks_needed * AES_BLOCK_SIZE);

    for block_counter in 0..blocks_needed {
        let mut iv = [0u8; AES_BLOCK_SIZE];
        iv[..14].copy_from_slice(&x);
        // Last 2 bytes are the block counter (big-endian).
        iv[14] = (block_counter >> 8) as u8;
        iv[15] = block_counter as u8;

        let encrypted = aes_ecb_encrypt(master_key, &iv)?;
        result.extend_from_slice(&encrypted);
    }

    result.truncate(out_len);
    Ok(result)
}

/// Generates an AES-CM keystream for SRTP payload encryption.
///
/// IV = (ssrc XOR salt) with packet index, per RFC 3711 §4.1.1.
fn generate_keystream(
    cipher_key: &[u8],
    session_salt: &[u8],
    ssrc: u32,
    index: u64,
    len: usize,
) -> Result<Vec<u8>> {
    // Build the IV per RFC 3711 §4.1.1:
    // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
    // In practice: 16-byte IV where:
    //   bytes 0-3: salt[0..4]
    //   bytes 4-7: salt[4..8] XOR SSRC
    //   bytes 8-13: salt[8..14] XOR index (48-bit, shifted left by 16)
    //   bytes 14-15: block counter
    let mut iv = [0u8; AES_BLOCK_SIZE];

    // Copy salt into iv[0..14].
    iv[..14].copy_from_slice(&session_salt[..14]);

    // XOR SSRC into iv[4..8].
    let ssrc_bytes = ssrc.to_be_bytes();
    for i in 0..4 {
        iv[4 + i] ^= ssrc_bytes[i];
    }

    // XOR index (48-bit packet index) into iv[8..14].
    // index is a 48-bit value. We place it at iv[8..14] (6 bytes).
    let index_bytes = index.to_be_bytes(); // 8 bytes, we use last 6
    for i in 0..6 {
        iv[8 + i] ^= index_bytes[2 + i];
    }

    let blocks_needed = len.div_ceil(AES_BLOCK_SIZE);
    let mut keystream = Vec::with_capacity(blocks_needed * AES_BLOCK_SIZE);

    for block_counter in 0..blocks_needed {
        let mut block_iv = iv;
        // Add block counter to bytes 14-15.
        let bc = block_counter as u16;
        block_iv[14] ^= (bc >> 8) as u8;
        block_iv[15] ^= bc as u8;

        let encrypted = aes_ecb_encrypt(cipher_key, &block_iv)?;
        keystream.extend_from_slice(&encrypted);
    }

    keystream.truncate(len);
    Ok(keystream)
}

/// AES-128 ECB encrypt a single block using inline implementation.
fn aes_ecb_encrypt(key: &[u8], block: &[u8; 16]) -> Result<[u8; 16]> {
    if key.len() != 16 {
        return Err(Error::Other("srtp: AES key must be 16 bytes".into()));
    }
    Ok(aes128_encrypt_block(key, block))
}

/// Computes the HMAC-SHA1-80 auth tag over the authenticated portion + ROC.
fn compute_auth_tag(auth_key: &[u8], authenticated: &[u8], roc: u32) -> [u8; AUTH_TAG_LEN] {
    let mut data = Vec::with_capacity(authenticated.len() + 4);
    data.extend_from_slice(authenticated);
    data.extend_from_slice(&roc.to_be_bytes());
    let full_mac = hmac_sha1(auth_key, &data);
    let mut result = [0u8; AUTH_TAG_LEN];
    result.copy_from_slice(&full_mac[..AUTH_TAG_LEN]);
    result
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Calculates the actual RTP header length including CSRC and extensions.
fn rtp_header_len(rtp: &[u8]) -> Result<usize> {
    if rtp.len() < RTP_HEADER_MIN {
        return Err(Error::Other("srtp: packet too short".into()));
    }
    let cc = (rtp[0] & 0x0F) as usize;
    let has_extension = (rtp[0] & 0x10) != 0;
    let mut len = RTP_HEADER_MIN + cc * 4;

    if has_extension {
        if rtp.len() < len + 4 {
            return Err(Error::Other("srtp: packet too short for extension".into()));
        }
        let ext_len = u16::from_be_bytes([rtp[len + 2], rtp[len + 3]]) as usize;
        len += 4 + ext_len * 4;
    }

    if len > rtp.len() {
        return Err(Error::Other("srtp: header exceeds packet length".into()));
    }
    Ok(len)
}

// --- SHA-1 + HMAC-SHA1 implementation ---

/// SHA-1 hash (FIPS 180-4). Returns 20-byte digest.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    // Pad message: append 0x80, then zeros, then 64-bit length.
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

/// HMAC-SHA1 (RFC 2104). Returns 20-byte MAC.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;

    // If key > block size, hash it first.
    let key_block = if key.len() > BLOCK_SIZE {
        let h = sha1(key);
        let mut kb = [0u8; BLOCK_SIZE];
        kb[..20].copy_from_slice(&h);
        kb
    } else {
        let mut kb = [0u8; BLOCK_SIZE];
        kb[..key.len()].copy_from_slice(key);
        kb
    };

    // Inner: SHA1(key XOR ipad || data)
    let mut inner = Vec::with_capacity(BLOCK_SIZE + data.len());
    for &b in &key_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    // Outer: SHA1(key XOR opad || inner_hash)
    let mut outer = Vec::with_capacity(BLOCK_SIZE + 20);
    for &b in &key_block {
        outer.push(b ^ 0x5C);
    }
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

// --- AES-128 implementation (lookup table based) ---

/// AES S-Box.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES round constants.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Expand AES-128 key to 11 round keys (176 bytes).
fn aes128_expand_key(key: &[u8]) -> [u8; 176] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(&key[..16]);

    for i in 1..11 {
        let prev = i * 16 - 16;
        let curr = i * 16;

        // RotWord + SubWord + Rcon
        let mut temp = [
            SBOX[w[prev + 13] as usize] ^ RCON[i - 1],
            SBOX[w[prev + 14] as usize],
            SBOX[w[prev + 15] as usize],
            SBOX[w[prev + 12] as usize],
        ];

        for j in 0..4 {
            let base = curr + j * 4;
            let prev_base = prev + j * 4;
            w[base] = w[prev_base] ^ temp[0];
            w[base + 1] = w[prev_base + 1] ^ temp[1];
            w[base + 2] = w[prev_base + 2] ^ temp[2];
            w[base + 3] = w[prev_base + 3] ^ temp[3];
            temp = [w[base], w[base + 1], w[base + 2], w[base + 3]];
        }
    }
    w
}

/// GF(2^8) multiplication by 2 in AES's field.
#[inline]
fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 {
        (a << 1) ^ 0x1b
    } else {
        a << 1
    }
}

/// Encrypt a single 16-byte block with AES-128.
fn aes128_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let rk = aes128_expand_key(key);
    let mut state = *block;

    // Initial AddRoundKey.
    for i in 0..16 {
        state[i] ^= rk[i];
    }

    // Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey.
    for round in 1..10 {
        // SubBytes
        for b in &mut state {
            *b = SBOX[*b as usize];
        }

        // ShiftRows
        shift_rows(&mut state);

        // MixColumns
        mix_columns(&mut state);

        // AddRoundKey
        let offset = round * 16;
        for i in 0..16 {
            state[i] ^= rk[offset + i];
        }
    }

    // Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns).
    for b in &mut state {
        *b = SBOX[*b as usize];
    }
    shift_rows(&mut state);
    let offset = 10 * 16;
    for i in 0..16 {
        state[i] ^= rk[offset + i];
    }

    state
}

fn shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    // Row 2: shift left by 2
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    // Row 3: shift left by 3 (= right by 1)
    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        let x = a0 ^ a1 ^ a2 ^ a3;
        state[i] = a0 ^ xtime(a0 ^ a1) ^ x;
        state[i + 1] = a1 ^ xtime(a1 ^ a2) ^ x;
        state[i + 2] = a2 ^ xtime(a2 ^ a3) ^ x;
        state[i + 3] = a3 ^ xtime(a3 ^ a0) ^ x;
    }
}

// --- Base64 (minimal, for SDES inline keying material) ---

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to base64.
pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Decode base64 string to bytes.
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => {
                return Err(Error::Other(format!(
                    "srtp: invalid base64 char: {}",
                    c as char
                )))
            }
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

// --- SDES crypto attribute helpers ---

/// Generates random keying material (master key + master salt) and returns the
/// base64-encoded inline key suitable for an SDP `a=crypto` line.
///
/// Uses the OS CSPRNG (`getrandom`) for cryptographically secure randomness.
pub fn generate_keying_material() -> Result<(Vec<u8>, String)> {
    let mut material = vec![0u8; KEYING_MATERIAL_LEN];
    getrandom::getrandom(&mut material)
        .map_err(|e| Error::Other(format!("srtp: OS CSPRNG failed: {}", e)))?;
    let encoded = base64_encode(&material);
    Ok((material, encoded))
}

/// Builds an SDP `a=crypto` attribute line.
/// Example: `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1pMzQ1NTY3ODkwMTIzNDU2Nzg5MA==`
pub fn build_crypto_attr(tag: u32, inline_key: &str) -> String {
    format!(
        "a=crypto:{} AES_CM_128_HMAC_SHA1_80 inline:{}",
        tag, inline_key
    )
}

/// The only cipher suite currently supported.
pub const SUPPORTED_SUITE: &str = "AES_CM_128_HMAC_SHA1_80";

/// Parses an SDP `a=crypto` attribute line.
/// Returns `(tag, suite_name, inline_key)` or None if parsing fails.
pub fn parse_crypto_attr(line: &str) -> Option<(u32, String, String)> {
    let val = line
        .strip_prefix("a=crypto:")
        .or_else(|| line.strip_prefix("crypto:"))?;
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let tag = parts[0].parse::<u32>().ok()?;
    let suite = parts[1].to_string();
    let key_param = parts[2].to_string();
    Some((tag, suite, key_param))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_known_vector() {
        // NIST AES-128 test vector (FIPS 197 Appendix B).
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let input: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let output = aes128_encrypt_block(&key, &input);
        assert_eq!(output, expected);
    }

    #[test]
    fn sha1_known_vector() {
        // NIST SHA-1 test: SHA1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let digest = sha1(b"abc");
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn sha1_empty() {
        // SHA1("") = da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709
        let digest = sha1(b"");
        assert_eq!(
            digest,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_test1() {
        // RFC 2202 Test Case 1:
        // Key = 0x0b repeated 20 times
        // Data = "Hi There"
        // HMAC-SHA-1 = b617318655057264e28bc0b6fb378c8ef146be00
        let key = [0x0bu8; 20];
        let mac = hmac_sha1(&key, b"Hi There");
        assert_eq!(
            mac,
            [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
            ]
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_test2() {
        // RFC 2202 Test Case 2:
        // Key = "Jefe"
        // Data = "what do ya want for nothing?"
        // HMAC-SHA-1 = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
        let mac = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
            ]
        );
    }

    #[test]
    fn base64_round_trip() {
        let data = b"Hello, SRTP world!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_keying_material() {
        // 30-byte keying material.
        let material = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e,
        ];
        let encoded = base64_encode(&material);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, material);
    }

    #[test]
    fn srtp_protect_unprotect_round_trip() {
        let master_key = [0x01u8; 16];
        let master_salt = [0x02u8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        // Build a minimal RTP packet.
        let mut rtp = vec![0u8; 12 + 160]; // header + payload
        rtp[0] = 0x80; // V=2
        rtp[1] = 0; // PT=0 (PCMU)
        rtp[2] = 0;
        rtp[3] = 1; // seq=1
                    // timestamp, ssrc = 0

        // Fill payload with known data.
        for (i, b) in rtp[12..].iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }

        let original = rtp.clone();
        let protected = sender.protect(&rtp).unwrap();

        // Protected should be longer (auth tag appended).
        assert_eq!(protected.len(), rtp.len() + AUTH_TAG_LEN);
        // Payload should be encrypted (different from original).
        assert_ne!(&protected[12..12 + 160], &original[12..]);

        let unprotected = receiver.unprotect(&protected).unwrap();
        assert_eq!(unprotected, original);
    }

    #[test]
    fn srtp_tampered_auth_fails() {
        let master_key = [0x03u8; 16];
        let master_salt = [0x04u8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        let mut rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]; // minimal header
        rtp.extend_from_slice(&[0xAA; 40]); // payload

        let mut protected = sender.protect(&rtp).unwrap();

        // Tamper with a payload byte.
        protected[12] ^= 0xFF;

        let result = receiver.unprotect(&protected);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication"));
    }

    #[test]
    fn srtp_multiple_packets() {
        let master_key = [0x05u8; 16];
        let master_salt = [0x06u8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        for seq in 0u16..100 {
            let mut rtp = vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            rtp[2] = (seq >> 8) as u8;
            rtp[3] = seq as u8;
            rtp.extend_from_slice(&[seq as u8; 80]);

            let original = rtp.clone();
            let protected = sender.protect(&rtp).unwrap();
            let unprotected = receiver.unprotect(&protected).unwrap();
            assert_eq!(unprotected, original, "mismatch at seq {}", seq);
        }
    }

    #[test]
    fn srtp_different_ssrc() {
        let master_key = [0x07u8; 16];
        let master_salt = [0x08u8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        let mut rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        // Set SSRC to 0xDEADBEEF.
        rtp[8] = 0xDE;
        rtp[9] = 0xAD;
        rtp[10] = 0xBE;
        rtp[11] = 0xEF;
        rtp.extend_from_slice(&[0x42; 60]);

        let original = rtp.clone();
        let protected = sender.protect(&rtp).unwrap();
        let unprotected = receiver.unprotect(&protected).unwrap();
        assert_eq!(unprotected, original);
    }

    #[test]
    fn sdes_inline_round_trip() {
        let (material, encoded) = generate_keying_material().unwrap();
        assert_eq!(material.len(), KEYING_MATERIAL_LEN);

        let ctx = SrtpContext::from_sdes_inline(&format!("inline:{}", encoded));
        assert!(ctx.is_ok());
    }

    #[test]
    fn parse_crypto_attr_valid() {
        let line = "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1pMzQ1NTY3ODkwMTIzNDU=";
        let (tag, suite, key) = parse_crypto_attr(line).unwrap();
        assert_eq!(tag, 1);
        assert_eq!(suite, "AES_CM_128_HMAC_SHA1_80");
        assert!(key.starts_with("inline:"));
    }

    #[test]
    fn parse_crypto_attr_invalid() {
        assert!(parse_crypto_attr("a=rtpmap:0 PCMU/8000").is_none());
        assert!(parse_crypto_attr("a=crypto:").is_none());
    }

    #[test]
    fn build_crypto_attr_format() {
        let attr = build_crypto_attr(1, "dGVzdGtleQ==");
        assert_eq!(
            attr,
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dGVzdGtleQ=="
        );
    }

    #[test]
    fn key_derivation_produces_different_keys() {
        let master_key = [0x0Au8; 16];
        let master_salt = [0x0Bu8; 14];

        let cipher = derive_session_key(&master_key, &master_salt, LABEL_CIPHER_KEY, 16).unwrap();
        let auth = derive_session_key(&master_key, &master_salt, LABEL_AUTH_KEY, 20).unwrap();
        let salt = derive_session_key(&master_key, &master_salt, LABEL_SALT, 14).unwrap();

        // All three should be different.
        assert_ne!(cipher, auth[..16]);
        assert_ne!(
            cipher,
            salt[..14]
                .iter()
                .copied()
                .chain(std::iter::repeat_n(0, 2))
                .collect::<Vec<_>>()
        );
        assert_ne!(auth[..14], salt[..14]);
    }

    #[test]
    fn rtp_header_len_basic() {
        // Standard 12-byte header.
        let rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        assert_eq!(rtp_header_len(&rtp).unwrap(), 12);
    }

    #[test]
    fn rtp_header_len_with_csrc() {
        // CC=2 → 12 + 8 = 20 bytes header.
        let mut rtp = vec![0; 28];
        rtp[0] = 0x82; // V=2, CC=2
        assert_eq!(rtp_header_len(&rtp).unwrap(), 20);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn protect_too_short_fails() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];
        let mut ctx = SrtpContext::new(&master_key, &master_salt).unwrap();
        assert!(ctx.protect(&[0; 4]).is_err());
    }

    #[test]
    fn unprotect_too_short_fails() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];
        let mut ctx = SrtpContext::new(&master_key, &master_salt).unwrap();
        assert!(ctx.unprotect(&[0; 15]).is_err());
    }

    #[test]
    fn wrong_key_fails_auth() {
        let master_key_a = [0x11u8; 16];
        let master_key_b = [0x22u8; 16];
        let master_salt = [0x33u8; 14];

        let mut sender = SrtpContext::new(&master_key_a, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key_b, &master_salt).unwrap();

        let mut rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        rtp.extend_from_slice(&[0xBB; 40]);

        let protected = sender.protect(&rtp).unwrap();
        let result = receiver.unprotect(&protected);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_master_key_length() {
        assert!(SrtpContext::new(&[0; 15], &[0; 14]).is_err());
        assert!(SrtpContext::new(&[0; 17], &[0; 14]).is_err());
    }

    #[test]
    fn invalid_master_salt_length() {
        assert!(SrtpContext::new(&[0; 16], &[0; 13]).is_err());
        assert!(SrtpContext::new(&[0; 16], &[0; 15]).is_err());
    }
}
