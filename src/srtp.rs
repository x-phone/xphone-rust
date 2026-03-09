//! SRTP (Secure RTP) implementation per RFC 3711 with SDES key exchange (RFC 4568).
//!
//! Supports `AES_CM_128_HMAC_SHA1_80` — the mandatory-to-implement cipher suite.
//! Operates on raw RTP byte slices: `protect()` encrypts payload + appends auth tag,
//! `unprotect()` verifies auth tag + decrypts payload.
//!
//! ## Known limitations
//!
//! - TODO: Implement full ROC estimation per RFC 3711 Appendix A instead of the
//!   simplified 0x1000/0xF000 threshold heuristic (fine for sequential telephony
//!   traffic but not robust against large packet reordering).
//! - TODO: Zeroize key material on drop (use `zeroize` crate on `SrtpContext` fields).
//! - TODO: Track per-SSRC crypto state for inbound streams (RFC 3711 §3.2.3).

use std::fmt;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::Mac;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

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

/// SRTCP key derivation labels per RFC 3711 §4.3.1.
const LABEL_SRTCP_CIPHER_KEY: u8 = 0x03;
const LABEL_SRTCP_AUTH_KEY: u8 = 0x04;
const LABEL_SRTCP_SALT: u8 = 0x05;

/// SRTCP index field length (4 bytes: E-bit + 31-bit index).
const SRTCP_INDEX_LEN: usize = 4;
/// Minimum RTCP header size (V, P, RC, PT, length, SSRC).
const RTCP_HEADER_MIN: usize = 8;

/// Default replay window size (128 packets). Covers ~2.5 seconds of audio at 50 pps.
const REPLAY_WINDOW_SIZE: u64 = 128;
const _: () = assert!(
    REPLAY_WINDOW_SIZE <= 128,
    "REPLAY_WINDOW_SIZE cannot exceed 128 (bitmap is u128)"
);

/// Sliding-window replay protection per RFC 3711 §3.3.2.
///
/// Tracks the highest accepted packet index and a bitmask of which of the
/// previous `REPLAY_WINDOW_SIZE` packets have been received. Rejects packets
/// that have already been seen or are too old.
struct ReplayWindow {
    /// Highest accepted 48-bit packet index.
    top: u64,
    /// Bitmask: bit 0 = `top`, bit 1 = `top - 1`, etc.
    bitmap: u128,
    /// Whether we've accepted at least one packet.
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            top: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// Returns `true` if the packet should be rejected (replay or too old).
    fn is_replay(&self, index: u64) -> bool {
        if !self.initialized {
            return false;
        }
        if index > self.top {
            // New packet ahead of window — not a replay.
            return false;
        }
        let delta = self.top - index;
        if delta >= REPLAY_WINDOW_SIZE {
            // Too old — behind the window.
            return true;
        }
        // Check if this exact index was already seen.
        (self.bitmap >> delta) & 1 == 1
    }

    /// Marks a packet index as received. Call only after successful authentication.
    fn accept(&mut self, index: u64) {
        if !self.initialized {
            self.top = index;
            self.bitmap = 1;
            self.initialized = true;
            return;
        }
        if index > self.top {
            let shift = index - self.top;
            if shift >= REPLAY_WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.top = index;
        } else {
            let delta = self.top - index;
            if delta < REPLAY_WINDOW_SIZE {
                self.bitmap |= 1u128 << delta;
            }
        }
    }
}

/// SRTP crypto context for a single direction (send or receive).
///
/// Holds both SRTP (RTP) and SRTCP (RTCP) session keys, derived from the
/// same master key/salt with different KDF labels per RFC 3711 §4.3.1.
pub struct SrtpContext {
    /// Cached AES-128 cipher (expanded key schedule), derived from master key.
    cipher: Aes128,
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
    /// Replay protection window (used by unprotect only).
    replay: ReplayWindow,

    // --- SRTCP fields (RFC 3711 §3.4) ---
    /// SRTCP: AES-128 cipher derived with label 0x03.
    srtcp_cipher: Aes128,
    /// SRTCP: HMAC-SHA1 authentication key (20 bytes), derived with label 0x04.
    srtcp_auth_key: [u8; 20],
    /// SRTCP: session salt (14 bytes), derived with label 0x05.
    srtcp_session_salt: [u8; 14],
    /// SRTCP: monotonically increasing 31-bit packet index (sender side).
    srtcp_index: u32,
    /// SRTCP: replay protection window (receiver side).
    srtcp_replay: ReplayWindow,
}

impl fmt::Debug for SrtpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpContext")
            .field("roc", &self.roc)
            .field("last_seq", &self.last_seq)
            .field("srtcp_index", &self.srtcp_index)
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

        // Derive SRTP session keys (labels 0x00-0x02).
        let cipher_key = derive_session_key(master_key, master_salt, LABEL_CIPHER_KEY, 16);
        let auth_key = derive_session_key(master_key, master_salt, LABEL_AUTH_KEY, 20);
        let salt_bytes = derive_session_key(master_key, master_salt, LABEL_SALT, 14);

        let cipher = Aes128::new(cipher_key[..16].into());
        let mut ak = [0u8; 20];
        ak.copy_from_slice(&auth_key);
        let mut ss = [0u8; 14];
        ss.copy_from_slice(&salt_bytes);

        // Derive SRTCP session keys (labels 0x03-0x05).
        let srtcp_ck = derive_session_key(master_key, master_salt, LABEL_SRTCP_CIPHER_KEY, 16);
        let srtcp_ak_bytes = derive_session_key(master_key, master_salt, LABEL_SRTCP_AUTH_KEY, 20);
        let srtcp_salt = derive_session_key(master_key, master_salt, LABEL_SRTCP_SALT, 14);

        let srtcp_cipher = Aes128::new(srtcp_ck[..16].into());
        let mut srtcp_ak = [0u8; 20];
        srtcp_ak.copy_from_slice(&srtcp_ak_bytes);
        let mut srtcp_ss = [0u8; 14];
        srtcp_ss.copy_from_slice(&srtcp_salt);

        Ok(Self {
            cipher,
            auth_key: ak,
            session_salt: ss,
            roc: 0,
            last_seq: 0,
            seq_initialized: false,
            replay: ReplayWindow::new(),
            srtcp_cipher,
            srtcp_auth_key: srtcp_ak,
            srtcp_session_salt: srtcp_ss,
            srtcp_index: 0,
            srtcp_replay: ReplayWindow::new(),
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
            &self.cipher,
            &self.session_salt,
            ssrc,
            index,
            out.len() - header_len,
        );
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

        // Replay check (RFC 3711 §3.3.2) — cheap, before expensive HMAC.
        if self.replay.is_replay(index) {
            return Err(Error::Other("srtp: replay detected".into()));
        }

        // Verify auth tag (constant-time via `subtle` crate inside `hmac`).
        if !verify_auth_tag(
            &self.auth_key,
            authenticated_portion,
            estimated_roc,
            received_tag,
        ) {
            return Err(Error::Other("srtp: authentication failed".into()));
        }

        // Auth passed — update ROC and replay window.
        self.update_roc_receiver(seq, estimated_roc);
        self.replay.accept(index);

        // Decrypt payload.
        let payload_len = authenticated_len - header_len;
        let keystream =
            generate_keystream(&self.cipher, &self.session_salt, ssrc, index, payload_len);

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

    // --- SRTCP (RFC 3711 §3.4) ---

    /// Encrypts an RTCP packet and appends SRTCP index + auth tag.
    ///
    /// Layout: `[header(8)][encrypted_payload][SRTCP_index(4)][auth_tag(10)]`
    /// - First 8 bytes stay cleartext (authenticated but not encrypted).
    /// - SRTCP index has E-bit (bit 31) set to indicate encryption.
    /// - Auth tag covers the entire encrypted packet + SRTCP index.
    pub fn protect_rtcp(&mut self, rtcp: &[u8]) -> Result<Vec<u8>> {
        if rtcp.len() < RTCP_HEADER_MIN {
            return Err(Error::Other("srtcp: packet too short".into()));
        }

        let ssrc = u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]);
        let index = self.srtcp_index;
        self.srtcp_index += 1;

        let mut out = rtcp.to_vec();

        // Encrypt bytes 8..end (header stays cleartext).
        if out.len() > RTCP_HEADER_MIN {
            let payload_len = out.len() - RTCP_HEADER_MIN;
            let keystream = generate_keystream(
                &self.srtcp_cipher,
                &self.srtcp_session_salt,
                ssrc,
                index as u64,
                payload_len,
            );
            for i in RTCP_HEADER_MIN..out.len() {
                out[i] ^= keystream[i - RTCP_HEADER_MIN];
            }
        }

        // Append SRTCP index with E-bit set (bit 31 = 1 → encrypted).
        let srtcp_index_word = 0x80000000 | index;
        out.extend_from_slice(&srtcp_index_word.to_be_bytes());

        // Auth tag covers: encrypted RTCP + SRTCP index.
        let tag = compute_srtcp_auth_tag(&self.srtcp_auth_key, &out);
        out.extend_from_slice(&tag);

        Ok(out)
    }

    /// Verifies auth tag, strips SRTCP index, and decrypts the SRTCP packet.
    ///
    /// Input: SRTCP bytes `[header][encrypted_payload][SRTCP_index(4)][auth_tag(10)]`
    /// Output: raw RTCP bytes.
    pub fn unprotect_rtcp(&mut self, srtcp: &[u8]) -> Result<Vec<u8>> {
        // Minimum: 8 (header) + 4 (SRTCP index) + 10 (auth tag) = 22.
        if srtcp.len() < RTCP_HEADER_MIN + SRTCP_INDEX_LEN + AUTH_TAG_LEN {
            return Err(Error::Other("srtcp: packet too short for unprotect".into()));
        }

        let tag_start = srtcp.len() - AUTH_TAG_LEN;
        let index_start = tag_start - SRTCP_INDEX_LEN;
        let received_tag = &srtcp[tag_start..];
        let authenticated_portion = &srtcp[..tag_start]; // everything before auth tag

        // Extract SRTCP index word (E-bit + 31-bit index).
        let index_word = u32::from_be_bytes([
            srtcp[index_start],
            srtcp[index_start + 1],
            srtcp[index_start + 2],
            srtcp[index_start + 3],
        ]);
        let encrypted = (index_word & 0x80000000) != 0;
        let index = index_word & 0x7FFFFFFF;

        // Replay check.
        if self.srtcp_replay.is_replay(index as u64) {
            return Err(Error::Other("srtcp: replay detected".into()));
        }

        // Verify auth tag (constant-time via hmac crate).
        if !verify_srtcp_auth_tag(&self.srtcp_auth_key, authenticated_portion, received_tag) {
            return Err(Error::Other("srtcp: authentication failed".into()));
        }

        // Auth passed — update replay window.
        self.srtcp_replay.accept(index as u64);

        // The RTCP data is everything before the SRTCP index.
        let mut out = srtcp[..index_start].to_vec();

        // Decrypt if E-bit is set.
        if encrypted && out.len() > RTCP_HEADER_MIN {
            let ssrc = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
            let payload_len = out.len() - RTCP_HEADER_MIN;
            let keystream = generate_keystream(
                &self.srtcp_cipher,
                &self.srtcp_session_salt,
                ssrc,
                index as u64,
                payload_len,
            );
            for i in RTCP_HEADER_MIN..out.len() {
                out[i] ^= keystream[i - RTCP_HEADER_MIN];
            }
        }

        Ok(out)
    }
}

/// Derives a session key using AES-128-CM key derivation (RFC 3711 §4.3.1).
///
/// key_derivation_rate = 0 (default), so `r = index DIV key_derivation_rate = 0`.
/// `x = label || r` (7 bytes of label padded to 14 bytes) XOR salt.
/// Session key = AES-CM(master_key, x, 0) for required length.
fn derive_session_key(master_key: &[u8], master_salt: &[u8], label: u8, out_len: usize) -> Vec<u8> {
    let cipher = Aes128::new(master_key.into());

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
        let mut iv = aes::Block::default();
        iv[..14].copy_from_slice(&x);
        iv[14] = (block_counter >> 8) as u8;
        iv[15] = block_counter as u8;

        cipher.encrypt_block(&mut iv);
        result.extend_from_slice(&iv);
    }

    result.truncate(out_len);
    result
}

/// Generates an AES-CM keystream for SRTP payload encryption.
///
/// IV = (ssrc XOR salt) with packet index, per RFC 3711 §4.1.1.
fn generate_keystream(
    cipher: &Aes128,
    session_salt: &[u8],
    ssrc: u32,
    index: u64,
    len: usize,
) -> Vec<u8> {
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

        let mut block = aes::Block::clone_from_slice(&block_iv);
        cipher.encrypt_block(&mut block);
        keystream.extend_from_slice(&block);
    }

    keystream.truncate(len);
    keystream
}

/// Computes the HMAC-SHA1-80 auth tag over the authenticated portion + ROC (for protect).
fn compute_auth_tag(auth_key: &[u8], authenticated: &[u8], roc: u32) -> [u8; AUTH_TAG_LEN] {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(authenticated);
    mac.update(&roc.to_be_bytes());
    let full_mac = mac.finalize().into_bytes();
    let mut result = [0u8; AUTH_TAG_LEN];
    result.copy_from_slice(&full_mac[..AUTH_TAG_LEN]);
    result
}

/// Verifies auth tag using HMAC's built-in constant-time comparison (via `subtle` crate).
fn verify_auth_tag(auth_key: &[u8], authenticated: &[u8], roc: u32, received_tag: &[u8]) -> bool {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(authenticated);
    mac.update(&roc.to_be_bytes());
    mac.verify_truncated_left(received_tag).is_ok()
}

/// Computes HMAC-SHA1-80 auth tag for SRTCP.
/// Unlike SRTP, the SRTCP index is already part of the authenticated data (no separate ROC append).
fn compute_srtcp_auth_tag(auth_key: &[u8], authenticated: &[u8]) -> [u8; AUTH_TAG_LEN] {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(authenticated);
    let full_mac = mac.finalize().into_bytes();
    let mut result = [0u8; AUTH_TAG_LEN];
    result.copy_from_slice(&full_mac[..AUTH_TAG_LEN]);
    result
}

/// Verifies SRTCP auth tag using constant-time comparison.
fn verify_srtcp_auth_tag(auth_key: &[u8], authenticated: &[u8], received_tag: &[u8]) -> bool {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(authenticated);
    mac.verify_truncated_left(received_tag).is_ok()
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

        let cipher = derive_session_key(&master_key, &master_salt, LABEL_CIPHER_KEY, 16);
        let auth = derive_session_key(&master_key, &master_salt, LABEL_AUTH_KEY, 20);
        let salt = derive_session_key(&master_key, &master_salt, LABEL_SALT, 14);

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

    // --- Replay protection tests ---

    fn make_rtp(seq: u16) -> Vec<u8> {
        let mut rtp = vec![0x80, 0, (seq >> 8) as u8, seq as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        rtp.extend_from_slice(&[0xAA; 40]);
        rtp
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(!w.is_replay(100));
        w.accept(100);
        assert!(w.is_replay(100)); // exact duplicate
    }

    #[test]
    fn replay_window_accepts_new_packets() {
        let mut w = ReplayWindow::new();
        for i in 0..200u64 {
            assert!(!w.is_replay(i));
            w.accept(i);
        }
    }

    #[test]
    fn replay_window_rejects_old_packets() {
        let mut w = ReplayWindow::new();
        // Accept packet 200.
        w.accept(200);
        // Packet 200 - REPLAY_WINDOW_SIZE = too old.
        assert!(w.is_replay(200 - REPLAY_WINDOW_SIZE));
        // Packet 0 is way too old.
        assert!(w.is_replay(0));
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Accept packets 0..=50.
        for i in 0..=50u64 {
            w.accept(i);
        }
        // Accept packet 100 (jump ahead).
        w.accept(100);
        // Packets 51..100 are within window and not yet seen.
        for i in 51..100u64 {
            assert!(!w.is_replay(i), "packet {} should not be a replay", i);
            w.accept(i);
        }
        // All explicitly accepted packets should now be replays.
        for i in 0..=100u64 {
            assert!(w.is_replay(i), "packet {} should be a replay", i);
        }
    }

    #[test]
    fn replay_window_boundary() {
        let mut w = ReplayWindow::new();
        w.accept(REPLAY_WINDOW_SIZE); // top = 128
                                      // delta = REPLAY_WINDOW_SIZE - 1 → last valid position in window.
        assert!(!w.is_replay(1)); // 128 - 1 = 127, within window
                                  // delta = REPLAY_WINDOW_SIZE → just outside window.
        assert!(w.is_replay(0)); // 128 - 0 = 128, too old
    }

    #[test]
    fn replay_window_large_jump() {
        let mut w = ReplayWindow::new();
        w.accept(0);
        // Jump far ahead — old bitmap should be cleared.
        w.accept(1000);
        assert!(w.is_replay(1000));
        assert!(w.is_replay(0)); // way behind window
        assert!(!w.is_replay(999)); // within window, not yet seen
        assert!(!w.is_replay(1001)); // ahead of top
    }

    #[test]
    fn srtp_replay_detected() {
        let master_key = [0x09u8; 16];
        let master_salt = [0x0Au8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        let rtp = make_rtp(1);
        let protected = sender.protect(&rtp).unwrap();

        // First unprotect succeeds.
        let result = receiver.unprotect(&protected);
        assert!(result.is_ok());

        // Replay of the same packet is rejected.
        let result = receiver.unprotect(&protected);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn srtp_out_of_order_within_window_ok() {
        let master_key = [0x0Bu8; 16];
        let master_salt = [0x0Cu8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        // Protect packets 1..=5.
        let mut protected = Vec::new();
        for seq in 1u16..=5 {
            let rtp = make_rtp(seq);
            protected.push(sender.protect(&rtp).unwrap());
        }

        // Receive out of order: 5, 3, 1, 2, 4.
        for &idx in &[4, 2, 0, 1, 3] {
            let result = receiver.unprotect(&protected[idx]);
            assert!(result.is_ok(), "seq {} should succeed", idx + 1);
        }

        // All should now be replays.
        for pkt in &protected {
            let result = receiver.unprotect(pkt);
            assert!(result.is_err());
        }
    }

    #[test]
    fn srtp_old_packet_rejected() {
        let master_key = [0x0Du8; 16];
        let master_salt = [0x0Eu8; 14];

        let mut sender = SrtpContext::new(&master_key, &master_salt).unwrap();
        let mut receiver = SrtpContext::new(&master_key, &master_salt).unwrap();

        // Protect and save packet with seq=1.
        let old_pkt = sender.protect(&make_rtp(1)).unwrap();

        // Send 200 more packets to push seq=1 out of the window.
        for seq in 2u16..202 {
            let pkt = sender.protect(&make_rtp(seq)).unwrap();
            receiver.unprotect(&pkt).unwrap();
        }

        // Old packet (seq=1) is now behind the window.
        let result = receiver.unprotect(&old_pkt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    // --- SRTCP tests ---

    /// Builds a minimal RTCP SR for testing (28 bytes: header + sender info, no report blocks).
    fn make_rtcp_sr(ssrc: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        buf[0] = 0x80; // V=2, P=0, RC=0
        buf[1] = 200; // PT=SR
        buf[2] = 0;
        buf[3] = 6; // length = 6 words
        buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
        // NTP timestamp, RTP timestamp, packet/octet counts are zero — fine for crypto tests.
        buf
    }

    #[test]
    fn srtcp_protect_unprotect_round_trip() {
        let mk = [0x10u8; 16];
        let ms = [0x11u8; 14];

        let mut sender = SrtpContext::new(&mk, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk, &ms).unwrap();

        let rtcp = make_rtcp_sr(0xDEADBEEF);
        let protected = sender.protect_rtcp(&rtcp).unwrap();
        let decrypted = receiver.unprotect_rtcp(&protected).unwrap();
        assert_eq!(decrypted, rtcp);
    }

    #[test]
    fn srtcp_header_stays_cleartext() {
        let mk = [0x12u8; 16];
        let ms = [0x13u8; 14];

        let mut ctx = SrtpContext::new(&mk, &ms).unwrap();
        let rtcp = make_rtcp_sr(0xCAFEBABE);
        let protected = ctx.protect_rtcp(&rtcp).unwrap();

        // First 8 bytes (V, PT, length, SSRC) must be identical.
        assert_eq!(&protected[..8], &rtcp[..8]);
    }

    #[test]
    fn srtcp_e_bit_set() {
        let mk = [0x14u8; 16];
        let ms = [0x15u8; 14];

        let mut ctx = SrtpContext::new(&mk, &ms).unwrap();
        let rtcp = make_rtcp_sr(0x11111111);
        let protected = ctx.protect_rtcp(&rtcp).unwrap();

        // SRTCP index is at [len - 14 .. len - 10] (before the 10-byte auth tag).
        let idx_start = protected.len() - AUTH_TAG_LEN - SRTCP_INDEX_LEN;
        let index_word = u32::from_be_bytes([
            protected[idx_start],
            protected[idx_start + 1],
            protected[idx_start + 2],
            protected[idx_start + 3],
        ]);
        assert_ne!(index_word & 0x80000000, 0, "E-bit must be set");
        assert_eq!(index_word & 0x7FFFFFFF, 0, "first packet index should be 0");
    }

    #[test]
    fn srtcp_index_increments() {
        let mk = [0x16u8; 16];
        let ms = [0x17u8; 14];

        let mut ctx = SrtpContext::new(&mk, &ms).unwrap();
        let rtcp = make_rtcp_sr(0x22222222);

        for expected_idx in 0u32..5 {
            let protected = ctx.protect_rtcp(&rtcp).unwrap();
            let idx_start = protected.len() - AUTH_TAG_LEN - SRTCP_INDEX_LEN;
            let index_word = u32::from_be_bytes([
                protected[idx_start],
                protected[idx_start + 1],
                protected[idx_start + 2],
                protected[idx_start + 3],
            ]);
            assert_eq!(index_word & 0x7FFFFFFF, expected_idx);
        }
    }

    #[test]
    fn srtcp_tampered_auth_fails() {
        let mk = [0x18u8; 16];
        let ms = [0x19u8; 14];

        let mut sender = SrtpContext::new(&mk, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk, &ms).unwrap();

        let rtcp = make_rtcp_sr(0x33333333);
        let mut protected = sender.protect_rtcp(&rtcp).unwrap();

        // Flip a byte in the encrypted payload.
        protected[10] ^= 0xFF;

        let result = receiver.unprotect_rtcp(&protected);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication"));
    }

    #[test]
    fn srtcp_replay_detected() {
        let mk = [0x1Au8; 16];
        let ms = [0x1Bu8; 14];

        let mut sender = SrtpContext::new(&mk, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk, &ms).unwrap();

        let rtcp = make_rtcp_sr(0x44444444);
        let protected = sender.protect_rtcp(&rtcp).unwrap();

        // First unprotect succeeds.
        assert!(receiver.unprotect_rtcp(&protected).is_ok());

        // Replay is rejected.
        let result = receiver.unprotect_rtcp(&protected);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn srtcp_wrong_key_fails() {
        let mk_a = [0x1Cu8; 16];
        let mk_b = [0x1Du8; 16];
        let ms = [0x1Eu8; 14];

        let mut sender = SrtpContext::new(&mk_a, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk_b, &ms).unwrap();

        let rtcp = make_rtcp_sr(0x55555555);
        let protected = sender.protect_rtcp(&rtcp).unwrap();
        assert!(receiver.unprotect_rtcp(&protected).is_err());
    }

    #[test]
    fn srtcp_protect_too_short_fails() {
        let mk = [0x1Fu8; 16];
        let ms = [0x20u8; 14];
        let mut ctx = SrtpContext::new(&mk, &ms).unwrap();
        assert!(ctx.protect_rtcp(&[0; 4]).is_err());
    }

    #[test]
    fn srtcp_unprotect_too_short_fails() {
        let mk = [0x21u8; 16];
        let ms = [0x22u8; 14];
        let mut ctx = SrtpContext::new(&mk, &ms).unwrap();
        // Need at least 22 bytes (8 + 4 + 10).
        assert!(ctx.unprotect_rtcp(&[0; 21]).is_err());
    }

    #[test]
    fn srtcp_key_derivation_differs_from_srtp() {
        let mk = [0x23u8; 16];
        let ms = [0x24u8; 14];

        let srtp_ck = derive_session_key(&mk, &ms, LABEL_CIPHER_KEY, 16);
        let srtcp_ck = derive_session_key(&mk, &ms, LABEL_SRTCP_CIPHER_KEY, 16);
        assert_ne!(srtp_ck, srtcp_ck, "SRTP and SRTCP cipher keys must differ");

        let srtp_ak = derive_session_key(&mk, &ms, LABEL_AUTH_KEY, 20);
        let srtcp_ak = derive_session_key(&mk, &ms, LABEL_SRTCP_AUTH_KEY, 20);
        assert_ne!(srtp_ak, srtcp_ak, "SRTP and SRTCP auth keys must differ");

        let srtp_salt = derive_session_key(&mk, &ms, LABEL_SALT, 14);
        let srtcp_salt = derive_session_key(&mk, &ms, LABEL_SRTCP_SALT, 14);
        assert_ne!(srtp_salt, srtcp_salt, "SRTP and SRTCP salts must differ");
    }

    #[test]
    fn srtcp_multiple_packets_round_trip() {
        let mk = [0x25u8; 16];
        let ms = [0x26u8; 14];

        let mut sender = SrtpContext::new(&mk, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk, &ms).unwrap();

        for i in 0u32..20 {
            let rtcp = make_rtcp_sr(0xAA000000 | i);
            let protected = sender.protect_rtcp(&rtcp).unwrap();
            let decrypted = receiver.unprotect_rtcp(&protected).unwrap();
            assert_eq!(decrypted, rtcp, "mismatch at SRTCP index {}", i);
        }
    }

    #[test]
    fn srtcp_out_of_order_within_window() {
        let mk = [0x27u8; 16];
        let ms = [0x28u8; 14];

        let mut sender = SrtpContext::new(&mk, &ms).unwrap();
        let mut receiver = SrtpContext::new(&mk, &ms).unwrap();

        // Protect 5 RTCP packets.
        let rtcp = make_rtcp_sr(0xBBBBBBBB);
        let mut protected = Vec::new();
        for _ in 0..5 {
            protected.push(sender.protect_rtcp(&rtcp).unwrap());
        }

        // Receive in reverse order — all should succeed within the replay window.
        for (i, pkt) in protected.iter().rev().enumerate() {
            let result = receiver.unprotect_rtcp(pkt);
            assert!(result.is_ok(), "reverse packet {} should succeed", i);
        }
    }
}
