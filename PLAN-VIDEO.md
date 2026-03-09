# Video Support (H.264 / VP8) — Implementation Plan

## Overview
Add video calling to xphone-rust. The library handles SDP negotiation, RTP packetization/depacketization, and frame assembly. It does NOT encode/decode video — consumers use platform APIs (VideoToolbox, VA-API, etc.) and feed raw encoded frames in/out.

## API (final agreed design)

```rust
// --- Types ---
pub enum VideoCodec { H264, VP8 }

pub struct VideoFrame {
    pub codec: VideoCodec,
    pub timestamp: u32,
    pub is_keyframe: bool,
    pub data: Vec<u8>,  // H.264: Annex-B NAL units, VP8: raw frame
}

// --- DialOptions ---
pub struct DialOptions {
    pub video: bool,                     // enable video in SDP offer
    pub video_codecs: Vec<VideoCodec>,   // preference order, default: [H264, VP8]
    // video_bandwidth deferred (REMB/TMMBR is its own feature)
}

// --- Call ---
impl Call {
    // Mute all outbound (audio + video) — backwards compatible
    fn mute() -> Result<()>;
    fn unmute() -> Result<()>;

    // Granular per-stream mute
    fn mute_audio() -> Result<()>;
    fn unmute_audio() -> Result<()>;
    fn mute_video() -> Result<()>;
    fn unmute_video() -> Result<()>;

    // Video — None/false if audio-only call
    fn has_video() -> bool;
    fn video_codec() -> Option<VideoCodec>;

    // Assembled frames (common case — library handles FU-A reassembly/fragmentation)
    fn video_reader() -> Option<Receiver<VideoFrame>>;
    fn video_writer() -> Option<Sender<VideoFrame>>;

    // Raw video RTP passthrough (recording, forwarding, power users)
    fn video_rtp_reader() -> Option<Receiver<RtpPacket>>;
    fn video_rtp_writer() -> Option<Sender<RtpPacket>>;

    // Request keyframe from remote (RTCP PLI)
    fn request_keyframe() -> Result<()>;
}
```

---

## PR 1: SDP multi-media

Extend SDP building/parsing to support multiple m= lines. No video flowing yet — audio behavior unchanged.

- [x] Add `VideoCodec` enum to `types.rs` (H264, VP8) with Display, payload type mappings
- [x] Add `video` and `video_codecs` fields to `DialOptions`
- [x] Extend `sdp.rs`: build `m=video` line with dynamic PT (96+)
- [x] Extend `sdp.rs`: `a=rtpmap` for H.264 (`H264/90000`) and VP8 (`VP8/90000`)
- [x] Extend `sdp.rs`: `a=fmtp` for H.264 (`profile-level-id=42e01f;packetization-mode=1`)
- [x] Extend `sdp.rs`: `a=rtcp-fb` lines (`nack`, `nack pli`, `ccm fir`)
- [x] Extend SDP parser: extract video codec, PT, fmtp from remote SDP
- [x] Extend SDP parser: handle multiple m= sections (audio + video)
- [x] Tests: SDP offer with video, SDP answer parsing, audio-only backwards compat
- [x] Verify: `cargo fmt && cargo clippy -- -D warnings && cargo test` all pass

## PR 2: MediaStream refactor (PURE REFACTOR — audio only)

Extract monolithic media pipeline into a per-stream `MediaStream` abstraction. Call holds a `Vec<MediaStream>`, audio is `streams[0]`. Zero new features — all existing tests must pass unchanged.

- [ ] Define `MediaStream` struct (owns: socket, jitter buffer, RTP state, codec, RTCP context)
- [ ] Extract current `media.rs` audio pipeline into `MediaStream`
- [ ] Call holds `Vec<MediaStream>`, `streams[0]` = audio
- [ ] Per-stream mute flag (audio stream only for now)
- [ ] Add `mute_audio()`/`unmute_audio()` methods on Call
- [ ] Update `mute()`/`unmute()` to mute all streams (backwards compatible)
- [ ] DTMF stays on audio stream (stream index 0)
- [ ] Hold/resume operates per-stream (`a=sendonly`/`a=inactive` per m= line)
- [ ] Per-stream RTCP with correct clock rate
- [ ] ALL existing tests pass unchanged (this is the acceptance criteria)
- [ ] Tests: per-stream mute, mute-all behavior
- [ ] Verify: `cargo fmt && cargo clippy -- -D warnings && cargo test` all pass

## PR 3: Video plumbing

Wire up the video stream. Second RTP/RTCP socket pair, video MediaStream, channels on Call.

- [ ] Allocate second RTP+RTCP socket pair when video negotiated
- [ ] Create video `MediaStream` (stream index 1) with 90kHz clock
- [ ] `VideoFrame` struct in `types.rs`
- [ ] `video_reader()`/`video_writer()` channels on Call (assembled frames)
- [ ] `video_rtp_reader()`/`video_rtp_writer()` channels on Call (raw RTP passthrough)
- [ ] `has_video()`, `video_codec()` query methods
- [ ] `mute_video()`/`unmute_video()` — stops sending on video stream
- [ ] `request_keyframe()` — sends RTCP PLI (RFC 4585)
- [ ] Add RTCP PLI/FIR packet building to `rtcp.rs`
- [ ] Wire video in `phone.rs` dial/incoming paths (pass video option through)
- [ ] Wire video SDP in call setup (offer with video, parse answer)
- [ ] Tests: video stream creation, channel wiring, mute_video, PLI generation
- [ ] Verify: `cargo fmt && cargo clippy -- -D warnings && cargo test` all pass

## PR 4: H.264 + VP8 packetizers

RTP-level frame assembly and fragmentation. This is the deepest work.

### H.264 (RFC 6184)
- [ ] `VideoDepacketizer` trait: `fn depacketize(&mut self, pkt: &RtpPacket) -> Option<VideoFrame>`
- [ ] `VideoPacketizer` trait: `fn packetize(&mut self, frame: &VideoFrame, mtu: usize) -> Vec<Vec<u8>>`
- [ ] `H264Depacketizer`: Single NAL unit mode (type 1-23)
- [ ] `H264Depacketizer`: STAP-A aggregation (type 24) — multiple NALs in one RTP
- [ ] `H264Depacketizer`: FU-A fragmentation (type 28) — stateful reassembly across packets
- [ ] `H264Depacketizer`: frame boundary detection (marker bit + timestamp change)
- [ ] `H264Depacketizer`: keyframe detection (NAL type 5 = IDR)
- [ ] `H264Depacketizer`: SPS/PPS parameter set handling
- [ ] `H264Packetizer`: fragment NAL units > MTU into FU-A packets
- [ ] `H264Packetizer`: small NALs sent as Single NAL unit
- [ ] Tests: FU-A reassembly, STAP-A, single NAL, keyframe detect, fragmentation round-trip

### VP8 (RFC 7741)
- [ ] `VP8Depacketizer`: VP8 payload descriptor parsing (S bit, PID, extensions)
- [ ] `VP8Depacketizer`: frame assembly from multiple RTP packets
- [ ] `VP8Depacketizer`: keyframe detection (VP8 frame header P bit)
- [ ] `VP8Packetizer`: split frame into MTU-sized payloads with correct descriptors
- [ ] Tests: VP8 depacketize/packetize round-trip, keyframe detection

### Integration
- [ ] Wire depacketizers into video `MediaStream` inbound path
- [ ] Wire packetizers into video `MediaStream` outbound path
- [ ] Register H264/VP8 by dynamic PT from SDP negotiation
- [ ] Integration test: video call through Docker Asterisk (if Asterisk supports video passthrough)
- [ ] Verify: `cargo fmt && cargo clippy -- -D warnings && cargo test` all pass

---

## Deferred (not in scope)
- Video encode/decode (consumer's job — platform APIs)
- Bandwidth estimation (REMB, TWCC, TMMBR)
- Simulcast / SVC layers
- H.265 / AV1
- BUNDLE (audio + video on same port)
- SRTP for video (reuse existing, just needs second context)
- Camera capture / display rendering

## Files (expected)

| File | What |
|------|------|
| `src/types.rs` | `VideoCodec`, `VideoFrame` |
| `src/sdp.rs` | Multi-media m= lines, video codec params |
| `src/media.rs` | `MediaStream` abstraction, video stream |
| `src/video/mod.rs` | `VideoDepacketizer`, `VideoPacketizer` traits |
| `src/video/h264.rs` | H.264 FU-A/STAP-A/Single NAL packetizer/depacketizer |
| `src/video/vp8.rs` | VP8 packetizer/depacketizer |
| `src/rtcp.rs` | PLI/FIR packet building |
| `src/call.rs` | Video channels, per-stream mute, request_keyframe |
| `src/phone.rs` | Video option in dial/incoming |
| `src/config.rs` | `video`/`video_codecs` in DialOptions |
