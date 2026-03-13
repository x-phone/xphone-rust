# xphone

[![Crates.io](https://img.shields.io/crates/v/xphone.svg)](https://crates.io/crates/xphone)
[![docs.rs](https://docs.rs/xphone/badge.svg)](https://docs.rs/xphone)
[![CI](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**A Rust library for embedding real phone calls into any application.**
No PBX. No Twilio. No per-minute fees. Just clean PCM audio, in and out.

> **xphone** is also available in [Go](https://github.com/x-phone/xphone-go).

xphone handles SIP signaling, RTP media, codecs, and call state so you can focus on what your application actually does with the audio — whether that's feeding frames to a speech model, recording to disk, or building a full softphone.

xphone supports two connection modes:

1. **`Phone`** — register to a SIP trunk or PBX like a normal endpoint
2. **`Server`** — accept and place calls directly with trusted SIP peers or trunk providers

In both cases, your application gets the same `Call` API and the same PCM/media pipeline.

---

## Why xphone?

Building anything that needs to make or receive real phone calls is surprisingly painful. Your options are usually:

- **Twilio / Vonage / Telnyx SDKs** — easy to start, but you're paying platform fees per minute, your audio routes through their cloud, and the media pipeline is a black box.
- **Raw SIP libraries** — full control, but you wire everything yourself: signaling, RTP sessions, jitter buffers, codec negotiation, call state machines. Weeks of work before you can answer a call.
- **Asterisk / FreeSWITCH via AMI/ARI** — mature and powerful, but now you're running and operating a PBX just to make a call from your application.

xphone sits in the middle: a high-level, event-driven Rust API that handles all the protocol complexity and hands you clean PCM audio frames — ready to pipe into Whisper, Deepgram, or any audio pipeline you choose. Your audio never leaves your infrastructure unless you choose to send it somewhere.

---

## What can you build with it?

### AI Voice Agents
Connect a real phone number directly to your LLM pipeline. No cloud telephony platform required.

```
DID (phone number)
    +-- SIP Trunk (Telnyx, Twilio SIP, Vonage...)
            +-- xphone (Phone mode: register, or Server mode: direct)
                    |-- pcm_reader ---------> Whisper / Deepgram (speech-to-text)
                    +-- paced_pcm_writer <-- ElevenLabs / TTS (text-to-speech)
```

Your bot gets a real phone number, connects to a SIP trunk provider (via registration or direct trunk), and handles calls end-to-end — no Asterisk, no middleman, no per-minute platform fees.

### Softphones & Click-to-Call
Embed a SIP phone into any Rust application. Accept calls, dial out, hold, transfer — all from code. Works against any SIP PBX (Asterisk, FreeSWITCH, 3CX, Cisco) or directly to a SIP trunk.

### Call Recording & Monitoring
Tap into the PCM audio stream on any call and write it to disk, stream it to S3, or run real-time transcription and analysis.

### Outbound Dialers
Programmatically dial numbers, play audio, detect DTMF responses — classic IVR automation without the IVR infrastructure.

### Unit-testable Call Flows
`MockPhone` and `MockCall` provide the full `Phone` and `Call` APIs. Test every branch of your call logic — accept, reject, hold, transfer, DTMF, hangup — without a real SIP server or network. This is a first-class design goal, not an afterthought.

---

## No PBX required

A common misconception: you don't need Asterisk or FreeSWITCH to use xphone. A SIP trunk is just a SIP server — xphone connects to it directly.

**Phone mode** — register with a SIP trunk like a normal endpoint:

```rust
let phone = Phone::new(Config {
    username: "your-username".into(),
    password: "your-password".into(),
    host: "sip.telnyx.com".into(),
    ..Config::default()
});
```

**Server mode** — accept SIP INVITEs directly from trunk providers or PBXes (no registration):

```rust
let server = Server::new(ServerConfig {
    listen: "0.0.0.0:5080".into(),
    peers: vec![PeerConfig {
        name: "twilio".into(),
        hosts: vec!["54.172.60.0/30".into()],
        ..Default::default()
    }],
    ..Default::default()
});
```

Both modes produce the same `Call` object — your call-handling code works identically regardless of how the call arrived.

> A PBX only becomes relevant when you need to route calls across multiple agents or extensions. For single-purpose applications — a voice bot, a recorder, a dialer — xphone + SIP trunk is all you need.

---

## Self-hosted vs cloud telephony

Most cloud telephony SDKs are excellent for getting started, but come with tradeoffs that matter at scale or in regulated environments:

| | xphone + SIP Trunk | Cloud Telephony SDK |
|---|---|---|
| **Cost** | SIP trunk rates only | Per-minute platform fees on top |
| **Audio privacy** | Media stays on your infrastructure | Audio routed through provider cloud |
| **Latency** | Direct RTP to your server | Extra hop through provider media servers |
| **Control** | Full access to raw PCM / RTP | API-level access only |
| **Compliance** | You control data residency | Provider's data policies apply |
| **Complexity** | You manage the SIP stack | Provider handles it |

xphone is the right choice when cost, latency, privacy, or compliance make self-hosting the media pipeline worth it.

> **SIP trunk providers** (Telnyx, Twilio SIP, Vonage, Bandwidth, and many others) offer DIDs and SIP credentials at wholesale rates — typically $0.001-$0.005/min, with no additional platform markup when you bring your own SIP client.

---

## Quick Start

### Install

Add to your `Cargo.toml`:

```toml
[dependencies]
xphone = "0.4"
```

Requires Rust 1.87+.

---

### Build an AI voice agent in ~40 lines

```rust
use std::sync::Arc;
use xphone::{Phone, Config, Call};

fn main() {
    let phone = Phone::new(Config {
        username: "1001".into(),
        password: "secret".into(),
        host: "sip.telnyx.com".into(),
        rtp_port_min: 10000,
        rtp_port_max: 20000,
        ..Config::default()
    });

    phone.on_registered(|| {
        println!("Registered -- ready to receive calls");
    });

    phone.on_incoming(move |call: Arc<Call>| {
        println!("Incoming call from {}", call.from());
        call.accept().unwrap();

        // Read decoded audio -- pipe to Whisper, Deepgram, etc.
        if let Some(pcm_rx) = call.pcm_reader() {
            std::thread::spawn(move || {
                while let Ok(frame) = pcm_rx.recv() {
                    // frame is Vec<i16>, mono, 8000 Hz, 160 samples (20ms)
                    transcribe(&frame);
                }
            });
        }
    });

    phone.connect().expect("failed to connect");

    // Run forever.
    std::thread::park();
}
```

PCM format: `Vec<i16>`, mono, 8000 Hz, 160 samples per frame (20ms) — the standard input format for most speech-to-text APIs.

---

### Make an outbound call

```rust
use xphone::DialOptions;
use std::time::Duration;

let opts = DialOptions {
    early_media: true, // hear ringback tones and IVR prompts before answer
    timeout: Duration::from_secs(30),
    ..Default::default()
};

let call = phone.dial("+15551234567", opts)?;

// Stream audio in and out.
if let Some(pcm_rx) = call.pcm_reader() {
    std::thread::spawn(move || {
        while let Ok(frame) = pcm_rx.recv() {
            process_audio(&frame);
        }
    });
}
```

`Dial` accepts a full SIP URI or just the number — if no host is given, your configured SIP server is used.

---

### Server mode (direct SIP trunk)

For deployments that receive SIP INVITEs directly from trunk providers (Twilio SIP Trunk, Telnyx, etc.) or PBXes — no registration needed:

```rust
use xphone::{Server, ServerConfig, PeerConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> xphone::Result<()> {
    let server = Server::new(ServerConfig {
        listen: "0.0.0.0:5080".into(),
        rtp_port_min: 10000,
        rtp_port_max: 20000,
        peers: vec![
            PeerConfig {
                name: "office-pbx".into(),
                host: Some("192.168.1.10".parse().unwrap()),
                ..Default::default()
            },
            PeerConfig {
                name: "twilio".into(),
                hosts: vec!["54.172.60.0/30".into(), "54.244.51.0/30".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    });

    // Same Call API as Phone mode
    server.on_incoming(|call| {
        println!("Incoming from {}", call.from());
        call.accept().unwrap();

        if let Some(pcm_rx) = call.pcm_reader() {
            std::thread::spawn(move || {
                while let Ok(frame) = pcm_rx.recv() {
                    transcribe(&frame);
                }
            });
        }
    });

    // Outbound calls to a named peer
    // let call = server.dial("office-pbx", "+15551234567", "+15559876543")?;

    server.listen().await
}
```

Peers are authenticated by source IP (fastest path) or SIP digest auth. Both `Phone` and `Server` produce identical `Call` objects — your call-handling code works with either mode.

---

## Features

| Feature | Status |
|---|---|
| **Connection Modes** | |
| Phone — SIP registration with PBX or trunk | Done |
| Server — direct SIP trunk host (no registration) | Done |
| Peer authentication (IP allowlist, CIDR, digest auth) | Done |
| **Calling** | |
| SIP Registration (auth, keepalive, auto-reconnect) | Done |
| Inbound & outbound calls | Done |
| Hold / Resume (re-INVITE) | Done |
| Blind transfer (REFER) | Done |
| Attended transfer (REFER with Replaces, RFC 3891) | Done |
| Call waiting (`Phone.calls()` API) | Done |
| Session timers (RFC 4028) | Done |
| Mute / Unmute | Done |
| 302 redirect following | Done |
| Early media (183 Session Progress) | Done |
| **DTMF** | |
| RFC 4733 (RTP telephone-events) | Done |
| SIP INFO (RFC 2976) | Done |
| **Audio codecs** | |
| G.711 u-law (PCMU), G.711 A-law (PCMA) | Done |
| G.722 wideband | Done |
| Opus (optional `opus-codec` feature, requires libopus) | Done |
| G.729 (optional `g729-codec` feature, pure Rust) | Done |
| PCM audio frames (`Vec<i16>`) and raw RTP access | Done |
| Jitter buffer | Done |
| **Video** | |
| H.264 (RFC 6184) and VP8 (RFC 7741) | Done |
| Video RTP pipeline with depacketizer/packetizer | Done |
| Mid-call video upgrade/downgrade (re-INVITE) | Done |
| Video upgrade accept/reject API (privacy-safe) | Done |
| VideoReader / VideoWriter / VideoRTPReader / VideoRTPWriter | Done |
| RTCP PLI/FIR for keyframe requests | Done |
| **Security** | |
| SRTP (AES_CM_128_HMAC_SHA1_80) with SDES key exchange | Done |
| SRTP replay protection (RFC 3711) | Done |
| SRTCP encryption (RFC 3711 §3.4) | Done |
| Key material zeroization | Done |
| Video SRTP (separate contexts for audio/video) | Done |
| **Network** | |
| TCP and TLS SIP transport | Done |
| STUN NAT traversal (RFC 5389) | Done |
| TURN relay for symmetric NAT (RFC 5766) | Done |
| ICE-Lite (RFC 8445 §2.2) | Done |
| RTCP Sender/Receiver Reports (RFC 3550) | Done |
| **Messaging** | |
| SIP MESSAGE instant messaging (RFC 3428) | Done |
| SIP SUBSCRIBE/NOTIFY (RFC 6665) | Done |
| Generic event subscriptions (presence, dialog, etc.) | Done |
| MWI / voicemail notification (RFC 3842) | Done |
| BLF / Busy Lamp Field monitoring | Done |
| **Testing** | |
| MockPhone & MockCall for unit testing | Done |

---

## Configuration

```rust
use xphone::{Config, PhoneBuilder, Phone, DtmfMode};
use xphone::types::Codec;
use std::time::Duration;

// Direct struct construction:
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "pbx.example.com".into(),
    port: 5060,
    transport: "udp".into(),                              // "udp" | "tcp" | "tls"
    rtp_port_min: 10000,
    rtp_port_max: 20000,
    codec_prefs: vec![Codec::Opus, Codec::PCMU],          // codec preference order
    jitter_buffer: Duration::from_millis(50),
    media_timeout: Duration::from_secs(30),
    nat_keepalive_interval: Some(Duration::from_secs(25)),
    stun_server: Some("stun.l.google.com:19302".into()),
    srtp: true,
    dtmf_mode: DtmfMode::Rfc4733,                        // or SipInfo, Both
    ice: true,
    turn_server: Some("turn.example.com:3478".into()),
    turn_username: Some("user".into()),
    turn_password: Some("pass".into()),
    ..Config::default()
});

// Or use the builder:
let phone = Phone::new(
    PhoneBuilder::new()
        .credentials("1001", "secret", "pbx.example.com")
        .rtp_ports(10000, 20000)
        .codecs(vec![Codec::Opus, Codec::PCMU])
        .srtp(true)
        .dtmf_mode(DtmfMode::Rfc4733)
        .stun_server("stun.l.google.com:19302")
        .ice(true)
        .turn_server("turn.example.com:3478")
        .turn_credentials("user", "pass")
        .nat_keepalive(Duration::from_secs(25))
        .build(),
);
```

See the [API documentation](https://docs.rs/xphone) for all options.

### RTP port range

Each concurrent call requires one even-numbered UDP port for RTP media. The `rtp_ports(min, max)` setting controls the range:

| Range | Concurrent calls | Use case |
|-------|-----------------|----------|
| `0, 0` (default) | OS-assigned | Development / single call |
| `10000, 10100` | 50 | Small deployment |
| `10000, 20000` | 5,000 | Production |

```rust
ConfigBuilder::new("sip.example.com", "alice", "secret")
    .rtp_ports(10000, 20000)
    .build();
```

> **Note:** When the port range is exhausted, new inbound calls receive a 500 error and new outbound calls fail. The error is not always obvious — if you're seeing intermittent call failures under load, check your port range first.

---

## NAT Traversal

xphone supports three levels of NAT traversal, depending on your network environment:

### STUN (most deployments)

Discovers your public IP via a STUN Binding Request. Sufficient when your NAT allows direct UDP:

```rust
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    stun_server: Some("stun.l.google.com:19302".into()),
    ..Config::default()
});
```

Common public STUN servers: `stun.l.google.com:19302`, `stun1.l.google.com:19302`, `stun.cloudflare.com:3478`

### TURN (symmetric NAT)

For environments where STUN alone fails (cloud VMs, corporate firewalls with symmetric NAT), TURN relays media through an intermediary:

```rust
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    turn_server: Some("turn.example.com:3478".into()),
    turn_username: Some("user".into()),
    turn_password: Some("pass".into()),
    ..Config::default()
});
```

### ICE-Lite

Enables ICE-Lite (RFC 8445 §2.2) for SDP-level candidate negotiation:

```rust
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    ice: true,
    stun_server: Some("stun.l.google.com:19302".into()),
    ..Config::default()
});
```

> Only enable STUN/TURN/ICE when the SIP server is on the public internet. Do not enable it when connecting via VPN or private network, as the discovered address will be unreachable from the server.

---

## Opus Codec

Opus support is optional and requires `libopus` installed on the system. The default build needs no external C libraries.

### Install libopus

```bash
# Debian / Ubuntu
sudo apt-get install libopus-dev

# macOS
brew install opus
```

### Build with Opus

```bash
cargo build --features opus-codec
cargo test --features opus-codec
```

### Usage

```rust
use xphone::types::Codec;

let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    codec_prefs: vec![Codec::Opus, Codec::PCMU], // prefer Opus, fall back to PCMU
    ..Config::default()
});
```

Opus runs at 8kHz natively — no resampling needed. PCM frames remain `Vec<i16>`, mono, 160 samples (20ms), same as G.711. RTP timestamps use 48kHz clock per RFC 7587.

Without the `opus-codec` feature, `Codec::Opus` is accepted in configuration but will not be negotiated (the codec processor returns `None`, so SDP negotiation falls through to the next preferred codec).

---

## G.729 Codec

G.729 support is optional via the `g729-codec` feature. Unlike Opus, it uses a pure Rust implementation (`g729-sys`) — no system libraries required.

### Build with G.729

```bash
cargo build --features g729-codec
cargo test --features g729-codec
```

### Usage

```rust
use xphone::types::Codec;

let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    codec_prefs: vec![Codec::G729, Codec::PCMU],
    ..Config::default()
});
```

G.729 runs at 8kHz, 8 kbps CS-ACELP. SDP advertises `annexb=no` — Annex B (VAD/CNG) is not supported.

---

## Call States

```
Idle -> Ringing (inbound) or Dialing (outbound)
     -> RemoteRinging -> Active <-> OnHold -> Ended
```

```rust
call.on_state(|state| {
    println!("State: {:?}", state);
});

call.on_ended(|reason| {
    println!("Ended: {:?}", reason);
});
```

---

## Working with Audio

xphone exposes audio as a stream of **PCM frames** through crossbeam channels. Understanding the frame format and channel behaviour is key to building anything on top of the library.

### Frame format

Every frame is a `Vec<i16>` with these fixed properties:

| Property | Value |
|---|---|
| Encoding | 16-bit signed PCM |
| Channels | Mono |
| Sample rate | 8000 Hz |
| Samples per frame | 160 |
| Frame duration | 20ms |

This is the native format expected by most speech-to-text APIs (Whisper, Deepgram, Google STT) and easily converted to `f32` for audio processing pipelines.

### Reading inbound audio

`call.pcm_reader()` returns a `crossbeam_channel::Receiver<Vec<i16>>`. Each receive gives you one 20ms frame of decoded audio from the remote party:

```rust
if let Some(pcm_rx) = call.pcm_reader() {
    std::thread::spawn(move || {
        while let Ok(frame) = pcm_rx.recv() {
            // frame is Vec<i16>, 160 samples, 20ms of audio
            send_to_stt(&frame);
        }
        // channel closes when the call ends
    });
}
```

> **Important:** Read frames promptly. The inbound buffer holds 256 frames (~5 seconds). If you fall behind, the oldest frames are silently dropped.

### Writing outbound audio

`call.pcm_writer()` returns a `crossbeam_channel::Sender<Vec<i16>>`. Send one 20ms frame at a time to transmit audio to the remote party:

```rust
if let Some(pcm_tx) = call.pcm_writer() {
    std::thread::spawn(move || {
        loop {
            let frame = get_next_tts_frame(); // Vec<i16>, 160 samples
            if pcm_tx.try_send(frame).is_err() {
                // outbound buffer full -- frame dropped, keep going
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
}
```

> **Important:** `pcm_writer()` sends each buffer as an RTP packet immediately — the caller must provide frames at real-time rate (one 160-sample frame every 20ms). For live microphone input this is natural; for TTS or file playback, use `paced_pcm_writer()` instead.

### Paced writer (for TTS / pre-generated audio)

`call.paced_pcm_writer()` accepts arbitrary-length PCM buffers and handles framing + pacing internally. Send entire TTS utterances at once — xphone splits them into 20ms frames and sends RTP at real-time pace:

```rust
if let Some(paced_tx) = call.paced_pcm_writer() {
    // Send an entire TTS utterance — any length, xphone handles pacing
    let tts_audio: Vec<i16> = deepgram_tts_response();
    paced_tx.send(tts_audio).unwrap();
}
```

> **Note:** `pcm_writer` and `paced_pcm_writer` are mutually exclusive — using one suppresses the other for that call.

### Silence frame

```rust
let silence = vec![0i16; 160]; // zero-value is silence
pcm_tx.send(silence).unwrap();
```

### Converting to f32 (for ML pipelines)

Many audio and ML libraries expect `Vec<f32>` normalized to `[-1.0, 1.0]`:

```rust
fn pcm_to_f32(frame: &[i16]) -> Vec<f32> {
    frame.iter().map(|&s| s as f32 / 32768.0).collect()
}
```

### Raw RTP access

For lower-level control — sending pre-encoded audio, implementing a custom codec, or inspecting RTP headers — use `rtp_reader()` and `rtp_writer()` instead of the PCM channels:

```rust
// Read raw RTP packets (post-jitter buffer, pre-decode)
if let Some(rtp_rx) = call.rtp_reader() {
    while let Ok(pkt) = rtp_rx.recv() {
        // pkt is RtpPacket { header, payload }
    }
}

// Write raw RTP packets (bypasses pcm_writer entirely)
if let Some(rtp_tx) = call.rtp_writer() {
    rtp_tx.send(my_rtp_packet).unwrap();
}
```

> Note: `rtp_writer` and `pcm_writer` are mutually exclusive — if you write to `rtp_writer`, `pcm_writer` is ignored for that call.

---

## Media Pipeline

### Audio

```
Inbound:
  SIP Trunk -> RTP/UDP -> Jitter Buffer -> Codec Decode -> pcm_reader (Vec<i16>)

Outbound:
  pcm_writer (Vec<i16>) -> Codec Encode -> RTP/UDP -> SIP Trunk
  rtp_writer             -> RTP/UDP -> SIP Trunk       (raw mode)
```

### Video

```
Inbound:
  SIP Trunk -> RTP/UDP -> Depacketizer (H.264/VP8) -> video_reader (VideoFrame)
                        -> video_rtp_reader (raw video RTP packets)

Outbound:
  video_writer (VideoFrame) -> Packetizer (H.264/VP8) -> RTP/UDP -> SIP Trunk
  video_rtp_writer          -> RTP/UDP -> SIP Trunk   (raw mode)
```

Video uses a separate RTP port and independent SRTP contexts. RTCP PLI/FIR requests trigger keyframe generation on the sender side.

All channels are buffered (256 entries). Inbound taps drop oldest on overflow; outbound writers drop newest. Audio frames are 160 samples at 8000 Hz = 20ms. Video frames carry codec-specific NAL units (H.264) or encoded frames (VP8).

Each pipeline runs on a dedicated `std::thread` per call, bridged to the application via `crossbeam-channel`.

---

## Call Control

```rust
// Hold & resume
call.hold()?;
call.resume()?;

// Blind transfer
call.blind_transfer("sip:1003@pbx.example.com")?;

// Attended transfer (consult call_b, then bridge)
phone.attended_transfer(&call_a, &call_b)?;

// Mute (suppresses outbound audio, inbound still flows)
call.mute()?;
call.unmute()?;

// DTMF
call.send_dtmf("5")?;
call.on_dtmf(|digit| {
    println!("Received: {}", digit);
});

// Mid-call video upgrade
call.add_video(&[VideoCodec::H264, VideoCodec::VP8], 10000, 20000)?;
call.on_video_request(|req: VideoUpgradeRequest| {
    req.accept(); // or req.reject()
});
call.on_video(|| {
    // Video is now active — read frames from call.video_reader()
});

// Instant messaging
phone.send_message("sip:1002@pbx", "Hello!")?;
```

---

## Testing

`MockPhone` and `MockCall` provide the same API as the real types — no real SIP server needed.

```rust
use xphone::mock::phone::MockPhone;

let phone = MockPhone::new();
phone.connect().unwrap();

phone.on_incoming(|call| {
    call.accept().unwrap();
});
phone.simulate_incoming("sip:1001@pbx");

assert_eq!(phone.last_call().unwrap().state(), CallState::Active);
```

```rust
use xphone::mock::call::MockCall;

let call = MockCall::new();
call.accept().unwrap();
call.send_dtmf("5").unwrap();
assert_eq!(call.sent_dtmf(), vec!["5"]);

call.simulate_dtmf("9");
```

---

## Integration Tests

Tests against a Docker Asterisk instance:

```bash
docker compose -f testutil/docker/docker-compose.yml up -d --wait
cargo test --features integration --test integration_test -- --nocapture --test-threads=1
docker compose -f testutil/docker/docker-compose.yml down
```

Or using the Makefile:

```bash
make test-docker
```

---

## Logging

xphone uses the `tracing` crate for structured logging:

```rust
// Enable debug logging
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

All SIP messages, RTP stats, media events, and call state transitions are instrumented with `tracing` spans and events.

---

## Example App

`examples/sipcli` is a fully interactive terminal SIP client — registration, inbound/outbound calls, hold, resume, DTMF, mute, transfer, video calls, echo mode, and system speaker output:

```bash
# Audio-only
cargo run --example sipcli --features cli -- --profile myserver

# With video display (H.264 decoding + window)
cargo run --example sipcli --features video-display -- --profile myserver
```

---

## Stack

| Layer | Implementation |
|---|---|
| SIP Signaling | Built-in (message parsing, digest auth, transactions, UDP/TCP/TLS) |
| RTP / SRTP / SRTCP | Built-in (`std::net::UdpSocket`, AES_CM_128_HMAC_SHA1_80, replay protection) |
| G.711 / G.722 | Built-in (PCMU, PCMA, G.722 ADPCM) |
| G.729 | [g729-sys](https://crates.io/crates/g729-sys) (optional, `g729-codec` feature, pure Rust) |
| Opus | [opus](https://crates.io/crates/opus) (optional, `opus-codec` feature, libopus FFI) |
| H.264 / VP8 | Built-in packetizer/depacketizer (RFC 6184, RFC 7741) |
| RTCP | Built-in (RFC 3550 SR/RR + PLI/FIR) |
| Jitter Buffer | Built-in |
| STUN | Built-in (RFC 5389) |
| TURN | Built-in (RFC 5766) |
| ICE-Lite | Built-in (RFC 8445 §2.2) |
| TUI (sipcli) | [ratatui](https://github.com/ratatui/ratatui) + [cpal](https://github.com/RustAudio/cpal) |

No external SIP or RTP crate dependencies — the entire protocol stack is implemented from scratch.

---

## Known Limitations

### Security

**SRTP uses SDES key exchange only.** DTLS-SRTP key exchange is not supported. SDES works well with most SIP trunks but is not suitable for WebRTC interop, which requires DTLS-SRTP.

### Codec coverage

**Opus requires libopus (C library).** G.729 uses a pure Rust implementation with no system dependencies. G.711 and G.722 are always available with no external dependencies.

**PCM sample rate is fixed at 8 kHz (narrowband) or 16 kHz (G.722 wideband).** Codec selection determines the rate — there is no configurable sample rate.

---

## Roadmap

- DTLS-SRTP key exchange (WebRTC interop)
- Full ICE (connectivity checks, nomination)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
