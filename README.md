# xphone

[![Crates.io](https://img.shields.io/crates/v/xphone.svg)](https://crates.io/crates/xphone)
[![docs.rs](https://docs.rs/xphone/badge.svg)](https://docs.rs/xphone)
[![CI](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Rust library for SIP calling and RTP media. Register with a SIP trunk or PBX, or accept calls directly as a SIP server — and get decoded PCM audio frames through crossbeam channels.

> Also available in [Go](https://github.com/x-phone/xphone-go) (the more mature implementation).

## Table of Contents

- [Status](#status--beta) | [Scope and Limitations](#scope-and-limitations) | [Tested Against](#tested-against) | [Use Cases](#use-cases)
- [Quick Start](#quick-start) | [Connection Modes](#connection-modes) | [Working with Audio](#working-with-audio)
- [Features](#features) | [Call States](#call-states) | [Call Control](#call-control) | [Media Pipeline](#media-pipeline)
- [Configuration](#configuration) | [RTP Port Range](#rtp-port-range) | [NAT Traversal](#nat-traversal) | [Opus Codec](#opus-codec) | [G.729 Codec](#g729-codec)
- [Testing](#testing) | [Example App](#example-app) | [Logging](#logging) | [Stack](#stack) | [Roadmap](#roadmap)

---

## Status — Beta

xphone-rust is in active development and used in production alongside [xbridge](https://github.com/x-phone/xbridge). Feature coverage is broad but real-world mileage is still limited — not all features have been exercised under diverse production conditions. The [Go implementation](https://github.com/x-phone/xphone-go) has more production exposure; if you're evaluating and language is flexible, start there.

The entire SIP and RTP stack is implemented from scratch in Rust — no external SIP or RTP crate dependencies.

---

## Scope and limitations

xphone is a **voice data-plane library** — SIP signaling and RTP media. It is not a telephony platform.

**You are responsible for:**

- Billing, number provisioning, and call routing rules
- Recording storage and playback infrastructure
- High availability, persistence, and failover
- Rate limiting, authentication, and abuse prevention at the application level

**Security boundaries:**

- SRTP uses SDES key exchange only. DTLS-SRTP is not supported — xphone cannot interop with WebRTC endpoints that require it.
- TLS is supported for SIP transport. See [Configuration](#configuration) for transport options.
- There is no built-in authentication layer for your application — xphone authenticates to SIP servers, not your end users.

**Codec constraints:**

- Opus requires the `opus-codec` feature and system-installed libopus.
- G.729 uses a pure Rust implementation (`g729-sys`) — no system dependencies.
- G.711 and G.722 are always available with no external dependencies.
- PCM sample rate is fixed at 8 kHz (narrowband) or 16 kHz (G.722 wideband). There is no configurable sample rate.

---

## Tested against

| Category | Tested with |
|---|---|
| **SIP trunks** | Telnyx, Twilio SIP, VoIP.ms, Vonage |
| **PBXes** | Asterisk, FreeSWITCH, 3CX |
| **Integration tests** | [fakepbx](https://github.com/x-phone/fakepbx) (in-process SIP server, real SIP over loopback) + Dockerized Asterisk ([xpbx](https://github.com/x-phone/xpbx)) in CI |
| **Unit tests** | MockPhone & MockCall — full Phone/Call API mocks |

This is not a comprehensive compatibility matrix. If you hit issues with a provider or PBX not listed here, please open an issue.

---

## Use cases

- **AI voice agents** — pipe call audio directly into your STT/LLM/TTS pipeline without a telephony platform
- **Softphones and click-to-call** — embed SIP calling into any Rust application against a trunk or PBX
- **Call recording and monitoring** — tap the PCM audio stream for transcription, analysis, or storage
- **Outbound dialers** — programmatic dialing with DTMF detection for IVR automation
- **Unit-testable call flows** — MockPhone and MockCall let you test every call branch without a SIP server

See the [demos repo](https://github.com/x-phone/demos) for working examples.

---

## Quick Start

### Install

Add to your `Cargo.toml`:

```toml
[dependencies]
xphone = "0.4"
```

Requires Rust 1.87+.

### Receive calls

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
    std::thread::park();
}
```

PCM format: `Vec<i16>`, mono, 8000 Hz, 160 samples per frame (20ms) — the standard input format for most speech-to-text APIs.

### Make an outbound call

```rust
use xphone::DialOptions;
use std::time::Duration;

let opts = DialOptions {
    early_media: true,
    timeout: Duration::from_secs(30),
    ..Default::default()
};

let call = phone.dial("+15551234567", opts)?;

if let Some(pcm_rx) = call.pcm_reader() {
    std::thread::spawn(move || {
        while let Ok(frame) = pcm_rx.recv() {
            process_audio(&frame);
        }
    });
}
```

`dial` accepts a full SIP URI or just the number — if no host is given, your configured SIP server is used.

---

## Connection Modes

xphone supports two ways to connect to the SIP world. Both produce the same `Call` API — accept, end, DTMF, pcm_reader/writer are identical.

### Phone mode (SIP client)

Registers with a SIP server like a normal endpoint. Use this with SIP trunks (Telnyx, Vonage), PBXes (Asterisk, FreeSWITCH), or any SIP registrar. No PBX is required — you can register directly with a SIP trunk provider:

```rust
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    ..Config::default()
});
phone.on_incoming(|call| { call.accept().unwrap(); });
phone.connect()?;
```

### Server mode (SIP trunk)

Accepts and places calls directly with trusted SIP peers — no registration required. Use this when trunk providers send INVITEs to your public IP, or when a PBX routes calls to your application:

```rust
let server = Server::new(ServerConfig {
    listen: "0.0.0.0:5080".into(),
    rtp_port_min: 10000,
    rtp_port_max: 20000,
    peers: vec![
        PeerConfig {
            name: "twilio".into(),
            hosts: vec!["54.172.60.0/30".into(), "54.244.51.0/30".into()],
            ..Default::default()
        },
        PeerConfig {
            name: "office-pbx".into(),
            host: Some("192.168.1.10".parse().unwrap()),
            ..Default::default()
        },
    ],
    ..Default::default()
});
server.on_incoming(|call| { call.accept().unwrap(); });
server.listen().await?;
```

Peers are authenticated by IP/CIDR or SIP digest auth. Per-peer codec and RTP address overrides are supported.

For zero-downtime deploys, use `listen_with_socket()` with a pre-bound socket (e.g., with `SO_REUSEPORT`):

```rust
let socket = std::net::UdpSocket::bind("0.0.0.0:5080").unwrap();
// socket2::Socket can set SO_REUSEPORT before binding
server.listen_with_socket(socket).await?;
```

> **Which mode?** Use **Phone** when you register to a SIP server (most setups). Use **Server** when SIP peers send INVITEs directly to your application (Twilio SIP Trunk, direct PBX routing, peer-to-peer).

---

## Working with Audio

xphone exposes audio as a stream of PCM frames through crossbeam channels.

### Frame format

| Property | Value |
|---|---|
| Encoding | 16-bit signed PCM |
| Channels | Mono |
| Sample rate | 8000 Hz |
| Samples per frame | 160 |
| Frame duration | 20ms |

### Reading inbound audio

`call.pcm_reader()` returns a `crossbeam_channel::Receiver<Vec<i16>>`:

```rust
if let Some(pcm_rx) = call.pcm_reader() {
    std::thread::spawn(move || {
        while let Ok(frame) = pcm_rx.recv() {
            send_to_stt(&frame);
        }
        // channel closes when the call ends
    });
}
```

> **Important:** Read frames promptly. The inbound buffer holds 256 frames (~5 seconds). If you fall behind, the oldest frames are silently dropped.

### Writing outbound audio

`call.pcm_writer()` returns a `crossbeam_channel::Sender<Vec<i16>>`. Send one 20ms frame at a time:

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

> **Important:** `pcm_writer()` sends each buffer as an RTP packet immediately — the caller must provide frames at real-time rate (one 160-sample frame every 20ms). For TTS or file playback, use `paced_pcm_writer()` instead.

### Paced writer (for TTS / pre-generated audio)

`call.paced_pcm_writer()` accepts arbitrary-length PCM buffers and handles framing + pacing internally:

```rust
if let Some(paced_tx) = call.paced_pcm_writer() {
    let tts_audio: Vec<i16> = deepgram_tts_response();
    paced_tx.send(tts_audio).unwrap();
}
```

> `pcm_writer` and `paced_pcm_writer` are mutually exclusive — using one suppresses the other for that call.

### Raw RTP access

For lower-level control — pre-encoded audio, custom codecs, or RTP header inspection:

```rust
if let Some(rtp_rx) = call.rtp_reader() {
    while let Ok(pkt) = rtp_rx.recv() {
        // pkt is RtpPacket { header, payload }
    }
}

if let Some(rtp_tx) = call.rtp_writer() {
    rtp_tx.send(my_rtp_packet).unwrap();
}
```

> `rtp_writer` and `pcm_writer` are mutually exclusive — if you write to `rtp_writer`, `pcm_writer` is ignored for that call.

### Converting to f32

```rust
fn pcm_to_f32(frame: &[i16]) -> Vec<f32> {
    frame.iter().map(|&s| s as f32 / 32768.0).collect()
}
```

---

## Features

### Calling — stable

- SIP registration with auto-reconnect and keepalive
- Inbound and outbound calls
- Hold / resume (re-INVITE)
- Blind transfer (REFER) and attended transfer (REFER with Replaces, RFC 3891)
- Call waiting (`Phone.calls()` API)
- Session timers (RFC 4028)
- Mute / unmute
- 302 redirect following
- Early media (183 Session Progress)
- Outbound proxy routing (`Config::outbound_proxy`)
- Separate outbound credentials (`outbound_username` / `outbound_password`)
- P-Asserted-Identity for caller ID (`DialOptions::caller_id`)
- Custom headers on outbound INVITEs (`DialOptions::custom_headers`)
- `Server::dial_uri` — dial arbitrary SIP URIs without pre-configured peers
- `EndReason::TransferFailed` — surfaces REFER failures instead of silently dropping them

### DTMF — stable

- RFC 4733 (RTP telephone-events)
- SIP INFO (RFC 2976)

### Audio codecs — stable

- G.711 u-law (PCMU), G.711 A-law (PCMA) — built-in
- G.722 wideband — built-in
- Opus — optional, requires libopus (`--features opus-codec`)
- G.729 — optional, pure Rust (`--features g729-codec`)
- Jitter buffer

### Video — newer, less production mileage

- H.264 (RFC 6184) and VP8 (RFC 7741)
- Depacketizer/packetizer pipeline
- Mid-call video upgrade/downgrade (re-INVITE)
- Video upgrade accept/reject API
- VideoReader / VideoWriter / VideoRTPReader / VideoRTPWriter
- RTCP PLI/FIR for keyframe requests

### Security — stable

- SRTP (AES_CM_128_HMAC_SHA1_80) with SDES key exchange
- SRTP replay protection (RFC 3711)
- SRTCP encryption (RFC 3711 §3.4)
- Key material zeroization
- Separate SRTP contexts for audio and video

### Network — stable

- TCP and TLS SIP transport
- STUN NAT traversal (RFC 5389)
- TURN relay for symmetric NAT (RFC 5766)
- ICE-Lite (RFC 8445 §2.2)
- RTCP Sender/Receiver Reports (RFC 3550)

### Messaging — newer, less production mileage

- SIP MESSAGE (RFC 3428)
- SIP SUBSCRIBE/NOTIFY (RFC 6665)
- Generic event subscriptions (presence, dialog, etc.)
- MWI / voicemail notification (RFC 3842)
- BLF / Busy Lamp Field monitoring

### Testing — stable

- MockPhone and MockCall — full API mocks for unit testing

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

## Call Control

```rust
call.hold()?;
call.resume()?;

call.blind_transfer("sip:1003@pbx.example.com")?;
call_a.attended_transfer(&call_b)?; // works for both Phone and Server calls

call.mute()?;
call.unmute()?;

call.send_dtmf("5")?;
call.on_dtmf(|digit| {
    println!("Received: {}", digit);
});

// Mid-call video upgrade
call.add_video(&[VideoCodec::H264, VideoCodec::VP8], 10000, 20000)?;
call.on_video_request(|req: VideoUpgradeRequest| {
    req.accept();
});
call.on_video(|| {
    // read frames from call.video_reader()
});

phone.send_message("sip:1002@pbx", "Hello!")?;
```

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

## Configuration

```rust
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
    dtmf_mode: DtmfMode::Rfc4733,
    ice: true,
    turn_server: Some("turn.example.com:3478".into()),
    turn_username: Some("user".into()),
    turn_password: Some("pass".into()),
    outbound_proxy: Some("sip:proxy.example.com:5060".into()), // route INVITEs via proxy
    outbound_username: Some("trunk-user".into()),               // separate INVITE auth
    outbound_password: Some("trunk-pass".into()),
    ..Config::default()
});

// Or use the builder:
let phone = Phone::new(
    PhoneBuilder::new()
        .credentials("1001", "secret", "pbx.example.com")
        .rtp_ports(10000, 20000)
        .codecs(vec![Codec::Opus, Codec::PCMU])
        .srtp(true)
        .stun_server("stun.l.google.com:19302")
        .outbound_proxy("sip:proxy.example.com:5060")
        .outbound_credentials("trunk-user", "trunk-pass")
        .build(),
);
```

See [docs.rs](https://docs.rs/xphone) for all options.

---

## RTP Port Range

Each active call requires an even-numbered UDP port for RTP audio. Configure an explicit range for production deployments behind firewalls:

```rust
let phone = Phone::new(Config {
    rtp_port_min: 10000,
    rtp_port_max: 20000,
    ..Config::default()
});
```

Only even ports are used (per RTP spec). Maximum concurrent audio-only calls = `(max - min) / 2`.

| Range | Even ports | Max concurrent calls |
|---|---|---|
| 10000–10100 | 50 | ~50 |
| 10000–12000 | 1000 | ~1000 |
| 10000–20000 | 5000 | ~5000 |

**When ports run out:** inbound calls receive a `500 Internal Server Error` and outbound dials fail with an error. Widen the range before investigating SIP server configuration.

Default (`0, 0`) lets the OS assign ephemeral ports. This works for development but is impractical in production where firewall rules need a known range.

---

## NAT Traversal

### STUN (most deployments)

Discovers your public IP via a STUN Binding Request:

```rust
let phone = Phone::new(Config {
    stun_server: Some("stun.l.google.com:19302".into()),
    ..Config::default()
});
```

### TURN (symmetric NAT)

For environments where STUN alone fails (cloud VMs, corporate firewalls):

```rust
let phone = Phone::new(Config {
    turn_server: Some("turn.example.com:3478".into()),
    turn_username: Some("user".into()),
    turn_password: Some("pass".into()),
    ..Config::default()
});
```

### ICE-Lite

SDP-level candidate negotiation (RFC 8445 §2.2):

```rust
let phone = Phone::new(Config {
    ice: true,
    stun_server: Some("stun.l.google.com:19302".into()),
    ..Config::default()
});
```

> Only enable STUN/TURN/ICE when the SIP server is on the public internet. Do not enable it when connecting via VPN or private network.

---

## Opus Codec

Opus is optional and requires system-installed libopus. The default build has no external C dependencies.

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
let phone = Phone::new(Config {
    codec_prefs: vec![Codec::Opus, Codec::PCMU],
    ..Config::default()
});
```

Opus runs at 8kHz natively — no resampling needed. PCM frames remain `Vec<i16>`, mono, 160 samples (20ms). RTP timestamps use 48kHz clock per RFC 7587.

Without the `opus-codec` feature, `Codec::Opus` is accepted in configuration but will not be negotiated.

---

## G.729 Codec

G.729 is optional via the `g729-codec` feature. Unlike Opus, it uses a pure Rust implementation (`g729-sys`) — no system libraries required.

### Build with G.729

```bash
cargo build --features g729-codec
cargo test --features g729-codec
```

### Usage

```rust
let phone = Phone::new(Config {
    codec_prefs: vec![Codec::G729, Codec::PCMU],
    ..Config::default()
});
```

G.729 runs at 8kHz, 8 kbps CS-ACELP. SDP advertises `annexb=no` — Annex B (VAD/CNG) is not supported.

---

## Testing

### Unit tests with mocks

`MockPhone` and `MockCall` provide the same API as the real types:

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

### Integration tests with FakePBX (no Docker)

```bash
cargo test --test fakepbx_test
cargo test --test server_test
```

### End-to-end tests with Asterisk

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

## Example App

`examples/sipcli` is a terminal SIP client with registration, calls, hold, resume, DTMF, mute, transfer, video calls, echo mode, and speaker output:

```bash
# Audio-only
cargo run --example sipcli --features cli -- --profile myserver

# With video display (H.264 decoding + window)
cargo run --example sipcli --features video-display -- --profile myserver
```

---

## Logging

xphone uses the `tracing` crate for structured logging:

```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

All SIP messages, RTP stats, media events, and call state transitions are instrumented with `tracing` spans and events.

To silence library logs in production:

```rust
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("xphone=warn"))
    .init();
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

## Roadmap

- DTLS-SRTP key exchange (WebRTC interop)
- Full ICE (connectivity checks, nomination)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
