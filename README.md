# xphone

[![Crates.io](https://img.shields.io/crates/v/xphone.svg)](https://crates.io/crates/xphone)
[![docs.rs](https://docs.rs/xphone/badge.svg)](https://docs.rs/xphone)
[![CI](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/x-phone/xphone-rust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**A Rust library for embedding real phone calls into any application.**
No PBX. No Twilio. No per-minute fees. Just clean PCM audio, in and out.

xphone handles SIP signaling, RTP media, codecs, and call state so you can focus on what your application actually does with the audio — whether that's feeding frames to a speech model, recording to disk, or building a full softphone.

Rust port of [xphone-go](https://github.com/x-phone/xphone-go), with the same event-driven API design.

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
            +-- xphone
                    |-- pcm_reader -> Whisper / Deepgram (speech-to-text)
                    +-- pcm_writer <- ElevenLabs / TTS (text-to-speech)
```

Your bot gets a real phone number, registers directly with a SIP trunk provider, and handles calls end-to-end — no Asterisk, no middleman, no per-minute platform fees.

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

A common misconception: you don't need Asterisk or FreeSWITCH to use xphone. A SIP trunk is just a SIP server — xphone registers with it directly, exactly like a desk phone would.

```rust
let phone = Phone::new(Config {
    username: "your-username".into(),
    password: "your-password".into(),
    host: "sip.telnyx.com".into(),
    ..Config::default()
});
```

That's it. Your application registers with the SIP trunk, receives calls on your DID, and can dial out — no additional infrastructure.

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
xphone = "0.1"
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

## Features

| Feature | Status |
|---|---|
| SIP Registration (auth, keepalive, auto-reconnect) | Done |
| Inbound & outbound calls | Done |
| Hold / Resume (re-INVITE) | Done |
| Blind transfer (REFER) | Done |
| DTMF send/receive (RFC 4733) | Done |
| Session timers (RFC 4028) | Done |
| Mute / Unmute | Done |
| G.711 u-law (PCMU), G.711 A-law (PCMA) | Done |
| G.722 wideband codec | Done |
| PCM audio frames (`Vec<i16>`) and raw RTP access | Done |
| Jitter buffer | Done |
| SRTP (encrypted media, AES_CM_128_HMAC_SHA1_80) | Done |
| TCP and TLS SIP transport | Done |
| Early media (183 Session Progress) | Done |
| STUN NAT traversal (RFC 5389) | Done |
| MockPhone & MockCall for unit testing | Done |
| Attended transfer | Planned |
| Opus codec | Planned |

---

## Configuration

```rust
use xphone::{Config, PhoneBuilder, Phone};
use std::time::Duration;

// Direct struct construction:
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "pbx.example.com".into(),
    port: 5060,
    transport: "udp".into(),
    rtp_port_min: 10000,
    rtp_port_max: 20000,
    nat_keepalive_interval: Some(Duration::from_secs(25)),
    media_timeout: Duration::from_secs(30),
    jitter_buffer: Duration::from_millis(50),
    ..Config::default()
});

// Or use the builder:
let phone = PhoneBuilder::new()
    .credentials("1001", "secret", "pbx.example.com")
    .rtp_ports(10000, 20000)
    .build();
```

---

## NAT Traversal (STUN)

If your application runs behind NAT (most deployments), configure a STUN server so xphone can discover your public IP and advertise it correctly in SIP and SDP:

```rust
let phone = Phone::new(Config {
    username: "1001".into(),
    password: "secret".into(),
    host: "sip.telnyx.com".into(),
    stun_server: Some("stun.l.google.com:19302".into()),
    ..Config::default()
});

// Or with the builder:
let phone = Phone::new(
    PhoneBuilder::new()
        .credentials("1001", "secret", "sip.telnyx.com")
        .stun_server("stun.l.google.com:19302")
        .build(),
);
```

When `stun_server` is set, xphone sends a STUN Binding Request at startup to learn your external IP. If the STUN server is unreachable, it falls back to local IP detection automatically.

Common public STUN servers:
- `stun.l.google.com:19302`
- `stun1.l.google.com:19302`
- `stun.cloudflare.com:3478`

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

> **Important:** Send frames at the natural 20ms pace. If you send faster than real-time, the outbound buffer fills and frames are dropped.

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

```
Inbound:
  SIP Trunk -> RTP/UDP -> Jitter Buffer -> Codec Decode -> pcm_reader (Vec<i16>)

Outbound:
  pcm_writer (Vec<i16>) -> Codec Encode -> RTP/UDP -> SIP Trunk
  rtp_writer             -> RTP/UDP -> SIP Trunk       (raw mode)
```

All channels are buffered (256 entries). Inbound drops oldest on overflow; outbound drops newest. Each frame is 160 samples at 8000 Hz = 20ms of audio.

The media pipeline runs on a dedicated `std::thread` (not async), bridged to the rest of the application via `crossbeam-channel`.

---

## Call Control

```rust
// Hold & resume
call.hold()?;
call.resume()?;

// Blind transfer
call.blind_transfer("sip:1003@pbx.example.com")?;

// Mute (suppresses outbound audio, inbound still flows)
call.mute()?;
call.unmute()?;

// DTMF
call.send_dtmf("5")?;
call.on_dtmf(|digit| {
    println!("Received: {}", digit);
});
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

`examples/sipcli` is a fully interactive terminal SIP client — registration, inbound/outbound calls, hold, resume, DTMF, mute, transfer, echo mode, and system speaker output:

```bash
# Using a profile from ~/.sipcli.yaml
cargo run --example sipcli --features cli -- --profile myserver

# Direct flags
cargo run --example sipcli --features cli -- --server pbx.example.com --user 1001 --pass secret
```

---

## Stack

| Layer | Implementation |
|---|---|
| SIP Signaling | Custom (message parsing, digest auth, transactions, UDP/TCP/TLS, STUN) |
| RTP / SRTP | Custom (`std::net::UdpSocket`, AES_CM_128_HMAC_SHA1_80) |
| G.711 / G.722 | Built-in (PCMU, PCMA, G.722) |
| Jitter Buffer | Built-in |
| TUI (sipcli) | [ratatui](https://github.com/ratatui/ratatui) + [cpal](https://github.com/RustAudio/cpal) |

No external SIP or RTP crate dependencies — the entire SIP stack is implemented from scratch.

---

## Known Limitations

This library is actively developed but not yet feature-complete. The gaps below are worth understanding before committing to it for a production deployment.

### Security

**SRTP is implemented but not yet hardened.** The `AES_CM_128_HMAC_SHA1_80` cipher suite is supported with SDES key exchange. Replay protection, key material zeroization, SRTCP encryption, and per-SSRC crypto state tracking are not yet implemented. DTLS-SRTP key exchange is not supported (SDES only). Evaluate accordingly for high-security environments.

### Codec coverage

**Opus is not yet supported.** G.711 (PCMU/PCMA) and G.722 are implemented. Opus is the dominant codec in WebRTC and modern VoIP — its absence limits interoperability with those platforms.

**G.729 is not supported.** G.729 remains widely deployed in enterprise PBX environments (Cisco, Avaya, Mitel). If your SIP trunk or PBX requires G.729, xphone cannot currently interoperate with it.

**PCM sample rate is fixed at 8 kHz (narrowband) or 16 kHz (G.722 wideband).** There is no configurable sample rate — codec selection determines the rate.

### Call control

**Attended (consultative) transfer is not implemented.** Only blind transfer via REFER is supported. Attended transfer requires coordinating two simultaneous call legs with a REFER/Replaces header.

**DTMF is RFC 4733 (RTP telephone-events) only.** Some legacy PBXes use SIP INFO (RFC 2976) for DTMF instead. If your system requires SIP INFO DTMF, tones may not be received.

**No call forwarding (302).** Incoming 302 Moved Temporarily responses are not followed automatically.

**No call parking.** Park/retrieve functionality (common in office deployments) is not implemented.

### Enterprise features

**No MWI (Message Waiting Indicator).** SIP SUBSCRIBE/NOTIFY for the `message-summary` event package (RFC 3842) is not implemented. Applications cannot detect voicemail presence.

**No presence or BLF.** SIP SUBSCRIBE/NOTIFY for presence (RFC 3856) and dialog state (RFC 4235 — Busy Lamp Field) are not implemented.

**No SIP MESSAGE (RFC 3428).** Instant messaging over SIP is not supported.

### Network & NAT

**STUN is supported for NAT-mapped address discovery.** Configure `stun_server` to use a public STUN server (e.g. `stun.l.google.com:19302`) for discovering your external IP. STUN should only be used when the SIP server is on the public internet — do not enable it when connecting via VPN or private network, as the STUN-mapped address will be unreachable from the server.

**No TURN or ICE.** TURN relay (RFC 5766) and full ICE (RFC 5245) are not implemented. In environments with symmetric NAT (common in cloud VMs and corporate firewalls), STUN alone may not be sufficient and RTP media may fail to flow.

### Media

**No video.** Only audio media (single `m=audio` line in SDP) is supported. H.264, VP8, and other video codecs are not implemented.

**No RTCP.** RTP Control Protocol feedback (jitter reports, packet loss, round-trip time) is not sent or processed.

### Project maturity

This is an early-stage project (v0.1.x). The API may change between releases. Evaluate accordingly for critical production workloads.

---

## Roadmap

- SRTP hardening — replay protection, DTLS-SRTP, key zeroization
- Opus codec
- Attended (consultative) transfer
- SIP INFO DTMF (RFC 2976) for legacy PBX compatibility
- TURN relay and full ICE for symmetric NAT
- RTCP support
- MWI (voicemail notification)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
