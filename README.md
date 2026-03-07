# xphone

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
| PCM audio frames (`Vec<i16>`) and raw RTP access | Done |
| Jitter buffer | Done |
| MockPhone & MockCall for unit testing | Done |
| G.722 codec | Planned |
| Attended transfer | Planned |
| Opus codec | Planned |
| SRTP (encrypted media) | Planned |

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
    .username("1001")
    .password("secret")
    .host("pbx.example.com")
    .rtp_ports(10000, 20000)
    .build();
```

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

let call = MockCall::new_inbound();
call.accept().unwrap();
call.send_dtmf("5").unwrap();
assert_eq!(call.sent_dtmf(), vec!["5"]);

call.simulate_dtmf("9");
```

---

## Integration Tests

Tests against a Docker Asterisk instance:

```bash
cd testutil/docker && docker compose up -d
cargo test --features integration --test integration_test -- --test-threads=1
cd testutil/docker && docker compose down
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
| SIP Signaling | Custom (message parsing, digest auth, transactions) |
| RTP Media | Custom (`std::net::UdpSocket`) |
| G.711 | Built-in (PCMU + PCMA) |
| Jitter Buffer | Built-in |
| TUI (sipcli) | [ratatui](https://github.com/ratatui/ratatui) + [cpal](https://github.com/RustAudio/cpal) |

No external SIP or RTP crate dependencies — the entire SIP stack is implemented from scratch.

---

## Known Limitations

This library is actively developed but not yet complete. The gaps below are worth understanding before committing to it for a production deployment.

### Security

**SRTP is not implemented.** All RTP audio is transmitted unencrypted over UDP. On untrusted or public networks, audio can be intercepted and recorded by anyone on the path between your server and the SIP trunk. Do not use in production environments where call privacy is required until SRTP support lands.

### Codec coverage

**G.722 and Opus are not yet supported.** Only G.711 (PCMU/PCMA) is implemented. Some SIP trunk providers default to wideband codecs and may require explicit configuration to fall back to G.711.

**G.729 is not supported.** G.729 is widely deployed in enterprise PBX environments. If your SIP trunk or PBX requires G.729, xphone cannot currently interoperate with it.

### Transport

**Only UDP is implemented.** TCP and TLS SIP transports are not yet available. Most SIP deployments use UDP, but some providers or firewalls require TCP/TLS.

### Call control

**Attended (consultative) transfer is not implemented.** Only blind transfer via REFER is supported.

**Call waiting is not handled.** A second inbound INVITE while a call is active is not surfaced to the application.

### Network & NAT

**No STUN/TURN/ICE support.** Only basic NAT keepalive is provided. In environments with strict or symmetric NAT (common in cloud VMs), RTP media may fail to flow even if SIP signaling succeeds.

### Project maturity

This is an early-stage project. The API may change between releases. Evaluate accordingly for critical production workloads.

---

## Roadmap

- SRTP — encrypted media (RFC 3711)
- G.722 codec
- Opus codec
- TCP/TLS SIP transport
- Attended (consultative) transfer
- STUN/ICE for NAT traversal

---

## License

MIT
