# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-08

### Added

- **302 redirect following** — INVITE automatically follows 3xx responses (up to 3 hops, RFC 3261 §17.1.1.3)
- **SRTP replay protection** — 128-packet sliding window bitmask rejects duplicates and too-old packets before HMAC (RFC 3711 §3.3.2)
- **RTCP sender/receiver reports** — periodic SR/RR packets every 5s with jitter, loss, NTP timestamps, and round-trip stats (RFC 3550)
- **Opus codec** — optional `opus-codec` feature adds Opus support (PT 111) at 8kHz mono VoIP mode with 48kHz RTP clock (RFC 7587). Requires libopus.

### Changed

- Switched SRTP crypto from hand-rolled implementations to audited RustCrypto crates (`aes`, `sha1`, `hmac`)
- SDP builders refactored: `build_offer`/`build_offer_srtp` now share a single `build_offer_inner` helper with `codec_fmtp()` lookup

## [0.1.1] - 2026-03-07

### Fixed

- Phone-level callbacks (on_state, on_ended, on_dtmf) no longer get overwritten when users set per-call callbacks — internal fields pattern keeps both independent
- Remote hold/resume (re-INVITE) now fires both phone-level and user-level on_state callbacks
- Lock ordering fix in wire_phone_call_callbacks to prevent potential deadlock

## [0.1.0] - 2025-03-07

### Added

- SIP registration with digest authentication and automatic refresh
- Outbound and inbound call support with full state machine
- Early media (183 Session Progress) — hear ringback tones and IVR prompts before answer
- G.711 codecs (PCMU / PCMA) and G.722 wideband codec
- SRTP encryption (AES_CM_128_HMAC_SHA1_80 with SDES key exchange)
- TCP and TLS SIP transports (via rustls)
- STUN NAT traversal (RFC 5389) for discovering external mapped address
- Jitter buffer with configurable depth
- Media pipeline on dedicated `std::thread` with crossbeam channels
- DTMF send (RFC 2833 telephone-event) and receive
- Hold / resume via re-INVITE
- Blind transfer via SIP REFER
- Session timers (RFC 4028)
- NAT keepalive (periodic OPTIONS)
- `MockPhone` and `MockCall` for unit testing without a real SIP server
- `sipcli` example: interactive TUI SIP client with multi-call support
- Integration test suite against Docker/Asterisk
- FakePBX-based test suite for fast CI

### Known Limitations

- SRTP not yet hardened (no replay protection, no key zeroization)
- Opus and G.729 codecs not supported
- No attended (consultative) transfer
- DTMF is RFC 4733 only (no SIP INFO fallback)
- No TURN relay or full ICE (STUN only)
