# Changelog

All notable changes to this project will be documented in this file.

## [0.4.8] - 2026-04-08

### Added

- **Per-call SIP auth credentials** — `DialOptions::auth` (`Option<Credentials>`) overrides config-level `outbound_username` / `outbound_password` for a single outbound call. Enables dialing through multiple SIP trunks with distinct proxy auth without creating separate `Phone` instances. Also available via `DialOptionsBuilder::auth("user", "pass")`. `Credentials` is now re-exported from the crate root. (xphone-go#90)

## [0.4.7] - 2026-03-31

### Added

- **`Server::on_options()` callback** — control the SIP OPTIONS response code for health checks. Returns `200` by default; set to `503` during drain for load balancer integration (e.g., Kamailio, OpenSIPS).

## [0.4.6] - 2026-03-30

### Added

- **Configurable User-Agent header** — `Config.user_agent` / `PhoneBuilder::user_agent()` sets the User-Agent string in all outgoing SIP requests. Defaults to `"xphone"`. PBXes use this to identify the device. (fixes xphone-go#75)
- **`Server::listen_with_socket()`** — start the SIP trunk server with a pre-bound UDP socket. Enables `SO_REUSEPORT` for zero-downtime deploys and other custom socket options without the library needing to know about deployment topology. (xphone-go#79)

## [0.4.5] - 2026-03-29

### Changed

- **`on_*` callbacks now append instead of replace** — calling any `on_*` setter (e.g., `on_ended`, `on_state`, `on_hold`) multiple times now registers all callbacks instead of silently dropping previous ones. Affects `Call`, `Phone`, `Server`, `MockCall`, `MockPhone`, `MwiSubscriber`, and `SubscriptionManager`. `on_video_request` remains single-handler (replace) since only one handler can respond to a video upgrade request.
- `Error` now derives `Clone`

## [0.4.4] - 2026-03-28

### Changed

- **`attended_transfer` moved from `Phone` to `Call`** — now works for both `Phone` and `Server` (trunk mode) calls. `Phone::attended_transfer` remains as a thin delegate (non-breaking). NOTIFY handler upgraded to handle transfer failures (3xx+) with `EndReason::TransferFailed`.

## [0.4.3] - 2026-03-28

### Added

- `Server::dial_uri(sip_uri, from)` — dial an arbitrary SIP URI directly, bypassing peer config resolution. Useful for dynamic outbound trunking.

## [0.4.2] - 2026-03-28

### Fixed

- **Trunk server ignoring NOTIFY requests** — incoming NOTIFYs (REFER progress) were rejected with `405 Method Not Allowed`. Now parsed for sipfrag status and dispatched to the call via `fire_notify()`, enabling blind transfer completion in trunk mode.
- **BlindTransfer silently ignoring transfer failures** — non-2xx NOTIFY status codes (e.g., 403, 480, 503) were silently dropped, leaving the call active indefinitely. Now ends the call with `EndReason::TransferFailed`. 1xx provisionals are correctly ignored.

### Added

- `EndReason::TransferFailed` variant — fired when a REFER transfer is rejected by the remote party (3xx/4xx/5xx/6xx NOTIFY status).

## [0.4.1] - 2026-03-20

### Changed

- Consolidated SIP URI-to-SocketAddr parsing into shared `sip::resolve_host()` — used by both outbound proxy URI parser and trunk server ACK routing. Adds DNS resolution and `;params` stripping to both paths consistently.
- `ClientConfig` now implements `Default` — reduces boilerplate when adding new optional fields (tests use `..Default::default()` instead of spelling out every `None`)

### Added

- **Outbound proxy support** — route outbound INVITEs through a proxy separate from the registrar via `Config::outbound_proxy` (e.g. `"sip:proxy.example.com:5060"`)
- **Separate outbound credentials** — `Config::outbound_username` / `outbound_password` for INVITE authentication distinct from REGISTER credentials
- **P-Asserted-Identity** — `DialOptions::caller_id` now sets the P-Asserted-Identity header on outbound INVITEs
- `PhoneBuilder::outbound_proxy()` and `PhoneBuilder::outbound_credentials()` builder methods

### Fixed

- **Custom headers not applied to outbound INVITEs** — `DialOptions::custom_headers` and `caller_id` were stored but never sent in the SIP INVITE. Now plumbed through `SipTransport::dial()` → `Client::send_invite()` → wire format.
- `Config.host` containing `host:port` (e.g. `"10.0.0.7:5060"`) no longer produces malformed SIP URIs with double ports. The embedded port is extracted automatically; explicit `.port()` calls take precedence.
- RTP port 0 in SDP when `rtp_port_min`/`rtp_port_max` are unset (default 0,0) — now falls back to OS-assigned ephemeral port instead of producing `m=audio 0` which rejects media per RFC 3264

## [0.4.0] - 2026-03-13

### Added

- **SIP trunk host server mode (`Server`)** — accept and place calls directly with trusted SIP peers (PBXes, trunk providers like Twilio/Telnyx) without requiring SIP registration. Both `Phone` and `Server` produce the same `Call` object with identical downstream API.
- New `trunk` module: `ServerConfig`, `PeerConfig`, `PeerAuthConfig` for peer configuration with IP allowlist and CIDR matching
- Peer authentication: IP-based (fastest path) and SIP digest auth (RFC 2617) for incoming INVITEs
- `TrunkDialog` implementing `Dialog` trait for both UAS (inbound) and UAC (outbound) roles
- `Server::listen()` — async UDP listener with SIP message routing, BYE/CANCEL handling, and dialog TTL reaper
- `Server::dial()` — outbound calls to named peers with SDP offer/answer
- `Server::calls()` and `Server::find_call()` for active call inspection
- Server-level callbacks: `on_incoming`, `on_call_state`, `on_call_ended`, `on_call_dtmf`
- 8 FakePBX integration tests: inbound/outbound calls, RTP round-trip, auth rejection, callbacks, find_call

## [0.3.3] - 2026-03-12

### Changed

- `Call::set_rtp_socket` and `Call::set_local_media` are now public API, enabling external SIP transports (e.g. xbridge trunk host) to wire media pipelines without going through `Phone`

## [0.3.2] - 2026-03-11

### Added

- CI check requiring `CHANGELOG.md` update on every PR
- Release checklist in project guidelines (CHANGELOG, README, version bump, tests, review)
- Updated README with paced PCM writer documentation and usage examples

## [0.3.1] - 2026-03-11

### Added

- **Paced PCM writer** — `Call::paced_pcm_writer()` accepts arbitrary-length PCM buffers (e.g. entire TTS utterances from Deepgram, ElevenLabs), splits into codec-frame-sized chunks, and sends RTP packets at real-time pace (one frame every 20ms)
- Mutual exclusion between `pcm_writer` and `paced_pcm_writer` prevents RTP stream corruption if both are used

### Fixed

- Audio playing at 10x+ speed when TTS providers deliver audio in bursts rather than at real-time rate

## [0.3.0] - 2026-03-10

### Added

- **Attended transfer** — consultative transfer via REFER with Replaces (RFC 3891)
- **SIP INFO DTMF** — send/receive DTMF via SIP INFO `application/dtmf-relay` (RFC 2976), configurable via `DtmfMode::SipInfo` or `DtmfMode::Both`
- **Call waiting** — multiple simultaneous calls with `Phone.calls()` API
- **G.729 codec** — optional `g729-codec` feature (PT 18, pure Rust via `g729-sys`, no system deps). SDP advertises `annexb=no`.
- **SRTCP encryption** — RTCP packets encrypted per RFC 3711 §3.4
- **Key material zeroization** — SRTP keys zeroed on drop
- **TURN relay** — NAT traversal for symmetric NAT environments (RFC 5766) with long-term credentials
- **ICE-Lite** — SDP candidate gathering and STUN responder (RFC 8445 §2.2)
- **SIP MESSAGE** — instant messaging over SIP (RFC 3428) via `Phone.send_message()`
- **SUBSCRIBE/NOTIFY** — generic event subscription framework (RFC 6665) via `Phone.subscribe_event()`
- **BLF** — Busy Lamp Field monitoring via dialog event package (RFC 4235)
- **MWI** — voicemail notification via `message-summary` event package (RFC 3842)
- **H.264 RTP packetizer/depacketizer** — Single NAL, STAP-A, FU-A modes (RFC 6184)
- **VP8 RTP packetizer/depacketizer** — RFC 7741
- **Video RTP pipeline** — separate video media stream with `video_reader()`, `video_writer()`, `video_rtp_reader()`, `video_rtp_writer()`
- **Mid-call video upgrade/downgrade** — re-INVITE to add or remove video
- **Video upgrade accept/reject API** — privacy-safe `VideoUpgradeRequest` with `accept()`/`reject()` and auto-reject on drop
- **Video SRTP** — separate SRTP contexts for audio and video streams
- **RTCP PLI/FIR** — keyframe requests for video (RFC 4585)
- **`video-display` feature** — sipcli with H.264 decoding (openh264) and video window (minifb)

### Changed

- `DialOptions` now supports `video: bool` and `video_codecs` for outbound video calls
- `Call::add_video()` for upgrading an existing audio call to video
- Features table in README fully categorized (Calling, DTMF, Audio, Video, Security, Network, Messaging, Testing)

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
