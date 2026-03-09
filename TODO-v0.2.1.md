# v0.2.1 Roadmap

## Features (in order of implementation)

- [x] **SIP INFO DTMF (RFC 2976)** — legacy PBX DTMF fallback
  - Send DTMF via SIP INFO with application/dtmf-relay body
  - Receive and parse incoming SIP INFO DTMF messages
  - Config option to select DTMF method (rfc4733 | sip-info | auto)
  - Branch: `feat/sip-info-dtmf`

- [ ] **Call Waiting / Multi-Call** — handle concurrent INVITEs
  - Surface 2nd INVITE via on_incoming even during active call
  - Application decides: accept (hold first), reject (486 Busy), or ignore
  - Branch: `feat/call-waiting`

- [ ] **SRTCP Encryption** — encrypt RTCP packets (RFC 3711 §3.4)
  - Protect/unprotect SRTCP using existing SRTP key material
  - SRTCP index with E-flag and rollover counter
  - Branch: `feat/srtcp`

- [ ] **Key Zeroization** — secure key material cleanup
  - Add `zeroize` crate dependency
  - Zeroize SRTP master key, session keys, and salt on drop
  - Zeroize SIP digest auth password after use
  - Branch: `feat/key-zeroize`

- [ ] **Attended Transfer (RFC 5589)** — consultative transfer
  - Coordinate two simultaneous call legs from one Phone instance
  - REFER with Replaces header to bridge the legs
  - State machine coordination between the two calls
  - Branch: `feat/attended-transfer`

## Tech Debt

- [ ] **Refactor MWI to use SubscriptionManager** — MWI's subscribe/unsubscribe/refresh lifecycle in `mwi.rs` duplicates ~40 lines of logic now provided by the generic `SubscriptionManager`. Refactor MWI to be built on top of it.

- [ ] **dialog-info XML parser: handle self-closing `<state/>`** — `parse_dialog_states` treats `Event::Empty` the same as `Event::Start`, which sets `in_state = true` but no `Text` event follows. Could misparse exotic dialog-info documents with self-closing state elements.

- [ ] **Unify `parse_param` and `param_value`** — `types.rs:parse_param` and `sip/message.rs:param_value` both extract named parameters from semicolon-separated strings with slightly different signatures. Consider unifying into a single utility.

## Process
- Each feature gets its own branch off main
- PR with CI green before merge
- Tag v0.2.1 after all features merged
