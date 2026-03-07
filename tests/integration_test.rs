//! Integration tests against a running Asterisk instance.
//!
//! Start with: cd testutil/docker && docker compose up -d
//! Run with:   cargo test --features integration --test integration_test -- --nocapture
//! Stop with:  cd testutil/docker && docker compose down
//!
//! These tests are gated behind the `integration` feature flag so they
//! never run during normal `cargo test`.

#![cfg(feature = "integration")]

use std::time::Duration;

use xphone::sip::client::{Client, ClientConfig};

fn asterisk_host() -> String {
    std::env::var("ASTERISK_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

fn integration_client_config(ext: &str, password: &str) -> ClientConfig {
    let host = asterisk_host();
    ClientConfig {
        local_addr: "0.0.0.0:0".into(),
        server_addr: format!("{}:5060", host).parse().unwrap(),
        username: ext.into(),
        password: password.into(),
        domain: host,
    }
}

// --- E1: Registration ---

/// Register extension 1001 with Asterisk and get 200 OK.
#[test]
fn register_1001() {
    let cfg = integration_client_config("1001", "test");
    let client = Client::new(cfg).unwrap();

    let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200, "expected 200, got {} {}", code, reason);

    client.close();
}

/// Register extension 1002 with Asterisk.
#[test]
fn register_1002() {
    let cfg = integration_client_config("1002", "test");
    let client = Client::new(cfg).unwrap();

    let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200, "expected 200, got {} {}", code, reason);

    client.close();
}

/// Registration with wrong password should fail (401 or rejected).
#[test]
fn register_wrong_password() {
    let cfg = integration_client_config("1001", "wrong");
    let client = Client::new(cfg).unwrap();

    let result = client.send_register(Duration::from_secs(5));
    match result {
        Ok((code, _)) => assert_ne!(code, 200, "should not get 200 with wrong password"),
        Err(_) => {} // transport error is also acceptable
    }

    client.close();
}

/// NAT keepalive should not error.
#[test]
fn keepalive() {
    let cfg = integration_client_config("1001", "test");
    let client = Client::new(cfg).unwrap();

    // Register first.
    let (code, _) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200);

    // Send keepalive — should not error.
    client.send_keepalive().unwrap();

    client.close();
}

// --- Placeholder tests for full E2E (require production SipTransport) ---
// These will be implemented once FakePBX-Rust / real SipTransport is ready.

#[test]
#[ignore = "requires production SipTransport (Phase 5.3)"]
fn dial_between_extensions() {
    // E2: p1 (1001) dials p2 (1002), p2 accepts, p1 ends call.
    todo!("implement once Phone can connect to real Asterisk")
}

#[test]
#[ignore = "requires production SipTransport (Phase 5.3)"]
fn inbound_accept_and_remote_bye() {
    // E3: p1 dials p2, p2 accepts, p1 sends BYE, p2 sees EndedByRemote.
    todo!("implement once Phone can connect to real Asterisk")
}

#[test]
#[ignore = "requires production SipTransport (Phase 5.3)"]
fn hold_resume() {
    // E4: establish call, hold, resume.
    todo!("implement once Phone can connect to real Asterisk")
}

#[test]
#[ignore = "requires production SipTransport (Phase 5.3)"]
fn dtmf_send_receive() {
    // E5: establish call, send DTMF from p2, receive on p1.
    todo!("implement once Phone can connect to real Asterisk")
}

#[test]
#[ignore = "requires production SipTransport (Phase 5.3)"]
fn echo_test() {
    // E6: dial 9999, send RTP, verify echo.
    todo!("implement once Phone can connect to real Asterisk")
}
