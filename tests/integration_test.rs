//! Integration tests against a running Asterisk instance.
//!
//! Start with: cd testutil/docker && docker compose up -d
//! Run with:   cargo test --features integration --test integration_test -- --nocapture --test-threads=1
//! Stop with:  cd testutil/docker && docker compose down
//!
//! These tests are gated behind the `integration` feature flag so they
//! never run during normal `cargo test`.

#![cfg(feature = "integration")]

use std::time::Duration;

use xphone::config::Config;
use xphone::sip::client::{Client, ClientConfig};
use xphone::Phone;

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

fn integration_phone_config(ext: &str, password: &str) -> Config {
    Config {
        username: ext.into(),
        password: password.into(),
        host: asterisk_host(),
        port: 5060,
        register_expiry: Duration::from_secs(10),
        register_retry: Duration::from_secs(1),
        register_max_retry: 3,
        media_timeout: Duration::from_secs(10),
        rtp_port_min: 20000,
        rtp_port_max: 20099,
        ..Config::default()
    }
}

// --- E1: Registration (low-level Client) ---

/// Register extension 1001 with Asterisk using raw SIP client.
#[test]
fn register_1001_raw() {
    let cfg = integration_client_config("1001", "test");
    let client = Client::new(cfg).unwrap();

    let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200, "expected 200, got {} {}", code, reason);

    client.close();
}

/// Register extension 1002 with Asterisk using raw SIP client.
#[test]
fn register_1002_raw() {
    let cfg = integration_client_config("1002", "test");
    let client = Client::new(cfg).unwrap();

    let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200, "expected 200, got {} {}", code, reason);

    client.close();
}

/// Registration with wrong password should fail.
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

    let (code, _) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200);

    client.send_keepalive().unwrap();
    client.close();
}

// --- E1b: Registration via Phone::connect() ---

/// Register extension 1001 via the full Phone::connect() path.
#[test]
fn phone_connect_and_disconnect() {
    let cfg = integration_phone_config("1001", "test");
    let phone = Phone::new(cfg);

    phone.connect().unwrap();
    assert_eq!(phone.state(), xphone::PhoneState::Registered);

    phone.disconnect().unwrap();
    assert_eq!(phone.state(), xphone::PhoneState::Disconnected);
}

/// Phone::connect() with wrong password should fail.
#[test]
fn phone_connect_wrong_password() {
    let cfg = integration_phone_config("1001", "wrong");
    let phone = Phone::new(cfg);

    let result = phone.connect();
    assert!(result.is_err());
}

// --- E2E call tests ---

/// E2: p1 (1001) dials p2 (1002), p2 accepts, p1 ends call.
#[test]
fn dial_between_extensions() {
    let cfg1 = integration_phone_config("1001", "test");
    let cfg2 = integration_phone_config("1002", "test");

    let p1 = Phone::new(cfg1);
    let p2 = Phone::new(cfg2);

    p1.connect().unwrap();
    p2.connect().unwrap();

    // Set up p2 to auto-accept incoming calls.
    let (call_tx, call_rx) = crossbeam_channel::bounded(1);
    p2.on_incoming(move |call| {
        call.accept().unwrap();
        let _ = call_tx.send(call);
    });

    // p1 dials p2.
    let opts = xphone::config::DialOptions {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let call1 = p1.dial("1002", opts).unwrap();

    // Wait for p2 to receive and accept the call.
    let call2 = call_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    // Both calls should be active.
    assert_eq!(call1.state(), xphone::types::CallState::Active);
    assert_eq!(call2.state(), xphone::types::CallState::Active);

    // p1 ends the call.
    call1.end().unwrap();

    // Give BYE time to propagate.
    std::thread::sleep(Duration::from_millis(500));

    // p2 should see the call ended by remote.
    assert_eq!(call2.state(), xphone::types::CallState::Ended);

    p1.disconnect().unwrap();
    p2.disconnect().unwrap();
}

/// E3: p1 dials p2, p2 accepts, p1 sends BYE, p2 sees EndedByRemote.
#[test]
fn inbound_accept_and_remote_bye() {
    let cfg1 = integration_phone_config("1001", "test");
    let cfg2 = integration_phone_config("1002", "test");

    let p1 = Phone::new(cfg1);
    let p2 = Phone::new(cfg2);

    p1.connect().unwrap();
    p2.connect().unwrap();

    let (ended_tx, ended_rx) = crossbeam_channel::bounded::<xphone::types::EndReason>(1);
    let (call_tx, call_rx) = crossbeam_channel::bounded(1);

    p2.on_incoming(move |call| {
        let ended_tx = ended_tx.clone();
        call.on_ended(move |reason| {
            let _ = ended_tx.send(reason);
        });
        call.accept().unwrap();
        let _ = call_tx.send(true);
    });

    let opts = xphone::config::DialOptions {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let call1 = p1.dial("1002", opts).unwrap();

    // Wait for accept.
    call_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    // p1 ends the call.
    call1.end().unwrap();

    // p2 should get EndedByRemote.
    let reason = ended_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(reason, xphone::types::EndReason::Remote);

    p1.disconnect().unwrap();
    p2.disconnect().unwrap();
}

#[test]
#[ignore = "requires re-INVITE hold support through Asterisk"]
fn hold_resume() {
    // E4: establish call, hold, resume.
    todo!()
}

#[test]
#[ignore = "requires RTP/DTMF pipeline"]
fn dtmf_send_receive() {
    // E5: establish call, send DTMF from p2, receive on p1.
    todo!()
}

#[test]
#[ignore = "requires RTP pipeline"]
fn echo_test() {
    // E6: dial 9999, send RTP, verify echo.
    todo!()
}
