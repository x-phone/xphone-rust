//! Integration tests against a running Asterisk instance.
//!
//! Start with: cd testutil/docker && docker compose up -d
//! Run with:   LOCAL_IP=192.168.65.254 cargo test --features integration --test integration_test -- --nocapture --test-threads=1
//! Stop with:  cd testutil/docker && docker compose down
//!
//! Environment variables:
//!   ASTERISK_HOST     — SIP server address (default: 127.0.0.1)
//!   ASTERISK_PORT     — SIP server port (default: 5160)
//!   ASTERISK_PASSWORD — Extension password (default: test)
//!   LOCAL_IP          — Local IP for SDP (required for Docker on macOS: 192.168.65.254)
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

fn asterisk_password() -> String {
    std::env::var("ASTERISK_PASSWORD").unwrap_or_else(|_| "test".into())
}

fn asterisk_port() -> u16 {
    std::env::var("ASTERISK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5160)
}

/// Local IP to advertise in SDP, overridable for Docker-on-macOS.
fn local_ip_override() -> Option<String> {
    std::env::var("LOCAL_IP").ok()
}

fn integration_client_config(ext: &str, password: &str) -> ClientConfig {
    let host = asterisk_host();
    let port = asterisk_port();
    ClientConfig {
        local_addr: "0.0.0.0:0".into(),
        server_addr: format!("{}:{}", host, port).parse().unwrap(),
        username: ext.into(),
        password: password.into(),
        domain: host,
        transport: "udp".into(),
        tls_config: None,
        stun_server: None,
    }
}

fn integration_phone_config(ext: &str, password: &str) -> Config {
    Config {
        username: ext.into(),
        password: password.into(),
        host: asterisk_host(),
        port: asterisk_port(),
        local_ip: local_ip_override().unwrap_or_default(),
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
    let cfg = integration_client_config("1001", &asterisk_password());
    let client = Client::new(cfg).unwrap();

    let (code, reason) = client.send_register(Duration::from_secs(5)).unwrap();
    assert_eq!(code, 200, "expected 200, got {} {}", code, reason);

    client.close();
}

/// Register extension 1002 with Asterisk using raw SIP client.
#[test]
fn register_1002_raw() {
    let cfg = integration_client_config("1002", &asterisk_password());
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
    let cfg = integration_client_config("1001", &asterisk_password());
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
    let cfg = integration_phone_config("1001", &asterisk_password());
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
    let cfg1 = integration_phone_config("1001", &asterisk_password());
    let cfg2 = integration_phone_config("1002", &asterisk_password());

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
    let cfg1 = integration_phone_config("1001", &asterisk_password());
    let cfg2 = integration_phone_config("1002", &asterisk_password());

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

/// E4: p1 dials p2, p2 accepts, p1 holds, p1 resumes, p1 ends.
#[test]
fn hold_resume() {
    let cfg1 = integration_phone_config("1001", &asterisk_password());
    let cfg2 = integration_phone_config("1002", &asterisk_password());

    let p1 = Phone::new(cfg1);
    let p2 = Phone::new(cfg2);

    p1.connect().unwrap();
    p2.connect().unwrap();

    let (call_tx, call_rx) = crossbeam_channel::bounded(1);
    p2.on_incoming(move |call| {
        call.accept().unwrap();
        let _ = call_tx.send(call);
    });

    let opts = xphone::config::DialOptions {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let call1 = p1.dial("1002", opts).unwrap();
    let _call2 = call_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    assert_eq!(call1.state(), xphone::types::CallState::Active);

    // Hold.
    call1.hold().unwrap();
    assert_eq!(call1.state(), xphone::types::CallState::OnHold);

    // Give Asterisk time to process the re-INVITE.
    std::thread::sleep(Duration::from_millis(500));

    // Resume.
    call1.resume().unwrap();
    assert_eq!(call1.state(), xphone::types::CallState::Active);

    std::thread::sleep(Duration::from_millis(500));

    // End.
    call1.end().unwrap();

    p1.disconnect().unwrap();
    p2.disconnect().unwrap();
}

/// E5: p1 dials p2, p2 sends DTMF "5", p1 receives it via OnDTMF.
/// Ignored in CI: Asterisk bridge DTMF relay is timing-sensitive.
/// Run locally: cargo test --features integration --test integration_test dtmf -- --ignored
#[test]
#[ignore]
fn dtmf_send_receive() {
    let cfg1 = integration_phone_config("1001", &asterisk_password());
    let cfg2 = integration_phone_config("1002", &asterisk_password());

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

    assert_eq!(call1.state(), xphone::types::CallState::Active);
    assert_eq!(call2.state(), xphone::types::CallState::Active);

    // Register DTMF callback on p1's outbound call.
    let (dtmf_tx, dtmf_rx) = crossbeam_channel::bounded(10);
    call1.on_dtmf(move |digit| {
        let _ = dtmf_tx.send(digit);
    });

    // Wait for RTP media paths to fully establish through Asterisk bridge.
    // CI environments are slower, so give extra time.
    std::thread::sleep(Duration::from_secs(2));

    // p2 sends DTMF digit "5" — retry up to 3 times in case the bridge isn't ready.
    let mut digit = None;
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        call2.send_dtmf("5").unwrap();
        if let Ok(d) = dtmf_rx.recv_timeout(Duration::from_secs(3)) {
            digit = Some(d);
            break;
        }
    }
    assert_eq!(digit.expect("DTMF digit never received by p1"), "5");

    call1.end().unwrap();

    p1.disconnect().unwrap();
    p2.disconnect().unwrap();
}

/// E6: dial 9999 (echo), send silence RTP, verify we receive echoed RTP back.
#[test]
fn echo_test() {
    let cfg = integration_phone_config("1001", &asterisk_password());
    let p = Phone::new(cfg);
    p.connect().unwrap();

    let opts = xphone::config::DialOptions {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let call = p.dial("9999", opts).unwrap();
    assert_eq!(call.state(), xphone::types::CallState::Active);

    // Get media channels.
    let rtp_writer = call.rtp_writer().expect("rtp_writer channel not available");
    let rtp_reader = call.rtp_reader().expect("rtp_reader channel not available");

    // Send silence via RTPWriter so Asterisk Echo() has something to reflect.
    let silence = vec![0xFFu8; 160]; // PCMU silence
    for i in 0..50 {
        let pkt = xphone::types::RtpPacket {
            header: xphone::types::RtpHeader {
                version: 2,
                payload_type: 0, // PCMU
                sequence_number: i as u16,
                timestamp: (i as u32) * 160,
                ssrc: 0xDEADBEEF,
                marker: false,
            },
            payload: silence.clone(),
        };
        let _ = rtp_writer.send(pkt);
        std::thread::sleep(Duration::from_millis(20));
    }

    // Verify we receive echoed RTP back.
    let pkt = rtp_reader
        .recv_timeout(Duration::from_secs(5))
        .expect("no echo response received");
    assert!(!pkt.payload.is_empty());

    call.end().unwrap();
    p.disconnect().unwrap();
}
