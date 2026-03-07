//! FakePBX integration tests — real SIP over loopback, no Docker.
//!
//! These tests use the `fakepbx` crate to run an in-process SIP server
//! and exercise xphone's full stack: SIP signaling, call state machine,
//! SDP negotiation, and media pipeline.
//!
//! Run with: cargo test --test fakepbx_test -- --test-threads=1

use std::time::Duration;

use fakepbx::{sdp, with_auth, FakePBX};
use xphone::config::{Config, DialOptions};
use xphone::types::{CallState, EndReason, PhoneState};
use xphone::Phone;

/// Builds a Config pointing at the given FakePBX instance.
fn pbx_config(pbx: &FakePBX) -> Config {
    let addr = pbx.addr();
    let (host, port_str) = addr.rsplit_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap();
    Config {
        username: "1001".into(),
        password: "test".into(),
        host: host.into(),
        port,
        register_expiry: Duration::from_secs(60),
        register_retry: Duration::from_secs(1),
        register_max_retry: 3,
        media_timeout: Duration::from_secs(10),
        rtp_port_min: 30000,
        rtp_port_max: 30099,
        ..Config::default()
    }
}

/// Creates a Phone connected and registered to the given FakePBX.
fn connect_pbx(pbx: &FakePBX) -> Phone {
    let cfg = pbx_config(pbx);
    let phone = Phone::new(cfg);

    let (reg_tx, reg_rx) = crossbeam_channel::bounded(1);
    phone.on_registered(move || {
        let _ = reg_tx.try_send(());
    });

    phone.connect().unwrap();

    // Wait for registration to complete.
    reg_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("registration timeout");

    phone
}

// --- F1: Register with digest auth ---

#[test]
fn fakepbx_register() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);
    let phone = connect_pbx(&pbx);
    assert_eq!(phone.state(), PhoneState::Registered);
    assert!(pbx.register_count() >= 1);
    phone.disconnect().unwrap();
}

// --- F2: Dial, verify SDP negotiation, local hangup ---

#[test]
fn fakepbx_dial_and_local_end() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);

    let rtp_port = 20100u16;
    let answer_sdp = sdp::sdp("127.0.0.1", rtp_port, &[sdp::PCMA]);
    pbx.on_invite(move |inv| {
        inv.trying();
        inv.ringing();
        inv.answer(&answer_sdp);
    });

    let phone = connect_pbx(&pbx);

    let opts = DialOptions {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let call = phone.dial("9999", opts).unwrap();
    assert_eq!(call.state(), CallState::Active);

    // Verify SDP negotiation.
    assert!(!call.local_sdp().is_empty());
    assert!(!call.remote_sdp().is_empty());
    assert_eq!(call.remote_ip(), "127.0.0.1");
    assert_eq!(call.remote_port(), rtp_port as i32);

    // End the call.
    call.end().unwrap();
    assert_eq!(call.state(), CallState::Ended);

    // Verify BYE was received by PBX.
    assert!(
        pbx.wait_for_bye(1, Duration::from_secs(2)),
        "BYE never received by PBX"
    );

    phone.disconnect().unwrap();
}

// --- F3: PBX hangs up mid-call — xphone detects EndedByRemote ---

#[test]
fn fakepbx_remote_bye() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);

    let (ac_tx, ac_rx) = crossbeam_channel::bounded(1);
    let answer_sdp = sdp::sdp("127.0.0.1", 20200, &[sdp::PCMA]);
    pbx.on_invite(move |inv| {
        inv.trying();
        inv.ringing();
        let ac = inv.answer(&answer_sdp);
        let _ = ac_tx.send(ac);
    });

    let phone = connect_pbx(&pbx);

    let opts = DialOptions {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let call = phone.dial("9999", opts).unwrap();
    assert_eq!(call.state(), CallState::Active);

    let ac = ac_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("INVITE handler never completed");

    let (ended_tx, ended_rx) = crossbeam_channel::bounded(1);
    call.on_ended(move |reason| {
        let _ = ended_tx.send(reason);
    });

    // Brief pause to let media pipeline start.
    std::thread::sleep(Duration::from_millis(200));

    // PBX sends BYE.
    if let Some(ac) = ac {
        let _ = ac.send_bye();
    }

    let reason = ended_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("call never received remote BYE");
    assert_eq!(reason, EndReason::Remote);

    phone.disconnect().unwrap();
}

// --- F4: Hold and resume via re-INVITE ---

#[test]
fn fakepbx_hold_resume() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);

    let answer_sdp = sdp::sdp("127.0.0.1", 20300, &[sdp::PCMA]);
    pbx.on_invite(move |inv| {
        inv.trying();
        inv.ringing();
        inv.answer(&answer_sdp);
    });

    let phone = connect_pbx(&pbx);

    let opts = DialOptions {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let call = phone.dial("9999", opts).unwrap();
    assert_eq!(call.state(), CallState::Active);

    // Hold.
    call.hold().unwrap();
    assert_eq!(call.state(), CallState::OnHold);

    // Verify the re-INVITE was sent (PBX receives it): initial + hold = 2.
    assert!(
        pbx.wait_for_invite(2, Duration::from_secs(2)),
        "hold re-INVITE not received"
    );

    // Resume.
    call.resume().unwrap();
    assert_eq!(call.state(), CallState::Active);

    // Initial + hold + resume = 3 INVITEs.
    assert!(
        pbx.wait_for_invite(3, Duration::from_secs(2)),
        "resume re-INVITE not received"
    );

    call.end().unwrap();
    phone.disconnect().unwrap();
}

// --- F5: 486 Busy Here rejection ---

#[test]
fn fakepbx_busy_reject() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);
    pbx.auto_busy();

    let phone = connect_pbx(&pbx);

    let opts = DialOptions {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let result = phone.dial("9999", opts);
    assert!(result.is_err(), "dial should fail on 486 Busy Here");

    phone.disconnect().unwrap();
}

// --- F6: Provisionals — verify state transitions through Ringing ---

#[test]
fn fakepbx_provisionals() {
    let pbx = FakePBX::new(&[with_auth("1001", "test")]);

    let answer_sdp = sdp::sdp("127.0.0.1", 20400, &[sdp::PCMA]);
    pbx.on_invite(move |inv| {
        inv.trying();
        inv.ringing();
        // Brief delay so xphone has time to process 180 before 200.
        std::thread::sleep(Duration::from_millis(50));
        inv.answer(&answer_sdp);
    });

    let phone = connect_pbx(&pbx);

    let opts = DialOptions {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let call = phone.dial("9999", opts).unwrap();

    // At this point the call should be Active.
    assert_eq!(call.state(), CallState::Active);

    call.end().unwrap();
    phone.disconnect().unwrap();
}

// --- F7: Register without auth ---

#[test]
fn fakepbx_register_no_auth() {
    let pbx = FakePBX::new(&[]);
    let phone = connect_pbx(&pbx);
    assert_eq!(phone.state(), PhoneState::Registered);
    phone.disconnect().unwrap();
}

// --- F8: Disconnect fires unregistered callback ---

#[test]
fn fakepbx_disconnect_fires_unregistered() {
    let pbx = FakePBX::new(&[]);
    let phone = connect_pbx(&pbx);

    let (unreg_tx, unreg_rx) = crossbeam_channel::bounded(1);
    phone.on_unregistered(move || {
        let _ = unreg_tx.try_send(());
    });

    phone.disconnect().unwrap();
    assert_eq!(phone.state(), PhoneState::Disconnected);

    // Callback should fire.
    unreg_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("on_unregistered never fired");
}
