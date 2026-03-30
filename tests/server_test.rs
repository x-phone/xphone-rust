//! Server mode integration tests — FakePBX acts as a SIP peer.
//!
//! These tests exercise the trunk Server's full stack: peer authentication,
//! SIP signaling, call state machine, SDP negotiation, and media pipeline.
//!
//! Run with: cargo test --test server_test

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fakepbx::{sdp, FakePBX};
use xphone::trunk::config::{PeerConfig, ServerConfig};
use xphone::trunk::server::Server;
use xphone::types::{CallState, EndReason};

/// Helper: start a Server on 127.0.0.1:0 with a peer configured for the given FakePBX.
fn make_server(pbx: &FakePBX) -> Server {
    let addr = pbx.addr();
    let (host, _) = addr.rsplit_once(':').unwrap();
    let ip: std::net::IpAddr = host.parse().unwrap();

    let config = ServerConfig {
        listen: "127.0.0.1:0".into(),
        peers: vec![PeerConfig {
            name: "test-peer".into(),
            host: Some(ip),
            ..Default::default()
        }],
        rtp_port_min: 31000,
        rtp_port_max: 31099,
        ..Default::default()
    };
    Server::new(config)
}

/// Helper: start server.listen() in background and wait for it to bind.
fn start_server(server: &Server) -> String {
    let s = server.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.listen().await.unwrap() });
    });

    // Poll until local_addr is available.
    for _ in 0..200 {
        if let Some(addr) = server.local_addr() {
            return addr.to_string();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not bind within 2 seconds");
}

// --- S1: Inbound call — FakePBX sends INVITE, Server accepts ---

#[test]
fn server_inbound_call_accept() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let accepted = Arc::new(AtomicBool::new(false));
    let a = accepted.clone();

    let (state_tx, state_rx) = crossbeam_channel::bounded::<CallState>(8);

    server.on_incoming(move |call| {
        a.store(true, Ordering::SeqCst);
        call.accept().unwrap();
    });

    server.on_call_state(move |_call, state| {
        let _ = state_tx.try_send(state);
    });

    let server_addr = start_server(&server);

    // FakePBX sends INVITE to server.
    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
    let oc = pbx
        .send_invite(&target, &offer_sdp)
        .expect("send_invite failed");

    assert!(
        accepted.load(Ordering::SeqCst),
        "on_incoming was not called"
    );
    assert_eq!(server.call_count(), 1);

    // End the call from the peer side.
    let bye_code = oc.send_bye().expect("send_bye failed");
    assert_eq!(bye_code, 200);

    // Wait for Ended state.
    let mut saw_ended = false;
    for _ in 0..20 {
        match state_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(CallState::Ended) => {
                saw_ended = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(saw_ended, "call did not reach Ended state");
    server.stop();
}

// --- S2: Inbound call — Server rejects (no handler) ---

#[test]
fn server_inbound_no_handler_rejects() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    // No on_incoming handler set — server should reject.
    let server_addr = start_server(&server);

    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);

    // send_invite returns Err for non-2xx responses.
    let result = pbx.send_invite(&target, &offer_sdp);
    assert!(result.is_err(), "expected rejection but got success");

    assert_eq!(server.call_count(), 0);
    server.stop();
}

// --- S3: Auth rejection — unknown source IP ---

#[test]
fn server_auth_rejects_unknown_ip() {
    let pbx = FakePBX::new(&[]);

    // Configure server with a peer on a different IP — 10.0.0.1 won't match 127.0.0.1.
    let config = ServerConfig {
        listen: "127.0.0.1:0".into(),
        peers: vec![PeerConfig {
            name: "remote-peer".into(),
            host: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        }],
        rtp_port_min: 31100,
        rtp_port_max: 31199,
        ..Default::default()
    };
    let server = Server::new(config);
    let server_addr = start_server(&server);

    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);

    // Should be rejected (403 Forbidden) since 127.0.0.1 doesn't match 10.0.0.1.
    let result = pbx.send_invite(&target, &offer_sdp);
    assert!(result.is_err(), "expected auth rejection but got success");
    server.stop();
}

// --- S4: Outbound call — Server dials FakePBX ---

#[test]
fn server_outbound_dial() {
    let pbx = FakePBX::new(&[]);
    pbx.auto_answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));

    // Parse FakePBX address for peer config.
    let pbx_addr = pbx.addr();
    let (host, port_str) = pbx_addr.rsplit_once(':').unwrap();
    let ip: std::net::IpAddr = host.parse().unwrap();
    let port: u16 = port_str.parse().unwrap();

    let config = ServerConfig {
        listen: "127.0.0.1:0".into(),
        peers: vec![PeerConfig {
            name: "test-pbx".into(),
            host: Some(ip),
            port,
            ..Default::default()
        }],
        rtp_port_min: 31200,
        rtp_port_max: 31299,
        ..Default::default()
    };
    let server = Server::new(config);

    let (ended_tx, ended_rx) = crossbeam_channel::bounded::<EndReason>(1);
    server.on_call_ended(move |_call, reason| {
        let _ = ended_tx.try_send(reason);
    });

    let server_addr = start_server(&server);
    // Sanity: server is listening.
    assert!(server.local_addr().is_some());
    let _ = server_addr; // used to start the server

    // Dial out to FakePBX.
    let call = server
        .dial("test-pbx", "1002", "1001")
        .expect("dial failed");

    // Wait for the call to become Active (200 OK received).
    for _ in 0..50 {
        if call.state() == CallState::Active {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(call.state(), CallState::Active, "call did not reach Active");
    assert_eq!(server.call_count(), 1);

    // End the call.
    call.end().unwrap();

    // Wait for ended callback.
    let reason = ended_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("on_call_ended not fired");
    assert!(
        matches!(reason, EndReason::Local),
        "expected Local end reason, got {reason:?}"
    );
    server.stop();
}

// --- S4b: Outbound dial via SIP URI (no peer config) ---

#[test]
fn server_outbound_dial_uri() {
    let pbx = FakePBX::new(&[]);
    pbx.auto_answer(&sdp::sdp("127.0.0.1", 20100, &[sdp::PCMU]));

    // Server with NO peers configured — dial_uri doesn't need them.
    let config = ServerConfig {
        listen: "127.0.0.1:0".into(),
        rtp_port_min: 31300,
        rtp_port_max: 31399,
        ..Default::default()
    };
    let server = Server::new(config);

    let (ended_tx, ended_rx) = crossbeam_channel::bounded::<EndReason>(1);
    server.on_call_ended(move |_call, reason| {
        let _ = ended_tx.try_send(reason);
    });

    let _server_addr = start_server(&server);

    // Dial directly using the FakePBX's SIP URI.
    let sip_uri = format!("sip:1002@{}", pbx.addr());
    let call = server.dial_uri(&sip_uri, "1001").expect("dial_uri failed");

    // Wait for the call to become Active.
    for _ in 0..50 {
        if call.state() == CallState::Active {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(call.state(), CallState::Active, "call did not reach Active");

    call.end().unwrap();

    let reason = ended_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("on_call_ended not fired");
    assert!(
        matches!(reason, EndReason::Local),
        "expected Local, got {reason:?}"
    );
    server.stop();
}

// --- S5: Inbound call with DTMF callback ---

#[test]
fn server_inbound_dtmf_callback() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let (dtmf_tx, dtmf_rx) = crossbeam_channel::bounded::<String>(8);

    server.on_incoming(|call| {
        call.accept().unwrap();
    });

    server.on_call_dtmf(move |_call, digit| {
        let _ = dtmf_tx.try_send(digit);
    });

    let server_addr = start_server(&server);

    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
    let _oc = pbx
        .send_invite(&target, &offer_sdp)
        .expect("send_invite failed");

    assert_eq!(server.call_count(), 1);

    // Note: we can't easily send RFC4733 DTMF via FakePBX in this test,
    // but we verify the callback was wired without panic.
    assert!(dtmf_rx.try_recv().is_err(), "no DTMF expected yet");

    server.stop();
}

// --- S6: Multiple inbound calls ---

#[test]
fn server_multiple_inbound_calls() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = call_count.clone();

    server.on_incoming(move |call| {
        cc.fetch_add(1, Ordering::SeqCst);
        call.accept().unwrap();
    });

    let server_addr = start_server(&server);

    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);

    // Send two INVITEs.
    let target1 = format!("sip:1002@{server_addr}");
    let oc1 = pbx
        .send_invite(&target1, &offer_sdp)
        .expect("first send_invite failed");

    let target2 = format!("sip:1003@{server_addr}");
    let oc2 = pbx
        .send_invite(&target2, &offer_sdp)
        .expect("second send_invite failed");

    assert_eq!(call_count.load(Ordering::SeqCst), 2);
    assert_eq!(server.call_count(), 2);

    // End both.
    oc1.send_bye().unwrap();
    oc2.send_bye().unwrap();

    // Wait for cleanup.
    for _ in 0..20 {
        if server.call_count() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(server.call_count(), 0);
    server.stop();
}

// --- S7: RTP round-trip — bidirectional audio through media pipeline ---

#[test]
fn server_rtp_round_trip() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let (call_tx, call_rx) = crossbeam_channel::bounded::<Arc<xphone::Call>>(1);

    server.on_incoming(move |call| {
        call.accept().unwrap();
        let _ = call_tx.try_send(call);
    });

    let server_addr = start_server(&server);

    // Bind a test RTP socket for the peer side.
    let rtp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rtp_port = rtp_socket.local_addr().unwrap().port();
    rtp_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Send INVITE with SDP pointing to our test RTP socket.
    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", rtp_port, &[sdp::PCMU]);
    let _oc = pbx
        .send_invite(&target, &offer_sdp)
        .expect("send_invite failed");

    // Get the accepted call.
    let call = call_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("on_incoming did not fire");

    // Wait for media to be active.
    for _ in 0..50 {
        if call.state() == CallState::Active {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(call.state(), CallState::Active);

    // --- Inbound: send RTP from test socket → Server's media pipeline ---

    // Extract the server's RTP port from the local SDP (m=audio {port} ...).
    let local_sdp = call.local_sdp();
    let server_rtp_port: u16 = local_sdp
        .lines()
        .find(|l| l.starts_with("m=audio "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|p| p.parse().ok())
        .expect("could not extract RTP port from local SDP");

    // Build a minimal RTP packet (PCMU silence).
    let rtp_packet = build_rtp_packet(0, 1, 160, &[0xFFu8; 160]); // 0xFF = mu-law silence
    let server_rtp_addr = format!("127.0.0.1:{server_rtp_port}");
    rtp_socket
        .send_to(&rtp_packet, &server_rtp_addr)
        .expect("send_to failed");

    // Read decoded PCM from the call's pcm_reader.
    let pcm_rx = call.pcm_reader().expect("pcm_reader not available");
    let pcm = pcm_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("no PCM data received from media pipeline");
    assert!(!pcm.is_empty(), "PCM frame should not be empty");

    // --- Outbound: write PCM into Server → read RTP on test socket ---

    let pcm_tx = call.pcm_writer().expect("pcm_writer not available");
    pcm_tx
        .send(vec![0i16; 160])
        .expect("pcm_writer send failed");

    // Read the encoded RTP packet from our test socket.
    let mut recv_buf = [0u8; 2048];
    let (len, _from) = rtp_socket
        .recv_from(&mut recv_buf)
        .expect("no RTP packet received from server");
    assert!(len > 12, "RTP packet too small (header is 12 bytes)");

    // Verify RTP header basics.
    let version = (recv_buf[0] >> 6) & 0x03;
    assert_eq!(version, 2, "RTP version should be 2");
    let payload_type = recv_buf[1] & 0x7F;
    assert_eq!(payload_type, 0, "payload type should be 0 (PCMU)");

    server.stop();
}

/// Build a minimal RTP packet.
fn build_rtp_packet(pt: u8, seq: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len());
    pkt.push(0x80); // V=2, P=0, X=0, CC=0
    pkt.push(pt); // M=0, PT
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&timestamp.to_be_bytes());
    pkt.extend_from_slice(&0x12345678u32.to_be_bytes()); // SSRC
    pkt.extend_from_slice(payload);
    pkt
}

// --- S8: FindCall and Calls — query active calls during and after ---

#[test]
fn server_find_call_and_calls() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let (call_tx, call_rx) = crossbeam_channel::bounded::<Arc<xphone::Call>>(1);

    server.on_incoming(move |call| {
        call.accept().unwrap();
        let _ = call_tx.try_send(call);
    });

    let server_addr = start_server(&server);

    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
    let oc = pbx
        .send_invite(&target, &offer_sdp)
        .expect("send_invite failed");

    // Get the call from callback.
    let call = call_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("on_incoming did not fire");

    // --- calls() returns the active call ---
    let active = server.calls();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].call_id(), call.call_id());

    // --- find_call() by SIP Call-ID ---
    let sip_call_id = call.call_id();
    let found = server.find_call(&sip_call_id);
    assert!(found.is_some(), "find_call should find active call");
    assert_eq!(found.unwrap().call_id(), sip_call_id);

    // --- find_call() with wrong ID returns None ---
    assert!(server.find_call("nonexistent@host").is_none());

    // End the call.
    oc.send_bye().unwrap();

    // Wait for cleanup.
    for _ in 0..20 {
        if server.call_count() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // --- After call ends, calls() is empty and find_call returns None ---
    assert!(server.calls().is_empty());
    assert!(server.find_call(&sip_call_id).is_none());

    server.stop();
}

// --- S10: listen_with_socket — pre-bound socket works like listen() ---

#[test]
fn server_listen_with_socket() {
    let pbx = FakePBX::new(&[]);
    let server = make_server(&pbx);

    let accepted = Arc::new(AtomicBool::new(false));
    let a = accepted.clone();

    server.on_incoming(move |call| {
        a.store(true, Ordering::SeqCst);
        call.accept().unwrap();
    });

    // Pre-bind a socket and pass it to the server.
    let std_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = std_socket.local_addr().unwrap().to_string();

    let s = server.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.listen_with_socket(std_socket).await.unwrap() });
    });

    // Wait for server to be ready.
    for _ in 0..200 {
        if server.local_addr().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(server.local_addr().is_some(), "server did not start");

    // FakePBX sends INVITE to the pre-bound socket address.
    let target = format!("sip:1002@{server_addr}");
    let offer_sdp = sdp::sdp("127.0.0.1", 22000, &[sdp::PCMU]);
    let oc = pbx
        .send_invite(&target, &offer_sdp)
        .expect("send_invite failed");

    assert!(
        accepted.load(Ordering::SeqCst),
        "on_incoming was not called"
    );
    assert_eq!(server.call_count(), 1);

    let bye_code = oc.send_bye().expect("send_bye failed");
    assert_eq!(bye_code, 200);

    server.stop();
}
