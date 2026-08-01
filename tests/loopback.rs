//! End-to-end loopback tests: agent + client in-process over real QUIC on
//! localhost (no SSH).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use portmanager::client::Origin;
use portmanager::conn::Conn;
use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec, ReverseSpec};
use portmanager::reverse::{self, ReverseSet};
use portmanager::{agent, client, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Grace long enough to never trigger during a test.
const TEST_GRACE: Duration = Duration::from_secs(600);

/// A trivial echo server; returns its bound address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Bring up an in-process agent endpoint pinned to `client_fp`; returns its addr.
fn spawn_agent(
    agent_id: &Identity,
    client_fp: portmanager::crypto::Fingerprint,
    timing: &Timing,
) -> SocketAddr {
    let server_cfg = crypto::server_config(agent_id, client_fp, timing).unwrap();
    let ep = transport::server_endpoint(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = ep.local_addr().unwrap();
    tokio::spawn(agent::serve_with_grace(ep, TEST_GRACE, None));
    addr
}

#[tokio::test]
async fn forwards_bytes_end_to_end() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    let echo_addr = spawn_echo().await;

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn = transport::connect(&client_ep, agent_addr).await.unwrap();

    let (_slot_tx, slot_rx) = client::conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
        ns_inherited: false,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
        local_port_auto: false,
        kind: Default::default(),
    };
    let (local_addr, _task) = client::bind_forward(slot_rx, forward, client::new_health_handle())
        .await
        .unwrap();

    // Drive a large payload through the local port and assert byte-exact echo.
    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(local_addr).await.unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    sock.read_to_end(&mut echoed).await.unwrap();

    assert_eq!(echoed.len(), payload.len(), "echoed length mismatch");
    assert_eq!(echoed, payload, "echoed bytes mismatch");
}

#[tokio::test]
async fn rejects_mismatched_fingerprint() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let imposter = Identity::generate().unwrap();
    let timing = Timing::default();

    // Client pins the WRONG agent fingerprint -> handshake must fail.
    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    let client_cfg = crypto::client_config(&client_id, imposter.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let result = transport::connect(&client_ep, agent_addr).await;
    assert!(result.is_err(), "connection should fail on pin mismatch");
}

/// Reverse forwarding (`ssh -R`), inverted end-to-end: the agent binds a remote
/// listener, opens a stream back to the client for each connection, and the
/// client dials a local target. Proves agent->client `open_bi`, the client's
/// `accept_bi` loop, and bidirectional splice.
#[tokio::test]
async fn reverse_forwards_bytes_end_to_end() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    // The client-local target the reverse forward dials.
    let echo_addr = spawn_echo().await;

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn = transport::connect(&client_ep, agent_addr).await.unwrap();

    // Pick a free port for the agent's remote bind (then free it for the agent).
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let remote_port = probe.local_addr().unwrap().port();
    drop(probe);

    let (_slot_tx, slot_rx) = client::conn_slot(Some(Conn::Quic(conn)));
    let reverse = Arc::new(ReverseSet::new());
    reverse
        .add(
            ReverseSpec {
                ns: NsSpec::Host,
                remote_bind_addr: Ipv4Addr::LOCALHOST.into(),
                remote_bind_port: remote_port,
                local_host: echo_addr.ip().to_string(),
                local_port: echo_addr.port(),
            },
            Origin::UserAdded,
        )
        .await
        .unwrap();
    tokio::spawn(reverse::watch(slot_rx, reverse.clone()));

    // Wait for the agent's remote listener to come up, then drive a payload
    // through it and assert byte-exact echo back from the client-local target.
    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let echoed = loop {
        if let Ok(mut sock) = TcpStream::connect((Ipv4Addr::LOCALHOST, remote_port)).await {
            sock.write_all(&payload).await.unwrap();
            sock.shutdown().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            if buf.len() == payload.len() {
                break buf;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("reverse listener never carried the payload");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(echoed, payload, "reverse-echoed bytes mismatch");
}

/// Reverse forwarding re-registers across a reconnect: after the connection
/// drops and a fresh one lands in the slot, the agent re-binds the remote
/// listener and traffic flows again.
#[tokio::test]
async fn reverse_re_registers_after_reconnect() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    let echo_addr = spawn_echo().await;

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn1 = transport::connect(&client_ep, agent_addr).await.unwrap();

    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let remote_port = probe.local_addr().unwrap().port();
    drop(probe);

    let (slot_tx, slot_rx) = client::conn_slot(Some(Conn::Quic(conn1.clone())));
    let reverse = Arc::new(ReverseSet::new());
    reverse
        .add(
            ReverseSpec {
                ns: NsSpec::Host,
                remote_bind_addr: Ipv4Addr::LOCALHOST.into(),
                remote_bind_port: remote_port,
                local_host: echo_addr.ip().to_string(),
                local_port: echo_addr.port(),
            },
            Origin::UserAdded,
        )
        .await
        .unwrap();
    tokio::spawn(reverse::watch(slot_rx, reverse.clone()));

    // Helper: connect to the remote bind and round-trip a small payload, retrying
    // until the listener is up (or a deadline passes).
    async fn roundtrip(port: u16) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(mut sock) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
                && sock.write_all(b"reverse-rt").await.is_ok()
            {
                let _ = sock.shutdown().await;
                let mut buf = Vec::new();
                if sock.read_to_end(&mut buf).await.is_ok() && buf == b"reverse-rt" {
                    return true;
                }
            }
            if tokio::time::Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    assert!(roundtrip(remote_port).await, "traffic before outage");

    // Simulate an outage: kill the connection, empty the slot, then restore.
    conn1.close(quinn::VarInt::from_u32(0), b"simulated outage");
    slot_tx.send_replace(None);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let conn2 = transport::connect(&client_ep, agent_addr).await.unwrap();
    slot_tx.send_replace(Some(Conn::Quic(conn2)));

    assert!(
        roundtrip(remote_port).await,
        "reverse forward must re-bind and carry traffic after reconnect"
    );
}

/// The plan's core resilience invariant: the local listener stays bound across
/// a connection loss, and traffic flows again once a new connection lands in
/// the slot — without rebinding anything.
#[tokio::test]
async fn listener_survives_reconnect() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    let echo_addr = spawn_echo().await;

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn1 = transport::connect(&client_ep, agent_addr).await.unwrap();

    let (slot_tx, slot_rx) = client::conn_slot(Some(portmanager::conn::Conn::Quic(conn1.clone())));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
        ns_inherited: false,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
        local_port_auto: false,
        kind: Default::default(),
    };
    let (local_addr, _task) = client::bind_forward(slot_rx, forward, client::new_health_handle())
        .await
        .unwrap();

    // Round-trip once on the first connection.
    let mut s1 = TcpStream::connect(local_addr).await.unwrap();
    s1.write_all(b"before-outage").await.unwrap();
    let mut buf = [0u8; 13];
    s1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before-outage");
    drop(s1);

    // Simulate a hard outage: kill the connection, empty the slot.
    conn1.close(quinn::VarInt::from_u32(0), b"simulated outage");
    slot_tx.send_replace(None);

    // New TCP connections during the outage wait for re-attach (within the
    // deadline). Start one now, then restore the session.
    let pending = tokio::spawn(async move {
        let mut s = TcpStream::connect(local_addr).await.unwrap();
        s.write_all(b"after-outage!").await.unwrap();
        let mut buf = [0u8; 13];
        s.read_exact(&mut buf).await.unwrap();
        buf
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let conn2 = transport::connect(&client_ep, agent_addr).await.unwrap();
    slot_tx.send_replace(Some(portmanager::conn::Conn::Quic(conn2)));

    let buf = pending.await.unwrap();
    assert_eq!(&buf, b"after-outage!", "traffic must flow after re-attach");
}
