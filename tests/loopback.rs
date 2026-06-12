//! End-to-end loopback tests: agent + client in-process over real QUIC on
//! localhost (no SSH).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec};
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
    tokio::spawn(agent::serve_with_grace(ep, TEST_GRACE));
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

    let (_slot_tx, slot_rx) = client::conn_slot(Some(conn));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
        local_port_auto: false,
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

    let (slot_tx, slot_rx) = client::conn_slot(Some(conn1.clone()));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
        local_port_auto: false,
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
    slot_tx.send_replace(Some(conn2));

    let buf = pending.await.unwrap();
    assert_eq!(&buf, b"after-outage!", "traffic must flow after re-attach");
}
