//! Spawn the real `portmanager agent` binary, drive the handshake over its
//! stdin/stdout pipes (as the SSH bootstrap would), then forward through it.
//! Covers `agent::run` + handshake codec + QUIC forwarding + lifecycle
//! (grace-window expiry, explicit shutdown) without needing SSH.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use portmanager::agent::CLOSE_SHUTDOWN;
use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec};
use portmanager::handshake::{Hello, Ready, Token};
use portmanager::{client, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

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

/// Launch the agent binary in foreground mode and complete the handshake.
async fn launch_agent(client_id: &Identity, grace_secs: u64) -> (Child, Ready) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_portmanager"))
        .args([
            "agent",
            "--listen",
            "127.0.0.1:0",
            "--foreground",
            "--grace-secs",
            &grace_secs.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    Hello {
        client_fp: client_id.fingerprint,
        token: Token::random().unwrap(),
    }
    .write(&mut stdin)
    .await
    .unwrap();

    let ready = Ready::read(&mut reader).await.unwrap();
    (child, ready)
}

#[tokio::test]
async fn agent_binary_bootstraps_and_forwards() {
    crypto::init();

    let echo_addr = spawn_echo().await;
    let client_id = Identity::generate().unwrap();
    let (mut child, ready) = launch_agent(&client_id, 600).await;

    let client_cfg = crypto::client_config(&client_id, ready.agent_fp, &Timing::default()).unwrap();
    let endpoint = transport::client_endpoint(client_cfg).unwrap();
    let agent_addr: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();
    let conn = transport::connect(&endpoint, agent_addr).await.unwrap();

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

    let payload = b"the quick brown fox jumps over the lazy dog".repeat(2000);
    let mut sock = TcpStream::connect(local_addr).await.unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    sock.read_to_end(&mut echoed).await.unwrap();

    assert_eq!(
        echoed, payload,
        "payload not echoed byte-exact through agent"
    );

    child.kill().await.unwrap();
}

/// Re-attach: after a client connection dies, a NEW QUIC connection to the same
/// agent (same port, same pinned identity) must be accepted — that's tier-2
/// recovery riding the agent's grace window.
#[tokio::test]
async fn agent_accepts_reattach_within_grace() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let (mut child, ready) = launch_agent(&client_id, 600).await;

    let client_cfg = crypto::client_config(&client_id, ready.agent_fp, &Timing::default()).unwrap();
    let endpoint = transport::client_endpoint(client_cfg).unwrap();
    let agent_addr: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();

    // First connection: drop it ungracefully (simulated network loss).
    let conn1 = transport::connect(&endpoint, agent_addr).await.unwrap();
    conn1.close(quinn::VarInt::from_u32(0), b"network died");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second connection must succeed — the agent held the session.
    let conn2 = transport::connect(&endpoint, agent_addr).await;
    assert!(conn2.is_ok(), "re-attach within grace must succeed");

    child.kill().await.unwrap();
}

/// Grace expiry: with a short grace and no client, the agent exits on its own
/// (orphan cleanup).
#[tokio::test]
async fn agent_exits_after_grace_expiry() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let (mut child, _ready) = launch_agent(&client_id, 1).await;

    // Never connect. The agent should exit within the 1s grace (+ margin).
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("agent did not exit after grace expiry")
        .unwrap();
    assert!(status.success(), "agent should exit cleanly: {status:?}");
}

/// Explicit shutdown: closing with CLOSE_SHUTDOWN makes the agent exit
/// immediately, without waiting out the grace window.
#[tokio::test]
async fn agent_exits_on_shutdown_close() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    // Long grace: exit must come from the shutdown code, not expiry.
    let (mut child, ready) = launch_agent(&client_id, 600).await;

    let client_cfg = crypto::client_config(&client_id, ready.agent_fp, &Timing::default()).unwrap();
    let endpoint = transport::client_endpoint(client_cfg).unwrap();
    let agent_addr: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();
    let conn = transport::connect(&endpoint, agent_addr).await.unwrap();

    conn.close(quinn::VarInt::from_u32(CLOSE_SHUTDOWN), b"shutdown");

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("agent did not exit on shutdown close")
        .unwrap();
    assert!(status.success(), "agent should exit cleanly: {status:?}");
}
