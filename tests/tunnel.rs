//! Drive the agent's SSH-tunnel transport (`--via-ssh`) without SSH. The data
//! plane's `ssh -L` hop is a transparent TCP relay, so the test connects the
//! client [`SshConn`] straight to the agent's loopback listener — exercising the
//! token gate, the opcode framing, the stream header, and the splice end to end.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use portmanager::conn::{Conn, OP_STREAM, SshConn};
use portmanager::crypto::{self, Identity};
use portmanager::forward::{ForwardSpec, NsSpec};
use portmanager::handshake::{Hello, Ready, Token};
use portmanager::client;
use portmanager::proto::StreamHeader;
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

/// Launch the agent binary in foreground tunnel mode and complete the
/// handshake, returning the (kept) session token so we can authorize the
/// data-plane connection ourselves.
async fn launch_tunnel_agent(client_id: &Identity, grace_secs: u64) -> (Child, Ready, Token) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_portmanager"))
        .args([
            "agent",
            "--listen",
            "127.0.0.1:0",
            "--foreground",
            "--tunnel",
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

    let token = Token::random().unwrap();
    Hello {
        client_fp: client_id.fingerprint,
        token: token.clone(),
    }
    .write(&mut stdin)
    .await
    .unwrap();

    let ready = Ready::read(&mut reader).await.unwrap();
    (child, ready, token)
}

#[tokio::test]
async fn tunnel_forwards_bytes_end_to_end() {
    crypto::init();

    let echo_addr = spawn_echo().await;
    let client_id = Identity::generate().unwrap();
    let (mut child, ready, token) = launch_tunnel_agent(&client_id, 600).await;

    // The `ssh -L` hop is a transparent relay; connect straight to the agent's
    // loopback listener instead.
    let agent_local: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();
    let conn = SshConn::connect(agent_local, token).await.unwrap();

    let (_slot_tx, slot_rx) = client::conn_slot(Some(Conn::Ssh(conn)));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
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

    let payload = b"the quick brown fox jumps over the lazy dog".repeat(2000);
    let mut sock = TcpStream::connect(local_addr).await.unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    sock.read_to_end(&mut echoed).await.unwrap();

    assert_eq!(echoed.len(), payload.len(), "echoed length mismatch");
    assert_eq!(echoed, payload, "echoed bytes mismatch");

    let _ = child.start_kill();
}

#[tokio::test]
async fn tunnel_shutdown_exits_agent() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let (mut child, ready, token) = launch_tunnel_agent(&client_id, 600).await;
    let agent_local: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();

    // A live session (the keepalive connection holds the agent open past grace).
    let conn = SshConn::connect(agent_local, token).await.unwrap();

    // Shutdown must make the agent exit now, not wait out its (600s) grace.
    conn.send_shutdown().await;
    let exited = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    assert!(
        exited.is_ok(),
        "agent did not exit promptly after OP_SHUTDOWN"
    );
}

#[tokio::test]
async fn tunnel_rejects_bad_token() {
    crypto::init();

    let echo_addr = spawn_echo().await;
    let client_id = Identity::generate().unwrap();
    let (mut child, ready, _token) = launch_tunnel_agent(&client_id, 600).await;
    let agent_local: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();

    // Present a wrong token, then try to drive a real stream. The agent must
    // drop the connection at the gate, so the stream read sees EOF.
    let mut tcp = TcpStream::connect(agent_local).await.unwrap();
    let wrong = Token::random().unwrap();
    tcp.write_all(wrong.as_bytes()).await.unwrap();
    tcp.write_u8(OP_STREAM).await.unwrap();
    StreamHeader {
        ns: String::new(),
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    }
    .write(&mut tcp)
    .await
    .unwrap();
    tcp.write_all(b"should never reach the echo").await.unwrap();

    // The gate dropped us: no echo comes back, the read ends at EOF.
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf).await;
    assert!(buf.is_empty(), "rejected connection must not be serviced");

    let _ = child.start_kill();
}
