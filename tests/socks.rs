//! SOCKS5 dynamic-proxy integration: a live in-process session (agent + client
//! over loopback QUIC) serving a `socks` forward. A real SOCKS5 CONNECT is
//! driven through the local listener to an echo server the agent dials, proving
//! the whole path: negotiation -> QUIC stream -> agent dial -> splice.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use portmanager::client::{ForwardSet, Origin, conn_slot};
use portmanager::crypto::{self, Identity, Timing};
use portmanager::{agent, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_GRACE: Duration = Duration::from_secs(600);

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

/// In-process agent + connected client; returns the live QUIC connection.
async fn session() -> quinn::Connection {
    crypto::init();
    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let server_cfg = crypto::server_config(&agent_id, client_id.fingerprint, &timing).unwrap();
    let ep = transport::server_endpoint(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = ep.local_addr().unwrap();
    tokio::spawn(agent::serve_with_grace(ep, TEST_GRACE, None));

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    transport::connect(&client_ep, addr).await.unwrap()
}

/// Pick a currently-free loopback TCP port (binds then drops).
async fn free_port() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    l.local_addr().unwrap().port()
}

/// Drive the client half of a SOCKS5 no-auth CONNECT to `target`, returning the
/// negotiated stream ready for payload.
async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    // Greeting: SOCKS5, one method, no-auth.
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00], "server must select no-auth");

    // CONNECT to an IPv4 target.
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!("test target is IPv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS reply should be success");
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn socks_proxy_connects_through_agent() {
    let conn = session().await;
    let echo = spawn_echo().await;

    let (_slot_tx, slot_rx) = conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    let forwards = Arc::new(ForwardSet::new(slot_rx));

    // Bind a SOCKS proxy on a known-free loopback port.
    let port = free_port().await;
    let spec = format!("socks->{port}").parse().unwrap();
    let local = forwards.add(spec, Origin::UserAdded).await.unwrap();
    assert_eq!(local.port(), port);

    // A SOCKS5 CONNECT to the echo server round-trips through the agent.
    let mut sock = socks_connect(local, echo).await;
    sock.write_all(b"socks-payload").await.unwrap();
    let mut buf = [0u8; 13];
    sock.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks-payload");

    // A second connection to a *different* target reuses the same proxy.
    let echo2 = spawn_echo().await;
    let mut sock2 = socks_connect(local, echo2).await;
    sock2.write_all(b"again").await.unwrap();
    let mut buf2 = [0u8; 5];
    sock2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"again");
}
