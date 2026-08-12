//! Loopback throughput benchmark for the splice path.
//!
//! Runs an in-process agent and client over real QUIC on localhost, so the
//! network is not the bottleneck and per-chunk splice overhead is visible.
//! Ignored by default (it is a measurement, not an assertion); run with:
//!
//! ```console
//! $ cargo test --release --test throughput -- --ignored --nocapture
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec};
use portmanager::{agent, client, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_GRACE: Duration = Duration::from_secs(600);
/// Payload per run. Large enough to amortise connection setup.
const BYTES: usize = 64 * 1024 * 1024;
const RUNS: usize = 5;

/// A server that writes `BYTES` to any connection then closes — the "download"
/// direction, where the agent is the QUIC sender.
async fn spawn_source() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let chunk = vec![0u8; 256 * 1024];
                let mut sent = 0;
                while sent < BYTES {
                    let n = chunk.len().min(BYTES - sent);
                    if sock.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    sent += n;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run explicitly with --ignored"]
async fn loopback_download_throughput() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let agent_addr = spawn_agent(&agent_id, client_id.fingerprint, &timing);
    let source_addr = spawn_source().await;

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn = transport::connect(&client_ep, agent_addr).await.unwrap();

    let (_slot_tx, slot_rx) = client::conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    let forward = ForwardSpec {
        ns: NsSpec::Host,
        remote_host: source_addr.ip().to_string(),
        remote_port: source_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
        local_port_auto: false,
        kind: Default::default(),
    };
    let (local_addr, _task) = client::bind_forward(slot_rx, forward, client::new_health_handle())
        .await
        .unwrap();

    let mut rates = Vec::new();
    for run in 1..=RUNS {
        let mut sock = TcpStream::connect(local_addr).await.unwrap();
        let mut buf = vec![0u8; 1 << 20];
        let mut got = 0usize;
        let start = Instant::now();
        loop {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        let secs = start.elapsed().as_secs_f64();
        let rate = (got as f64 / (1024.0 * 1024.0)) / secs;
        println!("run {run}: {got} bytes in {secs:.2}s = {rate:.1} MiB/s");
        rates.push(rate);
        assert_eq!(got, BYTES, "short transfer");
    }

    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "\nmedian {:.1} MiB/s  (min {:.1}, max {:.1})",
        rates[rates.len() / 2],
        rates[0],
        rates[rates.len() - 1]
    );
}
