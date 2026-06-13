//! Remote agent: accept QUIC connections, read each stream's target, dial it,
//! and splice. Runs on the remote host (launched over SSH in the full flow).
//!
//! ## Lifecycle (mosh-style)
//!
//! [`run`] performs the bootstrap handshake on the SSH session's stdio and then
//! **daemonizes** (fork + setsid, stdio detached), so the agent survives the SSH
//! session — and therefore network loss and client sleep. The QUIC socket is
//! bound *before* the fork so the reported port is authoritative.
//!
//! The session is held while any client connection is live, and for a **grace
//! window** after the last one drops (so a roaming/sleeping client re-attaches
//! to the same session). The agent self-terminates when:
//! - the grace window expires with no client attached, or
//! - a client closes its connection with [`CLOSE_SHUTDOWN`] (explicit Ctrl-C).
//!
//! Namespace dialing (`netns.rs`) is layered on later; for now a non-empty
//! namespace selector is rejected with a clear error.

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream, VarInt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::crypto::{self, Identity};
use crate::error;
use crate::forward::NsSpec;
use crate::handshake::{Hello, Ready, SessionId};
use crate::netns::HelperPool;
use crate::proto::{self, StreamHeader};

/// Application close code meaning "shut the session down now" (client Ctrl-C).
pub const CLOSE_SHUTDOWN: u32 = 0x10;

/// Agent entry point (the `agent` subcommand, launched over SSH).
///
/// Sync on purpose: the handshake and daemonization happen before any tokio
/// runtime exists, so the fork is single-threaded and safe.
pub fn run(listen: &str, grace: Duration, foreground: bool) -> Result<()> {
    // 1. Handshake on the SSH session's stdio.
    let hello = read_hello_stdin()?;
    let identity = Identity::generate()?;
    let session_id = SessionId::random()?;

    // 2. Bind the QUIC UDP socket pre-fork so the reported port is final.
    let bind: SocketAddr = listen.parse().context("parsing --listen address")?;
    let socket = std::net::UdpSocket::bind(bind).context("binding agent UDP socket")?;
    let local = socket.local_addr().context("reading bound UDP address")?;

    let ready = Ready {
        udp_port: local.port(),
        agent_fp: identity.fingerprint,
        session_id,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(ready.to_line().as_bytes())
            .and_then(|_| stdout.flush())
            .context("writing ready handshake to stdout")?;
    }

    // 3. Detach from the SSH session so we survive its death (mosh-server style).
    if !foreground {
        daemonize()?;
    }

    // Record this agent (pid/port/version/clients) so a future client can detect
    // a stale version and evict it only when idle — see bootstrap::reap_stale_agents.
    let state_path = if foreground {
        None
    } else {
        write_agent_state(local.port())
    };
    // serve_with_grace updates the live client count in this file; it needs its
    // own copy since the path is also used for cleanup after the runtime exits.
    let state_path_for_serve = state_path.clone();

    // 4. Now start the runtime and serve.
    let server_cfg = crypto::server_config(&identity, hello.client_fp, &crypto::Timing::default())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(async move {
        socket
            .set_nonblocking(true)
            .context("setting UDP socket non-blocking")?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_cfg),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .context("building QUIC endpoint")?;
        serve_with_grace(endpoint, grace, state_path_for_serve).await
    });

    // Clean up the state file on a graceful exit (best-effort).
    if let Some(path) = state_path {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Directory holding per-agent state files (`<udp_port>.json`).
pub fn agent_state_dir() -> Option<std::path::PathBuf> {
    directories::BaseDirs::new().map(|d| d.cache_dir().join("portmanager/agents"))
}

/// Persist this agent's identity for a future client's staleness check.
/// Best-effort: returns the written path, or `None` if it could not be written.
fn write_agent_state(udp_port: u16) -> Option<std::path::PathBuf> {
    let dir = agent_state_dir()?;
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{udp_port}.json"));
    write_agent_state_at(&path, udp_port, 0);
    Some(path)
}

/// (Re)write the agent state file with the current live client count. The
/// reaper uses `clients` to avoid evicting an agent that is actively serving.
fn write_agent_state_at(path: &std::path::Path, udp_port: u16, clients: usize) {
    let body = format!(
        r#"{{"pid":{},"udp_port":{},"version":"{}","clients":{}}}"#,
        std::process::id(),
        udp_port,
        env!("CARGO_PKG_VERSION"),
        clients,
    );
    let _ = std::fs::write(path, body);
}

/// Read the HELLO line from real (blocking) stdin.
fn read_hello_stdin() -> Result<Hello> {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        let line = match lines.next() {
            Some(l) => l.context("reading handshake from stdin")?,
            None => anyhow::bail!("stdin closed before HELLO"),
        };
        if line.trim().is_empty() {
            continue;
        }
        return Hello::parse_line(&line);
    }
}

/// Fork + setsid + detach stdio, so the process survives the SSH session.
/// stderr is redirected to a log file under `~/.cache/portmanager/`.
#[cfg(unix)]
fn daemonize() -> Result<()> {
    use nix::unistd::{ForkResult, fork, setsid};

    // SAFETY: no tokio runtime or extra threads exist yet (run() is sync and
    // this is called before the runtime is built).
    match unsafe { fork() }.context("fork for daemonize")? {
        ForkResult::Parent { .. } => {
            // Parent exits; the SSH session sees stdout EOF and terminates.
            std::process::exit(0);
        }
        ForkResult::Child => {}
    }
    setsid().context("setsid")?;

    // Detach stdio. stderr goes to a log file for post-mortem debugging.
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("opening /dev/null")?;
    let log_dir = directories::BaseDirs::new()
        .map(|d| d.cache_dir().join("portmanager"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    let _ = std::fs::create_dir_all(&log_dir);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("agent.log"))
        .ok();

    nix::unistd::dup2_stdin(&devnull).context("detaching stdin")?;
    nix::unistd::dup2_stdout(&devnull).context("detaching stdout")?;
    // Redirect stderr to the log file when available, else to /dev/null —
    // best-effort, never panic post-fork.
    match &log {
        Some(l) => nix::unistd::dup2_stderr(l).context("redirecting stderr to log")?,
        None => nix::unistd::dup2_stderr(&devnull).context("detaching stderr")?,
    }
    Ok(())
}

#[cfg(not(unix))]
fn daemonize() -> Result<()> {
    anyhow::bail!("agent daemonization is only supported on Unix-like remote hosts")
}

/// Accept connections, tracking how many are live; exit when the grace window
/// elapses with none attached (covers both "client gone" and "never connected"),
/// or immediately on an explicit shutdown close.
pub async fn serve_with_grace(
    endpoint: Endpoint,
    grace: Duration,
    state_path: Option<std::path::PathBuf>,
) -> Result<()> {
    info!(addr = ?endpoint.local_addr().ok(), grace_secs = grace.as_secs(), "agent listening");

    // (active connection count, explicit-shutdown flag)
    let (state_tx, mut state_rx) = watch::channel((0usize, false));
    // Namespace connect-helpers live as long as the session (reused across
    // client reconnects, torn down when the agent exits).
    let pool = Arc::new(HelperPool::new());

    // Mirror the live client count into the state file so a future bootstrap's
    // reaper only evicts this agent when it is idle (clients == 0).
    if let Some(path) = state_path {
        let udp_port = endpoint.local_addr().map(|a| a.port()).unwrap_or(0);
        let mut rx = state_rx.clone();
        tokio::spawn(async move {
            loop {
                let clients = rx.borrow_and_update().0;
                write_agent_state_at(&path, udp_port, clients);
                if rx.changed().await.is_err() {
                    break;
                }
            }
        });
    }

    let accept_endpoint = endpoint.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let state_tx = state_tx.clone();
            let pool = pool.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        state_tx.send_modify(|(n, _)| *n += 1);
                        let shutdown = handle_connection(conn, pool).await;
                        state_tx.send_modify(|(n, s)| {
                            *n -= 1;
                            *s |= shutdown;
                        });
                    }
                    Err(e) => warn!(error = %e, "handshake failed"),
                }
            });
        }
    });

    // Grace supervisor: wait out periods with zero connections.
    loop {
        let (count, shutdown) = *state_rx.borrow_and_update();
        if shutdown {
            info!("client requested shutdown");
            break;
        }
        if count == 0 {
            // No clients: give them `grace` to (re-)attach.
            let deadline = tokio::time::sleep(grace);
            tokio::pin!(deadline);
            let expired = loop {
                tokio::select! {
                    _ = &mut deadline => break true,
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            break true;
                        }
                        let (n, s) = *state_rx.borrow_and_update();
                        if s || n > 0 {
                            break false;
                        }
                        // still zero connections; keep waiting out the grace window
                    }
                }
            };
            let (_, s) = *state_rx.borrow();
            if s {
                info!("client requested shutdown");
                break;
            }
            if expired {
                info!(
                    grace_secs = grace.as_secs(),
                    "grace window expired with no client"
                );
                break;
            }
        } else if state_rx.changed().await.is_err() {
            break;
        }
    }

    accept.abort();
    endpoint.close(VarInt::from_u32(0), b"agent exiting");
    Ok(())
}

/// Serve all bidi streams on one authenticated connection.
/// Returns `true` if the client requested an explicit session shutdown.
async fn handle_connection(conn: Connection, pool: Arc<HelperPool>) -> bool {
    let peer = conn.remote_address();
    info!(%peer, "client connected");
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(ConnectionError::ApplicationClosed(close))
                if close.error_code == VarInt::from_u32(CLOSE_SHUTDOWN) =>
            {
                info!(%peer, "shutdown close received");
                return true;
            }
            Err(e) => {
                debug!(%peer, error = %e, "connection ended");
                return false;
            }
        };
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, pool).await {
                let error = error::format_chain(&e);
                warn!(%error, "stream failed");
            }
        });
    }
}

/// Read the header, dial the target (in-namespace when requested), and splice.
async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    pool: Arc<HelperPool>,
) -> Result<()> {
    let header = StreamHeader::read(&mut recv)
        .await
        .context("reading stream header")?;

    // Dedicated discovery stream (port scanner push channel).
    if header.host == crate::discovery::DISCOVERY_HOST {
        return crate::discovery::serve(send, recv).await;
    }

    let target = format!("{}:{}", header.host, header.port);
    let tcp = if header.ns.is_empty() {
        debug!(%target, "dialing target");
        match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                let _ = send.reset(VarInt::from_u32(2));
                return Err(e).context(format!("connecting to {target}"));
            }
        }
    } else {
        let ns = match NsSpec::from_wire(&header.ns) {
            Ok(ns) => ns,
            Err(e) => {
                let _ = send.reset(VarInt::from_u32(1));
                anyhow::bail!("bad namespace selector {:?}: {e}", header.ns);
            }
        };
        debug!(%target, ns = %header.ns, "dialing target in namespace");
        match pool.connect(&ns, &header.host, header.port).await {
            Ok(s) => s,
            Err(e) => {
                let _ = send.reset(VarInt::from_u32(1));
                return Err(e).context(format!("connecting to {target} in {}", header.ns));
            }
        }
    };

    proto::splice(tcp, send, recv).await.context("splicing")?;
    Ok(())
}
