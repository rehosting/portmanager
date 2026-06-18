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
use quinn::{Connection, ConnectionError, Endpoint, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::conn::{OP_KEEPALIVE, OP_SHUTDOWN, OP_STREAM};
use crate::crypto::{self, Identity};
use crate::error;
use crate::forward::NsSpec;
use crate::handshake::{Hello, Ready, SessionId, Token};
use crate::netns::HelperPool;
use crate::proto::{self, StreamHeader};

/// Application close code meaning "shut the session down now" (client Ctrl-C).
pub const CLOSE_SHUTDOWN: u32 = 0x10;

/// Agent entry point (the `agent` subcommand, launched over SSH).
///
/// Sync on purpose: the handshake and daemonization happen before any tokio
/// runtime exists, so the fork is single-threaded and safe.
pub fn run(listen: &str, grace: Duration, foreground: bool, tunnel: bool) -> Result<()> {
    // 1. Handshake on the SSH session's stdio.
    let hello = read_hello_stdin()?;
    let identity = Identity::generate()?;
    let session_id = SessionId::random()?;

    // SSH-tunnel transport: serve over a loopback TCP listener instead of QUIC
    // (the data plane rides `ssh -L`; SSH is the trust anchor, no TLS here).
    if tunnel {
        return run_tunnel(listen, grace, foreground, identity, session_id, hello.token);
    }

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
    let (state_tx, state_rx) = watch::channel((0usize, false));
    // Namespace connect-helpers live as long as the session (reused across
    // client reconnects, torn down when the agent exits).
    let pool = Arc::new(HelperPool::new());
    let port = endpoint.local_addr().map(|a| a.port()).unwrap_or(0);

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

    grace_loop(state_rx, grace, state_path, port).await;

    accept.abort();
    endpoint.close(VarInt::from_u32(0), b"agent exiting");
    Ok(())
}

/// Shared grace supervisor: mirror the live client count into the state file and
/// wait out periods with zero connections; return on explicit shutdown or once
/// the grace window elapses with no client attached. Transport-agnostic — both
/// the QUIC and SSH-tunnel serve paths drive it via their own accept loops.
async fn grace_loop(
    mut state_rx: watch::Receiver<(usize, bool)>,
    grace: Duration,
    state_path: Option<std::path::PathBuf>,
    port: u16,
) {
    // Mirror the live client count into the state file so a future bootstrap's
    // reaper only evicts this agent when it is idle (clients == 0).
    if let Some(path) = state_path {
        let mut rx = state_rx.clone();
        tokio::spawn(async move {
            loop {
                let clients = rx.borrow_and_update().0;
                write_agent_state_at(&path, port, clients);
                if rx.changed().await.is_err() {
                    break;
                }
            }
        });
    }

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
}

/// SSH-tunnel serve path: bind a loopback TCP listener (the `ssh -L` target),
/// report its port, daemonize, and serve token-gated connections. No TLS — SSH
/// is the trust anchor; the session token authorizes each connection.
fn run_tunnel(
    listen: &str,
    grace: Duration,
    foreground: bool,
    identity: Identity,
    session_id: SessionId,
    token: Token,
) -> Result<()> {
    let bind: SocketAddr = listen.parse().context("parsing --listen address")?;
    let listener = std::net::TcpListener::bind(bind).context("binding agent TCP listener")?;
    let local = listener.local_addr().context("reading bound TCP address")?;

    let ready = Ready {
        udp_port: local.port(),         // the loopback TCP port the client forwards to
        agent_fp: identity.fingerprint, // unused in tunnel mode (no TLS)
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

    if !foreground {
        daemonize()?;
    }

    let state_path = if foreground {
        None
    } else {
        write_agent_state(local.port())
    };
    let state_path_for_serve = state_path.clone();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(async move {
        listener
            .set_nonblocking(true)
            .context("setting TCP listener non-blocking")?;
        let listener =
            tokio::net::TcpListener::from_std(listener).context("adopting TCP listener")?;
        serve_tunnel_with_grace(listener, grace, state_path_for_serve, token).await
    });

    if let Some(path) = state_path {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Accept token-gated tunnel connections, tracking live clients for the grace
/// window exactly like the QUIC path.
async fn serve_tunnel_with_grace(
    listener: tokio::net::TcpListener,
    grace: Duration,
    state_path: Option<std::path::PathBuf>,
    token: Token,
) -> Result<()> {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    info!(addr = ?listener.local_addr().ok(), grace_secs = grace.as_secs(), "agent listening (ssh tunnel)");

    let (state_tx, state_rx) = watch::channel((0usize, false));
    let pool = Arc::new(HelperPool::new());
    let token = Arc::new(token);

    let accept = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, _peer)) => {
                    tokio::spawn(handle_tunnel_conn(
                        tcp,
                        token.clone(),
                        pool.clone(),
                        state_tx.clone(),
                    ));
                }
                Err(e) => {
                    warn!(error = %e, "tunnel accept failed");
                    break;
                }
            }
        }
    });

    grace_loop(state_rx, grace, state_path, port).await;
    accept.abort();
    Ok(())
}

/// One tunnel connection: verify the token, read the opcode, and dispatch.
async fn handle_tunnel_conn(
    mut tcp: TcpStream,
    token: Arc<Token>,
    pool: Arc<HelperPool>,
    state_tx: watch::Sender<(usize, bool)>,
) {
    let mut received = [0u8; 32];
    if tcp.read_exact(&mut received).await.is_err() {
        return;
    }
    if !Token::from_bytes(received).ct_eq(&token) {
        warn!(peer = ?tcp.peer_addr().ok(), "tunnel connection failed token check");
        return;
    }
    let opcode = match tcp.read_u8().await {
        Ok(b) => b,
        Err(_) => return,
    };

    match opcode {
        OP_KEEPALIVE => {
            // The persistent liveness connection: count it as a client and hold
            // it open until it closes (carries no payload).
            state_tx.send_modify(|(n, _)| *n += 1);
            let mut buf = [0u8; 64];
            loop {
                match tcp.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            state_tx.send_modify(|(n, _)| *n -= 1);
        }
        OP_SHUTDOWN => {
            info!("client requested shutdown (tunnel)");
            state_tx.send_modify(|(_, s)| *s = true);
        }
        OP_STREAM => {
            state_tx.send_modify(|(n, _)| *n += 1);
            let (read, write) = tcp.into_split();
            // No QUIC connection to open streams back on: reverse forwarding is
            // unsupported over the SSH tunnel (handle_stream rejects @reverse).
            if let Err(e) = handle_stream(write, read, pool, None).await {
                let error = error::format_chain(&e);
                warn!(%error, "tunnel stream failed");
            }
            state_tx.send_modify(|(n, _)| *n -= 1);
        }
        other => debug!(opcode = other, "unknown tunnel opcode"),
    }
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
        // Clone the connection so a reverse-registration stream can open data
        // streams back to the client.
        let back = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, pool, Some(back)).await {
                let error = error::format_chain(&e);
                warn!(%error, "stream failed");
            }
        });
    }
}

/// Read the header, dial the target (in-namespace when requested), and splice.
/// Generic over the transport's stream halves (QUIC streams or a tunnel TCP
/// connection's halves).
async fn handle_stream<W, R>(
    send: W,
    mut recv: R,
    pool: Arc<HelperPool>,
    back: Option<Connection>,
) -> Result<()>
where
    W: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let header = StreamHeader::read(&mut recv)
        .await
        .context("reading stream header")?;

    // Dedicated discovery stream (port scanner push channel).
    if header.host == crate::discovery::DISCOVERY_HOST {
        return crate::discovery::serve(send, recv).await;
    }

    // Dedicated reverse-forwarding registration stream (the agent binds remote
    // listeners and opens data streams back on `back`).
    if header.host == crate::reverse::REVERSE_HOST {
        return crate::reverse::serve_registration(send, recv, back).await;
    }

    let target = format!("{}:{}", header.host, header.port);
    let tcp = if header.ns.is_empty() {
        debug!(%target, "dialing target");
        TcpStream::connect(&target)
            .await
            .with_context(|| format!("connecting to {target}"))?
    } else {
        let ns = NsSpec::from_wire(&header.ns)
            .map_err(|e| anyhow::anyhow!("bad namespace selector {:?}: {e}", header.ns))?;
        debug!(%target, ns = %header.ns, "dialing target in namespace");
        pool.connect(&ns, &header.host, header.port)
            .await
            .with_context(|| format!("connecting to {target} in {}", header.ns))?
    };

    // The agent doesn't surface per-forward throughput (that's a client-side
    // concern), so it counts into throwaway tallies.
    use std::sync::atomic::AtomicU64;
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    proto::splice(tcp, send, recv, up, down)
        .await
        .context("splicing")?;
    Ok(())
}
