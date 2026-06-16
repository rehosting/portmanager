//! Never-give-up session supervisor: the mosh-feel layer.
//!
//! Owns the logical session (decoupled from any QUIC connection) and the
//! three-tier recovery ladder from the plan:
//!
//! 1. **Migration** — while the connection is alive, `netwatch` rebinds the
//!    endpoint on source-IP change; QUIC path validation migrates seamlessly.
//! 2. **Re-attach** — when the QUIC connection dies (sleep, long outage) but
//!    the agent's grace window is holding the session, dial the cached
//!    `host:udp_port` directly. No SSH involved; sub-second.
//! 3. **Re-bootstrap** — agent gone (grace expired, host rebooted): full SSH
//!    bootstrap again, then carry on with the same local listeners.
//!
//! The loop never abandons the session: capped exponential backoff with full
//! jitter, forever, exactly like mosh's `[network outage]` behavior. Local
//! listeners stay bound throughout (see `client.rs`).
//!
//! **Single client per session.** A supervisor owns exactly one logical session
//! and assumes it is the only client of its agent. On one machine the control
//! socket (`control.rs`) already refuses a second client for the same host. Two
//! independent launches bootstrap *separate* agent sessions (random token, own
//! UDP port), so they don't collide. Pointing two clients at one session (by
//! copying its secrets) is unsupported and undefined.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint, VarInt};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::agent::CLOSE_SHUTDOWN;
use crate::bootstrap::{self, AgentSession};
use crate::client::ConnSlot;
use crate::conn::{Conn, SshConn};
use crate::crypto::{self, Timing};
use crate::firewall::{self, AdvisePort};
use crate::handshake::Token;
use crate::tunnel::SshTunnel;
use crate::{client, netwatch, transport};

/// Per-attempt QUIC handshake timeout during recovery.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default remote UDP range, matching mosh's operational firewall convention.
const DEFAULT_UDP_PORT_START: u16 = 60000;
const DEFAULT_UDP_PORT_END: u16 = 61000;
/// Tier-2 attempts per cycle before escalating to a tier-3 re-bootstrap.
const REATTACH_ATTEMPTS_PER_CYCLE: u32 = 6;
/// Backoff parameters (full jitter, capped).
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Observable session state, for status output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connected,
    Reconnecting { attempt: u32 },
    Bootstrapping,
}

/// A running supervised session.
pub struct Supervisor {
    /// Slot the forwards watch for the current connection.
    pub slot: ConnSlot,
    /// Status feed for display.
    pub status: watch::Receiver<Status>,
    /// Current agent binary version (updates across re-bootstraps).
    pub agent_version: watch::Receiver<String>,
    shutdown_tx: watch::Sender<bool>,
    monitor: tokio::task::JoinHandle<()>,
}

impl Supervisor {
    /// Bootstrap `host` and start supervising. Returns once the first
    /// connection is up (so callers can bind forwards immediately).
    ///
    /// `verbose` is the client's `-v` count, threaded to the remote agent.
    pub async fn start(
        host: String,
        listen: Option<String>,
        verbose: u8,
        grace_secs: u64,
        via_ssh: bool,
    ) -> Result<Self> {
        if via_ssh {
            return Self::start_tunnel(host, verbose, grace_secs).await;
        }
        let timing = Timing::default();

        let (status_tx, status_rx) = watch::channel(Status::Bootstrapping);
        info!(%host, "bootstrapping agent over SSH");
        let session = bootstrap_agent(&host, listen.as_deref(), verbose, grace_secs).await?;
        let addr = resolve(&session.quic_target).await?;
        let (version_tx, version_rx) = watch::channel(session.agent_version.clone());

        // One endpoint for the whole session lifetime; per-connect configs
        // (the pinned agent fp changes across re-bootstraps).
        let client_cfg = crypto::client_config(&session.client_id, session.agent_fp, &timing)?;
        let endpoint = transport::client_endpoint_bare()?;

        let conn = match connect_once(&endpoint, client_cfg.clone(), addr).await {
            Ok(conn) => conn,
            Err(e) => {
                // Inbound UDP blocked is the most common cause. Attach a clear,
                // user-facing message laying out the options (open UDP /
                // --remote-udp / --via-ssh) to the *error* — not just a log line
                // — so it's visible in every mode, including a TUI launch that
                // aborts before the TUI (and its log pane) ever appears.
                let options = firewall::udp_failure_message(&host, advise_port(listen.as_deref())).await;
                return Err(e).context(options);
            }
        };
        info!(target = %session.quic_target, "connected to agent");
        status_tx.send_replace(Status::Connected);

        let (slot_tx, slot_rx) = client::conn_slot(Some(Conn::Quic(conn.clone())));
        let (target_tx, target_rx) = watch::channel(addr);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Tier-1: migration watcher.
        tokio::spawn(netwatch::run(endpoint.clone(), target_rx));

        let monitor = tokio::spawn(monitor_loop(MonitorCtx {
            host,
            listen,
            verbose,
            grace_secs,
            endpoint,
            timing,
            session,
            client_cfg,
            addr,
            conn,
            slot_tx,
            target_tx,
            status_tx,
            version_tx,
            shutdown_rx,
        }));

        Ok(Supervisor {
            slot: slot_rx,
            status: status_rx,
            agent_version: version_rx,
            shutdown_tx,
            monitor,
        })
    }

    /// SSH-tunnel variant of [`Supervisor::start`]: bootstrap a `--tunnel` agent,
    /// stand up the `ssh -L` forward, and connect over it. Used for hosts with no
    /// direct UDP path (reached only through a jump host).
    async fn start_tunnel(host: String, verbose: u8, grace_secs: u64) -> Result<Self> {
        let (status_tx, status_rx) = watch::channel(Status::Bootstrapping);
        info!(%host, "bootstrapping tunnel agent over SSH");
        let session = bootstrap::bootstrap_tunnel(&host, verbose, grace_secs).await?;
        let (version_tx, version_rx) = watch::channel(session.agent_version.clone());

        let tunnel = SshTunnel::spawn(&host, session.tcp_port)
            .await
            .context("setting up the ssh -L data tunnel")?;
        let conn = SshConn::connect(tunnel.local, session.token.clone())
            .await
            .context("connecting through the ssh -L tunnel")?;
        info!(port = session.tcp_port, "connected to agent over ssh tunnel");
        status_tx.send_replace(Status::Connected);

        let (slot_tx, slot_rx) = client::conn_slot(Some(Conn::Ssh(conn.clone())));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let monitor = tokio::spawn(monitor_loop_tunnel(TunnelCtx {
            host,
            verbose,
            grace_secs,
            tcp_port: session.tcp_port,
            token: session.token,
            tunnel,
            conn,
            slot_tx,
            status_tx,
            version_tx,
            shutdown_rx,
        }));

        Ok(Supervisor {
            slot: slot_rx,
            status: status_rx,
            agent_version: version_rx,
            shutdown_tx,
            monitor,
        })
    }

    /// Graceful shutdown: tell the agent to exit now (rather than waiting out
    /// its grace window) and stop supervising.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        // Give the monitor time to deliver the close — for the SSH tunnel this
        // includes waiting for the agent to ack the shutdown opcode (see
        // SshConn::send_shutdown), so the budget must exceed that ack timeout.
        let _ = tokio::time::timeout(Duration::from_secs(6), self.monitor).await;
    }
}

struct MonitorCtx {
    host: String,
    listen: Option<String>,
    verbose: u8,
    /// Grace window (seconds) handed to the agent on every (re-)bootstrap.
    grace_secs: u64,
    endpoint: Endpoint,
    timing: Timing,
    session: AgentSession,
    client_cfg: quinn::ClientConfig,
    addr: SocketAddr,
    conn: Connection,
    slot_tx: watch::Sender<Option<Conn>>,
    target_tx: watch::Sender<SocketAddr>,
    status_tx: watch::Sender<Status>,
    version_tx: watch::Sender<String>,
    shutdown_rx: watch::Receiver<bool>,
}

/// State for the SSH-tunnel monitor loop. The agent daemon persists across SSH
/// death (grace window), so recovery means re-standing the `ssh -L` forward and
/// reconnecting to the same agent; only after a cycle do we re-bootstrap.
struct TunnelCtx {
    host: String,
    verbose: u8,
    grace_secs: u64,
    /// Agent loopback port; updated on re-bootstrap.
    tcp_port: u16,
    /// Session token; updated on re-bootstrap.
    token: Token,
    /// Held to keep the forward alive; replaced (old one dropped/killed) on
    /// reconnect.
    tunnel: SshTunnel,
    conn: Arc<SshConn>,
    slot_tx: watch::Sender<Option<Conn>>,
    status_tx: watch::Sender<Status>,
    version_tx: watch::Sender<String>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Wait until the shutdown flag flips to true (drops the watch guard before
/// returning, so callers can await afterwards in a spawned task).
async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// The forever loop: watch the live connection, recover when it dies.
async fn monitor_loop(mut ctx: MonitorCtx) {
    loop {
        // Phase: connected. Wait for death or shutdown.
        let mut shutdown_rx = ctx.shutdown_rx.clone();
        let died = tokio::select! {
            reason = ctx.conn.closed() => Some(reason),
            _ = wait_shutdown(&mut shutdown_rx) => None,
        };
        match died {
            Some(reason) => warn!(%reason, "connection lost; recovering"),
            None => {
                info!("closing session");
                ctx.conn
                    .close(VarInt::from_u32(CLOSE_SHUTDOWN), b"shutdown");
                ctx.endpoint.wait_idle().await;
                return;
            }
        }

        ctx.slot_tx.send_replace(None);

        // Phase: recovery ladder. Never gives up.
        let mut attempt: u32 = 0;
        let conn = 'recover: loop {
            // Honor shutdown even mid-outage.
            if *ctx.shutdown_rx.borrow() {
                return;
            }

            attempt += 1;
            ctx.status_tx.send_replace(Status::Reconnecting { attempt });

            // Tier 2: direct re-attach to the (possibly still alive) agent.
            match connect_once(&ctx.endpoint, ctx.client_cfg.clone(), ctx.addr).await {
                Ok(conn) => {
                    info!(attempt, "re-attached to agent");
                    break 'recover conn;
                }
                Err(e) => {
                    info!(attempt, error = %e, "re-attach attempt failed");
                }
            }

            // The old socket may be bound to a dead interface after sleep;
            // refresh it occasionally so attempts use the current network.
            if attempt.is_multiple_of(2)
                && let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0")
            {
                let _ = sock.set_nonblocking(true);
                let _ = ctx.endpoint.rebind(sock);
            }

            // Tier 3: after a cycle of failed re-attaches, assume the agent is
            // gone and re-bootstrap over SSH.
            if attempt.is_multiple_of(REATTACH_ATTEMPTS_PER_CYCLE) {
                ctx.status_tx.send_replace(Status::Bootstrapping);
                info!("re-bootstrapping agent over SSH");
                match bootstrap_agent(
                    &ctx.host,
                    ctx.listen.as_deref(),
                    ctx.verbose,
                    ctx.grace_secs,
                )
                .await
                {
                    Ok(session) => match resolve(&session.quic_target).await {
                        Ok(addr) => {
                            match crypto::client_config(
                                &session.client_id,
                                session.agent_fp,
                                &ctx.timing,
                            ) {
                                Ok(cfg) => {
                                    ctx.version_tx.send_replace(session.agent_version.clone());
                                    ctx.session = session;
                                    ctx.client_cfg = cfg;
                                    ctx.addr = addr;
                                    ctx.target_tx.send_replace(addr);
                                    if let Ok(conn) =
                                        connect_once(&ctx.endpoint, ctx.client_cfg.clone(), addr)
                                            .await
                                    {
                                        info!("re-bootstrapped and connected");
                                        break 'recover conn;
                                    }
                                }
                                Err(e) => warn!(error = %e, "client config rebuild failed"),
                            }
                        }
                        Err(e) => warn!(error = %e, "resolve after re-bootstrap failed"),
                    },
                    Err(e) => {
                        info!(error = %e, "re-bootstrap failed (will keep trying)");
                    }
                }
            }

            // Full-jitter capped backoff, mosh-style patience.
            let delay = backoff_delay(attempt);
            let mut shutdown_rx = ctx.shutdown_rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = wait_shutdown(&mut shutdown_rx) => return,
            }
        };

        ctx.conn = conn.clone();
        ctx.slot_tx.send_replace(Some(Conn::Quic(conn)));
        ctx.status_tx.send_replace(Status::Connected);
        info!("session restored");
    }
}

/// The SSH-tunnel monitor loop: watch the keepalive connection (which also dies
/// when the `ssh -L` process dies), and on loss respawn the forward + reconnect,
/// escalating to a re-bootstrap after a cycle. Never gives up.
async fn monitor_loop_tunnel(mut ctx: TunnelCtx) {
    loop {
        let mut shutdown_rx = ctx.shutdown_rx.clone();
        let died = tokio::select! {
            _ = ctx.conn.wait_closed() => true,
            _ = wait_shutdown(&mut shutdown_rx) => false,
        };
        if !died {
            info!("closing session");
            ctx.conn.send_shutdown().await;
            return;
        }
        warn!("tunnel connection lost; recovering");
        ctx.slot_tx.send_replace(None);

        let mut attempt: u32 = 0;
        let (tunnel, conn) = 'recover: loop {
            if *ctx.shutdown_rx.borrow() {
                return;
            }
            attempt += 1;
            ctx.status_tx.send_replace(Status::Reconnecting { attempt });

            // Re-attach: respawn the forward and reconnect to the (still-alive)
            // agent with the same port + token.
            match try_tunnel_connect(&ctx.host, ctx.tcp_port, &ctx.token).await {
                Ok(pair) => {
                    info!(attempt, "re-attached over ssh tunnel");
                    break 'recover pair;
                }
                Err(e) => info!(attempt, error = %e, "tunnel re-attach failed"),
            }

            // Re-bootstrap: after a cycle of failures, assume the agent is gone.
            if attempt.is_multiple_of(REATTACH_ATTEMPTS_PER_CYCLE) {
                ctx.status_tx.send_replace(Status::Bootstrapping);
                info!("re-bootstrapping tunnel agent over SSH");
                match bootstrap::bootstrap_tunnel(&ctx.host, ctx.verbose, ctx.grace_secs).await {
                    Ok(session) => {
                        ctx.version_tx.send_replace(session.agent_version.clone());
                        ctx.tcp_port = session.tcp_port;
                        ctx.token = session.token.clone();
                        match try_tunnel_connect(&ctx.host, ctx.tcp_port, &ctx.token).await {
                            Ok(pair) => {
                                info!("re-bootstrapped and connected over ssh tunnel");
                                break 'recover pair;
                            }
                            Err(e) => info!(error = %e, "connect after re-bootstrap failed"),
                        }
                    }
                    Err(e) => info!(error = %e, "tunnel re-bootstrap failed (will keep trying)"),
                }
            }

            let delay = backoff_delay(attempt);
            let mut shutdown_rx = ctx.shutdown_rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = wait_shutdown(&mut shutdown_rx) => return,
            }
        };

        // Installing the new tunnel drops the old one (killing its ssh process).
        ctx.tunnel = tunnel;
        ctx.conn = conn.clone();
        ctx.slot_tx.send_replace(Some(Conn::Ssh(conn)));
        ctx.status_tx.send_replace(Status::Connected);
        info!("session restored");
    }
}

/// Stand up a fresh `ssh -L` forward and connect through it to the agent.
async fn try_tunnel_connect(
    host: &str,
    tcp_port: u16,
    token: &Token,
) -> Result<(SshTunnel, Arc<SshConn>)> {
    let tunnel = SshTunnel::spawn(host, tcp_port).await?;
    let conn = SshConn::connect(tunnel.local, token.clone()).await?;
    Ok((tunnel, conn))
}

/// Which UDP port (or the default range) to advise opening when the connect
/// fails: a `--remote-udp host:PORT` names one port; otherwise the whole range.
fn advise_port(listen: Option<&str>) -> AdvisePort {
    listen
        .and_then(|spec| spec.rsplit(':').next())
        .and_then(|p| p.trim().parse::<u16>().ok())
        .map(AdvisePort::Single)
        .unwrap_or(AdvisePort::Range(
            DEFAULT_UDP_PORT_START,
            DEFAULT_UDP_PORT_END,
        ))
}

async fn bootstrap_agent(
    host: &str,
    listen: Option<&str>,
    verbose: u8,
    grace_secs: u64,
) -> Result<AgentSession> {
    if let Some(listen) = listen {
        return bootstrap::bootstrap(host, listen, verbose, grace_secs).await;
    }

    let mut last_err = None;
    for port in DEFAULT_UDP_PORT_START..=DEFAULT_UDP_PORT_END {
        let listen = format!("0.0.0.0:{port}");
        match bootstrap::bootstrap(host, &listen, verbose, grace_secs).await {
            Ok(session) => return Ok(session),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("no ports in default UDP range"))
        .context(format!(
            "could not start remote agent on any UDP port in {DEFAULT_UDP_PORT_START}-{DEFAULT_UDP_PORT_END}"
        )))
}

/// One bounded QUIC connect attempt with an explicit (per-session) config.
async fn connect_once(
    endpoint: &Endpoint,
    cfg: quinn::ClientConfig,
    addr: SocketAddr,
) -> Result<Connection> {
    let fut = transport::connect_with(endpoint, cfg, addr);
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow::anyhow!("QUIC handshake timed out"))?
}

async fn resolve(target: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("resolving {target}"))?
        .next()
        .with_context(|| format!("no address for {target}"))
}

/// Full-jitter exponential backoff: uniform in [0, min(cap, base * 2^n)).
fn backoff_delay(attempt: u32) -> Duration {
    let exp = BACKOFF_BASE.saturating_mul(1u32 << attempt.min(16));
    let cap = exp.min(BACKOFF_CAP).max(Duration::from_millis(100));
    let mut buf = [0u8; 8];
    let r = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => 0x9e3779b97f4a7c15, // fixed fallback; jitter is best-effort
    };
    Duration::from_millis(r % cap.as_millis().max(1) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_and_jittered() {
        for attempt in 1..40 {
            let d = backoff_delay(attempt);
            assert!(d <= BACKOFF_CAP, "attempt {attempt} exceeded cap: {d:?}");
        }
    }
}
