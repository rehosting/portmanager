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

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint, VarInt};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::agent::CLOSE_SHUTDOWN;
use crate::bootstrap::{self, AgentSession};
use crate::client::ConnSlot;
use crate::crypto::{self, Timing};
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
    pub async fn start(host: String, listen: Option<String>, verbose: u8) -> Result<Self> {
        let timing = Timing::default();

        let (status_tx, status_rx) = watch::channel(Status::Bootstrapping);
        info!(%host, "bootstrapping agent over SSH");
        let session = bootstrap_agent(&host, listen.as_deref(), verbose).await?;
        let addr = resolve(&session.quic_target).await?;
        let (version_tx, version_rx) = watch::channel(session.agent_version.clone());

        // One endpoint for the whole session lifetime; per-connect configs
        // (the pinned agent fp changes across re-bootstraps).
        let client_cfg = crypto::client_config(&session.client_id, session.agent_fp, &timing)?;
        let endpoint = transport::client_endpoint_bare()?;

        let conn = connect_once(&endpoint, client_cfg.clone(), addr)
            .await
            .with_context(|| {
                format!(
                    "connecting to agent UDP listener at {} ({addr}); open/forward this UDP port \
                     on the remote, or choose an allowed port with --remote-udp 0.0.0.0:<PORT>",
                    session.quic_target
                )
            })?;
        info!(target = %session.quic_target, "connected to agent");
        status_tx.send_replace(Status::Connected);

        let (slot_tx, slot_rx) = client::conn_slot(Some(conn.clone()));
        let (target_tx, target_rx) = watch::channel(addr);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Tier-1: migration watcher.
        tokio::spawn(netwatch::run(endpoint.clone(), target_rx));

        let monitor = tokio::spawn(monitor_loop(MonitorCtx {
            host,
            listen,
            verbose,
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

    /// Graceful shutdown: tell the agent to exit now (rather than waiting out
    /// its grace window) and stop supervising.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        // Give the monitor a moment to deliver the close, then stop it.
        let _ = tokio::time::timeout(Duration::from_secs(2), self.monitor).await;
    }
}

struct MonitorCtx {
    host: String,
    listen: Option<String>,
    verbose: u8,
    endpoint: Endpoint,
    timing: Timing,
    session: AgentSession,
    client_cfg: quinn::ClientConfig,
    addr: SocketAddr,
    conn: Connection,
    slot_tx: watch::Sender<Option<Connection>>,
    target_tx: watch::Sender<SocketAddr>,
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
                match bootstrap_agent(&ctx.host, ctx.listen.as_deref(), ctx.verbose).await {
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
        ctx.slot_tx.send_replace(Some(conn));
        ctx.status_tx.send_replace(Status::Connected);
        info!("session restored");
    }
}

async fn bootstrap_agent(host: &str, listen: Option<&str>, verbose: u8) -> Result<AgentSession> {
    if let Some(listen) = listen {
        return bootstrap::bootstrap(host, listen, verbose).await;
    }

    let mut last_err = None;
    for port in DEFAULT_UDP_PORT_START..=DEFAULT_UDP_PORT_END {
        let listen = format!("0.0.0.0:{port}");
        match bootstrap::bootstrap(host, &listen, verbose).await {
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
