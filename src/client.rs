//! Client-side local listeners. Each accepted TCP connection opens a QUIC bidi
//! stream to the agent, writes the target header, and splices.
//!
//! Listeners are decoupled from any single QUIC connection: they watch a shared
//! slot holding the *current* connection (`None` during an outage). The
//! listener itself stays bound across reconnects — that's the plan's "listeners
//! stay bound" invariant — while each accepted TCP conn grabs whatever
//! connection is live, waiting up to a short deadline during outages before
//! giving up (accept-then-RST policy).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::conn::Conn;
use crate::error;
use crate::forward::ForwardSpec;
use crate::proto::{self, StreamHeader};
use crate::socks;

/// Default seconds an accepted local connection waits for a live agent
/// connection (e.g. mid-reconnect) before being dropped.
const ATTACH_DEADLINE_DEFAULT_SECS: u64 = 10;

/// How long an accepted local connection waits for a live agent connection
/// before being dropped. Defaults to [`ATTACH_DEADLINE_DEFAULT_SECS`]; override
/// with `PORTMANAGER_ATTACH_DEADLINE_SECS` (raise it to ride out long outages
/// without RSTing in-flight accepts). Read once and cached.
pub fn attach_deadline() -> Duration {
    static CACHE: OnceLock<Duration> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let secs = std::env::var("PORTMANAGER_ATTACH_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .unwrap_or(ATTACH_DEADLINE_DEFAULT_SECS);
        Duration::from_secs(secs)
    })
}

/// Shared slot holding the current agent connection (`None` while reconnecting).
pub type ConnSlot = watch::Receiver<Option<Conn>>;

/// Live health of one forward, updated as connections through it succeed/fail.
/// This is what lets `add`/`list`/`status` explain *why* a forward does nothing
/// (e.g. the agent can't reach the target) instead of silently appearing "up".
#[derive(Debug, Default)]
pub struct ForwardHealth {
    /// Connections that opened a stream and started splicing successfully.
    pub ok_connections: u64,
    /// Most recent connection failure (full cause chain), if any.
    pub last_error: Option<String>,
    /// Cumulative bytes sent client->agent across this forward's lifetime. Bumped
    /// live by the splice; sampled by the TUI to derive a throughput rate. Shared
    /// (`Arc`) so the splice task can count without holding the health mutex.
    pub bytes_up: Arc<AtomicU64>,
    /// Cumulative bytes received agent->client across this forward's lifetime.
    pub bytes_down: Arc<AtomicU64>,
}

/// Shared, cheaply-clonable handle to one forward's [`ForwardHealth`].
pub type HealthHandle = Arc<StdMutex<ForwardHealth>>;

/// Create a fresh, empty health handle.
pub fn new_health_handle() -> HealthHandle {
    Arc::new(StdMutex::new(ForwardHealth::default()))
}

/// How a forward came to be — used by the TUI's "Origin" column. Runtime-only;
/// not part of the spec and not persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Added explicitly on the CLI or via `add`/the TUI.
    UserAdded,
    /// Restored from the host's remembered state or a named profile at launch.
    Remembered,
    /// Bound automatically by discovery against an auto-forward rule.
    AutoForwarded,
}

impl Origin {
    /// Short label for the TUI column.
    pub fn label(self) -> &'static str {
        match self {
            Origin::UserAdded => "user",
            Origin::Remembered => "remembered",
            Origin::AutoForwarded => "auto",
        }
    }
}

/// Snapshot of one active forward for display (spec, bound addr, health).
#[derive(Debug, Clone)]
pub struct ForwardSnapshot {
    pub spec: ForwardSpec,
    pub local: SocketAddr,
    pub origin: Origin,
    pub ok_connections: u64,
    pub last_error: Option<String>,
    /// Cumulative bytes client->agent at snapshot time.
    pub bytes_up: u64,
    /// Cumulative bytes agent->client at snapshot time.
    pub bytes_down: u64,
}

/// Create a connection slot pair.
pub fn conn_slot(initial: Option<Conn>) -> (watch::Sender<Option<Conn>>, ConnSlot) {
    watch::channel(initial)
}

/// Step between successive human-friendly fallback ports. Keeps the low digits
/// of the preferred port intact (80 -> 1080 -> 2080 -> ...) so a bumped port is
/// still recognizable as "the one for 80".
const LOCAL_PORT_STEP: u16 = 1000;

/// Human-friendly fallback ports for a preferred local port: the preferred port
/// itself, then +1000, +2000, ... up to the last value that still fits in a
/// u16. For example 80 -> 80, 1080, 2080, ..., 65080. Callers append a final
/// `0` (OS-assigned ephemeral) as the last resort once every rung is taken.
fn fallback_ports(preferred: u16) -> impl Iterator<Item = u16> {
    std::iter::successors(Some(preferred), |p| p.checked_add(LOCAL_PORT_STEP))
}

/// Bind the local listener for `forward` and start serving it against whatever
/// connection the slot currently holds.
///
/// Returns the actually-bound local address (useful when the spec requested
/// port 0) and the accept-loop task handle.
pub async fn bind_forward(
    slot: ConnSlot,
    forward: ForwardSpec,
    health: HealthHandle,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind((forward.local_addr, forward.local_port))
        .await
        .with_context(|| {
            format!(
                "binding local listener on {}:{}",
                forward.local_addr, forward.local_port
            )
        })?;
    let local = listener
        .local_addr()
        .context("reading local listener addr")?;
    info!(
        %local,
        target = %format!("{}:{}", forward.remote_host, forward.remote_port),
        ns = %forward.ns.to_wire(),
        "forward up"
    );
    let handle = tokio::spawn(accept_loop(listener, slot, forward, health));
    Ok((local, handle))
}

/// One live forward: its spec, where it actually bound, and its accept task.
#[derive(Debug)]
pub struct ActiveForward {
    pub spec: ForwardSpec,
    pub local: SocketAddr,
    pub origin: Origin,
    health: HealthHandle,
    task: JoinHandle<()>,
}

/// The dynamic-forward core: the runtime-managed collection behind launch
/// args, the control socket, and auto-detect. All mutation funnels through
/// here so every source shares one bind/unbind path.
pub struct ForwardSet {
    slot: ConnSlot,
    active: Mutex<HashMap<u16, ActiveForward>>,
}

impl ForwardSet {
    pub fn new(slot: ConnSlot) -> Self {
        ForwardSet {
            slot,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Bind and start a forward. Returns the actual local address. Omitted
    /// local ports prefer the remote port; if it is unavailable they walk a
    /// human-friendly ladder (80 -> 1080 -> 2080 -> ...) and finally fall back
    /// to a free ephemeral port if every rung is taken. `origin` records where
    /// the forward came from for display only.
    pub async fn add(&self, spec: ForwardSpec, origin: Origin) -> Result<SocketAddr> {
        let mut active = self.active.lock().await;
        let mut bind_spec = spec.clone();
        let preferred_port = bind_spec.local_port;
        let health = new_health_handle();

        let (local, task) = if bind_spec.local_port_auto && preferred_port != 0 {
            // Try the preferred port, then 1080/2080/..., skipping ports we
            // already serve, then a final OS-assigned ephemeral port (0).
            let mut bound = None;
            let mut last_err = None;
            for candidate in fallback_ports(preferred_port).chain(std::iter::once(0)) {
                if candidate != 0 && active.contains_key(&candidate) {
                    continue;
                }
                bind_spec.local_port = candidate;
                match bind_forward(self.slot.clone(), bind_spec.clone(), health.clone()).await {
                    Ok(b) => {
                        bound = Some(b);
                        break;
                    }
                    Err(e) => {
                        warn!(
                            local_port = candidate,
                            error = %e,
                            "local port unavailable; trying next fallback"
                        );
                        last_err = Some(e);
                    }
                }
            }
            // The trailing 0 lets the OS pick, so failing every rung is rare;
            // surface the last bind error if it somehow happens.
            bound.ok_or_else(|| last_err.expect("fallback ladder yields at least one port"))?
        } else {
            // Strict explicit port, or an already-ephemeral (0) request: one shot.
            if bind_spec.local_port != 0 && active.contains_key(&bind_spec.local_port) {
                bail!("local port {} is already forwarded", bind_spec.local_port);
            }
            bind_forward(self.slot.clone(), bind_spec.clone(), health.clone()).await?
        };

        bind_spec.local_port = local.port();
        if local.port() != preferred_port && bind_spec.local_port_auto && preferred_port != 0 {
            info!(
                preferred = preferred_port,
                actual = local.port(),
                "forward used fallback local port"
            );
        }
        if active.contains_key(&local.port()) {
            bail!("local port {} is already forwarded", spec.local_port);
        }
        active.insert(
            local.port(),
            ActiveForward {
                spec: bind_spec,
                local,
                origin,
                health,
                task,
            },
        );
        Ok(local)
    }

    /// Stop a forward by local port: abort its accept loop (closing the
    /// listener) — active spliced connections drain on their own.
    pub async fn remove(&self, local_port: u16) -> Result<ForwardSpec> {
        let mut active = self.active.lock().await;
        let fwd = active
            .remove(&local_port)
            .with_context(|| format!("no forward on local port {local_port}"))?;
        fwd.task.abort();
        info!(local = %fwd.local, "forward dropped");
        Ok(fwd.spec)
    }

    /// Stop every forward, returning how many were removed.
    pub async fn clear(&self) -> usize {
        let mut active = self.active.lock().await;
        let n = active.len();
        for (_, fwd) in active.drain() {
            fwd.task.abort();
            info!(local = %fwd.local, "forward dropped");
        }
        n
    }

    /// Snapshot of all active forwards (spec, bound addr, health), ordered by
    /// local port.
    pub async fn list(&self) -> Vec<ForwardSnapshot> {
        let active = self.active.lock().await;
        let mut out: Vec<ForwardSnapshot> = active
            .values()
            .map(|f| {
                let h = f.health.lock().unwrap();
                ForwardSnapshot {
                    spec: f.spec.clone(),
                    local: f.local,
                    origin: f.origin,
                    ok_connections: h.ok_connections,
                    last_error: h.last_error.clone(),
                    bytes_up: h.bytes_up.load(Ordering::Relaxed),
                    bytes_down: h.bytes_down.load(Ordering::Relaxed),
                }
            })
            .collect();
        out.sort_by_key(|s| s.local.port());
        out
    }

    /// Whether some forward already targets `ns`+`remote_port` (dedup for
    /// auto-detect).
    pub async fn targets(&self, ns_wire: &str, remote_port: u16) -> bool {
        let active = self.active.lock().await;
        active
            .values()
            .any(|f| f.spec.ns.to_wire() == ns_wire && f.spec.remote_port == remote_port)
    }
}

/// Accept local connections forever, fanning each onto its own QUIC stream.
async fn accept_loop(
    listener: TcpListener,
    slot: ConnSlot,
    forward: ForwardSpec,
    health: HealthHandle,
) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                debug!(%peer, "local connection accepted");
                let slot = slot.clone();
                let forward = forward.clone();
                let health = health.clone();
                // Clone the shared byte counters out of the health handle so the
                // splice can tally without holding the health mutex.
                let (bytes_up, bytes_down) = {
                    let h = health.lock().unwrap();
                    (h.bytes_up.clone(), h.bytes_down.clone())
                };
                let target = format!("{}:{}", forward.remote_host, forward.remote_port);
                let ns = forward.ns.to_wire();
                tokio::spawn(async move {
                    match serve_one(slot, forward, tcp, bytes_up, bytes_down).await {
                        Ok(()) => {
                            health.lock().unwrap().ok_connections += 1;
                        }
                        Err(e) => {
                            let error = error::format_chain(&e);
                            {
                                let mut h = health.lock().unwrap();
                                h.last_error = Some(error.clone());
                            }
                            warn!(
                                %peer,
                                %target,
                                %ns,
                                %error,
                                "forward connection failed"
                            );
                        }
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "local accept failed");
                return;
            }
        }
    }
}

/// Open a stream for one accepted TCP connection and splice. If the session is
/// mid-reconnect, wait up to [`attach_deadline`] for a live connection; if a
/// stale connection fails at open, wait for a replacement within the same
/// deadline rather than failing immediately.
async fn serve_one(
    mut slot: ConnSlot,
    forward: ForwardSpec,
    mut tcp: TcpStream,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
) -> Result<()> {
    // The target is fixed for a direct forward, but for a SOCKS proxy it comes
    // from the client's per-connection handshake (which also lets the agent
    // resolve DNS remotely). The namespace still rides along either way.
    let is_socks = forward.is_socks();
    let header = if is_socks {
        let (host, port) = socks::negotiate(&mut tcp)
            .await
            .context("socks negotiation")?;
        StreamHeader {
            ns: forward.ns.to_wire(),
            host,
            port,
        }
    } else {
        StreamHeader {
            ns: forward.ns.to_wire(),
            host: forward.remote_host.clone(),
            port: forward.remote_port,
        }
    };

    let deadline = tokio::time::Instant::now() + attach_deadline();
    loop {
        // Wait (bounded) for a live connection.
        let conn = loop {
            if let Some(conn) = slot.borrow_and_update().clone() {
                break conn;
            }
            let timeout = tokio::time::sleep_until(deadline);
            tokio::select! {
                _ = timeout => {
                    if is_socks {
                        let _ = socks::reply(&mut tcp, socks::rep::GENERAL_FAILURE).await;
                    }
                    anyhow::bail!("no agent connection within attach deadline");
                }
                changed = slot.changed() => {
                    changed.context("session ended")?;
                }
            }
        };

        // Try to open the stream; on failure the connection is stale/dying —
        // loop back and wait for the supervisor to install a fresh one.
        match conn.open_bi().await {
            Ok((mut send, recv)) => {
                header
                    .write(&mut send)
                    .await
                    .context("writing stream header")?;
                // For SOCKS, acknowledge success only once the upstream stream is
                // open (so an unreachable agent surfaces as a failure reply). The
                // agent dials lazily, so a failed *remote* dial just closes the
                // stream — standard `ssh -D`-style best-effort connect semantics.
                if is_socks {
                    socks::reply(&mut tcp, socks::rep::SUCCESS)
                        .await
                        .context("socks success reply")?;
                }
                return proto::splice(tcp, send, recv, bytes_up, bytes_down)
                    .await
                    .context("splicing");
            }
            Err(e) => {
                debug!(error = %e, "open_bi on stale connection; waiting for reconnect");
                let timeout = tokio::time::sleep_until(deadline);
                tokio::select! {
                    _ = timeout => {
                        if is_socks {
                            let _ = socks::reply(&mut tcp, socks::rep::GENERAL_FAILURE).await;
                        }
                        anyhow::bail!("agent connection lost and not re-established in time");
                    }
                    changed = slot.changed() => {
                        changed.context("session ended")?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;

    use super::*;
    use crate::forward::NsSpec;

    fn spec(local_port: u16, local_port_auto: bool) -> ForwardSpec {
        ForwardSpec {
            ns: NsSpec::Host,
            remote_host: "127.0.0.1".into(),
            remote_port: local_port,
            local_addr: Ipv4Addr::LOCALHOST.into(),
            local_port,
            local_port_auto,
            kind: Default::default(),
        }
    }

    #[test]
    fn fallback_ladder_bumps_thousands_until_it_overflows() {
        let rungs: Vec<u16> = fallback_ports(80).take(4).collect();
        assert_eq!(rungs, vec![80, 1080, 2080, 3080]);

        // Last reachable rung keeps the suffix, then stops before overflowing.
        let all: Vec<u16> = fallback_ports(80).collect();
        assert_eq!(*all.last().unwrap(), 65080);

        // A preferred port whose next rung would overflow yields only itself.
        assert_eq!(fallback_ports(65000).collect::<Vec<_>>(), vec![65000]);
    }

    #[tokio::test]
    async fn omitted_local_port_falls_back_to_next_rung_when_preferred_is_busy() {
        // Bind a preferred port whose +1000 rung is free, so the ladder lands
        // on preferred+1000 rather than an OS-assigned ephemeral port.
        let busy = loop {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = l.local_addr().unwrap().port();
            if let Some(next) = port.checked_add(LOCAL_PORT_STEP)
                && TcpListener::bind((Ipv4Addr::LOCALHOST, next)).await.is_ok()
            {
                break l; // `next` is free (the probe listener dropped here)
            }
        };
        let preferred = busy.local_addr().unwrap().port();
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx);

        let local = forwards
            .add(spec(preferred, true), Origin::UserAdded)
            .await
            .unwrap();

        assert_eq!(local.port(), preferred + LOCAL_PORT_STEP);
        forwards.remove(local.port()).await.unwrap();
    }

    #[tokio::test]
    async fn omitted_local_port_falls_back_when_preferred_port_is_busy() {
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let preferred = busy.local_addr().unwrap().port();
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx);

        let local = forwards
            .add(spec(preferred, true), Origin::UserAdded)
            .await
            .unwrap();

        assert_ne!(local.port(), preferred);
        let active = forwards.list().await;
        assert_eq!(active[0].spec.local_port, local.port());
        assert!(active[0].spec.local_port_auto);

        forwards.remove(local.port()).await.unwrap();
    }

    #[tokio::test]
    async fn clear_removes_all_forwards() {
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx);

        // Two distinct ephemeral forwards (port 0 -> free port each).
        forwards
            .add(spec(0, false), Origin::UserAdded)
            .await
            .unwrap();
        forwards
            .add(spec(0, false), Origin::UserAdded)
            .await
            .unwrap();
        assert_eq!(forwards.list().await.len(), 2);

        assert_eq!(forwards.clear().await, 2);
        assert!(forwards.list().await.is_empty());
    }

    #[tokio::test]
    async fn explicit_local_port_stays_strict_when_busy() {
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let preferred = busy.local_addr().unwrap().port();
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx);

        assert!(
            forwards
                .add(spec(preferred, false), Origin::UserAdded)
                .await
                .is_err()
        );
    }
}
