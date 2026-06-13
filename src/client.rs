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
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use quinn::Connection;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error;
use crate::forward::ForwardSpec;
use crate::proto::{self, StreamHeader};

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
pub type ConnSlot = watch::Receiver<Option<Connection>>;

/// Live health of one forward, updated as connections through it succeed/fail.
/// This is what lets `add`/`list`/`status` explain *why* a forward does nothing
/// (e.g. the agent can't reach the target) instead of silently appearing "up".
#[derive(Debug, Default)]
pub struct ForwardHealth {
    /// Connections that opened a stream and started splicing successfully.
    pub ok_connections: u64,
    /// Most recent connection failure (full cause chain), if any.
    pub last_error: Option<String>,
}

/// Shared, cheaply-clonable handle to one forward's [`ForwardHealth`].
pub type HealthHandle = Arc<StdMutex<ForwardHealth>>;

/// Create a fresh, empty health handle.
pub fn new_health_handle() -> HealthHandle {
    Arc::new(StdMutex::new(ForwardHealth::default()))
}

/// Snapshot of one active forward for display (spec, bound addr, health).
#[derive(Debug, Clone)]
pub struct ForwardSnapshot {
    pub spec: ForwardSpec,
    pub local: SocketAddr,
    pub ok_connections: u64,
    pub last_error: Option<String>,
}

/// Create a connection slot pair.
pub fn conn_slot(initial: Option<Connection>) -> (watch::Sender<Option<Connection>>, ConnSlot) {
    watch::channel(initial)
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
    /// local ports prefer the remote port and fall back to a free ephemeral
    /// port if that local port is unavailable.
    pub async fn add(&self, spec: ForwardSpec) -> Result<SocketAddr> {
        let mut active = self.active.lock().await;
        let mut bind_spec = spec.clone();
        if bind_spec.local_port != 0 && active.contains_key(&bind_spec.local_port) {
            if bind_spec.local_port_auto {
                bind_spec.local_port = 0;
            } else {
                bail!("local port {} is already forwarded", bind_spec.local_port);
            }
        }

        let health = new_health_handle();
        let preferred_port = bind_spec.local_port;
        let (local, task) =
            match bind_forward(self.slot.clone(), bind_spec.clone(), health.clone()).await {
                Ok(bound) => bound,
                Err(e) if bind_spec.local_port_auto && preferred_port != 0 => {
                    warn!(
                        local_port = preferred_port,
                        error = %e,
                        "preferred local port unavailable; falling back to a free port"
                    );
                    bind_spec.local_port = 0;
                    bind_forward(self.slot.clone(), bind_spec.clone(), health.clone()).await?
                }
                Err(e) => return Err(e),
            };

        bind_spec.local_port = local.port();
        if local.port() != preferred_port && bind_spec.local_port_auto {
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
                    ok_connections: h.ok_connections,
                    last_error: h.last_error.clone(),
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
                let target = format!("{}:{}", forward.remote_host, forward.remote_port);
                let ns = forward.ns.to_wire();
                tokio::spawn(async move {
                    match serve_one(slot, forward, tcp).await {
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
async fn serve_one(mut slot: ConnSlot, forward: ForwardSpec, tcp: TcpStream) -> Result<()> {
    let header = StreamHeader {
        ns: forward.ns.to_wire(),
        host: forward.remote_host.clone(),
        port: forward.remote_port,
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
                _ = timeout => anyhow::bail!("no agent connection within attach deadline"),
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
                return proto::splice(tcp, send, recv).await.context("splicing");
            }
            Err(e) => {
                debug!(error = %e, "open_bi on stale connection; waiting for reconnect");
                let timeout = tokio::time::sleep_until(deadline);
                tokio::select! {
                    _ = timeout => anyhow::bail!("agent connection lost and not re-established in time"),
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
        }
    }

    #[tokio::test]
    async fn omitted_local_port_falls_back_when_preferred_port_is_busy() {
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let preferred = busy.local_addr().unwrap().port();
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx);

        let local = forwards.add(spec(preferred, true)).await.unwrap();

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
        forwards.add(spec(0, false)).await.unwrap();
        forwards.add(spec(0, false)).await.unwrap();
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

        assert!(forwards.add(spec(preferred, false)).await.is_err());
    }
}
