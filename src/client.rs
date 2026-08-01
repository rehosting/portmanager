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
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock as StdRwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::conn::Conn;
use crate::error::{self, SpecError};
use crate::forward::{ForwardSpec, NsSpec};
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
    /// Session-default namespace for specs that name none (`--ns`, re-pointable
    /// with `portmanager ns`). It lives here — not in a process-wide global like
    /// `forward::default_bind` — because it is *mutable* for the session's whole
    /// life and every later spec (control-socket `add`, TUI `a`) is parsed by
    /// this session's process against it. A plain `std` lock: reads are short and
    /// synchronous, so [`ForwardSet::parse_spec`] can stay non-async.
    default_ns: StdRwLock<Option<NsSpec>>,
}

impl ForwardSet {
    /// Create an empty set. `default_ns` is the session-default namespace
    /// inherited by specs that name none (`None` = the agent's own namespace).
    pub fn new(slot: ConnSlot, default_ns: Option<NsSpec>) -> Self {
        ForwardSet {
            slot,
            active: Mutex::new(HashMap::new()),
            default_ns: StdRwLock::new(default_ns.filter(|ns| !ns.is_host())),
        }
    }

    /// The session-default namespace, if one is set.
    pub fn default_ns(&self) -> Option<NsSpec> {
        self.default_ns
            .read()
            .expect("default namespace poisoned")
            .clone()
    }

    /// Parse a spec string against this session's defaults (namespace + local
    /// bind address).
    ///
    /// Every *late* source of forwards goes through here — the control socket's
    /// `add` and the TUI's `a` prompt — so inheritance is resolved client-side in
    /// exactly one place. Resolving it client-side (rather than shipping the
    /// default to the agent and expanding it there) keeps the agent stateless:
    /// each stream header already carries its own namespace, so nothing has to be
    /// re-sent on reconnect or re-bootstrap, an older agent works unchanged, and
    /// `list`/`status`/the TUI show the namespace a forward *actually* dials in
    /// instead of a bare spec the agent silently rewrites.
    pub fn parse_spec(&self, raw: &str) -> Result<ForwardSpec, SpecError> {
        let default_ns = self.default_ns();
        ForwardSpec::parse_with_defaults(raw, crate::forward::default_bind(), default_ns.as_ref())
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

    /// Point the session default namespace at `ns` and re-point every forward
    /// that inherited the old one. Returns how many were re-pointed, plus one
    /// message per forward that could not be rebound.
    ///
    /// This is the "the container restarted, its pid changed" path: the whole
    /// point is not having to drop and re-add each forward by hand. Every forward
    /// whose spec named no namespace moves — including ones added before any
    /// default existed, so `portmanager ns` also rescues a session whose bare
    /// forwards are silently reaching the wrong namespace. Forwards with an
    /// explicit `NS@`, and auto-forwards built from an observed listener, are left
    /// alone: those namespaces were stated, not defaulted. Re-pointing rebinds
    /// (rather than mutating the
    /// spec in place) because each accept loop owns a clone of its spec; the
    /// listener's port is preserved so local URLs keep working, and health
    /// counters restart since the dial path is genuinely new.
    pub async fn repoint_default_ns(&self, ns: Option<NsSpec>) -> (usize, Vec<String>) {
        {
            let mut slot = self.default_ns.write().expect("default namespace poisoned");
            *slot = ns.filter(|n| !n.is_host());
        }
        let effective = self.default_ns().unwrap_or(NsSpec::Host);

        let mut active = self.active.lock().await;
        let ports: Vec<u16> = active
            .iter()
            .filter(|(_, f)| f.spec.ns_inherited && f.spec.ns != effective)
            .map(|(port, _)| *port)
            .collect();

        let mut moved = 0;
        let mut errors = Vec::new();
        for port in ports {
            let old = active
                .remove(&port)
                .expect("port was listed from this map under the same lock");
            // Await the aborted accept loop so its listener is really closed
            // before we rebind the same port.
            old.task.abort();
            let _ = old.task.await;

            let mut spec = old.spec.clone();
            spec.ns = effective.clone();
            let health = new_health_handle();
            match bind_forward(self.slot.clone(), spec.clone(), health.clone()).await {
                Ok((local, task)) => {
                    spec.local_port = local.port();
                    active.insert(
                        local.port(),
                        ActiveForward {
                            spec,
                            local,
                            origin: old.origin,
                            health,
                            task,
                        },
                    );
                    moved += 1;
                }
                Err(e) => {
                    // Put the forward back in its old namespace rather than lose
                    // it; it still reaches whatever it reached a moment ago.
                    let health = new_health_handle();
                    match bind_forward(self.slot.clone(), old.spec.clone(), health.clone()).await {
                        Ok((local, task)) => {
                            active.insert(
                                local.port(),
                                ActiveForward {
                                    spec: old.spec,
                                    local,
                                    origin: old.origin,
                                    health,
                                    task,
                                },
                            );
                            errors.push(format!("local port {port}: {e:#} (kept previous)"));
                        }
                        Err(e2) => {
                            errors
                                .push(format!("local port {port}: {e:#}; restore failed: {e2:#}"));
                        }
                    }
                }
            }
        }
        if moved > 0 || !errors.is_empty() {
            info!(
                ns = %effective.to_wire(),
                repointed = moved,
                failed = errors.len(),
                "session default namespace changed"
            );
        }
        (moved, errors)
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
            ns_inherited: false,
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
        let forwards = ForwardSet::new(slot_rx, None);

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
        let forwards = ForwardSet::new(slot_rx, None);

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
        let forwards = ForwardSet::new(slot_rx, None);

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
    async fn later_adds_inherit_the_session_default_ns_and_are_repointed() {
        // The `portmanager add` / TUI-`a` path: specs parsed *after* launch must
        // inherit the session default, and a re-point must follow them.
        let (_slot_tx, slot_rx) = conn_slot(None);
        let set = ForwardSet::new(slot_rx, Some(NsSpec::Pid(4242)));
        assert_eq!(set.default_ns(), Some(NsSpec::Pid(4242)));

        let bare = set.parse_spec("18080").unwrap();
        assert_eq!(bare.ns, NsSpec::Pid(4242), "bare spec should inherit");
        assert!(bare.ns_inherited);
        let bare_local = set.add(bare, Origin::UserAdded).await.unwrap();

        // An explicit namespace still wins, and stays put across re-points.
        let explicit = set.parse_spec("pid:999@18081").unwrap();
        assert_eq!(explicit.ns, NsSpec::Pid(999));
        assert!(!explicit.ns_inherited);
        let explicit_local = set.add(explicit, Origin::UserAdded).await.unwrap();

        // Re-point: the inherited forward moves, on the same local port.
        let (moved, errors) = set
            .repoint_default_ns(Some(NsSpec::Podman("web".into())))
            .await;
        assert_eq!((moved, errors.len()), (1, 0));
        let list = set.list().await;
        let repointed = find_port(&list, bare_local.port());
        assert_eq!(repointed.spec.ns, NsSpec::Podman("web".into()));
        assert!(repointed.spec.ns_inherited, "still an inherited namespace");
        assert_eq!(
            find_port(&list, explicit_local.port()).spec.ns,
            NsSpec::Pid(999),
            "an explicitly-namespaced forward must not be re-pointed"
        );

        // Clearing sends inherited forwards back to the agent's own namespace.
        let (moved, errors) = set.repoint_default_ns(None).await;
        assert_eq!((moved, errors.len()), (1, 0));
        assert_eq!(set.default_ns(), None);
        let list = set.list().await;
        assert_eq!(find_port(&list, bare_local.port()).spec.ns, NsSpec::Host);
    }

    #[tokio::test]
    async fn repoint_rescues_bare_forwards_added_without_any_default() {
        // The reported case: ports added with no `--ns` at all, silently reaching
        // the wrong namespace. `portmanager ns` must adopt them.
        let (_slot_tx, slot_rx) = conn_slot(None);
        let set = ForwardSet::new(slot_rx, None);
        let bare = set.parse_spec("18090").unwrap();
        assert_eq!(bare.ns, NsSpec::Host);
        let local = set.add(bare, Origin::UserAdded).await.unwrap();

        let (moved, errors) = set.repoint_default_ns(Some(NsSpec::Pid(856_182))).await;
        assert_eq!((moved, errors.len()), (1, 0));
        let list = set.list().await;
        assert_eq!(find_port(&list, local.port()).spec.ns, NsSpec::Pid(856_182));
    }

    fn find_port(list: &[ForwardSnapshot], port: u16) -> &ForwardSnapshot {
        list.iter()
            .find(|s| s.local.port() == port)
            .expect("forward should still be bound on its original local port")
    }

    #[tokio::test]
    async fn explicit_local_port_stays_strict_when_busy() {
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let preferred = busy.local_addr().unwrap().port();
        let (_slot_tx, slot_rx) = conn_slot(None);
        let forwards = ForwardSet::new(slot_rx, None);

        assert!(
            forwards
                .add(spec(preferred, false), Origin::UserAdded)
                .await
                .is_err()
        );
    }
}
