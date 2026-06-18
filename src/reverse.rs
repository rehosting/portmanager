//! Reverse port forwarding (the `ssh -R` equivalent).
//!
//! Data flows opposite to a normal forward: the **agent** binds a listener on
//! the remote host, and each connection accepted there is carried back to the
//! **client**, which dials a local target and splices.
//!
//! The control path reuses the discovery convention — the client opens one
//! bidi stream per connection epoch whose [`StreamHeader::host`] is
//! [`REVERSE_HOST`] and sends the list of reverse forwards as JSON. The agent
//! then binds the remote listeners and, for each accepted connection, opens a
//! *fresh* stream back to the client ([`quinn::Connection::open_bi`]) carrying a
//! [`StreamHeader`] that names the client-local target. The client accepts those
//! streams ([`Conn::accept_bi`]), dials, and splices.
//!
//! Reverse forwarding is QUIC-only: the SSH tunnel carries only
//! client-initiated streams, so [`Conn::accept_bi`] errors there and the client
//! declines to register.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use quinn::Connection;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::client::{ConnSlot, HealthHandle, Origin, new_health_handle};
use crate::conn::Conn;
use crate::error;
use crate::forward::ReverseSpec;
use crate::proto::{self, StreamHeader};

/// Reserved stream-header host marking a reverse-registration stream.
pub const REVERSE_HOST: &str = "@reverse";

/// Per-spec result the agent reports back after attempting the remote bind.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BindResult {
    /// Canonical reverse-spec string (matches what the client sent).
    spec: String,
    /// Whether the remote listener bound successfully.
    ok: bool,
    /// Failure cause when `ok` is false.
    #[serde(default)]
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Agent side
// ---------------------------------------------------------------------------

/// Serve one reverse-registration stream: read the requested reverse forwards,
/// bind each remote listener, report results, then hold the stream open as the
/// epoch's liveness anchor. When it closes (client gone / connection dropped),
/// every remote listener is torn down so nothing leaks across reconnects.
///
/// `back` is the QUIC connection used to open data streams toward the client;
/// it is `None` on the SSH-tunnel transport, where reverse forwarding is
/// unsupported.
pub async fn serve_registration<W, R>(mut send: W, recv: R, back: Option<Connection>) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let Some(conn) = back else {
        anyhow::bail!("reverse forwarding requires the QUIC transport");
    };

    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading reverse registration")?;
    let specs: Vec<String> =
        serde_json::from_str(line.trim()).context("decoding reverse registration")?;
    info!(count = specs.len(), "reverse registration");

    let mut listeners: Vec<JoinHandle<()>> = Vec::new();
    let mut results: Vec<BindResult> = Vec::new();
    for raw in &specs {
        let result = match raw.parse::<ReverseSpec>() {
            Ok(spec) => match bind_remote(&spec, conn.clone()).await {
                Ok(handle) => {
                    listeners.push(handle);
                    BindResult {
                        spec: raw.clone(),
                        ok: true,
                        error: None,
                    }
                }
                Err(e) => {
                    let error = error::format_chain(&e);
                    warn!(%raw, %error, "reverse bind failed");
                    BindResult {
                        spec: raw.clone(),
                        ok: false,
                        error: Some(error),
                    }
                }
            },
            Err(e) => BindResult {
                spec: raw.clone(),
                ok: false,
                error: Some(format!("bad reverse spec: {e}")),
            },
        };
        results.push(result);
    }

    // Report bind results so the client can surface remote-side failures.
    let mut payload = serde_json::to_string(&results).context("encoding bind results")?;
    payload.push('\n');
    let _ = send.write_all(payload.as_bytes()).await;

    // Hold the stream as the liveness anchor; any read result (EOF or error)
    // means the epoch ended.
    let mut buf = [0u8; 64];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {} // client never sends more; ignore stray bytes
        }
    }
    for handle in listeners {
        handle.abort();
    }
    debug!("reverse registration ended; remote listeners torn down");
    Ok(())
}

/// Bind one remote listener and spawn its accept loop. Each accepted connection
/// opens a stream back to the client and splices.
async fn bind_remote(spec: &ReverseSpec, conn: Connection) -> Result<JoinHandle<()>> {
    if !spec.ns.is_host() {
        anyhow::bail!(
            "reverse forwarding inside a namespace ({}) is not supported yet",
            spec.ns.to_wire()
        );
    }
    let listener = TcpListener::bind((spec.remote_bind_addr, spec.remote_bind_port))
        .await
        .with_context(|| {
            format!(
                "binding remote listener {}:{}",
                spec.remote_bind_addr, spec.remote_bind_port
            )
        })?;
    info!(
        bind = %format!("{}:{}", spec.remote_bind_addr, spec.remote_bind_port),
        target = %format!("{}:{}", spec.local_host, spec.local_port),
        "reverse forward up"
    );
    let local_host = spec.local_host.clone();
    let local_port = spec.local_port;
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, peer)) => {
                    let conn = conn.clone();
                    let local_host = local_host.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_reverse_conn(conn, tcp, &local_host, local_port).await
                        {
                            let error = error::format_chain(&e);
                            warn!(%peer, %error, "reverse connection failed");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "reverse accept failed");
                    return;
                }
            }
        }
    });
    Ok(handle)
}

/// Open a stream back to the client for one accepted remote connection, name the
/// client-local target in the header, and splice.
async fn serve_reverse_conn(
    conn: Connection,
    tcp: TcpStream,
    local_host: &str,
    local_port: u16,
) -> Result<()> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .context("opening reverse stream to client")?;
    StreamHeader {
        ns: String::new(),
        host: local_host.to_string(),
        port: local_port,
    }
    .write(&mut send)
    .await
    .context("writing reverse stream header")?;
    // The agent doesn't surface per-forward throughput (a client-side concern).
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    proto::splice(tcp, send, recv, up, down)
        .await
        .context("splicing reverse")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Live health of one reverse forward (reuses the forward health model).
#[derive(Debug)]
struct ReverseEntry {
    spec: ReverseSpec,
    origin: Origin,
    health: HealthHandle,
}

/// Snapshot of one reverse forward for display.
#[derive(Debug, Clone)]
pub struct ReverseSnapshot {
    pub spec: ReverseSpec,
    pub origin: Origin,
    pub ok_connections: u64,
    pub last_error: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// The reverse-forward collection. Unlike [`crate::client::ForwardSet`] it binds
/// nothing locally — it records the desired reverse forwards and bumps a version
/// the watch loop observes to (re)register them with the agent.
pub struct ReverseSet {
    entries: Mutex<Vec<ReverseEntry>>,
    version_tx: watch::Sender<u64>,
}

impl ReverseSet {
    pub fn new() -> Self {
        ReverseSet {
            entries: Mutex::new(Vec::new()),
            version_tx: watch::channel(0).0,
        }
    }

    fn bump(&self) {
        self.version_tx.send_modify(|v| *v += 1);
    }

    /// A receiver that fires whenever the reverse-forward set changes.
    pub fn version_rx(&self) -> watch::Receiver<u64> {
        self.version_tx.subscribe()
    }

    /// Add a reverse forward (dedup by remote bind endpoint).
    pub async fn add(&self, spec: ReverseSpec, origin: Origin) -> Result<()> {
        let mut entries = self.entries.lock().await;
        if entries.iter().any(|e| e.spec.bind_key() == spec.bind_key()) {
            anyhow::bail!(
                "reverse forward on remote {}:{} already exists",
                spec.remote_bind_addr,
                spec.remote_bind_port
            );
        }
        entries.push(ReverseEntry {
            spec,
            origin,
            health: new_health_handle(),
        });
        drop(entries);
        self.bump();
        Ok(())
    }

    /// Remove a reverse forward by spec string or by remote bind port.
    pub async fn remove(&self, spec: &str) -> Result<ReverseSpec> {
        let mut entries = self.entries.lock().await;
        let idx = if let Ok(port) = spec.trim().parse::<u16>() {
            entries.iter().position(|e| e.spec.remote_bind_port == port)
        } else {
            let parsed: ReverseSpec = spec.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            entries
                .iter()
                .position(|e| e.spec.bind_key() == parsed.bind_key())
        };
        let idx = idx.with_context(|| format!("no reverse forward matching {spec:?}"))?;
        let removed = entries.remove(idx);
        drop(entries);
        self.bump();
        Ok(removed.spec)
    }

    /// Remove every reverse forward, returning how many were removed.
    pub async fn clear(&self) -> usize {
        let mut entries = self.entries.lock().await;
        let n = entries.len();
        entries.clear();
        drop(entries);
        if n > 0 {
            self.bump();
        }
        n
    }

    /// The current reverse specs (for registration) and the version they reflect.
    async fn registration(&self) -> (Vec<ReverseSpec>, u64) {
        let entries = self.entries.lock().await;
        let specs = entries.iter().map(|e| e.spec.clone()).collect();
        (specs, *self.version_tx.borrow())
    }

    /// The health handle and byte counters for the entry dialing `host:port`,
    /// if any. Lets an accepted data stream attribute its traffic.
    async fn health_for(&self, host: &str, port: u16) -> Option<HealthHandle> {
        let entries = self.entries.lock().await;
        entries
            .iter()
            .find(|e| e.spec.local_port == port && e.spec.local_host == host)
            .map(|e| e.health.clone())
    }

    /// Record the agent's per-spec bind results against the matching entries.
    async fn apply_results(&self, results: &[BindResult]) {
        let entries = self.entries.lock().await;
        for r in results {
            let Ok(parsed) = r.spec.parse::<ReverseSpec>() else {
                continue;
            };
            if let Some(e) = entries
                .iter()
                .find(|e| e.spec.bind_key() == parsed.bind_key())
            {
                let mut h = e.health.lock().unwrap();
                if r.ok {
                    h.last_error = None;
                } else {
                    h.last_error = Some(
                        r.error
                            .clone()
                            .unwrap_or_else(|| "remote bind failed".into()),
                    );
                }
            }
        }
    }

    /// Snapshot of all reverse forwards, ordered by remote bind port.
    pub async fn list(&self) -> Vec<ReverseSnapshot> {
        let entries = self.entries.lock().await;
        let mut out: Vec<ReverseSnapshot> = entries
            .iter()
            .map(|e| {
                let h = e.health.lock().unwrap();
                ReverseSnapshot {
                    spec: e.spec.clone(),
                    origin: e.origin,
                    ok_connections: h.ok_connections,
                    last_error: h.last_error.clone(),
                    bytes_up: h.bytes_up.load(Ordering::Relaxed),
                    bytes_down: h.bytes_down.load(Ordering::Relaxed),
                }
            })
            .collect();
        out.sort_by_key(|s| s.spec.remote_bind_port);
        out
    }

    /// Whether any reverse forwards are configured.
    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }
}

impl Default for ReverseSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a reverse epoch ended.
enum EpochEnd {
    /// The reverse-forward set changed; reopen the registration with a new list.
    Changed,
    /// The stream/connection closed.
    ConnEnded,
}

/// Run reverse forwarding for the session: (re)register on every connection
/// epoch and whenever the reverse set changes, then accept agent-initiated data
/// streams and splice each to its local target.
pub async fn watch(mut slot: ConnSlot, reverse: Arc<ReverseSet>) {
    let mut ver_rx = reverse.version_rx();
    let mut warned_ssh = false;
    loop {
        // Wait for a live connection epoch.
        let conn = loop {
            if let Some(conn) = slot.borrow_and_update().clone() {
                break conn;
            }
            if slot.changed().await.is_err() {
                return; // session over
            }
        };

        // Reverse forwarding is QUIC-only.
        if matches!(conn, Conn::Ssh(_)) {
            if !reverse.is_empty().await && !warned_ssh {
                warn!(
                    "reverse forwarding is not supported over --via-ssh; \
                     reverse forwards are inactive this session"
                );
                warned_ssh = true;
            }
            if slot.changed().await.is_err() {
                return;
            }
            continue;
        }

        let (specs, version) = reverse.registration().await;
        if specs.is_empty() {
            // Nothing to register yet — wait for the set to change or the
            // connection to drop, then re-evaluate.
            tokio::select! {
                r = ver_rx.changed() => { if r.is_err() { return; } }
                r = slot.changed() => { if r.is_err() { return; } }
            }
            continue;
        }

        match run_epoch(&conn, &reverse, version).await {
            Ok(EpochEnd::Changed) => {
                debug!("reverse set changed; re-registering");
                continue; // connection still live; reopen immediately
            }
            Ok(EpochEnd::ConnEnded) => debug!("reverse epoch ended"),
            Err(e) => debug!(error = %e, "reverse epoch error"),
        }

        // Connection died; wait for the slot to change before reopening.
        if slot.changed().await.is_err() {
            return;
        }
    }
}

/// One connection epoch: open the registration stream, send the spec list, read
/// the agent's bind results, then accept reverse data streams until the
/// connection dies or the reverse set changes.
async fn run_epoch(conn: &Conn, reverse: &Arc<ReverseSet>, version: u64) -> Result<EpochEnd> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .context("opening reverse registration stream")?;
    StreamHeader {
        ns: String::new(),
        host: REVERSE_HOST.to_string(),
        port: 0,
    }
    .write(&mut send)
    .await
    .context("writing reverse header")?;
    let spec_strings: Vec<String> = {
        let (specs, _) = reverse.registration().await;
        specs.iter().map(|s| s.to_spec_string()).collect()
    };
    let mut payload = serde_json::to_string(&spec_strings).context("encoding reverse specs")?;
    payload.push('\n');
    send.write_all(payload.as_bytes())
        .await
        .context("sending reverse registration")?;

    // Read the agent's bind results (best-effort).
    let mut reader = BufReader::new(recv);
    let mut ack = String::new();
    if reader.read_line(&mut ack).await.unwrap_or(0) > 0 {
        match serde_json::from_str::<Vec<BindResult>>(ack.trim()) {
            Ok(results) => {
                for r in &results {
                    if !r.ok {
                        warn!(spec = %r.spec, error = ?r.error, "remote reverse bind failed");
                    }
                }
                reverse.apply_results(&results).await;
            }
            Err(e) => debug!(error = %e, "bad reverse bind-results line"),
        }
    }

    // `send` must stay alive: dropping it closes the stream, which the agent
    // reads as "epoch over" and tears down its listeners.
    let _keepalive = send;
    let mut ver_rx = reverse.version_rx();
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let (s, r) = match accepted {
                    Ok(pair) => pair,
                    // The connection closed (outage / re-bootstrap); not an error.
                    Err(e) => {
                        debug!(error = %e, "reverse connection ended");
                        return Ok(EpochEnd::ConnEnded);
                    }
                };
                let reverse = reverse.clone();
                tokio::spawn(handle_reverse_stream(s, r, reverse));
            }
            changed = ver_rx.changed() => {
                changed.context("reverse set channel closed")?;
                if *ver_rx.borrow() != version {
                    return Ok(EpochEnd::Changed);
                }
            }
        }
    }
}

/// Handle one agent-initiated reverse stream: read the target header, dial the
/// local target, and splice.
async fn handle_reverse_stream(
    send: crate::conn::SendHalf,
    mut recv: crate::conn::RecvHalf,
    reverse: Arc<ReverseSet>,
) {
    let header = match StreamHeader::read(&mut recv).await {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "reading reverse stream header");
            return;
        }
    };
    let target = format!("{}:{}", header.host, header.port);
    let health = reverse.health_for(&header.host, header.port).await;
    let (bytes_up, bytes_down) = match &health {
        Some(h) => {
            let h = h.lock().unwrap();
            (h.bytes_up.clone(), h.bytes_down.clone())
        }
        None => (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))),
    };

    match TcpStream::connect(&target).await {
        Ok(tcp) => match proto::splice(tcp, send, recv, bytes_up, bytes_down).await {
            Ok(()) => {
                if let Some(h) = &health {
                    h.lock().unwrap().ok_connections += 1;
                }
            }
            Err(e) => {
                let error = format!("splicing: {e}");
                if let Some(h) = &health {
                    h.lock().unwrap().last_error = Some(error.clone());
                }
                warn!(%target, %error, "reverse splice failed");
            }
        },
        Err(e) => {
            let error = format!("dialing local target {target}: {e}");
            if let Some(h) = &health {
                h.lock().unwrap().last_error = Some(error.clone());
            }
            warn!(%error, "reverse local dial failed");
        }
    }
}
