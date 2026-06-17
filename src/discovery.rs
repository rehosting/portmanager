//! Listening-port discovery: the VSCode "port just appears" feature.
//!
//! The client opens one dedicated QUIC stream (target host [`DISCOVERY_HOST`])
//! per connection epoch and sends the list of namespaces to watch. The agent
//! then periodically scans those namespaces' TCP tables and pushes JSON
//! snapshot lines. The client diffs snapshots against its auto-forward rules
//! and remembered assignments, binding matching forwards via the shared
//! [`ForwardSet`] core.
//!
//! Scanning is setns-free: `/proc/<pid>/net/tcp{,6}` shows the *netns of that
//! PID*, so container listeners are read directly (via `procfs`).

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::client::ConnSlot;
use crate::client::ForwardSet;
use crate::config::{self, AutoForwardRule, HostState};
use crate::conn::Conn;
use crate::forward::{ForwardSpec, NsSpec};
#[cfg(target_os = "linux")]
use crate::netns;

/// Reserved stream-header host marking a discovery stream.
pub const DISCOVERY_HOST: &str = "@discovery";
/// Scan/push interval on the agent.
const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

/// One discovered listener.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    /// Namespace wire form (`""` = host).
    pub ns: String,
    /// Address the socket is bound to inside that namespace.
    pub ip: String,
    pub port: u16,
    /// The process that owns the listening socket, when it could be resolved.
    /// `None` on non-Linux remotes or when the owner can't be determined.
    #[serde(default)]
    pub process: Option<ListenerProc>,
}

/// The process owning a discovered listening socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListenerProc {
    pub pid: i32,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Agent side
// ---------------------------------------------------------------------------

/// Serve one discovery stream: read the watch list, then push snapshots until
/// the stream closes.
pub async fn serve<W, R>(mut send: W, recv: R) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading discovery watch list")?;
    let namespaces: Vec<NsSpec> = line
        .split_whitespace()
        .filter_map(|tok| {
            let wire = if tok == "host" { "" } else { tok };
            NsSpec::from_wire(wire).ok()
        })
        .collect();
    info!(count = namespaces.len(), "discovery stream up");

    loop {
        let snapshot = scan_all(&namespaces).await;
        let mut payload = serde_json::to_string(&snapshot).context("encoding snapshot")?;
        payload.push('\n');
        if send.write_all(payload.as_bytes()).await.is_err() {
            // Client gone (reconnect epoch); it will reopen the stream.
            return Ok(());
        }
        tokio::time::sleep(SCAN_INTERVAL).await;
    }
}

/// Scan every watched namespace in one blocking pass. The expensive part —
/// mapping listening-socket inodes back to their owning process — walks `/proc`
/// exactly once and reuses the result across every watched namespace.
async fn scan_all(namespaces: &[NsSpec]) -> Vec<Listener> {
    let namespaces = namespaces.to_vec();
    match tokio::task::spawn_blocking(move || scan_blocking(&namespaces)).await {
        Ok(found) => found,
        Err(e) => {
            warn!(error = %e, "scan task panicked");
            Vec::new()
        }
    }
}

/// List LISTEN sockets across the watched namespaces via /proc (no setns),
/// annotating each with its owning process. Dedups by `(ns, ip, port)`,
/// preferring the entry whose owner was resolved.
#[cfg(target_os = "linux")]
fn scan_blocking(namespaces: &[NsSpec]) -> Vec<Listener> {
    use std::collections::HashMap;

    use procfs::net::TcpState;

    // (netns inode, socket inode) -> owning process. Socket inodes are unique
    // only within a network namespace, so we key on the namespace too.
    let owners = socket_owners();

    let mut out: HashMap<(String, String, u16), Listener> = HashMap::new();
    for ns in namespaces {
        let wire = ns.to_wire();
        let pid = match netns::resolve_pid(ns) {
            Ok(pid) => pid,
            Err(e) => {
                debug!(error = %e, ns = %wire, "cannot resolve namespace pid");
                continue;
            }
        };
        let (tables, netns_inode) = match pid {
            None => (
                (procfs::net::tcp(), procfs::net::tcp6()),
                read_netns_inode(std::process::id() as i32),
            ),
            Some(pid) => match procfs::process::Process::new(pid) {
                Ok(proc) => ((proc.tcp(), proc.tcp6()), read_netns_inode(pid)),
                Err(e) => {
                    debug!(error = %e, ns = %wire, "opening container /proc failed");
                    continue;
                }
            },
        };
        let (tcp, tcp6) = tables;
        for entry in tcp.into_iter().flatten().chain(tcp6.into_iter().flatten()) {
            if entry.state != TcpState::Listen {
                continue;
            }
            let process = netns_inode
                .and_then(|nsi| owners.get(&(nsi, entry.inode)))
                .cloned();
            let listener = Listener {
                ns: wire.clone(),
                ip: entry.local_address.ip().to_string(),
                port: entry.local_address.port(),
                process,
            };
            out.entry((listener.ns.clone(), listener.ip.clone(), listener.port))
                .and_modify(|existing| {
                    // Keep whichever resolved an owner (e.g. v4 vs v6 row).
                    if existing.process.is_none() && listener.process.is_some() {
                        existing.process = listener.process.clone();
                    }
                })
                .or_insert(listener);
        }
    }
    let mut out: Vec<Listener> = out.into_values().collect();
    out.sort();
    out
}

/// Build a `(netns inode, socket inode) -> owning process` map by walking
/// `/proc` once. A process's listening sockets live in that process's network
/// namespace, so we tag each socket inode with its owner's netns inode; this is
/// what lets container listeners (scanned via the container pid's TCP table) be
/// attributed to the in-container process.
#[cfg(target_os = "linux")]
fn socket_owners() -> std::collections::HashMap<(u64, u64), ListenerProc> {
    use procfs::process::FDTarget;

    let mut map = std::collections::HashMap::new();
    let procs = match procfs::process::all_processes() {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "listing processes for socket ownership failed");
            return map;
        }
    };
    for proc in procs.flatten() {
        let pid = proc.pid();
        let Some(nsi) = read_netns_inode(pid) else {
            continue;
        };
        // comm is cheap and stable; fall back to the pid if it can't be read.
        let name = proc
            .stat()
            .map(|s| s.comm)
            .unwrap_or_else(|_| format!("pid {pid}"));
        let Ok(fds) = proc.fd() else { continue };
        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.entry((nsi, inode)).or_insert_with(|| ListenerProc {
                    pid,
                    name: name.clone(),
                });
            }
        }
    }
    map
}

/// Read the network-namespace inode for a pid from `/proc/<pid>/ns/net`
/// (`net:[INODE]`). `None` if the link can't be read (process gone, no perms).
#[cfg(target_os = "linux")]
fn read_netns_inode(pid: i32) -> Option<u64> {
    let target = std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
    let s = target.to_str()?;
    let inode = s.strip_prefix("net:[")?.strip_suffix(']')?;
    inode.parse::<u64>().ok()
}

/// Non-Linux platforms do not have Linux-style `/proc/<pid>/net/tcp` tables.
#[cfg(not(target_os = "linux"))]
fn scan_blocking(_namespaces: &[NsSpec]) -> Vec<Listener> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Run discovery for the session: (re)open the discovery stream on every
/// connection epoch, match pushed listeners against the rules, and auto-bind
/// via the shared forward core with stable assignments.
///
/// `snapshot_tx`, when present, publishes each raw snapshot for the TUI's
/// "Running Process" enrichment — discovery runs purely to annotate active
/// forwards even when there are no auto-forward rules. When neither rules nor a
/// snapshot consumer are present there is nothing to do.
pub async fn watch(
    host: String,
    mut slot: ConnSlot,
    forwards: Arc<ForwardSet>,
    rules: Vec<AutoForwardRule>,
    snapshot_tx: Option<watch::Sender<Vec<Listener>>>,
) {
    if rules.is_empty() && snapshot_tx.is_none() {
        debug!("no autoforward rules and no enrichment consumer; discovery not started");
        return;
    }

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

        // Watch list follows the live forward set (plus rule namespaces and the
        // host), recomputed each time we open the stream.
        let ns_set = active_namespaces(&forwards, &rules).await;
        let watch_list = ns_set.iter().cloned().collect::<Vec<_>>().join(" ");

        match run_epoch(
            &host,
            &conn,
            &watch_list,
            &forwards,
            &rules,
            &snapshot_tx,
            &ns_set,
        )
        .await
        {
            Ok(EpochEnd::NsChanged) => {
                debug!("discovery watch set changed; reopening stream");
                continue; // connection still live; reopen immediately
            }
            Ok(EpochEnd::ConnEnded) => debug!("discovery epoch ended"),
            Err(e) => debug!(error = %e, "discovery epoch error"),
        }

        // Connection died; wait for the slot to change before reopening.
        if slot.changed().await.is_err() {
            return;
        }
    }
}

/// Why a discovery epoch ended.
enum EpochEnd {
    /// The watched namespace set changed; reopen the stream with a new list.
    NsChanged,
    /// The stream/connection closed.
    ConnEnded,
}

/// The namespaces discovery should watch: the host, every rule's namespace, and
/// the namespace of every active forward (so the TUI can attribute each forward
/// to its remote process).
async fn active_namespaces(
    forwards: &Arc<ForwardSet>,
    rules: &[AutoForwardRule],
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    set.insert("host".to_string());
    for r in rules {
        set.insert(if r.ns.is_empty() {
            "host".to_string()
        } else {
            r.ns.clone()
        });
    }
    for f in forwards.list().await {
        let wire = f.spec.ns.to_wire();
        set.insert(if wire.is_empty() {
            "host".to_string()
        } else {
            wire
        });
    }
    set
}

/// One connection epoch: open the stream, process snapshots until it dies or
/// the watched namespace set changes.
async fn run_epoch(
    host: &str,
    conn: &Conn,
    watch_list: &str,
    forwards: &Arc<ForwardSet>,
    rules: &[AutoForwardRule],
    snapshot_tx: &Option<watch::Sender<Vec<Listener>>>,
    initial_ns: &BTreeSet<String>,
) -> Result<EpochEnd> {
    let (mut send, recv) = conn.open_bi().await.context("opening discovery stream")?;
    crate::proto::StreamHeader {
        ns: String::new(),
        host: DISCOVERY_HOST.to_string(),
        port: 0,
    }
    .write(&mut send)
    .await
    .context("writing discovery header")?;
    send.write_all(format!("{watch_list}\n").as_bytes())
        .await
        .context("sending watch list")?;

    let mut lines = BufReader::new(recv).lines();
    // The agent reads the watch list once per stream, so we reopen rather than
    // mutate it in place when the active namespace set changes.
    let mut ns_check = tokio::time::interval(SCAN_INTERVAL);
    ns_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.context("reading snapshot")? else {
                    return Ok(EpochEnd::ConnEnded);
                };
                let snapshot: Vec<Listener> = match serde_json::from_str(&line) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "bad discovery snapshot");
                        continue;
                    }
                };
                // Auto-forward (only when rules are configured).
                if !rules.is_empty() {
                    for l in &snapshot {
                        if let Err(e) = consider(host, l, forwards, rules).await {
                            debug!(error = %e, ns = %l.ns, port = l.port, "auto-forward failed");
                        }
                    }
                }
                // Publish for TUI enrichment (move the snapshot last).
                if let Some(tx) = snapshot_tx {
                    let _ = tx.send_replace(snapshot);
                }
            }
            _ = ns_check.tick() => {
                if active_namespaces(forwards, rules).await != *initial_ns {
                    return Ok(EpochEnd::NsChanged);
                }
            }
        }
    }
}

/// Build the default forward spec for a discovered listener: dial it inside its
/// own namespace (loopback when the listener is bound to a wildcard address) and
/// prefer its own port locally with human-friendly fallback. Shared by the
/// interactive TUI picker and the auto-forward path so both derive the target
/// identically.
pub fn spec_for_listener(l: &Listener) -> Result<ForwardSpec> {
    // Dial loopback inside the namespace for wildcard binds.
    let remote_host = match l.ip.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        ip => ip.to_string(),
    };
    let ns = NsSpec::from_wire(&l.ns).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(ForwardSpec {
        ns,
        remote_host,
        remote_port: l.port,
        local_addr: std::net::Ipv4Addr::LOCALHOST.into(),
        local_port: l.port,
        local_port_auto: true,
        kind: crate::forward::ForwardKind::Direct,
    })
}

/// Auto-bind one discovered listener if a rule matches and it isn't already
/// forwarded. Stable assignments: a remote port keeps its local port across
/// sessions; collisions fall back to an ephemeral port, then persist.
async fn consider(
    host: &str,
    l: &Listener,
    forwards: &Arc<ForwardSet>,
    rules: &[AutoForwardRule],
) -> Result<()> {
    let Some(rule) = rules.iter().find(|r| r.matches(&l.ns, l.port)) else {
        return Ok(());
    };
    if forwards.targets(&l.ns, l.port).await {
        return Ok(()); // already forwarded (manually or by a previous snapshot)
    }

    let key = HostState::assignment_key(&l.ns, l.port);
    let state = {
        let host = host.to_string();
        tokio::task::spawn_blocking(move || config::load_state(&host)).await??
    };
    let preferred = state
        .assignments
        .get(&key)
        .copied()
        .or(match rule.local.as_str() {
            "same" => Some(l.port),
            _ => None,
        });

    // Same target derivation as the TUI picker; auto-forward then pins the local
    // port to the remembered assignment (no ladder) so it stays stable.
    let mut spec = spec_for_listener(l)?;
    spec.local_port = preferred.unwrap_or(0);
    spec.local_port_auto = false;

    // Preferred port may collide; fall back to ephemeral.
    use crate::client::Origin;
    let local = match forwards.add(spec.clone(), Origin::AutoForwarded).await {
        Ok(local) => local,
        Err(_) if spec.local_port != 0 => {
            spec.local_port = 0;
            forwards.add(spec.clone(), Origin::AutoForwarded).await?
        }
        Err(e) => return Err(e),
    };
    info!(
        ns = %l.ns, remote = l.port, local = %local,
        "auto-forward bound (rule {:?})", rule.ports
    );

    // Remember the assignment for next time.
    let host = host.to_string();
    let port = local.port();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut state = config::load_state(&host)?;
        state.assignments.insert(key, port);
        config::save_state(&host, &state)
    })
    .await
    .context("assignment persistence task")?
    .unwrap_or_else(|e| warn!(error = %e, "assignment persistence failed"));
    Ok(())
}
