//! Per-session control socket: live `add`/`drop`/`list`/`status` against a
//! running session, with changes persisted to the host's state file.
//!
//! The running client listens on a Unix socket at
//! `$XDG_RUNTIME_DIR/portmanager/<host>.sock` (mode 0700 directory). The
//! `portmanager add|drop|list|status|stop <host> ...` subcommands connect to it.
//! Protocol: one JSON request line in, one JSON response line out.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::client::ForwardSet;
use crate::config::PersistTarget;
use crate::forward::ForwardSpec;
use crate::supervisor::Status;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Add {
        spec: String,
    },
    Drop {
        spec: String,
    },
    /// Remove every forward at once.
    Clear,
    List,
    Status,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok {
        message: String,
    },
    Forwards {
        entries: Vec<ForwardEntry>,
    },
    StatusIs {
        state: String,
        agent_version: String,
        entries: Vec<ForwardEntry>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardEntry {
    pub spec: String,
    pub local: String,
    /// Human-readable live health (e.g. `ok (3 conns)`, `last error: ...`,
    /// `session reconnecting`).
    #[serde(default)]
    pub health: String,
}

/// Control socket path for `host`.
#[cfg(unix)]
pub fn socket_path(host: &str) -> Result<PathBuf> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("portmanager");
    std::fs::create_dir_all(&dir).context("creating control socket dir")?;
    let mut perms = std::fs::metadata(&dir)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o700);
    std::fs::set_permissions(&dir, perms).context("restricting control dir")?;
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(dir.join(format!("{safe}.sock")))
}

/// Placeholder path for platforms where the Unix-socket control API is not
/// implemented yet.
#[cfg(not(unix))]
pub fn socket_path(host: &str) -> Result<PathBuf> {
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(std::env::temp_dir()
        .join("portmanager")
        .join(format!("{safe}.sock")))
}

/// Everything a control request can touch.
pub struct ControlCtx {
    pub host: String,
    pub forwards: Arc<ForwardSet>,
    pub status: watch::Receiver<Status>,
    /// Current agent binary version (for skew display in `status`).
    pub agent_version: watch::Receiver<String>,
    /// Optional shutdown signal for the owning session.
    pub shutdown: Option<mpsc::UnboundedSender<()>>,
    /// Where live changes are written back (host state or named profile).
    pub persist: PersistTarget,
}

/// Serve the control socket until the task is aborted. Stale sockets from a
/// dead session are replaced.
#[cfg(unix)]
pub async fn serve(ctx: ControlCtx) -> Result<()> {
    let path = socket_path(&ctx.host)?;
    if path.exists() {
        // Either a stale socket or a live concurrent session — probe it.
        if UnixStream::connect(&path).await.is_ok() {
            bail!(
                "another portmanager session for {:?} is already running ({})",
                ctx.host,
                path.display()
            );
        }
        let _ = std::fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    info!(path = %path.display(), "control socket up");

    let ctx = Arc::new(ctx);
    loop {
        let (stream, _) = listener.accept().await.context("control accept")?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, &ctx).await {
                warn!(error = %e, "control request failed");
            }
        });
    }
}

/// Windows support currently builds and runs foreground forwarding, but live
/// control needs a named-pipe transport instead of Unix sockets.
#[cfg(not(unix))]
pub async fn serve(ctx: ControlCtx) -> Result<()> {
    warn!(
        host = %ctx.host,
        "control socket unavailable on this platform; add/drop/list/status/stop are disabled"
    );
    std::future::pending::<Result<()>>().await
}

#[cfg(unix)]
async fn handle(stream: UnixStream, ctx: &ControlCtx) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(());
    };
    let (response, shutdown) = match serde_json::from_str::<Request>(&line) {
        Ok(req) => dispatch(req, ctx).await,
        Err(e) => (
            Response::Error {
                message: format!("bad request: {e}"),
            },
            false,
        ),
    };
    let mut out = serde_json::to_string(&response)?;
    out.push('\n');
    write.write_all(out.as_bytes()).await?;
    write.shutdown().await?;
    if shutdown && let Some(tx) = &ctx.shutdown {
        let _ = tx.send(());
    }
    Ok(())
}

#[cfg(unix)]
async fn dispatch(req: Request, ctx: &ControlCtx) -> (Response, bool) {
    match req {
        Request::Add { spec } => match add_forward(&spec, ctx).await {
            Ok(local) => {
                let message = match &*ctx.status.borrow() {
                    Status::Connected => format!("forward up on {local}"),
                    Status::Reconnecting { attempt } => format!(
                        "forward bound on {local} (session reconnecting, attempt {attempt} — \
                         will carry once restored)"
                    ),
                    Status::Bootstrapping => format!(
                        "forward bound on {local} (session bootstrapping — will carry once connected)"
                    ),
                };
                (Response::Ok { message }, false)
            }
            Err(e) => (
                Response::Error {
                    message: format!("{e:#}"),
                },
                false,
            ),
        },
        Request::Drop { spec } => match drop_forward(&spec, ctx).await {
            Ok(msg) => (Response::Ok { message: msg }, false),
            Err(e) => (
                Response::Error {
                    message: format!("{e:#}"),
                },
                false,
            ),
        },
        Request::Clear => {
            let n = ctx.forwards.clear().await;
            persist(ctx).await;
            (
                Response::Ok {
                    message: format!("dropped {n} forward(s)"),
                },
                false,
            )
        }
        Request::List => (
            Response::Forwards {
                entries: entries(ctx).await,
            },
            false,
        ),
        Request::Status => {
            let state = match &*ctx.status.borrow() {
                Status::Connected => "connected".to_string(),
                Status::Reconnecting { attempt } => format!("reconnecting (attempt {attempt})"),
                Status::Bootstrapping => "bootstrapping".to_string(),
            };
            let agent_version = ctx.agent_version.borrow().clone();
            (
                Response::StatusIs {
                    state,
                    agent_version,
                    entries: entries(ctx).await,
                },
                false,
            )
        }
        Request::Stop => {
            if ctx.shutdown.is_some() {
                (
                    Response::Ok {
                        message: "shutting down".into(),
                    },
                    true,
                )
            } else {
                (
                    Response::Error {
                        message: "this session does not support remote shutdown".into(),
                    },
                    false,
                )
            }
        }
    }
}

async fn entries(ctx: &ControlCtx) -> Vec<ForwardEntry> {
    let connected = matches!(&*ctx.status.borrow(), Status::Connected);
    ctx.forwards
        .list()
        .await
        .into_iter()
        .map(|s| ForwardEntry {
            spec: display_spec(&s.spec),
            local: s.local.to_string(),
            health: health_label(connected, &s),
        })
        .collect()
}

/// Render one forward's live health for `list`/`status`.
fn health_label(connected: bool, s: &crate::client::ForwardSnapshot) -> String {
    if !connected {
        return "session reconnecting".to_string();
    }
    match (s.ok_connections, &s.last_error) {
        (0, None) => "idle".to_string(),
        (0, Some(err)) => format!("last error: {err}"),
        (n, None) => format!("ok ({n} conns)"),
        (n, Some(err)) => format!("ok ({n} conns); last error: {err}"),
    }
}

async fn add_forward(spec: &str, ctx: &ControlCtx) -> Result<std::net::SocketAddr> {
    let parsed: ForwardSpec = spec.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let local = ctx.forwards.add(parsed).await?;
    persist(ctx).await;
    Ok(local)
}

/// `drop` accepts either a full spec or just a local port.
async fn drop_forward(spec: &str, ctx: &ControlCtx) -> Result<String> {
    let local_port = if let Ok(port) = spec.trim().parse::<u16>() {
        port
    } else {
        let parsed: ForwardSpec = spec.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
        parsed.local_port
    };
    let dropped = ctx.forwards.remove(local_port).await?;
    persist(ctx).await;
    Ok(format!("dropped {}", display_spec(&dropped)))
}

/// Write the live forward set back to the persistence target (host state file
/// or named profile), preserving assignments and rules.
async fn persist(ctx: &ControlCtx) {
    let specs: Vec<String> = ctx
        .forwards
        .list()
        .await
        .into_iter()
        .map(|s| display_spec(&s.spec))
        .collect();
    let target = ctx.persist.clone();
    let res = tokio::task::spawn_blocking(move || target.save_forwards(specs)).await;
    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %e, "persistence failed"),
        Err(e) => warn!(error = %e, "persistence task panicked"),
    }
}

/// Canonical CLI-grammar rendering of a spec (parseable back).
pub fn display_spec(spec: &ForwardSpec) -> String {
    let ns = spec.ns.to_wire();
    let prefix = if ns.is_empty() {
        String::new()
    } else {
        format!("{ns}@")
    };
    if spec.local_port_auto {
        // Auto local port: persist the short (preferred) form regardless of the
        // actually-bound port. Otherwise a fallback to an ephemeral port would
        // be written as a strict `->NNNNN` and frozen on the next launch,
        // instead of re-preferring the original port. The live bound port is
        // still visible in `list`'s local column.
        return format!("{prefix}{}:{}", spec.remote_host, spec.remote_port);
    }
    format!(
        "{prefix}{}:{}->{}",
        spec.remote_host, spec.remote_port, spec.local_port
    )
}

/// Client side: send one request to the session for `host`.
#[cfg(unix)]
pub async fn request(host: &str, req: &Request) -> Result<Response> {
    let path = socket_path(host)?;
    let stream = UnixStream::connect(&path).await.with_context(|| {
        format!(
            "no running session for {host:?} (control socket {} unreachable)",
            path.display()
        )
    })?;
    let (read, mut write) = stream.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    write.write_all(line.as_bytes()).await?;
    write.shutdown().await?;

    let mut lines = BufReader::new(read).lines();
    let resp = lines
        .next_line()
        .await?
        .context("session closed without responding")?;
    serde_json::from_str(&resp).context("parsing control response")
}

/// Client side: control requests are not implemented without Unix sockets.
#[cfg(not(unix))]
pub async fn request(host: &str, _req: &Request) -> Result<Response> {
    bail!("control commands are not supported on this platform for host {host:?}")
}

/// Best-effort cleanup of the socket on session end.
#[cfg(unix)]
pub fn cleanup(host: &str) {
    if let Ok(path) = socket_path(host) {
        let _ = std::fs::remove_file(path);
    }
}

/// Best-effort cleanup of the socket on session end.
#[cfg(not(unix))]
pub fn cleanup(_host: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_json_roundtrip() {
        let req = Request::Add {
            spec: "podman:web@5432->5432".into(),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&s).unwrap(),
            Request::Add { .. }
        ));

        let s = serde_json::to_string(&Request::Stop).unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&s).unwrap(),
            Request::Stop
        ));

        let resp = Response::StatusIs {
            state: "connected".into(),
            agent_version: "0.1.0".into(),
            entries: vec![ForwardEntry {
                spec: "127.0.0.1:8888->8888".into(),
                local: "127.0.0.1:8888".into(),
                health: "ok (1 conns)".into(),
            }],
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&s).unwrap(),
            Response::StatusIs { .. }
        ));
    }

    #[test]
    fn display_spec_roundtrips_through_parser() {
        for raw in [
            "8888",
            "192.168.4.2:8080->8080",
            "podman:web@10.88.0.5:5432->15432",
        ] {
            let spec: ForwardSpec = raw.parse().unwrap();
            let shown = display_spec(&spec);
            let back: ForwardSpec = shown.parse().unwrap();
            assert_eq!(
                spec, back,
                "display form {shown:?} must reparse identically"
            );
        }
    }

    #[test]
    fn auto_port_fallback_is_not_frozen_on_persist() {
        // Simulate an auto forward (`9001`) that fell back to an ephemeral local
        // port at bind time: local_port_auto stays true but local_port != remote.
        let spec = ForwardSpec {
            ns: crate::forward::NsSpec::Host,
            remote_host: "127.0.0.1".into(),
            remote_port: 9001,
            local_addr: std::net::Ipv4Addr::LOCALHOST.into(),
            local_port: 45000,
            local_port_auto: true,
        };
        // Persisted form must be the short (preferred) form, not `->45000`.
        let shown = display_spec(&spec);
        assert_eq!(shown, "127.0.0.1:9001");
        let back: ForwardSpec = shown.parse().unwrap();
        assert!(back.local_port_auto, "reparsed spec must stay auto");
        assert_eq!(back.local_port, 9001, "must re-prefer the original port");
    }
}
