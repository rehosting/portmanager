//! SSH bootstrap: detect the remote arch, deploy the agent binary, launch it,
//! and complete the [`crate::handshake`] over the SSH pipe.
//!
//! The system `ssh`/`scp` are shelled out to (via `tokio::process`) so all of
//! the user's `~/.ssh/config`, keys, agent, jump hosts and `known_hosts`
//! verification apply unchanged — that authenticated channel is our trust anchor.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::BufReader;
use tokio::process::Command;
use tracing::{debug, info};

use crate::crypto::{Fingerprint, Identity, Timing};
use crate::handshake::{Hello, Ready, SessionId, Token};

/// Connection timeout for every SSH invocation, so recovery attempts during an
/// outage fail fast instead of hanging the supervisor.
const SSH_CONNECT_TIMEOUT: &str = "ConnectTimeout=10";

/// Everything the client needs to connect to (and later re-attach to) the agent.
///
/// The agent daemonizes after the handshake (mosh-server style), so no SSH
/// process is held open: its lifetime is governed by its grace window and the
/// explicit shutdown close. That's what lets the session survive SSH death.
pub struct AgentSession {
    /// `hostname:udp_port` to dial the QUIC listener.
    pub quic_target: String,
    /// Agent's pinned certificate fingerprint.
    pub agent_fp: Fingerprint,
    /// Client identity used for the QUIC connection.
    pub client_id: Identity,
    /// Logical session id (for SSH-less re-attach).
    pub session_id: SessionId,
    /// Shared re-attach secret.
    pub token: Token,
    /// Agent binary version reported in the handshake (skew detection).
    pub agent_version: String,
}

/// Map `uname -s -m` output to the agent's cross-compile target triple.
pub fn target_triple(uname_sm: &str) -> Result<&'static str> {
    let mut parts = uname_sm.split_whitespace();
    let os = parts.next().unwrap_or_default();
    let arch = parts.next().unwrap_or_default();
    if os != "Linux" {
        bail!("unsupported remote OS {os:?}; v1 agents are Linux-only");
    }
    match arch {
        "x86_64" | "amd64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" | "arm64" => Ok("aarch64-unknown-linux-musl"),
        other => bail!("unsupported remote arch {other:?}; v1 supports x86_64 and aarch64"),
    }
}

/// Local arch as a `uname -m`-style token.
fn local_arch_token() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
}

/// Dist cache directories to search, most-likely first.
///
/// `scripts/build-agents.sh`, `scripts/pm.sh` and `scripts/install.sh` all write
/// the XDG path (`$XDG_CACHE_HOME`, else `~/.cache`) on every OS, so that one
/// comes first. The platform cache dir is also searched because it differs on
/// macOS (`~/Library/Caches`) — a client that only looked there never saw the
/// agents the scripts had just installed.
fn dist_caches() -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    let xdg = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().join(".cache")));
    out.extend(xdg.map(|p| p.join("portmanager/dist")));
    if let Some(base) = directories::BaseDirs::new() {
        let platform = base.cache_dir().join("portmanager/dist");
        if !out.contains(&platform) {
            out.push(platform);
        }
    }
    out
}

/// Agent paths to try for `triple`, in lookup order, given the path we were
/// invoked as, the path it resolves to (when that differs), and the dist cache.
///
/// Pure so the lookup order is testable without touching the filesystem.
fn agent_candidates(
    exe: &Path,
    real: Option<&Path>,
    caches: &[std::path::PathBuf],
    triple: &str,
) -> Vec<std::path::PathBuf> {
    let exes: Vec<&Path> = std::iter::once(exe).chain(real).collect();
    let mut out = Vec::new();

    for dir in exes.iter().filter_map(|e| e.parent()) {
        out.push(dir.join("agents").join(format!("agent-{triple}")));
        out.push(dir.join(format!("agent-{triple}")));
    }
    for cache in caches {
        out.push(cache.join(format!("agent-{triple}")));
    }
    for target_dir in exes.iter().filter_map(|e| {
        e.ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "target"))
    }) {
        out.push(target_dir.join(triple).join("release/portmanager"));
    }
    out
}

/// Locate the agent binary to deploy for `triple`, in preference order:
/// 1. `$PORTMANAGER_AGENT_BIN` (explicit override),
/// 2. `agents/agent-<triple>` next to this executable (release packages),
/// 3. `agent-<triple>` next to this executable,
/// 4. the dist caches (`~/.cache/portmanager/dist/agent-<triple>` and the
///    platform cache dir, populated by `scripts/build-agents.sh`),
/// 5. this workspace's own `target/<triple>/release/portmanager` (dev builds),
/// 6. our own binary, if the remote arch matches the local one.
///
/// Steps 2/3/5 are tried against both the path we were invoked as and the path
/// it resolves to: a symlink install (`scripts/pm.sh install`) puts the link in
/// `~/.local/bin` while the package's `agents/` sits beside the real binary, and
/// `current_exe()` does not resolve symlinks on macOS.
pub(crate) fn agent_binary_for(triple: &str, remote_arch: &str) -> Result<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PORTMANAGER_AGENT_BIN") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!("PORTMANAGER_AGENT_BIN={} does not exist", p.display());
    }

    let exe = std::env::current_exe().context("locating own binary")?;
    let real = std::fs::canonicalize(&exe).ok().filter(|r| *r != exe);

    let tried = agent_candidates(&exe, real.as_deref(), &dist_caches(), triple);
    if let Some(found) = tried.iter().find(|p| p.is_file()) {
        return Ok(found.clone());
    }

    if remote_arch == local_arch_token() {
        return Ok(exe);
    }

    let searched = tried
        .iter()
        .map(|p| format!("\n  {}", p.display()))
        .collect::<String>();
    bail!(
        "no agent binary for {triple} (remote arch {remote_arch}, local {}).\
         \nsearched:{searched}\
         \nfix: build the cross-arch agents with scripts/build-agents.sh (needs a \
         musl cross toolchain, e.g. `cargo install cargo-zigbuild && brew install zig`), \
         point PORTMANAGER_AGENT_BIN at an agent-{triple}, or install from the Docker \
         image (scripts/install.sh), which bundles both Linux agents.",
        local_arch_token()
    )
}

/// Bootstrap an agent on `host` listening on `listen` (a UDP bind spec).
///
/// `verbose` is the client's `-v` count, threaded to the agent so remote logs
/// match the requested verbosity. `grace_secs` is how long the agent holds the
/// session open after the last client disconnects before self-reaping.
pub async fn bootstrap(
    host: &str,
    listen: &str,
    verbose: u8,
    grace_secs: u64,
) -> Result<AgentSession> {
    let hostname = ssh_hostname(host).await?;

    let uname = ssh_capture(host, &["uname", "-sm"])
        .await
        .context("detecting remote OS/arch")?;
    let triple = target_triple(uname.trim())?;
    let remote_arch = uname.split_whitespace().nth(1).unwrap_or_default();

    let exe = agent_binary_for(triple, remote_arch)?;
    let remote_path = deploy_agent(host, &exe, triple).await?;

    // Autoupdate: evict any lingering agent running a different version than
    // the binary we just deployed, so the remote ends up on current code.
    reap_stale_agents(host, env!("CARGO_PKG_VERSION")).await;

    let client_id = Identity::generate()?;
    let token = Token::random()?;

    // Launch the agent over SSH with piped stdio for the handshake. The agent
    // daemonizes after replying READY, so this ssh process exits on its own.
    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg(&remote_path)
        .arg("agent")
        .arg("--listen")
        .arg(listen)
        .arg("--grace-secs")
        .arg(grace_secs.to_string());
    for _ in 0..verbose {
        cmd.arg("-v");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("launching agent over SSH")?;

    let mut stdin = child.stdin.take().context("agent stdin unavailable")?;
    let stdout = child.stdout.take().context("agent stdout unavailable")?;
    let mut reader = BufReader::new(stdout);

    Hello {
        client_fp: client_id.fingerprint,
        token: token.clone(),
    }
    .write(&mut stdin)
    .await
    .context("sending handshake")?;

    let ready = Ready::read(&mut reader)
        .await
        .context("agent did not complete handshake")?;

    // The agent has detached; reap the ssh process in the background.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });

    Ok(AgentSession {
        quic_target: format!("{hostname}:{}", ready.udp_port),
        agent_fp: ready.agent_fp,
        client_id,
        session_id: ready.session_id,
        token,
        agent_version: ready.version,
    })
}

/// Everything the client needs to reach a tunnel-mode agent: the agent's
/// loopback TCP port (forwarded by `ssh -L`) and the session token gating it.
pub struct TunnelSession {
    /// Loopback TCP port the agent listens on (the `ssh -L` forward target).
    pub tcp_port: u16,
    /// Shared session secret presented on every tunnel connection.
    pub token: Token,
    /// Agent binary version reported in the handshake (skew detection).
    pub agent_version: String,
}

/// Bootstrap a tunnel-mode agent on `host`: deploy the binary, launch it with
/// `--tunnel` (loopback TCP listener, no QUIC/UDP), and complete the handshake
/// over the SSH pipe. The data plane is carried later by `ssh -L` (see
/// [`crate::tunnel`]); this only establishes the agent and its token.
pub async fn bootstrap_tunnel(host: &str, verbose: u8, grace_secs: u64) -> Result<TunnelSession> {
    let uname = ssh_capture(host, &["uname", "-sm"])
        .await
        .context("detecting remote OS/arch")?;
    let triple = target_triple(uname.trim())?;
    let remote_arch = uname.split_whitespace().nth(1).unwrap_or_default();

    let exe = agent_binary_for(triple, remote_arch)?;
    let remote_path = deploy_agent(host, &exe, triple).await?;
    reap_stale_agents(host, env!("CARGO_PKG_VERSION")).await;

    let client_id = Identity::generate()?;
    let token = Token::random()?;

    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg(&remote_path)
        .arg("agent")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--tunnel")
        .arg("--grace-secs")
        .arg(grace_secs.to_string());
    for _ in 0..verbose {
        cmd.arg("-v");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("launching tunnel agent over SSH")?;

    let mut stdin = child.stdin.take().context("agent stdin unavailable")?;
    let stdout = child.stdout.take().context("agent stdout unavailable")?;
    let mut reader = BufReader::new(stdout);

    Hello {
        client_fp: client_id.fingerprint,
        token: token.clone(),
    }
    .write(&mut stdin)
    .await
    .context("sending handshake")?;

    let ready = Ready::read(&mut reader)
        .await
        .context("agent did not complete handshake")?;

    tokio::spawn(async move {
        let _ = child.wait().await;
    });

    Ok(TunnelSession {
        tcp_port: ready.udp_port,
        token,
        agent_version: ready.version,
    })
}

/// Terminate any daemonized agent recorded on `host` whose version differs from
/// `version` (the binary we are about to launch) **and that has no client
/// currently attached** (`clients == 0`, or the field is absent on a
/// pre-upgrade agent). An agent actively serving a client is left alone, so the
/// reap never drops a live session. Best-effort: a failure here just means a
/// stale agent lingers until its grace window, so errors are logged at debug
/// and swallowed. The script also prunes state files for dead pids and is fed
/// over stdin to avoid remote-shell quoting.
async fn reap_stale_agents(host: &str, version: &str) {
    const SCRIPT: &str = r#"
ver="$1"
dir="$HOME/.cache/portmanager/agents"
[ -d "$dir" ] || exit 0
for f in "$dir"/*.json; do
  [ -e "$f" ] || continue
  v=$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "$f")
  p=$(sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p' "$f")
  c=$(sed -n 's/.*"clients":\([0-9][0-9]*\).*/\1/p' "$f")
  [ -n "$c" ] || c=0
  [ -n "$p" ] || { rm -f "$f"; continue; }
  if ! kill -0 "$p" 2>/dev/null; then rm -f "$f"; continue; fi
  if [ "$v" != "$ver" ] && [ "$c" -eq 0 ]; then
    kill -TERM "$p" 2>/dev/null && echo "reaped idle stale agent pid=$p version=$v"
    rm -f "$f"
  fi
done
"#;

    let child = Command::new("ssh")
        .arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg("sh")
        .arg("-s")
        .arg("--")
        .arg(version)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "could not launch stale-agent reaper");
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(SCRIPT.as_bytes()).await;
        let _ = stdin.shutdown().await;
        drop(stdin);
    }
    match child.wait_with_output().await {
        Ok(out) => {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let line = line.trim();
                if !line.is_empty() {
                    info!(host, "{line}");
                }
            }
        }
        Err(e) => debug!(error = %e, "stale-agent reaper failed"),
    }
}

/// Run a shell `script` on `host` by feeding it to a remote `sh -s` over SSH
/// (stdin), capturing stdout. Avoids remote-shell re-quoting of multi-line
/// scripts. Used for best-effort probes (e.g. firewall detection).
pub(crate) async fn ssh_script(host: &str, script: &str) -> Result<String> {
    let mut child = Command::new("ssh")
        .arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg("sh")
        .arg("-s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("launching ssh sh -s")?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(script.as_bytes()).await;
        let _ = stdin.shutdown().await;
    }
    let out = child
        .wait_with_output()
        .await
        .context("running ssh script")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the real hostname for an SSH alias via `ssh -G`.
async fn ssh_hostname(host: &str) -> Result<String> {
    let out = ssh_g(host).await?;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("hostname ") {
            return Ok(rest.trim().to_string());
        }
    }
    // Fall back to the alias itself if `ssh -G` yielded nothing useful.
    Ok(host.to_string())
}

pub(crate) async fn ssh_g(host: &str) -> Result<String> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()
        .await
        .context("running ssh -G")?;
    if !output.status.success() {
        bail!("ssh -G {host} failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run a command on the remote over SSH and capture stdout.
pub(crate) async fn ssh_capture(host: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("ssh")
        .arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .args(args)
        .output()
        .await
        .context("running remote command over SSH")?;
    if !output.status.success() {
        bail!(
            "remote command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Ensure the agent binary exists in the remote cache; scp it if missing.
/// Returns the remote path (relative to the remote home directory).
async fn deploy_agent(host: &str, exe: &Path, triple: &str) -> Result<String> {
    let bytes = tokio::fs::read(exe)
        .await
        .with_context(|| format!("reading {}", exe.display()))?;
    let hash = Sha256::digest(&bytes);
    let short = hex::encode(&hash[..6]);
    let remote_path = format!(".cache/portmanager/agent-{triple}-{short}");

    // Already deployed (the hash is in the name, so existence implies a match)?
    let exists = Command::new("ssh")
        .arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg(format!("test -x {remote_path}"))
        .status()
        .await
        .context("checking remote agent cache")?
        .success();

    if exists {
        gc_stale_agents(host, triple, &short).await;
        return Ok(remote_path);
    }

    // mkdir -p, scp to a temp name, then atomically move + chmod.
    let mkdir = Command::new("ssh")
        .arg(host)
        .arg("mkdir -p .cache/portmanager")
        .status()
        .await
        .context("creating remote cache dir")?;
    if !mkdir.success() {
        bail!("failed to create remote cache directory");
    }

    let tmp = format!("{remote_path}.tmp");
    let scp = Command::new("scp")
        .arg("-q")
        .arg(exe)
        .arg(format!("{host}:{tmp}"))
        .status()
        .await
        .context("scp agent binary")?;
    if !scp.success() {
        bail!("scp of agent binary failed");
    }

    let finalize = Command::new("ssh")
        .arg(host)
        .arg(format!("chmod +x {tmp} && mv {tmp} {remote_path}"))
        .status()
        .await
        .context("finalizing agent deploy")?;
    if !finalize.success() {
        bail!("failed to install agent binary on remote");
    }

    gc_stale_agents(host, triple, &short).await;
    Ok(remote_path)
}

/// Best-effort removal of cached agent binaries for `triple` other than the
/// current one (`agent-<triple>-<keep>`). Unlinking a running ELF is safe on
/// Linux, so this never disturbs a live agent. Errors are ignored.
async fn gc_stale_agents(host: &str, triple: &str, keep: &str) {
    let find = format!(
        "find .cache/portmanager -maxdepth 1 -type f -name 'agent-{triple}-*' \
         ! -name 'agent-{triple}-{keep}' -delete 2>/dev/null || true"
    );
    let _ = Command::new("ssh")
        .arg("-o")
        .arg(SSH_CONNECT_TIMEOUT)
        .arg(host)
        .arg(find)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// Default QUIC timing for bootstrapped sessions.
pub fn default_timing() -> Timing {
    Timing::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_mapping() {
        assert_eq!(
            target_triple("Linux x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple("Linux aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple("Linux arm64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
    }

    #[test]
    fn triple_rejects_unsupported() {
        assert!(target_triple("Darwin arm64").is_err());
        assert!(target_triple("Linux riscv64").is_err());
        assert!(target_triple("").is_err());
    }

    /// A symlink install (`~/.local/bin/portmanager` -> a package dir) must also
    /// look beside the *resolved* binary, where the package's `agents/` lives.
    #[test]
    fn candidates_follow_the_symlink_target() {
        let exe = Path::new("/home/u/.local/bin/portmanager");
        let real = Path::new("/src/pm/dist/portmanager-x/portmanager");
        let caches = [
            std::path::PathBuf::from("/home/u/.cache/portmanager/dist"),
            std::path::PathBuf::from("/home/u/Library/Caches/portmanager/dist"),
        ];
        let got = agent_candidates(exe, Some(real), &caches, "x86_64-unknown-linux-musl");
        let got: Vec<String> = got.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            got,
            vec![
                "/home/u/.local/bin/agents/agent-x86_64-unknown-linux-musl",
                "/home/u/.local/bin/agent-x86_64-unknown-linux-musl",
                "/src/pm/dist/portmanager-x/agents/agent-x86_64-unknown-linux-musl",
                "/src/pm/dist/portmanager-x/agent-x86_64-unknown-linux-musl",
                "/home/u/.cache/portmanager/dist/agent-x86_64-unknown-linux-musl",
                "/home/u/Library/Caches/portmanager/dist/agent-x86_64-unknown-linux-musl",
            ]
        );
    }

    /// Both cache layouts are searched, XDG first, and never duplicated when
    /// the platform cache dir is the XDG one (Linux).
    #[test]
    fn dist_caches_prefers_xdg_without_duplicates() {
        let caches = dist_caches();
        assert!(!caches.is_empty());
        assert!(caches[0].ends_with("portmanager/dist"));
        let mut sorted = caches.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            caches.len(),
            "duplicate cache dirs: {caches:?}"
        );
    }

    /// Dev builds resolve through the `target/` ancestor, last.
    #[test]
    fn candidates_include_the_dev_target_dir() {
        let exe = Path::new("/src/pm/target/release/portmanager");
        let got = agent_candidates(exe, None, &[], "aarch64-unknown-linux-musl");
        assert_eq!(
            got.last().unwrap(),
            Path::new("/src/pm/target/aarch64-unknown-linux-musl/release/portmanager")
        );
    }
}
