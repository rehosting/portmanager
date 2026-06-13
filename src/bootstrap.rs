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

/// Locate the agent binary to deploy for `triple`, in preference order:
/// 1. `$PORTMANAGER_AGENT_BIN` (explicit override),
/// 2. `agents/agent-<triple>` next to this executable (release packages),
/// 3. `agent-<triple>` next to this executable,
/// 4. the dist cache (`~/.cache/portmanager/dist/agent-<triple>`, populated by
///    `scripts/build-agents.sh`),
/// 5. this workspace's own `target/<triple>/release/portmanager` (dev builds),
/// 6. our own binary, if the remote arch matches the local one.
pub(crate) fn agent_binary_for(triple: &str, remote_arch: &str) -> Result<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PORTMANAGER_AGENT_BIN") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!("PORTMANAGER_AGENT_BIN={} does not exist", p.display());
    }

    let exe = std::env::current_exe().context("locating own binary")?;
    if let Some(exe_dir) = exe.parent() {
        for packaged in [
            exe_dir.join("agents").join(format!("agent-{triple}")),
            exe_dir.join(format!("agent-{triple}")),
        ] {
            if packaged.is_file() {
                return Ok(packaged);
            }
        }
    }

    if let Some(base) = directories::BaseDirs::new() {
        let dist = base
            .cache_dir()
            .join("portmanager/dist")
            .join(format!("agent-{triple}"));
        if dist.is_file() {
            return Ok(dist);
        }
    }

    if let Some(target_dir) = exe
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "target"))
    {
        let dev = target_dir.join(triple).join("release/portmanager");
        if dev.is_file() {
            return Ok(dev);
        }
    }

    if remote_arch == local_arch_token() {
        return Ok(exe);
    }

    bail!(
        "no agent binary for {triple} (remote arch {remote_arch}, local {}). \
         Build one with scripts/build-agents.sh or set PORTMANAGER_AGENT_BIN.",
        local_arch_token()
    )
}

/// Bootstrap an agent on `host` listening on `listen` (a UDP bind spec).
///
/// `verbose` is the client's `-v` count, threaded to the agent so remote logs
/// match the requested verbosity.
pub async fn bootstrap(host: &str, listen: &str, verbose: u8) -> Result<AgentSession> {
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
        .arg(listen);
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
}
