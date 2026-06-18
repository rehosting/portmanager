//! SSH local-forward tunnel for the `--via-ssh` transport.
//!
//! For hosts reachable only through a jump host with no direct UDP path, the
//! data plane rides an `ssh -N -L <local>:127.0.0.1:<agent_port> <host>`
//! process: SSH applies any configured `ProxyJump` and multiplexes every
//! forwarded TCP connection over its single transport. The client then makes
//! plain TCP connections to the local forwarded port (see [`crate::conn`]).
//!
//! [`SshTunnel`] owns that long-lived process and the local port it allocated;
//! dropping it tears the forward down. The supervisor respawns one on loss.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

/// Connection timeout for the SSH invocation, matching the bootstrap.
const SSH_CONNECT_TIMEOUT: &str = "ConnectTimeout=10";
/// How long to wait for the local forwarded port to become connectable.
const FORWARD_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// A running `ssh -N -L` local-forward process and the loopback port it serves.
pub struct SshTunnel {
    child: Child,
    /// Client-local address forwarded to the agent's loopback listener.
    pub local: SocketAddr,
}

impl SshTunnel {
    /// Spawn `ssh -N -L 127.0.0.1:<L>:127.0.0.1:<agent_port> <host>`, picking a
    /// free local port `L`, and wait until it accepts connections.
    pub async fn spawn(host: &str, agent_port: u16) -> Result<SshTunnel> {
        let local_port = pick_free_local_port().context("reserving a local forward port")?;
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, local_port));
        let spec = format!("127.0.0.1:{local_port}:127.0.0.1:{agent_port}");

        let mut child = Command::new("ssh")
            .arg("-o")
            .arg(SSH_CONNECT_TIMEOUT)
            // Exit (rather than warn + keep running) if the forward can't bind,
            // so readiness-probe failure is observable as a process exit.
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            // Detect a dead transport reasonably fast.
            .arg("-o")
            .arg("ServerAliveInterval=10")
            .arg("-o")
            .arg("ServerAliveCountMax=3")
            .arg("-N")
            .arg("-L")
            .arg(&spec)
            .arg(host)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .context("launching ssh -L tunnel")?;

        wait_until_connectable(local, &mut child).await?;
        Ok(SshTunnel { child, local })
    }

    /// Resolve when the underlying SSH process exits (the tunnel is gone).
    pub async fn wait(&mut self) {
        let _ = self.child.wait().await;
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        // Best-effort: kill the forward process so the local port is released.
        let _ = self.child.start_kill();
    }
}

/// Reserve a free loopback TCP port by binding ephemeral and releasing it. A
/// small TOCTOU window remains before `ssh` rebinds it; acceptable here.
fn pick_free_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("binding ephemeral local port")?;
    Ok(listener.local_addr().context("reading local port")?.port())
}

/// Poll the local forwarded port until it accepts a connection, the SSH child
/// exits, or the timeout elapses.
async fn wait_until_connectable(local: SocketAddr, child: &mut Child) -> Result<()> {
    let deadline = tokio::time::Instant::now() + FORWARD_READY_TIMEOUT;
    loop {
        if TcpStream::connect(local).await.is_ok() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!("ssh -L tunnel exited before the forward came up (status {status})");
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.start_kill();
            bail!("timed out waiting for the SSH forward at {local} to come up");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
