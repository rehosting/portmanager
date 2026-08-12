//! Command-line interface definition (clap derive).
//!
//! The ergonomic form is `portmanager <host> <spec>...`; explicit subcommands
//! cover control-socket operations (`add`/`drop`/`list`/`status`) and the
//! remote `agent` role (launched over SSH, not by hand).

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "portmanager",
    version,
    about = "Resilient QUIC port forwarder with SSH auto-bootstrap",
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Default action: start a forwarding session (used when no subcommand is given).
    #[command(flatten)]
    pub run: RunArgs,

    /// Increase logging verbosity (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Remote host (an SSH alias from ~/.ssh/config or user@host).
    pub host: Option<String>,

    /// Forward specs, e.g. `8888` or `192.168.4.2:8080->8080` or `podman:web@5432->5432`.
    pub specs: Vec<String>,

    /// Reverse forwards (the `ssh -R` equivalent): expose a local target on the
    /// remote. Repeatable. Grammar: `[NS@][BINDADDR:]REMOTEPORT->[HOST:]LOCALPORT`,
    /// e.g. `-R 3000->3000` or `-R 0.0.0.0:8080->192.168.1.5:80`.
    #[arg(short = 'R', long = "reverse")]
    pub reverse: Vec<String>,

    /// Load a named profile from the config file instead of (or in addition to) specs.
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Start the local forwarding client in the background (no TUI).
    #[arg(short = 'd', long)]
    pub daemon: bool,

    /// UDP address the remote agent should bind. Defaults to the mosh-style
    /// 60000-61000 range; use this to force one specific allowed port.
    #[arg(long)]
    pub remote_udp: Option<String>,

    /// Carry the data plane over SSH (`ssh -L`) instead of a direct QUIC/UDP
    /// channel. Use for hosts reachable only through a jump host (ProxyJump)
    /// with no direct UDP path. Remembered per host once used; undo with
    /// `--no-via-ssh`.
    #[arg(long, overrides_with = "no_via_ssh")]
    pub via_ssh: bool,

    /// Force the direct QUIC/UDP data plane, clearing any remembered
    /// `--via-ssh` choice for this host. The tunnel transport is sticky once
    /// used, so this is how you get a host back onto QUIC.
    #[arg(long, overrides_with = "via_ssh")]
    pub no_via_ssh: bool,

    /// Default local bind address for forwards whose spec omits one (default
    /// loopback). Set `0.0.0.0` when running inside a VM-backed Docker runtime
    /// (Colima/Lima): it only re-exposes the VM's wildcard listeners on the
    /// host's loopback, not the VM's loopback. Also via PORTMANAGER_BIND_ADDR.
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<std::net::IpAddr>,

    /// How long the remote agent keeps the session alive after the last client
    /// disconnects, before self-reaping (the re-attach window for roaming /
    /// sleeping clients). Accepts `30s`, `15m`, `12h`, `2d` — a bare number is
    /// seconds.
    #[arg(long, value_parser = parse_grace, default_value = "12h")]
    pub agent_grace: std::time::Duration,
}

/// Parse a human duration like `30s`, `15m`, `12h`, `2d` into a [`Duration`].
/// A bare number is seconds. Used for `--agent-grace`.
fn parse_grace(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    let last = s.chars().last().ok_or("empty duration")?;
    let (digits, unit_secs) = match last {
        's' => (&s[..s.len() - 1], 1u64),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86400),
        c if c.is_ascii_digit() => (s, 1),
        other => {
            return Err(format!(
                "unknown duration unit {other:?}; use s, m, h, or d"
            ));
        }
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|e| format!("invalid duration {s:?}: {e}"))?;
    n.checked_mul(unit_secs)
        .map(std::time::Duration::from_secs)
        .ok_or_else(|| format!("duration {s:?} is too large"))
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Add forwards to the running session for HOST (via its control socket).
    Add {
        /// Target host whose session to modify.
        host: String,
        /// Forward specs to add (reverse specs when `--reverse` is set).
        specs: Vec<String>,
        /// Treat SPECS as reverse forwards (`ssh -R` equivalent).
        #[arg(short = 'R', long)]
        reverse: bool,
    },
    /// Remove forwards from the running session for HOST.
    Drop {
        /// Target host whose session to modify.
        host: String,
        /// Forward specs (or local ports) to remove. With `--reverse`, reverse
        /// specs (or remote bind ports).
        specs: Vec<String>,
        /// Remove every forward (ignores SPECS); same as `clear`.
        #[arg(long)]
        all: bool,
        /// Treat SPECS as reverse forwards (`ssh -R` equivalent).
        #[arg(short = 'R', long)]
        reverse: bool,
    },
    /// Remove every forward from the running session for HOST.
    Clear {
        /// Target host whose session to clear.
        host: String,
    },
    /// List active forwards for HOST's running session.
    List {
        /// Target host whose session to query.
        host: String,
    },
    /// Show connection/session status for HOST's running session.
    Status {
        /// Target host whose session to query.
        host: String,
    },
    /// Stop HOST's running background or foreground session.
    Stop {
        /// Target host whose session to stop.
        host: String,
    },
    /// Forget HOST's persisted state (remembered forwards, assignments, rules).
    /// Does not touch a running session; affects the next plain launch.
    Forget {
        /// Target host whose saved state to delete.
        host: String,
    },
    /// Tail the remote agent's log over SSH (for debugging).
    Logs {
        /// Target host whose agent log to read.
        host: String,
        /// Follow the log (`tail -f`) instead of printing the tail and exiting.
        #[arg(short, long)]
        follow: bool,
    },
    /// Diagnose connectivity and setup for HOST (SSH, arch, agent binary, session).
    Doctor {
        /// Target host to diagnose.
        host: String,
    },
    /// Remote agent role. Launched automatically over SSH; not for manual use.
    #[command(hide = true)]
    Agent(AgentArgs),
    /// In-namespace connect helper. Spawned by the agent under nsenter with a
    /// socketpair as stdin; not for manual use.
    #[command(hide = true, name = "ns-helper")]
    NsHelper,
}

#[derive(Debug, Args)]
pub struct AgentArgs {
    /// UDP address to bind the QUIC listener on (`0.0.0.0:0` picks a free port).
    #[arg(long, default_value = "0.0.0.0:0")]
    pub listen: String,

    /// Seconds to hold the session open with no client attached before exiting.
    /// This is the re-attach window for roaming/sleeping clients.
    #[arg(long, default_value_t = 300)]
    pub grace_secs: u64,

    /// Stay attached to the launching terminal/SSH session instead of
    /// daemonizing (used by tests and for debugging).
    #[arg(long)]
    pub foreground: bool,

    /// Serve the SSH-tunnel transport: listen on a loopback TCP port (carried by
    /// the client's `ssh -L`) instead of a QUIC/UDP listener. Set automatically
    /// by the client's bootstrap; not for manual use.
    #[arg(long)]
    pub tunnel: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_grace_units() {
        assert_eq!(parse_grace("90").unwrap().as_secs(), 90);
        assert_eq!(parse_grace("45s").unwrap().as_secs(), 45);
        assert_eq!(parse_grace("15m").unwrap().as_secs(), 900);
        assert_eq!(parse_grace("12h").unwrap().as_secs(), 43_200);
        assert_eq!(parse_grace("2d").unwrap().as_secs(), 172_800);
        assert_eq!(parse_grace(" 1h ").unwrap().as_secs(), 3_600);
    }

    #[test]
    fn parse_grace_rejects_bad_input() {
        assert!(parse_grace("").is_err());
        assert!(parse_grace("12x").is_err());
        assert!(parse_grace("abc").is_err());
    }

    #[test]
    fn default_agent_grace_is_12h() {
        let cli = Cli::try_parse_from(["portmanager", "myhost", "8888"]).unwrap();
        assert_eq!(cli.run.agent_grace.as_secs(), 43_200);
    }
}
