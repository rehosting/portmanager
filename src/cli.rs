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

    /// Load a named profile from the config file instead of (or in addition to) specs.
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Start the local forwarding client in the background.
    #[arg(long)]
    pub daemon: bool,

    /// UDP address the remote agent should bind. Defaults to the mosh-style
    /// 60000-61000 range; use this to force one specific allowed port.
    #[arg(long)]
    pub remote_udp: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Add forwards to the running session for HOST (via its control socket).
    Add {
        /// Target host whose session to modify.
        host: String,
        /// Forward specs to add.
        specs: Vec<String>,
    },
    /// Remove forwards from the running session for HOST.
    Drop {
        /// Target host whose session to modify.
        host: String,
        /// Forward specs (or local ports) to remove.
        specs: Vec<String>,
        /// Remove every forward (ignores SPECS); same as `clear`.
        #[arg(long)]
        all: bool,
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
}
