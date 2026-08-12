//! portmanager binary entry point.
//!
//! `main` is sync on purpose: the agent role daemonizes (forks) after its
//! stdio handshake, which must happen before any tokio runtime exists.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use portmanager::cli::{self, Cli, Command};
use portmanager::client::{ForwardSet, Origin};
use portmanager::control::{self, Request, Response};
use portmanager::forward::{ForwardSpec, ReverseSpec};
use portmanager::reverse::ReverseSet;
use portmanager::supervisor::{Status, Supervisor};
use portmanager::{agent, config, crypto, discovery, doctor, logbuf, netns, tui};

const DAEMON_CHILD_ENV: &str = "PORTMANAGER_DAEMON_CHILD";

fn main() -> Result<()> {
    use std::io::IsTerminal;

    let cli = Cli::parse();

    // Resolve the process-wide default local bind address before anything parses
    // a spec (launch args, profiles, control-socket adds, auto-forwards all read
    // it). `--bind` wins over the env; unset leaves the loopback default.
    if let Some(addr) = resolve_default_bind(&cli.run)? {
        portmanager::forward::set_default_bind(addr);
    }

    // Interactive TUI when launching a foreground session attached to a real
    // terminal. Daemon, daemon-child, subcommands, and piped/CI invocations
    // fall back to plain stderr logging. Decided before tracing init so the TUI
    // can capture logs into its in-memory pane.
    let tui_mode = cli.command.is_none()
        && !cli.run.daemon
        && std::env::var_os(DAEMON_CHILD_ENV).is_none()
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    let log_buf = tui_mode.then(logbuf::new_buffer);
    init_tracing(cli.verbose, log_buf.clone());
    crypto::init();

    match cli.command {
        Some(Command::Agent(args)) => agent::run(
            &args.listen,
            Duration::from_secs(args.grace_secs),
            args.foreground,
            args.tunnel,
        ),
        Some(Command::NsHelper) => netns::run_helper(),
        Some(cmd) => block_on(run_control_command(cmd)),
        None => {
            if cli.run.daemon && std::env::var_os(DAEMON_CHILD_ENV).is_none() {
                spawn_daemon(&cli.run, cli.verbose)?;
                Ok(())
            } else {
                block_on(run_client(cli.run, cli.verbose, log_buf))
            }
        }
    }
}

fn block_on<F: std::future::Future<Output = Result<()>>>(fut: F) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?
        .block_on(fut)
}

/// `add`/`drop`/`clear`/`list`/`status`/`stop`: talk to the running session's
/// control socket. `forget`/`logs`/`doctor` don't use the socket and are routed
/// here first.
async fn run_control_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::Forget { host } => return run_forget(&host).await,
        Command::Logs { host, follow } => return run_logs(&host, follow).await,
        Command::Doctor { host } => return doctor::run(&host).await,
        _ => {}
    }

    let (host, requests) = match cmd {
        Command::Add {
            host,
            specs,
            reverse,
        } => {
            if specs.is_empty() {
                bail!("add: pass at least one forward spec");
            }
            // Validate locally before bothering the session.
            for s in &specs {
                if reverse {
                    s.parse::<ReverseSpec>()
                        .map_err(|e| anyhow::anyhow!("invalid reverse spec {s:?}: {e}"))?;
                } else {
                    s.parse::<ForwardSpec>()
                        .map_err(|e| anyhow::anyhow!("invalid forward spec {s:?}: {e}"))?;
                }
            }
            (
                host,
                specs
                    .into_iter()
                    .map(|spec| {
                        if reverse {
                            Request::AddReverse { spec }
                        } else {
                            Request::Add { spec }
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        }
        Command::Drop {
            host,
            specs,
            all,
            reverse,
        } => {
            if all {
                (host, vec![Request::Clear])
            } else {
                if specs.is_empty() {
                    bail!("drop: pass at least one forward spec or local port (or --all)");
                }
                (
                    host,
                    specs
                        .into_iter()
                        .map(|spec| {
                            if reverse {
                                Request::DropReverse { spec }
                            } else {
                                Request::Drop { spec }
                            }
                        })
                        .collect(),
                )
            }
        }
        Command::Clear { host } => (host, vec![Request::Clear]),
        Command::List { host } => (host, vec![Request::List]),
        Command::Status { host } => (host, vec![Request::Status]),
        Command::Stop { host } => (host, vec![Request::Stop]),
        Command::Forget { .. } | Command::Logs { .. } | Command::Doctor { .. } => {
            unreachable!("handled above")
        }
        Command::Agent(_) | Command::NsHelper => unreachable!("handled in main"),
    };

    let mut failed = false;
    for req in &requests {
        match control::request(&host, req).await? {
            Response::Ok { message } => println!("{message}"),
            Response::Forwards { entries, reverse } => {
                print_entries(&entries);
                print_reverse_entries(&reverse);
            }
            Response::StatusIs {
                state,
                agent_version,
                entries,
                reverse,
            } => {
                println!(
                    "session: {state} (agent v{agent_version}, client v{})",
                    env!("CARGO_PKG_VERSION")
                );
                print_entries(&entries);
                print_reverse_entries(&reverse);
            }
            Response::Error { message } => {
                eprintln!("error: {message}");
                failed = true;
            }
        }
    }
    if failed {
        bail!("one or more control requests failed");
    }
    Ok(())
}

fn print_entries(entries: &[control::ForwardEntry]) {
    if entries.is_empty() {
        println!("(no forwards)");
        return;
    }
    for e in entries {
        if e.health.is_empty() {
            println!("{:<24} {}", e.local, e.spec);
        } else {
            println!("{:<24} {:<32} {}", e.local, e.spec, e.health);
        }
    }
}

/// Print reverse forwards (only when present) under a short header.
fn print_reverse_entries(entries: &[control::ForwardEntry]) {
    if entries.is_empty() {
        return;
    }
    println!("reverse forwards:");
    for e in entries {
        if e.health.is_empty() {
            println!("  {:<24} {}", e.local, e.spec);
        } else {
            println!("  {:<24} {:<32} {}", e.local, e.spec, e.health);
        }
    }
}

/// `forget`: delete a host's persisted state. Best-effort note if a live
/// session is still running (its in-memory set is unaffected until it next
/// persists, which would rewrite the file).
async fn run_forget(host: &str) -> Result<()> {
    let session_live = control::request(host, &Request::Status).await.is_ok();
    let forgot = tokio::task::spawn_blocking({
        let host = host.to_string();
        move || config::forget_state(&host)
    })
    .await??;
    if forgot {
        println!("forgot saved state for {host:?}");
    } else {
        println!("no saved state for {host:?}");
    }
    if session_live {
        println!(
            "note: a session for {host:?} is still running; its current forwards \
             will be re-saved if it persists again (stop it first to keep state cleared)"
        );
    }
    Ok(())
}

/// `logs`: tail the remote agent log over SSH. With `follow`, streams until the
/// user interrupts.
async fn run_logs(host: &str, follow: bool) -> Result<()> {
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.arg("-o").arg("ConnectTimeout=10").arg(host).arg("tail");
    if follow {
        cmd.arg("-f");
    }
    cmd.arg("-n").arg("200").arg(".cache/portmanager/agent.log");
    let status = cmd.status().await.context("running ssh tail")?;
    if !status.success() {
        bail!(
            "could not read remote agent log (it may not exist yet — has the agent run on {host:?}?)"
        );
    }
    Ok(())
}

/// Default action: bootstrap an agent on the host and serve the forward set
/// under the never-give-up supervisor, with control socket + discovery.
async fn run_client(
    args: cli::RunArgs,
    verbose: u8,
    log_buf: Option<logbuf::LogBuffer>,
) -> Result<()> {
    let tui_mode = log_buf.is_some();
    // Resolve host, initial forwards, reverse forwards, rules, and the
    // persistence target from either a named profile or per-host state.
    let (host, mut forwards, mut reverse_specs, rules, persist, via_ssh) =
        if let Some(name) = &args.profile {
            let config = tokio::task::spawn_blocking(config::load_config).await??;
            let profile = config
                .profiles
                .get(name)
                .with_context(|| format!("no profile {name:?} in config.toml"))?;
            let host = args.host.clone().unwrap_or_else(|| profile.host.clone());
            if host.is_empty() {
                bail!("profile {name:?} has no host and none was given on the CLI");
            }
            let mut forwards: Vec<(ForwardSpec, Origin)> = parse_specs(&profile.forwards)
                .with_context(|| format!("in profile {name:?}"))?
                .into_iter()
                .map(|s| (s, Origin::Remembered))
                .collect();
            forwards.extend(
                parse_specs(&args.specs)?
                    .into_iter()
                    .map(|s| (s, Origin::UserAdded)),
            );
            let mut reverse_specs: Vec<(ReverseSpec, Origin)> =
                parse_reverse_specs(&profile.reverse_forwards)
                    .with_context(|| format!("in profile {name:?}"))?
                    .into_iter()
                    .map(|s| (s, Origin::Remembered))
                    .collect();
            reverse_specs.extend(
                parse_reverse_specs(&args.reverse)?
                    .into_iter()
                    .map(|s| (s, Origin::UserAdded)),
            );
            (
                host,
                forwards,
                reverse_specs,
                profile.autoforward.clone(),
                config::PersistTarget::Profile { name: name.clone() },
                !args.no_via_ssh && (args.via_ssh || profile.via_ssh),
            )
        } else {
            let host = args
                .host
                .clone()
                .context("no host given; usage: portmanager <host> <spec>...")?;
            let state = {
                let host = host.clone();
                tokio::task::spawn_blocking(move || config::load_state(&host)).await??
            };
            let mut forwards: Vec<(ForwardSpec, Origin)> = parse_specs(&args.specs)?
                .into_iter()
                .map(|s| (s, Origin::UserAdded))
                .collect();
            for remembered in state.parsed_forwards() {
                if !forwards
                    .iter()
                    .any(|(f, _)| f.local_port == remembered.local_port)
                {
                    forwards.push((remembered, Origin::Remembered));
                }
            }
            let mut reverse_specs: Vec<(ReverseSpec, Origin)> = parse_reverse_specs(&args.reverse)?
                .into_iter()
                .map(|s| (s, Origin::UserAdded))
                .collect();
            for remembered in state.parsed_reverse_forwards() {
                if !reverse_specs
                    .iter()
                    .any(|(r, _)| r.bind_key() == remembered.bind_key())
                {
                    reverse_specs.push((remembered, Origin::Remembered));
                }
            }
            let via_ssh = !args.no_via_ssh && (args.via_ssh || state.via_ssh);
            (
                host.clone(),
                forwards,
                reverse_specs,
                state.autoforward,
                config::PersistTarget::HostState { host },
                via_ssh,
            )
        };

    // Dedup by remote target (CLI specs win over profile/state entries). Local
    // port conflicts are resolved while binding so omitted local ports can
    // fall back instead of being discarded here.
    {
        let mut seen = std::collections::HashSet::new();
        forwards
            .retain(|(f, _)| seen.insert((f.ns.to_wire(), f.remote_host.clone(), f.remote_port)));
    }
    // Dedup reverse forwards by remote bind endpoint (CLI wins over remembered).
    {
        let mut seen = std::collections::HashSet::new();
        reverse_specs.retain(|(r, _)| seen.insert(r.bind_key()));
    }
    // An empty session is valid: the TUI comes up empty and you add forwards
    // interactively, and a daemon can be populated later via `add`. Only the
    // non-interactive, non-daemon foreground path has nothing useful to do
    // empty — warn rather than fail.
    if forwards.is_empty()
        && reverse_specs.is_empty()
        && rules.is_empty()
        && !tui_mode
        && !args.daemon
    {
        warn!(
            "no forwards given and none remembered for {host:?}; \
             session will sit idle (add some with `portmanager add {host} <spec>`)"
        );
    }

    // Refuse a second session for the same host on this machine: the control
    // socket is per-host, so a second launch couldn't be managed and would only
    // bootstrap a redundant (leaked) agent. Fail fast, before bootstrapping.
    if control::session_is_live(&host).await {
        bail!(
            "a portmanager session for {host:?} is already running on this machine — \
             manage it with `portmanager list|add|stop {host}`, or stop it first"
        );
    }

    // Remember the tunnel choice so a later plain `portmanager <host>` keeps it,
    // and clear it again on an explicit `--no-via-ssh` so the choice is
    // reversible (otherwise one `--via-ssh` pins the host to the slower
    // transport forever).
    if let config::PersistTarget::HostState { host } = &persist {
        let host = host.clone();
        if via_ssh {
            let _ = tokio::task::spawn_blocking(move || config::remember_via_ssh(&host)).await;
        } else if args.no_via_ssh {
            let cleared =
                tokio::task::spawn_blocking(move || config::forget_via_ssh(&host)).await;
            if let Ok(Ok(true)) = cleared {
                info!("cleared the remembered --via-ssh choice; using the direct QUIC data plane");
            }
        }
    }

    // The transport is a large performance difference and was previously only
    // discoverable by inspecting the state file, so state it outright.
    if via_ssh {
        info!(
            "data plane: SSH tunnel (ssh -L) — all forwards share one TCP \
             connection; pass --no-via-ssh to use direct QUIC"
        );
    } else {
        info!("data plane: direct QUIC/UDP");
    }

    let supervisor = Supervisor::start(
        host.clone(),
        args.remote_udp.clone(),
        verbose,
        args.agent_grace.as_secs(),
        via_ssh,
    )
    .await
    .map_err(|e| {
        // The UDP-failure path attaches its own options message at the source
        // (firewall::udp_failure_message); other bootstrap errors (ssh/arch) are
        // self-describing. Only the tunnel path needs a top-level hint here.
        if via_ssh {
            e.context("session bootstrap failed over the SSH tunnel")
        } else {
            e
        }
    })?;

    let forward_set = Arc::new(ForwardSet::new(supervisor.slot.clone()));
    for (forward, origin) in forwards {
        forward_set
            .add(forward, origin)
            .await
            .context("binding forward")?;
    }

    // Reverse forwards (`ssh -R`): the agent binds the remote listeners; a watch
    // task registers the set on every connection epoch and dials local targets.
    let reverse_set = Arc::new(ReverseSet::new());
    for (spec, origin) in reverse_specs {
        if let Err(e) = reverse_set.add(spec, origin).await {
            warn!(error = %e, "skipping reverse forward");
        }
    }
    tokio::spawn(portmanager::reverse::watch(
        supervisor.slot.clone(),
        reverse_set.clone(),
    ));

    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

    // Control socket: live add/drop/list/status.
    let control_task = tokio::spawn(control::serve(control::ControlCtx {
        host: host.clone(),
        forwards: forward_set.clone(),
        reverse: reverse_set.clone(),
        status: supervisor.status.clone(),
        agent_version: supervisor.agent_version.clone(),
        shutdown: Some(shutdown_tx),
        persist,
    }));

    // In TUI mode, discovery runs to enrich the table with each forward's
    // remote process; otherwise it only matters for auto-forward rules.
    let discovery_tx = tui_mode.then(|| watch::channel(Vec::new()));
    let snapshot_rx = discovery_tx.as_ref().map(|(_, rx)| rx.clone());
    tokio::spawn(discovery::watch(
        host.clone(),
        supervisor.slot.clone(),
        forward_set.clone(),
        rules,
        discovery_tx.map(|(tx, _)| tx),
    ));

    if let Some(log_buf) = log_buf {
        // Interactive TUI: drive it until the user quits or the session stops.
        let result = tui::run(
            host.clone(),
            forward_set.clone(),
            reverse_set.clone(),
            supervisor.status.clone(),
            supervisor.agent_version.clone(),
            log_buf,
            snapshot_rx.expect("tui mode always has a discovery snapshot channel"),
            shutdown_rx,
            via_ssh,
        )
        .await;
        control_task.abort();
        control::cleanup(&host);
        supervisor.shutdown().await;
        return result;
    }

    // Mosh-style status: announce transitions until Ctrl-C.
    let mut status = supervisor.status.clone();
    info!("session up — Ctrl-C to stop");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                control_task.abort();
                control::cleanup(&host);
                supervisor.shutdown().await;
                return Ok(());
            }
            _ = shutdown_rx.recv() => {
                info!("shutting down");
                control_task.abort();
                control::cleanup(&host);
                supervisor.shutdown().await;
                return Ok(());
            }
            changed = status.changed() => {
                if changed.is_err() {
                    control::cleanup(&host);
                    bail!("supervisor exited unexpectedly");
                }
                match &*status.borrow_and_update() {
                    Status::Connected => info!("[connected]"),
                    Status::Reconnecting { attempt } => {
                        warn!("[reconnecting — attempt {attempt}]");
                    }
                    Status::Bootstrapping => warn!("[re-bootstrapping over SSH]"),
                }
            }
        }
    }
}

#[cfg(unix)]
fn spawn_daemon(args: &cli::RunArgs, verbose: u8) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let host = daemon_host(args)?;
    // Fast-fail before forking a redundant daemon (which would bootstrap a
    // leaked agent and never own the per-host control socket).
    if control::session_is_live_blocking(&host) {
        bail!(
            "a portmanager session for {host:?} is already running on this machine — \
             manage it with `portmanager list|add|stop {host}`, or stop it first"
        );
    }
    let exe = std::env::current_exe().context("resolving current executable")?;
    let log_dir = directories::BaseDirs::new()
        .map(|d| d.cache_dir().join("portmanager"))
        .unwrap_or_else(|| std::env::temp_dir().join("portmanager"));
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating log directory {}", log_dir.display()))?;
    let log_path = log_dir.join("client.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening log file {}", log_path.display()))?;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("opening /dev/null")?;

    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1))
        .env(DAEMON_CHILD_ENV, "1")
        .stdin(Stdio::from(
            devnull.try_clone().context("cloning /dev/null")?,
        ))
        .stdout(Stdio::from(devnull))
        .stderr(Stdio::from(log));

    // SAFETY: this hook runs in the freshly spawned child immediately before
    // exec. Only async-signal-safe setsid(2) is called.
    unsafe {
        cmd.pre_exec(|| {
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("spawning daemon client")?;
    wait_for_daemon(&host, &log_path, &mut child)?;
    if verbose > 0 {
        eprintln!(
            "started portmanager daemon pid={} log={}",
            child.id(),
            log_path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_daemon(
    host: &str,
    log_path: &std::path::Path,
    child: &mut std::process::Child,
) -> Result<()> {
    use std::os::unix::net::UnixStream;

    let path = control::socket_path(host)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if UnixStream::connect(&path).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("checking daemon child status")? {
            bail!(
                "daemon exited before control socket came up (status {status}); see {}",
                log_path.display()
            );
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for daemon control socket {} for {host:?}; see {}",
                path.display(),
                log_path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn spawn_daemon(_args: &cli::RunArgs, verbose: u8) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;

    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let exe = std::env::current_exe().context("resolving current executable")?;
    let log_dir = directories::BaseDirs::new()
        .map(|d| d.cache_dir().join("portmanager"))
        .unwrap_or_else(|| std::env::temp_dir().join("portmanager"));
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating log directory {}", log_dir.display()))?;
    let log_path = log_dir.join("client.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening log file {}", log_path.display()))?;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .context("opening NUL")?;

    let child = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(DAEMON_CHILD_ENV, "1")
        .stdin(Stdio::from(
            devnull.try_clone().context("cloning NUL handle")?,
        ))
        .stdout(Stdio::from(devnull))
        .stderr(Stdio::from(log))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("spawning daemon client")?;

    if verbose > 0 {
        eprintln!(
            "started portmanager daemon pid={} log={}",
            child.id(),
            log_path.display()
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn spawn_daemon(_args: &cli::RunArgs, _verbose: u8) -> Result<()> {
    bail!("daemon mode is not supported on this platform")
}

fn daemon_host(args: &cli::RunArgs) -> Result<String> {
    if let Some(host) = &args.host {
        return Ok(host.clone());
    }
    if let Some(name) = &args.profile {
        let config = config::load_config()?;
        let profile = config
            .profiles
            .get(name)
            .with_context(|| format!("no profile {name:?} in config.toml"))?;
        if !profile.host.is_empty() {
            return Ok(profile.host.clone());
        }
        bail!("profile {name:?} has no host and none was given on the CLI");
    }
    bail!("no host given; usage: portmanager --daemon <host> <spec>...");
}

/// Resolve the default local bind address for forwards: the `--bind` flag if
/// given, else the `PORTMANAGER_BIND_ADDR` env var, else `None` (loopback).
/// The env var lets the installer's Docker wrapper opt every invocation
/// (including `add`) into `0.0.0.0` under a VM-backed runtime like Colima.
fn resolve_default_bind(run: &cli::RunArgs) -> Result<Option<std::net::IpAddr>> {
    if let Some(addr) = run.bind {
        return Ok(Some(addr));
    }
    match std::env::var("PORTMANAGER_BIND_ADDR") {
        Ok(v) if !v.trim().is_empty() => {
            let addr = v.trim().parse::<std::net::IpAddr>().with_context(|| {
                format!("PORTMANAGER_BIND_ADDR={v:?} is not a valid IP address")
            })?;
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

/// Parse a list of forward-spec strings, surfacing the offending spec on error.
fn parse_specs(specs: &[String]) -> Result<Vec<ForwardSpec>> {
    specs
        .iter()
        .map(|s| {
            s.parse::<ForwardSpec>()
                .with_context(|| format!("invalid forward spec {s:?}"))
        })
        .collect()
}

/// Parse a list of reverse-spec strings, surfacing the offending spec on error.
fn parse_reverse_specs(specs: &[String]) -> Result<Vec<ReverseSpec>> {
    specs
        .iter()
        .map(|s| {
            s.parse::<ReverseSpec>()
                .with_context(|| format!("invalid reverse spec {s:?}"))
        })
        .collect()
}

fn init_tracing(verbose: u8, log_buf: Option<logbuf::LogBuffer>) {
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("portmanager={default}")));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    // In TUI mode the terminal owns stderr, so route logs into the in-memory
    // ring buffer the TUI renders (no ANSI). Otherwise log to stderr: stdout is
    // reserved for the agent's bootstrap handshake line (client never uses it).
    match log_buf {
        Some(buf) => builder
            .with_ansi(false)
            .with_writer(logbuf::MakeLogWriter::new(buf))
            .init(),
        None => builder.with_writer(std::io::stderr).init(),
    }
}
