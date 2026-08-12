//! Interactive, VSCode-style port-forwarding TUI for the foreground client.
//!
//! Shows a live table of forwards — Port, Forwarded Address, Running Process,
//! Namespace, Visibility, Origin, Health — over a header (session state + agent
//! version) and a log pane (errors, reconnects, bootstrap progress routed there
//! from tracing via [`crate::logbuf`]). Keys add/drop forwards, toggle a
//! forward's visibility (loopback vs `0.0.0.0`), and quit.
//!
//! The table reads the live [`ForwardSet`] each tick; "Running Process" is
//! filled by joining the discovery enrichment snapshot to each forward by
//! `(namespace, remote port)`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Stdout};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{ExecutableCommand, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Wrap,
};
use tokio::sync::{mpsc, watch};

use crate::client::{ForwardSet, ForwardSnapshot, Origin};
use crate::control;
use crate::discovery::{Listener, spec_for_listener};
use crate::forward::{ForwardSpec, ReverseSpec};
use crate::logbuf::LogBuffer;
use crate::reverse::{ReverseSet, ReverseSnapshot};
use crate::supervisor::Status;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Run the TUI until the user quits or the session is stopped. Restores the
/// terminal on every exit path (normal, error, or panic).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    host: String,
    forward_set: Arc<ForwardSet>,
    reverse_set: Arc<ReverseSet>,
    mut status: watch::Receiver<Status>,
    agent_version: watch::Receiver<String>,
    log_buf: LogBuffer,
    discovery_snapshot: watch::Receiver<Vec<Listener>>,
    mut shutdown_rx: mpsc::UnboundedReceiver<()>,
    via_ssh: bool,
) -> Result<()> {
    install_panic_hook();
    let mut terminal = setup_terminal()?;
    let _guard = TerminalGuard;

    // crossterm raw-mode reads are blocking; pump them off-thread into the
    // async loop. The thread dies with the process on quit.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        while let Ok(ev) = crossterm::event::read() {
            if key_tx.send(ev).is_err() {
                break;
            }
        }
    });

    let mut app = App::new(host, reverse_set.clone());
    app.via_ssh = via_ssh;
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    loop {
        // Refresh the view-model, then draw.
        app.forwards = forward_set.list().await;
        app.reverse = reverse_set.list().await;
        app.connected = matches!(*status.borrow(), Status::Connected);
        app.status = status.borrow().clone();
        app.agent_version = agent_version.borrow().clone();
        app.listeners = discovery_snapshot.borrow().clone();
        app.logs = log_buf.lock().unwrap().iter().cloned().collect();
        app.sample_throughput(Instant::now());
        app.clamp_selection();
        terminal.draw(|f| app.draw(f))?;

        tokio::select! {
            _ = tick.tick() => {}
            _ = status.changed() => {}
            _ = shutdown_rx.recv() => break, // `portmanager stop <host>` from elsewhere
            ev = key_rx.recv() => {
                let Some(ev) = ev else { break }; // input thread gone
                if let Event::Key(key) = ev
                    && key.kind != KeyEventKind::Release
                    && matches!(app.handle_key(key, &forward_set).await, Action::Quit)
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Whether the key loop should keep running.
enum Action {
    Continue,
    Quit,
}

/// The currently-selected table row: a forward or a reverse forward.
enum Selection {
    Forward(ForwardSnapshot),
    Reverse(ReverseSnapshot),
}

/// What the key loop and renderer are currently doing.
enum Mode {
    /// Browsing the forwards table.
    Normal,
    /// Typing a new forward spec.
    AddInput,
    /// Typing a substring filter over the forwards table.
    Filter,
    /// Confirming a drop of the selected forward (`y`/`n`).
    ConfirmDrop,
    /// Full keybinding reference overlay.
    Help,
    /// Expanded detail (+ throughput sparkline) for the selected forward.
    Detail,
    /// Picking from discovered-but-unforwarded ports to forward one.
    Picker,
}

/// Per-forward throughput, derived by sampling the cumulative byte counters once
/// per tick. Lives in the TUI (not the forward core) because rates are a view
/// concern: they need wall-clock deltas between frames.
struct PortThroughput {
    prev_up: u64,
    prev_down: u64,
    prev_at: Instant,
    /// Bytes/sec over the last sampled interval, each direction.
    rate_up: f64,
    rate_down: f64,
    /// Recent combined bytes-per-interval, newest last — feeds the sparkline.
    history: VecDeque<u64>,
}

/// How many sampled intervals the sparkline retains.
const THROUGHPUT_HISTORY: usize = 60;

struct App {
    host: String,
    forwards: Vec<ForwardSnapshot>,
    reverse: Vec<ReverseSnapshot>,
    /// Live reverse-forward set, so the `a` prompt can add reverse forwards.
    reverse_set: Arc<ReverseSet>,
    listeners: Vec<Listener>,
    logs: Vec<String>,
    status: Status,
    connected: bool,
    agent_version: String,
    table: TableState,
    /// Selection within the discovered-ports picker.
    picker: TableState,
    mode: Mode,
    input: String,
    /// Active table filter (empty = show all).
    filter: String,
    /// Lines scrolled up from the log tail (0 = pinned to newest).
    log_scroll: usize,
    /// Per-local-port throughput samples, pruned to live forwards each tick.
    throughput: HashMap<u16, PortThroughput>,
    /// Transient feedback shown in the footer (errors, confirmations).
    message: Option<String>,
    /// Whether the data plane is the SSH tunnel rather than direct QUIC. The
    /// tunnel is much slower (every forward shares one TCP connection) and is
    /// remembered per host, so the header calls it out rather than leaving it
    /// to be discovered from the state file.
    via_ssh: bool,
}

impl App {
    fn new(host: String, reverse_set: Arc<ReverseSet>) -> Self {
        let mut table = TableState::default();
        table.select(Some(0));
        let mut picker = TableState::default();
        picker.select(Some(0));
        App {
            host,
            forwards: Vec::new(),
            reverse: Vec::new(),
            reverse_set,
            listeners: Vec::new(),
            logs: Vec::new(),
            status: Status::Bootstrapping,
            connected: false,
            agent_version: String::new(),
            table,
            picker,
            mode: Mode::Normal,
            input: String::new(),
            filter: String::new(),
            log_scroll: 0,
            throughput: HashMap::new(),
            message: None,
            via_ssh: false,
        }
    }

    /// The forwards currently shown, after applying the active filter. Selection
    /// and the rendered table both index into this view.
    fn visible(&self) -> Vec<&ForwardSnapshot> {
        if self.filter.is_empty() {
            return self.forwards.iter().collect();
        }
        let needle = self.filter.to_lowercase();
        let proc = self.process_index();
        self.forwards
            .iter()
            .filter(|s| {
                let ns = s.spec.ns.to_wire();
                let process = proc.get(&(ns.clone(), s.spec.remote_port));
                let hay = format!(
                    "{} {}:{} {} {}",
                    s.local.port(),
                    s.spec.remote_host,
                    s.spec.remote_port,
                    ns,
                    process.map(String::as_str).unwrap_or("")
                )
                .to_lowercase();
                hay.contains(&needle)
            })
            .collect()
    }

    /// Discovered listeners not already targeted by an active forward (matched by
    /// namespace + remote port) — the candidates for the picker.
    fn discovered_unforwarded(&self) -> Vec<&Listener> {
        self.listeners
            .iter()
            .filter(|l| {
                !self
                    .forwards
                    .iter()
                    .any(|f| f.spec.ns.to_wire() == l.ns && f.spec.remote_port == l.port)
            })
            .collect()
    }

    /// Sample the cumulative byte counters into per-port rates and sparkline
    /// history. Called once per tick before drawing. Prunes ports whose forwards
    /// are gone.
    fn sample_throughput(&mut self, now: Instant) {
        let live: HashSet<u16> = self.forwards.iter().map(|s| s.local.port()).collect();
        self.throughput.retain(|port, _| live.contains(port));
        for s in &self.forwards {
            let port = s.local.port();
            let entry = self
                .throughput
                .entry(port)
                .or_insert_with(|| PortThroughput {
                    prev_up: s.bytes_up,
                    prev_down: s.bytes_down,
                    prev_at: now,
                    rate_up: 0.0,
                    rate_down: 0.0,
                    history: VecDeque::new(),
                });
            let dt = now.duration_since(entry.prev_at).as_secs_f64();
            if dt <= 0.0 {
                continue; // first sample for this port: baseline only
            }
            let dup = s.bytes_up.saturating_sub(entry.prev_up);
            let ddown = s.bytes_down.saturating_sub(entry.prev_down);
            entry.rate_up = dup as f64 / dt;
            entry.rate_down = ddown as f64 / dt;
            entry.history.push_back(dup + ddown);
            while entry.history.len() > THROUGHPUT_HISTORY {
                entry.history.pop_front();
            }
            entry.prev_up = s.bytes_up;
            entry.prev_down = s.bytes_down;
            entry.prev_at = now;
        }
    }

    /// Reverse forwards shown in the table. They appear (and are selectable)
    /// only when no filter is active — the filter matches forwards.
    fn reverse_visible(&self) -> Vec<&ReverseSnapshot> {
        if self.filter.is_empty() {
            self.reverse.iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Number of selectable rows: filtered forwards, then reverse forwards. The
    /// table selection indexes into this combined list (forwards first).
    fn selectable_len(&self) -> usize {
        self.visible().len() + self.reverse_visible().len()
    }

    /// Keep both selections within bounds as forwards and discovered ports come
    /// and go.
    fn clamp_selection(&mut self) {
        let rows = self.selectable_len();
        if rows == 0 {
            self.table.select(None);
        } else {
            let sel = self.table.selected().unwrap_or(0).min(rows - 1);
            self.table.select(Some(sel));
        }
        let discovered = self.discovered_unforwarded().len();
        if discovered == 0 {
            self.picker.select(None);
        } else {
            let sel = self.picker.selected().unwrap_or(0).min(discovered - 1);
            self.picker.select(Some(sel));
        }
    }

    /// The selected row (a forward or a reverse forward), indexed into the
    /// combined view. Cloned so the borrow of `self` doesn't outlive the lookup.
    fn selected_row(&self) -> Option<Selection> {
        let i = self.table.selected()?;
        let forwards = self.visible();
        if i < forwards.len() {
            return Some(Selection::Forward((*forwards[i]).clone()));
        }
        let reverse = self.reverse_visible();
        reverse
            .get(i - forwards.len())
            .map(|r| Selection::Reverse((*r).clone()))
    }

    /// The selected *forward* (None when a reverse row is selected). Used by the
    /// forward-only actions (open/copy/visibility).
    fn selected(&self) -> Option<ForwardSnapshot> {
        match self.selected_row() {
            Some(Selection::Forward(f)) => Some(f),
            _ => None,
        }
    }

    /// Whether the selected row is a reverse forward (forward-only actions hint
    /// instead of acting).
    fn reverse_selected(&self) -> bool {
        matches!(self.selected_row(), Some(Selection::Reverse(_)))
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.selectable_len() as isize;
        if len == 0 {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len);
        self.table.select(Some(next as usize));
    }

    fn move_picker(&mut self, delta: isize) {
        let len = self.discovered_unforwarded().len() as isize;
        if len == 0 {
            return;
        }
        let cur = self.picker.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len);
        self.picker.select(Some(next as usize));
    }

    async fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        match self.mode {
            Mode::AddInput => self.handle_add_input(key, forwards).await,
            Mode::Filter => self.handle_filter(key),
            Mode::ConfirmDrop => self.handle_confirm_drop(key, forwards).await,
            Mode::Help => self.handle_overlay_dismiss(key, KeyCode::Char('?')),
            Mode::Detail => self.handle_overlay_dismiss(key, KeyCode::Char('i')),
            Mode::Picker => self.handle_picker(key, forwards).await,
            Mode::Normal => self.handle_normal(key, forwards).await,
        }
    }

    async fn handle_normal(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        let ctrl_c =
            key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
        if ctrl_c {
            return Action::Quit;
        }
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Esc => {
                // Esc clears an active filter first; only quits when there's
                // nothing to back out of.
                if self.filter.is_empty() {
                    return Action::Quit;
                }
                self.filter.clear();
            }
            KeyCode::Char('a') => {
                self.mode = Mode::AddInput;
                self.input.clear();
                self.message = None;
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.selected_row().is_some() {
                    self.mode = Mode::ConfirmDrop;
                    self.message = None;
                }
            }
            KeyCode::Char('v') => {
                if self.reverse_selected() {
                    self.message =
                        Some("reverse visibility is set by its bind address at add time".into());
                } else {
                    self.toggle_visibility(forwards).await;
                }
            }
            KeyCode::Char('o') | KeyCode::Enter => {
                if self.reverse_selected() {
                    self.message = Some("open/copy apply to forwards only".into());
                } else {
                    self.open_selected();
                }
            }
            KeyCode::Char('y') => {
                if self.reverse_selected() {
                    self.message = Some("open/copy apply to forwards only".into());
                } else {
                    self.copy_selected();
                }
            }
            KeyCode::Char('i') => {
                if self.selected_row().is_some() {
                    self.mode = Mode::Detail;
                }
            }
            KeyCode::Char('f') => {
                self.picker.select(Some(0));
                self.mode = Mode::Picker;
                self.message = None;
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
                self.message = None;
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::PageUp => self.log_scroll = self.log_scroll.saturating_add(4),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(4),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            _ => {}
        }
        Action::Continue
    }

    /// Live substring filter: typing updates the view immediately. `Enter` keeps
    /// the filter and returns to browsing; `Esc` clears it.
    fn handle_filter(&mut self, key: crossterm::event::KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => self.mode = Mode::Normal,
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) => self.filter.push(c),
            _ => {}
        }
        Action::Continue
    }

    async fn handle_confirm_drop(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => self.drop_selected(forwards).await,
            _ => self.message = Some("drop cancelled".into()),
        }
        self.mode = Mode::Normal;
        Action::Continue
    }

    /// Dismiss a non-interactive overlay (help, detail): `Esc`, `q`, or the
    /// toggle key that opened it returns to browsing.
    fn handle_overlay_dismiss(
        &mut self,
        key: crossterm::event::KeyEvent,
        toggle: KeyCode,
    ) -> Action {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) || key.code == toggle {
            self.mode = Mode::Normal;
        }
        Action::Continue
    }

    async fn handle_picker(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Char('f') | KeyCode::Char('q') => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') => self.move_picker(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_picker(-1),
            KeyCode::Enter => self.forward_picked(forwards).await,
            _ => {}
        }
        Action::Continue
    }

    async fn handle_add_input(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.input.clear();
            }
            KeyCode::Enter => {
                let spec = self.input.trim().to_string();
                self.mode = Mode::Normal;
                self.input.clear();
                if spec.is_empty() {
                    return Action::Continue;
                }
                self.add_forward(&spec, forwards).await;
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
        Action::Continue
    }

    async fn add_forward(&mut self, spec: &str, forwards: &Arc<ForwardSet>) {
        // A leading `-R` (mirroring the CLI's `--reverse`) requests a reverse
        // forward; otherwise the spec is a normal forward. Both grammars use
        // `->`, so the flag is what disambiguates them.
        if let Some(rest) = reverse_flag_rest(spec) {
            self.add_reverse(rest).await;
            return;
        }
        let parsed: ForwardSpec = match spec.parse() {
            Ok(p) => p,
            Err(e) => {
                self.message = Some(format!("invalid spec {spec:?}: {e}"));
                return;
            }
        };
        match forwards.add(parsed, Origin::UserAdded).await {
            Ok(local) => self.message = Some(format!("forwarding on {local}")),
            Err(e) => self.message = Some(format!("add failed: {e:#}")),
        }
    }

    async fn add_reverse(&mut self, spec: &str) {
        let parsed: ReverseSpec = match spec.parse() {
            Ok(p) => p,
            Err(e) => {
                self.message = Some(format!("invalid reverse spec {spec:?}: {e}"));
                return;
            }
        };
        let bind = format!("{}:{}", parsed.remote_bind_addr, parsed.remote_bind_port);
        match self.reverse_set.add(parsed, Origin::UserAdded).await {
            Ok(()) => self.message = Some(format!("reverse forward bound on remote {bind}")),
            Err(e) => self.message = Some(format!("reverse add failed: {e:#}")),
        }
    }

    async fn drop_selected(&mut self, forwards: &Arc<ForwardSet>) {
        match self.selected_row() {
            Some(Selection::Forward(snap)) => {
                let port = snap.local.port();
                match forwards.remove(port).await {
                    Ok(spec) => {
                        self.message = Some(format!("dropped {}", control::display_spec(&spec)))
                    }
                    Err(e) => self.message = Some(format!("drop failed: {e:#}")),
                }
            }
            Some(Selection::Reverse(snap)) => {
                let spec = snap.spec.to_spec_string();
                match self.reverse_set.remove(&spec).await {
                    Ok(dropped) => {
                        self.message = Some(format!("dropped reverse {}", dropped.to_spec_string()))
                    }
                    Err(e) => self.message = Some(format!("drop failed: {e:#}")),
                }
            }
            None => {}
        }
    }

    /// Open the selected forward's local endpoint in the default web browser
    /// (VSCode's globe icon). We always dial loopback — even an exposed forward
    /// is reachable there — and assume `http`, the common case for a forwarded
    /// dev server.
    fn open_selected(&mut self) {
        let Some(snap) = self.selected() else { return };
        if snap.spec.is_socks() {
            // A SOCKS endpoint isn't an http URL; point the user at the proxy
            // address instead of launching a browser.
            self.message = Some(format!(
                "SOCKS proxy at socks5://127.0.0.1:{} (press 'y' to copy)",
                snap.local.port()
            ));
            return;
        }
        let url = forward_url(snap.local.port());
        self.message = Some(match open_in_browser(&url) {
            Ok(()) => format!("opening {url}"),
            Err(e) => format!("could not open browser: {e}"),
        });
    }

    /// Copy the selected forward's loopback URL to the system clipboard. For a
    /// SOCKS proxy this is a `socks5://` proxy address rather than an http URL.
    fn copy_selected(&mut self) {
        let Some(snap) = self.selected() else { return };
        let url = if snap.spec.is_socks() {
            format!("socks5://127.0.0.1:{}", snap.local.port())
        } else {
            forward_url(snap.local.port())
        };
        self.message = Some(match copy_to_clipboard(&url) {
            Ok(()) => format!("copied {url}"),
            Err(e) => format!("clipboard unavailable: {e}"),
        });
    }

    /// Forward the discovered port currently selected in the picker, building its
    /// spec the same way auto-forward does ([`spec_for_listener`]) and binding it
    /// through the shared [`ForwardSet`] as a user-added forward.
    async fn forward_picked(&mut self, forwards: &Arc<ForwardSet>) {
        let picked = {
            let discovered = self.discovered_unforwarded();
            let idx = self.picker.selected().unwrap_or(0);
            discovered.get(idx).map(|l| (*l).clone())
        };
        let Some(l) = picked else {
            self.mode = Mode::Normal;
            return;
        };
        match spec_for_listener(&l) {
            Ok(spec) => match forwards.add(spec, Origin::UserAdded).await {
                Ok(local) => self.message = Some(format!("forwarding {} on {local}", l.port)),
                Err(e) => self.message = Some(format!("add failed: {e:#}")),
            },
            Err(e) => self.message = Some(format!("cannot forward {}:{}: {e:#}", l.ns, l.port)),
        }
        self.mode = Mode::Normal;
    }

    /// Rebind the selected forward with its local bind address flipped between
    /// loopback (private) and `0.0.0.0` (exposed), pinning the bound port. On
    /// failure, restore the original binding.
    async fn toggle_visibility(&mut self, forwards: &Arc<ForwardSet>) {
        let Some(snap) = self.selected() else { return };
        if snap.spec.is_socks() {
            self.message = Some("SOCKS proxy stays loopback (no expose)".into());
            return;
        }
        let port = snap.local.port();
        let origin = snap.origin;
        let original = snap.spec.clone();

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let exposed = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let new_addr = if original.local_addr == loopback {
            exposed
        } else {
            loopback
        };
        let mut new_spec = original.clone();
        new_spec.local_addr = new_addr;
        new_spec.local_port = port;
        new_spec.local_port_auto = false;

        if let Err(e) = forwards.remove(port).await {
            self.message = Some(format!("toggle failed: {e:#}"));
            return;
        }
        match forwards.add(new_spec, origin).await {
            Ok(local) => {
                let vis = if new_addr == loopback {
                    "private"
                } else {
                    "exposed"
                };
                self.message = Some(format!("{local} now {vis}"));
            }
            Err(e) => {
                // Re-add the original so the forward isn't lost.
                let restored = forwards.add(original, origin).await;
                self.message = Some(match restored {
                    Ok(_) => format!("toggle failed (kept original): {e:#}"),
                    Err(e2) => format!("toggle failed and restore failed: {e:#}; {e2:#}"),
                });
            }
        }
    }

    // --- rendering -------------------------------------------------------

    fn draw(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // header
                Constraint::Min(3),    // table
                Constraint::Length(8), // log pane
                Constraint::Length(1), // footer
            ])
            .split(f.area());

        self.draw_header(f, chunks[0]);
        self.draw_table(f, chunks[1]);
        self.draw_logs(f, chunks[2]);
        self.draw_footer(f, chunks[3]);

        // Modal overlays draw on top of the base view.
        match self.mode {
            Mode::Help => self.draw_help(f),
            Mode::Detail => self.draw_detail(f),
            Mode::Picker => self.draw_picker(f),
            _ => {}
        }
    }

    fn draw_header(&self, f: &mut ratatui::Frame, area: Rect) {
        let (state, color) = match &self.status {
            Status::Connected => ("connected".to_string(), Color::Green),
            Status::Reconnecting { attempt } => {
                (format!("reconnecting (attempt {attempt})"), Color::Yellow)
            }
            Status::Bootstrapping => ("bootstrapping".to_string(), Color::Yellow),
        };
        let agent = if self.agent_version.is_empty() {
            String::new()
        } else {
            format!("  agent v{}", self.agent_version)
        };
        // The transport is the single biggest performance difference in the
        // session, so name it in the header instead of leaving it implicit.
        let transport = if self.via_ssh {
            Span::styled(
                "  SSH TUNNEL — not QUIC",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("  quic", Style::default().fg(Color::DarkGray))
        };
        let line = Line::from(vec![
            Span::styled(
                format!("portmanager  {}  ", self.host),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(state, Style::default().fg(color)),
            Span::raw(agent),
            transport,
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn draw_table(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let proc_by_target = self.process_index();
        let connected = self.connected;

        // Build owned rows from the filtered view, then drop the borrow so the
        // stateful render can take `&mut self.table`.
        let mut rows: Vec<Row> = {
            let visible = self.visible();
            visible
                .iter()
                .map(|s| {
                    let ns = s.spec.ns.to_wire();
                    let ns_disp = if ns.is_empty() {
                        "host".to_string()
                    } else {
                        ns.clone()
                    };
                    let process = proc_by_target
                        .get(&(ns, s.spec.remote_port))
                        .cloned()
                        .unwrap_or_else(|| "—".to_string());
                    let visibility = if s.spec.local_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
                        "private".to_string()
                    } else {
                        format!("exposed ({})", s.spec.local_addr)
                    };
                    let rate = self
                        .throughput
                        .get(&s.local.port())
                        .map(|t| fmt_rate(t.rate_up + t.rate_down))
                        .unwrap_or_else(|| "idle".to_string());
                    let forwarded = if s.spec.is_socks() {
                        "socks5 (dynamic)".to_string()
                    } else {
                        format!("{}:{}", s.spec.remote_host, s.spec.remote_port)
                    };
                    Row::new(vec![
                        Cell::from(format!("→ {}", s.local.port())),
                        Cell::from(forwarded),
                        Cell::from(process),
                        Cell::from(ns_disp),
                        Cell::from(visibility),
                        Cell::from(s.origin.label()),
                        Cell::from(rate),
                        Cell::from(control::health_label(connected, s)),
                    ])
                })
                .collect()
        };
        let forward_count = rows.len();

        // Reverse forwards (ssh -R) are appended as non-selectable rows: the data
        // direction is inverted (the agent binds the remote port, the client
        // dials the local target), so the Port column shows the remote bind and
        // the address column the local target. Hidden while a filter is active
        // (the filter only matches forwards). Their cells are dimmed to read as a
        // distinct, read-only section.
        if self.filter.is_empty() {
            let dim = Style::default().add_modifier(Modifier::DIM);
            for s in &self.reverse {
                let ns = s.spec.ns.to_wire();
                let ns_disp = if ns.is_empty() {
                    "host".to_string()
                } else {
                    ns.clone()
                };
                let visibility = if s.spec.remote_bind_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
                    "private".to_string()
                } else {
                    format!("exposed ({})", s.spec.remote_bind_addr)
                };
                rows.push(
                    Row::new(vec![
                        Cell::from(format!("← {}", s.spec.remote_bind_port)),
                        Cell::from(format!("{}:{}", s.spec.local_host, s.spec.local_port)),
                        Cell::from("—"),
                        Cell::from(ns_disp),
                        Cell::from(visibility),
                        Cell::from(s.origin.label()),
                        Cell::from("—"),
                        Cell::from(control::reverse_health_label(connected, s)),
                    ])
                    .style(dim),
                );
            }
        }
        let count = rows.len();

        let header = Row::new(vec![
            "Port",
            "Forwarded Address",
            "Running Process",
            "Namespace",
            "Visibility",
            "Origin",
            "Rate",
            "Health",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

        let widths = [
            Constraint::Length(7),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Min(18),
        ];

        let rev = self.reverse.len();
        let rev_suffix = if rev > 0 && self.filter.is_empty() {
            format!(" · reverse ({rev})")
        } else {
            String::new()
        };
        let title = if self.filter.is_empty() {
            format!(" forwards ({forward_count}){rev_suffix} ")
        } else {
            format!(" forwards ({forward_count}, filter {:?}) ", self.filter)
        };
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title.clone()))
            .row_highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        if count == 0 {
            let hint = if self.forwards.is_empty() {
                "No forwards yet. Press 'a' to add one (e.g. 8888), or 'f' to pick a discovered port."
            } else {
                "No forwards match the filter. Press Esc to clear it."
            };
            let empty =
                Paragraph::new(hint).block(Block::default().borders(Borders::ALL).title(title));
            f.render_widget(empty, area);
        } else {
            f.render_stateful_widget(table, area, &mut self.table);
        }
    }

    /// `(ns wire, remote port) -> "name (pid)"` from the discovery snapshot.
    fn process_index(&self) -> HashMap<(String, u16), String> {
        let mut map = HashMap::new();
        for l in &self.listeners {
            if let Some(p) = &l.process {
                map.entry((l.ns.clone(), l.port))
                    .or_insert_with(|| format!("{} ({})", p.name, p.pid));
            }
        }
        map
    }

    fn draw_logs(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let inner = area.height.saturating_sub(2) as usize; // borders
        let len = self.logs.len();
        let max_scroll = len.saturating_sub(inner);
        // Clamp the stored offset so PgDn always reaches the tail again.
        self.log_scroll = self.log_scroll.min(max_scroll);
        let end = len - self.log_scroll;
        let start = end.saturating_sub(inner);
        let text: Vec<Line> = self.logs[start..end]
            .iter()
            .map(|l| Line::from(l.as_str()))
            .collect();
        let title = if self.log_scroll > 0 {
            format!(" log (scrolled +{}, PgDn to follow) ", self.log_scroll)
        } else {
            " log ".to_string()
        };
        let logs = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(logs, area);
    }

    fn draw_footer(&self, f: &mut ratatui::Frame, area: Rect) {
        let cyan = Style::default().fg(Color::Cyan);
        let yellow = Style::default().fg(Color::Yellow);
        let dim = Style::default().fg(Color::DarkGray);
        let cursor = Span::styled("▏", Style::default().add_modifier(Modifier::SLOW_BLINK));
        let line = match self.mode {
            Mode::AddInput => Line::from(vec![
                Span::styled("add forward (-R for reverse): ", cyan),
                Span::raw(&self.input),
                cursor,
            ]),
            Mode::Filter => Line::from(vec![
                Span::styled("filter: ", cyan),
                Span::raw(&self.filter),
                cursor,
            ]),
            Mode::ConfirmDrop => {
                let what = match self.selected_row() {
                    Some(Selection::Forward(s)) => format!("port {}", s.local.port()),
                    Some(Selection::Reverse(s)) => {
                        format!("reverse R:{}", s.spec.remote_bind_port)
                    }
                    None => "selection".into(),
                };
                Line::from(Span::styled(format!("drop {what}? (y/n)"), yellow))
            }
            Mode::Picker => Line::from(Span::styled("↑/↓ select  enter forward  esc/f close", dim)),
            Mode::Help | Mode::Detail => Line::from(Span::styled("esc/q to close", dim)),
            Mode::Normal => {
                if let Some(msg) = &self.message {
                    Line::from(Span::styled(msg.as_str(), yellow))
                } else {
                    Line::from(Span::styled(
                        "a add  d drop  o open  y copy  i detail  v vis  f find  / filter  ? help  q quit",
                        dim,
                    ))
                }
            }
        };
        f.render_widget(Paragraph::new(line), area);
    }

    /// Centered keybinding reference.
    fn draw_help(&self, f: &mut ratatui::Frame) {
        let area = centered_rect(60, 70, f.area());
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" keybindings ");
        let rows = [
            ("a", "add a forward (spec, Enter; prefix -R for reverse)"),
            (
                "d / Del",
                "drop the selected row, forward or reverse (confirm)",
            ),
            ("o / Enter", "open the forward in a browser (forwards only)"),
            (
                "y",
                "copy the forward's URL to the clipboard (forwards only)",
            ),
            ("i", "inspect the selected row (detail + throughput)"),
            ("v", "toggle visibility, private ↔ exposed (forwards only)"),
            ("f", "find: pick a discovered port to forward"),
            ("/", "filter the table (Esc clears)"),
            ("PgUp / PgDn", "scroll the log pane"),
            ("↑/↓ or k/j", "move the selection"),
            ("? ", "toggle this help"),
            ("q", "quit"),
        ];
        let lines: Vec<Line> = rows
            .iter()
            .map(|(k, d)| {
                Line::from(vec![
                    Span::styled(format!("{k:>12}  "), Style::default().fg(Color::Cyan)),
                    Span::raw(*d),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    /// Centered detail card for the selected row, dispatching on its direction.
    fn draw_detail(&self, f: &mut ratatui::Frame) {
        match self.selected_row() {
            Some(Selection::Forward(snap)) => self.draw_forward_detail(f, &snap),
            Some(Selection::Reverse(snap)) => self.draw_reverse_detail(f, &snap),
            None => {}
        }
    }

    /// Centered detail card for a forward: full spec, health, the untruncated
    /// last error, and a live throughput sparkline.
    fn draw_forward_detail(&self, f: &mut ratatui::Frame, snap: &ForwardSnapshot) {
        let area = centered_rect(72, 80, f.area());
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" forward :{} ", snap.local.port()));
        let inner = block.inner(area);
        f.render_widget(block, area);

        // Info first (at least the 8 fixed fields plus an optional error line),
        // throughput sparkline pinned to a fixed height below it.
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(9), Constraint::Length(5)])
            .split(inner);

        let tp = self.throughput.get(&snap.local.port());
        let (ru, rd) = tp.map(|t| (t.rate_up, t.rate_down)).unwrap_or((0.0, 0.0));
        let ns = snap.spec.ns.to_wire();
        let ns_disp = if ns.is_empty() { "host" } else { &ns };
        let field = |k: &str, v: String| {
            Line::from(vec![
                Span::styled(format!("{k:<9}"), Style::default().fg(Color::Cyan)),
                Span::raw(v),
            ])
        };
        let mut lines = vec![
            field("spec:", control::display_spec(&snap.spec)),
            field("local:", snap.local.to_string()),
            field(
                "target:",
                if snap.spec.is_socks() {
                    "socks5 (dynamic, per-connection)".to_string()
                } else {
                    format!("{}:{}", snap.spec.remote_host, snap.spec.remote_port)
                },
            ),
            field("ns:", ns_disp.to_string()),
            field("origin:", snap.origin.label().to_string()),
            field("conns:", snap.ok_connections.to_string()),
            field(
                "up:",
                format!("{} ({})", fmt_bytes(snap.bytes_up), fmt_rate(ru)),
            ),
            field(
                "down:",
                format!("{} ({})", fmt_bytes(snap.bytes_down), fmt_rate(rd)),
            ),
        ];
        if let Some(err) = &snap.last_error {
            lines.push(Line::from(vec![
                Span::styled("error:   ", Style::default().fg(Color::Red)),
                Span::styled(err.clone(), Style::default().fg(Color::Red)),
            ]));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), parts[0]);

        let spark: Vec<u64> = tp
            .map(|t| t.history.iter().copied().collect())
            .unwrap_or_default();
        let sparkline = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" throughput (bytes/interval) "),
            )
            .data(&spark)
            .style(Style::default().fg(Color::Green));
        f.render_widget(sparkline, parts[1]);
    }

    /// Centered detail card for a reverse forward. No throughput sparkline —
    /// reverse rates aren't sampled — but cumulative byte counts and health are
    /// shown.
    fn draw_reverse_detail(&self, f: &mut ratatui::Frame, snap: &ReverseSnapshot) {
        let area = centered_rect(72, 80, f.area());
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" reverse R:{} ", snap.spec.remote_bind_port));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let ns = snap.spec.ns.to_wire();
        let ns_disp = if ns.is_empty() { "host" } else { &ns };
        let field = |k: &str, v: String| {
            Line::from(vec![
                Span::styled(format!("{k:<13}"), Style::default().fg(Color::Cyan)),
                Span::raw(v),
            ])
        };
        let mut lines = vec![
            field("spec:", snap.spec.to_spec_string()),
            field(
                "remote bind:",
                format!(
                    "{}:{}",
                    snap.spec.remote_bind_addr, snap.spec.remote_bind_port
                ),
            ),
            field(
                "local target:",
                format!("{}:{}", snap.spec.local_host, snap.spec.local_port),
            ),
            field("ns:", ns_disp.to_string()),
            field("origin:", snap.origin.label().to_string()),
            field("conns:", snap.ok_connections.to_string()),
            field("to remote:", fmt_bytes(snap.bytes_down)),
            field("from remote:", fmt_bytes(snap.bytes_up)),
        ];
        if let Some(err) = &snap.last_error {
            lines.push(Line::from(vec![
                Span::styled("error:       ", Style::default().fg(Color::Red)),
                Span::styled(err.clone(), Style::default().fg(Color::Red)),
            ]));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
    }

    /// Centered picker of discovered-but-unforwarded ports.
    fn draw_picker(&mut self, f: &mut ratatui::Frame) {
        let area = centered_rect(80, 70, f.area());
        f.render_widget(Clear, area);

        let rows: Vec<Row> = {
            let discovered = self.discovered_unforwarded();
            discovered
                .iter()
                .map(|l| {
                    let ns = if l.ns.is_empty() {
                        "host".to_string()
                    } else {
                        l.ns.clone()
                    };
                    let process = l
                        .process
                        .as_ref()
                        .map(|p| format!("{} ({})", p.name, p.pid))
                        .unwrap_or_else(|| "—".to_string());
                    Row::new(vec![
                        Cell::from(ns),
                        Cell::from(format!("{}:{}", l.ip, l.port)),
                        Cell::from(process),
                    ])
                })
                .collect()
        };
        let count = rows.len();

        let header = Row::new(vec!["Namespace", "Address", "Process"])
            .style(Style::default().add_modifier(Modifier::BOLD))
            .bottom_margin(1);
        let widths = [
            Constraint::Length(16),
            Constraint::Length(24),
            Constraint::Min(20),
        ];
        let title = format!(" discovered ports ({count}) ");
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title.clone()))
            .row_highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        if count == 0 {
            let empty = Paragraph::new(
                "No unforwarded ports detected. Listeners appear here as discovery sees them.",
            )
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(title));
            f.render_widget(empty, area);
        } else {
            f.render_stateful_widget(table, area, &mut self.picker);
        }
    }
}

// --- terminal lifecycle --------------------------------------------------

fn setup_terminal() -> Result<Term> {
    enable_raw_mode().context("entering raw mode")?;
    let mut stdout = io::stdout();
    stdout
        .execute(EnterAlternateScreen)
        .context("entering alternate screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("building terminal")
}

/// Restores the terminal when the TUI returns by any path (including `?`).
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Restore the terminal before a panic prints, so the backtrace is readable and
/// the user's shell isn't left in raw mode.
fn install_panic_hook() {
    use std::sync::Once;
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            original(info);
        }));
    });
}

// --- open in browser -----------------------------------------------------

/// The local URL for a forward bound on `local_port`. Always loopback (reachable
/// for both private and exposed forwards) and `http`, the common dev-server case.
fn forward_url(local_port: u16) -> String {
    format!("http://127.0.0.1:{local_port}")
}

/// If `input` begins with a `-R`/`--reverse` flag (the CLI's reverse marker),
/// return the trimmed remainder — the reverse spec. Returns `None` when no such
/// flag is present, so the input is a normal forward spec.
fn reverse_flag_rest(input: &str) -> Option<&str> {
    let trimmed = input.trim_start();
    for flag in ["--reverse", "-R", "-r"] {
        if let Some(rest) = trimmed.strip_prefix(flag) {
            // Require the flag to be a whole token (followed by whitespace or
            // end), so `-Rfoo` or a spec like `r->...` isn't misread.
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                return Some(rest.trim());
            }
        }
    }
    None
}

/// Hand `url` to the platform's default-application opener, detached. Returns an
/// error if the opener can't be spawned (e.g. headless host with no `xdg-open`).
fn open_in_browser(url: &str) -> Result<()> {
    use std::process::Stdio;

    let mut cmd = browser_command(url);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("launching browser opener for {url}"))?;
    Ok(())
}

/// Build the per-OS command that opens a URL in the default browser.
fn browser_command(url: &str) -> std::process::Command {
    let mut cmd;
    if cfg!(target_os = "macos") {
        cmd = std::process::Command::new("open");
        cmd.arg(url);
    } else if cfg!(target_os = "windows") {
        // `start` is a cmd builtin; the empty title arg keeps a quoted URL from
        // being treated as the window title.
        cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "start", "", url]);
    } else {
        cmd = std::process::Command::new("xdg-open");
        cmd.arg(url);
    }
    cmd
}

// --- clipboard -----------------------------------------------------------

/// Pipe `text` into the platform clipboard helper's stdin. Returns an error if
/// the helper can't be spawned (e.g. no `pbcopy`/`xclip` on the host).
fn copy_to_clipboard(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = clipboard_command()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning clipboard helper")?;
    child
        .stdin
        .take()
        .context("clipboard helper has no stdin")?
        .write_all(text.as_bytes())
        .context("writing to clipboard helper")?;
    let status = child.wait().context("waiting for clipboard helper")?;
    if !status.success() {
        anyhow::bail!("clipboard helper exited with {status}");
    }
    Ok(())
}

/// The per-OS command that reads clipboard contents from stdin.
fn clipboard_command() -> std::process::Command {
    if cfg!(target_os = "macos") {
        std::process::Command::new("pbcopy")
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("clip")
    } else {
        // X11's xclip is the most common; Wayland users typically have an
        // `xclip`-compatible shim or can alias wl-copy.
        let mut cmd = std::process::Command::new("xclip");
        cmd.args(["-selection", "clipboard"]);
        cmd
    }
}

// --- formatting & layout helpers -----------------------------------------

/// Human-readable byte count (binary units).
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Human-readable transfer rate, or `idle` below 1 byte/sec.
fn fmt_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "idle".to_string();
    }
    format!("{}/s", fmt_bytes(bytes_per_sec as u64))
}

/// A `Rect` centered within `r`, sized to the given percentage of each axis.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::discovery::ListenerProc;

    fn snapshot(spec: &str, local: &str, origin: Origin) -> ForwardSnapshot {
        ForwardSnapshot {
            spec: spec.parse().unwrap(),
            local: local.parse::<SocketAddr>().unwrap(),
            origin,
            ok_connections: 0,
            last_error: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn reverse_flag_detected_only_as_whole_token() {
        assert_eq!(reverse_flag_rest("-R 3000->3000"), Some("3000->3000"));
        assert_eq!(reverse_flag_rest("--reverse 8080->80"), Some("8080->80"));
        assert_eq!(reverse_flag_rest("  -R  3000->3000  "), Some("3000->3000"));
        // No flag: a normal forward spec passes through untouched.
        assert_eq!(reverse_flag_rest("3000->3000"), None);
        // The flag must be its own token, not glued to the spec.
        assert_eq!(reverse_flag_rest("-R3000->3000"), None);
    }

    #[tokio::test]
    async fn reverse_row_is_selectable_and_droppable() {
        let reverse_set = Arc::new(ReverseSet::new());
        reverse_set
            .add("3000->3000".parse().unwrap(), Origin::UserAdded)
            .await
            .unwrap();
        let mut app = App::new("h".into(), reverse_set.clone());
        app.status = Status::Connected;
        app.connected = true;
        app.forwards = vec![snapshot("8888", "127.0.0.1:8888", Origin::UserAdded)];
        app.reverse = reverse_set.list().await;

        // The reverse row renders as a dimmed `← R:<port>` row.
        let text = render(&mut app, 140, 24);
        assert!(text.contains("← 3000"), "reverse row missing: {text}");

        // Selection spans both rows; index 1 is the reverse forward.
        assert_eq!(app.selectable_len(), 2);
        app.table.select(Some(1));
        assert!(
            app.reverse_selected(),
            "row 1 should be the reverse forward"
        );
        assert!(matches!(app.selected_row(), Some(Selection::Reverse(_))));
        // The forward-only accessor is None on a reverse row.
        assert!(app.selected().is_none());

        // Dropping the selected reverse row removes it from the set.
        let forwards = Arc::new(ForwardSet::new(crate::client::conn_slot(None).1));
        app.drop_selected(&forwards).await;
        assert!(
            reverse_set.is_empty().await,
            "reverse forward should be dropped"
        );
    }

    #[test]
    fn header_names_the_transport() {
        // The SSH tunnel is much slower than QUIC and is remembered per host,
        // so a tunnelled session has to say so rather than looking identical.
        let mut app = App::new("myhost".into(), Arc::new(ReverseSet::new()));
        app.status = Status::Connected;
        app.connected = true;

        let text = render(&mut app, 140, 24);
        assert!(
            text.contains("quic"),
            "direct session should name QUIC: {text}"
        );
        assert!(
            !text.contains("SSH TUNNEL"),
            "direct session must not warn: {text}"
        );

        app.via_ssh = true;
        let text = render(&mut app, 140, 24);
        assert!(
            text.contains("SSH TUNNEL — not QUIC"),
            "tunnelled session must say so plainly: {text}"
        );
    }

    #[test]
    fn renders_columns_and_joins_process() {
        let mut app = App::new("myhost".into(), Arc::new(ReverseSet::new()));
        app.status = Status::Connected;
        app.connected = true;
        app.agent_version = "0.1.0".into();
        app.forwards = vec![snapshot("8888", "127.0.0.1:8888", Origin::UserAdded)];
        // Discovery says pid 42 ("nginx") owns host:8888 — must fill the column.
        app.listeners = vec![Listener {
            ns: String::new(),
            ip: "0.0.0.0".into(),
            port: 8888,
            process: Some(ListenerProc {
                pid: 42,
                name: "nginx".into(),
            }),
        }];

        let text = render(&mut app, 140, 24);
        assert!(text.contains("Running Process"), "header missing: {text}");
        assert!(text.contains("Forwarded Address"));
        assert!(text.contains("nginx (42)"), "process join missing: {text}");
        assert!(text.contains("private"), "loopback should read private");
        assert!(text.contains("user"), "origin column missing");
        assert!(text.contains("connected"), "session state missing");
    }

    #[test]
    fn exposed_forward_reads_exposed() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        app.forwards = vec![snapshot(
            "8080->0.0.0.0:8080",
            "0.0.0.0:8080",
            Origin::Remembered,
        )];
        let text = render(&mut app, 140, 24);
        assert!(
            text.contains("exposed"),
            "0.0.0.0 bind should read exposed: {text}"
        );
        assert!(text.contains("remembered"));
    }

    #[test]
    fn empty_session_shows_hint() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        let text = render(&mut app, 100, 20);
        assert!(
            text.contains("Press 'a' to add"),
            "empty hint missing: {text}"
        );
    }

    #[test]
    fn forward_url_is_loopback_http() {
        assert_eq!(forward_url(8888), "http://127.0.0.1:8888");
    }

    #[test]
    fn socks_forward_renders_as_dynamic() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        app.forwards = vec![snapshot("socks->1080", "127.0.0.1:1080", Origin::UserAdded)];
        let text = render(&mut app, 140, 20);
        assert!(
            text.contains("socks5 (dynamic)"),
            "socks row should read dynamic: {text}"
        );
    }

    #[test]
    fn help_overlay_lists_keys() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        app.mode = Mode::Help;
        let text = render(&mut app, 100, 30);
        assert!(text.contains("keybindings"), "help title missing: {text}");
        assert!(text.contains("copy"), "copy key missing: {text}");
        assert!(text.contains("filter"), "filter key missing: {text}");
    }

    #[test]
    fn confirm_drop_prompts_before_dropping() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        app.forwards = vec![snapshot("8888", "127.0.0.1:8888", Origin::UserAdded)];
        app.mode = Mode::ConfirmDrop;
        let text = render(&mut app, 100, 20);
        assert!(
            text.contains("drop port 8888?"),
            "confirm prompt missing: {text}"
        );
    }

    #[test]
    fn filter_hides_non_matching_rows() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        app.forwards = vec![
            snapshot("8888", "127.0.0.1:8888", Origin::UserAdded),
            snapshot("5432", "127.0.0.1:5432", Origin::UserAdded),
        ];
        app.filter = "5432".into();
        assert_eq!(app.visible().len(), 1, "filter should keep one row");
        let text = render(&mut app, 140, 20);
        assert!(text.contains("5432"), "matching row missing: {text}");
        assert!(
            !text.contains("8888"),
            "non-matching row should be hidden: {text}"
        );
    }

    #[test]
    fn detail_pane_shows_full_error_and_bytes() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        let mut snap = snapshot("8888", "127.0.0.1:8888", Origin::UserAdded);
        snap.bytes_up = 2048;
        snap.last_error = Some("connection refused dialing target".into());
        app.forwards = vec![snap];
        app.mode = Mode::Detail;
        let text = render(&mut app, 100, 24);
        assert!(
            text.contains("forward :8888"),
            "detail title missing: {text}"
        );
        assert!(text.contains("2.0 KiB"), "byte count missing: {text}");
        assert!(
            text.contains("connection refused"),
            "untruncated error missing: {text}"
        );
    }

    #[test]
    fn picker_lists_unforwarded_and_hides_forwarded() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        // 8888 is already forwarded; 9000 is not.
        app.forwards = vec![snapshot("8888", "127.0.0.1:8888", Origin::UserAdded)];
        app.listeners = vec![
            Listener {
                ns: String::new(),
                ip: "0.0.0.0".into(),
                port: 8888,
                process: None,
            },
            Listener {
                ns: String::new(),
                ip: "0.0.0.0".into(),
                port: 9000,
                process: Some(ListenerProc {
                    pid: 7,
                    name: "api".into(),
                }),
            },
        ];
        assert_eq!(app.discovered_unforwarded().len(), 1);
        app.mode = Mode::Picker;
        let text = render(&mut app, 100, 24);
        assert!(
            text.contains("discovered ports"),
            "picker title missing: {text}"
        );
        assert!(text.contains("9000"), "unforwarded port missing: {text}");
        assert!(text.contains("api (7)"), "process label missing: {text}");
    }

    #[test]
    fn throughput_rate_is_derived_between_samples() {
        let mut app = App::new("h".into(), Arc::new(ReverseSet::new()));
        let mut snap = snapshot("8888", "127.0.0.1:8888", Origin::UserAdded);
        app.forwards = vec![snap.clone()];
        let t0 = Instant::now();
        app.sample_throughput(t0); // baseline
        // Second sample one second later with 1000 more bytes up.
        snap.bytes_up = 1000;
        app.forwards = vec![snap];
        app.sample_throughput(t0 + Duration::from_secs(1));
        let tp = app.throughput.get(&8888).unwrap();
        assert!(
            (tp.rate_up - 1000.0).abs() < 1.0,
            "rate_up was {}",
            tp.rate_up
        );
        assert_eq!(tp.history.back().copied(), Some(1000));
    }

    #[test]
    fn fmt_bytes_and_rate_are_human_readable() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(fmt_rate(0.0), "idle");
        assert_eq!(fmt_rate(1024.0), "1.0 KiB/s");
    }

    #[test]
    fn clipboard_command_targets_a_known_helper() {
        let cmd = clipboard_command();
        let prog = cmd.get_program().to_string_lossy().to_string();
        assert!(
            ["pbcopy", "clip", "xclip"].contains(&prog.as_str()),
            "unexpected clipboard helper: {prog}"
        );
    }

    #[test]
    fn browser_command_targets_the_url() {
        let cmd = browser_command("http://127.0.0.1:8888");
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy()).collect();
        assert!(
            args.iter().any(|a| a == "http://127.0.0.1:8888"),
            "url should be passed to the opener: {args:?}"
        );
    }
}
