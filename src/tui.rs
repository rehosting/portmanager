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

use std::collections::HashMap;
use std::io::{self, Stdout};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

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
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use tokio::sync::{mpsc, watch};

use crate::client::{ForwardSet, ForwardSnapshot, Origin};
use crate::control;
use crate::discovery::Listener;
use crate::forward::ForwardSpec;
use crate::logbuf::LogBuffer;
use crate::supervisor::Status;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Run the TUI until the user quits or the session is stopped. Restores the
/// terminal on every exit path (normal, error, or panic).
pub async fn run(
    host: String,
    forward_set: Arc<ForwardSet>,
    mut status: watch::Receiver<Status>,
    agent_version: watch::Receiver<String>,
    log_buf: LogBuffer,
    discovery_snapshot: watch::Receiver<Vec<Listener>>,
    mut shutdown_rx: mpsc::UnboundedReceiver<()>,
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

    let mut app = App::new(host);
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    loop {
        // Refresh the view-model, then draw.
        app.forwards = forward_set.list().await;
        app.connected = matches!(*status.borrow(), Status::Connected);
        app.status = status.borrow().clone();
        app.agent_version = agent_version.borrow().clone();
        app.listeners = discovery_snapshot.borrow().clone();
        app.logs = log_buf.lock().unwrap().iter().cloned().collect();
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

/// Editing mode: browsing the table or typing a new forward spec.
enum Mode {
    Normal,
    AddInput,
}

struct App {
    host: String,
    forwards: Vec<ForwardSnapshot>,
    listeners: Vec<Listener>,
    logs: Vec<String>,
    status: Status,
    connected: bool,
    agent_version: String,
    table: TableState,
    mode: Mode,
    input: String,
    /// Transient feedback shown in the footer (errors, confirmations).
    message: Option<String>,
}

impl App {
    fn new(host: String) -> Self {
        let mut table = TableState::default();
        table.select(Some(0));
        App {
            host,
            forwards: Vec::new(),
            listeners: Vec::new(),
            logs: Vec::new(),
            status: Status::Bootstrapping,
            connected: false,
            agent_version: String::new(),
            table,
            mode: Mode::Normal,
            input: String::new(),
            message: None,
        }
    }

    /// Keep the selection within bounds as forwards come and go.
    fn clamp_selection(&mut self) {
        if self.forwards.is_empty() {
            self.table.select(None);
        } else {
            let max = self.forwards.len() - 1;
            let sel = self.table.selected().unwrap_or(0).min(max);
            self.table.select(Some(sel));
        }
    }

    fn selected(&self) -> Option<&ForwardSnapshot> {
        self.table.selected().and_then(|i| self.forwards.get(i))
    }

    fn move_selection(&mut self, delta: isize) {
        if self.forwards.is_empty() {
            return;
        }
        let len = self.forwards.len() as isize;
        let cur = self.table.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len);
        self.table.select(Some(next as usize));
    }

    async fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        forwards: &Arc<ForwardSet>,
    ) -> Action {
        match self.mode {
            Mode::AddInput => self.handle_add_input(key, forwards).await,
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
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('a') => {
                self.mode = Mode::AddInput;
                self.input.clear();
                self.message = None;
            }
            KeyCode::Char('d') | KeyCode::Delete => self.drop_selected(forwards).await,
            KeyCode::Char('v') => self.toggle_visibility(forwards).await,
            KeyCode::Char('o') | KeyCode::Enter => self.open_selected(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
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

    async fn drop_selected(&mut self, forwards: &Arc<ForwardSet>) {
        let Some(snap) = self.selected() else { return };
        let port = snap.local.port();
        match forwards.remove(port).await {
            Ok(spec) => self.message = Some(format!("dropped {}", control::display_spec(&spec))),
            Err(e) => self.message = Some(format!("drop failed: {e:#}")),
        }
    }

    /// Open the selected forward's local endpoint in the default web browser
    /// (VSCode's globe icon). We always dial loopback — even an exposed forward
    /// is reachable there — and assume `http`, the common case for a forwarded
    /// dev server.
    fn open_selected(&mut self) {
        let Some(snap) = self.selected() else { return };
        let url = forward_url(snap.local.port());
        self.message = Some(match open_in_browser(&url) {
            Ok(()) => format!("opening {url}"),
            Err(e) => format!("could not open browser: {e}"),
        });
    }

    /// Rebind the selected forward with its local bind address flipped between
    /// loopback (private) and `0.0.0.0` (exposed), pinning the bound port. On
    /// failure, restore the original binding.
    async fn toggle_visibility(&mut self, forwards: &Arc<ForwardSet>) {
        let Some(snap) = self.selected() else { return };
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
        let line = Line::from(vec![
            Span::styled(
                format!("portmanager  {}  ", self.host),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(state, Style::default().fg(color)),
            Span::raw(agent),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn draw_table(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let proc_by_target = self.process_index();
        let connected = self.connected;

        let rows: Vec<Row> = self
            .forwards
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
                Row::new(vec![
                    Cell::from(s.local.port().to_string()),
                    Cell::from(format!("{}:{}", s.spec.remote_host, s.spec.remote_port)),
                    Cell::from(process),
                    Cell::from(ns_disp),
                    Cell::from(visibility),
                    Cell::from(s.origin.label()),
                    Cell::from(control::health_label(connected, s)),
                ])
            })
            .collect();

        let header = Row::new(vec![
            "Port",
            "Forwarded Address",
            "Running Process",
            "Namespace",
            "Visibility",
            "Origin",
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
            Constraint::Min(20),
        ];

        let title = format!(" forwards ({}) ", self.forwards.len());
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title))
            .row_highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        if self.forwards.is_empty() {
            let empty = Paragraph::new("No forwards yet. Press 'a' to add one (e.g. 8888).").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" forwards (0) "),
            );
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

    fn draw_logs(&self, f: &mut ratatui::Frame, area: Rect) {
        let inner = area.height.saturating_sub(2) as usize; // borders
        let start = self.logs.len().saturating_sub(inner);
        let text: Vec<Line> = self.logs[start..]
            .iter()
            .map(|l| Line::from(l.as_str()))
            .collect();
        let logs =
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" log "));
        f.render_widget(logs, area);
    }

    fn draw_footer(&self, f: &mut ratatui::Frame, area: Rect) {
        let line = match self.mode {
            Mode::AddInput => Line::from(vec![
                Span::styled("add forward: ", Style::default().fg(Color::Cyan)),
                Span::raw(&self.input),
                Span::styled("▏", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]),
            Mode::Normal => {
                if let Some(msg) = &self.message {
                    Line::from(Span::styled(
                        msg.as_str(),
                        Style::default().fg(Color::Yellow),
                    ))
                } else {
                    Line::from(Span::styled(
                        "a add  d drop  o open  v visibility  ↑/↓ select  q quit",
                        Style::default().fg(Color::DarkGray),
                    ))
                }
            }
        };
        f.render_widget(Paragraph::new(line), area);
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
    fn renders_columns_and_joins_process() {
        let mut app = App::new("myhost".into());
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
        let mut app = App::new("h".into());
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
        let mut app = App::new("h".into());
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
    fn browser_command_targets_the_url() {
        let cmd = browser_command("http://127.0.0.1:8888");
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy()).collect();
        assert!(
            args.iter().any(|a| a == "http://127.0.0.1:8888"),
            "url should be passed to the opener: {args:?}"
        );
    }
}
