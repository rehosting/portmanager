//! Forward-spec grammar and the in-memory forward model.
//!
//! A forward spec describes one mapping: which remote target the agent should
//! dial (optionally inside a network namespace) and which local port the client
//! should listen on.
//!
//! Grammar (see the plan's "Forward spec grammar"):
//!
//! ```text
//! [NS@]REMOTE[->LOCALPORT]
//!
//! REMOTE   = [HOST:]PORT          ; HOST defaults to 127.0.0.1
//! NS       = podman:<name> | docker:<name> | pid:<n>
//!          | netns:<name> | nspath:<file>
//! ```
//!
//! Examples:
//! - `8888`                          -> dial 127.0.0.1:8888, prefer local 8888
//! - `192.168.4.2:8080->8080`        -> dial 192.168.4.2:8080, listen on 8080
//! - `podman:web@10.88.0.5:5432->5432` -> dial 10.88.0.5:5432 *inside* the
//!   `web` container's netns, listen on 5432
//!
//! When `->LOCALPORT` is omitted, the local port prefers the remote port and
//! falls back to an ephemeral free port if that local port is unavailable.
//!
//! When `NS@` is omitted, the spec dials in the session's **default namespace**
//! (`--ns`, or `portmanager ns <host> <ns>` on a live session) — the agent's own
//! namespace when no default is set. See [`ForwardSpec::parse_with_defaults`].

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::error::SpecError;

/// Selects the network namespace the agent dials *from*.
///
/// The default, [`NsSpec::Host`], dials in the agent's own namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsSpec {
    /// Agent's own (host) network namespace.
    Host,
    /// Resolve a rootless Podman container name to its PID, then enter it.
    Podman(String),
    /// Resolve a Docker container name to its PID, then enter it.
    Docker(String),
    /// Enter the namespaces of an explicit PID (`/proc/<pid>/ns/{user,net}`).
    Pid(i32),
    /// Enter a classic `ip netns` namespace (`/run/netns/<name>`). Rootful — v1
    /// parses it but rejects it at dial time (see plan: rootless-only for v1).
    Netns(String),
    /// Enter an explicit namespace file by path.
    NsPath(PathBuf),
}

impl NsSpec {
    /// Parse the portion before `@` into a namespace selector.
    fn parse(s: &str) -> Result<Self, SpecError> {
        let (kind, rest) = s.split_once(':').ok_or_else(|| {
            SpecError::BadNamespace(s.to_string(), "expected <kind>:<value>".into())
        })?;
        if rest.is_empty() {
            return Err(SpecError::BadNamespace(s.to_string(), "empty value".into()));
        }
        match kind {
            "podman" => Ok(NsSpec::Podman(rest.to_string())),
            "docker" => Ok(NsSpec::Docker(rest.to_string())),
            "pid" => {
                let pid = rest
                    .parse::<i32>()
                    .map_err(|e| SpecError::BadNamespace(s.to_string(), e.to_string()))?;
                Ok(NsSpec::Pid(pid))
            }
            "netns" => Ok(NsSpec::Netns(rest.to_string())),
            "nspath" => Ok(NsSpec::NsPath(PathBuf::from(rest))),
            other => Err(SpecError::BadNamespace(
                s.to_string(),
                format!("unknown namespace kind {other:?}"),
            )),
        }
    }

    /// Whether this selector requires entering a namespace at all.
    pub fn is_host(&self) -> bool {
        matches!(self, NsSpec::Host)
    }

    /// Whether this selector still means the same thing after the remote (or the
    /// workload inside it) restarts.
    ///
    /// Name- and path-based selectors are re-resolved on the remote at dial
    /// time, so they survive a restart. [`NsSpec::Pid`] does not: the pid is
    /// gone by the next session and pid reuse would silently dial from an
    /// unrelated process's namespace. Used to decide what may be *remembered*
    /// (see `config::HostState::parsed_default_ns`).
    pub fn is_stable(&self) -> bool {
        match self {
            NsSpec::Pid(_) => false,
            NsSpec::Host
            | NsSpec::Podman(_)
            | NsSpec::Docker(_)
            | NsSpec::Netns(_)
            | NsSpec::NsPath(_) => true,
        }
    }

    /// Canonical wire form, matching the CLI grammar. Empty string for the host
    /// namespace; otherwise `<kind>:<value>`.
    pub fn to_wire(&self) -> String {
        match self {
            NsSpec::Host => String::new(),
            NsSpec::Podman(n) => format!("podman:{n}"),
            NsSpec::Docker(n) => format!("docker:{n}"),
            NsSpec::Pid(p) => format!("pid:{p}"),
            NsSpec::Netns(n) => format!("netns:{n}"),
            NsSpec::NsPath(p) => format!("nspath:{}", p.display()),
        }
    }

    /// Parse a wire-form selector (the inverse of [`NsSpec::to_wire`]).
    pub fn from_wire(s: &str) -> Result<Self, SpecError> {
        if s.is_empty() {
            Ok(NsSpec::Host)
        } else {
            NsSpec::parse(s)
        }
    }
}

/// Whether a forward dials a fixed target or proxies dynamically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardKind {
    /// Dial the spec's `remote_host:remote_port` for every connection.
    #[default]
    Direct,
    /// A local SOCKS5 proxy: the target is taken from each connection's SOCKS
    /// handshake, so `remote_host`/`remote_port` are unused. Loopback-only.
    Socks,
}

/// One fully-parsed port forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Namespace the agent dials from.
    pub ns: NsSpec,
    /// Whether the spec named no namespace, so `ns` follows the session default
    /// (see [`ForwardSpec::parse_with_defaults`]) — including the "no default set,
    /// so [`NsSpec::Host`]" case. Mirrors `local_port_auto`: it records that the
    /// *spec* said nothing, so the short form is what gets persisted and a later
    /// `portmanager ns` may re-point the forward. Specs built from an observed
    /// listener (discovery) set this to `false`: their namespace is a fact, not a
    /// default.
    pub ns_inherited: bool,
    /// Remote host the agent connects to (resolved inside `ns`). Unused for
    /// [`ForwardKind::Socks`].
    pub remote_host: String,
    /// Remote port the agent connects to. Unused for [`ForwardKind::Socks`].
    pub remote_port: u16,
    /// Local address the client binds its listener on. Defaults to loopback.
    pub local_addr: IpAddr,
    /// Local port the client listens on.
    pub local_port: u16,
    /// Whether the local port was omitted and may fall back if unavailable.
    pub local_port_auto: bool,
    /// Direct target dial vs. dynamic SOCKS5 proxy.
    pub kind: ForwardKind,
}

impl ForwardSpec {
    /// Default loopback bind address for local listeners.
    const DEFAULT_LOCAL_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    /// Default remote host when a bare port is given.
    const DEFAULT_REMOTE_HOST: &'static str = "127.0.0.1";
    /// Default local port for a bare `socks` spec (the conventional SOCKS port).
    const SOCKS_DEFAULT_PORT: u16 = 1080;
    /// Grammar token that requests a dynamic SOCKS5 proxy in place of a target.
    const SOCKS_TOKEN: &'static str = "socks";

    /// Whether this is a dynamic SOCKS5 proxy rather than a fixed-target forward.
    pub fn is_socks(&self) -> bool {
        matches!(self.kind, ForwardKind::Socks)
    }

    /// A stable key identifying this forward by its local listen endpoint.
    ///
    /// Used for dedup and for `drop`-by-spec over the control socket.
    pub fn local_key(&self) -> (IpAddr, u16) {
        (self.local_addr, self.local_port)
    }
}

/// Process-wide default local bind address for forwards whose spec omits an
/// explicit one. Set once at startup; unset means loopback.
static DEFAULT_BIND: OnceLock<IpAddr> = OnceLock::new();

/// Configure the process-wide default local bind address (see [`default_bind`]).
///
/// Call once at startup, before any spec is parsed. The typical override is
/// `0.0.0.0`, used when the client runs inside a VM-backed Docker runtime
/// (Colima/Lima): such runtimes re-expose the VM's *wildcard* listeners on the
/// host's loopback, but never the VM's own loopback listeners, so a forward has
/// to bind `0.0.0.0` inside the VM to be reachable from the host.
pub fn set_default_bind(addr: IpAddr) {
    let _ = DEFAULT_BIND.set(addr);
}

/// The configured default local bind address, or loopback when unset.
///
/// Used for every forward whose spec doesn't name its own bind address —
/// launch specs, profile forwards, control-socket `add`s, TUI adds, and
/// auto-forwarded listeners — so a single startup override covers them all.
pub fn default_bind() -> IpAddr {
    DEFAULT_BIND
        .get()
        .copied()
        .unwrap_or(ForwardSpec::DEFAULT_LOCAL_ADDR)
}

impl FromStr for ForwardSpec {
    type Err = SpecError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_with_bind(input, default_bind())
    }
}

impl ForwardSpec {
    /// Parse a forward spec, using `default_bind` for the local listener when
    /// the spec omits an explicit bind address. [`FromStr`] delegates here with
    /// the process-wide [`default_bind`].
    pub fn parse_with_bind(input: &str, default_bind: IpAddr) -> Result<Self, SpecError> {
        Self::parse_with_defaults(input, default_bind, None)
    }

    /// Parse a forward spec against the session's defaults: `default_bind` for an
    /// omitted local bind address, and `default_ns` for an omitted `NS@` prefix.
    ///
    /// `default_ns` is the session-level namespace (`--ns`, or `portmanager ns`
    /// later): a spec that names no namespace dials inside it instead of the
    /// remote's own network namespace, which is what makes a bare `2080` reach a
    /// service inside a container. An `NS@` written into the spec always wins,
    /// and the inherited case is flagged (`ns_inherited`) so it can be persisted
    /// short and re-pointed later.
    pub fn parse_with_defaults(
        input: &str,
        default_bind: IpAddr,
        default_ns: Option<&NsSpec>,
    ) -> Result<Self, SpecError> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(SpecError::Empty);
        }

        // Split off an optional `NS@` prefix. We split on the *first* `@`; the
        // namespace selector itself never contains `@`. With no prefix the
        // session default applies — this is the single point where inheritance
        // happens, so launch specs, profile forwards, control-socket `add`s and
        // TUI adds all get it from one place.
        let (ns, ns_inherited, target) = match raw.split_once('@') {
            Some((ns_part, rest)) => (NsSpec::parse(ns_part)?, false, rest),
            // Flagged as inherited even when there is no default yet: the spec
            // named no namespace, so it should follow the session default later
            // too — that is what lets `portmanager ns` fix the bare forwards a
            // session already has.
            None => match default_ns {
                Some(ns) if !ns.is_host() => (ns.clone(), true, raw),
                _ => (NsSpec::Host, true, raw),
            },
        };

        // Split off an optional `->LOCALPORT` suffix.
        let (remote_part, local_part) = match target.split_once("->") {
            Some((r, l)) => (r.trim(), Some(l.trim())),
            None => (target.trim(), None),
        };

        // `socks` in the target position requests a dynamic SOCKS5 proxy: there
        // is no fixed remote target (it comes from each connection's handshake).
        if remote_part.eq_ignore_ascii_case(Self::SOCKS_TOKEN) {
            let (local_addr, local_port, local_port_auto) = match local_part {
                Some(l) => {
                    let (addr, port) = parse_bind_port(l, raw)?;
                    // A SOCKS proxy relays to the remote's *whole* network, so a
                    // spec may not expose it directly with an explicit
                    // non-loopback bind. The configured `default_bind` is
                    // trusted, though: an operator setting it to `0.0.0.0` for a
                    // VM Docker runtime only reaches the VM (Lima/Colima re-map
                    // that to the host's loopback), not the LAN.
                    if let Some(addr) = addr
                        && !addr.is_loopback()
                    {
                        return Err(SpecError::Malformed(
                            raw.to_string(),
                            "a SOCKS proxy is loopback-only; drop the bind address".into(),
                        ));
                    }
                    (addr.unwrap_or(default_bind), port, false)
                }
                None => (default_bind, Self::SOCKS_DEFAULT_PORT, true),
            };
            return Ok(ForwardSpec {
                ns,
                ns_inherited,
                remote_host: String::new(),
                remote_port: 0,
                local_addr,
                local_port,
                local_port_auto,
                kind: ForwardKind::Socks,
            });
        }

        let (remote_host, remote_port) = parse_host_port(remote_part, raw)?;

        let (local_addr, local_port) = match local_part {
            Some(l) => {
                let (addr, port) = parse_bind_port(l, raw)?;
                (addr.unwrap_or(default_bind), port)
            }
            None => (default_bind, remote_port),
        };

        Ok(ForwardSpec {
            ns,
            ns_inherited,
            remote_host,
            remote_port,
            local_addr,
            local_port,
            local_port_auto: local_part.is_none(),
            kind: ForwardKind::Direct,
        })
    }
}

/// One fully-parsed reverse port forward (the `ssh -R` equivalent).
///
/// The data direction is the inverse of [`ForwardSpec`]: the **agent** binds a
/// listener on the remote host, and each connection accepted there is dialed by
/// the **client** to a local target. Grammar:
///
/// ```text
/// [NS@]REMOTEBIND->LOCALTARGET
///   REMOTEBIND  = [BINDADDR:]PORT   ; the agent binds this remotely (default 127.0.0.1)
///   LOCALTARGET = [HOST:]PORT       ; the client dials this locally (default host 127.0.0.1)
/// ```
///
/// Examples:
/// - `3000->3000`                     -> agent binds remote 127.0.0.1:3000, client dials 127.0.0.1:3000
/// - `0.0.0.0:8080->192.168.1.5:80`   -> agent binds remote *:8080, client dials a LAN host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseSpec {
    /// Namespace the agent binds the remote listener in. v1 supports
    /// [`NsSpec::Host`] only, so the session default namespace deliberately does
    /// *not* apply here — inheriting it would break every `-R` spec in a session
    /// launched with `--ns`.
    pub ns: NsSpec,
    /// Address the agent binds on the remote host. Defaults to loopback.
    pub remote_bind_addr: IpAddr,
    /// Port the agent binds on the remote host. Strict (no fallback).
    pub remote_bind_port: u16,
    /// Host the client dials locally for each accepted remote connection.
    pub local_host: String,
    /// Port the client dials locally.
    pub local_port: u16,
}

impl ReverseSpec {
    /// A stable key identifying this reverse forward by its remote bind endpoint
    /// (plus namespace). Used for dedup and `drop`-by-spec.
    pub fn bind_key(&self) -> (String, IpAddr, u16) {
        (
            self.ns.to_wire(),
            self.remote_bind_addr,
            self.remote_bind_port,
        )
    }

    /// Canonical CLI-grammar rendering (parseable back via [`FromStr`]). Elides
    /// a loopback bind address and a `127.0.0.1` local host so the short forms
    /// round-trip.
    pub fn to_spec_string(&self) -> String {
        let ns = self.ns.to_wire();
        let prefix = if ns.is_empty() {
            String::new()
        } else {
            format!("{ns}@")
        };
        let bind = if self.remote_bind_addr == ForwardSpec::DEFAULT_LOCAL_ADDR {
            self.remote_bind_port.to_string()
        } else {
            match self.remote_bind_addr {
                IpAddr::V4(v4) => format!("{v4}:{}", self.remote_bind_port),
                IpAddr::V6(v6) => format!("[{v6}]:{}", self.remote_bind_port),
            }
        };
        let local = if self.local_host == ForwardSpec::DEFAULT_REMOTE_HOST {
            self.local_port.to_string()
        } else if self.local_host.contains(':') {
            // Bare IPv6 literal needs bracketing to reparse.
            format!("[{}]:{}", self.local_host, self.local_port)
        } else {
            format!("{}:{}", self.local_host, self.local_port)
        };
        format!("{prefix}{bind}->{local}")
    }
}

impl FromStr for ReverseSpec {
    type Err = SpecError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(SpecError::Empty);
        }

        let (ns, target) = match raw.split_once('@') {
            Some((ns_part, rest)) => (NsSpec::parse(ns_part)?, rest),
            None => (NsSpec::Host, raw),
        };

        let (bind_part, local_part) = target.split_once("->").ok_or_else(|| {
            SpecError::Malformed(
                raw.to_string(),
                "a reverse spec needs REMOTEBIND->LOCALTARGET".into(),
            )
        })?;

        // The bind is on the *remote* side, so the local default-bind override
        // never applies here; an omitted address stays loopback.
        let (remote_bind_addr, remote_bind_port) = parse_bind_port(bind_part.trim(), raw)?;
        let remote_bind_addr = remote_bind_addr.unwrap_or(ForwardSpec::DEFAULT_LOCAL_ADDR);
        let (local_host, local_port) = parse_host_port(local_part.trim(), raw)?;

        Ok(ReverseSpec {
            ns,
            remote_bind_addr,
            remote_bind_port,
            local_host,
            local_port,
        })
    }
}

/// Parse `[HOST:]PORT`, defaulting the host to loopback. Handles bracketed IPv6
/// hosts like `[::1]:8080`.
fn parse_host_port(s: &str, raw: &str) -> Result<(String, u16), SpecError> {
    if s.is_empty() {
        return Err(SpecError::MissingPort(raw.to_string()));
    }

    // Bracketed IPv6: [addr]:port
    if let Some(after) = s.strip_prefix('[') {
        let (host, rest) = after.split_once(']').ok_or_else(|| {
            SpecError::Malformed(raw.to_string(), "unterminated '[' in host".into())
        })?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| SpecError::MissingPort(raw.to_string()))?;
        return Ok((host.to_string(), parse_port(port, raw)?));
    }

    match s.rsplit_once(':') {
        // Bare-port shorthand: no colon at all -> loopback host.
        None => Ok((
            ForwardSpec::DEFAULT_REMOTE_HOST.to_string(),
            parse_port(s, raw)?,
        )),
        Some((host, port)) => {
            let host = if host.is_empty() {
                ForwardSpec::DEFAULT_REMOTE_HOST.to_string()
            } else {
                host.to_string()
            };
            Ok((host, parse_port(port, raw)?))
        }
    }
}

/// Parse the local part `[BINDADDR:]PORT` into an (optional bind address, port).
/// A `None` address means none was given, so the caller substitutes its default
/// (loopback, or a startup override). Bracketed IPv6 (`[::]:PORT`) is supported,
/// mirroring the remote-side host grammar. The bind address is how "visibility"
/// is expressed: loopback (private) vs `0.0.0.0` (exposed).
fn parse_bind_port(s: &str, raw: &str) -> Result<(Option<IpAddr>, u16), SpecError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SpecError::MissingPort(raw.to_string()));
    }

    // Bracketed IPv6 bind: [addr]:port
    if let Some(after) = s.strip_prefix('[') {
        let (addr, rest) = after.split_once(']').ok_or_else(|| {
            SpecError::Malformed(
                raw.to_string(),
                "unterminated '[' in local bind address".into(),
            )
        })?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| SpecError::MissingPort(raw.to_string()))?;
        return Ok((Some(parse_bind_addr(addr, raw)?), parse_port(port, raw)?));
    }

    match s.rsplit_once(':') {
        // No bind address: bare local port -> caller's default.
        None => Ok((None, parse_port(s, raw)?)),
        Some((addr, port)) => Ok((Some(parse_bind_addr(addr, raw)?), parse_port(port, raw)?)),
    }
}

fn parse_bind_addr(s: &str, raw: &str) -> Result<IpAddr, SpecError> {
    s.parse::<IpAddr>().map_err(|e| {
        SpecError::Malformed(
            raw.to_string(),
            format!("invalid local bind address {s:?}: {e}"),
        )
    })
}

fn parse_port(s: &str, raw: &str) -> Result<u16, SpecError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SpecError::MissingPort(raw.to_string()));
    }
    s.parse::<u16>()
        .map_err(|e| SpecError::InvalidPort(s.to_string(), e.to_string()))
        .and_then(|p| {
            if p == 0 {
                Err(SpecError::InvalidPort(
                    s.to_string(),
                    "port must be non-zero".into(),
                ))
            } else {
                Ok(p)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ForwardSpec {
        s.parse().unwrap()
    }

    #[test]
    fn bare_port_shorthand() {
        let f = parse("8888");
        assert_eq!(f.ns, NsSpec::Host);
        assert_eq!(f.remote_host, "127.0.0.1");
        assert_eq!(f.remote_port, 8888);
        assert_eq!(f.local_port, 8888);
        assert!(f.local_port_auto);
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn host_port_to_local() {
        let f = parse("192.168.4.2:8080->8080");
        assert_eq!(f.ns, NsSpec::Host);
        assert_eq!(f.remote_host, "192.168.4.2");
        assert_eq!(f.remote_port, 8080);
        assert_eq!(f.local_port, 8080);
        assert!(!f.local_port_auto);
    }

    #[test]
    fn distinct_local_port() {
        let f = parse("10.0.0.5:443->8443");
        assert_eq!(f.remote_host, "10.0.0.5");
        assert_eq!(f.remote_port, 443);
        assert_eq!(f.local_port, 8443);
        assert!(!f.local_port_auto);
    }

    #[test]
    fn host_port_without_arrow_mirrors_port() {
        let f = parse("db.internal:5432");
        assert_eq!(f.remote_host, "db.internal");
        assert_eq!(f.remote_port, 5432);
        assert_eq!(f.local_port, 5432);
        assert!(f.local_port_auto);
    }

    #[test]
    fn local_bind_address() {
        let f = parse("8080->0.0.0.0:8080");
        assert_eq!(f.remote_host, "127.0.0.1");
        assert_eq!(f.remote_port, 8080);
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(f.local_port, 8080);
        assert!(!f.local_port_auto, "an explicit bind pins the local port");
    }

    #[test]
    fn local_bind_address_with_remote_host_and_ns() {
        let f = parse("podman:web@10.88.0.5:5432->0.0.0.0:15432");
        assert_eq!(f.ns, NsSpec::Podman("web".into()));
        assert_eq!(f.remote_host, "10.88.0.5");
        assert_eq!(f.remote_port, 5432);
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(f.local_port, 15432);
    }

    #[test]
    fn local_bind_address_bracketed_ipv6() {
        let f = parse("8080->[::]:9090");
        assert_eq!(f.local_addr, "::".parse::<IpAddr>().unwrap());
        assert_eq!(f.local_port, 9090);
    }

    #[test]
    fn bare_local_port_stays_loopback() {
        let f = parse("192.168.4.2:8080->8080");
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn rejects_bad_bind_address() {
        assert!(matches!(
            "8080->nope:9090".parse::<ForwardSpec>(),
            Err(SpecError::Malformed(..))
        ));
    }

    #[test]
    fn ipv6_bracketed_host() {
        let f = parse("[fd00::1]:8080->9090");
        assert_eq!(f.remote_host, "fd00::1");
        assert_eq!(f.remote_port, 8080);
        assert_eq!(f.local_port, 9090);
    }

    #[test]
    fn namespace_podman() {
        let f = parse("podman:web@10.88.0.5:5432->5432");
        assert_eq!(f.ns, NsSpec::Podman("web".into()));
        assert_eq!(f.remote_host, "10.88.0.5");
        assert_eq!(f.remote_port, 5432);
        assert_eq!(f.local_port, 5432);
    }

    #[test]
    fn namespace_pid_and_bare_port() {
        let f = parse("pid:1234@8080");
        assert_eq!(f.ns, NsSpec::Pid(1234));
        assert_eq!(f.remote_host, "127.0.0.1");
        assert_eq!(f.remote_port, 8080);
        assert_eq!(f.local_port, 8080);
    }

    #[test]
    fn namespace_all_forms_parse() {
        assert_eq!(parse("docker:api@80").ns, NsSpec::Docker("api".into()));
        assert_eq!(parse("netns:blue@80").ns, NsSpec::Netns("blue".into()));
        assert_eq!(
            parse("nspath:/proc/9/ns/net@80").ns,
            NsSpec::NsPath(PathBuf::from("/proc/9/ns/net"))
        );
    }

    #[test]
    fn socks_default_port_is_auto_loopback() {
        let f = parse("socks");
        assert_eq!(f.kind, ForwardKind::Socks);
        assert!(f.is_socks());
        assert_eq!(f.ns, NsSpec::Host);
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(f.local_port, 1080);
        assert!(
            f.local_port_auto,
            "bare socks should fall back if 1080 is taken"
        );
    }

    #[test]
    fn socks_explicit_port_is_pinned() {
        let f = parse("socks->9050");
        assert_eq!(f.kind, ForwardKind::Socks);
        assert_eq!(f.local_port, 9050);
        assert!(!f.local_port_auto);
    }

    #[test]
    fn socks_carries_namespace() {
        let f = parse("podman:web@socks->9050");
        assert_eq!(f.kind, ForwardKind::Socks);
        assert_eq!(f.ns, NsSpec::Podman("web".into()));
        assert_eq!(f.local_port, 9050);
    }

    #[test]
    fn socks_rejects_non_loopback_bind() {
        assert!(matches!(
            "socks->0.0.0.0:1080".parse::<ForwardSpec>(),
            Err(SpecError::Malformed(..))
        ));
    }

    #[test]
    fn socks_allows_ipv6_loopback() {
        let f = parse("socks->[::1]:1080");
        assert_eq!(f.kind, ForwardKind::Socks);
        assert_eq!(f.local_addr, "::1".parse::<IpAddr>().unwrap());
    }

    // The default-bind override backs the Colima/VM-runtime path: forwards whose
    // spec omits a bind address adopt it, so a VM `0.0.0.0` listener gets
    // re-exposed on the host's loopback.
    const WILDCARD: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[test]
    fn default_bind_applies_when_spec_omits_address() {
        // Bare port, host:port, and arrowed forms all inherit the default.
        for spec in ["8080", "192.168.4.2:8080->8080", "db:5432"] {
            let f = ForwardSpec::parse_with_bind(spec, WILDCARD).unwrap();
            assert_eq!(f.local_addr, WILDCARD, "spec {spec:?} should adopt default");
        }
    }

    #[test]
    fn explicit_bind_beats_default() {
        // An address written in the spec always wins over the configured default.
        let f = ForwardSpec::parse_with_bind("8080->127.0.0.1:8080", WILDCARD).unwrap();
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn socks_adopts_default_bind() {
        // Bare `socks` and a port-only `socks->PORT` both take the default bind,
        // which is how a SOCKS proxy becomes reachable under Colima.
        for spec in ["socks", "socks->1080"] {
            let f = ForwardSpec::parse_with_bind(spec, WILDCARD).unwrap();
            assert!(f.is_socks());
            assert_eq!(f.local_addr, WILDCARD, "spec {spec:?} should adopt default");
        }
    }

    #[test]
    fn socks_still_rejects_explicit_non_loopback_even_with_default() {
        // The configured default is trusted, but an address typed into the spec
        // is not — an explicit wildcard SOCKS bind stays rejected.
        assert!(matches!(
            ForwardSpec::parse_with_bind("socks->0.0.0.0:1080", WILDCARD),
            Err(SpecError::Malformed(..))
        ));
    }

    // --- session default namespace ---------------------------------------
    //
    // The default is threaded in as a parameter (not a process global) so these
    // cases stay independent of each other and of the parse tests above.

    #[test]
    fn bare_spec_inherits_the_session_default_namespace() {
        // The launch case: `portmanager --ns pid:856182 host 80 2080` — every
        // spec that names no namespace dials inside pid 856182.
        let ns = NsSpec::Pid(856_182);
        for raw in ["80", "2080", "127.0.0.1:8080->8080", "socks"] {
            let f = ForwardSpec::parse_with_defaults(raw, default_bind(), Some(&ns)).unwrap();
            assert_eq!(f.ns, ns, "spec {raw:?} should inherit the default");
            assert!(f.ns_inherited, "spec {raw:?} should be marked inherited");
        }
    }

    #[test]
    fn explicit_namespace_beats_the_session_default() {
        // `pid:999@80` means 999 even when the session default is 856182.
        let f = ForwardSpec::parse_with_defaults(
            "pid:999@80",
            default_bind(),
            Some(&NsSpec::Pid(856_182)),
        )
        .unwrap();
        assert_eq!(f.ns, NsSpec::Pid(999));
        assert!(!f.ns_inherited, "an explicit namespace is not inherited");
    }

    #[test]
    fn bare_spec_without_a_default_stays_in_the_host_namespace() {
        // Unchanged behaviour when no default is set: the agent's own namespace.
        // Still flagged as inherited — the spec named no namespace, so a later
        // `portmanager ns` may re-point it.
        let f = ForwardSpec::parse_with_defaults("2080", default_bind(), None).unwrap();
        assert_eq!(f.ns, NsSpec::Host);
        assert!(f.ns_inherited);
        // A `host` default is no default at all.
        let f =
            ForwardSpec::parse_with_defaults("2080", default_bind(), Some(&NsSpec::Host)).unwrap();
        assert_eq!(f.ns, NsSpec::Host);
        assert!(f.ns_inherited);
    }

    #[test]
    fn default_namespace_does_not_touch_the_rest_of_the_grammar() {
        // Inheritance is only about the `NS@` prefix; ports, hosts and binds
        // parse exactly as before.
        let f = ForwardSpec::parse_with_defaults(
            "192.168.4.2:8080->0.0.0.0:9090",
            default_bind(),
            Some(&NsSpec::Podman("web".into())),
        )
        .unwrap();
        assert_eq!(f.ns, NsSpec::Podman("web".into()));
        assert_eq!(f.remote_host, "192.168.4.2");
        assert_eq!(f.remote_port, 8080);
        assert_eq!(f.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(f.local_port, 9090);
        assert!(!f.local_port_auto);
    }

    #[test]
    fn only_pid_namespaces_are_unstable() {
        // What may be remembered between sessions (see config::HostState).
        assert!(!NsSpec::Pid(1234).is_stable());
        assert!(NsSpec::Podman("web".into()).is_stable());
        assert!(NsSpec::Docker("api".into()).is_stable());
        assert!(NsSpec::Netns("blue".into()).is_stable());
        assert!(NsSpec::NsPath(PathBuf::from("/proc/9/ns/net")).is_stable());
    }

    #[test]
    fn rejects_empty() {
        assert_eq!("".parse::<ForwardSpec>(), Err(SpecError::Empty));
        assert_eq!("   ".parse::<ForwardSpec>(), Err(SpecError::Empty));
    }

    #[test]
    fn rejects_bad_port() {
        assert!(matches!(
            "70000".parse::<ForwardSpec>(),
            Err(SpecError::InvalidPort(..))
        ));
        assert!(matches!(
            "0".parse::<ForwardSpec>(),
            Err(SpecError::InvalidPort(..))
        ));
        assert!(matches!(
            "abc".parse::<ForwardSpec>(),
            Err(SpecError::InvalidPort(..))
        ));
    }

    #[test]
    fn rejects_missing_local_port() {
        assert!(matches!(
            "8080->".parse::<ForwardSpec>(),
            Err(SpecError::MissingPort(..))
        ));
    }

    #[test]
    fn rejects_unknown_namespace_kind() {
        assert!(matches!(
            "lxc:foo@80".parse::<ForwardSpec>(),
            Err(SpecError::BadNamespace(..))
        ));
        assert!(matches!(
            "podman:@80".parse::<ForwardSpec>(),
            Err(SpecError::BadNamespace(..))
        ));
    }

    fn rparse(s: &str) -> ReverseSpec {
        s.parse().unwrap()
    }

    #[test]
    fn reverse_bare_ports_default_loopback() {
        let r = rparse("3000->3000");
        assert_eq!(r.ns, NsSpec::Host);
        assert_eq!(r.remote_bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(r.remote_bind_port, 3000);
        assert_eq!(r.local_host, "127.0.0.1");
        assert_eq!(r.local_port, 3000);
    }

    #[test]
    fn reverse_explicit_bind_and_remote_target() {
        let r = rparse("0.0.0.0:8080->192.168.1.5:80");
        assert_eq!(r.remote_bind_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(r.remote_bind_port, 8080);
        assert_eq!(r.local_host, "192.168.1.5");
        assert_eq!(r.local_port, 80);
    }

    #[test]
    fn reverse_carries_namespace() {
        let r = rparse("podman:web@5432->5432");
        assert_eq!(r.ns, NsSpec::Podman("web".into()));
        assert_eq!(r.remote_bind_port, 5432);
        assert_eq!(r.local_port, 5432);
    }

    #[test]
    fn reverse_requires_arrow() {
        assert!(matches!(
            "3000".parse::<ReverseSpec>(),
            Err(SpecError::Malformed(..))
        ));
    }

    #[test]
    fn reverse_spec_string_roundtrips() {
        for raw in [
            "3000->3000",
            "0.0.0.0:8080->192.168.1.5:80",
            "podman:web@5432->5432",
            "[::]:8080->[::1]:9090",
        ] {
            let spec = rparse(raw);
            let shown = spec.to_spec_string();
            let back: ReverseSpec = shown.parse().unwrap();
            assert_eq!(
                spec, back,
                "reverse form {shown:?} must reparse identically"
            );
        }
    }
}
