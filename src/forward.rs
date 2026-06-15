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

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;

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

/// One fully-parsed port forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Namespace the agent dials from.
    pub ns: NsSpec,
    /// Remote host the agent connects to (resolved inside `ns`).
    pub remote_host: String,
    /// Remote port the agent connects to.
    pub remote_port: u16,
    /// Local address the client binds its listener on. Defaults to loopback.
    pub local_addr: IpAddr,
    /// Local port the client listens on.
    pub local_port: u16,
    /// Whether the local port was omitted and may fall back if unavailable.
    pub local_port_auto: bool,
}

impl ForwardSpec {
    /// Default loopback bind address for local listeners.
    const DEFAULT_LOCAL_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    /// Default remote host when a bare port is given.
    const DEFAULT_REMOTE_HOST: &'static str = "127.0.0.1";

    /// A stable key identifying this forward by its local listen endpoint.
    ///
    /// Used for dedup and for `drop`-by-spec over the control socket.
    pub fn local_key(&self) -> (IpAddr, u16) {
        (self.local_addr, self.local_port)
    }
}

impl FromStr for ForwardSpec {
    type Err = SpecError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(SpecError::Empty);
        }

        // Split off an optional `NS@` prefix. We split on the *first* `@`; the
        // namespace selector itself never contains `@`.
        let (ns, target) = match raw.split_once('@') {
            Some((ns_part, rest)) => (NsSpec::parse(ns_part)?, rest),
            None => (NsSpec::Host, raw),
        };

        // Split off an optional `->LOCALPORT` suffix.
        let (remote_part, local_part) = match target.split_once("->") {
            Some((r, l)) => (r.trim(), Some(l.trim())),
            None => (target.trim(), None),
        };

        let (remote_host, remote_port) = parse_host_port(remote_part, raw)?;

        let (local_addr, local_port) = match local_part {
            Some(l) => parse_bind_port(l, raw)?,
            None => (Self::DEFAULT_LOCAL_ADDR, remote_port),
        };

        Ok(ForwardSpec {
            ns,
            remote_host,
            remote_port,
            local_addr,
            local_port,
            local_port_auto: local_part.is_none(),
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

/// Parse the local part `[BINDADDR:]PORT` into a (bind address, port). When no
/// bind address is given it defaults to loopback. Bracketed IPv6 (`[::]:PORT`)
/// is supported, mirroring the remote-side host grammar. The bind address is
/// how "visibility" is expressed: loopback (private) vs `0.0.0.0` (exposed).
fn parse_bind_port(s: &str, raw: &str) -> Result<(IpAddr, u16), SpecError> {
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
        return Ok((parse_bind_addr(addr, raw)?, parse_port(port, raw)?));
    }

    match s.rsplit_once(':') {
        // No bind address: bare local port -> loopback.
        None => Ok((ForwardSpec::DEFAULT_LOCAL_ADDR, parse_port(s, raw)?)),
        Some((addr, port)) => Ok((parse_bind_addr(addr, raw)?, parse_port(port, raw)?)),
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
}
