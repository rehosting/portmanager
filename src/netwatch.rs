//! Network-change detection.
//!
//! quinn has no built-in watchdog: passive NAT-rebinds are handled by the
//! protocol, but an *interface* change (wifi -> ethernet, VPN up/down) leaves
//! the client's UDP socket bound to a dead source address and requires
//! [`quinn::Endpoint::rebind`]. We detect that by asking the OS routing table
//! which source IP would be used to reach the agent: a UDP `connect()` performs
//! the route lookup without sending a single packet.
//!
//! The *when* to re-check is event-driven where the OS exposes routing events —
//! Linux `NETLINK_ROUTE` multicast and macOS `PF_ROUTE` — so an interface flip
//! is noticed sub-second instead of waiting out a poll. Those events are used
//! only as a "something changed" trigger; the route decision itself stays in
//! [`source_ip_for`]. On any other platform, or if the event socket can't be
//! opened, we fall back to the original periodic poll.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// Poll interval for the fallback path (and the event path's safety net). Cheap
/// (one routing lookup, no packets).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long to wait after the first routing event before re-checking the route,
/// coalescing a burst of churn (interface up/down fires many messages) into a
/// single rebind check.
const DEBOUNCE: Duration = Duration::from_millis(400);

/// Resolve which local source IP the OS would use to reach `target` right now.
/// Returns `None` when there is no route (offline, mid-roam).
pub fn source_ip_for(target: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect(target).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Source of "re-check the route now" wakeups.
enum Trigger {
    /// OS routing events are available; each `()` is a debounced change signal.
    Events(mpsc::Receiver<()>),
    /// No event source — the caller falls back to a periodic poll.
    Poll,
}

/// Block until the next route re-check should happen. In event mode this is the
/// next debounced routing event; if the event source dies it degrades to the
/// poll. In poll mode it is just the poll interval.
async fn wakeup(trigger: &mut Trigger) {
    match trigger {
        Trigger::Events(rx) => {
            if rx.recv().await.is_none() {
                // The event task ended (socket error); degrade to polling so we
                // don't spin on a closed channel.
                warn!("route-event source ended; falling back to polling");
                *trigger = Trigger::Poll;
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
        Trigger::Poll => tokio::time::sleep(POLL_INTERVAL).await,
    }
}

/// Collapse a stream of raw routing events into at most one tick per [`DEBOUNCE`]
/// window. Factored out from the socket plumbing so it is unit-testable.
async fn coalesce(mut raw: mpsc::Receiver<()>, out: mpsc::Sender<()>, window: Duration) {
    while raw.recv().await.is_some() {
        // Let the churn settle, then drain anything that piled up during the
        // window and emit a single consolidated tick.
        tokio::time::sleep(window).await;
        while raw.try_recv().is_ok() {}
        if out.send(()).await.is_err() {
            return;
        }
    }
}

/// Watch the route to the agent and `rebind()` the endpoint when the source IP
/// changes (active migration trigger). The QUIC connection itself survives the
/// rebind via path validation — that's the seamless-roaming path.
///
/// `target_rx` carries the current agent address (it changes after a
/// re-bootstrap). Runs until the channel closes.
pub async fn run(endpoint: quinn::Endpoint, mut target_rx: watch::Receiver<SocketAddr>) {
    let mut trigger = change_events();
    if matches!(trigger, Trigger::Events(_)) {
        debug!("netwatch: using OS routing events");
    } else {
        debug!("netwatch: using {POLL_INTERVAL:?} polling");
    }
    let mut last_ip = source_ip_for(*target_rx.borrow());

    loop {
        let target = *target_rx.borrow_and_update();
        tokio::select! {
            _ = wakeup(&mut trigger) => {}
            changed = target_rx.changed() => {
                if changed.is_err() {
                    debug!("netwatch: session ended");
                    return;
                }
                // Target moved (re-bootstrap); reset the baseline.
                last_ip = source_ip_for(*target_rx.borrow());
                continue;
            }
        }

        let now_ip = source_ip_for(target);
        match (&last_ip, &now_ip) {
            (Some(old), Some(new)) if old != new => {
                info!(%old, %new, "network path changed; migrating QUIC endpoint");
                match std::net::UdpSocket::bind(if target.is_ipv4() {
                    "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                } else {
                    "[::]:0".parse::<SocketAddr>().unwrap()
                }) {
                    Ok(sock) => {
                        if let Err(e) = sock.set_nonblocking(true) {
                            warn!(error = %e, "rebind socket setup failed");
                        } else if let Err(e) = endpoint.rebind(sock) {
                            warn!(error = %e, "endpoint rebind failed");
                        } else {
                            info!("endpoint rebound; connection migrating");
                        }
                    }
                    Err(e) => warn!(error = %e, "could not bind fresh UDP socket"),
                }
                last_ip = now_ip;
            }
            (None, Some(new)) => {
                // Route came back (e.g. wifi reconnected on the same subnet).
                // Same source IP -> the existing socket still works and QUIC
                // retransmits on its own; just update the baseline.
                debug!(ip = %new, "route restored");
                last_ip = now_ip;
            }
            (Some(_), None) => {
                debug!("route lost (offline); waiting");
                last_ip = None;
            }
            _ => {}
        }
    }
}

/// Open an OS routing-event source. Returns [`Trigger::Poll`] on any platform
/// without an implementation or if the socket can't be set up — migration then
/// degrades to polling rather than breaking.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn change_events() -> Trigger {
    use tokio::io::unix::AsyncFd;

    let fd = match open_route_socket() {
        Ok(fd) => fd,
        Err(e) => {
            warn!(error = %e, "route-event socket unavailable; using poll");
            return Trigger::Poll;
        }
    };
    let afd = match AsyncFd::new(fd) {
        Ok(a) => a,
        Err(e) => {
            warn!(error = %e, "route-event socket not pollable; using poll");
            return Trigger::Poll;
        }
    };

    let (raw_tx, raw_rx) = mpsc::channel(1);
    let (out_tx, out_rx) = mpsc::channel(1);
    tokio::spawn(drain_route_socket(afd, raw_tx));
    tokio::spawn(coalesce(raw_rx, out_tx, DEBOUNCE));
    Trigger::Events(out_rx)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn change_events() -> Trigger {
    Trigger::Poll
}

/// Drain readiness on the route socket and emit a raw tick per burst. Reading
/// to `EWOULDBLOCK` each readiness clears the level-triggered fd so the task
/// doesn't busy-loop; the bounded(1) channel coalesces at the source.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn drain_route_socket(
    afd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    raw_tx: mpsc::Sender<()>,
) {
    use std::os::fd::AsRawFd;

    let fd = afd.get_ref().as_raw_fd();
    let mut buf = [0u8; 8192];
    loop {
        let mut guard = match afd.readable().await {
            Ok(g) => g,
            Err(_) => return,
        };
        loop {
            let n = unsafe { nix::libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n > 0 {
                continue;
            }
            if n == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            warn!(error = %err, "route-event socket read failed; ending event source");
            return;
        }
        guard.clear_ready();
        // A full channel already means "a check is pending" — drop, don't block.
        let _ = raw_tx.try_send(());
    }
}

/// Linux: a `NETLINK_ROUTE` socket subscribed to link/address/route multicast
/// groups. Non-blocking + close-on-exec.
#[cfg(target_os = "linux")]
fn open_route_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const GROUPS: u32 = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV6_ROUTE) as u32;

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Owns the fd from here so any early return closes it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = GROUPS;
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(owned)
}

/// macOS: a `PF_ROUTE` raw socket delivers `RTM_*` routing messages. Set
/// non-blocking explicitly (no `SOCK_NONBLOCK` on Darwin).
#[cfg(target_os = "macos")]
fn open_route_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ip_for_loopback_is_stable() {
        // Loopback always has a route and needs no egress, so this is
        // deterministic in CI.
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let a = source_ip_for(target);
        let b = source_ip_for(target);
        assert!(a.is_some(), "loopback should always resolve a source IP");
        assert_eq!(a, b, "repeated lookups should be stable");
    }

    #[tokio::test]
    async fn coalesce_collapses_burst_to_one_tick() {
        let (raw_tx, raw_rx) = mpsc::channel(1);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let window = Duration::from_millis(50);
        tokio::spawn(coalesce(raw_rx, out_tx, window));

        // A burst of events (mirrors interface churn) before the coalescer wakes.
        for _ in 0..10 {
            let _ = raw_tx.try_send(());
        }

        // Exactly one consolidated tick should emerge from the burst.
        tokio::time::timeout(Duration::from_millis(500), out_rx.recv())
            .await
            .expect("a tick should arrive")
            .expect("channel should be open");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
                .await
                .is_err(),
            "the burst should not produce a second tick"
        );
        drop(raw_tx);
    }

    #[tokio::test]
    async fn coalesce_emits_again_for_a_later_event() {
        let (raw_tx, raw_rx) = mpsc::channel(1);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let window = Duration::from_millis(20);
        tokio::spawn(coalesce(raw_rx, out_tx, window));

        raw_tx.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_millis(300), out_rx.recv())
            .await
            .expect("first tick")
            .expect("open");

        // A genuinely later event yields a fresh tick.
        raw_tx.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_millis(300), out_rx.recv())
            .await
            .expect("second tick")
            .expect("open");
    }
}
