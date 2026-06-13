//! Diagnose blocked inbound UDP — the most common confusing setup failure.
//!
//! The QUIC data channel needs the agent's UDP port reachable from the client.
//! When a remote host firewall blocks it, the only symptom is a QUIC connect
//! timeout. Over the SSH channel we already have, this module detects which host
//! firewall is *active* (root-free, via `systemctl is-active`) and produces an
//! advisory with the exact command to open the port.
//!
//! Policy: **print-only**. We never modify the remote firewall — reading rules
//! needs root and changing them is the operator's call. We pair the detected
//! firewall with a ready-to-paste command and note that cloud security groups
//! (AWS/GCP/Azure) are separate and can't be seen or changed from the host.

/// The port (or range) to advise opening, rendered per firewall syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisePort {
    Single(u16),
    Range(u16, u16),
}

impl AdvisePort {
    /// Human description, e.g. `UDP 60000-61000`.
    fn human(&self) -> String {
        match self {
            AdvisePort::Single(p) => format!("UDP {p}"),
            AdvisePort::Range(a, b) => format!("UDP {a}-{b}"),
        }
    }
    /// `ufw`/`iptables` range syntax uses a colon: `60000:61000`.
    fn colon(&self) -> String {
        match self {
            AdvisePort::Single(p) => p.to_string(),
            AdvisePort::Range(a, b) => format!("{a}:{b}"),
        }
    }
    /// `firewalld`/`nft` range syntax uses a dash: `60000-61000`.
    fn dash(&self) -> String {
        match self {
            AdvisePort::Single(p) => p.to_string(),
            AdvisePort::Range(a, b) => format!("{a}-{b}"),
        }
    }
}

/// A detected, active host firewall front-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firewall {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

impl Firewall {
    /// The command that opens `port` for inbound UDP under this firewall.
    fn open_command(&self, port: &AdvisePort) -> String {
        match self {
            Firewall::Ufw => format!("sudo ufw allow {}/udp", port.colon()),
            Firewall::Firewalld => format!(
                "sudo firewall-cmd --permanent --add-port={}/udp && sudo firewall-cmd --reload",
                port.dash()
            ),
            Firewall::Nftables => format!(
                "sudo nft add rule inet filter input udp dport {} accept  \
                 # table/chain names may differ; check `sudo nft list ruleset`",
                port.dash()
            ),
            Firewall::Iptables => format!(
                "sudo iptables -A INPUT -p udp --dport {} -j ACCEPT  \
                 # then persist (e.g. netfilter-persistent save)",
                port.colon()
            ),
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Firewall::Ufw => "ufw",
            Firewall::Firewalld => "firewalld",
            Firewall::Nftables => "nftables",
            Firewall::Iptables => "iptables",
        }
    }
}

/// Build a neutral advisory: which firewall is active and how to open `port`.
/// `chosen` is the highest-level active firewall, or `None` if none was detected.
pub fn advisory(chosen: Option<Firewall>, port: &AdvisePort) -> String {
    let cloud = "Cloud security groups / network ACLs (AWS, GCP, Azure, …) are \
                 separate and must be opened there too — they can't be seen or \
                 changed from inside the host.";
    match chosen {
        Some(fw) => format!(
            "Active host firewall: {}. To allow {} on the remote, run there:\n    {}\n{}",
            fw.label(),
            port.human(),
            fw.open_command(port),
            cloud,
        ),
        None => format!(
            "No active host firewall detected. If {} is blocked, it is most likely \
             a cloud security group / network ACL — open it there.\n{}",
            port.human(),
            cloud,
        ),
    }
}

/// Parse the detect-script markers into the highest-priority active firewall.
/// A host with `ufw`/`firewalld` active manages the lower layers, so prefer the
/// managing front-end; only fall to raw nft/iptables when nothing higher is up.
fn choose(markers: &str) -> Option<Firewall> {
    let has = |m: &str| markers.lines().any(|l| l.trim() == m);
    if has("active:ufw") {
        Some(Firewall::Ufw)
    } else if has("active:firewalld") {
        Some(Firewall::Firewalld)
    } else if has("active:nftables") {
        Some(Firewall::Nftables)
    } else if has("have:iptables") {
        Some(Firewall::Iptables)
    } else if has("have:nft") {
        Some(Firewall::Nftables)
    } else {
        None
    }
}

/// Root-free firewall probe fed to the remote `sh` over SSH.
const DETECT_SCRIPT: &str = r#"
for s in ufw firewalld nftables; do
  systemctl is-active --quiet "$s" 2>/dev/null && echo "active:$s"
done
command -v nft >/dev/null 2>&1 && echo "have:nft"
command -v iptables >/dev/null 2>&1 && echo "have:iptables"
"#;

/// Inspect `host`'s firewall over SSH and return a printable advisory for
/// opening `port`. Best-effort: if the probe can't run, returns a generic hint.
pub async fn diagnose(host: &str, port: AdvisePort) -> String {
    match crate::bootstrap::ssh_script(host, DETECT_SCRIPT).await {
        Ok(markers) => advisory(choose(&markers), &port),
        Err(_) => format!(
            "Could not inspect the remote firewall. Ensure {} is allowed inbound \
             (host firewall and any cloud security group).",
            port.human()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufw_command_range_and_single() {
        assert!(
            advisory(Some(Firewall::Ufw), &AdvisePort::Range(60000, 61000))
                .contains("sudo ufw allow 60000:61000/udp")
        );
        assert!(
            advisory(Some(Firewall::Ufw), &AdvisePort::Single(51820))
                .contains("sudo ufw allow 51820/udp")
        );
    }

    #[test]
    fn firewalld_and_iptables_and_nft_commands() {
        assert!(
            advisory(Some(Firewall::Firewalld), &AdvisePort::Range(60000, 61000))
                .contains("--add-port=60000-61000/udp")
        );
        assert!(
            advisory(Some(Firewall::Iptables), &AdvisePort::Range(60000, 61000))
                .contains("--dport 60000:61000 -j ACCEPT")
        );
        assert!(
            advisory(Some(Firewall::Nftables), &AdvisePort::Single(53))
                .contains("udp dport 53 accept")
        );
    }

    #[test]
    fn no_firewall_points_at_cloud() {
        let a = advisory(None, &AdvisePort::Range(60000, 61000));
        assert!(a.contains("cloud security group"));
        assert!(a.contains("UDP 60000-61000"));
    }

    #[test]
    fn choose_prefers_managing_frontend() {
        // ufw wins even when iptables is present (ufw manages it).
        assert_eq!(
            choose("active:ufw\nhave:iptables\nhave:nft"),
            Some(Firewall::Ufw)
        );
        assert_eq!(
            choose("active:firewalld\nhave:iptables"),
            Some(Firewall::Firewalld)
        );
        assert_eq!(choose("have:iptables"), Some(Firewall::Iptables));
        assert_eq!(choose(""), None);
    }
}
