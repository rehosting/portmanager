//! `portmanager doctor <host>`: a local diagnostic checklist.
//!
//! Walks the same path a real bootstrap takes — SSH reachability, remote
//! OS/arch detection, agent-binary availability for that arch, and any running
//! local session — printing pass/fail for each step so a stuck setup is easy to
//! triage. Read-only: it never deploys or launches anything.

use anyhow::Result;

use crate::bootstrap::{self, target_triple};
use crate::control::{self, Request, Response};

/// Run all checks for `host`, printing a checklist. Never errors out early — it
/// reports every check so the full picture is visible.
pub async fn run(host: &str) -> Result<()> {
    println!("diagnosing {host:?}\n");
    let mut failures = 0u32;

    // 1. ssh -G resolves the alias.
    let hostname = match bootstrap::ssh_g(host).await {
        Ok(out) => {
            let name = out
                .lines()
                .find_map(|l| l.strip_prefix("hostname "))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| host.to_string());
            pass(&format!("ssh config resolves {host:?} -> {name}"));
            Some(name)
        }
        Err(e) => {
            fail(&format!("ssh -G {host} failed: {e:#}"));
            failures += 1;
            None
        }
    };

    // 2. SSH connect + remote OS/arch detection + triple mapping.
    let mut triple_arch = None;
    match bootstrap::ssh_capture(host, &["uname", "-sm"]).await {
        Ok(uname) => {
            let uname = uname.trim().to_string();
            pass(&format!("ssh connect ok; remote uname -sm: {uname}"));
            match target_triple(&uname) {
                Ok(triple) => {
                    let arch = uname
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    pass(&format!("supported remote target: {triple}"));
                    triple_arch = Some((triple, arch));
                }
                Err(e) => {
                    fail(&format!("unsupported remote: {e:#}"));
                    failures += 1;
                }
            }
        }
        Err(e) => {
            fail(&format!("ssh connect / uname failed: {e:#}"));
            failures += 1;
        }
    }

    // 3. A deployable agent binary exists for that target.
    if let Some((triple, arch)) = &triple_arch {
        match bootstrap::agent_binary_for(triple, arch) {
            Ok(path) => pass(&format!("agent binary available: {}", path.display())),
            Err(e) => {
                fail(&format!("no agent binary: {e:#}"));
                failures += 1;
            }
        }
    }

    // 4. Any running local session for this host?
    match control::request(host, &Request::Status).await {
        Ok(Response::StatusIs {
            state,
            agent_version,
            entries,
        }) => {
            pass(&format!(
                "running session: {state}; agent v{agent_version}; {} forward(s)",
                entries.len()
            ));
            if agent_version != env!("CARGO_PKG_VERSION") {
                note(&format!(
                    "agent is v{agent_version} but this client is v{} — \
                     re-run `portmanager {host} ...` to redeploy/update the agent",
                    env!("CARGO_PKG_VERSION")
                ));
            }
        }
        Ok(_) => note("running session answered unexpectedly"),
        Err(_) => note(
            "no running local session for this host (start one with `portmanager <host> <spec>`)",
        ),
    }

    // 5. Tail the remote agent log, if present.
    if hostname.is_some() {
        match bootstrap::ssh_capture(host, &["tail", "-n", "10", ".cache/portmanager/agent.log"])
            .await
        {
            Ok(log) if !log.trim().is_empty() => {
                println!("\nremote agent log (last lines):");
                for line in log.lines() {
                    println!("  {line}");
                }
            }
            Ok(_) => note("remote agent log is empty"),
            Err(_) => note("no remote agent log yet (agent has not run on this host)"),
        }
    }

    println!();
    if failures == 0 {
        println!("all critical checks passed");
        Ok(())
    } else {
        anyhow::bail!("{failures} critical check(s) failed");
    }
}

fn pass(msg: &str) {
    println!("  [ok]   {msg}");
}
fn fail(msg: &str) {
    println!("  [FAIL] {msg}");
}
fn note(msg: &str) {
    println!("  [note] {msg}");
}
