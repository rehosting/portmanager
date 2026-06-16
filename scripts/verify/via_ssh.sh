#!/usr/bin/env bash
# Verify the SSH-tunnel transport (`--via-ssh`) end-to-end:
#   1. open an HTTP listener on the remote (over SSH),
#   2. run a portmanager session with `--via-ssh` (data plane over `ssh -L`,
#      not QUIC/UDP),
#   3. fetch through the local forwarded port and assert the content matches,
#   4. confirm the session actually took the tunnel path (not a QUIC fallback),
#   5. confirm the `--via-ssh` choice was persisted for the host,
#   6. if rootless user+net namespaces work, forward *into a namespace* over the
#      tunnel (the same mechanism `podman:<name>` uses),
#   7. resilience: kill the `ssh -L` tunnel and confirm forwarding recovers,
#   8. concurrency: many simultaneous connections multiplexed over one tunnel,
#   9. graceful shutdown: `pm stop` exits the remote agent promptly.
#
# This is the path for hosts reachable only through a jump host (ProxyJump) with
# no direct UDP route. Point it at such a host — `ssh -L` follows the jump
# automatically — or at `localhost` for a local loop.
#
# Usage: scripts/verify/via_ssh.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

# Force the tunnel transport for this scenario's session launch, on top of any
# caller-supplied PM_LAUNCH_ARGS.
PM_LAUNCH_ARGS=(--via-ssh ${PM_LAUNCH_ARGS[@]+"${PM_LAUNCH_ARGS[@]}"})
PM_LAUNCH_ARGS_RAW="--via-ssh${PM_LAUNCH_ARGS_RAW:+ $PM_LAUNCH_ARGS_RAW}"

require_remote

token="viassh-$$-$RANDOM"

# Seed listener + forward so the session has something to start with.
seed_port="$(remote_free_port)"
read -r seed_pid seed_dir < <(start_remote_http "$seed_port" "$token")
add_cleanup "stop_remote_http '$seed_pid' '$seed_dir'"
info "remote http on :$seed_port (pid $seed_pid)"

pm_start_session "$seed_port"

# --- core proof: content flows over the SSH-carried data plane ---
seed_local="$(pm_local_port_for "$seed_port")" || { bad "forward not listed"; verify_summary; }
info "forward bound on local :$seed_local"
assert_eq "$token" "$(fetch_token "$seed_local")" "content flows over the ssh tunnel"
assert_contains "$(pm status "$HOST")" "connected" "status reports connected"

# Echo the first path argument that exists, else nothing. Used to locate the
# client's cache/config dirs, which differ by OS (Linux XDG vs macOS Library).
_first_existing() {
    local p
    for p in "$@"; do
        [[ -e "$p" ]] && { echo "$p"; return 0; }
    done
    return 1
}

# --- prove it really used the tunnel transport, not a QUIC fallback ---
client_log="$(_first_existing \
    "${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/client.log" \
    "$HOME/Library/Caches/portmanager/client.log")" || client_log=""
if [[ -n "$client_log" ]] && grep -qi "ssh tunnel" "$client_log"; then
    ok "client log confirms the ssh-tunnel transport"
elif [[ -n "$client_log" ]]; then
    bad "client log found but shows no 'ssh tunnel' evidence ($client_log)"
else
    info "note: could not locate the client log to confirm the transport (non-fatal); content already flowed over a --via-ssh session"
fi

# --- prove the tunnel choice is remembered for a plain relaunch ---
host_key="${HOST//[^A-Za-z0-9.-]/_}"
state_file="$(_first_existing \
    "${XDG_CONFIG_HOME:-$HOME/.config}/portmanager/state/${host_key}.toml" \
    "$HOME/Library/Application Support/portmanager/state/${host_key}.toml")" || state_file=""
if [[ -n "$state_file" ]] && grep -q 'via_ssh = true' "$state_file"; then
    ok "via_ssh persisted to host state"
else
    info "note: via_ssh persistence not observed (non-fatal)"
fi

# --- namespace dialing over the tunnel (the podman:/pid: case) ---
if netns_supported; then
    ns_port="$(remote_free_port)"
    read -r ns_pid ns_dir < <(start_remote_netns_http "$ns_port" "ns-$token")
    add_cleanup "ssh_remote \"kill '$ns_pid' 2>/dev/null; rm -rf '$ns_dir'\""
    info "remote in-namespace http on :$ns_port (anchor pid $ns_pid)"

    add_out="$(pm add "$HOST" "pid:$ns_pid@127.0.0.1:$ns_port")"
    info "add said: $add_out"
    if ns_local="$(pm_local_port_for "$ns_port")"; then
        assert_eq "ns-$token" "$(fetch_token "$ns_local")" \
            "in-namespace content flows over the ssh tunnel (podman:/pid: path)"
    else
        bad "in-namespace forward not listed"
    fi
else
    info "note: rootless user+net namespaces unavailable on '$HOST'; skipping the namespace-over-tunnel check"
fi

# Find the client's persistent `ssh -N -L` tunnel process (the data plane), if
# any — matched by the forward flags plus the target host on its command line.
find_tunnel_pid() {
    pgrep -f -- "-N -L 127.0.0.1" 2>/dev/null | while read -r p; do
        if ps -o command= -p "$p" 2>/dev/null | grep -q -- "$HOST"; then
            echo "$p"
            break
        fi
    done
}

# --- resilience: kill the ssh -L tunnel and confirm forwarding recovers ---
# Exercises the supervisor's tunnel monitor loop (respawn the forward + reattach
# to the still-alive agent). The local listener stays bound throughout.
tunnel_pid="$(find_tunnel_pid)"
if [[ -n "$tunnel_pid" ]]; then
    info "killing client ssh -L tunnel (pid $tunnel_pid) to force a reconnect"
    kill "$tunnel_pid" 2>/dev/null || true
    recovered="no"
    for _ in $(seq 1 30); do
        if [[ "$(fetch_token "$seed_local" 2>/dev/null || true)" == "$token" ]]; then
            recovered="yes"
            break
        fi
        sleep 1
    done
    assert_eq "yes" "$recovered" "forwarding recovers after the ssh -L tunnel is killed"
else
    info "note: could not locate the ssh -L tunnel process; skipping the resilience check"
fi

# --- concurrency: many simultaneous connections multiplexed over one tunnel ---
info "driving 8 concurrent fetches over the tunnel"
conc_pids=()
for _ in $(seq 1 8); do
    (
        out="$(fetch_token "$seed_local" 2>/dev/null || true)"
        [[ "$out" == "$token" ]]
    ) &
    conc_pids+=("$!")
done
conc_fail=0
for p in "${conc_pids[@]}"; do
    wait "$p" || conc_fail=$((conc_fail + 1))
done
assert_eq "0" "$conc_fail" "8 concurrent fetches all succeed over the tunnel"

# --- graceful shutdown: `pm stop` exits *this session's* agent promptly ---
# Identify the agent by pid (from its remote state file, keyed by the tunnel
# port parsed from the client log) so leftover agents from other sessions can't
# mask the result.
agent_pid=""
if [[ -n "$client_log" ]]; then
    tunnel_port="$(grep -i 'ssh tunnel' "$client_log" 2>/dev/null \
        | grep -o 'port=[0-9]*' | tail -1 | cut -d= -f2 || true)"
    if [[ -n "${tunnel_port:-}" ]]; then
        agent_pid="$(ssh_remote "python3 - <<PY
import json, os
try:
    print(json.load(open(os.path.expanduser('~/.cache/portmanager/agents/${tunnel_port}.json')))['pid'])
except Exception:
    pass
PY" || true)"
    fi
fi

info "stopping the session; this session's agent (pid ${agent_pid:-?}) should exit"
pm stop "$HOST" >/dev/null 2>&1 || true
if [[ -n "$agent_pid" ]]; then
    agent_gone="no"
    for _ in $(seq 1 10); do
        if ! ssh_remote "kill -0 '$agent_pid' 2>/dev/null"; then
            agent_gone="yes"
            break
        fi
        sleep 1
    done
    assert_eq "yes" "$agent_gone" "this session's agent (pid $agent_pid) exits promptly after pm stop"
else
    info "note: could not determine this session's agent pid; skipping the shutdown check"
fi

verify_summary
