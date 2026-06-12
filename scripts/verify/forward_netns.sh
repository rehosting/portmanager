#!/usr/bin/env bash
# Verify forwarding *into a network namespace* (the rootless container case).
#
# Creates a fresh rootless user+net namespace on the remote with an HTTP server
# bound to 127.0.0.1 inside it, then forwards `pid:<pid>@127.0.0.1:<port>`. That
# loopback address is unreachable from the host namespace, so receiving the
# content proves the agent entered the namespace (via nsenter -U -n, the same
# path podman:/docker:/pid: use).
#
# Skips cleanly when the remote lacks rootless userns support.
#
# Usage: scripts/verify/forward_netns.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

if ! netns_supported; then
    skip "remote lacks rootless user+net namespace support (nsenter/unshare/ip or unprivileged userns disabled)"
fi

token="netns-$$-$RANDOM"

# Seed listener in the host namespace so the session can start.
seed_port="$(remote_free_port)"
read -r seed_pid seed_dir < <(start_remote_http "$seed_port" "seed-$token")
add_cleanup "stop_remote_http '$seed_pid' '$seed_dir'"
pm_start_session "$seed_port"

# HTTP server inside a rootless namespace; ns_pid anchors the namespace.
ns_port="$(remote_free_port)"
if ! read -r ns_pid ns_dir < <(start_remote_netns_http "$ns_port" "$token"); then
    skip "could not start a namespaced server on the remote"
fi
add_cleanup "stop_remote_http '$ns_pid' '$ns_dir'"
info "namespaced http on (ns of pid $ns_pid) 127.0.0.1:$ns_port"

# Sanity: that port is NOT reachable in the host namespace.
if ssh_remote "curl -fsS --max-time 2 http://127.0.0.1:$ns_port/token.txt" >/dev/null 2>&1; then
    bad "namespaced port is reachable from the host ns — test setup is not isolated"
else
    ok "namespaced port is isolated from the host namespace"
fi

spec="pid:${ns_pid}@127.0.0.1:${ns_port}"
info "adding namespace forward: $spec"
add_out="$(pm add "$HOST" "$spec")"
info "add said: $add_out"

ns_local="$(pm_local_port_for "$ns_port")" || { bad "namespace forward not listed"; verify_summary; }
info "namespace forward bound on local :$ns_local"

assert_eq "$token" "$(fetch_token "$ns_local")" "forward into the namespace serves the expected content"
assert_contains "$(pm list "$HOST")" "pid:${ns_pid}@" "list shows the namespace selector"

verify_summary
