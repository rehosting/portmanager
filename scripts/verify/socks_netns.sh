#!/usr/bin/env bash
# Verify a *namespace-scoped* SOCKS5 proxy: a single `pid:<pid>@socks` forward
# whose every proxied connection is dialed from inside a rootless network
# namespace. This is something `ssh -D` can't do — the proxy's exit point is the
# container's network view.
#
# Creates a fresh rootless user+net namespace on the remote with an HTTP server
# bound to 127.0.0.1 inside it (unreachable from the host ns), runs a
# `pid:<pid>@socks` proxy, and fetches through it: reaching the in-namespace
# server proves the agent entered the namespace per proxied connection.
#
# Skips cleanly when the remote lacks rootless userns support or local curl lacks
# SOCKS5.
#
# Usage: scripts/verify/socks_netns.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

if ! curl_supports_socks; then
    skip "local curl lacks SOCKS5 support (--socks5)"
fi
if ! netns_supported; then
    skip "remote lacks rootless user+net namespace support"
fi

token="socksns-$$-$RANDOM"

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

# A SOCKS proxy whose targets are dialed from inside that namespace.
spec="pid:${ns_pid}@socks"
info "starting namespace-scoped socks proxy: $spec"
pm_start_session "$spec"

socks_local="$(pm_socks_local_port)" || { bad "socks proxy not listed"; verify_summary; }
info "namespace socks proxy bound on local :$socks_local"
assert_contains "$(pm list "$HOST")" "pid:${ns_pid}@socks" "list shows the ns-scoped socks selector"

# Reaching the in-namespace loopback server through the proxy proves the agent
# dialed from inside the namespace.
assert_eq "$token" "$(fetch_token_socks "$socks_local" 127.0.0.1 "$ns_port" local)" \
    "ns-scoped socks proxy reaches the in-namespace server"

verify_summary
