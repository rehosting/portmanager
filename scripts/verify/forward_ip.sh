#!/usr/bin/env bash
# Verify forwarding to a *specific IP* on the remote's network (not the agent's
# default loopback target). Uses 127.0.0.2 — a distinct loopback address that
# needs no setup on Linux — so the agent must honor the HOST in HOST:PORT.
#
# Usage: scripts/verify/forward_ip.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

# 127.0.0.2 is loopback on Linux without any aliasing; bail clearly elsewhere.
if ! ssh_remote 'python3 -c "import socket;s=socket.socket();s.bind((\"127.0.0.2\",0));s.close()"' 2>/dev/null; then
    skip "remote can't bind 127.0.0.2 (non-Linux or restricted loopback)"
fi

token="ip-$$-$RANDOM"
ip="127.0.0.2"
port="$(remote_free_port)"
read -r pid dir < <(start_remote_http "$port" "$token" "$ip")
add_cleanup "stop_remote_http '$pid' '$dir'"
info "remote http on $ip:$port (pid $pid)"

# Start the session forwarding the specific-IP target directly.
pm_start_session "$ip:$port"

local_port="$(pm_local_port_for "$port")" || { bad "IP forward not listed"; verify_summary; }
info "forward $ip:$port bound on local :$local_port"

assert_eq "$token" "$(fetch_token "$local_port")" "forward to $ip serves the expected content"
assert_contains "$(pm list "$HOST")" "$ip:$port" "list shows the $ip target"

verify_summary
