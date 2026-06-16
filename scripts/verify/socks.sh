#!/usr/bin/env bash
# Verify the SOCKS5 dynamic proxy end-to-end (the `ssh -D` equivalent):
#   1. open an HTTP listener on the remote (over SSH),
#   2. run a session with a `socks` forward (one local SOCKS5 port),
#   3. fetch through the proxy by IP and assert the content matches,
#   4. fetch by *hostname* (remote DNS): the name resolves on the remote side,
#   5. drop the proxy and confirm it stops accepting.
#
# Proves the whole path: SOCKS negotiation -> QUIC stream -> agent dial -> splice,
# with no fixed target (the destination comes from each connection's handshake).
#
# Usage: scripts/verify/socks.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

if ! curl_supports_socks; then
    skip "local curl lacks SOCKS5 support (--socks5)"
fi

token="socks-$$-$RANDOM"

# A single HTTP server on the remote loopback is enough; the proxy reaches it.
http_port="$(remote_free_port)"
read -r http_pid http_dir < <(start_remote_http "$http_port" "$token")
add_cleanup "stop_remote_http '$http_pid' '$http_dir'"
info "remote http on :$http_port (pid $http_pid)"

# Launch with a bare `socks` forward (local 1080, or the next free rung). The
# SOCKS proxy is itself the session's seed forward.
pm_start_session "socks"

socks_local="$(pm_socks_local_port)" || { bad "socks proxy not listed"; verify_summary; }
info "socks proxy bound on local :$socks_local"
assert_contains "$(pm list "$HOST")" "socks" "list shows the socks forward"

# 1) Reach the remote server by IP through the proxy (curl resolves locally,
#    then asks the proxy to CONNECT to 127.0.0.1:<http_port> on the remote).
assert_eq "$token" "$(fetch_token_socks "$socks_local" 127.0.0.1 "$http_port" local)" \
    "socks proxy reaches the remote server by IP"

# 2) Remote DNS: send the *hostname* to the proxy so the agent resolves it on the
#    remote. `localhost` resolves to 127.0.0.1 over there, reaching the server —
#    proving names are resolved remotely, not locally.
assert_eq "$token" "$(fetch_token_socks "$socks_local" localhost "$http_port" remote)" \
    "socks proxy resolves the target hostname on the remote (remote DNS)"

# status should report a healthy, connected session.
assert_contains "$(pm status "$HOST")" "connected" "status reports connected"

# 3) Drop the proxy; it must stop accepting SOCKS connections.
pm drop "$HOST" "$socks_local" >/dev/null
sleep 0.5
if fetch_token_socks "$socks_local" 127.0.0.1 "$http_port" local >/dev/null 2>&1; then
    bad "socks proxy still serving after drop"
else
    ok "socks proxy closed after drop"
fi

verify_summary
