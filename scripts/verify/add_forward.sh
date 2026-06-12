#!/usr/bin/env bash
# Verify the live `add` path end-to-end:
#   1. open an HTTP listener on the remote (over SSH),
#   2. `portmanager add` that port to a running session,
#   3. fetch through the local forwarded port and assert the content matches.
#
# Usage: scripts/verify/add_forward.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

token="add-$$-$RANDOM"

# A seed listener+forward so the session has something to start with (a session
# needs at least one forward or rule to launch).
seed_port="$(remote_free_port)"
read -r seed_pid seed_dir < <(start_remote_http "$seed_port" "seed-$token")
add_cleanup "stop_remote_http '$seed_pid' '$seed_dir'"
info "remote seed http on :$seed_port (pid $seed_pid)"

pm_start_session "$seed_port"

# Sanity: the seed forward already carries content.
seed_local="$(pm_local_port_for "$seed_port")" || { bad "seed forward not listed"; verify_summary; }
assert_eq "seed-$token" "$(fetch_token "$seed_local")" "seed forward serves content"

# --- the actual test: open a NEW remote port and add it live ---
test_port="$(remote_free_port)"
read -r test_pid test_dir < <(start_remote_http "$test_port" "$token")
add_cleanup "stop_remote_http '$test_pid' '$test_dir'"
info "remote test http on :$test_port (pid $test_pid)"

add_out="$(pm add "$HOST" "$test_port")"
info "add said: $add_out"
assert_contains "$add_out" "forward" "add reports a forward was set up"

test_local="$(pm_local_port_for "$test_port")" || { bad "added forward not listed"; verify_summary; }
info "added forward bound on local :$test_local"

assert_eq "$token" "$(fetch_token "$test_local")" "added forward serves the expected content"

# list/status should show it as healthy after a successful fetch.
assert_contains "$(pm list "$HOST")" "127.0.0.1:$test_port" "list shows the added forward"
assert_contains "$(pm status "$HOST")" "connected" "status reports connected"

# drop it and confirm the local listener is gone.
pm drop "$HOST" "$test_local" >/dev/null
sleep 0.5
if curl -fsS --max-time 3 "http://127.0.0.1:$test_local/token.txt" >/dev/null 2>&1; then
    bad "local listener still up after drop"
else
    ok "local listener closed after drop"
fi

verify_summary
