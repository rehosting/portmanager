#!/usr/bin/env bash
# Verify the forward-health reporting: a forward whose target has no listener
# must surface a connection error in `list`/`status` instead of silently
# appearing "up".
#
# Usage: scripts/verify/health.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

token="health-$$-$RANDOM"

# Seed listener so the session can start and report "connected".
seed_port="$(remote_free_port)"
read -r seed_pid seed_dir < <(start_remote_http "$seed_port" "seed-$token")
add_cleanup "stop_remote_http '$seed_pid' '$seed_dir'"
pm_start_session "$seed_port"

# A remote port with NOTHING listening on it.
dead_port="$(remote_free_port)"
info "adding forward to dead remote port :$dead_port (no listener)"
pm add "$HOST" "$dead_port" >/dev/null
dead_local="$(pm_local_port_for "$dead_port")" || { bad "dead forward not listed"; verify_summary; }

# Trigger a connection so the agent attempts (and fails) to dial the target.
curl -s --max-time 3 "http://127.0.0.1:$dead_local/" >/dev/null 2>&1 || true
sleep 1

listing="$(pm list "$HOST")"
info "list output:"
printf '%s\n' "$listing"

# The dead forward's line should carry an error; the seed line should not.
dead_line="$(grep -E "127\.0\.0\.1:${dead_port}([[:space:]]|->)" <<<"$listing" || true)"
assert_contains "$dead_line" "last error" "dead-target forward shows a last error"

seed_line="$(grep -E "127\.0\.0\.1:${seed_port}([[:space:]]|->)" <<<"$listing" || true)"
if [[ "$seed_line" == *"last error"* ]]; then
    bad "healthy seed forward unexpectedly shows an error: $seed_line"
else
    ok "healthy seed forward shows no error"
fi

verify_summary
