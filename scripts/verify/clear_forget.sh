#!/usr/bin/env bash
# Verify `clear` (drop every forward live) and `forget` (delete persisted state).
#
# Usage: scripts/verify/clear_forget.sh [HOST]   (default: localhost)
set -euo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
source "$(dirname "$0")/lib.sh"

require_remote

token="clear-$$-$RANDOM"

# Two remote listeners; one seeds the session, one is added live.
p1="$(remote_free_port)"
read -r pid1 dir1 < <(start_remote_http "$p1" "one-$token")
add_cleanup "stop_remote_http '$pid1' '$dir1'"
pm_start_session "$p1"

p2="$(remote_free_port)"
read -r pid2 dir2 < <(start_remote_http "$p2" "two-$token")
add_cleanup "stop_remote_http '$pid2' '$dir2'"
pm add "$HOST" "$p2" >/dev/null

count="$(pm list "$HOST" | grep -cE '127\.0\.0\.1:[0-9]+')"
assert_eq "2" "$count" "two forwards active before clear"

clear_out="$(pm clear "$HOST")"
info "clear said: $clear_out"
assert_contains "$clear_out" "dropped 2" "clear reports dropping both forwards"

after="$(pm list "$HOST")"
assert_contains "$after" "(no forwards)" "list is empty after clear"

# Persisted state should now be empty; stop the session, then forget it.
pm stop "$HOST" >/dev/null 2>&1 || true
# Remove the auto-registered cleanup stop (session already stopped) is harmless.
forget_out="$(pm forget "$HOST")"
info "forget said: $forget_out"
assert_contains "$forget_out" "$HOST" "forget acknowledges the host"

# A second forget should report nothing left to forget.
forget_again="$(pm forget "$HOST")"
assert_contains "$forget_again" "no saved state" "state is gone after forget"

verify_summary
