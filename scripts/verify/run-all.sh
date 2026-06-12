#!/usr/bin/env bash
# Run every portmanager verification scenario against HOST and summarize.
#
# Usage: scripts/verify/run-all.sh [HOST]   (default: localhost)
#
# Each scenario is self-contained (starts/stops its own session and remote
# listeners). A failing scenario does not stop the others.
set -uo pipefail
HOST="${1:-${PM_HOST:-localhost}}"
dir="$(dirname "$0")"
scenarios=(add_forward forward_ip forward_netns health clear_forget)

# Parallel indexed arrays (no associative arrays — must work on bash 3.2/macOS).
statuses=()
fail=0
for s in "${scenarios[@]}"; do
    printf '\n\033[1;35m########## %s ##########\033[0m\n' "$s"
    "$dir/$s.sh" "$HOST"
    case $? in
        0) statuses+=("PASS") ;;
        2) statuses+=("SKIP") ;;
        *) statuses+=("FAIL"); fail=1 ;;
    esac
done

printf '\n\033[1;35m===== summary (host: %s) =====\033[0m\n' "$HOST"
i=0
for s in "${scenarios[@]}"; do
    printf '  %-14s %s\n' "$s" "${statuses[$i]}"
    i=$((i + 1))
done
exit "$fail"
