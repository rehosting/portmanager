#!/usr/bin/env bash
# Shared helpers for portmanager end-to-end verification scripts.
#
# These drive the *real* path: SSH to a host, open a listener on it, run a
# portmanager session, manipulate it, and assert content flows through the
# local forwarded port.
#
# Requirements for the target host ($HOST, default "localhost"):
#   - passwordless SSH (key-based; these run with BatchMode where possible)
#   - python3 on the remote (used to serve/verify content and pick free ports)
#
# Scenario scripts set HOST (from $1 or $PM_HOST) and then `source` this file.
set -euo pipefail

HOST="${HOST:-${PM_HOST:-localhost}}"
# Extra args passed to the portmanager session launch (e.g. -v, --remote-udp).
# Keep the raw string for display; split into an array for passing.
PM_LAUNCH_ARGS_RAW="${PM_LAUNCH_ARGS:-}"
# shellcheck disable=SC2206  # intentional word-splitting of the arg string
PM_LAUNCH_ARGS=($PM_LAUNCH_ARGS_RAW)

# ---------------------------------------------------------------------------
# Locate the portmanager client. Prefer the built package (bundled agents),
# fall back to a plain release build.
# ---------------------------------------------------------------------------
_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
_host_triple="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p' || true)"
PM_BIN="${PM_BIN:-}"
if [[ -z "$PM_BIN" ]]; then
    for _cand in \
        "$_repo_root/dist/portmanager-$_host_triple/portmanager" \
        "$_repo_root/target/release/portmanager"; do
        if [[ -x "$_cand" ]]; then PM_BIN="$_cand"; break; fi
    done
fi
if [[ -z "$PM_BIN" || ! -x "$PM_BIN" ]]; then
    echo "error: no portmanager binary found; run 'scripts/pm.sh build' first" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Logging + assertions
# ---------------------------------------------------------------------------
_pass=0
_fail=0
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok:\033[0m %s\n' "$*"; _pass=$((_pass + 1)); }
bad()  { printf '\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; _fail=$((_fail + 1)); }
# Report a scenario as skipped (unsupported environment). Exits 2 so the runner
# can distinguish a skip from a pass.
skip() { printf '\033[1;33mSKIP:\033[0m %s\n' "$*" >&2; exit 2; }

assert_eq() { # expected actual message
    if [[ "$1" == "$2" ]]; then ok "$3"; else
        bad "$3 (expected '$1', got '$2')"
    fi
}
assert_contains() { # haystack needle message
    if [[ "$1" == *"$2"* ]]; then ok "$3"; else
        bad "$3 (missing '$2' in: $1)"
    fi
}

# Print the pass/fail tally and exit non-zero on any failure. Call at the end.
verify_summary() {
    echo
    if [[ "$_fail" -eq 0 ]]; then
        info "all $_pass check(s) passed"
        return 0
    fi
    bad "$_fail check(s) failed ($_pass passed)"
    return 1
}

# ---------------------------------------------------------------------------
# Cleanup framework: register teardown commands, run them in reverse on exit.
# ---------------------------------------------------------------------------
_cleanup=()
add_cleanup() { _cleanup+=("$1"); }
_run_cleanup() {
    local rc=$?
    for ((i = ${#_cleanup[@]} - 1; i >= 0; i--)); do
        eval "${_cleanup[$i]}" >/dev/null 2>&1 || true
    done
    return $rc
}
trap _run_cleanup EXIT

# ---------------------------------------------------------------------------
# SSH + remote helpers
# ---------------------------------------------------------------------------
ssh_remote() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" "$@"; }

# Verify the host is reachable and has python3; abort early with a clear error.
require_remote() {
    if ! ssh_remote true >/dev/null 2>&1; then
        echo "error: cannot SSH to '$HOST' non-interactively (need key-based auth)" >&2
        exit 1
    fi
    if ! ssh_remote 'command -v python3' >/dev/null 2>&1; then
        echo "error: python3 not found on '$HOST' (needed to serve/verify content)" >&2
        exit 1
    fi
    info "host '$HOST' reachable; client: $PM_BIN"
}

# Echo a free TCP port on the remote (loopback).
remote_free_port() {
    ssh_remote "python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY"
}

# Start an HTTP server on the remote serving a single file 'token.txt' whose
# body is $2, on port $1, bound to IP $3 (default 127.0.0.1). Echoes
# "<pid> <dir>" for stop_remote_http.
start_remote_http() { # port token [bind_ip]
    local port="$1" token="$2" ip="${3:-127.0.0.1}"
    ssh_remote "python3 - <<PY
import os, subprocess, tempfile
d = tempfile.mkdtemp(prefix='pm-verify-')
open(os.path.join(d, 'token.txt'), 'w').write('$token')
p = subprocess.Popen(
    ['python3', '-m', 'http.server', '$port', '--bind', '$ip'],
    cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=True,
)
print(p.pid, d)
PY"
}

# Kill a remote http server and remove its temp dir.
stop_remote_http() { # pid dir
    ssh_remote "kill '$1' 2>/dev/null; rm -rf '$2'" || true
}

# Whether the remote supports rootless user+net namespace entry (the path
# pid:/podman: forwards use). Checks for the tools and that an unprivileged
# `unshare -Urn` actually succeeds (some kernels disable it).
netns_supported() {
    ssh_remote 'command -v nsenter >/dev/null 2>&1 \
        && command -v unshare >/dev/null 2>&1 \
        && command -v ip >/dev/null 2>&1 \
        && unshare -Urn true >/dev/null 2>&1'
}

# Start an HTTP server inside a fresh rootless user+net namespace, bound to
# 127.0.0.1 *inside that namespace* (so it's unreachable from the host ns —
# reaching it proves the agent entered the namespace). Echoes "<pid> <dir>";
# the pid is the namespace's anchor process, usable as `pid:<pid>@`.
start_remote_netns_http() { # port token  -> "pid dir"
    local port="$1" token="$2"
    ssh_remote bash -s "$port" "$token" <<'REMOTE'
set -e
port="$1"; token="$2"
dir="$(mktemp -d -t pm-ns-XXXXXX)"
printf '%s' "$token" > "$dir/token.txt"
# nohup so it survives this SSH shell exiting; no -f so $! is the final
# (post-exec) process pid, which lives in the new user+net namespace.
nohup unshare -Urn bash -c \
    "ip link set lo up; cd '$dir'; exec python3 -m http.server $port --bind 127.0.0.1" \
    >/dev/null 2>&1 &
pid=$!
disown 2>/dev/null || true
sleep 0.6
kill -0 "$pid" 2>/dev/null || { echo "namespace server failed to start" >&2; exit 1; }
echo "$pid $dir"
REMOTE
}

# ---------------------------------------------------------------------------
# portmanager client wrapper + session helpers
# ---------------------------------------------------------------------------
pm() { "$PM_BIN" "$@"; }

# Start a background daemon session forwarding the seed spec(s). Registers a
# stop + cleanup. Best-effort stops any pre-existing session for $HOST first.
pm_start_session() { # spec...
    pm stop "$HOST" >/dev/null 2>&1 || true
    info "starting session: $HOST $* $PM_LAUNCH_ARGS_RAW"
    # The ${arr[@]+"${arr[@]}"} idiom expands to nothing when the array is empty,
    # avoiding the "unbound variable" error set -u raises in bash 3.2 (macOS).
    if ! pm --daemon ${PM_LAUNCH_ARGS[@]+"${PM_LAUNCH_ARGS[@]}"} "$HOST" "$@"; then
        echo "error: failed to start session; recent client log:" >&2
        local log="${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/client.log"
        [[ -f "$log" ]] && tail -n 20 "$log" >&2
        exit 1
    fi
    add_cleanup "pm stop '$HOST'"
}

# Echo the bound local port for the forward whose *remote* port is $1, by
# parsing `pm list`. Works for any spec form (loopback, HOST:PORT, NS@HOST:PORT)
# by matching the remote port at the tail of the spec column (field 2), after
# stripping any `->LOCAL` suffix. The first column is the local addr:port.
pm_local_port_for() { # remote_port
    local out
    out="$(pm list "$HOST" | awk -v rp="$1" '
        {
            spec = $2
            sub(/->.*/, "", spec)          # drop ->LOCAL
            n = split(spec, a, ":")        # last component is the remote port
            if (a[n] == rp) {
                m = split($1, b, ":")      # local addr:port
                print b[m]
            }
        }')"
    [[ -n "$out" ]] || return 1
    echo "$out"
}

# Fetch http://127.0.0.1:<port>/token.txt (short timeout); echoes the body.
fetch_token() { # local_port
    curl -fsS --max-time 5 "http://127.0.0.1:$1/token.txt"
}
