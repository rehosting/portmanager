#!/usr/bin/env bash
# install.sh — install portmanager onto the local system *from the published
# Docker image*, no source checkout or Rust toolchain required.
#
# Quick install (fresh machine):
#   curl -fsSL https://raw.githubusercontent.com/lacraig2/portmanager/main/scripts/install.sh | bash
#
# The published image (see .github/workflows/docker.yml) carries a static-musl
# client binary plus both bundled Linux agents. How we install depends on the
# host OS, because that musl binary only runs on Linux:
#
#   Linux            -> extract the static binary into $PREFIX and the bundled
#                       agents into the dist cache. `portmanager` then runs
#                       natively; Docker is NOT needed at runtime.
#   macOS / other    -> install a thin `portmanager` wrapper into $PREFIX that
#                       runs the client inside the container (the docker-run
#                       recipe). Docker IS needed at runtime.
#
# Environment overrides:
#   PORTMANAGER_IMAGE   image ref to install from (default below; also overridable
#                       as the first positional arg)
#   PORTMANAGER_PREFIX  install dir for the `portmanager` binary/wrapper
#                       (default $HOME/.local/bin)
#   XDG_CACHE_HOME      base for the agent cache (default $HOME/.cache)
set -euo pipefail

IMAGE="${1:-${PORTMANAGER_IMAGE:-lacraig2/portmanager:latest}}"
PREFIX="${PORTMANAGER_PREFIX:-$HOME/.local/bin}"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/dist"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found (needed to fetch the image)"

# Warn if the install dir isn't on PATH so the user knows why `portmanager`
# might not be found after install.
path_hint() {
    case ":$PATH:" in
        *":$PREFIX:"*) ;;
        *) warn "$PREFIX is not on your PATH — add it, e.g.:";
           warn "  echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.profile" ;;
    esac
}

install_native() {
    log "pulling $IMAGE"
    docker pull "$IMAGE"

    local cid
    cid="$(docker create "$IMAGE")"
    # shellcheck disable=SC2064
    trap "docker rm -f '$cid' >/dev/null 2>&1 || true" EXIT

    mkdir -p "$PREFIX" "$CACHE"

    log "installing client -> $PREFIX/portmanager"
    docker cp "$cid:/usr/local/bin/portmanager" "$PREFIX/portmanager"
    chmod 0755 "$PREFIX/portmanager"

    # Lay the bundled agents into the dist cache so a `portmanager` on PATH
    # finds them (bootstrap lookup: ~/.cache/portmanager/dist/agent-<triple>).
    local tmp
    tmp="$(mktemp -d)"
    docker cp "$cid:/usr/local/bin/agents/." "$tmp/"
    local f n=0
    for f in "$tmp"/agent-*; do
        [ -e "$f" ] || continue
        install -m 0755 "$f" "$CACHE/$(basename "$f")"
        n=$((n + 1))
    done
    rm -rf "$tmp"
    log "installed $n bundled agent(s) -> $CACHE"

    log "done. native install — no Docker needed at runtime."
    path_hint
    log "try: portmanager --help"
}

install_wrapper() {
    log "pulling $IMAGE (warming the local image cache)"
    docker pull "$IMAGE"

    mkdir -p "$PREFIX"
    local target="$PREFIX/portmanager"
    log "installing docker wrapper -> $target"

    # The image's Linux binary can't run natively on this OS, so the wrapper
    # runs the client in a container with the mounts SSH needs: host networking
    # (forwarded ports land on the VM's loopback), ~/.ssh read-only, the invoking
    # user + /etc/passwd so SSH key ownership/perm checks pass, and the SSH
    # agent socket when present. Mirrors `scripts/pm.sh docker-run`.
    #
    # Under a VM-backed runtime (Colima/Lima) "host" is the Linux VM, not this
    # Mac. Such runtimes re-expose the VM's *wildcard* (0.0.0.0) listeners on the
    # Mac's loopback, but never the VM's own loopback listeners — so the wrapper
    # detects that case at runtime and defaults forwards to 0.0.0.0 (inside the
    # VM), which lands them back on the Mac's 127.0.0.1. Docker Desktop doesn't
    # bridge host-network ports either way; prefer the foreground form there.
    cat > "$target" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
IMAGE="\${PORTMANAGER_IMAGE:-$IMAGE}"
args=(
    --rm -it
    --network host
    --user "\$(id -u):\$(id -g)"
    -v /etc/passwd:/etc/passwd:ro
    -v /etc/group:/etc/group:ro
    -v "\$HOME/.ssh:\$HOME/.ssh:ro"
    -e HOME="\$HOME"
)
if [[ -n "\${SSH_AUTH_SOCK:-}" && -S "\${SSH_AUTH_SOCK:-}" ]]; then
    args+=(-v "\$SSH_AUTH_SOCK:\$SSH_AUTH_SOCK" -e "SSH_AUTH_SOCK=\$SSH_AUTH_SOCK")
fi
# Colima/Lima re-expose VM 0.0.0.0 ports on the Mac's loopback; bind forwards
# there so they're reachable. Honor an explicit PORTMANAGER_BIND_ADDR if set.
if [[ -z "\${PORTMANAGER_BIND_ADDR:-}" ]] \\
   && docker context inspect 2>/dev/null | grep -qiE 'colima|lima'; then
    args+=(-e PORTMANAGER_BIND_ADDR=0.0.0.0)
elif [[ -n "\${PORTMANAGER_BIND_ADDR:-}" ]]; then
    args+=(-e "PORTMANAGER_BIND_ADDR=\$PORTMANAGER_BIND_ADDR")
fi
exec docker run "\${args[@]}" "\$IMAGE" "\$@"
WRAPPER
    chmod 0755 "$target"

    log "done. wrapper install — Docker is required at runtime."
    if docker context inspect 2>/dev/null | grep -qiE 'colima|lima'; then
        log "detected a Colima/Lima Docker context — forwards will bind 0.0.0.0"
        log "inside the VM and surface on your Mac's 127.0.0.1."
    else
        warn "host networking behaves differently on Docker Desktop (macOS/Windows);"
        warn "the control socket lives inside the container, so prefer the foreground form."
    fi
    path_hint
    log "try: portmanager --help"
}

main() {
    local os
    os="$(uname -s)"
    log "image:  $IMAGE"
    log "prefix: $PREFIX"
    case "$os" in
        Linux) install_native ;;
        Darwin) install_wrapper ;;
        *) warn "unrecognized OS '$os' — installing the Docker wrapper"; install_wrapper ;;
    esac
}

main "$@"
