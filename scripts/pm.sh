#!/usr/bin/env bash
# pm.sh — single entrypoint to build, test, run, and package portmanager.
#
# portmanager ships as a *package*: a host-platform client binary plus the
# bundled static-musl Linux agents the client deploys to remotes. The client
# looks for `agents/agent-<triple>` next to itself (see src/bootstrap.rs), so a
# package directory laid out that way is directly runnable and exercises the
# real multi-target deploy path.
#
# Usage:
#   scripts/pm.sh build            # client (release) + Linux agents -> package dir
#   scripts/pm.sh test [ARGS...]   # cargo test (extra args forwarded)
#   scripts/pm.sh check            # fmt --check + clippy -D warnings + test (CI parity)
#   scripts/pm.sh run [ARGS...]    # run the packaged client (builds it if missing)
#   scripts/pm.sh package          # tar.gz the package dir for distribution
#   scripts/pm.sh agents           # (re)build just the bundled agents
#   scripts/pm.sh docker-build      # build the slim Docker image (portmanager:local)
#   scripts/pm.sh docker-run [ARGS] # run the client from the Docker image
#   scripts/pm.sh docker-push [REPO[:TAG]] # build + push to a registry (needs docker login)
#   scripts/pm.sh clean            # remove the dist package dir
#   scripts/pm.sh help
#
# The package dir is dist/portmanager-<host-triple>/. Agents are also installed
# into the dist cache (~/.cache/portmanager/dist) so a globally-installed or
# `cargo run` client finds them too.
set -euo pipefail

cd "$(dirname "$0")/.."

# Linux remote targets the agent is cross-compiled for (must match the set in
# bootstrap::target_triple).
AGENT_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

DIST_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/dist"

host_triple() { rustc -vV | sed -n 's/^host: //p'; }
pkg_dir() { echo "dist/portmanager-$(host_triple)"; }

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Cross-compile one agent target into target/<triple>/release/portmanager.
# Tries cargo-zigbuild (best on macOS), then cross (Linux), then native musl-gcc.
# Returns non-zero (and warns) if no suitable toolchain is available.
build_agent() {
    local triple="$1"
    local cc="${triple%%-*}-linux-musl-gcc"

    if command -v cargo-zigbuild >/dev/null 2>&1; then
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo zigbuild --release --target "$triple"
    elif [[ "$(uname -s)" == "Linux" ]] && command -v cross >/dev/null 2>&1; then
        cross build --release --target "$triple"
    elif command -v "$cc" >/dev/null 2>&1; then
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo build --release --target "$triple"
    else
        warn "skipping agent $triple: no Linux-musl cross toolchain found"
        warn "  install one of: cargo install cargo-zigbuild && brew install zig"
        warn "                  cargo install cross   # Linux hosts"
        warn "                  $cc"
        return 1
    fi
}

cmd_agents() {
    local pkg agents_dir built=0
    pkg="$(pkg_dir)"
    agents_dir="$pkg/agents"
    mkdir -p "$agents_dir" "$DIST_CACHE"
    for triple in "${AGENT_TARGETS[@]}"; do
        log "building agent $triple"
        if build_agent "$triple"; then
            install -m 0755 "target/$triple/release/portmanager" "$agents_dir/agent-$triple"
            install -m 0755 "target/$triple/release/portmanager" "$DIST_CACHE/agent-$triple"
            log "  -> $agents_dir/agent-$triple"
            built=$((built + 1))
        fi
    done
    if [[ "$built" -eq 0 ]]; then
        warn "no agents were built — packages for Linux remotes will be incomplete."
        warn "the client can still serve a same-arch Linux remote via its own binary."
    fi
}

cmd_build() {
    local pkg
    pkg="$(pkg_dir)"
    log "building client (release)"
    cargo build --release
    mkdir -p "$pkg"
    install -m 0755 target/release/portmanager "$pkg/portmanager"
    cmd_agents
    log "package ready: $pkg"
    printf '  %s\n' "$pkg"/* "$pkg"/agents/* 2>/dev/null || true
}

cmd_test() { log "cargo test"; cargo test "$@"; }

cmd_check() {
    log "fmt --check";  cargo fmt --all --check
    log "clippy";       cargo clippy --all-targets -- -D warnings
    log "test";         cargo test
}

cmd_run() {
    local pkg client
    pkg="$(pkg_dir)"
    client="$pkg/portmanager"
    if [[ ! -x "$client" ]]; then
        log "package client missing; building first"
        cmd_build
    fi
    log "running $client $*"
    exec "$client" "$@"
}

cmd_package() {
    local pkg
    pkg="$(pkg_dir)"
    [[ -x "$pkg/portmanager" ]] || die "no package to archive; run '$0 build' first"
    mkdir -p packages
    local name; name="$(basename "$pkg")"
    tar -C dist -czf "packages/$name.tar.gz" "$name"
    log "wrote packages/$name.tar.gz"
}

cmd_clean() {
    rm -rf "$(pkg_dir)"
    log "removed $(pkg_dir)"
}

DOCKER_IMAGE="${PORTMANAGER_IMAGE:-portmanager:local}"

cmd_docker_build() {
    command -v docker >/dev/null 2>&1 || die "docker not found"
    log "building image $DOCKER_IMAGE"
    docker build -t "$DOCKER_IMAGE" "$@" .
    log "built $DOCKER_IMAGE"
}

# Run the client from the image with the mounts SSH needs. Uses host networking
# so forwarded local ports are reachable on the host's loopback, and runs as the
# invoking user (with /etc/passwd mounted) so SSH key ownership/perms match.
cmd_docker_run() {
    command -v docker >/dev/null 2>&1 || die "docker not found"
    local args=(
        --rm -it
        --network host
        --user "$(id -u):$(id -g)"
        -v /etc/passwd:/etc/passwd:ro
        -v /etc/group:/etc/group:ro
        -v "$HOME/.ssh:$HOME/.ssh:ro"
        -e HOME="$HOME"
    )
    # Forward the SSH agent socket if one is available.
    if [[ -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK:-}" ]]; then
        args+=(-v "$SSH_AUTH_SOCK:$SSH_AUTH_SOCK" -e "SSH_AUTH_SOCK=$SSH_AUTH_SOCK")
    fi
    log "docker run $DOCKER_IMAGE $*"
    exec docker run "${args[@]}" "$DOCKER_IMAGE" "$@"
}

# Build and push the image to a registry. Single-arch (host) for a quick manual
# publish — multi-arch publishing is CI's job (.github/workflows/docker.yml).
# Requires `docker login` as an account with push access to REPO.
cmd_docker_push() {
    command -v docker >/dev/null 2>&1 || die "docker not found"
    local ref="${1:-lacraig2/portmanager:latest}"
    [[ "$ref" == *:* ]] || ref="$ref:latest"
    log "building $ref"
    docker build -t "$ref" .
    log "pushing $ref (must be 'docker login'd as an account with push access)"
    docker push "$ref"
    log "pushed $ref"
}

# Print the leading comment block (after the shebang), stripping `# `.
cmd_help() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

main() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        build)   cmd_build "$@" ;;
        agents)  cmd_agents "$@" ;;
        test)    cmd_test "$@" ;;
        check)   cmd_check "$@" ;;
        run)     cmd_run "$@" ;;
        package) cmd_package "$@" ;;
        docker-build) cmd_docker_build "$@" ;;
        docker-run)   cmd_docker_run "$@" ;;
        docker-push)  cmd_docker_push "$@" ;;
        clean)   cmd_clean "$@" ;;
        help|-h|--help) cmd_help ;;
        *) die "unknown subcommand '$sub' (try '$0 help')" ;;
    esac
}

main "$@"
