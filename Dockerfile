# syntax=docker/dockerfile:1
#
# Slim runtime image for the portmanager *client*. The client shells out to
# ssh/scp and deploys a bundled static-musl agent to the remote, so the image
# carries: a static-musl client binary + both Linux agents + openssh-client.
#
# Build (current host arch):       docker build -t portmanager:local .
# Build multi-arch:                docker buildx build --platform linux/amd64,linux/arm64 ...
# Run (see scripts/pm.sh docker-run for the full mount recipe):
#   docker run --rm -it --network host \
#     --user "$(id -u):$(id -g)" -v /etc/passwd:/etc/passwd:ro \
#     -v "$HOME/.ssh:$HOME/.ssh:ro" -e HOME="$HOME" \
#     portmanager:local <host> <spec>...

# ---------------------------------------------------------------------------
# Builder: build the static-musl client for the target arch plus BOTH Linux
# agents (the client deploys whichever matches the remote). zig gives painless
# musl cross-compilation, matching scripts/pm.sh's zigbuild path.
# Runs on the *build* platform (native, fast) and cross-compiles as needed.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder
ARG TARGETARCH
ARG ZIG_VERSION=0.13.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Install zig (for cargo-zigbuild cross-musl).
RUN set -eux; \
    a="$(uname -m)"; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${a}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -C /opt/zig --strip-components=1 -xJf /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig
RUN cargo install cargo-zigbuild --locked
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /src
COPY . .
RUN cargo zigbuild --release \
    --target x86_64-unknown-linux-musl \
    --target aarch64-unknown-linux-musl
# Assemble: client matching the runtime arch, plus both bundled agents laid out
# as `agents/agent-<triple>` (the layout src/bootstrap.rs deploys from).
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) ctriple=x86_64-unknown-linux-musl ;; \
      arm64) ctriple=aarch64-unknown-linux-musl ;; \
      "")    ctriple=x86_64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH '$TARGETARCH'" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out/agents; \
    cp "target/$ctriple/release/portmanager" /out/portmanager; \
    cp target/x86_64-unknown-linux-musl/release/portmanager  /out/agents/agent-x86_64-unknown-linux-musl; \
    cp target/aarch64-unknown-linux-musl/release/portmanager /out/agents/agent-aarch64-unknown-linux-musl; \
    chmod 0755 /out/portmanager /out/agents/*

# ---------------------------------------------------------------------------
# Runtime: slim Alpine with just the SSH client. The static-musl binary needs
# no libc; agents/ sits next to the binary so bootstrap finds them.
# ---------------------------------------------------------------------------
FROM alpine:3.20
RUN apk add --no-cache openssh-client
COPY --from=builder /out/portmanager /usr/local/bin/portmanager
COPY --from=builder /out/agents      /usr/local/bin/agents
ENTRYPOINT ["portmanager"]
