# portmanager

Resilient QUIC port forwarder with SSH auto-bootstrap — VSCode-style port
forwarding with mosh-style stamina. Forward ports from a remote machine (and
from networks/containers *behind* it) to local ports, surviving Wi-Fi roaming,
VPN flaps, and laptop sleep without ever refreshing anything.

```console
$ portmanager myhost 8888 192.168.4.2:8080->8080 podman:web@5432->5432
INFO bootstrapping agent over SSH
INFO connected to agent
INFO forward up local=127.0.0.1:8888 target=127.0.0.1:8888
INFO forward up local=127.0.0.1:8080 target=192.168.4.2:8080
INFO forward up local=127.0.0.1:5432 target=10.88.0.5:5432 ns=podman:web
INFO session up — Ctrl-C to stop
```

Launched on a terminal, the foreground client opens an **interactive TUI** — a
VSCode-style table of forwards (Port · Forwarded Address · Running Process ·
Namespace · Visibility · Origin · Rate · Health) with a session-state header and
a log pane. You don't need to pass any specs: start `portmanager myhost` and add
them live.

```text
portmanager  myhost  connected  agent v0.1.0
┌ forwards (2) ───────────────────────────────────────────────────────────────────────┐
│ Port    Forwarded Address    Running Process   Namespace  Visibility  Origin  Rate    │
│▶ 8888   127.0.0.1:8888       node (5123)       host       private     user    1.2 MiB/s│
│  5432   10.88.0.5:5432       postgres (1847)   podman:web private     user    idle     │
└───────────────────────────────────────────────────────────────────────────────────────┘
 a add  d drop  o open  y copy  i detail  v vis  f find  / filter  ? help  q quit
```

Keys: `a` add a forward (type any spec), `d` drop the selected one (with a `y/n`
confirm), `o` open it in your web browser (`http://127.0.0.1:<port>`), `y` copy
its URL to the clipboard, `i` inspect it (full health, byte counts, and a live
throughput sparkline), `v` toggle its visibility (loopback ↔ exposed on
`0.0.0.0`), `f` open the **discovered-ports picker** to forward a port the agent
sees but you haven't forwarded yet, `/` filter the table, `PgUp`/`PgDn` scroll
the log, `?` show all keys, `q` quit. The "Rate" column and detail sparkline show
live throughput. "Running Process" is resolved on the remote (Linux remotes
only). Piped/non-TTY invocations fall back to plain logging.

Run the local client in the background (no TUI) with `-d`/`--daemon`:

```console
$ portmanager -d myhost 8888 db.internal:5432
$ portmanager status myhost
$ portmanager stop myhost
```

## Install

Install from the published Docker image — no source checkout or Rust toolchain
needed:

```console
$ curl -fsSL https://raw.githubusercontent.com/lacraig2/portmanager/main/scripts/install.sh | bash
```

Already have the image, or prefer not to fetch from GitHub? The installer is
baked into the image — stream it out and run it (same effect, no GitHub fetch):

```console
$ docker run --rm --entrypoint cat lacraig2/portmanager:latest /install.sh | bash
```

The image (multi-arch, `lacraig2/portmanager`) carries a static-musl client
binary plus both bundled Linux agents, and the installer adapts to your OS:

- **Linux** — extracts the static binary into `~/.local/bin/portmanager` and the
  bundled agents into the dist cache (`~/.cache/portmanager/dist/`). It runs
  natively afterward; **Docker is not needed at runtime.**
- **macOS / other** — installs a thin `portmanager` wrapper into `~/.local/bin`
  that runs the client inside the container (the `docker-run` recipe below).
  **Docker is required at runtime.**

Override the source image or install dir with `PORTMANAGER_IMAGE` /
`PORTMANAGER_PREFIX`, or pin a version by passing it as an argument:

```console
$ curl -fsSL .../scripts/install.sh | bash -s -- lacraig2/portmanager:v0.0.19
```

Have a checkout? Build from source instead — see [Build](#build).

## Why

- **mosh can't forward ports** (terminal only), **VSCode forwarding needs
  constant window refreshing**, and `ssh -L` dies with the connection.
- portmanager runs its data channel over **QUIC**: connection migration makes
  interface changes (wifi→ethernet) seamless *while awake*, and a mosh-style
  session layer (re-attach by session id against a server-side grace window)
  makes sleep/outage recovery automatic and sub-second. The reconnect loop
  never gives up — capped backoff with jitter, forever, like mosh's
  `[network outage]`.

## How it works

1. **Bootstrap over SSH** (your `~/.ssh/config`, keys, agent, jump hosts —
   unchanged). The client detects the remote arch, scp's a static musl agent
   binary into `~/.cache/portmanager/`, and launches it.
2. The agent **handshakes on the SSH pipe, then daemonizes** (mosh-server
   style) — it survives SSH death. Secrets travel the SSH channel, never argv.
3. The data channel is **QUIC with mutual TLS 1.3, pinned both ways**:
   ephemeral per-session certs, SHA-256 fingerprints exchanged over the
   authenticated SSH channel. No PKI, no TOFU window, no unencrypted mode.
4. Each forwarded TCP connection is one QUIC stream; everything multiplexes
   over a single connection.

### SSH-tunnel transport (`--via-ssh`)

The QUIC data channel dials the agent's UDP port **directly** — which needs a
UDP path from client to agent. For hosts reachable only through a jump host
(`ProxyJump`/bastion) with **no direct UDP route**, pass `--via-ssh`:

```
portmanager --via-ssh backend 8000
portmanager --via-ssh backend podman:web@10.88.0.5:5432->5432
```

In this mode the agent listens on a **loopback TCP port** instead of QUIC, and
the client carries the data plane over `ssh -N -L` — so any configured
`ProxyJump` applies automatically and SSH's own channel multiplexing moves every
forwarded connection. SSH is the trust anchor (no separate TLS); each connection
is gated by the session token. No directly reachable port and no firewall hole
are needed. The choice is remembered per host, so a later plain
`portmanager backend` keeps using it.

It still reconnects like the QUIC path: the agent daemon persists across SSH
death, so a dropped tunnel is re-stood and reattached; only when the agent is
gone does it re-bootstrap. Throughput is bounded by the single SSH channel — fine
for dev/db/web forwards; expect SSH-tunnel speeds for bulk transfers. All other
features (the `podman:`/`docker:`/`pid:` namespace dialing below, discovery, the
TUI, the control socket) work unchanged.

### Forward spec grammar

```
[NS@][HOST:]PORT[->[BINDADDR:]LOCALPORT]
[NS@]socks[->LOCALPORT]

8888                          # remote 127.0.0.1:8888 -> local 8888, or a free port if busy
192.168.4.2:8080              # remote 192.168.4.2:8080 -> local 8080, or a free port if busy
192.168.4.2:8080->8080        # a host on the remote's network
8080->0.0.0.0:8080            # expose the forward on the LAN, not just loopback
podman:web@10.88.0.5:5432->5432   # inside a rootless container's netns
pid:1234@8080                 # inside any process's netns (yours)
nspath:/run/user/1000/netns/x@80  # explicit namespace file
socks                         # a SOCKS5 proxy on local 1080 -> the remote's whole network
socks->9050                   # ...on a specific local port
podman:web@socks->1080        # ...whose targets are dialed from inside a container's netns
```

If `->LOCALPORT` is omitted, portmanager prefers the same local port and falls
back to an available ephemeral port. If `->LOCALPORT` is present, that local
port is strict and binding fails if it is unavailable. An optional `BINDADDR:`
before the local port sets the listener's bind address — loopback by default
(private), or `0.0.0.0` to expose the forward on the LAN. The TUI's `v` key
toggles this on a live forward.

### Reverse forwarding (`-R`)

`-R`/`--reverse` exposes a **local** service **on the remote** — the `ssh -R`
equivalent, the inverse of the default direction. The agent binds a listener on
the remote host, and each connection accepted there is carried back over the
data channel to the client, which dials a local target:

```
portmanager myhost -R 3000->3000                 # remote 127.0.0.1:3000 -> your local 3000
portmanager myhost -R 0.0.0.0:8080->192.168.1.5:80  # expose on the remote LAN, dial a local-network host
portmanager add  myhost -R 9000->9000            # add one to a running session
portmanager drop myhost -R 9000                  # drop by spec or remote bind port
```

Grammar: `[NS@][BINDADDR:]REMOTEPORT->[HOST:]LOCALPORT`. `BINDADDR` defaults to
the remote's loopback (use `0.0.0.0` to expose on the remote LAN); `HOST`
defaults to your `127.0.0.1`. The remote bind port is strict (no fallback). The
data path is bounded by remote DNS/reachability from the **client** side.
Reverse forwards are remembered per host like normal forwards and shown in the
TUI table as dimmed `← <port>` rows (vs `→ <port>` for forwards); select one and
press `d` to drop or `i` to inspect it, or add one live with `a` then
`-R <spec>`. Reverse forwarding is **QUIC-only** — it is not available over
`--via-ssh` (use `ssh -R` directly there).

### SOCKS5 dynamic proxy

`socks` binds a local SOCKS5 proxy instead of a fixed-target forward — the
`ssh -D` equivalent. Point a browser, `proxychains`, or `curl --socks5-hostname
localhost:1080 …` at it and every connection is dialed by the agent on the
remote, so you reach the remote's entire network from one port. Hostnames
resolve **on the remote** (remote DNS), so internal names that only resolve over
there just work. Prefixing a namespace (`podman:web@socks->1080`) dials every
proxied connection from *inside* that container's network view. SOCKS proxies
are loopback-only (no LAN exposure) and support no-auth CONNECT.

Namespace dialing enters rootless namespaces (userns+netns, the
`podman unshare` trick) via a resident per-namespace helper that hands
connected sockets back over SCM_RIGHTS. No published ports, no root.
Rootful `netns:<name>` is parsed but not yet supported.

### Live control & memory

```console
$ portmanager add   myhost 9000->9000   # bind on the running session, no restart
$ portmanager drop  myhost 8888         # by spec or local port
$ portmanager drop  myhost --all        # drop everything (alias: `clear`)
$ portmanager clear myhost
$ portmanager list  myhost              # shows per-forward health (ok / last error)
$ portmanager status myhost             # session state + agent/client versions
$ portmanager stop  myhost
$ portmanager forget myhost             # delete the saved state for this host
```

`add`/`list`/`status` report **live health**, not just whether the listener
bound: `add` tells you if the session is mid-reconnect, and `list`/`status` show
the most recent connection error per forward (e.g. the agent couldn't reach the
target) instead of a forward silently doing nothing.

### Debugging

```console
$ portmanager logs   myhost        # tail the remote agent log over SSH
$ portmanager logs   myhost -f     # follow it
$ portmanager doctor myhost        # checklist: SSH, arch, agent binary, session, log
$ portmanager -vv myhost 8888      # -v/-vv is threaded through to the remote agent
```

### Agent autoupdate

The agent binary is content-addressed on the remote (`agent-<triple>-<hash>`), so
a fresh launch always deploys the current client's agent. On bootstrap the client
also **evicts any lingering agent running a different version** (recorded in
`~/.cache/portmanager/agents/<port>.json`) and **garbage-collects stale cached
binaries**, so the remote converges on current code after a client upgrade.
`status`/`doctor` surface the running agent's version next to the client's so
skew is visible.

Changes persist: a plain `portmanager myhost` resumes the set you ended with
(per-host state), and `--profile NAME` uses/updates a named profile in
`config.toml`. Auto-forward rules make discovered listeners appear
automatically — the agent scans `/proc/<pid>/net/tcp` (host and watched
container namespaces, no setns) and the client binds matches with stable
local-port assignments:

```toml
# ~/.config/portmanager/state/myhost.toml (or a profile)
[[autoforward]]
ns = "podman:web"   # or "host"
ports = "*"          # or "8080, 9090"
local = "same"       # mirror remote port; fall back to a free one
```

## Honest limits

- A hard outage RSTs *in-flight* TCP connections (a byte stream can't be
  resumed losslessly — unlike mosh's terminal, there's no idempotent state to
  re-sync). Listeners stay bound and the session re-attaches; apps reconnect.
  Brief roaming within a live QUIC connection is fully lossless.
- The remote must allow **inbound UDP** on the agent's port (not just SSH/22).
  By default portmanager uses the mosh-style UDP range `60000-61000`; use
  `--remote-udp 0.0.0.0:PORT` if the remote firewall only allows one specific
  UDP port. When the QUIC connect can't reach the agent, portmanager inspects
  the remote's host firewall over SSH (ufw/firewalld/nftables/iptables) and
  prints the exact command to open the port — it never changes the firewall for
  you. `portmanager doctor <host>` reports this proactively. Cloud security
  groups / network ACLs are separate and must be opened in your provider.
- The agent's UDP listener is mutually authenticated, but it *is* a listening
  port run with your remote user's privileges; the grace window bounds how long
  it outlives a client. After the last client disconnects the agent waits this
  long for a re-attach (roaming/sleep/outage) before self-reaping. The default
  is **12 hours**; set it per-launch with `--agent-grace` (`30s`/`15m`/`12h`/`2d`,
  a bare number is seconds — e.g. `--agent-grace 2d` to survive a weekend, or
  `--agent-grace 5m` to reap quickly).
- One client per session. The control socket prevents a second client for the
  same host on one machine; two separate launches get separate agent sessions.
  Sharing a single session across clients (by copying its secrets) is
  unsupported.
- The accept-then-wait deadline for an in-flight local connection during an
  outage defaults to 10s; raise it with `PORTMANAGER_ATTACH_DEADLINE_SECS` to
  ride out longer reconnects without RSTing accepted connections.

## Build

`scripts/pm.sh` is the single entrypoint that handles the multi-target build
(host client + bundled Linux agents) and packaging:

```console
$ scripts/pm.sh build              # client (release) + musl agents -> package dir
$ scripts/pm.sh run myhost 8888    # run the packaged client (builds if missing)
$ scripts/pm.sh test               # cargo test (args forwarded)
$ scripts/pm.sh check              # fmt --check + clippy -D warnings + test (CI parity)
$ scripts/pm.sh package            # tar.gz the package for distribution
```

`build` assembles `dist/portmanager-<host-triple>/` — the client plus
`agents/agent-<triple>` beside it — which is the layout the client deploys
from, and also installs the agents into `~/.cache/portmanager/dist/`. Agent
cross-compilation uses `cargo-zigbuild`, `cross`, or a local `*-linux-musl-gcc`,
whichever is available (missing toolchains are skipped with a warning).

Plain cargo still works for a quick same-arch build:

```console
$ cargo build --release            # client (and same-arch agent)
$ scripts/build-agents.sh          # just the static musl agents, into the dist cache
```

Release packages include the client for one platform plus Linux agents under
`agents/`, so a Windows or macOS client can still deploy to Linux remotes. The
client looks for `agents/agent-<triple>` next to itself, then
`~/.cache/portmanager/dist/agent-<triple>`. `PORTMANAGER_AGENT_BIN` overrides
both for manual testing.

### Docker

A slim image (Alpine + `openssh-client` + a static-musl client with both Linux
agents bundled) runs the client from a container:

```console
$ scripts/pm.sh docker-build                 # -> portmanager:local
$ scripts/pm.sh docker-run myhost 8888 db.internal:5432
```

`docker-run` uses host networking (so forwarded ports land on the host's
loopback) and mounts your `~/.ssh` read-only, running as your own UID with
`/etc/passwd` mounted so SSH key ownership/permission checks pass; it forwards
`$SSH_AUTH_SOCK` when present. Equivalent raw command:

```console
$ docker run --rm -it --network host \
    --user "$(id -u):$(id -g)" -v /etc/passwd:/etc/passwd:ro \
    -v "$HOME/.ssh:$HOME/.ssh:ro" -e HOME="$HOME" \
    portmanager:local myhost 8888
```

Notes: `--network host` is Linux-only (Docker Desktop on macOS/Windows handles
it differently), and the control socket lives inside the container — use the
foreground form, or `docker exec` into the same container for `add`/`list`.
Multi-arch: `docker buildx build --platform linux/amd64,linux/arm64 .`.

#### Published image

Released images are pushed to Docker Hub as
[`lacraig2/portmanager`](https://hub.docker.com/r/lacraig2/portmanager):

```console
$ docker pull lacraig2/portmanager:latest
$ docker run --rm -it --network host \
    --user "$(id -u):$(id -g)" -v /etc/passwd:/etc/passwd:ro \
    -v "$HOME/.ssh:$HOME/.ssh:ro" -e HOME="$HOME" \
    lacraig2/portmanager myhost 8888
```

To install a `portmanager` command onto the host straight from this image
(native binary on Linux, a docker wrapper elsewhere), use the one-liner in
[Install](#install) — it runs `scripts/install.sh`.

CI builds and pushes a multi-arch manifest (`linux/amd64`, `linux/arm64`) on
pushes to `main` and on `vX.Y.Z` tags, via `.github/workflows/docker.yml`. A
main push publishes `:latest` **and** `:<version>` — the same next version
`ci.yml`'s release job computes (`reecetech/version-increment`), so the image
version matches the GitHub release cut from that commit. That workflow needs two repo secrets:
`DOCKERHUB_USERNAME` (`lacraig2`) and `DOCKERHUB_TOKEN` (a Docker Hub access
token). To publish by hand instead: `docker login -u lacraig2 && scripts/pm.sh
docker-push`.

## Test

```console
$ cargo test                       # unit + loopback QUIC + real agent process
$ podman run --rm -d --name pmtest alpine sleep 60
$ podman exec -d pmtest nc -l -p 7777 -s 127.0.0.1
$ cargo test --test netns_helper -- --ignored   # real namespace-entry proof
```
