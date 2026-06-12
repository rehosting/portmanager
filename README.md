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

Run the local client in the background with `--daemon`:

```console
$ portmanager --daemon myhost 8888 db.internal:5432
$ portmanager status myhost
$ portmanager stop myhost
```

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

### Forward spec grammar

```
[NS@][HOST:]PORT[->LOCALPORT]

8888                          # remote 127.0.0.1:8888 -> local 8888, or a free port if busy
192.168.4.2:8080              # remote 192.168.4.2:8080 -> local 8080, or a free port if busy
192.168.4.2:8080->8080        # a host on the remote's network
podman:web@10.88.0.5:5432->5432   # inside a rootless container's netns
pid:1234@8080                 # inside any process's netns (yours)
nspath:/run/user/1000/netns/x@80  # explicit namespace file
```

If `->LOCALPORT` is omitted, portmanager prefers the same local port and falls
back to an available ephemeral port. If `->LOCALPORT` is present, that local
port is strict and binding fails if it is unavailable.

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
  UDP port.
- The agent's UDP listener is mutually authenticated, but it *is* a listening
  port run with your remote user's privileges; the grace window
  (`--grace-secs`, default 300) bounds how long it outlives a client.

## Build

```console
$ cargo build --release            # client (and same-arch agent)
$ scripts/build-agents.sh          # static musl agents (x86_64 + aarch64)
```

Release packages include the client for one platform plus Linux agents under
`agents/`, so a Windows or macOS client can still deploy to Linux remotes. The
client looks for `agents/agent-<triple>` next to itself, then
`~/.cache/portmanager/dist/agent-<triple>`. `PORTMANAGER_AGENT_BIN` overrides
both for manual testing.

## Test

```console
$ cargo test                       # unit + loopback QUIC + real agent process
$ podman run --rm -d --name pmtest alpine sleep 60
$ podman exec -d pmtest nc -l -p 7777 -s 127.0.0.1
$ cargo test --test netns_helper -- --ignored   # real namespace-entry proof
```
