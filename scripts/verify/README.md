# End-to-end verification scripts

Behavioral checks that drive the **real** path: SSH to a host, open a listener
on it, run a portmanager session, manipulate it, and assert that content flows
through the local forwarded port.

```console
$ scripts/pm.sh build                 # build the client + bundled agents first
$ scripts/verify/run-all.sh [HOST]    # run every scenario (default HOST: localhost)
$ scripts/verify/add_forward.sh myhost   # or run one scenario against a host
```

`HOST` comes from the first argument or `$PM_HOST` (default `localhost`). It must
be an SSH alias / `user@host` reachable **non-interactively** (key-based auth)
with `python3` available remotely.

## Scenarios

| script | what it proves |
| --- | --- |
| `add_forward.sh` | open a remote port, `add` it live, fetch through the local port, content matches; `drop` closes the listener |
| `forward_ip.sh` | forward to a specific IP (`127.0.0.2`) on the remote, not just the agent's loopback |
| `forward_netns.sh` | forward into a rootless network namespace via `pid:<pid>@…` (skips if unprivileged userns is unavailable) |
| `socks.sh` | a `socks` dynamic proxy reaches the remote by IP and by hostname (remote DNS); `drop` closes it (skips if local curl lacks SOCKS5) |
| `socks_netns.sh` | a `pid:<pid>@socks` proxy dials every connection from inside a rootless namespace, reaching an in-namespace server (skips if userns/curl-SOCKS5 unavailable) |
| `health.sh` | a forward to a dead target surfaces a `last error` in `list`/`status` instead of silently doing nothing |
| `clear_forget.sh` | `clear` drops every forward live; `forget` deletes persisted host state |
| `via_ssh.sh` | the `--via-ssh` SSH-tunnel transport carries content (data plane over `ssh -L`, not QUIC); confirms the tunnel path was taken and the choice persisted; forwards into a namespace over the tunnel (`podman:`/`pid:`, if rootless ns work); and exercises **recovery** (kill the `ssh -L` tunnel → forwarding resumes), **concurrency** (8 simultaneous fetches), and **graceful shutdown** (`pm stop` exits the agent) |

Each scenario is self-contained: it starts and stops its own session and remote
listeners (cleanup runs on exit). `run-all.sh` reports PASS/FAIL/SKIP per
scenario and exits non-zero if any failed.

## Run against localhost

Point them at `localhost` for a fully local loop (no second machine), provided
`ssh localhost` works without a password:

```console
$ ssh-copy-id localhost        # one-time, if not already key-authed
$ scripts/verify/run-all.sh
```

Overrides: `PM_BIN` (client binary path), `PM_LAUNCH_ARGS` (extra session launch
args, e.g. `PM_LAUNCH_ARGS="-v"`).

## UDP-restricted hosts

The direct QUIC data plane needs **inbound UDP** open on the remote (default
ports 60000–61000). On hosts that filter it (many HPC clusters and locked-down
clouds), a direct launch fails with "could not reach the agent's UDP listener".
When `pm_start_session` sees that, it automatically retries over the SSH tunnel
(`--via-ssh`) so the scenarios still run; if the client build doesn't support
`--via-ssh`, the scenario is reported **SKIP** rather than FAIL. Force the tunnel
for the whole run with `PM_LAUNCH_ARGS=--via-ssh scripts/verify/run-all.sh HOST`.
