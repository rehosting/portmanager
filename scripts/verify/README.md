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
| `health.sh` | a forward to a dead target surfaces a `last error` in `list`/`status` instead of silently doing nothing |
| `clear_forget.sh` | `clear` drops every forward live; `forget` deletes persisted host state |

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
