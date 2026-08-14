# Full flow sweep, build 69aa65a, Linux

Two real peers (`alpha`, `bravo`) paired by the real `add` ceremony, plus a third
(`charlie`) enrolled by bounded invitation. Isolated config dirs, hosted binary
from the test hub, sha256 verified against the manifest. No seeded stores.

This is what was actually observed, not what changed.

## Works, verified

| flow | evidence |
|---|---|
| `init` | identity created, `id` shows fingerprint + 90d cert |
| `add` mint + claim | `gigantic-element-1893`, both stores list the other |
| `send` + `receive` with a code | 390KB, receiver printed "verified (whole-file sha256 matched), acked" |
| `send --to <known>` | delivered + verified, 225 MB/s |
| `add --for device` + `join` | claimed in under 1s, `caps: transfer, mount`, ceiling persisted |
| armed store written with no daemon | `armed.json` present after mint; this is the #205 redesign |
| `reach` | `cold · would connect in ~297ms`, 1s |
| `doctor` | `verdict: healthy (total 0.3s)` with path breakdown |
| `forward` | `listening on 127.0.0.1:9999 -> bravo:9999` |
| `expose` | saved, and honestly reported L3 not up with the exact fix command |
| `mount` (3-arg form) | FUSE mount established read-only, remote contents listed |
| `shell` with acceptor + grant | exit 0 in **1s**, remote stdout returned |
| `grant` / `revoke` | cap appears and disappears in `devices`; revoke also removed the authorized_keys block |
| `devices rename` | renamed, correctly noted as a local alias only |
| `up --detach`, `status`, `down` | pidfile + log path named, status reports the pid, down stops that pid |
| `logs`, `logs --tail` | real daemon activity; empty state reads "no log yet (nothing written so far)" |
| `requests` | clean empty state |
| `reset` | itemised list of exactly what was wiped |
| `up --shell` as root | correctly REFUSED with the owner-equivalence warning |
| `join` on an already-joined device | refused with the right reason |

## Broken, filed today

- **#219** `shell` hangs with no output when the peer's daemon is up but not running
  the acceptor; also when the caller is outside its own ceiling, which is knowable
  locally. Contrast: with no daemon at all it errors cleanly at 45s. And `up --help`
  lists shell among what it serves, which is only true with `--shell`/`FILAMENT_L2=1`.
- **#220** main help teaches `mount <device>:<dir>`, which `mount` rejects; the real
  form is three positionals. The banner-vs-clap test cannot catch a wrong argument
  shape, only a missing verb.
- **#221** `send --to <unknown>` silently ignores the target and falls back to
  local-network discovery for 60s. `mount` rejects the same unknown name in 0s.

## Also observed, not filed separately

- `devices` renders cert expiry as `expires in 129600m`. That is 90 days in minutes.
  The short-duration formatter exists and is used correctly on the invitation screen.
- `offline` next to `(last seen just now)` reproduced (already #217).
- Non-interactive `init` demands `--recovery-file`, then on the next attempt `--yes`.
  Two round trips to learn the requirements; they should be stated together.

## Not covered, and why

- **Windows and macOS.** Everything above is Linux. The Windows equivalents need the
  pty cells on windows-latest or the owner's machine.
- **`up --install`.** Installs a real service; on this host that is the production
  signaling box, so it was not run.
- **Expired and spent invitations.** The reuse attempt was confounded: the peer had
  already joined, so it refused for a different (correct) reason before reaching the
  spent-token check.
- **`forget` cap survival.** Needs two peers in one store; the store under test had one.
- **`up` attached and codeless `receive`.** Both are long-running listeners; killed by
  the harness timeout, which is correct behaviour and proves nothing either way.

## Method note

Two findings this sweep were mine, not the product's, and both were caught by
checking rather than reporting: `--word` sets the words but the connect number is
machine-assigned, so claiming without it is correctly rejected; and `reach` takes 1s,
not the 40s a cold first call suggested. A sweep that reports those as bugs is worse
than no sweep.
