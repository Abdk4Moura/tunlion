# Shell/link durability soak

Status: **test-only harness**. It changes no production code, no Cargo manifest,
and no shipped default. The first CI run is the evidence; do not read this page
as a claim that the soak has already passed.

The report this exists for: a native `tunlion shell` reconnecting by itself
roughly every two minutes, and live shells dropping when a second connection or
`exec` happened. #498 fixed one transport-teardown race; this is the repeatable
instrument that should go red if it returns, and that gives a reviewer logs
instead of a recollection.

## What it runs

One process-level, single-host (loopback) scenario per `run`:

| stage | what happens | what must hold |
|---|---|---|
| setup | isolated backend + flaky signaling proxy, two config dirs, reciprocal same-owner pair secret, two `up` daemons with `TUNLION_L2=1`, explicit `grant` both ways; log offsets are taken **before** the second client exists | both daemons serve; prerequisites missing = exit 2 |
| simultaneous | two real `tunlion shell` clients in opposite directions, each on a real PTY; each uses a pinned `TUNLION_SHELL_SESSION` and proves it rode the daemon's warm link | both remote PIDs exist; shell state marker round-trips; the first shell is re-checked after the second joins and the setup window shows no reattach/drop |
| stable | 60% idle, 40% active (default 150s total; active probe every 5s) | **zero** unsolicited `pty REATTACHED`, `drop_link(`, mux `closing streams`, supersede, warm-hold re-establish, or client reconnect; same PIDs/state at the end |
| concurrent | `exec` A->B, `exec` B->A, and a real `forward` TCP stream (loopback echo target) while both shells are live | all three succeed; both shells keep the same PID; daemons stay quiet |
| signaling flap | existing `runner/sim/flaky_proxy.py` severs every client<->backend TCP for ~8s, then heals; shells are probed every second | the daemons log a real `signaling reconnected`; both shells answer across the outage; no reattach/drop; the post-heal 12s idle window must not reap the link |
| intentional drop | the reverse shell is closed; the **initiator** daemon is SIGKILL'd and restarted (the peer hosting the PTY stays up) | peer logs `pty REATTACHED`; **same remote shell PID**, same shell variable state, `/proc/<pid>` alive, and a fresh command works |

The intentional drop is a hard daemon kill + restart rather than a packet filter
because it is deterministic and exercises the real client reconnect/reattach
loop; SIGKILL avoids a graceful shutdown sending stream-close frames that a
real network loss would not. It
destroys the link, not the session host, which is the property reported broken.
The signaling flap is a real socket sever through the existing fixture, not a
simulated log line.

Assertions read daemon debug transcripts (`TUNLION_LOG=debug`) and client
trace transcripts (`TUNLION_LOG=trace`, used to prove the shell rode the
daemon's warm link) at byte offsets marking each stage. Waits for establishment, reattach, and reconnection
are condition-based with bounded timeouts; the only deliberate sleeps are the
observation windows themselves (the failure under test is time-based) and a
short settle after stream teardown.

## Run it

```bash
(cd cli && cargo build --release --features test-hooks)
scripts/durability-soak.sh --runs 2 --stable-secs 150
```

Or directly:

```bash
TUNLION_BIN=$PWD/target/release/tunlion \
  python3 cli/tests/durability_soak.py --runs 1 --stable-secs 150
```

Bound the runtime: one run is roughly `stable_secs + 2.5 minutes` of setup,
concurrency, flap, drop, and teardown. `--runs 2 --stable-secs 150` is about
10-12 minutes on a stock Linux runner. CI's manual workflow uses a 30 minute
ceiling.

`stable_secs` must exceed the reported churn period (about 120s) or the window
can miss it; 150s is the default for exactly that reason. Do not shrink it to
make CI faster and then call a green run coverage.

### CI

Manual dispatch (and a PR that edits the harness itself):

```bash
gh workflow run durability-soak.yml --ref <branch> \
  -f runs=2 -f stable-secs=150
gh run watch
```

The workflow builds `--release --features test-hooks`, starts its own backend,
and uploads the entire evidence directory with `if-no-files-found: error`. It is
not wired to every PR and is not a required check.

## Evidence and failure triage

Every run keeps:

```
/tmp/tunlion-durability-soak/run-<n>-<timestamp>-<pid>/
  summary.json        result, binary sha256/version, host, checks, stage counts
  harness.log         timestamped stage timeline
  daemon-a.log        initiator daemon (TUNLION_LOG=debug)
  daemon-b.log        session-host daemon
  shell-a-to-b.log    raw PTY transcript of the A->B shell
  shell-b-to-a.log    raw PTY transcript of the B->A shell
  backend.log  proxy.log  forward.log
```

`summary.json` records, per stage and per daemon, the number of
`pty REATTACHED`, `drop_link(`, and `ignoring tunnel ... selected transport is
alive` lines. The last one is **informational**: #498 intentionally ignores a
losing candidate's state while the selected transport is alive. It is not a
drop.

In `stable`, a non-zero `pty_reattach` **or** `drop_link` is a failure. In
`concurrent`/`signaling`, the `drop_link` count is reported but not asserted
directly: each `exec` and cold `forward` owns a short-lived client link, and its
normal exit makes the peer log a drop for that client. Those stages instead
assert the PTY/session-specific signals (`pty REATTACHED`, warm-pty death,
supersede, warm-hold re-dial) plus unchanged shell PIDs and state. A live shell
link that actually dies still fails, either through one of those signals or
through the PID/state check.

On failure, start with the failed check's detail in the console/summary, then:

1. `shell-*-to-*.log` — did the client print
   `tunlion: link to ... lost, reconnecting...` (the native PTY path itself reconnects silently; the daemon-side `pty REATTACHED` line is the authoritative signal), and at what point?
2. `daemon-*.log` around the same timestamp — `drop_link(<pid>) ordered by
   <file>:<line>` names the caller that tore the link down; a nearby
   `tunnel ... closing streams` is the mux being retired.
3. `pty REATTACHED` without a preceding intentional drop is the unsolicited
   reconnect signature.
4. `warm-hold: will establish` / `warm-hold: failed to connect` in a quiet
   window is proactive re-dial churn, even if no data was lost this second.
5. The signaling stage must contain `signaling reconnected`. If it does not,
   the proxy did not actually sever the socket; the run fails as an injection
   failure rather than pretending the no-drop result meant something.

If the harness exposes a real bug: report the failing check, the exact log
lines, the binary sha, and a proposed fix. Do not "fix" the assertion to make it
green, and do not change production code in the harness PR.

## Finding from the first CI run (2026-10-18)

The first two-run CI execution was **red in the signaling stage only**; the
stable, concurrent, and intentional-drop stages passed. Both runs reproduced a
live direct link being torn down on a **signaling reconnect**, with both shell
clients reattaching. This is the class of event the report describes, and it is
kept as a failure rather than excused.

Concrete evidence (run 1, `daemon-b.log`; run 2 is the same shape):

```
12:12:19Z   drop_link(RNjtxf4seDFiqLDvAAAB) ordered by cli/src/recv_cmd.rs:4271:30
12:12:19Z   o soak-a  left, still listening
12:12:21Z l2: link closed cleanly peer=RNjtxf4seDFiqLDvAAAB primary=true frames=140 (connection lost)
12:12:22Z l2: pty REATTACHED to 'soak-a', 120x40
```

Immediately before the drop the same daemon logged
`warm-hold: skip 'soak-a' (link ... live)`, and the link's route was
`direct over lo` — so presence was momentarily absent while the transport was
alive and carrying a shell. The drop site is the **channel-digest reconcile**
loop in `cli/src/recv_cmd.rs` (`for pid in channel_gone { ... conn.drop_link(&pid); }`),
which fires after two consecutive digest misses. Unlike `on_peer_left`, it does
not consult the transport's liveness or `link_flowing`, and it has no deferral
path. A signaling reconnect can therefore retire a healthy direct link.

Proposed fix (NOT applied here; this PR is test-only): make the digest
reconcile liveness-aware, the way `on_peer_left` is. Do not drop a link whose
transport is alive and flowing; defer it and let `reap_deferred` decide when it
is genuinely idle/dead. Also verify that the known-device channels are
re-subscribed before the post-reconnect digest is acted on, so a transient
presence gap cannot look like departure. This is a separate site from #498's
`PcState` teardown.

A second, intermittent link-drop signal appeared in the concurrent stage on
run 1 (not run 2): `warm-pick` chose the just-created one-shot `exec` link
(`lMt35…`, age 24 ms) over the long-lived daemon link (`qjJB…`, age 156 s),
then the verification timed out:

```
12:33:14Z warm-pick 'soak-b': pid=lMt35… chosen=true direct=true alive=true age_ms=Some(24)
12:33:16Z tunlion: warm link to 'soak-b' is a zombie (warm link unresponsive after 2500ms (zombie)); dropping + establishing fresh
12:33:16Z   drop_link(lMt35…) ordered by cli/src/recv_cmd.rs:4153:26
```

The shells kept their PIDs and the forward succeeded on the cold fallback, so
this is a transient link-selection drop, not a shell loss. Proposed fix: in
`warm_link_for`/`place`, prefer the **longest-lived** live link (or exclude a
link owned by a one-shot exec client) instead of taking the last equal link.
The user's report explicitly couples drops with a second connection/exec, so
this is kept in the harness as a finding rather than filtered out.

## Assumptions and honest limits

- **Linux only.** The harness uses Unix PTYs, process groups, SIGTERM, and
  `/proc`. It exits 2 on other platforms; that is a missing prerequisite, not a
  skip.
- **One host.** Both daemons and the backend are on loopback. There is no NAT,
  no TURN relay, no asymmetric routing, no real packet loss on the data path,
  and no clock skew. The signaling flap is a real TCP sever, but it is local.
- **Same-owner reciprocal secret.** This is the shell-gates/exec-gates topology,
  not an invitation/certificate enrolment. The durability question is link/PTY
  lifecycle, not authorization; capabilities have their own gates.
- **Daemon restart, not link-layer fault injection.** It proves the client
  reconnects and reattaches the surviving session, but not that a half-open
  packet-blackholed link is detected at the same speed a clean process exit is.
- **Bounded, not a 24h soak.** `--runs N` repeats the same scenario; it does not
  become a long-duration memory/fd soak.

### Still manual: Windows <-> Linux over a real network

Not replaceable on one Linux runner. The manual matrix, when a Windows and a
Linux box are available:

1. Pair them normally (invitation, not a hand-placed secret), `up --shell` on
   the Linux acceptor, confirm both directions with
   `tunlion shell <peer> -- echo OK`.
2. Open two interactive shells in opposite directions. Record
   `echo $$` and a shell variable in each. Leave them idle for at least five
   minutes, then run `exec` and `forward` on the same peer while both are live.
3. On the network path, force a transient outage (Wi-Fi off/on, `tc netem` on a
   router, or the VPN reconnect the report came from) for 5-15 seconds. Bring it
   back and re-run the PID/state checks.
4. On Windows, the equivalent of the intentional drop is stopping/restarting
   the **initiating** CLI/daemon while the Linux side keeps the session; the
   remote PID must survive and the reattach must replay the buffer.
5. Collect `TUNLION_LOG=debug` output from both ends and the client terminals.
   Record OS builds, route (direct/relay), and the outage mechanism next to the
   result. Without that, "it reconnected" is not evidence.

This gap is stated rather than hidden: the local harness is the strongest
two-process/loopback coverage available in CI, and it is not a substitute for
two machines under a hostile network.
