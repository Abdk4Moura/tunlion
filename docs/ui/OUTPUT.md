# What tunlion is allowed to print, and how

Rules for anything a person reads. Written down because the UI layer is the
part most often finished last, by whoever is closest to the feature, and it is
where this project's recurring defect lives.

## The rule that matters most

**Only assert what the program has established at the moment it speaks.**

One week produced four bugs that were all this:

- #204 `! autostart installed; starting the receiver now failed` — the receiver
  had started. The liveness check read `/proc` and was constant-false on Windows.
- #205 `the always-on receiver is not running` — it was running. The control
  socket is a unix socket and the Windows stub returns None.
- #206 `mount-open-ack not received (timed out)` — the peer refused, instantly.
  The protocol has no denial message, so refusal and silence look identical.
- #207 `keep this window open until the other device claims it` — the window
  plays no part in the claim.

Four subsystems, one defect. Each line was written by someone who knew what was
true at that moment, and each reads as confident fact to a user who does not.

If the program cannot establish a claim, say the weaker true thing. "Could not
confirm a receiver on this platform" is worth more than a confident wrong
"the receiver is not running", because it sends the reader somewhere useful.
A denial with a reason beats a timeout. "We are still waiting" beats "it failed".

The test for a line: **what would have to be true for this sentence to be a
lie, and does the code rule that out?** If it does not rule it out, weaken the
sentence or strengthen the check.

## A true sentence can still be the bug

The rule above catches false statements. This one catches the harder case: a
statement that is **exactly true** and creates a false belief anyway. It passes
review, because review asks whether the sentence is true and it is.

The example is `revoke`, which printed:

```
revoked 'laptop'; it is denied on reconnect
```

Every word is accurate. It is also the whole of #235: a device that never
disconnects is never denied, so a held-open mount kept serving files created
after the revoke. The limitation was stated, precisely, in the success message
of the verb, and everyone who read it, including the person who later quoted it
as evidence the mitigation worked, read it as a guarantee.

Two names worth knowing, because the fix differs at each layer. **Paltering** is
the deception-literature term for a true statement chosen because the impression
it leaves is false; the finding that matters is that people who palter judge
themselves honest, because they check their sentence rather than the belief it
produced. **Vacuous truth** is the formal version: a property over an empty set
holds and asserts nothing.

### The question to ask, which is checkable

"Is this misleading?" is useless in review, because it requires the reviewer to
already know the answer. This is not:

> **A guarantee conditioned on an event is only as strong as your control over
> that event.** Any security statement of the form "X happens on E" must name who
> controls E. If the adversary does, the statement is vacuous at their
> discretion.

"Denied on reconnect" is universally quantified over reconnections and the
attacker decides whether any occur. "Will learn about it when it next connects"
has the same shape. So does any future "revoked everywhere" that depends on
delivery.

Where the honest sentence cannot be unconditional, state the bound you can
actually deliver. "Loses access within 10 minutes of hearing, or when its roster
expires" is worth more than "denied on reconnect", because the reader can act on
a number and cannot act on a condition they do not control.

### It is the same defect as an unfalsifiable test

`cli/src/main.rs` once asserted `is_tunlion_process(std::process::id())` where
the test binary is named `tunlion-<hash>`, so the input could not fail and the
check was never exercised (#224). **A test that cannot fail and a sentence that
cannot be false are the same defect in different materials.**

The red-before-green rule on the gate board catches the executable case. Nothing
automatic catches the prose case, which is why it is written down here.

## stdout and stderr are different audiences

**stdout is for machines.** JSON under `--json`, tokens, paths, anything a user
pipes into something else. Use `println!`. Never gate it on verbosity: a script
that gets less output under `-q` is broken.

**stderr is for humans**, and always through `ui::`. Never `eprintln!`.

Mixing them inside one screen is the specific bug to avoid. The invitation
screen currently prints its body with `eprintln!` and its footer with
`ui::say`, so under `-q` you get the footer and not the invitation.

## Levels

- `ui::critical` — must-see even under `-q`. Route label, relay banner, a path
  changing under the user, fatal errors. Use sparingly; everything cannot be critical.
- `ui::say` — the default. Normal useful narration. Suppressed by `-q`.
- `ui::debug` — internals a user may want on demand: resilience events, stalls,
  repairs, reconnects, upgrade probes, and diagnostics addressed to us rather
  than to them. Shown at `-v`.
- `ui::trace` — the noisy layer: ICE candidates, per-frame detail. Shown at
  `-vv`.

If a line is worth printing at all, it belongs at exactly one of these. Deciding
is part of writing the feature, not a finishing pass.

This list said `ui::trace` was the `-v` level until 2026-08-18, when someone
implementing #231 read the doc, wrote the fix to it, and found the code maps
`-v` to `ui::debug` and `-vv` to `ui::trace`. A doc that misstates a level sends
diagnostics one notch quieter or louder than intended and nothing catches it,
which is how internal telemetry ended up on the flagship receive path in the
first place.

## Styling

`ui::paint(Tone, s)` for colour, `ui::glyph_*()` for symbols. Both already
handle terminals that cannot render them, so never hardcode an escape or a
Unicode glyph. `ui::paint_when(color, ...)` where the caller knows colour is off.

Style goes *inside* a `ui::` call, never around a bare print. `ui::paint` inside
`eprintln!` gets the colour and loses the verbosity gate, which is the trap: it
looks like it went through the UI layer.

## Prose

Plain sentences that stop when they are done. No em dashes. Do not tell the user
what to feel about an outcome, and do not congratulate them.

Name the thing that has to happen next, in the words of the command that does
it. "start `tunlion up`" beats "ensure a receiver is available".

Never print an instruction naming a command that does not exist. Three did:
`tunlion netcat` from six internal call sites, and `tunlion proxy` and
`tunlion dial` from a printed hint (#202).

## Do not offer what cannot work

The launcher offered "Mount remote files" to a device whose ceiling was
`transfer`, which it had printed during join minutes earlier (#206). Either do
not offer it, or offer it and explain before opening a stream that will time out.

A menu entry is a promise. Removing one is also a change: after any removal,
diff the surface against the previous tag and account for every entry that
disappeared. #198 shipped because a removal audit checked that the new thing
worked, not that the old thing still existed.

## Prompts

`[y/N]` promises one keypress. Read one key when interactive on a TTY; Enter
takes the capitalised default; keep line reading for non-TTY stdin so scripts
are unaffected (#208).

Say what a pause is for. If the program is waiting on the user rather than on
the network, the prompt should say so.

## One shape per repeated result

A verb that prints a result more than once prints the SAME line every time, from
one formatter. `reach` renders every probe through `ping::probe_line`:

```
pong via relay(198.51.100.4:3478) 41 ms
pong via 203.0.113.7:41641 (direct-quic) 9 ms
```

`reach` prints it once, `reach --until-direct` once a second until the link is
direct. One formatter means one unit test for the shape, and it means a reader
who has seen the line once can read the loop.

Under `--json` the same probe is one envelope per line on stdout,
`{"ok","verb":"reach","data":{route,direct,rtt_ms,addr}}` — per verb, not a
global wrapper, and the exit code is what a script branches on (0 direct,
5 still on a relay at the timeout, 6 no link at all: the peer is offline).
A plain `reach --json` carries the same `ok`, `verb` and `data` keys next to
the flat fields older scripts read (`warm`, `route`, `established`,
`total_ms`, `failed_phase`), and `ok` is true only when the peer answered.

## Exit codes

Every verb ends in one of these. They are printed in `tunlion --help` (EXIT
CODES) and defined once, in `cli/src/exit_codes.rs` (`ExitKind`), which a unit
test holds to the help text.

| code | token (`error.code`) | means |
|---|---|---|
| 0 | | success |
| 1 | `error` | anything not classified below |
| 2 | `usage` | bad arguments or flags |
| 3 | `unknown_device` | no such device, or not paired with this one |
| 4 | `denied` | refused by the peer, a capability or ceiling, or the system |
| 5 | `still_relayed` | `reach --until-direct`: the link is up but still on a relay |
| 6 | `unreachable` | the peer is offline, unreachable, or did not answer in time |
| 7 | `network` | the tunlion server cannot be reached (no internet, DNS) |
| 8 | `partial` | some files moved and some did not (`send`, `sync`) |
| 9 | `no_identity` | this device has no identity yet: `tunlion init`, or `tunlion join <invitation>` |
| 130 | | interrupted |

Rules that go with them:

- **Codes 3, 4 and 5 kept the meanings they already had** (`sync`,
  `devices --caps`, `reach --until-direct`), because gates assert them. `sync`
  moved its unreachable from 5 to 6 and its partial from 7 to 8, so one number
  means one thing across every verb.
- **`exec` passes the remote command's own status through.** A remote `exit 3`
  is a local 3; tunlion's own failures use the table, so for `exec` alone a
  low code is ambiguous. `1` is still the catch-all for anything unclassified,
  so a script that only tests `!= 0` is unaffected by any of this.
- **A command that only looks never creates an identity.** On a keyless
  device `id` answers `no identity yet; run ...` and exits 9 (`--json`:
  `"identity": null`). `status --json` and `doctor --json` report
  `"identity": null` and keep their own exit rules; `status` and `devices`
  print the same one-line hint.
- **`ok` describes the outcome, not the invocation.** `reach` and `doctor` on
  an offline peer are `"ok": false` with exit 6; `doctor` with the tunlion
  server unreachable is `"ok": false` with exit 7.
- **Under `--json`, a failure is one JSON object on stdout**:
  `{"ok":false,"verb":"<verb>","error":{"code":"<token>","exit":<n>,"message":"<text>"}}`,
  plus `detail` with the raw error chain when it differs from the message.
  stderr still carries the human line, for a log.
- **A network failure is one plain line**, `Can't reach the tunlion server (no
  internet or DNS?). Run tunlion doctor for details.`; the raw error chain is
  shown under `-v`.
- **`send --json`** prints one result object: `ok`, `verb`, `peer`, `bytes`
  (total), `files` (each with `file`, `bytes`, `sha256`, `delivered`,
  `declined`), `file` and `sha256` at the top when exactly one file was sent,
  and `error` on failure. There is no `stored_name`: no receiver reports the
  name it stored under. A send whose files were all declined exits 4; some
  delivered and some declined exits 8.
- **`up --detach` waits up to 10 s** for the daemon to report it is serving
  (the ready marker it writes beside systemd's READY=1, or its control
  socket). A daemon that exits during startup is reported with its last lines
  of output and a nonzero exit (7 when it said the network was the cause). A
  daemon still waiting for the network is reported as started but not
  connected yet, exit 0: it keeps retrying, by design.
- **`up` does not exit when the tunlion server is unreachable.** The daemon
  retries with backoff (1, 2, 4, 8, 16, then every 30 s) and says once that it
  is waiting for the network.
- **`up.pid` holds the pid alone**, so `kill $(cat up.pid)` works. The
  executable the daemon started from is in `up.exe` beside it.

## Enforcing this

`cli/tests/surface_output.rs` holds a per-file budget of bare print macros and
fails when one grows. It is a ratchet, not a wall: 338 existing sites are
grandfathered, and the number may only go down. New user-facing output goes
through `ui::`.

To lower a budget, convert the calls and lower the number in the same commit.
Raising one needs a comment saying why, and "it was easier" is not a why.

The ratchet exists because documentation has not been enough. The surface rules
that would have prevented #198 and #202 were already written down. What caught
the dead verbs in the end was a test that reads the source.
