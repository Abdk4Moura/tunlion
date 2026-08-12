# What filament is allowed to print, and how

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
- `ui::trace` — resilience internals: stalls, repairs, reconnects, upgrade
  probes. Shown at `-v`.

If a line is worth printing at all, it belongs at exactly one of these. Deciding
is part of writing the feature, not a finishing pass.

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
it. "start `filament up`" beats "ensure a receiver is available".

Never print an instruction naming a command that does not exist. Three did:
`filament netcat` from six internal call sites, and `filament proxy` and
`filament dial` from a printed hint (#202).

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
