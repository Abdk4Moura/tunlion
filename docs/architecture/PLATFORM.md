# Where platform differences are allowed to live

The rule is one line: **platform-conditional code lives in `platform/`. Everything
else calls a portable function.**

We already had that structure. We were not using it. When this was written there
were 254 platform-conditional blocks in `cli/src`, and only 40 of them were in
`platform/`. `main.rs` alone had 97, more than twice the adapter layer it is
supposed to call.

That is not a style complaint. It is the direct cause of a week of bugs.

## What routing around the adapter cost

Every one of these was platform logic written where it was convenient rather
than behind the layer that exists for it.

- **#204** `daemon_alive()` read `/proc/<pid>/cmdline` inline in `main.rs`, with
  no Windows arm. It returned false on Windows always. `up` started a second
  daemon instead of following the first, `down` did nothing, `status` lied, and
  the first-run wizard reported that the receiver had failed to start when it
  had started. Three of those were features shipped that same release.
- **#215** `detach_up` branches on `cfg(unix)` / `cfg(windows)` inline. The unix
  arm opens `daemon.log` and redirects into it; the Windows arm computes the
  same path and then discards it. `filament logs`, `up` following a running
  daemon, and `up --detach` all dead-end on Windows.
- **#205** `ctl.rs` is gated to unix with a non-unix stub returning `None`. The
  mint could not tell the daemon an invitation was outstanding, so bounded
  invitations minted on Windows could not be claimed at all.
- **#202** not a `cfg` at all, but the same shape: six call sites built a
  subcommand string for a verb that had been deleted, because nothing owned the
  question "what does filament invoke on itself".

The pattern is identical every time. Someone needed a platform fact, wrote it
where they needed it, tested it on the platform they had, and it was wrong
somewhere else for an unknown number of releases.

## The stronger move: need fewer adapters

The best fix for #205 is not a named-pipe adapter beside the unix-socket one.
It is to stop needing IPC.

Arming the daemon means "an invitation is outstanding". That fact lived in a
`OnceLock<Mutex<ArmedSet>>`, in the daemon's memory, so the only way to deliver
it was inter-process communication, and IPC is precisely the thing with no
portable form. Make it a file in the config dir, owner-only, expiry-pruned, and
the mint writes it directly. The daemon's arm-gate already re-reads on every
loop iteration (`main.rs:15778`), so it is picked up within a tick.

That deletes a platform adapter rather than adding one, and it closes #205
(no channel on Windows), #211 (the socket was not bound yet), and the unfiled
case where restarting the daemon silently disarmed every outstanding invitation.

So: **prefer mechanisms with one implementation over abstractions with N.** A
file, a timer, the existing store. An adapter you do not need cannot have a
Windows branch somebody forgot.

## What is legitimately platform-specific

Not every `cfg` is a mistake. `mount_proto.rs` has 47 and most are irreducible:
path encoding genuinely differs between platforms and pretending otherwise loses
data. The test is not zero. The test is:

- the branching lives in one place, and
- callers above it are written once and read as if the world were uniform.

If you are writing `#[cfg(windows)]` in a file that is not under `platform/`,
the question to answer first is *what portable operation am I actually asking
for*. Usually there is one, and it belongs in the adapter with both arms written
at the same time by the same person. Both arms at once is the important part:
#215 exists because someone wrote one arm and left the other for later.

## The ratchet

`cli/tests/surface_platform.rs` holds a per-file budget of platform-conditional
blocks outside `platform/` and fails when one grows. 214 sites are
grandfathered; the number may only go down.

To lower a budget, move the logic into `platform/` and lower the number in the
same commit. Raising one needs a comment saying why, and "it was easier here" is
not a why.

`platform/` itself is exempt. That is the point of it.

Documentation alone would not hold this. The rules that should have prevented
#198 and #202 were already written down; what caught the dead verbs in the end
was a test that reads the source. Same reasoning as `docs/ui/OUTPUT.md`, which
carries its own ratchet for the same reason.

## Paying it down

`main.rs` first, at 97. That is where the user-facing flows are and where every
bug above came from. The candidates in order:

1. process liveness and daemon control (`daemon_alive`, spawn, detach) — three
   bugs already, and the smallest genuinely portable surface: "is this pid our
   daemon", "start a detached daemon writing to this log".
2. the ctl channel, which the armed-set change should mostly delete.
3. paths, which are already `platform::Paths` and only need the stragglers
   routed through it (#184 was the last one of those).
