# Flow sweep, 2026-08-15

Build `b9808062` (`verify/0.8.6`), hub binary sha256 `9eb885e4…`, plus a control
run on released `0.8.5` (`bacae2f`).

Two to four isolated identities on one Linux host, separate `FILAMENT_CONFIG_DIR`
per identity, daemons on `--userspace --no-proxy-fallback` so the host network
and the production daemon were never touched. Interactive cells driven through a
real pty, not a pipe.

The purpose was to answer whether the flows work, not whether the tests pass.
Every claim below is something a command actually did.

## Works

| flow | evidence |
|---|---|
| `init` | both identities, recovery file written |
| `add --for` mint | invitation written, `armed.json` holds the key, **daemon already running before the mint** (the #205 condition) |
| `join --invite-file` | enrolled in under 1s, ceiling persisted |
| single-use enforcement | second claim refused, `this invitation has already been used`, exit 1. #222 closed |
| `send --to <device>` | 2.9 MB at 245 MB/s, sha256 matched, both directions |
| bare `filament <file>` | speakable code, clipboard, browser fallback, 10 min expiry |
| `receive <code>` | stranger with no pairing, authenticated, sha256 matched |
| `reach` | 1 ms on a warm link, cold path reports an estimate |
| `mount` | FUSE read-only, listing and reads correct |
| mount write refusal | write to a read-only mount refused |
| `shell`, capability in the invitation ceiling | remote execution proven with output the input never contained |
| `revoke --certificate` | binds within seconds on mount, transfer and shell alike |
| `doctor` | signaling, ICE, interfaces, names the VPN confounder |
| `devices forget` | states plainly that the peer keeps its half |
| `down` | stops the right daemon by pid |
| `status`, `up.log` | receives log written and rendered correctly |
| root-shell guard | `up --shell` as root refuses without `--shell-user` or `--i-know` |

## Broken, filed

Ordered by how much damage the wrong belief causes.

**#228, revoke is inert for a fleet device.** `revoke <device> shell` reports
success and the device keeps a working root shell. Reproduced on **released
0.8.5**, so holding the tag does not contain it. `revoke --certificate` binds and
is the mitigation. The message also reports removing the managed
`authorized_keys` block, which it really does, and which only governs `--ssh`.

**#226, grant is inert for the same devices.** `grant <device> shell`, then
`requests approve --allow shell`, then `filament devices` all report the
capability held; the acceptor refuses it. `grant` targets `peer_cert.user_pub`,
which for a delegated device is the issuer's own owner key, and enforcement reads
the enrollment ceiling instead. The enforcement is right. Three surfaces
asserting owner-equivalent access that does not exist is the bug.

**#223, a refused stream reports success.** Acceptor logs `pty refused: … not in
auth key caps` or `device revoked`; the initiator gets an empty screen and exit 0,
so `filament shell host -- deploy.sh && echo done` prints `done` after a refusal.
Full four-cell matrix is on the issue, including the positive control.

**#232, `forward` announces success at the moment of refusal.** Prints `the link
is live` while the acceptor logs `refused stream 0x80000000: not in auth key
caps`, and the tunnel returns nothing. Third stream type in the #223 family after
mount and pty, which is the argument for one per-stream outcome channel rather
than a fix per verb.

**#224, `daemon_alive()` greps the command line for "filament".** The same binary
renamed to `fil` reports not running while running; `down` and `up` follow. The
existing test cannot fail, because the test binary is named `filament-<hash>`.

**#230, `filament send <file>` does not mint a code** although the banner says it
does, while bare `filament <file>` does. The verb form is the one people type.

**#229 and #227, printed commands that do not exist.** `filament unmount`, after
every successful mount. `filament requests approve <id>`, missing two required
flags. `filament forward <lport> <device> <rport>`, wrong arity. Three
subsystems, three authors, one shape. #229 carries a design for the guard.

**#231, `CAP-SHADOW` telemetry prints during a normal receive** at default
verbosity, on the flagship code-claim path.

Fixed in this branch: the `refusing {action}` sentence, which shipped as
"refusing shut down the daemon without --yes" because one string served both the
imperative prompt and the infinitive refusal.

## Retracted

**#225** claimed `status` mislabels a log tail as "recent receives". It does not.
`up.log` is written only on a completed receive and the label is correct. My own
`nohup … > $CONFIG/up.log` had clobbered it. Closed with the correction. I filed
it after checking that the heading sat above unexpected text, without checking
what writes the file underneath.

An earlier #223 comment was also withdrawn: `shell <peer> -- cmd` passes `[ARGS]`
that are ssh-only, so the command never ran, and the acceptor was on plain `up`.
Either alone explained the result. Replaced with the pty-driven matrix.

## Not covered, and why it matters

**Windows and macOS.** Everything here is Linux. The Windows arming half of #205
is covered by `arm_mechanism_tests.rs` in CI on all three runners; the claim half
is not, and only the owner's machine or a runner pair can close it.

**Two hosts.** One box means no NAT, no relay, no asymmetric routing. Every
transfer here went over loopback or a host candidate. Nothing about TURN, glare
(#214) or enrollment ICE on constrained networks (#212) is exercised.

**The launcher.** The interactive menu was not driven in this sweep. #209 and
#216 are untouched.

**`expose` end to end.** Config saved correctly, but `--userspace` left no L3
overlay up, so nothing was reached through a `.mesh` address.

A sweep that says "the flows work" and quietly means "on one Linux box, over
loopback" is worth less than one that says where it stopped.
