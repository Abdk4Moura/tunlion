# Changelog

All notable, user-facing changes to filament are recorded here. This file was
started at the 0.7 capability cutover; earlier history lives in the git log and
the GitHub release notes.

## [0.8.3] - 2026-08-08

### Breaking

- **The command surface changed twice in one week, and we are telling you why.**
  0.8.0 shipped three verbs for connecting a device: `add`, `invite`, and
  `join`. The person who designed them could not work out which to use,
  standing in front of the QR code the command had just printed. Three
  verbs with illegible boundaries are a worse product than one verb with a
  clear split, and we would rather break the surface once more before anyone
  depends on it than defend a confusing shape for a year.

  The surface now has TWO roles, not three:

  - **MINT** is `filament add`. It prints a code (the other device claims it
    with `add <code>`) or, with `add --for <device|person>`, a bounded
    invitation (the other device claims it with `join`).
  - **CLAIM** is `add <code>` (a pairing code) or `join` (a bounded
    invitation).

  `invite` is gone. The bare verb errors with a did-you-mean to `add --for`,
  not an alias: an alias silently works, a did-you-mean refuses and teaches.
  The pairing protocol and the capability ceiling are unchanged; only the
  surface over them moved.

## [0.8.2] - 2026-08-08

### Fixed

- **Windows: no more "repaired permissions" on every command.** Every
  invocation, including `--version` and `--help`, began with
  `filament: repaired permissions on 4 sensitive config path(s)`. Nothing was
  being repaired. The Windows arm of the check reasserted the owner-only ACL
  and reported a repair unconditionally, so the number was simply how many
  sensitive files existed.

  The sweep is a migration: files this version writes already get the right
  ACL when created, and the sweep exists only to catch files from older
  releases. It now runs once, records a version stamp, and is skipped
  entirely after that. A security-flavoured message printed on every command
  is worse than useless, because a real permissions problem would have been
  invisible inside noise the tool had always emitted.

- **Windows: a failed install no longer reports success.** Setting up
  background receive printed `installed as a system service (autostart at
  boot)` immediately after Windows had refused to start the service. Neither
  half was true. Exit statuses are now checked, so a failure is reported as
  one, and `sc` output is captured instead of leaking raw `[SC]` text.

- **Creating an invitation no longer requires a running receiver.** `invite`
  refused to mint unless the background receiver was already up, and sent the
  user to a command that could not succeed on Windows, so one broken installer
  disabled the whole flow. Minting an invitation is a local act: it produces a
  bounded key. The receiver matters when someone claims it. `invite` now mints
  and arms the receiver when it can, with a note when it cannot. The
  precondition is also no longer checked after the interactive prompt, so the
  flow cannot ask a question and then discard the answer.

- **The pairing screen says to keep the window open.** `add` and `invite`
  printed a code and a QR without mentioning that the command must keep
  running until the other device claims it. Leaving the screen cancelled the
  pairing with `Error: interrupted` and no explanation.

## [0.8.1] - 2026-08-08

### Fixed

- **Windows: setting up background receive no longer fails for a normal user.**
  Answering yes to "Stay available in the background?" in the first-run wizard
  aborted with `schtasks failed: ERROR: Access is denied.` for any account
  without administrator rights, which is the default. No UAC prompt appeared,
  because the code that raises one could not run.

  Three things were wrong. `is_elevated()` returned true unconditionally on
  Windows, on the assumption that its only caller was an already-elevated
  re-launch; it is also the first, non-elevated call, so the elevation path was
  unreachable. The advertised fallback to a user-level autostart dispatched to
  the same function as the system install, so it retried the operation that had
  just failed and reported the same error. And the task was created in the
  Task Scheduler root, which requires administrator rights.

  Background receive is now a per-user autostart
  (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) that needs no
  elevation, matching what Linux and macOS already did with a systemd user
  service and a LaunchAgent. Starting your own receiver when you log in is not
  an administrative act. A machine-wide service that starts before login is
  still available through `--install-system`, and that path now genuinely
  elevates: `is_elevated()` reads the process token instead of assuming.

  The `[SC] OpenSCManager FAILED 5` line printed alongside the error came from
  an unconditional `sc delete` during cleanup. It now runs only when elevated,
  so an ordinary uninstall is quiet.

  Found by running the wizard on Windows as a non-administrator, which nothing
  had done before.

## [0.8.0] - 2026-08-07

### Breaking

- **The command surface is a clean break.** `identity`, `pair`, and `recv`
  are gone. The commands are `id`, `add`, and `receive`; the old names error
  with a did-you-mean to the renamed verb. The audience meets the product
  afresh, so there are no compatibility aliases.

### Security

- **Revocation binds for a first typed-code transfer once the sender's
  identity resolves, on both transports.**
  A revoked device that reconnects through a freshly minted code was authorized
  until its identity resolved, because shadow mode never issued the identity
  challenge and the first offer was decided before the DirectReady challenge.
  In earlier releases revocation did not bind on any transport; 0.8.0 makes it
  bind on the direct path and the WebRTC/relay path alike. The receiver issues
  the possession challenge in both modes for a typed-code link (at DirectReady
  on the direct path and at PAKE confirm, re-issued at ChannelReady when the
  transport arrives late, on the WebRTC path) and holds the first offer until
  the sender's identity resolves, so the gate's absolute denial of a durably
  revoked device fires before any bytes land. The bound is explicit: a peer
  whose identity resolves is decided with it (revoked denied, legitimate
  accepted); a peer whose identity ceremony does NOT complete within the hold
  window (a slow fallback link or a lost challenge) is decided by the normal
  gate. Peers too old to run the encrypted handshake abort earlier with an
  update message and never reach this hold; peers that can run the handshake,
  including 0.7.7 senders, answer the possession challenge and resolve within
  the window on a functioning link. The probe that found the window stays
  permanently: it goes quiet only when the ordering is fixed.


- **Revoking a device now actually denies it.** `filament revoke <name>
  --certificate` cut fleet auto-trust and nothing else. Two separate paths kept
  authorizing a revoked device:

  - an **explicit grant** for the attempted action authorized independently of
    revocation. Grants are how the deliberate tier is reached (shell,
    write-mount, out-of-scope reach), so revocation failed hardest for the
    devices holding the most authority.
  - in the **default (shadow) mode**, which is what ships, the decision falls
    through to a caller-supplied `legacy_allowed` that never saw the revocation
    at all. This was not gated behind `FILAMENT_CAP_AUTHORITATIVE`; it applied
    with no flag set.

  Revocation is now an absolute denial evaluated before any grant is consulted,
  in both modes.

  **Neither of those two defects exposed anything** in the sense of an attacker
  gaining access they did not have: both failed to *withdraw* authorization
  rather than conferring it. What was wrong is that a revocation you performed
  did less than its message said.

  **Introduced in 0.7.7, with certificate revocation itself.** Earlier releases
  have no `revoke --certificate` and are unaffected: you cannot have a defect in
  revocation in a release that has no revocation.

  The one residual this fix left open, a revoked device completing a *first*
  operation over a freshly typed pairing code before its identity resolved, is
  closed by "Revocation binds before the first typed-code transfer" in this same
  release. Both halves shipped together, so no release ever carried the absolute
  denial without the ordering fix.

  Both messages that described the old behaviour are corrected. The pre-action
  warning no longer claims revocation removes access "entirely", and the success
  line names the capability gate rather than "fleet access".

### Added

- **Recoverable identity.** `filament init` creates your identity from a
  random 12-word BIP39 recovery phrase. The identity is committed only after
  you prove you wrote the phrase down (a word transcription check); `id
  recover` restores the same identity from the phrase on another device.
  Recovery phrases and invitation secrets are written only to owner-only
  files or a terminal, never to argv, logs, or stdout.
- **Bounded invitations.** `filament invite` mints a key with a capability
  ceiling and a lifetime; `filament join` claims it and becomes a delegated
  device whose ceiling is persisted in one record and restored on reconnect.
  A re-joining device gets the NEW key's bounds, never a wider inherited set;
  a lapsed device revives, a revoked one does not.
- **Device lifecycle.** A joined device has an effective deadline (the
  earliest of its cert expiry, its offline budget, and its absolute stop),
  named in `devices` output. Idle-but-connected devices do not decay
  (liveness is observed, not traffic-driven). Past-deadline devices are
  marked `lapsed` and kept as evidence. `devices revoke`/`restore` durably
  revokes: the marker survives cert renewal and overrides any standing grant.
  `filament depart` signs and announces a goodbye; it is advisory, never
  load-bearing.
- **Ephemeral enrollment.** An ephemeral auth key admits a device in memory
  only, gone at restart; a persistent key writes the durable record. The
  device validates the ack against the key's persistence choice.
- **Guided flows.** Bare `filament` on a terminal opens a picker; every
  file, mount, and identity flow shows a review screen naming the exact
  replay command. Mounts default to read-only with an explicit
  `--read-write`; the remote side still enforces its share root and grant.

### Fixed

- **A device that was never revoked is no longer treated as revoked.**
  `device_cert_revoked` returned "revoked" for four conditions, three correctly
  fail-closed and one not: a **known** device record carrying no `certRevoked`
  field. Nothing writes that field except an explicit revoke, so every device
  enrolled normally read as revoked. Under `FILAMENT_CAP_AUTHORITATIVE=1` that
  made fleet auto-trust (the same-owner recognition added in 0.7.4)
  unreachable for every existing device. An unknown device, an unreadable store
  and unparseable JSON still fail closed.

- **An unidentified peer is no longer treated as a revoked one.** The gate
  derived its revocation input as "no device identity ⇒ revoked". Harmless while
  that only cut fleet auto-trust; once revocation became an absolute denial it
  would have refused every peer before its identity resolved, breaking transfers
  outright. The unknown-*device* case remains fail-closed where that judgement
  belongs.

- **Releases no longer publish stray repository files as assets.** The release
  job began checking out the repository in 0.7.7 so notes could be generated from
  this changelog, which put the working tree where two `filament-*` globs could
  match it. `cli-v0.7.7` consequently shipped three unrelated repository
  documents (`filament-status-2026-06-14.md`,
  `filament-update-2026-06-14b.md` and
  `filament-webshell-redesign-2026-06-15.md`, all ordinary session records) as
  release assets and attested them in `SHA256SUMS`. Artifacts are now assembled
  in a dedicated directory that the globs are scoped to, and a check refuses to
  publish unless the asset set is exactly the four platform archives plus
  `SHA256SUMS`. `cli-v0.7.7` is not regenerated: its manifest and its assets
  agree with each other, and rewriting a published checksum file would break that.

### Removed

- **The cone-NAT gate is retired**, along with its STUN fixture. Its hole-punch
  assertion had never passed on any NAT topology, only on the no-NAT control,
  so it had no positive control **under NAT** and could not discriminate there.
  Separately, its "cone" proof measured endpoint-independent *mapping* only;
  cone requires endpoint-independent mapping **and** filtering, and Linux
  `MASQUERADE` is EI mapping with ED filtering, so a correct measurement of one
  property was being read as a claim about another. To be precise about what is
  lost: the transfer assertion **ran and failed** under NAT rather than being
  skipped, so the gate was never silently reporting success; it simply could
  never demonstrate the thing it existed to demonstrate. Cone-NAT traversal was
  not verified before this change and is not verified after it. The mapping probe
  that was correct is kept and still classifies both mapping types.
## [0.7.7] - 2026-08-06

### Security

- **`.part` files are no longer opened through a symlink or directory junction.**
  A junction or symlink planted at the `.part` path was followed when the receiver
  opened it, redirecting the write outside the download directory with the
  authority of the user running filament.

  **The affected platforms differ by version. Read the row that applies to you.**

  **Every released version is affected.** The pattern is present in `cli-v0.1.0`,
  the first tag this project ever cut, so there is no unaffected release to
  upgrade sideways to. What changes across versions is which platforms:

  | versions | affected platforms |
  |---|---|
  | **every release through 0.7.1** (0.1.0 onward, stable and beta alike) | **all platforms**, including Linux and macOS |
  | **0.7.2** through 0.7.6 | **Windows only** |

  Through 0.7.1 the receiver opened the `.part` path with a bare
  `OpenOptions::new().write(true).open(&part_path)` and there was no file-type
  check on any platform: no `cfg` split, no helper, no guard. 0.7.2 introduced the
  `safe_resume_part` / `safe_create_part` helpers and fixed the unix arm, which
  fstats the open file descriptor and refuses non-regular files.
  The Windows arm was explicitly deferred in the 0.7.2 and 0.7.3 release notes, and
  the deferral was never closed, so from 0.7.2 to 0.7.6 unix is guarded and Windows
  is not.

  Fixed by opening with `FILE_FLAG_OPEN_REPARSE_POINT` so the link is not followed,
  then rejecting reparse points and non-regular files via
  `GetFileInformationByHandle` on the open handle. Handle-based, so there is no
  TOCTOU window between the check and the use, matching what the unix arm already
  did.

  **Scope, stated plainly.** This is a local issue, not a remote one. An attacker
  must already be able to write into the download directory in order to plant the
  reparse point; a remote sender can influence the `.part` filename but cannot
  create the link. It is not remote code execution. What it is, is a confused
  deputy that converts write access to the download directory into write access
  anywhere the running user can write, which matters most on shared machines and in
  the download-style directories where untrusted content lands.

  Demonstrated rather than inferred: with the fix removed, the helper returns
  `Ok(File)` whose resolved handle path is the outside directory, and one
  regression test that asserts the refusal goes red
  (`win_safe_resume_part_refuses_symlink`). Two did at the time of the finding;
  the second, `win_safe_open_part_refuses_symlink`, was removed along with the
  dead `safe_open_part` helper it exercised, so the difference is a deletion and
  not a regression. Both numbers are recorded because two independent reds were
  stronger evidence that the control discriminated than one is, and that was
  true when the finding was made.

### Fixed

- **Files whose names are not valid UTF-8 can be read through a mount again.**
  Two conversions inside `safe_open_beneath` went through a UTF-8 string on the
  way to the syscall: the Linux `openat2` path and the component walk used on
  other Unix. A name containing a byte like `0xFF` was either refused outright
  or silently emptied, so a file that exists on the server was unreadable, or
  readable as nothing, through the mount. Both now carry the raw bytes to the
  syscall, and interior-NUL validation is unchanged. Lookup and open of a
  non-UTF-8 name are byte-exact.

- **Directory listing through a mount works again.** `ls` and `find` over a
  mount returned `EINVAL` and enumerated nothing, for every filename, not only
  unusual ones. `safe_open_beneath` computed the `openat2` mode as
  `if (flags & (O_CREAT | O_TMPFILE)) != 0 { 0o644 }`, but `O_TMPFILE` is a
  multi-bit constant that CONTAINS `O_DIRECTORY`, so the test was true for every
  directory open. Each one sent a non-zero mode without `O_CREAT`, which
  `openat2` rejects with `EINVAL` exactly as documented. File opens carry no
  `O_DIRECTORY` bit, so they kept working, which is why reading a known path
  succeeded while listing the directory containing it did not. A root-directory
  open also resolved to an empty relative path, which `openat2` rejects
  separately; it is now normalized to `.`.

  Broken in 0.7.3, when this call site moved to `openat2`. It was masked until
  0.7.6 by a NUL-termination bug in the same call that failed earlier with
  `EFAULT`; fixing that in 0.7.6 exposed this one. `cli-v0.6.0` enumerates
  correctly, `cli-v0.7.6` does not.

  The reason this survived four releases is that no test enumerated a mounted
  directory. The one gate that listed anything was the non-UTF-8 name gate, so a
  total enumeration failure could only ever present as a name-encoding problem.
  A gate that lists a plain ASCII directory now exists.

- **The Linux `openat2` path now actually applies `RESOLVE_BENEATH`.** The
  constants were declared as `RESOLVE_BENEATH = 0x02` and
  `RESOLVE_NO_MAGICLINKS = 0x04`; those values are really `NO_MAGICLINKS` and
  `NO_SYMLINKS`. `RESOLVE_BENEATH` was therefore never passed to the kernel from
  0.7.3 through 0.7.6, while a comment on the non-Linux arm stated that Linux was
  relying on it for containment.

  **No release was exposed.** Containment held throughout by other means: peer
  supplied paths are normalized and rejected by a lexical `starts_with(root)`
  guard before the syscall, so no `..` component ever reaches it, and the value
  set by mistake was `NO_SYMLINKS`, which is stricter on symlinks than
  `RESOLVE_BENEATH` is. Every vector `RESOLVE_BENEATH` would have covered was
  covered by something else. This entry records a corrected safety claim, not a
  vulnerability.

  Because the corrected flags are less strict about symlinks by design, the
  `.part` write path now passes `RESOLVE_NO_SYMLINKS` explicitly. A symlink at
  a `.part` path is still refused, including one pointing at a file in the same
  directory, which the flag correction alone would have permitted.

## [0.7.6] - 2026-07-31

`shell` defaults to a native PTY, and file transfers stop spuriously rejecting
perfectly good files.

### Changed

- **`filament shell <device>` now opens filament's own native PTY by default**
  (the peer must run `up --shell`). Use `filament shell <device> --ssh` to run
  your real ssh over the data channel via ProxyCommand as before. The refined PTY
  engine (warm-link reuse, resumable reconnect, single shared stdin reader) is
  unchanged; only which command drives it changed.

### Fixed

- **Transfers no longer spuriously reject good files as "corrupt" (Linux).** The
  intermittent "received all bytes but whole-file checksum FAILED, refusing to
  accept a corrupt file" was never corrupted data: `safe_open_beneath` passed a
  non-NUL-terminated `&str` as the `openat2` pathname, so the kernel read past the
  name into adjacent memory and created the `.part` under a garbage-suffixed
  filename (mode 000). Verification then hashed the clean intended path, found
  nothing, and refused a byte-perfect file. Fixed by NUL-terminating the pathname
  (and setting the file mode only when creating). A cross-machine rig confirms the
  verify-failure rate drops from ~77% / ~89% to 0% on both transports, with the
  received bytes byte-identical to source every time. This was also the cause of
  intermittent `.part` symlink-refusal test flakiness.
- **A single bad `.part` no longer takes down the whole receive session.** A
  leftover `.part` from an interrupted transfer, or a common filename re-offered
  by another peer, made the fresh `O_EXCL` create return `EEXIST`, and that error
  unwound the entire receive loop, killing every other in-flight transfer.
  Restart-from-zero now replaces a stale partial, and a per-file open failure
  declines just that file instead of aborting the loop.
- **Remote file names are stripped of control bytes** before becoming a path, so
  a peer cannot embed a NUL (or other control characters) in an offered filename.

### Internal

- DataChannel now frames the absolute chunk offset like the QUIC transport, the
  reassembly coverage map is written by the writer after the bytes land (not as
  pre-write intent), completion gates on a contiguous byte range, and a contiguity
  guard reports the exact gap on any future regression instead of a bare digest
  mismatch. Concurrent coverage writers use `fetch_max` so a reordered store can
  never regress the received count.

## [0.7.5] - 2026-07-31

The command surface, finished: a clean ~15-verb CLI with no legacy names.

### Changed

- **Legacy commands are deleted, not aliased.** With no external users yet, the old names
  are simply gone (a deleted name errors with a "did you mean" suggestion): `ssh`/`pty` →
  `shell`; `netcat`/`dial` → `reach` (`--socks` for a proxy); `unexpose` → `expose --off`;
  `unmount` → `mount --off`; `cap-status`/`ping` → `status`/`doctor`; `get`/`unset` → `set`
  (`set <key>` shows, `set <key> <val>` sets, `set <key> --unset` clears); `introduce` →
  `devices vouch`; `serve-tun`/`tag-bind` removed. `filament --help` now lists exactly the
  real verbs, grouped (Connect / Share / Devices / Identity / Mesh). ~360 lines removed.

## [0.7.4] - 2026-07-31

Command-surface simplification and a genuinely useful `--help`, plus the
same-owner-devices "auto-detect" half of fleet trust.

### Changed

- **`filament --help` is now a grouped, curated command reference** (Connect / Share /
  Devices / Identity / Mesh) instead of a flat dump of every subcommand with deprecated
  and canonical names side by side. Each command still has its own `filament <cmd> --help`.
- **Simpler verbs:** `filament shell <device>` (folds `ssh`/`pty`), `filament reach
  <device>:<port>` (folds `netcat`/`dial`; `--socks` for a local proxy), `filament devices
  vouch <a> <b>` (folds `introduce`). All 13 old names keep working as deprecation aliases
  with a one-line note to stderr (suppress with `FILAMENT_NO_DEPRECATION=1`), so no
  existing script or muscle memory breaks.

### Added

- **Same-owner device auto-recognition (opt-in enforcement).** A genuine second device of
  your own (same user key, its own device key, your owner-signed cert) now reaches Proven
  and gets scoped auto-trust over direct, relay, AND reconnect — not just at your desk.
  Rig-verified cross-machine on all three paths. Enforcement stays opt-in
  (`FILAMENT_CAP_AUTHORITATIVE=1`).

### Fixed

- The Linux transfer-resume path no longer hangs if a FIFO is planted at the `.part` path
  (`O_NONBLOCK` on open; the non-regular-file refusal still applies).

### Notes

- Still landing (0.7.5): the `mint` wizard, `identity restore/rotate/guardians`,
  `devices promote`, and the `expose --off` / `mount --off` / `status`-absorbing folds.

## [0.7.3] - 2026-07-30

Release-engineering fixes for the 0.7.2 content. 0.7.2's release build failed on Windows
and its crates.io publish failed, so no 0.7.2 binaries or crates shipped; 0.7.3 carries
the same features and actually builds and publishes.

### Fixed

- **Windows build broke on the mount server.** `do_create` used `libc::O_CREAT | O_EXCL`
  without a cfg gate (introduced by the 0.7.2 transfer/mount symlink hardening), which
  does not compile on Windows where `libc` is absent. Gated the POSIX flags to Unix; the
  non-Unix `safe_open_beneath` fallback is used on Windows.
- **crates.io publish of the CLI failed to verify.** `filament-cap` gained new public API
  in this release (fleet-trust: `fleet_auto_trust`, `evaluate_grants_only`,
  `is_scoped_default_action`, and the shared delegated-ceiling helper) but was still
  `0.1.0` on crates.io and got skipped as already-published, so the CLI's publish
  verification built against a `filament-cap` that lacked those functions. Bumped
  `filament-cap` to `0.1.1` and the CLI's dependency pin to match, so the crate
  republishes and the CLI verifies against the API it actually uses.

## [0.7.2] - 2026-07-30 (release build failed on Windows; superseded by 0.7.3)

### Added

- **Fleet trust — the auth-key half: your own devices join with a minted key and
  just work, scoped.** Enroll a device with an ephemeral auth key and it becomes a
  Proven member of your fleet. Within scoped defaults it needs no per-capability
  grant: it can drop files in your inbox and reach the ports you've exposed. Opening
  a shell, writing to a mount, or reaching a port you did NOT expose stays the
  deliberate tier — an explicit grant, every time. Delegated enrollment reaches
  Proven over any transport (direct or relay). (Same-account "your devices find each
  other" auto-detection is not in this release; it is the next slice.)

### Security / Fixed

- **Fleet shell revocation now actually removes the SSH key.** The shell-key
  reconciler used the owner shortcut, so a same-owner (fleet) device was never listed
  as revoked and its managed `authorized_keys` block survived forever after you
  revoked its shell grant — permanent SSH on the one surface that bypasses every
  filament gate. It now tracks the grant exactly like an external device: revoke
  shell → key removed. Proven live via a fixed-vs-buggy binary differential.
- **Transfer scope is enforced against the real write target, not asserted.** The
  fleet transfer scope check was a dead binding; it now verifies the landing path is
  within the receiving directory, failing closed to grant-only if the sanitizer or
  the receive directory ever changes.
- **Transfer writes refuse symlinks and non-regular files (Unix).** Received `.part`
  files are created and resumed with symlink/FIFO/device refusal —
  `openat2`/`RESOLVE_BENEATH` on Linux, `O_NOFOLLOW` + a post-open `fstat` on other
  Unix — so a symlink or FIFO planted at the target cannot redirect a write. On
  Windows the resume path is not yet hardened (tracked as a follow-up); this
  protection is Unix-only in 0.7.2.
  [correction 2026-08-04: it was NOT tracked. Nothing followed it up. The
  Windows arm shipped unhardened through 0.7.6 and was found only when a branch
  pushed on 2026-07-31 with no PR was noticed. The parenthetical above is left
  as written because it is what the release said; this note records that it was
  false. See the entry under `[Unreleased]`.]
- **Shared the delegated-principal ceiling and the grant scan** between the two
  authorization paths so they cannot diverge (the recurring "two copies of a
  security check drift apart" bug class).

### Changed

- **Enrollment presence oracle closed in production.** The signaling server now
  handles `channel-goodbye` (unsubscribe without dropping the socket) on the Redis
  path. Deployed and verified live.
- **The mount scoped-default is not shipped yet.** A fleet device does not get an
  automatic read-only mount in this release: it is not drivable end-to-end yet, so
  its scope enforcement has never been exercised. Mount requires an explicit grant.
  It ships, rig-verified, with the same-account auto-detect slice.

### Notes

- Enforcement remains opt-in (`FILAMENT_CAP_AUTHORITATIVE=1`). Fleet auto-trust for
  the scoped defaults works in both shadow and authoritative mode.

## [0.7.1] - 2026-07-29

### Changed

- **Reverted the default-on capability flip: enforcement is opt-in again.** The
  0.7.0 default-on flip was premature. Real same-owner fleets show
  `flip_ready=false` (paired daemons aren't provisioned), so authoritative-by-
  default broke the owner's own ssh/transfer/mount until every capability was
  granted by hand. `cap_authoritative()` now defaults OFF (legacy shadow
  gating); enable enforcement explicitly with `FILAMENT_CAP_AUTHORITATIVE=1`
  (or `true`). Any other value, or leaving it unset, keeps shadow gating. The
  env var is now the opt-in switch, pending same-owner fleet-trust that makes a
  default-on flip safe. Everything else the 0.7.0 flip added (the self-genesis
  header, the restrictive gates, the shell-key reconciler) stays; only the
  default changed. See `docs/cap-flip-checklist.md`.

### Added

- **`filament reset`** — a conservative clean slate for the local machine.
  Wipes only filament's own state (identity + overlay keys, the paired-device
  store, the capability store, pending consent requests, exposed-service and
  mount records, per-peer + global settings, the managed ssh material) and
  strips the delimited `# BEGIN/END filament-managed <device>` blocks it
  installed in `~/.ssh/authorized_keys`. Your own ssh keys and any lines
  outside those blocks are never touched. Destructive: prompts for
  confirmation (required `-y`/`--yes` from a non-TTY) and refuses while the
  daemon is running (`filament down` first). Prints exactly what it removed.

### Fixed

- CLI ergonomics: `filament init` now hints `filament identity init`;
  `filament help` works as an alias for `--help`; `filament devices remove <x>`
  now suggests `forget` (the semantic match) instead of clap's `rename`; and
  the Windows managed-key install no longer leaks `icacls`' "Successfully
  processed 1 files" banner to stdout (captured, surfaced only on error).

## [0.7.0] - unreleased

### Changed

- **BREAKING: capability enforcement is now authoritative by default.** Devices
  without a matching grant are denied shell/transfer/mount. Opt out with
  `FILAMENT_CAP_AUTHORITATIVE=0` (shadow mode), which restores the previous
  legacy gating. The environment variable is the rollback: unset (or `=1`)
  keeps enforcement on, `=0`/`=false` turns it off. See
  `docs/cap-flip-checklist.md` for the evidence trail behind the flip.
  **(Reverted in 0.7.1 — see above.)**
