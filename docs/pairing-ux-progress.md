# Lightweight pairing UX: implementation tracker

Approved 2026-10-20. Reference prototype and detailed decisions:
`/root/pairing-ux/MESH-INTENT.md` and `/root/pairing-ux/MESH-PLAN.md`
(local design workspace, not production dependencies).

## Current slice

### Raw categories and separator cleanup (2026-10-21, verified remotely)

- New private payload types distinguish pairing codes, transfer codes,
  invitation material and invitation paths. Raw prefixes/JSON/path syntax are
  reserved before any code cleanup; missing files and malformed invitations
  never fall through into another admission ceremony.
- Guided and positional `join` share this boundary. Explicit file/fd/env
  material stays in the invitation parser. File errors are material-free.
- Only code entry maps disallowed characters to collapsed `-` separators.
  Leading/trailing separators trim before the checked 48-character limit;
  the full value is rejected rather than truncated. A partial editor retains
  a trailing separator while the user is between words.
- Released `filament_pair::norm_code`/WASM normalization stays frozen. New pure
  entry helpers produce checked canonical ASCII, idempotent under that primitive.
  Rust and browser helpers share golden fixtures; creator/claimer/word surfaces
  use the same policy. Browser rejection cannot silently generate replacement words.
- Path category means explicit path syntax (separators, `./`, `~/`, drive/UNC),
  a known credential filename extension, or an existing file. A bare dotted code
  is cleaned as a code, so `brave.otter.3141` becomes `brave-otter-3141`. Use
  `./name` or `--invite-file` when an ambiguous bare name is meant as a file;
  a missing explicit path never falls through to pairing.
- Final remote run `validation-20261021T034112-18751` passed **154 Rust tests**
  (34 entry, 24 join, 6 category, 6 explicit creator/claimer, 2 classifier,
  3 invitation, 56 UI, 23 pairing library). All join PTYs passed at 40×12 and
  96×24, including dotted-code display, sticky masking, Unicode, paste-as-data,
  64 KiB and normalized 48-character boundaries. **17 category-isolation cases**
  saw zero TCP connections and no membership writes. Browser/Rust golden
  fixtures passed 12/12, the production browser build passed, and both real
  PAKE ceremonies, resize and fragmented-paint/visual checks passed.
- Copy/paste wrappers around token/JSON prefixes are reserved too, and the
  editor's final limit ignores its retained trailing separator. Display judges
  code shape after separator cleanup when no path-ish character is present, so
  `brave.otter.3141` is visible while slash/colon/dotfile opaque tokens stay
  masked. A purely alphabetic token remains indistinguishable from code words;
  documented, and use an invitation file for unsupported formats.
- Reviewed source is committed locally as `a1584fa5` + `84f43f45`, not
  pushed/merged. Evidence archive:
  `/root/Tunlion/tunlion-pairing-ux-category.tar.gz`, SHA-256
  `d5c96a40b8eff05331b0729bdcae76f2cc76998ae9fa8856994c99e20497486e`,
  extracted under `/root/pairing-ux/evidence/category-final`; 26 source hashes
  matched locally. Isolated preview SHA-256
  `5ed2d5c23653833c7ff09e84ea2fedd6e7afafbcd13ab5bc38ca5c6b735bbd6d`;
  prior binary retained as `bin/tunlion-pairing-ux.before-category`.
- Shared worker run39533233389 replaces the expired prior lease. Its lock was
  wedged by a dead wrapper's inherited descriptor; with the relay owner and
  coordinator authorizing exact scoped cleanup, only the orphan fixture and
  waiting wrappers were stopped, the stale inode was renamed rather than
  deleted, and canonical `build.lock` was recreated. `flock --close` is now in
  the helper and was verified against a surviving background child. No daemon
  restart, production binary change, or local build/test occurred.

### Previous verified inline-join slice

Latest remote follow-on evidence (replacement worker run39457508933): **140
Rust tests pass** (33 entry, 23 join, 3 classifier, 3 invitation, 56 UI, 22 pairing library).
Dedicated join PTYs pass at 40×12/96×24: sticky invitation/JSON masking, edited
prefixes, Unicode editing, paste-as-data, whole-insertion 64 KiB refusal,
normalized 48-character limits (including sticky masking, punctuation, Unicode,
six-digit suffixes and trailing newlines), hidden opaque slash/URL tokens,
cancel/interrupt, NO_COLOR and escape-free hidden plain input. Real
guided inline `join` at 40×12 passed live PAKE, matching stores, single-use
replay refusal and authenticated reach; generated-code argv joining at 96×24
also passed. Xterm resize/editing and light/dark browser rendering passed;
fragmented output remained pixel-identical until synchronized commit. Review
hardening removes post-submit credential echoes, redacts classifier Debug,
and handles BOM-prefixed invitations. Final review found a leading-dash length
bypass; fixed by measuring before dash trimming, with unit and both-size PTY
regressions. File parsing also strips BOM and never echoes normalized material
in errors. All checks were rerun successfully after these fixes.
The verified source is committed locally as `4247ea94` + `96b8485b` (not pushed/merged).
Evidence archive: `/root/Tunlion/tunlion-pairing-ux-join-reviewed.tar.gz`, SHA-256
`46e898082a4205ba06dc63d7598a13a612abe39b5223d2e2d4124e0be9496654`;
extracted under `/root/pairing-ux/evidence/join-reviewed`. Exact source hashes were
matched locally before atomically refreshing only the isolated preview binary.
Current preview SHA-256:
`ad229b4fc3fae4b04dd602b3bf279490ccacaed0cfd39d520907da162f5343bf`.
Previous preview is retained as `bin/tunlion-pairing-ux.before-inline-join`;
existing processes/state, installed production binary and daemon PID8921 remain
unchanged. `/tmp` was full during initial extraction; only the partial binary
created by this task was removed, and evidence was extracted to disk instead.
Python prototype: all 351 combined tests and enrollment two-process PTYs pass,
including durable receipt consumption, concurrent apply and no resurrection
after device/membership removal. These are prototype results, not Rust backend
ownership/delegation/request completion.

Join input boundaries: bracketed paste in a capable terminal is data, not
submission. The genuinely escape-free hidden fallback is single-line input;
multiline material should use the existing invitation-file/descriptor surfaces.
It cannot provide bracketed-paste semantics without emitting terminal escapes.
The internal non-TTY reader is not a newly exposed CLI stdin interface.
Short ordinary pairing-word prefixes remain visible; arbitrary word-shaped
secrets cannot be distinguished from code typing, so use an invitation file for
credentials outside the supported prefixed formats. Invitation/JSON prefixes,
opaque blobs and sticky-masked edits must never be echoed by join receipts.
Absolute paths deliberately display, so slash-leading opaque strings (including
protocol-relative URLs or base64) are ambiguous and can display as paths. Use
an invitation file/descriptor for unsupported raw credential formats. External
SIGTERM raw-terminal cleanup remains an existing limitation; keyboard interrupt
and normal/error/cancel cleanup are verified.

- [x] Refresh main: `3920402f`; inspect overlapping #542/#543 and open #395.
- [x] Compact inline word/code entry with separate contextual hint and bounded rows.
- [x] Request a thin yellow caret; restore terminal defaults on exit (PTY verified).
- [x] Quiet yellow selection marker in menus; text entry uses only the real caret. No fullscreen/alternate screen for this widget.
- [x] Safe paste, rejection blocks submission, editing-window tests and small-terminal coverage.
- [x] Dynamic xterm reflow/resize coverage and actual light/dark terminal image review.
- [x] Escape-free TERM=dumb/redirected-output fallback: numbered menu once, hidden code input; no cursor or paste-mode escapes. TERM=dumb PTY entry/picker tests pass.
- [x] Compact PairOk wait output; code displayed once after allocation, QR only when it fits. PairMatched says claimed/connecting, not authenticated success.
- [x] Scoped Rust tests and PTY checks on the remote worker, exact source digest verified.
- [x] Full real two-client code-pairing test, with chosen words at 40×12 and Enter-generated words at 96×24: actual loopback signaling + PAKE, matching peer records, replay refusal and authenticated reach. No seeded pair secrets.
- [x] General `join` code/invitation/file prompt: inline reader implemented and
  integrated; remote secrecy/editing PTYs and guided PAKE validation pass;
  review findings resolved with the explicit input boundaries above.
  Reuses the shared painter; sticky masking and hidden escape-free fallback.

### Build safety / reusable CI worker

- [x] Stop local Cargo after user correction. No further local Rust builds/tests.
- [x] Bring up one reusable `ci-dogfood` worker session, not a machine per job.
- [x] Configure shell-only audience `dovm`; use a dedicated single-use invitation
  secret, never credentials in argv. Do not change the existing host daemon.
- [x] Reuse its Cargo target/dependency caches; serialize builds with `flock` and
  cap compile parallelism at two. Send source snapshots and run jobs via Tunlion.
- [x] Run Rust tests and PTY checks remotely; preserve logs/results on the worker.

GitHub-hosted sessions have a six-hour hard job limit; this worker accepts a
1–330 minute lease. Reuse the active session rather than redispatching per test.
No paid Codespace/VM is started. A true always-on worker beyond that lease is a
separate hosting choice, not something this workflow silently provides.

Active session (2026-10-20): `ci-worker-dovm`, host `runnervm8k3b6`;
[run 39457508933](https://github.com/Abdk4Moura/tunlion/actions/runs/39457508933).
Prior run 39409083354 expired its lease; this replacement is warm and reused
for all subsequent commands. Greeting's independent Linux/Windows devloops
and their single-writer command/results branches remain untouched.
Workflow bootstrap commit `db54dbeb` on `work/pairing-inline-worker`. Source
snapshot and job script were sent over Tunlion with verified SHA-256 receipts;
Rust tests and PTY checks passed remotely. The dedicated admission secret
and local invitation file were removed after joining. Session metadata is at
`/tmp/opencode/pairing-ci-worker/session.json` on the dev box. Reuse this session
rather than starting another worker for the next job. Infrastructure-only
`ci/tunlion-worker-cache-20261020` (`a8df791c`) adds dependency/target cache
restoration across future leases; it does not push or deploy the Rust UX work.
Local infrastructure follow-on `dc67795a` also exposes the remote bootstrap
binary to isolated Python smoke fixtures through the helper's PATH.

Initial verification on that **same** worker: 27 entry tests (plus the two ignored PTY
drivers exercised by the runner), 56 UI tests (including 10 pairing-presentation
tests), 22 pairing-library tests; all passed. Eight PTY sessions cover 40×12 and
96×24 submission/cancel/interrupt, invitation-paste refusal, no implicit submit,
caret/default restoration, no alternate screen/full clear, no wrapping rows,
NO_COLOR and the narrow picker viewport. The second job reused the same hostname
and Cargo target cache; cached CLI test preparation took 0.18 s. The helper's
exact argv handling was also checked with spaces and a literal semicolon.

Final verification: **28 entry + 56 UI + 22 pairing-library tests**, ten basic
PTY sessions (including plain entry/picker), two xterm-backed resize/editing
sessions, and the two live pairing cases above. All passed. Visual review used
browser xterm replay of actual PTY bytes, not an HTML approximation; light/dark
entry and picker screenshots were inspected. Native caret requests and default
restoration are verified separately; terminals may override their appearance.

The UI now enforces the existing **48-character protocol limit**, including the
minted number on creation, instead of letting the shared normalizer truncate
input. Rejected input cannot submit a previous buffer. On resize, reflow makes
old row offsets ambiguous: retain that snapshot and reserve a fresh bottom
region, like the Python prototype. Ordinary typing then stays in that region;
the xterm test checks that it does not scroll. No history is guessed or erased.

Final source digest for `cli/src/codeentry.rs`:
`6bc01893b295b7f017b715c6546d6334dbb218070b7028451ccf4bedf19bd1ba`.
The final source and every harness match the remote `SOURCE_SHA256` manifest.
Worker evidence: `results/validation-20261020T110628-11516` and
`results/pairing-verification-v3.log`. Downloaded evidence survives the worker
lease at `/root/Tunlion/pairing-ux-evidence.tar` (SHA-256
`20f5167149f8fac1d975b8d8f0fde39c0dde90beccc8967a4b674377907ee804`),
extracted under `/tmp/opencode/pairing-ci-worker/final-evidence`. Only test
logs/screenshots/manifests were returned; fixture identity/private-key files
were not included. This slice is not merged or deployed; see Git history for
its source commit. Latest main was rechecked and remains `3920402f`.

## Final review of this slice

**Assessment: approved for the bounded CLI code-entry/picker slice.** Reviewed
`cli/src/codeentry.rs`, `pair_cmd.rs`, `ui.rs`, the worker workflow/helper and
the pairing verification harnesses.

- Correctness: explicit Enter, atomic insertion/refusal, protocol-sized input,
  caret cleanup, prior-frame row accounting and safe resize re-anchoring tested.
- Security: no new authority decisions or backend trust bypass; invitations
  refused/masked before code-entry rendering, including plain input kernel echo.
  This does not replace the general credential reader listed above.
- Performance: bounded inline rows and input, no fake progress/idle redraw loop;
  worker reuses caches and serializes builds. No further local Cargo runs.
- Style: normal-weight body text and one yellow marker, no block highlight;
  real screenshots checked in light/dark themes. Existing backend warnings were
  not mixed into this UI change.

No blocking findings remain **within this slice**. The unchanged debug transfer
assertion and unported backend/general-credential-reader work remain open below.

## Typing feedback: remove redundant marker and redraw-induced flicker

- [x] Remove the static `|` from text entry. It was only decorative; menu `|`
  markers still identify the selected option.
- [x] Cache the prior three-row frame. Paint only changed suffixes, erase only
  obsolete tails, and leave unchanged header/input/hint cells untouched. Pure
  tests prove a normal append can be just one character and a no-op writes zero
  bytes. The input reservation is cleared only initially or after resize.
- [x] Buffer each paint into one write, bracketed by synchronized-output mode
  (DEC 2026). No per-key cursor hide/show. Cleanup also releases that mode after
  an interrupted/erroring paint. Picker frames are batched too.
- [x] Verify actual browser-terminal behavior with a deliberately fragmented
  transaction: the before/during images are byte-identical, including across
  animation frames, until the end marker presents the finished update. This
  proves no intermediate blank frame in the supported xterm renderer. Terminals
  that ignore synchronized updates still get suffix-only, single-write edits;
  their own cursor/render behavior cannot be guaranteed by the application.
- [x] Re-run the full remote suite: **33 entry + 56 UI + 22 pairing tests**,
  PTY/plain/reflow/editing, both live PAKE cases and light/dark visual checks pass.
- [x] Refresh only the parallel test executable, by atomic rename; retain the
  old copy as `bin/tunlion-pairing-ux.before-flicker`. Do not interrupt an active
  test session or change its state. The installed production binary hash, daemon
  PID 8921 and identity were checked unchanged.

Evidence: worker `results/validation-20261020T115204-14343`, archive
`/root/Tunlion/tunlion-pairing-ux-flicker.tar.gz` (SHA-256
`efd20466f61971757632ea522e6689a8e41cb025a3ab4c4e3f037a299687f547`),
extracted at `/tmp/opencode/pairing-ci-worker/flicker-release`. The source and
every harness match its `SOURCE_SHA256` manifest; refined `codeentry.rs` hash is
`f6a9979d6ac3785597f0f680d51db0261a1dc0e246afe74592f6738a005c879a`.
The updated parallel binary hash is
`6060853d38e01211927bed45990a755050c0ee4bb43e760508249e322acc2b38`.
An already-running test keeps its old executable until the user exits/restarts.

No new production commands, no Python rendezvous backend in Rust, no implied
remote acceptance from a local Enter key. Plain/noninteractive paths stay plain.

## Backend work still pending

- [ ] **Independent ownership/membership:** an external participant keeps their
  own identity; joining is not ownership transfer. Current identity-store
  extraction (#543) is not implementation of these semantics.
- [ ] **Delegated authority:** primary roster and safe acknowledged handoff;
  bounded delegation with scope, lifetime and revocation enforcement; ordinary
  membership invitations cannot appoint administrators.
- [ ] **Durable asynchronous requests:** receiver-daemon persistence and
  sender-retained exact offers/retries; one-shot manifest/destination consent,
  not a standing capability; accepted sender-offline offers wait for sender.
  Reuse requests and post-commit notification adapters, not a mailbox subsystem.
- [ ] Recheck latest main and #395/#542/#543 before touching their engine/store
  seams. Preserve existing peerloop ownership and shutdown boundaries.
- [ ] Existing debug receive assertion after fresh ordinary code pairing:
  `cli/src/capability.rs:506`, "legacy trust with no resolved device identity".
  Reproduced after successful PAKE + authenticated reach, then a file send to
  that legacy-secret peer. Pairing records match; no permission gate is relaxed.
  Optional `runner/pairing-code-e2e.py ... --transfer` preserves the strict failing
  probe. Evidence on worker: `results/pairing-e2e-v1/narrow/receiver.log`.

The UI slice does not mark any of these backend tracks complete. Python-only
remaining work includes invite-file/non-waiting inviter reconciliation and the
remaining integrated restart/notification scenarios.
