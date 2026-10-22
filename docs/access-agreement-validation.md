# Access agreement lane validation

Worktree: `/root/opencode-work/access-agreement-core`, branch
`work/access-agreement-core`, base `27d7bfea`.

All compilation/tests ran remotely on the existing `ci-worker-dovm` identity,
lease workflow run `39685340961`. Local work was reads/edits/git/source sync only.
No production daemon, credentials, configuration or binary was changed.

The source-sync wrapper already owns the worker's shared build lock and target.
Do not nest another `flock` inside it or override the shared target.

## Passed access/ceremony slice

Exact command:

```sh
bash /root/opencode-work/worker-job.sh core-access-pake-20261022-05 /root/opencode-work/access-agreement-core -- bash -lc 'set -euo pipefail; timeout 900 bash -lc "cargo test -p filament-peerloop --lib access::tests -- --test-threads=2 && cargo test -p filament-peerloop --lib send::ceremony::tests -- --test-threads=2 && cargo check -p filament-peerloop --no-default-features --features dispatch"'
```

Exit 0: 8 access tests passed; 14 ceremony tests passed; reduced dispatch profile
check passed. Existing unrelated warning output remains. Remote source/job:

`/home/runner/work/_temp/tunlion-work/jobs/core-access-pake-20261022-05`

Full local wrapper log:

`/root/.local/share/opencode/shell/cd31f2124f23b5c0556ebda23ab6bff6bdc91712/sh_160ae93a8001g7P9Szt1h6vYaL.out`

Coverage includes actual two-party SPAKE2, session/role-bound Ed25519 possession,
authenticated full host review, explicit recipient acceptance, real TCP bytes
both directions, existing L2 Mux acknowledgement/data pumps, revocation socket
closure, unrelated agreement/name retention, scope revision and peer mismatch,
purpose downgrade/role reflection/replay refusal, 32 concurrent open/end races,
and ascending `-1`/`-2`/`-3` name allocation. The Mux transport in the fixture is
in-memory, and the target is a real localhost TCP listener. This is not a
signaling-server or two-machine CLI end-to-end claim.

## Prior runs, not hidden

- `core-access-tests-20261022-01` and `core-access-pake-20261022-02`: accidental
  nested-flock deadlock before cargo ran; coordinator terminated only these
  wrappers (exit 143). Source directories retained; no test result claimed.
- `core-access-pake-20261022-03`: compile failed E0509 (struct-update from a Drop
  type); fixed by explicit state initialization in `0eca216a`.
- `core-access-pake-20261022-04`: 6/7 access tests passed. Real TCP transfer and
  revocation succeeded; final assertion expected `Unsupported` for the inert
  host's actual `PermissionDenied`, which correctly maps to `Unavailable`.
  Assertion fixed without changing host denial semantics; superseded by run 05.

## Follow-up commands

Bootstrap command:

```sh
bash /root/opencode-work/worker-job.sh core-access-bootstrap-20261022-06 /root/opencode-work/access-agreement-core -- bash -lc 'set -euo pipefail; timeout 900 bash -lc "cargo test -p filament-peerloop --lib identity_bootstrap_is_mutating -- --test-threads=2 && cargo test -p tunlion-core --lib -- --test-threads=2"'
```

Cancellation/reduced tests command:

```sh
bash /root/opencode-work/worker-job.sh core-access-cancel-20261022-07 /root/opencode-work/access-agreement-core -- bash -lc 'set -euo pipefail; timeout 900 bash -lc "cargo test -p filament-peerloop --lib access::tests -- --test-threads=2 && cargo test -p filament-peerloop --lib l2::mux::tests -- --test-threads=2 && cargo test -p filament-peerloop --no-default-features --features dispatch --lib access::tests -- --test-threads=2"'
```

Run 06 exited 0: the bootstrap concurrency/preservation test passed and all 50
`tunlion-core` library tests passed. Its remote directory is
`/home/runner/work/_temp/tunlion-work/jobs/core-access-bootstrap-20261022-06`;
local full log is
`/root/.local/share/opencode/shell/cd31f2124f23b5c0556ebda23ab6bff6bdc91712/sh_160b02ace001FcqQc5EUye8BqT.out`.

Run 07 exited 0: 8 access tests (including dropped/aborted serving-future socket
cleanup), 13 existing Mux tests, and 7 reduced-profile access tests passed. Its
remote directory is
`/home/runner/work/_temp/tunlion-work/jobs/core-access-cancel-20261022-07`;
local full log is
`/root/.local/share/opencode/shell/cd31f2124f23b5c0556ebda23ab6bff6bdc91712/sh_160b1022f001yCLbIrs7UVwPli.out`.

## Exact-tree core08 follow-up

After coordinator confirmation of replacement worker run `39718656335`, the
parent authorized this exact command from clean
`8f8d66e5e73cfe9ed4628875f13a1097776ae729`:

```sh
bash /root/opencode-work/worker-job.sh core-access08-8f8d66e5-20261022a /root/opencode-work/access-agreement-core -- bash -lc 'set -euo pipefail; timeout 1200 bash -lc "cargo test -p filament-peerloop --lib access::tests -- --test-threads=2 && cargo test -p filament-peerloop --lib mount_proto::tests -- --test-threads=2 && cargo test -p filament-pair --lib && cargo test -p filament-transport --lib control_limits::tests && cargo check -p filament-peerloop --no-default-features --features dispatch && cargo check -p filament-peerloop --lib && cargo check -p tunlion-core --lib"' > /root/pairing-ux/evidence/access-checkpoint-20261022/core08-8f8d66e5.log 2>&1
```

Exit 0. Results: **11 access tests, 36 existing mount-protocol tests, 23 pairing
tests, and 1 raw control-limit test passed**. Reduced dispatch, default peerloop
library, and tunlion-core library checks all passed. Existing warnings remain.

Remote source/job:
`/home/runner/work/_temp/tunlion-work/jobs/core-access08-8f8d66e5-20261022a`.
The durable raw log is the redirect target above; direct redirection preserves
the wrapper exit status. No local build/test/formatter was run.

New folder fixtures confirm real existing-protocol RO reads, rejection of RO
write/rename and symlink/parent escapes, RW writes and rename, no redirect to a
substituted live root, per-buffered-request admission after revocation, and
task-abort cleanup. A filesystem request admitted before revocation may finish;
there is no rollback promise. This remains library integration coverage, not a
CLI folder download/mount or two-device platform-endpoint claim.

## Prior paused checkpoint (superseded by core08)

At the coordinator's usage-limit pause, there are no active lane jobs. The old
worker lease is rolling to run `39718656335`; no job 08 was submitted and no new
CPU work should start before the coordinator confirms the same worker reachable.

At that pause these follow-ups were source-only; core08 above subsequently
validated all three against the exact recorded tree:

- Linux folder endpoint: `serve_folder` reuses the existing mount server,
  pins a directory descriptor, owns cancellation/join, and adds per-request
  agreement admission for buffered requests. New RO/RW, root-substitution,
  escape, buffered-revoke and task-abort fixtures have not run.
- Shared `filament-transport::control_limits` bounds raw control metadata at
  256 KiB and nesting depth 32 before JSON parsing; direct control lengths are
  checked before body allocation. New tests have not run. The upstream legacy
  `Ev` queue remains genuinely unbounded and needs a producer/receiver migration.
- `96ccaad3` imports only the exact reviewed #566 pair-code entry helper and
  fixture hunks from `6cf86beb`, leaving `norm_code` unchanged. Not yet tested in
  this lane; the larger CLI classifier integration is held by the parent.

Unimplemented platform resources, background handoff, complete reconnect after
room loss, ownership/primary migration and CLI integration boundaries are listed
in [access-agreements.md](access-agreements.md).

## Temporary shell endpoint checkpoint

Source adds `AgreementEngine::serve_shell` and the initiator-side
`AccessHandle::open_shell`/`AccessShell`/`ShellRequest` plus
`AccessDispatch::new_with_shell`. The host admission re-checks the exact accepted
revision, proven peer and `spec.shell`; the process mechanism is wrapped in
`StandardLocalExecProcess` before streams or argv resolution; serving delegates
to the existing `shell::exec_server` state machine on the accepted agreement's
own `Mux`/transport. End, removing revisions and dropped/aborted sessions latch
the same cancellation, and a `ShellCleanup` guard releases both stream ids if the
embedding future is aborted. Exec-class `tty:true` remains refused by the
existing exec server (interactive PTY is its own endpoint below), and Windows
remains `Unsupported`.

Refs (no merge/deploy): exact validated source commit
`0c5a685290ce8e5d2fc299115500fc4cd526af48` (feature commit `7af5516a`, followed
by validation-record and comment/docs commits). The reusable Linux worker
(`ci-worker-dovm`, shared `build.lock`) ran jobs
`core-access-shell-20261022-02` through `-05`, all exit 0; `-04` and the final
`-05` ran the exact tree named here:

```sh
cargo test -p filament-peerloop --lib access::tests -- --test-threads=2
cargo test -p filament-peerloop --lib access_session::tests -- --test-threads=2
cargo test -p tunlion-core --lib access::tests -- --test-threads=2
cargo check -p filament-peerloop --no-default-features --features dispatch
cargo check -p filament-peerloop --lib
cargo check -p tunlion-core --lib
```

Results on `0c5a6852`: **14 access tests**, **6 access-session tests** and
**1 tunlion-core access test** passed; reduced dispatch, default peerloop
library and tunlion-core library checks passed. The new tests include
`shell_scope_is_the_accepted_revision_and_peer_not_a_caller_flag`,
`shell_endpoint::shell_serving_checks_the_agreement_before_it_resolves_or_spawns`,
and
`shell_contract::shell_open_uses_the_accepted_agreement_standard_account_and_end_tears_down`.
The shell fixture ran as the worker's real nonroot account and inspected the
exact spawn argv/env (`hello world` kept as one argument, `SECRET` filtered, no
account-switch call).

Local durable log:
`/root/pairing-ux/evidence/access-checkpoint-20261022/core-shell-05.log`.
Remote job directory: `/home/runner/work/_temp/tunlion-work/jobs/core-access-shell-20261022-05`.
No local build/test/formatter was run.

Remaining gaps from that checkpoint: `tunlion-core`'s reduced profile still
refuses to draft a shell offer because it has no embedded process/PTY backend, so
the host composition must come from the CLI/daemon adapter lane; Windows has no
standard token backend; the authoritative primary role store/consent migration
described above remains unimplemented. Interactive PTY support is recorded in the
next section.

## Agreement-scoped interactive PTY checkpoint

Source adds `AgreementEngine::serve_pty`, initiator-side
`AccessHandle::open_pty`/`AccessPty`/`PtyRequest`, and a shared host seam
`recv::servers::shell::attach_pty`. The standing `pty-open` endpoint and the
agreement endpoint now use that ONE seam for reservation, PTY stream/owner
registration, the resize channel, `pty-open-ack`, spawn, pumps and natural-end
cleanup; PTY field sanitization is shared via
`shell::admit::parse_pty_open_fields`. Agreement admission is the same engine
check as exec shell (exact accepted revision, exact proven peer, live state and
`spec.shell`) and runs before any backend effect. `StandardLocalAccount` (the
account half of `StandardLocalExecProcess`) is resolved before streams/argv and
revalidated immediately before spawn; root/service identity, UID changes and
account switching are refused. PTY sessions are one-shot: `resume`/`resume_from`
is refused, so reconnect cannot revive a terminal agreement.

End, a removing revision, expiry, stream close or a dropped/aborted serving
future calls the host's `PtySession::end` (the existing PTY teardown kills the
shell and closes the PTY), forgets the host session record and releases the mux
stream/resizer. `PtySessionGuard` covers abnormal future exit. The fixture
accepts real stream input, returns PTY output, applies `pty-resize`, and observes
the session end on agreement End; it also asserts no device/cap store writes.

Refs (no merge/deploy): exact validated source commit
`119e8d48d382f29ca6db3525f073f81e3ce03aad` (feature commit; the validation-record
commit follows and changes docs only). Job `core-access-pty-20261022-05` on the
reusable Linux worker (`ci-worker-dovm`, shared `build.lock`) exited 0:

```sh
cargo test -p filament-peerloop --lib access::tests -- --test-threads=2
cargo test -p filament-peerloop --lib access_session::tests -- --test-threads=2
cargo test -p filament-peerloop --lib recv::servers::shell::tests -- --test-threads=2
cargo test -p filament-peerloop --lib shell::admit::tests -- --test-threads=2
cargo test -p filament-peerloop --lib shell::standard_account::tests -- --test-threads=2
cargo test -p tunlion-core --lib access::tests -- --test-threads=2
cargo check -p filament-peerloop --no-default-features --features dispatch
cargo check -p filament-peerloop --lib
cargo check -p tunlion-core --lib
```

Results on `119e8d48`: **15 access tests**, **7 access-session tests**, **23
standing PTY tests**, **15 PTY admission tests**, **2 standard-account tests**,
and **1 tunlion-core access test** passed; reduced dispatch, default peerloop
library and tunlion-core library checks passed. New coverage includes
`access::tests::shell_endpoint::pty_serving_checks_the_agreement_before_it_reaches_the_backend`
and
`access_session::tests::pty_contract::interactive_pty_is_agreement_scoped_and_end_kills_the_session`;
the existing standing PTY suite (including ack/cap/collision/reattach/teardown
ordering) stayed green after the shared-seam refactor.

Local durable log:
`/root/pairing-ux/evidence/access-checkpoint-20261022/core-pty-05.log`.
Remote job directory: `/home/runner/work/_temp/tunlion-work/jobs/core-access-pty-20261022-05`.
No local build/test/formatter was run.

Remaining gaps: the real `PtyBackend`/`PtySession` implementation still lives in
the CLI adapter lane (`CliPty`), so `tunlion-core` continues to refuse drafting a
shell offer; the CLI/daemon adapter must compose it and must not route temporary
opens through standing shell admission. Windows has no standard token or ConPTY
agreement backend; the authoritative primary role store/consent migration remains
unimplemented. Process-tree termination is the existing PTY `end`/child-kill
behavior, not a new tree-kill mechanism.

## Windows folder serving and owned-download checkpoint

Source adds a Windows `AgreementEngine::serve_folder` arm and a Windows
`download_output::OwnedDownload` arm. The endpoint admission, per-request gate,
revoke/cancel, expiry and SID cleanup are the existing agreement semantics; the
platform difference is the pin. Windows opens the host-selected root once with
`FILE_OPEN_REPARSE_POINT`, refuses a junction/symlink/reparse root, verifies the
following open reports the same volume serial/file index, and serves every
request by opening each component relative to the retained directory HANDLE.
There is no path join and no unchecked fallback. Read-only and read-write modes
use the accepted `FolderMode`; `ReadLink` stays refused because the Windows caps
do not advertise symlinks.

Downloads remain caller-selected: an existing directory plus one plain name.
Windows creates a private staging file relative to the pinned directory and
renames the OPEN HANDLE with `replace_if_exists = 0`, so existing names are
never clobbered and concurrent publishers receive `name-1`, `name-2`, ... .
Publication is atomic on one volume. Windows cannot guarantee directory-entry
durability, so `PublishedDownload::durable` is false when the best-effort
directory flush is unavailable; a real post-commit flush error returns
`DurabilityUnknown(path)`.

Refs (no merge/deploy): exact validated source commit
`e121b2ff520e8e409bbc9dfb1d3dab12c7e7edb9` (documentation-only commits follow).
Windows validation ran on the leased `windows-devloop` run `39873516584` at CI
head `da9dba8e` (source parent `e121b2ff`):

```text
cargo test -p filament-peerloop --lib mount_proto::tests -- --test-threads=2
cargo test -p filament-peerloop --lib access::tests -- --test-threads=2
cargo test -p filament-peerloop --lib download_output::tests -- --test-threads=2
```

`DEVRESULT ok code=0 secs=173 head=da9dba8e`: **45 mount_protocol tests**,
**12 access tests** and **4 owned-download tests** passed. New coverage includes
Windows pinned-root reparse/parent escape refusal, root-path substitution
survival, handle-relative write/rename/truncate/delete, directory listing from
an open HANDLE, no-clobber publication against an existing name, binary/empty
byte integrity, cancellation/drop cleanup, and an authenticated agreement
folder read/End/abort fixture. The lease was stopped after the result.

Host Linux checks ran on the reusable worker (`ci-worker-dovm`, shared
`build.lock`) in job `core-win-folder-linux-final-20261022e` against the same
source: **15 access tests**, **36 mount_protocol tests** and **5 Linux
owned-download tests** passed; reduced dispatch and default peerloop library
checks passed. No local build/test/formatter was run.

Boundaries: this is still a library protocol endpoint, not a WinFsp mount, a
recipient download UI, a two-machine CLI flow, or an OS-level folder activation.
Windows reports no symlink support and refuses reparse entries rather than
following in-share links. Directory-entry durability is not claimed on Windows.
The existing upper-directory ACL and the host-selected canonical root remain the
operator's responsibility; a reparse point above the selected root is resolved
by the host's canonicalisation before the pin.
