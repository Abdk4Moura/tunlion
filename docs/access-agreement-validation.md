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
