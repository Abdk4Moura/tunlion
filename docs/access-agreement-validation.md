# Temporary shell integration validation (CLI)

Worktree: `/root/opencode-work/access-shell-cli`, branch
`integration/access-shell-cli`, base `2f18f09d`.

All compilation/tests ran remotely on the existing `ci-worker-dovm` identity
through `/root/opencode-work/worker-job.sh` (shared `build.lock`, unique job
names, job-local Python venv for the real transport cells, `CI=1`). Local work
was reads/edits/git/source sync only: no local cargo/rustc/clippy/test/formatter
and no CPU builds. No merge to main, deploy, production daemon or credential was
touched.

## Integrated core commits

The branch carries the minimal shell lane from
`/root/opencode-work/access-agreement-core`:

- `154f27d0` — refuse a temporary delegation ceiling bypass at host seams.
- `8f232994` — fail-closed existing standard-account exec host seam.
- `7af5516a` — agreement-scoped exec-class shell over the existing exec server.
- `119e8d48` — agreement-scoped interactive PTY over the shared PTY host seam.

Folder download/browse work already on this branch is preserved. The merge
resolved only documentation table text; no folder or End behavior was dropped.

## CLI adapter behavior

- `temporary_session::Session::host` composes the CLI's existing process/PTY
  primitives once: `ShellRuntime::new(CliExecProcess, log).with_pty(CliPty)`
  (reduced builds use `pty_only(CliPty)`). The `CliPty` instance owns a fresh
  foreground session map; it does not share or enter standing shell admission.
- Host `access-open{kind:"pty"}` parses the existing `pty-open` fields and calls
  `AgreementEngine::serve_pty` with the exact offer ID, revision and proven peer.
  The engine re-checks the accepted revision, peer, live state and `spec.shell`
  before the backend is reached. `serve_pty` delegates to the shared
  `recv::servers::shell::attach_pty` seam, resolves/revalidates
  `StandardLocalAccount`, and refuses root/service identity, UID change or
  account switching. `resume`/`resume_from` is refused.
- Host `access-open{kind:"shell"}` (exec-class) is served by
  `serve_shell`/`StandardLocalExecProcess`; the foreground CLI UI opens the
  interactive PTY form.
- Owner End, a removing revision, expiry and drop latch the engine operation
  cancellation. The PTY host `end` kills the shell and its PTY, forgets the
  session record and releases the mux stream/resizer. `PtySessionGuard` covers an
  abnormally dropped serving future.
- The temporary basket has a first-class shell row (host review and live
  Change access both toggle it). The recipient reviews the shell line before
  accepting and opens a real terminal from the active-session menu.
- The recipient terminal bridge uses only the agreement Mux: terminal input and
  output ride `sid`, `pty-resize` forwards local size changes, Ctrl-] detaches
  locally, and End/removal closes the stream. It never connects to a daemon.
- No Windows shell/PTY support is claimed. Non-Unix builds have no runtime and
  refuse the endpoint; the existing Windows branch/worktree was not edited.

## Remote evidence

Integration code commit: `8ce36c95` (`feat(cli): integrate agreement-scoped
temporary shell and PTY`). Full logs are under
`/root/pairing-ux/evidence/access-shell-cli-20261022/`; remote job directories
are under `/home/runner/work/_temp/tunlion-work/jobs/` with the names below.

| Job | Commands | Result |
| --- | --- | --- |
| `access-shell-cli-check-20261022a` | `cargo check -p filament-cli --bin tunlion --locked` | pass |
| `access-shell-cli-unit-20261022b` | `access_ui::tests`, `temporary_session::tests`, `pty_flows --no-run` | 7 + 5 unit tests pass |
| `access-shell-cli-pty-20261022c` | real two-process shell PTY I/O + resize + End | pass, 6.02s |
| `access-shell-cli-pty-20261022d` | real 1s expiry | pass, 8.13s |
| `access-shell-cli-pty-20261022h` | live shell removal through a signed narrowing | pass, 8.22s |
| `access-shell-cli-regress-20261022i` | service End, service revisions, folder download, draft cancel | 4/4 pass |
| `access-shell-cli-core-20261022j` | core shell/PTY/admit/account suites, reduced/default/Core checks, `shell_gate::tests`, print ratchet | 15 access, 7 access-session, 23 standing PTY, 15 admission, 2 account, 1 Core; all checks pass |
| `access-shell-cli-features-20261022k` | CLI check without `pty-server`; CLI check without `exec-server`; `access_bootstrap`; spawn ratchet | pass |
| `access-shell-cli-final-20261022m` | exact-tree rerun: unit suites, shell gate, Core/reduced checks, ratchets, 7 temporary real-transport cells | all pass |
| `access-shell-cli-final-remove-20261022n` | exact-tree rerun of live shell removal | pass, 8.22s |

The real cells use two isolated CLI processes on one Linux worker, the actual
signaling/PAKE path, an authenticated scope review, and a real remote PTY. They
assert remote command output (`REMOTE_PTY_42`), terminal size after resize
(`40 120`), End/removal/expiry teardown, and no `devices.json`,
`identity.ed25519`, device certificate, `armed.json`, capabilities, `up.pid` or
`exec.groups` standing records. They do not claim two physical devices or
Windows.

Prior failed attempts are not hidden: `pty-20261022e` removed the only scope
resource (invalid empty scope) and failed; `pty-20261022f` had a test-source
brace error; `pty-20261022g` asserted on a pre-narrowing menu redraw and was
corrected to assert after activation. None were reported as green.

## Windows folder serving and owned-download checkpoint

Merged from the validated core lane. Source adds a Windows
`AgreementEngine::serve_folder` arm and a Windows `download_output::OwnedDownload`
arm. The endpoint admission, per-request gate, revoke/cancel, expiry and SID
cleanup are the existing agreement semantics; the platform difference is the
pin. Windows opens the host-selected root once with
`FILE_OPEN_REPARSE_POINT`, refuses a junction/symlink/reparse root, verifies the
following open reports the same volume serial/file index, and serves every
request by opening each component relative to the retained directory HANDLE.
There is no path join and no unchecked fallback. Read-only and read-write modes
use the accepted `FolderMode`; `ReadLink` stays refused because the Windows caps
do not advertise symlinks.

Downloads remain caller-selected: an existing directory plus one plain name.
Windows creates a private staging file relative to the pinned directory and
renames the OPEN file HANDLE with `replace_if_exists = 0`, so existing names are
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

Boundaries: this is still a library protocol endpoint, not a WinFsp mount and
not a two-machine CLI flow. Windows reports no symlink support and refuses
reparse entries rather than following in-share links. Directory-entry durability
is not claimed on Windows. The existing upper-directory ACL and the host-selected
canonical root remain the operator's responsibility; a reparse point above the
selected root is resolved by the host's canonicalisation before the pin.

## Integrated CLI folder lane (Linux + Windows)

Merge commit `88eee3f0` integrates the validated Windows folder endpoint
(`fb9a01f0`, validated source `e121b2ff`) into the shell CLI lane at base
`1d286207`. Only the folder/CLI adapter changed: `platform::folder_download_supported`
now reports true on Windows when `mount-server` is built (the pinned
`OwnedDownload` publisher exists there), while browse and preview remain
protocol-level. Unix shell/PTY serving and its admission path are unchanged; the
Windows shell arm stays `Unsupported` and was not edited.

Integration commits: `39d86bcd` adds the platform capability test, the
Windows-specific recipient path test, and platform-neutral publication-name
assertions; `07244821` reverts the attempted Windows two-process E2E (its tree
is byte-identical to `39d86bcd` for the lane).

Linux host checks on exact head `39d86bcd` (reusable worker `ci-worker-dovm`,
shared `build.lock`, job-local Python venv, `CI=1`):

| Job | Suites | Result |
| --- | --- | --- |
| `access-shell-folder-check-20261022a` | `cargo check -p filament-cli --bin tunlion` | pass |
| `access-shell-folder-final-unit-39d86bcd` | CLI `access_ui` 7, `temporary_session` 5, `folder_access::protocol_tests` 3, platform capability 1; peerloop `access` 15, `mount_proto` 36, `download_output` 5, `access_session` 7 | 79 passed, 0 failed |
| `access-shell-folder-e2e-20261022d` (88eee3f0) and `access-shell-folder-e2e-72d64255` | `pty_flows` temporary cells incl. real folder browse/binary+empty read/download/no-clobber/symlink escape/End | 7/7 pass, 59.15s |
| `access-shell-folder-regress-20261022g` | live shell removal by signed narrowing; End during revised review | 2/2 pass |
| `access-shell-folder-feat-20261022f` | peerloop reduced/default; CLI without `pty-server`; CLI without `exec-server` | 4/4 pass |

Windows validation used the coordinated leased `windows-devloop` (not
`test.yml`) on run `39875620887`, CI head `761b038a` (code tree `39d86bcd` plus
`.devloop/cmd.txt` only), `DEVRESULT ok code=0 secs=338`:

- CLI `tunlion` and `filament-peerloop` Windows compile pass.
- `mount_proto` 45, `access` 12 (including `windows_folders` junction-root,
  substitution/End, and RW/abort cells), `download_output` 4, `access_session`
  4.
- CLI `folder_access::protocol_tests` 4 (including
  `windows_download_is_offered_and_peer_paths_cannot_become_local_paths`),
  platform capability 1, `access_ui` 7, `temporary_session` 5.
- All 82 tests passed; 0 failed. The lease was stopped after the result.

Windows two-process CLI E2E is **not** validated. Two attempts were made on the
same leased runner with a job-local venv and `CI=1`; neither is reported green:

- `39876983973`: PowerShell parsed `"tunlion.exe" --server ...` as an
  expression (`Unexpected token 'server'`). Added the PowerShell call operator.
- `39878237001`: with `& "tunlion.exe" --server ... add`, the interactive
  `tunlion` process on ConPTY printed `thread 'main' has overflowed its stack`
  before the temporary-access menu appeared. A non-interactive diagnostic
  (`--version`, and `add` with stdin closed) exited 0, so this is the
  interactive Windows terminal path, not folder protocol admission.

The folder E2E therefore stays `#[cfg(target_os = "linux")]`. Windows coverage
is the compiled CLI, recipient protocol/publication tests and the Windows core
suite above. Do not claim a two-process Windows CLI folder pass, a WinFsp mount,
or Windows shell/PTY support. The Windows branch/worktree was not modified.

## Remaining gaps

- The foreground CLI is the validated adapter. `tunlion-core`'s reduced profile
  still refuses to draft a shell offer because it embeds no process/PTY backend;
  a daemon/background handoff and its readiness protocol are not present.
- PTY sessions are one-shot: no resume/reattach. Full transport-loss resume is
  still explicitly unavailable.
- The authoritative primary-role/incoming-shell consent migration described in
  `access-agreements.md` is unimplemented.
- Windows has no standard token/ConPTY agreement backend; no Windows shell/PTY
  support is claimed by this lane. Windows folder protocol serving and
  caller-destination download are the validated `e121b2ff` slice; a WinFsp
  mount is not implemented or claimed.
- Process-tree termination is the existing PTY `end`/child-kill behavior, not a
  new tree-kill mechanism.
