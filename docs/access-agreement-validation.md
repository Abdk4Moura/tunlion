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

## Remaining gaps

- The foreground CLI is the validated adapter. `tunlion-core`'s reduced profile
  still refuses to draft a shell offer because it embeds no process/PTY backend;
  a daemon/background handoff and its readiness protocol are not present.
- PTY sessions are one-shot: no resume/reattach. Full transport-loss resume is
  still explicitly unavailable.
- The authoritative primary-role/incoming-shell consent migration described in
  `access-agreements.md` is unimplemented.
- Windows has no standard token/ConPTY agreement backend; no Windows support is
  claimed by this lane.
- Process-tree termination is the existing PTY `end`/child-kill behavior, not a
  new tree-kill mechanism.
