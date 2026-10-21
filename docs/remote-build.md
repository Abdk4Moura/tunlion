# Remote builds

The dev box is small (2 cores, 5 GB), so tunlion compiles elsewhere via
[rbuild](https://github.com/Abdk4Moura/rbuild). Defaults for this repo live in
`.rbuild` at the root (musl static release of `cli/`, binary `tunlion`).

    rbuild                          # build the current pushed branch on GitHub's free 4-core runner
    rbuild --ref main --out ~/.local/bin
    rbuild --profile measure        # functional iteration: opt 1, no LTO, roughly half the time
    rbuild --profile dev --test

Builds run in the rbuild repo's Actions, not here, so this repo's Actions view
stays CI-only. The binary lands in `~/.cache/rbuild/Abdk4Moura-tunlion/` with
a `BUILD_INFO` file. Actions builds what is pushed; dirty or unpushed work
makes `rbuild` refuse until you push or pass `--force`.

Expect about 5 minutes for a release build and 2 for `measure`; the release
floor is the fat-LTO single-codegen-unit link of the CLI crate, not
dependencies (those come from a shared R2 sccache plus a cached target dir).

For an interactive loop (debugging, a live binary) use the reserve Codespace,
which is metered, so stop it when done:

    rbuild cs run --ref my-branch   # up, build, fetch, down
    rbuild cs up && rbuild cs sh
    rbuild cs down

Install: `git clone https://github.com/Abdk4Moura/rbuild ~/rbuild && ~/rbuild/install.sh`
(needs `gh` with `repo`, `workflow`, `codespace` scopes and `jq`).

## Reuse one worker for iterative jobs

**Do not run Cargo on the small dev box.** For a sequence of compile/test jobs,
the `ci-dogfood.yml` workflow has an explicit `worker_minutes` mode (1–330).
It starts one GitHub-hosted box and leaves its checkout, Cargo dependencies and
`cargo-target` directory in place for the whole session. Do not dispatch again
for each job. GitHub has a six-hour job ceiling; this is session persistence,
not an always-on VM or a paid Codespace.

Provisioning requires a dedicated single-use **device** invitation with
`transfer,shell` and a bounded lifetime, delivered through the repository secret
`TUNLION_CI_WORKER_INVITE`. Credentials must never be argv or logs. The original
single-payload mode keeps using its separate `TUNLION_INVITE` secret. Worker
mode uses `up --shell-only <host_name> --i-know --userspace`, not blanket shell
serving. Remove the dedicated secret after the worker has joined.

Wait for `tunlion reach <worker> --timeout 60`, not `devices.online`. Then use
`tunlion send` for source snapshots and `tunlion exec` for commands. Shell/exec
uses a sanitized environment: pass `--env HOME=/home/runner` and a PATH including
`/home/runner/.cargo/bin` when using the runner's Rust toolchain. Source
`/home/runner/work/_temp/tunlion-work/worker.env` inside the remote job to get
the common Cargo target dir and two-job compile limit. Serialize build jobs
with `flock` on that root's `build.lock`; keep job logs/results under `results`.

`bash scripts/ci-worker-exec.sh <program> <args>...` sets that environment and
serializes the command on the **existing** `ci-worker-dovm` session (override
`TUNLION_CI_WORKER` for another named session). It never provisions a new box,
evaluates a command string, or compiles locally. Pass `bash -c '...'` explicitly
when a job genuinely needs shell syntax. Commands start in the worker root.
Do not take the same build lock again inside a command run through this helper.

The trusted caller can end the session by creating `STOP` in that worker root,
or cancelling its workflow run. Cleanup calls `tunlion down -y`. No checkout
credentials or owner signing keys need to be copied to the worker.
