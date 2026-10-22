# Foreground temporary access adapter

**Linux service vertical slice verified, not a complete product release.** Exact
tested code `81919a30` passed remote job `ux-access-ack-81919a30-20261022b`: four
session/ack tests, the real two-process signaling/PAKE/review/TCP-echo/End test,
and two shell-gate regressions. The test asserts socket closure and no permanent
records. Full raw log:
`/root/pairing-ux/evidence/access-checkpoint-20261022/ux-ack-81919a30-20261022b.log`.
This uses two isolated processes on one Linux worker, not two physical devices or
Windows. Earlier missing-backend and activation-ack failures were hard failures,
then repaired; they were never reclassified as success.

## Implemented code paths

Run `tunlion add` in a terminal and choose **Temporary access**:

- Add multiple existing folders, initially read-only, with explicit read/write
  and removal choices. Folder endpoints are explicitly unavailable until the
  library's scoped mount adapter is integrated and tested.
- Add explicit TCP ports or IP:port targets. A bare port means loopback. There
  is no implicit discovery scan or invented service list.
- Select services with arrows, Space and Enter. IDs are indices, never labels
  split on commas. Review the complete scope once or cancel without mutation.
- Create a real one-claim code through the existing signaling and shared PAKE
  ceremony, with an explicit authenticated temporary purpose. No sample code is
  returned as a live credential.

On the other terminal, `tunlion join <code>` waits for the host's first ceremony
element. Shared proof/digest/role verification selects temporary access before
any permanent-pairing write. Only authenticated full scope is reviewed. Explicit
acceptance signs the engine's exact versioned bytes. Loopback TCP listeners are
created only after the host acknowledges that same agreement/revision.

`temporary_session.rs` routes resource IDs through `AgreementEngine::serve_forward`
and the existing per-peer Mux. It never invokes generic standing forward admission.
The engine, not peer-supplied targets, chooses the exact socket. The host's inline
Change access / Set expiry / End controls operate on engine snapshots. Signed
revisions are reviewed on the recipient; narrowing removes affected listeners,
and unchanged service identities retain their streams. End cancels serving and
closes the recipient endpoints. Basic service use and End are verified; additional
multi-resource narrowing, revision, expiry and decline scenarios need their own
real CLI tests, not just the shared engine fixtures.

Until-ended is the default; claim expiry is separate. Background persistence,
shell, device networking, mount-ready paths and `.mesh` DNS are not offered as
working features. Full transport-loss resume is currently explicitly unavailable;
the adapter does not create a replacement claim or permanent contact. The current
foreground implementation cleans up the host agreement on exit, including a
fatal transport error. This reconnect limitation is an unfinished requirement,
not a substitute for same-identity agreement resume.

The shell command remains outward-only, using its existing known-device path.
Temporary-shell code entry is on hold until the bounded, conflicting #566 input
safety dependency can be composed safely. No second credential parser is added.

## Identity and lifecycle boundaries

Draft/review/cancel do not create identity, contact, grant or listener state.
Confirmed temporary mutations use only the existing secure internal overlay key;
no owner identity, membership certificate, armed invitation or permanent device
record is written. Owner-signing add actions use the existing atomic identity lock
only after validation/cancellation points. Existing and joined identities are
never silently replaced. Read-only commands do not mint keys. Join defaults to
the hostname rather than asking a mandatory naming question.

Primary incoming-shell consent and platform account/elevation logic are not
changed here. Preserving their baseline is not claiming newly implemented primary
policy. Optional endpoints remain unavailable until their authoritative engine
and safe existing-user account adapters are ready.

## Required remote validation

Use the approved worker wrapper and exact committed source, never local CPU jobs.
On a replacement worker, first create a **job-local** Python venv from
`backend/requirements.txt`, then point `TUNLION_TEST_VENV` to `.venv/bin/python`:

```sh
cargo test -p filament-cli --bin tunlion access_ui::tests
cargo test -p filament-cli --bin tunlion temporary_session::tests
cargo test -p filament-cli --test access_bootstrap
cargo test -p filament-cli --test pty_flows temporary_access_cancel_and_failed_connect
CI=1 TUNLION_TEST_VENV="$PWD/.venv/bin/python" cargo test -p filament-cli \
  --test pty_flows temporary_service_pairing_uses_real_transport_and_end_closes_the_socket \
  -- --nocapture
cargo test -p filament-cli --bin tunlion shell_gate::tests
```

The real PTY test drives two isolated CLI processes through signaling, PAKE,
authenticated scope review, TCP echo and End, asserting socket closure and no
standing records. It must not be reported green until it actually runs. Save the
complete worker log durably before lease retirement. Windows validation is also
pending the coordinated windows-devloop lane; no local cross-compile is permitted.
