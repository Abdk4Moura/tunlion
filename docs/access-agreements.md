# Foreground access agreements

Implementation entry points: `filament_peerloop::access` and
`filament_peerloop::send::ceremony`. This is a bounded library slice, not a claim
that all CLI invitations, platform endpoints, or background operation are ready.

**Validated library checkpoint:** exact-tree remote core08 at `8f8d66e5` passed
Linux `serve_folder` / per-request mount admission and raw transport control-limit
tests plus reduced/default/Core checks. This does not prove CLI folder download,
FUSE/WinFsp mount activation, or cross-platform endpoint readiness.
The validated boundary and exact jobs are in
[access-agreement-validation.md](access-agreement-validation.md).

## One engine, existing transport

`AccessSpec` composes multiple absolute folder paths with explicit RO/RW modes,
multiple exact TCP/UDP sockets, shell, and device networking independently.
`Lifetime::UntilEnded` is the default. The invitation claim deadline is separate:
once claimed, reconnect and a new scope review do not renew or re-claim it.
There is no subnet grant, wildcard target, implicit permanent contact, or
label-based identity. The engine creates no device/certificate/contact records.

The temporary host flow is:

1. Build a typed spec and `TemporaryBinding::new(host_key, &spec, lifetime,
   claim_deadline)`. Use the existing real nameplate/code allocation; the random
   offer ID is not a pairing code or bearer credential.
2. Run `Ceremony::new_temporary` with `TemporaryRole::Host` or `Recipient` over
   the existing `pake-msg` / `pake-confirm` relay. A recipient may inspect the
   **untrusted** binding with `inspect_temporary_binding` only to select its
   ceremony before sending its first element. Do not display actionable scope
   or act on it yet. Purpose mismatch or an unsupported counterpart fails
   closed, never falls back to standing pairing. Legacy pairing is unchanged.
3. After PAKE confirmation, sign `temporary_possession_message(sender, receiver)`
   with the existing overlay key. The shared `temporary_proof_payload` and
   `authenticate_temporary_payload` helpers bind both keys, roles, purpose, offer
   digest and this PAKE session. The result is a sealed `ProvenPeer`.
4. Host calls `AgreementEngine::offer_bound`, then signs `review_message` and
   sends the full typed snapshot over the same authenticated transport.
   Recipient calls `Ceremony::review_temporary_offer`, displays the resulting
   `AuthenticatedReview`, and only on explicit acceptance signs its
   `acceptance_message`. Host calls `accept` with that signature and proven peer.
   Viewing, cancelling and declining do not grant access.
5. Route temporary service opens to `serve_forward` with the accepted agreement,
   revision, proven peer, resource ID, SID and the **existing shared per-peer
   Mux**. Continue feeding subsequent L2 frames/close messages into that same
   Mux. Do not route temporary opens through standing shell admission, insert a
   remembered contact, or expose the Mux's unrestricted dial API to the peer.

`serve_forward` uses the existing host connector, L2 acknowledgement, byte pumps
and close frames. It does not add another permission store or transport. The
accepted spec, not a peer-supplied hostname/port, selects the exact target.
`serve_tcp` is the corresponding host seam for an already authenticated stream.
The Mux's actual `l2-open-ack` / `l2-close` is the activation result; returning
from a serving task is not proof that an endpoint became available.

## Lifecycle guarantees and limits

- Acceptance signs a domain-separated exact agreement/revision, both peer keys,
  full resource spec, lifetime, name and claim deadline. Host review and recipient
  acceptance use different signing domains. Possession alone is not acceptance.
- Existing-link `ProvenPeer::from_conn` requires a trusted link and **Proven**
  identity binding, not the inferred name/certificate cache. Delegated links are
  refused here: this adapter cannot bypass their authoritative signed ceiling.
- Revision checks and operation admission/removal/end share one mutex. Removal
  cancels affected operations; end cancels all operations for that agreement.
  Unrelated agreements' resources and names are left alone. Scope additions,
  changed targets, RW upgrades, and lifetime extension require a newly accepted
  full revision. Conservative cancellation occurs on additions/lifetime change.
- Expiry gates every new operation; active operations have a deadline timer.
  Disconnect is not end, acceptance, expiry renewal, or a new invitation claim.
  Reconnect still requires an authenticated peer and the accepted revision.
- Snapshots are authoritative. Events carry a monotonic cursor and retain 256
  entries; `reset_required` means reload snapshots. There are at most 128
  agreements, 64 resources per bundle and 256 concurrent operations per agreement.
  Terminal records are retained to reject replay; a full foreground instance
  returns `Capacity` rather than silently evicting legitimate state.
- This is foreground/in-memory only. Owner cancellation must call `end` and join
  serving tasks before returning. Process exit kills foreground access; dropping
  engine state cancels registered operations. Do not claim daemon/background or
  restart persistence. A durable daemon handoff/readiness protocol is not present.
- DNS labels normalize to ASCII and allocate base, base-1, base-2, etc., checking
  remembered and active names without overwriting. Labels remain stable for the
  agreement, are released at end, and never imply DNS integration. No `.mesh`
  endpoint, mount path or OS route is advertised by this module.

## Endpoint and authority readiness

| Resource | This slice |
| --- | --- |
| Exact TCP service | Real existing L2 Mux / HostServices connector integration; `forward-server` feature and a working host connector required |
| UDP service | Typed review only; operation returns `Unsupported` |
| Folder RO/RW protocol serving | Linux and Windows `mount-server` profiles use the accepted canonical root and per-request agreement admission. Linux pins a directory descriptor; Windows pins the host-selected root with a retained HANDLE and serves every request relative to it (reparse points/junctions are refused, never joined from a path). Other platforms return `Unsupported` |
| Shell (exec-class) | Unix only: accepted `spec.shell` + exact revision/peer is re-checked by the engine before the existing exec server spawns; the account is the daemon's existing nonroot login account via `StandardLocalExecProcess`, with no account switching, no daemon/SYSTEM fallback and no elevation. Windows returns `Unsupported` until a standard token backend exists |
| PTY / interactive terminal | Unix only: accepted `spec.shell` + exact revision/peer admitted through the same engine check, then the existing `PtyBackend`/`PtySession` seam (interactive login argv, real terminal IO, resize, process teardown). One-shot: no resume/reattach. Windows returns `Unsupported`. SSH remains typed review only |
| Recipient folder download / local mount | Client activation/UI is not integrated here; no successful local mount path is promised. The core `download_output::OwnedDownload` publisher is pinned and no-clobber on Linux and Windows (atomic same-directory publish; Windows does not claim directory-entry durability) |
| Device networking / subnet | Typed separately; no agreement-aware packet policy integration; unavailable |
| Background/restart | Unavailable; no durable handoff acknowledgement |
| Owned/delegated relationship creation | Unavailable; temporary engine does not manufacture ownership or delegated ceilings |

### Agreement-scoped shell (exec and PTY)

`AccessHandle::open_shell` sends the existing exec vocabulary (`argv`, `cwd`,
`env`, `alive_ms`) in an `access-open` with `kind: "shell"`, on the accepted
revision's own Mux/transport. The host endpoint (`AgreementEngine::serve_shell`)
re-checks the agreement, exact revision, proven peer and `spec.shell` **before**
registering streams or resolving a program; the caller's revision or an
`accepted` boolean is not authority. It then delegates to the existing
`shell::exec_server` state machine and its stdout/stderr/heartbeat/cancellation
paths, so no second shell or transport loop exists here.

On Unix the process mechanism is wrapped in `StandardLocalExecProcess`: the
account is the daemon's existing nonroot login account read from the password
database, revalidated immediately before spawn. Account switching is refused, as
is root/effective-UID mismatch; there is no daemon-identity, SYSTEM-token or
elevation fallback. Windows keeps returning `Unsupported` until a standard token
backend exists. The exec-class form is not a PTY: `tty: true` on an exec open is
still refused.

`AccessHandle::open_pty` sends `access-open` with `kind: "pty"` and the existing
terminal fields (`cols`, `rows`, `term`, optional one-shot `cmd`) on that same
Mux/transport. `AgreementEngine::serve_pty` applies the same exact
agreement/peer/revision/`spec.shell` admission, resolves and revalidates the
standard nonroot account, then delegates to the existing PTY host seam:
`recv::servers::shell::attach_pty` owns reservation, PTY stream/owner
registration, the resize channel, `pty-open-ack`, spawn and pumps. The standing
`pty-open` endpoint uses that same seam, so admission policy and field
sanitization are shared rather than duplicated. Terminal input rides `sid`,
output comes back on it, `pty-resize` reaches the existing resizer, and closing
the stream or dropping the handle sends the existing `l2-close`. PTY sessions are
one-shot: `resume`/`resume_from` is refused, so reconnect cannot revive a
terminal agreement or reattach its shell.

The shell session (exec or PTY) is an operation in the agreement. End, a removing
revision, expiry or dropping the engine latches its cancellation; exec drops the
owned `ExecChild`, while PTY calls the host's `PtySession::end` (which kills the
shell and closes its PTY) and forgets the host session record. An acceptor must
pass `ShellRuntime` to `AccessDispatch::new_with_shell`; use `with_pty` or
`pty_only` to supply a real `PtyBackend`. A `spec.shell` offer without any
matching backend fails closed instead of advertising an endpoint it cannot
serve. The reduced `tunlion-core` profile still has no embedded process/PTY
backend, so it continues to refuse drafting a shell offer even though the
library/driver API and initiator-side opens are available to a host adapter that
owns one.

Main at `27d7bfea` contains real feature-gated PTY/exec/mount/forward servers;
`tunlion-core` deliberately composes a reduced receive/transfer profile. Neither
fact means those endpoints are ready for temporary agreements. The CLI adapter
must branch before every ordinary pair enrollment/contact write, preserve real
PAKE code allocation, own inline review and cancellation, and route scoped opens
through the shared engine. This document does not claim that adapter is delivered
by the library commits alone.

Primary-device incoming-shell consent also needs an authoritative local role
representation migration. Existing `DeviceCert`/principal kinds model owner,
delegated and fleet trust, not primary appointment. Transport variables named
`primary` are unrelated. A real implementation must persist role-backed local
owned-audience opt-in, feed the same effective decision to PTY/exec/SSH admission,
and revoke their active sessions on opt-out. A preset, hostname, caller boolean,
or daemon elevation token is not a substitute. No process/account elevation is
performed by this slice.

The required migration is phased, not an unsigned settings shortcut:

1. `crates/filament-id/src/lib.rs`: define a versioned owner-authorized role
   designation bound to the device key, owner domain and monotonic designation
   revision. Settle appointment/removal/last-admin authority before interpreting
   it as primary status. Do not reinterpret transport primacy or existing certs.
2. `crates/filament-peerloop/src/recv/store.rs`: persist and verify that role
   statement separately from a device name, plus a private local incoming-shell
   opt-in bound to the local device key and owned audience. Missing/invalid
   role facts must not turn ordinary paired devices into owned primaries.
3. `crates/filament-peerloop/src/shell_gate.rs` and `host.rs`: expose the verified
   local consent decision as one restrictive input to the existing common
   PTY/exec/SSH gate; never a permissive replacement for delegated ceilings.
   `recv/servers/shell.rs`, `shell/admit.rs`, `ssh_ca.rs`, and the existing
   `HostServices::live_session_cut`/session cancellation paths must consume the
   same opt-out revocation generation for already-active sessions.
4. CLI settings and daemon host adapters (a separate lane) write the local
   opt-in on explicit user mutation, disclose the bound local account, distinguish
   saved consent from serving readiness, and report platform launch failures.
   Reduced `tunlion-core` must continue to refuse absent endpoints.

## Validation

The access tests cover mixed bundles, full signature/revision/peer binding,
decline/cancellation, claim-versus-agreement expiry, reconnect refusal after end,
scope removal, unrelated operations/names, ascending collisions and concurrency.
The TCP test uses a real localhost listener through `HostServices`, copies bytes
both ways, then verifies revocation closes both sockets. The ceremony tests run
two actual SPAKE2 instances and Ed25519 proof/review/acceptance, including purpose,
role, replay and scope tampering. These are **not** signaling-server/two-device
CLI end-to-end tests. Remote job commands/results are recorded in the lane report.
