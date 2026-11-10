# Device removal service

> Status: commit 1 of the shared removal service. The CLI's `devices forget` and
> the ladder's cut/restore path go through `filament_peerloop::removal`. The
> daemon console's `forget` command and `send_cmd`'s bare `devices_remove` call
> are intentionally **not** migrated yet; see *Follow-ups*.

## Why this exists

Forget, cut off and restore used to be CLI-only sequences. Four different call
sites could each write `devices.json` themselves, and a second client (Core,
Android, a future desktop UI) had no shared ordering to call. The ordering is
now one value and one writer:

```text
plan_removal(record, cert, owner, mode, now) -> RemovalPlan
DeviceStore::apply_removal(&plan, owner_key, remove_ssh_key) -> RemovalReceipt
```

`plan_removal` is pure. `apply_removal` is the only writer of the sequence.

## The invariants

- **Key is identity, name is presentation.** The device key from the stored
  certificate is what the key block names and what grant tombstones target. A
  name is only how the record is found. Before any write, the service re-reads
  the record and refuses if the name now holds a different key (a reused
  petname cannot remove a different device). A certified record with no planned
  device key is refused rather than removed fail-open.
- **Revocation first.** Forget writes `revoked-keys.json` before grants, the
  SSH key hook and the record. A crash after the first write leaves the refusal
  durable; the record is still there to retry.
- **Fail closed.** A missing store is empty. An existing `devices.json`,
  `revoked-keys.json` or `caps.json` that cannot be read or parsed is an error.
  Every store a plan will touch is preflighted before the first write; damage is
  never written over.
- **Idempotent.** A retry with the same plan is safe: an absent record is
  already removed (`record_removed = false`), an already-lifted block is a
  no-op, and re-marking `certRevoked` writes the same decision.
- **Local only.** The receipt describes this machine's stores.

## Modes and their order

| Mode | Key block | Grants | SSH hook | Record | `certRevoked` |
| --- | --- | --- | --- | --- | --- |
| `Forget` | write first | revoke by device key | call | remove **last** | record is removed |
| `CutOff` | untouched | untouched | untouched | kept | writes `true` (with display-only `revokedAt`/`principalState`) |
| `Restore` | lift by device key | untouched | untouched | kept | clears |

`CutOff` keeps the record on purpose: a device revoked in place must still meet
the capability gate on its next open and be told *why*. `Restore` lifts the key
block by the record's device key. It falls back to the name only when no record
or certificate exists any more (`promote <name>` after a forget); no record is
recreated.

## Receipt fields

`RemovalReceipt` is returned only after the store sequence completed (or
completed idempotently):

| Field | Meaning |
| --- | --- |
| `mode` | `Forget`, `CutOff` or `Restore`: what was planned and applied. |
| `name` | The presentation name the caller asked about. |
| `device_key` | The certificate's device key that the operation was keyed by, when one exists. `None` for a plain pair or a name-only restore. |
| `refused_until` | For a Forget of a live owner certificate: the certificate expiry that bounds the `revoked-keys.json` entry. `None` for CutOff (indefinite until Restore), Restore, and a forget with no live certificate from this owner. |
| `grants_revoked` | Count of resources whose owner-signed device-key grants became revoke tombstones. `0` for CutOff/Restore and for a device with no matching grant. |
| `record_removed` | `true` only when this call removed the record. A retry that finds it already gone is success with `false`. |
| `sessions` | Typed `SessionsSummary`: `NotTouched` (Restore) or `EndsOnRecheck` (Forget/CutOff). See the non-claims. |
| `local_only` | Always `true`. A field so a client cannot infer a remote effect from a successful receipt. |
| `key_block_written` | `true` when this call wrote/refreshed the block. |
| `key_blocks_lifted` | Blocks a Restore removed, with the recorded name, `revokedAt`, and device key hex. |

## What the receipt does NOT claim

- **No remote deletion.** Nothing is sent to the peer. Its record, key, grants
  and any cached name for this machine are untouched by this service. A peer
  that still holds a valid certificate from another trust anchor is not made to
  forget anything.
- **No session termination yet.** `SessionsSummary::EndsOnRecheck` says live
  sessions are expected to be cut by the daemon's existing liveness re-check,
  not that this call ended one. The service owns no session handle. A daemon
  that is not running has not applied anything until its next start; the CLI
  reports that separately (`revocation_live`).
- **No CRL or fleet-wide propagation.** The key block is local. An owner-signed
  roster or revocation distribution is a separate mechanism; this service does
  not write or send one.
- **No remote grant acknowledgement.** Revolved grants are local capability
  tombstones. The peer is not asked to confirm it dropped a cached grant.
- **No SSH key removal on a client without that hook.** The hook is injected by
  the host. The library service only claims the stores it wrote.

## Call sites in this commit

Migrated:

- `cli/src/fleet_support.rs::forget_device` — builds `Forget` and applies it,
  preserving the existing `Forgot …` line and exit codes.
- `cli/src/ladder.rs::cut_off` — builds `CutOff` and applies it, preserving the
  `Revoked …` line and exit codes.
- `cli/src/ladder.rs::restore` and `cli/src/identity_state.rs::set_device_revoked`
  — build `Restore` and apply it.
- `cli/src/device_caps.rs` no longer carries its own grant-revocation loop; the
  one copy is in the service.

## Follow-ups (deliberately not changed here)

- **Daemon console `forget <name>`** in
  `crates/filament-peerloop/src/recv/dispatch.rs`: still calls
  `ports.store.devices_remove(n)` directly. It predates the key block and grant
  revocation, so it needs a plan built from the record and the owner key, not a
  bare record delete.
- **`send_cmd`'s declined-remember removal**
  (`cli/src/send_cmd.rs`): calls `devices_remove(&name)` for a record that was
  just created and never granted. It is a rollback, not a user removal, but it
  should say so explicitly rather than sit beside the shared path.
- **Core/Android surface.** `tunlion-core` reads removal state but does not yet
  expose a removal operation. The service lives in `filament-peerloop`, so the
  FFI can add one without moving store policy again.
- **Capability-store lock coverage.** The service writes `caps.json` under a
  sidecar lock and the existing atomic writer, but older CLI writers still call
  `save_cap_store` without that lock. Unifying those writers is a separate
  change.
