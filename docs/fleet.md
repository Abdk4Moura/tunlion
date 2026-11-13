# Fleet: connect your own devices

> Status: canonical usage and security reference.
> Last source-verified: 2026-11-02 against `a5f525e04577602796034b8add96b7eff8dd0dc0`.
> This describes current behavior, not proposed UX. The fleet trust model landed
> in PRs #609 and #616; later transport fixes do not change its defaults.

- [Choose the relationship](#choose-the-relationship-before-adding-a-device)
- [Connect and use the fleet](#connect-and-use-the-fleet)
- [Grant access](#grant-on-this-device-or-on-another-device)
- [Remove access](#remove-access-choose-the-scope)
- [Evidence and maintenance](#evidence-and-maintenance)

## Choose the relationship before adding a device

| Intent | Offer on this machine | Result |
|---|---|---|
| Remember a peer without fleet membership | `tunlion add --name phone` | Ordinary pairing, no fleet enrollment |
| Enroll one of your own devices | `tunlion add --for device --name laptop` | Owner-certified fleet device |
| Connect someone else's device | `tunlion add --for person --name alice` | External relationship, not one of your fleet devices |
| Admit temporary unattended compute | `tunlion add --for runner --out runner.key` | Temporary enrollment, not a lasting fleet member |

The owner is the machine holding the owner signing key, normally created by
`tunlion init`. Offer fleet enrollment there. The receiving machine accepts with
`tunlion join <code>` or `tunlion join <invitation-file>`. `--out <file>` on the
offer writes an invitation instead of displaying a code. Treat that file as a
credential; do not paste its contents into argv, logs or chat.

`tunlion add laptop` is shorthand for adding your own device, not for an
ordinary pairing. Use the explicit forms above when the distinction matters.
Do not choose `device` for a contractor or borrowed machine just to make it
easier to connect. Invitation capabilities and lifetime also bound enrollment;
a later grant cannot widen an invitation ceiling.

## Connect and use the fleet

Run `tunlion up` on devices that should be available, or deliberately install a
background service with `tunlion up --install`. Online siblings under the same
owner discover each other without pairwise pairing. Each must prove its own
owner-signed certificate; admission also checks the owner's signed roster.

```sh
tunlion devices
tunlion reach laptop
tunlion send report.pdf --to laptop
```

Use names from `devices`, not names supplied by an unverified peer. A device
being listed is not proof it is online or that an operation is authorized.

### What membership does and does not grant

For a **fleet sibling** (same owner, never paired directly with the receiver):

- File transfer into the receiver's configured inbox is the one default. No
  explicit grant is needed. This is not permission to write arbitrary paths.
- Shell/exec/PTY, mount, forwarding and routes are not implied by membership.
  They need their applicable explicit authorization and serving configuration.
- Local denies, device revocation and certificate expiry override grants.
- Ordinary paired devices, owner links and invitation-bounded devices have
  their own policies. Do not infer their permissions from sibling defaults.

Validated at integration head `9144ee749`, not yet merged to main:

- A certificate-less authenticated pair retains shell access granted explicitly
  on the serving machine.
- An anonymous peer is transfer-only.
- A replacement transport does not inherit the previous transport's fleet
  verification or nonces.

There is no transitive trust across owners and no multi-hop routing through a
sibling. A connection may use a direct transport or a relay. Discovery does not
guarantee reachability.

The browser currently supports pairwise files and shell but does not enroll into
a fleet. That is an implementation gap in the browser client, not a separate
security model. Browser parity is a target, not current behavior: the goal is
for every client to consume the same universal core semantics, with the browser
using a WASM binding. Platform limits remain explicit: a browser can be a remote
terminal client but cannot serve a native PTY, and it cannot serve an OS
filesystem mount.

## Grant on this device or on another device

On the receiving device, `tunlion grant laptop shell` grants laptop access to
**this machine**, subject to its other bounds. Shell is owner-equivalent remote
command execution as the serving user; it is not a file-transfer permission.

On the owner, `tunlion grant laptop shell --on server` requests shell for laptop
on server. Only `transfer`, `mount` and `shell` are distributed this way. The
owner daemon must deliver the signed set to the target, and the target's local
policy decides whether it applies:

| Target's `fleet.owner_grants` | Owner-signed grants that can apply |
|---|---|
| `off` | None; the sibling inbox default still exists |
| `files` (default) | Transfer and mount, not shell |
| `all` | Transfer, mount and shell |

Inspect with `tunlion set fleet.owner_grants` on the target. Change it there
only when intended. `all` permits applicable owner-signed shell grants; it does
not itself grant every sibling shell. This setting does not restrict a grant
made locally on the receiver, and cannot override a local deny.

**Recorded is not applied.** A successful owner grant command records intent,
not an acknowledgment that the target received or enabled it. `tunlion devices`
on the target identifies held shell grants that its policy does not apply.

Signed sets expire, by default after 15 minutes without refresh. If the owner
stays offline, they stop authorizing new operations after expiry. The sibling
inbox default does not depend on those sets or on the owner staying online.

## Remove access: choose the scope

| Intent | Command and boundary |
|---|---|
| Revoke a capability on this machine | `tunlion revoke laptop shell`; this is not fleet removal. An invitation-ceiling capability cannot be removed this way; the command refuses and names the cut-off remedy. |
| Withdraw an owner-distributed grant | On owner: `tunlion revoke laptop shell --on server`. Target stops applying it after delivery, or after the held set expires if disconnected. |
| Cut a device off | `tunlion demote laptop --to cut`. On owner, the signed roster carries removal to siblings. |
| Prevent future invitation claims | `tunlion add --withdraw <invitation-name>`. Already-enrolled devices keep access; cut them off separately. |

**Withdrawing an owner grant or narrowing `fleet.owner_grants` does not close
an already-open session.** It refuses new sessions once effective. An existing
session ends normally or when its link closes. Do not report that all access has
ended merely because a grant was withdrawn.

Whole-device revocation and certificate expiry close affected sibling links;
this guide does not claim that a cut or a capability revoke terminates every
session kind. Owner revocation is not instant global delivery: a sibling
unreachable from the owner cannot learn a new roster until contact. The fleet rendezvous secret is
not rotated on revocation; removal denies admission, not all presence visibility.
For sibling admission, the newest held roster remains in use even past its
validity timestamp; do not confuse it with the expiring owner-grant sets.
Confirm delivery and link closure on affected machines before claiming a cut is
effective everywhere. Do not silently restart services as a workaround.

## Evidence and maintenance

- `cli/tests/fleet-automesh-gates.sh`: enrollment, sibling reach, bidirectional
  inbox delivery to the named device, refusal, revocation and unaffected peers.
- `cli/tests/fleet-trust-gates.sh`: owner grants, target policy, local deny,
  withdrawal, expiry, and mixed versions.
- At integration head `9144ee749`, the exec (29/29), SSH (8/8) and terminal
  withdrawal (19/19) suites were green. That run covers those suites only.
- `proofs/fleet_automesh_model.py` and `proofs/fleet_trust_model.py`: modeled
  admission and grant invariants, with mutation controls. Models are not proof
  of every runtime path or network topology.
- `design-fleet-automesh.md`: implementation history, including superseded
  behavior. Use this guide for present usage, not its historical command tables.

Different versions enforce their own receiver policy; an older peer does not
acquire these safety rules just because its neighbor was upgraded. New validation
must name its exact source head and run on approved workers or CI, not a live
production host.
