# Owned-device shell by default

Status: implemented on work/owned-shell-default; review ruling F1(a) applied; Q2-Q4 proposed below for review. Owner-approved direction 2026-10-25. Not for merge until the review closes.
Source of intent: /root/pairing-ux/MESH-INTENT.md "Shell account and primary-device
consent", and the owner's choice to make owned-device shell the default.

## Rule

A peer gets an incoming shell (PTY, non-interactive exec, SSH certificate) on THIS
device WITHOUT a per-device grant when ALL hold:

1. **Same owner**: the peer's device certificate chains to this device's owner key
   (`same_owner`, as computed today at the policy site).
2. **Proven** binding (device-key possession), never `Inferred`/`None`.
3. **Not revoked**, not explicitly denied (`deniedCaps`), certificate not expired.
4. **Not delegated**: no auth-key ceiling (`auth_key_caps` is `None`). Delegated
   and invited devices stay bounded by their signed ceiling, unchanged.
5. **This device accepts owned shells** (`owned_shell_accepted`):
   - on a device that is NOT the primary (holds a device certificate, no owner key):
     yes, unless the local setting `own-devices-shell` is `off`;
   - on the PRIMARY (holds the owner key): only when `own-devices-shell` is `on`.
     One persistent local opt-in for the whole owned-device audience: not a prompt
     per connection, not a grant per peer, not an account choice.

Everything else is unchanged: external devices, persons, runners, delegated devices,
explicit grants, the legacy `shell` setting / `up --shell` policy for paired devices,
forward-to-exposed-port bounds.

## Where

- `filament-peerloop::shell_gate::gather_shell_gate_inputs` is the one gather point
  for exec, PTY and SSH-sign. It sets `scoped_default` for the shell action to
  `host.owned_shell_accepted() && ak_caps.is_none()`. `scoped_default` feeds
  `scoped_in_bounds`, so the decision reuses the existing Proven-gated
  `fleet_auto_trust` path with every guard it already has (same owner, Proven,
  not revoked, deny short-circuit, expiry recheck). No new authorization path.
- `HostServices::owned_shell_accepted()` with a default of `false`, so every host
  that does not opt in (reduced core, test hosts) keeps today's behaviour.
- CLI host: `!is_primary() && setting != off  ||  is_primary() && setting == on`.
- Setting `own-devices-shell`: `Enum(["auto","on","off"])`, default `auto`
  (= member yes, primary no), global, daemon-reconfigurable.
- `is_deliberate_capability(shell)` stays true: shell is still never implied by
  MEMBERSHIP alone; it is implied by membership plus this device's acceptance.

## Turning it off

`own-devices-shell off` (or the primary switching back) blocks new opens at the gate
immediately (the gate reads the setting per open) and terminates existing incoming
owned-device shell/exec sessions through the live daemon reconfigure path. Session
teardown is part of this change, not a follow-up.

## Not changed here

Shell runs as the device owner's existing local account, non-elevated (the Windows
S4U shell-plane work is separate). No new commands. No prompt per connection.

## UX that rides on it (UI branch)

- Own-device review: "✓ Open a shell, as your own account" only after this lands.
- Just-in-time primary opt-in: the first owned shell into a primary that has not
  opted in creates a request there ("Allow your devices to open shells here?
  Always allow / Not now"); the requester is told in one line. "Always allow" sets
  `own-devices-shell on`.

## Tests

- Gate matrix gains the axes `owned_shell_accepted` x `primary` x `delegated`;
  exec/PTY/SSH equivalence keeps holding for every cell.
- Proven same-owner member: allowed with no grant. Inferred: denied.
- Primary without opt-in: denied; with opt-in: allowed.
- Revoked / denied / expired / delegated / external: denied exactly as today.
- Setting off on a member: denied; live sessions end on reconfigure.


## Review ruling F1(a) (applied)

- The owner-signed enrolment ceiling is a HARD ceiling for shell. The owned
  class requires `ceiling_covers(shell)`; pairing never exceeds what was signed.
- Own-device enrolment signs shell by DEFAULT (`default_device_ceiling`, and the
  `add --for device` default). Changeable at mint time: `--allow transfer,mount`,
  the invitation picker's "Files and folders only", and a hint on the code
  screen. Person and runner ceilings never include shell by default.
- Local acceptance gates BOTH no-grant paths for shell
  (`shell_gate::shell_gate_classes`): the owned class AND the ceiling path. A
  signed shell ceiling alone never authorizes a shell on a device that has not
  accepted owned shells. Delegated principals keep their ceiling path (gated the
  same way) and never ride the owned class.
- Live sessions admitted through either path end on the next recheck tick when
  acceptance is withdrawn or the ceiling narrows.

## Proposed semantics for Q2-Q4

**Q2, shadow vs authoritative.** The owned class is a scoped default, so it
decides in BOTH modes, exactly like transfer/mount scoped defaults. The ceiling
path stays authoritative-only for its decision, as today. Both are gated on local
acceptance. Rationale: the owned class is strictly narrower than the ceiling path
(same owner + Proven + not revoked/denied/expired + not delegated + signed shell
ceiling + local acceptance), and the owner chose it as the default posture.
Test: policy-site cell per guard (capability.rs) + `shell_gate_classes` matrix.

**Q3, primary.** Primary = this device's owner key file is present
(`UserKey::load` returns Some). A joined device that later imports the owner key
becomes a primary and therefore NEEDS the opt-in: the change is toward narrower.
A load error counts as primary (never widen on a read failure). Test:
`owned_shell_accepted_for` (settings.rs).

**Q4, what outlives an opt-out.**
- New opens: refused at once (acceptance is read fresh per open).
- Live PTY/exec admitted via the owned class or the shell ceiling: ended on the
  next `revoke_recheck_interval` tick. E2E cell 5 asserts a live owned shell ends
  within 30 s of `own-devices-shell off`.
- Warm links: no bypass. Every pty/exec/ssh-sign open re-enters the gate.
- SSH certificates already signed: NOT revoked by an opt-out; they stay valid to
  their TTL (`ssh.cert_ttl`, default 1h, max 24h), because sshd trusts the CA
  independently of the daemon. PROPOSAL: a certificate signed on the owned-class
  path gets TTL min(ssh.cert_ttl, 10 min), so an opt-out converges within 10
  minutes; explicitly granted certificates keep the configured TTL. Not yet
  implemented; awaiting the ruling.

## End-to-end test

`capability_harness::owned_device_shell_member_default_primary_opt_in_and_opt_out_ends_live`:
two real daemons WITHOUT `up --shell` (no blanket policy, no grant). Primary to
member allowed; member to primary refused, then allowed after the primary opts
in; member opt-out refuses; opt-out ends a live owned shell.
