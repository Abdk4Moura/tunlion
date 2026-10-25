# Owned-device shell by default

Status: implemented on work/owned-shell-default, unvalidated (no remote build yet), pending security review. Owner-approved direction 2026-10-25.
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
