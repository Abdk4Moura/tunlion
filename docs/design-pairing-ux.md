# Pairing & fleet-trust UX

Status: design (adversarially reviewed, pre-implementation). This is the spec the
next pairing/identity version is built against, and the model authoritative
enforcement is worth re-flipping on — because here the fleet defaults are *safe*,
not merely permissive.

## The invariant

> **A capability that can name an arbitrary resource is not a capability, it is an
> account.**

Scope is part of the capability, not a separate setting. Every *default* capability
names a **bounded** resource by construction. This is the single rule the whole
design turns on; if a default can name any file, any port, or any path, it has
already lost.

## Why this exists

0.7.0 flipped capability enforcement to authoritative-by-default. Real-world result
(the owner's own fleet, on upgrade): devices that were already paired could no longer
`ssh`/`transfer` without hand-granting each capability, per device, per direction;
`cap-status` reported `flip_ready=false`. Deny-by-default is right for *strangers* and
wrong for *your own devices*. The fix is not "turn enforcement off" — it's a model
where your fleet is permissive within safe scopes and only outsiders are denied by
default. 0.7.1 reverted the flip to opt-in pending this design.

## Two relationships (the wizard's first job)

`filament pair` establishes one of two fundamentally different things, and every
default flips between them. The wizard's first job is not "what permissions" — it is
**"is this me, or someone else?"**, answered by whether the peer's device cert chains
to *my* user key.

### Same-user (fleet add)
Peer cert chains to my user key **and** the link binding is `Proven` (device-key
possession — see rules). → permissive **within scoped defaults**. The device joins my
fleet; it is mine.

### Inter-user (external share)
Different identity. → **deny-by-default**, time-boxed, explicit, no identity
contamination. This is a bilateral *share*, not a fleet join. The one place the
authoritative instinct belongs.

The wizard never blurs the two. An inter-user pair can never masquerade as a fleet add.

## The scoped default set (same-user fleet)

A freshly-added fleet device gets, with **no further grants**:

| Default cap | Scope (bounded by construction) |
|---|---|
| `transfer` | into a **designated inbox** directory, not arbitrary paths |
| `reach` | **only ports the owner has already exposed** (`expose.json`) |
| `mount` | **read-only**, of an **explicit share root** — never home |

### The deliberate tier
Never a default. Never grantable by a flag alone. Requires an **interactive confirm on
the granting device**:

- `shell` — arbitrary code execution on the target
- `write-mount` — rewrites arbitrary files, **including `~/.filament/caps.json`**: a
  capability that edits its own leash (authority-equivalent)
- `mount` of a broader root (home, `/`)
- `reach` of a non-exposed or privileged local port

### Why each *unscoped* default is dangerous (the review that produced this table)
- **write-mount = authority-equivalent.** It rewrites `caps.json`/`devices.json`/the
  arming state. The capability layer is self-referentially unsound if the bounded
  party can edit where the bound is stored. (This also falsifies the "caps.json is
  owner-only local state" assumption relied on for the decorative self-header
  signature — tracked as a dependency.)
- **read-mount of home = key/credential theft, no code execution.** Exposes `~/.ssh`
  private keys, cloud/AWS/npm credentials, and on a **primary** device the user private
  key. Root-of-trust compromise for free.
- **reach-any-port = confused deputy.** Localhost services authenticate by "you are on
  localhost, so you are the user": unauthenticated Redis/Postgres, the Docker API
  (straight root exec), kubelet, metadata proxies, sshd itself. Reach-any-port hands a
  fleet device the union of every local service's ambient authority.

Shrinking mount to read-only does **not** fix this; only scoping does.

## Trust-establishment rules

1. **Proven, never Inferred.** Fleet-auto-trust gates on `binding == Proven`
   (device-key possession via the identity-expose possession-sig), never `Inferred`
   (a symmetric pairing-secret + name lookup from `resolve_peer_identity`). Otherwise a
   leaked *pairing secret* — not a device key — buys the permissive fleet defaults.
   This is the shell-key-reconciler finding resurfacing at the UX layer with far higher
   stakes. **Verified in code, not just asserted here**: the fleet path must be
   unreachable on `Inferred`.

2. **Short, auto-renewed fleet certs.** There is no global revocation and expiry is the
   only bound. A long-lived cert means a stolen device holds full fleet trust until it
   expires. Fleet certs are **short (days)**, **auto-renewed by a primary while the
   device is in good standing**. Removing a device is "**stop renewing**" — a pull model
   that works offline and needs nothing to reach the thief. A device offline past its
   TTL falls out and must be re-added: the correct failure direction, made **visible**
   in the UI rather than mysterious. Renewal *is* revocation-without-propagation.

3. **Interactive primary signing.** The user private key lives on 1–2 **primary**
   devices. Joining a device = a primary signs its fleet cert. Keystore/TPM stops
   *exfiltration* but not *use-while-present*, so the containment is real only if
   **signing requires a human at the primary** approving a named device + fingerprint.
   **No ambient or remote signing path, ever** — otherwise any code on any fleet device
   that can reach a primary mints a rogue fleet cert, and one compromise becomes fleet
   compromise. **"Primary" is a security role, not a convenience one** — resist the
   natural drift of making every device a primary "so joining is easier," which
   dissolves the containment.

4. **Migration into review, not trust.** Every legacy device has a pairing secret and
   possibly a cert. "Chains to my user key ⇒ fleet" would silently promote every
   previously-paired device into the new permissive defaults on upgrade, unreviewed.
   Legacy devices instead land in a **needs-review** state retaining their **old,
   narrower effective caps**; the user promotes per device.

## Inter-user rules

- **Deny-by-default**, per-capability, **directional** ("they send to me" ≠ "I send to
  them" ≠ "they shell in" — each a separate deliberate choice), **time-boxed by
  default** (reuses the ephemeral-auth-key TTL machinery).
- **The PAKE spoken-words ceremony is the trust flow.** Fingerprint display is
  *informational only* — real-world fingerprint-comparison compliance is ~zero and the
  design must not depend on a verification nobody performs. The spoken-word PAKE's
  security does not rest on a human comparing hex.
- **Bilateral consent.** What I grant, they accept; what they grant, I accept — the
  `requests` consent-queue surfaces on both ends. Neither side is unilaterally trusted.
- **No identity contamination.** Their device becomes a *labeled external peer* with a
  scoped grant. It is never signed under my user key, never joins my fleet, never
  inherits fleet trust.
- **No transitive fleet reach.** An inter-user capability can never name a
  *fleet-internal* resource; inter-user `reach` is limited to ports explicitly marked
  **external-safe**. (A coarse capability subsuming finer ones is the WG-mesh-limit
  shape.)

## The interactive wizard

`filament pair` is **interactive by default** (it routes same-vs-inter-user and sets
caps/expiry/direction/name); flags are the scriptable escape hatch — same pattern as
the existing interactive-code-entry / `--no-interactive`.

**Same-user (fleet add):**
```
$ filament pair 7f3k-otter
  connecting… "work-laptop" — identity 7b7e03e8 ✓ this is YOU  (binding: Proven)
  add to your fleet? [Y/n]
    default (scoped):  [x] transfer→inbox   [x] reach→exposed ports   [x] mount→share (ro)
    deliberate:        [ ] shell   [ ] write-mount   (confirm here to enable)
    name: work-laptop
  ✓ in your fleet. it just works. (cert renews every 3 days from a primary)
```

**Inter-user (external share):**
```
$ filament pair 7f3k-otter
  connecting… "alice-mbp" — identity 3f9c… ⚠ NOT you (alice)
  [speak/verify the pairing words]  otter · cobalt · ninth
  this is a SHARE, not a fleet add. grant nothing by default:
    [ ] alice sends files to me            [ ] I send files to alice
    [ ] alice reaches a port I expose  →   which (external-safe only)? ____
    [ ] alice shells in                    ⚠ full control — almost never
  expires: [7 days ▾]
  → alice will be asked to accept the reverse. send request? [y/N]
```

## `--yes` and scripting

- Under `--yes`, capabilities must be **named explicitly on the command line**, so a
  pasted command's blast radius is visible in the text the victim can read. `--yes`
  never carries implicit defaults. (Defuses the "just run `filament pair X --yes`"
  curl-pipe-bash vector.)
- The **deliberate tier stays deliberate under `--yes`**: no flag combination grants
  `shell` or `write-mount` without an interactive confirmation on the *granting* device.

## The refined model, in one paragraph

Same-user is permissive only within **scoped** defaults (transfer to an inbox, reach to
exposed ports, read-only mount of a share root), gated on `binding == Proven`, on short
auto-renewed fleet certs, with `shell` and `write-mount` in a deliberate tier no flag
can bypass. Inter-user stays deny-by-default and time-boxed, restricted to resources
explicitly marked external-safe, established over the spoken-word PAKE. Primaries sign
only with a human present. Legacy devices migrate into review, not into trust. And the
invariant behind all of it: every default capability carries its own scope, because a
capability that can name an arbitrary resource is not a capability, it is an account.

## User-less devices: identity is opt-in, never forced

A device must be fully functional with **no user identity at all**. Identity is an
opt-in layer that *adds* fleet auto-trust; it is never a precondition for using
filament. (0.7.0 violated this — authoritative-by-default made "create a user first"
feel mandatory. It isn't.)

Three tiers:
1. **No identity — "no account" mode (the original pitch).** `filament video.mp4` →
   speak a code → the other side claims it; `filament pair phone` remembers a specific
   device. **Consent-gated, not capability-gated**: you approve each incoming action.
   The capability layer never gates this path. Works forever with zero identity.
2. **User identity (opt-in) — the fleet.** Add an identity and your own devices
   auto-trust within scoped defaults.
3. **Inter-user shares** layer on top of either.

A user-less device lives in "explicit consent per action" mode; you opt into identity
only when you want your own fleet to stop asking. The account-free onboarding is a
feature, not a gap.

## Approvals: pull-safe now, push-better later

Every approval in this design — a fleet join, a deliberate-tier grant, an inter-user
share — is **asynchronous and often cross-device** (the action starts on one device,
the approval happens on a primary). Unlike `sudo` or a git credential helper, which
prompt synchronously in the context you're already in, filament cannot assume the human
is watching the granting device. And it has **no persistent notification channel yet**
(the tray/companion app is a future feature).

So the rule: **approvals are pull-safe now, push-better later.**
- **The substrate is the consent queue** (`filament requests` — list/approve/deny).
  Every approval lands there durably. With zero notification channel you can
  `filament requests` on a primary and act. This is the sudo-equivalent: it waits for
  the human, in a queue instead of a blocked terminal.
- **Notify hooks fire OS-native notifications now** as the stopgap (`notify-send` /
  Windows toast / `osascript`) — the consent-notify hooks already exist; wiring them to
  a desktop toast closes most of the gap before any app ships.
- **The tray/applet is a delivery upgrade, not a prerequisite.** No flow may work
  *only* with push; everything routes through the queue first, push is enhancement.

## Worked example: headless cloud fleet via an auth-key

Scenario: a user wants all his devices in one mesh, everything reachable, and shell into
every cloud box. You can't interactively pair 30 VMs — the auth-key (pre-auth
self-enrollment) is the primitive. Same shape as `tailscale up --authkey`.

```
# on his primary, once — the ONE deliberate act:
$ filament mint --fleet --shell --fleet-open --ttl 1h
  ⚠ devices with this key can SHELL your fleet and reach ALL fleet ports.
    confirm on this device: [y/N] y
  fk_7b7e03e8_9d2a…   (valid 1h)

# one line in cloud-init / Ansible / Dockerfile for every VM:
  curl -fsSL https://filament.autumated.com/install | sh && \
    filament identity join --key fk_7b7e03e8_9d2a… && filament up --shell
```

The security model holds: `shell` + `fleet-open` (reach-all-ports) are the deliberate
tier, so **minting the key is the single deliberate decision** (interactive confirm on
the primary), not one per box; `mint --fleet` *without* those flags gives the scoped
defaults. Short TTL for the provisioning burst + short auto-renewed enrolled certs mean
a leaked key or a decommissioned box **ages out** — no chasing 30 machines to revoke.
Interactive primary-approval is for phones/laptops; the auth-key is for headless/scripted
fleets; the two paths coexist.

## Open UX questions (next round)

- **Inbox / share-root defaults.** Where is the default transfer inbox and the default
  read-only share root? Per-device override? First-run setup vs sane built-in?
- **Primary designation UX.** How does a user mark a device primary, see which are, and
  recover if all primaries are lost (the encrypted backup phrase flow)?
- **The needs-review queue.** What does `filament devices` show for review-pending
  legacy devices, and what's the one-command promote?
- **Renewal visibility.** How does the UI show "this device renews every N days / falls
  out if offline > N" without being noise?
- **Re-flip criteria.** What must `cap-status`/`flip_ready` show on real fleets before
  authoritative-by-default is re-enabled?
- **Naming & discovery.** Same-owner devices announcing themselves for zero-config
  add (the Tailscale "it just appeared" feel) without leaking presence to strangers.
