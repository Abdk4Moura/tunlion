# Groups and tags as capability target kinds

> Status: design (2026-07-27). Builds on `docs/design-identity-access-ux.md` (section 5,
> "Groups are separate capability objects") and the existing `evaluate()` in
> `cli/src/capability.rs`. This note extends the capability target-kinds from
> `User=0x00 | Device=0x01` to include `Group=0x02` and `Tag=0x03`, plus
> wildcards. Design only; no code, no harness touch. Adversarial items for
> claude-advisor at the bottom.

## 1. The goal: ACL-grade expressiveness, no central file

Tailscale ACLs express "who can reach what on which port" via a central JSON
file. filament rejects the central file and the port model. This note extends
the existing edge-local owner-signed capability model so it matches Tailscale
on expressiveness (groups, tags, wildcards, subject-to-object rules) and beats
it on legibility via semantic actions (`shell`, `mount`, `forward`, `gpu-run`)
instead of raw port numbers.

The substrate does not change: every grant is still an owner-signed `CapOp`
with `target_kind` and `target_bytes`. What changes is that `evaluate()` learns
to resolve indirections (group membership, tag bearing) and wildcards.

## 2. Current state (baseline)

`target_kind` values today:

| byte | kind   | target          | match in `evaluate()`                     |
|------|--------|-----------------|-------------------------------------------|
| 0x00 | User   | `user_pub[32]`  | `target == principal_user_pub`            |
| 0x01 | Device | `device_pub[32]`| `target == principal_device_pub`          |

Unknown `target_kind` values are skipped (`_ => continue`), so adding new
kinds is backward-compatible: old peers ignore them; upgraded peers resolve
them. A grant targeting a Group at a pre-extension peer is simply not seen.

`evaluate()` is a single pure fn called by both enforcement and preview, so
preview cannot diverge.

## 3. New target kinds

### 3.1 Group (0x02)

A **Group** is a separate owner-signed capability object stored as a
`cap_group` entry in the capability store. It carries a member list and an
expiry.

```
Group {
    group_id: String,         // owner-chosen, scoped to owner_pub
    owner_pub: [u8; 32],      // the signer
    members: [GroupMember],   // ordered list
    version: u64,             // monotonic, owner-signed
    issued_at: u64,
    expires: u64,
    sig: [u8; 64],
}

GroupMember {
    kind: u8,                 // 0x00 = user_pub, 0x01 = device_pub
    pub: [u8; 32],
}
```

A grant targeting `Group` stores the tuple `(owner_pub, group_id)` in its
target bytes. The encoding is `SHA-256(owner_pub || group_id.as_bytes())`,
which is 32 bytes and fits the existing `target: [u8; 32]` field. This avoids
widening the CapOp wire format.

**Resolution in `evaluate()`** (pseudocode, single-pure-fn extension):

```
if target_kind == 0x02:
    // target bytes = SHA-256(owner_pub || group_id)
    let group = find_group_in_store(store, grantor, target_bytes)
    if group is None: skip (grant refers to a group we have not seen)
    if group.expires <= eval_time: skip
    // Check membership
    for member in group.members:
        if member.kind == 0x00 && member.pub == principal_user_pub: MATCH
        if member.kind == 0x01 && member.pub == principal_device_pub: MATCH
    // No match: continue scanning for other grants
```

Key properties:

- **Owner-scoped.** A Group is signed by one owner and scoped to that owner.
  `grantor == group.owner_pub` is an invariant; a grant cannot reference
  another owner's group. The group ID is local to the owner; two owners can
  each have a group named `"contacts"` and they are distinct objects.
- **Resolution hop.** `evaluate()` does one level of indirection: find the
  group object, check membership. No recursive groups (a group member is
  always a concrete user_pub or device_pub, never another group).
- **Monotonic / owner-signed.** Group updates are versioned and owner-signed,
  same as CapOp. `version` is monotonic; membership is a CRDT (latest
  owner-signed version wins). A replayed old version is rejected by version
  monotonicity.
- **Membership changes propagate edge-local.** Like all capabilities, there is
  no global membership push. A peer receives the latest group object when it
  receives the capability store entries. Until then, the stale group object
  governs. Expiry bounds this window (see Sharp edges).

### 3.2 Tag (0x03)

A **Tag** is an owner-signed label applied to a device or resource. It is a
**property**, not a container. A grant targeting `Tag` matches any principal
or resource that bears that tag, as asserted by the owner.

```
Tag {
    tag_id: String,           // owner-chosen, scoped to owner_pub
    owner_pub: [u8; 32],      // the signer
    version: u64,
    issued_at: u64,
    expires: u64,
    sig: [u8; 64],
}

TagBinding {
    tag_ref: [u8; 32],        // SHA-256(owner_pub || tag_id)
    subject_kind: u8,         // 0x00 = user_pub, 0x01 = device_pub, 0x03 = resource_id
    subject: [u8; 32],        // the bearer's pub or resource id
    owner_pub: [u8; 32],
    version: u64,
    issued_at: u64,
    expires: u64,
    sig: [u8; 64],
}
```

The tag value (e.g. `"prod"`, `"gpu-cluster"`, `"ci"`) is the tag ID. A
binding says "this device bears tag X". A grant targeting `tag:X` says "any
device bearing tag X may `shell`".

**Resolution in `evaluate()`**:

```
if target_kind == 0x03:
    // target bytes = SHA-256(owner_pub || tag_id)
    let bindings = find_tag_bindings(store, grantor, target_bytes)
    let match = bindings.iter().any(|b|
        (b.subject_kind == 0x00 && b.subject == principal_user_pub)
        || (b.subject_kind == 0x01 && b.subject == principal_device_pub)
        || (b.subject_kind == 0x03 && b.subject == resource_id_bytes(resource))
    )
    if match: AUTHORIZED
```

Key properties:

- **Owner-scoped.** Same as groups: only the owner who signed the tag can
  assert bindings for it. A grant targeting `tag:prod` from Alice means
  "devices Alice has tagged as prod." Bob's `tag:prod` is unrelated.
- **Resource tagging.** `subject_kind == 0x03` means the tag is on a resource,
  not a principal. This allows "grant tag:gpu-cluster `gpu-run`" where the
  resource (the GPU host) self-reports its tag at enrollment.
- **Tag on auth keys.** The existing `AuthKey.tag` field ("ci", "gpu-borrower")
  becomes a `TagBinding` at enrollment time. A device enrolled under an auth
  key tagged `"ci"` automatically receives the owner-signed `TagBinding` for
  `"ci"`. This closes the loop: the auth key's tag is now a capability tag.

## 4. Wildcards

### 4.1 Per-person wildcard (already exists)

A `User`-targeted grant matches any device whose `principal_user_pub` matches.
This is the existing semantic: grant `User(Alice)`, and every device Alice owns
inherits the grant. No change needed.

### 4.2 Scoped wildcard

A scoped wildcard is a Group of "all my contacts." Implemented as a regular
Group with special semantics:

- **auto-contacts group**: the owner's contact list is a `Group` that
  auto-populates from the identity store. Any introduced peer (contact book
  entry) is a member. The owner can still override by pinning a specific
  version. This is a convenience shorthand, not a new mechanism.
- **"any of my devices"**: already covered by the per-person wildcard (the
  `User` target kind is the wildcard for device scope). A group containing all
  the owner's own device_pubs would be redundant with `User`.
- **"any device tagged X"**: this is the `Tag` target kind, not a wildcard.

### 4.3 True `*` (mesh-add)

A grant targeting `*` (anyone who can reach this resource) is weighty and
rare. filament has no tailnet boundary, so `*` means anyone on the mesh who
can resolve a path to you.

```
target_kind: 0xFE   // Wildcard = reserve a non-colliding byte
target: [0u8; 32]   // zero bytes, sentinel
```

Properties:

- **Not a default.** Never suggested, never auto-generated. `*` must be an
  explicit, deliberate grant.
- **Flagged in UI.** The preview + directed-graph view must show `*` with a
  bright visual marker and a confirmation gate. The same human-confirm gate
  pattern (introduce, grant, recovery, GPU consent) gates `*`.
- **Not a group.** `*` is not a Group with infinite members; it is a sentinel
  in evaluate(). A Group can contain all contacts; it cannot contain
  "everyone."
- **Bounded by expiry.** A `*` grant without expiry is disallowed by
  construction (same mandatory-expiry rule as auth keys). The maximum TTL for
  `*` is capped low (24h default, configurable by the owner up to a hard
  ceiling).
- **Self-lockout guard.** A `*` grant for `shell` on your own resource PLUS a
  revoke of your own device's access must trigger the self-lockout check. The
  owner's own access is always preserved (derived from ownership).

### 4.4 What `*` is NOT

- Not a mesh-join shortcut. Mesh-join (`filament serve-tun`) grants L3 IP
  reach and is a separate, coarser trust tier (see the WG mesh boundary in
  `capability.rs`). A `*` capability grant does not confer mesh join.
- Not a tailnet. `*` on filament is `*` on the public mesh. If the mesh has
  10k nodes and you grant `* shell`, every one of them can `shell` you. The
  blast radius is honest and loud.

## 5. evaluate() extension (summary)

The single pure `evaluate()` fn, extended:

```
evaluate(store, header, principal_device_pub, principal_user_pub, resource, action, now):
    if principal_user_pub == header.owner_pub: return Authorized  // unchanged

    eval_time = max(now, ratchet_for(store, header.owner_pub))
    if ratchet is None: return Denied("ratchet uninitialized")

    for entry in store where entry.type == "cap_grant":
        if entry.grantor != header.owner_pub: continue
        if entry.resource != resource: continue
        if eval_time >= entry.expires: continue

        match entry.target_kind:
            0x00 (User):    target == principal_user_pub
            0x01 (Device):  target == principal_device_pub
            0x02 (Group):   resolve group -> check membership
            0x03 (Tag):     resolve tag bindings -> check bearer
            0xFE (Wildcard): ALWAYS matches (the `*` sentinel)
            _:              continue  // unknown kind, skip (forward-compat)

        if match && action in entry.permissions: return Authorized

    return Denied("not authorized")
```

Deny-by-default is preserved: if no grant matches, access is denied.

## 6. Group and Tag object distribution

Group and Tag objects (`cap_group`, `cap_tag`, `cap_tag_binding`) are entries
in the capability store (`caps.json`), same lifecycle as `cap_grant` entries:

- **Sync.** The existing capability CRDT sync (versioned, owner-signed, latest
  wins) covers them. No new wire format; `cap_group` is just another
  `{"type":"cap_group", ...}` JSON entry.
- **Discovery.** A grant that references a group or tag the verifier has not
  yet received is simply skipped (the grant is invisible until the referenced
  object arrives). This is the same behavior as a grant with unknown
  `target_kind`.
- **Pinning.** The owner can pin a specific group version in a grant to avoid
  the grant silently changing meaning when membership updates. Without pinning,
  the latest group version at eval time applies. This is a tradeoff: pinning
  gives stability; unpinned gives live membership. Both are valid in different
  contexts. The default is unpinned (the grant references the group by ID, not
  by version).

## 7. Multi-owner and the boundary

filament capabilities are edge-local and owner-signed. A Group contains only
members the owner chose. A Tag binding is only asserted by the tag's owner. No
third party can add you to a group or tag your resource.

**Out of scope (stated explicitly):** a third-party admin authoring global
policy over resources they do not own. In filament, only the resource owner
grants access. Multi-owner central authoring is the enterprise envelope (task
#6, demand-pulled, built last). Single-owner fleet ergonomics come from groups
and tags. An org admin who wants to enforce "every device tagged `prod` must
have 2FA" needs the enterprise envelope. Until then, fleet management is the
owner using groups and tags on their own resources.

## 8. Sharp edges

- **Resolution hop.** Evaluating a Group or Tag grant requires a lookup in the
  store. This is O(n) per grant today (scanning the flat `Vec<Value>`), and
  groups/tags add a second dimension: for each group-targeted grant, scan for
  the group object, then scan the member list. With many groups and many
  grants, this is quadratic. Mitigation: index the store by `(type, owner,
  group_id)` in a HashMap at load time, kept consistent with `save_cap_store`.
  The index is ephemeral (rebuilt on load) and never persisted.

- **Stale membership.** A group update that removes a member does not
  immediately revoke access. The old group object is valid until expiry. The
  same no-global-revocation bound as capabilities applies. Expiry is the
  control. Short group expiry (hours) for sensitive memberships; long expiry
  (months) for stable teams. No new mechanism.

- **Tag binding staleness.** Same as above. A device tagged `prod` retains the
  tag until the binding expires. Untagging a device pushes a new binding
  version with `permissions: []` (empty = remove), but the old binding is
  valid until its own expiry. The owner must issue bindings with short expiry
  if fast revocation matters.

- **Wildcard blast radius.** `*` on a mesh with no tailnet boundary is `*` on
  the public internet. The preview + directed-graph view must expand groups
  and tags to show the real effective set. A grant to `group:contacts` must
  show the actual member count and names. A grant to `*` must show a red
  banner: "Everyone who can reach you." The preview is the safety net.

- **Group object churn.** Every contact add/remove changes the group version.
  If the group is large and changes frequently, the version counter races and
  the sync overhead grows. Mitigation: diff-based sync (future, not this
  design). For now, groups are expected to be small (< 100 members) and
  infrequently changed. Large, high-churn groups are a known stress point.

- **No recursive groups.** A group member is a concrete user_pub or device_pub,
  not another group. This avoids infinite recursion and keeps resolution O(1)
  indirection. If nesting is ever demanded, it must carry a depth cap and an
  explicit cycle guard; that is out of scope here.

- **Group ID collision.** Two owners can each have a group named `contacts`.
  The group_id is owner-scoped, and the target bytes encode `SHA-256(owner_pub
  || group_id)`, so the 32-byte target is unique per (owner, group_id) pair.
  No collision.

- **Store growth.** Each group, tag, and tag binding is a store entry. A fleet
  owner with 100 devices, 10 groups, 50 tags, and 200 bindings adds ~360
  entries to caps.json. This is manageable (JSON, one file). For 10k-device
  fleets, a flat JSON file is not the right storage; that is the enterprise
  envelope, not this design.

## 9. Backward compatibility

Unknown `target_kind` values are skipped (`_ => continue`). A Group or Tag
grant at a pre-extension peer is invisible; it neither authorizes nor errors.
This is safe: deny-by-default means the old peer grants less access, never
more.

Group and Tag objects are new `type` values in the store (`cap_group`,
`cap_tag`, `cap_tag_binding`). Old peers ignore unknown store entry types. New
peers resolve them.

The CapOp wire format is unchanged. `target_kind` gains 0x02, 0x03, and 0xFE;
`target` remains `[u8; 32]`. No protocol version negotiation needed.

## 10. Interaction with delegated principals (auth keys)

A delegated principal's effective rights are `effective(owner) INTERSECT
auth_key.caps`. When `effective(owner)` is computed, group and tag resolution
is part of that computation. The ceiling still applies: a grant to
`group:all-contacts` may authorize a delegated principal, but the delegated
principal's caps are still capped by `auth_key.caps`. If `auth_key.caps` is
`["gpu-run"]` and the group grant says `["shell"]`, the delegated principal
gets `["gpu-run"]` (the intersection), not `["shell"]`.

Tag on auth keys: an auth key tagged `"ci"` results in a `TagBinding` for the
enrolled device. This is the mechanism that lets "any device tagged `ci`"
grants apply to CI runners.

## Open / to settle before build

- **Pinned vs unpinned group versions in grants.** Default: unpinned (latest
  group version at eval time). Pin as an opt-in per-grant. Design: `version`
  in the group reference (a variant of `target_bytes` that includes a
  `group_version`), or a separate `target_version` field in CapOp. The
  separate field is cleaner but widens the wire format.
- **Group-as-contact-book auto-population.** Should the auto-contacts group be
  a special built-in group (`group_id = "__contacts__"`) or a regular group
  the user opts into syncing? Built-in is simpler; regular group gives the
  user control. Leaning built-in with a `auto_sync` flag.
- **`*` TTL cap.** Hard ceiling at 24h (owner-configurable down, not up), or
  let the owner set any expiry with a loud UI warning? The auth-key precedent
  (capped low by construction) favors a hard ceiling. 24h is the proposal.
- **Tag binding garbage collection.** When a tag binding expires, should the
  store entry be pruned or kept as a tombstone? Pruning is cleaner; tombstone
  prevents replay of an old binding. Since bindings are versioned, replay is
  already blocked by monotonic version checks; pruning is safe.
- **Index strategy.** Build the store index at load time (HashMap) or at first
  evaluate() call (lazy)? Load-time is simpler and the store is small. The
  index must be invalidated on every `apply_cap_op` / `apply_header` call.
- **CapFloor for groups/tags.** Floors currently gate per-target `(kind,
  bytes)`. A group's `target_bytes` is `SHA-256(owner_pub || group_id)`. A
  floor on that hash is meaningful: it prevents replay of an old group
  version. But the floor is on the grant target, not on the group object
  itself. Should there be a separate floor mechanism for group/tag object
  versions? The CapOp version monotonicity already covers this for the grant;
  the group object's own version monotonicity covers the group. Two layers are
  not worse, but they must not conflict.
- **Resource-as-tag-bearer.** `subject_kind == 0x03` for resource tagging is
  new. Today resources are identified by their capability header's `resource`
  field (the self-certifying resource id). A tag binding on a resource must
  use that id as the subject. This is clean but means a resource can only bear
  tags from its own owner (the `owner_pub` in the binding must match the
  header's `owner_pub`). Cross-owner resource tagging is out of scope.
- **Preview expansion cost.** Expanding groups to show real effective sets on
  every preview is O(groups * members * grants). For 10 groups with 50 members
  and 100 grants, this is 50k operations. Acceptable in a CLI preview. For the
  directed-graph view in the companion app, cache the expansion.

## Adversarial items for claude-advisor

1. **Group membership injection.** If an attacker can inject a `cap_group`
   entry into the store with a valid owner signature but an attacker-chosen
   member list, they gain access to any grant targeting that group. The group
   must be verified against the owner's key before membership is trusted.
   Today `evaluate()` does not verify grant entries beyond the grantor check
   (`entry["grantor"] == owner_hex`). Group objects need the same verification:
   `group.owner_pub == entry_owner && verify(group.sig, group.owner_pub)`.
   This must be enforced in the resolution path, not at store insertion time
   (a peer could receive a forged group object over sync).

2. **Tag binding forgery.** Same attack vector: an attacker injects a tag
   binding claiming "device X bears tag prod." The grant then matches. The
   binding must be owner-signed and verified at resolution time, same as
   groups.

3. **Group version rollback.** An attacker replays an old group version that
   includes a removed member. The version monotonicity check on the group
   object defeats this, but only if the check is enforced at resolution time.
   A peer that has not yet seen the latest group version (due to sync lag)
   would accept the stale version. This is the accepted no-global-revocation
   bound, but it is worse for groups than for grants because a group update
   can silently expand access (add a member) or contract it (remove a member),
   and the contract case is the security-relevant one.

4. **`*` escalation via group.** A group that contains `*` as a member would
   be a backdoor wildcard. `GroupMember.kind` must reject `0xFE` (wildcard).
   A group member is always a concrete `user_pub` or `device_pub`.

5. **Recursive group via tag.** If tag binding `subject_kind == 0x02` (tag on
   a group) were allowed, an attacker could construct cyclic resolution
   (group -> tag -> group). `TagBinding.subject_kind` must reject 0x02.

6. **Ratcheted eval_time defeats short group expiry.** If the ratchet for an
   owner is set far in the future (e.g. a grant with `issued_at` at
   `now + 1 year`), `eval_time` is clamped forward and a short-expiry group
   object may be skipped because `eval_time >= group.expires`. This is
   correct: the ratchet is a freshness floor. But it means the ratchet
   controls expiry more than the group's own `expires` field. The ratchet
   update path (`update_ratchet`) already clamps `issued_at` to
   `local_clock + MAX_SKEW_SECS` (300s). A far-future `issued_at` is
   rejected. The ratchet cannot be pushed arbitrarily far; the 300s skew bound
   limits this attack surface.

7. **DoS via group object flooding.** An attacker who can write to the store
   could inject thousands of group objects, making resolution O(n^2) and
   denying service. This is not a new vector (the same attacker could flood
   grant entries). The store is on disk; the attack requires filesystem write
   access, at which point the attacker already owns the machine. If the store
   is synced over the mesh, a malicious peer could flood the sync channel.
   Mitigation: per-owner entry caps in the sync path (future, not this
   design).
