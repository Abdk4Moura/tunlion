# Capability authoritative-flip checklist

Prerequisites for setting `FILAMENT_CAP_AUTHORITATIVE=1` (making the capability
layer the live gate instead of shadow). Do NOT flip until every item holds. The
first week after a flip is exactly when someone reads the denial logs to work out
what broke, so the diagnosability items matter as much as the correctness ones.

Owner: whoever writes the flip commit. Cite the evidence in that commit.

## Hard gate (ShadowCounts::flip_ready)

- [ ] `la_authorized > 0`: a real, meaningful sample of legacy-ALLOWED opens was
      observed on real traffic (not a token count, not a legacy-DENIED-only sample).
- [ ] `la_denied == 0`: no header that EXISTS disagreed with a legacy-allowed open
      (no BREAKAGE). Any `CAP-SHADOW CRITICAL` line is a blocker; fix the grant or
      the header, do not reinterpret the criterion.
- [ ] `la_no_header == 0`: every resource EXERCISED in the window was provisioned.
      Caveat: this proves it for resources exercised, not all resources. Tight today
      (all gates pass "self", one resource); becomes a sampled claim when resources
      multiply, revisit then.

Read these from the running daemon via the shadow-status surface (task #16), since
the counters are process-global and a fresh CLI invocation reads zeros.

## Mandatory review citation (not a boolean)

- [ ] Cite `ld_authorized`, the WIDENING count: opens legacy REFUSED that cap
      AUTHORIZES, which the flip will newly PERMIT. If nonzero, enumerate the
      distinct `(action, resource, device)` triples from the `CAP-SHADOW WIDENING`
      log and justify each: why should this access, absent before, exist now? This
      is the direction access appears silently; a migration to deny-by-default must
      not grant new access unseen.

## Diagnosability (fix before flip, correct in shadow so not shipped yet)

- [ ] Gate-level denial strings must defer to the cap outcome under authoritative.
      All five are currently worded for the LEGACY cause (l2-open "device not granted
      shell"; shell-bootstrap / pty "no shell cap / untrusted"; file-offer daemon
      "unverified peer"; mount "not authorized (mount capability required)"). Under
      authoritative these can be flatly false: a peer refused because the resource is
      UNPROVISIONED gets told "unverified peer", pointing the debugger at trust when
      the fix is to provision a header. A confidently wrong diagnostic is worse than
      silence. Fix: have `cap_gate_effective` hand back the reason it already computes
      (Denied vs Unprovisioned) so each gate says what actually happened rather than
      what usually does. The bool return currently discards that string.

## Performance

- [x] `load_cap_store` cache with invalidation. DONE (#27): nanosecond-mtime cache,
      explicitly invalidated inside `save_cap_store` (the single write funnel; all
      persists go through `save_and_list_revoked` -> `save_cap_store`). Nanosecond (not
      seconds) mtime so a sub-second direct rewrite can't serve stale data. Known
      follow-up (non-blocking): `save_cap_store` still uses `std::fs::write` (non-atomic),
      unlike the devices.json path made atomic in #23; deferred under the clean-slate call.

## Correctness corroboration (owed by capability.rs owner)

- [ ] Self genesis header is valid by construction: its signature verifies as stored
      (the `resource` field is overridden to "self" after signing) and its self-cert
      / genesis check passes. `la_no_header == 0` on a provisioned node corroborates
      this empirically, but confirm it structurally too.

## Authoritative-only restrictive gates (added, all purely restrictive)

Under `FILAMENT_CAP_AUTHORITATIVE` the effective decision is composed from the cap
outcome plus these gates, each of which can only downgrade Authorized -> Denied,
never widen. All are no-ops in shadow. Each has a both-branches CI test.

- [x] #21 binding-strength: a cap-authorized open with binding != `Proven` (identity
      not device_priv-proven) is denied. `cap_authorize_proven`.
- [x] #22 cert-expiry: re-checked per authorize (not only at resolve); expired or
      unknown-expiry (None) fails closed. `cap_authorize_expired`.
- [x] #26 trust floor: for gates whose legacy check is trust-based (transfer, mount),
      an untrusted link (not pair-proven) is denied even if cap-authorized. Prevents the
      flip from silently swapping the trust basis from pair-proof to device-key.
      `cap_trust_floor`. Shell is exempt (its legacy check is capability-equivalent).

### Caveat: shadow counters are BLIND to these gates

The shadow counters (and therefore `flip_ready`) bucket the raw cap-STORE outcome.
The restrictive gates above are no-ops in shadow, so `flip_ready == true` means
"the cap store agrees with legacy", NOT "the full authoritative gate agrees with
legacy." A peer that is la_authorized in shadow can still be denied at the flip by a
restrictive gate (e.g. an Inferred-binding, shell-granted peer). Do NOT read
`flip_ready` as "nothing breaks at the flip." If a breakage-accurate sample is ever
needed, the counters must apply the restrictive gates as-if-authoritative for the
COUNTING (separate from the returned decision).

## Migration (#25): RESOLVED — no migration, clean slate

Owner decision (2026-07-27): there is no install base to preserve, so the flip
simply reconciles away any device that is legacy-shell-authorized but has no cap
grant (hard cutover). No preview command, no auto-migrate. The blast-radius
enumeration exists if ever needed (`devices_with_shell_revoked` / the `CAP-SHADOW
RECONCILE: WOULD remove` log lines), but is not a gating concern for this flip.

## Validation status (as of this session)

- [x] Cap gate LOGIC: proven by unit tests (feat 054f41d, full binary suite green,
      incl. both-branches tests for every restrictive gate).
- [x] Shadow SAMPLING on real traffic: proven (la_authorized=3, shell+mount coverage,
      zero disagreement, single stable daemon PID). Instrument proven by the six-bucket
      detector-proof.
- [x] Authoritative grant / evaluate / cap-status display: confirmed working under
      `FILAMENT_CAP_AUTHORITATIVE=1`.
- [ ] Live-traffic authoritative ENFORCEMENT matrix (granted->allow, revoked->deny +
      key removed, ungranted->deny, Inferred->deny, trust-floor, rollback): NOT yet run.
      Blocked on the same-box rig by transport (signaling `api.filament.autumated.com`
      503; same-box direct/loopback also won't establish). Controlled-proven to be a
      transport-layer limitation, not authoritative-mode-specific (a fresh SHADOW daemon
      fails transport identically). Run this on a CROSS-MACHINE rig (do-vm <-> other-do)
      when signaling is healthy before a production flip.

## Rollback

The flag is the rollback: unset `FILAMENT_CAP_AUTHORITATIVE` to return to legacy
gating instantly. Counters keep accumulating in both modes, so post-flip evidence
is not lost.
