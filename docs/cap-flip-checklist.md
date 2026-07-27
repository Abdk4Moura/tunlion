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

- [ ] `load_cap_store` cache with invalidation. `cap_authorize` reads and JSON-parses
      the store on every open now (correct for sampling in shadow). Before authoritative
      under load, cache it and invalidate on `apply_cap_op` / `apply_header`.

## Correctness corroboration (owed by capability.rs owner)

- [ ] Self genesis header is valid by construction: its signature verifies as stored
      (the `resource` field is overridden to "self" after signing) and its self-cert
      / genesis check passes. `la_no_header == 0` on a provisioned node corroborates
      this empirically, but confirm it structurally too.

## Rollback

The flag is the rollback: unset `FILAMENT_CAP_AUTHORITATIVE` to return to legacy
gating instantly. Counters keep accumulating in both modes, so post-flip evidence
is not lost.
