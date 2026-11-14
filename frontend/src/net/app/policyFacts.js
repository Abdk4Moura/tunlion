// APPLICATION layer: the browser's real link facts, shaped for the shared
// transfer policy (lib/policy.js -> tunlion-policy-wasm -> filament-policy).
//
// The browser has no device certificate and no owner certificate. What it does
// know is:
//   - the transfer's direction and status;
//   - whether a one-time code ceremony authenticated THIS link (byCode);
//   - whether a pair-proof matched a stored device record on THIS link (proven);
//   - that record's agreed caps, while the record still exists;
//   - whether a human consented: they typed the code, or they remembered the
//     device.
//
// Revocation, certificate expiry, same-owner and an invitation ceiling are not
// facts this client can establish. They stay absent, and the decision core
// decides without them. Nothing here permits a transfer on its own.

export function linkPolicyFacts({ transfer, byCode = false, proven = false, caps = null, now } = {}) {
  const remembered = Array.isArray(caps)
  return {
    direction: transfer && transfer.direction,
    status: transfer && transfer.status,
    byCode: byCode === true,
    // A pair-proof only means something while the record it proved still
    // exists. A forgotten record turns the link back into an unknown peer,
    // even if the proof arrived before the record was removed.
    proven: proven === true && remembered,
    relationship: remembered ? 'remembered' : 'unknown',
    caps: remembered ? caps : null,
    // The human act: typing the code, or remembering the device. This is not a
    // link proof by itself; lib/policy.js requires the matching identity before
    // it reaches the core as a legacy allow.
    consent: byCode === true || remembered,
    now,
  }
}
