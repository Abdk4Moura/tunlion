// RESILIENCE layer — stall handling (keeping an OPEN-but-dark link alive).
//
// First seam of the resilience layer (consolidation-GOAL.md §4). Resilience OWNS
// the timers and the mutable episode/idle state — unlike PROTOCOL it is NOT pure
// overall — but the POLICY pieces that don't need a clock are split out here so
// they are directly node-testable. This module currently holds the ladder SHAPE;
// the detection reducer (idle/away/progress/accumulate/grace → correct) and the
// timer-owning StallController are the next slice (they need the freeze-shim
// browser gate / netns lab to verify under real fault, per §6).
//
// The ladder mirrors the Rust `correct_stall` rungs (cli/src/...): least
// disruptive first, bounded, then fail CLEAN (transfers paused/resumable, never
// silently dead).

// The correction rungs, least-disruptive first:
//   'a' liveness ping + (impolite, connected) restartIce — cheapest, in place
//   'b' re-offer/resume unfinished transfers so the data path re-flows
//   'c' escalate to the onStall hook (P1 relay-preferred rebuild)
export const STALL_LADDER = ['a', 'b', 'c']

// Given the rung of the CURRENT in-flight episode (undefined when none is open),
// return the rung to execute NOW. No episode → start at 'a'; 'a' → 'b'; 'b' →
// 'c'; 'c' (ladder spent) → 'fail'. Pure; the caller runs the rung's mechanics
// and latches the new episode.
export function nextStallRung(currentRung) {
  if (!currentRung) return STALL_LADDER[0]
  const i = STALL_LADDER.indexOf(currentRung)
  // Unknown/last rung → ladder exhausted.
  return i >= 0 && i + 1 < STALL_LADDER.length ? STALL_LADDER[i + 1] : 'fail'
}
