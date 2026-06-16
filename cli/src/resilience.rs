//! RESILIENCE — keeping a hostile link alive (the Rust mirror of the JS
//! `net/resilience` layer). This module holds the timer-free POLICY of the stall
//! correction ladder; `Conn::correct_stall` in `main.rs` owns the state + I/O
//! (the repair/escalate side effects) and calls in here to classify each tick.
//!
//! Discipline (consolidation-GOAL.md §3): if it has a timer/retry/reconnect it is
//! RESILIENCE — but the *decision* of which rung to take is pure, so it lives here
//! and is unit-tested directly. Mirrors `frontend/src/net/resilience/stall.js`
//! (`nextStallRung`) + `net/app/recovery.js` (`decideStallEscalation`).

/// Which correction action the stall ladder should take this tick. Pure
/// classification of `Conn::correct_stall`'s nested branches; the caller performs
/// the matching side effect and maps it to the public `Rung`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StallAction {
    /// attempt 0 + a warm relay standby is eligible → instant relay failover.
    WarmCutover,
    /// attempt 0 → re-offer unfinished transfers on the SAME transport (rung a).
    Resume,
    /// 0 < attempt < max → repair the transport IN PLACE (rung c).
    Repair,
    /// attempt >= max, relay permitted → re-establish over the TURN relay (rung d).
    RelayEscalate,
    /// attempt >= max but `--no-relay` → fail clean (partial kept).
    ExhaustedRelayForbidden,
    /// attempt >= max and already on relay → fail clean (no harder rung).
    ExhaustedAlreadyRelay,
}

/// Decide the stall-correction action for this attempt. Pure.
///
/// `attempt` is the 0-based count BEFORE this one (rung a is attempt 0). The
/// warm-cutover early-return guard (an episode already cut over) is handled by the
/// caller before this is reached.
///
///   attempt          0-based correction attempt for this episode
///   max_repairs      STALL_MAX_REPAIRS (the in-place-repair ceiling)
///   warm_eligible    a warm relay standby exists and may be used (long-lived
///                    session, relay permitted, not already on relay, not yet cut over)
///   relay_forbidden  the `--no-relay` hard direct-only promise
///   already_relayed  this link is ALREADY the relay (relay_only)
pub fn decide_stall_action(
    attempt: u32,
    max_repairs: u32,
    warm_eligible: bool,
    relay_forbidden: bool,
    already_relayed: bool,
) -> StallAction {
    if attempt == 0 {
        return if warm_eligible { StallAction::WarmCutover } else { StallAction::Resume };
    }
    if attempt >= max_repairs {
        if relay_forbidden {
            return StallAction::ExhaustedRelayForbidden;
        }
        if already_relayed {
            return StallAction::ExhaustedAlreadyRelay;
        }
        return StallAction::RelayEscalate;
    }
    StallAction::Repair
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAX: u32 = 5;

    #[test]
    fn attempt0_warm_eligible_cuts_over() {
        assert_eq!(decide_stall_action(0, MAX, true, false, false), StallAction::WarmCutover);
    }

    #[test]
    fn attempt0_not_warm_resumes() {
        assert_eq!(decide_stall_action(0, MAX, false, false, false), StallAction::Resume);
    }

    #[test]
    fn middle_attempts_repair_in_place() {
        for a in 1..MAX {
            assert_eq!(decide_stall_action(a, MAX, false, false, false), StallAction::Repair);
        }
    }

    #[test]
    fn exhausted_escalates_to_relay_when_permitted() {
        assert_eq!(decide_stall_action(MAX, MAX, false, false, false), StallAction::RelayEscalate);
        assert_eq!(decide_stall_action(MAX + 3, MAX, false, false, false), StallAction::RelayEscalate);
    }

    #[test]
    fn exhausted_with_no_relay_fails_clean() {
        assert_eq!(decide_stall_action(MAX, MAX, false, true, false), StallAction::ExhaustedRelayForbidden);
    }

    #[test]
    fn exhausted_already_on_relay_fails_clean() {
        assert_eq!(decide_stall_action(MAX, MAX, false, false, true), StallAction::ExhaustedAlreadyRelay);
    }

    #[test]
    fn no_relay_takes_priority_over_already_relayed_at_exhaustion() {
        // Mirrors correct_stall: the relay_forbidden branch is checked first.
        assert_eq!(decide_stall_action(MAX, MAX, false, true, true), StallAction::ExhaustedRelayForbidden);
    }

    #[test]
    fn warm_cutover_only_on_first_attempt() {
        // A warm-eligible link past attempt 0 repairs/escalates, never re-cuts-over.
        assert_eq!(decide_stall_action(1, MAX, true, false, false), StallAction::Repair);
        assert_eq!(decide_stall_action(MAX, MAX, true, false, false), StallAction::RelayEscalate);
    }
}
