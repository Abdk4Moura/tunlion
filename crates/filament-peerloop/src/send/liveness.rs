//! What `send` says, and how long it really waits, when its receiver goes away.
//!
//! The blind run found three untrue sentences here: "the other device
//! disconnected, waiting up to 120s" (the wait was the 45 s unannounced rejoin
//! window, and the sender gave up after ~15 s anyway, through the delivery-ack
//! fallback), a roster line that read as an empty name ("the other device
//! disconnected"), and a wait for a code receiver that could never return
//! because its code had burned. The sentences are built here, from the window
//! the sender actually enforces.

/// The line when the receiver disconnects mid-transfer. `who` is its name when
/// it has a real one; `by_code` is a send to a one-time code.
pub fn disconnect_line(who: Option<&str>, secs: u64, by_code: bool) -> String {
    let who = who
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| format!("'{n}'"))
        .unwrap_or_else(|| "the receiver".to_string());
    let mut line = format!("  {who} disconnected; waiting up to {secs}s for it to come back");
    if by_code {
        line.push_str(
            ". The code is used up, so `receive <code>` cannot rejoin: if it does not come back, \
             run the same `tunlion send` again for a new code",
        );
    }
    line
}

/// The error when the receiver did not come back within the window. Says
/// "unreachable" (exit 6 under the taxonomy) and the one way on that works.
pub fn receiver_gone_message(secs: u64, by_code: bool) -> String {
    let way_on = if by_code {
        "The code is used up: run the same `tunlion send` again for a new code. A receiver that \
         kept a partial and receives into the same folder continues from it"
    } else {
        "Run the same `tunlion send` again once it is back; it continues from any partial the \
         receiver kept"
    };
    format!("the receiver is unreachable: it disconnected and did not come back within {secs}s. {way_on}")
}

/// The error when the stall ladder runs out of attempts on the active link.
/// Pure. `down_secs` is how long the link has been down when a channel had
/// been up, None when none ever was.
///
/// Once a channel was up, the receiver went away mid-send, and the end says
/// so the way the link-down clock does: unreachable, with the way on for a
/// spent code. When a dead channel started counting as a stall (so the ladder
/// re-dials it), a frozen receiver used up the re-dials well inside the rejoin
/// window, and the send ended with "lost the receiving peer ... re-run the same
/// `tunlion send`", which for a code send is advice that cannot work: the code
/// is spent (gate 11). Before any channel came up, nothing was ever reached
/// and the attempt count is the honest account.
pub fn ladder_exhausted_message(down_secs: Option<u64>, attempts: u32, by_code: bool) -> String {
    match down_secs {
        Some(secs) => receiver_gone_message(secs, by_code),
        None => format!(
            "lost the receiving peer after {attempts} attempts; the partial is kept, re-run the same `tunlion send` to resume"
        ),
    }
}

/// How often a send that is waiting says so. `exec` uses the same 7 s.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(7);

/// The progress line for a send that is waiting on its peer, or None when
/// there is nothing to say. A peer frozen or killed mid-send used to mean a
/// minute of silence before the error. `heard_ms` is how long since the peer
/// last sent anything (None when the link does not track it). Pure.
pub fn still_waiting_line(
    peer: &str,
    established: bool,
    elapsed: std::time::Duration,
    heard_ms: Option<u64>,
    unfinished: bool,
) -> Option<String> {
    if !unfinished {
        return None;
    }
    if !established {
        return Some(format!("  still waiting for {peer} to connect ({}s)", elapsed.as_secs()));
    }
    match heard_ms? {
        h if h < HEARTBEAT.as_millis() as u64 => None,
        u64::MAX => Some(format!(
            "  still waiting for {peer}: the link is down, trying to reconnect ({}s)",
            elapsed.as_secs()
        )),
        h => Some(format!("  still waiting for {peer}: no answer for {}s", h / 1000)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiting_send_says_so_and_a_flowing_one_does_not() {
        let s = std::time::Duration::from_secs(21);
        let l = still_waiting_line("bravo", false, s, None, true).unwrap();
        assert!(l.contains("still waiting for bravo") && l.contains("21s"), "{l}");
        let l = still_waiting_line("bravo", true, s, Some(14_200), true).unwrap();
        assert!(l.contains("no answer for 14s"), "{l}");
        assert!(still_waiting_line("bravo", true, s, Some(800), true).is_none());
        assert!(still_waiting_line("bravo", true, s, Some(14_200), false).is_none());
        assert!(still_waiting_line("bravo", true, s, None, true).is_none());
    }

    /// The window printed is the window passed in (the one enforced), and an
    /// empty name is never printed as a name.
    #[test]
    fn the_disconnect_line_states_the_real_window_and_a_real_name() {
        let l = disconnect_line(Some(""), 25, false);
        assert!(l.starts_with("  the receiver disconnected; waiting up to 25s"), "{l}");
        assert!(!l.contains("120s") && !l.contains("  disconnected"), "{l}");
        let named = disconnect_line(Some("laptop"), 25, false);
        assert!(named.contains("'laptop' disconnected"), "{named}");
        let code = disconnect_line(None, 25, true);
        assert!(code.contains("code is used up") && code.contains("new code"), "{code}");
    }

    /// A send that had a channel says the receiver is unreachable and, for a
    /// spent code, that a new code is the way on; one that never connected
    /// keeps the attempt count.
    #[test]
    fn an_exhausted_ladder_after_a_link_says_unreachable() {
        let m = ladder_exhausted_message(Some(41), 5, true);
        assert!(m.contains("receiver is unreachable") && m.contains("within 41s"), "{m}");
        assert!(m.contains("new code") && !m.contains("lost the receiving peer"), "{m}");
        let n = ladder_exhausted_message(None, 5, true);
        assert!(n.starts_with("lost the receiving peer after 5 attempts"), "{n}");
    }

    #[test]
    fn giving_up_says_unreachable_and_the_way_on() {
        let m = receiver_gone_message(25, true);
        assert!(m.contains("unreachable") && m.contains("within 25s"), "{m}");
        assert!(m.contains("new code"), "{m}");
        assert!(!m.contains("partial state kept"), "{m}");
        let k = receiver_gone_message(25, false);
        assert!(!k.contains("code"), "{k}");
    }
}
