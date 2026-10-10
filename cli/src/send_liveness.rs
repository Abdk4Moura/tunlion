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
pub(crate) fn disconnect_line(who: Option<&str>, secs: u64, by_code: bool) -> String {
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
pub(crate) fn receiver_gone_message(secs: u64, by_code: bool) -> String {
    let way_on = if by_code {
        "The code is used up: run the same `tunlion send` again for a new code. A receiver that \
         kept a partial and receives into the same folder continues from it"
    } else {
        "Run the same `tunlion send` again once it is back; it continues from any partial the \
         receiver kept"
    };
    format!("the receiver is unreachable: it disconnected and did not come back within {secs}s. {way_on}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
