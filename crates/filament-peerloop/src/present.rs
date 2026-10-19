//! PRESENTATION INTERFACE: the terminal state the loop drives, without a terminal.
//!
//! [`LogSink`](crate::host::LogSink) carries LINES. This trait carries the other
//! half of what the receive loop does to a live screen: it keeps a sticky status
//! line, fronts a waiting question in it, draws transfer bars, puts a value on
//! the OS clipboard and echoes a keystroke read in raw mode. None of those is a
//! message and none is a host FACT, so they get their own seam instead of being
//! smeared into the two traits next door.
//!
//! Why not more `LogSink` methods: a daemon journal or a library build can carry
//! every line the loop says while having no screen at all, and the loop must
//! still run. [`NoScreen`] is that implementation: it renders nothing, and a
//! transfer still transfers.
//!
//! The one method whose inert form needs a decision is
//! [`Presentation::sticky_ask`]. A question that needs an answer must not vanish
//! because no screen exists to front it, so it returns [`Ask`] and the caller has
//! to deal with [`Ask::Unshown`]: the question is still open, put it on the log
//! sink. A `()` here would silently swallow the one thing the person has to see.

/// What happened to a question handed to the front of the screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ask {
    /// A live screen is showing it in the sticky area.
    Fronted,
    /// There is no screen to front it at. The question is still OPEN and still
    /// needs an answer, so the caller must make sure it reaches a person: the
    /// [`LogSink`](crate::host::LogSink) is the one channel a screen-less loop
    /// has.
    Unshown,
}

/// A transfer bar, created by [`Presentation::progress`].
///
/// The two verbs are exactly the two the receive loop uses: advance to the
/// bytes received so far, and land the final summary once the bytes are stored.
/// A live bar rate-limits its own redraws; [`NoBar`] draws nothing at all.
///
/// `Sync` matters because a receive loop owns the bar behind an `Arc` inside
/// `IncomingFile`; a spawned dispatch future must be `Send`, and holding
/// `&IncomingFile` across an await requires the bar to be `Sync`.
pub trait Progress: Send + Sync {
    /// Advance the bar to `bytes` received.
    fn tick(&mut self, bytes: u64);
    /// The transfer finished having stored `bytes`; print the summary once.
    fn done(&self, bytes: u64);
}

/// The terminal state the peer loop drives. One owned object per session, like
/// [`LogSink`](crate::host::LogSink) and [`HostServices`](crate::host::HostServices),
/// so a test can capture it, a daemon can journal it and a library consumer can
/// install [`NoScreen`].
pub trait Presentation: Send + Sync + 'static {
    /// Drop the sticky status line, if one is up.
    fn clear_sticky(&self);
    /// Put `question` at the front of the sticky area, marked as waiting on the
    /// person. Returns whether a screen actually fronts it; see [`Ask`].
    #[must_use = "an unfronted question still needs to reach a person: handle Ask::Unshown"]
    fn sticky_ask(&self, question: &str) -> Ask;
    /// A bar for a transfer of `total` bytes under `label`.
    fn progress(&self, label: &str, total: u64) -> Box<dyn Progress>;
    /// Offer `text` to the OS clipboard (OSC 52 on a terminal).
    fn clipboard(&self, text: &str);
    /// Echo a keystroke the loop consumed, since raw mode does not.
    fn answer_echo(&self, ch: char);
}

/// A [`Presentation`] with no screen: every terminal side effect is inert.
///
/// This is the host-free default for a library consumer and the base for a test
/// that only cares about one method. It is honest rather than silent about the
/// one thing a person must still see: [`sticky_ask`](Presentation::sticky_ask)
/// reports [`Ask::Unshown`], so the caller puts the question on its log sink
/// instead of the ask path waiting on a screen that will never appear.
#[derive(Clone, Copy, Default)]
pub struct NoScreen;

impl Presentation for NoScreen {
    fn clear_sticky(&self) {}
    fn sticky_ask(&self, _question: &str) -> Ask {
        Ask::Unshown
    }
    fn progress(&self, _label: &str, _total: u64) -> Box<dyn Progress> {
        Box::new(NoBar)
    }
    fn clipboard(&self, _text: &str) {}
    fn answer_echo(&self, _ch: char) {}
}

/// The inert [`Progress`]: no bar, no summary line, no bell. The transfer itself
/// is unaffected, it simply has nothing to draw.
#[derive(Clone, Copy, Default)]
pub struct NoBar;

impl Progress for NoBar {
    fn tick(&mut self, _bytes: u64) {}
    fn done(&self, _bytes: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen-less host must not let a waiting question disappear: it says so,
    /// and the caller still owns the ask.
    #[test]
    fn no_screen_reports_a_question_as_unshown() {
        assert_eq!(NoScreen.sticky_ask("keep this file?"), Ask::Unshown);
    }

    /// The inert bar accepts every call the receive path makes and draws nothing.
    #[test]
    fn no_bar_accepts_tick_and_done() {
        let mut bar = NoScreen.progress("(stdout)", 10);
        bar.tick(4);
        bar.tick(10);
        bar.done(10);
    }
}
