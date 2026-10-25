// Interactive, steered, color-coded code entry, the CLI sibling of the
// browser's CodeInput / CustomCodeEntry. When `pair`/`recv`/`send` run WITHOUT
// a code (or with a malformed one) AND we're allowed to be interactive (see the
// gate in main.rs), we drop into a browser-like live entry:
//
//   * auto-inserts dashes (space -> '-'), refuses bad characters entirely,
//   * judges the code instantly with color (red / amber / green),
//   * steers the user (REPL-like: won't submit an incomplete code).
//
// DESIGN: the crossterm event loop is kept THIN. ALL formatting + judging lives
// in PURE functions (`format_buffer`, `judge`) so they're unit-testable with no
// TTY. The judging uses the SHARED `filament_pake` split/normalize functions and
// the crate's `password_word_tokens`, so the CLI's verdict matches the browser
// and the actual PAKE parse byte-for-byte.

use crate::ui;
use std::io::Write;

/// Which side of the ceremony we're judging for. CREATE = the user is minting a
/// code for someone else (pair creator / `send --code`); CLAIM = the user is
/// typing a code somebody read them (`pair <code>` / `recv <code>`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Create,
    Claim,
}

/// How "done" the current buffer is. Drives the color of the steer line and
/// whether Enter is allowed to submit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// nothing typed yet, dim hint
    Empty,
    /// content, but not a submittable code, amber, keep steering
    Incomplete,
    /// a complete, submittable code, green, Enter submits
    Ready,
}

/// The pure verdict for a buffer: a level (color), a one-line steer message, and
/// an optional preview of the resolved code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub level: Level,
    pub steer: String,
    pub preview: Option<String>,
}

/// Normalize a raw buffer the way the browser's CodeInput `format` does, but
/// toward the SPAKE2-normalized lower-case form (so what the user sees IS what
/// gets hashed). Pure + total:
///   * lowercase,
///   * map space (and any whitespace) -> '-',
///   * collapse runs of '-' to a single '-',
///   * strip leading '-',
///   * KEEP only [a-z0-9-]; everything else is dropped (bad chars never enter).
///
/// We intentionally do NOT strip a trailing '-' here, the user may be mid-type
/// between words, and a visible trailing dash is correct feedback. `judge`
/// tolerates it via the shared split.
pub fn format_buffer(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let mapped = if ch.is_whitespace() { '-' } else { ch.to_ascii_lowercase() };
        if mapped == '-' {
            // collapse runs; drop a leading dash entirely
            if prev_dash || out.is_empty() {
                continue;
            }
            out.push('-');
            prev_dash = true;
        } else if mapped.is_ascii_lowercase() || mapped.is_ascii_digit() {
            out.push(mapped);
            prev_dash = false;
        }
        // anything else (punctuation, symbols, non-ascii) is simply not inserted
    }
    out
}

/// Is `s` a 3-5 ASCII-digit nameplate (the minted-code suffix shape)?
fn is_nameplate(s: &str) -> bool {
    (3..=5).contains(&s.len()) && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Judge a buffer for the given mode. PURE, uses the shared pake split/normalize
/// and the crate strength floor, so it agrees with the browser and the real parse.
///
/// `auto_nameplate` is the stable machine-minted number shown (dimmed) in the
/// CREATE preview, mint it ONCE per session (like the browser's autoNpRef) and
/// pass it in, so the preview doesn't reshuffle on every keystroke.
pub fn judge(buf: &str, mode: Mode, auto_nameplate: &str) -> Judgment {
    let normalized = crate::pake::norm_code(buf);
    let trimmed = normalized.trim_matches('-');

    // An INVITATION pasted into a code reader. The buffer filter drops the
    // colons, so it arrives as `filament-invitev2...`. It is never a code,
    // and pressing Enter on it would mint or claim garbage: name the reader
    // that takes it instead.
    if pasted_invitation(trimmed) {
        return Judgment {
            level: Level::Incomplete,
            steer: INVITATION_IN_CODE_ENTRY.to_string(),
            preview: None,
        };
    }

    if trimmed.is_empty() {
        let steer = match mode {
            Mode::Claim => "type the code they read you, e.g. brave-otter-3141".to_string(),
            Mode::Create => "type two words, or press Enter for a generated pair".to_string(),
        };
        return Judgment { level: Level::Empty, steer, preview: None };
    }

    match mode {
        Mode::Claim => {
            // Claim side: the shared `split_code` peels the TRAILING dash-group as
            // the nameplate; everything before it is the password (words).
            let (np, pw) = crate::pake::split_code(trimmed);
            let has_words = !pw.is_empty();
            let np_ok = is_nameplate(&np);
            if np_ok && has_words {
                return Judgment {
                    level: Level::Ready,
                    steer: "✓ ready, press enter".to_string(),
                    preview: Some(format!("{pw} · {np}")),
                };
            }
            // A single trailing group, no words (split_code returns np=whole, pw
            // empty). Two shapes land here and need different nudges:
            //   * a bare NUMBER (e.g. "3141"): the words are what's missing.
            //   * a bare WORD (e.g. "brave"): split_code mistook the lone word for
            //     a nameplate, so "add the words before the number" reads wrong;
            //     nudge toward the full words-then-number shape instead.
            if !has_words {
                let bare_is_number = np.bytes().all(|b| b.is_ascii_digit());
                let steer = if bare_is_number {
                    "add the words before the number".to_string()
                } else {
                    "keep going, a full code is words then a 3-5 digit number".to_string()
                };
                return Judgment {
                    level: Level::Incomplete,
                    steer,
                    preview: None,
                };
            }
            // Words present but the trailing group isn't a 3-5 digit nameplate.
            Judgment {
                level: Level::Incomplete,
                steer: "keep going, a full code ends in a 3-5 digit number".to_string(),
                preview: None,
            }
        }
        Mode::Create => {
            // A whole code typed where words are chosen: someone was GIVEN a
            // code and is accepting it. The nameplate is always machine-minted,
            // so a creator never types one; minting `<their words>-<our number>`
            // from it (what this used to do) left both sides waiting on
            // different codes. Enter accepts it instead (Outcome::Claim).
            if let Some(code) = received_code_in_create(trimmed) {
                return Judgment {
                    level: Level::Ready,
                    steer: format!("\u{2713} that is a code you were given, press enter to accept {code}"),
                    preview: None,
                };
            }
            // Create side: keep ALL words as the password; the nameplate is always
            // machine-minted. `split_chosen_code` only strips a trailing 3-5 digit
            // group, so "gigantic-element" keeps both words.
            let (words, _np) = crate::pake::split_chosen_code(trimmed);
            if crate::password_word_tokens(&words) < 2 {
                return Judgment {
                    level: Level::Incomplete,
                    steer: "add another word, easier to say and harder to guess".to_string(),
                    preview: None,
                };
            }
            Judgment {
                level: Level::Ready,
                steer: format!("✓ {words}, press enter to create"),
                // the auto-nameplate rides along dimmed in the preview
                preview: Some(format!("{words}-{auto_nameplate}")),
            }
        }
    }
}

/// What the steer line says when an invitation lands in a code entry.
pub(crate) const INVITATION_IN_CODE_ENTRY: &str =
    "that is an invitation, not a code: press Esc, then run `tunlion join` and paste it there";

/// Does the (normalized) buffer hold a pasted invitation? Pure.
pub(crate) fn pasted_invitation(normalized: &str) -> bool {
    normalized.starts_with("filament-invite")
}

/// In a CREATE entry, a buffer that is a complete received code (two or more
/// words, then a 3-5 digit nameplate) is the code to accept, normalized. A
/// creator never types the number, so its presence is the signal. Pure.
pub(crate) fn received_code_in_create(normalized: &str) -> Option<String> {
    let trimmed = normalized.trim_matches('-');
    let (np, pw) = crate::pake::split_code(trimmed);
    if is_nameplate(&np) && crate::password_word_tokens(&pw) >= 2 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// The OUTCOME of one interactive entry session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user submitted a Ready buffer. For CREATE this is the words-only
    /// password (no nameplate); for CLAIM it's the normalized full code.
    Submitted(String),
    /// CREATE only: the user typed a complete code they were GIVEN. The caller
    /// accepts it (the join path) instead of minting a new one.
    Claim(String),
    /// The user pressed Enter on an EMPTY buffer (a deliberate "use the default",
    /// auto-mint for create, local-network for recv/send).
    Empty,
    /// Esc (or Ctrl-D on an empty buffer), the user backed out entirely.
    Cancelled,
    /// Ctrl-C. Raw mode turns it into a key, so no SIGINT arrives; the caller
    /// must still exit as an interrupt (130), as the shell would report it.
    Interrupted,
}

// --------------------------------------------------------------------------
// The thin crossterm event loop. Everything above is pure + tested; this part
// only wires keystrokes -> format_buffer/judge and paints.
// --------------------------------------------------------------------------

/// RAII guard: enables raw mode on construction and ALWAYS restores the terminal
/// on drop (success, cancel, error, OR panic). This is the one thing we must
/// never get wrong, a leaked raw mode wedges the user's shell.
pub struct RawGuard {
    active: bool,
    newline: bool,
}

impl RawGuard {
    pub fn enable() -> std::io::Result<RawGuard> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true, newline: true })
    }

    /// For screens that erase themselves and manage their own line endings (the
    /// picker): restore the terminal without adding a blank line, or every
    /// answered choice would leave a gap behind it.
    pub fn enable_inline() -> std::io::Result<RawGuard> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true, newline: false })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            // Best-effort restore; never panic in drop.
            let _ = crossterm::terminal::disable_raw_mode();
            // Move to a fresh line and show the cursor so the prompt that follows
            // starts clean.
            let mut err = std::io::stderr();
            let _ = crossterm::execute!(err, crossterm::cursor::Show);
            if self.newline {
                let _ = write!(err, "\r\n");
            }
            let _ = err.flush();
        }
    }
}

/// The color for a level, from the design palette (nothing when color is off).
fn level_color(level: Level) -> String {
    ui::tone_code(match level {
        Level::Empty => ui::Tone::Dim,
        Level::Incomplete => ui::Tone::Warn,
        Level::Ready => ui::Tone::Ok,
    })
}

/// Render the entry on a SINGLE line, redrawn in place. We deliberately avoid
/// save/restore-cursor (`\x1b[s`/`\x1b[u`) and newlines: some shells ignore SCO
/// save/restore, which made the entry walk down a line per keystroke on those
/// terminals. A single line cleared with CR + erase-line (`\r\x1b[2K`) redraws
/// consistently on every terminal.
fn render(prompt: &str, buf: &str, j: &Judgment) {
    let mut err = std::io::stderr();
    let reset = ui::tone_reset();
    let color = level_color(j.level);
    let preview = match &j.preview {
        Some(p) => format!("  {}", ui::paint(ui::Tone::Dim, p)),
        None => String::new(),
    };
    // Clear the whole line, then draw: prompt+buffer, a gap, the colored steer
    // plus optional dim preview.
    let _ = write!(err, "\r\x1b[2K{prompt}{buf}   {color}{}{reset}{preview}", j.steer);
    // Put the caret back right after the typed buffer (browser-like), so typing
    // continues at the end of the code rather than after the steer text.
    let col = prompt.chars().count() + buf.chars().count();
    let _ = write!(err, "\r");
    if col > 0 {
        let _ = write!(err, "\x1b[{col}C");
    }
    let _ = err.flush();
}

/// Which slice of a list a picker shows, and how much is out of sight.
///
/// Split out because it is the only arithmetic in the renderer and it is the
/// part that can be wrong in a way nobody notices: an off-by-one here either
/// hides a row or reports a count that does not match what is drawn, and the
/// redraw then rewinds the wrong number of lines and eats the scrollback.
///
/// Returns `(first, view, above, below)`.
fn viewport_window(sel: usize, len: usize, max: usize) -> (usize, usize, usize, usize) {
    let view = max.min(len);
    if view == 0 {
        return (0, 0, 0, 0);
    }
    // Keep the selection inside the window, scrolling only as far as needed.
    let first = sel.saturating_sub(view - 1).min(len - view);
    (first, view, first, len - first - view)
}

/// How many list rows a picker shows at once before it starts scrolling.
const VIEWPORT: usize = 7;

// --------------------------------------------------------------------------
// The one picker. Every interactive choice in the CLI draws through here, so a
// flow never changes look halfway (the access screens used to have their own
// `>` picker with different keys and hints next to this one's `❯`).
//
// Fluid, not stacked: while open, the list redraws in place. Once answered, the
// list is ERASED and, by default, one dim summary line stays (`✓ Temporary
// access`), so a session reads as a short trail of decisions instead of a wall of
// stale menus. Number keys answer immediately; arrows + Enter still work.
// --------------------------------------------------------------------------

/// What remains on screen after a picker is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collapse {
    /// Erase the list, leave `✓ <chosen item>`. The default for one-shot choices.
    Summary,
    /// Erase the list and leave nothing. For menus a flow revisits in a loop
    /// (a composer's main screen), where a trail of summaries would pile up.
    Erase,
}

/// Options for one picker session. `Default` is a plain one-shot choice.
#[derive(Clone, Copy, Default)]
pub struct PickOpts<'a> {
    /// Extra single-key answers shown on the hint line, e.g. `('r', "refresh")`.
    pub hints: &'a [(char, &'a str)],
    /// `None` means Summary.
    pub collapse: Option<Collapse>,
    /// When set, the picker also returns `Cancelled` as soon as this flips, so a
    /// live screen (running access) can be torn down by the session ending.
    pub stop: Option<&'a std::sync::atomic::AtomicBool>,
    /// Which row starts selected (clamped), e.g. the finish row of a composer
    /// once something is chosen, so Enter alone completes the common path.
    pub initial: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Picked {
    Item(usize),
    Key(char),
    Cancelled,
}

/// The digit that answers item `i` directly, when the list is short enough for
/// one keystroke per item and the digit is not already a hint key. Pure.
pub(crate) fn digit_for(i: usize, len: usize, hints: &[(char, &str)]) -> Option<char> {
    if len > 9 || i >= len {
        return None;
    }
    let d = char::from(b'1' + i as u8);
    (!hints.iter().any(|(h, _)| *h == d)).then_some(d)
}

/// The hint line under a list, as plain text. Pure, so tests pin the wording.
pub(crate) fn hint_line(len: usize, hints: &[(char, &str)]) -> String {
    let mut line = String::from("\u{2191}\u{2193} move \u{b7} \u{23ce} choose");
    if digit_for(0, len, hints).is_some() {
        let last = len.min(9);
        line.push_str(&if last == 1 { " \u{b7} 1 picks".to_string() } else { format!(" \u{b7} 1-{last} pick") });
    }
    for (k, label) in hints {
        line.push_str(&format!(" \u{b7} {k} {label}"));
    }
    line.push_str(" \u{b7} esc back");
    line
}

/// Clip a label to the terminal width so a long path never wraps: a wrapped row
/// makes the in-place redraw rewind the wrong number of lines.
fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if width < 8 || n <= width {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('\u{2026}');
    out
}

fn term_width() -> usize {
    crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(80)
}

/// Draw the list once. Returns how many lines it drew, so the caller can rewind
/// exactly that many (never a recomputed guess).
fn render_picker(header: &str, items: &[String], sel: usize, prev: usize, hints: &[(char, &str)]) -> usize {
    let mut err = std::io::stderr();
    let width = term_width().saturating_sub(4);
    let (first, view, above, below) = viewport_window(sel, items.len(), VIEWPORT);
    if prev > 0 {
        let _ = write!(err, "\x1b[{prev}A");
    }
    let mut drawn = 0;
    if !header.is_empty() {
        let _ = write!(err, "\r\x1b[2K{}\r\n", ui::header(ui::Tone::Brand, ui::Tone::Bold, header));
        drawn += 1;
    }
    let dim = ui::tone_code(ui::Tone::Dim);
    let reset = ui::tone_reset();
    if above > 0 {
        let _ = write!(err, "\r\x1b[2K  {dim}\u{2191} {above} more{reset}\r\n");
        drawn += 1;
    }
    for (i, it) in items.iter().enumerate().skip(first).take(view) {
        let digit = digit_for(i, items.len(), hints)
            .map(|d| format!("{dim}{d}{reset} "))
            .unwrap_or_default();
        let text = fit(it, width.saturating_sub(4));
        if i == sel {
            let c = ui::tone_code(ui::Tone::Brand);
            let r = ui::tone_reset();
            let _ = write!(err, "\r\x1b[2K  {c}\u{276f}{r} {digit}{c}{text}{r}\r\n");
        } else {
            let _ = write!(err, "\r\x1b[2K    {digit}{text}\r\n");
        }
        drawn += 1;
    }
    if below > 0 {
        let _ = write!(err, "\r\x1b[2K  {dim}\u{2193} {below} more{reset}\r\n");
        drawn += 1;
    }
    let _ = write!(err, "\r\x1b[2K  {dim}{}{reset}\r\n", fit(&hint_line(items.len(), hints), width));
    drawn += 1;
    let _ = err.flush();
    drawn
}

/// Erase what a picker drew (cursor is parked just below it) and leave the
/// cursor at the top of that space.
fn erase_drawn(drawn: usize) {
    let mut err = std::io::stderr();
    if drawn > 0 {
        let _ = write!(err, "\x1b[{drawn}A");
    }
    let _ = write!(err, "\r\x1b[J");
    let _ = err.flush();
}

/// The one-line record of an answered choice. Pure.
pub(crate) fn summary_line(item: &str) -> String {
    format!("\u{2713} {item}")
}

/// Interactive picker: arrows (or k/j) move, Enter or a number chooses, Esc/q/
/// Ctrl-C go back. Returns the chosen index, or None on cancel. The terminal is
/// ALWAYS restored.
pub fn pick(header: &str, items: &[String]) -> std::io::Result<Option<usize>> {
    match pick_opts(header, items, PickOpts::default())? {
        Picked::Item(i) => Ok(Some(i)),
        Picked::Key(_) | Picked::Cancelled => Ok(None),
    }
}

pub fn pick_with_keys(header: &str, items: &[String], hints: &[(char, &str)]) -> std::io::Result<Picked> {
    pick_opts(header, items, PickOpts { hints, ..PickOpts::default() })
}

pub fn pick_opts(header: &str, items: &[String], opts: PickOpts<'_>) -> std::io::Result<Picked> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use std::sync::atomic::Ordering;
    if items.is_empty() {
        return Ok(Picked::Cancelled);
    }
    let stopped = || opts.stop.is_some_and(|s| s.load(Ordering::Acquire));
    let _guard = RawGuard::enable_inline()?;
    let mut sel = opts.initial.min(items.len() - 1);
    let mut drawn = 0usize;
    let outcome = loop {
        if stopped() {
            break Picked::Cancelled;
        }
        drawn = render_picker(header, items, sel, drawn, opts.hints);
        if opts.stop.is_some() {
            // Wake periodically so a flipped stop flag tears the screen down
            // without waiting for a key.
            let mut ready = false;
            while !ready {
                if stopped() {
                    break;
                }
                ready = event::poll(std::time::Duration::from_millis(100))?;
            }
            if !ready {
                break Picked::Cancelled;
            }
        }
        let Event::Key(k) = event::read()? else { continue };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        match k.code {
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break Picked::Cancelled,
            KeyCode::Char('\u{3}') => break Picked::Cancelled,
            KeyCode::Up | KeyCode::Char('k') => sel = if sel == 0 { items.len() - 1 } else { sel - 1 },
            KeyCode::Down | KeyCode::Char('j') => sel = (sel + 1) % items.len(),
            KeyCode::Home => sel = 0,
            KeyCode::End => sel = items.len() - 1,
            KeyCode::Enter => break Picked::Item(sel),
            KeyCode::Esc | KeyCode::Char('q') => break Picked::Cancelled,
            KeyCode::Char(c) if k.modifiers.is_empty() && opts.hints.iter().any(|(h, _)| *h == c) => {
                break Picked::Key(c)
            }
            KeyCode::Char(c) if k.modifiers.is_empty() || k.modifiers == KeyModifiers::SHIFT => {
                if let Some(i) = (0..items.len()).find(|&i| digit_for(i, items.len(), opts.hints) == Some(c)) {
                    sel = i;
                    break Picked::Item(i);
                }
            }
            _ => {}
        }
    };
    erase_drawn(drawn);
    if let (Picked::Item(i), Collapse::Summary) = (&outcome, opts.collapse.unwrap_or(Collapse::Summary)) {
        let mut err = std::io::stderr();
        let width = term_width().saturating_sub(4);
        let _ = write!(err, "\r\x1b[2K  {}\r\n", ui::paint(ui::Tone::Dim, &fit(&summary_line(&items[*i]), width)));
        let _ = err.flush();
    }
    Ok(outcome)
}

pub fn run(prompt: &str, mode: Mode, prefill: &str, auto_nameplate: &str) -> std::io::Result<Outcome> {
    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    let _guard = RawGuard::enable()?;

    let mut buf = format_buffer(prefill);
    // Initial paint.
    {
        let j = judge(&buf, mode, auto_nameplate);
        render(prompt, &buf, &j);
    }

    loop {
        let ev = event::read()?;
        let Event::Key(KeyEvent { code, modifiers, kind, .. }) = ev else { continue };
        // Only react to presses (Windows sends Release/Repeat too).
        if kind == KeyEventKind::Release {
            continue;
        }
        match code {
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(Outcome::Interrupted);
            }
            KeyCode::Char('\u{3}') => {
                // #203: the lone 0x03 byte in raw mode.
                return Ok(Outcome::Interrupted);
            }
            KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl-D on empty = cancel (EOF-like); otherwise ignore.
                if buf.is_empty() {
                    return Ok(Outcome::Cancelled);
                }
            }
            KeyCode::Esc => return Ok(Outcome::Cancelled),
            KeyCode::Enter => {
                let j = judge(&buf, mode, auto_nameplate);
                match j.level {
                    Level::Ready => {
                        if mode == Mode::Create {
                            if let Some(code) =
                                received_code_in_create(&crate::pake::norm_code(&buf))
                            {
                                return Ok(Outcome::Claim(code));
                            }
                        }
                        let result = match mode {
                            // CREATE submits the words-only password (no nameplate);
                            // the caller mints the nameplate.
                            Mode::Create => {
                                let (words, _np) = crate::pake::split_chosen_code(
                                    &crate::pake::norm_code(&buf),
                                );
                                words
                            }
                            // CLAIM submits the normalized full code.
                            Mode::Claim => crate::pake::norm_code(&buf),
                        };
                        return Ok(Outcome::Submitted(result));
                    }
                    Level::Empty => return Ok(Outcome::Empty),
                    // Incomplete: refuse to submit, keep steering (REPL-like).
                    Level::Incomplete => { /* fall through, redraw */ }
                }
            }
            KeyCode::Backspace => {
                buf.pop();
                buf = format_buffer(&buf);
            }
            KeyCode::Char(c) => {
                // Run the new char through the filter by appending then
                // re-formatting; bad chars are simply not inserted.
                let mut candidate = buf.clone();
                candidate.push(c);
                buf = format_buffer(&candidate);
            }
            _ => {}
        }
        let j = judge(&buf, mode, auto_nameplate);
        render(prompt, &buf, &j);
    }
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_lowercases_and_keeps_valid() {
        assert_eq!(format_buffer("Brave-Otter-3141"), "brave-otter-3141");
        assert_eq!(format_buffer("ABC123"), "abc123");
    }

    #[test]
    fn format_maps_space_to_dash() {
        assert_eq!(format_buffer("gigantic element"), "gigantic-element");
        assert_eq!(format_buffer("brave otter ruby"), "brave-otter-ruby");
    }

    #[test]
    fn format_collapses_dashes_and_strips_leading() {
        assert_eq!(format_buffer("brave---otter"), "brave-otter");
        assert_eq!(format_buffer("---brave"), "brave");
        assert_eq!(format_buffer("  leading"), "leading");
        // multiple spaces collapse too
        assert_eq!(format_buffer("a   b"), "a-b");
    }

    #[test]
    fn format_rejects_bad_chars_entirely() {
        // '!', '@', '/', emoji etc. never enter the buffer.
        assert_eq!(format_buffer("brave!otter"), "braveotter");
        assert_eq!(format_buffer("a@b/c"), "abc");
        assert_eq!(format_buffer("café"), "caf"); // non-ascii 'é' dropped
        assert_eq!(format_buffer("UP!!!"), "up");
    }

    #[test]
    fn format_keeps_trailing_dash_midtype() {
        // mid-type between words, trailing dash is honest feedback
        assert_eq!(format_buffer("brave-"), "brave-");
    }

    const NP: &str = "1234";

    // ---- CLAIM judgments ----

    #[test]
    fn claim_empty_is_dim_hint() {
        let j = judge("", Mode::Claim, NP);
        assert_eq!(j.level, Level::Empty);
        assert!(j.steer.contains("brave-otter-3141"));
        assert_eq!(j.preview, None);
    }

    #[test]
    fn claim_words_without_nameplate_is_amber() {
        let j = judge("brave-otter", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("3-5 digit"));
    }

    #[test]
    fn claim_bare_number_steers_to_add_words() {
        let j = judge("3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("add the words"));
    }

    #[test]
    fn claim_lone_word_nudges_to_full_shape() {
        // A single bare word (no number): split_code treats the lone group as the
        // nameplate, so the old "add the words before the number" read wrong.
        // It should now nudge toward the full words-then-number shape.
        let j = judge("brave", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("words then a 3-5 digit number"));
        assert!(!j.steer.contains("add the words before the number"));
    }

    #[test]
    fn claim_full_code_is_ready_with_preview() {
        let j = judge("brave-otter-3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
        assert!(j.steer.contains("ready"));
        assert_eq!(j.preview.as_deref(), Some("brave-otter · 3141"));
    }

    #[test]
    fn claim_three_word_code_is_ready() {
        let j = judge("brave-otter-ruby-314", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
        assert_eq!(j.preview.as_deref(), Some("brave-otter-ruby · 314"));
    }

    #[test]
    fn claim_short_trailing_group_not_nameplate() {
        // a 2-digit trailing group is NOT a 3-5 digit nameplate
        let j = judge("brave-otter-31", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
    }

    #[test]
    fn claim_tolerates_messy_input() {
        // upper case + spaces + bad chars all normalize
        let j = judge("BRAVE  OTTER!! 3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
    }

    // ---- CREATE judgments ----

    #[test]
    fn create_empty_is_dim_hint() {
        let j = judge("", Mode::Create, NP);
        assert_eq!(j.level, Level::Empty);
    }

    #[test]
    fn create_single_word_is_amber() {
        let j = judge("gigantic", Mode::Create, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("add another word"));
    }

    #[test]
    fn create_two_words_is_ready_with_auto_nameplate() {
        let j = judge("gigantic-element", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
        assert!(j.steer.contains("gigantic-element"));
        assert_eq!(j.preview.as_deref(), Some("gigantic-element-1234"));
    }

    #[test]
    fn create_treats_a_typed_full_code_as_one_to_accept() {
        // Eval item 1: "Pair with a code I was given" opened this entry, the
        // person typed the code they were given, and it minted
        // `comic-otter-<our number>` from it, so both sides waited on
        // different codes. A creator never types the number (it is always
        // machine-minted), so a full code here is a code to ACCEPT. This
        // replaces the old assertion that the number was silently stripped,
        // which pinned exactly that bug.
        let j = judge("comic-otter-1950", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
        assert!(j.steer.contains("code you were given"), "{}", j.steer);
        assert!(j.steer.contains("comic-otter-1950"), "{}", j.steer);
        assert_eq!(j.preview, None, "must not preview a freshly minted code");
        assert_eq!(
            received_code_in_create(&crate::pake::norm_code("Comic Otter 1950")).as_deref(),
            Some("comic-otter-1950")
        );
        // Choosing words is unchanged.
        assert_eq!(received_code_in_create("gigantic-element"), None);
    }

    #[test]
    fn an_invitation_in_a_code_entry_names_join() {
        let pasted = format_buffer("filament-invite:v2:AbCdEf0123");
        for mode in [Mode::Create, Mode::Claim] {
            let j = judge(&pasted, mode, NP);
            assert_eq!(j.level, Level::Incomplete, "{mode:?}");
            assert!(j.steer.contains("tunlion join"), "{}", j.steer);
        }
    }

    #[test]
    fn create_space_separated_words_ready() {
        let j = judge("brave otter", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
    }

    #[test]
    fn create_single_word_plus_number_still_amber() {
        // "cat-12345" -> split_chosen strips 12345, leaves "cat" = 1 token
        let j = judge("cat-12345", Mode::Create, NP);
        assert_eq!(j.level, Level::Incomplete);
    }
}

#[cfg(test)]
mod viewport_tests {
    use super::viewport_window;

    #[test]
    fn a_short_list_shows_everything_and_claims_nothing_hidden() {
        let (first, view, above, below) = viewport_window(0, 3, 7);
        assert_eq!((first, view, above, below), (0, 3, 0, 0));
    }

    #[test]
    fn a_long_list_admits_what_is_below_before_you_scroll() {
        // 20 items, window of 7, sitting at the top: 13 are out of sight and the
        // picker must say so. Silently truncating is the failure this prevents.
        let (first, view, above, below) = viewport_window(0, 20, 7);
        assert_eq!((first, view, above, below), (0, 7, 0, 13));
    }

    #[test]
    fn the_window_follows_the_selection_and_the_counts_stay_consistent() {
        for sel in 0..20 {
            let (first, view, above, below) = viewport_window(sel, 20, 7);
            assert!(sel >= first && sel < first + view, "selection {sel} must be visible");
            assert_eq!(above + view + below, 20, "counts must account for every row");
        }
    }

    #[test]
    fn the_end_of_the_list_pins_the_window_rather_than_running_past_it() {
        let (first, view, above, below) = viewport_window(19, 20, 7);
        assert_eq!((first, view, above, below), (13, 7, 13, 0));
    }

    #[test]
    fn an_empty_list_is_not_a_panic() {
        assert_eq!(viewport_window(0, 0, 7), (0, 0, 0, 0));
    }
}
