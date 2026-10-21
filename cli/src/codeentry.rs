// Interactive, steered, color-coded code entry, the CLI sibling of the
// browser's CodeInput / CustomCodeEntry. When `pair`/`recv`/`send` run WITHOUT
// a code (or with a malformed one) AND we're allowed to be interactive (see the
// gate in main.rs), we drop into a browser-like live entry:
//
//   * maps spaces/disallowed characters to collapsed dash separators,
//   * judges the code instantly with color (red / amber / green),
//   * steers the user (REPL-like: won't submit an incomplete code).
//
// DESIGN: the crossterm event loop is kept THIN. ALL formatting + judging lives
// in PURE functions (`format_buffer`, `judge`) so they're unit-testable with no
// TTY. The judging uses the SHARED `filament_pake` split/normalize functions and
// the crate's `password_word_tokens`, so the CLI's verdict matches the browser
// and the actual PAKE parse byte-for-byte.

use crate::ui;
use std::io::{IsTerminal, Write};

// Matches filament_pair::norm_code. Never preview/submit a silently truncated
// buffer; creator words must also leave room for the machine-minted suffix.
const CODE_LIMIT: usize = 48;

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
///   * map whitespace and every disallowed character -> '-',
///   * collapse runs of '-' to a single '-',
///   * strip leading '-',
///   * KEEP only [a-z0-9-], without joining words across discarded punctuation.
///
/// We intentionally do NOT strip a trailing '-' here, the user may be mid-type
/// between words, and a visible trailing dash is correct feedback. `judge`
/// tolerates it via the shared split.
pub fn format_buffer(raw: &str) -> String {
    crate::join_input::PairingCode::format_partial(raw)
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
    if crate::join_input::invitation_material(buf) {
        return Judgment { level: Level::Incomplete, steer: INVITATION_IN_CODE_ENTRY.to_string(), preview: None };
    }
    let canonical = crate::join_input::PairingCode::normalize(buf);
    if canonical.len() > CODE_LIMIT {
        return Judgment { level: Level::Incomplete,
            steer: "Code limit: 48 characters; shorten it first.".to_string(), preview: None };
    }
    let normalized = crate::pake::norm_code(&canonical);
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
            if words.len() + 1 + auto_nameplate.len() > CODE_LIMIT {
                return Judgment { level: Level::Incomplete,
                    steer: "Shorten the words to leave room for the number.".to_string(), preview: None };
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
    normalized.starts_with("filament-invite") || normalized.starts_with("tlninv-")
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
    rows_below: u16,
    inline: bool,
    cursor_controls: bool,
}

impl RawGuard {
    pub fn enable() -> std::io::Result<RawGuard> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true, rows_below: 0, inline: false, cursor_controls: true })
    }

    fn enable_inline() -> std::io::Result<RawGuard> {
        let mut guard = Self::enable()?;
        if !ui::caps().live {
            guard.cursor_controls = false;
            return Ok(guard);
        }
        guard.inline = true;
        let mut err = std::io::stderr();
        crossterm::execute!(err, crossterm::event::EnableBracketedPaste,
                           crossterm::cursor::SetCursorStyle::SteadyBar)?;
        // OSC 12/112 set/reset the terminal caret color. Unsupported terminals
        // ignore them. NO_COLOR and the CLI color setting must still win.
        if ui::caps().color {
            write!(err, "\x1b]12;#e6b450\x1b\\")?;
            err.flush()?;
        }
        Ok(guard)
    }

    /// Raw mode without any terminal-control output. A `TERM=dumb` fallback
    /// still needs echo suppressed before a secret is read, but it must never
    /// emit cursor show/hide or alternate-screen noise. When stdin is not a
    /// terminal there is no kernel echo to suppress, so this is a no-op guard.
    pub(crate) fn enable_hidden() -> std::io::Result<RawGuard> {
        let active = std::io::stdin().is_terminal();
        if active {
            crossterm::terminal::enable_raw_mode()?;
        }
        Ok(RawGuard { active, rows_below: 0, inline: false, cursor_controls: false })
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
            if self.inline {
                let _ = crossterm::execute!(err, crossterm::terminal::EndSynchronizedUpdate,
                                           crossterm::event::DisableBracketedPaste,
                                           crossterm::cursor::SetCursorStyle::DefaultUserShape);
                if ui::caps().color {
                    let _ = write!(err, "\x1b]112\x1b\\");
                }
            }
            if self.cursor_controls {
                let _ = crossterm::execute!(err, crossterm::cursor::Show);
            }
            if self.rows_below > 0 {
                let _ = crossterm::execute!(err, crossterm::cursor::MoveDown(self.rows_below));
            }
            let _ = write!(err, "\r\n");
            let _ = err.flush();
        }
    }
}

/// Three reserved inline rows, never an alternate screen. Each row leaves the
/// last terminal cell empty so automatic wrapping cannot move our anchor.
fn cell_width(character: char) -> usize {
    // Conservative for arbitrary device labels: non-ASCII may occupy two cells.
    if character.is_ascii() || character == '✓' || character == '·' { 1 } else { 2 }
}

fn clipped(text: &str, width: usize) -> String {
    let mut cells = 0;
    text.chars().filter(|c| !c.is_control()).take_while(|c| {
        cells += cell_width(*c);
        cells <= width
    }).collect()
}

fn cells(text: &str) -> usize {
    text.chars().map(cell_width).sum()
}

fn cells_before(text: &str, characters: usize) -> usize {
    text.chars().take(characters).map(cell_width).sum()
}

fn entry_window(buf: &str, cursor: usize, width: usize) -> (&str, usize) {
    let start = cursor.saturating_sub(width.saturating_sub(1));
    let end = (start + width).min(buf.len());
    (&buf[start..end], cursor - start)
}

/// Character-indexed window for the inline field. The code entry buffer is
/// ASCII, but a file path may be Unicode; slicing it by byte would panic and a
/// window measured in bytes could hide the caret. Display text passed here is
/// already escaped to printable ASCII by `join_entry`, so chars are cells.
fn field_window(text: &str, caret: usize, width: usize) -> (String, usize) {
    let characters: Vec<char> = text.chars().collect();
    let caret = caret.min(characters.len());
    let start = caret.saturating_sub(width.saturating_sub(1));
    let end = (start + width).min(characters.len());
    (characters[start..end].iter().collect(), caret - start)
}

fn entry_hint(j: &Judgment, mode: Mode, width: usize) -> String {
    match j.level {
        Level::Empty if width < 60 => match mode {
            Mode::Create => "Enter generates · Esc cancels".to_string(),
            Mode::Claim => "Type words-number · Esc cancels".to_string(),
        },
        Level::Ready => match (&j.preview, mode) {
            (Some(code), Mode::Create) => format!("Enter creates {code}"),
            _ => "Enter accepts this code · Esc cancels".to_string(),
        },
        _ => j.steer.clone(),
    }
}

fn entry_judgment(buf: &str, mode: Mode, nameplate: &str, error: Option<&str>) -> Judgment {
    match error {
        Some(message) => Judgment { level: Level::Incomplete, steer: message.to_string(), preview: None },
        None => judge(buf, mode, nameplate),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryFrame {
    rows: [String; 3],
    caret: usize,
}

impl EntryFrame {
    fn new(prompt: &str, buf: &str, cursor: usize, j: &Judgment, mode: Mode, width: usize) -> Self {
        let (visible, caret) = entry_window(buf, cursor, width.saturating_sub(2).max(1));
        Self::from_parts(prompt, visible, caret, &entry_hint(j, mode, width), width)
    }

    /// Build a frame from an already-displayed field row. `caret` counts
    /// CHARACTERS, not bytes, so a Unicode (escaped) path cannot split or
    /// misplace the native caret.
    fn from_parts(prompt: &str, visible: &str, caret: usize, hint: &str, width: usize) -> Self {
        Self {
            rows: [clipped(prompt.trim_end(), width), clipped(&format!("  {visible}"), width),
                   clipped(&format!("  {hint}"), width)],
            caret: (2 + cells_before(visible, caret)).min(width.saturating_sub(1)),
        }
    }
}

fn move_entry_cursor(output: &mut String, position: &mut (usize, usize), row: usize, column: usize) {
    if position.0 != row {
        let (count, direction) = if position.0 > row { (position.0 - row, 'A') } else { (row - position.0, 'B') };
        output.push_str(&format!("\x1b[{count}{direction}"));
    }
    if position.1 != column { output.push_str(&format!("\x1b[{}G", column + 1)); }
    *position = (row, column);
}

/// Paint only changed suffixes, never blank-and-retype an unchanged row. The
/// native caret is the input indicator; a second yellow `|` served no purpose.
fn entry_delta(previous: Option<&EntryFrame>, next: &EntryFrame, dim: &str, reset: &str) -> String {
    let mut output = String::new();
    let mut position = (1, previous.map_or(0, |frame| frame.caret));
    for row in 0..3 {
        let old = previous.map(|frame| frame.rows[row].as_str());
        let new = &next.rows[row];
        if old == Some(new.as_str()) { continue; }
        let prefix = old.map_or(0, |text| text.chars().zip(new.chars())
            .take_while(|(left, right)| left == right).map(|(character, _)| character.len_utf8()).sum());
        move_entry_cursor(&mut output, &mut position, row, cells(&new[..prefix]));
        if old.is_none() { output.push_str("\x1b[2K"); } // once, on reservation only
        if prefix < new.len() {
            if row != 1 { output.push_str(dim); }
            output.push_str(&new[prefix..]);
            if row != 1 { output.push_str(reset); }
        }
        position.1 = cells(new);
        if old.is_some_and(|text| cells(text) > cells(new)) { output.push_str("\x1b[K"); }
    }
    move_entry_cursor(&mut output, &mut position, 1, next.caret);
    output
}

/// One buffered write per update; supported terminals present it atomically.
/// Others still benefit from suffix-only edits with no intervening blank rows.
fn write_paint(output: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    if body.is_empty() { return Ok(()); }
    let mut frame = Vec::with_capacity(body.len() + 32);
    crossterm::queue!(frame, crossterm::terminal::BeginSynchronizedUpdate)?;
    frame.extend_from_slice(body);
    crossterm::queue!(frame, crossterm::terminal::EndSynchronizedUpdate)?;
    output.write_all(&frame)?;
    output.flush()
}

#[derive(Default)]
struct EntryPainter {
    previous: Option<EntryFrame>,
}

impl EntryPainter {
    fn draw(&mut self, prompt: &str, buf: &str, cursor: usize, j: &Judgment, mode: Mode) -> std::io::Result<()> {
        if !ui::caps().live { return Ok(()); }
        let width = usize::from(crossterm::terminal::size()?.0).saturating_sub(1);
        let next = EntryFrame::new(prompt, buf, cursor, j, mode, width);
        let body = entry_delta(self.previous.as_ref(), &next, &ui::tone_code(ui::Tone::Dim), ui::tone_reset());
        write_paint(&mut std::io::stderr(), body.as_bytes())?;
        self.previous = Some(next);
        Ok(())
    }
}

/// A small inline field for other credential prompts (`join`). It OWNS the
/// `RawGuard` and the shared `EntryPainter`, so the caller cannot forget to
/// restore the terminal and cannot grow a second renderer. The caller only
/// supplies three plain rows: prompt, already-safe display text, and hint.
/// `caret` counts characters in the display text.
///
/// The display text must be printable ASCII with no control characters. A
/// masked secret is `*`; non-ASCII input is escaped by the caller, which keeps
/// the native caret and width arithmetic exact.
pub(crate) struct InlineField {
    _guard: RawGuard,
    painter: EntryPainter,
    live: bool,
}

impl InlineField {
    /// Enable the editor. In a live terminal this reserves three rows and
    /// enables bracketed paste + a steady native caret; on `TERM=dumb` it only
    /// suppresses kernel echo, emitting no cursor controls at all.
    pub(crate) fn open() -> std::io::Result<InlineField> {
        if !ui::caps().live || !std::io::stdin().is_terminal() {
            return Ok(InlineField {
                _guard: RawGuard::enable_hidden()?,
                painter: EntryPainter::default(),
                live: false,
            });
        }
        let mut guard = RawGuard::enable_inline()?;
        // Reserve the three rows before the first paint, even at the bottom of
        // a terminal. Cleanup leaves the shell below them, not inside a row.
        write!(std::io::stderr(), "\r\n\r\n\x1b[1A")?;
        std::io::stderr().flush()?;
        guard.rows_below = 1;
        Ok(InlineField { _guard: guard, painter: EntryPainter::default(), live: true })
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live
    }

    /// Paint through the shared suffix-only painter. With no changed rows this
    /// writes nothing (not even an empty synchronized-update pair).
    pub(crate) fn draw(
        &mut self,
        prompt: &str,
        display: &str,
        caret: usize,
        hint: &str,
    ) -> std::io::Result<()> {
        if !self.live { return Ok(()); }
        let width = usize::from(crossterm::terminal::size()?.0).saturating_sub(1);
        let (visible, caret) = field_window(display, caret, width.saturating_sub(2).max(1));
        let next = EntryFrame::from_parts(prompt, &visible, caret, hint, width);
        let body = entry_delta(self.painter.previous.as_ref(), &next, &ui::tone_code(ui::Tone::Dim), ui::tone_reset());
        write_paint(&mut std::io::stderr(), body.as_bytes())?;
        self.painter.previous = Some(next);
        Ok(())
    }

    /// Reflow invalidates relative row counts. Keep the old snapshot in
    /// scrollback and start a fresh field at the new bottom; the next draw
    /// rebuilds the three owned rows.
    pub(crate) fn resized(&mut self, rows: u16) -> std::io::Result<()> {
        if !self.live { return Ok(()); }
        after_resize(rows)?;
        write!(std::io::stderr(), "\r\n\r\n\x1b[1A")?;
        std::io::stderr().flush()?;
        self.painter.previous = None;
        Ok(())
    }
}

/// Reflow invalidates relative row counts. Preserve the old snapshot and start
/// below it at the terminal bottom; never erase or rewind into unknown history.
/// Only resizing does this. Normal keystrokes repaint the same owned rows.
fn after_resize(rows: u16) -> std::io::Result<()> {
    let mut err = std::io::stderr();
    crossterm::execute!(err, crossterm::cursor::MoveTo(0, rows.saturating_sub(1)))?;
    write!(err, "\r\n")?;
    err.flush()
}

/// Redraw the picker list in place: a header plus one line per item, the selected
/// one marked and colored. After the first paint the cursor is parked below the
/// list, so subsequent paints move up `items+1` lines first. Raw mode disables
/// newline translation, hence explicit `\r\n`.
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

fn render_picker(header: &str, items: &[String], sel: usize, previous_rows: usize, hints: &[(char, &str)]) -> std::io::Result<usize> {
    let mut frame = Vec::new();
    let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));
    let width = usize::from(width).saturating_sub(1);
    let max_rows = usize::from(height).saturating_sub(6).clamp(1, VIEWPORT);
    // Header + items + (a hint line, when there are hints). The cursor rewind
    // must count exactly what was drawn or the redraw walks up the scrollback.
    // A viewport, so a long list does not scroll the terminal away. The window
    // follows the selection and the counts below say how much is out of sight:
    // a list that silently truncates is worse than one that admits its length.
    let (first, view, above, below) = viewport_window(sel, items.len(), max_rows);
    let drawn =
        view + 1 + usize::from(above > 0) + usize::from(below > 0) + usize::from(!hints.is_empty());
    if previous_rows > 0 {
        write!(frame, "\x1b[{previous_rows}A")?;
    }
    write!(frame, "\r\x1b[2K{}\r\n", ui::paint(ui::Tone::Dim, &clipped(header, width)))?;
    let dim = ui::tone_code(ui::Tone::Dim);
    let reset0 = ui::tone_reset();
    if above > 0 {
        let line = clipped(&format!("  ↑ {above} more"), width);
        write!(frame, "\r\x1b[2K{dim}{line}{reset0}\r\n")?;
    }
    for (i, it) in items.iter().enumerate().skip(first).take(view) {
        let mark = if i == sel { ui::cursor_accent("|") } else { " ".to_string() };
        let it = clipped(it, width.saturating_sub(4));
        write!(frame, "\r\x1b[2K  {mark} {it}\r\n")?;
    }
    if below > 0 {
        let line = clipped(&format!("  ↓ {below} more"), width);
        write!(frame, "\r\x1b[2K{dim}{line}{reset0}\r\n")?;
    }
    // The ambient hint line. Always-visible keybindings beat a menu ITEM for the
    // same job: an item consumes a slot, sits in the arrow-key path, and reads as
    // a choice with the same weight as the real ones. A hint is present without
    // competing, and the list stays about the actual decision.
    if !hints.is_empty() {
        let reset = ui::tone_reset();
        let mut line = String::from("  \u{2191}\u{2193} move \u{b7} \u{23ce} select");
        for (k, label) in hints {
            line.push_str(&format!(" \u{b7} {k} {label}"));
        }
        line.push_str(" \u{b7} esc cancel");
        let line = clipped(&line, width);
        write!(frame, "\r\x1b[2K{dim}{line}{reset}\r\n")?;
    }
    // Viewport counts can add/remove rows as the selection moves. Rewind the
    // previous frame's height, not the new height; erase stale trailing rows.
    let stale = previous_rows.saturating_sub(drawn);
    for _ in 0..stale { write!(frame, "\r\x1b[2K\r\n")?; }
    if stale > 0 { write!(frame, "\x1b[{stale}A")?; }
    write_paint(&mut std::io::stderr(), &frame)?;
    Ok(drawn)
}

/// Interactive picker: Up/Down (or k/j) to move, Enter to choose, Esc/q/Ctrl-C to
/// cancel. Returns the chosen index, or None on cancel. The terminal is ALWAYS
/// restored (RawGuard). Callers append their own "none of these" item if they want
/// an in-list escape hatch.
pub fn pick(header: &str, items: &[String]) -> std::io::Result<Option<usize>> {
    match pick_with_keys(header, items, &[])? {
        Picked::Item(i) => Ok(Some(i)),
        Picked::Key(_) | Picked::Cancelled => Ok(None),
    }
}

/// What a picker returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Picked {
    /// An item was chosen.
    Item(usize),
    /// One of the caller's hint keys was pressed.
    Key(char),
    /// Esc, q, or Ctrl-C.
    Cancelled,
}

/// `pick`, plus caller-defined keys advertised on an ambient hint line.
///
/// The alternative is an extra ITEM ("More options..."), and an item is worse
/// for this job: it consumes a slot, sits in the arrow-key path between real
/// choices, and reads with the same weight as them even though it decides
/// nothing. A key is present without competing, so the list stays about the
/// actual decision and the escape hatch is always visible.
///
/// Hint keys are matched WITHOUT modifiers and after the navigation keys, so a
/// caller cannot accidentally shadow j/k/q or Ctrl-C.
pub fn pick_with_keys(
    header: &str,
    items: &[String],
    hints: &[(char, &str)],
) -> std::io::Result<Picked> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    if items.is_empty() {
        return Ok(Picked::Cancelled);
    }
    if !ui::caps().live {
        return pick_plain(header, items, hints);
    }
    let _guard = RawGuard::enable_inline()?;
    let mut sel = 0usize;
    let mut previous_rows = 0;
    loop {
        previous_rows = render_picker(header, items, sel, previous_rows, hints)?;
        let ev = event::read()?;
        if let Event::Resize(_, rows) = ev {
            after_resize(rows)?;
            previous_rows = 0;
            continue;
        }
        let Event::Key(k) = ev else { continue };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        match k.code {
            // #203: in raw mode the kernel does not synthesise SIGINT, and
            // crossterm may deliver the lone 0x03 byte WITHOUT the CONTROL
            // modifier. Match the raw control byte as well as the composed
            // Ctrl-C, so the keypress dismisses the picker on every platform.
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return Ok(Picked::Cancelled),
            KeyCode::Char('\u{3}') => return Ok(Picked::Cancelled),
            KeyCode::Up | KeyCode::Char('k') => sel = if sel == 0 { items.len() - 1 } else { sel - 1 },
            KeyCode::Down | KeyCode::Char('j') => sel = (sel + 1) % items.len(),
            KeyCode::Enter => return Ok(Picked::Item(sel)),
            KeyCode::Esc | KeyCode::Char('q') => return Ok(Picked::Cancelled),
            // AFTER navigation, so a hint key can never shadow j/k/q.
            KeyCode::Char(c) if k.modifiers.is_empty()
                && hints.iter().any(|(h, _)| *h == c) => return Ok(Picked::Key(c)),
            _ => {}
        }
    }
}

/// Real line-oriented fallback: print the menu once, then read explicit lines.
/// Never emit a cursor command, including during cleanup.
fn pick_plain(header: &str, items: &[String], hints: &[(char, &str)]) -> std::io::Result<Picked> {
    let mut err = std::io::stderr();
    writeln!(err, "{}", clipped(header, usize::MAX))?;
    for (index, item) in items.iter().enumerate() {
        writeln!(err, "  {}. {}", index + 1, clipped(item, usize::MAX))?;
    }
    for (key, label) in hints { writeln!(err, "  {key}: {}", clipped(label, usize::MAX))?; }
    loop {
        write!(err, "Choose a number (Enter = 1, q = cancel): ")?;
        err.flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 { return Ok(Picked::Cancelled); }
        let answer = line.trim();
        if matches!(answer, "q" | "\u{1b}") { return Ok(Picked::Cancelled); }
        if answer.is_empty() { return Ok(Picked::Item(0)); }
        if answer.len() == 1 && hints.iter().any(|(key, _)| answer.starts_with(*key)) {
            return Ok(Picked::Key(answer.chars().next().unwrap()));
        }
        if let Ok(index) = answer.parse::<usize>() {
            if (1..=items.len()).contains(&index) { return Ok(Picked::Item(index - 1)); }
        }
        writeln!(err, "Choose 1 through {}.", items.len())?;
    }
}

/// Drive the live, steered entry. Returns the user's outcome. The terminal is
/// ALWAYS restored before returning (RawGuard). `prefill` seeds the buffer (used
/// for the malformed-arg "fix it" path). Pass the SAME `auto_nameplate` you'll
/// use to actually mint, so the preview is honest.
pub fn run(prompt: &str, mode: Mode, prefill: &str, auto_nameplate: &str) -> std::io::Result<Outcome> {
    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    let mut guard = RawGuard::enable_inline()?;
    let mut painter = EntryPainter::default();

    let mut buf = String::new();
    let mut cursor = 0;
    let mut entry_error = insert_text(&mut buf, &mut cursor, prefill).err();
    // Reserve our three rows before the first draw, even at the bottom of a
    // terminal. Cleanup leaves the shell below them, not inside the hint row.
    if ui::caps().live {
        write!(std::io::stderr(), "\r\n\r\n\x1b[1A")?;
        guard.rows_below = 1;
    } else {
        // Raw mode disables echo before this prompt: an invite accidentally
        // pasted into this code-only reader must not leak through kernel echo.
        write!(std::io::stderr(), "{prompt}\r\n  Input hidden; Enter submits, Ctrl-U clears, Esc cancels.\r\n")?;
        if mode == Mode::Create {
            write!(std::io::stderr(), "  Type two words, or Enter generates a pair.\r\n")?;
        }
        std::io::stderr().flush()?;
    }
    // Initial paint.
    painter.draw(prompt, &buf, cursor, &entry_judgment(&buf, mode, auto_nameplate, entry_error), mode)?;

    loop {
        let ev = event::read()?;
        if let Event::Paste(text) = &ev {
            if entry_error != Some(INVITATION_IN_CODE_ENTRY) {
                entry_error = insert_text(&mut buf, &mut cursor, text).err();
            }
            let j = entry_judgment(&buf, mode, auto_nameplate, entry_error);
            painter.draw(prompt, &buf, cursor, &j, mode)?;
            continue; // Pasted Enter/Esc/control bytes are never key events.
        }
        if let Event::Resize(_, rows) = ev {
            if !ui::caps().live { continue; }
            after_resize(rows)?;
            write!(std::io::stderr(), "\r\n\r\n\x1b[1A")?;
            painter.previous = None;
            painter.draw(prompt, &buf, cursor, &entry_judgment(&buf, mode, auto_nameplate, entry_error), mode)?;
            continue;
        }
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
                let j = entry_judgment(&buf, mode, auto_nameplate, entry_error);
                match j.level {
                    Level::Ready => {
                        if mode == Mode::Create {
                            if let Some(code) =
                                received_code_in_create(&crate::join_input::PairingCode::normalize(&buf))
                            {
                                return Ok(Outcome::Claim(code));
                            }
                        }
                        let result = match mode {
                            // CREATE submits the words-only password (no nameplate);
                            // the caller mints the nameplate.
                            Mode::Create => {
                                let (words, _np) = crate::pake::split_chosen_code(
                                    &crate::join_input::PairingCode::normalize(&buf),
                                );
                                words
                            }
                            // CLAIM submits the normalized full code.
                            Mode::Claim => crate::join_input::PairingCode::normalize(&buf),
                        };
                        return Ok(Outcome::Submitted(result));
                    }
                    Level::Empty => return Ok(Outcome::Empty),
                    // Incomplete: refuse to submit, keep steering (REPL-like).
                    Level::Incomplete => {
                        if !ui::caps().live {
                            write!(std::io::stderr(), "\r\n{}\r\n", j.steer)?;
                            std::io::stderr().flush()?;
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                if cursor > 0 { cursor -= 1; buf.remove(cursor); }
                if buf.is_empty() || entry_error != Some(INVITATION_IN_CODE_ENTRY) { entry_error = None; }
            }
            KeyCode::Delete => {
                if cursor < buf.len() { buf.remove(cursor); }
                if buf.is_empty() || entry_error != Some(INVITATION_IN_CODE_ENTRY) { entry_error = None; }
            }
            KeyCode::Left => cursor = cursor.saturating_sub(1),
            KeyCode::Right => cursor = (cursor + 1).min(buf.len()),
            KeyCode::Home => cursor = 0,
            KeyCode::End => cursor = buf.len(),
            KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                buf.clear(); cursor = 0; entry_error = None;
            }
            KeyCode::Char(c) if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                if entry_error != Some(INVITATION_IN_CODE_ENTRY) {
                    entry_error = insert_text(&mut buf, &mut cursor, &c.to_string()).err();
                }
            }
            _ => {}
        }
        let j = entry_judgment(&buf, mode, auto_nameplate, entry_error);
        painter.draw(prompt, &buf, cursor, &j, mode)?;
    }
}

/// Codes are short ASCII, not a transport for invitation material. Reject an
/// entire oversized/secret paste instead of displaying it or accepting a prefix.
fn insert_text(buf: &mut String, cursor: &mut usize, text: &str) -> Result<(), &'static str> {
    if text.len() > 4096 {
        return Err("Too long; nothing inserted (48-character code limit).");
    }
    if crate::join_input::invitation_material(text)
        || crate::join_input::invitation_material(&format!("{}{}", &buf[..*cursor], text)) {
        return Err(INVITATION_IN_CODE_ENTRY);
    }
    if crate::join_input::reserved_code_path(&format!("{}{}", &buf[..*cursor], text)) {
        return Err("That is a file path or URL, not a code; use `tunlion join` with an invitation file.");
    }
    let left = format_buffer(&format!("{}{}", &buf[..*cursor], text));
    let candidate = format_buffer(&format!("{}{}", left, &buf[*cursor..]));
    if candidate.trim_end_matches('-').len() > CODE_LIMIT {
        return Err("Too long; nothing inserted (48-character code limit).");
    }
    if pasted_invitation(&candidate) {
        return Err(INVITATION_IN_CODE_ENTRY);
    }
    *cursor = left.len().min(candidate.len());
    *buf = candidate;
    Ok(())
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet_frame(text: &str, caret: usize) -> EntryFrame {
        EntryFrame { rows: ["  add / choose words".into(), format!("  {text}"),
            "  add another word".into()], caret: 2 + caret }
    }

    #[test]
    fn typing_appends_only_the_new_character_without_erasing_or_repainting() {
        let old = quiet_frame("kgkg", 4);
        let new = quiet_frame("kgkgk", 5);
        assert_eq!(entry_delta(Some(&old), &new, "DIM", "RESET"), "k");
        assert_eq!(entry_delta(Some(&new), &new, "DIM", "RESET"), "");
    }

    #[test]
    fn cursor_navigation_paints_no_text_and_backspace_only_erases_the_old_tail() {
        let old = quiet_frame("abc", 3);
        assert_eq!(entry_delta(Some(&old), &quiet_frame("abc", 2), "", ""), "\x1b[5G");
        assert_eq!(entry_delta(Some(&old), &quiet_frame("ab", 2), "", ""), "\x1b[5G\x1b[K");
    }

    #[test]
    fn changed_hints_leave_header_and_input_untouched() {
        let old = quiet_frame("kg", 2);
        let mut new = old.clone();
        new.rows[2] = "  add another word, easier to say".into();
        let delta = entry_delta(Some(&old), &new, "DIM", "RESET");
        assert!(delta.contains(", easier to say"));
        assert!(!delta.contains("choose words"));
        assert!(!delta.contains("kg"));
        assert!(!delta.contains("\x1b[2K"));
    }

    #[test]
    fn only_the_initial_reservation_clears_rows_and_no_fake_input_marker_is_drawn() {
        let frame = quiet_frame("abalaka-world", 13);
        let first = entry_delta(None, &frame, "", "");
        assert_eq!(first.matches("\x1b[2K").count(), 3);
        assert!(!first.contains('|'));
        let next = entry_delta(Some(&frame), &quiet_frame("abalaka-worldx", 14), "", "");
        assert_eq!(next, "x");
    }

    #[test]
    fn paint_is_one_synchronized_buffered_write_and_noops_write_nothing() {
        #[derive(Default)]
        struct Output { bytes: Vec<u8>, writes: usize, flushes: usize }
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.writes += 1; self.bytes.extend_from_slice(bytes); Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> { self.flushes += 1; Ok(()) }
        }
        let mut output = Output::default();
        write_paint(&mut output, b"k").unwrap();
        assert_eq!(output.bytes, b"\x1b[?2026hk\x1b[?2026l");
        assert_eq!((output.writes, output.flushes), (1, 1));
        write_paint(&mut output, b"").unwrap();
        assert_eq!((output.writes, output.flushes), (1, 1));
    }

    // PTY drivers exercise this very event loop, not a replica or a production
    // test flag. See runner/pairing-inline-pty.py for submit/cancel/cleanup.
    #[test]
    #[ignore = "requires a PTY; run runner/pairing-inline-pty.py"]
    fn pty_entry_driver() {
        let outcome = run("  add / choose words", Mode::Create, "", "1740").unwrap();
        println!("ENTRY:{outcome:?}");
    }

    #[test]
    #[ignore = "requires a PTY; run runner/pairing-inline-pty.py"]
    fn pty_picker_driver() {
        let items = (0..12).map(|i| format!("Device {i} — a long label that should not wrap across terminal rows")).collect::<Vec<_>>();
        println!("PICK:{:?}", pick("tunlion / Devices", &items).unwrap());
    }

    #[test]
    fn entry_window_keeps_editing_caret_visible() {
        assert_eq!(entry_window("abalaka-world", 13, 8), ("a-world", 7));
        assert_eq!(entry_window("abalaka-world", 0, 8), ("abalaka-", 0));
        for width in 1..80 {
            for cursor in 0..=13 {
                let (shown, col) = entry_window("abalaka-world", cursor, width);
                assert!(shown.len() <= width);
                assert!(col < width);
            }
        }
    }

    #[test]
    fn hints_distinguish_create_claim_and_preview_once() {
        assert!(entry_hint(&judge("", Mode::Create, "1740"), Mode::Create, 39).contains("generates"));
        assert!(!entry_hint(&judge("", Mode::Claim, ""), Mode::Claim, 39).contains("generates"));
        let hint = entry_hint(&judge("abalaka-world", Mode::Create, "1740"), Mode::Create, 95);
        assert_eq!(hint, "Enter creates abalaka-world-1740");
        assert_eq!(hint.matches("abalaka-world").count(), 1);
        assert!(entry_hint(&judge("brave-otter-3141", Mode::Claim, ""), Mode::Claim, 39).contains("accepts"));
    }

    #[test]
    fn rejected_input_blocks_submission_even_with_a_ready_or_empty_buffer() {
        for buf in ["", "abalaka-world"] {
            let j = entry_judgment(buf, Mode::Create, "1740", Some(INVITATION_IN_CODE_ENTRY));
            assert_eq!(j.level, Level::Incomplete);
            assert!(j.preview.is_none());
            assert_eq!(j.steer, INVITATION_IN_CODE_ENTRY);
        }
    }

    #[test]
    fn protocol_limit_includes_the_minted_nameplate() {
        let words = "abalaka-world-abalaka-world-brave-otterxxxx";
        assert_eq!(words.len() + "-1740".len(), CODE_LIMIT);
        assert_eq!(judge(words, Mode::Create, "1740").level, Level::Ready);
        let longer = format!("{words}x");
        assert_eq!(judge(&longer, Mode::Create, "1740").level, Level::Incomplete);
        let code = format!("{words}-1740");
        assert_eq!(judge(&code, Mode::Claim, "").level, Level::Ready);
        assert_eq!(judge(&format!("{code}1"), Mode::Claim, "").level, Level::Incomplete);
        let mut buf = code.clone();
        let mut cursor = buf.len();
        assert!(insert_text(&mut buf, &mut cursor, "1").is_err());
        assert_eq!(buf, code);
    }

    #[test]
    fn clipping_never_emits_control_bytes_or_wraps() {
        for width in 0..80 {
            let line = clipped("  hello\x1b[2J\r\n世界✓ · long words", width);
            assert!(line.chars().count() <= width);
            assert!(!line.chars().any(char::is_control));
        }
    }

    #[test]
    fn paste_is_only_insertion_and_middle_editing_preserves_suffix() {
        let mut buf = "brave-3141".to_string();
        let mut cursor = 6;
        insert_text(&mut buf, &mut cursor, "otter ").unwrap();
        assert_eq!(buf, "brave-otter-3141");
        assert_eq!(cursor, 12);
        let mut buf = String::new();
        let mut cursor = 0;
        insert_text(&mut buf, &mut cursor, "brave\notter\r3141\x03\x1b").unwrap();
        assert_eq!(buf, "brave-otter-3141-");
        // Submission is exclusively in Event::Key(Enter), never insert_text.
        assert_eq!(cursor, buf.len());
    }

    #[test]
    fn secret_and_oversized_pastes_leave_buffer_and_cursor_unchanged() {
        for text in ["filament-invite:v2:SECRET".to_string(),
                     "TLNINV-SECRET".to_string(), "{\"secret\":true}".to_string(),
                     "a".repeat(257), "x".repeat(4097)] {
            let mut buf = "brave-otter".to_string();
            let mut cursor = 5;
            assert!(insert_text(&mut buf, &mut cursor, &text).is_err());
            assert_eq!(buf, "brave-otter");
            assert_eq!(cursor, 5);
        }
    }

    #[test]
    fn typing_an_invitation_prefix_cannot_reveal_payload() {
        let mut buf = String::new();
        let mut cursor = 0;
        let mut refused = false;
        for ch in "filament-invite:v2:SECRET".chars() {
            if insert_text(&mut buf, &mut cursor, &ch.to_string()).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused);
        assert!(!buf.contains("secret"));
    }

    #[test]
    fn format_lowercases_and_keeps_valid() {
        assert_eq!(format_buffer("Brave-Otter-3141"), "brave-otter-3141");
        assert_eq!(format_buffer("ABC123"), "abc123");
    }

    #[test]
    fn final_limit_ignores_the_editors_trailing_separator_without_guessing_material() {
        let code = format!("{}-{}-1234", "a".repeat(20), "b".repeat(22));
        let mut buf = code.clone();
        let mut cursor = buf.len();
        insert_text(&mut buf, &mut cursor, " ").unwrap();
        assert_eq!(buf, format!("{code}-"));
        assert_eq!(judge(&buf, Mode::Claim, "").level, Level::Ready);
        for raw in ["`[\"brave-otter-3141\"]`", "'TLNINV-brave-otter-3141'"] {
            let result = judge(raw, Mode::Claim, "");
            assert_eq!(result.level, Level::Incomplete);
            assert!(result.preview.is_none());
        }
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
    fn format_turns_disallowed_characters_into_separators() {
        // '!', '@', '/', emoji etc. never enter the buffer.
        assert_eq!(format_buffer("brave!otter"), "brave-otter");
        assert_eq!(format_buffer("a@b/c"), "a-b-c");
        assert_eq!(format_buffer("café"), "caf-");
        assert_eq!(format_buffer("UP!!!"), "up-");
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
