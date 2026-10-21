//! Reading the one thing `tunlion join` accepts: a pairing code, an
//! invitation/auth key, a JSON credential, or the path to an invitation file.
//!
//! This module is ONLY an input surface. It does not classify, touch the
//! filesystem, parse an invitation, or claim that anything is valid. The
//! existing `identity_flow::classify_join_input` remains authoritative after
//! Enter (and its file-existence check happens outside entry).
//!
//! Two safety rules drive the display:
//!
//! * invitation material is ALWAYS masked, including a typed prefix, a JSON
//!   payload, leading whitespace, and edits that later hide the prefix;
//! * material this module cannot recognize as a code or a path is masked too.
//!   A credential reader must never print an unrecognized token payload.
//!
//! Codes and paths may display. Non-ASCII input is kept byte-for-byte and is
//! shown ASCII-escaped (`\u{e9}`), so a wide/combining character cannot split
//! the native caret or smuggle a terminal control.
//!
//! Paste is data. It is inserted through the same sanitizer as typing, which
//! removes only C0/DEL/C1 terminal controls except the ordinary JSON
//! whitespace `\t`, `\n`, `\r`. A pasted newline can therefore never become
//! Enter, and a pasted ESC/`^C` can never become a key. Enter is the only
//! submit path; no helper submits as a side effect.

use crate::codeentry::InlineField;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// The same protocol limit code entry uses. A full code, including its
/// machine-minted suffix, is never silently shortened to fit: the complete
/// input stays visible and Enter is blocked with an explicit error.
const CODE_LIMIT: usize = 48;

/// Hard ceiling for the whole credential. An insertion that would cross it is
/// rejected whole, never truncated, so no half-invitation is submitted.
const CREDENTIAL_CAP: usize = 64 * 1024;

/// Longest all-alpha group still treated as a familiar code word for DISPLAY.
/// Real minted words are shorter than this; a 16-char bare hex blob is not a
/// code word and must stay hidden. This is presentation only, never a limit.
const WORD_DISPLAY_MAX: usize = 12;

const PROMPT: &str = "  code or invitation: pairing code, invitation, or file path";

/// What the person chose at the join prompt. The raw material is held in a
/// zeroizing buffer and is handed to the existing classifier untouched.
pub(crate) enum InputOutcome {
    Submitted(Zeroizing<String>),
    Cancelled,
    Interrupted,
}

/// Never print the submitted material by accident (`{:?}` on an outcome).
impl std::fmt::Debug for InputOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputOutcome::Submitted(value) => {
                write!(formatter, "Submitted(<hidden>, {} bytes)", value.len())
            }
            InputOutcome::Cancelled => formatter.write_str("Cancelled"),
            InputOutcome::Interrupted => formatter.write_str("Interrupted"),
        }
    }
}

/// Read one join credential from the terminal. The guard and painter are
/// dropped (raw mode restored, cursor shown) before the outcome escapes.
pub(crate) fn read_input() -> io::Result<InputOutcome> {
    let mut field = FieldState::new();
    let mut surface = InlineField::open()?;
    let terminal_input = std::io::stdin().is_terminal();
    if !surface.is_live() {
        let mut err = std::io::stderr();
        if terminal_input {
            // Raw mode suppresses newline translation; be explicit so the
            // fallback never stair-steps a TERM=dumb terminal. Bracketed paste
            // is impossible without escape bytes, so this path is line-based.
            write!(
                err,
                "{PROMPT}\r\n  Single-line input only; use a file for multiline invitations.\r\n  Input is not echoed. Enter submits when complete; Esc cancels; Ctrl-C interrupts.\r\n  Ctrl-U clears the field.\r\n"
            )?;
        } else {
            writeln!(err, "{PROMPT}")?;
            writeln!(err, "  Input is not echoed. Reading from stdin until EOF.")?;
        }
        err.flush()?;
    }

    let result = if surface.is_live() {
        edit_live(&mut field, &mut surface)
    } else if terminal_input {
        edit_hidden(&mut field)
    } else {
        read_piped(&mut field)
    };
    drop(surface);
    result
}

// ------------------------------------------------------------------ editing --

/// Pure, IO-free editor state. All masking decisions and limits live here so
/// unit tests can drive every transition without a TTY.
struct FieldState {
    /// Exact (sanitized) credential bytes. Never UTF-8 truncated: every edit
    /// keeps `cursor` on a char boundary.
    buf: Zeroizing<String>,
    cursor: usize,
    /// Sticky: once material may be an invitation or an opaque secret, it stays
    /// masked until a deliberate FULL clear. Editing the prefix away does not
    /// reveal the payload that was typed after it.
    secret: bool,
    /// Explicit, blocking problem. Enter cannot submit while this is set.
    error: Option<String>,
}

impl FieldState {
    fn new() -> FieldState {
        FieldState {
            buf: Zeroizing::new(String::new()),
            cursor: 0,
            secret: false,
            error: None,
        }
    }

    fn text(&self) -> &str {
        &self.buf
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buf.len()
    }

    #[cfg(test)]
    fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    fn is_secret(&self) -> bool {
        self.secret
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Insert text exactly as data. Returns false when nothing changed (empty
    /// sanitized input) or when an explicit limit rejected the WHOLE insertion.
    fn insert(&mut self, raw: &str) -> bool {
        if raw.is_empty() {
            return false;
        }
        // Reject an oversized paste before allocating a second copy of it.
        if raw.len() > CREDENTIAL_CAP {
            self.reject_oversize();
            return false;
        }
        let clean = Zeroizing::new(sanitize_input(raw));
        if clean.is_empty() {
            return false;
        }
        if self.buf.len().saturating_add(clean.len()) > CREDENTIAL_CAP {
            self.reject_oversize();
            return false;
        }
        self.buf.insert_str(self.cursor, clean.as_str());
        self.cursor += clean.len();
        self.after_edit();
        true
    }

    fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let previous = previous_boundary(&self.buf, self.cursor);
        self.buf.remove(previous);
        self.cursor = previous;
        self.after_edit();
        true
    }

    fn delete(&mut self) -> bool {
        if self.cursor >= self.buf.len() {
            return false;
        }
        self.buf.remove(self.cursor);
        self.after_edit();
        true
    }

    fn left(&mut self) {
        self.cursor = previous_boundary(&self.buf, self.cursor);
    }

    fn right(&mut self) {
        self.cursor = next_boundary(&self.buf, self.cursor);
    }

    fn home(&mut self) {
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.cursor = self.buf.len();
    }

    /// Deliberate full clear is the ONLY way out of sticky secret mode.
    fn clear(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.secret = false;
        self.error = None;
    }

    /// Enter's only action. An empty/whitespace-only buffer and any blocked
    /// error submit nothing. The buffer is moved, not cloned.
    fn take_submission(&mut self) -> Option<Zeroizing<String>> {
        if self.error.is_some() || self.buf.trim().is_empty() {
            return None;
        }
        let value = std::mem::take(&mut *self.buf);
        self.cursor = 0;
        Some(Zeroizing::new(value))
    }

    fn reject_oversize(&mut self) {
        self.error = Some(
            "Input is larger than 64 KiB; nothing was inserted. Edit it or Ctrl-U to clear."
                .to_string(),
        );
    }

    fn after_edit(&mut self) {
        if self.buf.is_empty() {
            self.secret = false;
            self.error = None;
            return;
        }
        if is_secret_material(&self.buf) {
            self.secret = true;
        }
        self.error = self.validate();
    }

    fn validate(&self) -> Option<String> {
        // Sticky secrecy is PRESENTATION, not a limit exemption. A field that
        // became secret earlier can be edited down to a full code; that code
        // still has to obey the protocol ceiling.
        if let Some(length) = code_limit_overrun(&self.buf) {
            return Some(format!(
                "Codes are limited to {CODE_LIMIT} characters after normalization; this is {length} and was not truncated. Edit it or Ctrl-U."
            ));
        }
        None
    }

    /// Safe display text plus the caret position in CHARACTERS. Secrets are
    /// one `*` per input character. Non-secret text escapes every non-ASCII
    /// char and the three preserved whitespace controls, so the row cannot
    /// contain a terminal escape or a wide cell.
    fn render(&self) -> (String, usize) {
        if self.secret {
            let total = self.buf.chars().count();
            let before = self.buf[..self.cursor].chars().count();
            return ("*".repeat(total), before);
        }
        let mut shown = String::with_capacity(self.buf.len());
        for character in self.buf[..self.cursor].chars() {
            push_display_char(&mut shown, character);
        }
        let caret = shown.len();
        for character in self.buf[self.cursor..].chars() {
            push_display_char(&mut shown, character);
        }
        (shown, caret)
    }

    /// Honest shape feedback only. It never says a credential is valid, and it
    /// never includes secret material.
    fn hint(&self) -> String {
        if let Some(error) = &self.error {
            return format!("! {error}");
        }
        if self.buf.is_empty() {
            return "Paste a pairing code, invitation, JSON, or invitation-file path · Esc cancels"
                .to_string();
        }
        let trimmed = trim_input_start(&self.buf);
        if self.secret {
            let kind = if invitation_prefix(trimmed) {
                "Invitation material"
            } else if json_material(trimmed) {
                "JSON material"
            } else {
                "Hidden; not recognized as a code or path"
            };
            return format!("{kind} · hidden · Enter submits for checking · Esc cancels");
        }
        if looks_like_path(trimmed) {
            let mut hint =
                "File path · Enter submits; the file is checked after entry · Esc cancels"
                    .to_string();
            if !self.buf.is_ascii() {
                hint.push_str(" · Unicode shown escaped; input unchanged");
            }
            return hint;
        }
        code_hint(&self.buf)
    }
}

/// A key's effect, independent of terminal mode. Kept pure so the live and
/// hidden loops cannot drift.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyAction {
    Insert(char),
    Backspace,
    Delete,
    Left,
    Right,
    Home,
    End,
    Clear,
    Submit,
    Cancel,
    Interrupt,
    Ignore,
}

fn key_action(code: KeyCode, modifiers: KeyModifiers) -> KeyAction {
    match code {
        // Raw mode may deliver the lone control byte without the modifier.
        KeyCode::Char('c' | 'C') if modifiers.contains(KeyModifiers::CONTROL) => {
            KeyAction::Interrupt
        }
        KeyCode::Char('\u{3}') => KeyAction::Interrupt,
        KeyCode::Char('u' | 'U') if modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Clear,
        KeyCode::Char('\u{15}') => KeyAction::Clear,
        KeyCode::Esc => KeyAction::Cancel,
        KeyCode::Enter => KeyAction::Submit,
        KeyCode::Backspace => KeyAction::Backspace,
        KeyCode::Delete => KeyAction::Delete,
        KeyCode::Left => KeyAction::Left,
        KeyCode::Right => KeyAction::Right,
        KeyCode::Home => KeyAction::Home,
        KeyCode::End => KeyAction::End,
        KeyCode::Char(character)
            if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                && !character.is_control() =>
        {
            KeyAction::Insert(character)
        }
        _ => KeyAction::Ignore,
    }
}

fn apply_action(field: &mut FieldState, action: KeyAction) -> Option<InputOutcome> {
    match action {
        KeyAction::Insert(character) => {
            let mut encoded = [0u8; 4];
            field.insert(character.encode_utf8(&mut encoded));
        }
        KeyAction::Backspace => {
            field.backspace();
        }
        KeyAction::Delete => {
            field.delete();
        }
        KeyAction::Left => field.left(),
        KeyAction::Right => field.right(),
        KeyAction::Home => field.home(),
        KeyAction::End => field.end(),
        KeyAction::Clear => field.clear(),
        KeyAction::Submit => {
            if let Some(value) = field.take_submission() {
                return Some(InputOutcome::Submitted(value));
            }
        }
        KeyAction::Cancel => return Some(InputOutcome::Cancelled),
        KeyAction::Interrupt => return Some(InputOutcome::Interrupted),
        KeyAction::Ignore => {}
    }
    None
}

// ------------------------------------------------------------------- loops --

fn edit_live(field: &mut FieldState, surface: &mut InlineField) -> io::Result<InputOutcome> {
    draw(field, surface)?;
    loop {
        let next_event = event::read()?;
        match next_event {
            Event::Paste(text) => {
                // Data, never keys: an embedded newline/ESC/^C stays text
                // (dangerous controls are removed by the sanitizer).
                let text = Zeroizing::new(text);
                field.insert(&text);
            }
            Event::Resize(_, rows) => {
                surface.resized(rows)?;
            }
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind,
                ..
            }) => {
                if kind == KeyEventKind::Release {
                    continue;
                }
                if let Some(outcome) = apply_action(field, key_action(code, modifiers)) {
                    return Ok(outcome);
                }
            }
            _ => continue,
        }
        draw(field, surface)?;
    }
}

/// No redraw at all. Used for `TERM=dumb` on a real terminal: raw mode keeps
/// the secret out of kernel echo, and only the final classification is shown.
/// This fallback is deliberately LINE-ORIENTED: bracketed paste needs escape
/// bytes, which a dumb terminal must not receive, so a newline is Enter and
/// multiline material must come from a file. Nothing is redrawn per keystroke.
fn edit_hidden(field: &mut FieldState) -> io::Result<InputOutcome> {
    loop {
        match event::read()? {
            Event::Paste(text) => {
                let text = Zeroizing::new(text);
                field.insert(&text);
            }
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind,
                ..
            }) => {
                if kind == KeyEventKind::Release {
                    continue;
                }
                let action = key_action(code, modifiers);
                if action == KeyAction::Submit {
                    if let Some(value) = field.take_submission() {
                        return Ok(InputOutcome::Submitted(value));
                    }
                    if let Some(error) = field.error() {
                        // This branch only runs on a real terminal in raw mode.
                        write!(std::io::stderr(), "  {error}\r\n")?;
                    }
                } else if let Some(outcome) = apply_action(field, action) {
                    return Ok(outcome);
                }
            }
            _ => {}
        }
    }
}

/// Non-terminal stdin (CI, a pipe, a secret manager). There is no echo and no
/// key stream to interpret: every byte is data, including newlines, so a
/// multi-line JSON credential survives. EOF is the explicit end of input.
fn read_piped(field: &mut FieldState) -> io::Result<InputOutcome> {
    let mut bytes = Zeroizing::new(Vec::new());
    {
        let mut stdin = std::io::stdin().lock();
        (&mut stdin)
            .take((CREDENTIAL_CAP + 1) as u64)
            .read_to_end(&mut *bytes)?;
    }
    if bytes.len() > CREDENTIAL_CAP {
        let message = "join input is larger than 64 KiB; nothing was submitted";
        writeln!(std::io::stderr(), "  {message}")?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, message));
    }
    let text = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => text,
        Err(error) => {
            // Do not leave the rejected bytes in a freed allocation.
            let mut rejected = error.into_bytes();
            rejected.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "join input is not valid UTF-8; nothing was submitted",
            ));
        }
    };
    let text = Zeroizing::new(text);
    if text.trim().is_empty() {
        return Ok(InputOutcome::Cancelled);
    }
    field.insert(&text);
    if field.text().trim().is_empty() {
        return Ok(InputOutcome::Cancelled);
    }
    if let Some(value) = field.take_submission() {
        return Ok(InputOutcome::Submitted(value));
    }
    let message = field
        .error()
        .unwrap_or("no usable join input; nothing was submitted");
    writeln!(std::io::stderr(), "  {message}")?;
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        message.to_string(),
    ))
}

fn draw(field: &FieldState, surface: &mut InlineField) -> io::Result<()> {
    let (display, caret) = field.render();
    surface.draw(PROMPT, &display, caret, &field.hint())
}

// ---------------------------------------------------------- pure classifiers --

/// Strip only terminal-dangerous controls. Ordinary JSON whitespace is data and
/// must survive byte-for-byte: `\t`, `\n` and `\r` are kept, every other C0,
/// DEL (0x7f) and C1 control is dropped. In particular ESC never reaches the
/// backend, and a pasted `^C` is not a key event in the first place.
fn sanitize_input(text: &str) -> String {
    text.chars()
        .filter(|character| matches!(*character, '\t' | '\n' | '\r') || !character.is_control())
        .collect()
}

fn trim_input_start(text: &str) -> &str {
    text.trim_start_matches(|character: char| character.is_whitespace() || character == '\u{feff}')
}

fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Any prefix of the invitation/auth-key forms is treated as invitation
/// material from the moment it is unambiguous. `filament-` is not a pairing
/// word and `tlninv` is not either, so masking here does not hide ordinary
/// codes. Once set, the caller's sticky bit keeps it masked after edits.
fn invitation_prefix(text: &str) -> bool {
    starts_with_ignore_ascii_case(text, "filament-")
        || starts_with_ignore_ascii_case(text, "tlninv")
        || starts_with_ignore_ascii_case(text, "tunlion-invite")
}

fn json_material(text: &str) -> bool {
    text.starts_with('{') || text.starts_with('[')
}

/// A path may display only when it is unambiguously one: an explicit
/// absolute/relative/home/UNC/drive prefix, or a known credential-file
/// extension. A bare leading dot is NOT enough, and an arbitrary `dir/file`,
/// a base64 token containing `/`, or a URL stays hidden as unknown material.
/// Hidden input still submits unchanged; this only decides what is painted.
fn looks_like_path(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return false;
    }
    if windows_drive_prefix(trimmed)
        || trimmed.starts_with("\\\\")
        || trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("~/")
    {
        return true;
    }
    if url_like(trimmed) {
        return false;
    }
    known_file_extension(trimmed)
}

/// `C:\...` or `C:/...`. A bare drive-relative `C:name` is not displayed.
fn windows_drive_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn url_like(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme.as_bytes()[0].is_ascii_alphabetic()
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn known_file_extension(text: &str) -> bool {
    let Some((_, extension)) = text.rsplit_once('.') else {
        return false;
    };
    if extension.is_empty() || extension.len() > 12 {
        return false;
    }
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt"
            | "json"
            | "inv"
            | "invite"
            | "key"
            | "pem"
            | "crt"
            | "yaml"
            | "yml"
            | "toml"
            | "conf"
            | "cfg"
            | "env"
            | "token"
            | "cred"
            | "credential"
    )
}

/// Pairing codes and their partial prefixes may display. The shape is narrow:
/// every group is a short ASCII word, and only the LAST group may instead be a
/// partial 1-5 digit nameplate. That keeps a UUID, a hex/base64 token, or a
/// long all-alpha blob OUT of the display path; those stay masked as unknown.
/// The word cap is deliberately the familiar wordlist length, not a security
/// claim: short all-alpha typing must remain visible while a 16-char blob does
/// not. Limiting is handled separately by `code_limit_overrun`.
fn looks_like_code(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || !trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character.is_whitespace()
        })
    {
        return false;
    }
    let groups: Vec<&str> = trimmed
        .split(|character: char| character == '-' || character.is_whitespace())
        .filter(|group| !group.is_empty())
        .collect();
    let Some((last, words)) = groups.split_last() else {
        return false;
    };
    let last = *last;
    if groups.iter().any(|group| group.len() > WORD_DISPLAY_MAX) {
        return false;
    }
    let word = |group: &str| {
        group
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    };
    let nameplate = |group: &str| {
        !group.is_empty()
            && group.len() <= 5
            && group.chars().all(|character| character.is_ascii_digit())
    };
    if !words.iter().all(|group| word(*group)) {
        return false;
    }
    if nameplate(last) {
        return true;
    }
    if !word(last) {
        return false;
    }
    // A long ALL-WORDS buffer is not a familiar partial code. Short words stay
    // visible (typing a minted code), but a long all-alpha blob does not. Hex
    // strings are a common opaque-token shape and are hidden earlier.
    let total: usize = groups.iter().map(|group| group.len()).sum();
    let all_hex = groups
        .iter()
        .all(|group| group.chars().all(|character| character.is_ascii_hexdigit()));
    !(total > 24 || (total >= 16 && all_hex))
}

fn is_secret_material(text: &str) -> bool {
    let trimmed = trim_input_start(text);
    if trimmed.is_empty() {
        return false;
    }
    if invitation_prefix(trimmed) || json_material(trimmed) {
        return true;
    }
    if looks_like_path(trimmed) {
        return false;
    }
    // Codes and their partial prefixes are the only other material we can
    // recognize. Judge the SHAPE AFTER separator cleanup, so typing
    // `brave.otter.3141` shows the code the boundary will actually submit.
    // Path-ish separators and dotfile syntax are never normalized for display:
    // they can spell an opaque token, and a token must stay hidden. Inspecting
    // only the raw text would instead mask a dotted code permanently via the
    // sticky bit, even after its digits made it recognizable.
    if !trimmed.starts_with('.') && !trimmed.contains(['/', '\\', ':'])
        && looks_like_code(&crate::join_input::PairingCode::normalize(trimmed))
    {
        return false;
    }
    !looks_like_code(trimmed)
}

/// The 48-character protocol limit applies only to a FULL code shape: ASCII
/// words plus a trailing numeric nameplate of 2+ digits (transfer grammar) or
/// 3-5 digits (pairing grammar). A long file name that merely contains dashes
/// is a path, not a code to truncate or refuse, and invitation or JSON material
/// is exempt regardless of sticky masking.
///
/// Length is measured on the UNBOUNDED normalized code, not the raw row: spaces
/// around or between words vanish, so a padded 48-character code is accepted.
/// Do NOT use `pake::norm_code` here: it caps at 48 characters, which would
/// hide the suffix this check exists to protect.
///
/// Returns the offending normalized length. This is deliberately independent
/// of `looks_like_code` (which may hide a long single group as unknown); a
/// secret-looking buffer can still be a real over-limit code after an edit.
fn code_limit_overrun(text: &str) -> Option<usize> {
    let current = trim_input_start(text);
    if crate::join_input::invitation_material(current)
        || crate::join_input::invitation_path(current) || current.contains(':') {
        return None;
    }
    // Use the code-only cleanup shared with the post-Enter typed boundary.
    // Reservation of credential/path syntax must precede this transformation.
    let code = normalized_code_unbounded(text);
    if code.len() <= CODE_LIMIT {
        return None;
    }
    let (nameplate, words) = crate::pake::split_code(code.trim_matches('-'));
    // The transfer-code grammar accepts any trailing numeric group of 2+ (not
    // just the 3-5 digit pairing nameplate). A 6-digit suffix still normalizes
    // into that shape, so normalizing to 48 must not hide it. Longer digit
    // runs are equally unsafe to submit with a silent suffix cut.
    let full_code = nameplate.len() >= 2
        && nameplate.bytes().all(|byte| byte.is_ascii_digit())
        && !words.trim_matches('-').is_empty();
    full_code.then_some(code.len())
}

/// The same normalization the real parser uses, without `norm_code`'s
/// 48-character truncation. Lowercase is Unicode-aware like `norm_code`, so a
/// character such as `İ` that lowers to ASCII `i` still counts; characters
/// that lower only to non-ASCII are dropped exactly as the parser drops them.
fn normalized_code_unbounded(text: &str) -> String {
    crate::join_input::PairingCode::normalize(text)
}

fn code_hint(text: &str) -> String {
    let normalized = normalized_code_unbounded(text);
    let code = normalized.trim_matches('-');
    if crate::token_is_pairing_code(code) {
        "Pairing-code shape · Enter submits for checking · Esc cancels".to_string()
    } else if crate::regex_lite_code(code) {
        "One-time transfer-code shape; `tunlion receive` claims those · Esc cancels".to_string()
    } else {
        "Pairing code: words, then a 3-5 digit number · Enter submits · Esc cancels".to_string()
    }
}

fn previous_boundary(text: &str, index: usize) -> usize {
    text[..index]
        .char_indices()
        .next_back()
        .map(|(offset, _)| offset)
        .unwrap_or(0)
}

fn next_boundary(text: &str, index: usize) -> usize {
    text[index..]
        .chars()
        .next()
        .map(|character| index + character.len_utf8())
        .unwrap_or(text.len())
}

fn push_display_char(shown: &mut String, character: char) {
    match character {
        '\n' => shown.push_str("\\n"),
        '\r' => shown.push_str("\\r"),
        '\t' => shown.push_str("\\t"),
        character if character.is_ascii() && !character.is_control() => shown.push(character),
        character => {
            // Unicode stays the real input; only the display is escaped.
            shown.push_str(&format!("\\u{{{:x}}}", character as u32));
        }
    }
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    // All-alpha groups within `WORD_DISPLAY_MAX`, so these stay visible while
    // exercising the 48/49 boundary. Lengths: 48, 49, 56, 58.
    const CODE48_GROUPS: &str = "abcdefghijkl-mnopqrstuvwx-yzabcdefghi-abcde-1234";
    const CODE49_GROUPS: &str = "abcdefghijkl-mnopqrstuvwx-yzabcdefghi-abcdef-1234";
    const CODE_LONG_GROUPS: &str = "abcdefghijkl-mnopqrstuvwx-yzabcdefghij-abcdefghijkl-1234";
    const CODE_LONG_NAME: &str = "abcdefghijkl-mnopqrstuvwx-yzabcdefghij-abcdefghijkl-backup";

    fn field_with(text: &str) -> FieldState {
        let mut field = FieldState::new();
        assert!(field.insert(text));
        field
    }

    #[test]
    fn invitation_material_is_masked_and_masking_is_sticky_through_prefix_edits() {
        let mut field = field_with("filament-invite:v2:SECRET");
        assert!(field.is_secret());
        let (shown, _) = field.render();
        assert_eq!(
            shown,
            "*".repeat("filament-invite:v2:SECRET".chars().count())
        );
        assert!(!shown.contains("SECRET"));

        // Remove the recognizable prefix from the FRONT. The payload was
        // typed while the field was secret, so it must stay hidden.
        field.home();
        for _ in 0.."filament-".len() {
            field.delete();
        }
        assert!(field.is_secret());
        let (shown, _) = field.render();
        assert!(shown.chars().all(|character| character == '*'));
        assert!(!shown.contains("SECRET"));

        // Only a deliberate full clear resets it.
        field.clear();
        assert!(!field.is_secret());
        assert!(field.insert("brave-otter-3141"));
        assert!(!field.is_secret());
        assert!(field.render().0.contains("brave-otter-3141"));
    }

    #[test]
    fn typed_invitation_prefixes_and_leading_whitespace_cannot_reveal_payload() {
        for material in [
            "filament-invite:v2:AbC_d-0",
            "  \n\tfilament-invite:v2:AbC_d-0",
            "TLNINV-SECRET-PAYLOAD",
            "tlninv-secret-payload",
            " \u{feff}  {\"invite\":\"SECRET\"}",
            "\n[1,2,3]",
        ] {
            let field = field_with(material);
            assert!(field.is_secret(), "{material:?}");
            let (shown, _) = field.render();
            assert!(!shown.contains("SECRET"), "{material:?}");
            assert!(!shown.contains("AbC"), "{material:?}");
            assert!(field.hint().contains("hidden"), "{}", field.hint());
        }
    }

    #[test]
    fn typing_an_invitation_prefix_never_shows_its_payload() {
        let mut field = FieldState::new();
        for character in "filament-invite:v2:SECRET".chars() {
            field.insert(&character.to_string());
            let (shown, _) = field.render();
            assert!(
                !shown.contains("SECRET"),
                "payload shown at {:?}",
                field.text()
            );
        }
        assert!(field.is_secret());
    }

    #[test]
    fn json_keeps_its_multiline_bytes_but_displays_only_masks() {
        let material = " {\n  \"token\": \"a b c\",\n  \"n\": 1\n}\n";
        let field = field_with(material);
        assert_eq!(
            field.text(),
            material,
            "ordinary whitespace and multi-line JSON stay intact"
        );
        assert!(field.is_secret());
        let (shown, caret) = field.render();
        assert!(shown.chars().all(|character| character == '*'));
        assert_eq!(caret, material[..material.len()].chars().count());
        assert!(!field.hint().contains("token"));
    }

    #[test]
    fn unicode_stays_real_input_and_is_only_escaped_on_screen() {
        let mut field = field_with("café-東京.txt");
        assert_eq!(field.text(), "café-東京.txt");
        assert!(looks_like_path(field.text()));
        assert!(!field.is_secret());
        let (shown, caret) = field.render();
        assert!(shown.is_ascii());
        assert!(shown.contains("caf\\u{e9}"));
        assert!(shown.contains("\\u{6771}"));
        assert_eq!(caret, shown.len());
        assert!(field.hint().contains("Unicode shown escaped"));

        // Cursor movement and deletion respect UTF-8 boundaries.
        field.home();
        field.right();
        field.right();
        field.right();
        field.right(); // past "café"
        assert_eq!(&field.text()[..field.cursor()], "café");
        assert!(field.backspace());
        assert_eq!(field.text(), "caf-東京.txt");
    }

    #[test]
    fn ascii_48_character_code_limit_is_explicit_and_never_truncates_the_suffix() {
        let code = CODE49_GROUPS.to_string();
        assert_eq!(code.len(), CODE_LIMIT + 1);
        let mut field = field_with(&code);
        assert_eq!(
            field.text(),
            code.as_str(),
            "the complete code and its suffix stay in the buffer"
        );
        let (shown, _) = field.render();
        assert!(shown.contains(&code));
        let error = field.error().expect("a 49-character code is blocked");
        assert!(error.contains("48"), "{error}");
        assert!(error.contains("not truncated"), "{error}");
        assert!(field.take_submission().is_none());

        assert!(field.backspace());
        assert_eq!(field.text().len(), CODE_LIMIT);
        assert!(field.error().is_none());
        let submitted = field.take_submission().expect("48 characters may submit");
        assert_eq!(submitted.as_str(), &code[..CODE_LIMIT]);
    }

    #[test]
    fn the_protocol_limit_sees_a_suffix_beyond_the_old_truncation_point() {
        let long_code = CODE_LONG_GROUPS.to_string();
        let field = field_with(&long_code);
        assert!(
            field.error().is_some(),
            "the suffix is still visible beyond 48 chars"
        );
        assert!(field.render().0.contains("-1234"));

        // A long dashed NAME is not a code with a suffix, so it is not blocked
        // even though the conservative display rule hides its alphabetic blob.
        let long_name = CODE_LONG_NAME.to_string();
        let mut field = field_with(&long_name);
        assert!(field.is_secret(), "long all-alpha name stays hidden");
        assert!(field.error().is_none(), "{:?}", field.error());
        assert!(
            field.take_submission().is_some(),
            "hidden is presentation, not refusal"
        );
    }

    #[test]
    fn numeric_suffixes_of_two_or_more_digits_are_bounded_when_over_48() {
        // Four 12-char groups + dashes is already 51 normalized bytes, so any
        // 2+ digit suffix crosses the ceiling. Transfer grammar accepts 2+
        // digits; a 6-digit run must not slip through `norm_code`'s cut either.
        let words = "abcdefghijkl-mnopqrstuvwx-yzabcdefghij-abcdefghijkl";
        for suffix in ["12", "3141", "123456"] {
            let text = format!("{words}-{suffix}");
            let field = field_with(&text);
            assert!(
                field.error().is_some(),
                "suffix {suffix} must be over the normalized limit"
            );
        }
    }

    #[test]
    fn punctuation_and_unicode_wrapping_cannot_hide_an_oversized_code() {
        for text in [
            format!("?{CODE49_GROUPS}"),
            format!("{CODE49_GROUPS}!"),
            format!("\u{2728}{CODE49_GROUPS}\u{2728}"),
            format!("\u{0130}{CODE48_GROUPS}"),
        ] {
            let mut field = field_with(&text);
            // Wrapping punctuation is a separator, so the field may display;
            // that must not waive the normalized length check.
            assert!(
                field.error().is_some(),
                "normalization still sees an over-limit code: {text:?}"
            );
            assert!(field.take_submission().is_none());
        }

        // The same wrapping must not push an exactly-48-byte code over the
        // limit: only the NORMALIZED length decides.
        let text = format!("?{CODE48_GROUPS}!");
        let mut field = field_with(&text);
        assert!(field.error().is_none(), "{:?}", field.error());
        assert!(
            field.take_submission().is_some(),
            "a normalized 48-byte code may submit even while masked"
        );
    }

    #[test]
    fn leading_dashes_are_cleaned_before_the_checked_protocol_boundary() {
        for text in [format!("-{CODE48_GROUPS}"), format!("--{}", &CODE48_GROUPS[1..])] {
            let mut field = field_with(&text);
            assert!(field.error().is_none(), "canonical code is within the limit");
            assert!(field.take_submission().is_some());
        }
    }

    #[test]
    fn sticky_masking_does_not_exempt_an_edited_over_limit_code() {
        let code = CODE49_GROUPS.to_string();
        assert_eq!(code.len(), CODE_LIMIT + 1);
        let mut field = field_with(&code);
        assert!(field.error().is_some());

        // Punctuation is a separator, so this stays a visible over-limit code.
        // Display is irrelevant to the limit: Enter must still be blocked.
        assert!(field.insert("?"));
        assert!(!field.is_secret());
        assert!(
            field.error().is_some(),
            "punctuation must not hide the normalized 49-byte code"
        );
        assert!(field.backspace());
        assert!(
            field.error().is_some(),
            "the over-limit code is still blocked after the edit"
        );
        assert!(field.take_submission().is_none());

        // The reported path: paste invitation material, then delete the
        // recognizable prefix until the remainder is a valid 49-character
        // code. Sticky secrecy must not exempt it.
        let mut field = field_with(&format!("filament-{code}"));
        assert!(field.is_secret());
        assert!(field.error().is_none(), "invitation material is exempt");
        field.home();
        for _ in 0.."filament-".len() {
            field.delete();
        }
        assert_eq!(field.text(), code.as_str());
        assert!(field.is_secret(), "the earlier invitation stays masked");
        assert!(
            field.error().is_some(),
            "the remaining code is over the protocol ceiling"
        );
        assert!(field.take_submission().is_none());

        // The same rule must hold when secrecy arrived from an earlier
        // invitation edit rather than a typed scalar.
        let mut field = field_with(&code);
        field.secret = true;
        assert!(
            field.validate().is_some(),
            "secrecy cannot waive the code ceiling"
        );
    }

    #[test]
    fn padded_but_normalized_48_character_codes_are_accepted() {
        let code48 = CODE48_GROUPS.to_string();
        assert_eq!(code48.len(), CODE_LIMIT);
        let padded = format!("   {code48}   ");
        assert!(padded.len() > CODE_LIMIT, "the raw row is longer than 48");
        let mut field = field_with(&padded);
        assert!(field.error().is_none(), "{:?}", field.error());
        assert!(!field.is_secret());
        assert!(field.take_submission().is_some());

        let code49 = CODE49_GROUPS.to_string();
        assert_eq!(code49.len(), CODE_LIMIT + 1);
        let padded = format!("   {code49}   ");
        let field = field_with(&padded);
        assert!(
            field.error().is_some(),
            "padding cannot hide a 49-character normalized code"
        );
    }

    #[test]
    fn a_masked_long_single_group_is_still_checked_for_a_code_suffix() {
        let text = format!("{}-1234", "a".repeat(80));
        let mut field = field_with(&text);
        assert!(
            field.is_secret(),
            "looks_like_code hides a single group over 64 chars"
        );
        let error = field
            .error()
            .expect("the trailing nameplate still makes this an over-limit code");
        assert!(error.contains("48"), "{error}");
        assert!(field.take_submission().is_none());
    }

    #[test]
    fn separator_spelling_displays_but_opaque_dotted_tokens_stay_hidden() {
        let dotted = field_with("brave.otter.3141");
        assert!(!dotted.is_secret(), "a dotted code must not be masked");
        assert!(dotted.hint().contains("Pairing-code shape"), "{}", dotted.hint());
        assert!(dotted.error().is_none());

        // A JWT-like or base64-like token does not reduce to a code shape.
        for raw in ["eyJhbGciOi.eyJzdWIi.SflKxwRJSM", "abc123.def456.ghi789", "a1b2.c3d4.e5f6"] {
            assert!(field_with(raw).is_secret(), "{raw} must stay hidden");
        }
    }

    #[test]
    fn invitations_and_paths_are_not_blocked_by_the_code_ceiling() {
        let invitation = format!("TLNINV-{}-1234", "A".repeat(60));
        let mut field = field_with(&invitation);
        assert!(field.is_secret());
        assert!(field.error().is_none(), "{:?}", field.error());
        assert!(field.take_submission().is_some());

        let path = format!("/tmp/{}-1234.json", "a".repeat(80));
        let mut field = field_with(&path);
        assert!(!field.is_secret());
        assert!(field.error().is_none(), "{:?}", field.error());
        assert!(field.take_submission().is_some());

        let json = format!("{{\"token\":\"{}-1234\"}}", "a".repeat(80));
        let field = field_with(&json);
        assert!(field.is_secret());
        assert!(field.error().is_none(), "{:?}", field.error());
    }

    #[test]
    fn oversize_input_is_rejected_whole_and_blocks_enter_until_an_edit() {
        let original = "brave-otter-3141";
        let mut field = field_with(original);
        assert!(!field.insert(&"x".repeat(CREDENTIAL_CAP)));
        assert_eq!(
            field.text(),
            original,
            "nothing from the oversized paste is inserted"
        );
        assert!(field.error().unwrap().contains("64 KiB"));
        assert!(field.take_submission().is_none());

        // A cursor move is not an edit and does not unblock.
        field.left();
        assert!(field.error().is_some());
        assert!(field.take_submission().is_none());

        // A real edit clears the block (this buffer is still a valid shape).
        assert!(field.backspace());
        assert!(field.error().is_none());
        assert!(field.take_submission().is_some());
    }

    #[test]
    fn paste_sanitizes_only_terminal_controls_and_preserves_json_whitespace() {
        let field = field_with("a\x1b[2Jb\x03c\r\n\t d\x7f");
        assert_eq!(field.text(), "a[2Jbc\r\n\t d");
        assert_eq!(sanitize_input("\u{0}\u{1b}\u{7f}\u{9b}"), "");
        assert_eq!(
            sanitize_input(" {\n\t\"x\": \"y\"\r\n}"),
            " {\n\t\"x\": \"y\"\r\n}"
        );
    }

    #[test]
    fn paste_is_data_and_insertion_has_no_submit_side_effect() {
        let mut field = FieldState::new();
        assert!(field.take_submission().is_none(), "empty cannot submit");
        assert!(field.insert("brave\notter\r3141\x03\x1b"));
        assert_eq!(field.text(), "brave\notter\r3141");
        assert!(
            field.error().is_none(),
            "the pasted control bytes did not become keys or errors"
        );
        // Insertion only edits: the buffer is still here and can take more
        // text. `take_submission` remains the sole way a value leaves.
        assert!(field.insert("-3141"));
        assert!(
            field.take_submission().is_some(),
            "only the explicit Enter path moves the value out"
        );
    }

    #[test]
    fn a_partial_code_displays_with_a_shape_hint_and_no_secret_claim() {
        let field = field_with("brave-ot");
        assert!(!field.is_secret());
        assert!(field.error().is_none());
        let (shown, _) = field.render();
        assert_eq!(shown, "brave-ot");
        assert!(!shown.contains('*'));
        let hint = field.hint();
        assert!(hint.contains("Pairing code"), "{hint}");
        for claim in ["verified", "authenticated", "trusted", "valid"] {
            assert!(!hint.contains(claim), "hint made an auth claim: {hint}");
        }
    }

    #[test]
    fn a_full_code_displays_and_paths_display_while_unknown_tokens_stay_hidden() {
        let code = field_with("Brave Otter 3141");
        assert!(!code.is_secret());
        assert!(code.render().0.contains("Brave Otter 3141"));
        assert!(code.hint().contains("Pairing-code shape"));

        let path = field_with("  /tmp/invitation.json  ");
        assert!(!path.is_secret());
        assert!(path.render().0.contains("/tmp/invitation.json"));
        assert!(path.hint().contains("File path"));

        let opaque = field_with("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(opaque.is_secret());
        assert!(opaque.render().0.chars().all(|character| character == '*'));
        assert!(!opaque.hint().contains("ghp_"));

        for opaque in [
            "550e8400-e29b-41d4-a716-446655440000",
            "abc-1234567",
            "deadbeefcafebabe",
            "deadbeefcafebabe0123456789abcdef",
        ] {
            let field = field_with(opaque);
            assert!(field.is_secret(), "{opaque}");
            assert!(
                field.render().0.chars().all(|character| character == '*'),
                "{opaque}"
            );
        }
    }

    #[test]
    fn ambiguous_slashes_urls_and_long_alpha_blobs_are_hidden() {
        for text in [
            "YWJj/ZGVm",
            "https://host/?token=SECRET",
            "https://host/invite.json",
            "dir/file",
            ".secret-token",
            "deadbeefcafebabe",
            "deadbeef-cafebabe",
            "abcdefghijklmnop",
            "abcdefghijkl-mnopqrstuvwx-yzabcdefghij",
        ] {
            let field = field_with(text);
            assert!(field.is_secret(), "{text}");
            assert!(
                field.render().0.chars().all(|character| character == '*'),
                "{text}"
            );
        }
    }

    #[test]
    fn explicit_paths_and_known_extensions_still_display() {
        for text in [
            "/tmp/invite",
            "./invite",
            "../invite",
            "~/invite",
            "C:\\tmp\\invite",
            "C:/tmp/invite",
            "\\\\server\\share\\invite",
            "invite.json",
            ".env",
        ] {
            let field = field_with(text);
            assert!(looks_like_path(text), "{text}");
            assert!(!field.is_secret(), "{text}");
        }
    }

    #[test]
    fn transfer_codes_name_the_verb_that_accepts_them_without_auth_claims() {
        let field = field_with("brave-otter-314");
        let hint = field.hint();
        assert!(hint.contains("tunlion receive"), "{hint}");
        assert!(!hint.contains("pairing-code shape"), "{hint}");
    }

    #[test]
    fn cursor_moves_by_character_and_ctrl_u_is_the_only_full_reset() {
        let mut field = field_with("abé");
        field.left();
        assert_eq!(field.cursor(), 2); // before 'é'
        field.left();
        assert_eq!(field.cursor(), 1);
        field.right();
        assert_eq!(field.cursor(), 2);
        field.end();
        assert_eq!(field.cursor(), 4);
        field.home();
        field.delete();
        assert_eq!(field.text(), "bé");
        field.clear();
        assert_eq!(field.text(), "");
        assert_eq!(field.cursor(), 0);
        assert!(field.error().is_none());
        assert!(!field.is_secret());
    }

    /// PTY driver for the external runner. It prints only the outcome KIND and
    /// a length; never the credential itself. `read_input` is the production
    /// entry point, not a test-only replica.
    #[test]
    #[ignore = "requires a PTY; driven by the join runner"]
    fn pty_driver() {
        let outcome = read_input().expect("read join input");
        match outcome {
            InputOutcome::Submitted(value) => println!("JOIN:submitted len={}", value.len()),
            InputOutcome::Cancelled => println!("JOIN:cancelled"),
            InputOutcome::Interrupted => println!("JOIN:interrupted"),
        }
        let _ = std::io::stdout().flush();
    }
}
