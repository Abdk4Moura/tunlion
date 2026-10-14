//! `tunlion demo`: a guided tour that plays entirely on this machine.
//!
//! Every peer, code and output line in the tour is scripted. Nothing here
//! opens a socket, reads the user's identity or writes their state:
//! `async_main` calls [`isolate`] first, which points TUNLION_CONFIG_DIR at a
//! path under the temp directory that is never created, and skips its
//! start-up housekeeping (the permission sweep writes a stamp file), so the
//! real config directory is neither read nor written.
//!
//! The commands shown are the real ones. A unit test parses each of them with
//! the real command-line definition, so the tour cannot drift into showing a
//! verb or a flag the binary no longer has.
//!
//! Look and motion come from the shared design palette in `style.rs`: the
//! tunnel mark with its cursor block, the accent, the "pulse" (the cursor
//! squashing on a |..|| rhythm) while waiting on the other side, and the
//! "knock" (three hops) when something waits on you. Motion stops under
//! --reduced-motion or TUNLION_REDUCED_MOTION, and on any terminal that cannot
//! redraw in place.

use anyhow::Result;
use std::io::{IsTerminal, Write};
use crate::style;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- script --

/// One beat of a step.
#[derive(Debug)]
pub(crate) enum Act {
    /// A short plain explanation, wrapped to the terminal.
    Say(&'static str),
    /// A command the user runs on `on` (a device name shown in the prompt).
    Run { on: &'static str, cmd: &'static str },
    /// A line typed for the user inside a remote shell (`prompt` is shown as is).
    Remote { prompt: &'static str, cmd: &'static str },
    /// One output line. Leading markers: `OK ` (success glyph), `ERR ` (error,
    /// red), `~ ` (quiet), `* ` (accent), `$ ` (a command in the text).
    /// `{.}` becomes a middle dot where the terminal can show one.
    Out(&'static str),
    /// Waiting on the other side: the pulse, for `ms` milliseconds.
    Wait(&'static str, u32),
    /// A transfer progress bar that fills in `ms` milliseconds.
    Bar(&'static str, u32),
    /// Time passes in the story.
    Later(&'static str),
}

pub(crate) struct Step {
    pub(crate) title: &'static str,
    pub(crate) acts: &'static [Act],
}

use Act::*;

pub(crate) static STEPS: &[Step] = &[
    Step {
        title: "Send a file with a code",
        acts: &[
            Say("Send a file to anyone. You get a short code you can read out loud. No account, no upload: the file goes straight from this machine to theirs."),
            Run { on: "laptop", cmd: "tunlion send holiday-photos.zip --code" },
            Out("send: holiday-photos.zip (2.9 MiB)"),
            Out(""),
            Out("*  code   amber-otter-4417"),
            Out("   terminal: tunlion receive amber-otter-4417"),
            Out("   browser:  tunlion.autumated.com (receive with code)"),
            Out("~  one claim {.} expires in 10 min {.} end-to-end encrypted"),
            Out(""),
            Wait("waiting for someone to claim the code", 2600),
            Out("   code claimed, connecting..."),
            Out("OK friend-laptop"),
            Out("   authenticated, sending"),
            Bar("holiday-photos.zip  2.9 MiB", 1800),
            Out("OK holiday-photos.zip  2.9 MiB {.} 22.4 MiB/s"),
            Out("   holiday-photos.zip delivered + verified (whole-file sha256 matched)"),
            Out("done."),
            Say("Your friend typed the code into tunlion receive, or into tunlion.autumated.com in any browser. The code works once, then it is gone."),
        ],
    },
    Step {
        title: "Receive on the other side",
        acts: &[
            Say("This is what your friend saw. A code is already consent, so there is nothing to confirm."),
            Run { on: "friend-laptop", cmd: "tunlion receive amber-otter-4417" },
            Out("OK code accepted, joining sender"),
            Out("OK laptop"),
            Out("   authenticated, receiving"),
            Bar("holiday-photos.zip  2.9 MiB", 1500),
            Out("OK holiday-photos.zip  2.9 MiB {.} 22.8 MiB/s"),
            Out("   -> ~/Tunlion/holiday-photos.zip"),
            Out("   holiday-photos.zip verified (whole-file sha256 matched), acked"),
            Out("done (1 file)."),
        ],
    },
    Step {
        title: "Pair two of your own devices",
        acts: &[
            Say("Pair once and your devices remember each other. After that they find each other by name, with no codes."),
            Run { on: "laptop", cmd: "tunlion add" },
            Out("*      MUSHY-BEAGLE-2643"),
            Out("   on the other device: tunlion join mushy-beagle-2643"),
            Out("~  one claim {.} expires in 10 min {.} no key ever crosses the server"),
            Wait("waiting for the other device", 1400),
            Run { on: "web-vps", cmd: "tunlion join mushy-beagle-2643" },
            Out("   claiming mushy-beagle-2643..."),
            Out("OK code accepted, connecting"),
            Out("OK laptop mutually remembered, verified end-to-end"),
            Out("   remembered as 'laptop' (rename: tunlion devices rename laptop <name>)"),
            Say("Keep the server reachable in the background:"),
            Run { on: "web-vps", cmd: "tunlion up --detach" },
            Out("OK daemon detached and serving (pid 4182)"),
        ],
    },
    Step {
        title: "Send to a device you know",
        acts: &[
            Say("Between your own devices there is no code. Name the device."),
            Run { on: "laptop", cmd: "tunlion send report.pdf --to web-vps" },
            Out("send: report.pdf (1.9 MiB)"),
            Out("OK web-vps {.} direct"),
            Bar("report.pdf  1.9 MiB", 1200),
            Out("OK report.pdf  1.9 MiB {.} 31.0 MiB/s"),
            Out("   report.pdf delivered + verified (whole-file sha256 matched)"),
            Out("done."),
        ],
    },
    Step {
        title: "Open a shell on your server",
        acts: &[
            Say("Remote shell is off until you allow it, one device at a time. On the server, let your laptop in:"),
            Run { on: "web-vps", cmd: "tunlion grant laptop shell" },
            Out("granted 'shell' to 'laptop'. OWNER-EQUIVALENT: they can act as you"),
            Out("through `tunlion shell`, `tunlion exec` and `tunlion shell --ssh`."),
            Say("Now from the laptop. No sshd and no open port needed:"),
            Run { on: "laptop", cmd: "tunlion shell web-vps" },
            Out("~tunlion: tunnel up to 'web-vps' {.} direct"),
            Remote { prompt: "sam@web-vps:~$ ", cmd: "uptime" },
            Out(" 14:02:11 up 41 days,  3:12,  1 user,  load average: 0.08, 0.05, 0.01"),
            Remote { prompt: "sam@web-vps:~$ ", cmd: "exit" },
            Out("~tunlion: session closed"),
        ],
    },
    Step {
        title: "Run one command",
        acts: &[
            Say("For a single command, exec passes the arguments exactly and returns the remote exit code. Scripts and AI agents use this."),
            Run { on: "laptop", cmd: "tunlion exec web-vps -- df -h /" },
            Out("Filesystem      Size  Used Avail Use% Mounted on"),
            Out("/dev/vda1        78G   31G   47G  40% /"),
        ],
    },
    Step {
        title: "Reach a port on the server",
        acts: &[
            Say("The database on the server listens only on its own localhost. Bring it to yours:"),
            Run { on: "laptop", cmd: "tunlion forward web-vps:5432" },
            Out("tunlion: ready - 127.0.0.1:5432 -> web-vps:5432 over the daemon's"),
            Out("live direct link"),
            Say("Your tools now connect to localhost:5432 as if the database were here. Ctrl-C stops the forward."),
        ],
    },
    Step {
        title: "Access that ends by itself",
        acts: &[
            Say("A guest needs a shell for a short job. Give them an invitation with an end time. The end time is enforced everywhere, even in a session that is still open."),
            Run { on: "laptop", cmd: "tunlion add guest --allow transfer,shell --expires 2m --out guest.txt" },
            Out("OK invitation written to guest.txt"),
            Out("   Anyone who reads that file can join until it is used or expires."),
            Out("   next: copy it to the other device, then run there: tunlion join guest.txt"),
            Run { on: "guest", cmd: "tunlion join guest.txt" },
            Out("OK invitation loaded (caps: transfer, shell)"),
            Out("OK joined as 'guest'"),
            Run { on: "guest", cmd: "tunlion exec laptop -- sh -c \"while true; do date +%T; sleep 30; done\"" },
            Out("07:13:37"),
            Out("07:14:07"),
            Out("07:14:37"),
            Later("two minutes after the invitation was made"),
            Out("ERR Error: 'laptop' refused exec: access expired at 07:14:58 UTC: the invitation"),
            Out("ERR that admitted this device has ended"),
            Say("The open session was cut the second the invitation ended, and every later attempt is refused. Only the owner can let the guest back in."),
        ],
    },
    Step {
        title: "Cut a device off",
        acts: &[
            Say("Lost a phone? Cut it off. It is refused from that moment, and its open sessions close within seconds."),
            Run { on: "laptop", cmd: "tunlion devices revoke old-phone" },
            Out("durably revoke old-phone (it will stop being recognized and cannot"),
            Out("rejoin until restored)? [y/N] y"),
            Out("revoked 'old-phone'; it is denied on reconnect and a fresh invitation"),
            Out("cannot revive it (only `tunlion devices restore old-phone` can)"),
        ],
    },
    Step {
        title: "See every device at a glance",
        acts: &[
            Say("One list shows each device, whether it is online, what it can do here, and until when."),
            Run { on: "laptop", cmd: "tunlion devices" },
            Out("*  FLEET  /  your devices, permissive within scope"),
            Out("     web-vps      online   inbox            cert expires in 90d"),
            Out("     guest        idle     no access (expired)  expired 07:14 UTC"),
            Out("     old-phone    revoked  refused on reconnect"),
            Out(""),
            Out("~  This is a local index; each device's own capability list is authoritative."),
        ],
    },
];

/// Shown after the last step.
const OUTRO: &[&str] = &[
    "That's the tour. To start for real:",
    "",
    "$ tunlion init                   set up this device",
    "$ tunlion send <file> --code     send something now",
    "$ tunlion add                    pair another of your devices",
    "$ tunlion skill install          teach your AI agent tunlion",
    "",
    "Or open tunlion.autumated.com on any device. Nothing to install.",
];

// ------------------------------------------------------------ invocation --

/// Global options that take a value, so their value is not mistaken for the
/// subcommand when deciding whether this process is `tunlion demo`.
const VALUE_FLAGS: &[&str] = &["--server", "--name-as", "--color"];

/// Whether argv names the `demo` subcommand. Pure.
pub(crate) fn invoked(argv: &[String]) -> bool {
    let mut it = argv.iter().skip(1);
    while let Some(t) = it.next() {
        if VALUE_FLAGS.contains(&t.as_str()) {
            it.next();
            continue;
        }
        if t.starts_with('-') {
            continue;
        }
        return t == "demo";
    }
    false
}

static TEMP_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Point this process's config directory at a path under the temp directory,
/// before anything can read the real one. The path is never created: a
/// missing directory reads as an empty state, and nothing in the demo writes.
pub(crate) fn isolate() {
    let dir = std::env::temp_dir().join(format!("tunlion-demo-{}", std::process::id()));
    let _ = TEMP_DIR.set(dir.clone());
    // SAFETY: called at the top of async_main, before this process spawns any
    // task of its own; the same pattern sets TUNLION_NAME there.
    unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
}

/// Whether [`isolate`] ran in this process.
pub(crate) fn isolated() -> bool {
    TEMP_DIR.get().is_some()
}

/// Remove the isolated config path if anything did create it. Idempotent.
pub(crate) fn cleanup() {
    if let Some(d) = TEMP_DIR.get() {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Leave the terminal as we found it: cooked mode, cursor shown, colors off.
/// A pipe gets nothing: it was never a terminal to restore.
fn restore_terminal() {
    if !std::io::stdout().is_terminal() {
        return;
    }
    let _ = crossterm::terminal::disable_raw_mode();
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b[0m\x1b[?25h");
    let _ = out.flush();
}

// ----------------------------------------------------------------- style --

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Plain,
    Strong,
    Quiet,
    Ok,
    Bad,
    Accent,
    Code,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Style {
    pub(crate) color: bool,
    pub(crate) depth: style::Depth,
    pub(crate) bg: style::Bg,
    pub(crate) unicode: bool,
    /// The terminal can redraw a line in place.
    pub(crate) live: bool,
    /// Animations play (live and not reduced).
    pub(crate) motion: bool,
}

impl Style {
    fn detect(reduced: bool) -> Style {
        let term = std::env::var("TERM").unwrap_or_default();
        let tty = std::io::stdout().is_terminal();
        let live = tty && term != "dumb";
        let var = |k: &str| std::env::var(k).ok();
        let reduced = reduced || style::reduced_motion_from(var("TUNLION_REDUCED_MOTION").as_deref());
        Style {
            color: crate::ui::stdout_color(),
            depth: style::depth_from(var("COLORTERM").as_deref(), &term),
            bg: style::bg_from(var("TUNLION_THEME").as_deref(), var("COLORFGBG").as_deref()),
            unicode: crate::ui::caps().unicode,
            live,
            motion: live && !reduced,
        }
    }

    /// Plain text, no color, no motion: what a pipe or a test gets.
    #[cfg(test)]
    fn plain() -> Style {
        Style {
            color: false,
            depth: style::Depth::Ansi256,
            bg: style::Bg::Unknown,
            unicode: false,
            live: false,
            motion: false,
        }
    }

    /// The shared design palette (`style.rs`) for each tone.
    fn sgr(&self, t: Tone) -> String {
        let (role, bold) = match t {
            Tone::Plain => return String::new(),
            Tone::Strong => (style::Role::Strong, true),
            Tone::Quiet => (style::Role::Sub, false),
            Tone::Ok => (style::Role::Ok, false),
            Tone::Bad => (style::Role::Bad, false),
            Tone::Accent => (style::Role::Accent, true),
            Tone::Code => (style::Role::Accent, false),
        };
        style::sgr(role, bold, self.depth, self.bg)
    }

    pub(crate) fn paint(&self, t: Tone, s: &str) -> String {
        if !self.color || t == Tone::Plain || s.is_empty() {
            return s.to_string();
        }
        format!("{}{s}\x1b[0m", self.sgr(t))
    }

    fn dot(&self) -> &'static str {
        if self.unicode { "·" } else { "-" }
    }
    fn ok_glyph(&self) -> &'static str {
        if self.unicode { "✓" } else { "ok" }
    }
    fn err_glyph(&self) -> &'static str {
        if self.unicode { "✗" } else { "x" }
    }
    fn rule(&self) -> &'static str {
        if self.unicode { "─" } else { "-" }
    }
}

// ---------------------------------------------------------------- motion --

/// Which motif a cursor block shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Motion {
    /// At rest (no motion, or reduced motion).
    Rest,
    /// Waiting on the other side: the pulse.
    Pulse(u128),
    /// Waiting on you: the knock.
    Knock(u128),
}

/// The cursor block for a motif frame, from the shared palette's motion. Pure.
fn block(unicode: bool, m: Motion) -> String {
    match m {
        Motion::Rest => style::pulse_frame(0, unicode, true),
        Motion::Pulse(ms) => style::pulse_frame(ms, unicode, false),
        Motion::Knock(ms) => style::knock_frame(ms, unicode, false),
    }
    .to_string()
}

// ------------------------------------------------------------------ text --

/// Greedy word wrap to `width` columns, each line prefixed with `indent`. Pure.
pub(crate) fn wrap(text: &str, width: usize, indent: &str) -> Vec<String> {
    let room = width.saturating_sub(indent.chars().count()).max(20);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let len = cur.chars().count();
        if len > 0 && len + 1 + word.chars().count() > room {
            lines.push(format!("{indent}{cur}"));
            cur.clear();
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(format!("{indent}{cur}"));
    }
    lines
}

/// Split a command line the way a shell would for these simple cases:
/// whitespace separates, double quotes group. Pure. Used by the test that
/// parses every command the tour shows.
#[cfg(test)]
pub(crate) fn split_command(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in cmd.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Typed text matches the command, ignoring repeated spaces at the ends and
/// between words. Pure.
pub(crate) fn same_command(typed: &str, cmd: &str) -> bool {
    typed.split_whitespace().eq(cmd.split_whitespace())
}

// ---------------------------------------------------------------- player --

/// Why a step stopped early.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Esc: go to the next step.
    Skip,
    /// Ctrl-C.
    Interrupt,
    /// End of input in line mode.
    Eof,
}

#[derive(Debug, PartialEq, Eq)]
enum Key {
    Enter,
    Tab,
    Backspace,
    Esc,
    CtrlC,
    CtrlU,
    Char(char),
    Other,
}

/// How input arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// --auto: nothing is read.
    None,
    /// A terminal in raw mode: keys one at a time, ghost text, animation.
    Keys,
    /// A terminal that cannot redraw (TERM=dumb): whole lines.
    Lines,
}

pub(crate) struct Opts {
    pub(crate) auto: bool,
    pub(crate) step: Option<usize>,
    pub(crate) speed: f64,
    pub(crate) reduced_motion: bool,
}

pub(crate) struct Player<W: Write> {
    out: W,
    style: Style,
    input: Input,
    speed: f64,
    width: usize,
    /// Rest of this step plays without pauses (Enter during playback).
    fast: bool,
    /// Nothing has been printed since the step header (which ends in a blank).
    fresh: bool,
    /// The keys hint has been shown.
    hinted: bool,
}

impl<W: Write> Player<W> {
    pub(crate) fn new(out: W, style: Style, auto: bool, speed: f64, width: usize) -> Self {
        let input = if auto {
            Input::None
        } else if style.live {
            Input::Keys
        } else {
            Input::Lines
        };
        Player { out, style, input, speed, width: width.clamp(40, 80), fast: false, fresh: true, hinted: false }
    }

    fn nl(&self) -> &'static str {
        if self.input == Input::Keys { "\r\n" } else { "\n" }
    }

    fn line(&mut self, s: &str) {
        let nl = self.nl();
        let _ = write!(self.out, "{s}{nl}");
        let _ = self.out.flush();
    }

    fn redraw(&mut self, s: &str) {
        let _ = write!(self.out, "\r\x1b[2K{s}");
        let _ = self.out.flush();
    }

    fn paint(&self, t: Tone, s: &str) -> String {
        self.style.paint(t, s)
    }

    /// Wait `ms` scaled by speed. In key mode this listens: Enter or space
    /// fast-forwards the step, Esc skips it, Ctrl-C quits.
    fn pause(&mut self, ms: u32) -> Result<(), Stop> {
        if self.fast || self.speed <= 0.0 || ms == 0 {
            return Ok(());
        }
        let total = Duration::from_secs_f64(ms as f64 / 1000.0 / self.speed);
        if self.input != Input::Keys {
            std::thread::sleep(total);
            return Ok(());
        }
        let end = Instant::now() + total;
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            match read_key(left) {
                Some(Key::CtrlC) => return Err(Stop::Interrupt),
                Some(Key::Esc) => return Err(Stop::Skip),
                Some(Key::Enter) | Some(Key::Char(' ')) => {
                    self.fast = true;
                    return Ok(());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn banner(&mut self) {
        let s = self.style;
        let (top, side) = if s.unicode { ("╭───╮", "│") } else { (".---.", "|") };
        let b = self.paint(Tone::Accent, &block(s.unicode, Motion::Rest));
        self.line("");
        self.line(&format!("  {top}"));
        let title = self.paint(Tone::Strong, "tunlion demo");
        self.line(&format!("  {side} {b} {side}   {title}"));
        let sub = self.paint(Tone::Quiet, "a guided tour, played on this computer only");
        self.line(&format!("  {side} {b} {side}   {sub}"));
        self.line("");
        let how = match self.input {
            Input::None => "Playing the whole tour. Nothing here touches the network, an account or your files. Ctrl-C stops it.",
            Input::Keys => "Each step shows a real command. Type it, or press Enter and it is typed for you. Nothing here touches the network, an account or your files.",
            Input::Lines => "Each step shows a real command. Type it and press Enter, or press Enter on an empty line. Type skip to skip a step. Nothing here touches the network or your files.",
        };
        for l in wrap(how, self.width, "  ") {
            let l = self.paint(Tone::Quiet, &l);
            self.line(&l);
        }
    }

    fn header(&mut self, i: usize, n: usize, title: &str) {
        let s = self.style;
        let count = format!("{}/{}", i + 1, n);
        let lead = format!("{} ", s.rule().repeat(2));
        let used = 2 + lead.chars().count() + count.chars().count() + 2 + title.chars().count() + 1;
        let tail = s.rule().repeat(self.width.saturating_sub(used).max(3));
        let line = format!(
            "  {}{}  {} {}",
            self.paint(Tone::Quiet, &lead),
            self.paint(Tone::Accent, &count),
            self.paint(Tone::Strong, title),
            self.paint(Tone::Quiet, &tail)
        );
        self.line("");
        self.line(&line);
        self.line("");
    }

    fn say(&mut self, text: &str) -> Result<(), Stop> {
        // Set an explanation apart from the output above it.
        if !self.fresh {
            self.line("");
        }
        for l in wrap(text, self.width, "  ") {
            let l = self.paint(Tone::Quiet, &l);
            self.line(&l);
        }
        self.line("");
        self.pause(700)
    }

    /// One output line, with its markers resolved.
    pub(crate) fn render_out(&self, raw: &str) -> String {
        let s = self.style;
        let text = raw.replace("{.}", s.dot());
        if let Some(rest) = text.strip_prefix("OK ") {
            format!("  {} {rest}", self.paint(Tone::Ok, s.ok_glyph()))
        } else if let Some(rest) = text.strip_prefix("ERR ") {
            self.paint(Tone::Bad, &format!("{} {rest}", s.err_glyph()))
        } else if let Some(rest) = text.strip_prefix('~') {
            self.paint(Tone::Quiet, rest)
        } else if let Some(rest) = text.strip_prefix('*') {
            self.paint(Tone::Accent, rest)
        } else if let Some(rest) = text.strip_prefix("$ ") {
            // A command in the text: the command in the code tone, its note quiet.
            let (cmd, note) = rest.split_at(rest.find("  ").unwrap_or(rest.len()));
            format!("  {}{}", self.paint(Tone::Code, cmd), self.paint(Tone::Quiet, note))
        } else {
            text
        }
    }

    fn out_line(&mut self, raw: &str) -> Result<(), Stop> {
        let l = self.render_out(raw);
        self.line(&l);
        self.pause(90)
    }

    fn prompt(&self, on: &str, frame: Motion) -> String {
        format!(
            "{} {} $ ",
            self.paint(Tone::Accent, &block(self.style.unicode, frame)),
            self.paint(Tone::Quiet, on)
        )
    }

    /// Type `text` after `prefix` character by character.
    fn type_out(&mut self, prefix: &str, text: &str) -> Result<(), Stop> {
        if self.speed <= 0.0 || self.fast || !self.style.live {
            let t = self.paint(Tone::Strong, text);
            self.line(&format!("{prefix}{t}"));
            return Ok(());
        }
        let _ = write!(self.out, "{prefix}");
        for c in text.chars() {
            let ch = self.paint(Tone::Strong, &c.to_string());
            let _ = write!(self.out, "{ch}");
            let _ = self.out.flush();
            self.pause(28)?;
        }
        let nl = self.nl();
        let _ = write!(self.out, "{nl}");
        let _ = self.out.flush();
        self.pause(250)
    }

    fn run_cmd(&mut self, on: &str, cmd: &str) -> Result<(), Stop> {
        self.fast = false;
        match self.input {
            Input::None => {
                let p = self.prompt(on, Motion::Rest);
                self.pause(400)?;
                self.type_out(&p, cmd)
            }
            Input::Lines => self.run_lines(on, cmd),
            Input::Keys => self.run_keys(on, cmd),
        }
    }

    fn run_lines(&mut self, on: &str, cmd: &str) -> Result<(), Stop> {
        let hint = format!("  type: {cmd}   (or press Enter)");
        self.line(&hint);
        loop {
            let p = format!("{on} $ ");
            let _ = write!(self.out, "{p}");
            let _ = self.out.flush();
            let mut buf = String::new();
            match std::io::stdin().read_line(&mut buf) {
                Ok(0) | Err(_) => return Err(Stop::Eof),
                Ok(_) => {}
            }
            let typed = buf.trim();
            if typed.is_empty() {
                self.line(&format!("{p}{cmd}"));
                return Ok(());
            }
            if typed == "skip" {
                return Err(Stop::Skip);
            }
            if same_command(typed, cmd) {
                return Ok(());
            }
            self.line(&format!("  not quite; type: {cmd}   (or press Enter)"));
        }
    }

    fn input_line(&self, on: &str, cmd: &str, buf: &str, frame: Motion) -> (String, usize) {
        let mut typed = String::new();
        let want: Vec<char> = cmd.chars().collect();
        let mut matches = true;
        for (i, c) in buf.chars().enumerate() {
            // After the first wrong character everything is wrong: a later
            // character that happens to line up is not progress.
            if matches && want.get(i) == Some(&c) {
                typed.push_str(&self.paint(Tone::Strong, &c.to_string()));
            } else {
                matches = false;
                typed.push_str(&self.paint(Tone::Bad, &c.to_string()));
            }
        }
        // Without color a ghost would look typed, so it is left out and the
        // command is shown on its own line instead (run_keys).
        let ghost: String = if matches && self.style.color {
            want.iter().skip(buf.chars().count()).collect()
        } else {
            String::new()
        };
        let back = ghost.chars().count();
        let ghost = self.paint(Tone::Quiet, &ghost);
        (format!("{}{typed}{ghost}", self.prompt(on, frame)), back)
    }

    fn run_keys(&mut self, on: &str, cmd: &str) -> Result<(), Stop> {
        if !self.hinted {
            self.hinted = true;
            let h = self.paint(Tone::Quiet, "  Enter types it for you · Tab completes · Esc skips this step · Ctrl-C quits");
            let h = if self.style.unicode { h } else { h.replace('·', "-") };
            self.line(&h);
        }
        if !self.style.color {
            self.line(&format!("  type: {cmd}"));
        }
        let mut buf = String::new();
        let start = Instant::now();
        let mut last_glyph = String::new();
        let mut dirty = true;
        loop {
            let frame = if self.style.motion { Motion::Knock(start.elapsed().as_millis()) } else { Motion::Rest };
            let glyph = block(self.style.unicode, frame);
            if dirty || glyph != last_glyph {
                let (l, back) = self.input_line(on, cmd, &buf, frame);
                self.redraw(&l);
                if back > 0 {
                    let _ = write!(self.out, "\x1b[{back}D");
                    let _ = self.out.flush();
                }
                last_glyph = glyph;
                dirty = false;
            }
            let Some(k) = read_key(Duration::from_millis(40)) else { continue };
            dirty = true;
            match k {
                Key::CtrlC => return Err(Stop::Interrupt),
                Key::Esc => {
                    self.line("");
                    return Err(Stop::Skip);
                }
                Key::Tab => buf = cmd.to_string(),
                Key::Backspace => {
                    buf.pop();
                }
                Key::CtrlU => buf.clear(),
                Key::Char(c) => buf.push(c),
                Key::Enter if buf.trim().is_empty() => {
                    let p = self.prompt(on, Motion::Rest);
                    self.redraw("");
                    return self.type_out(&p, cmd);
                }
                Key::Enter if same_command(&buf, cmd) => {
                    let (l, _) = self.input_line(on, cmd, cmd, Motion::Rest);
                    self.redraw(&l);
                    self.line("");
                    return Ok(());
                }
                Key::Enter => {
                    // Keep what they typed; say how to get unstuck.
                    self.redraw("");
                    let h = self.paint(Tone::Quiet, "  not quite: Tab completes it, or clear the line and press Enter");
                    self.line(&h);
                }
                Key::Other => dirty = false,
            }
        }
    }

    fn wait(&mut self, label: &str, ms: u32) -> Result<(), Stop> {
        let scaled = if self.speed <= 0.0 { 0.0 } else { ms as f64 / self.speed };
        if !self.style.motion || self.fast || scaled < 1.0 {
            let l = format!("  {} {}", self.paint(Tone::Accent, &block(self.style.unicode, Motion::Rest)), self.paint(Tone::Quiet, label));
            self.line(&l);
            return self.pause(ms);
        }
        let start = Instant::now();
        let total = Duration::from_secs_f64(scaled / 1000.0);
        while start.elapsed() < total {
            let f = Motion::Pulse(start.elapsed().as_millis());
            let l = format!("  {} {}", self.paint(Tone::Accent, &block(self.style.unicode, f)), self.paint(Tone::Quiet, label));
            self.redraw(&l);
            self.pause_raw(40)?;
            if self.fast {
                break;
            }
        }
        self.redraw("");
        Ok(())
    }

    /// An unscaled frame delay (animation ticks are wall time).
    fn pause_raw(&mut self, ms: u32) -> Result<(), Stop> {
        let saved = self.speed;
        self.speed = 1.0;
        let r = self.pause(ms);
        self.speed = saved;
        r
    }

    fn bar(&mut self, label: &str, ms: u32) -> Result<(), Stop> {
        let scaled = if self.speed <= 0.0 { 0.0 } else { ms as f64 / self.speed };
        if !self.style.live || self.fast || scaled < 1.0 {
            return Ok(());
        }
        let (full, empty) = if self.style.unicode { ("█", "░") } else { ("#", "-") };
        let start = Instant::now();
        let total = Duration::from_secs_f64(scaled / 1000.0);
        loop {
            let p = (start.elapsed().as_secs_f64() / total.as_secs_f64()).min(1.0);
            let n = (p * 24.0).round() as usize;
            let bar = format!("{}{}", full.repeat(n), empty.repeat(24 - n));
            let l = format!("  {} {:>3}%  {label}", self.paint(Tone::Accent, &bar), (p * 100.0).round() as u32);
            self.redraw(&l);
            if p >= 1.0 || self.fast {
                break;
            }
            self.pause_raw(40)?;
        }
        self.redraw("");
        Ok(())
    }

    fn later(&mut self, text: &str) -> Result<(), Stop> {
        let d = if self.style.unicode { "···" } else { "..." };
        let l = self.paint(Tone::Quiet, &format!("  {d} {text} {d}"));
        self.pause(500)?;
        self.line(&l);
        self.pause(900)
    }

    fn act(&mut self, a: &Act) -> Result<(), Stop> {
        let r = self.act_inner(a);
        self.fresh = matches!(a, Say(_)) && r.is_ok();
        r
    }

    fn act_inner(&mut self, a: &Act) -> Result<(), Stop> {
        match a {
            Say(t) => self.say(t),
            Run { on, cmd } => self.run_cmd(on, cmd),
            Remote { prompt, cmd } => {
                self.pause(500)?;
                self.type_out(prompt, cmd)
            }
            Out(l) => self.out_line(l),
            Wait(l, ms) => self.wait(l, *ms),
            Bar(l, ms) => self.bar(l, *ms),
            Later(t) => self.later(t),
        }
    }

    /// Between steps: Enter (or Esc) goes on.
    fn next_step(&mut self) -> Result<(), Stop> {
        match self.input {
            Input::None => self.pause(1400),
            Input::Lines => {
                let _ = write!(self.out, "  Press Enter for the next step ");
                let _ = self.out.flush();
                let mut buf = String::new();
                match std::io::stdin().read_line(&mut buf) {
                    Ok(0) | Err(_) => Err(Stop::Eof),
                    Ok(_) => Ok(()),
                }
            }
            Input::Keys => {
                let h = self.paint(Tone::Quiet, "  Enter: next step   Ctrl-C: quit");
                self.line("");
                let _ = write!(self.out, "{h}");
                let _ = self.out.flush();
                loop {
                    match read_key(Duration::from_millis(200)) {
                        Some(Key::CtrlC) => return Err(Stop::Interrupt),
                        Some(Key::Enter) | Some(Key::Esc) | Some(Key::Char(' ')) => {
                            self.redraw("");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Play the tour from step `from` (0-based). Ok at the end of the tour.
    pub(crate) fn play(&mut self, from: usize) -> Result<(), Stop> {
        self.banner();
        let n = STEPS.len();
        for (i, step) in STEPS.iter().enumerate().skip(from) {
            self.header(i, n, step.title);
            self.fast = false;
            self.fresh = true;
            let mut skipped = false;
            for a in step.acts {
                match self.act(a) {
                    Ok(()) => {}
                    Err(Stop::Skip) => {
                        skipped = true;
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            if skipped {
                let l = self.paint(Tone::Quiet, "  (skipped)");
                self.line(&l);
                continue;
            }
            if i + 1 < n {
                self.next_step()?;
            }
        }
        self.line("");
        for l in OUTRO {
            let l = if l.starts_with("$ ") { self.render_out(l) } else { format!("  {l}") };
            self.line(&l);
        }
        self.line("");
        Ok(())
    }
}

/// One key within `timeout`, or None. Raw mode must be on.
fn read_key(timeout: Duration) -> Option<Key> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    if !event::poll(timeout).ok()? {
        return None;
    }
    let Event::Key(k) = event::read().ok()? else { return Some(Key::Other) };
    if k.kind == KeyEventKind::Release {
        return Some(Key::Other);
    }
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    Some(match k.code {
        // #203: in raw mode Ctrl-C may arrive as the bare 0x03 byte.
        KeyCode::Char('c') if ctrl => Key::CtrlC,
        KeyCode::Char('\u{3}') => Key::CtrlC,
        KeyCode::Char('u') if ctrl => Key::CtrlU,
        KeyCode::Char('d') if ctrl => Key::CtrlC,
        KeyCode::Enter => Key::Enter,
        KeyCode::Tab => Key::Tab,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Esc => Key::Esc,
        KeyCode::Char(c) if !ctrl => Key::Char(c),
        _ => Key::Other,
    })
}

// ------------------------------------------------------------------ verb --

/// `tunlion demo`.
pub(crate) async fn demo_cmd(opts: Opts) -> Result<()> {
    let n = STEPS.len();
    if let Some(s) = opts.step {
        if s == 0 || s > n {
            crate::bail_usage!("--step takes a number from 1 to {n}");
        }
    }
    if !opts.speed.is_finite() || opts.speed < 0.0 {
        crate::bail_usage!("--speed takes a number of 0 or more (1 is normal pace, 0 plays without pauses)");
    }
    let interactive_ok = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !opts.auto && !interactive_ok {
        crate::bail_usage!(
            "The demo is an interactive tour and needs a terminal. To play it without input (for a recording or a pipe), run: tunlion demo --auto"
        );
    }
    let style = Style::detect(opts.reduced_motion);
    let width = crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(80);
    let keys = !opts.auto && style.live;
    // Ctrl-C outside raw mode (auto and line mode) and SIGTERM: put the
    // terminal back and leave with the shell's codes for those signals.
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            restore_terminal();
            cleanup();
            std::process::exit(crate::exit_codes::INTERRUPTED);
        }
    });
    tokio::spawn(async {
        crate::platform::terminate_requested().await;
        restore_terminal();
        cleanup();
        std::process::exit(crate::exit_codes::TERMINATED);
    });
    let from = opts.step.map(|s| s - 1).unwrap_or(0);
    let (auto, speed) = (opts.auto, opts.speed);
    let played = tokio::task::spawn_blocking(move || {
        if keys && crossterm::terminal::enable_raw_mode().is_err() {
            return Err(Stop::Eof);
        }
        let mut p = Player::new(std::io::stdout(), style, auto, speed, width);
        p.play(from)
    })
    .await;
    restore_terminal();
    cleanup();
    match played {
        Ok(Ok(())) | Ok(Err(Stop::Eof)) | Ok(Err(Stop::Skip)) => Ok(()),
        Ok(Err(Stop::Interrupt)) => {
            // End the tour's last line; it is the tour's own stdout, not a log.
            let _ = writeln!(std::io::stdout());
            std::process::exit(crate::exit_codes::INTERRUPTED)
        }
        Err(e) => Err(anyhow::anyhow!("the demo stopped unexpectedly: {e}")),
    }
}

// ----------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn invoked_finds_the_subcommand_past_global_flags() {
        assert!(invoked(&argv("tunlion demo")));
        assert!(invoked(&argv("tunlion demo --auto")));
        assert!(invoked(&argv("tunlion --color never demo")));
        assert!(invoked(&argv("tunlion -v --server http://x demo --step 3")));
        assert!(!invoked(&argv("tunlion")));
        assert!(!invoked(&argv("tunlion send demo")));
        assert!(!invoked(&argv("tunlion --color demo send x")));
    }

    /// Every command the tour shows parses with the real CLI definition, so the
    /// tour can never teach a verb or flag the binary does not have.
    #[test]
    fn every_command_in_the_tour_is_a_real_command() {
        use clap::Parser;
        let mut seen = 0;
        for step in STEPS {
            for a in step.acts {
                if let Run { cmd, .. } = a {
                    let words = split_command(cmd);
                    assert_eq!(words[0], "tunlion", "{cmd}");
                    if let Err(e) = crate::Cli::try_parse_from(&words) {
                        panic!("`{cmd}` does not parse: {e}");
                    }
                    seen += 1;
                }
            }
        }
        for l in OUTRO.iter().filter_map(|l| l.strip_prefix("$ ")) {
            let cmd = l.split("  ").next().unwrap().replace("<file>", "notes.txt");
            crate::Cli::try_parse_from(split_command(&cmd)).unwrap_or_else(|e| panic!("`{cmd}`: {e}"));
        }
        assert!(seen >= STEPS.len());
    }

    #[test]
    fn every_step_has_a_title_and_something_to_run() {
        for s in STEPS {
            assert!(!s.title.is_empty());
            assert!(s.acts.iter().any(|a| matches!(a, Run { .. })), "{}", s.title);
        }
    }

    /// The tour's own words follow the project's rule: no em or en dashes.
    #[test]
    fn no_em_or_en_dashes_in_the_tour() {
        let mut all: Vec<&str> = OUTRO.to_vec();
        for s in STEPS {
            all.push(s.title);
            for a in s.acts {
                match a {
                    Say(t) | Out(t) | Later(t) => all.push(*t),
                    Run { cmd, .. } | Remote { cmd, .. } => all.push(*cmd),
                    Wait(t, _) | Bar(t, _) => all.push(*t),
                }
            }
        }
        for t in all {
            assert!(!t.contains('\u{2014}') && !t.contains('\u{2013}'), "{t}");
        }
    }

    /// Output lines fit an 80-column terminal once indented.
    #[test]
    fn output_lines_fit_eighty_columns() {
        let p = Player::new(Vec::new(), Style::plain(), true, 0.0, 80);
        for s in STEPS {
            for a in s.acts {
                if let Out(l) = a {
                    let r = p.render_out(l);
                    assert!(r.chars().count() <= 80, "{} chars: {r}", r.chars().count());
                }
            }
        }
    }

    #[test]
    fn auto_play_without_color_prints_every_step_and_no_escapes() {
        let mut buf = Vec::new();
        {
            let mut p = Player::new(&mut buf, Style::plain(), true, 0.0, 80);
            assert_eq!(p.play(0), Ok(()));
        }
        let s = String::from_utf8(buf).unwrap();
        for (i, step) in STEPS.iter().enumerate() {
            assert!(s.contains(step.title), "missing {}", step.title);
            assert!(s.contains(&format!("{}/{}", i + 1, STEPS.len())));
        }
        assert!(s.contains("That's the tour."));
        assert!(!s.contains('\x1b'), "plain output carries an escape sequence");
        assert!(!s.contains('\r'), "line output carries a carriage return");
        assert!(s.contains("tunlion send holiday-photos.zip --code"));
    }

    #[test]
    fn auto_play_from_a_later_step_starts_there() {
        let mut buf = Vec::new();
        Player::new(&mut buf, Style::plain(), true, 0.0, 80).play(7).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains(STEPS[0].title));
        assert!(s.contains(STEPS[7].title));
    }

    #[test]
    fn color_uses_the_shared_palette() {
        let mut st = Style::plain();
        st.color = true;
        let p = Player::new(Vec::new(), st, true, 0.0, 80);
        // The accent, ok and bad roles of style.rs, unknown background, 256 colors.
        assert!(p.render_out("*  code").contains(&style::sgr(style::Role::Accent, true, style::Depth::Ansi256, style::Bg::Unknown)));
        assert!(p.render_out("OK done").contains(&style::sgr(style::Role::Ok, false, style::Depth::Ansi256, style::Bg::Unknown)));
        assert!(p.render_out("ERR no").contains(&style::sgr(style::Role::Bad, false, style::Depth::Ansi256, style::Bg::Unknown)));
        st.depth = style::Depth::True;
        st.bg = style::Bg::Light;
        assert_eq!(st.paint(Tone::Ok, "x"), format!("{}x\x1b[0m", style::sgr(style::Role::Ok, false, style::Depth::True, style::Bg::Light)));
    }

    #[test]
    fn the_cursor_block_moves_only_when_asked() {
        assert_eq!(block(true, Motion::Rest), block(true, Motion::Pulse(0)));
        let pulse: std::collections::BTreeSet<String> = (0..2000).step_by(10).map(|t| block(true, Motion::Pulse(t))).collect();
        assert!(pulse.len() >= 2, "the pulse never squashes");
        let knock: std::collections::BTreeSet<String> = (0..2000).step_by(10).map(|t| block(true, Motion::Knock(t))).collect();
        assert!(knock.len() >= 2, "the knock never hops");
        assert!(block(false, Motion::Rest).is_ascii());
    }

    #[test]
    fn markers_resolve() {
        let p = Player::new(Vec::new(), Style::plain(), true, 0.0, 80);
        assert_eq!(p.render_out("OK done"), "  ok done");
        assert_eq!(p.render_out("ERR bad"), "x bad");
        assert_eq!(p.render_out("~quiet"), "quiet");
        assert_eq!(p.render_out("a {.} b"), "a - b");
        assert_eq!(p.render_out("$ tunlion init   set up"), "  tunlion init   set up");
    }

    #[test]
    fn wrap_respects_width_and_indent() {
        let lines = wrap("one two three four five six seven eight nine ten eleven twelve", 30, "  ");
        assert!(lines.iter().all(|l| l.chars().count() <= 30 && l.starts_with("  ")));
        assert_eq!(lines.join(" ").split_whitespace().count(), 12);
    }

    #[test]
    fn split_and_compare_commands() {
        assert_eq!(
            split_command("tunlion exec laptop -- sh -c \"a b; c\""),
            vec!["tunlion", "exec", "laptop", "--", "sh", "-c", "a b; c"]
        );
        assert!(same_command("  tunlion   add ", "tunlion add"));
        assert!(!same_command("tunlion ad", "tunlion add"));
    }

}
