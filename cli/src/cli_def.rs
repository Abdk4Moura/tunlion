//! The clap command surface: the version and help text and the whole CLI shape.
//!
//! `const VERSION`, `const EXAMPLES`, `struct Cli`, `enum Cmd` and the four
//! subcommand enums `Cmd`'s variants are built from (`EphemeralAction`,
//! `IdAction`, `RequestsAction`, `DevicesAction`) -- moved as one group, verbatim
//! and in order, so every `#[command(...)]` attribute, every derive and every doc
//! comment that clap turns into help text travelled with the item it belongs to.
//!
//! The six names main.rs must keep reachable (everything except VERSION and
//! EXAMPLES, which clap uses only through this module's own attributes) are
//! `pub(crate)` and re-exported from the crate root, so existing imports such as
//! dispatch.rs's `use anyhow::{Context, Result, anyhow, bail};
use crate::DEFAULT_SERVER;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const VERSION: &str = env!("FILAMENT_BUILD_INFO"); // stamped by build.rs

pub(crate) const EXAMPLES: &str = "\
COMMANDS
  Start
    init                   create your Tunlion identity and first device
    add                    offer: a code, or an invitation file with --out
    add --for device       ...and enrol them into your mesh (--for person to not)
    join                   accept: join <code>, or join --invite-file <path>
    id                     show your identity and certified devices
  Share
    send <file>            send files (mints a one-time code, or --to <device>)
    receive [code]         receive from a code or your nearby network
    shell <device>         open a shell on a device (native PTY; --ssh for real ssh)
    exec <device> [--] cmd run a command on a device (argv crosses exactly)
    sync <dir> <device>:<dir>  mirror a directory onto a device (only changes move)
    reach <device>         check if a device is reachable (direct/relay + rtt)
    forward <device>:<port>  tunnel to a peer's port   (--socks for a local proxy)
    expose <port>          publish a local port on your mesh address
    mount <device> <dir> [local]  mount a remote folder over the mesh
  Serve
    up                     serve: receive, mount (run attached; shell with --shell)
    up --install           the same, always-on (autostart at logon)
    up --detach            the same, detached in the background (no service manager)
    down                   stop the daemon
    logs                   follow the daemon's log (-f follows, ctrl-c detaches)
    reset                  wipe this machine's state (destructive)
  Devices
    devices                list your known devices
    requests               approve or deny access others asked for
    grant / revoke         give or take a capability on a device
    add --for runner       a temporary key someone can enrol with (CI, borrowed box)
    ephemeral enroll       use such a key to enrol (run on the CI / borrowed box)
    status                 what the daemon is doing / recently received
  Mesh
    addr                   show your overlay address (or a device's)
    doctor                 diagnose a link

EXAMPLES
  tunlion video.mp4                 send it; mints a speakable one-time code + QR
  tunlion receive clever-lynx-63    claim a code and receive
  tunlion send big.iso --to laptop  send to a remembered device, no code
  tunlion add                       offer a code; the other device runs `tunlion join <code>`
  tunlion add --for person          bounded invitation; the other device runs `tunlion join`
  tunlion up --install              always-on receiver (the daemon, autostart)
  tunlion shell laptop              open a shell on a known device
  tunlion reach laptop              check if a device is reachable
  tunlion forward laptop:5432       tunnel to a peer's localhost port

  The other end never needs anything installed: https://tunlion.autumated.com
  Run `tunlion <command> --help` for details.";

#[derive(Parser)]
// Custom help template: clap has no native grouping for SUBCOMMANDS
// (next_help_heading groups args, not subcommands), so we omit the auto
// {subcommands} list entirely and present a curated, GROUPED command reference in
// the after-help (EXAMPLES). Every subcommand still exists, still works, and still
// has its own `tunlion <cmd> --help`; the top-level help just stops being a flat
// 27-item dump with deprecated + canonical names side by side.
#[command(
    name = "tunlion",
    version = VERSION,
    about = "One thread across your devices, end-to-end encrypted: send, receive, mount files, and open an authorized shell without an account or cloud upload.",
    after_help = EXAMPLES,
    help_template = "{about-with-newline}\n{usage-heading} {usage}\n\n{after-help}\n\nOptions:\n{options}"
)]
pub(crate) struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    pub(crate) server: String,
    /// Force TURN relay (testing/privacy; hides your IP from the peer)
    #[arg(long, global = true)]
    pub(crate) relay: bool,
    /// Forbid relay: keep a hard direct-only promise. The never-flaky guarantee
    /// is traded for "no middleman, ever", a path that can't go direct FAILS
    /// CLEANLY (a clear error, a kept partial) instead of falling back to a TURN
    /// relay. Conflicts with --relay (which forces relay).
    #[arg(long, global = true, conflicts_with = "relay")]
    pub(crate) no_relay: bool,
    /// Display name shown to peers (default: config file, then your platform username@hostname)
    #[arg(long, global = true)]
    pub(crate) name_as: Option<String>,
    /// Verbose output: -v shows resilience internals (stalls, repairs,
    /// reconnects, upgrade probes); -vv adds ICE/per-frame trace. The
    /// value-prop lines (route, relay banner) always print. Overridden by
    /// FILAMENT_LOG=<critical|info|debug|trace>.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    /// Quiet: print only the must-see lines (route label, relay banner, P1/P5
    /// path changes, fatal errors). Conflicts with -v. Overridden by
    /// FILAMENT_LOG.
    #[arg(short = 'q', long = "quiet", global = true, conflicts_with = "verbose")]
    pub(crate) quiet: bool,
    /// Never drop into the guided interactive code entry, fail fast instead.
    /// Use in scripts/automation. A non-TTY stdin is ALWAYS non-interactive even
    /// without this; the env var FILAMENT_NONINTERACTIVE=1 does the same thing.
    #[arg(long, global = true)]
    pub(crate) no_interactive: bool,
    /// Open the guided human flow even when all command arguments were supplied.
    /// Requires a TTY. Conflicts with --no-interactive and --json (enforced in
    /// code, because subcommands shadow the global json arg).
    #[arg(long, global = true, conflicts_with = "no_interactive")]
    pub(crate) interactive: bool,
    /// Colorize output: auto (default; only at a TTY), always, or never. A flag
    /// overrides NO_COLOR/TERM. Equivalent to FILAMENT_COLOR.
    #[arg(long, global = true, value_name = "WHEN", value_parser = ["auto", "always", "never"])]
    pub(crate) color: Option<String>,
    /// JSON output (structured, parseable) where a command supports it: init,
    /// add, join, id, status, set, reach, sync, doctor, addr and devices. Any
    /// other command refuses --json rather than mixing human text into it.
    /// Independent of TTY: a pipe still gets human text unless --json is set.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Auto-confirm prompts: down, reset, revoke, devices revoke, unmount,
    /// unexpose, set --reset, add --for with remote authority, and init.
    /// Required for these from a non-TTY; a TTY prompts instead.
    #[arg(short = 'y', long = "yes", global = true)]
    pub(crate) yes: bool,
    #[command(subcommand)]
    pub(crate) cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    // ── Start ───────────────────────────────────────────────────────
    /// Create your Tunlion identity and configure this first device.
    Init {
        /// Name this device (default: hostname).
        #[arg(long)]
        name: Option<String>,
        /// Directory where received files land (default: ~/Filament if it exists, else ~/Tunlion).
        #[arg(long)]
        inbox: Option<PathBuf>,
        /// Write the recovery phrase to a new owner-only file for automation.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_fd")]
        recovery_file: Option<PathBuf>,
        /// Write the recovery phrase to an already-open file descriptor.
        #[arg(long, value_name = "FD", conflicts_with = "recovery_file")]
        recovery_fd: Option<i32>,
        /// Install the always-on receive service without prompting.
        #[arg(long, conflicts_with = "no_background")]
        background: bool,
        /// Leave the always-on receive service off.
        #[arg(long, conflicts_with = "background")]
        no_background: bool,
    },
    // ── Share ───────────────────────────────────────────────────────
    /// Send files or directories to a peer (browser or CLI).
    #[command(next_help_heading = "Share")]
    Send {
        /// Files or directories to send; '-' reads stdin
        paths: Vec<String>,
        /// Mint a speakable one-time code the receiver claims
        #[arg(long)]
        code: bool,
        /// Choose the one-time code word yourself (implies --code)
        #[arg(long)]
        word: Option<String>,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only connect to a peer whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// Override the offered file name (for stdin '-', or a single file)
        #[arg(long)]
        name: Option<String>,
        /// Enroll as delegated principal using an auth key file before sending
        #[arg(long, hide = true)]
        auth_key: Option<PathBuf>,
    },
    /// Receive files from a peer (browser or CLI).
    ///
    /// In a terminal with no code this opens a guided code entry (or press enter
    /// for the local-network auto room). Scripts are safe by default: a non-TTY
    /// uses the auto room; under a TTY set FILAMENT_NONINTERACTIVE=1 or pass
    /// --no-interactive to skip the prompt.
    #[command(next_help_heading = "Share")]
    Receive {
        /// One-time code spoken by the sender (omit to use the auto room)
        code: Option<String>,
        /// Directory to write received files into
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Accept every offer without prompting
        #[arg(long, short = 'y')]
        yes: bool,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only accept a sender whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// Keep listening after a sender disconnects
        #[arg(long)]
        keep_open: bool,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Rename the (single) received file; '-' streams it to stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
        /// Install the always-on receive service instead of listening once.
        #[arg(long)]
        background: bool,
    },
    /// Add a device or person with consent on both ends.
    #[command(next_help_heading = "Connect")]
    Add {
        /// Who you are adding: a name for the device or person. `tunlion add
        /// laptop` is the short way to say `--for laptop`, which means a device
        /// of yours called laptop.
        ///
        /// The name is the thing you always know, so it is the thing that does
        /// not need a flag. Everything else has a default or is asked.
        who: Option<String>,
        /// What to call them (asked interactively if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Choose your own pairing words instead of minting (the SPAKE2
        /// password; the connect number is still machine-assigned). Use at
        /// least two words, e.g. --word "gigantic element".
        #[arg(long)]
        word: Option<String>,
        /// Who is joining: `device` (one of yours, enrolled into your mesh),
        /// `person` (someone else, paired only), or `runner` (unattended: CI, a
        /// borrowed box; a temporary key, not a member). A device name is
        /// accepted and means `device`.
        ///
        /// With `--out` this is delivered as a bounded invitation file. Without
        /// it, at a terminal you get a pairing code to read out; from a script
        /// there is nobody to read it to, so it is written to a file instead.
        /// Either way the other side accepts with `join`. The transport
        /// differs; the question does not.
        ///
        /// Omit the value on a terminal to be asked. Omit the flag entirely for
        /// an ordinary pair, which confers no membership.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        for_: Option<String>,
        /// Maximum capabilities for the bounded invitation. Defaults to
        /// transfer+mount for a device, transfer for a person.
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,
        /// Invitation and joined certificate lifetime, such as 1h or 30d.
        #[arg(long)]
        expires: Option<String>,
        /// Write the invitation to a new owner-only file instead of displaying it.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// How they get it: `code` (spoken now, both of you present) or `file`
        /// (written, claimed later). Implied by --out when omitted. This is the
        /// SAME question the guided flow asks, spelled the same way, so the two
        /// modes do not diverge.
        #[arg(long, value_name = "WAY")]
        via: Option<String>,
    },
    /// Accept: claim a pairing code, or a bounded invitation file.
    ///
    /// `add` offers and `join` accepts. Which transport carried the offer (a
    /// code you read aloud, or a file you were handed) is an argument here, not
    /// a different verb: accepting used to be `add <code>` for one and `join`
    /// for the other, so the verb named the transport rather than what you were
    /// doing. `add <code>` still works.
    Join {
        /// A pairing code, or the PATH to an invitation file. Invitation
        /// material itself is never accepted in argv (it would land in `ps`
        /// output and shell history); a path is not material.
        code: Option<String>,
        /// Read the invitation from an owner-only regular file.
        #[arg(long, value_name = "PATH", conflicts_with = "invite_fd")]
        invite_file: Option<PathBuf>,
        /// Read the invitation from an already-open file descriptor.
        #[arg(long, value_name = "FD", conflicts_with = "invite_file")]
        invite_fd: Option<i32>,
        /// Proposed name for this device (default: hostname).
        #[arg(long)]
        name: Option<String>,
        /// Owner device display name when several owners are present.
        #[arg(long)]
        to: Option<String>,
    },
    /// Tell the owner you are shutting down so it frees your slot now.
    /// Advisory only: if the owner is unreachable, the offline budget still
    /// lapses you. A joined device's end-of-life verb.
    #[command(hide = true)]
    Depart,
    // ── Devices ─────────────────────────────────────────────────────
    /// List known devices (trusted for --to and auto-accept)
    #[command(next_help_heading = "Devices")]
    Devices {
        #[command(subcommand)]
        action: Option<DevicesAction>,
        /// Machine-readable JSON (for scripts): [{name, channel, caps}].
        #[arg(long)]
        json: bool,
        /// What each device can do to this machine, and until when: one row per
        /// capability with its source, expiry and whether the gate honours it
        /// right now. Give a device name to show just that device. Read-only.
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "DEVICE")]
        caps: Option<String>,
    },
    /// Always-on receiver: trusted known devices only, invisible to strangers
    Up {
        /// Install + start a per-user service instead of running attached
        /// (systemd --user on Linux, a LaunchAgent on macOS, a logon entry on
        /// Windows). Every other `up` flag given here is carried into it. Add
        /// --system for a machine-wide service instead.
        #[arg(long)]
        install: bool,
        /// Run the daemon detached from this terminal (background). For
        /// machines without a service manager, this is the middle between
        /// attached-now and service-forever; the daemon survives closing the
        /// terminal. Its output goes to {config}/daemon.log. Every other `up`
        /// flag given here is carried into the detached daemon.
        #[arg(long)]
        detach: bool,
        /// With --install: install a machine-wide service instead of a per-user
        /// one. On Linux, a system unit (one-time sudo) that runs as you and gets
        /// CAP_NET_ADMIN from systemd via AmbientCapabilities, so the overlay's
        /// kernel TUN needs NO setcap on the binary and `tunlion update` never
        /// prompts for a password again. On macOS, a LaunchDaemon (administrator
        /// prompt). Not available on Windows yet.
        #[arg(long, requires = "install")]
        system: bool,
        /// Force the ZERO-PRIVILEGE userspace overlay (an in-process smoltcp netstack
        /// instead of a kernel TUN): no CAP_NET_ADMIN, no /dev/net/tun, works in a
        /// container. Note: host firewall rules do not apply and native tools reach
        /// <peer>.mesh only via `tunlion forward <peer>:<port> --socks`. Default is auto (kernel TUN
        /// when available, userspace otherwise).
        #[arg(long)]
        userspace: bool,
        /// Drop directory (default: `tunlion config dir`, else ~/Filament if it exists, else ~/Tunlion)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Accept seamless `tunlion shell --ssh` from ANY paired (proof-verified) device,
        /// no per-device `grant` needed. Enables the tunnel acceptor too, so you
        /// don't also need FILAMENT_L2=1. Strangers still can't get in (pairing is
        /// required). Prints a security banner.
        #[arg(long)]
        shell: bool,
        /// Like --shell but ONLY for these devices (comma-separated petnames);
        /// every other device still needs an explicit `grant <dev> shell`.
        #[arg(long, value_name = "DEVICES")]
        shell_only: Option<String>,
        /// The shell program to spawn for PTY sessions (overrides platform default).
        /// Can carry args: `--shell-program "bash -l"`, `"pwsh -NoLogo"`.
        /// Persistent: use `tunlion set shell-program "<program>"` for the daemon.
        /// Env: `FILAMENT_SHELL`.
        #[arg(long, value_name = "PROGRAM")]
        shell_program: Option<String>,
        /// Drop the web-shell / ssh PTY to this non-root account (via
        /// `runuser -l <user>`). STRONGLY recommended when `up` runs as root:
        /// without it, a granted device gets a shell as the up-process user
        /// (often root). Requires `up` to run as root (runuser is setuid).
        #[arg(long, value_name = "USER")]
        shell_user: Option<String>,
        /// Acknowledge that serving shell without --shell-user grants owner authority.
        #[arg(long)]
        i_know: bool,
        /// Internal: re-invoked after elevation to do the system-level install.
        #[arg(long, hide = true)]
        install_system: bool,
        /// When kernel TUN is unavailable, auto-start a SOCKS5 proxy on port
        /// 1080 so native tools (curl, ssh) can reach <peer>.mesh. Opt out
        /// with --no-proxy-fallback or `tunlion set auto-proxy off`.
        #[arg(long)]
        no_proxy_fallback: bool,
    },
    /// Show whether the daemon runs and what it received recently
    Status {
        /// Machine-readable JSON (for scripts): {running, pid, devices, exposed, recent}.
        #[arg(long)]
        json: bool,
    },
    // ── Advanced ────────────────────────────────────────────────────
    /// Stop the daemon
    Down,
    /// Show the daemon's output: the journal when it runs as a systemd
    /// service, else {config}/daemon.log (written by `up --detach`), else the
    /// diagnostic timeline diag.jsonl as raw JSON lines.
    Logs {
        /// Follow the log as new lines arrive (like docker logs -f).
        #[arg(short = 'f', long)]
        follow: bool,
        /// Show only the last N lines before following/stopping (default 20;
        /// 0 = live only, never replay history).
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    ///
    /// No args prints all settings with their value, scope, and where each came
    /// from (env > peer > config > default). Strictly imperative: `set` only
    /// changes the key you name.
    #[command(
        hide = true,
        after_help = "\x1b[1mExamples:\x1b[0m\n  \
        tunlion set                          show every setting + where it came from\n  \
        tunlion set auto-extract on          change one setting (partial, never resets others)\n  \
        tunlion set shell on --peer laptop   per-device override\n  \
        tunlion set drop-dir                 read one value (bare value on stdout when piped)\n  \
        tunlion set relay --unset            reset one setting to its default\n  \
        tunlion set --reset --yes            reset ALL settings to their defaults\n\n\
        Some keys: name, server, drop-dir, relay, auto-extract, shell, shell-user (`tunlion set` lists all)"
    )]
    Set {
        /// Setting name (run `tunlion set` to list them all)
        key: Option<String>,
        /// New value. `tunlion set` with no arguments lists every setting;
        /// `tunlion set <key>` reads one.
        value: Option<String>,
        /// Scope this change to one or more known devices (per-peer settings
        /// only). Comma-separated or repeatable: --peer a,b  or  --peer a --peer b
        #[arg(long, value_name = "DEVICE", value_delimiter = ',')]
        peer: Vec<String>,
        /// Show what would change without writing
        #[arg(long)]
        dry_run: bool,
        /// With a key: reset that one setting to its default (same as --unset).
        /// Without a key: reset ALL settings (global and per-device); asks
        /// first, and needs the global --yes from a pipe or CI.
        #[arg(long, conflicts_with = "value")]
        reset: bool,
        /// Reset this one setting to its default; with --peer, remove just that
        /// device's override.
        #[arg(long, requires = "key", conflicts_with_all = ["value", "reset"])]
        unset: bool,
        /// Prefer strength: hard (always prefer, even if slower). `prefer` only.
        #[arg(long, conflicts_with = "soft")]
        hard: bool,
        /// Prefer strength: soft (prefer unless much faster), the default.
        /// `prefer` only.
        #[arg(long, conflicts_with = "hard")]
        soft: bool,
    },
    // ── Mesh ────────────────────────────────────────────────────────
    /// Show this machine's overlay address, or a device's info
    #[command(next_help_heading = "Mesh")]
    Addr {
        /// Device name to show info for (omit for this machine's address).
        device: Option<String>,
        /// Print the IPv4 overlay address (dual-stack) instead of the IPv6 one.
        #[arg(long)]
        v4: bool,
    },
    // ── Identity ────────────────────────────────────────────────────
    /// Manage your user identity (key + device certs)
    #[command(next_help_heading = "Identity")]
    Id {
        #[command(subcommand)]
        action: Option<IdAction>,
    },
    /// Raw config escape hatch (key value lines in ~/.config/filament/config).
    /// Prefer `tunlion set`; this is kept for scripts that wrote it directly.
    #[command(hide = true)]
    Config {
        key: Option<String>,
        value: Option<String>,
    },
    /// Update tunlion to the latest release
    #[command(hide = true)]
    Update {
        /// Check only; don't install
        #[arg(long)]
        check: bool,
        /// Include prerelease (beta) builds
        #[arg(long)]
        beta: bool,
    },
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    #[command(hide = true)]
    Completions { shell: clap_complete::Shell },
    /// Print the manual. On a TTY, shows readable help; piped, emits roff
    /// (for `tunlion man > tunlion.1`). `tunlion man routing` shows the
    /// connection & interface selection model.
    #[command(hide = true)]
    Man {
        /// Manual page: routing, or omit for the full man page
        page: Option<String>,
    },
    /// Forward a local port to a known peer's port.
    ///
    /// Local TCP listener; each connection becomes one stream to the peer's
    /// localhost:<rport>.
    Forward {
        /// `<device>:<port>` to tunnel to (e.g. laptop:5432); the local port is
        /// the same as the remote one unless --lport says otherwise.
        target: String,
        /// Override the local listen port.
        #[arg(long)]
        lport: Option<u16>,
        /// Pipe instead of listen: attach stdin/stdout to the peer's port (the
        /// `netcat` shape, used as an ssh ProxyCommand). This is the transport
        /// an external process expects on its own stdio.
        #[arg(long)]
        stdio: bool,
        /// Run a local SOCKS5 proxy for mesh access from any app.
        #[arg(long)]
        socks: bool,
        /// SOCKS5 proxy port (default: 1080)
        #[arg(long, default_value_t = 1080)]
        port: u16,
        /// Proxy bind address (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// HTTP CONNECT proxy port (0 = disabled)
        #[arg(long, default_value_t = 0)]
        http_port: u16,
    },
    /// (hidden for one release) The netcat shape moved into `forward --stdio`.
    #[command(hide = true)]
    Netcat {
        /// Known device (petname) whose port to reach
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Publish a local port on this device's mesh address (peers reach it at
    /// <this-device>.mesh:<port>), like a Tailscale-served port.
    ///
    /// The daemon binds the overlay address (a private ULA, reachable only over
    /// the mesh) and forwards each connection to a local target. Needs L3 up
    /// (`tunlion set tun-addr auto`). Persists across restarts.
    ///
    /// Use `tunlion expose <port> --off` to stop exposing a port.
    Expose {
        /// Port to publish on the overlay. Omit together with --list or --off.
        port: Option<u16>,
        /// Local target: host:port, a bare port (127.0.0.1:PORT), or a bare host
        #[arg(long, value_name = "HOST:PORT")]
        to: Option<String>,
        /// Restrict to these paired devices (petnames, comma-separated). Default: any.
        #[arg(long, value_name = "DEVICE", value_delimiter = ',')]
        peer: Vec<String>,
        /// List exposed ports and exit.
        #[arg(long)]
        list: bool,
        /// Stop exposing the given port (replaces `tunlion unexpose`).
        #[arg(long)]
        off: bool,
    },
    /// Reach a peer: check whether it is reachable, and how (direct/relay + rtt).
    ///
    /// To TUNNEL to a peer's port, use `tunlion forward <device>:<port>`.
    #[command(next_help_heading = "Mesh")]
    Reach {
        /// Device to probe (omit for the environment preflight).
        dev: Option<String>,
        /// Keep probing (one line a second) until the link is direct: exit 0 on
        /// the first direct path, exit 5 if it is still on a relay at --timeout.
        #[arg(long)]
        until_direct: bool,
        /// Seconds to wait for a direct path with --until-direct.
        #[arg(long, value_name = "SECS", default_value_t = 30)]
        timeout: u64,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// Moved to `forward --socks`. Kept hidden so the old form teaches.
        #[arg(long, hide = true)]
        socks: bool,
    },
    /// Diagnose connect health: where SSH/L2 establishment is slow or stalls.
    ///
    /// With a device: run an "establish then drop" probe and print the per-phase
    /// ladder + verdict. Without a device: environment preflight.
    Doctor {
        /// Known device (petname) to probe; omit for environment preflight
        device: Option<String>,
        /// Repeat the probe until interrupted-ish (a bounded default count)
        #[arg(long)]
        watch: bool,
        #[arg(long)]
        repeat: Option<u32>,
        /// Machine-readable JSON output (for scripting)
        #[arg(long)]
        json: bool,
    },
    /// Grant a known device a capability (deny-by-default). `shell` permits
    /// seamless `tunlion shell --ssh` into THIS machine, a separate consent from
    /// file transfer; pairing alone never yields a shell.
    ///
    /// `tunlion grant <device> <capability>`, or `tunlion grant --tag <tag>
    /// <capability>` to grant every device carrying that tag.
    Grant {
        /// Known device (petname). Omit it when --tag is given.
        #[arg(value_name = "DEVICE")]
        device: Option<String>,
        /// Capability to grant (e.g. `shell`, or `route:10.0.0.0/24`)
        #[arg(value_name = "CAPABILITY")]
        capability: Option<String>,
        /// Target a tag instead of a device
        #[arg(long)]
        tag: Option<String>,
    },
    /// Revoke a capability or a fleet certificate from a known device.
    Revoke {
        /// Known device (petname)
        device: String,
        /// Capability to revoke (e.g. `shell`)
        capability: Option<String>,
        /// Revoke the device's local fleet certificate instead of a capability.
        #[arg(long)]
        certificate: bool,
    },
    /// Mount a remote directory over Tunlion's native filesystem protocol.
    /// Read-only is the default; the remote share root and grant remain authoritative.
    Mount {
        /// Known device (petname) to mount from
        peer: Option<String>,
        /// Remote directory path
        remote: Option<String>,
        /// Local mount point (default: ~/Tunlion Mounts/<device>/<remote>)
        local: Option<String>,
        /// Permit writes when the remote grant also allows them. Read-only is the default.
        #[arg(long)]
        read_write: bool,
        /// Extra sshfs options (comma-separated)
        #[arg(long, hide = true)]
        options: Option<String>,
        /// Run sshfs in the foreground (blocks terminal)
        #[arg(long, hide = true)]
        foreground: bool,
        /// Auto-restore this mount on daemon start (off by default)
        #[arg(long, hide = true)]
        save_auto: bool,
        /// List all tunlion mounts and their status
        #[arg(long)]
        list: bool,
        /// Check if a mount is healthy
        #[arg(long, value_name = "PATH")]
        check: Option<String>,
        /// Save current mounts as a named profile
        #[arg(
            long = "save-profile",
            alias = "save",
            value_name = "NAME",
            hide = true
        )]
        save_profile: Option<String>,
        /// Apply a saved mount profile
        #[arg(
            long = "apply-profile",
            alias = "apply",
            value_name = "NAME",
            hide = true
        )]
        apply_profile: Option<String>,
        /// List saved mount profiles
        #[arg(long, hide = true)]
        profiles: bool,
        /// Delete a saved mount profile
        #[arg(long, value_name = "NAME", hide = true)]
        delete_profile: Option<String>,
        /// Unmount a tunlion mount point (replaces `tunlion unmount`).
        #[arg(long, value_name = "PATH")]
        off: Option<String>,
    },
    /// Sync files to/from a peer via rsync over the mesh.
    ///
    /// Requires rsync on both ends. Uses `tunlion shell --ssh` as the remote shell,
    /// so the same transport and bootstrap logic applies.
    #[command(hide = true)]
    Backup {
        /// Known device (petname) to back up from/to
        peer: String,
        /// Source path (local or remote as peer:path)
        source: String,
        /// Destination path (local or remote as peer:path)
        dest: String,
        /// Exclude files matching pattern (repeatable)
        #[arg(long)]
        exclude: Vec<String>,
        /// Show what would be transferred without doing it
        #[arg(long)]
        dry_run: bool,
        /// Delete extraneous files in destination
        #[arg(long)]
        delete: bool,
        /// Extra rsync options (space-separated)
        #[arg(long)]
        options: Option<String>,
    },
    /// Run a command on a device. The argument vector crosses exactly;
    /// opt into a shell explicitly with --shell (never implied).
    Exec {
        /// Known device (petname) to run on
        peer: Option<String>,
        /// Run under `/bin/sh -c` (cmd /C on Windows) instead of direct spawn
        #[arg(long)]
        shell: bool,
        /// Allocate a pty instead of pipes (refused loudly until supported)
        #[arg(long)]
        tty: bool,
        /// Working directory on the remote (default: the daemon's home)
        #[arg(long, value_name = "DIR")]
        cwd: Option<PathBuf>,
        /// Extra environment as KEY=VALUE (repeatable; TERM/LANG/LC_* pass anyway)
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// The command and its arguments, passed exactly (trailing)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Mirror a local directory onto a paired device; only changed chunks move.
    ///
    /// The receiver's `tunlion up` writes under its drop directory, so
    /// <remote-dir> is relative to (or absolute within) that directory. The
    /// receiver's consent is the existing pairing and transfer grant: there is
    /// no prompt on either end. Re-running after an interruption moves only
    /// what is still missing.
    Sync {
        /// Local directory to mirror
        local: PathBuf,
        /// Destination as <device>:<remote-dir>
        dest: String,
        /// Remove files on the device that are not in the local directory
        #[arg(long)]
        delete: bool,
        /// Print the plan (what would move) and move nothing
        #[arg(long, short = 'n')]
        dry_run: bool,
    },
    /// Open a shell on a device.
    ///
    // #234: this said "The peer must explicitly authorize shell", which reads as
    // per-device and is why `up --shell` surprised people: one flag on the
    // acceptor admits every paired device, present and future. The behaviour is
    // deliberate (see ShellPolicy::All); the sentence describing it was not.
    // Rationale lives here, in a comment. The doc line below is what a user
    // reads, so it states the two ways in and nothing else.
    /// Default: Tunlion's native PTY. The peer must authorize shell, either
    /// per-device with `grant <device> shell`, or for every paired device at
    /// once by serving `up --shell` (use `up --shell-only a,b` to scope it).
    /// With `--ssh`: runs your real ssh over the data channel via ProxyCommand
    /// (reuses your keys, known_hosts, and ~/.ssh/config).
    Shell {
        /// Known device (petname) to open a shell on
        peer: Option<String>,
        /// Use real ssh (ProxyCommand over tunlion) instead of the native PTY
        #[arg(long, hide = true)]
        ssh: bool,
        /// Extra args passed through to ssh (only with --ssh)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// List, approve, or deny pending consent requests from peers.
    Requests {
        #[command(subcommand)]
        action: Option<RequestsAction>,
    },
    /// Mint auth keys or enroll as an ephemeral delegated device.
    ///
    /// Unhidden 2026-08-29. It was hidden while the banner did not mention it,
    /// so the only way to find a working verb was to already know it existed.
    /// `help_banner_agrees_with_clap_visibility` states the rule this now
    /// satisfies: a command that works is discoverable, or it is removed.
    Ephemeral {
        #[command(subcommand)]
        action: EphemeralAction,
    },
    /// Wipe this machine's tunlion state (clean slate). DESTRUCTIVE.
    ///
    /// Removes the local identity + overlay keys, the paired-device store, the
    /// capability store, pending consent requests, and the managed ssh material
    /// (private key, known_hosts, bootstrap cache), and strips the
    /// filament-managed blocks it installed in ~/.ssh/authorized_keys. Your own
    /// ssh keys and any non-tunlion lines in authorized_keys are left untouched.
    /// Stop the daemon first (`tunlion down`); reset refuses while it runs.
    ///
    /// Pass the global `-y`/`--yes` to skip the confirmation prompt (required
    /// from a non-TTY / scripts).
    Reset,
}

/// Ephemeral device commands: mint auth keys, enroll as delegated.
#[derive(Subcommand)]
pub(crate) enum EphemeralAction {
    /// Enroll as an ephemeral delegated device using an auth key.
    Enroll {
        /// Owner-only file containing the auth key bundle.
        #[arg(long, value_name = "PATH")]
        auth_key_file: PathBuf,
        /// Target peer display name or channel (the owner device to enroll at)
        #[arg(long)]
        to: Option<String>,
    },
}

/// User identity management: generate the identity key, show the fingerprint,
/// certify a known device so peers can verify it belongs to the same person.
#[derive(Subcommand)]
pub(crate) enum IdAction {
    /// Show the user identity fingerprint + certified devices.
    Show,
    /// Restore an identity from its 12-word recovery phrase.
    Recover {
        /// Read recovery words from an owner-only regular file.
        #[arg(long, value_name = "PATH", conflicts_with = "words_fd")]
        words_file: Option<PathBuf>,
        /// Read recovery words from an already-open file descriptor.
        #[arg(long, value_name = "FD", conflicts_with = "words_file")]
        words_fd: Option<i32>,
    },
}

/// Consent request management: list, approve, or deny pending requests.
#[derive(Subcommand)]
pub(crate) enum RequestsAction {
    /// List pending requests (default: pending-only; --all for full history).
    List {
        /// Show all requests including approved/denied/expired
        #[arg(long)]
        all: bool,
    },
    /// Approve a pending request by id and grant the capability.
    Approve {
        /// Request id
        id: u64,
        /// Capability requested by the peer
        #[arg(long)]
        allow: String,
        /// Duration, for example 1h, 30m, or 1d
        #[arg(long = "for")]
        duration: String,
    },
    /// Deny a pending request by id.
    Deny {
        /// Request id
        id: u64,
    },
}

/// Petname management (C12): names are LOCAL aliases for pair secrets, the
/// secret is the identity, the name is yours to fix when you mislabel one.
#[derive(Subcommand)]
pub(crate) enum DevicesAction {
    /// Forget a device: deletes the secret; it can no longer find you
    Forget { name: String },
    /// Rename your local alias (the other side is unaffected)
    Rename { old: String, new: String },
    /// Vouch between two known devices: mints a fresh secret and delivers it
    /// to both over verified channels (run on the device that knows both)
    Vouch { a: String, b: String },
    /// Durable revoke: the device stops being recognized NOW and forever (the
    /// record survives as evidence; the gate refuses it on reconnect).
    Revoke { name: String },
    /// Undo a durable revoke. The device returns to its prior state.
    Restore { name: String },
}

#[cfg(test)]
mod tests {
    use crate::{Cli, EXAMPLES};

    #[test]
    fn help_banner_agrees_with_clap_visibility() {
        // 0.8.5 (rec 5): the help COMMANDS banner is a hand-written list and a
        // second source of truth. This test is the enforcement: every clap-
        // visible subcommand appears in the banner, and every leading verb in
        // the banner's COMMANDS section is a clap-visible subcommand. A command
        // hidden from clap must not appear as discoverable, and a visible one
        // must be listed. (Deriving the banner from clap outright is awkward
        // because it is a grouped static const; the agreement test is the
        // accepted second best.)
        use clap::CommandFactory;
        let cmd = Cli::command();
        let visible: std::collections::HashSet<String> = cmd
            .get_subcommands()
            .filter(|sc| !sc.is_hide_set())
            .map(|sc| sc.get_name().to_string())
            .collect();
        // Every visible subcommand is in the banner.
        for name in &visible {
            assert!(
                EXAMPLES.contains(name.as_str()),
                "visible command '{name}' must appear in the help banner"
            );
        }
        // Every leading verb in the banner's COMMANDS section is visible.
        let section = EXAMPLES.split("\nEXAMPLES").next().unwrap_or(EXAMPLES);
        for line in section.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("COMMANDS") {
                continue;
            }
            let first = trimmed.split_whitespace().next().unwrap_or("");
            let verb = first.trim_end_matches(':');
            // Group headings in the banner (Start/Share/Serve/Devices/Mesh) are
            // not commands.
            if matches!(verb, "Start" | "Share" | "Serve" | "Devices" | "Mesh") {
                continue;
            }
            if verb.is_empty() || verb.starts_with("add") || verb.starts_with("up") {
                continue; // `add --for`, `add <code>`, `up --install` all key off add/up
            }
            assert!(
                visible.contains(verb),
                "banner lists '{verb}' but clap hides it; a command that works must be discoverable or deliberately removed"
            );
        }
    }

    fn parse(words: &[&str]) -> Result<Cli, clap::Error> {
        use clap::Parser;
        Cli::try_parse_from(std::iter::once("tunlion").chain(words.iter().copied()))
    }

    /// Every `tunlion ...` line in README.md's fenced blocks is a command this
    /// build accepts, and does what its comment says where that is checkable.
    /// The README had `tunlion forward 5432 dovm:5432` (does not parse),
    /// `tunlion mount dovm:~/data ./data` (parses, mounts the wrong thing) and
    /// `tunlion up  # receive in the background` (runs attached).
    #[test]
    fn readme_commands_parse_and_mean_what_they_say() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../README.md");
        let readme = std::fs::read_to_string(&path).expect("README.md next to cli/");
        let mut in_fence = false;
        let mut checked = 0;
        for line in readme.lines() {
            let t = line.trim();
            if t.starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if !in_fence || !t.starts_with("tunlion ") {
                continue;
            }
            let (cmd, comment) = match t.split_once(" #") {
                Some((c, rest)) => (c.trim(), rest),
                None => (t, ""),
            };
            if cmd.contains('<') {
                continue; // a placeholder, not a runnable command
            }
            let words: Vec<&str> = cmd.split_whitespace().skip(1).collect();
            let cli = parse(&words)
                .unwrap_or_else(|e| panic!("README command does not parse: `{cmd}`\n{e}"));
            match cli.cmd {
                Some(crate::Cmd::Up { install, detach, .. }) if comment.contains("background") => {
                    assert!(
                        install || detach,
                        "README says `{cmd}` runs in the background, but plain `up` runs attached"
                    );
                }
                // `<device>:<path>` is only split when no remote is given; with
                // one, the whole `dev:path` would be taken as the device name.
                Some(crate::Cmd::Mount { peer: Some(ref p), remote: Some(_), .. }) => {
                    assert!(!p.contains(':'), "README `{cmd}`: device '{p}' is not a device name");
                }
                _ => {}
            }
            checked += 1;
        }
        assert!(checked >= 8, "found only {checked} README commands; did the fences move?");
    }

    /// The global --json help names exactly the commands that honour it.
    #[test]
    fn json_help_lists_exactly_the_supported_commands() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let help = cmd
            .get_arguments()
            .find(|a| a.get_id() == "json")
            .and_then(|a| a.get_long_help().or(a.get_help()))
            .expect("--json has help")
            .to_string();
        let list = help
            .split("supports it:")
            .nth(1)
            .and_then(|rest| rest.split('.').next())
            .expect("the --json help lists the supporting commands");
        let names: Vec<String> = list
            .replace(" and ", ", ")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(names.len() >= 5, "parsed {names:?} from {help:?}");
        fn sample<'a>(name: &'a str) -> Vec<&'a str> {
            match name {
                "sync" => vec!["sync", ".", "laptop:dir"],
                other => vec![other],
            }
        }
        for name in &names {
            let cli = parse(&sample(name))
                .unwrap_or_else(|e| panic!("--json help names `{name}`, which does not parse: {e}"));
            let c = cli.cmd.expect("a subcommand");
            assert!(
                crate::dispatch::json_supported(&c),
                "--json help names `{name}` but dispatch refuses --json for it"
            );
        }
        let down = parse(&["down"]).unwrap().cmd.unwrap();
        assert!(!crate::dispatch::json_supported(&down));
        assert!(!names.iter().any(|n| n == "down"));
    }

    /// `grant --tag <tag> <capability>` works as the help says: the device is
    /// optional with --tag (it was a required positional, so the documented
    /// form was a parse error).
    #[test]
    fn grant_takes_a_tag_instead_of_a_device() {
        use crate::dispatch::grant_operands;
        let get = |words: &[&str]| match parse(words).expect("parses").cmd {
            Some(crate::Cmd::Grant { device, capability, tag, .. }) => (device, capability, tag),
            _ => unreachable!(),
        };
        let (d, c, t) = get(&["grant", "--tag", "ci", "shell"]);
        assert_eq!(grant_operands(d, c, t.as_deref()).unwrap(), (None, "shell".to_string()));
        let (d, c, t) = get(&["grant", "laptop", "shell"]);
        assert_eq!(
            grant_operands(d, c, t.as_deref()).unwrap(),
            (Some("laptop".to_string()), "shell".to_string())
        );
        let (d, c, t) = get(&["grant", "laptop"]);
        assert!(grant_operands(d, c, t.as_deref()).is_err(), "a device grant needs a capability");
        let (d, c, t) = get(&["grant", "--tag", "ci", "laptop", "shell"]);
        assert!(grant_operands(d, c, t.as_deref()).is_err(), "--tag with a device is ambiguous");
    }

    /// The global -y help names `down`, which refuses without it from a pipe.
    #[test]
    fn yes_help_names_the_commands_that_need_it() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let help = cmd
            .get_arguments()
            .find(|a| a.get_id() == "yes")
            .and_then(|a| a.get_long_help().or(a.get_help()))
            .expect("--yes has help")
            .to_string();
        for verb in ["down", "reset", "revoke", "unmount", "unexpose", "set --reset"] {
            assert!(help.contains(verb), "-y help does not mention {verb}: {help}");
        }
    }

    /// The pairing-timeout hint names the verbs the two sides actually run.
    #[test]
    fn pairing_timeout_hint_names_add_and_join() {
        let src = include_str!("pair_cmd.rs");
        assert!(!src.contains("make sure both run `tunlion add`"));
        assert!(src.contains("while the other runs `tunlion join <code>`"));
    }
}
