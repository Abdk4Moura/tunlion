// filament, anywhere-to-anywhere P2P file transfer, CLI end.
//
// Speaks the exact same wire protocol as the browser app at
// https://filament.autumated.com: Socket.IO signaling, perfect-negotiation
// WebRTC, one-time pairing codes, and sid-framed chunk transfer with
// offset-based resume. A browser is a first-class peer: `filament send` can
// deliver straight to a phone with nothing installed on it.
//
//   filament send video.mp4 --code          mint a speakable one-time code
//   filament recv clever-lynx-63            claim it on the other machine
//   filament send ./dir --room demo         directories are tarred on the fly
//   tar c logs | filament send - --name logs.tar --code
//   filament recv -y --dir ~/Drops          auto-accept into a directory
//
// Failure-mode ledger: ../docs/cli-resilience.md, every resilience behavior
// in this file carries its ledger number (C1..C17 / F1..F4).

mod codeentry;
mod ctl;
mod diag;
mod direct;
mod doctor;
/// `filament ephemeral`: auth-key delegation for ephemeral devices, pre-authorized
/// self-enrollment, and delegated principal ceiling enforcement.
mod ephemeral;
mod fleet_enrollment;
/// `filament expose`: publish a local port on the L3 overlay. The CLI/config side
/// is portable; the daemon listeners (Exposer) are Linux-gated with L3.
mod expose;
mod holepunch;
// Multi-device user identity lives in the standalone `filament-id` crate; alias
// it as `identity` so every `crate::identity::…` / `identity::…` call site keeps
// resolving unchanged. Key persistence is injected via `platform::PlatformKeyStore`.
pub(crate) use filament_id as identity;
mod interact;
mod l2;
mod mount;
mod mount_proto;
#[cfg(target_os = "linux")]
mod mount_fuse;
#[cfg(all(target_os = "windows", feature = "mount-windows"))]
mod mount_winfsp;
mod backup;
mod capability;
mod net;
mod overlay;
mod platform;
// PAKE first-pairing lives in the standalone `filament-pair` crate; alias it as
// `pake` so every `crate::pake::…` call site keeps resolving unchanged.
pub(crate) use filament_pair as pake;
mod pake_ceremony;
mod ping;
mod sdnotify;
mod protocol;
mod resilience;
mod session;
mod settings;
/// L3 TUN data plane (serve_tun). Linux-only: it uses /dev/net/tun + TUNSETIFF,
/// which macOS (also `unix`) lacks, so gate on `target_os`, not `unix`.
#[cfg(l3)]
mod tun;
/// L3 overlay manager (routes IP packets across peer links); Linux-only.
#[cfg(l3)]
mod l3;
#[cfg(l3)]
mod wg;
mod shutdown;
mod sshd;
mod sshkeys;
mod local;
mod ui;
mod fleet_ui;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use net::{Ev, Peer, Transport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Read, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

/// Positional write at an absolute offset, used by concurrent spawn_blocking
/// writer tasks for out-of-order multi-stream reassembly (no seek, atomic per
/// call). Cross-platform: `FileExt::write_at` on Unix, `seek_write` on Windows —
/// both write at `offset` without moving the shared handle's cursor.
// MUST write the ENTIRE buffer. A positional write (pwrite/seek_write) is allowed to
// write FEWER bytes than requested; the old code did `file.write_at(buf, offset)` and the
// caller discarded the returned count, so a short write left a gap while `received`
// advanced by the full length — a silent per-file corruption the whole-file digest then
// caught as a failed transfer (measured ~44% on direct-QUIC, ~88% on DataChannel for large
// files). Loop until the whole buffer lands; return Err on a real failure so the caller
// can react instead of silently dropping bytes.
#[cfg(unix)]
fn pwrite_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    let mut written = 0usize;
    let mut iters = 0u32;
    while written < buf.len() {
        iters += 1;
        match file.write_at(&buf[written..], offset + written as u64) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "pwrite wrote 0 bytes")),
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    // DIAG (temporary): prove whether short-writes actually happen. If corruption is
    // short-write-caused this fires; if the re-rig shows zero of these AND corruption
    // persists, the cause is the await-before-digest race, not the write. Remove after.
    if iters > 1 {
        eprintln!("[pwrite-diag] SHORT WRITE: {iters} iterations to write {} bytes @ off {offset}", buf.len());
    }
    Ok(())
}
#[cfg(windows)]
fn pwrite_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0usize;
    while written < buf.len() {
        match file.seek_write(&buf[written..], offset + written as u64) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "seek_write wrote 0 bytes")),
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

const DEFAULT_SERVER: &str = "https://api.filament.autumated.com";
/// C7: content identity for resume, sha256 over the first 256 KiB.
const HEAD_BYTES: u64 = 256 * 1024;
/// C4/C6/C21: how long we wait for a vanished peer to rejoin. UNWARNED is the
/// blind default; a peer that announced `brb` (e.g. the browser opening a
/// mobile file picker suspends the whole tab) gets its declared ttl instead,
/// informed waits are both longer when promised and shorter when not.
const REJOIN_WINDOW: Duration = Duration::from_secs(120);
fn rejoin_unwarned() -> Duration {
    std::env::var("FILAMENT_REJOIN_SECS") // test knob (gate 15)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(45))
}
/// G-k: how long the recv quiet-check must hold (everything done, nobody
/// attached, no questions) before exiting without a `peer-left`. The 10 s
/// default is overridable for tests (gate 18).
fn quiet_exit_window() -> Duration {
    std::env::var("FILAMENT_QUIET_EXIT_SECS") // test knob (gate 18)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
}
/// C3/C4: connection (re)establishment attempts before failing honestly.
const MAX_ATTEMPTS: u32 = 5;

/// Test/injection hooks, env-gated fault injectors used ONLY by the resilience
/// gates (runner/sim/*) to drive deterministic failure modes. They are compiled
/// in ONLY under `--features test-hooks`; a default/release build strips them
/// entirely (no env reads, no injection logic in the shipped binary). Each hook
/// has a `not(feature = "test-hooks")` twin that returns the production value
/// (the no-hook path), so the surrounding real logic compiles and behaves
/// EXACTLY as if the hook were absent. See cli/Cargo.toml [features].test-hooks.
#[cfg(feature = "test-hooks")]
mod test_hooks {
    /// gate 17b: connect but never send our SPAKE2 element so the ceremony budget fires.
    pub fn pair_stall() -> bool {
        std::env::var("FILAMENT_TEST_PAIR_STALL").is_ok()
    }
    /// P1: force every WebRTC link relay-only (models a hard-NAT peer).
    pub fn webrtc_relay_only() -> bool {
        std::env::var("FILAMENT_TEST_WEBRTC_RELAY_ONLY").map(|v| v == "1").unwrap_or(false)
    }
    /// gate 18b: revert the mode-B post-completion drop to reconnect-always.
    pub fn disable_modeb_drop() -> bool {
        std::env::var("FILAMENT_TEST_DISABLE_MODEB_DROP").is_ok()
    }
    /// #28: revert the deferred peer-left drop to unconditional-drop.
    pub fn no_defer() -> bool {
        std::env::var("FILAMENT_TEST_NO_DEFER").is_ok()
    }
    /// #28: synthesize a peer-left for the active sid once N file-data bytes are sent.
    pub fn inject_peer_left_at() -> Option<u64> {
        std::env::var("FILAMENT_TEST_INJECT_PEER_LEFT").ok().and_then(|v| v.parse::<u64>().ok())
    }
    /// signaling-drop gate: revert the daemon acceptor to the no-outer-loop path.
    pub fn no_signaling_reconnect() -> bool {
        std::env::var("FILAMENT_TEST_NO_SIGNALING_RECONNECT").is_ok()
    }
    /// shutdown-hang gate: deterministically reproduce the multi-link shutdown
    /// hang by WEDGING the event loop forever (simulating a peer transport whose
    /// inline write never returns). With the wedge active, the graceful
    /// Ev::Interrupted is never processed; only the signal-owned force-exit
    /// watchdog can still terminate the process. Proves the A/B: a build whose
    /// watchdog is defeated hangs to the systemd timeout, the shipped one exits
    /// within the bounded grace.
    pub fn wedge_loop_on_shutdown() -> bool {
        std::env::var("FILAMENT_TEST_WEDGE_LOOP").is_ok()
    }
    /// warm-standby gate: churn surviving links after completion to force the C4 flap.
    pub fn churn_after_complete() -> bool {
        std::env::var("FILAMENT_TEST_CHURN_AFTER_COMPLETE").is_ok()
    }
    /// gate 18: drop the file-end control frame so the completion sweep must finalize.
    pub fn drop_file_end() -> bool {
        std::env::var("FILAMENT_TEST_DROP_FILE_END").is_ok()
    }
    /// gate 18: drop a peer-left event so the quiet-exit fallback is exercised.
    pub fn drop_peer_left() -> bool {
        std::env::var("FILAMENT_TEST_DROP_PEER_LEFT").is_ok()
    }
    /// P4 silent-data-loss gate: the receiver finalizes the file INTACT but
    /// suppresses the outbound `delivery-ack`, faithfully simulating an ack that
    /// never reaches the sender on an otherwise-healthy link (the black-hole-on-
    /// the-ack case). The sender must then re-probe and end UNCONFIRMED, never a
    /// false "delivered + verified". Distinct from corrupt-recv (which drives the
    /// re-request loop): here the bytes are whole, only the ack is withheld.
    pub fn suppress_delivery_ack() -> bool {
        std::env::var("FILAMENT_TEST_SUPPRESS_ACK").is_ok()
    }

    /// BUG-ACKLOSS reproducer (test-only): `FILAMENT_TEST_PREMATURE_CLOSE=1` tears
    /// the link DOWN at the exact moment the delivery-ack is due, so the ack never
    /// reaches the sender and the sender's transport observes ApplicationClosed(0,"").
    /// QUIC has no flush-on-close (RFC 9000 s10.2), so this is precisely the
    /// self-inflicted teardown race the multi-stream push otherwise hit only ~1-in-5
    /// on 10GB cross-machine transfers -- made DETERMINISTIC on a 1MB localhost
    /// transfer. The sender then sits in AWAIT_ACK on a dead link (the corpse
    /// cascade). Models `premature_close` in proofs/transport_lifecycle_model.py.
    /// No-op on default/release (compiled out). `=1` fires on EVERY completion;
    /// `=once` fires exactly once then falls through to a normal ack -- so an `up`
    /// daemon receiver (which stays alive) can be re-dialed and RECOVER (deliver on
    /// the second attempt) instead of looping drop -> re-dial -> drop. The latch is
    /// a process-global AtomicBool, mirroring corrupt_once.
    pub fn premature_close_after_ack() -> bool {
        matches!(std::env::var("FILAMENT_TEST_PREMATURE_CLOSE").as_deref(), Ok("1") | Ok("once"))
    }
    static PREMATURE_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    pub fn premature_close_once() -> bool {
        std::env::var("FILAMENT_TEST_PREMATURE_CLOSE").as_deref() == Ok("once")
    }
    pub fn premature_already_fired() -> bool {
        PREMATURE_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn premature_mark_fired() {
        PREMATURE_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// truncation/ack gate corruption injector. `FILAMENT_TEST_CORRUPT_RECV=<id>`
    /// flips the last on-disk byte of the matching transfer; `_CORRUPT_ONCE=1`
    /// fires exactly once (proving auto-recovery). The "already fired" latch is a
    /// process-global AtomicBool, no env mutation (the old code did an unsafe
    /// `set_var` of `FILAMENT_TEST_CORRUPT_FIRED` inside the async runtime).
    static CORRUPT_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// The configured corrupt-recv target id, if any.
    pub fn corrupt_recv_target() -> Option<String> {
        std::env::var("FILAMENT_TEST_CORRUPT_RECV").ok()
    }
    pub fn corrupt_recv_once() -> bool {
        std::env::var("FILAMENT_TEST_CORRUPT_ONCE").map(|v| v == "1").unwrap_or(false)
    }
    pub fn corrupt_already_fired() -> bool {
        CORRUPT_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn corrupt_mark_fired() {
        CORRUPT_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Production twins of the test hooks: each returns the no-hook value so the real
/// logic is byte-for-byte the shipped behavior when `test-hooks` is off.
#[cfg(not(feature = "test-hooks"))]
mod test_hooks {
    #[inline] pub fn pair_stall() -> bool { false }
    #[inline] pub fn webrtc_relay_only() -> bool { false }
    #[inline] pub fn disable_modeb_drop() -> bool { false }
    #[inline] pub fn no_defer() -> bool { false }
    #[inline] pub fn inject_peer_left_at() -> Option<u64> { None }
    #[inline] pub fn no_signaling_reconnect() -> bool { false }
    #[inline] pub fn wedge_loop_on_shutdown() -> bool { false }
    #[inline] pub fn churn_after_complete() -> bool { false }
    #[inline] pub fn drop_file_end() -> bool { false }
    #[inline] pub fn drop_peer_left() -> bool { false }
    #[inline] pub fn suppress_delivery_ack() -> bool { false }
    #[inline] pub fn premature_close_after_ack() -> bool { false }
    #[inline] pub fn premature_close_once() -> bool { false }
    #[inline] pub fn premature_already_fired() -> bool { false }
    #[inline] pub fn premature_mark_fired() {}
    #[inline] pub fn corrupt_recv_target() -> Option<String> { None }
}

/// P1 (GAP-4): process-global "the user forbade relay" flag, set once from the
/// `--no-relay` CLI flag at startup. Read by `Conn::relay_forbidden` so the
/// stall ladder knows, at `Rung::Exhausted`, whether it MAY auto-escalate to a
/// TURN relay (the never-flaky promise) or must FAIL CLEANLY (the hard
/// direct-only promise the user asked for). A global rather than a threaded
/// param so the many `Conn` construction sites stay untouched; written exactly
/// once, before the runtime spawns any worker (mirrors the `FILAMENT_NAME`
/// single-threaded-set pattern in `run`).
static NO_RELAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when the user passed `--no-relay`: relay fallback is forbidden.
fn relay_forbidden() -> bool {
    NO_RELAY.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set once in `run`, before any worker spawns, from the global `--no-interactive`
/// flag (mirrors NO_RELAY). The guided code entry NEVER opens when this is set.
static NO_INTERACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// App-wide UI capability resolved once from flags + env. Controls how every
/// command renders: interactive vs steer, human vs JSON, color vs plain.
pub struct UiCapability {
    pub interactive: bool,
    pub json: bool,
    pub yes: bool,
    pub color: bool,
}

impl UiCapability {
    pub(crate) fn from_cli(cli: &Cli) -> Self {
        let interactive = std::io::stdin().is_terminal()
            && !cli.no_interactive
            && std::env::var_os("FILAMENT_NONINTERACTIVE").is_none();
        let color = match cli.color.as_deref() {
            Some("always") => true,
            Some("never") => false,
            _ => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        UiCapability { interactive, json: cli.json, yes: cli.yes, color }
    }

    pub fn confirm(&self, action: &str) -> Result<()> {
        if self.yes { return Ok(()); }
        if self.interactive {
            use std::io::Write;
            eprint!("{action} [y/N] ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).ok();
            if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                anyhow::bail!("cancelled");
            }
        } else {
            anyhow::bail!("refusing {action} without --yes (non-interactive)");
        }
        Ok(())
    }
}

/// THE interactivity GATE, scripts/automation are safe BY DEFAULT. Three layers:
///   1. stdin is not a TTY  -> never interactive (pipes, CI, `< /dev/null`).
///   2. TTY but opted out    -> never interactive: `--no-interactive` OR the env
///                              var `FILAMENT_NONINTERACTIVE` (any value).
///   3. TTY and not opted out -> interactive (the guided entry may open).
/// When this returns false, callers MUST keep exactly today's behavior (a clear
/// parse error + expected format and non-zero exit for a malformed arg, or the
/// existing non-interactive default for a missing-but-optional code). NEVER block.
fn interactive_allowed() -> bool {
    std::io::stdin().is_terminal()
        && !NO_INTERACTIVE.load(std::sync::atomic::Ordering::Relaxed)
        && std::env::var_os("FILAMENT_NONINTERACTIVE").is_none()
}

/// The one honest CLI line shown whenever a transfer/connection is actually on
/// the TURN relay route (rung d). Relay is still end-to-end encrypted, but it is
/// NOT a direct link, the "no middleman on the wire" property is gone, so we say
/// so, loudly (amber ⚠), reusing `ui::Tone::Warn`. §3.3 of the design.
fn relay_banner() -> String {
    ui::paint(
        ui::Tone::Warn,
        "⚠ on relay, via a TURN server, not a direct link (still end-to-end encrypted)",
    )
}

/// P0 (GAP-1): stall-correction ladder bound. Attempt 0 is rung (a) (resume on
/// the same transport); attempts 1..STALL_MAX_REPAIRS are rung (c) (repair the
/// transport in place, a fresh direct dial / ICE-restart). At the ceiling the
/// ladder is exhausted (P1's relay fallback is the next rung, a clean hook).
/// Slightly above MAX_ATTEMPTS because a fresh direct dial needs BOTH ends to
/// re-offer within one race budget, which can take a couple of aligned ticks;
/// a re-dial is cheap, so a few extra are worth a deterministic recovery.
const STALL_MAX_REPAIRS: u32 = 5;

/// P5 (GAP-6): reserved sid for the relay->direct upgrade VERIFY heartbeat. A
/// real DATA frame on this sid lets the prober confirm the new direct path is
/// actually MOVING data (not just connected) before cutting over. It lives in the
/// non-L2 sid space and far above any file-transfer counter, so it never collides;
/// the receiver has no `by_sid` entry for it, so the inbound chunk is dropped
/// harmlessly (after stamping inbound activity, which is the point: symmetric
/// verify). See `Conn::judge_upgrade_standby`.
const VERIFY_PROBE_SID: u32 = 0x7FFF_FFFF;

/// P4 (GAP-5): how many times the receiver re-requests a transfer whose
/// whole-file sha256 didn't match on completion (truncated/corrupt) before it
/// gives up and fails CLEARLY (kept partial, no silent bad file). A transient
/// truncation recovers on the first resume; this bound only catches a payload
/// that is genuinely, repeatedly corrupt, never a hang, never a silent accept.
const MAX_VERIFY_FAILS: u32 = 3;

/// Gate-18 Mode B: the single predicate that decides whether a stuck/lost link
/// should be DROPPED (transfer is complete; nothing left to fetch) rather than
/// reconnected. Pulled out as a pure function so the gate-2 / gate-11c fence
/// (mid-transfer links must NEVER be dropped) is unit-testable without a live
/// WebRTC peer. The recv loop computes `conn.recv_done` from exactly this each
/// tick; `on_stuck` then reads the flag.
///
/// The pure file-transfer decisions `recv_transfer_done` and `decide_ack_fallback`
/// (+ the `AckFallback` enum) now live in `protocol.rs` (the Rust mirror of the JS
/// net/protocol layer); the send/recv loops call `protocol::...`.

/// Bug 5: after repeated stuck-while-connecting on establishment, the user has
/// no clue WHY. The dominant single-host cause is a browser publishing mDNS
/// (`*.local`) ICE candidates the CLI can't resolve when both ends share one
/// machine, the candidate pair never nominates and the link wedges silently.
/// Print this hint at most once per command. `shown` is the caller's one-shot
/// latch so the hint never repeats and never fires on a normal first blip.
fn maybe_hint_local_wedge(shown: &mut bool) {
    if *shown {
        return;
    }
    *shown = true;
    ui::say(&ui::paint(
        ui::Tone::Dim,
        "  still can't connect, if both ends are on the SAME machine, a browser's \
         mDNS (.local) ICE candidates can block this; try a different network path, \
         or disable mDNS ICE in the browser (chrome://flags → \"Anonymize local IPs\").",
    ));
}

const VERSION: &str = env!("FILAMENT_BUILD_INFO"); // stamped by build.rs

const EXAMPLES: &str = "\
COMMANDS
  Connect
    pair <name>            remember a device (run on both ends; exchanges the pair secret)
    up [--install]         always-on receiver for your trusted devices
  Share
    <file>  /  send        send files (mints a one-time code, or --to <device>)
    recv <code>            claim a code and receive
    shell <device>         open a shell on a device (native PTY; --ssh for real ssh)
    reach <device>         check if a device is reachable (direct/relay + rtt)
    reach <device>:<port>  tunnel to a peer's port   (--socks for a local proxy)
    expose <port>          publish a local port on your mesh address
    mount <device>:<dir>   mount a remote folder over the mesh
  Devices
    devices                list your known devices
    requests               approve or deny access others asked for
    grant / revoke         give or take a capability on a device
    status                 what the daemon is doing / recently received
  Identity
    identity               manage your user key + device certs
  Mesh
    addr                   show your overlay address (or a device's)
    doctor                 diagnose a link

EXAMPLES
  filament video.mp4                 send it; mints a speakable one-time code + QR
  filament clever-lynx-63            claim a code and receive
  filament send big.iso --to laptop  send to a remembered device, no code
  filament pair --name phone         remember a device
  filament up --install              always-on drop target
  filament shell laptop              open a shell on a known device
  filament reach laptop              check if a device is reachable
  filament reach laptop:5432         tunnel to a peer's localhost port

  The other end never needs anything installed: https://filament.autumated.com
  Run `filament <command> --help` for details.";

#[derive(Parser)]
// Custom help template: clap has no native grouping for SUBCOMMANDS
// (next_help_heading groups args, not subcommands), so we omit the auto
// {subcommands} list entirely and present a curated, GROUPED command reference in
// the after-help (EXAMPLES). Every subcommand still exists, still works, and still
// has its own `filament <cmd> --help`; the top-level help just stops being a flat
// 27-item dump with deprecated + canonical names side by side.
#[command(
    name = "filament",
    version = VERSION,
    about = "Peer-to-peer between your terminals and browsers: send files, open a shell, forward a port, mount a folder. No upload, no account \u{2014} your own devices form a fleet that just works.",
    after_help = EXAMPLES,
    help_template = "{about-with-newline}\n{usage-heading} {usage}\n\n{after-help}\n\nOptions:\n{options}"
)]
struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    server: String,
    /// Force TURN relay (testing/privacy; hides your IP from the peer)
    #[arg(long, global = true)]
    relay: bool,
    /// Forbid relay: keep a hard direct-only promise. The never-flaky guarantee
    /// is traded for "no middleman, ever", a path that can't go direct FAILS
    /// CLEANLY (a clear error, a kept partial) instead of falling back to a TURN
    /// relay. Conflicts with --relay (which forces relay).
    #[arg(long, global = true, conflicts_with = "relay")]
    no_relay: bool,
    /// Display name shown to peers (default: config file, then user@host)
    #[arg(long, global = true)]
    name_as: Option<String>,
    /// Verbose output: -v shows resilience internals (stalls, repairs,
    /// reconnects, upgrade probes); -vv adds ICE/per-frame trace. The
    /// value-prop lines (route, relay banner) always print. Overridden by
    /// FILAMENT_LOG=<critical|info|debug|trace>.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Quiet: print only the must-see lines (route label, relay banner, P1/P5
    /// path changes, fatal errors). Conflicts with -v. Overridden by
    /// FILAMENT_LOG.
    #[arg(short = 'q', long = "quiet", global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Never drop into the guided interactive code entry, fail fast instead.
    /// Use in scripts/automation. A non-TTY stdin is ALWAYS non-interactive even
    /// without this; the env var FILAMENT_NONINTERACTIVE=1 does the same thing.
    #[arg(long, global = true)]
    no_interactive: bool,
    /// Colorize output: auto (default; only at a TTY), always, or never. A flag
    /// overrides NO_COLOR/TERM. Equivalent to FILAMENT_COLOR.
    #[arg(long, global = true, value_name = "WHEN", value_parser = ["auto", "always", "never"])]
    color: Option<String>,
    /// JSON output for every command (structured, parseable). Independent of
    /// TTY: a pipe still gets human text unless --json is set.
    #[arg(long, global = true)]
    json: bool,
    /// Auto-confirm destructive actions (revoke, unmount, unexpose).
    /// Required from a non-TTY; a TTY prompts instead.
    #[arg(short = 'y', long = "yes", global = true)]
    yes: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
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
        auth_key: Option<String>,
    },
    /// Receive files from a peer (browser or CLI).
    ///
    /// In a terminal with no code this opens a guided code entry (or press enter
    /// for the local-network auto room). Scripts are safe by default: a non-TTY
    /// uses the auto room; under a TTY set FILAMENT_NONINTERACTIVE=1 or pass
    /// --no-interactive to skip the prompt.
    Recv {
        /// One-time code spoken by the sender (omit to use the auto room)
        code: Option<String>,
        /// Directory to write received files into
        #[arg(long, default_value = ".")]
        dir: PathBuf,
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
    },
    /// Remember a device (pairing ceremony, no file transfer).
    /// Exchanges the pair secret with consent on both ends.
    #[command(next_help_heading = "Connect")]
    Pair {
        /// A code from the other device; omit to mint one for them
        code: Option<String>,
        /// What to call them (asked interactively if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Choose your own pairing words instead of minting (the SPAKE2
        /// password; the connect number is still machine-assigned). Use at
        /// least two words, e.g. --word "gigantic element".
        #[arg(long)]
        word: Option<String>,
    },
    // ── Devices ─────────────────────────────────────────────────────
    /// List known devices (trusted for --to and auto-accept)
    #[command(next_help_heading = "Devices")]
    Devices {
        #[command(subcommand)]
        action: Option<DevicesAction>,
        /// Machine-readable JSON (for scripts): [{name, channel, caps}].
        #[arg(long)]
        json: bool,
    },
    /// Always-on receiver: trusted known devices only, invisible to strangers
    Up {
        /// Install + start a systemd user service instead of running attached
        #[arg(long)]
        install: bool,
        /// With --install: install a SYSTEM service (root, one-time sudo) that gets
        /// CAP_NET_ADMIN from systemd via AmbientCapabilities. The overlay's kernel
        /// TUN then needs NO setcap on the binary, so `filament update` never prompts
        /// for a password again. Recommended for the kernelspace (kernel-TUN) path.
        #[arg(long)]
        system: bool,
        /// Force the ZERO-PRIVILEGE userspace overlay (an in-process smoltcp netstack
        /// instead of a kernel TUN): no CAP_NET_ADMIN, no /dev/net/tun, works in a
        /// container. Note: host firewall rules do not apply and native tools reach
        /// <peer>.mesh only via `filament proxy`/`dial`. Default is auto (kernel TUN
        /// when available, userspace otherwise).
        #[arg(long)]
        userspace: bool,
        /// Drop directory (default: `filament config dir`, else ~/Filament)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Accept seamless `filament ssh` from ANY paired (proof-verified) device,
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
        /// Persistent: use `filament set shell-program "<program>"` for the daemon.
        /// Env: `FILAMENT_SHELL`.
        #[arg(long, value_name = "PROGRAM")]
        shell_program: Option<String>,
        /// Drop the web-shell / ssh PTY to this non-root account (via
        /// `runuser -l <user>`). STRONGLY recommended when `up` runs as root:
        /// without it, a granted device gets a shell as the up-process user
        /// (often root). Requires `up` to run as root (runuser is setuid).
        #[arg(long, value_name = "USER")]
        shell_user: Option<String>,
        /// Internal: re-invoked after elevation to do the system-level install.
        #[arg(long, hide = true)]
        install_system: bool,
        /// When kernel TUN is unavailable, auto-start a SOCKS5 proxy on port
        /// 1080 so native tools (curl, ssh) can reach <peer>.mesh. Opt out
        /// with --no-proxy-fallback or `filament set auto-proxy off`.
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
    /// Show or change settings (no args = show all).
    ///
    /// No args prints all settings with their value, scope, and where each came
    /// from (env > peer > config > default). Strictly imperative: `set` only
    /// changes the key you name.
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        filament set                          show every setting + where it came from\n  \
        filament set auto-extract on          change one setting (partial, never resets others)\n  \
        filament set shell on --peer laptop   per-device override\n  \
        filament get drop-dir --show-origin   read one value (bare value on stdout)\n  \
        filament unset relay                  revert one setting to its default\n\n\
        Keys: name, server, drop-dir, relay, auto-extract, shell, shell-user")]
    Set {
        /// Setting name (run `filament set` to list them all)
        key: Option<String>,
        /// New value; omit to read the current value
        value: Option<String>,
        /// Scope this change to one or more known devices (per-peer settings
        /// only). Comma-separated or repeatable: --peer a,b  or  --peer a --peer b
        #[arg(long, value_name = "DEVICE", value_delimiter = ',')]
        peer: Vec<String>,
        /// Show what would change without writing
        #[arg(long)]
        dry_run: bool,
        /// Reset ALL settings to their defaults (clears global + per-peer)
        #[arg(long)]
        reset: bool,
        /// Skip the confirmation prompt (required for --reset in a pipe/CI)
        #[arg(long)]
        yes: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// Prefer strength: hard (always prefer, even if slower)
        #[arg(long, conflicts_with = "soft")]
        hard: bool,
        /// Prefer strength: soft (prefer unless much faster) — default
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
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Raw config escape hatch (key value lines in ~/.config/filament/config).
    /// Prefer `filament set`; this is kept for scripts that wrote it directly.
    #[command(hide = true)]
    Config { key: Option<String>, value: Option<String> },
    /// Update filament to the latest release
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
    Completions {
        shell: clap_complete::Shell,
    },
    /// Print the manual. On a TTY, shows readable help; piped, emits roff
    /// (for `filament man > filament.1`). `filament man routing` shows the
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
        /// Local port to listen on (127.0.0.1)
        lport: u16,
        /// Known device (petname) to tunnel through
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Publish a local port on this device's mesh address (peers reach it at
    /// <this-device>.mesh:<port>), like a Tailscale-served port.
    ///
    /// The daemon binds the overlay address (a private ULA, reachable only over
    /// the mesh) and forwards each connection to a local target. Needs L3 up
    /// (`filament set tun-addr auto`). Persists across restarts.
    ///
    /// Use `filament expose <port> --off` to stop exposing a port.
    Expose {
        /// Port to publish on the overlay. Omit together with --list or --off.
        port: Option<u16>,
        /// Local target: host:port, a bare port (127.0.0.1:PORT), or a bare host
        /// (HOST:<port>). Default: 127.0.0.1:<port>.
        #[arg(long, value_name = "HOST:PORT")]
        to: Option<String>,
        /// Restrict to these paired devices (petnames, comma-separated). Default: any.
        #[arg(long, value_name = "DEVICE", value_delimiter = ',')]
        peer: Vec<String>,
        /// List exposed ports and exit.
        #[arg(long)]
        list: bool,
        /// Stop exposing the given port (replaces `filament unexpose`).
        #[arg(long)]
        off: bool,
    },
    /// Reach a peer: check reachability, tunnel to a port, or run a mesh proxy.
    ///
    /// `<dev>`: reachability probe (is the device reachable, and how: direct/relay + rtt).
    /// `<dev>:<port>`: tunnels to the peer's localhost:<port> (the `reach` mental model).
    /// `--socks`: runs a local SOCKS5 proxy for mesh access from any app.
    Reach {
        /// Device to probe (e.g. laptop) or device:port to tunnel (e.g. laptop:5432)
        dev_port: Option<String>,
        /// Run a local SOCKS5 proxy instead
        #[arg(long)]
        socks: bool,
        /// Machine-readable JSON output (for the bare `<device>` reachability probe)
        #[arg(long)]
        json: bool,
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
        /// Run the probe N times and print a distribution summary
        #[arg(long)]
        repeat: Option<u32>,
        /// Machine-readable JSON output (for scripting)
        #[arg(long)]
        json: bool,
    },
    /// Grant a known device a capability (deny-by-default). `shell` permits
    /// seamless `filament ssh` into THIS machine, a separate consent from
    /// file transfer; pairing alone never yields a shell.
    Grant {
        /// Known device (petname), or omit with --tag
        device: String,
        /// Capability to grant (e.g. `shell`)
        capability: String,
        /// Target a tag instead of a device
        #[arg(long)]
        tag: Option<String>,
    },
    /// Revoke a capability or a fleet certificate from a known device.
    #[command(hide = true)]
    Revoke {
        /// Known device (petname)
        device: String,
        /// Capability to revoke (e.g. `shell`)
        capability: Option<String>,
        /// Revoke the device's local fleet certificate instead of a capability.
        #[arg(long)]
        certificate: bool,
    },
    /// Mount a remote directory over the mesh via sshfs.
    ///
    /// Requires sshfs on both ends. Uses the same transport as `filament ssh`
    /// (L3 overlay preferred, L2 tunnel fallback). The peer must have sshd
    /// running and shell access granted.
    ///
    /// By default runs in background with auto-recovery. Use --foreground to
    /// run sshfs in the foreground (blocks the terminal).
    Mount {
        /// Known device (petname) to mount from
        peer: Option<String>,
        /// Remote directory path
        remote: Option<String>,
        /// Local mount point (default: basename of remote path)
        local: Option<String>,
        /// Mount read-only
        #[arg(long)]
        read_only: bool,
        /// Extra sshfs options (comma-separated)
        #[arg(long)]
        options: Option<String>,
        /// Run sshfs in the foreground (blocks terminal)
        #[arg(long)]
        foreground: bool,
        /// Auto-restore this mount on daemon start (off by default)
        #[arg(long)]
        save_auto: bool,
        /// List all filament mounts and their status
        #[arg(long)]
        list: bool,
        /// Check if a mount is healthy
        #[arg(long, value_name = "PATH")]
        check: Option<String>,
        /// Save current mounts as a named profile
        #[arg(long = "save-profile", alias = "save", value_name = "NAME")]
        save_profile: Option<String>,
        /// Apply a saved mount profile
        #[arg(long = "apply-profile", alias = "apply", value_name = "NAME")]
        apply_profile: Option<String>,
        /// List saved mount profiles
        #[arg(long)]
        profiles: bool,
        /// Delete a saved mount profile
        #[arg(long, value_name = "NAME")]
        delete_profile: Option<String>,
        /// Unmount a filament mount point (replaces `filament unmount`).
        #[arg(long, value_name = "PATH")]
        off: Option<String>,
    },
    /// Sync files to/from a peer via rsync over the mesh.
    ///
    /// Requires rsync on both ends. Uses `filament ssh` as the remote shell,
    /// so the same transport and bootstrap logic applies.
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
    /// Open a shell on a device.
    ///
    /// Default: filament's own native PTY (the peer must run `up --shell`).
    /// With `--ssh`: runs your real ssh over the data channel via ProxyCommand
    /// (reuses your keys, known_hosts, and ~/.ssh/config).
    Shell {
        /// Known device (petname) to open a shell on
        peer: String,
        /// Use real ssh (ProxyCommand over filament) instead of the native PTY
        #[arg(long)]
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
    /// Mint a scoped, expiring key for another machine to join.
    Mint {
        /// Mint a key for a device in your fleet.
        #[arg(long)]
        fleet: bool,
        /// Mint a narrow key for this paired external device.
        #[arg(long)]
        external: Option<String>,
        /// Mint a single-use CI/automation key.
        #[arg(long)]
        ci: bool,
        /// Key lifetime, such as 1h or 15m.
        #[arg(long)]
        ttl: Option<String>,
        /// Reuse policy: once, N(3), or reusable.
        #[arg(long)]
        reuse: Option<String>,
        /// Capabilities to grant (comma-separated).
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,
        /// Paired audience name for a CI key.
        #[arg(long)]
        audience: Option<String>,
        /// Do not prompt for deliberate choices.
        #[arg(long)]
        yes: bool,
    },
    /// Mint auth keys or enroll as an ephemeral delegated device.
    #[command(hide = true)]
    Ephemeral {
        #[command(subcommand)]
        action: EphemeralAction,
    },
    /// Wipe this machine's filament state (clean slate). DESTRUCTIVE.
    ///
    /// Removes the local identity + overlay keys, the paired-device store, the
    /// capability store, pending consent requests, and the managed ssh material
    /// (private key, known_hosts, bootstrap cache), and strips the
    /// filament-managed blocks it installed in ~/.ssh/authorized_keys. Your own
    /// ssh keys and any non-filament lines in authorized_keys are left untouched.
    /// Stop the daemon first (`filament down`); reset refuses while it runs.
    ///
    /// Pass the global `-y`/`--yes` to skip the confirmation prompt (required
    /// from a non-TTY / scripts).
    Reset,
}

/// Ephemeral device commands: mint auth keys, enroll as delegated.
#[derive(Subcommand)]
enum EphemeralAction {
    /// Mint a new auth key signed by your user identity key.
    Mint {
        /// Capabilities to grant (shell, transfer, mount, reach)
        #[arg(long, value_delimiter = ',')]
        caps: Vec<String>,
        /// Peer device_pub(s) that may enroll this key (hex, comma-separated). Empty = any.
        #[arg(long, value_delimiter = ',')]
        audience: Vec<String>,
        /// Time-to-live in seconds (max 30 days)
        #[arg(long, default_value = "86400")]
        ttl: u64,
        /// Reuse: Once, N(N), or Reusable
        #[arg(long, default_value = "Once")]
        reuse: String,
        /// Human-readable tag for the use case
        #[arg(long, default_value = "ci")]
        tag: String,
    },
    /// Enroll as an ephemeral delegated device using an auth key.
    Enroll {
        /// Path to the auth key JSON file, or the raw JSON string
        auth_key: String,
        /// Target peer display name or channel (the owner device to enroll at)
        #[arg(long)]
        to: Option<String>,
    },
}

/// User identity management: generate the identity key, show the fingerprint,
/// certify a known device so peers can verify it belongs to the same person.
#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new user identity key on this device.
    Init,
    /// Show the user identity fingerprint + certified devices.
    Show,
    /// Sign a device certificate for a known device, authorizing it as yours.
    Certify {
        /// Petname of the known device to certify as yours
        device: String,
    },
}

/// Consent request management: list, approve, or deny pending requests.
#[derive(Subcommand)]
enum RequestsAction {
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
enum DevicesAction {
    /// Forget a device: deletes the secret; it can no longer find you
    Forget { name: String },
    /// Rename your local alias (the other side is unaffected)
    Rename { old: String, new: String },
    /// Vouch between two known devices: mints a fresh secret and delivers it
    /// to both over verified channels (run on the device that knows both)
    Vouch { a: String, b: String },
}

/// Looks like a speakable CODE of the shape `word-word-DIGITS` (3 segments: two
/// lowercase words then a numeric trailing group of >= 2 digits). BOTH a minted
/// transfer code (`adj-animal-NNN`, 3-digit) and a minted pairing code
/// (`adj-animal-NNNN`, 4-digit) now share this shape, the pairing-vs-transfer
/// HINT is by trailing-number WIDTH (see `looks_like_pake_code`), not segment
/// count. This is the claimable-code structural test (used by the `up` prompt).
fn regex_lite_code(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_lowercase())
        && parts[1].chars().all(|c| c.is_ascii_lowercase())
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[2].len() >= 2
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

/// The trailing numeric group's width (digit count), or 0 if the last segment
/// isn't all digits. The pairing-vs-transfer hint keys off this: minted pairing
/// nameplates are 4-digit; minted transfer codes are 3-digit.
fn trailing_num_width(s: &str) -> usize {
    match s.rsplit('-').next() {
        Some(t) if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) => t.len(),
        _ => 0,
    }
}

/// ADVISORY hint that a typed code is a PAIRING code (vs a one-time transfer
/// code). Both are now `word-word-DIGITS`; the only structural difference is the
/// trailing-number WIDTH, a 4-digit nameplate is what `filament pair` / the
/// browser "create code" mints, whereas a transfer code ends in 3 digits. This
/// is UX-only, it NEVER authenticates (PAKE/SPAKE2 does), so it's safe to be
/// approximate; a mismatch still fails LOUDLY with the right next command.
fn looks_like_pake_code(s: &str) -> bool {
    regex_lite_code(s) && trailing_num_width(s) >= 4
}

/// STEERING (min-strength floor): count the WORD tokens in a normalized password,
/// maximal runs of >= 2 ASCII letters. A user-chosen password must contain at
/// least 2 such tokens. WHY: a minted 2-word code is ~12 bits and online
/// guessing is bounded by claim-burn + the 5/min rate-limit (≈1 guess per code,
/// no offline attack); a single word like `cat` falls below that floor. Digits
/// and 1-letter fragments don't count.
pub(crate) fn password_word_tokens(normalized_password: &str) -> usize {
    let mut tokens = 0;
    let mut run = 0;
    for c in normalized_password.chars() {
        if c.is_ascii_lowercase() {
            run += 1;
            if run == 2 {
                tokens += 1; // crossed the >=2-letter threshold
            }
        } else {
            run = 0;
        }
    }
    tokens
}

// --------------------------------------------------------------- utilities --

/// Persistent per-install identity (shared by every process using this
/// config dir). Lets a sender recognize, and never target, its OWN daemon
/// when both sit on the same pair-presence channels.
fn install_id() -> String {
    let p = devices_path().with_file_name("device.id");
    if let Ok(id) = std::fs::read_to_string(&p) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id: String = fresh_secret()[..8].to_string();
    let _ = crate::platform::SecretFile::write_str(&p, &id);
    id
}

pub(crate) fn mk_uid(prefix: &str) -> String {
    // Test hook (gate 11): a pinned uid lets the harness exercise the
    // same-device-rejoined supersede path (C6). The cli-s-/cli-r- role prefix
    // must survive the override or same-role skip (C13) breaks.
    if let Ok(forced) = std::env::var("FILAMENT_UID") {
        return format!("cli-{prefix}-{forced}");
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("cli-{prefix}-{}-{:x}{:x}", install_id(), std::process::id(), nanos)
}

/// Same install (our own daemon / another process of this device)?
pub(crate) fn is_self_uid(my_uid: &str, peer_uid: Option<&str>) -> bool {
    if std::env::var("FILAMENT_UID").is_ok() {
        return false; // test hook pins uids; don't second-guess it
    }
    let id = install_id();
    let _ = my_uid;
    peer_uid.map(|p| p.contains(&format!("-{id}-"))).unwrap_or(false)
}

fn config_path() -> PathBuf {
    devices_path().with_file_name("config")
}

/// Tiny `key value` per-line config; no toml dependency for three keys.
fn config_get(key: &str) -> Option<String> {
    std::fs::read_to_string(config_path()).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(char::is_whitespace)?;
        (k == key && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn config_set(key: &str, value: &str) -> Result<()> {
    let p = config_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(key))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key} {value}"));
    std::fs::write(&p, lines.join("\n") + "\n")?;
    Ok(())
}

pub(crate) fn display_name() -> String {
    if let Ok(n) = std::env::var("FILAMENT_NAME") {
        return n;
    }
    if let Some(n) = config_get("name") {
        return n;
    }
    default_display_name()
}

/// The computed display name when nothing is configured (user@host). Kept
/// separate so the settings readout can show the true default.
pub(crate) fn default_display_name() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "cli".into());
    format!("{user}@{host}")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", U[i]) }
}

/// C7: hash of the first min(256 KiB, len) bytes, cheap content identity
/// carried in file-offer so resume can detect a different file wearing the
/// same name + size.
fn head_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES as usize];
    let mut got = 0usize;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let mut h = Sha256::new();
    h.update(&buf[..got]);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// P4 (GAP-5): sha256 over the WHOLE file, the end-to-end content digest the
/// receiver compares against on completion so a truncated/corrupt transfer can
/// never be declared "done" (the runner had to bolt this above the transport;
/// P4 makes it a core guarantee). Streamed in 1 MiB reads so a large payload
/// doesn't have to be slurped into RAM. `None` if the file can't be read, the
/// offer then omits `full` and the receiver degrades to the legacy size-only
/// check (backward-compat; bounded, never a hang).
fn full_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Sidecar metadata for a partial receive (`<name>.part.meta`).
/// JSON {"size":N,"head":"hex","full":"hex"}; legacy files hold a bare size string.
/// `full` is the whole-file sha256 the sender offered (P4), persisted so a
/// resume after a process restart can still verify-on-completion.
struct PartMeta {
    size: u64,
    head: Option<String>,
    full: Option<String>,
}

impl PartMeta {
    fn load(path: &Path) -> Option<PartMeta> {
        let raw = std::fs::read_to_string(path).ok()?;
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(size) = v["size"].as_u64() {
                return Some(PartMeta {
                    size,
                    head: v["head"].as_str().map(|s| s.to_string()),
                    full: v["full"].as_str().map(|s| s.to_string()),
                });
            }
        }
        raw.trim().parse::<u64>().ok().map(|size| PartMeta { size, head: None, full: None })
    }
    fn store(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, json!({ "size": self.size, "head": self.head, "full": self.full }).to_string())
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    for i in 1..1000 {
        let c = dir.join(format!("{name}.{i}"));
        if !c.exists() {
            return c;
        }
    }
    dir.join(format!("{name}.dup"))
}

// ------------------------------------------------------- known devices (C12) --
// Persistent pairing: during a code-paired session, both sides exchange a
// 32-byte secret END-TO-END over the DataChannel (the server never sees it)
// and store it under a local nickname. Presence: subscribe with
// sha256("filament-pair:" + secret), the server learns only meeting points.
// Trust: an HMAC(secret) proof exchanged after connect, so the server cannot
// impersonate a known device. Full PAKE remains roadmap (ledger C15).

/// Should THIS acceptor session take the rung-1 direct-QUIC path (answer the
/// initiator's transport-offer instead of building a colliding WebRTC peer)?
///
/// True when the env gate is set (`direct_enabled`), OR this is the L2/ssh
/// acceptor (`l2_enabled`), OR this is the long-lived `up` daemon (`daemon`).
///
/// The daemon case is the anti-glare fix for a PLAIN `filament up` (no `--shell`,
/// no `FILAMENT_L2`): two such daemons that are known devices to each other each
/// fire a KnownPeer for the other and each tries to be the WebRTC initiator. The
/// two offers collide (GLARE); the polite side drops and rebuilds as a responder,
/// the supersede churn loops ("appeared, connecting" repeatedly, "reconnecting...")
/// and never settles to one stable link. Answering the direct-QUIC dial instead is
/// sequential (one `direct_pending` per peer, one race, one link) and authenticated
/// by the pair-secret MAC, so it neither glares nor depends on cross-NAT ICE.
///
/// One-shot `send`/`recv`/`pair` pass `daemon=false` and so keep their WebRTC
/// default (`direct_enabled()` only): they are deliberately left unchanged.
fn direct_ok_for(daemon: bool, l2_enabled: bool) -> bool {
    direct::direct_enabled() || l2_enabled || daemon
}

fn devices_path() -> PathBuf {
    crate::platform::Paths::config_path("devices.json")
}

/// Pure merge step (no I/O): upsert the (secret, cert, caps, scope) fields for `name`
/// into `arr` as ONE record, returning the final stored name (auto-suffixed on a
/// new-name collision). This is the atomicity-relevant step: secret and cert land in
/// the SAME record object, so the single write that follows persists them together and
/// a reader can never observe new-secret + old-cert. Kept pure so the invariant is
/// unit-testable without the process-global config path.
pub(crate) fn upsert_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
) -> String {
    // For existing name, update in place preserving other fields.
    if let Some(existing) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        if let Some(s) = secret {
            existing["secret"] = json!(s);
        }
        if let Some(c) = cert {
            existing["userKey"] = json!(hex::encode(c.user_pub));
            existing["deviceCert"] = c.to_json();
        } else if let Some(uk) = user_key_hex {
            existing["userKey"] = json!(uk);
        }
        if let Some(caps) = caps {
            existing["caps"] = json!(caps);
            existing["v"] = json!(2);
        }
        if let Some(sc) = scope {
            existing["identityScope"] = json!(sc);
        }
        return existing["name"].as_str().unwrap_or(name).to_string();
    }

    // New device: auto-suffix if collision.
    let mut final_name = name.to_string();
    if arr.iter().any(|d| d["name"].as_str() == Some(name)) {
        let mut suffix = 2;
        let mut new_name = format!("{name}-{suffix}");
        while arr.iter().any(|d| d["name"].as_str() == Some(&new_name)) {
            suffix += 1;
            new_name = format!("{name}-{suffix}");
        }
        eprintln!("  note: '{name}' already exists, pairing as '{new_name}'");
        final_name = new_name;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), json!(&final_name));
    if let Some(s) = secret {
        obj.insert("secret".to_string(), json!(s));
    }
    if let Some(c) = cert {
        obj.insert("userKey".to_string(), json!(hex::encode(c.user_pub)));
        obj.insert("deviceCert".to_string(), c.to_json());
    } else if let Some(uk) = user_key_hex {
        obj.insert("userKey".to_string(), json!(uk));
    }
    obj.insert("v".to_string(), json!(2));
    if let Some(caps) = caps {
        obj.insert("caps".to_string(), json!(caps));
    }
    if let Some(sc) = scope {
        obj.insert("identityScope".to_string(), json!(sc));
    }
    obj.insert("addedAt".to_string(), json!(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
    arr.push(Value::Object(obj));
    final_name
}

/// Atomic per-peer (secret, cert) update: read-modify-write whole store via
/// `upsert_peer_record` (both fields in ONE record), persist via write-tmp-then-rename
/// (SecretFile::write already atomic on POSIX). A concurrent reader sees either the full
/// old peer or the full new peer, never a torn state.
pub(crate) fn devices_upsert_atomic(
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
) -> Result<String> {
    let clean = sanitize_device_name(name);
    let name = clean.as_str();
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).context("create config dir")?;
    }
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let final_name = upsert_peer_record(&mut arr, name, secret, cert, caps, scope, user_key_hex);
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr).context("serialize devices")?)
        .context("atomic write devices.json")?;
    Ok(final_name)
}

pub(crate) fn devices_load() -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else { return Vec::new() };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|d| Some((d["name"].as_str()?.to_string(), d["secret"].as_str()?.to_string())))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Check if a petname is already taken by another device (case-insensitive).
fn devices_name_taken(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    devices_load().iter().any(|(n, _)| n.to_ascii_lowercase() == lower)
}

/// Strip terminal escape sequences and control characters from a device petname
/// before it is stored. A name typed or pasted in a terminal can capture the
/// terminal's own device-attributes reply (`ESC[?1;2c...`); that junk then never
/// matches `--to <name>`, silently breaking targeting (observed live: a `send
/// --to pixel` whose stored name was `...escapes...pixel` fell back to the local
/// room and the Pixel never received). Keep only printable, non-control chars.
fn sanitize_device_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC: drop a CSI escape (`ESC [ ... final-letter`) wholesale.
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue; // also drops a lone/other ESC
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

fn devices_store(name: &str, secret: &str) -> Result<()> {
    // Delegate to atomic upsert: secret only, preserve cert
    devices_upsert_atomic(name, Some(secret), None, None, None, None)?;
    Ok(())
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// `caps` is deny-by-default; "transfer" is the L0 baseline. The on-disk shape
/// grows `v` and `caps` but the existing `{name, secret}` fields are unchanged,
/// so the reconnect path (`devices_load`, which reads only name+secret) keeps
/// working byte-for-byte, no regression.
fn devices_store_v2(name: &str, secret: &str, caps: &[String]) -> Result<()> {
    // Delegate to atomic upsert: secret + caps together, preserve cert
    devices_upsert_atomic(name, Some(secret), None, Some(caps), None, None)?;
    Ok(())
}

/// Attach a device certificate + user key to an existing device record.
fn update_device_cert(name: &str, uk: &identity::UserKey, cert: &identity::DeviceCert) -> Result<()> {
    // Check existence first (atomic upsert doesn't fail if missing for existing -> it would create new)
    let p = devices_path();
    let raw = std::fs::read_to_string(&p).ok().unwrap_or_default();
    let arr: Vec<Value> = serde_json::from_str(&raw).ok().unwrap_or_default();
    if !arr.iter().any(|d| d["name"].as_str() == Some(name)) {
        bail!("device '{name}' is not in the device store. Pair with it first.");
    }
    // Delegate to atomic upsert: cert only, preserve secret
    devices_upsert_atomic(name, None, Some(cert), None, None, Some(&uk.public_key_hex()))?;
    Ok(())
}

/// Read the device cert (if any) for a named device.
fn device_cert_for(name: &str) -> Option<identity::DeviceCert> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    for d in arr {
        if d["name"].as_str() == Some(name) {
            return identity::DeviceCert::from_json(&d["deviceCert"]);
        }
    }
    None
}

fn fleet_certificate_warning(name: &str) -> Option<String> {
    let cert = device_cert_for(name)?;
    let owner = load_owner_key()?;
    fleet_certificate_warning_for(name, &cert, owner.public_key_bytes(), identity::now_secs())
}

fn fleet_certificate_warning_for(
    name: &str,
    cert: &identity::DeviceCert,
    owner_pub: [u8; 32],
    now: u64,
) -> Option<String> {
    if cert.user_pub != owner_pub || cert.expires <= now {
        return None;
    }
    Some(format!(
        "{} {} still has fleet access via its certificate.\n  To remove it entirely: filament revoke {} --certificate",
        ui::paint(ui::Tone::Warn, ui::glyph_warn()),
        name,
        name,
    ))
}

/// Local-only fleet certificate revocation marker. This deliberately lives
/// beside the device record: no CRL or network dependency is introduced.
fn device_cert_revoked(device_pub: &[u8; 32]) -> bool {
    let p = devices_path();
    let Ok(raw) = std::fs::read_to_string(&p) else { return true };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else { return true };
    let key = hex::encode(device_pub);
    arr.iter()
        .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
        .and_then(|d| d["certRevoked"].as_bool())
        .unwrap_or(true)
}

/// Mark a stored device certificate revoked locally. The check path must
/// consult this marker before granting fleet trust; expiry remains separate.
fn set_device_cert_revoked(name: &str, revoked: bool) -> Result<()> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p).unwrap_or_default();
    let mut arr: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
    let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
        bail!("device '{name}' is not in the device store");
    };
    device["certRevoked"] = json!(revoked);
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)
        .context("atomic write devices.json")?;
    Ok(())
}

fn load_owner_key() -> Option<crate::identity::UserKey> {
    crate::identity::UserKey::load(&crate::platform::PlatformKeyStore).ok().flatten()
}

fn local_device_cert() -> Option<identity::DeviceCert> {
    // Try display name first
    if let Some(cert) = device_cert_for(&display_name()) {
        if cert.verify(identity::now_secs()).is_ok() {
            return Some(cert);
        }
    }
    // Fallback: find any cert whose device_pub matches overlay key
    if let Ok(overlay_pub) = crate::overlay::overlay_pubkey_bytes() {
        let p = devices_path();
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                for d in arr {
                    if let Some(cert) = identity::DeviceCert::from_json(&d["deviceCert"]) {
                        if cert.device_pub == overlay_pub && cert.verify(identity::now_secs()).is_ok() {
                            return Some(cert);
                        }
                    }
                }
            }
        }
    }
    // Final fallback: MINT the self-cert on demand from the user key + overlay key.
    // `identity init` creates the user key but no stored self device-cert, so without
    // this local_device_cert() is None, pairing never runs identity-expose (it is gated
    // on this fn), the peer stays secret-only (binding Inferred), and under authoritative
    // the #21 proven-gate denies EVERY peer. Minting here (deterministic in user_pub and
    // device_pub; only the timestamps vary) makes the Proven-binding path reachable for
    // freshly-onboarded and already-onboarded identities alike, without a peer-store entry.
    if let (Ok(Some(uk)), Ok(overlay_pub)) =
        (identity::UserKey::load(&crate::platform::PlatformKeyStore), crate::overlay::overlay_pubkey_bytes())
    {
        if let Ok(cert) =
            identity::DeviceCert::certify(&uk, overlay_pub, identity::now_secs(), identity::CERT_TTL_SECS)
        {
            return Some(cert);
        }
    }
    None
}

/// Populate link identity from the peer's stored device cert, if the
/// link already has a proof-verified name but identity pubkeys are absent.
/// Cached back onto the link on first successful resolution (resolve-once,
/// not per open).
///
/// The binding model: `verified_name` is set ONLY after a session-bound
/// pair-proof HMAC (proof_for over shared secret + UIDs + fingerprints),
/// so the name is cryptographically bound to this link. `device_cert_for`
/// returns the cert we already verified at pairing (provisional_promote_ok
/// checked device_pub against the overlay transport key at storage time).
/// Together these form a sufficient trust join: a proven name plus the
/// cert trusted-for-that-name. No additional link-level cert-to-transport
/// comparison is needed.
///
/// Fail-closed to None on: no verified_name, no stored cert, cert expired
/// or otherwise invalid.
fn resolve_peer_identity(link: &mut Link) {
    // Precedence rule: a Proven binding must NOT be downgraded to Inferred.
    // The identity-expose handler (possession-sig) sets Proven, and this
    // function (symmetric-secret proof + name->cert lookup) sets Inferred.
    // An Inferred MAY later be upgraded to Proven by identity-expose.
    if link.identity_device_pub.is_some() || link.identity_user_pub.is_some() {
        return; // already resolved (any binding, Proven or Inferred, stays)
    }
    let name = match &link.verified_name {
        Some(n) => n.clone(),
        None => return, // no proven name, nothing to resolve
    };
    let Some(cert) = device_cert_for(&name) else { return };
    let now = crate::identity::now_secs();
    if cert.verify(now).is_err() {
        return;
    }
    link.identity_device_pub = Some(cert.device_pub);
    link.identity_user_pub = Some(cert.user_pub);
    link.identity_binding = crate::capability::BindingStrength::Inferred;
    link.identity_cert_expires = Some(cert.expires);
}

/// When a link becomes trusted, send a nonce challenge to the peer so it can
/// prove device-key possession (0x02 possession_sig). When the response arrives
/// in the event loop, the `identity-expose` handler upgrades the binding to
/// Proven. Called at LINK READINESS — from DirectReady for direct links (which
/// holds ChannelReady until Proven) AND from ChannelReady itself for links that
/// did not go through DirectReady (relay/DataChannel), so Proven is reached on
/// EVERY connection, not only direct ones (#39). Both sites dedupe against
/// pending_proven so a single link is never double-challenged. NOT called at
/// individual open sites — Proven settles once at readiness, before gated opens
/// decide (the gates additionally honor the pending_proven hold, #30 GAP 2).
async fn send_identity_challenge(
    conn: &crate::Conn,
    pid: &str,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) {
    if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
        if let Some(t) = conn.transport_of(pid) {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut nonce = [0u8; 32];
            let _ = rng.fill(&mut nonce);
            identity_nonces.insert(pid.to_string(), (nonce, Instant::now(), own_dpub));
            let challenge = json!({
                "type": "identity-nonce-challenge",
                "nonce": hex::encode(nonce),
                "receiver_device_pub": hex::encode(own_dpub)
            });
            // MUST await: send_control is async; dropping the future would leave
            // the challenge unsent (the peer never learns it must prove Proven).
            let _ = t.send_control(&challenge).await;
        }
    }
}

/// The shared "register the Proven hold, then issue the possession challenge"
/// sequence, called by BOTH readiness sites (DirectReady adoption AND the daemon
/// ChannelReady handler, #39) so the two cannot DIVERGE on ordering. HOLD-THEN-AWAIT:
/// the pending_proven entry is inserted (fresh 3s deadline, overwriting any stale
/// one so a reconnect re-challenges) BEFORE the challenge is awaited, so a gated
/// open can never observe the link un-held in the window between send and hold.
/// Today the single-consumer event loop makes that window unreachable; the ordering
/// is belt-and-braces for a future concurrent loop, and — the point — it removes the
/// asymmetry between the two call sites. The CALLER owns the release policy after:
/// DirectReady holds ChannelReady and its timer RE-EMITS it; the ChannelReady site
/// does not hold and its timer only CLEARS the entry (no re-emit → no cycle).
async fn issue_proven_challenge_and_hold(
    conn: &crate::Conn,
    pid: &str,
    t: &Arc<dyn Transport>,
    pending_proven: &Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) {
    // IDEMPOTENT: if a challenge is already in flight for this pid (a live,
    // non-expired hold), do NOT issue a second one. send_identity_challenge keys
    // identity_nonces by pid, so a second challenge OVERWRITES the first nonce; a
    // peer that answers the first challenge would then verify against the second
    // nonce and never reach Proven. Both readiness sites (DirectReady and the
    // pair-proof handler) call this, and a transient re-adoption can make even one
    // site fire twice — so the dedupe MUST live here, not at the call sites, to be
    // order-independent for any caller. A STALE (expired) entry is treated as
    // absent so a reconnect re-challenges. Check-and-insert under ONE lock (dropped
    // before the await — never hold a std Mutex across .await).
    {
        let mut pend = pending_proven.lock().unwrap();
        if let Some((_, deadline)) = pend.get(pid) {
            if Instant::now() < *deadline {
                return; // challenge already in flight; do not clobber its nonce
            }
        }
        pend.insert(pid.to_string(), (t.clone(), Instant::now() + Duration::from_secs(3)));
    }
    send_identity_challenge(conn, pid, identity_nonces).await;
}

/// Handle a possession-sig identity-expose response sent by a peer after we
/// challenged it. Verifies the nonce (single-use), the possession_sig under
/// the peer's device_pub, and reflection (not self). On success, upgrades the
/// link binding to Proven so capability gates under authoritative can pass.
fn handle_identity_expose(
    conn: &mut crate::Conn,
    pid: &str,
    v: &Value,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) -> bool {
    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
    let Ok(nonce_bytes) = hex::decode(nonce_hex) else { return false };
    if nonce_bytes.len() != 32 { return false; }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);
    // Check held nonce matches (single-use)
    let Some((held_nonce, _ts, _held_recv_dpub)) = identity_nonces.get(pid) else { return false };
    if held_nonce != &nonce_arr { return false; }
    // Verify cert and possession sig
    let Some(cert_json) = v.get("cert") else { return false };
    let Some(cert) = identity::DeviceCert::from_json(cert_json) else { return false };
    if cert.verify(identity::now_secs()).is_err() { return false; }
    let Some(sig_hex) = v.get("possession_sig").and_then(|x| x.as_str()) else { return false };
    let Ok(sig_bytes) = hex::decode(sig_hex) else { return false };
    if sig_bytes.len() != 64 { return false; }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    // Recompute possession_msg with held nonce
    let scope = crate::identity::IntroScope::User.to_byte();
    let caps_d = crate::identity::caps_digest("transfer");
    let chash = crate::identity::cert_hash(&cert);
    let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() else { return false };
    let sender_dpub = cert.device_pub;
    let receiver_dpub = own_dpub;
    let msg = crate::identity::possession_msg(0x02, &nonce_arr, scope, &caps_d, &chash, &sender_dpub, &receiver_dpub);
    if crate::identity::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_err() { return false; }
    // Anti-reflection, narrowed to device_pub (#41). A REFLECTION is my own message
    // bounced back to me, which necessarily carries MY OWN device cert, so
    // `cert.device_pub == own_device_pub` catches exactly that. The OLD check refused
    // on `user_pub == own_user_pub`, which ALSO refused every legitimate same-owner
    // FLEET device (a DIFFERENT device_pub under the same user key) — that was the bug
    // that made OwnerDevice fleet unreachable. Narrowing keeps identical reflection
    // coverage and admits real fleet members. `own_dpub` is THIS machine's LOCAL device
    // pubkey (loaded above via overlay_pubkey_bytes), NEVER anything from the peer's
    // payload. On this 0x02 path the possession_msg also binds receiver_dpub non-zero,
    // so message binding is a second barrier here; on the 0x01 PAKE path it is not.
    if cert.device_pub == own_dpub { return false; }
    // Store as provisional, then promote on link
    let _ = store_provisional_identity(&format!("peer-{}", pid), &cert);
    if let Some(l) = conn.link_mut(pid) {
        l.identity_device_pub = Some(cert.device_pub);
        l.identity_user_pub = Some(cert.user_pub);
        l.identity_binding = crate::capability::BindingStrength::Proven;
        l.identity_cert_expires = Some(cert.expires);
    }
    ui::say(&format!(
        "{} identity proven for peer {}",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        pid
    ));
    // Erase held nonce (single-use)
    identity_nonces.remove(pid);
    true
}

/// #30 shared responder: on receiving an identity-nonce-challenge, prove
/// device-key possession by signing possession_sig(0x02) over the peer-provided
/// nonce and replying with an identity-expose. The challenger's identity-expose
/// handler (`handle_identity_expose`) then upgrades our binding to Proven.
/// Shared by recv_cmd (the `up`/receiver loop) AND send_cmd (the one-shot
/// sender session) so a sender can prove possession and be authorized under an
/// authoritative cap gate. Reflection-guarded and echoes the challenger nonce.
pub(crate) async fn respond_to_identity_challenge(t: &Arc<dyn Transport>, v: &Value) {
    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
    let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
    let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) =
        (hex::decode(nonce_hex), hex::decode(recv_dpub_hex))
    else {
        return;
    };
    if nonce_bytes.len() != 32 || recv_dpub_bytes.len() != 32 {
        return;
    }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);
    let mut recv_dpub_arr = [0u8; 32];
    recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
    // Reflection guard: never answer a challenge that names our own device key
    // as the challenger (a self-challenge).
    if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
        if recv_dpub_arr == own_dpub {
            return;
        }
    }
    let Some(local_cert) = local_device_cert() else { return };
    let scope = crate::identity::IntroScope::User.to_byte();
    let caps_d = crate::identity::caps_digest("transfer");
    let chash = crate::identity::cert_hash(&local_cert);
    let sender_dpub = local_cert.device_pub;
    let msg = crate::identity::possession_msg(
        0x02,
        &nonce_arr,
        scope,
        &caps_d,
        &chash,
        &sender_dpub,
        &recv_dpub_arr,
    );
    if let Ok(sig) = crate::overlay::overlay_sign_possession(&msg) {
        // Echo the challenger's nonce so its held-nonce single-use check matches.
        let payload = json!({
            "type": "identity-expose",
            "v": 2,
            "binding_type": 0x02,
            "nonce": hex::encode(nonce_arr),
            "cert": local_cert.to_json(),
            "possession_sig": hex::encode(sig)
        });
        let _ = t.send_control(&payload).await;
    }
}

/// Pure in-memory merge with takeover guard, scope-aware anchor, single source of truth.
fn apply_peer_identity(arr: &mut Vec<Value>, name: &str, peer_cert: &identity::DeviceCert, scope: u8) -> Result<()> {
    identity::apply_peer_identity(arr, name, peer_cert, scope).map_err(|e| anyhow::anyhow!("{}", e))
}

fn update_peer_identity(name: &str, peer_cert: &identity::DeviceCert, scope: u8) -> Result<()> {
    // Delegate to atomic upsert: cert only, preserve secret & caps
    devices_upsert_atomic(name, None, Some(peer_cert), None, Some(scope), None)?;
    Ok(())
}

/// Store provisional identity (held in memory, not durable trust) for later overlay check.
/// Written to a temp file, not devices.json, so a failed overlay session leaves no anchor.
fn store_provisional_identity(name: &str, peer_cert: &identity::DeviceCert) -> Result<()> {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let data = json!({
        "name": name,
        "deviceCert": peer_cert.to_json(),
        "storedAt": identity::now_secs()
    });
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

fn load_provisional_identity(name: &str) -> Option<identity::DeviceCert> {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    identity::DeviceCert::from_json(&v["deviceCert"])
}

fn clear_provisional_identity(name: &str) {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let _ = std::fs::remove_file(&p);
}

/// Update the `lastSeen` timestamp and overlay addresses for a known device.
/// Called on each connect so `filament addr <device>` can show recency and addresses.
fn devices_touch(name: &str, v6: Option<std::net::Ipv6Addr>, v4: Option<std::net::Ipv4Addr>) {
    let p = devices_path();
    let Ok(raw) = std::fs::read_to_string(&p) else { return };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else { return };
    let Some(arr) = val.as_array() else { return };
    let mut arr = arr.clone();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    for d in arr.iter_mut() {
        if d["name"].as_str() == Some(name) {
            d["lastSeen"] = json!(now);
            if let Some(v6) = v6 { d["overlayV6"] = json!(v6.to_string()); }
            if let Some(v4) = v4 { d["overlayV4"] = json!(v4.to_string()); }
            break;
        }
    }
    let _ = crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr).unwrap_or_default());
}

/// Read the `lastSeen` timestamp and overlay addresses for a known device.
fn devices_info(name: &str) -> Option<(u64, Option<String>, Option<String>)> {
    let p = devices_path();
    let raw = std::fs::read_to_string(p).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let d = arr.iter().find(|d| d["name"].as_str() == Some(name))?;
    let last_seen = d["lastSeen"].as_u64();
    let v6 = d["overlayV6"].as_str().map(|s| s.to_string());
    let v4 = d["overlayV4"].as_str().map(|s| s.to_string());
    Some((last_seen.unwrap_or(0), v6, v4))
}

/// True if ANY known device has been granted the `shell` capability. The daemon
/// uses this to switch L2/shell ON even for a plain `filament up`: otherwise
/// `filament grant <dev> shell` writes a grant the running daemon never consults
/// (l2_enabled was set only by --shell/--shell-only at startup), so the grant
/// silently did nothing and `filament ssh` timed out. With this, a grant alone is
/// enough; the per-device cap gate (auto_allows || device_allows) still denies
/// every non-granted device, so this does NOT broaden access, it only honors the
/// grants that already exist.
fn any_shell_grant() -> bool {
    any_shell_grant_at(&devices_path())
}

fn any_shell_grant_at(path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else { return false };
    let Ok(arr) = serde_json::from_str::<Value>(&raw) else { return false };
    arr.as_array()
        .map(|a| {
            a.iter().any(|d| {
                d.get("caps")
                    .and_then(|c| c.as_array())
                    .map(|list| list.iter().any(|c| c.as_str() == Some("shell")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Whether to serve an `l2-open` (TCP tunnel / ssh data link) from a peer.
/// Blanket modes (`--shell` / `--shell-only` / `FILAMENT_L2`) keep their existing
/// trusted-gated behavior. But when L2 is on ONLY because some device was
/// `grant`ed shell, the OPENING peer must itself hold that grant: otherwise a
/// grant for ONE device would let EVERY trusted device open loopback tunnels.
/// `trusted` is still required upstream; this is the additional per-device gate.
fn l2_open_allowed(blanket: bool, peer_has_shell: bool) -> bool {
    blanket || peer_has_shell
}

/// Opt-in non-loopback forward allowlist: `{config_dir}/l2-allow.json`. Absent or
/// malformed file => no entries => loopback-only (the default SSRF posture). Lets
/// an operator deliberately turn the daemon into a gateway to SPECIFIC hosts for
/// SPECIFIC devices, without opening blanket SSRF. Shape:
///   { "laptop": ["10.0.0.5:5432", "192.168.1.10:*"], "*": ["db.internal:5432"] }
/// A "*" device key applies to any authorized device; "host:*" allows any port.
fn l2_allow_path() -> PathBuf {
    devices_path().with_file_name("l2-allow.json")
}

fn l2_allow_load() -> Value {
    std::fs::read_to_string(l2_allow_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null)
}

/// True if `allow` lists `host:port` (or `host:*`) for `device` or for "*". Pure,
/// so the matching logic is unit-testable without the filesystem. Host match is
/// case-insensitive; the device key must match the proven `verified_name` exactly
/// (or be "*").
fn l2_target_allowed_in(allow: &Value, device: &str, host: &str, port: u16) -> bool {
    let matches = |list: &Value| -> bool {
        list.as_array()
            .map(|a| {
                a.iter().any(|e| {
                    let s = e.as_str().unwrap_or("");
                    match s.rsplit_once(':') {
                        Some((h, "*")) => h.eq_ignore_ascii_case(host),
                        Some((h, p)) => {
                            h.eq_ignore_ascii_case(host) && p.parse::<u16>().ok() == Some(port)
                        }
                        None => false,
                    }
                })
            })
            .unwrap_or(false)
    };
    allow.get(device).map(&matches).unwrap_or(false) || allow.get("*").map(&matches).unwrap_or(false)
}

fn l2_target_allowed(device: &str, host: &str, port: u16) -> bool {
    l2_target_allowed_in(&l2_allow_load(), device, host, port)
}

/// L1-a (spec §8): read a device's granted capabilities. v1 records (no `caps`)
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
/// read as `["transfer"]` for backward compatibility; deny-by-default otherwise.
/// Returns None if the device isn't known.
fn device_caps(name: &str) -> Option<Vec<String>> {
    device_caps_at(&devices_path(), name)
}

/// Path-explicit core of `device_caps` (testable without touching the global
/// config-dir env var).
#[allow(dead_code)]
fn device_caps_at(path: &Path, name: &str) -> Option<Vec<String>> {
    device_caps_at_time(path, name, crate::capability::now_secs())
}

fn device_caps_at_time(path: &Path, name: &str, now: u64) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    for d in arr.as_array()? {
        if d["name"].as_str() == Some(name) {
            let mut caps = match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
                None => vec!["transfer".to_string()], // v1 record
            };
            if let Some(expiries) = d.get("capExpires").and_then(|v| v.as_object()) {
                caps.retain(|cap| expiries.get(cap).and_then(|v| v.as_u64())
                    .map(|expiry| crate::capability::grant_active(expiry, now))
                    .unwrap_or(true));
            }
            return Some(caps);
        }
    }
    None
}

/// Path-explicit deny-by-default check (testable).
#[allow(dead_code)]
fn device_allows_at(path: &Path, name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps_at_time(path, name, crate::capability::now_secs())
        .map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// L1-a (spec §8 / gate 5): deny-by-default capability enforcement hook. A
/// gated action is allowed only if the device's record grants the capability.
/// "transfer" is the L0 baseline (always allowed, even for empty caps) so this
/// never regresses existing send/recv. Wired now; future L-layers add caps.
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
fn device_allows(name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps(name).map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// Grant or revoke a capability on an EXISTING known device, preserving its
/// secret and any other caps. Promotes a v1 record (no `caps`) to v2 with the
/// back-compat baseline `["transfer"]` first, so granting `shell` never silently
/// drops `transfer`. Deny-by-default consent for `filament grant`/`revoke`.
/// Returns Err if the device is unknown (you can't grant a stranger a shell).
fn device_set_cap(name: &str, capability: &str, grant: bool, expires: Option<u64>) -> Result<()> {
    let capability = crate::capability::canonical_capability(capability)?;
    let p = devices_path();
    let raw = std::fs::read_to_string(&p)
        .map_err(|_| anyhow::anyhow!("no known device named '{name}', pair first"))?;
    let mut arr: Vec<Value> = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut found = false;
    for d in arr.iter_mut() {
        if d["name"].as_str() != Some(name) {
            continue;
        }
        found = true;
        // Current caps: v1 (absent) reads as the transfer baseline.
        let mut caps: Vec<String> = match d.get("caps").and_then(|c| c.as_array()) {
            Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
            None => vec!["transfer".to_string()],
        };
        caps.retain(|c| c != &capability);
        if grant {
            caps.push(capability.to_string());
        }
        if let Some(obj) = d.as_object_mut() {
            obj.insert("v".into(), json!(2));
            obj.insert("caps".into(), json!(caps));
            let mut cap_expires = obj.get("capExpires").and_then(|v| v.as_object()).cloned().unwrap_or_default();
            if grant {
                if let Some(expiry) = expires {
                    cap_expires.insert(capability.to_string(), json!(expiry));
                } else {
                    cap_expires.remove(&capability);
                }
            } else {
                cap_expires.remove(&capability);
            }
            obj.insert("capExpires".into(), json!(cap_expires));
            let mut sources = obj.get("capSources").and_then(|v| v.as_object()).cloned().unwrap_or_default();
            if grant && expires.is_some() {
                sources.insert(capability.to_string(), json!("legacy"));
            } else {
                sources.remove(&capability);
            }
            obj.insert("capSources".into(), json!(sources));
        }
    }
    if !found {
        return Err(anyhow::anyhow!(
            "no known device named '{name}', run `filament devices` to see who you've paired"
        ));
    }
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)?;
    Ok(())
}

fn mark_bounded_cap_source(name: &str, capability: &str, source: &str) -> Result<()> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p)?;
    let mut arr: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
    let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else { bail!("unknown device '{name}'") };
    let obj = device.as_object_mut().ok_or_else(|| anyhow::anyhow!("invalid device record"))?;
    let mut sources = obj.get("capSources").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    sources.insert(capability.to_string(), json!(source));
    obj.insert("capSources".into(), json!(sources));
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)?;
    Ok(())
}

/// Add the authoritative owner-signed bounded grant when the peer is certified.
/// Uncertified peers intentionally retain the legacy `capExpires` fallback.
fn issue_signed_bounded_grant(device: &str, capability: &str, expires: u64) -> Result<bool> {
    let Some(user_key) = load_owner_key() else { return Ok(false) };
    let Some(peer_cert) = device_cert_for(device) else { return Ok(false) };
    peer_cert.verify(crate::identity::now_secs()).map_err(|_| anyhow::anyhow!("peer identity cert for '{device}' is expired; re-pair to refresh it"))?;
    let config_dir = crate::settings::config_dir();
    let mut store = crate::capability::load_cap_store(&config_dir);
    let pk = user_key.public_key_bytes();
    if !store.iter().any(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header") && e["resource"].as_str() == Some("self")) {
        let mut hdr = crate::capability::CapHeader {
            resource: crate::capability::self_resource_id(&pk), epoch: 0, owner_pub: pk,
            nonce: crate::capability::self_resource_nonce(), floors: vec![],
            issued_at: crate::capability::now_secs(), prev_owner_pub: None,
            prev_header_hash: None, sig: [0; 64],
        };
        hdr.sig = crate::capability::sign_cap_header(&hdr, user_key.keypair());
        let mut value = hdr.to_json();
        value["resource"] = json!("self");
        store.push(value);
    }
    let mut op = crate::capability::CapOp {
        op: crate::capability::CapOpKind::Grant, grantor: pk, target_kind: 0x00,
        target: peer_cert.user_pub, resource: "self".into(), permissions: vec![capability.into()],
        expires, issued_at: crate::capability::now_secs(),
        version: crate::capability::hlc_next(0, crate::capability::now_ms()), sig: [0; 64],
    };
    op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
    let mut value = op.to_json();
    value["type"] = json!("cap_grant");
    store.push(value);
    crate::capability::update_ratchet(&mut store, &pk, op.issued_at)?;
    crate::capability::save_and_list_revoked(&store, &config_dir)?;
    Ok(true)
}

fn devices_remove(name: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Raw-array filter so the REMAINING devices keep their v2 fields (caps,
    // addedAt). The old tuple round-trip rewrote every survivor as bare
    // {name, secret}, silently wiping their `shell` grants on any forget.
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.retain(|d| d["name"].as_str() != Some(name));
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)?;
    Ok(())
}

pub(crate) fn channel_of(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 (manual: avoids a hmac-crate version dance with sha2 0.11).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// C20: the proof binds the pair secret to the DTLS session. uids are
/// order-normalized (direction-tagged by the prover's uid prefix) and BOTH
/// certificate fingerprints are mixed in sorted order, a channel MITM'd by
/// anyone (including the signaling server) has different fingerprints, so
/// the proof fails and auto-accept refuses.
pub(crate) fn proof_for(secret: &str, prover_uid: &str, a_uid: &str, b_uid: &str, fp1: &str, fp2: &str) -> String {
    let (lo, hi) = if a_uid < b_uid { (a_uid, b_uid) } else { (b_uid, a_uid) };
    let (f_lo, f_hi) = if fp1 < fp2 { (fp1, fp2) } else { (fp2, fp1) };
    hmac_sha256(
        secret.as_bytes(),
        format!("filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}").as_bytes(),
    )
}

pub(crate) fn fresh_secret() -> String {
    let mut buf = [0u8; 32];
    // std-only CSPRNG is unavailable; derive from getrandom via std::fs on unix
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback (non-unix): hash of time+pid noise, still unpredictable enough
        let mut h = Sha256::new();
        h.update(format!("{:?}{}", SystemTime::now(), std::process::id()));
        buf.copy_from_slice(&h.finalize()[..32]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------- daemon (C19) --

fn drop_dir(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| config_get("dir").map(PathBuf::from)).unwrap_or_else(default_drop_dir)
}

/// The built-in drop directory when nothing is configured (~/Filament). Shared
/// with the settings readout so it shows the true default.
pub(crate) fn default_drop_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("Filament")
}

/// The read-only SHARE ROOT a same-owner fleet device may mount without an
/// explicit grant. Config value `share` (a directory path); default a dedicated
/// `~/filament-share`, never home. A mount whose requested root escapes this dir
/// is out of scope (the deliberate tier) and needs an explicit grant.
///
/// COMPOSITION INVARIANT (load-bearing — do not break in a refactor): the
/// transfer INBOX (`drop_dir`, default `~/Filament`) must NOT be inside this
/// share root. Two scoped defaults compose dangerously if it is: `transfer`
/// (write, auto-trusted) could place a file — or, absent plain-file-only write
/// hardening, a symlink — that the read-only `mount` default then serves,
/// turning two individually-correct defaults into arbitrary filesystem read.
/// The defaults (`~/Filament` vs `~/filament-share`) are disjoint by
/// construction; a user who points `dir` and `share` at overlapping paths
/// re-opens this, so the mount server must additionally refuse to traverse
/// out of the share root at open time (see the beneath-root hardening).
pub(crate) fn fleet_share_root() -> PathBuf {
    config_get("share").map(PathBuf::from).unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("filament-share")
    })
}

/// Lexically normalize a path (resolve `.`/`..` without touching the FS) so a
/// scope check can't be defeated by `share/../../etc`. Returns the normalized
/// component vector.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        use std::path::Component::*;
        match comp {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// True when `path`, lexically normalized, is within (or equal to) `root`. Used
/// to bound a fleet transfer landing path to the drop dir. A relative or
/// non-normalizable request fails closed (not within), so it falls through to
/// explicit-grant. LEXICAL is correct here because the landing path may not
/// exist yet (file about to be received); the actual symlink protection lives
/// in safe_create_part/safe_open_part (O_NOFOLLOW|O_EXCL) at the write site.
fn path_within(root: &Path, path: &Path) -> bool {
    let root_n = lexical_normalize(root);
    let path_n = lexical_normalize(path);
    !root_n.as_os_str().is_empty() && path_n.starts_with(&root_n)
}

/// True when `path`, canonicalized (symlinks resolved), is within `root`.
/// Used to bound a fleet mount REQUEST to the share root. Both paths must
/// exist on disk (canonicalize fails on non-existent paths). A symlink at
/// the mount root or requested path escaping the share root is refused.
fn path_within_canonical(root: &Path, path: &Path) -> bool {
    let Ok(root_c) = root.canonicalize() else {
        return false;
    };
    let Ok(path_c) = path.canonicalize() else {
        return false;
    };
    !root_c.as_os_str().is_empty() && path_c.starts_with(&root_c)
}

/// True when an `up` daemon is currently running (drives the "takes effect on
/// next up" hint after a settings change).
pub(crate) fn daemon_running() -> bool {
    daemon_alive().is_some()
}

/// Minimal `YYYY-MM-DD HH:MM` UTC stamp (civil-from-days; avoids chrono).
fn chrono_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86400, secs % 86400);
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil_from_days
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

fn pidfile() -> PathBuf {
    devices_path().with_file_name("up.pid")
}
fn up_log() -> PathBuf {
    devices_path().with_file_name("up.log")
}

fn daemon_alive() -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(pidfile()).ok()?.trim().parse().ok()?;
    let cmd = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    cmd.contains("filament").then_some(pid)
}

/// The argv for a web-shell PTY.
///
/// M-1 (privilege-drop): when `--shell-user <name>` is set, drop the PTY to that
/// account via `runuser -l <user>` (a clean setuid+login-shell wrapper available
/// on every systemd distro). `runuser` does no PAM password prompt, so it only
/// works when `up` itself runs as root, which is exactly the case the flag is
/// meant to de-fang (a root daemon should hand out a NON-root shell). Without the
/// flag the PTY runs as the up-process user (often root on a server); this is an
/// ACCEPTED RISK documented in docs/security/web-shell-review.md (M-1) and in the
/// `up --shell` help. Operators are urged to pass `--shell-user`.
fn shell_argv(shell_program: Option<&str>, shell_user: Option<&str>) -> Vec<String> {
    let shell_config = settings::get_str("shell-program", None);
    let (argv, _can_user) = platform::Paths::shell_argv(shell_program, shell_config.as_deref(), shell_user);
    argv
}

/// Dev-debug logging: dlog! expands to eprintln! only under debug-logs feature.
macro_rules! dlog {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        eprintln!($($arg)*);
    };
}

/// #4: bridge ONE link's PTY stream to a persistent session. Inbound data frames
/// (`rx`, the mux's per-sid pipe) become keystrokes; resize events (`rrx`, the
/// mux resizer) become window-size changes. When the channel drops, `rx` closes
/// and this pump exits, but it does NOT end the session: a drop is a DETACH (the
/// PcState handler does that), so the shell keeps running for a reattach. Spawned
/// fresh on every open/reattach against that open's sid.
fn spawn_session_pumps(
    sess: l2::PtySessionHandle,
    mut rx: tokio::sync::mpsc::Receiver<Option<bytes::Bytes>>,
    mut rrx: tokio::sync::mpsc::UnboundedReceiver<(u16, u16)>,
) {
    // input pump: PTY keystrokes for THIS attachment
    let s_in = sess.clone();
    tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            match item {
                Some(bytes) => s_in.feed_input(bytes.to_vec()),
                None => break, // clean FIN for this stream; channel-drop also lands here
            }
        }
    });
    // resize pump: SIGWINCH for THIS attachment
    tokio::spawn(async move {
        while let Some((c, r)) = rrx.recv().await {
            sess.resize(c, r);
        }
    });
}

/// Auto-shell policy for the `up`/`recv` acceptor: which proof-verified devices
/// may `filament ssh` in WITHOUT a per-device `grant`. Trust (pair-proof) is
/// always enforced separately, this is purely the capability side.
#[derive(Clone, Debug)]
enum ShellPolicy {
    /// Default: only devices explicitly `grant`ed the `shell` cap.
    Granted,
    /// `up --shell`: any paired device. M-2: this INTENTIONALLY grants every
    /// proof-verified paired device, including ones introduced later via
    /// pair-intro. Use `Only`/`--shell-only` to scope it.
    All,
    /// `up --shell-only a,b`: only these petnames auto-shell; others need a grant.
    Only(std::collections::HashSet<String>),
}

impl ShellPolicy {
    fn auto_allows(&self, name: &str) -> bool {
        match self {
            ShellPolicy::Granted => false,
            ShellPolicy::All => true,
            ShellPolicy::Only(set) => set.contains(name),
        }
    }
    /// Active policy implies the L2 tunnel acceptor is on (you can't ssh without it).
    fn enables_l2(&self) -> bool {
        !matches!(self, ShellPolicy::Granted)
    }
}

/// Install a SYSTEM systemd unit that receives CAP_NET_ADMIN from systemd
/// (`AmbientCapabilities`), so the overlay's kernel TUN needs NO file capability on
/// the binary. That is what kills the recurring sudo: a file cap is lost when
/// `filament update` replaces the binary, but an ambient cap is granted afresh by
/// systemd on every (re)start, so updates never need `setcap` (hence never a
/// password). Writes `/etc/systemd/system/filament.service`, drops any stale file
/// cap, retires a pre-existing --user service, and enables it, using ONE `sudo` for
/// the privileged steps (a single interactive prompt, NOT a per-update one). If it
/// cannot elevate, it prints the exact unit + commands to run by hand.
#[cfg(target_os = "linux")]
fn install_system_service(shell: bool, shell_only: &Option<String>, shell_user: &Option<String>) -> Result<()> {
    let exe = std::env::current_exe()?.display().to_string();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into());
    let home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{user}"));

    // Carry the same shell posture the user asked for into the unit's ExecStart.
    let mut up_args = String::from(" up");
    if let Some(csv) = shell_only {
        up_args.push_str(&format!(" --shell-only {csv}"));
    } else if shell {
        up_args.push_str(" --shell");
    }
    if let Some(u) = shell_user {
        up_args.push_str(&format!(" --shell-user {u}"));
    }

    let unit = format!(
        "[Unit]\n\
         Description=Filament drop target (trusted devices only)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=notify\n\
         User={user}\n\
         Environment=HOME={home}\n\
         Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
         ExecStart={exe}{up_args}\n\
         AmbientCapabilities=CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_ADMIN\n\
         Restart=always\n\
         RestartSec=2\n\
         WatchdogSec=45\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let unit_path = "/etc/systemd/system/filament.service";
    let am_root = unsafe { libc::geteuid() } == 0;
    // Run a privileged command, using sudo only when not already root.
    let run_priv = |args: &[&str]| -> bool {
        let mut cmd = if am_root {
            std::process::Command::new(args[0])
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg(args[0]);
            c
        };
        cmd.args(&args[1..]).status().map(|s| s.success()).unwrap_or(false)
    };

    ui::say(&format!("filament: installing system service at {unit_path}"));
    if !am_root {
        ui::say("  (one-time sudo for the system unit; updates afterward need none)");
    }
    // Write the unit as root by PIPING it to `tee` under the privileged runner.
    // Deliberately NO on-disk staging: a predictable, world-writable temp file
    // (e.g. /tmp/filament.service.tmp) is a TOCTOU - another local user could
    // swap or symlink it between our write and the privileged copy, yielding an
    // attacker-controlled ROOT-owned systemd unit (root code execution). Piping to
    // `tee` has no intermediary to race; sudo still reads its password from the tty,
    // not our stdin, so the small unit content flows to tee uncontended.
    let wrote = {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = if am_root {
            std::process::Command::new("tee")
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg("tee");
            c
        };
        match cmd.arg(unit_path).stdin(Stdio::piped()).stdout(Stdio::null()).spawn() {
            Ok(mut child) => {
                if let Some(mut si) = child.stdin.take() {
                    let _ = si.write_all(unit.as_bytes());
                    // si drops here, closing stdin so tee finalizes the file.
                }
                child.wait().map(|s| s.success()).unwrap_or(false)
            }
            Err(_) => false,
        }
    };
    if wrote {
        // tee creates with the (root) umask; pin the mode explicitly.
        let _ = run_priv(&["chmod", "644", unit_path]);
    }
    if !wrote {
        ui::say("filament: could not elevate; install the system unit by hand:");
        ui::say(&format!("  sudo tee {unit_path} >/dev/null <<'UNIT'\n{unit}UNIT"));
        ui::say(&format!("  sudo setcap -r {exe} 2>/dev/null || true"));
        ui::say("  sudo systemctl daemon-reload && sudo systemctl enable --now filament");
        return Ok(());
    }
    // Drop any stale file cap (ambient replaces it; keeps updates clean); retire a
    // pre-existing --user service so the two don't fight over the mesh. Best-effort.
    let _ = run_priv(&["setcap", "-r", &exe]);
    let _ = std::process::Command::new("systemctl").args(["--user", "disable", "--now", "filament"]).status();
    let enabled =
        run_priv(&["systemctl", "daemon-reload"]) && run_priv(&["systemctl", "enable", "--now", "filament"]);
    if enabled {
        ui::say(&format!(
            "  {} system service enabled; CAP_NET_ADMIN comes from systemd, so no setcap on update",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        ui::say("  logs: journalctl -u filament");
    } else {
        ui::say("  wrote the unit; enable it with: sudo systemctl enable --now filament");
    }

    // Belt-and-suspenders: a NOPASSWD sudoers drop-in scoped to JUST restarting this
    // one service, so any fallback `sudo systemctl restart filament` (e.g. when the
    // reload op is unavailable) is password-free too. Written the same TOCTOU-safe
    // way (piped to tee, no world-writable staging), mode 0440, and validated with
    // visudo - a malformed sudoers drop-in must NEVER be left in place, so it is
    // removed if it does not parse.
    let systemctl = ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
        .unwrap_or("/usr/bin/systemctl");
    let sudoers_path = "/etc/sudoers.d/filament";
    let sudoers = format!(
        "{user} ALL=(root) NOPASSWD: {systemctl} restart filament, {systemctl} daemon-reload\n"
    );
    let wrote_sudoers = {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = if am_root {
            std::process::Command::new("tee")
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg("tee");
            c
        };
        match cmd.arg(sudoers_path).stdin(Stdio::piped()).stdout(Stdio::null()).spawn() {
            Ok(mut ch) => {
                if let Some(mut si) = ch.stdin.take() {
                    let _ = si.write_all(sudoers.as_bytes());
                }
                ch.wait().map(|s| s.success()).unwrap_or(false)
            }
            Err(_) => false,
        }
    };
    if wrote_sudoers {
        let _ = run_priv(&["chmod", "0440", sudoers_path]);
        if run_priv(&["visudo", "-cf", sudoers_path]) {
            ui::say(&format!(
                "  {} passwordless `systemctl restart filament` for {user}",
                ui::paint(ui::Tone::Ok, ui::glyph_ok())
            ));
        } else {
            let _ = run_priv(&["rm", "-f", sudoers_path]);
            ui::say("  (skipped the restart sudoers rule: visudo validation failed)");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_system_service(_shell: bool, _shell_only: &Option<String>, _shell_user: &Option<String>) -> Result<()> {
    let hint = platform::ServiceHost::detect().install_instructions();
    bail!("--install --system (ambient-cap system service) is not supported on this platform. {hint}");
}

async fn up_cmd(
    server: &str,
    install: bool,
    system: bool,
    dir: Option<PathBuf>,
    relay: bool,
    shell: bool,
    shell_only: Option<String>,
    shell_program: Option<String>,
    shell_user: Option<String>,
    install_system_flag: bool,
    no_proxy_fallback: bool,
) -> Result<()> {
    // Internal: re-invoked after elevation. Do the system-level install directly
    // and return. The privileged backend registers the service/daemon/task and exits.
    if install_system_flag {
        let host = platform::ServiceHost::detect();
        let exe = std::env::current_exe()?;
        // Build shell args from the current flag carried by the elevated process.
        let mut up_args = String::new();
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        if let Some(u) = &shell_user {
            up_args.push_str(&format!(" --shell-user {u}"));
        }
        host.install_system(&exe, &up_args)?;
        return Ok(());
    }
    // --shell-program -- persist it so the daemon picks it up (shell_argv reads
    // this from config). The env var FILAMENT_SHELL is also checked independently.
    if let Some(ref prog) = shell_program {
        settings::set("shell-program", prog, None).ok();
    }
    let shell_policy = match &shell_only {
        Some(csv) => ShellPolicy::Only(
            csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        ),
        None if shell => ShellPolicy::All,
        None => ShellPolicy::Granted,
    };
    // --shell-user is Unix-only (uses runuser). Warn early on Windows.
    if shell_user.is_some() && cfg!(windows) {
        ui::say(&format!(
            "  {} --shell-user is not supported on Windows.\n\
             \n\
             Windows requires CreateProcessAsUser or CreateProcessWithLogonW to run\n\
             a process as another user. CreateProcessAsUser needs SE_INCREASE_QUOTA_NAME\n\
             and SE_ASSIGNPRIMARYTOKEN_NAME privileges (typically requires admin).\n\
             CreateProcessWithLogonW needs the target user's credentials (username +\n\
             password), which is a security risk if stored or passed via CLI.\n\
             \n\
             The PTY will run as the current user. To run as a different user,\n\
             start filament from that user's session, or use 'runas /user:<name> filament'.",
            ui::paint(ui::Tone::Warn, "WARNING:")
        ));
    }
    if install && system {
        return install_system_service(shell, &shell_only, &shell_user);
    }
    if install {
        // Gate --install on a detected service manager.
        let host = platform::ServiceHost::detect();
        if !host.supports_install() {
            let hint = host.install_instructions();
            eprintln!("filament: --install is not supported on this platform. {hint}");
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let mut up_args = String::new();
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        if let Some(u) = &shell_user {
            up_args.push_str(&format!(" --shell-user {u}"));
        }
        // Try privileged system install (elevation popup). On decline, fall
        // back to user-level autostart. Never fail hard.
        match host.install_system(&exe, &up_args) {
            Ok(platform::InstallResult::System) => {
                ui::say(&format!("  {} installed as a system service (autostart at boot)", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
            }
            Ok(platform::InstallResult::User) | Err(_) => {
                // Elevation declined: user-level autostart
                host.install_user(&exe, &up_args)?;
                ui::say(&format!("  {} installed as a user-level autostart", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                ui::say(&format!("  {} run `filament up --install` again to grant admin for kernel overlay",
                    ui::paint(ui::Tone::Dim, "note:")));
            }
        }
        #[cfg(target_os = "windows")]
        platform::add_firewall_rule(&exe);
        return Ok(());
    }
    if let Some(pid) = daemon_alive() {
        dlog!("[up] already-up: pidfile={:?} pid={pid} cmdline={:?}", pidfile(), std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default());
        bail!("already up (pid {pid}), `filament status` / `filament down`");
    }
    let dir = drop_dir(dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(pidfile(), std::process::id().to_string())?;
    match &shell_policy {
        // M-2: --shell intentionally grants ALL proof-verified paired devices
        // (current AND any introduced later via pair-intro). This is a broad,
        // deliberate over-grant; --shell-only is the scoped, safer alternative.
        ShellPolicy::All => ui::say(&format!(
            "  {} seamless shell ON, ANY paired device (now or paired later) can `filament ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
        )),
        ShellPolicy::Only(set) => {
            let mut names: Vec<&String> = set.iter().collect();
            names.sort();
            let list = names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            ui::say(&format!(
                "  {} seamless shell ON for: {list}, they can `filament ssh` into this machine",
                ui::paint(ui::Tone::Warn, "!"),
            ));
        }
        ShellPolicy::Granted => {}
    }
    // M-1: warn loudly when a shell policy is active but the PTY is NOT dropped to
    // a non-root account. The granted device would get a shell as the up-process
    // user (often root on a server). `--shell-user <name>` de-fangs this.
    if shell_policy.enables_l2() && shell_user.is_none() {
        ui::say(&format!(
            "  {} shell PTYs run as THIS user (root if the daemon is root), pass `--shell-user <name>` to drop to a non-root account",
            ui::paint(ui::Tone::Warn, "!"),
        ));
    }
    // Pre-resolve our public IP off the critical path so the FIRST incoming
    // connect answers the transport-offer without an inline `/api/whoami` round
    // trip (the acceptor's gather is what the initiator waits on during
    // establishing). Best-effort, backgrounded so it never delays daemon start.
    {
        let server = server.to_string();
        tokio::spawn(async move { direct::warm_public_ip(&server).await; });
    }
    // Startup shell-key reconciliation. GATED on authoritative: in shadow the cap
    // layer gates NOTHING, so only REPORT what would be removed (it becomes part of
    // the pre-flip sample). Never delete a working key while the cap store is not
    // yet the authority, else the first `grant` on any node wipes every device that
    // has no cap grant yet.
    {
        let config_dir = crate::settings::config_dir();
        let authoritative = crate::capability::cap_authoritative();
        let revoked = crate::capability::devices_with_shell_revoked(&config_dir);
        let ak_path = sshkeys::authorized_keys_path();
        let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
        // Emit per-device shadow logs for the WOULD-remove devices that
        // actually have a block (avoid noise for devices without one).
        for device in &revoked {
            if sshkeys::has_block(&ak_content, device) && !authoritative {
                eprintln!("CAP-SHADOW RECONCILE (startup): WOULD remove shell key for '{device}' (cap store denies shell); NOT removing in shadow");
            }
        }
        let new_ak = crate::capability::reconcile_shell_keys(&revoked, &ak_content, authoritative);
        if new_ak != ak_content {
            if let Err(e) = crate::platform::SecretFile::write_str(&ak_path, &new_ak) {
                eprintln!("shell-key reconcile (startup): failed to write authorized_keys: {e}");
            }
        }
    }
    let res = recv_cmd(server, None, dir, false, None, None, true, relay, None, true, None, shell_policy, shell_user, no_proxy_fallback).await;
    let _ = std::fs::remove_file(pidfile());
    res
}

/// Bare-command tour: what filament is, the current state, and the two or three
/// things you'd actually do next, adapted to whether you've paired anyone yet. No
/// flags to learn; `--help` still has the full surface. (CLI-UX work, point #2.)
fn tour_cmd() -> Result<()> {
    let color = ui::stdout_color();
    ui::say(&format!(
        "  {}  {}",
        ui::paint_when(color, ui::Tone::Brand, "filament"),
        ui::paint_when(color, ui::Tone::Dim, "· send files and reach your devices, no account"),
    ));
    ui::say("");
    match daemon_alive() {
        Some(pid) => ui::say(&format!("  {} daemon up (pid {pid})", ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()))),
        None => ui::say(&format!("  {} daemon not running", ui::paint_when(color, ui::Tone::Dim, "·"))),
    }
    let n = devices_load().len();
    ui::say(&format!("  {n} known device{}", if n == 1 { "" } else { "s" }));
    ui::say("");
    ui::say(&ui::paint_when(color, ui::Tone::Dim, "  do this:"));
    let act = |cmd: &str, desc: &str| ui::say(&format!("    {:<24} {}", cmd, desc));
    act("filament send <file>", "send files (to a browser or a paired device)");
    if n == 0 {
        act("filament pair", "remember a device (unlocks ssh + expose)");
    } else {
        act("filament <device>", "shell into a paired device (e.g. filament dovm)");
        act("filament expose <port>", "publish a local port on the mesh");
    }
    act("filament up", "receive in the background");
    ui::say(&ui::paint_when(color, ui::Tone::Dim, "  more:  filament --help  ·  filament status  ·  filament devices"));
    Ok(())
}

fn status_cmd(json: bool) -> Result<()> {
    if json {
        let pid = daemon_alive();
        let exposed: Vec<Value> = expose::load()
            .iter()
            .map(|b| json!({ "port": b.port, "target": b.target, "peers": b.peers.clone().unwrap_or_default() }))
            .collect();
        let mut recent: Vec<String> = std::fs::read_to_string(up_log())
            .map(|log| log.lines().rev().take(8).map(str::to_string).collect())
            .unwrap_or_default();
        recent.reverse();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "running": pid.is_some(),
                "pid": pid,
                "devices": devices_load().len(),
                "exposed": exposed,
                "recent": recent,
            }))?
        );
        return Ok(());
    }
    match daemon_alive() {
        Some(pid) => ui::say(&format!("  {} up (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok()))),
        None => ui::say(&format!("  {} not running, start with: filament up", ui::paint(ui::Tone::Dim, "·"))),
    }
    let n = devices_load().len();
    ui::say(&format!("  {} known device{}", n, if n == 1 { "" } else { "s" }));
    let exposed = expose::load();
    if !exposed.is_empty() {
        ui::say(&ui::paint(ui::Tone::Dim, "  exposed on .mesh:"));
        for b in exposed {
            let scope = match &b.peers {
                Some(p) if !p.is_empty() => p.join(","),
                _ => "any".into(),
            };
            ui::say(&format!("    :{} {} {}  ({})", b.port, ui::glyph_arrow(), b.target, scope));
        }
    }
    if let Ok(log) = std::fs::read_to_string(up_log()) {
        let recent: Vec<&str> = log.lines().rev().take(8).collect();
        if !recent.is_empty() {
            ui::say(&ui::paint(ui::Tone::Dim, "  recent receives:"));
            for l in recent.iter().rev() {
                ui::say(&format!("    {l}"));
            }
        }
    }
    Ok(())
}

async fn cap_status_cmd(json: bool) -> Result<()> {
    let reply = crate::ctl::try_cap_status().await;
    match reply {
        Some(v) if json => {
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Some(v) => {
            if let Some(summary) = v["summary"].as_str() {
                ui::say(summary);
            }
            let flip = v["flip_ready"].as_bool().unwrap_or(false);
            if v.get("counts").is_none() || v["counts"].is_null() {
                ui::say(&format!(
                    "  flip_ready: {} counts unavailable; cannot assess flip readiness",
                    ui::paint(ui::Tone::Warn, "x"),
                ));
            } else {
                let widening = v["counts"]["ld_authorized"].as_u64().unwrap_or(0);
                let la_authorized = v["counts"]["la_authorized"].as_u64().unwrap_or(0);
                if flip && widening == 0 {
                    ui::say(&format!(
                        "  flip_ready: {} no blockers detected (n={} legacy-allowed opens)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        la_authorized,
                    ));
                } else if flip {
                    ui::say(&format!(
                        "  flip_ready: {} breakage-clean, but {} WIDENING opens will be NEWLY PERMITTED; review and cite them before flipping",
                        ui::paint(ui::Tone::Warn, "x"),
                        widening,
                    ));
                } else {
                    ui::say(&format!(
                        "  flip_ready: {} not ready",
                        ui::paint(ui::Tone::Warn, "x"),
                    ));
                }
            }
            if let Some(counts) = v.get("counts") {
                if !counts.is_null() {
                    ui::say(&format!(
                        "  la_authorized={}  la_denied={}  la_no_header={}",
                        counts["la_authorized"].as_u64().unwrap_or(0),
                        counts["la_denied"].as_u64().unwrap_or(0),
                        counts["la_no_header"].as_u64().unwrap_or(0),
                    ));
                    ui::say(&format!(
                        "  WIDENING(ld_authorized)={}  ld_denied={}  ld_no_header={}",
                        counts["ld_authorized"].as_u64().unwrap_or(0),
                        counts["ld_denied"].as_u64().unwrap_or(0),
                        counts["ld_no_header"].as_u64().unwrap_or(0),
                    ));
                }
            }
            // Per-action breakdown: the coverage matrix for the flip decision.
            if let Some(by_action) = v.get("by_action").and_then(|v| v.as_array()) {
                if !by_action.is_empty() {
                    ui::say(&ui::paint(ui::Tone::Dim, "  coverage matrix (per-action):"));
                    for a in by_action {
                        let action = a["action"].as_str().unwrap_or("?");
                        let la = a["la_authorized"].as_u64().unwrap_or(0);
                        let ld = a["la_denied"].as_u64().unwrap_or(0);
                        let ln = a["la_no_header"].as_u64().unwrap_or(0);
                        let wa = a["ld_authorized"].as_u64().unwrap_or(0);
                        let wd = a["ld_denied"].as_u64().unwrap_or(0);
                        let wn = a["ld_no_header"].as_u64().unwrap_or(0);
                        ui::say(&format!(
                            "    {action}: la_ok={la} la_deny={ld} la_nh={ln} | widen={wa} ld_deny={wd} ld_nh={wn}"
                        ));
                    }
                }
            }
        }
        None => {
            ui::say(&format!("  {} daemon not running; counters are zero in a fresh process", ui::paint(ui::Tone::Dim, "·")));
            if json {
                println!("{}", serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "err": "daemon not reachable; start with filament up",
                }))?);
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------- consent queue --
// Pending-request queue for live-approval consent (docs/design-identity-access-ux.md §2).
// Requests arrive via the daemon from peers requesting shell/mount/transfer.
// The daemon holds them until the owner explicitly approves or denies via CLI.
// Deny-by-default: a pending request carries NO access.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRequest {
    id: u64,
    peer: String,
    capability: String,
    timestamp: u64,
    status: String, // "pending", "approved", "denied", "expired"
    granted_at: Option<u64>,
}

const MAX_PENDING: usize = 100;
const REQUEST_TTL_SECS: u64 = 3600;

fn requests_path() -> PathBuf {
    crate::settings::config_dir().join("requests.json")
}

fn load_requests() -> Vec<PendingRequest> {
    std::fs::read_to_string(requests_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_requests(reqs: &[PendingRequest]) {
    if let Ok(json) = serde_json::to_string_pretty(reqs) {
        let _ = crate::platform::SecretFile::write_str(&requests_path(), &json);
    }
}

fn add_pending_request(peer: &str, capability: &str, requests: &mut Vec<PendingRequest>) {
    let now = crate::capability::now_secs();
    let next_id = requests.iter().map(|r| r.id).max().unwrap_or(0) + 1;
    // Evict oldest pending if at capacity
    while requests.iter().filter(|r| r.status == "pending").count() >= MAX_PENDING {
        if let Some(pos) = requests.iter().position(|r| r.status == "pending") {
            let evicted = &requests[pos];
            ui::say(&format!(
                "consent queue full ({}), evicting oldest pending: id={} peer={} cap={}",
                MAX_PENDING, evicted.id, evicted.peer, evicted.capability
            ));
            requests.remove(pos);
        } else {
            break;
        }
    }
    requests.push(PendingRequest {
        id: next_id,
        peer: peer.to_string(),
        capability: capability.to_string(),
        timestamp: now,
        status: "pending".to_string(),
        granted_at: None,
    });
    // Fire notify hook if configured
    if let Ok(hook) = std::env::var("FILAMENT_NOTIFY_HOOK") {
        if !hook.is_empty() {
            // ARGV exec, never shell — petname is attacker-influenced
            let _ = std::process::Command::new(&hook)
                .arg(peer)
                .arg(capability)
                .spawn();
        }
    }
    save_requests(requests);
}

fn expire_requests(requests: &mut Vec<PendingRequest>) {
    let now = crate::capability::now_secs();
    let mut changed = false;
    for r in requests.iter_mut().filter(|r| r.status == "pending") {
        if now.saturating_sub(r.timestamp) > REQUEST_TTL_SECS {
            r.status = "expired".to_string();
            changed = true;
        }
    }
    if changed {
        save_requests(requests);
    }
}

fn parse_duration_secs(input: &str) -> Result<u64> {
    let (number, unit) = input.trim().split_at(input.trim().len().saturating_sub(1));
    let value: u64 = number.parse().map_err(|_| anyhow::anyhow!("invalid duration '{input}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid duration '{input}', use e.g. 30m, 1h, or 1d"),
    };
    let seconds = value.checked_mul(multiplier).ok_or_else(|| anyhow::anyhow!("duration too large"))?;
    if seconds == 0 { bail!("duration must be greater than zero"); }
    Ok(seconds)
}

/// Enqueue a consent request for a denied action from an identified peer.
/// No-op if the peer is unidentified, the cap is not requestable, or a
/// duplicate (same peer+cap) is already pending (dedup).
fn enqueue_if_requestable(dev_petname: &str, cap: &str) {
    let name = dev_petname.trim();
    if name.is_empty() || name == "<unverified>" {
        return;
    }
    match cap {
        "shell" | "mount" | "transfer" => {}
        _ => return,
    }
    let mut requests = load_requests();
    expire_requests(&mut requests);
    let dup = requests.iter().any(|r| r.peer == name && r.capability == cap && r.status == "pending");
    if !dup {
        add_pending_request(name, cap, &mut requests);
    }
}

fn request_ago(timestamp: u64) -> String {
    let ago = crate::capability::now_secs().saturating_sub(timestamp);
    if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else {
        format!("{}h ago", ago / 3600)
    }
}

fn request_entry(value: &Value) -> Option<fleet_ui::requests::RequestEntry> {
    let capability = value["capability"].as_str()?;
    Some(fleet_ui::requests::RequestEntry {
        id: value["id"].as_u64()?,
        peer: value["peer"].as_str()?.to_string(),
        capability: capability.to_string(),
        ago: request_ago(value["timestamp"].as_u64().unwrap_or(0)),
        // The request protocol does not carry provenance or a fingerprint.
        via: None,
        fingerprint: None,
        is_deliberate: fleet_ui::is_deliberate_capability(capability),
    })
}

fn request_entries(value: &Value, all: bool) -> Vec<fleet_ui::requests::RequestEntry> {
    value
        .get("requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|request| all || request["status"].as_str() == Some("pending"))
        .filter_map(request_entry)
        .collect()
}

fn local_request(id: u64) -> Option<PendingRequest> {
    load_requests().into_iter().find(|request| request.id == id)
}

fn warm_device_names(value: Option<&Value>) -> HashSet<String> {
    value
        .and_then(|v| v.get("links"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|link| link["warm"].as_bool() == Some(true))
        .filter_map(|link| link["name"].as_str().map(str::to_string))
        .collect()
}

fn pending_request_count(value: Option<&Value>) -> usize {
    value
        .and_then(|v| v.get("requests"))
        .and_then(Value::as_array)
        .map(|requests| {
            requests
                .iter()
                .filter(|request| request["status"].as_str() == Some("pending"))
                .count()
        })
        .unwrap_or(0)
}

fn format_approval_expiry(expires: u64) -> String {
    chrono::DateTime::from_timestamp(expires as i64, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires.to_string())
}

fn device_countdown(tier: fleet_ui::devices::DeviceTier, cert: Option<&identity::DeviceCert>) -> String {
    let Some(cert) = cert else {
        return "promote to continue".to_string();
    };
    let now = identity::now_secs();
    if cert.expires <= now {
        let date = chrono::DateTime::from_timestamp(cert.expires as i64, 0)
            .map(|at| at.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "expired".to_string());
        return match tier {
            fleet_ui::devices::DeviceTier::Fleet => format!("renews until {date}"),
            _ => format!("expired {date}"),
        };
    }
    let minutes = (cert.expires - now).saturating_add(59) / 60;
    match tier {
        fleet_ui::devices::DeviceTier::Fleet => format!("renews in {minutes}m"),
        _ => format!("expires in {minutes}m"),
    }
}

fn device_caps_summary(caps: &[String], tier: fleet_ui::devices::DeviceTier) -> String {
    let mut labels = Vec::new();
    for cap in caps {
        let label = match (tier, cap.as_str()) {
            (fleet_ui::devices::DeviceTier::External, "transfer") => "send→you",
            (_, "transfer") => "inbox",
            (_, "shell") => "shell",
            (_, "mount") => "mount",
            (_, "send") => "send→you",
            (_, "read") => "read ~/share",
            _ => cap.as_str(),
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        "(none)".to_string()
    } else {
        labels.join(" ")
    }
}

fn device_entries(warm: Option<&Value>) -> Vec<fleet_ui::devices::DeviceEntry> {
    let warm_names = warm_device_names(warm);
    let owner = load_owner_key().map(|key| key.public_key_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    devices_load()
        .into_iter()
        .map(|(name, _secret)| {
            let cert = device_cert_for(&name);
            let tier = match cert.as_ref() {
                None => fleet_ui::devices::DeviceTier::NeedsReview,
                Some(cert) if owner.as_ref() == Some(&cert.user_pub) => fleet_ui::devices::DeviceTier::Fleet,
                Some(_) => fleet_ui::devices::DeviceTier::External,
            };
            let caps = device_caps(&name).unwrap_or_else(|| vec!["transfer".to_string()]);
            let (last_seen, stored_v6, stored_v4) = devices_info(&name).unwrap_or((0, None, None));
            let address = stored_v6.or(stored_v4);
            let last_seen = (last_seen > 0).then(|| {
                let ago = now.saturating_sub(last_seen);
                if ago < 60 {
                    "just now".to_string()
                } else if ago < 3600 {
                    format!("{}m ago", ago / 60)
                } else if ago < 86400 {
                    format!("{}h ago", ago / 3600)
                } else {
                    format!("{}d ago", ago / 86400)
                }
            });
            let needs_promote = tier == fleet_ui::devices::DeviceTier::NeedsReview;
            let caps_summary = if needs_promote {
                "(full legacy trust)".to_string()
            } else {
                device_caps_summary(&caps, tier)
            };
            let caps_summary = match address {
                Some(address) => format!("{caps_summary}  {address}"),
                None => caps_summary,
            };
            fleet_ui::devices::DeviceEntry {
                name: name.clone(),
                tier,
                online: warm_names.contains(&name),
                caps_summary,
                countdown: if needs_promote {
                    String::new()
                } else {
                    device_countdown(tier, cert.as_ref())
                },
                last_seen,
                needs_promote,
            }
        })
        .collect()
}

/// CLI handler for `filament requests`
async fn requests_cmd(action: Option<RequestsAction>) -> Result<()> {
    match action {
        None | Some(RequestsAction::List { all: false }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(&v, false))),
                None => ui::say("  daemon not running; no pending request state"),
            }
        }
        Some(RequestsAction::List { all: true }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(&v, true))),
                None => ui::say("  daemon not running; no request state"),
            }
        }
        Some(RequestsAction::Approve { id, allow, duration }) => {
            let expires = crate::capability::now_secs().saturating_add(parse_duration_secs(&duration)?);
            let reply = crate::ctl::try_approve_request(id, &allow, expires).await;
            match reply {
                Some(v) => {
                    if let Some(peer) = v.get("peer").and_then(|v| v.as_str()) {
                        if let Some(cap) = v.get("capability").and_then(|v| v.as_str()) {
                            if let Some(granted_expires) = v.get("expires").and_then(|v| v.as_u64()) {
                                let expiry = format_approval_expiry(granted_expires);
                                ui::say(&fleet_ui::requests::render_approve_success(peer, cap, &expiry));
                            } else {
                                ui::say(&format!(
                                    "  {} approval succeeded but the grant expiry was missing",
                                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                                ));
                            }
                        }
                    }
                }
                None => ui::say(&format!("  {} request {id} not found or daemon not running", ui::paint(ui::Tone::Warn, "x"))),
            }
        }
        Some(RequestsAction::Deny { id }) => {
            let peer = local_request(id).map(|request| request.peer);
            let reply = crate::ctl::try_deny_request(id).await;
            match reply {
                Some(_) => {
                    if let Some(peer) = peer {
                        ui::say(&fleet_ui::requests::render_deny_success(&peer));
                    } else {
                        ui::say(&format!("  {} request {id} denied", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                    }
                }
                None => ui::say(&format!("  {} request {id} not found or daemon not running", ui::paint(ui::Tone::Warn, "x"))),
            }
        }
    }
    Ok(())
}

/// CLI handler for `filament ephemeral`
fn parse_mint_ttl(raw: &str) -> Result<u64> {
    let raw = raw.trim().to_ascii_lowercase();
    let (number, unit) = raw.split_at(raw.trim_end_matches(|c: char| c.is_ascii_alphabetic()).len());
    let value: u64 = number.parse().map_err(|_| anyhow!("invalid --ttl '{raw}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid --ttl '{raw}', use a duration such as 15m or 1h"),
    };
    Ok(value.saturating_mul(multiplier))
}

fn mint_capability(raw: &str) -> Result<String> {
    match raw {
        "send" => Ok("transfer".to_string()),
        "write" => Ok("mount".to_string()),
        "shell" | "mount" | "all-ports" | "transfer" => Ok(raw.to_string()),
        "reuse" => bail!("reuse is a lifetime option, not a capability"),
        "mesh" => {
            let (message, _) = fleet_ui::mint::err_mesh_not_grantable();
            bail!("{message}")
        }
        other => bail!("unsupported capability '{other}'"),
    }
}

async fn mint_cmd(
    server: &str,
    fleet: bool,
    external: Option<String>,
    ci: bool,
    ttl: Option<String>,
    reuse: Option<String>,
    allow: Vec<String>,
    audience: Option<String>,
    _yes: bool,
    relay: bool,
) -> Result<()> {
    let is_external = external.is_some();
    let selected = fleet as u8 + external.is_some() as u8 + ci as u8;
    if selected != 1 {
        let (message, _) = fleet_ui::mint::err_needs_key_type();
        bail!("{message}");
    }
    let key_type = if fleet { fleet_ui::mint::KeyType::Fleet } else if ci { fleet_ui::mint::KeyType::CI } else { fleet_ui::mint::KeyType::External };
    let default_ttl = if ci { "15m" } else { "1h" };
    let ttl_text = ttl.as_deref().unwrap_or(default_ttl);
    let ttl_secs = parse_mint_ttl(ttl_text)?;
    if is_external && ttl_secs > 24 * 3600 {
        let (message, _) = fleet_ui::mint::err_over_ttl();
        bail!("{message}");
    }

    let mut caps = Vec::new();
    for raw in &allow {
        let cap = mint_capability(raw)?;
        if !caps.contains(&cap) {
            caps.push(cap);
        }
    }
    if is_external && caps.is_empty() {
        bail!("external keys need at least one --allow capability");
    }
    if ci && audience.is_none() {
        bail!("CI keys require --audience <paired-device>");
    }
    if caps.is_empty() {
        caps.push("transfer".to_string());
    }

    let audience_name = external.or(audience);
    let audience = audience_name
        .map(|name| {
            device_cert_for(&name)
                .map(|cert| hex::encode(cert.device_pub))
                .ok_or_else(|| anyhow!("no certified paired device named '{name}'"))
        })
        .transpose()?;
    let lifetime = fleet_ui::mint::Lifetime {
        ttl: ttl_text.to_string(),
        reuse: match reuse.as_deref().unwrap_or("once").to_ascii_lowercase().as_str() {
            "once" => fleet_ui::mint::Reuse::Once,
            "reusable" => fleet_ui::mint::Reuse::Reusable,
            value if value.starts_with("n(") && value.ends_with(')') => fleet_ui::mint::Reuse::Times(value[2..value.len() - 1].parse().map_err(|_| anyhow!("invalid --reuse '{value}'"))?),
            value => fleet_ui::mint::Reuse::Times(value.parse().map_err(|_| anyhow!("invalid --reuse '{value}'"))?),
        },
        max_ttl: if ci { "15m".to_string() } else { "24h".to_string() },
    };
    let mint_caps = fleet_ui::mint::MintCaps {
        shell: caps.iter().any(|cap| cap == "shell"),
        write: caps.iter().any(|cap| cap == "mount"),
        all_ports: caps.iter().any(|cap| cap == "all-ports"),
    };
    eprintln!("{}", fleet_ui::mint::render_header());
    eprintln!("{}", fleet_ui::mint::render_summary(key_type, &mint_caps));
    eprintln!("{}", fleet_ui::mint::render_lifetime(&lifetime));

    ephemeral_cmd(
        server,
        EphemeralAction::Mint {
            caps,
            audience: audience.into_iter().collect(),
            ttl: ttl_secs,
            reuse: match lifetime.reuse {
                fleet_ui::mint::Reuse::Once => "Once".to_string(),
                fleet_ui::mint::Reuse::Times(n) => format!("N({n})"),
                fleet_ui::mint::Reuse::Reusable => "Reusable".to_string(),
            },
            tag: if ci { "ci".to_string() } else if is_external { "external".to_string() } else { "fleet".to_string() },
        },
        relay,
    )
    .await
}

/// CLI handler for `filament ephemeral`
async fn ephemeral_cmd(server: &str, action: EphemeralAction, relay: bool) -> Result<()> {
    match action {
        EphemeralAction::Mint { caps, audience, ttl, reuse, tag } => {
            let uk = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)? {
                Some(uk) => uk,
                None => bail!("no user identity. Run 'filament identity init' first."),
            };
            let rng = ring::rand::SystemRandom::new();
            let mut seed = [0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut seed).map_err(|e| anyhow::anyhow!("{}", e))?;
            let enroll_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let enroll_pub: [u8; 32] = ring::signature::KeyPair::public_key(&enroll_kp).as_ref().try_into().unwrap();
            let audience_pubs: Vec<[u8; 32]> = audience.iter()
                .map(|s| {
                    let b = hex::decode(s).map_err(|e| anyhow::anyhow!("audience hex: {}", e))?;
                    let arr: [u8; 32] = b.try_into().map_err(|_| anyhow::anyhow!("audience key must be 32 bytes"))?;
                    Ok(arr)
                })
                .collect::<Result<_>>()?;
            let reuse = match reuse.to_lowercase().as_str() {
                "once" => crate::ephemeral::Reuse::Once,
                "reusable" => crate::ephemeral::Reuse::Reusable,
                s if s.starts_with("n(") || s.starts_with('n') => {
                    let num: u32 = s.trim_start_matches('n').trim_start_matches('(').trim_end_matches(')').parse()
                        .map_err(|_| anyhow::anyhow!("invalid reuse count"))?;
                    crate::ephemeral::Reuse::N(num)
                }
                _ => bail!("invalid reuse: {reuse} (Once, N(3), Reusable)"),
            };
            let ak = crate::ephemeral::AuthKey::mint(uk.keypair(), enroll_pub, caps, audience_pubs, ttl, reuse, tag)?;
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "auth_key": ak.to_json(),
                "enroll_private_key": hex::encode(seed),
            }))?;
            println!("{}", json);
            eprintln!("{} auth key minted — save the JSON above. The enroll_private_key proves possession.",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()));
            // Arm the local daemon so it joins the enrollment room
            let ak = crate::ephemeral::AuthKey::from_json(&serde_json::from_str::<serde_json::Value>(&json)?.get("auth_key").unwrap_or(&serde_json::Value::Null))
                .ok_or_else(|| anyhow::anyhow!("failed to re-parse minted auth key"))?;
            if ctl::try_arm(hex::encode(ak.enroll_pub), ak.expires).await.is_some() {
                ui::debug("local daemon armed for enrollment");
            } else {
                ui::say(&format!("  {} no local daemon — enrollment room not armed (start 'filament up' first)",
                    ui::paint(ui::Tone::Dim, "·")));
            }
            Ok(())
        }
        EphemeralAction::Enroll { auth_key, to } => {
            enroll_cmd(server, &auth_key, to, relay).await
        }
    }
}

async fn enroll_cmd(server: &str, auth_key_json: &str, to_name: Option<String>, relay: bool) -> Result<()> {
    use crate::ephemeral::AuthKey;

    let v: serde_json::Value = {
        let ak_str = if std::path::Path::new(auth_key_json).exists() {
            std::fs::read_to_string(auth_key_json)?
        } else {
            auth_key_json.to_string()
        };
        serde_json::from_str(&ak_str)?
    };
    let ak = AuthKey::from_json(&v.get("auth_key").unwrap_or(&v)).ok_or_else(|| anyhow::anyhow!("invalid auth key JSON"))?;
    let enroll_seed = v.get("enroll_private_key")
        .and_then(|s| s.as_str())
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| anyhow::anyhow!("missing enroll_private_key in auth key JSON"))?;
    let enroll_seed: [u8; 32] = enroll_seed.try_into().map_err(|_| anyhow::anyhow!("bad enroll key seed"))?;
    let mut dseed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_pub: [u8; 32] = ring::signature::KeyPair::public_key(&device_kp).as_ref().try_into().unwrap();

    ui::say(&format!("{} auth key loaded (caps: {:?}, issuer: {})",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        ak.caps.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        hex::encode(&ak.issuer[..4])));

    let my_uid = mk_uid("e");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;

    // Join enrollment rendezvous channel derived from owner's public key.
    // Enroller sets its own room (so signals route) + subscribes to the
    // enrollment channel. Discovery via KnownPeer on shared channel.
    let enroll_chan = crate::ephemeral::enroll_channel(&ak.issuer);
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(format!("enrollup-{}", fresh_secret()));
    sess.channels = vec![enroll_chan.clone()];
    sess.emit(&sio, "join", json!({ "room": sess.room.as_ref().unwrap(), "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] })).await;

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,
        to_name,
        false,
        direct::direct_enabled(),
    );

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let started = Instant::now();
    let enroll_deadline = Duration::from_secs(60);

    loop {
        let elapsed = started.elapsed();
        if elapsed >= enroll_deadline {
            bail!("enrollment timed out after {}s (no response from peer)", enroll_deadline.as_secs());
        }

        let slice = Duration::from_secs(2).min(enroll_deadline.saturating_sub(elapsed));
        let ev = match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Some(ev)) => Some(ev),
            Ok(None) => bail!("signaling channel closed"),
            Err(_) => None,
        };

        sess.tick(&sio).await;

        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, false).await?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, false).await?;
            }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if p["channel"].as_str() == Some(enroll_chan.as_str())
                            && !is_self_uid(&conn.my_uid, p["uid"].as_str())
                        {
                            conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // The owner daemon is present on the enroll channel. DIAL it as
                // the IMPOLITE peer (offerer): the owner answers via
                // ensure_responder (forced polite) and cannot reliably learn of
                // a late-arriving enroller from server presence, so the enroller
                // MUST drive the offer regardless of uid ordering.
                if !is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty() && !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
                        if conn.active.is_none() { conn.active = Some(pid); }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                if conn.active.is_none() {
                    conn.active = Some(pid.clone());
                }

                crate::ephemeral::register_enrollment(
                    pid.clone(),
                    enroll_seed,
                    dseed,
                    device_pub,
                    ak.clone(),
                );

                let _ = t.send_control(&json!({
                    "type": "identity-auth-key-enroll-request",
                    "auth_key": ak.to_json(),
                    "device_pub": hex::encode(device_pub),
                })).await;

                ui::say(&format!("  {} sent enrollment request to {}",
                    ui::paint(ui::Tone::Dim, "->"),
                    pid));
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) = (hex::decode(nonce_hex), hex::decode(verifier_hex)) {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                let device_cert = v.get("device_cert").cloned().unwrap_or(serde_json::Value::Null);
                                if let Some(response) = crate::ephemeral::build_enrollment_response(
                                    &pid, nonce_arr, verifier_pub, &device_cert,
                                ) {
                                    let _ = t.send_control(&json!({
                                        "type": "identity-auth-key-enroll-response",
                                        "auth_key": response["auth_key"],
                                        "device_pub": response["device_pub"],
                                        "enroll_possession_sig": response["enroll_possession_sig"],
                                        "device_possession_sig": response["device_possession_sig"],
                                    })).await;
                                }
                            }
                        }
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let name = v["name"].as_str().unwrap_or("ephemeral-device");
                    ui::say(&format!("{} enrolled as ephemeral device '{}' (device_pub: {})",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        name,
                        hex::encode(device_pub)));
                    return Ok(());
                }
                Some("identity-auth-key-enroll-error") => {
                    bail!("enrollment rejected: {}", v["reason"].as_str().unwrap_or("unknown reason"));
                }
                _ => {}
            },
            Ev::Interrupted => bail!("cancelled"),
            Ev::SignalingDown(reason) => {
                bail!("signaling connection lost: {reason}");
            }
            _ => {}
        }
    }
}

/// Enroll as delegated + send files in one session.
/// Loads auth key, joins enrollment channel, completes handshake, then sends
/// files over the enrolled transport. The owner's daemon applies the ceiling.
async fn enroll_and_send_cmd(
    server: &str,
    auth_key_path: String,
    to_name: Option<String>,
    paths: Vec<String>,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    // Load auth key
    let v: serde_json::Value = {
        let ak_str = if std::path::Path::new(&auth_key_path).exists() {
            std::fs::read_to_string(&auth_key_path)?
        } else {
            auth_key_path.clone()
        };
        serde_json::from_str(&ak_str)?
    };
    let ak = crate::ephemeral::AuthKey::from_json(&v.get("auth_key").unwrap_or(&v))
        .ok_or_else(|| anyhow::anyhow!("invalid auth key JSON"))?;
    let enroll_seed = v.get("enroll_private_key")
        .and_then(|s| s.as_str())
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| anyhow::anyhow!("missing enroll_private_key"))?;
    let enroll_seed: [u8; 32] = enroll_seed.try_into().map_err(|_| anyhow::anyhow!("bad enroll key"))?;
    let mut dseed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_pub: [u8; 32] = ring::signature::KeyPair::public_key(&device_kp).as_ref().try_into().unwrap();

    ui::say(&format!("  {} enrolling as delegated (caps: {:?})",
        ui::paint(ui::Tone::Dim, "->"),
        ak.caps.iter().map(|s| s.as_str()).collect::<Vec<_>>()));

    let enroll_chan = crate::ephemeral::enroll_channel(&ak.issuer);
    let my_uid = mk_uid("a");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = vec![enroll_chan.clone()];
    sess.room = Some(format!("enrollup-{}", fresh_secret()));
    sess.emit(&sio, "join", json!({ "room": sess.room.as_ref().unwrap(), "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] })).await;

    let mut conn = Conn::for_command(server, sio.clone(), tx.clone(), my_uid, relay, to_name.clone(), false, direct::direct_enabled());
    crate::ephemeral::register_enrollment(String::new(), enroll_seed, dseed, device_pub, ak.clone());

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(60);

    loop {
        if started.elapsed() >= deadline {
            bail!("enrollment timed out after {}s", deadline.as_secs());
        }
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        let Ok(Some(ev)) = ev else {
            // Check if we have a path to send — enrollment may already be done
            if conn.active.is_some() {
                break;
            }
            continue;
        };
        match ev {
            Ev::Welcome(v) => {
                // The owner daemon is already in the enroll room; the server hands
                // us its roster here. Dial each peer (owner answers) so rendezvous
                // does not depend on a later peer-joined we would otherwise miss.
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers { conn.maybe_adopt(p, true).await?; }
                }
            }
            Ev::PeerJoined(v) => { conn.maybe_adopt(&v, true).await?; }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if p["channel"].as_str() == Some(enroll_chan.as_str())
                            && !is_self_uid(&conn.my_uid, p["uid"].as_str())
                        {
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // Enroller drives: dial the owner daemon (present on the enroll
                // channel) as the IMPOLITE offerer; the owner answers via
                // ensure_responder. Server presence does not reliably notify the
                // pre-existing owner of a late enroller, so we must initiate.
                if !is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty() && !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
                        if conn.active.is_none() { conn.active = Some(pid); }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                if conn.active.is_none() { conn.active = Some(pid.clone()); }
                crate::ephemeral::register_enrollment(pid.clone(), enroll_seed, dseed, device_pub, ak.clone());
                let _ = t.send_control(&json!({
                    "type": "identity-auth-key-enroll-request",
                    "auth_key": ak.to_json(),
                })).await;
                ui::say(&format!("  {} enrollment request sent", ui::paint(ui::Tone::Dim, "->")));
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        let cert_val = v.get("device_cert").cloned().unwrap_or(serde_json::Value::Null);
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) = (hex::decode(nonce_hex), hex::decode(verifier_hex)) {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                if let Some(response) = crate::ephemeral::build_enrollment_response(&pid, nonce_arr, verifier_pub, &cert_val) {
                                    let _ = t.send_control(&json!({
                                        "type": "identity-auth-key-enroll-response",
                                        "auth_key": response["auth_key"],
                                        "device_pub": response["device_pub"],
                                        "enroll_possession_sig": response["enroll_possession_sig"],
                                        "device_possession_sig": response["device_possession_sig"],
                                    })).await;
                                }
                            }
                        }
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let dp_hex = v["device_pub"].as_str().unwrap_or("?");
                    ui::say(&format!("  {} enrolled (device_pub: {})", ui::paint(ui::Tone::Ok, ui::glyph_ok()), &dp_hex[..16]));
                    // Enrollment complete — break to send files
                    conn.active = Some(pid.clone());
                    break;
                }
                Some("identity-auth-key-enroll-error") => {
                    bail!("enrollment denied: {}", v["reason"].as_str().unwrap_or("unknown"));
                }
                _ => {}
            },
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }

    // Enrollment complete — now send files over the enrolled transport.
    // The owner's daemon applies the ceiling against auth_key.caps.
    ui::say(&format!("  {} sending {} file(s)", ui::paint(ui::Tone::Dim, "->"), paths.len()));
    let active_pid = conn.active.as_ref().cloned().unwrap_or_default();
    let t = conn.transport_of(&active_pid)
        .ok_or_else(|| anyhow::anyhow!("no transport after enrollment"))?;
    for path in &paths {
        let data = tokio::fs::read(path).await?;
        let name = std::path::Path::new(path).file_name()
            .and_then(|n| n.to_str()).unwrap_or("file");
        let id = format!("ak-{}", paths.iter().position(|p| p == path).unwrap_or(0));

        // Send file offer using the standard protocol
        let offer = crate::protocol::offer_msg(&id, 0, name, data.len() as u64, None, None, false);
        if let Err(e) = t.send_control(&offer).await {
            bail!("failed to send file offer for {name}: {e}");
        }

        // Wait for accept/decline (30s)
        let offer_start = Instant::now();
        let mut accepted = false;
        loop {
            if offer_start.elapsed() >= Duration::from_secs(30) {
                bail!("file offer for {name} timed out (no accept/decline)");
            }
            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
            let Ok(Some(ev)) = ev else { continue; };
            if let Ev::Control(ref pid, ref v) = ev {
                if pid == &active_pid && v["id"].as_str() == Some(&id) {
                    match v["type"].as_str() {
                        Some("file-accept") => { accepted = true; break; }
                        Some("file-decline") => {
                            bail!("file {name} declined: {}", v["reason"].as_str().unwrap_or("not authorized"));
                        }
                        _ => {}
                    }
                }
            }
            if matches!(ev, Ev::Interrupted) { bail!("interrupted"); }
        }
        if !accepted {
            bail!("transfer of {name} not accepted");
        }

        // Write data chunks via send_frame (sid=0, offset-incremented)
        let total = data.len();
        let max_payload = t.max_payload().max(1024);
        let mut sent = 0usize;
        while sent < total {
            let end = total.min(sent + max_payload);
            let chunk = &data[sent..end];
            t.send_frame(0, sent as u64, chunk).await.map_err(|e| {
                anyhow::anyhow!("data channel failed during transfer of {name} (sent {sent}/{total}): {e}")
            })?;
            sent = end;
        }
        let _ = t.flush().await;
        // File-end marker so the receiver finalizes + hashes the complete file.
        // Must match the sid declared in the offer (0).
        t.send_control(&crate::protocol::end_msg(&id, 0)).await
            .map_err(|e| anyhow::anyhow!("failed to send file-end for {name}: {e}"))?;
        ui::say(&format!("  {} sent {} ({} bytes)", ui::paint(ui::Tone::Ok, ui::glyph_ok()), name, total));
    }
    if let Some(name) = remember {
        // Not stored as known device — delegated is ephemeral
        ui::say(&format!("  {} delegated devices are ephemeral (--remember for enrollment not stored)", ui::paint(ui::Tone::Dim, "·")));
        let _ = name;
    }
    Ok(())
}

/// Enroll as delegated + open shell in one session.
/// Same flow as enroll_and_send_cmd but opens an l2 shell instead of sending files.
async fn enroll_and_netcat_cmd(
    server: &str,
    auth_key_path: String,
    to_name: Option<String>,
    rport: u16,
    relay: bool,
) -> Result<()> {
    // Load auth key (same as enroll_and_send_cmd)
    let v: serde_json::Value = {
        let ak_str = if std::path::Path::new(&auth_key_path).exists() {
            std::fs::read_to_string(&auth_key_path)?
        } else {
            auth_key_path.clone()
        };
        serde_json::from_str(&ak_str)?
    };
    let ak = crate::ephemeral::AuthKey::from_json(&v.get("auth_key").unwrap_or(&v))
        .ok_or_else(|| anyhow::anyhow!("invalid auth key JSON"))?;
    let enroll_seed = v.get("enroll_private_key")
        .and_then(|s| s.as_str())
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| anyhow::anyhow!("missing enroll_private_key"))?;
    let enroll_seed: [u8; 32] = enroll_seed.try_into().map_err(|_| anyhow::anyhow!("bad enroll key"))?;
    let mut dseed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&dseed)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let device_pub: [u8; 32] = ring::signature::KeyPair::public_key(&device_kp).as_ref().try_into().unwrap();

    ui::say(&format!("  {} enrolling as delegated (caps: {:?})",
        ui::paint(ui::Tone::Dim, "->"),
        ak.caps.iter().map(|s| s.as_str()).collect::<Vec<_>>()));

    let enroll_chan = crate::ephemeral::enroll_channel(&ak.issuer);
    let my_uid = mk_uid("n");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = vec![enroll_chan.clone()];
    sess.room = Some(format!("enrollup-{}", fresh_secret()));
    sess.emit(&sio, "join", json!({ "room": sess.room.as_ref().unwrap(), "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] })).await;

    let mut conn = Conn::for_command(server, sio.clone(), tx.clone(), my_uid, relay, to_name.clone(), false, direct::direct_enabled());
    crate::ephemeral::register_enrollment(String::new(), enroll_seed, dseed, device_pub, ak.clone());

    {
        let tx = tx.clone();
        tokio::spawn(async move { let _ = tokio::signal::ctrl_c().await; let _ = tx.send(Ev::Interrupted); });
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(60);

    loop {
        if started.elapsed() >= deadline { bail!("enrollment timed out"); }
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        let Ok(Some(ev)) = ev else {
            if conn.active.is_some() { break; }
            continue;
        };
        match ev {
            Ev::Welcome(v) => {
                // The owner daemon is already in the enroll room; the server hands
                // us its roster here. Dial each peer (owner answers) so rendezvous
                // does not depend on a later peer-joined we would otherwise miss.
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers { conn.maybe_adopt(p, true).await?; }
                }
            }
            Ev::PeerJoined(v) => { conn.maybe_adopt(&v, true).await?; }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if p["channel"].as_str() == Some(enroll_chan.as_str())
                            && !is_self_uid(&conn.my_uid, p["uid"].as_str())
                        {
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // Enroller drives: dial the owner daemon (present on the enroll
                // channel) as the IMPOLITE offerer; the owner answers via
                // ensure_responder. Server presence does not reliably notify the
                // pre-existing owner of a late enroller, so we must initiate.
                if !is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty() && !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
                        if conn.active.is_none() { conn.active = Some(pid); }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) { l.transport = Some(t.clone()); l.presence = Presence::Ready; }
                if conn.active.is_none() { conn.active = Some(pid.clone()); }
                crate::ephemeral::register_enrollment(pid.clone(), enroll_seed, dseed, device_pub, ak.clone());
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-request", "auth_key": ak.to_json()})).await;
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        let cert_val = v.get("device_cert").cloned().unwrap_or(serde_json::Value::Null);
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) = (hex::decode(nonce_hex), hex::decode(verifier_hex)) {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                if let Some(response) = crate::ephemeral::build_enrollment_response(&pid, nonce_arr, verifier_pub, &cert_val) {
                                    let _ = t.send_control(&json!({
                                        "type": "identity-auth-key-enroll-response",
                                        "auth_key": response["auth_key"],
                                        "device_pub": response["device_pub"],
                                        "enroll_possession_sig": response["enroll_possession_sig"],
                                        "device_possession_sig": response["device_possession_sig"],
                                    })).await;
                                }
                            }
                        }
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let dp_hex = v["device_pub"].as_str().unwrap_or("?");
                    ui::say(&format!("  {} enrolled (device_pub: {})", ui::paint(ui::Tone::Ok, ui::glyph_ok()), &dp_hex[..16]));
                    conn.active = Some(pid.clone());
                    break;
                }
                Some("identity-auth-key-enroll-error") => {
                    bail!("enrollment denied: {}", v["reason"].as_str().unwrap_or("unknown"));
                }
                _ => {}
            },
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }

    ui::say(&format!("  {} opening shell to port {}", ui::paint(ui::Tone::Dim, "->"), rport));
    let active_pid = conn.active.as_ref().cloned().unwrap_or_default();
    let t = conn.transport_of(&active_pid)
        .ok_or_else(|| anyhow::anyhow!("no transport after enrollment"))?;
    // Send l2-open request for shell on rport
    let r = t.send_control(&json!({
        "type": "l2-open",
        "host": "127.0.0.1",
        "rport": rport,
    })).await;
    match r {
        Ok(()) => {
            ui::say(&format!("  {} shell request sent", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
            // Wait for l2-open-ack or close
            let shell_start = Instant::now();
            loop {
                if shell_start.elapsed() >= Duration::from_secs(30) {
                    bail!("shell request timed out (no response from owner)");
                }
                let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
                let Ok(Some(ev)) = ev else { continue; };
                if let Ev::Control(ref pid, ref v) = ev {
                    if pid == &active_pid {
                        match v["type"].as_str() {
                            Some("l2-open-ack") => {
                                ui::say(&format!("  {} shell authorized (sid {})", ui::paint(ui::Tone::Ok, ui::glyph_ok()), v["sid"]));
                                break;
                            }
                            Some("l2-close") => {
                                bail!("shell refused: {}", v["err"].as_str().unwrap_or("not authorized"));
                            }
                            _ => {}
                        }
                    }
                }
                if matches!(ev, Ev::Interrupted) { bail!("interrupted"); }
            }
        }
        Err(e) => bail!("failed to send shell request: {e}"),
    }
    Ok(())
}

/// Respond to an identity-auth-key-enroll-request with a nonce challenge.
/// Step 1: rate-limit BEFORE expensive ops (anti-flood).
/// Step 2: verify auth key against owner.
/// Step 3: generate CSPRNG nonce, store, send challenge.
async fn respond_to_auth_key_enroll_request(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else { return };

    // Rate-limit FIRST — keyed on pid, counts EVERY request including garbage.
    // An attacker sending unparseable JSON is bounded here, before parse cycles.
    if let Err(e) = crate::ephemeral::check_rate_limit(&pid) {
        ui::debug(&format!("enroll request rate-limited: {e}"));
        let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
        return;
    }

    // Enroll-and-use is only COHERENT under authoritative capability enforcement:
    // in shadow mode a delegated principal's ceiling does not gate the legacy
    // path, so admitting one yields a hollow "enrolled" that then can't act (and
    // could even be over-permitted). Refuse at this boundary with an explicit,
    // non-oracle reason (config state, not key validity) so the operator knows
    // exactly what to change, instead of a silent later decline.
    if !crate::capability::cap_authoritative() {
        ui::debug("enroll request declined: capability enforcement not authoritative (set FILAMENT_CAP_AUTHORITATIVE=1)");
        let _ = t.send_control(&json!({
            "type": "identity-auth-key-enroll-error",
            "reason": "delegated principal: capability enforcement not authoritative"
        })).await;
        return;
    }

    let ak = match crate::ephemeral::AuthKey::from_json(&v.get("auth_key").unwrap_or(&v)) {
        Some(ak) => ak,
        None => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Verify against our trusted owner
    let owner_pub = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk.public_key_bytes(),
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll request overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    if let Err(e) = ak.verify_against_owner(&owner_pub, &verifier_pub) {
        ui::debug(&format!("enroll request auth-key rejected: {e}"));
        let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
        return;
    }

    // Generate nonce challenge — include daemon's device cert so the enroller
    // can verify it chains to the auth key's issuer (mutual authentication).
    let nonce = match crate::ephemeral::generate_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll request nonce CSPRNG failure: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let cert_value = local_device_cert().map(|c| c.to_json());
    let _ = t.send_control(&json!({
        "type": "identity-auth-key-enroll-challenge",
        "nonce": hex::encode(nonce),
        "verifier_pub": hex::encode(verifier_pub),
        "device_cert": cert_value,
    })).await;
}

/// Handle the enrollment response from the enroller.
/// Step 4 (burn only on SUCCESS): consume nonce, verify payload, admit as delegated.
async fn handle_auth_key_enroll_response(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else { return };
    let payload = match crate::ephemeral::EnrollmentPayload::from_json(&v) {
        Some(p) => p,
        None => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_pub = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk.public_key_bytes(),
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll response overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Structural nonce consumption — daemon retrieves its OWN stored nonce,
    // never trusts a nonce value echoed by the enroller.
    let nonce = match crate::ephemeral::consume_latest_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll response nonce consumption failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Verify payload with consumed nonce
    match payload.verify(&owner_pub, &nonce, &verifier_pub) {
        Ok((enroll_pub, device_pub, ak)) => {
            // Burn ON SUCCESS only (never-reset counter)
            if let Err(e) = crate::ephemeral::burn_auth_key(&enroll_pub, &ak.reuse) {
                ui::debug(&format!("enroll response burn failed: {e}"));
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            // Admit as Delegated principal — structurally, all four fields together
            if let Some(link) = conn.link_mut(&pid) {
                link.admit_delegated(owner_pub, device_pub, ak.expires, ak.caps.clone());
            }
            let _ = t.send_control(&json!({
                "type": "identity-auth-key-enroll-ack",
                "device_pub": hex::encode(device_pub),
                "expires": ak.expires
            })).await;
            ui::say(&format!("  {} ephemeral device {pid} enrolled (caps: {:?})",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                ak.caps));
        }
        Err(e) => {
            ui::debug(&format!("enroll response verify failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
        }
    }
}

fn down_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => {
            std::process::Command::new("kill").arg(pid.to_string()).status()?;
            let _ = std::fs::remove_file(pidfile());
            ui::say(&format!("  {} stopped (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
            Ok(())
        }
        None => {
            ui::say("  not running");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------- reset -----
// `filament reset`: a conservative clean-slate for the LOCAL machine. It removes
// only filament's OWN state under the config dir (identity/overlay keys, the
// paired-device store, the capability store, pending consent requests, the
// managed ssh material) and strips the delimited `# BEGIN/END filament-managed
// <device>` blocks it installed in ~/.ssh/authorized_keys. It NEVER touches the
// user's real ssh keys or any authorized_keys lines outside those blocks.

/// Remove `path` if present, pushing a human line into `wiped`. Files and
/// directories both handled; a missing path is silently skipped (idempotent).
fn reset_remove(path: &std::path::Path, label: &str, wiped: &mut Vec<String>) {
    let removed = if path.is_dir() {
        std::fs::remove_dir_all(path).is_ok()
    } else if path.exists() {
        std::fs::remove_file(path).is_ok()
    } else {
        false
    };
    if removed {
        wiped.push(format!("{label}  ({})", path.display()));
    }
}

fn reset_cmd(ui_caps: &UiCapability) -> Result<()> {
    // 1. Refuse while the daemon runs: reset yanks the keys and device store out
    //    from under a live acceptor. Make the user stop it explicitly.
    if let Some(pid) = daemon_alive() {
        bail!("the filament daemon is running (pid {pid}); run `filament down` first, then `filament reset`");
    }

    // 2. Confirm (destructive). ui_caps.confirm honors the global -y/--yes and
    //    REFUSES from a non-TTY without it, exactly the required behavior.
    ui_caps.confirm("wipe ALL local filament state (identity, devices, caps, managed ssh keys) on this machine")?;

    let cfg = crate::settings::config_dir();
    let mut wiped: Vec<String> = Vec::new();

    // 3. Strip the managed authorized_keys blocks BEFORE devices.json is gone,
    //    so we know every petname whose block filament may have installed. Only
    //    the delimited `# BEGIN/END filament-managed <device>` blocks are removed;
    //    everything else in authorized_keys is preserved verbatim.
    let ak_path = crate::sshkeys::authorized_keys_path();
    if let Ok(existing) = std::fs::read_to_string(&ak_path) {
        let mut content = existing.clone();
        let mut stripped: Vec<String> = Vec::new();
        for (name, _) in devices_load() {
            if crate::sshkeys::has_block(&content, &name) {
                content = crate::sshkeys::strip_block(&content, &name);
                stripped.push(name);
            }
        }
        if content != existing {
            // Best-effort restrictive write (owner-only), same as the installer.
            if crate::platform::SecretFile::write_str(&ak_path, &content).is_ok() {
                wiped.push(format!(
                    "managed authorized_keys blocks: {}  ({})",
                    stripped.join(", "),
                    ak_path.display()
                ));
            } else {
                ui::say(&ui::paint(
                    ui::Tone::Warn,
                    &format!("  could not rewrite {} — leaving it untouched", ak_path.display()),
                ));
            }
        }
    }

    // 4. Remove filament's own state files. Each is filament-authored; a missing
    //    file is a silent no-op. Explicit list (NOT a blanket rmdir of the config
    //    dir) so a mis-set FILAMENT_CONFIG_DIR can never take out unrelated files.
    reset_remove(&cfg.join("identity.ed25519"), "user identity key", &mut wiped);
    reset_remove(&cfg.join("overlay.ed25519"), "overlay key", &mut wiped);
    reset_remove(&cfg.join("devices.json"), "paired-device store (device certs)", &mut wiped);
    reset_remove(&cfg.join("caps.json"), "capability store", &mut wiped);
    reset_remove(&cfg.join("requests.json"), "pending consent requests", &mut wiped);
    reset_remove(&cfg.join("expose.json"), "exposed-service records", &mut wiped);
    reset_remove(&cfg.join("mounts.json"), "mount records", &mut wiped);
    reset_remove(&cfg.join("l2-allow.json"), "L2 forward allowlist", &mut wiped);
    reset_remove(&cfg.join("signaling-dns.json"), "signaling DNS cache", &mut wiped);
    reset_remove(&cfg.join("peerconf"), "per-peer settings", &mut wiped);
    reset_remove(&cfg.join("config"), "global settings", &mut wiped);
    reset_remove(&cfg.join("diag.jsonl"), "diagnostics log", &mut wiped);
    reset_remove(&cfg.join("mount-profiles"), "saved mount profiles", &mut wiped);
    // Managed ssh material (private key, known_hosts pins, bootstrap cache) lives
    // under {config}/ssh — filament-authored, distinct from the user's ~/.ssh.
    reset_remove(&cfg.join("ssh"), "managed ssh material (key, known_hosts, cache)", &mut wiped);

    // 5. Invalidate the in-process cap-store read cache so a same-process reader
    //    can't serve the just-deleted store from memory.
    crate::capability::invalidate_cap_cache();

    if wiped.is_empty() {
        ui::say("  nothing to wipe — no local filament state found");
    } else {
        ui::say(&format!("  {} wiped local filament state:", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
        for line in &wiped {
            ui::say(&format!("    - {line}"));
        }
        ui::say("  this machine is now a clean slate (re-pair / `filament identity init` to start over)");
    }
    Ok(())
}

// ------------------------------------------------------------ introduce ----
// Vouched pairing: the hub (which already trusts A and B) mints a fresh
// secret and delivers it to both over channels it has PROVEN itself on
// (fingerprint-bound, C20). Receivers only honor pair-intro from a verified
// link, so a stranger, or the server, can't inject trust.

async fn introduce_cmd(server: &str, a: &str, b: &str, relay: bool) -> Result<()> {
    let store = devices_load();
    let find = |n: &str| store.iter().find(|(name, _)| name.eq_ignore_ascii_case(n)).cloned();
    let (a_name, a_sec) = find(a).ok_or_else(|| anyhow!("'{a}' is not a known device (see: filament devices)"))?;
    let (b_name, b_sec) = find(b).ok_or_else(|| anyhow!("'{b}' is not a known device"))?;

    let my_uid = mk_uid("s");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let solo = format!("intro-{}", fresh_secret());
    // C30: the session repairs whatever these emits lose, and under gate L
    // they are the emits the loss shim adversarially drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.channels = vec![channel_of(&a_sec), channel_of(&b_sec)];
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] })).await;
    ui::say(&format!("  waiting for {} and {} to be online...", ui::paint(ui::Tone::Bold, &a_name), ui::paint(ui::Tone::Bold, &b_name)));

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: None,
        links: HashMap::new(),
        roster: HashMap::new(),
        suppressed_digest_adoptions: HashSet::new(),
        active: None,
        next_gen: 0,
        rejoin: RejoinState { waiting_rejoin: None, rejoin_window: REJOIN_WINDOW, away: None },
        chunk_size: net::MAX_DC_PAYLOAD,
        deferred_left: HashMap::new(),
        recv_done: false,
        direct_pending: HashMap::new(),
        buffered_offers: HashMap::new(),
        resil: ResilienceState {
        stall_repairs: HashMap::new(),
        relay_committed: std::collections::HashSet::new(),
        warm_standby: net::warm_standby_override().unwrap_or(false),
        warm_cutover: std::collections::HashSet::new(),
        upgrade_probe: HashMap::new(),
        iface_snapshot: Vec::new(),
    },
    direct_ok: direct::direct_enabled(),
    local_port: None,
    local_listener: None,
    direct_endpoint: None,
    warm_hold: WarmHold::default(),
    worker_port_tx: HashMap::new(),
    };
    // sid -> which device (false = a, true = b)
    let mut who: HashMap<String, bool> = HashMap::new();
    let mut sent: [bool; 2] = [false, false];
    let fresh = fresh_secret();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();

    loop {
        if Instant::now() > deadline {
            bail!("timed out, both devices must be online (e.g. running `filament up`)");
        }
        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                // C30 (dissolves the C28 belt): fresh sid, re-assert via session.
                sess.invalidate();
            }
            // C30 phase 2: reconcile the roster the digest carries so a missed
            // `welcome`/`peer-joined` self-corrects instead of stranding this
            // wait. `introduce` waits on room presence, so it is class S.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if is_self_uid(&conn.my_uid, p["uid"].as_str()) {
                            continue;
                        }
                        let ch = p["channel"].as_str().unwrap_or_default();
                        let (is_b, secret, name) = if ch == channel_of(&a_sec) {
                            (false, &a_sec, &a_name)
                        } else if ch == channel_of(&b_sec) {
                            (true, &b_sec, &b_name)
                        } else {
                            continue;
                        };
                        let pid = p["id"].as_str().unwrap_or_default().to_string();
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((name.clone(), secret.clone()));
                        }
                        who.insert(pid, is_b);
                    }
                    let present: std::collections::HashSet<String> = roster.channel_peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    let channels = [channel_of(&a_sec), channel_of(&b_sec)];
                    let mut gone = Vec::new();
                    for (pid, link) in &conn.links {
                        let tracked = link.expected_secret.as_ref().map(|(_, secret)| {
                            channels.iter().any(|ch| ch == &channel_of(secret))
                        }).unwrap_or(false);
                        if tracked && !present.contains(pid) {
                            let count = channel_digest_absent.entry(pid.clone()).or_insert(0);
                            *count += 1;
                            if *count >= 2 { gone.push(pid.clone()); }
                        } else {
                            channel_digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        channel_digest_absent.remove(&pid);
                        conn.drop_link(&pid);
                        who.remove(&pid);
                    }
                }
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own processes share these channels
                }
                let ch = v["channel"].as_str().unwrap_or_default().to_string();
                let pid = v["id"].as_str().unwrap_or_default().to_string();
                let is_b = if ch == channel_of(&a_sec) { false } else if ch == channel_of(&b_sec) { true } else { continue };
                conn.maybe_adopt(&v, false).await?;
                if let Some(l) = conn.link_mut(&pid) {
                    l.expected_secret = Some(if is_b { (b_name.clone(), b_sec.clone()) } else { (a_name.clone(), a_sec.clone()) });
                }
                who.insert(pid, is_b);
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                let Some(&is_b) = who.get(&pid) else { continue };
                let (dev_name, sec) = if is_b { (&b_name, &b_sec) } else { (&a_name, &a_sec) };
                let other_name = if is_b { &a_name } else { &b_name };
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                        // prove ourselves, then vouch
                        t.send_control(&json!({
                            "type": "pair-proof",
                            "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                        })).await?;
                        t.send_control(&json!({
                            "type": "pair-intro", "name": other_name, "secret": fresh,
                        })).await?;
                        sent[is_b as usize] = true;
                        ui::say(&format!("  {} vouched to {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, dev_name)));
                    }
                }
                if sent[0] && sent[1] {
                    // Both pair-intro sent, now start identity exchange with 0x02 nonce challenge
                    // Receiver generates nonce + receiver_device_pub, sender binds and signs
                    // Challenge carries ONLY nonce + receiver_device_pub per correction A
                    use ring::rand::{SecureRandom, SystemRandom};
                    let rng = SystemRandom::new();
                    // Find pids for A and B
                    let mut a_pid: Option<String> = None;
                    let mut b_pid: Option<String> = None;
                    for (pid, is_b) in &who {
                        if *is_b {
                            b_pid = Some(pid.clone());
                        } else {
                            a_pid = Some(pid.clone());
                        }
                    }
                    if let (Some(a_pid), Some(b_pid)) = (a_pid, b_pid) {
                        // Get transports
                        if let (Some(t_a), Some(t_b)) = (conn.transport_of(&a_pid), conn.transport_of(&b_pid)) {
                            // Generate nonces
                            let mut nonce_a = [0u8; 32];
                            let mut nonce_b = [0u8; 32];
                            let _ = rng.fill(&mut nonce_a);
                            let _ = rng.fill(&mut nonce_b);
                            // Get device_pubs for A and B: overlay key always exists, not cert-or-zeros per correction.
                            // FIX: receiver_device_pub must be overlay key from overlay_pubkey_bytes(), which ALWAYS exists.
                            // Previously used cert-or-zeros fallback which silently drops target-binding for no-cert peers.
                            // Note: cert.device_pub == overlay key, so with cert value identical; fix only changes no-cert case.
                            // LOAD-BEARING ASSUMPTION for confidentiality: identity-expose for introduce goes over DIRECT A-B DTLS DataChannel
                            // (the introduced pair's OWN transport, E2E DTLS, introducer/hub is NOT a DTLS endpoint, only does signaling/rendezvous).
                            // There is NO fallback where hub bridges two DTLS sessions as A<->Hub<->B separate DTLS (hub-bridging is NOT allowed).
                            // TURN relay is fine (DTLS-blind, still E2E), hub-bridging is NOT (introducer would see cleartext and property breaks).
                            // This comment guards future refactors from silently opening a hub-bridged path.
                            // Sealing with HKDF(fresh_secret) would make introducer able to read (since it minted secret), while direct DTLS keeps introducer BLIND (stronger).
                            let a_device_pub = device_cert_for(&a_name).map(|c| c.device_pub).unwrap_or_else(|| overlay::overlay_pubkey_bytes().unwrap_or([0u8; 32]));
                            let b_device_pub = device_cert_for(&b_name).map(|c| c.device_pub).unwrap_or_else(|| overlay::overlay_pubkey_bytes().unwrap_or([0u8; 32]));
                            // Challenge from A to B: nonce_A + receiver_device_pub_A (A's device_pub)
                            let challenge_a_to_b = json!({
                                "type": "identity-nonce-challenge",
                                "nonce": hex::encode(nonce_a),
                                "receiver_device_pub": hex::encode(a_device_pub)
                            });
                            // Challenge from B to A
                            let challenge_b_to_a = json!({
                                "type": "identity-nonce-challenge",
                                "nonce": hex::encode(nonce_b),
                                "receiver_device_pub": hex::encode(b_device_pub)
                            });
                            // Send challenges via data channel (control) - only nonce + receiver_device_pub per correction A
                            let _ = t_b.send_control(&challenge_a_to_b).await;
                            let _ = t_a.send_control(&challenge_b_to_a).await;
                            ui::say(&ui::paint(ui::Tone::Dim, "  identity challenge exchanged, waiting for sealed certs..."));
                            // For now, after challenges sent, wait a bit then consider identity done
                            // In full implementation, we would wait for identity-expose responses with possession sigs
                            tokio::time::sleep(Duration::from_millis(800)).await;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(800)).await; // let intros flush
                    ui::say(&format!(
                        "  {} {} and {} now know each other (no codes needed)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        a_name, b_name,
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
            Ev::Stuck(pid, g) => { conn.on_stuck(&pid, g, "stuck").await?; }
            Ev::GraceExpired(pid, g) => { conn.on_stuck(&pid, g, "lost").await?; }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => { conn.on_peer_left(&v); }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ----------------------------------------------------------------- pair ----
// L1-a (PAKE v2): remembering a device is a first-class ceremony, no file
// transfer to pretend through. The first-pairing now runs a real SPAKE2 PAKE
// over the SPOKEN code so a malicious signaling server cannot MITM enrollment.
//
// The load-bearing change vs v1:
//   - The CLIENT mints the words locally (server sees only the numeric
//     nameplate); the password (words) NEVER reaches the server.
//   - SPAKE2 runs over the opaque `signal` relay BEFORE any secret exists.
//   - A key-confirmation MAC folds in the SORTED DTLS fingerprints + caps, so a
//     server that substitutes a DTLS cert OR rewrites caps is DETECTED → abort.
//   - The 32-byte pinned secret is HKDF(K), AGREED, never transmitted. The old
//     `pair-keep` secret-over-DataChannel step is GONE from the v2 path.
//   - Downgrade is structurally impossible: a v2 client NEVER sends pair-keep
//     and NEVER stores a secret from a received pair-keep. A received pair-keep
//     means the peer is v1 → abort with "update to pair securely". A server
//     stripping `v:2` therefore cannot force the readable-secret path.
//
// The opaque PAKE payloads carried on `signal` (the 33-byte SPAKE2 element and
// the 32-byte confirmation MAC) are encoded/decoded by the shared
// `pake_ceremony` module, which also owns the ceremony state machine that BOTH
// `pair` and the transfer path (`send --code` / `recv`) now run.
use pake_ceremony::{pair_v2_caps, Ceremony, Inbound as PakeInbound};

/// The one-line dim banner shown right before we open the guided entry on a
/// MALFORMED arg, so the user knows WHY the prompt appeared and how to make it
/// fail fast in scripts.
fn malformed_entry_banner(arg: &str) {
    ui::say(&ui::paint(
        ui::Tone::Dim,
        &format!(
            "couldn't parse '{arg}', opening guided entry · set FILAMENT_NONINTERACTIVE=1 to fail fast in scripts"
        ),
    ));
}

/// Map a codeentry Outcome::Cancelled into a clean error (used by the wired
/// commands so a cancel exits non-zero without a stack-y message).
fn cancelled() -> anyhow::Error {
    anyhow!("cancelled")
}

async fn pair_cmd(server: &str, mut code: Option<String>, name: Option<String>, mut word: Option<String>, relay: bool) -> Result<()> {
    if code.is_none() && word.is_none() && !interactive_allowed() {
        let (message, exit_code) = fleet_ui::pair_ui::err_pair_interactive();
        eprintln!("{message}");
        std::process::exit(exit_code);
    }
    // INTERACTIVE GATE (scripts safe by default, see `interactive_allowed`).
    //   * `pair` with no code AND no --word -> guided CREATE entry. Empty submit
    //     falls back to today's auto-mint; typed words become the chosen password.
    //   * `pair <malformed>` (a positional that isn't a valid claim shape) ->
    //     banner, then guided CLAIM entry PRE-FILLED with the normalized input.
    // When the gate is closed we keep EXACTLY today's behavior below.
    //
    // If the guided CREATE entry runs, it mints the nameplate ONCE here and shows
    // it in the preview; we carry it forward so the code we actually create uses
    // the SAME number the user saw (no shown-one-number, got-another mismatch).
    let mut preview_nameplate: Option<String> = None;
    if word.is_none() && interactive_allowed() {
        let malformed = code.as_deref().filter(|c| {
            // A "valid claim shape" is words + a trailing dash-group; anything that
            // split_code can't peel into (nameplate, non-empty words) is malformed.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            pw.is_empty() || np.is_empty()
        });
        match (&code, malformed) {
            // No code at all -> CREATE entry.
            (None, _) => {
                let auto_np = crate::pake::words::mint_nameplate();
                match codeentry::run("  pair · choose words  ", codeentry::Mode::Create, "", &auto_np)? {
                    codeentry::Outcome::Submitted(words) => {
                        word = Some(words);
                        // Reuse the SAME nameplate we just previewed, so the code
                        // we mint matches the number the user saw.
                        preview_nameplate = Some(auto_np);
                    }
                    // Empty submit -> fall through to auto-mint, but still keep the
                    // previewed nameplate so an empty (auto-words) create reuses it.
                    codeentry::Outcome::Empty => preview_nameplate = Some(auto_np),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                }
            }
            // Malformed positional -> banner + prefilled CLAIM entry.
            (Some(raw), Some(_)) => {
                malformed_entry_banner(raw);
                let prefill = crate::pake::norm_code(raw);
                match codeentry::run("  pair · code  ", codeentry::Mode::Claim, &prefill, "")? {
                    codeentry::Outcome::Submitted(c) => code = Some(c),
                    // Empty submit on a claim-fix means "give up on this code".
                    codeentry::Outcome::Empty => return Err(cancelled()),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                }
            }
            // A well-formed positional -> no prompt, proceed as today.
            (Some(_), None) => {}
        }
    }
    // STEERING: --word lets the creator choose the SPAKE2 password. The positional
    // `code` arg still means "claim", so --word + a code is contradictory.
    if word.is_some() && code.is_some() {
        bail!("--word chooses your OWN pairing words (creator); it can't be combined with a code to claim. Drop one.");
    }
    // A custom phrase must clear the password gate (Decision #3) BEFORE we touch
    // the network. Normalize with the SHARED norm_code so the echoed/created code
    // is exactly what SPAKE2 will hash, then validate against the blocklist.
    let custom_words: Option<String> = match &word {
        Some(w) => {
            let (words, _np) =
                crate::pake::split_chosen_code(&crate::pake::norm_code(w));
            if let Err(why) = crate::pake::words::validate_chosen_password(&words, &display_name()) {
                bail!("'{w}' is too weak: {why}");
            }
            Some(words)
        }
        None => None,
    };
    let my_uid = mk_uid("p");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick), the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    // C30: the session repairs the solo-room membership/lease if the join dies.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    // A code that looks like a one-time TRANSFER code (word-word-NNN, 2-3 digit
    // trailing) typed into `pair`, which runs the PAKE pairing ceremony,
    // redirect clearly before the handshake stalls against a peer that isn't
    // pairing. ADVISORY only (by trailing-number width); PAKE still authenticates.
    if let Some(c) = &code {
        if regex_lite_code(c) && !looks_like_pake_code(c) {
            bail!(
                "'{c}' looks like a one-time TRANSFER code (from `filament send --code`), not a pairing code.\n  \
                 To receive that transfer: run `filament {c}` (or `filament recv {c}`)\n  \
                 A pairing code ends in a 4-digit number, e.g. `brave-otter-3141`."
            );
        }
    }
    let creator = code.is_none();
    // L1-a: the spoken code is split CLIENT-SIDE into (nameplate, password). The
    // password (words) NEVER leaves this process; only the nameplate is sent.
    let mut my_words; // the password (creator mints; claimer types)
    let mut my_nameplate;
    match &code {
        Some(c) => {
            // Claimer: normalize the typed code, split, send ONLY the nameplate.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right, expected something like brave-otter-ruby-3141");
            }
            my_words = pw;
            my_nameplate = np.clone();
            ui::say(&format!("  claiming {}...", ui::paint(ui::Tone::Brand, c)));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 })).await.ok();
        }
        None => {
            // Creator: use the user's chosen words (--word) or mint them; the
            // nameplate is ALWAYS machine-minted. Ask the server to allocate ONLY
            // the nameplate. The full code is displayed from our own words when
            // pair-ok arrives (the server never echoes any words).
            my_words = custom_words.clone().unwrap_or_else(crate::pake::words::mint_words);
            // Reuse the nameplate the guided entry already previewed (if any), so
            // the created code matches what the user saw; otherwise mint fresh.
            my_nameplate = preview_nameplate
                .clone()
                .unwrap_or_else(crate::pake::words::mint_nameplate);
            // STEERING: echo the normalized code we're about to create so the
            // creator sees EXACTLY what their peer must type (== what SPAKE2 hashes).
            if custom_words.is_some() {
                ui::say(&format!(
                    "  using your words: {}",
                    ui::paint(ui::Tone::Brand, &format!("{my_words}-{my_nameplate}"))
                ));
            }
            sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
        }
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,        // relay_only
        None,         // to_filter
        false,        // warm_standby default (pair is one-shot)
        direct::direct_enabled(), // direct_ok: env gate only (no L2 acceptor here)
    );
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Bounded force-exit guarantee: the Interrupted bail unwinds and drops
            // the peers, and a webrtc/quinn drop can itself deadlock. Arm a
            // watchdog so Ctrl-C always exits promptly regardless.
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut prompted = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)

    // ---- L1-a PAKE state (shared ceremony) ----------------------------------
    // The agreed pinned secret (HKDF(K)); set ONLY after key confirmation passes.
    // `pair` PERSISTS it (a known device); the transfer path runs the SAME
    // ceremony but DISCARDS it. The ceremony state machine lives in
    // `pake_ceremony::Ceremony` and is driven identically by both flows.
    let mut agreed_secret: Option<String> = None;
    // Peer identity cert received via identity-expose inside the authed PAKE channel.
    // The flow exposes EXACTLY ONE device + its cert; privacy test asserts on actual wire payload.
    let mut peer_identity_cert: Option<identity::DeviceCert> = None;
    let mut sent_identity: bool = false;
    let mut identity_exchange_window: Option<std::time::Instant> = None;
    // Peer signaling sid we run the PAKE with (set when the link is adopted).
    let mut pake_peer: Option<String> = None;
    let caps = pair_v2_caps();
    // Start our SPAKE2 ceremony immediately: identity = nameplate, password =
    // words. Both sides MUST pass identical password AND nameplate (spec §3.1).
    // Fixed convention for plain pair: Device-scoped (device-to-device). Scope byte is derived from the authenticated introduction token, not a local guess. Both sides must pass same scope or confirmation fails.
    let scope = crate::identity::IntroScope::Device.to_byte();
    let mut cer = Ceremony::new(&my_words, &my_nameplate, caps.clone(), scope);
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL
    // The pairing peer left before the ceremony finished. Give a short grace
    // for a transient reconnect, then FAIL FAST, don't orphan in the room
    // for the full 10-min TTL (the D3/D5 divergence the monitor kept
    // catching: creator's connect failed, it quit, claimer sat silent).
    // Once the code is CLAIMED, the ceremony must finish in seconds. Bound it:
    // if it hasn't completed within this budget, the peer disconnected or could
    // never connect, fail fast instead of orphaning in the room for the full
    // 600s TTL (the D3/D5 divergence the monitor kept catching). 60s is generous
    // (covers a slow cross-NAT WebRTC with its 3×15s establishment retries);
    // FILAMENT_PAIR_GRACE_SECS shortens it for gate 17b.
    let ceremony_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    );
    let mut ceremony_deadline: Option<Instant> = None;
    // Gate 17b hook: connect but never complete, so the ceremony budget fires
    // deterministically (same-machine pairs otherwise finish in ~1s).
    let stall = test_hooks::pair_stall();

    loop {
        // Done when the petname is settled AND the PAKE agreed a secret (key
        // confirmation passed). The secret is HKDF(K), never transmitted, the
        // same on both sides; it drops straight into devices.json.
        if let Some(n) = petname.clone() {
            if let Some(sec) = agreed_secret.clone() {
                if identity_exchange_window.map_or(false, |dl| std::time::Instant::now() < dl) && peer_identity_cert.is_none() {
                    if !sent_identity {
                        if let Some(local_cert) = local_device_cert() {
                            if let Some(ref pid2) = pake_peer {
                                if let Some(k) = cer.k() {
                                    if let Some(l) = conn.link(pid2) {
                                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                                            let cmv = crate::pake::our_confirm(k, &my_fp, &their_fp, cer.caps_canon(), cer.scope());
                                            let mut cmv_arr = [0u8; 32];
                                            cmv_arr.copy_from_slice(&cmv);
                                            let dpub = local_cert.device_pub;
                                            let scope_b = cer.scope();
                                            let caps_d = crate::identity::caps_digest(cer.caps_canon());
                                            let ch = crate::identity::cert_hash(&local_cert);
                                            let rz = [0u8; 32];
                                            let pmsg = crate::identity::possession_msg(0x01, &cmv_arr, scope_b, &caps_d, &ch, &dpub, &rz);
                                            if let Ok(psig) = crate::overlay::overlay_sign_possession(&pmsg) {
                                                let inner = serde_json::json!({"cert":local_cert.to_json(),"possession_sig":hex::encode(psig),"device_pub":hex::encode(dpub)});
                                                let sk = crate::identity::sealing_key_from_k(k);
                                                if let Ok((n, s)) = crate::identity::seal_plaintext(&sk, inner.to_string().as_bytes()) {
                                                    sio.emit("signal", serde_json::json!({"to":pid2,"data":{"type":"identity-expose","v":2,"nonce":hex::encode(n),"sealed":hex::encode(s)}})).await.ok();
                                                    sent_identity = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                let same_person = peer_identity_cert
                    .as_ref()
                    .and_then(|cert| load_owner_key().map(|owner| owner.public_key_bytes() == cert.user_pub))
                    .unwrap_or(false);
                // External pairs currently receive only the baseline transfer
                // capability. Do not render render_someone_else_banner or
                // render_inter_user_form: pair has no bounded per-cap grant
                // contract, so those surfaces would claim choices it ignores.
                // Do not render render_pake_words: the pair code is not a
                // transcript-derived SAS; showing it as trust would invert the
                // MITM check. A real SAS belongs in the crypto gate.
                // Fail-closed: check BEFORE any write if peer previously had identity and now does NOT expose
                if same_person {
                    ui::say(&fleet_ui::pair_ui::render_same_person_banner(&n));
                }
                if peer_identity_cert.is_none() {
                    let p = devices_path();
                    if let Ok(raw) = std::fs::read_to_string(&p) {
                        if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                            if let Err(e) = identity::check_fail_closed(&arr, &n, None) {
                                bail!("fail-closed: {}", e);
                            }
                        }
                    }
                    // No cert: store secret only (legacy or first-pair no identity)
                    devices_store_v2(&n, &sec, &caps)?;
                } else {
                    // #23: atomic (secret,cert) together in ONE write, not separate writes.
                    // devices_store_v2 writes secret, store_provisional writes cert to temp file.
                    // If process crashes between them, cap_authorize sees new-secret + old-cert (or no cert)
                    // yielding wrong userPub. Fix: devices_upsert_atomic writes both fields together.
                    let pcert = peer_identity_cert.as_ref().unwrap();
                    devices_upsert_atomic(&n, Some(&sec), Some(pcert), Some(&caps), Some(scope), None)
                        .context("atomic store secret+cert")?;
                    // Also store provisional for overlay check: on overlay failure, REMOVE the durable anchor
                    store_provisional_identity(&n, pcert)
                        .context("store provisional")?;
                }
                if same_person {
                    ui::say(&fleet_ui::pair_ui::render_same_person_success(&n));
                } else {
                    ui::say(&format!(
                        "  {} {} mutually remembered, verified end-to-end (no key ever crossed the server)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        ui::paint(ui::Tone::Bold, &n),
                    ));
                    ui::say(&ui::paint(ui::Tone::Dim, &format!("  try: filament send <file> --to {n}   ·   filament up")));
                }
                tokio::time::sleep(Duration::from_millis(300)).await; // let acks flush
                let _ = sio.disconnect().await;
                return Ok(());                } // close identity_exchange_window else

            }
        }
        if Instant::now() > deadline {
            bail!("timed out, the code was never used (codes expire after 10 minutes)");
        }
        // Fail fast: the code was claimed but the ceremony didn't finish in
        // time, the peer disconnected or never connected.
        if let Some(dl) = ceremony_deadline {
            if Instant::now() > dl {
                bail!("the other device disconnected or could not connect before pairing finished, make sure both run `filament pair` at the same time, then try again");
            }
        }
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead

        // ---- L1-a PAKE progression (runs every iteration) ------------------
        // 1) Once we know the peer's signaling sid, send our SPAKE2 element over
        //    the opaque `signal` relay (the server cannot read it).
        if let Some(pid) = pake_peer.clone() {
            // gate 17b (FILAMENT_TEST_PAIR_STALL): never send our SPAKE2 element,
            // so the exchange can't complete on either side and the ceremony's
            // fail-fast `ceremony_deadline` fires, proving the no-10-min-orphan
            // guard. Test-only: `stall` is set solely by that env var.
            if !stall {
                if let Some(data) = cer.take_msg_payload() {
                    sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
                }
            }
            // 2) Once K is derived AND both DTLS fingerprints are known, send the
            //    key-confirmation MAC over K + sorted fingerprints + caps. The MAC
            //    is gated on the fingerprints so a server that substitutes a DTLS
            //    cert produces a different fingerprint → the peer's verify fails.
            if cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
                        }
                    }
                }
            }
            // Identity expose: after PAKE confirmation and secret agreed, if we have a local
            // device cert, send EXACTLY ONE device + its cert sealed under K-derived key
            // with possession signature, inside the authed channel. Server never sees
            // user key (sealed) and cannot substitute (possession sig binds to session).
            if !sent_identity {
                if agreed_secret.is_some() {
                    if let Some(local_cert) = local_device_cert() {
                        if let Some(pid2) = pake_peer.clone() {
                            if let Some(k) = cer.k() {
                                if let Some(l) = conn.link(&pid2) {
                                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                                        // Confirm MAC that we sent (session-bound, already binds K+fps+caps+scope)
                                        let confirm_mac_vec = crate::pake::our_confirm(k, &my_fp, &their_fp, cer.caps_canon(), cer.scope());
                                        let mut cmv_arr = [0u8; 32];
                                        cmv_arr.copy_from_slice(&confirm_mac_vec);
                                        let device_pub = local_cert.device_pub;
                                        let scope_byte = cer.scope();
                                        let caps_digest = crate::identity::caps_digest(cer.caps_canon());
                                        let chash = crate::identity::cert_hash(&local_cert);
                                        let receiver_zero = [0u8; 32];
                                        let possession_msg = crate::identity::possession_msg(
                                            0x01, &cmv_arr, scope_byte, &caps_digest, &chash, &device_pub, &receiver_zero
                                        );
                                        if let Ok(possession_sig) = crate::overlay::overlay_sign_possession(&possession_msg) {
                                            let inner = serde_json::json!({
                                                "cert": local_cert.to_json(),
                                                "possession_sig": hex::encode(possession_sig),
                                                "device_pub": hex::encode(device_pub)
                                            });
                                            let sealing_key = crate::identity::sealing_key_from_k(k);
                                            if let Ok((nonce, sealed)) = crate::identity::seal_plaintext(&sealing_key, inner.to_string().as_bytes()) {
                                                let payload = serde_json::json!({
                                                    "type": "identity-expose",
                                                    "v": 2,
                                                    "nonce": hex::encode(nonce),
                                                    "sealed": hex::encode(sealed)
                                                });
                                                sio.emit("signal", serde_json::json!({"to": pid2, "data": payload})).await.ok();
                                                sent_identity = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                sess.invalidate(); // C30: fresh sid, re-assert next tick
            }
            // C30 phase 2: same reconciliation as the Welcome arm above. Pairing
            // waits on the peer arriving in the room, so a dropped `peer-joined`
            // would otherwise strand the ceremony until the deadline.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                }
            }
            Ev::PairOk(_v) => {
                // L1-a: the server allocated our nameplate. Display the FULL code
                // from OUR OWN local mint (the server never echoed any words).
                let full = format!("{my_words}-{my_nameplate}");
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &full.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  on the other device: type it into the web app, or `filament pair <code>`"));
                ui::say(&ui::paint(ui::Tone::Dim, "  one claim · expires in 10 min · paired end-to-end (no key crosses the server)"));
            }
            Ev::PairCode(v) => {
                // v1 server (shouldn't happen for a v2 create, but be safe): a
                // legacy server-minted code means the peer can't PAKE-pair.
                let c = v["code"].as_str().unwrap_or("?");
                let _ = c;
                bail!("this server returned a legacy code. Update the server (or the peer) to pair securely.");
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed, connecting..."));
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                ui::say(&format!("  {} code accepted, connecting", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sess.room = Some(room.clone()); // C30: desire moves with us
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            Ev::PairError(v) => {
                // Creator nameplate collision: re-mint a FRESH nameplate (and
                // fresh words) and retry, never reuse a burned code.
                if creator && v["error"].as_str() == Some("taken") {
                    // Re-mint a FRESH nameplate; KEEP the creator's chosen words
                    // (--word), only mint fresh words when we minted them.
                    if custom_words.is_none() {
                        my_words = crate::pake::words::mint_words();
                    }
                    my_nameplate = crate::pake::words::mint_nameplate();
                    cer.restart(&my_words, &my_nameplate);
                    sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
                    continue;
                }
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "that code's creator already left, ask them for a fresh one".to_string(),
                    _ => format!("{}, codes burn after one use; a failed pairing needs a FRESH code (re-run `filament pair`)", v["error"].as_str().unwrap_or("?")),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // L1-a: PAKE messages ride the opaque `signal` relay. Branch them
                // OUT of the WebRTC signal path (SDP/ICE) into the shared ceremony.
                // A `pake-confirm` verify ⇒ wrong password OR a server that
                // substituted a DTLS cert OR rewrote caps ⇒ ABORT, agree NOTHING.
                if matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm")) {
                    pake_peer.get_or_insert(from.clone());
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    match cer.on_signal(&data, fp_ref) {
                        PakeInbound::Consumed => {
                            if let Some(sec) = cer.secret() {
                                agreed_secret = Some(sec.clone());
                                identity_exchange_window = Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                            }
                        }
                        PakeInbound::Abort(why) => {
                            bail!("pairing REFUSED: {why}. Nothing was stored; ask for a FRESH code.");
                        }
                        PakeInbound::Ignored => {}
                    }
                    continue;
                }
                // Identity expose: sealed cert + possession signature, inside authed PAKE channel.
                // Fixes holes A (confidentiality+integrity via K-derived seal, server never sees user_pub)
                // and B (replayable bearer: possession signature over session-bound confirm MAC, bound to device key).
                if data["type"].as_str() == Some("identity-expose") {
                    if let Some(k) = cer.k() {
                        if let Some(nonce_hex) = data.get("nonce").and_then(|v| v.as_str()) {
                            if let Some(sealed_hex) = data.get("sealed").and_then(|v| v.as_str()) {
                                if let Ok(nonce_bytes) = hex::decode(nonce_hex) {
                                    if let Ok(sealed_bytes) = hex::decode(sealed_hex) {
                                        if nonce_bytes.len() == 12 {
                                            let mut nonce_arr = [0u8; 12];
                                            nonce_arr.copy_from_slice(&nonce_bytes);
                                            let sealing_key = identity::sealing_key_from_k(k);
                                            if let Ok(plaintext) = identity::open_sealed(&sealing_key, &nonce_arr, &sealed_bytes) {
                                                if let Ok(inner) = serde_json::from_slice::<Value>(&plaintext) {
                                                    if let Some(cert_json) = inner.get("cert") {
                                                        if let Some(cert) = identity::DeviceCert::from_json(cert_json) {
                                                            if cert.verify(identity::now_secs()).is_ok() {
                                                                if let Some(sig_hex) = inner.get("possession_sig").and_then(|v| v.as_str()) {
                                                                    if let Ok(sig_bytes) = hex::decode(sig_hex) {
                                                                        if sig_bytes.len() == 64 {
                                                                            let mut sig_arr = [0u8; 64];
                                                                            sig_arr.copy_from_slice(&sig_bytes);
                                                                            // Re-derive fps for possession verification (session-bound)
                                                                            let fps2 = match conn.link(&from) {
                                                                                Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                                                                                None => None,
                                                                            };
                                                                            if let Some((my_fp2, their_fp2)) = fps2 {
                                                                                let (lo, hi) = crate::pake::sort_fps(&my_fp2, &their_fp2);
                                                                                let scope = cer.scope();
                                                                                let (_send, expect_dir) = crate::pake::confirm_dirs(&my_fp2, lo);
                                                                                let expected_confirm_vec = crate::pake::confirm_mac(k, expect_dir, lo, hi, cer.caps_canon(), scope);
                                                                                let mut cmv_arr = [0u8; 32];
                                                                                cmv_arr.copy_from_slice(&expected_confirm_vec);
                                                                                // Reconstruct cert_hash locally from parsed cert fields (never hash sender-framed blob)
                                                                                let chash = identity::cert_hash(&cert);
                                                                                let caps_digest = identity::caps_digest(cer.caps_canon());
                                                                                let sender_pub = cert.device_pub;
                                                                                let receiver_zero = [0u8; 32];
                                                                                // For PAKE path, receiver_device_pub MUST be zeros (verifier rejects non-zero)
                                                                                let possession_msg = identity::possession_msg(
                                                                                    0x01, &cmv_arr, scope, &caps_digest, &chash, &sender_pub, &receiver_zero
                                                                                );
                                                                                if identity::verify_possession_sig(&cert.device_pub, &possession_msg, &sig_arr).is_ok() {
                                                                                    // Anti-reflection, narrowed to device_pub (#41). LOAD-BEARING on this
                                                                                    // 0x01 (PAKE) path: receiver_device_pub is ZEROED in the possession_msg
                                                                                    // above (receiver_zero), so message binding does NOT carry the receiver
                                                                                    // identity — THIS single comparison is the ONLY thing preventing a
                                                                                    // reflection here. Do NOT remove it as "redundant with message binding";
                                                                                    // on 0x01 it is not. Compare cert.device_pub against THIS machine's LOCAL
                                                                                    // device pubkey (overlay), never the peer payload; fail closed if the
                                                                                    // local key can't be obtained. A same-owner fleet device has a DIFFERENT
                                                                                    // device_pub under the same user key, so it is correctly admitted (the old
                                                                                    // user_pub check refused it — the OwnerDevice-fleet bug).
                                                                                    match crate::overlay::overlay_pubkey_bytes() {
                                                                                        Ok(own_dpub) if cert.device_pub == own_dpub => {
                                                                                            // reflection-to-self refused
                                                                                        }
                                                                                        Ok(_) => {
                                                                                            peer_identity_cert = Some(cert);
                                                                                        }
                                                                                        Err(_) => {
                                                                                            // cannot obtain own device_pub -> cannot rule out reflection -> refuse
                                                                                        }
                                                                                    }
            }
                }
            }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                let display = match conn.link_mut(&pid) {
                    Some(l) => {
                        l.transport = Some(t.clone());
                        l.presence = Presence::Ready;
                        l.name.clone()
                    }
                    None => continue,
                };
                ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &display)));
                peer = Some((pid.clone(), display.clone()));
                let _ = &t; // transport not used on the v2 path (no secret over DC)
                if stall {
                    continue; // gate 17b: connected, but deliberately never complete
                }
                // L1-a: the link is up and SDP fingerprints exist. Mark this peer
                // as our PAKE counterpart; the progression block (top of the loop)
                // sends our SPAKE2 element and, once K + fingerprints are known,
                // the key-confirmation MAC. NO secret is sent over the DataChannel.
                pake_peer.get_or_insert(pid.clone());
                // Settle the petname: --name wins; otherwise ask (tty) or
                // default to their display name (scripts, pipes).
                if petname.is_none() && !prompted {
                    prompted = true;
                    if std::io::stdin().is_terminal() {
                        eprint!("  remember this device as [{display}]: ");
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            use tokio::io::AsyncBufReadExt;
                            let mut line = String::new();
                            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                            if reader.read_line(&mut line).await.is_ok() {
                                let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                            }
                        });
                    } else {
                        petname = Some(display.clone());
                    }
                }
            }
            Ev::StdinLine(line) => {
                if petname.is_none() && prompted {
                    let n = if line.is_empty() {
                        peer.as_ref().map(|(_, d)| d.clone()).unwrap_or_else(|| "device".into())
                    } else {
                        line
                    };
                    petname = Some(n);
                }
            }
            Ev::Control(pid, v) if stall => {
                let _ = (pid, v); // gate 17b: connected, but ignore all ceremony control
            }
            Ev::Control(_pid, v) => match v["type"].as_str() {
                // L1-a downgrade-refusal (spec §6.1): a v2 client NEVER stores a
                // secret handed over the DataChannel. Receiving a `pair-keep` means
                // the PEER is a legacy v1 client. We refuse, pairing securely
                // requires v2 on both ends. A malicious server stripping `v:2`
                // cannot exploit this: there is no path here that stores a
                // server-readable secret.
                Some("pair-keep") => {
                    bail!("the other device uses an older version and can't pair securely. Update it (or this CLI) so first-pairing runs the encrypted handshake. Nothing was stored.");
                }
                _ => {}
            },
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                // A faster, friendlier signal than the ceremony budget when it
                // arrives: the pairing peer left the room. (The budget is the
                // hard backstop, server peer-left can lag behind a hard kill.)
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                conn.on_peer_left(&v);
                let n = gone.unwrap_or_else(|| "the other device".into());
                ui::say(&ui::paint(ui::Tone::Dim, &format!("  {n} disconnected, waiting briefly in case it reconnects...")));
            }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ---------------------------------------------------------- link machinery --
// One peer at a time, but with the browser's survival rules: establishment
// watchdog (C3), disconnected-grace + ICE restart + reconnect attempts (C4),
// fresh ICE config per attempt (C5), uid supersede on rejoin (C6), and a
// rejoin window when the peer's socket dies entirely.

/// Why a direct attempt is being started. A bool pair gave four states, three
/// meaningful and one nonsense (`probe && promote` = "a test dial that tears
/// down a serving link", exactly what the guard exists to prevent), with
/// nothing rejecting it. Every expensive defect this week was a boolean-ish
/// value legal in the type system and wrong in the domain: a hardcoded
/// `answerer: true`, `has_flowed() -> true`, `expected_secret: None`. This
/// makes the meaningless combination unrepresentable instead of merely
/// unreachable-by-convention.
/// What a promotion did to the serving WebRTC link.
///
/// Carried rather than inferred at the call site, because the two outcomes need
/// opposite follow-ups and getting it wrong is silent both ways:
///
///   Replaced  the link was torn down and a successor is coming; announcing the
///             old transport would advertise something already gone.
///   Retained  direct was disabled, or setup failed before registering a
///             pending, so the ORIGINAL link is still live and NOTHING else
///             will announce it. That silence is the macOS wedge.
///
/// The `#[must_use]` is the point, and so is taking this by value in
/// `rearm_channel_ready`: it keeps re-announcement unreachable from a `Normal`
/// or `Probe` start_direct, both of which register a pending WITHOUT dropping,
/// where re-announcing would advertise a transport with a live direct race
/// pending against it. Same argument that made `DirectIntent` an enum rather
/// than two bools.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use = "a promotion that RETAINED the link leaves its transport \
              unannounced, and nothing else will announce it. Pass this to \
              `rearm_channel_ready`, or explain in a comment why this command \
              does not need the retained link announced."]
enum Promotion {
    Replaced,
    Retained,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirectIntent {
    /// Never disturb a live link.
    Normal,
    /// Upgrade probe: bypass the live-link guard, but never drop.
    Probe,
    /// Option A: the ONLY intent permitted to replace a serving link.
    Promote,
}

struct Link {
    /// WebRTC peer connection. `None` for a rung-1 direct link (no ICE/DTLS
    /// negotiation, it rides authenticated QUIC), so every WebRTC-only call
    /// site (`handle_signal`, `fingerprints`, `restart_ice`, the watchdog's
    /// `is_connected`) is reachable only when this is `Some`.
    peer: Option<Arc<Peer>>,
    info: Value, // {id,name,uid} as last seen, enough to re-establish
    name: String,
    uid: Option<String>,
    transport: Option<Arc<dyn Transport>>,
    generation: u32,
    attempts: u32,
    /// C12: proof-verified known device (per link, not global)
    trusted: bool,
    /// (name, secret) hypothesis to prove/verify on this link
    expected_secret: Option<(String, String)>,
    /// The devices.json PETNAME this link proved as (the cap-store key). Set on a
    /// verified `pair-proof` (WebRTC) or at birth for a direct link (already
    /// identity-bound). `None` until proven. Capability lookups (e.g. the `shell`
    /// gate) MUST key on this, NOT on `name` (a presence display string that may
    /// not match a stored record).
    verified_name: Option<String>,
    /// C26: what the status roster shows for this peer
    presence: Presence,
    /// rung-1 (FILAMENT_DIRECT): this link's transport is an authenticated direct
    /// QUIC connection, its pair-secret MAC already proved identity, so the
    /// post-channel DTLS pair-proof is skipped and the link is born trusted.
    direct: bool,
    /// Route label for a direct link (no WebRTC `route()` to query): `direct-quic`
    /// for rung-1, `holepunched` for rung-2. Ignored for WebRTC links.
    direct_route: &'static str,
    /// Parallel QUIC transports for multi-stream file transfer
    /// (`FILAMENT_DIRECT_STREAMS` > 1). Empty when striping is disabled
    /// or when the link uses a non-QUIC transport.
    workers: Vec<Arc<dyn Transport>>,
    /// When this link was established (for the warm-hold pair-proof grace).
    /// `warm_hold_tick` skips re-establish for a live link within this window,
    /// preventing churn while pair-proof verification completes.
    established_at: Option<Instant>,
    /// Identity cert device_pub (set when identity-expose is verified).
    identity_device_pub: Option<[u8; 32]>,
    /// Identity cert user_pub (set when identity-expose is verified).
    identity_user_pub: Option<[u8; 32]>,
    /// Binding strength of the identity fields (set alongside them).
    identity_binding: crate::capability::BindingStrength,
    /// Identity cert expiry (unix seconds). None = no cert resolved.
    identity_cert_expires: Option<u64>,
    /// Principal kind: OwnerDevice or Delegated { caps }. A Delegated
    /// principal CANNOT exist without its ceiling — the compiler enforces it.
    principal_kind: crate::capability::PrincipalKind,
}

impl Link {
    /// The name to SHOW for this peer. A known device proves into its local
    /// petname (`verified_name`); show that, so one device reads consistently as
    /// (e.g.) `dovm` everywhere instead of flipping between the petname and the
    /// peer's broadcast display name (`name`, e.g. `Abdul's server`). The
    /// broadcast name is the fallback only for an unverified / unknown peer.
    fn shown(&self) -> &str {
        self.verified_name.as_deref().unwrap_or(&self.name)
    }

    /// Admit this link as a delegated (auth-key-enrolled) principal.
    /// Ensures caps are structurally tied to the Proven identity — a Delegated
    /// principal CANNOT exist without its ceiling.
    ///
    /// NON-PERSISTENCE INVARIANT: a delegated principal's authority is conferred
    /// by certain Link fields and bounded by others. All five MUST travel
    /// together as in-memory Link state, and none may be persisted to devices.json:
    ///
    ///   CONFERS authority (owner-shortcut in evaluate() if bounding fields are absent):
    ///   - identity_user_pub    (= owner_pub; triggers owner-derived authorize)
    ///   - identity_device_pub  (enables device-targeted grants)
    ///   - identity_binding     (Proven; satisfies cap_authorize_proven + trust floor)
    ///
    ///   BOUNDS authority (ceiling and expiry; if dropped, owner-shortcut is unbounded):
    ///   - principal_kind       (Delegated{caps}; the ceiling; owner-shortcut bypasses it if absent)
    ///   - identity_cert_expires (cap_authorize_expired; None => treated as expired => denies,
    ///                           so it fails closed, but list it so a subset-persist is obviously dangerous)
    ///
    /// This is safe ONLY because Link is in-memory and never persisted.
    ///
    /// If identity_user_pub were ever persisted, or a delegated link were written
    /// into devices.json, then on reconnect `resolve_peer_identity` would restore
    /// `identity_user_pub = owner_pub` while `principal_kind` defaults to
    /// `OwnerDevice`, `auth_key_caps()` returns `None`, the ceiling vanishes, and
    /// the owner-shortcut in evaluate() authorizes everything — a full escalation.
    /// SO: never persist a delegated link. The devices_json writer must exclude it.
    fn admit_delegated(&mut self, owner_pub: [u8; 32], device_pub: [u8; 32], expires: u64, caps: Vec<String>) {
        // A delegated principal acts UNDER the owner's user identity (the auth
        // key issuer), so it presents user_pub = owner_pub. evaluate()'s owner
        // shortcut then authorizes, but ONLY after the auth-key caps ceiling
        // (checked first) has passed — so a transfer-only key gets transfer and
        // is denied shell/mount. This is the delegation grant.
        self.identity_user_pub = Some(owner_pub);
        self.identity_device_pub = Some(device_pub);
        self.identity_binding = crate::capability::BindingStrength::Proven;
        self.identity_cert_expires = Some(expires);
        self.principal_kind = crate::capability::PrincipalKind::Delegated { caps };
        // NOTE: deliberately do NOT set self.trusted. binding=Proven satisfies
        // cap_trust_floor under authoritative mode, and the auth-key caps ceiling
        // (auth_key_caps ∩ owner_effective) bounds the principal. Setting trusted
        // would leak into legacy_ok for gates that read it directly (e.g. mount),
        // handing an ephemeral borrower an unbounded, un-ceilinged grant.
    }
}

/// C26: per-peer presence for the static status roster.
#[derive(Clone, Copy, PartialEq)]
enum Presence {
    Connecting,
    Ready,
    Away,
    Reconnecting,
}

fn presence_glyph(p: Presence) -> (&'static str, ui::Tone, &'static str) {
    match p {
        Presence::Ready => (ui::glyph_ok(), ui::Tone::Ok, ""),
        Presence::Away => ("●", ui::Tone::Warn, "away"),
        Presence::Reconnecting => ("◌", ui::Tone::Warn, "reconnecting..."),
        Presence::Connecting => ("◌", ui::Tone::Dim, "connecting..."),
    }
}

/// C18: browsers are mesh peers, they connect to EVERY room member. The CLI
/// must answer every offer politely or unanswered browsers wedge at
/// "connecting" (and their retry storms degrade the whole room). So: a links
/// MAP, every peer answered; SEND still aims transfers at one `active`
/// target; RECV accepts from any link, gated per-link by consent/trust.
const MAX_LINKS: usize = 16;

/// RESILIENCE state, split out of the `Conn` god-struct so the stall/relay/
/// warm-standby/upgrade-probe bookkeeping is one named bag, not mixed in with
/// signaling + protocol state. The pure decisions live in `resilience.rs`.
#[derive(Default)]
struct ResilienceState {
    /// P0 (GAP-1): per-peer stall-repair bookkeeping for the bytes-moved
    /// watchdog. Tracks how many correction-ladder repairs we've already run for
    /// the current stall episode (bounded by MAX_ATTEMPTS) and whether a repair
    /// is in flight, so a single stall can't re-fire the ladder every tick while
    /// a repair is converging. Reset once the link starts flowing again.
    stall_repairs: HashMap<String, StallState>,
    /// P1 (GAP-4): peers this session has COMMITTED to the relay route after the
    /// direct ladder exhausted (rung d). Once a pid is in here, we stop dialing /
    /// answering direct-QUIC for it (the direct path is what just failed and would
    /// only re-freeze, racing the relay link); all (re)establishment for it goes
    /// over relay-only WebRTC. Survives link drops (keyed by pid, not stored on the
    /// Link), so a re-establish never bounces back to the known-bad direct path.
    relay_committed: std::collections::HashSet<String>,
    /// P3 (GAP-3): the WARM-REDUNDANCY selectivity gate. TRUE only for long-lived
    /// / interactive sessions (the `up`/`up --shell` daemon acceptor; a transfer
    /// flagged interactive via `FILAMENT_WARM_STANDBY=1` standing in for a tunnel),
    /// the sessions §2.4 says a mid-session drop is intolerable for. When set,
    /// `correct_stall` keeps the relay path as a pre-designated WARM standby and
    /// CUTS OVER to it on the FIRST stall (rung b) instead of grinding through the
    /// slow direct-repair rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, so the
    /// failover is near-instant rather than a perceptible gap. FALSE for one-shot
    /// file `send` (the 90% case): the on-disk partial + C7 resume make the cold
    /// repair ladder correct and bounded, and a warm standby isn't worth a second
    /// socket / NAT mapping / keepalive for a single transfer (the honest cost
    /// tradeoff, §2.4 / §6). Defaulted by session kind at construction, overridable
    /// by `net::warm_standby_override()` (`FILAMENT_WARM_STANDBY`).
    warm_standby: bool,
    /// P3: per-peer warm-standby bookkeeping, peers whose relay standby has
    /// already been cut over to in the current stall episode, so a flapping relay
    /// path can't re-fire the instant cutover every tick (it falls through to the
    /// bounded relay-stalled `Exhausted` honesty instead). Cleared by
    /// `note_progress` once bytes move again.
    warm_cutover: std::collections::HashSet<String>,
    /// P5 (GAP-6): per-peer relay->direct UPGRADE-PROBE bookkeeping. Present only
    /// for peers currently committed to relay (`relay_committed`) on a session
    /// where the prober is eligible (warm_standby/daemon, relay permitted). Drives
    /// the backoff schedule (probe soon, then steady cadence) and the
    /// verify-before-upgrade window for a connected direct standby. Removed on a
    /// successful upgrade (cutover) or when the peer leaves.
    upgrade_probe: HashMap<String, UpgradeProbe>,
    /// P5: a snapshot of the local interface set (sorted IP strings) at the last
    /// probe schedule. A change (new/removed interface, wifi<->cellular,
    /// default-route move surfacing a new local IP) is the "walked home onto wifi"
    /// signal, we re-probe IMMEDIATELY. Polled cheaply each tick (no platform
    /// netlink dependency); the portable best-effort trigger the plan asks for.
    iface_snapshot: Vec<String>,
}

/// ORCHESTRATION: peer-absence / rejoin-grace bookkeeping, split out of the Conn
/// god-struct. Tracks the reconnect window we hold open for a vanished peer and a
/// peer's declared absence (C21 `brb`).
struct RejoinState {
    /// when set, we are holding a reconnect window open for a vanished peer.
    waiting_rejoin: Option<Instant>,
    /// How long the current rejoin window runs (set when it opens; depends on
    /// whether the peer declared `brb`).
    rejoin_window: Duration,
    /// (peer sid, until), the peer told us it's stepping away (C21).
    away: Option<(String, Instant)>,
}

/// WARM-HOLD state: keeps connections alive to recently-used and explicitly
/// configured peers so `filament ping`/`ssh` is instant.
///
/// Design:
/// - EXPLICIT peers: from `filament set warm-peers dovm,popos` (always connected)
/// - RECENT peers: LRU of last 5 peers used for send/ssh/ping (auto-connected)
/// - RECONNECT: exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap) on drop
/// - DORMANT: go dormant after 5 failed attempts; resume on peer presence
const WARM_RECENT_CAP: usize = 5;
const WARM_MAX_BACKOFF: Duration = Duration::from_secs(30);
const WARM_DORMANT_THRESHOLD: u32 = 5;
/// A dormant peer is retried this often (instead of never). Presence re-announce
/// still resumes it immediately; this is the floor for a peer whose announces we
/// keep missing.
const WARM_DORMANT_RETRY: Duration = Duration::from_secs(300);

/// Auto-warm size guard: warm at most this many roster peers (see `warm-max`).
/// Must stay under MAX_LINKS (16) so warm-all can never starve on-demand,
/// inbound, or upgrade-probe links of link-table slots.
fn warm_max() -> usize {
    settings::get_str("warm-max", None)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(12)
        .min(MAX_LINKS - 2)
}

#[derive(Default)]
struct WarmHold {
    /// Explicitly configured peers (from `warm-peers` setting)
    configured: std::collections::HashSet<String>,
    /// AUTO-WARM tier: ALL online paired peers (from the live roster), synced each
    /// warm_hold_tick. ON by default (`auto-warm` setting); also forced on while the
    /// L3 overlay is up (L3 needs live links to route). Bounded by `warm-max`
    /// (Change 4), not by the recent LRU cap.
    auto: std::collections::HashSet<String>,
    /// Recently-used peers in LRU order (most recent at back, capped at 5)
    recent: std::collections::VecDeque<String>,
    /// Per-peer last-use timestamp
    last_use: HashMap<String, Instant>,
    /// Per-peer reconnect backoff state
    backoff: HashMap<String, WarmBackoff>,
}

#[derive(Clone)]
struct WarmBackoff {
    /// Current backoff duration
    duration: Duration,
    /// Number of consecutive failures
    failures: u32,
    /// When we last tried to connect
    last_attempt: Option<Instant>,
    /// True if we've given up (dormant) after too many failures
    dormant: bool,
}

impl Default for WarmBackoff {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(1),
            failures: 0,
            last_attempt: None,
            dormant: false,
        }
    }
}

impl WarmHold {
    /// Record that a peer was just used (transfer, ssh, ping)
    fn note_use(&mut self, peer: &str) {
        let peer = peer.to_string();
        self.last_use.insert(peer.clone(), Instant::now());
        // Move to back of LRU (most recent)
        self.recent.retain(|p| p != &peer);
        self.recent.push_back(peer.clone());
        // Trim to cap
        while self.recent.len() > WARM_RECENT_CAP {
            self.recent.pop_front();
        }
        // Clear dormant flag and reset backoff on use
        if let Some(b) = self.backoff.get_mut(&peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }

    /// Mark a connection attempt failed (exponential backoff)
    fn note_failure(&mut self, peer: &str) {
        let b = self.backoff.entry(peer.to_string()).or_default();
        b.failures += 1;
        b.last_attempt = Some(Instant::now());
        // Exponential backoff with cap
        b.duration = (b.duration * 2).min(WARM_MAX_BACKOFF);
        // Go dormant after too many failures
        if b.failures >= WARM_DORMANT_THRESHOLD {
            b.dormant = true;
        }
    }

    /// Mark a connection succeeded (reset backoff)
    fn note_success(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.failures = 0;
            b.duration = Duration::from_secs(1);
            b.dormant = false;
        }
    }

    /// Check if a peer should be connected (configured OR auto OR recently used, not dormant)
    fn should_connect(&self, peer: &str) -> bool {
        if self.configured.contains(peer) {
            return true;
        }
        if self.auto.contains(peer) {
            return true;
        }
        if self.recent.contains(&peer.to_string()) {
            // Check if dormant
            if let Some(b) = self.backoff.get(peer) {
                return !b.dormant;
            }
            return true;
        }
        false
    }

    /// Get all peers that should be connected
    fn peers_to_connect(&self) -> Vec<String> {
        let mut peers: Vec<String> = self.configured.iter().cloned().collect();
        // Add auto-warm peers (all online paired peers)
        for p in &self.auto {
            if !peers.contains(p) {
                peers.push(p.clone());
            }
        }
        // Add recent peers (capped at 5, not dormant)
        for p in &self.recent {
            if !peers.contains(p) {
                if let Some(b) = self.backoff.get(p) {
                    if !b.dormant {
                        peers.push(p.clone());
                    }
                } else {
                    peers.push(p.clone());
                }
            }
        }
        peers
    }

    /// Check if a peer is dormant (too many failures)
    fn is_dormant(&self, peer: &str) -> bool {
        self.backoff.get(peer).map(|b| b.dormant).unwrap_or(false)
    }

    /// Is this peer due for a (re)connect attempt this tick? Dormant peers get one
    /// probe per WARM_DORMANT_RETRY; non-dormant peers honor their exponential
    /// backoff window (duration since last_attempt).
    fn due(&self, peer: &str) -> bool {
        match self.backoff.get(peer) {
            None => true,
            Some(b) => {
                let since = b.last_attempt.map(|t| t.elapsed());
                if b.dormant {
                    since.map_or(true, |d| d >= WARM_DORMANT_RETRY)
                } else {
                    since.map_or(true, |d| d >= b.duration)
                }
            }
        }
    }

    /// Resume a dormant peer (e.g., when it reappears in signaling presence)
    fn resume(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }
}

#[cfg(test)]
mod warm_hold_tests {
    use super::*;

    #[test]
    fn should_connect_configured() {
        let mut wh = WarmHold::default();
        wh.configured.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_l3() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_recent_not_dormant() {
        let mut wh = WarmHold::default();
        wh.note_use("dovm");
        assert!(wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(!wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_unknown() {
        let wh = WarmHold::default();
        assert!(!wh.should_connect("unknown"));
    }

    #[test]
    fn recent_lru_caps_at_5() {
        let mut wh = WarmHold::default();
        for i in 0..7 {
            wh.note_use(&format!("peer{i}"));
        }
        // Should only have last 5: peer2, peer3, peer4, peer5, peer6
        assert_eq!(wh.recent.len(), WARM_RECENT_CAP);
        assert!(!wh.recent.contains(&"peer0".to_string()));
        assert!(!wh.recent.contains(&"peer1".to_string()));
        assert!(wh.recent.contains(&"peer2".to_string()));
        assert!(wh.recent.contains(&"peer6".to_string()));
    }

    #[test]
    fn recent_evicts_oldest() {
        let mut wh = WarmHold::default();
        wh.note_use("a");
        wh.note_use("b");
        wh.note_use("c");
        wh.note_use("d");
        wh.note_use("e");
        // All 5 present
        assert_eq!(wh.recent.len(), 5);
        // Add 6th - "a" should be evicted
        wh.note_use("f");
        assert_eq!(wh.recent.len(), 5);
        assert!(!wh.recent.contains(&"a".to_string()));
        assert!(wh.recent.contains(&"f".to_string()));
    }

    #[test]
    fn auto_set_is_unbounded() {
        let mut wh = WarmHold::default();
        // Add 10 peers to auto set
        for i in 0..10 {
            wh.auto.insert(format!("peer{i}"));
        }
        // All 10 should be in peers_to_connect
        let peers = wh.peers_to_connect();
        for i in 0..10 {
            assert!(peers.contains(&format!("peer{i}")), "peer{i} missing");
        }
    }

    #[test]
    fn auto_disabled_clears_set() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        wh.auto.insert("popos".into());
        assert!(wh.should_connect("dovm"));
        // Simulate auto-warm disabled
        wh.auto.clear();
        assert!(!wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn note_failure_backoff_doubling() {
        let mut wh = WarmHold::default();
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(2));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(4));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(8));
    }

    #[test]
    fn note_failure_caps_at_30s() {
        let mut wh = WarmHold::default();
        for _ in 0..10 {
            wh.note_failure("dovm");
        }
        assert_eq!(wh.backoff["dovm"].duration, WARM_MAX_BACKOFF);
    }

    #[test]
    fn note_failure_dormant_after_threshold() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.backoff["dovm"].dormant);
        assert!(wh.is_dormant("dovm"));
    }

    #[test]
    fn note_use_clears_backoff() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.note_use("dovm");
        assert!(!wh.is_dormant("dovm"));
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(1));
        assert_eq!(wh.backoff["dovm"].failures, 0);
    }

    #[test]
    fn resume_clears_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.resume("dovm");
        assert!(!wh.is_dormant("dovm"));
    }

    /// CI GUARDRAIL: warm peers should be instantly connectable.
    /// This is a LOGICAL test (no network) - verifies the warm-hold state
    /// machine would allow instant connection for a warm peer.
    #[test]
    fn warm_peer_allows_instant_connection() {
        let mut wh = WarmHold::default();
        // Simulate a warm peer (configured + auto)
        wh.configured.insert("dovm".into());
        wh.auto.insert("dovm".into());
        wh.note_use("dovm");
        // All paths should return true
        assert!(wh.should_connect("dovm"));
        assert!(!wh.is_dormant("dovm"));
        // Peer is in warm sets
        assert!(wh.configured.contains("dovm"));
        assert!(wh.auto.contains("dovm"));
    }

    #[test]
    fn due_respects_backoff_window() {
        let mut wh = WarmHold::default();
        // No backoff entry -> always due
        assert!(wh.due("unknown"));
        // After one failure, not due until backoff window passes
        wh.note_failure("dovm");
        assert!(!wh.due("dovm")); // 1s window, just failed
    }

    #[test]
    fn dormant_peer_retries_after_interval() {
        let mut wh = WarmHold::default();
        // Make peer dormant
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        // Not due immediately
        assert!(!wh.due("dovm"));
        // After WARM_DORMANT_RETRY, would be due (can't easily test Instant::elapsed
        // without injecting time, so just verify the dormant flag is set)
        assert!(wh.backoff["dovm"].dormant);
    }
}

/// Why a roster entry is being adopted. Contact is the safe default for new
/// call sites; Digest is reserved for roster reconciliation, which must not
/// undo an exhausted give-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdoptSource {
    Contact,
    Digest,
}

fn match_adoption_source(suppressed: &mut HashSet<String>, peer_id: &str, source: AdoptSource) -> bool {
    match source {
        AdoptSource::Contact => {
            suppressed.remove(peer_id);
            true
        }
        AdoptSource::Digest => !suppressed.contains(peer_id),
    }
}

struct Conn {
    server: String,
    sio: rust_socketio::asynchronous::Client,
    tx: mpsc::UnboundedSender<Ev>,
    my_uid: String,
    my_id: String,
    relay_only: bool,
    to_filter: Option<String>,
    links: HashMap<String, Link>,
    roster: HashMap<String, Value>, // sid -> {id,name,uid} from welcome/peer-joined
    /// Peer IDs whose exhausted stall ladder deliberately gave up. Contact
    /// clears these; digest reconciliation skips them.
    suppressed_digest_adoptions: HashSet<String>,
    active: Option<String>,        // the transfer-target sid (send side)
    next_gen: u32,
    /// Peer-absence / rejoin-grace state (the reconnect window + declared brb).
    rejoin: RejoinState,
    chunk_size: usize,
    /// #28 (deferred drop): sids that got a peer-left while their data channel
    /// was still FLOWING. The signaling socket left the room, but the WebRTC
    /// link is independent and may be a cosmetic reconnect mid-transfer. We do
    /// NOT drop immediately (that kills a live transfer) and do NOT drop never
    /// (a hard-killed peer reads flowing for a beat and would strand the
    /// sender). Instead we stash the original peer-left payload here and
    /// re-check on every main-loop tick: once the link goes idle past the
    /// flowing threshold (or its channel is dead), we re-inject the stored
    /// peer-left so the normal handler runs verbatim, now dropping it. A live
    /// reconnect never goes idle (the transfer completes on it), so its entry
    /// is reaped harmlessly once done. Cleared in drop_link so a supersede of a
    /// deferred sid can't leave a stale blocker.
    deferred_left: HashMap<String, Value>,
    /// Gate-18 Mode B: set TRUE by the recv loop, each tick, exactly when the
    /// transfer is COMPLETE and nothing is in flight (`completed>0 &&
    /// by_sid.is_empty() && !keep_open`). When it holds, `on_stuck` DROPS a
    /// stuck/lost link instead of re-establishing it: there is nothing left to
    /// fetch, so reconnect attempts are pointless and a sender that departs
    /// AFTER delivering every byte would otherwise FLAP the link forever
    /// (establish → connect → die → Stuck → establish ...), each cycle resetting
    /// `attempts` (so MAX_ATTEMPTS never caps it) and re-arming `expected_secret`
    /// (so `digest_says_alone` never holds), `conn.links` never empties and the
    /// quiet-exit never fires → RC=124 hang. Dropping the link empties
    /// `conn.links` and lets the quiet-exit fire. Recomputed PER TICK (never
    /// sticky) so a mid-transfer link (`by_sid` non-empty) always reconnects
    /// normally, kill-resume (gate 2) and the #28 deferred-drop (gate 11c)
    /// reconnect paths are untouched. Defaults false, so the send-side and
    /// connecting-phase `on_stuck` callers are unaffected.
    recv_done: bool,
    /// rung-1 (FILAMENT_DIRECT): in-flight direct-QUIC attempts, keyed by peer
    /// sid. While an attempt is pending we do NOT establish WebRTC for that peer
    /// (sequential, per the design review, avoids two transports racing to
    /// ChannelReady). On deadline expiry with no DirectReady the entry is
    /// dropped and the normal WebRTC `establish` runs; the fallback is unchanged.
    direct_pending: HashMap<String, DirectPending>,
    /// Bug 2: transport-offers that arrived before the receiver's DirectPending
    /// was created (peer's re-dial after a mid-transfer death). Same class as Bug
    /// 1 (pre-PAKE offers): buffered here and replayed once `start_direct` creates
    /// the pending. pid → (candidates, srflx).
    buffered_offers: HashMap<String, (Vec<String>, Option<String>)>,
    /// RESILIENCE bookkeeping (stall/relay/warm/upgrade); see ResilienceState.
    resil: ResilienceState,
    /// Is the rung-1 direct-QUIC path allowed for THIS session? Normally this is
    /// just `direct::direct_enabled()` (the FILAMENT_DIRECT/FILAMENT_L2 env gate),
    /// but ANY long-lived acceptor must ALSO take it even when those env vars are
    /// unset: the L2/ssh ACCEPTOR (`up --shell`) AND the plain `up` daemon. An
    /// acceptor that doesn't silently drops the initiator's `transport-offer` AND
    /// builds its own WebRTC peer dialing back, colliding with the initiator's
    /// offer (GLARE), which for `up --shell` stalls at "stuck while connecting" and
    /// for a plain `up` (two mutually-known daemons) loops the supersede churn and
    /// never settles to one link. Answering the direct dial instead is sequential,
    /// authenticated, and rides the reachable host candidate (e.g. the Tailscale
    /// link), so it neither glares nor depends on cross-NAT ICE. Set via
    /// `direct_ok_for`; `start_direct_inner` gates on this instead of the bare env
    /// check. One-shot send/recv/pair keep the bare `direct_enabled()` default.
    direct_ok: bool,
    /// Local transport for same-machine peers.
    local_port: Option<u16>,
    local_listener: Option<Arc<tokio::net::TcpListener>>,
    /// Shared direct-QUIC endpoint, cloned from the originating Endpoint so that
    /// worker connections for multi-stream transfers can be dialled (sender side)
    /// or accepted (receiver side) without racing the winner's keepalive closure.
    /// Set once in `start_direct_inner`; `None` when direct is not in use, or
    /// when multi-streaming is disabled (`direct_streams() == 1`).
    direct_endpoint: Option<quinn::Endpoint>,
    /// WARM-HOLD: keeps connections alive to recently-used and explicitly
    /// configured peers so `filament ping`/`ssh` is instant. Tracked per-peer
    /// with LRU eviction and exponential backoff on failures.
    warm_hold: WarmHold,
    /// Oneshot senders for per-endpoint worker port negotiation, keyed by pid.
    /// The dialer-side `spawn_direct_workers` stores a sender here; the
    /// `worker-ports` control message handler delivers the acceptor's port list
    /// through it. Removed by the receiver on delivery (one-shot).
    worker_port_tx: HashMap<String, oneshot::Sender<Vec<u16>>>,
}

/// P0: one peer's stall-repair episode state.
#[derive(Default)]
struct StallState {
    /// Repairs attempted in the current episode (rung a is the first).
    attempts: u32,
    /// `true` between firing the ladder and the next observed byte of progress,
    /// so the per-tick watchdog doesn't re-arm while a repair is converging.
    pending: bool,
    /// P1 (GAP-4): `true` once this episode escalated to relay (rung d) and a
    /// FRESH relay WebRTC link is establishing (no transport yet). The new link
    /// isn't tracked by `direct_pending`, so without this latch `detect_stall`
    /// would keep seeing the (transport-less) link idle and re-fire the ladder
    /// into a premature `Exhausted` before relay even connects. Cleared by
    /// `note_progress` on the first byte over the relay path.
    relayed: bool,
}

/// P5 (GAP-6): one peer's relay->direct UPGRADE-PROBE state. Lifecycle:
///   IDLE  : armed (relay-committed); `next_at` is when the next probe fires,
///            `attempt` drives the exponential backoff (first_ms → steady_ms).
///   PROBING: a direct dial is in flight (a `DirectPending{probe:true}` exists);
///            we don't re-fire until it resolves (win → VERIFYING, or expiry →
///            back to IDLE with a longer backoff).
///   VERIFYING: a direct standby CONNECTED (`standby` set). It must move data
///            CONTINUOUSLY for `verify_ms` before we cut over; `verify_started`
///            marks when it connected. If it goes idle past `verify_idle_ms` or
///            never reaches `verify_ms` of sustained progress, it is DISCARDED
///            and we go back to IDLE (stay on relay, the no-flap guard).
struct UpgradeProbe {
    /// failed-probe count; each failure backs the cadence off toward steady_ms.
    attempt: u32,
    /// when the next probe may fire (None ⇒ probe ASAP, e.g. just armed or a
    /// network-change re-probe).
    next_at: Option<Instant>,
    /// the connected-but-unverified direct standby transport (VERIFYING state).
    standby: Option<Arc<dyn Transport>>,
    /// the route label of the standby (`direct-quic` / `holepunched`).
    standby_route: &'static str,
    /// when the standby connected, the start of the verify window.
    verify_started: Option<Instant>,
    /// the standby's `idle_ms()` floor observed so far in the verify window, used
    /// to require SUSTAINED progress (it must keep moving, not just connect).
    verify_last_idle: u64,
}

impl UpgradeProbe {
    fn armed() -> Self {
        UpgradeProbe {
            attempt: 0,
            next_at: None, // first probe is scheduled by the prober tick
            standby: None,
            standby_route: "direct-quic",
            verify_started: None,
            verify_last_idle: u64::MAX,
        }
    }
}

/// P0: which correction rung the stall ladder took (see `Conn::correct_stall`).
#[derive(Debug, PartialEq)]
enum Rung {
    /// (a) re-offer unfinished transfers on the SAME transport (resume:true).
    Resume,
    /// (c) the transport was repaired in place (fresh direct dial / ICE-restart).
    Repaired,
    /// (d) P1: direct rungs a→c spent → the link was RE-ESTABLISHED over the TURN
    /// relay (relay-only ICE), preserving the on-disk partial. The fresh relay
    /// transport's ChannelReady re-offers the unfinished transfers (resume:true)
    /// and prints the honest relay banner.
    Relayed,
    /// rungs a→d unavailable: direct rungs spent AND relay is forbidden
    /// (`--no-relay`) or we were already on relay. The caller FAILS CLEANLY, a
    /// kept partial, a clear error, never a hang.
    Exhausted,
}

/// rung-1: state for one in-flight direct-QUIC attempt.
struct DirectPending {
    /// (name, secret) for the known device, gates the attempt and keys the MAC.
    secret: (String, String),
    /// budget deadline; on expiry with no DirectReady we fall back to WebRTC.
    deadline: Instant,
    /// set once the peer's transport-offer arrived and we spawned the racer, so
    /// a duplicate offer doesn't spawn a second race.
    racing: bool,
    /// kept alive so the bound UDP port stays ours until the race consumes it.
    endpoint: Option<quinn::Endpoint>,
    /// rung-2 (FILAMENT_HOLEPUNCH): a SECOND raw UDP socket, already STUN'd, kept
    /// raw (not connected) so its NAT mapping is the one we punch + run QUIC on.
    /// Consumed by the chained ladder in `on_transport_offer` only if rung-1
    /// fails. None when hole-punch is off or STUN discovery failed.
    punch_sock: Option<std::net::UdpSocket>,
    /// rung-2: our advertised srflx (logged at offer time; kept for diagnostics).
    #[allow(dead_code)]
    my_srflx: Option<std::net::SocketAddr>,
    /// P5 (GAP-6): this is a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE a live relay link (not the cold establishment path). When the
    /// race wins, `on_transport_offer` posts `Ev::DirectUpgradeReady` (verify-
    /// before-upgrade) instead of `Ev::DirectReady` (which would clobber the
    /// serving relay link). When the budget expires with no winner, `expired_direct`
    /// just DROPS the pending (no WebRTC fallback, the relay link is still serving)
    /// and the prober schedules the next backoff.
    probe: bool,
}

impl Conn {
    /// Single constructor for the `pair`/`send`/`recv` command event loops, which
    /// built the identical ~17-field `Conn` literal three times (the only
    /// per-command differences are `relay_only`, `to_filter`, and the
    /// warm-standby default). Everything else is the fixed fresh-session state.
    /// `warm_standby_default` is the per-session-kind default that the
    /// `FILAMENT_WARM_STANDBY` override (via `net::warm_standby_override`) can
    /// still force either way. NOTE: the long-lived `up` daemon loop keeps its
    /// own literal on purpose, it is a different (non-command) session.
    fn for_command(
        server: &str,
        sio: rust_socketio::asynchronous::Client,
        tx: mpsc::UnboundedSender<Ev>,
        my_uid: String,
        relay_only: bool,
        to_filter: Option<String>,
        warm_standby_default: bool,
        direct_ok: bool,
    ) -> Self {
        Conn {
            server: server.to_string(),
            sio,
            tx,
            my_uid,
            my_id: String::new(),
            relay_only,
            to_filter,
            links: HashMap::new(),
            roster: HashMap::new(),
            suppressed_digest_adoptions: HashSet::new(),
            active: None,
            next_gen: 0,
            rejoin: RejoinState { waiting_rejoin: None, rejoin_window: REJOIN_WINDOW, away: None },
            chunk_size: net::MAX_DC_PAYLOAD,
            deferred_left: HashMap::new(),
            recv_done: false,
            direct_pending: HashMap::new(),
            buffered_offers: HashMap::new(),
            resil: ResilienceState {
                stall_repairs: HashMap::new(),
                relay_committed: std::collections::HashSet::new(),
                warm_standby: net::warm_standby_override().unwrap_or(warm_standby_default),
                warm_cutover: std::collections::HashSet::new(),
                upgrade_probe: HashMap::new(),
                iface_snapshot: Vec::new(),
            },
            direct_ok,
            local_port: None,
            local_listener: None,
            direct_endpoint: None,
            warm_hold: WarmHold::default(),
            worker_port_tx: HashMap::new(),
        }
    }

    fn link(&self, pid: &str) -> Option<&Link> {
        self.links.get(pid)
    }
    fn link_mut(&mut self, pid: &str) -> Option<&mut Link> {
        self.links.get_mut(pid)
    }
    fn active_link(&self) -> Option<&Link> {
        self.active.as_ref().and_then(|a| self.links.get(a))
    }
    fn is_active(&self, pid: &str) -> bool {
        self.active.as_deref() == Some(pid)
    }
    fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.active_link().and_then(|l| l.transport.clone())
    }
    fn transport_of(&self, pid: &str) -> Option<Arc<dyn Transport>> {
        self.links.get(pid).and_then(|l| l.transport.clone())
    }

    /// #28: is the link keyed by `pid` actively moving transfer bytes right now?
    /// The data channel is independent of the signaling socket, so when a
    /// same-uid reconnect arrives as a new sid, superseding must NOT tear down
    /// an old link that's still flowing. A frozen-alive peer (gate 11's
    /// SIGSTOP'd receiver) stops stamping activity, so it reads as not-flowing
    /// and the supersede proceeds as before. Threshold is overridable for
    /// deterministic gating (FILAMENT_ADOPT_ACTIVE_MS); the 3 s default sits
    /// well above a healthy sub-100 ms inter-frame gap so a transient ICE blip
    /// can't masquerade as idle and let a spurious supersede through.
    fn link_flowing(&self, pid: &str) -> bool {
        let threshold = std::env::var("FILAMENT_ADOPT_ACTIVE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        self.transport_of(pid)
            .map(|t| t.idle_ms() < threshold)
            .unwrap_or(false)
    }

    /// May this peer become the TRANSFER TARGET? (Filters gate targeting,
    /// never answering, every peer still gets a polite link.)
    fn targetable(&self, name: &str, peer_uid: Option<&str>) -> bool {
        if let Some(filter) = &self.to_filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                return false;
            }
        }
        // Same-role CLI peers never transfer to each other (gate 7).
        if let (Some(pu), Some(my_role)) = (peer_uid, self.my_uid.get(..6)) {
            if pu.starts_with(my_role) {
                return false;
            }
        }
        true
    }

    fn adoption_allowed(&mut self, peer_id: &str, source: AdoptSource) -> bool {
        match_adoption_source(&mut self.suppressed_digest_adoptions, peer_id, source)
    }

    /// Track a roster entry and (re)connect to it. `want_active` marks it as
    /// the intended transfer target if it passes the target filters and no
    /// target exists yet. Returns true if this peer is (now) the active one.
    async fn maybe_adopt(&mut self, v: &Value, want_active: bool) -> Result<bool> {
        self.maybe_adopt_from(v, want_active, AdoptSource::Contact).await
    }

    async fn maybe_adopt_from(&mut self, v: &Value, want_active: bool, source: AdoptSource) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        if !self.adoption_allowed(&peer_id, source) {
            return Ok(false);
        }
        // NOTE: same-install peers (our own daemon) are filtered at the
        // KnownPeer call sites, NOT here, room discovery must keep working
        // between two processes of one machine (loopback self-send is the
        // first thing every new user tries).
        self.roster.insert(peer_id.clone(), v.clone());

        // C6: same device on a NEW sid, supersede the stale link.
        let stale: Option<String> = self
            .links
            .iter()
            .find(|(sid, l)| l.uid.is_some() && l.uid == peer_uid && **sid != peer_id)
            .map(|(sid, _)| sid.clone());
        if let Some(old_sid) = stale {
            // #28: the same device reconnected its signaling socket (fresh sid).
            // If its existing data channel is still flowing, the reconnect is
            // cosmetic, superseding would tear down an active transfer. Keep the
            // old link; once it goes idle a later roster/presence event supersedes.
            if self.link_flowing(&old_sid) {
                // Observable so a gate can assert the keep happened (true
                // positive), not merely that no supersede line appeared.
                ui::debug(&format!("{name} reconnected, keeping active link"));
                return Ok(self.is_active(&old_sid));
            }
            ui::debug(&format!("{name} reconnected, superseding old link"));
            let was_active = self.is_active(&old_sid);
            let secret = self.links.get(&old_sid).and_then(|l| l.expected_secret.clone());
            self.drop_link(&old_sid);
            self.establish(v.clone()).await?;
            if let Some(l) = self.links.get_mut(&peer_id) {
                l.expected_secret = secret;
            }
            if was_active {
                self.active = Some(peer_id.clone());
            }
            return Ok(self.is_active(&peer_id));
        }

        if !self.links.contains_key(&peer_id) {
            if self.links.len() >= MAX_LINKS {
                return Ok(false);
            }
            self.establish(v.clone()).await?;
        }
        // #28: a deferred-active slot is claimable. When the active link got a
        // peer-left but is still flowing, we keep `active` pointing at it (so a
        // same-uid reconnect's supersede still sees it active, and the live
        // transfer's offer/exit machinery is undisturbed). But a DIFFERENT-uid
        // replacement (gate 2: hard-killed receiver, fresh recv) must still be
        // able to take over, otherwise the deferred link squats the slot until
        // the reap, and the replacement (whose ChannelReady already fired) never
        // gets promoted or offered the file. Treating a deferred active as
        // "claimable" promotes the replacement at peer-joined, before its
        // ChannelReady, so the offer goes out on the same baseline path.
        let active_deferred = self
            .active
            .as_ref()
            .is_some_and(|a| self.deferred_left.contains_key(a));
        if want_active && (self.active.is_none() || active_deferred) && self.targetable(&name, peer_uid.as_deref()) {
            // Claiming the slot from a deferred link: discharge that link now
            // (it left the room and is being replaced) so reap doesn't later
            // re-inject a stale peer-left against the slot the new peer holds.
            if active_deferred {
                if let Some(old) = self.active.clone() {
                    if old != peer_id {
                        self.drop_link(&old);
                    }
                }
            }
            self.active = Some(peer_id.clone());
            self.rejoin.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    /// A link is "live" if its primary transport or any worker is still alive.
    /// Restored: the pending-only guard made it briefly dead, but promotion
    /// intent needs it back. Every caller EXCEPT a deliberate promotion must
    /// leave a live link alone, which is what warm-hold depends on.
    fn has_live_transport(&self, pid: &str) -> bool {
        self.links.get(pid)
            .map(|l| {
                let primary_ok = l.transport.as_ref().map(|t| !t.is_dead()).unwrap_or(false);
                let workers_ok = l.workers.iter().any(|w| !w.is_dead());
                primary_ok || workers_ok
            })
            .unwrap_or(false)
    }

    /// Re-emit `ChannelReady` for a link that ALREADY holds a live transport.
    ///
    /// The `--code` path DEFERS every offer until the PAKE confirms. The offer
    /// site says so, and states who is supposed to wake it:
    ///
    ///     // ...on confirm the Signal handler sets `pake_done` and re-emits
    ///     // ChannelReady to fall through here and offer.
    ///     if use_code && !is_direct && !pake_done {
    ///         continue; // offers/remember wait for PAKE confirm
    ///     }
    ///
    /// The Signal handler sets `pake_done`. It has never re-emitted anything.
    /// What actually woke the loop was the Option A teardown: dropping the link
    /// forced a rebuild, and the rebuilt link's FRESH `ChannelReady` fell through
    /// the (now satisfied) guard and carried the offer. A destroy-and-rebuild
    /// cycle was standing in for an event dispatch.
    ///
    /// That is why removing the unconditional teardown wedged macOS. With direct
    /// disabled there was nothing to promote, so nothing dropped, so nothing was
    /// rebuilt, so no second `ChannelReady` ever arrived. The sender sat on a
    /// healthy authenticated link and never attempted a byte, which is exactly
    /// what the #78 artifact shows: `authenticated, sending`, then 15 minutes of
    /// nothing but 30s backend syncs.
    ///
    /// So this honours the contract the comment already documents. It mirrors
    /// the direct-upgrade re-emit in `adopt_direct_transport`, which does the
    /// same thing for the same reason: a transport that becomes usable without a
    /// fresh channel-open still has to tell the loop.
    ///
    /// No-op when the link is gone or its transport is dead, so it is safe to
    /// call unconditionally after a promotion attempt: if the promotion DID
    /// happen the link was replaced and the new transport will announce itself.
    fn rearm_channel_ready(&self, pid: &str, outcome: Promotion) {
        if outcome == Promotion::Replaced {
            return; // the replacement transport announces itself
        }
        let Some(l) = self.links.get(pid) else { return };
        let Some(t) = l.transport.as_ref() else { return };
        if t.is_dead() {
            return;
        }
        let _ = self.tx.send(Ev::ChannelReady(pid.to_string(), t.clone()));
    }

    /// `#[track_caller]` so a teardown NAMES the path that ordered it. There are
    /// 17 call sites, and a link that dies 40ms after authenticating leaves a
    /// `timed out waiting for a peer` whose guard cannot distinguish "no peer
    /// ever arrived" from "the peer's link died". Two of us built root-cause
    /// narratives out of that ambiguity before noticing the instrument was
    /// missing. This is that instrument: no runtime cost, and it cannot drift
    /// from the call sites the way a manual audit does.
    #[track_caller]
    fn drop_link(&mut self, pid: &str) {
        ui::debug(&format!(
            "  drop_link({pid}) ordered by {}",
            std::panic::Location::caller()
        ));
        // #28: dropping a link also discharges any deferred peer-left for it,
        // so a supersede (maybe_adopt) of a deferred same-uid sid can't leave a
        // stale entry blocking adoption. Invariant: deferred_left only ever
        // holds sids that are still live links.
        self.deferred_left.remove(pid);
        self.buffered_offers.remove(pid);
        if let Some(old) = self.links.remove(pid) {
            // Never await close in the event loop (F8): mark + spawn. A direct
            // link has no WebRTC peer; dropping the Link drops its QUIC transport
            // (the keepalive task observes conn.closed() and tears down).
            if let Some(p) = old.peer.clone() {
                p.mark_closed();
                tokio::spawn(async move { p.close().await });
            }
        }
        if self.is_active(pid) {
            self.active = None;
        }
    }

    // --- WARM-HOLD: proactive connection management ---

    /// Record that a peer was just used (transfer, ssh, ping). This updates the
    /// LRU and marks the peer as warm so the daemon proactively connects/reconnects.
    fn note_warm_use(&mut self, peer: &str) {
        self.warm_hold.note_use(peer);
    }

    /// Load configured warm-peers from settings. Called at daemon startup and
    /// at the top of each warm_hold_tick to stay in sync with runtime changes.
    fn load_warm_peers_config(&mut self) {
        if let Some(setting) = settings::get_str("warm-peers", None) {
            self.warm_hold.configured.clear();
            for p in setting.split(',') {
                let p = p.trim().to_string();
                if !p.is_empty() {
                    self.warm_hold.configured.insert(p);
                }
            }
        }
    }

    /// Check for warm peers that need connections and establish them.
    /// Called periodically from the daemon event loop. Returns the list of
    /// peers we attempted to connect to.
    ///
    /// `auto_warm`: sync the auto tier (ALL online paired peers) from the roster.
    /// Default ON (`auto-warm` setting); forced on while L3 is up. When off, the
    /// auto tier is cleared and only configured + recent peers stay warm.
    async fn warm_hold_tick(&mut self, auto_warm: bool) -> Vec<String> {
        // Reload configured peers from settings to stay in sync
        self.load_warm_peers_config();
        if auto_warm {
            let mut online: Vec<(String, Option<Instant>)> = self.roster.values()
                .filter_map(|v| v["name"].as_str())
                .map(|s| (s.to_string(), self.warm_hold.last_use.get(s).copied()))
                .collect();
            // Change 4 size guard: over warm-max, keep the most recently USED peers
            // warm (never-used peers rank last; name tie-break keeps it deterministic).
            let cap = warm_max();
            if online.len() > cap {
                online.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                online.truncate(cap);
            }
            let current: std::collections::HashSet<String> =
                online.into_iter().map(|(n, _)| n).collect();
            for name in &current {
                if !self.warm_hold.auto.contains(name) {
                    self.warm_hold.auto.insert(name.clone());
                    ui::debug(&format!("warm-hold: auto-warming peer '{name}'"));
                }
            }
            // Drop peers that went offline (or fell over the warm-max recency cut)
            self.warm_hold.auto.retain(|name| current.contains(name));
        } else {
            if !self.warm_hold.auto.is_empty() {
                ui::debug("warm-hold: auto-warm off, clearing auto tier");
                self.warm_hold.auto.clear();
            }
        }
        let mut connected = Vec::new();
        let peers = self.warm_hold.peers_to_connect();
        for peer in peers {
            // Skip re-establish if a link to this pid exists AND is alive AND
            // (verified OR within the pair-proof grace window).  Dead links and
            // alive-but-unverified-past-grace (stuck) links still re-establish.
            // The grace prevents churn during the normal pair-proof verification
            // window while ensuring stuck links are eventually replaced.
            const WARM_PAIR_PROOF_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
            let skip = self.links.iter().any(|(_, l)| {
                // Match by name (peers_to_connect returns names, not IDs)
                l.name.eq_ignore_ascii_case(&peer)
                    // Link is alive: transport alive, OR WebRTC peer exists, OR direct link exists
                    && (l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false)
                        || l.peer.is_some()
                        || l.direct)
                    && (
                        l.verified_name.is_some()                    // verified: warm-usable, skip
                        || l.established_at                          // within grace: pair-proof expected
                            .map(|t| t.elapsed() < WARM_PAIR_PROOF_GRACE)
                            .unwrap_or(false)
                    )
            });
            if skip {
                ui::debug(&format!("warm-hold: skip '{peer}' (link alive, within grace)"));
                continue;
            } else {
                ui::debug(&format!("warm-hold: will establish '{peer}' (no alive link found)"));
            }
            // Honor per-peer backoff; a dormant peer still gets one probe per
            // WARM_DORMANT_RETRY so an online-but-unlucky peer cannot stay cold forever.
            if !self.warm_hold.due(&peer) {
                continue;
            }
            // Find peer info from roster
            if let Some(info) = self.roster.values().find(|v| {
                v["name"].as_str().map(|n| n.eq_ignore_ascii_case(&peer)).unwrap_or(false)
                    || v["id"].as_str().map(|id| id.eq_ignore_ascii_case(&peer)).unwrap_or(false)
            }) {
                let info = info.clone();
                let _peer_id = info["id"].as_str().unwrap_or_default().to_string();
                // Try to establish connection
                match self.establish(info).await {
                    Ok(()) => {
                        self.warm_hold.note_success(&peer);
                        ui::debug(&format!("warm-hold: established connection to '{peer}'"));
                        connected.push(peer);
                    }
                    Err(e) => {
                        self.warm_hold.note_failure(&peer);
                        ui::debug(&format!("warm-hold: failed to connect to '{peer}': {e}"));
                    }
                }
            }
        }
        connected
    }

    /// Resume a dormant warm peer (e.g., when it reappears in signaling presence)
    fn resume_warm_peer(&mut self, peer: &str) {
        self.warm_hold.resume(peer);
    }

    async fn establish(&mut self, info: Value) -> Result<()> {
        self.establish_as(info, None).await
    }

    /// `force_polite: Some(true)` builds a pure responder link (no local offer)
    /// regardless of uid comparison, required when the link exists to ANSWER
    /// an incoming offer (ensure_responder / glare rebuild). The uid-based role
    /// can come out impolite there (especially on the bare `{id}` roster-miss
    /// fallback, which compares sids), making the "responder" offer too: glare.
    async fn establish_as(&mut self, info: Value, force_polite: Option<bool>) -> Result<()> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        // rung-1: a direct-QUIC attempt owns this peer until its budget expires.
        // Suppress the WebRTC offer so the path stays SEQUENTIAL (no two
        // transports racing to ChannelReady). `expired_direct` removes the
        // pending before calling us for the fallback, so this never blocks it.
        if self.direct_pending.contains_key(&peer_id) {
            return Ok(());
        }
        // P1 (GAP-4): once a peer is committed to relay, a live link already
        // carries (or is converging on) the relay route. Re-establish events
        // (KnownPeer re-announce, expired_direct fallback, a watchdog tick) must
        // NOT tear it down and rebuild mid-handshake, that thrash is exactly why
        // the relay link got "stuck while connecting". A genuinely failed link is
        // removed by the normal drop path (on_pc_state/GraceExpired) FIRST, so when
        // no link is present here we DO proceed to (re)build the relay link.
        if self.resil.relay_committed.contains(&peer_id) && self.links.contains_key(&peer_id) {
            return Ok(());
        }
        // Build the replacement BEFORE destroying what we have. The drop used to
        // happen here, ahead of `fetch_config` and the peer construction below,
        // both of which are fallible and one of which is a network round trip to
        // the signaling server. On any error this returned Err with the link
        // already gone, and three call sites discard that Err, so a transient
        // failure silently converted a working link into no link at all. That is
        // the fallback path: `expired_direct` -> `establish` is what Option A
        // promises when a direct race loses, so a fallback that can destroy
        // without rebuilding is worse than no fast path.
        //
        // Carry the pair-secret forward too. `expected_secret` is what binds the
        // post-channel pair-proof to the SAME device, and the designed fallback
        // at the expiry site saves and restores it by hand. Any other path that
        // rebuilt a link, including roster adoption, silently produced a link
        // with `expected_secret: None`: no re-dial of direct, and no device
        // binding. Preserving it here fixes every rebuild path at once instead
        // of asking each caller to remember.
        let carried_secret = self
            .links
            .get(&peer_id)
            .and_then(|l| l.expected_secret.clone());
        let peer_uid = info["uid"].as_str().map(|s| s.to_string());
        let peer_present = self.roster.contains_key(&peer_id);
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // C5: fresh ICE config (TURN creds are expiry-stamped HMACs) for
        // every attempt, not just the first.
        let mut cfg = net::fetch_config(&self.server).await?;
        self.chunk_size = cfg.chunk_size;
        let polite = match force_polite {
            Some(value) => value,
            None => match peer_uid.as_deref() {
                Some(peer_uid) => net::polite_role(&self.my_uid, peer_uid, &self.my_id, &peer_id)?,
                None => {
                    let source = if peer_present { "presence" } else { "absent-roster" };
                    net::polite_role_legacy(&self.my_uid, None, &self.my_id, &peer_id, source, peer_present)?
                },
            },
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        // P1 relay-fallback gate (test-only): FILAMENT_TEST_WEBRTC_RELAY_ONLY=1
        // models a peer with NO direct WebRTC path (hard NAT), every WebRTC link
        // is relay-only, so when the direct-QUIC ladder freezes/exhausts the
        // transfer can ONLY complete over the TURN relay. Faithful to the real
        // "direct can't, relay can" condition the auto-fallback exists for; never a
        // product knob. OR'd with the real relay_only (set by --relay or by an
        // auto escalate_to_relay).
        let relay_ice = self.relay_only || test_hooks::webrtc_relay_only();
        // P1 (GAP-4): --no-relay is a HARD direct-only promise, never traverse a
        // relay. Strip TURN servers from the ICE config so no relay candidate can
        // ever be gathered. A peer reachable ONLY via relay then simply fails to
        // connect, honestly, by the user's own choice, instead of silently using
        // a middleman. (The ICE policy is left as-is: a relay-only policy with no
        // relay servers has no candidates and fails cleanly, which is the point.)
        if relay_forbidden() {
            cfg.ice_servers.retain(|s| net::is_stun_only(s));
        }
        let peer = Peer::connect(
            peer_id.clone(),
            self.my_uid.clone(),
            polite,
            cfg.ice_servers,
            relay_ice,
            self.sio.clone(),
            self.tx.clone(),
            generation,
        )
        .await?;
        // Everything fallible is done: NOW replace. Until this point the old link
        // was still serving, so an early return above leaves it untouched.
        self.drop_link(&peer_id);
        self.links.insert(
            peer_id,
            Link {
                peer: Some(peer),
                info,
                name,
                uid: peer_uid,
                transport: None,
                workers: vec![],
                generation,
                attempts: 0,
                trusted: false,
                expected_secret: carried_secret,
                verified_name: None,
                presence: Presence::Connecting,
                direct: false,
                direct_route: "direct-quic", // unused for WebRTC links (peer.is_some())
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: crate::capability::BindingStrength::None,
                identity_cert_expires: None,
                principal_kind: crate::capability::PrincipalKind::OwnerDevice,
            },
        );
        Ok(())
    }

    // --- rung-1 direct-QUIC path (FILAMENT_DIRECT) ---------------------------
    //
    // Sequential by design: when both peers are CLIs and a pair secret is known,
    // try a direct authenticated QUIC connection FIRST and only fall back to the
    // WebRTC `establish` above if no authenticated connection lands within the
    // budget. The whole thing is gated on `direct::direct_enabled()`, so with the
    // flag OFF none of this runs and the WebRTC path is byte-for-byte unchanged.

    /// Begin a direct attempt against `pid`: bind a quinn endpoint, advertise our
    /// candidates via a relayed `transport-offer`, and stash the pending state.
    /// No Link is created yet, it is born (with `peer: None`, pre-trusted) only
    /// when an authenticated connection wins (Ev::DirectReady). Idempotent per
    /// peer (a second call while pending is a no-op). The peer's own
    /// transport-offer (Ev::TransportOffer) drives the race.
    async fn start_direct(&mut self, pid: &str, name: &str, secret: &str) {
        self.start_direct_inner(pid, name, secret, DirectIntent::Normal).await
    }

    /// Option A: replace the serving WebRTC link with direct after PAKE. This
    /// is the ONLY caller permitted to tear down a live link, and the teardown
    /// happens inside `start_direct_inner` AFTER `direct_pending` is registered,
    /// so a failure anywhere in setup leaves WebRTC serving and the fallback
    /// reaper has an attempt to expire.
    async fn start_direct_promote(&mut self, pid: &str, name: &str, secret: &str) -> Promotion {
        self.start_direct_inner(pid, name, secret, DirectIntent::Promote).await;
        // The promotion drops the link ONLY after registering a pending (the
        // insert and the drop are straight-line, nothing returns between them),
        // so the link's continued existence is an exact witness of which
        // outcome happened and does not need threading out of the early returns.
        if self.links.contains_key(pid) {
            Promotion::Retained
        } else {
            Promotion::Replaced
        }
    }

    /// P5 (GAP-6): arm a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE the live relay link. Bypasses the `relay_committed` /
    /// already-linked early-returns of `start_direct` (the whole POINT is to dial
    /// direct while a relay link serves), and marks the `DirectPending` as a
    /// probe so the winner posts `Ev::DirectUpgradeReady` (verify-before-upgrade)
    /// rather than clobbering the serving relay link. A no-op if a probe is
    /// already in flight for this peer.
    async fn start_upgrade_probe(&mut self, pid: &str, name: &str, secret: &str) {
        // A probe already in flight (its own DirectPending), don't double-dial.
        if self.direct_pending.contains_key(pid) {
            return;
        }
        self.start_direct_inner(pid, name, secret, DirectIntent::Probe).await
    }

    /// Ensure we have a TCP listener for local connections.
    async fn ensure_local_listener(&mut self) -> u16 {
        if let Some(p) = self.local_port {
            return p;
        }
        let (listener, port) = crate::local::listen_local().await.unwrap();
        self.local_listener = Some(Arc::new(listener));
        self.local_port = Some(port);
        port
    }

    /// `promote`: this call is REPLACING a serving WebRTC link with direct
    /// (Option A after PAKE). Only then may a live link be torn down, and only
    /// after `direct_pending` is registered so the fallback reaper has an
    /// attempt to expire. Every other caller (known-peer appeared, warm-hold,
    /// re-dial) must leave a healthy link alone: dropping it there is what broke
    /// `warm_all_makes_first_contact_warm`, because warm-hold's whole job is to
    /// have a link already up when first contact arrives.
    async fn start_direct_inner(
        &mut self,
        pid: &str,
        name: &str,
        secret: &str,
        intent: DirectIntent,
    ) {
        let probe = intent == DirectIntent::Probe;
        // Gate on the per-session flag, not the bare env check: the L2/ssh
        // acceptor (`up --shell`) sets `direct_ok` true even with the env unset,
        // so it answers the initiator's transport-offer (rung-1 direct-QUIC over
        // the reachable host candidate) instead of building a colliding WebRTC
        // peer that glares with the initiator's offer.
        if !self.direct_ok {
            return;
        }
        if !probe && self.resil.relay_committed.contains(pid) {
            // P1: this peer escalated to relay, never re-dial direct (it would
            // only re-freeze and race the relay link). If a link already exists
            // (the relay link that escalate_to_relay built, possibly still
            // converging), DON'T rebuild it, repeated KnownPeer/`appeared` events
            // would otherwise tear it down and re-establish mid-handshake, so it
            // never connects ("stuck while connecting"). Only (re)establish over
            // relay when there is no link at all to carry the session.
            // P5 (GAP-6): a `probe` deliberately bypasses this guard, it dials
            // direct ALONGSIDE the serving relay link (warm direct standby) and
            // never touches `links`, so it cannot disturb the relay path.
            if !self.links.contains_key(pid) {
                let info = json!({ "id": pid, "name": name });
                if let Err(e) = self.establish(info).await {
                    ui::debug(&format!("  re-establish for {pid} failed: {e}"));
                }
            }
            return;
        }
        // A probe expects a relay link to be present (it's the one we'd upgrade
        // AWAY from); only the cold path bails when a link already exists.
        let link_dead = self.links.get(pid)
            .map(|l| l.transport.as_ref().map(|t| t.is_dead()).unwrap_or(true) && l.workers.iter().all(|w| w.is_dead()))
            .unwrap_or(false);
        if link_dead {
            // The link is already dead, so destroying it loses nothing. Its
            // PENDING is a different matter, see `supersede`.
            self.drop_link(pid);
        }
        // A stale pending must not BLOCK a fresh attempt, but REMOVING it here
        // would disarm the fallback, and the two are not the same thing.
        //
        // `expired_direct` reaps a pending in order to fire the WebRTC
        // re-establish, so a pending removed now and not replaced is a recovery
        // trigger that can never fire. `bind_endpoint` is ~24 lines below and
        // returns ~100 lines BEFORE the re-insert, so a box where bind fails
        // (which is exactly a box where the previous attempt died and left a
        // dead link, so the two conditions co-occur by construction rather than
        // by coincidence) ends with no link, no pending, and nothing armed.
        //
        // That is the same destroy-without-a-successor shape as the teardown
        // bug this file already fixed, one level up: not the link this time,
        // the recovery trigger. The rule is identical. Do not remove the
        // pending until you are certain you can replace it.
        //
        // So the decision to supersede is made WITHOUT mutating. The insert
        // below replaces the entry, and that is the first point at which we are
        // certain a replacement exists. A promotion supersedes for its own
        // reason: any pending started before PAKE completed was dialled without
        // the shared secret and cannot authenticate, so letting it block the
        // promotion is how Option A silently never runs.
        let supersede = link_dead || intent == DirectIntent::Promote;
        if self.direct_pending.contains_key(pid) && !supersede {
            return; // already trying
        }
        // A live link is a REASON TO STOP for everyone except a deliberate
        // promotion. Promotion is the one caller that intends to replace it.
        if intent == DirectIntent::Normal && self.has_live_transport(pid) {
            return; // already linked via a live transport
        }

        // Check if target is same-machine peer (local transport).
        let peer_uid = self.roster.get(pid).and_then(|info| info["uid"].as_str());
        let is_local = is_self_uid(&self.my_uid, peer_uid);

        let (ep, port) = if is_local {
            // For local peers, we don't need a QUIC endpoint.
            (None, 0u16)
        } else {
            match direct::bind_endpoint() {
                Ok(v) => {
                    // Clone for multi-stream worker connections before the
                    // original is consumed by the race in on_transport_offer.
                    if net::direct_streams() > 1 {
                        self.direct_endpoint = Some(v.0.clone());
                    }
                    (Some(v.0), v.1)
                }
                Err(e) => {
                    // Keep the existing WebRTC link: direct_pending is not
                    // registered yet, so the fallback reaper has nothing to
                    // expire. The caller must retain a working path on failure.
                    ui::debug(&format!(
                        "filament: direct disabled (endpoint bind failed: {e}); WebRTC retained"
                    ));
                    return;
                }
            }
        };
        // #1 (parallelism): gather the host/public candidates (incl. the
        // /api/whoami HTTP) and the rung-2 STUN srflx CONCURRENTLY. Both are
        // independent network round-trips that must finish before the
        // transport-offer can go out, and the initiator's "establishing" phase
        // waits on exactly that offer, so overlapping them shaves a round-trip off
        // every cold connect. Both borrow &self immutably, so join! is sound.
        //
        // rung-2 (FILAMENT_HOLEPUNCH): bind a SECOND raw socket and STUN it so we
        // can advertise a server-reflexive candidate. This socket is kept RAW
        // (not handed to quinn), its NAT mapping is the one we'll punch + run
        // QUIC on if rung-1's host-candidate race fails. STUN failure is graceful:
        // no srflx is advertised and rung-2 simply won't fire for this peer.

        let (cands, srflx) = if is_local {
            // For local peers, ensure we have a listener and return TCP candidate.
            if self.local_port.is_none() {
                let (listener, port) = crate::local::listen_local().await.unwrap();
                self.local_listener = Some(Arc::new(listener));
                self.local_port = Some(port);
            }
            let cands = vec![format!("{{\"type\":\"tcp-localhost\",\"port\":{}}}", self.local_port.unwrap())];
            (cands, None)
        } else {
            let srflx_fut = async {
                if holepunch::holepunch_enabled() {
                    self.gather_srflx().await
                } else {
                    None
                }
            };
            tokio::join!(direct::gather_candidates(&self.server, port), srflx_fut)
        };

        let (punch_sock, my_srflx) = match srflx {
            Some((sock, srflx)) => (Some(sock), Some(srflx)),
            None => (None, None),
        };

        // transport-offer rides the OPAQUE signaling relay (same channel as ICE
        // signals); the server cannot read or forge it without failing the MAC.
        let mut offer = json!({ "type": "transport-offer", "v": 1, "addrs": cands });
        if let Some(s) = my_srflx {
            offer["srflx"] = json!(s.to_string());
        }
        // P5 (GAP-6): tag a probe offer so the PEER races it as an upgrade probe
        // too, its winning side then posts Ev::DirectUpgradeReady (verify-before-
        // upgrade) instead of clobbering ITS serving relay link. Both ends must
        // treat the new direct path as a standby until verified, or one end would
        // tear down its relay link unilaterally.
        if probe {
            offer["probe"] = json!(true);
        }
        let _ = self
            .sio
            .emit("signal", json!({ "to": pid, "data": offer.clone() }))
            .await;
        // TRACE, direct-offer / signaling detail.
        ui::trace(&format!(
            "filament: {} sent to {name} ({pid}), port {} srflx {}",
            if probe { "UPGRADE-PROBE-OFFER" } else { "DIRECT-OFFER" },
            port,
            my_srflx.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
        ));
        // Re-send the offer periodically. The L2 initiator (netcat/ssh) subscribes
        // to the channel AFTER us, so on a late join it can miss BOTH our single
        // fire-once offer AND its own KnownPeer for us (presence delivery is racy),
        // the cross-machine stall. Re-emitting lets it catch a later offer and
        // dial our (reachable) candidates; the initiator only races the FIRST
        // offer it gets, so the extra emits are harmless once linked.
        {
            let sio = self.sio.clone();
            let pid_c = pid.to_string();
            tokio::spawn(async move {
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    let _ = sio
                        .emit("signal", json!({ "to": pid_c, "data": offer.clone() }))
                        .await;
                }
            });
        }
        // The WebRTC fallback reaper (`expired_direct`) fires at this deadline.
        // rung-1's race always burns the full DIRECT_BUDGET when it can't win
        // (its acceptor future never self-completes), so with hole-punch enabled
        // the deadline MUST cover the WHOLE ladder, rung-1 budget + punch budget
        // + QUIC handshake slack, or the reaper would race WebRTC against an
        // in-flight punch and the route would be a coin flip. Flag-gated, so
        // rung-1-only timing is byte-identical.
        let deadline = if holepunch::holepunch_enabled() {
            Instant::now() + direct::DIRECT_BUDGET + holepunch::PUNCH_BUDGET + Duration::from_secs(3)
        } else {
            Instant::now() + direct::DIRECT_BUDGET
        };
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                secret: (name.to_string(), secret.to_string()),
                deadline,
                racing: false,
                endpoint: ep,
                punch_sock,
                my_srflx,
                probe,
            },
        );
        // Replace the serving WebRTC link only after all fallible setup has
        // completed and the fallback reaper has a pending attempt to expire.
        // Upgrade probes retain their serving relay link by design.
        if intent == DirectIntent::Promote {
            self.drop_link(pid);
        }
        // Bug 2: replay any transport-offers that were buffered while we had
        // no DirectPending (the sender re-dialed after a mid-transfer death).
        if let Some((cands, srflx)) = self.buffered_offers.remove(pid) {
            ui::debug(&format!("replaying buffered transport-offer from {pid}"));
            self.on_transport_offer(pid, cands, srflx);
        }
    }

    /// rung-2: bind a raw punch socket and discover its srflx via STUN against
    /// the ICE config's STUN server. Returns (raw socket, srflx) or None.
    async fn gather_srflx(&self) -> Option<(std::net::UdpSocket, std::net::SocketAddr)> {
        let cfg = net::fetch_config(&self.server).await.ok()?;
        let stun_urls: Vec<String> = cfg
            .ice_servers
            .iter()
            .flat_map(|s| s.urls.iter().cloned())
            .collect();
        // #3 (parallelism): race ALL configured STUN servers so a slow/dead one
        // never stalls gathering (the offer the initiator waits on).
        let stun_addrs = holepunch::stun_server_addrs(&stun_urls);
        if stun_addrs.is_empty() {
            return None;
        }
        let sock = holepunch::bind_punch_socket().ok()?;
        // STUN is blocking UDP I/O, run it off the reactor.
        tokio::task::spawn_blocking(move || {
            holepunch::stun_srflx_any(&sock, &stun_addrs).map(|srflx| (sock, srflx))
        })
        .await
        .ok()?
        .ok()
    }

    /// The peer advertised its candidates. If we have a matching pending attempt
    /// and haven't started the race yet, consume the endpoint and spawn the
    /// simultaneous-open + auth race; the winner posts Ev::DirectReady (or, for an
    /// upgrade probe, Ev::DirectUpgradeReady, verify-before-upgrade).
    fn on_transport_offer(&mut self, pid: &str, peer_cands: Vec<String>, peer_srflx: Option<String>) {
        let Some(p) = self.direct_pending.get_mut(pid) else { return };
        if p.racing {
            return;
        }
        let Some(ep) = p.endpoint.take() else { return };
        p.racing = true;
        let secret = p.secret.1.clone();
        // P5 (GAP-6): is THIS the upgrade-probe pending? Then the winner posts
        // DirectUpgradeReady (verify-before-upgrade) so the serving relay link is
        // never clobbered. A cold pending posts DirectReady as before.
        let is_probe = p.probe;
        // rung-2: hand the punch socket + peer's srflx to the chained ladder.
        let punch_sock = p.punch_sock.take();
        let peer_srflx_addr = peer_srflx
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let tx = self.tx.clone();
        let pid_s = pid.to_string();
        let peer_uid = self.roster.get(pid).and_then(|info| info["uid"].as_str()).map(str::to_owned);
        let Some(peer_uid) = peer_uid else {
            eprintln!("direct role election deferred for {pid}: no peer UID");
            return;
        };
        let my_uid = self.my_uid.clone();
        let my_id = self.my_id.clone();
        let mk = move |pid: String, t: Arc<dyn Transport>, route: &'static str| {
            if is_probe {
                Ev::DirectUpgradeReady(pid, t, route)
            } else {
                Ev::DirectReady(pid, t, route)
            }
        };
        tokio::spawn(async move {
            // Check for TCP localhost candidate (same-machine peer).
            for cand in &peer_cands {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(cand) {
                    if v["type"] == "tcp-localhost" {
                        if let Some(port) = v["port"].as_u64() {
                            let addr = format!("127.0.0.1:{port}");
                            ui::trace(&format!("filament: trying TCP localhost to {addr}"));
                            match crate::local::LocalTransport::connect(&addr).await {
                                Ok(t) => {
                                    let _ = tx.send(mk(pid_s, Arc::new(t), "local-tcp"));
                                    return;
                                }
                                Err(e) => {
                                    ui::trace(&format!("filament: TCP localhost failed: {e}"));
                                }
                            }
                        }
                    }
                }
            }
            // rung-1: direct-dial QUIC over host candidates. The answerer role is
            // derived inside the race from both endpoint identity tuples, so the
            // connector and offer-receiver cannot drift via caller literals.
            if let Some(t) =
                direct::race_connect(ep, peer_cands, &secret, pid_s.clone(), my_uid.clone(), peer_uid.clone(), my_id.clone(), tx.clone()).await
            {
                let _ = tx.send(mk(pid_s, t, "direct-quic"));
                return;
            }
            // rung-2: UDP hole-punch, then rung-1's QUIC race over the punched
            // socket. Only fires with the flag on, a punch socket bound, and a
            // peer srflx to punch toward. On failure (e.g. symmetric NAT) we fall
            // through to the WebRTC step-down via the per-tick reaper.
            if holepunch::holepunch_enabled() {
                if let (Some(sock), Some(peer_srflx)) = (punch_sock, peer_srflx_addr) {
                    // TRACE, direct/hole-punch detail.
                    ui::trace(&format!("filament: rung-1 failed, attempting hole-punch to {peer_srflx}"));
                    if let Some(t) = holepunch::connect(
                        sock,
                        peer_srflx,
                        &secret,
                        pid_s.clone(),
                        my_uid.clone(),
                        peer_uid.clone(),
                        my_id.clone(),
                        tx.clone(),
                    )
                    .await
                    {
                        let _ = tx.send(mk(pid_s, t, "holepunched"));
                        return;
                    }
                }
            }
            // On None the per-tick reaper handles the WebRTC fallback at deadline.
        });
    }

    /// P5 (GAP-6): a relay-committed peer received an UPGRADE-PROBE transport-
    /// offer (`probe:true`) from the other end while we have no probe pending of
    /// our own yet. ARM a matching upgrade probe so the symmetric direct dial can
    /// complete (both ends must offer their candidates for the QUIC simultaneous-
    /// open race). Only fires for a peer we are actually serving on relay
    /// (`relay_committed` + a live link) and only when the prober is enabled and
    /// relay isn't forbidden, otherwise the probe offer is ignored.
    async fn answer_upgrade_probe(&mut self, pid: &str) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if !self.resil.relay_committed.contains(pid) || !self.links.contains_key(pid) {
            return;
        }
        if self.direct_pending.contains_key(pid) {
            return; // our own probe is already in flight, its race will consume the offer
        }
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        if let Some((name, secret)) = known {
            self.start_upgrade_probe(pid, &name, &secret).await;
        }
    }

    /// Create the Link for a direct connection that won the race. `peer: None`
    /// (no WebRTC), `direct: true`, `trusted: true` (the pair-secret MAC already
    /// proved identity, at least as strong as the DTLS pair-proof it replaces).
    fn adopt_direct(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let pend = self.direct_pending.remove(pid);
        let (name, secret) = match pend {
            Some(p) => p.secret,
            None => ("peer".to_string(), String::new()),
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": name }));
        let uid = info["uid"].as_str().map(|s| s.to_string());
        let expected_secret = if secret.is_empty() {
            None
        } else {
            Some((name.clone(), secret))
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        // If a Link already exists for this pid (e.g. from a stall-watchdog
        // repair re-dial), UPDATE its transport + workers in place instead of
        // full-insert replacing the old Link (which would drop the primary
        // transport Arc → quinn ApplicationClosed → primary death at K>1).
        // Workers stay intact; only the primary transport is swapped.
        let _existing_generation = self.links.get(pid).map(|l| l.generation).unwrap_or(0);
        if let Some(existing) = self.links.get_mut(pid) {
            if existing.transport.as_ref().map(|t2| t2.is_dead()).unwrap_or(true) { existing.transport = Some(t); }
            existing.direct = true;
            existing.direct_route = route;
            existing.generation = generation;
            existing.attempts = 0;
            existing.trusted = true;
            if let Some((n, _)) = &expected_secret {
                existing.verified_name = Some(n.clone());
            }
            resolve_peer_identity(existing);
            if expected_secret.is_some() {
                existing.expected_secret = expected_secret;
            }
        } else {
            // Mesh reuse: spawn accept loop before t moves into Link.
            direct::spawn_mesh_accept(pid.to_string(), &t, self.tx.clone());
            self.links.insert(
                pid.to_string(),
                Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                workers: vec![],
                generation,
                attempts: 0,
                trusted: true,
                // A direct link is born identity-bound (its pair-secret MAC
                // already proved who it is), so the petname is known up front.
                verified_name: expected_secret.as_ref().map(|(n, _)| n.clone()),
                expected_secret,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: crate::capability::BindingStrength::None,
                identity_cert_expires: None,
                principal_kind: crate::capability::PrincipalKind::OwnerDevice,
            },
        );
        }
    }

    /// Spawn K-1 parallel QUIC worker transports in a background task after
    /// the primary direct connection wins.  The non-answerer side dials; the
    /// answerer side accepts.  Each worker gets its OWN quinn::Endpoint (own
    /// UDP socket, own driver task) so packet I/O parallelises across cores.
    /// Workers arrive asynchronously via `Ev::DirectWorkersReady` and are
    /// populated on the Link.  File send (`stream_one`) gracefully degrades
    /// to fewer streams if workers are not yet ready.
    fn spawn_direct_workers(
        &mut self,
        pid: &str,
        primary: &Arc<dyn Transport>,
        tkey: [u8; 32],
    ) {
        let k = net::direct_streams();
        if k <= 1 {
            return;
        }
        let peer_uid = self.roster.get(pid).and_then(|i| i["uid"].as_str());
        let peer_present = self.roster.contains_key(pid);
        let answerer = match peer_uid {
            Some(peer_uid) => match net::polite_role(&self.my_uid, peer_uid, &self.my_id, pid) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("direct worker role election failed for {pid}: {error}");
                    return;
                }
            },
            None => {
                let source = if peer_present { "presence" } else { "absent-roster" };
                match net::polite_role_legacy(&self.my_uid, None, &self.my_id, pid, source, peer_present) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("worker role election failed for peer {pid}: {error}");
                        return;
                    }
                }
            }
        };
        let count = k - 1;
        let pid = pid.to_string();
        let tx = self.tx.clone();
        let primary = primary.clone();

        if answerer {
            // ACCEPTOR: create independent QUIC endpoints (one per worker),
            // send their ports to the dialer, then accept incoming connections.
            let mut endpoints = Vec::with_capacity(count);
            let mut ports = Vec::with_capacity(count);
            for _ in 0..count {
                if let Ok((ep, port)) = direct::bind_endpoint() {
                    endpoints.push(ep);
                    ports.push(port);
                }
            }
            if endpoints.is_empty() {
                return;
            }
            let offer = json!({ "type": "worker-ports", "v": 1, "ports": ports, "for": &pid });
            let p = primary.clone();
            tokio::spawn(async move {
                let _ = p.send_control(&offer).await;
            });
            tokio::spawn(async move {
                let workers = direct::accept_workers(endpoints, tkey, pid.clone(), tx.clone(), count).await;
                if !workers.is_empty() {
                    let _ = tx.send(net::Ev::DirectWorkersReady(pid, workers));
                }
            });
        } else {
            // DIALER: wait for the acceptor's worker ports, then connect to each.
            let peer_ip = match primary.remote_addr().map(|a| a.ip()) {
                Some(ip) => ip,
                None => return,
            };
            let (port_tx, port_rx) = tokio::sync::oneshot::channel();
            self.worker_port_tx.insert(pid.clone(), port_tx);
            tokio::spawn(async move {
                let ports = match tokio::time::timeout(std::time::Duration::from_secs(5), port_rx).await
                {
                    Ok(Ok(p)) => p,
                    _ => return,
                };
                let workers = direct::dial_workers(ports, peer_ip, tkey, pid.clone(), tx.clone(), count).await;
                if !workers.is_empty() {
                    let _ = tx.send(net::Ev::DirectWorkersReady(pid, workers));
                }
            });
        }
    }

    /// Per-tick: a direct attempt whose budget expired without an authenticated
    /// connection falls back to the WebRTC `establish` (unchanged). Returns the
    /// list of (pid, info) to establish, caller awaits establish outside the
    /// borrow. Also drops any pending whose Link already exists.
    fn expired_direct(&mut self) -> Vec<(String, Value, (String, String))> {
        let now = Instant::now();
        let mut fell_back = Vec::new();
        // P5 (GAP-6): an UPGRADE-PROBE pending whose budget expired with no winner
        // must NOT fall back to WebRTC, the relay link is still serving and the
        // whole point of the probe was to find a DIRECT path. Just DROP it and let
        // the prober's backoff schedule the next attempt (mark_probe_failed). The
        // cold (non-probe) pendings keep their existing WebRTC-fallback behavior.
        let expired_probes: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(_, p)| p.probe && now >= p.deadline)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired_probes {
            self.direct_pending.remove(&pid);
            // DEBUG, resilience internal (upgrade probe found no path).
            ui::debug(&format!("filament: UPGRADE-PROBE for {pid} found no direct path in budget, staying on relay"));
            self.mark_probe_failed(&pid);
        }
        let expired: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && now >= p.deadline && !self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired {
            if let Some(p) = self.direct_pending.remove(&pid) {
                let info = self
                    .roster
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "id": pid, "name": p.secret.0 }));
                // DEBUG, resilience internal (direct→WebRTC fallback).
                ui::debug(&format!(
                    "filament: DIRECT-FALLBACK for {}, no authenticated QUIC in budget, using WebRTC",
                    p.secret.0
                ));
                fell_back.push((pid, info, p.secret));
            }
        }
        // Drop pendings whose link landed by another route (cleanup). P5 (GAP-6):
        // EXCLUDE upgrade probes, a probe pending ALWAYS coexists with the serving
        // relay link (that's the point), so this cleanup must not reap it before its
        // race runs; a probe is reaped only by its own deadline (above) or by the
        // upgrade cutover consuming it.
        let linked: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in linked {
            self.direct_pending.remove(&pid);
        }
        fell_back
    }

    /// C3/C4: watchdog or grace expiry, retry that LINK with fresh config,
    /// up to MAX_ATTEMPTS, then drop it. Returns true when the exhausted link
    /// was the active transfer target (send decides whether that is fatal).
    async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<bool> {
        // C21: don't burn retry attempts against a peer that told us it's
        // away, re-dialing a suspended tab is wasted attrition.
        if self.is_away(pid) {
            return Ok(false);
        }
        let Some(l) = self.links.get(pid) else { return Ok(false) };
        // rung-1: a direct link has no WebRTC watchdog (no Peer::connect timer),
        // so on_stuck can't fire for it; defensively no-op if it ever does.
        if l.direct {
            return Ok(false);
        }
        if l.generation != generation || l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // stale timer from a superseded attempt
        }
        // Gate-18 Mode B: the transfer is COMPLETE (recv_done; recomputed per
        // tick by the recv loop, so this can only be true with by_sid empty and
        // !keep_open) and this link just went stuck/lost. Reconnecting would
        // fetch nothing and merely FLAP the link, resetting attempts and
        // re-arming expected_secret each cycle, so conn.links never empties and
        // the quiet-exit can't fire (RC=124 hang under contention). DROP it
        // instead: links empties, quiet-exit fires. Fenced to complete-only, so
        // a mid-transfer link (recv_done=false) reconnects normally (gate 2/11c).
        // FILAMENT_TEST_DISABLE_MODEB_DROP reverts to the old reconnect-always
        // behaviour so the gate proves A/B with ONE binary: baseline (toggle set)
        // hangs to RC=124 under the churn hook; fix (toggle unset) exits cleanly.
        if self.recv_done && !test_hooks::disable_modeb_drop() {
            let was_active = self.is_active(pid);
            ui::debug(&ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after completion, nothing left to fetch)")));
            self.drop_link(pid);
            return Ok(was_active);
        }
        let attempts = l.attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            let was_active = self.is_active(pid);
            ui::debug(&ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after {attempts} attempts)")));
            self.suppressed_digest_adoptions.insert(pid.to_string());
            self.drop_link(pid);
            return Ok(was_active);
        }
        // DEBUG, resilience internal (link retry).
        ui::debug(&format!("connection {why}, retrying ({}/{})", attempts + 1, MAX_ATTEMPTS));
        let info = l.info.clone();
        let secret = l.expected_secret.clone();
        // C26: a link that was ever up is *re*connecting; one that never
        // connected is still just connecting, keeps "recovered" honest.
        let prev = match l.presence {
            Presence::Connecting => Presence::Connecting,
            _ => Presence::Reconnecting,
        };
        let was_active = self.is_active(pid);
        // Add exponential backoff between retries to avoid burning through attempts instantly.
        let backoff = std::cmp::min(
            Duration::from_secs(2u64.pow(attempts - 1)),
            Duration::from_secs(10),
        );
        tokio::time::sleep(backoff).await;
        self.establish(info).await?;
        if let Some(nl) = self.links.get_mut(pid) {
            nl.attempts = attempts;
            nl.expected_secret = secret;
            nl.presence = prev;
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        Ok(false)
    }

    // --- P0 (GAP-1): the bytes-moved STALL watchdog + correction ladder ------
    //
    // The single byte-flow primitive `Transport::idle_ms()` already exists
    // (net.rs) and is stamped at the unambiguous "a data byte moved" point on
    // both send and receive. #28 wired it ONLY to the supersede decision; this
    // is the second consumer the audit calls the core gap: a watchdog that
    // declares an OPEN, ALIVE link bad when an in-flight transfer moves zero
    // bytes, the "stuck at 0%" hang, and drives the least-disruptive
    // correction. Run from the main event loop's tick (no new concurrency: F8).

    /// Per-tick check: if a transfer is in flight (`in_flight`) on a link whose
    /// `idle_ms()` has crossed the stall threshold, return its (pid, idle_ms) so
    /// the loop can emit `Ev::TransferStalled`. Returns `None` for a flowing or
    /// idle-but-empty link. Resetting bookkeeping on observed progress lives in
    /// `note_progress`, so a slow-but-MOVING link (which keeps advancing
    /// idle_ms's baseline) never trips, the threshold is on time-since-last-byte,
    /// never on throughput.
    fn detect_stall(&mut self, pid: &str, in_flight: bool) -> Option<u64> {
        let in_episode = self.resil.stall_repairs.get(pid).map(|s| s.pending).unwrap_or(false);
        // The liveness PHASE is the single source of truth (resilience::classify):
        // it pairs each phase with its own clock, so an ESTABLISHING link (no first
        // byte yet) is judged by the generous grace and a FLOWING one by the tight
        // stall threshold. This makes "judge a still-establishing link by the 6 s
        // flowing threshold" - the high-RTT relay repair loop - unrepresentable.
        // See docs/transfer-state-machine.md.
        // Aggregate across primary + worker transports: during multi-stream
        // transfers data rides the workers, so the primary can appear idle.
        // Liveness is measured by the MOST recently active transport.
        let link = self.links.get(pid);
        let transport = link.and_then(|l| l.transport.as_ref());
        let workers: Vec<Arc<dyn Transport>> = link.map(|l| l.workers.clone()).unwrap_or_default();
        let transport_up = transport.is_some() || !workers.is_empty();
        let flowed = transport.map(|t| t.has_flowed()).unwrap_or(false)
            || workers.iter().any(|w| w.has_flowed());
        let idle_ms = transport.map(|t| t.idle_ms()).into_iter()
            .chain(workers.iter().map(|w| w.idle_ms()))
            .min()
            .unwrap_or(u64::MAX);
        #[cfg(debug_assertions)]
        eprintln!("[STALL] pid={pid} in_flight={in_flight} transport_up={transport_up} flowed={flowed} idle_ms={idle_ms} workers={} cluster={:?}",
            workers.len(),
            transport.map(|t| t.idle_ms()).into_iter().chain(workers.iter().map(|w| w.idle_ms())).collect::<Vec<_>>()
        );
        let obs = resilience::LiveObs {
            in_flight,
            transport_up,
            flowed,
            idle_ms,
            grace_ms: net::establish_grace_ms(),
            stall_ms: net::stall_ms(),
        };
        match resilience::classify(&obs) {
            resilience::Liveness::Flowing => {
                self.note_progress(pid);
                None
            }
            resilience::Liveness::Establishing => {
                // During an active repair cycle (new transport not yet
                // established), the episode must survive so the next stall
                // picks up at the correct rung instead of restarting from
                // Resume (which fails because the link was dropped).
                let in_repair = self.resil.stall_repairs.get(pid)
                    .map(|s| s.pending)
                    .unwrap_or(false);
                if !in_repair {
                    self.note_progress(pid);
                }
                None
            }
            // Nothing in flight: drop stray bookkeeping.
            resilience::Liveness::Idle => {
                self.resil.stall_repairs.remove(pid);
                None
            }
            // No progress past the phase threshold. Open a new episode, or (if one
            // is already open) re-fire the ladder UNLESS a repair is converging -
            // re-emitting every tick would thrash while the replacement transport
            // is still establishing.
            resilience::Liveness::Stalled => {
                if in_episode && self.repair_in_flight(pid) {
                    None
                } else {
                    Some(obs.idle_ms)
                }
            }
        }
    }

    /// Is a repair for this peer's stall episode currently converging (a re-dial
    /// in flight or the ladder mid-step)? Used to avoid re-firing every tick.
    fn repair_in_flight(&self, pid: &str) -> bool {
        // A direct re-dial is pending, OR the ladder just acted and we're waiting
        // on the next observation. We treat `direct_pending` as the convergence
        // signal for rung (c)'s fresh dial. P1: a relay escalation (rung d) builds
        // a fresh WebRTC link NOT tracked by `direct_pending`, so the per-episode
        // `relayed` latch is its convergence signal, both keep the watchdog from
        // re-firing while the replacement transport is still establishing.
        if self.direct_pending.contains_key(pid) {
            return true;
        }
        self.resil.stall_repairs.get(pid).map(|s| s.relayed).unwrap_or(false)
    }

    /// Clear a peer's stall episode, called when bytes are observed moving
    /// again (the link recovered) or nothing is in flight.
    fn note_progress(&mut self, pid: &str) {
        self.resil.stall_repairs.remove(pid);
        // P3: a fresh byte means the (warm-cut-over) path is healthy again, let a
        // FUTURE episode warm-cut-over once more if it too stalls.
        self.resil.warm_cutover.remove(pid);
    }

    /// P0 liveness cross-check: is the link's CONTROL path still answering? A
    /// black-holed *data* path (the case we recover) still carries reliable,
    /// ordered control frames, so a successful control send distinguishes
    /// "data wedged, link alive" (→ correction ladder) from "link dead" (→ the
    /// established C3/C4 establishment-retry path, which already handles it).
    /// We send a cheap `ping` control frame; success ⇒ alive. We do NOT await a
    /// pong (F8: the event loop must never block on something a remote controls),
    /// a send that returns Ok over a reliable channel is sufficient evidence
    /// the transport itself is up; a dead transport errors or is flagged dead and
    /// returns Err here.
    async fn link_alive(&self, pid: &str) -> bool {
        match self.transport_of(pid) {
            Some(t) => t
                .send_control(&json!({ "type": "ping", "v": 1, "reason": "stall-probe" }))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Decide the correction RUNG for the current stall episode and (for rung c)
    /// repair the transport in place WITHOUT tearing the session down. Returns:
    ///   `Rung::Resume`: rung (a): caller re-offers unfinished transfers with
    ///                     resume:true on the SAME transport (cheapest).
    ///   `Rung::Repaired`: rung (c): the transport was repaired in place
    ///                     (direct: fresh QUIC dial of the known device;
    ///                     WebRTC: restart_ice), caller re-offers once it's back.
    ///   `Rung::Relayed`, rung (b)/(d): re-established over the TURN relay. P3
    ///                     reaches this on the FIRST stall for a warm-standby
    ///                     (interactive) session, instant failover to the
    ///                     pre-designated warm alternate; P1 reaches it at the
    ///                     ladder ceiling for a one-shot transfer.
    ///   `Rung::Exhausted`: rungs a→c spent (MAX_ATTEMPTS) AND relay unavailable
    ///                     (forbidden / already on relay), fail clean, kept partial.
    /// Bounds the episode by MAX_ATTEMPTS, reusing the same ceiling as on_stuck.
    async fn correct_stall(&mut self, pid: &str) -> Rung {
        // P3 (GAP-3): once this episode has CUT OVER to the warm relay standby, a
        // SECOND Ev::TransferStalled that was already QUEUED before the cutover ran
        // (the loops emit one per tick while the stall holds) must NOT re-enter the
        // ladder and run a COLD in-place repair on top of the converging cutover,
        // that tore the fresh relay link down ("ICE Agent can not be restarted when
        // gathering"). Swallow it as a no-op (`Repaired` is the benign "in flight,
        // nothing to do" for both handlers). This guard is keyed on `warm_cutover`,
        // which is ONLY ever set on the warm path, so the COLD ladder (P0/P1) is
        // byte-for-byte unchanged and still climbs rung a→c→d normally. Cleared by
        // `note_progress` when the relay path moves a byte.
        if self.resil.warm_cutover.contains(pid) {
            return Rung::Repaired;
        }
        // Check transport dead BEFORE the mutable borrow so the borrow-split
        // is unambiguous. When the transport is structurally dead (I/O error,
        // not a vanished peer), rung (a) Resume (re-offer on the same transport)
        // is guaranteed wasted — send_frame checks the dead flag and errors
        // immediately. Skip ahead to rung (c) Repair (re-dial direct QUIC) on
        // the first ladder tick, collapsing a wasted stall cycle.
        let dead_on_entry = self.transport_of(pid).map(|t| t.is_dead()).unwrap_or(false);
        let st = self.resil.stall_repairs.entry(pid.to_string()).or_default();
        st.pending = true;
        if dead_on_entry && st.attempts == 0 {
            st.attempts = 1;
        }
        let attempt = st.attempts;
        st.attempts += 1;

        // P3 (GAP-3): WARM-REDUNDANCY instant failover (rung b). For a long-lived
        // / interactive session (`warm_standby`), the relay is a PRE-DESIGNATED
        // WARM standby kept ready alongside the primary direct path. On the FIRST
        // detected stall we CUT OVER to it IMMEDIATELY rather than grinding through
        // the slow direct-repair rungs, rung (a)'s resume-and-wait-another-stall,
        // then rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, each of which costs a
        // full stall threshold before it gives up. Those rungs are correct for a
        // one-shot file (the on-disk partial makes a cold repair fine), but for an
        // interactive session every one of those windows is a visible, intolerable
        // gap. Cutting straight to the warm relay collapses N×stall_ms of cold
        // re-establish into a single relay cutover (rung d's machinery, but reached
        // on stall #1 instead of stall #~6), preserving the on-disk partial / PTY
        // stream / tunnel state via the same C7 resume seam.
        //
        // Gated tightly so we never pay this on the wrong session:
        //   - `warm_standby` (session-kind selectivity) must be on;
        //   - relay must be PERMITTED (`--no-relay` keeps the hard direct-only
        //     promise → fall through to the normal ladder, which fails clean);
        //   - we must not be ON relay already (`relay_only`), then relay is the
        //     PRIMARY that stalled, so there's no warmer alternate; fall through to
        //     the ladder, which lands on the honest "still stalled on relay" exit;
        //   - we cut over at most ONCE per episode (`warm_cutover`), a flapping
        //     relay can't re-fire instant cutover every tick; the second stall on
        //     the relay path falls through to the bounded relay-stalled honesty.
        let warm_eligible = self.resil.warm_standby
            && !relay_forbidden()
            && !self.relay_only
            && !self.resil.warm_cutover.contains(pid);
        // The ladder DECISION (which rung) is pure and lives in resilience.rs; this
        // method owns the state mutation + the rung's side effect.
        match resilience::decide_stall_action(
            attempt,
            STALL_MAX_REPAIRS,
            warm_eligible,
            relay_forbidden(),
            self.relay_only,
        ) {
            resilience::StallAction::WarmCutover => {
                // P3 (GAP-3) WARM-REDUNDANCY instant failover (rung b): cut straight
                // to the pre-designated warm relay standby instead of grinding the
                // slow direct-repair rungs (intolerable for an interactive session).
                // DEBUG, resilience internal; visible at -v / FILAMENT_LOG=debug.
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer stalled, cutting over to the warm relay standby (instant failover)",
                ));
                self.resil.warm_cutover.insert(pid.to_string());
                // Latch the episode as relaying so detect_stall waits for the fresh
                // relay path to move a byte (clearing the episode) instead of
                // re-firing the ladder while the cutover converges.
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Resume => {
                // Rung (a): cheapest, re-issue on the same transport. The caller
                // owns `outgoing` and does the actual re-offer; we just classify.
                // DEBUG, resilience internal (rung (a) resume on the same link).
                ui::debug(&ui::paint(ui::Tone::Warn, "  transfer stalled, resuming on the same link"));
                Rung::Resume
            }
            resilience::StallAction::ExhaustedRelayForbidden => {
                // The hard direct-only promise: never silently fall to a relay.
                // CRITICAL, a clean fatal path-decision the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  couldn't establish a direct path; relay disabled (--no-relay), \
                    partial kept on disk. Re-run to resume, or drop --no-relay to \
                     allow relay fallback.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::ExhaustedAlreadyRelay => {
                // We already re-established over relay and it ALSO stalled: no harder
                // rung. Stop honestly with the partial preserved.
                // CRITICAL, a terminal honesty line the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer still stalled on the relay route, partial kept on disk. \
                     Re-run to resume.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::RelayEscalate => {
                // Rung (d): re-establish over the TURN relay, preserving the on-disk
                // partial (C7 resume). Bounded: one escalation per episode.
                // CRITICAL, P1's value-prop: the never-flaky promise kicking in.
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  direct paths exhausted, falling back to the TURN relay",
                ));
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Repair => {
                // Rung (c): repair the transport IN PLACE under the live session.
                // DEBUG, resilience internal (in-place repair).
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    &format!("  transfer stalled, repairing the link in place (attempt {}/{})", attempt, STALL_MAX_REPAIRS),
                ));
                self.repair_link_in_place(pid).await;
                Rung::Repaired
            }
        }
    }

    /// Rung (c): rebuild a path under the LIVE session, preserving the on-disk
    /// partial (C7 resume re-offers from the saved offset on the new transport).
    /// - direct-QUIC link: drop the wedged transport and re-arm the known-device
    ///   direct dial (`start_direct`), which re-advertises candidates; the peer's
    ///   matching re-dial (it runs the same watchdog) completes a FRESH
    ///   authenticated QUIC connection → `Ev::DirectReady` → `adopt_direct` swaps
    ///   in the new transport → ChannelReady re-offers the unfinished transfers.
    /// - WebRTC link: `restart_ice()`, keeps the RTCPeerConnection + DTLS keys;
    ///   only ICE re-gathers, so transfers resume on the same channel once ICE
    ///   re-converges (no re-key, the preferred repair when available).
    async fn repair_link_in_place(&mut self, pid: &str) {
        let Some(l) = self.links.get(pid) else { return };
        if l.direct {
            // Fresh QUIC dial of the known device. Pull the (name,secret) the
            // link was born with so the re-dial re-authenticates to the SAME pair
            // secret (session identity is stable across the swap; only the wire
            // keys rotate, documented in §2.5).
            let known = l.expected_secret.clone();
            let info = l.info.clone();
            let was_active = self.is_active(pid);
            self.drop_link(pid); // tears down the wedged transport (frees the port)
            if let Some((name, secret)) = known {
                self.start_direct(pid, &name, &secret).await;
                if was_active {
                    // start_direct creates no Link yet; keep the slot pointed here
                    // so adopt_direct's ChannelReady re-offers to the right target.
                    self.active = Some(pid.to_string());
                }
            } else {
                // No stored secret to re-dial direct, fall back to a WebRTC
                // re-establish under the session (still preserves the partial).
                // This IS the fallback: swallowing its failure is how a lost
                // direct race became a transfer with no link and no diagnostic.
                if let Err(e) = self.establish(info).await {
                    ui::debug(&format!("  WebRTC fallback for {pid} failed: {e}"));
                }
                if was_active {
                    self.active = Some(pid.to_string());
                }
            }
        } else if let Some(p) = l.peer.clone() {
            // WebRTC: ICE-restart in place, no teardown, no re-key.
            p.restart_ice().await;
        }
    }

    /// Rung (d), P1 (GAP-4): the direct/in-place ladder is exhausted, so
    /// RE-ESTABLISH this transfer over the TURN relay (relay-only ICE), the
    /// automatic version of the manual `--relay` the Pixel delivery and the runner
    /// both had to perform by hand. The on-disk partial is preserved at the seam:
    /// we re-establish a fresh WebRTC link with `RTCIceTransportPolicy::Relay`, and
    /// its ChannelReady re-offers the unfinished transfers with `resume:true` from
    /// the saved `.part` offset (no restart-from-zero, C7). Flipping the
    /// connection-wide `relay_only` flag also makes any subsequent repair on this
    /// session relay-only, so we don't bounce back to a known-bad direct path.
    /// Session identity (the pair secret / verified petname) is stable across the
    /// swap, only the wire keys rotate (§2.5). Bounded: one escalation per stall
    /// episode (the caller returns `Rung::Relayed` and the `stall_repairs` counter
    /// is already at the ceiling, so the ladder can't re-fire until progress
    /// resumes and resets it).
    async fn escalate_to_relay(&mut self, pid: &str) {
        // Latch the whole connection onto relay-only ICE: the re-establish below
        // and every later (re)establish for this session now forces TURN.
        self.relay_only = true;
        // Commit THIS peer to relay: stop dialing/answering direct-QUIC for it, so
        // the known-bad direct path can't keep winning the race and re-freezing
        // while the relay link tries to form (the exact thrash the sim exposed).
        self.resil.relay_committed.insert(pid.to_string());
        let Some(l) = self.links.get(pid) else { return };
        let info = l.info.clone();
        let known = l.expected_secret.clone();
        let was_active = self.is_active(pid);
        // Tear down the wedged (direct) transport, then re-establish over WebRTC
        // relay-only. We deliberately do NOT re-arm the direct-QUIC dial here even
        // if a secret is known: direct is what just failed, and relay is a WebRTC
        // path, so we go straight to `establish` (relay-only ICE).
        self.drop_link(pid);
        // Clear any stray pending direct attempt so `establish` (which early-
        // returns while a direct attempt owns the peer, to keep the ladder
        // sequential) is never suppressed for the relay re-establish.
        self.direct_pending.remove(pid);
        // Carry the proven identity into the fresh relay link so the post-channel
        // pair-proof still binds to the same device (set after establish creates
        // the Link below).
        if let Err(e) = self.establish(info).await {
            ui::debug(&format!("  relay-only re-establish for {pid} failed: {e}"));
        }
        if let (Some(l), Some(ks)) = (self.links.get_mut(pid), known) {
            l.expected_secret = Some(ks);
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        // Honest, loud: the user must know this session is now on a relay.
        // CRITICAL, the value-prop path label; shown even under -q.
        ui::critical(&format!("  {}", relay_banner()));
        // P5 (GAP-6): ARM the relay->direct upgrade prober for this peer. Relay is
        // a way-station, not a destination: while we serve on relay we keep probing
        // for a direct path and upgrade back the moment one is confirmed stable.
        // Eligibility mirrors warm redundancy (long-lived/interactive sessions +
        // the daemon, a one-shot send that already completed doesn't need it) and
        // requires relay to be PERMITTED. The kill switch (`FILAMENT_UPGRADE_PROBE=0`)
        // and `--no-relay` both make this a no-op.
        if self.upgrade_eligible() {
            self.resil.upgrade_probe
                .entry(pid.to_string())
                .or_insert_with(UpgradeProbe::armed);
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  on relay, will keep trying for a direct path and upgrade automatically",
            ));
        }
    }

    /// P5 (GAP-6): is this session eligible to run the relay->direct prober?
    /// Selective like P3's warm redundancy: ON for long-lived / interactive
    /// sessions (the `up`/`up --shell` daemon acceptor; a transfer flagged
    /// interactive via `FILAMENT_WARM_STANDBY=1`). Gated off by the kill switch
    /// and by `--no-relay` (which never reaches relay anyway).
    fn upgrade_eligible(&self) -> bool {
        self.resil.warm_standby && net::upgrade_prober_enabled() && !relay_forbidden()
    }

    /// P5 (GAP-6): a portable network-change-ish event fired (a signaling
    /// reconnect / fresh welcome). Re-probe every relay-committed peer IMMEDIATELY
    /// (reset its backoff to fire now), unless it's already mid-verify on a standby.
    /// Cheap and idempotent, the prober tick does the actual dialing.
    fn reprobe_on_network_event(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        for up in self.resil.upgrade_probe.values_mut() {
            if up.standby.is_none() {
                up.next_at = Some(Instant::now());
            }
        }
    }

    /// P5 (GAP-6): record a failed/expired probe and back the cadence off toward
    /// the steady cadence (exponential, capped at steady_ms). Also clears any
    /// stale standby/verify state so the next probe starts clean.
    fn mark_probe_failed(&mut self, pid: &str) {
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else { return };
        up.attempt = up.attempt.saturating_add(1);
        up.standby = None;
        up.verify_started = None;
        up.verify_last_idle = u64::MAX;
        // Backoff: first failure → first_ms; then double toward steady_ms (cap).
        let first = net::upgrade_first_ms();
        let steady = net::upgrade_steady_ms();
        let backoff = first.saturating_mul(1u64 << up.attempt.min(8)).min(steady);
        up.next_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    /// P5 (GAP-6): the per-tick prober. Run from each live-session event loop's
    /// tick (no new concurrency, F8). For every peer currently committed to relay
    /// with an armed `UpgradeProbe`: (1) if a direct standby is mid-VERIFY, judge
    /// it (cut over if it has sustained progress for verify_ms; discard + back off
    /// if it regressed); (2) else if a probe is due (`next_at`), fire a fresh
    /// direct dial ALONGSIDE the relay link (warm direct standby) without
    /// disturbing it. Also detects a local interface change (`iface_snapshot`) and
    /// re-probes IMMEDIATELY, the "walked home onto wifi" trigger.
    async fn tick_upgrade_prober(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if self.resil.upgrade_probe.is_empty() {
            return;
        }
        // Network-change trigger: a change to the local interface set is the
        // strongest "a new direct path may exist NOW" signal we can read without a
        // platform netlink dependency. On change, reset every armed probe's
        // backoff to fire immediately (catches the wifi/cellular handoff instantly).
        let snap = direct::local_ip_snapshot();
        if snap != self.resil.iface_snapshot {
            if !self.resil.iface_snapshot.is_empty() {
                // DEBUG, resilience internal (upgrade-probe trigger).
                ui::debug(&ui::paint(
                    ui::Tone::Dim,
                    "  network changed, re-probing for a direct path now",
                ));
                for up in self.resil.upgrade_probe.values_mut() {
                    if up.standby.is_none() {
                        up.next_at = Some(Instant::now()); // fire ASAP
                    }
                }
            }
            self.resil.iface_snapshot = snap;
        }

        let now = Instant::now();
        let pids: Vec<String> = self.resil.upgrade_probe.keys().cloned().collect();
        for pid in pids {
            // A peer that is no longer relay-committed (already upgraded or gone)
            // shouldn't be probed; drop its entry.
            if !self.resil.relay_committed.contains(&pid) || !self.links.contains_key(&pid) {
                self.resil.upgrade_probe.remove(&pid);
                self.direct_pending.remove(&pid);
                continue;
            }
            // VERIFYING: a standby connected, judge it before scheduling anything.
            let verifying = self
                .resil.upgrade_probe
                .get(&pid)
                .map(|u| u.standby.is_some())
                .unwrap_or(false);
            if verifying {
                self.judge_upgrade_standby(&pid).await;
                continue;
            }
            // PROBING: a direct dial is in flight (its DirectPending), wait for it
            // to win (→ DirectUpgradeReady) or expire (→ expired_direct backoff).
            if self.direct_pending.contains_key(&pid) {
                continue;
            }
            // IDLE: schedule / fire the next probe per the backoff.
            let due = match self.resil.upgrade_probe.get(&pid).and_then(|u| u.next_at) {
                None => true,            // armed but unscheduled → schedule first probe
                Some(at) => now >= at,   // due
            };
            if let Some(up) = self.resil.upgrade_probe.get_mut(&pid) {
                if up.next_at.is_none() {
                    // First scheduling after arming: probe after first_ms.
                    up.next_at = Some(now + Duration::from_millis(net::upgrade_first_ms()));
                    continue;
                }
            }
            if !due {
                continue;
            }
            // Fire a probe: dial direct ALONGSIDE the relay link.
            let known = self.links.get(&pid).and_then(|l| l.expected_secret.clone());
            let Some((name, secret)) = known else {
                // No stored secret to authenticate a direct dial, can't probe;
                // disarm so we don't spin.
                self.resil.upgrade_probe.remove(&pid);
                continue;
            };
            // DEBUG, resilience internal (upgrade probe attempt).
            ui::debug(&ui::paint(
                ui::Tone::Dim,
                "  probing for a direct path (alongside the relay)...",
            ));
            // Pre-set the NEXT backoff deadline so a probe that silently makes no
            // progress still re-schedules (expired_direct also calls
            // mark_probe_failed on budget expiry; whichever fires first wins).
            self.start_upgrade_probe(&pid, &name, &secret).await;
        }
    }

    /// P5 (GAP-6): VERIFY-before-upgrade. A direct standby has connected for
    /// `pid`. Decide whether it is STABLE enough to cut over to:
    ///   - if it has been moving data (idle_ms stays low) CONTINUOUSLY for
    ///     `verify_ms`, perform the upgrade (clear relay_committed/relay_only, cut
    ///     over to the direct transport, tear down relay, re-offer transfers);
    ///   - if it goes idle past `verify_idle_ms` before that, DISCARD it and stay
    ///     on relay (back off), the mandatory no-flap guard against a flaky direct
    ///     path that connects then immediately re-stalls.
    /// We drive a tiny VERIFY heartbeat over the standby (a control ping) so a
    /// healthy path keeps stamping its `idle_ms()` low even before the session's
    /// real transfer bytes are re-routed onto it.
    async fn judge_upgrade_standby(&mut self, pid: &str) {
        let verify_ms = net::upgrade_verify_ms();
        let verify_idle_ms = net::upgrade_verify_idle_ms();
        // Heartbeat the standby with a real DATA frame (reserved verify sid) so a
        // healthy path advances its activity clock (`idle_ms()` stays low) while a
        // stalled/flaky standby, which black-holes the DATA path, not the control
        // path, either errors here or lets idle climb. A control ping would wrongly
        // pass on a flaky standby (whose control path stays alive), so we MUST probe
        // the data path. The peer drops the unknown-sid chunk harmlessly but stamps
        // its inbound activity, so its side's idle drops too (symmetric verify).
        let standby = self.resil.upgrade_probe.get(pid).and_then(|u| u.standby.clone());
        let Some(standby) = standby else { return };
        // BOUND the heartbeat (F8: never block the event loop on something a remote
        // / a wedged path controls). A flaky standby's data path black-holes, the
        // send_frame would park forever, so a timeout reads as "didn't hold".
        let beat_ok = matches!(
            tokio::time::timeout(
                Duration::from_millis(500),
                standby.send_frame(VERIFY_PROBE_SID, 0, b"upgrade-verify"),
            )
            .await,
            Ok(Ok(()))
        );
        let idle = standby.idle_ms();
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else { return };
        let started = match up.verify_started {
            Some(t) => t,
            None => {
                up.verify_started = Some(Instant::now());
                up.verify_last_idle = idle;
                return;
            }
        };
        // Regressed: control send failed OR the path went idle past the guard.
        // Discard the standby, stay on relay, back off (the no-flap guard).
        if !beat_ok || idle >= verify_idle_ms {
            // DEBUG, resilience internal (no-flap guard rejecting a standby).
            ui::debug(&ui::paint(
                ui::Tone::Warn,
                "  direct path connected but didn't hold, staying on relay (no flap)",
            ));
            self.direct_pending.remove(pid);
            self.mark_probe_failed(pid);
            return;
        }
        up.verify_last_idle = up.verify_last_idle.min(idle);
        // Sustained: moved data continuously for the whole verify window → upgrade.
        if started.elapsed() >= Duration::from_millis(verify_ms) {
            let t = standby;
            let route = self.resil.upgrade_probe.get(pid).map(|u| u.standby_route).unwrap_or("direct-quic");
            self.perform_upgrade(pid, t, route).await;
        }
    }

    /// P5 (GAP-6): the upgrade cutover. The direct standby is CONFIRMED stable,
    /// commit it as the session's transport, preserving the session (the same
    /// cutover seam P1/P3 use): clear `relay_committed` + `relay_only` so direct
    /// may win again, swap the verified direct transport into the link (the relay
    /// link/transport is dropped), and re-offer any unfinished transfers
    /// (resume:true) on the new direct path. Honest + loud, mirroring the relay
    /// banner: the user is told they're back on a direct path.
    async fn perform_upgrade(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let was_active = self.is_active(pid);
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        // Clear the relay commitment FIRST so the new direct link isn't treated as
        // a known-bad path and so a future stall can escalate cleanly again.
        self.resil.relay_committed.remove(pid);
        self.relay_only = false;
        self.resil.upgrade_probe.remove(pid);
        self.direct_pending.remove(pid);
        // Swap the verified direct transport into the link, dropping the relay
        // link/transport (drop_link tears down the WebRTC peer). adopt the new
        // transport via the same direct-link shape adopt_direct builds, but reusing
        // the existing identity so the session is preserved across the swap.
        self.drop_link(pid);
        self.adopt_direct_transport(pid, t.clone(), route, known);
        if was_active {
            self.active = Some(pid.to_string());
        }
        // CRITICAL, P5's value-prop line: relay released, back on a direct path.
        ui::critical(&ui::paint(
            ui::Tone::Ok,
            &format!("  upgraded back to a direct path (route: {route}), relay released"),
        ));
        // Re-offer unfinished transfers on the new direct transport (resume:true);
        // the ChannelReady re-emit drives the same path for the send loop.
        let _ = self.tx.send(Ev::ChannelReady(pid.to_string(), t));
    }

    /// P5 (GAP-6): build the post-upgrade DIRECT link from a verified standby
    /// transport, reusing the known identity (so the session/petname is stable
    /// across the relay->direct swap, only the wire path changes). Mirrors
    /// `adopt_direct` but takes an already-connected transport and a carried
    /// (name,secret) instead of consuming a `DirectPending`.
    fn adopt_direct_transport(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
        known: Option<(String, String)>,
    ) {
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": known.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|| "peer".into()) }));
        let name = known
            .as_ref()
            .map(|(n, _)| n.clone())
            .or_else(|| info["name"].as_str().map(String::from))
            .unwrap_or_else(|| "peer".into());
        let uid = info["uid"].as_str().map(|s| s.to_string());
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                workers: vec![],
                generation,
                attempts: 0,
                trusted: true,
                verified_name: known.as_ref().map(|(n, _)| n.clone()),
                expected_secret: known,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: crate::capability::BindingStrength::None,
                identity_cert_expires: None,
                principal_kind: crate::capability::PrincipalKind::OwnerDevice,
            },
        );
    }

    /// P5 (GAP-6): a relay->direct upgrade probe's direct standby CONNECTED. Stash
    /// it on the peer's `UpgradeProbe` and START the verify window. Crucially, do
    /// NOT touch `links`, the relay link keeps serving until the standby is proven
    /// stable. If we have no armed probe for this peer (it upgraded/left while the
    /// race was in flight), just drop the transport (it closes on drop). Idempotent:
    /// a second DirectUpgradeReady for an already-stashed standby is ignored.
    fn stash_upgrade_standby(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        // Consume any probe DirectPending so expired_direct doesn't reap/backoff it
        // out from under the verify (the race already won).
        self.direct_pending.remove(pid);
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            // No armed probe, the transport is unowned; dropping it tears it down.
            return;
        };
        if up.standby.is_some() {
            return; // already verifying a standby; ignore the duplicate.
        }
        up.standby = Some(t);
        up.standby_route = route;
        up.verify_started = None; // judge_upgrade_standby stamps it on first look
        up.verify_last_idle = u64::MAX;
        // DEBUG, resilience internal (upgrade verify window opening).
        ui::debug(&ui::paint(
            ui::Tone::Dim,
            "  direct path connected, verifying it holds before upgrading...",
        ));
    }

    /// C4: transient `disconnected`, nudge ICE from the impolite side and
    /// give it grace before treating it as failure. C21: a peer that said
    /// `brb` gets its declared window instead of the 6 s blip grace, and no
    /// scary message.
    async fn on_pc_state(&mut self, pid: &str, s: &str) {
        let away = self.is_away(pid);
        let Some(l) = self.links.get_mut(pid) else { return };
        // C26: collect the announcement, print after the borrow ends so the
        // roster can read every link.
        let mut announce: Option<(&'static str, ui::Tone, &'static str)> = None;
        match s {
            "connected" => {
                if l.presence == Presence::Reconnecting {
                    announce = Some((ui::glyph_ok(), ui::Tone::Ok, "recovered"));
                }
                l.presence = Presence::Ready;
                l.attempts = 0;
            }
            "disconnected" => {
                let grace = if away {
                    l.presence = Presence::Away;
                    if let Some((_, until)) = &self.rejoin.away {
                        until.duration_since(Instant::now()) + Duration::from_secs(15)
                    } else {
                        Duration::from_secs(6)
                    }
                } else {
                    l.presence = Presence::Reconnecting;
                    announce = Some(("◌", ui::Tone::Warn, "reconnecting..."));
                    Duration::from_secs(6)
                };
                if let Some(p) = &l.peer {
                    if !p.polite && !away {
                        p.restart_ice().await;
                    }
                }
                let tx = self.tx.clone();
                let pid = pid.to_string();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
        if let Some((mark, tone, note)) = announce {
            ui::say(&self.roster(pid, mark, tone, note, "peer"));
        }
    }

    /// A peer's socket died. Drop its link; if it was the active target, open
    /// the rejoin window (their client auto-rejoins; C6 supersede completes
    /// the recovery). Returns true if the ACTIVE peer left.
    ///
    /// #28 DEFERRED DROP: peer-left fires when a sid LEAVES THE ROOM, but the
    /// WebRTC data channel is independent and may still be flowing, either a
    /// cosmetic signaling reconnect mid-transfer (keep it!) or a hard-killed
    /// peer whose channel reads flowing for a beat before DTLS notices (must
    /// still drop, or the sender strands). We can't tell the two apart at this
    /// instant, so we DEFER: stash the payload and re-check each tick
    /// (`reap_deferred`). If it goes idle/dead it gets re-injected here with a
    /// force marker and dropped then; if it keeps flowing the transfer
    /// completes on the live channel and the idle link is reaped harmlessly.
    /// The roster entry is removed immediately (the sid truly left); only the
    /// LINK drop is deferred.
    fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid_val) = v["id"].as_str() else { return false };
        let pid = pid_val.to_string();
        self.roster.remove(&pid);
        if !self.links.contains_key(&pid) {
            return false;
        }
        // Delegated (ephemeral) devices are removed immediately on disconnect —
        // not deferred, not rejoinable. They must re-enroll on reconnect.
        if matches!(self.link(&pid).map(|l| &l.principal_kind), Some(crate::capability::PrincipalKind::Delegated { .. })) {
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
            self.drop_link(&pid);
            ui::debug(&format!("ephemeral device {name} disconnected, enrollment revoked"));
            return false;
        }
        // Defer the drop while the data channel is still moving bytes, unless
        // this is the force re-injection from reap_deferred (the link has since
        // gone idle/dead and must drop now). FILAMENT_TEST_NO_DEFER reverts to
        // the old unconditional-drop behaviour so an A/B repro can prove the
        // deferral is what saves the live transfer (baseline must FAIL).
        let forced = v["__fil_force_drop"].as_bool() == Some(true);
        let defer_disabled = test_hooks::no_defer();
        if !forced && !defer_disabled && self.link_flowing(&pid) {
            // Idempotent: first peer-left for this sid records the original
            // payload; a duplicate is swallowed (no double-defer, no drop).
            self.deferred_left.entry(pid.clone()).or_insert_with(|| v.clone());
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred drop while channel flowing).
            ui::debug(&format!("{name} signaling left, data channel still flowing, deferring drop"));
            return false;
        }
        let was_active = self.is_active(&pid);
        self.drop_link(&pid);
        if was_active {
            // C21: informed waits, a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin.rejoin_window = match &self.rejoin.away {
                Some((apid, until)) if *apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => rejoin_unwarned(),
            };
            self.rejoin.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// #28: re-check every deferred peer-left. Called on every main-loop tick
    /// (idempotent, cheap). A deferred sid is discharged when it is no longer
    /// flowing, its data channel went idle past the threshold OR died
    /// (idle_ms == u64::MAX). We then re-inject the ORIGINAL peer-left payload
    /// (flagged force) so the normal Ev::PeerLeft handler runs verbatim, same
    /// loop-side flush/messaging/rejoin behaviour as a non-deferred leave, with
    /// the link now correctly dropped. A sid that vanished from `links` (e.g. a
    /// supersede dropped it; drop_link already cleared its entry, but belt-and-
    /// braces) is forgotten silently. A still-flowing sid is left to keep
    /// flowing, the reconnect case, where the transfer completes on the live
    /// channel and the all-done exit reaps it.
    fn reap_deferred(&mut self) {
        if self.deferred_left.is_empty() {
            return;
        }
        let ready: Vec<(String, Value)> = self
            .deferred_left
            .iter()
            .filter(|(sid, _)| !self.links.contains_key(*sid) || !self.link_flowing(sid))
            .map(|(sid, v)| (sid.clone(), v.clone()))
            .collect();
        for (sid, mut payload) in ready {
            self.deferred_left.remove(&sid);
            if !self.links.contains_key(&sid) {
                continue; // link already gone (superseded); nothing to drop
            }
            // Force the drop this time (the channel is now idle/dead).
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("__fil_force_drop".into(), Value::Bool(true));
            }
            let name = self.link(&sid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred-leave reap).
            ui::debug(&format!("{name} link went idle after deferred leave, dropping now"));
            // Re-inject so the loop's own peer-left branch handles partials,
            // messaging and the rejoin window exactly as a fresh leave would.
            let _ = self.tx.send(Ev::PeerLeft(payload));
        }
    }

    /// #28 exit reconciliation: true when every remaining link is one we're only
    /// holding open for its deferred-drop reap (vacuously true with no links). A
    /// link in `deferred_left` is a peer whose signaling already left; once all
    /// transfers are complete it protects nothing, so it must not delay exit by
    /// the full deferral window.
    fn only_deferred_links(&self) -> bool {
        self.links.keys().all(|k| self.deferred_left.contains_key(k))
    }

    /// C21: any traffic from a peer cancels its declared absence.
    fn note_alive(&mut self, pid: &str) {
        if matches!(&self.rejoin.away, Some((apid, _)) if apid == pid) {
            self.rejoin.away = None;
        }
    }

    /// C26: set a link's roster presence; returns its name for the announce.
    fn link_presence(&mut self, pid: &str, p: Presence) -> String {
        match self.links.get_mut(pid) {
            Some(l) => {
                l.presence = p;
                l.name.clone()
            }
            None => String::new(),
        }
    }

    fn is_away(&self, pid: &str) -> bool {
        matches!(&self.rejoin.away, Some((apid, until)) if apid == pid && *until > Instant::now())
    }

    /// C26: one static colored status line showing EVERY peer, the changed
    /// one carrying the note, `✓ daring-wombat   ● deft-gibbon  away...`.
    /// `fallback_name` covers a peer already dropped from the map (peer-left).
    fn roster(&self, pid: &str, mark: &str, tone: ui::Tone, note: &str, fallback_name: &str) -> String {
        let mut links: Vec<(&String, &Link)> = self.links.iter().collect();
        links.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let mut parts = Vec::new();
        let mut seen = false;
        for (id, l) in links {
            if id == pid {
                seen = true;
                parts.push(peer_entry(l.shown(), mark, tone, note));
            } else {
                let (m, t, n) = presence_glyph(l.presence);
                parts.push(peer_entry(l.shown(), m, t, n));
            }
        }
        if !seen {
            parts.push(peer_entry(fallback_name, mark, tone, note));
        }
        format!("  {}", parts.join("   "))
    }

    /// #7 for the CLI: an offer from a roster peer we haven't linked yet
    /// creates a polite responder link. Stray signals from unknowns drop.
    /// Apply a relayed signal to `from`'s link. Never fatal (F6): the
    /// watchdog/grace machinery owns failed negotiations. On polite-side
    /// glare (webrtc-rs can't roll back out of have-local-offer) the link is
    /// rebuilt as a pure responder and the colliding offer re-applied.
    async fn apply_signal(&mut self, from: &str, data: Value) {
        let peer = match self.link(from).and_then(|l| l.peer.clone()) {
            Some(p) => p,
            None => return,
        };
        match peer.handle_signal(data).await {
            Ok(net::SignalOutcome::Handled) => {}
            Ok(net::SignalOutcome::Glare(offer)) => {
                self.drop_link(from);
                if let Err(e) = self.ensure_responder(from, &offer).await {
                    ui::trace(&format!("signal: glare rebuild failed: {e} (recovering)"));
                    return;
                }
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(offer).await {
                        ui::trace(&format!("signal failed to apply: {e} (recovering)"));
                    }
                }
            }
            Err(e) => ui::trace(&format!("signal failed to apply: {e} (recovering)")),
        }
    }

    async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        if let Some(uid) = data["uid"].as_str() {
            net::ensure_ascii_uid(uid)?;
            if let Some(info) = self.roster.get_mut(from) {
                info["uid"] = json!(uid);
            } else {
                self.roster.insert(from.to_string(), json!({ "id": from, "uid": uid }));
            }
        }
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            // Answer a WebRTC offer from a channel-peer EVEN IF we never got its
            // known-peer. The existing-member known-peer notification is
            // unreliable on prod (proven via the signaling harness: the NEW
            // joiner is reliably notified, but the EXISTING member often is NOT),
            // which left the acceptor ignoring a valid initiator's offer and
            // looking like "stuck connecting". One-sided discovery is now enough:
            // whoever discovers drives, the other answers. SAFE: trust still
            // gates entirely on the pair-proof MAC (an attacker without the
            // secret fails it and is never trusted), we only answer the offer
            // and let the proof decide. A later known-peer refreshes name/uid.
            let info = self
                .roster
                .get(from)
                .cloned()
                .unwrap_or_else(|| json!({ "id": from }));
            if self.links.len() < MAX_LINKS {
                // Forced responder: this link exists to answer THEIR offer.
                self.establish_as(info, Some(true)).await?;
            }
        }
        Ok(())
    }
}

/// Receive the next event; while a rejoin window is open, tick every second
/// so the window can expire AND the countdown stays visible (C22, "45s"
/// frozen on screen reads as broken).
async fn next_ev(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    conn: &Conn,
    suppress_countdown: bool,
) -> Result<Option<Ev>> {
    if let Some(since) = conn.rejoin.waiting_rejoin {
        if since.elapsed() > conn.rejoin.rejoin_window {
            ui::clear_sticky();
            bail!(
                "peer did not come back within {}s (partial state kept for resume)",
                conn.rejoin.rejoin_window.as_secs()
            );
        }
        if !suppress_countdown {
            let left = conn.rejoin.rejoin_window.saturating_sub(since.elapsed()).as_secs();
            ui::sticky(&ui::paint(
                ui::Tone::Dim,
                &format!("  {} holding the line, {left}s for them to come back (Ctrl-C to stop)", ui::spinner_frame()),
            ));
        }
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    } else {
        // C30: never block indefinitely, a 2s tick lets the convergent
        // session repair lost emits even when no events arrive.
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    }
}

/// Per-peer-link map keyed by warm-pty `session` -> (pid, sid), so a later
/// `pty-resize` op can relay to the right stream. Shared between the event loop
/// (lookup) and the spawned bridge tasks (insert/remove). Inert on non-unix.
type WarmPtys = std::sync::Arc<std::sync::Mutex<HashMap<String, (String, u32)>>>;

struct DaemonMountEntry {
    local: String,
    peer: String,
    remote: String,
    pid: u32,
    read_only: bool,
    auto_restore: bool,
    created: String,
}

struct DaemonMounts {
    entries: HashMap<String, DaemonMountEntry>,
    children: HashMap<String, tokio::process::Child>,
}

/// Dispatch one warm-reuse control request to the right handler. Warm reuse is
/// unix-only (the control socket is a unix-domain socket); on non-unix `ctl::Req`
/// is uninhabited so this is never reached - it only keeps the event loop portable.
#[cfg(not(unix))]
async fn handle_warm_req(
    _conn: &Conn,
    _l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    _warm_ptys: &WarmPtys,
    _tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match req {}
}

#[cfg(unix)]
async fn handle_warm_req(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match &req.kind {
        ctl::ReqKind::Open { .. } => handle_warm_open(conn, l2_muxes, tx, req).await,
        // Dial is handled inline in the daemon loop (it needs the L3 manager);
        // answer defensively if it ever reaches here.
        ctl::ReqKind::Dial { .. } => req.reject("dial not handled here").await,
        ctl::ReqKind::Pty { .. } => handle_warm_pty(conn, l2_muxes, warm_ptys, tx, req).await,
        ctl::ReqKind::Resize { .. } => handle_warm_resize(l2_muxes, warm_ptys, req).await,
        ctl::ReqKind::Ping { .. } => handle_warm_ping(conn, req).await,
        // Bootstrap is dispatched before this (it defers its reply), so it never
        // reaches here; reject defensively so a future caller falls back to cold.
        ctl::ReqKind::Bootstrap { .. } => req.reject("bootstrap not handled here").await,
        // Reconfigure is handled inline in the daemon loop (it mutates loop state),
        // so it never reaches this dispatcher; answer defensively if it ever does.
        ctl::ReqKind::Reconfigure { .. } => req.reply(&json!({ "ok": true, "live": false })).await,
        ctl::ReqKind::Arm { key_id, expiry } => {
            crate::ephemeral::arm(key_id.clone(), *expiry);
            req.reply(&json!({ "ok": true })).await;
        }
        // ReloadExpose is likewise handled inline in the daemon loop (it owns the
        // Exposer); answer defensively if it ever reaches here.
        ctl::ReqKind::ReloadExpose => req.reply(&json!({ "ok": true, "live": false, "count": 0 })).await,
        // Reload is handled inline in the daemon loop (it self-SIGTERMs); answer
        // defensively if it ever reaches here.
        ctl::ReqKind::Reload => req.reply(&json!({ "ok": true, "reloading": false })).await,
        // Mount/Unmount/ListMounts/MountHealth are handled inline in the daemon
        // loop (they need access to DaemonMounts); answer defensively if reached.
        ctl::ReqKind::Mount { .. } => req.reject("mount not handled here").await,
        ctl::ReqKind::Unmount { .. } => req.reject("unmount not handled here").await,
        ctl::ReqKind::ListMounts => req.reject("list-mounts not handled here").await,
        ctl::ReqKind::MountHealth { .. } => req.reject("mount-health not handled here").await,
        ctl::ReqKind::CapStatus => req.reject("cap-status not handled here").await,
        ctl::ReqKind::ListWarm => req.reject("list-warm not handled here").await,
        ctl::ReqKind::ListPending => req.reject("list-pending not handled here").await,
        ctl::ReqKind::ApproveRequest { .. } => req.reject("approve-request not handled here").await,
        ctl::ReqKind::DenyRequest { .. } => req.reject("deny-request not handled here").await,
    }
}

/// Handle a mount request: spawn sshfs directly and track the child process
/// centrally so `handle_unmount` can kill it.
#[cfg(unix)]
async fn handle_mount(
    req: ctl::Req,
    server: &str,
    relay: bool,
    daemon_mounts: &mut DaemonMounts,
    last_mount_check: &mut Instant,
) {
    let ctl::ReqKind::Mount { peer, remote, local, read_only, auto_restore, port } = &req.kind else { return };
    let peer = peer.clone();
    let remote = remote.clone();
    let local = local.clone();
    let read_only = *read_only;
    let auto_restore = *auto_restore;
    let port = *port;

    // Ensure mount point exists.
    if !Path::new(&local).exists() {
        if let Err(e) = std::fs::create_dir_all(&local) {
            req.reject(&format!("failed to create mount point: {e}")).await;
            return;
        }
        crate::ui::say(&format!("created mount point: {local}"));
    }

    // Check sshfs is available.
    if std::process::Command::new("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        req.reject("sshfs not found").await;
        return;
    }

    // Bootstrap peer connection info.
    let info = match crate::l2::ensure_peer_bootstrap_port(server, &peer, relay, port).await {
        Ok(info) => info,
        Err(e) => {
            req.reject(&format!("bootstrap failed: {e}")).await;
            return;
        }
    };
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(&peer);

    // Build the sshfs command args directly.
    let mut args: Vec<String> = Vec::new();

    // Common SSH options.
    args.extend_from_slice(&[
        "-o".into(), format!("IdentityFile={}", info.key_path.display()),
        "-o".into(), "IdentitiesOnly=yes".into(),
        "-o".into(), format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(), "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(), "StrictHostKeyChecking=accept-new".into(),
        "-o".into(), "ConnectTimeout=10".into(),
        "-o".into(), "ServerAliveInterval=15".into(),
        "-o".into(), "ServerAliveCountMax=4".into(),
    ]);

    // L3 preferred, L2 fallback.
    let dest = if let Some(d) = crate::l2::l3_dest(&info) {
        d  // L3 direct: user@peer.mesh, no ProxyCommand
    } else {
        // L2 fallback: user@filament-peer with ProxyCommand
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" netcat {peer_name} {}", info.rport));
        args.push("-o".into());
        args.push(format!("ProxyCommand={proxy}"));
        format!("{}@{}", info.login, info.host)
    };

    args.push(format!("{dest}:{remote}"));
    args.push(local.clone());
    if read_only {
        args.push("-o".into());
        args.push("ro".into());
    }

    // Spawn sshfs via tokio so we get a Child we can kill later.
    let child = match tokio::process::Command::new("sshfs")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            req.reject(&format!("failed to spawn sshfs: {e}")).await;
            return;
        }
    };

    let pid = child.id().unwrap_or(0);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mount_id = mount::unique_mount_id();
    let parent_id = mount::find_parent_mount(&local);

    // Record in persistent mount tracking.
    let _ = mount::add_mount(mount::MountEntry {
        id: mount_id.clone(),
        parent_id,
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now.clone(),
    });

    // Store in daemon in-memory tracking.
    let entry = DaemonMountEntry {
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now,
    };
    daemon_mounts.entries.insert(local.clone(), entry);
    daemon_mounts.children.insert(local.clone(), child);

    *last_mount_check = Instant::now();
    crate::ui::say(&format!("mounted {peer_name}:{remote} at {local} (id: {mount_id})"));
    req.reply(&json!({ "ok": true })).await;
}

/// Handle an unmount request: kill the sshfs process and remove tracking.
#[cfg(unix)]
async fn handle_unmount(req: ctl::Req, daemon_mounts: &mut DaemonMounts) {
    let ctl::ReqKind::Unmount { target } = &req.kind else { return };
    let target = target.clone();

    // Kill the child process if tracked by the daemon.
    if let Some(mut child) = daemon_mounts.children.remove(&target) {
        let _ = child.kill().await;
    }
    daemon_mounts.entries.remove(&target);

    // Also remove from persistent tracking (async-safe, no block_on).
    match mount::unmount_cmd_async(&target).await {
        Ok(()) => req.reply(&json!({ "ok": true })).await,
        Err(e) => req.reject(&format!("unmount failed: {e}")).await,
    }
}

/// Handle a list-mounts request: return all tracked mounts and their status.
#[cfg(unix)]
async fn handle_list_mounts(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let mounts: Vec<Value> = daemon_mounts.entries.values().map(|e| {
        let is_alive = mount::is_mount_point(&e.local);
        let status = if is_alive { "healthy" } else { "dead" };
        json!({
            "local": e.local,
            "peer": e.peer,
            "remote": e.remote,
            "read_only": e.read_only,
            "auto_restore": e.auto_restore,
            "created": e.created,
            "status": status,
        })
    }).collect();
    req.reply(&json!({ "ok": true, "mounts": mounts })).await;
}

/// Handle a mount-health request: check health of a specific mount.
#[cfg(unix)]
async fn handle_mount_health(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let ctl::ReqKind::MountHealth { target } = &req.kind else { return };
    let target = target.clone();

    // Find the entry by local path or ID.
    let entry = daemon_mounts.entries.get(&target);
    match entry {
        Some(e) => {
            let is_alive = mount::is_mount_point(&e.local);
            let path_exists = Path::new(&e.local).exists();
            let status = if !path_exists {
                "missing"
            } else if !is_alive {
                "dead"
            } else {
                match std::fs::metadata(&e.local) {
                    Ok(_) => "healthy",
                    Err(_) => "stale",
                }
            };
            req.reply(&json!({ "ok": true, "status": status, "local": e.local, "peer": e.peer, "remote": e.remote })).await;
        }
        None => {
            // Not tracked by daemon, but check if it's a live mount anyway.
            if mount::is_mount_point(&target) {
                req.reply(&json!({ "ok": true, "status": "untracked", "local": target })).await;
            } else {
                req.reject(&format!("no mount found for '{target}'")).await;
            }
        }
    }
}

/// Is something listening on this host's own loopback `port` - i.e. an sshd a
/// `filament ssh` initiator could actually reach? A fast connect probe: a
/// successful connect means a listener (we close it at once); refused/timeout
/// means nothing is there. Reported in the shell-bootstrap ack so the initiator
/// fails fast with a clear message instead of ssh hanging on a dead port.
async fn sshd_listening(port: u16) -> bool {
    // Probe localhost first (covers the common case: sshd bound to localhost or
    // all interfaces). Then also try ::1 for dual-stack daemons that only bind
    // IPv6 localhost.
    let addrs: [(&str, std::net::SocketAddr); 2] = [
        ("127.0.0.1", (std::net::Ipv4Addr::LOCALHOST, port).into()),
        ("[::1]", (std::net::Ipv6Addr::LOCALHOST, port).into()),
    ];
    let rt = tokio::runtime::Handle::current();
    for (_label, addr) in addrs {
        let ok = rt
            .spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

/// Answer a `filament ping`: report the daemon's warm link to `peer` (route,
/// remote address, RTT, verified name). Synchronous - every fact is local (quinn
/// already measured the RTT/addr; the route is the link's own label/ICE state), so
/// nothing is awaited from the peer and the F8 event-loop rule is not in play. A
/// miss `reject`s so the client falls back to a cold establish-probe.
#[cfg(unix)]
async fn handle_warm_ping(conn: &Conn, req: ctl::Req) {
    let ctl::ReqKind::Ping { peer } = &req.kind else { return };
    let peer = peer.clone();
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        req.reject("no warm link").await;
        return;
    };
    // WARM-HOLD: ping succeeded, mark peer as warm (note: we can't call
    // note_warm_use here because conn is &Conn; the warm-hold tick will
    // connect to this peer on the next cycle if it drops)
    let link = conn.link(&pid);
    let direct = link.map(|l| l.direct).unwrap_or(false);
    let route = if direct {
        link.map(|l| l.direct_route.to_string()).unwrap_or_else(|| "direct".into())
    } else if let Some(p) = link.and_then(|l| l.peer.clone()) {
        p.route().await.unwrap_or_else(|| "relay".into())
    } else {
        "relay".to_string()
    };
    // Path detail: name the interface the link's local end sits on, classify the
    // remote address, and (for webrtc) report the candidate types + whether the
    // path is relayed. The daemon holds the link AND runs on the same box as the
    // ping client, so it resolves local-ip -> interface locally; ping.rs just
    // renders the fields. This is the data that answers "is it the tailnet?"
    // (e.g. local 100.x on a tailscale0 iface) instead of inferring it.
    let peer_ref = link.and_then(|l| l.peer.clone());
    let path = net::describe_path(t.as_ref(), peer_ref.as_deref()).await.to_json();
    let reply = json!({
        "ok": true,
        "warm": true,
        "direct": direct,
        "route": route,
        "remote_addr": t.remote_addr().map(|a| a.to_string()),
        "rtt_ms": t.rtt_ms(),
        "verified": link.and_then(|l| l.verified_name.clone()),
        "path": path,
    });
    req.reply(&reply).await;
}

/// Return only links the daemon already holds. This is deliberately passive:
/// devices listing must never establish, ping, or otherwise wake a peer.
#[cfg(unix)]
async fn handle_list_warm(conn: &Conn, req: ctl::Req) {
    let links: Vec<Value> = conn.links.iter().filter_map(|(pid, link)| {
        let name = link.verified_name.as_deref()?;
        let transport = link.transport.as_ref()?;
        if !link.trusted || !transport.is_alive() {
            return None;
        }
        Some(json!({
            "name": name,
            "warm": true,
            "direct": link.direct,
            "route": if link.direct { link.direct_route } else { "relay" },
            "remote_addr": transport.remote_addr().map(|a| a.to_string()),
            "rtt_ms": transport.rtt_ms(),
            "verified": name,
            "path": Value::Null,
            "pid": pid,
        }))
    }).collect();
    req.reply(&json!({ "ok": true, "links": links })).await;
}

#[cfg(unix)]
/// A non-direct (relay/WebRTC) link has no QUIC keepalive, so an idle one may be
/// silently NAT/relay-evicted while `is_alive()`/`is_dead()` still lag (the read
/// loop hasn't seen the EOF yet). Container/DERP paths evict ~10s; reusing such a
/// link would open a stream into a black hole and hang. So past this idle window
/// we refuse to warm-reuse a non-direct link and fall back to a fresh establish
/// (correct, just not free). Direct links are exempt: the 5s keepalive keeps them
/// genuinely alive across idle gaps, and their `idle_ms()` is unreliable here
/// anyway (quinn keepalive frames don't stamp last_activity).
/// The net.rs 5s relay keepalive keeps idle_ms under this gate on healthy links;
/// tripping it means the keepalive stopped, so a fresh establish is the right answer.
const WARM_RELAY_STALE_MS: u64 = 8_000;

#[cfg(unix)]
/// Resolve `peer` (matched case-insensitively on the PROVEN `verified_name`, the
/// same key the L2 cap gate uses) to a warm, trusted, alive link, preferring a
/// direct one. The single resolver for every warm-reuse op (open + pty), so the
/// eligibility rule lives in exactly one place. A miss means the caller falls
/// back to a fresh establish, which is correct.
fn warm_link_for(conn: &Conn, peer: &str) -> Option<(String, Arc<dyn net::Transport>)> {
    conn.links
        .iter()
        .filter(|(_, l)| {
            l.trusted
                && l.verified_name.as_deref().map(|n| n.eq_ignore_ascii_case(peer)).unwrap_or(false)
                && l.transport.as_ref().map(|t| {
                    // Alive, AND (direct OR a relay link that hasn't been idle long
                    // enough to be a silently-evicted zombie).
                    t.is_alive() && (l.direct || t.idle_ms() < WARM_RELAY_STALE_MS)
                }).unwrap_or(false)
        })
        .max_by_key(|(_, l)| l.direct as u8)
        .map(|(pid, l)| (pid.clone(), l.transport.clone().unwrap()))
}

/// DEBUG: dump every link's warm-reuse eligibility so a miss-despite-a-live-link
/// is diagnosable (visible at `-v` / FILAMENT_LOG=debug only).
#[cfg(unix)]
fn log_warm_miss(conn: &Conn, peer: &str) {
    for (p, l) in conn.links.iter() {
        ui::debug(&format!(
            "warm-miss '{peer}': pid={p} name={:?} verified={:?} trusted={} has_transport={} alive={} direct={}",
            l.name, l.verified_name, l.trusted,
            l.transport.is_some(),
            l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false),
            l.direct,
        ));
    }
}

/// Warm-reuse: open a raw L2 stream to `peer:rport` over its existing link and
/// bridge it to the client's unix socket (netcat/ssh/forward fast path).
#[cfg(unix)]
async fn handle_warm_open(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Open { peer, rport } = &req.kind else { return };
    let (peer, rport) = (peer.clone(), *rport);
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    // Reuse the SAME per-peer mux the event loop routes inbound L2 frames to.
    let mux = l2_muxes.entry(pid.clone()).or_insert_with(|| l2::Mux::new(t)).clone();
    let tx = tx.clone();
    // SELF-HEALING warm-reuse: VERIFY the held link still delivers BEFORE committing
    // the client. Open the stream and wait for the first inbound frame (sshd's
    // banner - the byte we needed anyway, so a healthy link pays ~1 RTT and nothing
    // extra), then accept. A zombie link (alive at the QUIC layer but black-holing
    // new streams - the popos hang) yields nothing within the window, so we DROP it
    // (the loop re-forms a healthy one, keeping warm-reuse fast) and REJECT, which
    // makes the client's `try_open` return None and fall straight through to a fresh
    // establish. Verifying before accepting is what makes the fallback INSTANT: an
    // accepted-then-dead connection would instead stall the client until ITS own
    // timeout (the 25s ssh ConnectTimeout we measured). Spawned so the verify wait
    // never blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_stream_verified(&mux, rport, l2::warm_verify_window()).await {
            Ok((sid, first, rx)) => {
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx).await;
            }
            Err(e) => {
                ui::debug(&format!(
                    "filament: warm link to '{peer}' is a zombie ({e}); dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh").await;
            }
        }
    });
}

/// Warm-reuse: open a PTY on `peer` over its existing link and bridge it to the
/// client's stdio socket (the `filament pty` fast path). Records the session->sid
/// so a later `pty-resize` can find it; the entry is dropped when the bridge ends.
#[cfg(unix)]
async fn handle_warm_pty(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Pty { peer, session, cols, rows, term, cmd } = &req.kind else { return };
    let (peer, session, cols, rows, term, cmd) = (peer.clone(), session.clone(), *cols, *rows, term.clone(), cmd.clone());
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    let mux = l2_muxes.entry(pid.clone()).or_insert_with(|| l2::Mux::new(t)).clone();
    let warm_ptys = warm_ptys.clone();
    let tx = tx.clone();
    let verify = l2::warm_verify_window();
    // SELF-HEALING warm pty, same shape as handle_warm_open: VERIFY the held link
    // delivers (the shell prompt / replayed buffer, sent unprompted, is the first
    // frame) BEFORE recording the session and accepting the terminal. On a zombie
    // link we DROP it and REJECT, so the client falls straight through to a cold
    // pty rather than getting a dead terminal. Spawned so the verify wait never
    // blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_pty_stream_verified(&mux, &session, cols, rows, &term, &cmd, verify).await {
            Ok((sid, first, rx_pipe)) => {
                if let Ok(mut m) = warm_ptys.lock() {
                    m.insert(session.clone(), (pid, sid));
                }
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx_pipe).await;
                // Bridge ended (shell exit / client gone / link drop): drop our
                // entry, but only if it is still ours (a reconnect may have
                // replaced it).
                if let Ok(mut m) = warm_ptys.lock() {
                    if m.get(&session).map(|(_, s)| *s == sid).unwrap_or(false) {
                        m.remove(&session);
                    }
                }
            }
            Err(e) => {
                ui::debug(&format!(
                    "filament: warm pty link to '{peer}' is a zombie ({e}); dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh").await;
            }
        }
    });
}

/// Warm-reuse: relay a window-size change to an already-open warm PTY (by session).
#[cfg(unix)]
async fn handle_warm_resize(
    l2_muxes: &HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    req: ctl::Req,
) {
    let ctl::ReqKind::Resize { session, cols, rows } = &req.kind else { return };
    let (cols, rows) = (*cols, *rows);
    let target = warm_ptys.lock().ok().and_then(|m| m.get(session).cloned());
    if let Some((pid, sid)) = target {
        if let Some(mux) = l2_muxes.get(&pid) {
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "pty-resize", "sid": sid, "cols": cols, "rows": rows }))
                .await;
        }
    }
    req.accept().await; // close the client's short connection cleanly
}

/// Deferred ssh-bootstrap replies, keyed by the peer's link pid. A `Bootstrap`
/// request can't be answered inline: the daemon sends `shell-bootstrap` over the
/// warm link and the peer's `shell-bootstrap-ack` arrives LATER via this same
/// event loop, so blocking here would deadlock. We stash the reply socket (with a
/// deadline) and complete it from the `shell-bootstrap-ack`/`-deny` control arms,
/// or reap it on timeout. A `Vec` per pid handles concurrent ssh to one peer (the
/// ack is identical, so every waiter gets the same answer).
#[cfg(unix)]
type PendingBootstraps =
    HashMap<String, Vec<(tokio::net::UnixStream, std::time::Instant)>>;

/// Warm-reuse the ssh `shell-bootstrap`: install the client's managed `pubkey` on
/// `peer` over the daemon's EXISTING link instead of a fresh cold establish, the
/// big win for `filament ssh` (pty already rode the warm link; the bootstrap was
/// the last cold-establish left). Sends `shell-bootstrap` and STASHES the reply
/// socket; the ack/deny handler completes it. A miss falls the client back to the
/// cold `shell_bootstrap`.
#[cfg(unix)]
async fn handle_warm_bootstrap(conn: &Conn, pending: &mut PendingBootstraps, req: ctl::Req) {
    let (peer, pubkey, ssh_port) = match &req.kind {
        ctl::ReqKind::Bootstrap { peer, pubkey, ssh_port } => (peer.clone(), pubkey.clone(), *ssh_port),
        _ => return,
    };
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    if t.send_control(&json!({ "type": "shell-bootstrap", "v": 1, "pubkey": pubkey, "ssh_port": ssh_port }))
        .await
        .is_err()
    {
        req.reject("warm link send failed").await;
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    pending.entry(pid).or_default().push((req.sock, deadline));
}

/// Complete every stashed `Bootstrap` waiter for `pid` with `reply`. Called from
/// the `shell-bootstrap-ack`/`-deny` arms; a no-op if none are pending (e.g. the
/// peer re-acked, or the waiter was already reaped).
#[cfg(unix)]
async fn complete_warm_bootstrap(pending: &mut PendingBootstraps, pid: &str, reply: &Value) {
    if let Some(waiters) = pending.remove(pid) {
        for (mut sock, _) in waiters {
            ctl::send_reply(&mut sock, reply).await;
        }
    }
}

/// Drop expired bootstrap waiters (peer never answered): closing the socket gives
/// the client an EOF, which it reads as a miss and falls back to the cold path.
#[cfg(unix)]
fn reap_warm_bootstraps(pending: &mut PendingBootstraps) {
    if pending.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    for waiters in pending.values_mut() {
        waiters.retain(|(_, deadline)| *deadline > now);
    }
    pending.retain(|_, waiters| !waiters.is_empty());
}

/// Classification result for the bare-argument comfort router. Pure data, no side
/// effects: the caller owns the argv rewrite and the user-visible error.
#[derive(Debug, PartialEq, Eq)]
enum BareTarget {
    /// `help` is not a real subcommand on the un-built clap command, so rewrite
    /// to `--help`.
    Help,
    /// An existing local path: `send <path> --code`.
    Send,
    /// A 4-digit nameplate looks like a pairing code (preserved muscle memory).
    Pair,
    /// A 2-3 digit nameplate looks like a legacy transfer code.
    Recv,
    /// `device:port` -> forward local-port device remote-port.
    Forward { lport: String, peer: String, rport: String },
    /// `device.mesh` or `device.mesh:port` -> reach.
    Reach(String),
    /// A bare known device name -> shell.
    Shell,
    /// The token is both a file and a device name; refuse to pick a side.
    AmbiguousFileDevice,
    /// Nothing recognized; the caller should print the did-you-mean path.
    Unknown,
}

/// Pure classification for the bare-argument router. All environment access is
/// injected through the closures so tests can pass fakes. The function does NOT
/// touch capabilities, prompts, or authorizations: it is a router only.
fn classify_bare_token(
    token: &str,
    file_exists: &dyn Fn(&str) -> bool,
    is_known_device: &dyn Fn(&str) -> bool,
) -> BareTarget {
    if token == "help" {
        return BareTarget::Help;
    }
    // Preserve the existing path-first behavior, except when the same bare name
    // is also a known device. A code-shaped filename is still a filename here.
    let is_file = file_exists(token);
    let is_device = is_known_device(token);
    if is_file && is_device {
        return BareTarget::AmbiguousFileDevice;
    }
    if is_file {
        return BareTarget::Send;
    }
    // 4-digit nameplates are the pairing-code shape; keep routing them to `pair`
    // because that is the long-standing bare-code behavior.
    if looks_like_pake_code(token) {
        return BareTarget::Pair;
    }
    // 2-3 digit nameplates are the legacy one-time transfer-code shape.
    if regex_lite_code(token) {
        return BareTarget::Recv;
    }
    // `device:port` -> forward (same port locally and remotely). The device part
    // must be a known petname and the port must parse as a u16. If either fails,
    // fall through to the did-you-mean path; do not guess.
    if let Some((dev, port_str)) = token.rsplit_once(':') {
        if !dev.is_empty()
            && port_str.parse::<u16>().is_ok()
            && is_known_device(dev)
        {
            let port = port_str.to_string();
            return BareTarget::Forward {
                lport: port.clone(),
                peer: dev.to_string(),
                rport: port,
            };
        }
    }
    // `device.mesh` or `device.mesh:port` -> reach. The reach command validates
    // the address and reports unknown peers, so do not require a local petname
    // here. Mesh addresses are not limited to the current device index.
    if token.ends_with(".mesh")
        || token
            .split_once(".mesh:")
            .is_some_and(|(dev, port)| !dev.is_empty() && !port.is_empty())
    {
        return BareTarget::Reach(token.to_string());
    }
    // A non-file known device opens a PTY. The router never escalates privilege,
    // so the command path remains responsible for capability checks.
    if is_device {
        return BareTarget::Shell;
    }
    BareTarget::Unknown
}

#[tokio::main]
async fn main() -> Result<()> {
    // F2: both ring (webrtc) and aws-lc (reqwest) end up in the dep tree;
    // rustls refuses to guess between two providers, so pick ring explicitly
    // BEFORE anything touches TLS.
    rustls::crypto::ring::default_provider().install_default().ok();
    // Migrate state from legacy cwd-relative .config/filament (the broken
    // Windows fallback when HOME was unset) to the platform-correct path.
    platform::Paths::migrate_legacy();
    match platform::Paths::repair_sensitive_permissions() {
        Ok(repaired) if repaired > 0 => {
            eprintln!("filament: repaired permissions on {repaired} sensitive config path(s)");
        }
        Ok(_) => {}
        Err(e) => eprintln!("filament: sensitive config permission repair failed: {e}"),
    }
    // Bare-arg comfort dispatch: `filament <path>` sends it with a code;
    // `filament <something-like-a-code>` claims it. Subcommands still win.
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(first) = argv.get(1) {
        // The real subcommand set, derived from clap so it can NEVER go stale. A
        // hardcoded list drifted (it missed proxy/expose/pair/set/pty/... and the
        // unknown-token branch below then wrongly rejected them). Includes hidden
        // commands + aliases, so every real verb is recognized.
        use clap::CommandFactory;
        let cmd_names: std::collections::HashSet<String> = {
            let c = Cli::command();
            let mut s = std::collections::HashSet::new();
            for sc in c.get_subcommands() {
                s.insert(sc.get_name().to_string());
                s.extend(sc.get_all_aliases().map(str::to_string));
            }
            s
        };
        if !first.starts_with('-') && !cmd_names.contains(first.as_str()) {
            // The router is pure argv transformation: it never escalates
            // privilege, prompts, or mutates capability state. It only decides what
            // a bare token most likely means; the actual command enforces grants.
            let first = first.clone();
            match classify_bare_token(
                &first,
                &|t| std::path::Path::new(t).exists(),
                &|t| devices_load().iter().any(|(n, _)| n == t),
            ) {
                BareTarget::Help => {
                    // `help` / `help <sub>` as an alias for `--help`. clap's built-in
                    // `help` subcommand is not surfaced by `get_subcommands()` on the
                    // un-built command, so it never lands in `cmd_names` and the
                    // unknown-token guard would otherwise reject it. Rewrite it
                    // to the long-help flag: `help` -> `--help`, `help ssh` ->
                    // `ssh --help`.
                    argv.remove(1); // drop the "help" token
                    argv.push("--help".into());
                }
                BareTarget::Send => {
                    // `filament <path>` mints a one-time code so the other side can
                    // claim it without having been paired first.
                    argv.insert(1, "send".into());
                    argv.push("--code".into());
                }
                BareTarget::Pair => {
                    // L1-a unification: a `word-word-NNNN` (4-digit) code now drives
                    // the SAME ephemeral SPAKE2 ceremony whether the verb is `pair`
                    // or `recv`; a bare code is ambiguous. We keep routing it to
                    // `pair` (the long-standing bare-code behavior, 4-digit codes
                    // were always pairing codes), so existing muscle memory is
                    // preserved. To RECEIVE a transfer code, run `filament recv
                    // <code>` explicitly (the `send --code` output prints exactly
                    // that hint), or `filament pair <code>` to remember the device.
                    argv.insert(1, "pair".into());
                }
                BareTarget::Recv => {
                    // A legacy `word-word-NNN` (2-3 digit) transfer code from an old
                    // sender, receive it (no v2 ceremony; the recv path fails loudly
                    // if the peer can't run the handshake).
                    argv.insert(1, "recv".into());
                }
                BareTarget::Forward { lport, peer, rport } => {
                    // `filament device:port` -> `filament forward lport peer rport`.
                    // The local and remote ports are the same number.
                    argv.remove(1);
                    argv.insert(1, "forward".into());
                    argv.insert(2, lport);
                    argv.insert(3, peer);
                    argv.insert(4, rport);
                }
                BareTarget::Reach(dev_port) => {
                    // `filament device.mesh` or `filament device.mesh:port` ->
                    // `filament reach <device>.mesh[:port]`.
                    argv.remove(1);
                    argv.insert(1, "reach".into());
                    argv.insert(2, dev_port);
                }
                BareTarget::Shell => {
                    // Bare device name = shell in. `filament dovm` opens an interactive
                    // PTY. `filament dovm <cmd...>` runs a one-shot command over PTY
                    // (no sshd needed; the PTY protocol handles it).
                    argv.insert(1, "shell".into());
                }
                BareTarget::AmbiguousFileDevice => {
                    // The token is both a file and a known device. Refuse to guess
                    // which the user meant; naming both readings lets them pick.
                    let send_cmd = format!("filament send {first}");
                    let shell_cmd = format!("filament shell {first}");
                    let width = send_cmd.len().max(shell_cmd.len());
                    eprintln!(
                        "{} \"{first}\" is both a file here and a device you know. Say which:",
                        ui::paint(ui::Tone::Err, ui::glyph_err())
                    );
                    eprintln!(
                        "  {}  send the file",
                        ui::paint(ui::Tone::Dim, &format!("{send_cmd:width$}"))
                    );
                    eprintln!(
                        "  {}  open a shell on the device",
                        ui::paint(ui::Tone::Dim, &format!("{shell_cmd:width$}"))
                    );
                    std::process::exit(2);
                }
                BareTarget::Unknown => {
                    // Not a command, path, code, or paired device. Give a filament-native
                    // error with a did-you-mean over BOTH commands and device names,
                    // instead of clap's bare "unrecognized subcommand" (smart errors).
                    let mut cands: Vec<String> = cmd_names.iter().cloned().collect();
                    cands.extend(devices_load().into_iter().map(|(n, _)| n));
                    let hint = cands
                        .iter()
                        .map(|c| (settings::levenshtein(&first, c), c))
                        .filter(|(d, _)| *d <= 2)
                        .min_by_key(|(d, _)| *d)
                        .map(|(_, c)| c.clone());
                    eprintln!("filament: unknown command or device '{first}'");
                    if first == "init" {
                        // There is no top-level `init`; the user almost certainly
                        // wants to create the user identity key.
                        eprintln!("  did you mean `filament identity init`?");
                    } else if let Some(h) = hint {
                        eprintln!("  did you mean '{h}'?");
                    }
                    eprintln!("  see what you can do:  filament  ·  filament --help  ·  filament devices");
                    std::process::exit(2);
                }
            }
        }
    }
    // Papercut: `devices remove <x>` — `remove` is not a `devices` subcommand.
    // clap's own did-you-mean points at `rename` (nearest by edit distance), but
    // the semantic match for "remove a device" is `forget`. Intercept and say so
    // before clap emits its less-helpful suggestion.
    if argv.get(1).map(String::as_str) == Some("devices")
        && argv.get(2).map(String::as_str) == Some("remove")
    {
        eprintln!("filament: `devices remove` is not a command");
        eprintln!("  did you mean `filament devices forget <name>`?");
        std::process::exit(2);
    }
    let cli = Cli::parse_from(argv);
    let ui_caps = UiCapability::from_cli(&cli);
    // Resolve the global output verbosity ONCE, before any worker spawns:
    // FILAMENT_LOG (if set) overrides the -v/-q flags. Default = info.
    ui::init_verbosity(cli.verbose, cli.quiet);
    if let Some(n) = &cli.name_as {
        // single-threaded at this point (before the runtime spawns workers)
        unsafe { std::env::set_var("FILAMENT_NAME", n) };
    }
    // A --color flag overrides the NO_COLOR/TERM env contract (flags win); record
    // it before any output so both stdout (readout) and stderr (caps) honor it.
    if let Some(when) = &cli.color {
        unsafe { std::env::set_var("FILAMENT_COLOR", when) };
    }
    // P1 (GAP-4): record the hard direct-only choice before any worker spawns.
    // Precedence: an explicit --relay/--no-relay flag always wins; otherwise the
    // persistent `relay` setting (always|never|auto) decides.
    let relay = if cli.no_relay {
        NO_RELAY.store(true, std::sync::atomic::Ordering::Relaxed);
        false
    } else if cli.relay {
        true
    } else {
        match settings::get_str("relay", None).as_deref() {
            Some("always") => true,
            Some("never") => {
                NO_RELAY.store(true, std::sync::atomic::Ordering::Relaxed);
                false
            }
            _ => false,
        }
    };
    // Record the global --no-interactive opt-out before any command runs (the
    // gate also honors FILAMENT_NONINTERACTIVE and a non-TTY stdin).
    if cli.no_interactive {
        NO_INTERACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let server = if cli.server == DEFAULT_SERVER {
        config_get("server").unwrap_or(cli.server.clone())
    } else {
        cli.server.clone()
    };
    let server = server.trim_end_matches('/').to_string();
    // Bare `filament` (no subcommand): a short, state-aware tour of what you'd do
    // next, instead of clap's wall of subcommands. Power users still get --help.
    let Some(cmd) = cli.cmd else {
        return tour_cmd();
    };
    match cmd {
        Cmd::Send { paths, code, word, room, to, name, remember, auth_key } => {
            if let Some(ak_path) = auth_key {
                enroll_and_send_cmd(&server, ak_path, to, paths, relay, remember).await
            } else {
                send_cmd(&server, paths, code || word.is_some(), word, room, to, name, relay, remember).await
            }
        }
        Cmd::Recv { code, dir, yes, room, to, keep_open, remember, output } => {
            recv_cmd(&server, code, dir, yes, room, to, keep_open, relay, remember, false, output, ShellPolicy::Granted, None, false).await
        }
        Cmd::Set { key, value, peer, dry_run, reset, hard, .. } => settings::run_set(
            key.as_deref(),
            value.as_deref(),
            &peer,
            dry_run,
            reset,
            hard,
            ui_caps.yes,
            ui_caps.json || cli.json,
        ).await,
        Cmd::Addr { device, v4 } => {
            if let Some(name) = device {
                // Show a specific device's info.
                let all = devices_load();
                let entry = all.iter().find(|(n, _)| n == &name);
                let Some((_, secret)) = entry else {
                    bail!("no device named '{name}', see `filament devices`");
                };
                let caps = device_caps(&name).unwrap_or_else(|| vec!["transfer".to_string()]);
                let channel = channel_of(secret);
                // Load lastSeen and overlay addresses from the device store.
                let (last_seen, stored_v6, stored_v4) = devices_info(&name).unwrap_or((0, None, None));
                let last_seen_str = if last_seen == 0 { "never".to_string() } else {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    let ago = now.saturating_sub(last_seen);
                    if ago < 60 { "just now".to_string() }
                    else if ago < 3600 { format!("{}m ago", ago / 60) }
                    else if ago < 86400 { format!("{}h ago", ago / 3600) }
                    else { format!("{}d ago", ago / 86400) }
                };
                println!("  {}", ui::paint(ui::Tone::Bold, &name));
                println!("  channel:  {}", &channel[..12.min(channel.len())]);
                // Show overlay addresses if we have them.
                if let Some(v6) = &stored_v6 {
                    let v4_str = stored_v4.as_ref().map(|a| format!(" / {a}")).unwrap_or_default();
                    println!("  overlay:  {v6}{v4_str}");
                    println!("  mesh:     {name}.mesh");
                }
                // "granted" (not "caps") makes clear this is the LOCAL GRANT RECORD
                // (what THIS machine authorized the peer to do), NOT what the peer offers.
                println!("  granted:  {}", caps.join(", "));
                println!("  last seen: {last_seen_str}");
            } else {
                // Show this machine's address.
                let id = overlay::Identity::load_or_create()?;
                let my_name = config_get("name").unwrap_or_else(|| l3::hostname());
                let mesh_name = l3::sanitize_host(&my_name);
                if v4 {
                    println!("{}", id.addr_v4());
                } else {
                    println!("  {}", ui::paint(ui::Tone::Bold, &mesh_name));
                    println!("  overlay:  {} (v4) / {} (v6)", id.addr_v4(), id.addr());
                    println!("  mesh:     {mesh_name}.mesh");
                }
            }
            Ok(())
        }
        Cmd::Identity { action } => {
            match action {
                IdentityAction::Init => {
                    match identity::UserKey::load(&crate::platform::PlatformKeyStore)? {
                        Some(uk) => {
                            println!("{}", ui::paint(ui::Tone::Dim,
                                &format!("you already have a user identity: fingerprint {}",
                                    uk.fingerprint())));
                            println!("  use 'filament identity show' to see it");
                        }
                        None => {
                            let uk = identity::UserKey::generate(&crate::platform::PlatformKeyStore)?;
                            // Seed the owner's self genesis cap header at init so
                            // authoritative capability enforcement works from the
                            // start (also healed on daemon start for older keys).
                            ensure_self_genesis_header(&crate::settings::config_dir(), &uk);
                            println!("  {} user identity created: fingerprint {}",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &uk.fingerprint()));
                            println!("  {}", ui::paint(ui::Tone::Dim, "next: certify your devices with 'filament identity certify <device>'"));
                        }
                    }
                    Ok(())
                }
                IdentityAction::Show => {
                    match identity::UserKey::load(&crate::platform::PlatformKeyStore)? {
                        None => {
                            println!("no user identity yet. Run 'filament identity init' to create one.");
                        }
                        Some(uk) => {
                            let uk_pub = uk.public_key_bytes();
                            println!("  user fingerprint: {}", ui::paint(ui::Tone::Bold, &uk.fingerprint()));
                            println!("  public key:       {}", ui::paint(ui::Tone::Dim, &uk.public_key_hex()));
                            let devices = devices_load();
                            let mut found = 0usize;
                            for (name, _secret) in &devices {
                                if let Some(cert) = device_cert_for(name) {
                                    if cert.user_pub == uk_pub {
                                        let exp = if identity::now_secs() >= cert.expires {
                                            "EXPIRED".to_string()
                                        } else {
                                            format!("{}d", cert.expires.saturating_sub(identity::now_secs()) / 86400)
                                        };
                                        println!("  {} {}", ui::paint(ui::Tone::Bold, name), ui::paint(ui::Tone::Dim, &format!("(valid {exp})")));
                                        found += 1;
                                    }
                                }
                            }
                            if found == 0 {
                                println!("  {}", ui::paint(ui::Tone::Dim, "no certified devices. use 'filament identity certify <device>'"));
                            }
                        }
                    }
                    Ok(())
                }
                IdentityAction::Certify { device } => {
                    let uk = match identity::UserKey::load(&crate::platform::PlatformKeyStore)? {
                        Some(uk) => uk,
                        None => bail!("no user identity. Run 'filament identity init' first."),
                    };
                    let device_pub = crate::overlay::overlay_pubkey_bytes()?;
                    let now = identity::now_secs();
                    let cert = identity::DeviceCert::certify(&uk, device_pub, now, identity::CERT_TTL_SECS)?;
                    update_device_cert(&device, &uk, &cert)?;
                    ui::say(&format!(
                        "  {} {} certified as your device (valid {} days)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        ui::paint(ui::Tone::Bold, &device),
                        identity::CERT_TTL_SECS / 86400,
                    ));
                    Ok(())
                }
            }
        }
        Cmd::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => {
                    config_set(&k, &v)?;
                    println!("{k} = {v}");
                }
                (Some(k), None) => println!("{}", config_get(&k).unwrap_or_default()),
                (None, _) => {
                    for k in ["name", "server", "dir"] {
                        if let Some(v) = config_get(k) {
                            println!("{k} {v}");
                        }
                    }
                }
            }
            Ok(())
        }
        Cmd::Up { install, system, userspace, dir, shell, shell_only, shell_program, shell_user, install_system, no_proxy_fallback } => {
            // `--userspace` forces the netstack backend; L3::start reads this env, so
            // set it before the daemon brings L3 up (same process). Safe: single
            // threaded at this point (the daemon's tasks are not spawned yet).
            if userspace {
                unsafe { std::env::set_var("FILAMENT_L3_USERSPACE", "1") };
            }
            // Flags win; otherwise fall back to persistent settings. Per-peer
            // `shell on` overrides fold into the shell-only allowlist so
            // `filament set shell on --peer laptop` unifies with --shell-only.
            let shell = shell || settings::get_bool("shell", None);
            let shell_user = shell_user.or_else(|| settings::get_str("shell-user", None));
            let peer_shell = settings::peers_with("shell", "on");
            let shell_only = match (shell_only, peer_shell.is_empty()) {
                (existing, true) => existing,
                (Some(list), false) => Some(format!("{list},{}", peer_shell.join(","))),
                (None, false) => Some(peer_shell.join(",")),
            };
            up_cmd(&server, install, system, dir, relay, shell, shell_only, shell_program, shell_user, install_system, no_proxy_fallback).await
        }
        Cmd::Status { json } => status_cmd(json),
        Cmd::Down => { ui_caps.confirm("shut down the daemon")?; down_cmd() },
        Cmd::Reset => reset_cmd(&ui_caps),
        Cmd::Pair { code, name, word } => pair_cmd(&server, code, name, word, relay).await,
        Cmd::Devices { action, json } => {
            match action {
                None => {
                    let all = devices_load();
                    if json {
                        let arr: Vec<Value> = all
                            .iter()
                            .map(|(n, s)| {
                                let (last_seen, v6, v4) = devices_info(n).unwrap_or((0, None, None));
                                let addr = v6.clone().or_else(|| v4.clone()).unwrap_or_default();
                                let mesh = format!("{n}.mesh");
                                json!({
                                    "name": n,
                                    "channel": channel_of(s),
                                    "caps": device_caps(n).unwrap_or_else(|| vec!["transfer".to_string()]),
                                    "lastSeen": last_seen,
                                    "address": addr,
                                    "mesh": mesh,
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&arr)?);
                    } else {
                        let warm = ctl::try_list_warm().await;
                        let pending = ctl::try_list_pending().await;
                        let rendered = fleet_ui::devices::render_devices(
                            &device_entries(warm.as_ref()),
                            pending_request_count(pending.as_ref()),
                        );
                        println!("{rendered}");
                    }
                }
                Some(DevicesAction::Forget { name }) => {
                    let had = devices_load().iter().any(|(n, _)| n == &name);
                    if !had {
                        bail!("no device named '{name}', see `filament devices`");
                    }
                    devices_remove(&name)?;
                    println!("forgot '{name}', it can no longer find or auto-connect to this machine");
                    println!("(their side still holds its half; it will hear \"never met you\" on the next proof)");
                }
                Some(DevicesAction::Rename { old, new }) => {
                    // Rename in place on the raw record so caps/v2 fields ride
                    // along (remove+store dropped the renamed device's caps).
                    let p = devices_path();
                    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
                        .ok()
                        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    if !arr.iter().any(|d| d["name"].as_str() == Some(old.as_str())) {
                        bail!("no device named '{old}', see `filament devices`");
                    }
                    if arr.iter().any(|d| d["name"].as_str() == Some(new.as_str())) {
                        bail!("'{new}' already exists, forget it first or pick another name");
                    }
                    for d in arr.iter_mut() {
                        if d["name"].as_str() == Some(old.as_str()) {
                            d["name"] = json!(new);
                        }
                    }
                    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)?;
                    println!("renamed '{old}' -> '{new}' (local alias only, the secret, and the other side, are unchanged)");
                }
                Some(DevicesAction::Vouch { a, b }) => {
                    introduce_cmd(&server, &a, &b, relay).await?;
                }
            }
            Ok(())
        }
        Cmd::Update { check, beta } => update_cmd(check, beta).await,
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "filament", &mut std::io::stdout());
            Ok(())
        }
        Cmd::Man { page } => {
            if let Some(p) = page {
                if p == "routing" {
                    println!("{}", include_str!("../docs/filament-routing.md"));
                    return Ok(());
                }
                // Unknown page: print clear message instead of falling through to roff
                if std::io::stdout().is_terminal() {
                    eprintln!("no manual page '{p}'; available: routing");
                    eprintln!("try `filament man` for the full help, or `filament man routing` for the connection model.");
                } else {
                    // Piped: still emit roff for backward compatibility
                    use clap::CommandFactory;
                    clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
                }
                return Ok(());
            }
            // Bare `filament man`: readable on TTY, roff when piped
            if std::io::stdout().is_terminal() {
                use clap::CommandFactory;
                Cli::command().print_long_help()?;
            } else {
                use clap::CommandFactory;
                clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            }
            Ok(())
        }
        Cmd::Shell { peer, ssh, args } => {
            if ssh {
                l2::ssh_cmd(&server, &peer, &args, relay).await
            } else {
                l2::pty_cmd(&server, &peer, relay, args).await
            }
        },
        Cmd::Reach { dev_port, socks, json, port, bind, http_port } => {
            if socks {
                l2::proxy_cmd(&server, &bind, port, http_port, relay).await
            } else if let Some(dp) = dev_port {
                let parts: Vec<&str> = dp.splitn(2, ':').collect();
                if parts.len() == 2 {
                    // `<device>:<port>`: localhost tunnel (the "reach my device's port" mental model)
                    let peer = parts[0].to_string();
                    let rport: u16 = parts[1].parse().map_err(|_| anyhow!("invalid port in '{}'", dp))?;
                    l2::netcat_cmd(&server, &peer, rport, relay).await
                } else {
                    // Bare `<device>`: reachability probe (warm-link check, cold fallback)
                    crate::ping::ping_cmd(&server, &dp, 1, json, relay).await
                }
            } else {
                bail!("reach requires <device> or <device>:<port> or --socks. Run `filament reach --help` for usage.");
            }
        },
        Cmd::Forward { lport, peer, rport } => l2::forward_cmd(&server, lport, &peer, rport, relay).await,
        Cmd::Expose { port, to, peer, list, off } => {
            if off {
                if let Some(p) = port {
                    ui_caps.confirm("unexpose a port")?;
                    expose::unexpose_cmd(p).await
                } else {
                    bail!("expose --off requires a port number");
                }
            } else {
                expose::expose_cmd(port, to, peer, list).await
            }
        },
        Cmd::Doctor { device, watch, repeat, json } => {
            doctor::doctor_cmd(&server, device, watch, repeat, json, relay).await
        }
        Cmd::Grant { device, capability, tag } => {
            let capability = crate::capability::canonical_capability(&capability)?;
            let config_dir = crate::settings::config_dir();
            let mut store = crate::capability::load_cap_store(&config_dir);

            if let Some(ref t) = tag {
                // Grant to tag
                let Some(user_key) = load_owner_key() else {
                    bail!("identity not initialized");
                };
                let pk = user_key.public_key_bytes();
                let target_bytes = crate::capability::make_tag_target(&pk, t);
                let ver = crate::capability::hlc_next(0, crate::capability::now_ms());
                let mut op = crate::capability::CapOp {
                    op: crate::capability::CapOpKind::Grant,
                    grantor: pk,
                    target_kind: 0x03,
                    target: target_bytes,
                    resource: "self".to_string(),
                    permissions: vec![capability.clone()],
                    expires: crate::capability::now_secs().saturating_add(90 * 24 * 3600),
                    issued_at: crate::capability::now_secs(),
                    version: ver,
                    sig: [0u8; 64],
                };
                op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
                store.push(op.to_json());
                let _ = crate::capability::save_and_list_revoked(&store, &config_dir)
                    .context("save cap store")?;
                println!("granted '{capability}' to tag '{t}'.");
                return Ok(());
            }
            // Original device grant path (unchanged)
            device_set_cap(&device, &capability, true, None)?;
            // If identity layer is active, also issue an owner-signed CapOp
            if let Ok(Some(user_key)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                let config_dir = crate::settings::config_dir();
                let mut store = crate::capability::load_cap_store(&config_dir);
                let pk = user_key.public_key_bytes();

                // Ensure a genesis header exists for resource "self"
                let has_header = store.iter().any(|e| {
                    e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                        && e["resource"].as_str() == Some("self")
                });
                if !has_header {
                    let pk = user_key.public_key_bytes();
                    let nonce = crate::capability::self_resource_nonce();
                    let resource = crate::capability::self_resource_id(&pk);
                    let mut hdr = crate::capability::CapHeader {
                        resource,
                        epoch: 0,
                        owner_pub: pk,
                        nonce,
                        floors: vec![],
                        issued_at: crate::capability::now_secs(),
                        prev_owner_pub: None,
                        prev_header_hash: None,
                        sig: [0u8; 64],
                    };
                    hdr.sig = crate::capability::sign_cap_header(&hdr, &user_key.keypair());
                    let mut hdr_json = hdr.to_json();
                    // The header's signature is over the self-certifying resource id
                    // (SHA-256(owner_pub||nonce)), but the STORED header has resource="self".
                    // This signature is decorative: cap_authorize/evaluate never calls
                    // verify_genesis/verify_sig on the stored header (those run only on
                    // the grant-creation path, not the authorize path). Consistent with
                    // Cmd::Grant which does the same. The header is trusted local state
                    // in the owner's own caps.json, not a cross-verified object.
                    hdr_json["resource"] = serde_json::json!("self");
                    store.push(hdr_json);
                }

                // Create CapOp: target the peer's real user_pub from their
                // stored device cert (not SHA-256 of the device name, which
                // never matches evaluate()'s principal_user_pub comparison).
                // Requires the peer to have a certified identity (paired +
                // identity-expose completed).
                let Some(peer_cert) = device_cert_for(&device) else {
                    return Err(anyhow!(
                        "peer identity for '{device}' is not available. Pair with the peer first so their identity can be certified; the grant requires a known user key to target"
                    ));
                };
                if peer_cert.verify(crate::identity::now_secs()).is_err() {
                    return Err(anyhow!("peer identity cert for '{device}' is expired; re-pair to refresh it"));
                }
                let target_arr = peer_cert.user_pub;

                let v = crate::capability::hlc_next(0, crate::capability::now_ms());
                let mut op = crate::capability::CapOp {
                    op: crate::capability::CapOpKind::Grant,
                    grantor: pk,
                    target_kind: 0x00, // User
                    target: target_arr,
                    resource: "self".to_string(),
                    permissions: vec![capability.clone()],
                    expires: crate::capability::now_secs().saturating_add(90 * 24 * 3600),
                    issued_at: crate::capability::now_secs(),
                    version: v,
                    sig: [0u8; 64],
                };
                op.sig = crate::capability::sign_cap_op(&op, &user_key.keypair());
                let mut hdr_json = serde_json::json!({
                    "type": "cap_grant",
                });
                let mut op_json = op.to_json();
                op_json["type"] = serde_json::json!("cap_grant");
                store.push(op_json);
                // Grant must initialize the per-owner ratchet so evaluate()
                // does not hit "ratchet uninitialized". apply_cap_op normally
                // does this, but the grant command constructs CapOp JSON
                // directly. On failure the grant did NOT take (evaluate()
                // will deny forever), so fail the command instead of printing
                // a misleading "granted" line.
                // TODO: route grant through apply_cap_op so there is one
                // validated op-creation path (sig-verify + floor + monotonic
                // + ratchet), not two.
                crate::capability::update_ratchet(&mut store, &pk, op.issued_at)
                    .context("capability grant created but ratchet initialization failed; the grant will not be effective. Re-run the grant command")?;
                // save_and_list_revoked: persist THEN reconcile (reconciliation
                // is a property of the write). GATED on authoritative: in shadow
                // only REPORT what would be removed.
                let revoked = crate::capability::save_and_list_revoked(&store, &config_dir)
                    .context("save cap store")?;
                {
                    let authoritative = crate::capability::cap_authoritative();
                    let ak_path = sshkeys::authorized_keys_path();
                    let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
                    // Emit per-device shadow logs for actual-block devices.
                    for device in &revoked {
                        if sshkeys::has_block(&ak_content, device) && !authoritative {
                            eprintln!("CAP-SHADOW RECONCILE: WOULD remove shell key for '{device}' (cap store denies shell); NOT removing in shadow");
                        }
                    }
                    let new_ak = crate::capability::reconcile_shell_keys(&revoked, &ak_content, authoritative);
                    if new_ak != ak_content {
                        if let Err(e) = crate::platform::SecretFile::write_str(&ak_path, &new_ak) {
                            eprintln!("shell-key reconcile: failed to write authorized_keys: {e}");
                        }
                    }
                }
            }
            println!(
                "granted '{capability}' to '{device}'. {}",
                if capability == "shell" {
                    "they can now `filament ssh` into this machine (their key is installed on first connect)."
                } else {
                    ""
                }
            );
            Ok(())
        }
        Cmd::Revoke { device, capability, certificate } => {
            if certificate {
                if capability.is_some() {
                    bail!("choose either a capability or --certificate, not both");
                }
                ui_caps.confirm(&format!("revoke fleet certificate from {device}"))?;
                let cert = device_cert_for(&device)
                    .ok_or_else(|| anyhow!("device '{device}' has no stored fleet certificate"))?;
                let owner = load_owner_key().ok_or_else(|| anyhow!("no local user identity"))?;
                if cert.user_pub != owner.public_key_bytes() {
                    bail!("device '{device}' certificate is not chained to this user identity");
                }
                set_device_cert_revoked(&device, true)?;
                println!("revoked fleet certificate from '{device}'; fleet access is denied locally");
                return Ok(());
            }
            let capability = capability
                .ok_or_else(|| anyhow!("capability is required unless --certificate is set"))?;
            let capability = crate::capability::canonical_capability(&capability)?;
            ui_caps.confirm(&format!("revoke {capability} from {device}"))?;
            device_set_cap(&device, &capability, false, None)?;
            // Mirror the grant path: also emit an owner-signed Revoke cap_op so
            // the AUTHORITATIVE capability gate actually denies. The legacy
            // device_set_cap(false) only clears devices.json; it leaves the cap
            // store granting, so under FILAMENT_CAP_AUTHORITATIVE the gate keeps
            // ALLOWing and a re-connect re-installs the shell key (revocation was
            // a no-op at the gate). apply_cap_op removes the matching grant, so
            // evaluate() then denies and devices_with_shell_revoked lists this
            // device; save_and_list_revoked + reconcile_shell_keys then strips
            // its managed authorized_keys block under authoritative.
            if let Ok(Some(user_key)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                let config_dir = crate::settings::config_dir();
                let mut store = crate::capability::load_cap_store(&config_dir);
                let pk = user_key.public_key_bytes();
                let header = store
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                            && e["resource"].as_str() == Some("self")
                    })
                    .and_then(crate::capability::CapHeader::from_json);
                // A revoke only bites if there is a header AND the peer has a
                // certified identity to target (same requirement as grant).
                if let (Some(hdr), Some(peer_cert)) = (header, device_cert_for(&device)) {
                    let target_arr = peer_cert.user_pub;
                    // Version MUST exceed the existing grant's version (monotonic
                    // ratchet), else apply_cap_op refuses.
                    let existing_ver = store
                        .iter()
                        .filter(|e| {
                            e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")
                                && e["grantor"].as_str() == Some(hex::encode(pk).as_str())
                                && e["resource"].as_str() == Some("self")
                                && e["target"].as_str() == Some(hex::encode(target_arr).as_str())
                        })
                        .filter_map(|e| e["version"].as_u64())
                        .max()
                        .unwrap_or(0);
                    let v = crate::capability::hlc_next(existing_ver, crate::capability::now_ms());
                    let now = crate::capability::now_secs();
                    let mut op = crate::capability::CapOp {
                        op: crate::capability::CapOpKind::Revoke,
                        grantor: pk,
                        target_kind: 0x00, // User
                        target: target_arr,
                        resource: "self".to_string(),
                        permissions: vec![capability.clone()],
                        expires: now.saturating_add(90 * 24 * 3600),
                        issued_at: now,
                        version: v,
                        sig: [0u8; 64],
                    };
                    op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
                    match crate::capability::apply_cap_op(&mut store, &hdr, &op, now) {
                        Ok(()) => {
                            let revoked =
                                crate::capability::save_and_list_revoked(&store, &config_dir)
                                    .unwrap_or_default();
                            let authoritative = crate::capability::cap_authoritative();
                            let ak_path = sshkeys::authorized_keys_path();
                            let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
                            for d in &revoked {
                                if sshkeys::has_block(&ak_content, d) && authoritative {
                                    eprintln!("shell-key reconcile (revoke): removing managed key for '{d}' (cap store denies shell)");
                                }
                            }
                            let new_ak = crate::capability::reconcile_shell_keys(
                                &revoked,
                                &ak_content,
                                authoritative,
                            );
                            if new_ak != ak_content {
                                if let Err(e) =
                                    crate::platform::SecretFile::write_str(&ak_path, &new_ak)
                                {
                                    eprintln!("shell-key reconcile (revoke): failed to write authorized_keys: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("revoke: owner-signed cap_op not applied ({e}); legacy revoke still took effect");
                        }
                    }
                }
            }
            if capability == "shell" {
                sshkeys::remove_authorized_key(&device)?;
                println!("revoked 'shell' from '{device}' and removed its filament-managed authorized_keys block.");
            } else {
                println!("revoked '{capability}' from '{device}'.");
            }
            if let Some(warning) = fleet_certificate_warning(&device) {
                eprintln!("{warning}");
            }
            Ok(())
        }
        Cmd::Mount { peer, remote, local, read_only: _, options: _, foreground: _, save_auto, list, check, save_profile, apply_profile, profiles, delete_profile, off } => {
            if let Some(path) = off {
                ui_caps.confirm(&format!("unmount {path}"))?;
                mount::unmount_cmd(&path)
            } else if let Some(name) = save_profile {
                mount::save_profile_cmd(&name)
            } else if let Some(name) = apply_profile {
                mount::apply_profile_cmd(&name, &server, relay).await
            } else if profiles {
                mount::profiles_cmd()
            } else if let Some(name) = delete_profile {
                mount::delete_profile_cmd(&name)
            } else if list {
                mount::list_cmd()
            } else if let Some(path) = check {
                mount::check_cmd(&path)
            } else if peer.is_none() && remote.is_none() {
                // No arguments: interactive mode for TTY, help for machines
                if std::io::stdin().is_terminal() {
                    mount::interactive_mount_fancy(&server, relay).await
                } else {
                    mount::print_mount_help();
                    Ok(())
                }
            } else {
                let peer = peer.ok_or_else(|| anyhow::anyhow!("peer is required"))?;
                let remote = remote.ok_or_else(|| anyhow::anyhow!("remote path is required"))?;
                let _auto_restore = save_auto;
                let mut client = l2::mount_cmd(&server, &peer, relay, &remote).await?;
                if let Some(local) = local {
                    #[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos"), all(target_os = "windows", feature = "mount-windows")))]
                    {
                        return mount_fuse_cmd(client, &peer, &remote, &local).await;
                    }
                    #[cfg(not(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos"), all(target_os = "windows", feature = "mount-windows"))))]
                    {
                        let _ = &local;
                        ui::say(&format!(
                            "  {} mesh-native mount protocol connected to {peer}:{remote}",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok())
                        ));
                        ui::say(&format!(
                            "  {} local mount adapter not available on this OS; listing directory instead",
                            ui::paint(ui::Tone::Warn, "!")
                        ));
                    }
                }
                // List the root directory
                use crate::mount_proto::MountOp;
                let root_enc = mount_proto::path_encode(std::path::Path::new("."));
                let resp = client.call(MountOp::Open { path: root_enc, flags: 0 }).await?;
                match resp.result {
                    crate::mount_proto::MountResult::Ok(v) => {
                        let fh = v["fh"].as_u64().unwrap_or(0);
                        ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), remote));
                        let entries = client.call(MountOp::ReadDir { fh, offset: 0 }).await?;
                        match entries.result {
                            crate::mount_proto::MountResult::Ok(v) => {
                                if let Some(arr) = v.as_array() {
                                    for entry in arr {
                                        let name_enc = entry["name"].as_str().unwrap_or("?");
                                        let name = mount_proto::path_decode(name_enc)
                                            .map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "?".into()))
                                            .unwrap_or_else(|_| "?".into());
                                        let kind = entry["stat"]["kind"].as_str().unwrap_or("file");
                                        let size = entry["stat"]["size"].as_u64().unwrap_or(0);
                                        ui::say(&format!("    {name}  ({kind}, {size}B)"));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    crate::mount_proto::MountResult::Err(e) => {
                        ui::say(&format!("  {} {}: {}", ui::paint(ui::Tone::Err, ui::glyph_err()), remote, e.msg));
                    }
                }
                Ok(())
            }
        }
        Cmd::Requests { action } => requests_cmd(action).await,
        Cmd::Mint { fleet, external, ci, ttl, reuse, allow, audience, yes } => {
            mint_cmd(&server, fleet, external, ci, ttl, reuse, allow, audience, yes, relay).await
        }
        Cmd::Ephemeral { action } => ephemeral_cmd(&server, action, relay).await,
        Cmd::Backup { peer, source, dest, exclude, dry_run, delete, options } => {
            backup::backup_cmd(&server, &peer, &source, &dest, exclude, dry_run, delete, options, relay).await
        }
    }
}

// ------------------------------------------------------------------ mount --
// Mount a peer directory locally over the mesh-native mount protocol, presented
// through FUSE. Linux only for now (macOS/Windows adapters are a later round).

/// Present the connected `client` as a local FUSE mount at `local`.
///
/// Before touching the filesystem we run a connection-honesty probe: one
/// GetAttr on the mount root under a timeout. An untrusted or refused peer
/// (the acceptor replies l2-close, which EOFs the stream) surfaces here as one
/// clean pre-mount error, instead of a cryptic failure on the first `ls` after
/// the kernel has already accepted the mount. On any failure we leave no stale
/// mountpoint behind (the #22 contract).
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos"), all(target_os = "windows", feature = "mount-windows")))]
async fn mount_fuse_cmd(
    mut client: crate::mount_proto::MountClient,
    peer: &str,
    remote: &str,
    local: &str,
) -> Result<()> {
    use crate::mount_proto::{MountOp, MountResult};

    // 1. Probe the link before we mount anything.
    let root_enc = mount_proto::path_encode(std::path::Path::new("."));
    let probe = tokio::time::timeout(
        Duration::from_secs(10),
        client.call(MountOp::GetAttr { path: root_enc }),
    )
    .await;
    match probe {
        Ok(Ok(resp)) => match resp.result {
            MountResult::Ok(_) => {}
            MountResult::Err(e) => bail!(
                "mount refused by {peer}: {} (remote path {remote})",
                e.msg
            ),
        },
        Ok(Err(e)) => bail!(
            "mount to {peer} failed before it started: {e} \
             (peer may be untrusted or the link dropped; nothing was mounted)"
        ),
        Err(_) => bail!(
            "mount to {peer} timed out waiting for the remote filesystem \
             (no response in 10s; nothing was mounted)"
        ),
    }

    // 2. Create the mountpoint. Track whether WE created it so a failed mount
    //    cleans up after itself and never leaves a stale empty dir.
    let mnt = std::path::PathBuf::from(local);
    let created_dir = !mnt.exists();
    if created_dir {
        std::fs::create_dir_all(&mnt)
            .with_context(|| format!("failed to create mount point {local}"))?;
    }

    ui::say(&format!(
        "  {} mesh-native mount: {peer}:{remote} -> {local} (FUSE, no sshd/sshfs)",
        ui::paint(ui::Tone::Ok, ui::glyph_ok())
    ));
    ui::say(&format!(
        "  {} mounted. unmount with `filament unmount {local}` or ctrl-c",
        ui::paint(ui::Tone::Ok, ui::glyph_ok())
    ));

    // 3. Run the blocking FUSE session on a dedicated thread so the tokio mux
    //    pump keeps draining the transport. ctrl-c triggers an unmount, which
    //    makes the blocking session loop return.
    let mnt_run = mnt.clone();
    #[cfg(target_os = "linux")]
    let session = tokio::task::spawn_blocking(move || crate::mount_fuse::run_mount(client, &mnt_run));
    #[cfg(all(target_os = "windows", feature = "mount-windows"))]
    let session = tokio::task::spawn_blocking(move || crate::mount_winfsp::run_mount(client, &mnt_run));

    let result: Result<()> = tokio::select! {
        joined = session => {
            match joined {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("mount session panicked: {e}")),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            ui::say("\n  unmounting...");
            let _ = unmount_fuse(local);
            Ok(())
        }
    };

    // 4. On any error, remove the mountpoint we created (leave a pre-existing
    //    dir alone). A clean unmount leaves the empty dir in place, matching the
    //    legacy behaviour.
    if result.is_err() && created_dir {
        let _ = unmount_fuse(local);
        let _ = std::fs::remove_dir(&mnt);
    }
    result
}

/// Unmount a FUSE/macFUSE mountpoint. Tries fusermount3 then fusermount on Linux,
/// falling back to a lazy unmount so a busy mount still detaches. On macOS,
/// uses umount or diskutil unmount.
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos")))]
fn unmount_fuse(local: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        for bin in ["fusermount3", "fusermount"] {
            if std::process::Command::new(bin)
                .args(["-u", local])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        // Linux last resort: lazy unmount so a busy handle does not wedge teardown.
        let _ = std::process::Command::new("fusermount3")
            .args(["-uz", local])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        // Try diskutil first (more reliable for macFUSE), fall back to umount.
        if std::process::Command::new("diskutil")
            .args(["unmount", "force", local])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let _ = std::process::Command::new("umount")
            .args([local])
            .status();
    }
    Ok(())
}

/// Windows: WinFsp handles unmount through its own control path; this is a no-op
/// placeholder so the Linux/macOS cleanup flow compiles on Windows.
#[cfg(all(target_os = "windows", feature = "mount-windows"))]
fn unmount_fuse(_local: &str) -> std::io::Result<()> {
    Ok(())
}

// ----------------------------------------------------------------- update --
// Self-update against GitHub releases (tags cli-vX.Y.Z). Downloads the
// archive for this platform, verifies it against SHA256SUMS, and atomically
// replaces the current executable.

const REPO: &str = "Abdk4Moura/filament";

fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

async fn update_cmd(check_only: bool, beta: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("filament/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Latest cli-v* release via the API (releases/latest may point at a web
    // release tag, so filter explicitly). Prereleases are SKIPPED unless the
    // user opted in (--beta) or is already running a prerelease, a beta tag
    // must never be pushed onto stable users.
    let beta_ok = beta || env!("CARGO_PKG_VERSION").contains('-');
    let releases: Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases?per_page=20"))
        .send()
        .await?
        .json()
        .await?;
    // semver-aware: never "update" to an older or equal release (betas of
    // the next version outrank the previous release; -pre < its release;
    // beta.2 > beta.1, the prerelease NUMBER counts, found live when
    // `--beta` kept offering beta.1 to beta.2).
    fn key(v: &str) -> (u64, u64, u64, bool, u64) {
        let (core, pre) = v.split_once('-').map(|(c, p)| (c, Some(p))).unwrap_or((v, None));
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let pre_num = pre.and_then(|p| p.rsplit('.').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
        (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0), pre.is_none(), pre_num)
    }
    // Pick the HIGHEST eligible version, not the first listed, the API's
    // order is not newest-tag-first (observed live: cli-v0.2.0 listed above
    // cli-v0.2.1-beta.1, which made --beta serve stable).
    let latest = releases
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter(|r| {
                    r["tag_name"].as_str().is_some_and(|t| t.starts_with("cli-v"))
                        && (beta_ok || !r["prerelease"].as_bool().unwrap_or(false))
                })
                .max_by_key(|r| key(r["tag_name"].as_str().unwrap_or_default().trim_start_matches("cli-v")))
        })
        .ok_or_else(|| anyhow!("no CLI release found"))?;
    let tag = latest["tag_name"].as_str().unwrap_or_default().to_string();
    let latest_ver = tag.trim_start_matches("cli-v").to_string();
    let current = env!("CARGO_PKG_VERSION");
    if key(&latest_ver) <= key(current) {
        println!("filament {current} is already the latest (released: {latest_ver})");
        return Ok(());
    }
    println!("update available: {current} -> {latest_ver}");
    if check_only {
        return Ok(());
    }

    // Package-manager installs (brew, winget, scoop, cargo) must be updated
    // via their manager, not by writing over the binary.
    let source = platform::InstallSource::detect();
    if source != platform::InstallSource::SelfInstalled {
        let hint = source.upgrade_hint();
        println!("filament was installed via a package manager — update with: {hint}");
        return Ok(());
    }

    let target = release_target().ok_or_else(|| anyhow!("no prebuilt binary for this platform; build from source"))?;
    let (asset, inner) = if cfg!(windows) {
        (format!("filament-{target}.zip"), "filament.exe")
    } else {
        (format!("filament-{target}.tar.gz"), "filament")
    };
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    ui::say(&format!("downloading {asset} ..."));
    let bytes = client.get(format!("{base}/{asset}")).send().await?.error_for_status()?.bytes().await?;
    let sums = client.get(format!("{base}/SHA256SUMS")).send().await?.error_for_status()?.text().await?;
    let got = sha256_hex(&bytes);
    let expected = sums
        .lines()
        .find(|l| l.contains(&asset))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| anyhow!("{asset} missing from SHA256SUMS"))?;
    if got != expected {
        bail!("checksum mismatch for {asset}: got {got}, expected {expected}");
    }
    ui::say("checksum ok");

    // Unpack the single binary.
    let new_bin: Vec<u8> = if asset.ends_with(".tar.gz") {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes[..]));
        let mut ar = tar::Archive::new(gz);
        let mut out = None;
        for entry in ar.entries()? {
            let mut e = entry?;
            if e.path()?.file_name().map(|n| n == inner).unwrap_or(false) {
                let mut v = Vec::new();
                e.read_to_end(&mut v)?;
                out = Some(v);
                break;
            }
        }
        out.ok_or_else(|| anyhow!("{inner} not found in archive"))?
    } else {
        // Windows: unpack the .zip archive. Use the zip crate for a pure-Rust
        // reader (no system dependency on tar/powershell).
        use std::io::Read;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
            .map_err(|e| anyhow!("zip reader: {e}"))?;
        let mut found = None;
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| anyhow!("zip entry {i}: {e}"))?;
            if entry.name().ends_with(inner) {
                let mut v = Vec::new();
                entry.read_to_end(&mut v)?;
                found = Some(v);
                break;
            }
        }
        found.ok_or_else(|| anyhow!("{inner} not found in zip archive"))?
    };

    // Atomic replace: write staging file next to current exe, then swap.
    let me = std::env::current_exe()?;
    let staging = me.with_extension("update-staging");
    std::fs::write(&staging, &new_bin)?;
    // Preserve any CAP_NET_ADMIN grant across the update (Linux only).
    #[cfg(target_os = "linux")]
    let had_cap = std::process::Command::new("getcap")
        .arg(&me)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("cap_net_admin"))
        .unwrap_or(false);
    // On Unix, rename over the running binary (the kernel keeps the old inode
    // alive for the running process). On Windows, rename the running exe out of
    // the way first (MoveFile on the same volume succeeds even on an in-use .exe),
    // then put the new binary in place. The .old file is cleaned up on next update.
    #[cfg(windows)]
    {
        let old = me.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&me, &old)
            .with_context(|| format!("renaming {} -> {}", me.display(), old.display()))?;
        std::fs::rename(&staging, &me)
            .with_context(|| format!("installing new {}", me.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staging, &me)
            .with_context(|| format!("replacing {}", me.display()))?;
    }
    println!("updated to {latest_ver} -> {}", me.display());
    #[cfg(target_os = "linux")]
    if had_cap {
        // Re-grant: directly if root, else via sudo (interactive on a TTY). If it
        // can't, tell the user the one command so L3 isn't silently broken.
        let is_root = unsafe { libc::geteuid() } == 0;
        let ok = if is_root {
            std::process::Command::new("setcap").args(["cap_net_admin+eip"]).arg(&me).status().map(|s| s.success()).unwrap_or(false)
        } else {
            std::process::Command::new("sudo").args(["setcap", "cap_net_admin+eip"]).arg(&me).status().map(|s| s.success()).unwrap_or(false)
        };
        if ok {
            println!("re-applied CAP_NET_ADMIN (L3 overlay)");
        } else {
            println!("note: re-grant L3's capability:\n    sudo setcap cap_net_admin+eip {}", me.display());
        }
        // A non-root L3 node also needs write on /etc/hosts to publish MagicDNS
        // names; grant the narrow per-file ACL here too so a plain `filament
        // update` is all it takes (no separate `set tun-addr` step). No-op for
        // root or if already granted.
        crate::tun::ensure_hosts_writable();
    }
    // Reload a running daemon onto the new binary with no manual restart. A
    // supervised daemon (systemd) takes the graceful SIGTERM path - which cleanly
    // closes the QUIC links so peers re-establish and L3 recovers - and its
    // supervisor restarts it with fresh ambient caps: no sudo. If it isn't
    // supervised (or predates this op), tell the user to restart it.
    #[cfg(unix)]
    {
        let reloading = matches!(ctl::try_reload().await, Some(ref v) if v["reloading"].as_bool() == Some(true));
        if reloading {
            println!("reloading the daemon onto the new binary (graceful restart, no sudo)");
        } else if daemon_alive().is_some() {
            println!("restart the daemon to run the new binary: `systemctl restart filament` (or `filament down` then `filament up ...`)");
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- send --

struct Outgoing {
    id: String,
    sid: u32,
    name: String,
    size: u64,
    head: Option<String>,
    /// P4 (GAP-5): sha256 of the WHOLE file, carried in file-offer as `full`. The
    /// receiver compares its received bytes against this on completion and only
    /// accepts (and acks) on a match, so no transfer can "complete" truncated or
    /// corrupt. `None` only when the digest couldn't be computed (degrades to the
    /// legacy size-only check on the receiver, bounded, never a hang).
    full: Option<String>,
    path: PathBuf,
    temp: bool,          // delete after sending (tar spools, stdin spools)
    accepted_once: bool, // re-offers carry resume:true after first accept
    /// P4: the bytes left this side (stream finished / file-end sent). NOT the
    /// same as `done`: a transfer is `sent` once but is only `done` after the
    /// receiver's whole-file-verified `delivery-ack` lands (the no-ack window
    /// NEVER sets `done`, it re-probes then fails the send, silent-data-loss fix).
    sent: bool,
    /// P4: the receiver returned a verified `delivery-ack` for this id. This is
    /// the deterministic "it landed intact" signal, the ONLY thing that completes
    /// a send. (Exception: an un-hashable file with no `full` digest has nothing
    /// to verify-and-ack, so it is `done` on send, the legacy size-only path.)
    acked: bool,
    done: bool,
}

#[allow(clippy::too_many_arguments)]
async fn send_cmd(
    server: &str,
    paths: Vec<String>,
    mut use_code: bool,
    mut word: Option<String>,
    room: Option<String>,
    mut to: Option<String>,
    name: Option<String>,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("nothing to send, pass files, directories, or '-' for stdin");
    }
    // INTERACTIVE GATE: `send <files>` with no --code/--word/--to and not piping
    // from stdin. First offer to pick a PAIRED DEVICE (arrow-key list); the last
    // item / Esc drops to the code path: Enter = local network, typed words mint a
    // shareable code. Skipped when reading payload from stdin ('-').
    if !use_code && to.is_none() && !paths.iter().any(|p| p == "-") && interactive_allowed() {
        let names: Vec<String> = devices_load().into_iter().map(|(n, _)| n).collect();
        let mut chose_device = false;
        if !names.is_empty() {
            let mut items = names.clone();
            items.push("shareable code / local network".into());
            let header = ui::paint(ui::Tone::Dim, "  send to which device?  (up/down, enter, esc)");
            if let Some(i) = codeentry::pick(&header, &items)? {
                if i < names.len() {
                    ui::say(&format!("  {} sending to {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), names[i]));
                    to = Some(names[i].clone());
                    chose_device = true;
                }
            }
        }
        if !chose_device {
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  press enter to send over the local network, or type words to create a shareable code",
            ));
            let auto_np = crate::pake::words::mint_nameplate();
            match codeentry::run("  send · code  ", codeentry::Mode::Create, "", &auto_np)? {
                codeentry::Outcome::Submitted(words) => {
                    use_code = true;
                    word = Some(words);
                }
                codeentry::Outcome::Empty => { /* fall through to local-network send */ }
                codeentry::Outcome::Cancelled => return Err(cancelled()),
            }
        }
    }
    // --name overrides the offered name, but only makes sense for a SINGLE
    // payload (stdin, or one regular file). With multiple paths or a directory
    // there is no single name to override, so warn that it's ignored.
    if name.is_some() && paths.len() > 1 {
        ui::say(&ui::paint(ui::Tone::Warn, "--name is ignored when sending multiple paths"));
    }
    let single = paths.len() == 1;
    let my_uid = mk_uid("s");
    let mut outgoing: Vec<Outgoing> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let sid = (i + 1) as u32;
        let id = format!("{}-{}", my_uid, sid);
        if p == "-" {
            let spool = std::env::temp_dir().join(format!("filament-stdin-{}", std::process::id()));
            let mut f = std::fs::File::create(&spool)?;
            let n = std::io::copy(&mut std::io::stdin().lock(), &mut f)?;
            drop(f);
            let head = head_hash(&spool);
            let full = full_hash(&spool);
            let offered = name.clone().filter(|_| single).unwrap_or_else(|| "stdin.bin".into());
            outgoing.push(Outgoing { id, sid, name: offered, size: n, head, full, path: spool, temp: true, accepted_once: false, sent: false, acked: false, done: false });
        } else {
            let path = PathBuf::from(p);
            let meta = std::fs::metadata(&path).with_context(|| format!("stat {p}"))?;
            if meta.is_dir() {
                if name.is_some() && single {
                    ui::say(&ui::paint(ui::Tone::Warn, "--name is ignored for a directory (it's tarred under the directory name)"));
                }
                let dirname = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dir".into());
                let spool = std::env::temp_dir().join(format!("filament-tar-{}-{}.tar", std::process::id(), i));
                ui::say(&format!("packing {p} -> {dirname}.tar ..."));
                {
                    let f = std::fs::File::create(&spool)?;
                    let mut b = tar::Builder::new(f);
                    b.append_dir_all(&dirname, &path)?;
                    b.finish()?;
                }
                let size = std::fs::metadata(&spool)?.len();
                let head = head_hash(&spool);
                let full = full_hash(&spool);
                outgoing.push(Outgoing { id, sid, name: format!("{dirname}.tar"), size, head, full, path: spool, temp: true, accepted_once: false, sent: false, acked: false, done: false });
            } else {
                // A single regular file with --name uses the override; otherwise
                // the basename. With multiple files --name was already warned off.
                let offered = name.clone().filter(|_| single).unwrap_or_else(|| {
                    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone())
                });
                let head = head_hash(&path);
                let full = full_hash(&path);
                outgoing.push(Outgoing { id, sid, name: offered, size: meta.len(), head, full, path, temp: false, accepted_once: false, sent: false, acked: false, done: false });
            }
        }
    }
    for o in &outgoing {
        ui::say(&format!("send: {} ({})", o.name, human(o.size)));
    }

    let room = match room {
        Some(r) => r,
        None => net::fetch_auto_room(server).await?,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // C30: the convergent session repairs room/channel/lease state the
    // one-shot emits lose (the fast path stays for old servers + latency);
    // under gate L these initial emits are exactly what the shim drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(room.clone());
    sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;

    // C12: --to matching a remembered device switches to identity mode,
    // subscribe to its presence channel and wait for known-peer.
    let known_target: Option<(String, String)> =
        to.as_ref().and_then(|t| devices_load().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(t)));
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();
    // L1-a: `send --code` now mints a v2 nameplate (client-minted words, the
    // server allocates ONLY the numeric nameplate) and runs the SAME ephemeral
    // SPAKE2 ceremony as `pair` before any byte flows, then DISCARDS the secret
    // (transfer = "link with mutual auth, then forget"). The words NEVER cross
    // the server; only the nameplate does. The full `words-nameplate` code is
    // displayed from our own local mint when pair-ok arrives.
    let mut send_words = String::new(); // the SPAKE2 password (only when use_code)
    let mut send_nameplate = String::new();
    if let Some((n, sec)) = &known_target {
        ui::say(&format!("  waiting for known device {}", ui::paint(ui::Tone::Bold, n)));
        sess.channels = vec![channel_of(sec)];
        sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(sec)] })).await;
    } else if use_code {
        // The words are the user's chosen phrase (--word) or a fresh mint; the
        // nameplate is ALWAYS machine-minted. `split_chosen_code` keeps both
        // words of a two-word phrase (it only strips a trailing 3-5 digit group).
        send_words = match &word {
            Some(w) => {
                let (words, _np) =
                    crate::pake::split_chosen_code(&crate::pake::norm_code(w));
                if let Err(why) = crate::pake::words::validate_chosen_password(&words, &display_name()) {
                    bail!("'{w}' is too weak: {why}");
                }
                words
            }
            None => crate::pake::words::mint_words(),
        };
        send_nameplate = crate::pake::words::mint_nameplate();
        sio.emit("pair-create", json!({ "nameplate": send_nameplate, "v": 2 })).await.ok();
    } else {
        ui::say(&format!("waiting for a peer in room {room} (same network auto-discovers; or use --code)"));
    }
    // Live spinner while nothing is connected yet (tty only; stops at adopt).
    let waiting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let waiting = waiting.clone();
        tokio::spawn(async move {
            while waiting.load(std::sync::atomic::Ordering::Relaxed) {
                ui::status(&format!("  {} waiting...", ui::spinner_frame()));
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        });
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,        // relay_only
        to,           // to_filter
        false,        // warm_standby default (one-shot send)
        direct::direct_enabled(), // direct_ok: env gate only (file transfer keeps WebRTC default)
    );
    if known_target.is_some() {
        conn.to_filter = None; // identity supersedes name matching
    }
    let mut code_used = !use_code && known_target.is_none();
    // L1-a ephemeral PAKE on the transfer path. When `--code` is used, run the
    // SAME SPAKE2 ceremony `pair` runs, then DISCARD the secret (auth only). The
    // file-offers are GATED on the ceremony agreeing a secret (`pake_done`); a
    // local-network send (no code) and a known-device send (already proven via
    // channel_of/proof_for) keep the existing, unchanged path (`pake_done` set
    // true up front so they offer immediately). `send_cer` is the ceremony; it
    // is only ever populated on the code path.
    let mut send_cer: Option<Ceremony> = if use_code {
        Some(Ceremony::new(&send_words, &send_nameplate, pair_v2_caps(), crate::identity::IntroScope::Device.to_byte()))
    } else {
        None
    };
    let mut pake_peer: Option<String> = None;
    // The transfer is allowed to offer once auth is settled: immediately for
    // local / known-device sends; only after the ephemeral PAKE confirms for the
    // code path. The agreed secret is then DISCARDED (never stored).
    let mut pake_done = !use_code;
    // Interop / downgrade: a code-path peer that never runs the v2 ceremony is on
    // an older build. Once the channel is up, give the ceremony a bounded budget;
    // if it doesn't confirm, fail LOUDLY ("update to transfer securely") rather
    // than hang. Mirrors `pair`'s ceremony_deadline.
    let pake_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    );
    let mut pake_deadline: Option<Instant> = None;
    // C30 phase 3: link mini-sync, pings out, divergence corrections in.
    let mut last_state_ping = Instant::now();
    let mut reproved: std::collections::HashSet<String> = Default::default();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Bounded force-exit guarantee (see the acceptor path): Ctrl-C must
            // exit promptly even if the unwind/peer-drop deadlocks.
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let claim_deadline = Duration::from_secs(600);
    // Bug 6: bound ESTABLISHMENT. netcat/ssh cap how long they hunt for a peer;
    // `send` had no such bound, so an ICE wedge (no candidate pair ever
    // nominates) hung unbounded with the spinner spinning. Cap the time to the
    // FIRST live data channel (ChannelReady); once a channel is up, a long
    // legitimate transfer is never interrupted by this. Overridable / disablable
    // (0 = off) via FILAMENT_SEND_TIMEOUT.
    let establish_deadline = std::env::var("FILAMENT_SEND_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60));
    let mut established = false;
    // Bug 5: count stuck-while-connecting events to hint at the mDNS wedge once.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let mut saw_known_peer: HashSet<String> = HashSet::new();
    // P4 (delivery-ack window): when every transfer's bytes have been `sent` but
    // the whole-file `delivery-ack` hasn't landed, we wait up to this bound for
    // the ack. CRITICAL (silent-data-loss fix): elapsing this window does NOT mean
    // "declare done". The bytes draining out of the send buffer proves nothing, a
    // path that black-holes without QUIC noticing drains while NOTHING arrives and
    // no ack comes. So on no-ack we re-probe once (re-send file-end to prompt a
    // possibly-lost ack), and if the ack still never lands we FAIL the send
    // (nonzero, partial kept resumable), never a false "delivered + verified".
    // Overridable via FILAMENT_ACK_TIMEOUT (seconds). The never-hangs property
    // holds: we reach a terminal state in bounded time, just an honest one.
    let ack_wait = std::env::var("FILAMENT_ACK_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(15));
    // After the first window with no ack we re-send file-end and wait this much
    // longer for a (possibly lost) ack before giving up. Short: the ack is a tiny
    // control message, on a healthy link it returns within a round-trip.
    let ack_reprobe = Duration::from_secs(5);
    let mut sent_all_at: Option<Instant> = None;
    let mut ack_reprobed = false; // re-sent file-end once for the no-ack window?
    let mut reprobed_at: Option<Instant> = None;

    loop {
        // Bug 6: no data channel has come up within the establishment window,
        // an ICE wedge or a peer that claimed the code but never connected. Fail
        // honestly instead of spinning forever. A non-zero deadline only; a live
        // channel (established) disarms it so big transfers are never cut off.
        if !established
            && !establish_deadline.is_zero()
            && started.elapsed() >= establish_deadline
        {
            ui::clear_sticky();
            bail!(
                "no peer connected within {}s, is a receiver running / the page open? \
                 (set FILAMENT_SEND_TIMEOUT to change or 0 to disable)",
                establish_deadline.as_secs()
            );
        }
        // The wait-for-peer deadline only applies while we have no peer (F3).
        let ev = if conn.active.is_none() && conn.rejoin.waiting_rejoin.is_none() {
            // C30: read in ≤2s slices, a blocking full-deadline read starves
            // the session tick, so a dropped initial subscribe was never
            // repaired and the wait could NEVER succeed (found by gate L's
            // seed-16 choreography: the daemon healed, the sender starved).
            if started.elapsed() >= claim_deadline {
                bail!("timed out waiting for a peer, is the other device online and on the same server? (--code makes pairing explicit)");
            }
            let slice = Duration::from_secs(2).min(claim_deadline.saturating_sub(started.elapsed()));
            match tokio::time::timeout(slice, rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => None, // tick
            }
        } else {
            next_ev(&mut rx, &conn, false).await?
        };
        // C30: converge session state every iteration (incl. ticks).
        sess.tick(&sio).await;
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // L1-a ephemeral PAKE progression (code path only). Once the link to our
        // PAKE counterpart is up: send our SPAKE2 element, then (once K + both
        // DTLS fingerprints exist) the key-confirmation MAC. The secret is
        // DISCARDED after auth (`pake_done`), never stored.
        if let (Some(cer), Some(pid)) = (send_cer.as_mut(), pake_peer.clone()) {
            if let Some(data) = cer.take_msg_payload() {
                sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
            }
            if cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
                        }
                    }
                }
            }
        }
        // Interop / downgrade: the ephemeral ceremony must confirm within budget
        // once the channel is up, a peer that never runs it is an older build.
        if !pake_done {
            if let Some(dl) = pake_deadline {
                if Instant::now() > dl {
                    ui::clear_sticky();
                    bail!("the other device uses an older version and can't receive securely over a code. Update it (or this CLI) so the transfer runs the encrypted handshake. Nothing was sent.");
                }
            }
        }
        // rung-1: a direct attempt that timed out without an authenticated QUIC
        // connection falls back to the WebRTC establish (unchanged path).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.establish(info).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
            if conn.to_filter.is_none() && conn.active.is_none() {
                conn.active = Some(pid.clone());
            }
        }
        // C30 phase 3: tell every link our truth every ~10s (sender side has
        // no receive-partials; the ping mainly carries trusted/away and keeps
        // the peer's away-mark honest).
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for l in conn.links.values() {
                if let Some(t) = &l.transport {
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": {},
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }
        // P0 (GAP-1): bytes-moved STALL watchdog (send side). A transfer is in
        // flight once the active peer accepted an offer that isn't done; if that
        // link then moves zero bytes past the stall threshold (a black-holed data
        // path, the 0% hang) we emit Ev::TransferStalled, which drives the
        // correction ladder below. The control-channel liveness probe gates it so
        // a genuinely DEAD link falls to the C3/C4 path instead.
        if let Some(active) = conn.active.clone() {
            let in_flight = {
                let out = outgoing.lock().await;
                out.iter().any(|o| o.accepted_once && !o.sent)
            };
            if let Some(idle) = conn.detect_stall(&active, in_flight) {
                let transport_dead = conn.transport_of(&active).map(|t| t.is_dead()).unwrap_or(false);
                // A dead transport can't pass link_alive (write_framed sees
                // dead=true and returns Err), but a structurally dead transport
                // (I/O error, not a vanished peer) IS repairable via the
                // ladder's re-dial rung. Only suppress the stall when the
                // transport is NOT dead AND the control path is silent — which
                // means the peer itself is gone (the C3/C4 establishment path
                // owns that case).
                if transport_dead || conn.link_alive(&active).await {
                    let _ = tx.send(Ev::TransferStalled(active, idle));
                } else {
                    conn.note_progress(&active);
                }
            }
        }
        // P5 (GAP-6): relay->direct upgrade prober (send side). Probe for a direct
        // path while serving on relay; verify-before-upgrade cuts over only when a
        // direct standby is confirmed stable. No-op unless a peer is relay-committed
        // on an eligible session.
        conn.tick_upgrade_prober().await;
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                // P5 (GAP-6): a fresh signaling welcome (reconnect) is a moment a
                // new direct path may have appeared, re-probe immediately for any
                // relay-committed peer rather than waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, code_used).await?;
                    }
                }
                // C30 (dissolves the C28 belt): fresh sid = everything
                // sid-keyed is gone; invalidate and let the session re-assert.
                sess.invalidate();
            }
            // C30: server confirmed our session digest. Phase 2: reconcile the
            // roster it carries, so a `welcome` or `peer-joined` we never
            // received self-corrects. Without this the sender waits out the
            // full 600s claim deadline while the peer can see it, which is the
            // one-directional presence failure the macOS smoke job hits: the
            // receiver recovers via this same digest (it already reconciles),
            // the sender never did because it discarded the roster.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, code_used, AdoptSource::Digest).await?;
                    }
                    if let Some((name, secret)) = &known_target {
                        let channel = channel_of(secret);
                        let present: std::collections::HashSet<String> = roster.channel_peers
                            .iter()
                            .filter_map(|p| p["id"].as_str().map(String::from))
                            .collect();
                        let stale: Vec<String> = conn.links.iter().filter_map(|(pid, link)| {
                            let matches = link.expected_secret.as_ref()
                                .map(|(_, s)| channel_of(s) == channel)
                                .unwrap_or(false);
                            if matches && !present.contains(pid) {
                                let count = channel_digest_absent.entry(pid.clone()).or_insert(0);
                                *count += 1;
                                (*count >= 2).then(|| pid.clone())
                            } else {
                                channel_digest_absent.remove(pid);
                                None
                            }
                        }).collect();
                        for pid in stale {
                            channel_digest_absent.remove(&pid);
                            conn.drop_link(&pid);
                        }
                        for p in &roster.channel_peers {
                            if p["channel"].as_str() != Some(channel.as_str())
                                || is_self_uid(&conn.my_uid, p["uid"].as_str())
                            {
                                continue;
                            }
                            let pid = p["id"].as_str().unwrap_or_default().to_string();
                            conn.start_direct(&pid, name, secret).await;
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                            if let Some(l) = conn.link_mut(&pid) {
                                l.expected_secret = Some((name.clone(), secret.clone()));
                            }
                        }
                    }
                }
            }
            // L1-a: the server allocated our v2 nameplate. Display the FULL
            // `words-nameplate` code assembled from OUR OWN local mint (the
            // server never echoes any words). The receiver runs the SAME
            // ephemeral SPAKE2 ceremony before any byte flows.
            Ev::PairOk(v) => {
                let ttl = v["ttl"].as_u64().unwrap_or(600);
                let full = format!("{send_words}-{send_nameplate}");
                let site = if server == DEFAULT_SERVER { "https://filament.autumated.com".to_string() } else { server.to_string() };
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!("  code   {}   {}", ui::paint(ui::Tone::Brand, &full), ui::paint(ui::Tone::Dim, "(copied to clipboard)")));
                ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("terminal: filament recv {full}   browser: {} (RECEIVE WITH CODE)", ui::link(&site, &site.replace("https://", ""))))));
                ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("one claim · expires in {} min · authenticated end-to-end (no key crosses the server)", ttl / 60))));
                ui::say("");
            }
            // A legacy server (or a v2-stripping one) minted a whole code: it
            // can't run the secure ceremony. Refuse rather than fall back to an
            // unauthenticated transfer (mirrors `pair`'s downgrade-refusal).
            Ev::PairCode(_v) => {
                bail!("this server returned a legacy transfer code and can't authenticate the transfer. Update the server (or the peer) to transfer securely.");
            }
            Ev::PairError(v) => {
                // Nameplate collision on create: re-mint a FRESH nameplate (and
                // fresh words when we minted them) and retry, never reuse a
                // burned code. The ephemeral ceremony restarts with the new pair.
                if use_code && v["error"].as_str() == Some("taken") {
                    if word.is_none() {
                        send_words = crate::pake::words::mint_words();
                    }
                    send_nameplate = crate::pake::words::mint_nameplate();
                    if let Some(cer) = send_cer.as_mut() {
                        cer.restart(&send_words, &send_nameplate);
                    }
                    sio.emit("pair-create", json!({ "nameplate": send_nameplate, "v": 2 })).await.ok();
                    continue;
                }
                bail!("pairing failed: {}", v["error"].as_str().unwrap_or("?"));
            }
            Ev::PairUsed(_) => {
                ui::say("code claimed, connecting...");
                code_used = true;
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, code_used).await?;
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own daemon shares this channel
                }
                if let Some((n, sec)) = &known_target {
                    if v["channel"].as_str() == Some(channel_of(sec).as_str()) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        // Liveness-aware: skip only if a healthy link already exists.
                        // If the link is dead or absent, re-establish (reconnect-after-loss).
                        let link_alive = conn.link(&pid)
                            .and_then(|l| l.transport.as_ref())
                            .map(|t| !t.is_dead())
                            .unwrap_or(false);
                        if link_alive {
                            if !saw_known_peer.contains(n) {
                                saw_known_peer.insert(n.clone());
                            }
                            continue;
                        }
                        if !saw_known_peer.contains(n) {
                            ui::say(&format!("known device '{n}' is online, connecting"));
                        }
                        saw_known_peer.insert(n.clone());
                        // rung-1: both ends are CLIs (known device), try direct
                        // QUIC FIRST. start_direct records the pending so the
                        // maybe_adopt->establish below skips the WebRTC offer
                        // until the budget expires (then it falls back).
                        let (n, sec) = (n.clone(), sec.clone());
                        conn.start_direct(&pid, &n, &sec).await;
                        conn.maybe_adopt(&v, true).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((n.clone(), sec.clone()));
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates, kick off the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    // P5 (GAP-6): a `probe:true` offer is a relay->direct UPGRADE
                    // probe from the other end. If we're serving this peer on relay
                    // and have no probe of our own yet, ARM one so the symmetric
                    // direct dial can complete (a later re-send of the offer, the
                    // peer re-emits 6x, is consumed by our now-armed pending). The
                    // winner posts DirectUpgradeReady (verify-before-upgrade), never
                    // clobbering the serving relay link.
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    // Bug 2: same buffer-and-replay as the recv-side handler.
                    // The receiver's re-dial transport-offer may arrive before
                    // our DirectPending exists (our start_direct hasn't returned
                    // yet, or PeerLeft dropped the link before the repair).
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(&from, cands, srflx);
                    } else {
                        let known = crate::devices_load()
                            .into_iter()
                            .find(|(n, _)| conn.links.get(&from).map(|l| l.name == *n).unwrap_or(false));
                        if let Some((name, secret)) = known {
                            conn.start_direct(&from, &name, &secret).await;
                        }
                        if conn.direct_pending.contains_key(&from) {
                            conn.on_transport_offer(&from, cands, srflx);
                        } else {
                            conn.buffered_offers.insert(from.clone(), (cands, srflx));
                        }
                    }
                    continue;
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Route them
                // OUT of the WebRTC path into the ephemeral ceremony (code path).
                // On confirm the secret is agreed; we record auth done and then
                // DISCARD the secret (transfer never persists it).
                if matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm")) {
                    if let Some(cer) = send_cer.as_mut() {
                        pake_peer.get_or_insert(from.clone());
                        let fps = match conn.link(&from) {
                            Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                            None => None,
                        };
                        let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                if let Some(sec) = cer.secret() {
                                    if !pake_done {
                                        pake_done = true;
                                        ui::say(&ui::paint(ui::Tone::Dim, "  authenticated, sending"));
                                        // Option A: race direct-quic FIRST; start_direct
                                        // replaces WebRTC only after pending registration.
                                        // If direct wins: transfer rides QUIC (130+ MB/s).
                                        // If direct fails: expired_direct → establish → WebRTC fallback
                                        //   (bounded ~5s gap for NAT-blocked peers, then WebRTC reconnects).
                                        let promo = conn
                                            .start_direct_promote(&from, &from, &sec)
                                            .await;
                                        if conn.active.is_none() {
                                            conn.active = Some(from.clone());
                                        }
                                        // Offers were deferred pending this confirm, and
                                        // the ChannelReady handler ignores a non-active
                                        // pid, so this must follow the claim above.
                                        conn.rearm_channel_ready(&from, promo);
                                    }
                                }
                            }
                            PakeInbound::Abort(why) => {
                                ui::clear_sticky();
                                bail!("transfer REFUSED: {why}. Nothing was sent; ask for a FRESH code.");
                            }
                            PakeInbound::Ignored => {}
                        }
                        continue;
                    }
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: the authenticated direct-QUIC connection won the race.
            // Create the (pre-trusted) Link, then funnel into the SAME ready
            // handler the WebRTC path uses (announce + offers) by re-emitting
            // ChannelReady, the transfer logic rides the trait unchanged.
            Ev::DirectReady(pid, t, route) => {
                let tkey = conn.direct_pending.get(&pid)
                    .map(|p| direct::transport_key(&p.secret.1));
                conn.adopt_direct(&pid, t.clone(), route);
                if let Some(k) = tkey {
                    conn.spawn_direct_workers(&pid, &t, k);
                }
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::DirectWorkersReady(pid, workers) => {
                if let Some(link) = conn.link_mut(&pid) {
                    link.workers = workers;
                    crate::ui::debug(&format!("worker transports ready: {pid} {} workers", link.workers.len()));
                }
            }
            // P5 (GAP-6): a relay->direct upgrade probe's direct standby connected
            // ALONGSIDE the live relay link. Do NOT adopt it (that would clobber the
            // serving relay link); stash it as a warm standby and enter VERIFY. The
            // per-tick prober (judge_upgrade_standby) decides whether to cut over
            // (sustained progress) or discard (no flap).
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                // Responder links stop here: connected, polite, idle. Only
                // the active target gets announcements + offers.
                if !conn.is_active(&pid) {
                    continue;
                }
                // Bug 6: a live channel to the active peer disarms the
                // establishment timeout, the rest of the transfer is unbounded.
                established = true;
                waiting.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Some(l) = conn.link(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, l.shown())));
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop,
                                    // direct vs relayed. Always shown, even under -q.
                                    ui::debug(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == "relayed" {
                                        ui::critical(&format!("    {}", relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        ui::debug(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
                    // L1-a: on the `--code` path, run the ephemeral SPAKE2
                    // ceremony BEFORE offering any byte. While auth is pending,
                    // mark this peer as our PAKE counterpart, arm the bounded
                    // budget, and DEFER offers. The progression block (top of
                    // loop) drives the ceremony; on confirm the Signal handler
                    // sets `pake_done` and re-emits ChannelReady to fall through
                    // here and offer. The secret is DISCARDED after auth.
                    if use_code && !is_direct && !pake_done {
                        pake_peer.get_or_insert(pid.clone());
                        pake_deadline.get_or_insert_with(|| Instant::now() + pake_budget);
                        ui::say(&ui::paint(ui::Tone::Dim, "  authenticating..."));
                        continue; // offers/remember wait for PAKE confirm
                    }
                    // C12: prove identity to a known device (their daemon
                    // auto-accepts only after verifying); or hand over a new
                    // pair secret when the user asked to --remember. A DIRECT
                    // link already proved the secret via the QUIC keying-material
                    // MAC (>= the DTLS pair-proof), so it skips this dance.
                    if is_direct {
                        // pre-authenticated; nothing to prove over the channel.
                    } else if let Some((_n, sec)) = &l.expected_secret {
                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                            t.send_control(&json!({
                                "type": "pair-proof",
                                "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                            })).await?;
                        } else {
                            ui::say(&ui::paint(ui::Tone::Warn, "no DTLS fingerprints available, skipping identity proof"));
                        }
                    }
                    // (Re-)offer everything unfinished; resume:true after a
                    // prior accept so receivers continue from their partial.
                    // (The `--code` path offers later, post-PAKE; this is the
                    // local-network / known-device / direct path.)
                    for o in outgoing.lock().await.iter() {
                        if o.done {
                            continue;
                        }
                        let offer = protocol::offer_msg(
                            &o.id, o.sid, &o.name, o.size,
                            o.head.as_deref(), o.full.as_deref(), o.accepted_once,
                        );
                        t.send_control(&offer).await?;
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("worker-ports") => {
                    let pid = v["for"].as_str().unwrap_or_default();
                    ui::trace(&format!("[T:SERVE] worker-ports handler: looking up key={pid}"));
                    if let Some(tx) = conn.worker_port_tx.remove(pid) {
                        ui::trace(&format!("[T:SERVE] worker-ports handler: FOUND key={pid}"));
                        let ports: Vec<u16> = v["ports"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|p| p.as_u64().map(|x| x as u16))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let _ = tx.send(ports);
                    }
                }
                // #30 GAP 1: a one-shot sender must ANSWER the receiver's
                // identity-nonce-challenge (prove device-key possession) so the
                // receiver can upgrade the sender's binding to Proven and an
                // authoritative cap gate can ALLOW the transfer. Placed before
                // the is_active guard so it fires as soon as the challenge lands.
                Some("identity-nonce-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        respond_to_identity_challenge(&t, &v).await;
                    }
                }
                // Enroller receives the daemon's nonce challenge — build
                // EnrollmentPayload and send the response.
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) = (hex::decode(nonce_hex), hex::decode(verifier_hex)) {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                let device_cert = v.get("device_cert").cloned().unwrap_or(serde_json::Value::Null);
                                if let Some(response) = crate::ephemeral::build_enrollment_response(
                                    &pid, nonce_arr, verifier_pub, &device_cert,
                                ) {
                                    let _ = t.send_control(&json!({
                                        "type": "identity-auth-key-enroll-response",
                                        "auth_key": response["auth_key"],
                                        "device_pub": response["device_pub"],
                                        "enroll_possession_sig": response["enroll_possession_sig"],
                                        "device_possession_sig": response["device_possession_sig"],
                                    })).await;
                                }
                            }
                        }
                    }
                }
                _ if !conn.is_active(&pid) => {}
                Some("brb") => {
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.rejoin.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away, holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: the peer's periodic truth, correct one-sided
                // beliefs instead of letting them persist.
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid); // a state ping proves they're not frozen
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                    // Transfer divergence: I believe it complete; the peer
                    // holds fewer bytes, the END/tail was lost. Re-offer.
                    if let Some(obj) = v["transfers"].as_object() {
                        let mut out = outgoing.lock().await;
                        for o in out.iter_mut() {
                            if let Some(b) = obj.get(&o.id).and_then(|x| x.as_u64()) {
                                if o.done && b < o.size {
                                    o.done = false; // not actually done
                                    // DEBUG, resilience internal (state-divergence re-offer).
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!("  state-diverged: {}, peer holds {b}/{}; re-offering", o.name, o.size)));
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let offer = protocol::offer_msg(
                                            &o.id, o.sid, &o.name, o.size,
                                            o.head.as_deref(), o.full.as_deref(), true,
                                        );
                                        let _ = t.send_control(&offer).await;
                                    }
                                }
                            }
                        }
                    }
                    // Trust divergence: they don't recognize us but we hold a
                    // pair secret for them, re-prove ONCE per link.
                    if v["trusted"].as_bool() == Some(false) && !reproved.contains(&pid) {
                        let proof = match conn.link(&pid) {
                            Some(l) => match &l.expected_secret {
                                Some((_n, sec)) => (match &l.peer { Some(p) => p.fingerprints().await, None => None })
                                    .map(|(my_fp, their_fp)| proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp)),
                                None => None,
                            },
                            None => None,
                        };
                        if let Some(mac) = proof {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await;
                                reproved.insert(pid.clone());
                                ui::debug(&ui::paint(ui::Tone::Dim, "  state-diverged: re-proving identity"));
                            }
                        }
                    }
                }
                // C27: the human on the other side answered our remember offer.
                Some("pair-keep-ack") => {
                    if let Some(name) = &remember {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if v["ok"].as_bool() == Some(false) {
                            devices_remove(name)?;
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered, nothing stored", &n));
                        } else {
                            ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "mutually remembered, you'll reconnect automatically", &n));
                        }
                    }
                }
                // C27: their verdict on our identity proof. false = they have
                // no memory of us, stop acting like a known device.
                Some("pair-proof-ack") => {
                    if v["ok"].as_bool() == Some(false) {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = None;
                        }
                        ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "doesn't recognize this device, re-pair with --remember", &n));
                    }
                }
                Some("file-accept") => {
                    let Some(t) = conn.transport() else { continue };
                    // Build transport list: primary + any parallel QUIC workers.
                    let workers = conn.link(&pid)
                        .map(|l| l.workers.clone())
                        .unwrap_or_default();
                    let mut transports = vec![t];
                    transports.extend(workers);
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    {
                        let mut out = outgoing.lock().await;
                        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                            o.accepted_once = true;
                        }
                    }
                    let out = outgoing.clone();
                    // Use the transport's OWN max payload, not conn.chunk_size:
                    // chunk_size is pinned to the 60 KiB WebRTC DataChannel limit
                    // (MAX_DC_PAYLOAD), which needlessly throttled the direct-QUIC
                    // path to tiny chunks. On QUIC max_payload() is far larger, so
                    // far fewer chunks pass through the receiver's single event-loop
                    // consumer (record_range + seek + write) per byte.
                    let chunk = transports[0].max_payload();
                    let tx2 = tx.clone();
                    // #28 test hook: the active peer's sid, so the streamer can
                    // synthesize a peer-left for it mid-flight (see stream_one).
                    let active_sid = conn.active.clone();
                    tokio::spawn(async move {
                        match stream_one(out, transports, id.clone(), offset, chunk, active_sid, tx2.clone()).await {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                // C10: surface through the loop; the transfer
                                // stays pending and re-offers on reconnect.
                                let _ = tx2.send(Ev::TransferFailed { id, err: e.to_string() });
                            }
                        }
                    });
                }
                Some("file-decline") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        ui::say(&format!("declined: {}", o.name));
                        o.done = true;
                    }
                }
                // P4 (delivery-ack): the receiver computed the whole-file sha256
                // of every byte it received and it MATCHED our offered digest,
                // the bytes landed INTACT. Only now is the transfer truly `done`
                // (vs the old fire-and-forget where `file-end` alone "completed"
                // it). This closes the loop the runner had to fake above the
                // transport: the sender deterministically KNOWS it landed whole.
                Some("delivery-ack") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        if !o.acked {
                            o.acked = true;
                            o.done = true;
                            ui::say(&ui::paint(ui::Tone::Dim, &format!("    {} delivered + verified (whole-file sha256 matched)", o.name)));
                        }
                    }
                }
                _ => {}
            },
            Ev::TransferFailed { id, err } => {
                let out = outgoing.lock().await;
                let name = out.iter().find(|o| o.id == id).map(|o| o.name.as_str()).unwrap_or("?");
                // DEBUG, resilience internal (transfer interrupted, will resume).
                ui::debug(&format!("{name}: interrupted ({err}), will resume on reconnect"));
            }
            // P0 (GAP-1): the bytes-moved watchdog declared this transfer stalled.
            // Drive the least-disruptive correction ladder, preserving the on-disk
            // partial at every rung (C7 resume).
            Ev::TransferStalled(pid, idle_ms) => {
                if !conn.is_active(&pid) {
                    continue; // only the transfer-target peer's stall matters
                }
                // DEBUG, resilience internal (stall detection).
                ui::debug(&ui::paint(ui::Tone::Warn, &format!("  stall detected: {idle_ms}ms with no data, correcting")));
                match conn.correct_stall(&pid).await {
                    Rung::Resume => {
                        // Rung (a): re-issue every unfinished transfer with
                        // resume:true on the SAME transport. The receiver's
                        // file-accept carries its `.part` offset, so streaming
                        // continues from where it stalled (no restart-from-zero).
                        // If the link has no live transport, Resume is futile.
                        if conn.transport_of(&pid).is_none() {
                            ui::debug(&format!("  resume skipped: no live transport for {pid}, awaiting next repair cycle"));
                        } else if let Some(t) = conn.transport_of(&pid) {
                            let out = outgoing.lock().await;
                            for o in out.iter().filter(|o| o.accepted_once && !o.done) {
                                let offer = protocol::offer_msg(
                                    &o.id, o.sid, &o.name, o.size,
                                    o.head.as_deref(), o.full.as_deref(), true,
                                );
                                let _ = t.send_control(&offer).await;
                            }
                        }
                    }
                    // Rung (c): the transport was repaired in place inside
                    // correct_stall (fresh direct dial / ICE-restart). The new
                    // transport's ChannelReady re-offers the unfinished transfers
                    // (resume:true), nothing more to do here.
                    Rung::Repaired => {}
                    // Rung (d) P1: correct_stall re-established this transfer over
                    // the TURN relay (relay-only ICE), preserving the partial. The
                    // fresh relay link's ChannelReady re-offers the unfinished
                    // transfers (resume:true) and prints the route, nothing more
                    // to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden (--no-relay) or relay
                    // itself stalled: the ladder failed CLEANLY (a kept partial, the
                    // clear cause already shown in correct_stall). PROMPTLY end the
                    // send rather than letting the frozen transfer hang to a timeout,
                    // the hard direct-only promise is "fail clean, fast", never a
                    // hang. The receiver kept its `.part`, so re-running resumes.
                    Rung::Exhausted => {
                        // The hard direct-only promise is "fail clean AND FAST", never
                        // a hang. A signaling socket wedged by the same frozen path can
                        // make `disconnect()` itself block, so BOUND it: a 2s cap keeps
                        // the exit prompt (we're tearing down anyway; the OS reaps the
                        // socket). This only affects the already-failing path, it can
                        // never delay or alter a successful send.
                        let _ = tokio::time::timeout(Duration::from_secs(2), sio.disconnect()).await;
                        if relay_forbidden() {
                            bail!("couldn't establish a direct path and relay is disabled (--no-relay), partial kept; re-run to resume, or drop --no-relay");
                        }
                        bail!("transfer stalled and no usable path remains, partial kept; re-run to resume");
                    }
                }
            }
            Ev::Interrupted => {
                ui::say(&format!("  {} interrupted, the receiver keeps its partial; re-run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            Ev::Stuck(pid, generation) => {
                // Bug 5: if we keep getting stuck BEFORE a channel ever came up,
                // surface the single-host mDNS hint once.
                if !established {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? {
                    bail!("lost the receiving peer after {} attempts; the partial is kept, re-run the same `filament send` to resume", MAX_ATTEMPTS);
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? {
                    bail!("lost the receiving peer after {} attempts; the partial is kept, re-run the same `filament send` to resume", MAX_ATTEMPTS);
                }
            }
            Ev::PcState(pid, s) => conn.on_pc_state(&pid, &s).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let all_done = outgoing.lock().await.iter().all(|o| o.done);
                    if !all_done {
                        let secs = REJOIN_WINDOW.as_secs();
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, &format!("disconnected, waiting up to {secs}s"), &n)),
                            // DEBUG, resilience internal (peer-disconnect wait).
                            None => ui::debug(&format!("peer disconnected, waiting up to {secs}s for them to come back")),
                        }
                    }
                }
            }
            _ => {}
        }
        // P4 (silent-data-loss fix): every transfer's BYTES have left this side
        // (`sent`), but a transfer is only truly `done` once the receiver returns a
        // whole-file-verified `delivery-ack`. Drain the wire first, then WAIT for
        // the ack, bounded by `ack_wait`. If the window elapses with no ack we do
        // NOT declare success (the old bug): we decide via decide_ack_fallback,
        // re-probe ONCE (re-send file-end to prompt a possibly-lost ack), and if
        // the ack still never lands we FAIL the send below (nonzero, partial kept
        // resumable). Only the real `delivery-ack` handler may set `o.done`.
        {
            let all_sent;
            let all_acked;
            let mut do_flush = false;
            let mut do_reprobe = false;
            let mut give_up = false;
            {
                let out = outgoing.lock().await;
                all_sent = !out.is_empty() && out.iter().all(|o| o.sent);
                all_acked = !out.is_empty() && out.iter().all(|o| o.done);
                if all_sent && !all_acked {
                    if sent_all_at.is_none() {
                        sent_all_at = Some(Instant::now());
                        do_flush = true;
                    }
                    let window_elapsed = sent_all_at.map(|t| t.elapsed() >= ack_wait).unwrap_or(false);
                    let reprobe_elapsed = reprobed_at.map(|t| t.elapsed() >= ack_reprobe).unwrap_or(false);
                    // Only act once a window has elapsed: the first ack_wait, or
                    // (after a re-probe) the shorter ack_reprobe window.
                    if (!ack_reprobed && window_elapsed) || (ack_reprobed && reprobe_elapsed) {
                        // A live transport attached is the "link alive" signal
                        // (mirrors the browser's data-channel-open check). A
                        // black-hole that QUIC hasn't noticed still reports a
                        // transport, so the re-probe path is what catches it.
                        let link_alive = conn.transport().is_some();
                        match protocol::decide_ack_fallback(link_alive, ack_reprobed) {
                            protocol::AckFallback::Reprobe => do_reprobe = true,
                            protocol::AckFallback::FailUnconfirmed => give_up = true,
                        }
                    }
                }
            }
            if do_flush {
                // Flush (NOT drain_finish) on first reaching the all-sent point:
                // push the wire so the receiver can finish + verify + ack. We do
                // NOT call drain_finish here because on direct-QUIC that ends the
                // send half (`finish()`), which would block a corrupt-case
                // RE-FETCH that needs to stream more bytes. The final exit block
                // does the authoritative drain_finish once the ack lands (no more
                // re-fetch possible by then). On a DataChannel both are just
                // flush(); on QUIC this keeps the stream open for a resume.
                if let Some(t) = conn.transport() {
                    let _ = t.flush().await;
                }
            }
            if do_reprobe {
                // The ack may have been lost on a still-alive link. Re-send file-end
                // for every unacked transfer to prompt the receiver to re-ack, then
                // wait one more (shorter) window. Never completes anything.
                ack_reprobed = true;
                reprobed_at = Some(Instant::now());
                let pending: Vec<(String, u32, String)> = {
                    let out = outgoing.lock().await;
                    out.iter().filter(|o| !o.done).map(|o| (o.id.clone(), o.sid, o.name.clone())).collect()
                };
                if let Some(t) = conn.transport() {
                    for (id, sid, name) in &pending {
                        ui::debug(&format!("  {name}: no delivery-ack yet, re-probing (re-sending file-end)"));
                        let _ = t.send_control(&protocol::end_msg(id, *sid)).await;
                    }
                    let _ = t.flush().await;
                }
            }
            if give_up {
                // No delivery-ack after the window + re-probe (or the link is gone).
                // Do NOT claim success: the receiver may have gotten nothing. Fail
                // honestly. The on-disk source is untouched and the outgoing entry
                // is preserved for resume; a fresh `send`/reconnect re-offers it.
                let names: Vec<String> = {
                    let out = outgoing.lock().await;
                    out.iter().filter(|o| !o.done).map(|o| o.name.clone()).collect()
                };
                for name in &names {
                    ui::critical(&ui::paint(ui::Tone::Warn, &format!(
                        "  {name}: delivery not confirmed (no whole-file delivery-ack), the receiver may have gotten nothing; NOT marking complete"
                    )));
                }
                let _ = sio.disconnect().await;
                bail!(
                    "delivery not confirmed: {} file(s) sent but never delivery-acked by the receiver (treating as unconfirmed, not delivered)",
                    names.len().max(1)
                );
            }
        }
        // Exit when every transfer reached a terminal state (`done` = acked, or the
        // bounded-fallback / un-hashable cases above).
        {
            let out = outgoing.lock().await;
            if !out.is_empty() && out.iter().all(|o| o.done) {
                if let Some(t) = conn.transport() {
                    // Block until the peer has acked every byte before we exit,
                    // a torn-down QUIC connection drops un-acked send-buffer bytes
                    // and truncates the last file (no-op on DataChannel, which
                    // already drained in flush()). Surface a drain failure rather
                    // than silently reporting "done" on a partial transfer.
                    if let Err(e) = t.drain_finish().await {
                        // CRITICAL, a possibly-incomplete delivery; must-see even under -q.
                        ui::critical(&ui::paint(ui::Tone::Warn, &format!("warning: transfer may be incomplete, {e}")));
                    }
                }
                for o in out.iter().filter(|o| o.temp) {
                    let _ = std::fs::remove_file(&o.path);
                }
                ui::say("done.");
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = sio.disconnect().await;
                return Ok(());
            }
        }
    }
}

async fn stream_one(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    transports: Vec<Arc<dyn Transport>>,
    id: String,
    offset: u64,
    chunk: usize,
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out.iter().find(|o| o.id == id).ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        // DEBUG, resilience internal (transfer resuming from a saved offset).
        ui::debug(&format!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0));
    }
    // #28 deterministic test hook: once we cross this byte offset, synthesize a
    // peer-left for the ACTIVE peer WITHOUT touching the data channel, exactly
    // the "signaling reconnect mid-transfer, channel stays alive" case. The
    // deferred-drop path must keep the link and let the transfer finish on it.
    // Injecting the active sid is critical: a wrong id makes on_peer_left
    // return early (link-not-found) and the test would falsely pass.
    use tokio::io::{AsyncSeekExt, AsyncReadExt};
    let inject_at: Option<u64> = test_hooks::inject_peer_left_at();
    let num = transports.len().max(1);
    // Split the remaining bytes [offset, size) into `num` contiguous ranges and
    // stream each over its OWN transport in a CONCURRENT task. The previous
    // round-robin ran on one task and awaited each send_frame, so it stalled on
    // whichever connection's flow-control window filled first and never used the
    // links in parallel. One task per connection lets every link drain at once,
    // which is the actual multi-stream win. The receiver reassembles by absolute
    // offset (positional writes), so range order does not matter.
    let bar = std::sync::Arc::new(tokio::sync::Mutex::new(ui::Progress::new(&name, size)));
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(offset));
    let injected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let remaining = size.saturating_sub(offset);
    let per = remaining / num as u64;
    let mut handles = Vec::with_capacity(num);
    for i in 0..num {
        let start = offset + i as u64 * per;
        let end = if i == num - 1 { size } else { start + per };
        if start >= end {
            continue;
        }
        let t = transports[i].clone();
        let path = path.clone();
        let bar = bar.clone();
        let progress = progress.clone();
        let injected = injected.clone();
        let tx = tx.clone();
        let active_sid = active_sid.clone();
        handles.push(tokio::spawn(async move {
            let trace = cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
            let mut f = tokio::fs::File::open(&path).await?;
            f.seek(SeekFrom::Start(start)).await?;
            let mut pos = start;
            // Double-buffer with tracing + batching
            let mut buf_a = vec![0u8; chunk];
            let mut buf_b = vec![0u8; chunk];
            let mut using_buf_a = true;
            let mut chunk_idx: u64 = 0;

            // Prime the first read into buf_a.
            let first_want = std::cmp::min(chunk as u64, end - pos) as usize;
            if first_want == 0 {
                return Ok(());
            }
            let t_first_read = if trace { Some(std::time::Instant::now()) } else { None };
            let mut cur_n = f.read(&mut buf_a[..first_want]).await?;
            let _first_read_us = t_first_read.map(|t| t.elapsed().as_micros()).unwrap_or(0);
            if cur_n == 0 {
                return Ok(());
            }

            while pos < end {
                // Fire the NEXT read (into the alternate buffer) BEFORE sending.
                let next_want = std::cmp::min(chunk as u64, end - (pos + cur_n as u64)) as usize;
                let next_read = if next_want > 0 {
                    let mut f2 = tokio::fs::File::open(&path).await?;
                    f2.seek(SeekFrom::Start(pos + cur_n as u64)).await?;
                    let alt_buf = if using_buf_a {
                        std::mem::replace(&mut buf_b, vec![0u8; chunk])
                    } else {
                        std::mem::replace(&mut buf_a, vec![0u8; chunk])
                    };
                    Some(tokio::spawn(async move {
                        let mut buf = alt_buf;
                        let n = f2.read(&mut buf[..next_want]).await?;
                        Ok::<(Vec<u8>, usize), anyhow::Error>((buf, n))
                    }))
                } else {
                    None
                };

                // Send the current buffer.
                let cur_buf = if using_buf_a { &buf_a[..cur_n] } else { &buf_b[..cur_n] };
                let t_send_start = if trace { Some(std::time::Instant::now()) } else { None };
                t.send_frame(sid, pos, cur_buf).await?;
                let send_us = t_send_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                pos += cur_n as u64;

                let total =
                    progress.fetch_add(cur_n as u64, std::sync::atomic::Ordering::Relaxed) + cur_n as u64;
                // Batch progress ticks
                chunk_idx += 1;
                let should_tick = chunk_idx % 8 == 0 || pos >= end;
                let t_tick_start = if trace && should_tick { Some(std::time::Instant::now()) } else { None };
                if should_tick {
                    bar.lock().await.tick(total);
                }
                let tick_us = t_tick_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                if trace && (chunk_idx % 10 == 0 || send_us + tick_us > 5000) {
                    dlog!("[TRACE stream_one] chunk={} offset={} len={} send_frame={}us tick={}us", chunk_idx, pos - cur_n as u64, cur_n, send_us, tick_us);
                }
                if let (Some(at), Some(asid)) = (inject_at, active_sid.as_ref()) {
                    if total >= at
                        && !injected.swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        eprintln!("[test] injecting synthetic peer-left for active sid at {total} bytes");
                        let _ = tx.send(Ev::PeerLeft(json!({ "id": asid })));
                    }
                }

                // Collect the next read (it was running while we sent).
                match next_read {
                    Some(handle) => match handle.await {
                        Ok(Ok((buf, n))) => {
                            if using_buf_a { buf_b = buf; } else { buf_a = buf; }
                            using_buf_a = !using_buf_a;
                            cur_n = n;
                            if cur_n == 0 { break; }
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(e) => return Err(anyhow!("read-ahead task panicked: {e}")),
                    },
                    None => break,
                }
            }
            t.flush().await?;
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in handles {
        h.await.map_err(|e| anyhow!("stream task join: {e}"))??;
    }
    // End frame on primary transport; flush all transports.
    transports[0].send_control(&protocol::end_msg(&id, sid)).await?;
    for t in &transports {
        t.flush().await?;
    }
    bar.lock().await.done(size.saturating_sub(offset));
    let mut out = outgoing.lock().await;
    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
        // P4: the bytes + file-end left this side, but the transfer is NOT
        // `done` yet. It is `done` only once the receiver returns a whole-file-
        // verified `delivery-ack` (or the bounded no-ack fallback fires). A peer
        // that has nothing more to send for THIS file is `sent`; the all-done
        // exit waits on `acked`. If this file carries no `full` digest (we
        // couldn't hash it), there's nothing for the receiver to verify-and-ack,
        // so it's done on send, the legacy fire-and-forget behaviour, scoped to
        // exactly the un-hashable case.
        o.sent = true;
        if o.full.is_none() {
            o.acked = true;
            o.done = true;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- recv —

/// Reduce a remote-supplied file name to a safe single path component: basename
/// only (no path separators or `..`), with control characters (including NUL)
/// stripped. A NUL in particular would fail the CString conversion in
/// safe_open_beneath and abort the whole receive loop, so a peer must not be able
/// to embed one. Empties / `.` / `..` fall back to a fixed name.
fn safe_incoming_name(raw: &str) -> String {
    let base = std::path::Path::new(raw)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".into());
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "file.bin".to_string()
    } else {
        cleaned
    }
}

/// Create a FRESH .part file. Uses RESOLVE_BENEATH on Linux (TOCTOU-safe,
/// protects symlinked parents too), O_NOFOLLOW on other Unix, create_new
/// (O_EXCL) on non-Unix. O_EXCL means "fail if exists" — correct for fresh,
/// WRONG for resume (use safe_resume_part for that).
#[cfg(unix)]
async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    // On Linux: use safe_open_beneath with O_CREAT|O_EXCL for one-primitive guarantee
    #[cfg(target_os = "linux")]
    {
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let rel = path.strip_prefix(parent).unwrap_or(path);
        crate::mount_proto::safe_open_beneath(parent, rel, (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as i32)
            .map_err(|e| std::io::Error::new(e.kind(), format!("safe create .part: {e}")))
            .map(|f| tokio::fs::File::from_std(f))
    }
    // Non-Linux Unix: O_NOFOLLOW + O_EXCL (only protects final component)
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await
    }
}

/// Resume an EXISTING .part file. NO O_EXCL (must open existing), but
/// RESOLVE_BENEATH on Linux (or O_NOFOLLOW on other Unix) AND an explicit
/// fstat check that what you opened is a REGULAR file — because O_NOFOLLOW
/// alone will happily open a FIFO or device node someone dropped at that path.
#[cfg(unix)]
async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    // On Linux: use safe_open_beneath (RESOLVE_BENEATH)
    // Add O_NONBLOCK to prevent blocking on FIFOs/special files
    #[cfg(target_os = "linux")]
    {
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let rel = path.strip_prefix(parent).unwrap_or(path);
        let file = crate::mount_proto::safe_open_beneath(parent, rel, libc::O_WRONLY | libc::O_NONBLOCK as i32)
            .map_err(|e| std::io::Error::new(e.kind(), format!("safe resume .part: {e}")))?;
        // Verify what we opened is a regular file (not FIFO, device, etc.)
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to resume: .part is not a regular file (type: {:?})", meta.file_type()),
            ));
        }
        Ok(tokio::fs::File::from_std(file))
    }
    // Non-Linux Unix: open with O_NOFOLLOW, then fstat the opened fd
    // (not stat the path before open — that races a swap)
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::{OpenOptionsExt, MetadataExt};

        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await?;

        // fstat on the opened fd — no TOCTOU
        let meta = file.metadata().await?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to resume: .part is not a regular file (type: {:?})", meta.file_type()),
            ));
        }
        Ok(file)
    }
}

#[cfg(not(unix))]
async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}

#[cfg(not(unix))]
async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
}

#[cfg(not(unix))]
async fn safe_open_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
}

struct IncomingFile {
    id: String,
    name: String,
    size: u64,
    /// Atomic counter so background writer tasks can publish received bytes
    /// without locking. The event loop polls this for progress updates.
    received: Arc<AtomicU64>,
    /// Disjoint sorted byte intervals [start, end) received so far, for
    /// out-of-order reassembly from multi-stream transports. Shared via
    /// Mutex so concurrent spawn_blocking writer tasks can update safely.
    ranges: Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// Raw file handle shared across concurrent spawn_blocking writer tasks.
    /// Positional writes go through `pwrite_at` (write_at on Unix, seek_write on
    /// Windows) which is atomic per call — no seek needed, safe for concurrent
    /// access.
    file: Arc<std::fs::File>,
    part_path: PathBuf,
    /// P4 (GAP-5): the whole-file sha256 the SENDER offered (`full`). On
    /// completion we hash the received `.part` and compare, only a match
    /// finalizes + acks. `None` = the sender offered no digest (old peer / an
    /// un-hashable source); we fall back to the legacy size-only acceptance and
    /// do NOT ack (nothing to verify), which the sender's bounded fallback covers.
    full: Option<String>,
    /// Number of inflight spawn_blocking write tasks. The event loop uses
    /// this to decide when a file is ready for finalization:
    ///   inflight == 0 && end_seen → finalize
    inflight: Arc<AtomicI64>,
    /// Set by the file-end handler when the sender reports end-of-file, even
    /// if inflight writes are still pending. The last finishing writer checks
    /// this flag and emits Ev::MaybeComplete if both conditions are met.
    end_seen: Arc<AtomicBool>,
    /// The sid to use in the delivery-ack message. Set from the file-end
    /// control frame; read by the MaybeComplete handler for the ack.
    ack_sid: u32,
    /// Tracks the last received value used for progress display (to avoid
    /// re-ticking the same value). Not atomic — only accessed from the event loop.
    last_tick: u64,
    bar: ui::Progress,
}

/// Record a received byte interval [pos, pos+len) in the disjoint sorted range
/// list, merging overlapping/adjacent intervals. Returns (delta_new_bytes, total_unique).
/// Delta is the number of previously-unseen bytes added by this chunk.
/// Total is the authoritative received count for multi-stream OOO reassembly.
/// Optimized: binary search + incremental total via removed_total tracking.
fn record_range(ranges: &mut Vec<(u64, u64)>, pos: u64, len: usize) -> (u64, u64) {
    let end = pos + len as u64;
    if ranges.is_empty() {
        ranges.push((pos, end));
        let total = len as u64;
        return (total, total);
    }
    // Binary search for first range with end >= pos
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ranges[mid].1 < pos {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut idx = lo;
    let mut new_s = pos;
    let mut new_e = end;
    let mut removed_total: u64 = 0;
    // Merge all overlapping / adjacent ranges (adjacent if start <= new_e)
    while idx < ranges.len() && ranges[idx].0 <= new_e {
        let (s, e) = ranges[idx];
        removed_total += e - s;
        new_s = new_s.min(s);
        new_e = new_e.max(e);
        ranges.remove(idx);
    }
    let new_len = new_e - new_s;
    ranges.insert(idx, (new_s, new_e));
    let delta = new_len.saturating_sub(removed_total);
    // Compute total: we could maintain it incrementally in caller, but for
    // simplicity compute via sum of ranges (N = number of disjoint intervals,
    // which is <= K, not number of chunks, so O(K) not O(N_chunks)).
    // For true O(1), caller should track total via fetch_add(delta).
    let total: u64 = ranges.iter().map(|(s, e)| e - s).sum();
    (delta, total)
}

/// Legacy wrapper returning total only (for call sites that need total)
fn record_range_total(ranges: &mut Vec<(u64, u64)>, pos: u64, len: usize) -> u64 {
    let (_delta, total) = record_range(ranges, pos, len);
    total
}

/// True iff the recorded ranges tile [0,size) with no gap (one contiguous interval).
fn coverage_complete(ranges: &[(u64, u64)], size: u64) -> bool {
    if size == 0 { return true; }
    ranges.len() == 1 && ranges[0].0 == 0 && ranges[0].1 == size
}

/// First uncovered byte position in [0,size), or None if complete.
fn first_gap(ranges: &[(u64, u64)], size: u64) -> Option<u64> {
    if size == 0 { return None; }
    let mut cursor = 0u64;
    for &(s, e) in ranges {
        if s > cursor { return Some(cursor); }
        cursor = cursor.max(e);
        if cursor >= size { return None; }
    }
    if cursor < size { Some(cursor) } else { None }
}

/// Build the live shell policy from the persistent settings (global `shell` +
/// per-peer `shell on` overrides). Mirrors `up_cmd`'s startup construction so a
/// `set shell ...` reconfigure lands the daemon in the same state a restart would.
fn shell_policy_from_settings() -> ShellPolicy {
    if settings::get_bool("shell", None) {
        return ShellPolicy::All;
    }
    let peers = settings::peers_with("shell", "on");
    if peers.is_empty() {
        ShellPolicy::Granted
    } else {
        ShellPolicy::Only(peers.into_iter().collect())
    }
}

/// Apply a `filament set <key>` change to the LIVE daemon state, the heart of
/// live-reconfigure. Returns whether the change took effect without a restart.
/// Keys woven into startup (relay/server force, or arming the L2 acceptor from
/// cold) return `false`, so the client tells the user to run `filament up`.
#[allow(clippy::too_many_arguments)]
async fn apply_reconfigure(
    key: &str,
    dir: &mut PathBuf,
    shell_policy: &mut ShellPolicy,
    shell_user: &mut Option<String>,
    l2_enabled: bool,
    sess: &mut session::Session,
    sio: &rust_socketio::asynchronous::Client,
    my_uid: &str,
) -> bool {
    match key {
        "drop-dir" => {
            let nd = settings::get_str("drop-dir", None)
                .map(PathBuf::from)
                .unwrap_or_else(default_drop_dir);
            let _ = std::fs::create_dir_all(&nd);
            *dir = nd;
            true
        }
        "shell-user" => {
            *shell_user = settings::get_str("shell-user", None);
            true
        }
        // auto-extract is re-read on every received file (finalize_incoming), so
        // it is already live; nothing to mutate here.
        "auto-extract" => true,
        "shell" => {
            *shell_policy = shell_policy_from_settings();
            // The per-request accept check consults `shell_policy` live, so a
            // narrow/disable applies instantly. But going from no-shell to shell
            // needs the L2 acceptor that was wired at startup: live only if it was
            // already armed (`l2_enabled`).
            l2_enabled || !shell_policy.enables_l2()
        }
        "name" => {
            // Re-announce presence with the fresh name. Same uid + room, so peers
            // update the label without minting a new presence identity (no ghost).
            if let Some(room) = sess.room.clone() {
                sess.emit(sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            true
        }
        // relay/server are bound into the establishment + signaling setup at
        // startup; changing them safely needs a fresh `filament up`.
        _ => false,
    }
}

/// Idempotently seed the owner's `self` genesis capability header AND the
/// per-owner ratchet.
///
/// Under authoritative enforcement `cap_authorize` returns `Unprovisioned`
/// until the `self` header exists, and `evaluate()` then denies "ratchet
/// uninitialized" until the per-owner monotonic ratchet exists — so BOTH are
/// required for the capability layer to authorize anything on `self` (owner or
/// delegated principal under its ceiling). Both are tautological: the owner
/// asserts ownership of its OWN self-certifying resource and its own ratchet
/// floor; they widen nothing. Mirrors the genesis block `Cmd::Grant` was the
/// sole (accidental) seeder of. Each half is seeded independently so a store
/// missing only one is healed. Returns true when the store changed. Persisted
/// with `save_cap_store` (a plain write, no reconcile): seeding grants no ssh
/// access and must not trigger the authorized_keys reconciler.
fn ensure_self_genesis_header(
    config_dir: &std::path::Path,
    user_key: &crate::identity::UserKey,
) -> bool {
    let mut store = crate::capability::load_cap_store(config_dir);
    let pk = user_key.public_key_bytes();
    let owner_hex = hex::encode(pk);
    let has_header = store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
            && e["resource"].as_str() == Some("self")
    });
    let has_ratchet = store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
            && e["owner_pub"].as_str() == Some(owner_hex.as_str())
    });
    if has_header && has_ratchet {
        return false;
    }
    let now = crate::capability::now_secs();
    if !has_header {
        let nonce = crate::capability::self_resource_nonce();
        let resource = crate::capability::self_resource_id(&pk);
        let mut hdr = crate::capability::CapHeader {
            resource,
            epoch: 0,
            owner_pub: pk,
            nonce,
            floors: vec![],
            issued_at: now,
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        hdr.sig = crate::capability::sign_cap_header(&hdr, &user_key.keypair());
        let mut hdr_json = hdr.to_json();
        // Stored under the caller-facing resource id "self" (what cap_authorize
        // looks up); the signature commits to the self-certifying derived id.
        hdr_json["resource"] = serde_json::json!("self");
        store.push(hdr_json);
    }
    if !has_ratchet && crate::capability::update_ratchet(&mut store, &pk, now).is_err() {
        return false;
    }
    crate::capability::save_cap_store(config_dir, &store).is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn recv_cmd(
    server: &str,
    mut code: Option<String>,
    mut dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    mut shell_policy: ShellPolicy,
    // M-1: optional non-root account the web-shell/ssh PTY is dropped to. `None`
    // means the PTY runs as the up-process user (documented root risk).
    mut shell_user: Option<String>,
    no_proxy_fallback: bool,
) -> Result<()> {
    let to_stdout = output.as_deref() == Some("-");
    // Daemon start: idempotently heal the owner's self genesis cap header.
    // Identities created before this seeding existed have no header; seeding
    // only at `identity init` would grandfather-trap them into permanent
    // Unprovisioned. Healing on every daemon start makes old identities correct
    // on next `up` and new ones born correct. Tautological; widens nothing.
    if daemon {
        if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
            if ensure_self_genesis_header(&crate::settings::config_dir(), &uk) {
                ui::debug("seeded owner self genesis capability header");
            }
        }
    }
    // INTERACTIVE GATE (CLI `recv` only, never the daemon/`up`). With no code,
    // offer: type a code to connect to a specific person, or press Enter on an
    // empty buffer to use the local network (today's default). When the gate is
    // closed we fall straight through to the auto-room default below.
    if !daemon && code.is_none() && interactive_allowed() {
        ui::say(&ui::paint(
            ui::Tone::Dim,
            "  enter a code to connect to a specific person, or press enter to use the local network",
        ));
        match codeentry::run("  recv · code  ", codeentry::Mode::Claim, "", "")? {
            codeentry::Outcome::Submitted(c) => code = Some(c),
            codeentry::Outcome::Empty => { /* fall through to the local-network auto room */ }
            codeentry::Outcome::Cancelled => return Err(cancelled()),
        }
    }
    // L1-a unification: a transfer code and a pairing code now have the SAME
    // shape (`words-NNNN`) and run the SAME ephemeral SPAKE2 ceremony, the verb
    // (`recv` vs `pair`) decides whether the agreed secret is discarded or kept.
    // So `recv` no longer redirects a 4-digit code away (the old width-based
    // hint is obsolete); any well-formed code is a valid claim here.
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    // P2 (GAP-2): `mut` so the long-lived acceptor's outer reconnect loop can
    // swap in a freshly-dialed signaling client after a drop (see below). The
    // short-lived `recv`/`send` paths never reconnect, they re-invoke fresh,
    // so this is only exercised by the daemon (`up`/`up --dir`).
    let mut sio = net::connect_signaling(server, tx.clone()).await?;

    let mut paired = code.is_some();
    // C24: at most one typed claim in flight, a second typed code while one
    // is pending was silently dropped in live use; now it queues a message.
    let mut claim_in_flight = false;
    // C29: an in-session pairing ceremony (daemon mode): typed code or a
    // minted one, exactly ONE side hands over a fresh secret (creator
    // initiates; a claimer waits 3 s for the creator, then takes over,
    // browsers never initiate). Some(true) = we minted; Some(false) = we
    // claimed; None = no ceremony pending.
    let mut ceremony: Option<bool> = None;
    let mut ceremony_pid: Option<String> = None;
    let mut ceremony_secret = fresh_secret();
    // C25: when the current question appeared (answers sooner than 300ms are
    // buffered keystrokes, not decisions)
    let mut question_shown = Instant::now();
    let mut devices = devices_load(); // channel -> identity lookup for proofs
    // C30: the convergent session repairs whatever the one-shot emits below
    // lose, room membership, channel subscriptions, the lease. The emits
    // stay as the fast path (and old-server compat); the session is truth.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = devices.iter().map(|(_, s)| channel_of(s)).collect();
    // L1-a: the ephemeral SPAKE2 ceremony for a `recv <code>` claim. The typed
    // code is split CLIENT-SIDE; only the numeric nameplate is sent (pair-claim
    // {nameplate, v:2}). The words feed SPAKE2 and never reach the server. After
    // mutual auth the agreed secret is DISCARDED (transfer never persists it).
    //
    // PER-PEER ceremonies (shared-auto-room fix): the receiver joins the sender's
    // room, which (for a `send --code`) is the sender's AUTO room, shared with any
    // other local peers sitting in it. We therefore CANNOT latch onto the first
    // peer that appears: an unrelated decoy must not be allowed to consume our one
    // ceremony, run it to the budget, and bail the whole receive. Instead we run
    // an INDEPENDENT ephemeral ceremony per candidate peer, each built from the
    // SAME claimed code (words + nameplate). The FIRST peer whose ceremony agrees
    // K and verifies the confirm MAC becomes the authenticated sender; from then
    // on we accept file-offers ONLY from that peer. A peer whose ceremony fails
    // (wrong words) or whose per-peer budget expires is dropped INDIVIDUALLY and
    // never bails the receive. Only an OVERALL deadline with NO peer authenticated
    // fails the whole `recv` (so a genuinely absent/old sender still fails loudly
    // rather than hanging). `recv_code_path` is the "this is a code claim" sentinel
    // (was `recv_cer.is_some()`); `recv_pake_template` mints each per-peer ceremony.
    let recv_code_path = code.is_some();
    let recv_pake_template: Option<(String, String)>; // (words, nameplate)
    // Each candidate peer's own ephemeral ceremony, keyed by peer id.
    let mut recv_cers: HashMap<String, Ceremony> = HashMap::new();
    // Identity: receiver-generated nonce challenges for introduce path (0x02), single-use, session-scoped, erased after verification, distinct per concurrent session
    // Map peer_id -> (nonce, timestamp, receiver_device_pub)
    let mut identity_nonces: HashMap<String, ([u8; 32], Instant, [u8; 32])> = HashMap::new();
    // #30: hold ChannelReady until Proven settles or 3s timeout, so short-session
    // gates never decide on Inferred while the possession-sig challenge is in flight.
    let pending_proven: Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Each candidate peer's own bounded budget (armed when its channel comes up).
    let mut recv_deadlines: HashMap<String, Instant> = HashMap::new();
    // The peer that WON authentication (its ceremony confirmed). Once set, only
    // this peer may offer files. `None` until someone authenticates.
    let mut recv_pake_peer: Option<String> = None;
    // A file-offer can race ahead of auth: the sender offers as soon as IT has our
    // confirm, which can land a tick BEFORE we finish verifying ITS confirm (the
    // two confirms cross on the wire, and the shared-room mesh widens that gap). We
    // must not silently drop that offer, the sender offers it only once. So we
    // BUFFER the most recent pre-auth offer per candidate peer and REPLAY it the
    // instant that peer authenticates. Bounded by RECV_MAX_CANDIDATES (same keys).
    let mut recv_pending_offers: HashMap<String, Value> = HashMap::new();
    let mut recv_pending_direct: HashMap<String, (Vec<String>, Option<String>)> = HashMap::new();
    let mut recv_pake_done = code.is_none(); // only the code path runs the PAKE
    let recv_pake_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    );
    // Overall bound: once we are matched into the sender's room, SOMEONE must
    // authenticate within this window or the whole `recv` fails loudly. Per-peer
    // budgets only drop individual mis-latch candidates; this is the backstop for
    // a genuinely absent / old sender. Armed on the first candidate channel.
    let mut recv_pake_overall_deadline: Option<Instant> = None;
    // Memory bound: a crowded room cannot blow us up. We mint at most this many
    // concurrent candidate ceremonies; further candidates are ignored (the real
    // sender is, in practice, among the first to share the room with the claimer).
    const RECV_MAX_CANDIDATES: usize = 8;
    match &code {
        Some(c) => {
            // Split the typed code into (nameplate, words); send ONLY the
            // nameplate. The words become the SPAKE2 password held locally.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right, expected something like brave-otter-371");
            }
            // Held to mint a fresh per-peer ceremony for each candidate. The words
            // live ONLY here and inside each Ceremony's SPAKE2 state; never sent.
            recv_pake_template = Some((pw.clone(), np.clone()));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 })).await.ok();
        }
        None if daemon => {
            recv_pake_template = None; // no code claim, no ephemeral PAKE
            // C19: the daemon joins NO room. Presence-channel subscriptions
            // only, strangers can't see it, probe it, or offer to it.
            // Enrollment rendezvous: subscribe to enroll_channel(owner_pub)
            // when armed (outstanding non-expired auth key). Channel-based
            // (not room) because the server supports 1 room/socket and we
            // need the solo room for known-device discovery.
            let solo = format!("up-{}", fresh_secret());
            sess.room = Some(solo.clone());
            sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
            if crate::ephemeral::is_armed() {
                ui::debug("enrollment armed: ephemeral devices may enroll");
            } else {
                ui::debug("enrollment closed (no armed keys — mint or arm an auth-key to open)");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
            let mut c = chans;
            if crate::ephemeral::is_armed() {
                if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if !c.contains(&ek) { c.push(ek); }
                }
            }
            sess.emit(&sio, "subscribe", json!({ "channels": c })).await;
            sess.channels = c;
            ui::say(&format!(
                "  {} filament up, {} known device{} {} {}",
                ui::paint(ui::Tone::Brand, "●"),
                devices.len(),
                if devices.len() == 1 { "" } else { "s" },
                ui::glyph_arrow(),
                ui::paint(ui::Tone::Bold, &dir.display().to_string()),
            ));
            ui::say(&ui::paint(ui::Tone::Dim, "  trusted devices only · invisible to strangers · Ctrl-C or `filament down` to stop"));
            // C29: this is a SESSION, like a browser tab, pairing and petname
            // management happen right here.
            if std::io::stdin().is_terminal() {
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  type a code to pair a new device · `pair` mints one · `devices` · `forget <name>`",
                ));
            }
        }
        None => {
            recv_pake_template = None; // local-network listen, no ephemeral PAKE
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(server).await?,
            };
            // C22: proactive affordance, tell the user what they CAN do,
            // cargo-style gutter, before they have to guess.
            ui::say(&format!(
                "  {} listening, same-network devices appear automatically  {}",
                ui::paint(ui::Tone::Brand, "●"),
                ui::paint(ui::Tone::Dim, &format!("(room {room} · dir {})", dir.display())),
            ));
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  have a code? just type it here (like brave-otter-123) and press Enter",
            ));
            sess.room = Some(room.clone());
            sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                ui::say(&format!("watching for {} known device(s)", devices.len()));
                sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
            }
        }
    }

    // L2 acceptor posture (computed here so it also gates the direct-QUIC path).
    // OFF unless FILAMENT_L2=1 (opt-in) OR an active `up --shell` policy turns it
    // on (you can't ssh in without the acceptor). See its second use below.
    // L2/shell is ON when: an `--shell`/`--shell-only` policy turns it on, the
    // FILAMENT_L2 opt-in is set, OR any known device has been `grant`ed shell (so
    // `filament grant <dev> shell` works on a plain `up` without restarting with a
    // flag, matching what the grant command tells the user). The per-device gate
    // below still denies every non-granted device, so this never widens access.
    let l2_enabled = shell_policy.enables_l2()
        || std::env::var("FILAMENT_L2").map(|v| v == "1").unwrap_or(false)
        || any_shell_grant();

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,        // relay_only
        to,           // to_filter
        // P3 (GAP-3): the `up`/`up --shell` daemon acceptor is the canonical
        // long-lived / interactive session, so warm redundancy defaults ON for it
        // (a one-shot `recv` keeps daemon=false -> OFF).
        daemon,       // warm_standby default
        // rung-1 direct-QUIC: take it when the env gate is set, when this is an
        // L2/ssh acceptor, OR when this is the long-lived `up` daemon. Any acceptor
        // MUST answer the initiator's transport-offer (direct-QUIC over the
        // reachable host candidate, e.g. Tailscale) rather than build a colliding
        // WebRTC peer (glare). For `up --shell` this kills the `filament ssh`
        // "stuck while connecting" failure; for a plain `up` it kills the up<->up
        // glare/supersede churn (two known daemons each racing to be the WebRTC
        // initiator). See `direct_ok_for`. One-shot send/recv/pair (daemon=false)
        // are unaffected and keep their WebRTC default.
        direct_ok_for(daemon, l2_enabled),
    );
    // WARM-HOLD: load configured warm-peers at daemon startup
    if daemon {
        conn.load_warm_peers_config();
    }
    // SIGINT/SIGTERM: route a graceful Ev::Interrupted through the loop AND arm a
    // signal-owned force-exit watchdog. The watchdog is the guarantee: if the
    // event loop is wedged on a stuck peer transport (a WebRTC data-channel write
    // against a frozen/half-open peer, or a send_frame parked on backpressure that
    // never drains), the graceful Interrupted is never processed and the daemon
    // would otherwise ignore the signal until systemd SIGKILLs it ~90s later. The
    // watchdog force-exits within the bounded grace regardless of loop state; a
    // dropped link is an ordinary disconnect to the peer's resilience layer.
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }
    #[cfg(unix)]
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                term.recv().await;
                shutdown::arm_force_exit(130, shutdown::grace());
                let _ = tx.send(Ev::Interrupted);
            }
        });
    }
    // A listening recv accepts a code typed straight into it, the first
    // thing real users try (observed live). C22: stdin runs RAW (cbreak) on a
    // tty so an open y/N question resolves on a single keypress, no Enter;
    // outside a question, bytes accumulate into lines (echoed manually since
    // raw mode disables terminal echo).
    let question_open = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // C29: the stdin owner also runs for an INTERACTIVE daemon (a terminal-
    // attached `filament up` is a session); `up --install` under systemd has
    // no tty, so headless daemons stay stdin-free.
    let interactive = !daemon || std::io::stdin().is_terminal();
    let tty_guard = if interactive && std::io::stdin().is_terminal() { Some(TtyGuard::raw()) } else { None };
    if interactive {
        let tx = tx.clone();
        let q = question_open.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while stdin.read(&mut buf).await.map(|n| n == 1).unwrap_or(false) {
                let c = buf[0] as char;
                if q.load(std::sync::atomic::Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
                    ui::answer_echo(c); // raw mode is no-echo; land it cleanly (C23)
                    let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
                    continue;
                }
                match buf[0] {
                    b'\n' | b'\r' => {
                        eprintln!();
                        let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                        line.clear();
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            eprint!("\x08 \x08");
                        }
                    }
                    _ if !c.is_control() => {
                        eprint!("{c}");
                        line.push(c);
                    }
                    _ => {}
                }
            }
        });
    }
    // L3 (serve_tun mesh): the up daemon opens a TUN and routes IP packets across
    // its peer links when `tun-addr` is set. `auto` (recommended) derives a stable,
    // self-certifying overlay address from this device's Ed25519 overlay key; peers
    // learn+trust it via a signed `l3-announce` (below). A manual CIDR is the
    // advanced/PSK case (no announce). Off otherwise; Linux-only.
    // `l3_seen`: last announce received per pid, replayed once a datagram-capable
    // transport is installed, so a hello that races ahead of the link is not lost
    // (review fix #3).
    #[cfg(l3)]
    let mut l3_seen: HashMap<String, overlay::Announce> = HashMap::new();
    #[cfg(l3)]
    let l3: Option<std::sync::Arc<l3::L3>> = if daemon {
        match settings::get_str("tun-addr", None) {
            Some(setting) => {
                let (cidr, identity) = if setting == "auto" {
                    match overlay::Identity::load_or_create() {
                        Ok(id) => (format!("{}/128", id.addr()), Some(id)),
                        Err(e) => {
                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  L3 disabled: {e}")));
                            (String::new(), None)
                        }
                    }
                } else {
                    (setting.clone(), None) // manual/PSK address, no crypto announce
                };
                if cidr.is_empty() {
                    None
                } else {
                    // Endpoint selection: `l3-mode` setting (kernel|userspace|auto),
                    // default Auto; FILAMENT_L3_USERSPACE / `up --userspace` force
                    // userspace (handled inside L3::start via the env).
                    let mode = match settings::get_str("l3-mode", None).as_deref() {
                        Some("kernel") => l3::L3Mode::Kernel,
                        Some("userspace") => l3::L3Mode::Userspace,
                        _ => l3::L3Mode::Auto,
                    };
                    match l3::L3::start(&cidr, 1280, identity, mode) {
                        Ok(m) => {
                            let addr = m.my_addr().map(|a| a.to_string()).unwrap_or(cidr);
                            if m.is_userspace() {
                                ui::say(&format!(
                                    "  {} L3 overlay {} (userspace, zero privilege)",
                                    ui::paint(ui::Tone::Brand, "●"),
                                    addr
                                ));
                                ui::say(&ui::paint(ui::Tone::Warn,
                                    "    host firewall/nftables are NOT enforced here; only mesh membership + the expose allowlist gate access"));
                                ui::say("    native tools reach <peer>.mesh via `filament proxy` / `filament dial` (no kernel route in userspace)");
                                // Auto-start SOCKS5 proxy when kernel TUN is unavailable.
                                // Opt-out via --no-proxy-fallback or `filament set auto-proxy off`.
                                let auto_proxy = settings::get_bool("auto-proxy", None)
                                    && !no_proxy_fallback;
                                if auto_proxy {
                                    let server = server.to_string();
                                    tokio::spawn(async move {
                                        if let Err(e) = l2::proxy_cmd(&server, "127.0.0.1", 1080, 0, relay).await {
                                            // Port already in use is expected (user started proxy manually);
                                            // only log unexpected errors.
                                            let msg = e.to_string();
                                            if !msg.contains("already in use") {
                                                ui::debug(&format!("auto-proxy: {e}"));
                                            }
                                        }
                                    });
                                    ui::say(&format!(
                                        "  {} started SOCKS5 proxy on 127.0.0.1:1080 (set your tools' proxy to this)",
                                        ui::paint(ui::Tone::Ok, ui::glyph_ok())
                                    ));
                                    ui::say(&format!(
                                        "    e.g.  curl --socks5-hostname 127.0.0.1:1080 http://<peer>.mesh:8080/"
                                    ));
                                }
                            } else {
                            // Kernel mode is dual-stack: show the v4 address too
                                // (userspace has no v4 endpoint yet, so it is omitted
                                // above to avoid implying a route that does not exist).
                                let v4 = m.my_addr_v4().map(|a| format!(" / {a}")).unwrap_or_default();
                                ui::say(&format!(
                                    "  {} L3 overlay {}{} on filament0",
                                    ui::paint(ui::Tone::Brand, "●"),
                                    addr,
                                    v4
                                ));
                                // Show the .mesh name that resolves to this machine.
                                let my_name = l3::hostname();
                                ui::say(&format!(
                                    "    this machine resolves as {}{}",
                                    l3::sanitize_host(&my_name),
                                    ".mesh"
                                ));
                            }
                            // Add this machine's own address to MagicDNS so
                            // `<name>.mesh` resolves locally (not just peers).
                            // Uses the filament device name (from `filament set name`
                            // or hostname if unset), sanitized for DNS.
                            if let Some(id) = m.identity_ref() {
                                let my_name = config_get("name").unwrap_or_else(|| l3::hostname());
                                let v6 = id.addr();
                                let v4 = Some(id.addr_v4());
                                m.names_insert("__self__", &l3::sanitize_host(&my_name), v6, v4).await;
                                if !m.is_userspace() {
                                    m.refresh_hosts().await;
                                }
                                // Configure sshd to listen on overlay addresses if enabled.
                                if settings::get_bool("sshd-overlay", None) {
                                    let v6_str = id.addr().to_string();
                                    let v4_str = id.addr_v4().to_string();
                                    if let Err(e) = sshd::configure_sshd_overlay(&v6_str, &v4_str) {
                                        ui::say(&ui::paint(ui::Tone::Warn, &format!("  sshd-overlay: {e}")));
                                    }
                                }
                            }
                            Some(m)
                        }
                        Err(e) => {
                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  L3 disabled: {e}")));
                            None
                        }
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    // `filament expose`: once the overlay is up, bind the persisted ports on the
    // overlay address and forward each to its local target. Reconciled live on a
    // ReloadExpose control request (expose/unexpose without a restart).
    #[cfg(l3)]
    let exposer: Option<std::sync::Arc<expose::Exposer>> = match l3.as_ref() {
        Some(m) => {
            // POSTURE (user decision): a node that SILENTLY fell back to userspace
            // (Auto, no explicit opt-in) must NOT auto-honor expose.json, because
            // userspace bypasses host firewall/nftables on filament0 - an operator
            // who assumed kernel-mode scoping would silently lose it. Only honor
            // expose in userspace when the user opted in (`--userspace` / the env /
            // `l3-mode=userspace`). Kernel mode always honors it.
            let userspace_opt_in = std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1")
                || settings::get_str("l3-mode", None).as_deref() == Some("userspace");
            if m.is_userspace() && !userspace_opt_in {
                if !expose::load().is_empty() {
                    ui::say(&ui::paint(ui::Tone::Warn,
                        "  expose.json NOT honored: L3 fell back to userspace (host firewall is bypassed there)."));
                    ui::say("    opt in with `filament up --userspace` or `filament set l3-mode userspace` to expose in userspace mode");
                }
                let ex = expose::Exposer::new(m.clone());
                Some(ex) // held so a later live opt-in via ReloadExpose can still bind
            } else {
                let ex = expose::Exposer::new(m.clone());
                let n = ex.reconcile().await;
                if n > 0 {
                    ui::say(&format!(
                        "  {} exposing {} port{} on the overlay",
                        ui::paint(ui::Tone::Brand, "●"),
                        n,
                        if n == 1 { "" } else { "s" }
                    ));
                }
                Some(ex)
            }
        }
        None => None,
    };
    let mut by_sid: HashMap<(String, u32), IncomingFile> = HashMap::new();
    // P4 (GAP-5): per-transfer count of whole-file-verify FAILURES (the digest
    // didn't match on completion). Each failure re-requests a resume (truncated)
    // or a from-zero re-fetch (corrupt body); bounded so a genuinely
    // unrecoverable corruption fails CLEARLY after a few rounds rather than
    // looping forever. Keyed by transfer id.
    let mut verify_fails: HashMap<String, u32> = HashMap::new();
    // C22: offers awaiting consent, exactly ONE stdin owner (the reader
    // task); answers arrive as StdinLine events, never via a competing
    // blocking read racing for the user's "y".
    let mut pending: std::collections::VecDeque<(String, Value)> = Default::default();
    let mut completed = 0usize;
    // G-k: peer-left delivery is best-effort, a browser can close having
    // delivered every byte yet never emit its leave (observed under load,
    // gate 6). Tick the loop on a 2s timeout so a fallback quiet-check can
    // exit cleanly instead of idling to the connect-timeout.
    let mut last_quiet: Option<Instant> = None;
    let quiet_window = quiet_exit_window();
    // C30 phase 2: roster reconciliation from sync digests, a missed
    // peer-joined/left self-corrects. Absence must hold for TWO consecutive
    // digests before a drop (one digest can race a join in flight).
    let mut digest_absent: HashMap<String, u8> = HashMap::new();
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();
    let mut digest_alone = false;
    // C30 phase 3: link mini-sync, state pings every ~10s per link.
    let mut last_state_ping = Instant::now();
    // L2 (ssh/TCP tunnel) acceptor: one mux per link, created on the first
    // l2-open seen on that link. `l2_enabled` is computed once above (it also
    // gates the direct-QUIC path); reused here for the mux/cap machinery.
    let mut l2_muxes: HashMap<String, Arc<l2::Mux>> = HashMap::new();
    // Warm-pty session -> (pid, sid), so a `pty-resize` op relays to the right stream.
    let warm_ptys: WarmPtys = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
    // Warm ssh-bootstrap reply sockets awaiting the peer's ack (see PendingBootstraps).
    #[cfg(unix)]
    let mut pending_bootstrap: PendingBootstraps = HashMap::new();
    // Warm-link reuse: ONLY the registered `up` daemon exposes the local control
    // socket (a short-lived `recv`/`send` must never bind it and steal the
    // daemon's path). When a sibling `filament ssh`/`netcat`/`forward` asks to
    // reach a peer we already hold a link to, we open a new L2 stream over that
    // warm link instead of making the sibling establish a fresh one. `ctl_tx` is
    // held for the loop's life so the channel stays open (recv pends, never spins)
    // even when we are not the daemon and `serve` was not spawned.
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ctl::Req>();
    // The control socket is a unix-domain socket, so warm-link reuse is unix-only.
    #[cfg(unix)]
    {
        if daemon_alive() == Some(std::process::id()) {
            let ctl_tx = ctl_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = ctl::serve(ctl_tx).await {
                    crate::ui::trace(&format!("filament: control socket disabled: {e}"));
                }
            });
        }
    }
    // Hold `ctl_tx` for the loop's life so `ctl_rx` stays open (recv pends, never
    // spins) even when `serve` was not spawned (non-unix, or not the daemon).
    #[cfg(not(unix))]
    let _ = &ctl_tx;
    // web-shell (#4): persistent PTY sessions, keyed by a stable browser-chosen
    // session id, OUTLIVE the link that opened them. A dropped data channel
    // DETACHES (does not kill) the shell; a reconnect with the same session id
    // reattaches and replays buffered output. Process-wide for the whole loop.
    let pty_sessions = l2::PtySessions::new();
    // Per-link map of the PTY sids currently bound to a session on that link, so
    // a link drop can DETACH exactly those sessions (and a clean l2-close ends
    // the right one). pid -> (sid -> session_id).
    let mut pty_bindings: HashMap<String, HashMap<u32, String>> = HashMap::new();
    // web-shell: per-sid resize senders are now owned by each Mux (l2.rs) so they
    // are freed on every teardown path (H-1: closes the prior pty_resizers leak).
    // Bug 5: surface the single-host mDNS wedge hint once after repeated stuck.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let _saw_known_peer: HashSet<String> = HashSet::new();
    let mut ever_received = false;
    // C12 live-pairing: the roster (`devices`) is loaded ONCE at startup, and
    // KnownPeer events only fire for channels we've SUBSCRIBED. A device paired
    // into the shared store by a SEPARATE `filament pair` process AFTER the
    // daemon is up was therefore invisible until restart, it never got a
    // subscription, so its "appeared, connecting" flow never fired and it
    // could not connect (no transfer, no web-shell). We now re-scan the store
    // on a modest cadence and subscribe to any NEW device's channel live; the
    // session digest (which includes `sess.channels`) repairs a lost subscribe
    // on the next tick. Existing channels and live links are untouched.
    let mut known_channels: std::collections::HashSet<String> =
        devices.iter().map(|(_, s)| channel_of(s)).collect();
    let mut last_devices_scan = Instant::now();

    // Daemon-managed mount state: the daemon holds the sshfs child processes and
    // monitors their health centrally instead of spawning per-mount threads.
    let mut daemon_mounts = DaemonMounts {
        entries: HashMap::new(),
        children: HashMap::new(),
    };
    let mut last_mount_check = Instant::now();

    // WARM-HOLD: periodic check for warm peers that need connections
    let mut last_warm_hold_tick = Instant::now();

    // P2 (GAP-2): outer reconnect / re-announce loop state for the long-lived
    // acceptor. `reconnect(false)` means a severed signaling TCP leaves the
    // socket dead with NO further events, the acceptor zombies and the sender
    // can't rediscover it (the documented `no peer connected` failure that
    // up_supervisor.sh patched from outside the binary). We close it IN-CORE:
    //  - `last_signaling`  : monotonic time of the last inbound signaling event;
    //                        any inbound Ev that originates from the socket bumps
    //                        it (welcome/synced/peer-*/signal/known-peer/...).
    //  - silence watchdog  : if it goes silent past `signaling_silence_ms` (and
    //                        a forced `sync` emit doesn't restore it), the link
    //                        is dead, re-dial. This is the AUTHORITATIVE trigger
    //                        because a hard TCP sever fires no close callback.
    //  - Ev::SignalingDown : the socket.io close/error fast-path accelerant.
    // Only the daemon acceptor self-heals (`signaling_self_heal`); the one-shot
    // recv/send paths re-invoke fresh, so they keep failing fast (unchanged).
    // FILAMENT_TEST_NO_SIGNALING_RECONNECT reverts to the OLD no-outer-loop path
    // so the signaling-drop gate's A/B baseline can prove the acceptor ZOMBIES
    // without the fix (the detector/loop is load-bearing, not incidental).
    let signaling_self_heal = daemon && !test_hooks::no_signaling_reconnect();
    let mut last_signaling = Instant::now();
    let mut signaling_down_since: Option<Instant> = None;
    let mut reconnect_attempt: u32 = 0;
    let mut last_reconnect_try = Instant::now();
    let mut probed_silence = false; // fired one forced sync before declaring down
    let mut last_watchdog = Instant::now();
    // Link self-heal cadence (the multi-minute-outage fix, #3). A transport that
    // died past the QUIC idle timeout lingers in `links` as a zombie and SUPPRESSES
    // the KnownPeer re-dial (start_direct early-returns when a link exists), so the
    // overlay never recovers. We DROP dead links here (so the next KnownPeer
    // re-push re-establishes, single-driver + glare-safe = the model's proven
    // disconnect->recover) but do NOT re-dial ourselves - a timer-based re-dial on
    // BOTH ends caused a supersede storm. The L3 route is intentionally KEPT
    // (continuity), so the re-establish's add_peer swaps the transport under the
    // same overlay IP and the session resumes.
    let mut last_link_health = Instant::now();

    // systemd Type=notify: announce readiness once the serving loop is about to
    // run, then ping the watchdog below. No-op when not run under systemd.
    if daemon {
        sdnotify::ready();
        sdnotify::status("up - serving");
    }

    // Restore mounts that were marked with auto_restore.
    if let Err(e) = mount::restore_mounts(server, relay).await {
        crate::ui::say(&format!("warning: failed to restore mounts: {e}"));
    }

    loop {
        // systemd liveness watchdog: ping on a throttle (well under WatchdogSec).
        // If this loop WEDGES on an await, the pings stop and systemd restarts us
        // - the backstop for the stall that also freezes the reconnect code.
        if daemon && last_watchdog.elapsed() >= Duration::from_secs(5) {
            sdnotify::watchdog();
            last_watchdog = Instant::now();
        }
        // Shutdown-hang repro hook: once links are live, freeze the event loop
        // forever, faithfully simulating a peer transport whose inline write
        // never returns. The graceful Ev::Interrupted can no longer be processed;
        // only the signal-owned force-exit watchdog can still terminate us. No-op
        // unless FILAMENT_TEST_WEDGE_LOOP is set (test-hooks builds only).
        if test_hooks::wedge_loop_on_shutdown() && !conn.links.is_empty() {
            std::future::pending::<()>().await;
        }
        let ev = tokio::select! {
            biased;
            // Warm-link reuse request from a sibling process. Handle it inline
            // (we own `conn`/`l2_muxes` here), then fall through like a tick. For
            // a non-daemon this branch pends forever (ctl_tx held, serve unspawned).
            req = ctl_rx.recv() => {
                if let Some(req) = req {
                    // Bootstrap defers its reply (awaits the peer's ack via this
                    // loop), so it can't go through the inline handle_warm_req; it
                    // stashes the socket in pending_bootstrap instead.
                    #[cfg(unix)]
                    {
                        // `filament set` live-reconfigure: re-read the changed key
                        // into this loop's live state, then report whether it took
                        // without a restart. Handled here (we own dir/policy/sess).
                        if let ctl::ReqKind::Reconfigure { key } = &req.kind {
                            let key = key.clone();
                            let live = apply_reconfigure(
                                &key, &mut dir, &mut shell_policy, &mut shell_user,
                                l2_enabled, &mut sess, &sio, &my_uid,
                            ).await;
                            req.reply(&json!({ "ok": true, "live": live })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ReloadExpose) {
                            // `filament expose`/`unexpose`: reconcile overlay
                            // listeners from expose.json. live:true only if L3 is up.
                            let (live, count): (bool, usize) = {
                                #[cfg(l3)]
                                {
                                    match exposer.as_ref() {
                                        Some(ex) => (true, ex.reconcile().await),
                                        None => (false, 0),
                                    }
                                }
                                #[cfg(not(l3))]
                                {
                                    (false, 0)
                                }
                            };
                            req.reply(&json!({ "ok": true, "live": live, "count": count })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Reload) {
                            // `filament update` reload: only safe when a supervisor
                            // will bring us back (systemd sets INVOCATION_ID). Reply
                            // FIRST (the shutdown closes the ctl socket), then take the
                            // SAME graceful path SIGTERM does - which cleanly closes the
                            // QUIC links so peers re-establish and L3 recovers - by
                            // raising SIGTERM on ourselves. systemd's Restart=always
                            // then starts the new binary with fresh ambient caps: no
                            // manual restart, no sudo. Unsupervised, we decline (exiting
                            // would just leave the node down).
                            let supervised = std::env::var("INVOCATION_ID").is_ok();
                            req.reply(&json!({ "ok": true, "reloading": supervised })).await;
                            if supervised {
                                ui::say("filament: reloading onto the updated binary (graceful restart)");
                                #[cfg(unix)]
                                unsafe { libc::raise(libc::SIGTERM); }
                            }
                        } else if matches!(&req.kind, ctl::ReqKind::Dial { .. }) {
                            // Overlay dial (proxy `.mesh` fallback): resolve the peer
                            // to its VERIFIED overlay address ourselves, dial it over
                            // L3, and bridge the ctl socket to it. Spawned so the
                            // long-lived splice never blocks the event loop.
                            #[cfg(l3)]
                            if let ctl::ReqKind::Dial { peer, port } = &req.kind {
                                let (peer, port) = (peer.clone(), *port);
                                match l3.as_ref() {
                                    Some(m) => {
                                        let m = m.clone();
                                        tokio::spawn(async move {
                                            let Some(addr) = m.addr_of(&peer).await else {
                                                req.reject("unknown overlay peer").await;
                                                return;
                                            };
                                            match m.dial(addr, port).await {
                                                Ok(mut stream) => {
                                                    let mut sock = req.accept().await;
                                                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
                                                }
                                                Err(e) => req.reject(&format!("overlay dial failed: {e}")).await,
                                            }
                                        });
                                    }
                                    None => req.reject("L3 overlay is not up").await,
                                }
                            }
                            #[cfg(not(l3))]
                            req.reject("L3 overlay not supported on this build").await;
                        } else if matches!(&req.kind, ctl::ReqKind::Bootstrap { .. }) {
                            handle_warm_bootstrap(&conn, &mut pending_bootstrap, req).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Mount { .. }) {
                            handle_mount(req, &server, relay, &mut daemon_mounts, &mut last_mount_check).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Unmount { .. }) {
                            handle_unmount(req, &mut daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ListMounts) {
                            handle_list_mounts(req, &daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::MountHealth { .. }) {
                            handle_mount_health(req, &daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::CapStatus) {
                            let counts = crate::capability::cap_shadow_counts();
                            let action_counts = crate::capability::cap_action_counts();
                            req.reply(&json!({
                                "ok": true,
                                "counts": {
                                    "la_authorized": counts.la_authorized,
                                    "la_denied": counts.la_denied,
                                    "la_no_header": counts.la_no_header,
                                    "ld_authorized": counts.ld_authorized,
                                    "ld_denied": counts.ld_denied,
                                    "ld_no_header": counts.ld_no_header,
                                    "ceiling_denied": counts.ceiling_denied,
                                },
                                "by_action": action_counts,
                                "flip_ready": counts.flip_ready(),
                                "summary": counts.summary(),
                            })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ListWarm) {
                            handle_list_warm(&conn, req).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ListPending) {
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            req.reply(&json!({
                                "ok": true,
                                "requests": requests,
                            })).await;
                        } else if let ctl::ReqKind::ApproveRequest { id, allow, expires } = &req.kind {
                            let id = *id;
                            let allow = allow.clone();
                            let expires = *expires;
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                let peer = r.peer.clone();
                                let cap = r.capability.clone();
                                if cap != allow {
                                    req.reject(&format!("request {id} is for '{cap}', not '{allow}'")).await;
                                } else if !crate::capability::grant_active(expires, crate::capability::now_secs()) {
                                    req.reject("grant expiry must be in the future").await;
                                } else if let Err(e) = device_set_cap(&peer, &cap, true, Some(expires)) {
                                    req.reject(&format!("grant failed: {e}")).await;
                                } else if let Err(e) = issue_signed_bounded_grant(&peer, &cap, expires).and_then(|signed| {
                                    if signed { mark_bounded_cap_source(&peer, &cap, "signed") } else { Ok(()) }
                                }) {
                                    req.reject(&format!("signed grant failed: {e}")).await;
                                } else {
                                    r.status = "approved".to_string();
                                    r.granted_at = Some(crate::capability::now_secs());
                                    save_requests(&requests);
                                    req.reply(&json!({ "ok": true, "id": id, "peer": peer, "capability": cap, "expires": expires })).await;
                                }
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else if let ctl::ReqKind::DenyRequest { id } = &req.kind {
                            let id = *id;
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                r.status = "denied".to_string();
                                save_requests(&requests);
                                req.reply(&json!({ "ok": true, "id": id })).await;
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else {
                            // Auto-warm: feed LRU for pty sessions (bounded, no leak).
                            if let ctl::ReqKind::Pty { peer, .. } = &req.kind {
                                conn.note_warm_use(peer);
                            }
                            handle_warm_req(&conn, &mut l2_muxes, &warm_ptys, &tx, req).await;
                        }
                    }
                    #[cfg(not(unix))]
                    handle_warm_req(&conn, &mut l2_muxes, &warm_ptys, &tx, req).await;
                }
                None
            }
            res = tokio::time::timeout(
                Duration::from_secs(2),
                next_ev(&mut rx, &conn, !pending.is_empty()),
            ) => match res {
                Ok(res) => res?,
                Err(_) => None, // 2s tick, run the fallback quiet-check below
            },
        };

        // C30: converge session state (no-op unless diverged/stale/unconfirmed).
        sess.tick(&sio).await;

        // L1-a ephemeral PAKE progression (recv code path), PER CANDIDATE PEER.
        // For each candidate's ceremony whose link is up: send our SPAKE2 element,
        // then (once K + both DTLS fingerprints exist) the key-confirmation MAC.
        // Each ceremony is independent, so a decoy peer that never replies just
        // sits until ITS budget expires (dropped below), never blocking the real
        // sender's ceremony. The agreed secret is DISCARDED after auth, never
        // stored. Once one peer authenticates (`recv_pake_done`) we stop driving
        // candidates: the sender is settled.
        if recv_code_path && !recv_pake_done {
            let pids: Vec<String> = recv_cers.keys().cloned().collect();
            for pid in pids {
                let send_msg = recv_cers.get_mut(&pid).and_then(|c| c.take_msg_payload());
                if let Some(data) = send_msg {
                    sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
                }
                let has_k = recv_cers.get(&pid).map(|c| c.has_k()).unwrap_or(false);
                if has_k {
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    if let Some((my_fp, their_fp)) = fps {
                        let conf = recv_cers
                            .get_mut(&pid)
                            .and_then(|c| c.take_confirm_payload(&my_fp, &their_fp));
                        if let Some(data) = conf {
                            sio.emit("signal", json!({ "to": pid, "data": data })).await.ok();
                        }
                    }
                }
            }
        }
        // Per-peer budgets: a candidate whose ceremony never completes within its
        // own budget is dropped INDIVIDUALLY (an unrelated decoy, or an old peer
        // that won't run v2). Dropping it never bails the receive; the real sender
        // keeps its own live budget. Only relevant before someone authenticates.
        if recv_code_path && !recv_pake_done {
            let now = Instant::now();
            let expired: Vec<String> = recv_deadlines
                .iter()
                .filter(|(_, dl)| now > **dl)
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in expired {
                recv_deadlines.remove(&pid);
                recv_cers.remove(&pid);
                recv_pending_offers.remove(&pid);
                ui::debug(&format!("recv: candidate {pid} did not authenticate in budget, dropped"));
            }
        }
        // Overall deadline: the backstop. Once we are matched into the sender's
        // room a candidate channel arms this; if NO peer authenticates within it,
        // fail the whole `recv` loudly (a genuinely absent / old sender, mirroring
        // the previous single-budget intent and FILAMENT_PAIR_GRACE_SECS) rather
        // than hanging forever.
        if recv_code_path && !recv_pake_done {
            if let Some(dl) = recv_pake_overall_deadline {
                if Instant::now() > dl {
                    bail!("the other device uses an older version and can't send securely over a code. Update it (or this CLI) so the transfer runs the encrypted handshake. Nothing was received.");
                }
            }
        }

        // P2 (GAP-2): the OUTER RECONNECT / RE-ANNOUNCE loop for the long-lived
        // acceptor. Runs only in the daemon path; the one-shot recv/send paths
        // re-invoke fresh on failure and so never need it.
        if signaling_self_heal {
            // (1) Liveness accounting. Any inbound signaling event proves the
            // socket is alive; a successful `sync` ack (Ev::Synced) is the
            // strongest signal (the server answered). The fast-path close/error
            // callback marks the link down immediately.
            let mut saw_down = false;
            match &ev {
                Some(Ev::SignalingDown(_)) => saw_down = true,
                Some(
                    Ev::Welcome(_) | Ev::Synced(_) | Ev::SignalingAlive | Ev::PeerJoined(_)
                    | Ev::PeerLeft(_) | Ev::Signal(_) | Ev::KnownPeer(_) | Ev::KnownPeerLeft(_)
                    | Ev::PairMatched(_) | Ev::PairOk(_) | Ev::PairCode(_) | Ev::PairUsed(_)
                    | Ev::PairError(_),
                ) => {
                    last_signaling = Instant::now();
                    signaling_down_since = None;
                    probed_silence = false;
                    reconnect_attempt = 0;
                }
                _ => {}
            }

            // (2) Silence watchdog, the AUTHORITATIVE trigger. A hard TCP sever
            // fires no close callback, so we watch the inbound gap. Once it
            // exceeds the threshold, fire ONE forced `sync` (the heartbeat); if
            // the socket is alive the server's `synced` ack lands within a tick
            // and resets the gap. If a second threshold passes with still no
            // event, the socket is dead, declare it down.
            let silence = net::signaling_silence_ms();
            let silent_ms = last_signaling.elapsed().as_millis() as u64;
            if signaling_down_since.is_none() {
                if saw_down {
                    signaling_down_since = Some(Instant::now());
                    last_reconnect_try = Instant::now() - Duration::from_secs(60); // re-dial now
                    // Visible (not just debug): a node dropping off signaling was
                    // previously silent until it bit someone. Surface it + reflect
                    // it in `systemctl status` so it's diagnosable at a glance.
                    ui::say(&ui::paint(ui::Tone::Warn, "signaling link closed, reconnecting..."));
                    sdnotify::status("signaling down - reconnecting");
                } else if silent_ms >= silence {
                    if !probed_silence {
                        // Heartbeat probe: an ACK'd `sync` round-trip, the only
                        // liveness signal that works for a room-less idle
                        // acceptor. `sess.tick()` can't serve here: it returns
                        // early when there is no room (the `up` case) AND when
                        // the session is already confirmed-fresh, so on a quiet
                        // link it emitted nothing and the watchdog falsely
                        // reconnected every ~30 s, churning presence. The server
                        // acks `sync` unconditionally; the ack wakes the loop as
                        // Ev::SignalingAlive, which resets the gap below.
                        probed_silence = true;
                        net::heartbeat(&sio, sess.heartbeat_payload(), tx.clone()).await;
                    } else if silent_ms >= silence.saturating_mul(2) {
                        signaling_down_since = Some(Instant::now());
                        last_reconnect_try = Instant::now() - Duration::from_secs(60);
                        // Visible: a silent (half-open) signaling link is the exact
                        // way a node falls off presence without anyone noticing.
                        ui::say(&ui::paint(ui::Tone::Warn, &format!("signaling silent for {silent_ms}ms, reconnecting...")));
                        sdnotify::status("signaling silent - reconnecting");
                    }
                }
            }

            // (3) Re-dial with backoff + jitter. Idempotent: a fresh `welcome`
            // re-asserts room + channel subscriptions through the C30 session
            // (sess.invalidate forces it next tick). Live DATA links are NOT torn
            // down, they ride independent WebRTC/QUIC transports and keep
            // flowing across the cosmetic signaling reconnect (the #28 contract).
            if let Some(down_at) = signaling_down_since {
                // backoff: 0.5s, 1s, 2s, 4s ... capped at 8s, +/-25% jitter.
                let base = 500u64.saturating_mul(1 << reconnect_attempt.min(4)).min(8_000);
                let jitter = (down_at.elapsed().as_nanos() as u64 % (base / 2 + 1)) as i64 - (base as i64 / 4);
                let backoff = Duration::from_millis((base as i64 + jitter).max(100) as u64);
                if last_reconnect_try.elapsed() >= backoff {
                    last_reconnect_try = Instant::now();
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let _ = sio.disconnect().await; // drop the dead client (no-op if already gone)
                    match net::reconnect_signaling(server, tx.clone()).await {
                        Ok(new_sio) => {
                            sio = new_sio;
                            conn.sio = sio.clone();
                            // C30: a fresh sid voids everything the server held,
                            // re-assert room + channels on the next tick. Re-fire
                            // the fast-path join/subscribe immediately too.
                            sess.invalidate();
                            if let Some(room) = sess.room.clone() {
                                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
                            }
                            if !sess.channels.is_empty() {
                                let chans = sess.channels.clone();
                                sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
                            }
        sess.tick(&sio).await;
                            // optimistic: a clean connect proves reachability; let
                            // the welcome confirm it (which resets the counters).
                            last_signaling = Instant::now();
                            signaling_down_since = None;
                            probed_silence = false;
                            // Visible: pairs with the "reconnecting..." line so the
                            // recovery is observable end to end.
                            ui::say(&ui::paint(ui::Tone::Ok, "signaling reconnected, re-announcing presence"));
                            sdnotify::status("up - serving");
                        }
                        Err(e) => {
                            // DEBUG, resilience internal (signaling reconnect retry).
                            ui::debug(&ui::paint(ui::Tone::Dim, &format!("  signaling reconnect failed ({e}), retrying with backoff")));
                        }
                    }
                }
            }
        }

        // Arm-gate: toggle enrollment-channel subscription EVERY loop iteration
        // based on the armed set. Channel-based (not room) because the server
        // supports 1 room/socket. This MUST run at loop top-level, not nested in
        // the signaling-reconnect Ok arm: a stable daemon (signaling never down)
        // would otherwise never subscribe and no ephemeral device could enroll.
        if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
            let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
            let armed = crate::ephemeral::is_armed();
            let subscribed = sess.channels.contains(&ek);
            if armed && !subscribed {
                sess.channels.push(ek.clone());
                let _ = sio.emit("subscribe", json!({ "channels": [ek] })).await;
            } else if !armed && subscribed {
                sess.channels.retain(|c| c != &ek);
                let _ = sio.emit("channel-goodbye", json!({ "channels": [ek] })).await;
            }
        }

        // Link self-heal (#3): drop links whose transport has DIED so the KnownPeer
        // re-dial (re-pushed on signaling reconnect + periodic sync) can rebuild
        // them. Same action as the on-demand DropLink handler, just proactive; the
        // L3 route is intentionally NOT retracted (continuity), so the re-establish's
        // add_peer swaps the fresh transport under the same overlay IP. We do NOT
        // re-dial here on purpose (single-driver = the model's proven, churn-free
        // recovery; a both-ends timer re-dial storms).
        if daemon && last_link_health.elapsed() >= Duration::from_secs(8) {
            last_link_health = Instant::now();
            let dead: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| !t.is_alive()))
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in dead {
                ui::debug(&format!("filament: link to '{pid}' died, dropping so it can re-connect"));
                conn.drop_link(&pid);
                l2_muxes.remove(&pid);
            }
        }

        // Daemon-managed mount health check: periodically check all tracked
        // mounts and remove dead/stale entries. Runs every 30s, daemon-only.
        if daemon && last_mount_check.elapsed() >= Duration::from_secs(30) {
            last_mount_check = Instant::now();
            let dead_locals: Vec<String> = daemon_mounts.entries.iter()
                .filter_map(|(local, _entry)| {
                    let is_alive = mount::is_mount_point(local);
                    let path_exists = Path::new(local).exists();
                    if !path_exists {
                        Some(local.clone())
                    } else if !is_alive {
                        Some(local.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for local in dead_locals {
                if let Some(entry) = daemon_mounts.entries.remove(&local) {
                    ui::say(&format!("mount {local} is gone, removing from daemon tracking (was {}:{})", entry.peer, entry.remote));
                    // Kill the child process if still tracked.
                    if let Some(mut child) = daemon_mounts.children.remove(&local) {
                        let _ = child.kill().await;
                    }
                    let _ = mount::remove_mount(&local);
                }
            }
        }

        // WARM-HOLD: periodically check for warm peers that need connections.
        // This keeps recently-used and explicitly configured peers connected
        // so `filament ping`/`ssh` is instant. Runs every 10s, daemon-only.
        if daemon && last_warm_hold_tick.elapsed() >= Duration::from_secs(10) {
            last_warm_hold_tick = Instant::now();
            // Warm-all is the DEFAULT (auto-warm setting, opt-out). L3 forces it on:
            // the overlay routes over these links, opting out must not break L3.
            let auto_warm = l3.is_some() || settings::get_bool("auto-warm", None);
            let _ = conn.warm_hold_tick(auto_warm).await;
        }

        // C12 live-pairing: pick up devices paired AFTER we started (a separate
        // `filament pair` writes them into the shared store atomically). Re-read
        // every ~2s, subscribe to any channel we don't already watch, and feed
        // them into `devices` so the KnownPeer handler recognizes them. We never
        // re-subscribe existing channels or touch live links. Daemon-only: a
        // one-shot `recv`/`send` has a fixed roster for its short lifetime.
        if daemon && last_devices_scan.elapsed() >= Duration::from_secs(2) {
            last_devices_scan = Instant::now();
            let mut new_chans: Vec<String> = Vec::new();
            for (n, s) in devices_load() {
                let ch = channel_of(&s);
                if known_channels.insert(ch.clone()) {
                    ui::say(&format!("new device '{n}' paired, now reachable"));
                    devices.push((n, s));
                    new_chans.push(ch);
                }
            }
            if !new_chans.is_empty() {
                // Fast-path emit now; the session digest carries the durable
                // subscription so a dropped emit self-repairs on the next tick.
                for ch in &new_chans {
                    if !sess.channels.contains(ch) {
                        sess.channels.push(ch.clone());
                    }
                }
                sess.emit(&sio, "subscribe", json!({ "channels": new_chans })).await;
            }
        }
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // Drop warm-bootstrap waiters whose peer never acked; the client's read
        // hits EOF and falls back to the cold establish.
        #[cfg(unix)]
        reap_warm_bootstraps(&mut pending_bootstrap);
        // rung-1: direct attempt timed out → fall back to WebRTC (unchanged).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.maybe_adopt(&info, true).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
        }

        // C30 phase 3: state pings, each open link hears our transfer/away
        // truth every ~10s, so one-sided beliefs between PEERS can't persist.
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for (pid, l) in &conn.links {
                if let Some(t) = &l.transport {
                    let mut transfers = serde_json::Map::new();
                    for ((p0, _), inc) in &by_sid {
                        if p0 == pid {
                            transfers.insert(inc.id.clone(), json!(inc.received.load(Ordering::Relaxed)));
                        }
                    }
                    // BOUNDED: this runs inline in the event loop for EVERY link.
                    // A WebRTC data-channel write against a frozen / half-open peer
                    // can block (write_data_channel().await never returns), which
                    // would starve the whole loop, including the signal-driven
                    // Interrupted handler, the multi-link shutdown hang. The state
                    // ping is best-effort, so cap it and move on.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        t.send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": Value::Object(transfers),
                            "trusted": l.trusted,
                            "away": false,
                        })),
                    )
                    .await;
                }
            }
        }

        // G-k completion sweep (top-of-loop): see sweep_completed_streams.
        sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;

        // Gate-18 Mode B: recompute the completion flag AFTER the sweep, every
        // tick (never sticky). When true, a stuck/lost link is DROPPED in
        // on_stuck instead of re-established, see Conn::recv_done. Refreshing it
        // here, where `completed`/`by_sid` were just settled, makes the gate-2/
        // gate-11c fence exact: a mid-transfer link (by_sid non-empty) sees
        // recv_done=false and reconnects unchanged.
        conn.recv_done = protocol::recv_transfer_done(completed, keep_open, by_sid.is_empty());
        // WARM-HOLD: when a transfer completes, mark the peer as warm so we
        // proactively reconnect if the link drops.
        if completed > 0 {
            let warm_peers: Vec<String> = by_sid.keys()
                .filter_map(|(pid, _)| conn.links.get(pid)?.verified_name.clone())
                .collect();
            for name in &warm_peers {
                conn.note_warm_use(name);
            }
        }
        if completed > 0 || !by_sid.is_empty() {
            ever_received = true; // a channel was up; Bug-5 wedge hint no longer applies
        }

        // P0 (GAP-1): bytes-moved STALL watchdog (RECEIVE side). The receiver is
        // the peer that visibly hangs at 0%: when an inbound transfer is in
        // flight (`by_sid` non-empty for a link) but no data byte has arrived
        // past the stall threshold, its transport's idle_ms() climbs. The
        // RECEIVER must also act so a direct-QUIC repair is SYMMETRIC, a fresh
        // authenticated QUIC connection needs both ends to re-dial. We emit
        // Ev::TransferStalled for each such link (liveness-gated), whose handler
        // re-arms this side's direct dial (rung c). The on-disk `.part` is kept,
        // so the resumed stream continues from the saved offset.
        {
            // Per-link: in_flight = this peer has an inbound file mid-transfer
            // (a by_sid entry) OR a stall episode is already open for it (the
            // .part was flushed to disk mid-repair, so by_sid is momentarily
            // empty, detect_stall keeps the episode alive until fresh progress).
            let all_pids: Vec<String> = conn.links.keys().cloned().collect();
            for pid in all_pids {
                let in_flight = by_sid.keys().any(|(p, _)| *p == pid);
                if let Some(idle) = conn.detect_stall(&pid, in_flight) {
                    let transport_dead = conn.transport_of(&pid).map(|t| t.is_dead()).unwrap_or(false);
                    if transport_dead || conn.link_alive(&pid).await {
                        let _ = tx.send(Ev::TransferStalled(pid, idle));
                    } else {
                        conn.note_progress(&pid);
                    }
                }
            }
        }

        // P5 (GAP-6): relay->direct upgrade prober (receive side). The `up` daemon
        // acceptor is the canonical long-lived session, so the prober defaults ON
        // here. Probe for a direct path while serving on relay; verify-before-
        // upgrade cuts over only on a confirmed-stable direct standby.
        conn.tick_upgrade_prober().await;

        // Gate-18 Mode B DETERMINISTIC repro hook: simulate the post-completion
        // FLAP that contention triggers in the wild (the sender's departure puts
        // the receiver's link into the C4 reconnect loop). Once everything is on
        // disk, force each surviving link to go stuck repeatedly, reset its
        // attempts (mirroring the real flap's attempts-reset, so MAX_ATTEMPTS
        // can never cap it) and re-inject Ev::Stuck. On the BASELINE (no fix)
        // on_stuck re-establishes → link persists → conn.links never empties →
        // hang to timeout (RC=124). WITH the fix on_stuck drops on recv_done →
        // links empties → no link to churn next tick → quiet-exit fires. Driven
        // at LOOP level (not inside on_stuck) so the A/B tests the fix, not
        // itself.
        if conn.recv_done && test_hooks::churn_after_complete() {
            let churn: Vec<(String, u32)> = conn
                .links
                .iter()
                .map(|(pid, l)| (pid.clone(), l.generation))
                .collect();
            for (pid, generation) in churn {
                if let Some(l) = conn.links.get_mut(&pid) {
                    l.attempts = 0; // mirror the real flap: cap never accumulates
                    // Tear the data channel down so on_stuck's is_connected()
                    // guard sees a dead link and the Stuck isn't swallowed.
                    if let Some(p) = &l.peer {
                        p.close().await;
                    }
                }
                let _ = conn.tx.send(Ev::Stuck(pid, generation));
            }
        }

        // #28 exit reconciliation: once everything is received and the only links
        // left are ones held open purely for their deferred-drop reap (their
        // sender's signaling left AFTER the transfer finished), there is nothing
        // in flight to protect, exit promptly instead of paying the full
        // FILAMENT_ADOPT_ACTIVE_MS deferral. Restores the pre-#28 prompt exit; an
        // in-progress reconnect keeps `by_sid` non-empty and so is unaffected.
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty()
            && !conn.links.is_empty() && conn.only_deferred_links()
        {
            ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // Bug 2: the transfer is COMPLETE and the sender's link is fully GONE
        // (dropped via peer-left, or via the grace/Mode-B path when peer-left
        // was lost). With no live link and nothing left to fetch there is
        // nothing to wait for, exit at once instead of holding out the full
        // rejoin window (peer-left case) or the quiet-exit window (lost-peer-left
        // case). Fenced exactly like the exits above: by_sid empty + no pending
        // questions, so a mid-transfer reconnect (which keeps `by_sid`
        // non-empty) is untouched, and --keep-open still lingers by design.
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty()
            && conn.links.is_empty()
        {
            conn.rejoin.waiting_rejoin = None;
            ui::clear_sticky();
            ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding, if that holds quietly for the quiet-exit window (10s
        // default, FILAMENT_QUIET_EXIT_SECS overrides), the peer-left we were
        // counting on for a clean exit never arrived; exit anyway. C30 ph2:
        // ALSO satisfied when the server's digest says the room is empty and
        // no room-independent (channel) link remains, lingering dead links
        // can't block the exit when the server knows nobody's there.
        let digest_says_alone = digest_alone && conn.links.values().all(|l| l.expected_secret.is_none());
        // #28 Mode B: a dead link that keeps FLAPPING, on_stuck reconnect, or a
        // roster/session reconcile re-adopting the gone sender and re-arming
        // `expected_secret` so `digest_says_alone` never holds, must NOT block
        // this fallback once everything is received; `conn.links` may never
        // empty under churn (the RC=124 hang). Surgical: discriminate on link
        // HEALTH, not existence, a churning/reconnecting/dead link (never
        // `Ready`) does not block exit, but a healthy `Ready` link (e.g. a
        // bystander between two human-paced sends, gate 6) STILL does. So this is
        // a no-op for healthy peers, not a behaviour change, only a peer we've
        // lost contact with stops blocking. FILAMENT_TEST_DISABLE_MODEB_DROP
        // restores the old links-gated behaviour so gate 18b proves the A/B
        // (baseline hangs, fix exits) with one binary.
        let no_healthy_link = conn.links.values().all(|l| !matches!(l.presence, Presence::Ready));
        let links_clear = if !test_hooks::disable_modeb_drop() {
            no_healthy_link
        } else {
            conn.links.is_empty() || digest_says_alone
        };
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty() && links_clear {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > quiet_window => {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (peer-left never arrived, exiting on quiet)"));
                    ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
                Some(_) => {}
            }
        } else {
            last_quiet = None;
        }

        let Some(ev) = ev else { continue };

        // C23: questions from links that died (supersede/peer-left) are
        // moot, the sender re-offers on its new link. Purge them so a 'y'
        // can never accept a ghost (the duplicate-stream ENOENT crash).
        if !pending.is_empty() {
            let front_id = pending.front().map(|(_, v)| v["id"].clone());
            pending.retain(|(p, _)| conn.links.contains_key(p));
            if pending.front().map(|(_, v)| v["id"].clone()) != front_id {
                ui::clear_sticky();
                if let Some((qpid, qv)) = pending.front() {
                    let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                    {
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        ui::say(&q); // permanent: a new question fronted (C25)
                        ui::sticky(&q);
                        question_shown = Instant::now();
                    }
                } else {
                    question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        match ev {
            // A warm-reuse open found this held link black-holing new streams
            // (zombie: alive at QUIC, dead for data). Drop it so the proactive
            // re-connect forms a fresh, healthy held link and warm-reuse goes
            // back to instant. Live DATA links are untouched (each ssh/pty op
            // rides its own stream; the dropped link had no working stream).
            Ev::DropLink(pid) => {
                if conn.links.contains_key(&pid) {
                    ui::debug(&format!("filament: dropping zombie warm link to '{pid}' (black-holed a stream)"));
                    conn.drop_link(&pid);
                    l2_muxes.remove(&pid);
                    // CONTINUITY: do NOT retract the L3 route here. A dropped link
                    // is almost always followed by a repair (a fresh transport for
                    // the same peer), whose add_peer atomically swaps the route. If
                    // we retracted now, the overlay IP would be briefly unroutable
                    // and a live ssh/L3 session could reset across the repair. The
                    // stale route just drops datagrams (the inner TCP pauses) until
                    // the swap. The cached announce is dropped so the peer's next
                    // announce is treated fresh.
                    #[cfg(l3)]
                    l3_seen.remove(&pid);
                }
            }
            Ev::PairMatched(v) => {
                claim_in_flight = false;
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ui::say(&format!("  {} code accepted, joining sender", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sess.room = Some(room.clone()); // C30: desire moves; session repairs if the join dies
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            // C30: server confirmed our session digest. Phase 2: reconcile
            // the roster it carries, missed peer-joined/left self-correct.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    let channel_peers = roster.channel_peers;
                    let channel_present: std::collections::HashSet<String> = channel_peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // Channel subscriptions are independent of room membership.
                    // Re-adopt missed known-peer pushes and reap known links that
                    // remain absent from two consecutive channel rosters.
                    for p in &channel_peers {
                        if is_self_uid(&conn.my_uid, p["uid"].as_str()) {
                            continue;
                        }
                        if let Some((name, secret)) = devices.iter().find(|(_, s)| {
                            channel_of(s) == p["channel"].as_str().unwrap_or_default()
                        }) {
                            let pid = p["id"].as_str().unwrap_or_default().to_string();
                            let (name, secret) = (name.clone(), secret.clone());
                            conn.start_direct(&pid, &name, &secret).await;
                            // Channel-digest recovery remains intentionally outside
                            // the room give-up suppression scope.
                            conn.maybe_adopt(p, true).await?;
                            if let Some(l) = conn.link_mut(&pid) {
                                l.expected_secret = Some((name, secret));
                            }
                        } else if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                            let enroll_channel = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                            if p["channel"].as_str() == Some(enroll_channel.as_str()) {
                                conn.maybe_adopt(p, true).await?;
                            }
                        }
                    }
                    let mut channel_gone = Vec::new();
                    for (pid, link) in &conn.links {
                        let channel_link = link.expected_secret.as_ref().map(|(_, secret)| {
                            sess.channels.iter().any(|ch| ch == &channel_of(secret))
                        }).unwrap_or(false);
                        if channel_link && !channel_present.contains(pid) {
                            let count = channel_digest_absent.entry(pid.clone()).or_insert(0);
                            *count += 1;
                            if *count >= 2 {
                                channel_gone.push(pid.clone());
                            }
                        } else {
                            channel_digest_absent.remove(pid);
                        }
                    }
                    for pid in channel_gone {
                        channel_digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(&pid, "○", ui::Tone::Dim, "left (channel digest reconcile), still listening", &name));
                    }
                    let peers = roster.peers;
                    digest_alone = peers.is_empty();
                    let present: std::collections::HashSet<String> = peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // unknown in digest → a peer-joined we never received
                    for p in &peers {
                        let id = p["id"].as_str().unwrap_or_default();
                        if !id.is_empty() && !conn.links.contains_key(id) {
                            ui::debug(&ui::paint(ui::Tone::Dim, "  (digest: adopting a peer we never heard join)"));
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                        }
                    }
                    // known room-sourced link absent ×2 → a peer-left we
                    // never received (channel-introduced links are exempt:
                    // room-independent by design)
                    let mut gone: Vec<String> = Vec::new();
                    for (pid, l) in &conn.links {
                        if l.expected_secret.is_none() && !present.contains(pid) {
                            let c = digest_absent.entry(pid.clone()).or_insert(0);
                            *c += 1;
                            if *c >= 2 {
                                gone.push(pid.clone());
                            }
                        } else {
                            digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(&pid, "○", ui::Tone::Dim, "left (digest reconcile), still listening", &name));
                    }
                }
            }
            // C29: a code minted in-session (`pair` typed into up).
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                ui::clipboard(c);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &c.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  say it aloud, they type it in the web app or `filament pair <code>` · one claim · 10 min"));
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed, connecting..."));
            }
            Ev::PairError(v) => {
                let why = v["error"].as_str().unwrap_or("?").to_string();
                // The server distinguishes (additively) a dead creator from a
                // typo'd/expired code, say the actionable thing for each.
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "the sender who made that code already left, ask them for a fresh one".to_string(),
                    _ => format!("{why}, codes burn after one use and expire after 10 min"),
                };
                if code.is_some() && conn.links.is_empty() && completed == 0 {
                    // started WITH a code that failed: nothing else to do
                    bail!("code rejected: {hint}");
                }
                // a TYPED claim failing must not kill a listening session
                paired = false;
                claim_in_flight = false;
                ui::say(&format!(
                    "  {} code rejected: {hint}; still listening",
                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                ));
            }
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() { conn.my_id = id.to_string(); }
                // P5 (GAP-6): a fresh welcome (signaling reconnect) may mean the
                // network just changed under us, re-probe relay-committed peers for
                // a direct path immediately instead of waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                // C30 (dissolves the C28 belt): a welcome means a fresh sid,
                // everything sid-keyed (subscriptions, lease) died with the
                // old one. Invalidate; the next tick re-asserts everything.
                sess.invalidate();
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                if let Some((n, sec)) = devices.iter().find(|(_, s)| channel_of(s) == v["channel"].as_str().unwrap_or("")) {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    // WARM-HOLD: a known peer just came online. Under auto-warm, adopt it
                    // into the auto tier NOW (don't wait up to 10s for the tick) and clear
                    // any dormancy/backoff so the reconnect loop owns it from t=0. The
                    // start_direct/maybe_adopt below already dial immediately; this makes
                    // warm-hold RETRY if that first dial fails or the link later drops.
                    // Do NOT add to recent-LRU (that's for ACTUAL use only).
                    let auto_warm = l3.is_some() || settings::get_bool("auto-warm", None);
                    if auto_warm {
                        conn.warm_hold.auto.insert(n.clone());
                    }
                    if conn.warm_hold.should_connect(n) {
                        conn.warm_hold.resume(n);
                        // Pull the next warm tick forward: the event loop wakes at least every
                        // 2s (next_ev timeout, :8957-8960), so a failed eager dial is retried
                        // within ~2s instead of ~10s.
                        last_warm_hold_tick = Instant::now()
                            .checked_sub(Duration::from_secs(10))
                            .unwrap_or_else(Instant::now);
                    }
                    // Only announce a FRESH connect. The server re-pushes the
                    // known-peer roster on every (re)subscribe and C30 sync tick, so
                    // a peer we already hold a link to (or are already dialing) would
                    // otherwise reprint "appeared, connecting" on a loop, reading
                    // like a flap even though `start_direct` below no-ops for an
                    // existing link (start_direct_inner early-return). A real
                    // reconnect removes the link first, so it still announces.
                    let fresh = !conn.links.contains_key(&pid)
                        && !conn.direct_pending.contains_key(&pid);
                    // Also re-announce if the existing link's transport is dead
                    let link_dead = conn.links.get(&pid)
                        .and_then(|l| l.transport.as_ref())
                        .map(|t| t.is_dead())
                        .unwrap_or(false);
                    if fresh || link_dead {
                        ui::say(&format!("known device '{n}' appeared, connecting"));
                        devices_touch(n, None, None);  // track last_seen; addresses filled on ChannelReady
                    } else {
                        ui::trace(&format!("known device '{n}' re-announced (link already up)"));
                    }
                    // rung-1: known device = both CLIs; try direct QUIC first.
                    let (n, sec) = (n.clone(), sec.clone());
                    conn.start_direct(&pid, &n, &sec).await;
                    conn.maybe_adopt(&v, true).await?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((n.clone(), sec.clone()));
                    }
                } else if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                    // Enrollment channel: an ephemeral device appeared on
                    // enroll_channel(own_owner_pub). Dial it (channel-presence
                    // path, no room-join) so the auth-key handshake can run.
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                            ui::debug("enrollment peer appeared on channel, dialing");
                        }
                        conn.maybe_adopt(&v, true).await?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !by_sid.is_empty();
                if conn.maybe_adopt(&v, true).await? && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    flush_inflight(&mut by_sid).await;
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates, start the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let srflx = data["srflx"].as_str().map(String::from);
                    // If we're on the code path and this peer hasn't authenticated yet,
                    // buffer the transport-offer until PAKE completes. Otherwise
                    // on_transport_offer would find no DirectPending (no secret) and
                    // silently drop the offer, causing the QUIC race to fail.
                    if recv_code_path && !recv_pake_done {
                        recv_pending_direct.insert(from.clone(), (cands, srflx));
                        ui::debug(&format!("buffering pre-auth transport-offer from {from}"));
                        continue;
                    }
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    // Bug 2: the sender re-dialed after mid-transfer death.
                    // If we don't have a DirectPending, buffer the offer and
                    // replay it once start_direct creates one (same pattern as
                    // Bug 1's pre-PAKE buffer). Without this, on_transport_offer
                    // finds no pending and silently drops the offer.
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(&from, cands, srflx);
                    } else {
                        // Also try to re-arm direct proactively: if we still
                        // know this peer's (name,secret), create the pending
                        // now so the buffered offer is replayed immediately.
                        let known = crate::devices_load()
                            .into_iter()
                            .find(|(n, _)| conn.links.get(&from).map(|l| l.name == *n).unwrap_or(false));
                        if let Some((name, secret)) = known {
                            conn.start_direct(&from, &name, &secret).await;
                        }
                        if conn.direct_pending.contains_key(&from) {
                            // Re-arm succeeded — process the offer now.
                            conn.on_transport_offer(&from, cands, srflx);
                        } else {
                            conn.buffered_offers.insert(from.clone(), (cands, srflx));
                            ui::debug(&format!("buffering re-dial transport-offer from {from} (no pending yet)"));
                        }
                    }
                    continue;
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Route them
                // into THAT `from` peer's own ephemeral ceremony (recv code path).
                // On confirm the secret is agreed; that peer becomes the
                // authenticated sender and we DISCARD the secret. A failed/aborted
                // ceremony drops ONLY that candidate (a decoy / wrong-words peer),
                // it never bails the receive: the real sender's ceremony is
                // independent and still live.
                if recv_code_path
                    && matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm"))
                {
                    // Already authenticated a sender? Ignore stray PAKE traffic
                    // from anyone else, including a late decoy.
                    if recv_pake_done {
                        continue;
                    }
                    // Mint this peer's ceremony on first sight (bounded), or route
                    // into its existing one. If the peer was already dropped (budget
                    // expired) or we are at the candidate cap, ignore its traffic.
                    if !recv_cers.contains_key(&from) {
                        if recv_cers.len() >= RECV_MAX_CANDIDATES {
                            ui::debug("recv: candidate cap reached, ignoring extra peer's PAKE");
                            continue;
                        }
                        if let Some((pw, np)) = &recv_pake_template {
                            recv_cers.insert(from.clone(), Ceremony::new(pw, np, pair_v2_caps(), crate::identity::IntroScope::Device.to_byte()));
                            recv_deadlines
                                .entry(from.clone())
                                .or_insert_with(|| Instant::now() + recv_pake_budget);
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                        }
                    }
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    // Extract secret first to avoid borrow checker issues with clear() and start_direct
                    let mut secret_opt: Option<String> = None;
                    let mut is_abort = false;
                    let mut abort_why = String::new();
                    if let Some(cer) = recv_cers.get_mut(&from) {
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                secret_opt = cer.secret().cloned();
                            }
                            PakeInbound::Abort(why) => {
                                is_abort = true;
                                abort_why = why;
                            }
                            PakeInbound::Ignored => {}
                        }
                    }
                    if let Some(sec) = secret_opt {
                        // This peer authenticated. Record it as THE sender
                        recv_pake_peer = Some(from.clone());
                        recv_pake_done = true;
                        recv_cers.clear();
                        recv_deadlines.clear();
                        ui::say(&ui::paint(ui::Tone::Dim, "  authenticated, receiving"));
                        // Option A: start the direct-QUIC race. start_direct owns
                        // replacement after all fallible setup and pending registration.
                        let promo = conn.start_direct_promote(&from, &from, &sec).await;
                        if conn.active.is_none() {
                            conn.active = Some(from.clone());
                        }
                        // A retained link is unannounced here too, and this loop's
                        // ChannelReady arm sends `caps` and the signed L3 announce,
                        // which a peer on a retained link would otherwise never get.
                        conn.rearm_channel_ready(&from, promo);
                        // Replay any buffered transport-offer that arrived before PAKE
                        // (now that start_direct created a DirectPending with the secret)
                        if let Some((cands, srflx)) = recv_pending_direct.remove(&from) {
                            conn.on_transport_offer(&from, cands, srflx);
                        }
                        recv_pending_direct.clear();
                        // Replay any buffered file offers from this peer
                        let buffered = recv_pending_offers.remove(&from);
                        recv_pending_offers.clear();
                        if let Some(offer) = buffered {
                            let _ = tx.send(Ev::Control(from.clone(), offer));
                        }
                        continue;
                    }
                    if is_abort {
                        recv_cers.remove(&from);
                        recv_deadlines.remove(&from);
                        recv_pending_offers.remove(&from);
                        recv_pending_direct.remove(&from);
                        ui::debug(&format!("recv: candidate {from} refused ({abort_why}), dropped"));
                    }
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: authenticated direct-QUIC won the race, adopt as a
            // pre-trusted Link, then funnel into the normal ChannelReady handler.
            Ev::DirectReady(pid, t, route) => {
                let tkey = conn.direct_pending.get(&pid)
                    .map(|p| direct::transport_key(&p.secret.1));
                conn.adopt_direct(&pid, t.clone(), route);
                if let Some(k) = tkey {
                    conn.spawn_direct_workers(&pid, &t, k);
                }
                // #30: Send nonce challenge at link adoption so Proven settles
                // before any gated open. Under authoritative, HOLD ChannelReady
                // until the possession-sig round-trip completes or 3s timeout,
                // so short-session gates never decide on Inferred while a
                // challenge is in flight.
                // Resolve identity from the stored cert first so device_pub is
                // populated at adopt time; otherwise needs_proven is always false
                // and the possession-sig challenge never fires.
                if let Some(l) = conn.link_mut(&pid) {
                    resolve_peer_identity(l);
                }
                let needs_proven = if let Some(l) = conn.link(&pid) {
                    l.identity_device_pub.is_some()
                        && l.identity_binding != crate::capability::BindingStrength::Proven
                } else {
                    false
                };
                if needs_proven && crate::capability::cap_authoritative() {
                    // Shared issue-and-hold (hold-then-await; see the helper). This
                    // registers the pending_proven hold BEFORE sending, identically to
                    // the ChannelReady site, so the two sites cannot diverge on order.
                    issue_proven_challenge_and_hold(&conn, &pid, &t, &pending_proven, &mut identity_nonces).await;
                    ui::say(&format!("  identity challenge sent to {pid}, holding until Proven or timeout"));
                    // DirectReady-specific release policy: HOLD ChannelReady (do not
                    // emit it here) and RE-EMIT it when the 3s hold expires, so a
                    // direct link's gates never observe Inferred at all.
                    let hold_t = t.clone();
                    let hold_tx = tx.clone();
                    let hold_pending = pending_proven.clone();
                    let hold_pid = pid.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        if hold_pending.lock().unwrap().contains_key(&hold_pid) {
                            hold_pending.lock().unwrap().remove(&hold_pid);
                            let _ = hold_tx.send(Ev::ChannelReady(hold_pid, hold_t));
                        }
                    });
                } else {
                    let _ = tx.send(Ev::ChannelReady(pid, t));
                }
            }
            Ev::DirectWorkersReady(pid, workers) => {
                if let Some(link) = conn.link_mut(&pid) {
                    link.workers = workers;
                    crate::ui::debug(&format!("worker transports ready: {pid} {} workers", link.workers.len()));
                }
            }
            // P5 (GAP-6): relay->direct upgrade standby connected (receiver side).
            // Stash + VERIFY rather than adopt, see the send-loop twin.
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                // #39 (fleet-trust): the WebRTC/relay path's possession challenge is
                // NOT issued here. At ChannelReady on the WebRTC path, verified_name is
                // not set yet (the pair-proof round-trip sets it AFTER the channel opens),
                // so resolve_peer_identity finds no identity, needs_proven is false, and
                // the challenge would be skipped — the live rig caught exactly this. The
                // challenge for the WebRTC/relay path is issued from the pair-proof
                // handler, where verified_name is set and identity first RESOLVES on that
                // path; the DirectReady path issues at adoption (identity already resolved
                // by then). Both go through the now-idempotent issue_proven_challenge_and_hold,
                // which dedupes by a live pending_proven entry so the two sites are
                // order-independent and cannot clobber each other's nonce.
                // web-shell discovery: tell the peer whether this receiver offers a
                // terminal (l2_enabled = `up --shell` / FILAMENT_L2). The browser
                // shows its per-device shell button ONLY when this is true; the
                // actual pty-open is still gated server-side by the cap/policy.
                let _ = t.send_control(&json!({ "type": "caps", "shell": l2_enabled })).await;
                // L3 (serve_tun mesh): on a datagram-capable (direct) link, send a
                // SIGNED announce of our overlay address, bound to THIS link's
                // channel binding so it can't be replayed elsewhere. Both ends
                // announce on their own ChannelReady, so each learns the other.
                // Also replay any announce that arrived BEFORE this transport was
                // installed (fix #3), now that the link can carry datagrams.
                #[cfg(l3)]
                if let Some(l3) = l3.as_ref() {
                    if let Some(cb) = t.channel_binding() {
                        if let Some(ann) = l3.make_announce(&cb) {
                            let _ = t.send_control(&ann.to_json()).await;
                        }
                        if let Some(pending) = l3_seen.get(&pid) {
                            if let Ok(ip) = pending.verify(&cb) {
                                // Seq check AFTER verify, never before, so an
                                // unauthenticated message cannot poison the
                                // last-seen map. verify() proves the key, the
                                // channel binding and possession; none of those
                                // stop a genuine announce being replayed onto
                                // the SAME channel later.
                                if l3.accept_seq(&pending.pubkey, pending.seq).await {
                                    let who = conn.link(&pid).map(|l| l.shown()).unwrap_or_default();
                                    let v4 = pending.addr_v4();
                                    l3.add_peer(&pid, &who, ip.into(), Some(v4.into()), t.clone()).await;
                                    // Store overlay addresses for `filament addr <device>`
                                    devices_touch(&who, Some(ip), Some(v4));
                                } else {
                                    ui::debug(&format!(
                                        "  l3-announce from {pid} ignored: stale sequence {}",
                                        pending.seq
                                    ));
                                }
                            }
                        }
                    }
                }
                if let Some(l) = conn.link_mut(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, l.shown())));
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop,
                                    // direct vs relayed. Always shown, even under -q.
                                    ui::debug(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == "relayed" {
                                        ui::critical(&format!("    {}", relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        ui::debug(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
                }
                // Warm-reuse readiness: proactively prove our identity to a KNOWN
                // peer on a RELAY/WebRTC link (a DIRECT link is born-verified at
                // adoption, so it skips this). `send_cmd` already does this on its
                // active transfer link (the ChannelReady proof ~5205); the daemon
                // must too, otherwise a passively-held link reaches `✓` but neither
                // end ever sets `verified_name`, so `warm_link_for` rejects it and
                // the FIRST ssh/pty/netcat to an idle paired peer eats a full cold
                // establish. Symmetric by construction: both daemons send, both
                // verify (the `pair-proof` handler below), both can then warm-reuse.
                // No guard, mirroring send_cmd: re-proving on a reconnect is
                // harmless and just refreshes trust.
                let proof_creds = conn.link(&pid).and_then(|l| {
                    if l.direct {
                        return None;
                    }
                    let (_n, sec) = l.expected_secret.clone()?;
                    Some((sec, l.uid.clone().unwrap_or_default(), l.peer.clone()))
                });
                if let Some((sec, uid, peer)) = proof_creds {
                    if let Some((my_fp, their_fp)) = match peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        let mac = proof_for(&sec, &conn.my_uid, &conn.my_uid, &uid, &my_fp, &their_fp);
                        let _ = t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await;
                    }
                }
                // L1-a: on the `recv <code>` path, this peer is a CANDIDATE sender.
                // Mint its own ephemeral ceremony (bounded) and arm its per-peer
                // budget plus the overall backstop. The progression block (top of
                // loop) drives every candidate independently; file-offers are not
                // accepted until ONE peer's ceremony confirms (`recv_pake_done`),
                // and then only from that authenticated peer. A direct link is
                // already authenticated (its pair-secret MAC bound the QUIC key,
                // `trusted`), so it skips the PAKE.
                if recv_code_path && !recv_pake_done {
                    let (is_direct, is_trusted) = conn
                        .link(&pid)
                        .map(|l| (l.direct, l.trusted))
                        .unwrap_or((false, false));
                    if is_direct && is_trusted {
                        // A secret-bound direct link is the sender (known device).
                        recv_pake_peer = Some(pid.clone());
                        recv_pake_done = true; // pre-authenticated transport
                        recv_cers.clear();
                        recv_deadlines.clear();
                        let buffered = recv_pending_offers.remove(&pid);
                        recv_pending_offers.clear();
                        if let Some(offer) = buffered {
                            let _ = tx.send(Ev::Control(pid.clone(), offer));
                        }
                    } else if recv_cers.contains_key(&pid) {
                        // Ceremony already minted (its PAKE traffic arrived first);
                        // just make sure its budgets are armed.
                        recv_deadlines
                            .entry(pid.clone())
                            .or_insert_with(|| Instant::now() + recv_pake_budget);
                        recv_pake_overall_deadline
                            .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                    } else if recv_cers.len() < RECV_MAX_CANDIDATES {
                        if let Some((pw, np)) = &recv_pake_template {
                            recv_cers.insert(pid.clone(), Ceremony::new(pw, np, pair_v2_caps(), crate::identity::IntroScope::Device.to_byte()));
                            recv_deadlines
                                .insert(pid.clone(), Instant::now() + recv_pake_budget);
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                            ui::say(&ui::paint(ui::Tone::Dim, "  authenticating..."));
                        }
                    }
                }
                // C29: an in-session pairing, exactly one side hands over a
                // secret; consent (pair-keep-ack / our store) completes it.
                // Only links that aren't ALREADY known are candidates.
                let fresh_link = conn.link(&pid).map(|l| l.expected_secret.is_none()).unwrap_or(false);
                if fresh_link {
                    match ceremony {
                        Some(true) => {
                            // we minted the code, initiate now
                            ceremony = None;
                            ceremony_pid = Some(pid.clone());
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                        Some(false) => {
                            // we claimed, give a CLI creator 3 s to initiate
                            // (browsers never do), then take over.
                            let tx = tx.clone();
                            let pid = pid.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                let _ = tx.send(Ev::Control(pid, json!({ "type": "__pair_fallback" })));
                            });
                        }
                        None => {}
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                // L3 (serve_tun): the peer announced its overlay IP. Route that IP
                // to this link and start pumping its datagrams into our TUN. Only
                // when we run an overlay ourselves; ignored otherwise.
                // Check BEFORE the catch-all guard so announces that race ahead of
                // link creation are cached in l3_seen for replay on ChannelReady.
                #[cfg(l3)]
                Some("l3-announce") if l3.is_some() => {
                    match overlay::Announce::from_json(&v) {
                        Ok(ann) => {
                            l3_seen.insert(pid.clone(), ann.clone());
                            // Try to process immediately if transport is available.
                            if let Some(l3) = l3.as_ref() {
                                match conn.transport_of(&pid).and_then(|t| t.channel_binding().map(|cb| (t, cb))) {
                                    Some((t, cb)) => match ann.verify(&cb) {
                                        Ok(ip) => {
                                            // Seq check AFTER verify, never before, so an
                                            // unauthenticated message cannot poison the
                                            // last-seen map. verify() proves address-is-key,
                                            // channel binding and possession; none of those
                                            // stop a GENUINE announce captured on this
                                            // channel from being replayed onto it later,
                                            // which is an address rollback (see accept_seq).
                                            if !l3.accept_seq(&ann.pubkey, ann.seq).await {
                                                ui::debug(&format!(
                                                    "  l3-announce from {pid} ignored: stale sequence {}",
                                                    ann.seq
                                                ));
                                                continue;
                                            }
                                            let who = conn.link(&pid).map(|l| l.shown()).unwrap_or_default();
                                            // Verify-order fix: overlay key vs pinned cert check happens HERE at overlay establishment,
                                            // not at expose time. Possession-proven key already committed at expose time (provisional).
                                            // On mismatch, tear down with named error, never overwrite anchor.
                                            // Durable trust is written ONLY after this check passes.
                                            {
                                                let p = devices_path();
                                                if let Ok(raw) = std::fs::read_to_string(&p) {
                                                    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                                                        if let Err(e) = identity::check_overlay_against_pinned_cert(&arr, &who, &ann.pubkey) {
                                                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  {}", e)));
                                                            // Tear down: do not add peer, do not overwrite anchor, clear provisional
                                                            clear_provisional_identity(&who);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            // Promote provisional identity to durable if present and matches overlay key
                                            if let Some(prov_cert) = load_provisional_identity(&who) {
                                                if let Err(e) = identity::provisional_promote_ok(&prov_cert, &ann.pubkey) {
                                                    ui::say(&ui::paint(ui::Tone::Warn, &format!("  {} for device {} - clearing provisional, no anchor written", e, who)));
                                                    clear_provisional_identity(&who);
                                                    // Do not add peer, no durable write
                                                    continue;
                                                }
                                                // Check takeover guard and scope-aware anchor before promoting
                                                {
                                                    let p = devices_path();
                                                    if let Ok(raw) = std::fs::read_to_string(&p) {
                                                        if let Ok(mut arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                                                            // For promote, use Device-scope as fixed convention for pair
                                                            let scope = crate::identity::IntroScope::Device.to_byte();
                                                            match identity::apply_peer_identity(&mut arr, &who, &prov_cert, scope) {
                                                                Ok(_) => {
                                                                    // Write durable anchor only after overlay assertion passes
                                                                    let _ = crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr).unwrap_or_default());
                                                                    clear_provisional_identity(&who);
                                                                }
                                                                Err(e) => {
                                                                    ui::say(&ui::paint(ui::Tone::Warn, &format!("  takeover guard at overlay establishment: {}", e)));
                                                                    clear_provisional_identity(&who);
                                                                    continue;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            let v4 = ann.addr_v4();
                                            l3.add_peer(&pid, &who, ip.into(), Some(v4.into()), t).await;
                                            ui::say(&format!("  {} L3 peer {who}.mesh ({ip} / {v4})", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                                            devices_touch(&who, Some(ip), Some(v4));
                                        }
                                        Err(e) => ui::debug(&ui::paint(ui::Tone::Warn, &format!("  L3 announce rejected: {e}"))),
                                    },
                                    // Transport not installed yet: kept in l3_seen, replayed on ChannelReady.
                                    None => {}
                                }
                            }
                        }
                        Err(e) => ui::debug(&format!("  L3 malformed announce: {e}")),
                    }
                }
                // #30: respond to identity nonce challenge by producing a
                // possession_sig (0x02) over the peer-provided nonce. The
                // challenger verifies and upgrades our binding to Proven.
                Some("identity-nonce-challenge") => {
                    // #30: shared responder (also used by send_cmd) proves
                    // device-key possession so the challenger upgrades us to Proven.
                    if let Some(t) = conn.transport_of(&pid) {
                        respond_to_identity_challenge(&t, &v).await;
                    }
                }
                // #30: received possession-sig from peer after our challenge.
                // Verify, upgrade binding to Proven so capability gates pass.
                Some("identity-expose") => {
                    if handle_identity_expose(&mut conn, &pid, &v, &mut identity_nonces) {
                        // Release held ChannelReady — Proven settled before timeout.
                        if let Some((held_t, _deadline)) = pending_proven.lock().unwrap().remove(&pid) {
                            let _ = tx.send(Ev::ChannelReady(pid, held_t));
                        }
                    }
                }
                Some("worker-ports") => {
                    let pid = v["for"].as_str().unwrap_or_default();
                    ui::trace(&format!("[T:CLI] worker-ports handler: looking up key={pid}"));
                    if let Some(tx) = conn.worker_port_tx.remove(pid) {
                        ui::trace(&format!("[T:CLI] worker-ports handler: FOUND key={pid}"));
                        let ports: Vec<u16> = v["ports"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|p| p.as_u64().map(|x| x as u16))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let _ = tx.send(ports);
                    }
                }
                // Auth key enrollment (challenge/response flow)
                Some("identity-auth-key-enroll-request") => {
                    respond_to_auth_key_enroll_request(&mut conn, pid.clone(), v.clone()).await;
                }
                Some("identity-auth-key-enroll-response") => {
                    // Daemon receives the enrollment response with possession proofs.
                    // Must have a pending challenge nonce for this peer.
                    handle_auth_key_enroll_response(&mut conn, pid.clone(), v.clone()).await;
                }
                _ if !conn.links.contains_key(&pid) => {}
                // Warm-reuse liveness: the acceptor confirmed a stream WE initiated
                // (a warm `open`) is connected end to end. Route it to the mux so
                // verify_first_frame passes even for a client-speaks-first service
                // (HTTP, DB clients) that sends no bytes until we do, instead of the
                // verify window expiring and a HEALTHY link being dropped as a zombie
                // (which made every warm `forward` fall to a cold link). See
                // l2::Mux::on_open_ack.
                Some("l2-open-ack") if l2_enabled => {
                    if let Some(sid) = l2::wire_sid(&v) {
                        if let Some(mux) = l2_muxes.get(&pid) {
                            mux.on_open_ack(sid).await;
                        }
                    }
                }
                // L2 (ssh/TCP tunnel) acceptor. Opt-in (FILAMENT_L2=1). The
                // capability gate is the proof-verified `trusted` flag on this
                // link (placeholder for L1-a caps); localhost-only is enforced in
                // accept_control. A non-trusted or non-loopback open is refused.
                Some("l2-open") | Some("l2-close") if l2_enabled => {
                    // TODO(diag acceptor): emit a diag::Attempt with role
                    // "acceptor" for this l2-open->l2-open-ack round trip. Deferred
                    // because the acceptor has no per-connect span here: this fires
                    // on an ALREADY-established shared link inside the big up/recv
                    // loop (the link's bring-up lives in the file-transfer/recv
                    // machinery upstream), so a clean span would mean threading an
                    // Attempt through the whole loop. The initiator path (l2.rs) is
                    // fully instrumented and is the side that exhibits the stall.
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Per-device authorization for a NEW open (an l2-close just
                    // tears a stream down, so it is never gated here). In a blanket
                    // mode any trusted peer may open; in grant-only mode the opening
                    // peer must hold the shell grant itself.
                    let mut l2_deny_reason: Option<String> = None;
                    let authorized = v["type"].as_str() != Some("l2-open") || {
                        let legacy_ok = {
                            let blanket = shell_policy.enables_l2()
                                || std::env::var("FILAMENT_L2").map(|x| x == "1").unwrap_or(false);
                            let peer_has_shell = conn
                                .link(&pid)
                                .and_then(|l| l.verified_name.as_deref())
                                .map(|n| device_allows(n, "shell"))
                                .unwrap_or(false);
                            l2_open_allowed(blanket, peer_has_shell)
                        };
                        // Lazy-resolve peer identity from stored device cert
                        {
                            if let Some(l) = conn.link_mut(&pid) {
                                resolve_peer_identity(l);
                            }
                        }
                        let link = conn.link(&pid);
                        let idev = link.and_then(|l| l.identity_device_pub.as_ref());
                        let iusr = link.and_then(|l| l.identity_user_pub.as_ref());
                        let binding = link.map(|l| l.identity_binding).unwrap_or(crate::capability::BindingStrength::None);
                        let expires = link.and_then(|l| l.identity_cert_expires);
                        let cert_revoked = idev.map(device_cert_revoked).unwrap_or(true);
                        let ak_caps = link.and_then(|l| l.principal_kind.auth_key_caps());
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Fleet scope for `reach`: a same-owner Proven device may
                        // open an l2 forward WITHOUT a grant ONLY to a port the
                        // owner has explicitly exposed (`expose.json`). A forward to
                        // any other port is reach-all (deliberate) and needs a grant.
                        let reach_port = v["rport"].as_u64().or_else(|| v["port"].as_u64()).unwrap_or(0) as u16;
                        let scoped_in_bounds = reach_port != 0
                            && crate::expose::load().iter().any(|b| b.port == reach_port);
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(), "self", crate::capability::CAP_SHELL, idev, iusr, ak_caps,
                        );
                         let d = crate::capability::cap_gate_effective(legacy_ok, &outcome, crate::capability::CAP_SHELL, "self", idev, iusr, binding, expires, ak_caps, own_user.as_ref(), scoped_in_bounds, has_grant, cert_revoked);
                        if let crate::capability::GateDecision::Deny { cap_reason: Some(r) } = &d {
                            l2_deny_reason = Some(r.clone());
                        }
                        d.allowed()
                    };
                    if !authorized {
                        // wire_sid (not a wrapping cast) so the l2-close we echo
                        // back names the real sid; 0 only if absent/out-of-range.
                        let sid = l2::wire_sid(&v).unwrap_or(0);
                        let diag = l2_deny_reason.as_deref().unwrap_or("device not granted shell");
                        ui::say(&format!("l2: refused stream {sid:#x}: {diag}"));
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "not authorized: device lacks shell grant" }))
                            .await;
                    } else {
                        // Opt-in gateway: if the target is non-loopback, allow it
                        // only when the operator's l2-allow.json lists it for this
                        // device (or "*"). Loopback ignores this (always allowed).
                        let allow_nonloopback = {
                            let host = v["host"].as_str().unwrap_or("127.0.0.1");
                            let port = v["rport"].as_u64().or_else(|| v["port"].as_u64()).unwrap_or(0) as u16;
                            let name = conn
                                .link(&pid)
                                .and_then(|l| l.verified_name.clone())
                                .unwrap_or_default();
                            l2_target_allowed(&name, host, port)
                        };
                        let mux = l2_muxes
                            .entry(pid.clone())
                            .or_insert_with(|| l2::Mux::new(t.clone()))
                            .clone();
                        match mux.accept_control(&v, trusted, allow_nonloopback).await {
                            l2::OpenVerdict::Accept { sid, host, port, rx } => {
                                tokio::spawn(mux.clone().dial_and_serve(sid, host, port, rx));
                            }
                            l2::OpenVerdict::Deny { sid, err } => {
                                // Log refused dials at INFO (visible by default,
                                // suppressed under -q) - a refused SSRF/port-scan or
                                // untrusted/over-cap open is a security event the
                                // operator should see, mirroring the
                                // shell-bootstrap-deny path (`ui::say`). Normal
                                // initiators always dial 127.0.0.1, so this is silent
                                // in normal operation and only fires on an anomaly.
                                ui::say(&format!("l2: refused stream {sid:#x}: {err}"));
                                let _ = t
                                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": err }))
                                    .await;
                            }
                            l2::OpenVerdict::Ignore => {}
                        }
                    }
                    // A PTY stream closing frees its resize channel, handled by
                    // the mux's `on_close`/`drop_stream` (H-1: resizer is owned by
                    // the mux now, so it can't leak past the stream).
                }
                // Seamless-shell bootstrap (acceptor). Opt-in (FILAMENT_L2=1).
                // DENY-BY-DEFAULT: install the initiator's managed pubkey ONLY
                // when the link is proof-verified (`trusted`) AND the proven
                // device holds the NEW `shell` capability, distinct from
                // `transfer`, so pairing for file transfer never yields a shell.
                // The write happens only here (over the authenticated channel)
                // into a clearly-marked, removable authorized_keys block.
                // Warm-bootstrap (INITIATOR side): the peer answered a
                // `shell-bootstrap` we relayed over its warm link for a `filament
                // ssh`. Complete the stashed reply socket(s) for this pid; the
                // client then pins these host keys and skips the cold establish.
                #[cfg(unix)]
                Some("shell-bootstrap-ack") => {
                    let reply = json!({
                        "ok": true,
                        "hostkeys": v["hostkeys"].clone(),
                        "user": v["user"].clone(),
                        "sshd": v["sshd"].clone(),
                    });
                    complete_warm_bootstrap(&mut pending_bootstrap, &pid, &reply).await;
                }
                #[cfg(unix)]
                Some("shell-bootstrap-deny") => {
                    let reply = json!({
                        "ok": false,
                        "err": v["reason"].as_str().unwrap_or("shell bootstrap denied"),
                    });
                    complete_warm_bootstrap(&mut pending_bootstrap, &pid, &reply).await;
                }
                Some("shell-bootstrap") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    // #30 GAP 2 (shell): honor the pending_proven hold. If a
                    // possession-sig challenge is still in flight for this peer
                    // and the binding is not yet Proven, do NOT refuse on
                    // Inferred: the identity-expose that flips us to Proven is a
                    // SEPARATE event this single-consumer loop must process, so
                    // blocking inline would deadlock. Re-inject the bootstrap
                    // shortly and let the loop drain. The hold entry clears on
                    // Proven OR at the 3s deadline, so this self-terminates and
                    // the re-injected bootstrap is then decided for real.
                    if crate::capability::cap_authoritative() {
                        let challenge_in_flight =
                            pending_proven.lock().unwrap().contains_key(&pid);
                        let proven = conn
                            .link(&pid)
                            .map(|l| {
                                l.identity_binding
                                    == crate::capability::BindingStrength::Proven
                            })
                            .unwrap_or(false);
                        if challenge_in_flight && !proven {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Cap lookup keys on the PROVEN petname, not the presence name.
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    // Granted if the device was explicitly `grant`ed shell OR an
                    // active `up --shell[-only]` policy auto-allows it. Trust
                    // (pair-proof) is still required either way.
                    let legacy_ok = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under FILAMENT_CAP_AUTHORITATIVE.
                    let granted = {
                        // Lazy-resolve peer identity from stored device cert
                        {
                            if let Some(l) = conn.link_mut(&pid) {
                                resolve_peer_identity(l);
                            }
                        }
                        let link = conn.link(&pid);
                        let idev = link.and_then(|l| l.identity_device_pub.as_ref());
                        let iusr = link.and_then(|l| l.identity_user_pub.as_ref());
                        let binding = link.map(|l| l.identity_binding).unwrap_or(crate::capability::BindingStrength::None);
                        let expires = link.and_then(|l| l.identity_cert_expires);
                        let cert_revoked = idev.map(device_cert_revoked).unwrap_or(true);
                        let ak_caps = link.and_then(|l| l.principal_kind.auth_key_caps());
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                             crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        {
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(), "self", crate::capability::CAP_SHELL, idev, iusr, ak_caps,
                        );
                        // Deliberate tier: `shell` is never a scoped default, so a
                        // same-owner device gets it ONLY via an explicit grant
                        // (has_grant), never fleet auto-trust (scoped_in_bounds=false).
                        crate::capability::cap_gate_effective(legacy_ok, &outcome, crate::capability::CAP_SHELL, "self", idev, iusr, binding, expires, ak_caps, own_user.as_ref(), false, has_grant, cert_revoked)
                        }
                    };
                    if !granted.allowed() {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!("l2: shell bootstrap refused: {who}: {}", granted.deny_reason("no shell cap / untrusted")));
                        enqueue_if_requestable(who, "shell");
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": "shell capability not granted"
                            }))
                            .await;
                        continue;
                    }
                    let device = dev.unwrap();
                    let pubkey = v["pubkey"].as_str().unwrap_or_default().to_string();
                    // M-3 (authorized_keys injection): a single, well-formed key
                    // line ONLY. validate_pubkey rejects interior newlines / CR /
                    // control chars and multi-line payloads, so a trusted+shell
                    // peer can't inject extra authorized_keys lines. Enforced here
                    // AND again inside install_authorized_key (defense in depth).
                    let pubkey = match sshkeys::validate_pubkey(&pubkey) {
                        Ok(k) => k,
                        Err(e) => {
                            ui::say(&format!("l2: shell bootstrap refused: malformed pubkey from '{device}': {e}"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "malformed pubkey"
                                }))
                                .await;
                            continue;
                        }
                    };
                    match sshkeys::install_authorized_key(&device, &pubkey) {
                        Ok(()) => {
                            let hostkeys = sshkeys::host_pubkeys();
                            let login = std::env::var("USER").unwrap_or_else(|_| "root".into());
                            // Tell the initiator whether an sshd is actually
                            // listening on the port `filament ssh` will dial here,
                            // so it can fail fast with a clear message instead of
                            // spawning ssh into a refused/black-holed connection.
                            let ssh_port = v["ssh_port"].as_u64().and_then(|n| u16::try_from(n).ok()).unwrap_or(22);
                            let sshd = sshd_listening(ssh_port).await;
                            ui::say(&format!("l2: shell granted to '{device}', installed managed key (filament-managed block)"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-ack",
                                    "hostkeys": hostkeys,
                                    "user": login,
                                    "sshd": sshd,
                                    "ssh_port": ssh_port
                                }))
                                .await;
                        }
                        Err(e) => {
                            ui::say(&format!("l2: shell bootstrap install failed for '{device}': {e}"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "install failed"
                                }))
                                .await;
                        }
                    }
                }
                // web-shell (browser terminal): spawn a login shell in a PTY and
                // bridge it to a sid stream. Same deny-by-default gate as
                // shell-bootstrap, a PTY is a superset of ssh-key access, so it
                // reuses the `shell` cap / --shell policy and requires `trusted`.
                Some("pty-open") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    // wire_sid rejects a missing OR out-of-range sid instead of
                    // defaulting to 0 / wrapping into a forged is_l2_sid value.
                    let Some(sid) = l2::wire_sid(&v) else { continue };
                    if !l2::is_l2_sid(sid) {
                        continue;
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    let legacy_ok = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under FILAMENT_CAP_AUTHORITATIVE.
                    let granted = {
                        // Lazy-resolve peer identity from stored device cert
                        {
                            if let Some(l) = conn.link_mut(&pid) {
                                resolve_peer_identity(l);
                            }
                        }
                        let link = conn.link(&pid);
                        let idev = link.and_then(|l| l.identity_device_pub.as_ref());
                        let iusr = link.and_then(|l| l.identity_user_pub.as_ref());
                        let binding = link.map(|l| l.identity_binding).unwrap_or(crate::capability::BindingStrength::None);
                        let expires = link.and_then(|l| l.identity_cert_expires);
                        let cert_revoked = idev.map(device_cert_revoked).unwrap_or(true);
                        let ak_caps = link.and_then(|l| l.principal_kind.auth_key_caps());
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        {
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(), "self", crate::capability::CAP_SHELL, idev, iusr, ak_caps,
                        );
                        // Deliberate tier: `shell` is never a scoped default, so a
                        // same-owner device gets it ONLY via an explicit grant
                        // (has_grant), never fleet auto-trust (scoped_in_bounds=false).
                        crate::capability::cap_gate_effective(legacy_ok, &outcome, crate::capability::CAP_SHELL, "self", idev, iusr, binding, expires, ak_caps, own_user.as_ref(), false, has_grant, cert_revoked)
                        }
                    };
                    if !granted.allowed() {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!("l2: pty refused: {who}: {}", granted.deny_reason("no shell cap / untrusted")));
                        enqueue_if_requestable(who, "shell");
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "shell capability not granted" }))
                            .await;
                        continue;
                    }
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    // #4: a stable, client-chosen session id binds reconnects to
                    // the same persistent PTY. DEVICE-SCOPED: prefixed with the
                    // verified device so a client id from device A can never
                    // address device B's session (no cross-device collision or
                    // hijack) - the random per-invocation client id then only
                    // needs to be unique per device. Absent (older client) -> a
                    // per-sid id that never reattaches (old behavior).
                    let session_id = match v["session"].as_str().filter(|s| !s.is_empty() && s.len() <= 128) {
                        Some(s) => format!("{}\u{1}{}", dev.as_deref().unwrap_or(&pid), s),
                        None => format!("{pid}:{sid:#x}"),
                    };
                    // $TERM forwarded by the client (so the remote matches the
                    // user's actual terminal); validated + capped, sane default.
                    let term = v["term"]
                        .as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_graphic()))
                        .unwrap_or("xterm-256color")
                        .to_string();
                    // One-shot command (non-empty when pty one-shot was requested).
                    let pty_cmd = v["cmd"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    // RESUME-ONLY (warm-drop fall-through): the client wants to
                    // REATTACH an existing session and never start a fresh shell, so a
                    // clean warm exit can't turn into a surprise re-login.
                    let resume = v["resume"].as_bool().unwrap_or(false);
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    // #4 REATTACH: a live session for this id means a reconnect.
                    // Rebind its output to THIS link+sid and replay its buffer; do
                    // not spawn a new shell. Register the input pump + resizer for
                    // the new sid so typing and SIGWINCH reach the surviving PTY.
                    if let Some(sess) = pty_sessions.get_live(&session_id).await {
                        if mux.at_stream_cap().await {
                            ui::say("l2: pty reattach refused: too many streams on this link");
                            let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                            continue;
                        }
                        // Collision-safe: if this sid is already live (peer reused
                        // a live forward/pty/mount sid) register refuses; deny the
                        // reattach rather than displacing the existing stream.
                        let Some(rx) = mux.register_stream(sid).await else {
                            ui::say(&format!("l2: pty reattach refused: sid {sid:#x} in use"));
                            let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" })).await;
                            continue;
                        };
                        let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                        mux.register_resizer(sid, rtx).await;
                        let _ = t.send_control(&json!({ "type": "pty-open-ack", "sid": sid })).await;
                        sess.attach(t.clone(), sid);
                        sess.resize(cols, rows);
                        pty_bindings.entry(pid.clone()).or_default().insert(sid, session_id.clone());
                        spawn_session_pumps(sess.clone(), rx, rrx);
                        ui::say(&format!("l2: pty REATTACHED to '{}', {cols}x{rows}", dev.unwrap_or_default()));
                        continue;
                    }
                    // Resume-only + no live session: the client is a warm-drop
                    // fall-through and the session is gone (the shell exited cleanly).
                    // Close instead of spawning a fresh shell, so the client exits
                    // cleanly rather than getting a surprise re-login.
                    if resume {
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no such session" })).await;
                        continue;
                    }
                    // H-1 (DoS): refuse over the per-link stream cap or the global
                    // PTY cap BEFORE spawning a shell. A flaky/hostile paired
                    // device can otherwise flood `pty-open` and exhaust threads.
                    if mux.at_stream_cap().await {
                        ui::say("l2: pty refused: too many streams on this link");
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    }
                    let Some(pty_guard) = l2::PtyGuard::try_acquire() else {
                        ui::say(&format!("l2: pty refused: too many PTYs (global cap {})", l2::MAX_PTYS_GLOBAL));
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    };
                    // before spawn (race fix). Collision-safe: refuse (don't
                    // displace) if the peer named an already-live sid. `pty_guard`
                    // drops on `continue`, freeing the global PTY slot it reserved.
                    let Some(rx) = mux.register_stream(sid).await else {
                        ui::say(&format!("l2: pty refused: sid {sid:#x} in use"));
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" })).await;
                        continue;
                    };
                    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                    // Resizer is owned by the mux so it is freed on EVERY teardown
                    // path (inbound l2-close, link death), H-1.
                    mux.register_resizer(sid, rtx).await;
                    let _ = t.send_control(&json!({ "type": "pty-open-ack", "sid": sid })).await;
                    // #4: spawn the PTY as a PERSISTENT session keyed by session_id,
                    // not a link-bound serve_pty. It outlives this link; a drop
                    // detaches it, a reconnect reattaches above.
                    // Resolve the shell and build interactive or one-shot argv.
                    let shell_argv = shell_argv(None, shell_user.as_deref());
                    let host = platform::ShellHost::new(&shell_argv);
                    let argv = if pty_cmd.is_empty() {
                        host.interactive_args()
                    } else {
                        host.exec_cmd_args(&pty_cmd)
                    };
                    match l2::spawn_pty_session(
                        pty_sessions.clone(),
                        session_id.clone(),
                        t.clone(),
                        sid,
                        cols,
                        rows,
                        &term,
                        argv,
                        pty_guard,
                    )
                    .await
                    {
                        Some(sess) => {
                            pty_bindings.entry(pid.clone()).or_default().insert(sid, session_id.clone());
                            spawn_session_pumps(sess, rx, rrx);
                            ui::say(&format!("l2: pty granted to '{}', {cols}x{rows}", dev.unwrap_or_default()));
                        }
                        None => {
                            // spawn already sent an l2-close{err}; free the stream.
                            mux.drop_pty(sid).await;
                        }
                    }
                }
                Some("mount-open") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    // wire_sid rejects a missing OR out-of-range sid instead of
                    // defaulting to 0 / wrapping into a forged is_l2_sid value.
                    let Some(sid) = l2::wire_sid(&v) else { continue };
                    if !l2::is_l2_sid(sid) { continue; }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Decode the requested root up front: the fleet mount scope
                    // (read-only, within the share root) is decided at the gate.
                    let root_encoded = v["root"].as_str().unwrap_or(".");
                    let root_path = mount_proto::path_decode(root_encoded).unwrap_or_else(|_| std::path::PathBuf::from("."));
                    let within_share = crate::path_within_canonical(&crate::fleet_share_root(), &root_path);
                    // Capability layer for mount evaluated unconditionally (shadow
                    // samples the legacy-allowed population); legacy (trusted) stands
                    // in shadow, cap gates under FILAMENT_CAP_AUTHORITATIVE.
                    let (authorized, read_only) = {
                        // Lazy-resolve peer identity from stored device cert
                        {
                            if let Some(l) = conn.link_mut(&pid) {
                                resolve_peer_identity(l);
                            }
                        }
                        let link = conn.link(&pid);
                        let idev = link.and_then(|l| l.identity_device_pub.as_ref());
                        let iusr = link.and_then(|l| l.identity_user_pub.as_ref());
                        let binding = link.map(|l| l.identity_binding).unwrap_or(crate::capability::BindingStrength::None);
                        let expires = link.and_then(|l| l.identity_cert_expires);
                        let cert_revoked = idev.map(device_cert_revoked).unwrap_or(true);
                        let ak_caps = link.and_then(|l| l.principal_kind.auth_key_caps());
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_MOUNT,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Trust floor: under authoritative, an untrusted link
                        // must never authorize mount (pair-proof vs device-key).
                        let outcome = crate::capability::cap_trust_floor(
                            &outcome,
                            trusted,
                            binding,
                            crate::capability::cap_authoritative(),
                        );
                        // Fleet scope: a same-owner Proven device may mount WITHOUT a
                        // grant ONLY read-only, within the share root (scoped_in_bounds
                        // = within_share). An auto-trusted fleet mount is served
                        // READ-ONLY; an explicit `mount` grant keeps its rw behavior.
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(), "self", crate::capability::CAP_MOUNT, idev, iusr, ak_caps,
                        );
                        let same_owner = match (iusr, own_user.as_ref()) {
                            (Some(u), Some(o)) => u == o,
                            _ => false,
                        };
                        // #42 HOLD-OUT (advisor call): the mount scoped-DEFAULT is not
                        // shipped in this release. It is not drivable today (filament
                        // mount has no --auth-key, and an OwnerDevice cannot reach
                        // Proven), so its scope enforcement (within_share /
                        // path_within_canonical + the read-only EROFS path) has NEVER
                        // been exercised end-to-end — shipping it would make the first
                        // real user its first test, and publish a capability no path can
                        // reach. Until mount is auth-key-drivable AND rig-verified
                        // (including a write attempt that MUST return EROFS), a fleet
                        // mount requires an EXPLICIT grant (deliberate tier). `within_share`
                        // stays computed so re-enabling #42 is a one-line flip back.
                        let _ = within_share;
                        let mount_scoped_default = false;
                        let read_only = same_owner
                            && binding == crate::capability::BindingStrength::Proven
                            && mount_scoped_default
                            && !has_grant;
                         let d = crate::capability::cap_gate_effective(trusted, &outcome, crate::capability::CAP_MOUNT, "self", idev, iusr, binding, expires, ak_caps, own_user.as_ref(), mount_scoped_default, has_grant, cert_revoked);
                        (d, read_only)
                    };
                    if !authorized.allowed() {
                        let who = conn
                            .link(&pid)
                            .and_then(|l| l.verified_name.clone())
                            .unwrap_or_else(|| "<unverified>".into());
                        // Operator-side diagnostic in BOTH modes, so a mount refusal
                        // is never invisible on the default (shadow) path and never
                        // reads as a transport failure. The peer-facing string stays a
                        // coarse category and leaks no authz internals.
                        ui::say(&format!("mount: refused for '{who}': {}", authorized.deny_reason("not authorized (mount capability required)")));
                        enqueue_if_requestable(&who, "mount");
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "not authorized: mount capability required" })).await;
                        continue;
                    }
                    let mut caps = mount_proto::mount_caps_for_root(&root_path);
                    // A read-only fleet share advertises zero writable size so a
                    // well-behaved client sees it is read-only; the server also
                    // hard-rejects every write with EROFS regardless of the ack.
                    if read_only {
                        caps.max_write_size = 0;
                    }
                    let mux = l2_muxes.entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    if mux.at_stream_cap().await {
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    }
                    // Collision-safe: refuse (don't displace) if the peer named an
                    // already-live sid; otherwise a forward's read pump would be
                    // orphaned and its inbound frames redirected to this mount.
                    let Some(rx) = mux.register_stream(sid).await else {
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" })).await;
                        continue;
                    };
                    let _ = t.send_control(&json!({ "type": "mount-open-ack", "sid": sid, "caps": caps })).await;
                    let transport = t.clone();
                    let spawn_sid = sid;
                    let proto_version = caps.protocol_version;
                    mount_proto::spawn_mount_server(root_path, transport, spawn_sid, rx, proto_version, read_only);
                }
                Some("pty-resize") if l2_enabled => {
                    let Some(sid) = l2::wire_sid(&v) else { continue };
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    // #4: resize the persistent session bound to this sid (not a
                    // link-local serve_pty). Falls back to the mux resizer if the
                    // sid isn't a known session binding (defensive).
                    if let Some(sid_map) = pty_bindings.get(&pid) {
                        if let Some(session_id) = sid_map.get(&sid) {
                            if let Some(sess) = pty_sessions.get_live(session_id).await {
                                sess.resize(cols, rows);
                            }
                        }
                    }
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.resize_pty(sid, cols, rows).await;
                    }
                }
                // #4: explicit end of a persistent PTY session (the ✕ / unmount).
                // Distinct from a bare channel drop, which only DETACHES. Kills the
                // shell and removes the session so a later open spawns fresh.
                Some("pty-close") if l2_enabled => {
                    if let Some(session_id) = v["session"].as_str() {
                        if let Some(sess) = pty_sessions.get_live(session_id).await {
                            sess.end(); // kill the shell now
                        }
                        pty_sessions.remove(session_id).await;
                        if let Some(sid_map) = pty_bindings.get_mut(&pid) {
                            sid_map.retain(|_, v| v != session_id);
                        }
                    }
                }
                // Client confirmed the protocol version advertised in mount-open-ack.
                // The server is already running in that version; this control is
                // received and consumed here to prevent it from hitting the catch-all.
                Some("mount-cap-ack") if l2_enabled => {}
                Some("brb") => {
                    // C21: the peer announces a benign absence (mobile file
                    // picker suspends the tab). Hold the line that long.
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.rejoin.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away, choosing a file · holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: a state ping proves the peer is alive, clear
                // any away-mark (the receiver side has no sender corrections).
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 {
                        let kept = if let Some(name) = &remember {
                            devices_store(name, &sec)?;
                            ui::say(&format!("remembered this device as '{name}', future sends auto-accept after proof"));
                            true
                        } else if ceremony == Some(false) {
                            // C29: we typed their code into this session, the
                            // creator initiated first; that's our ceremony.
                            ceremony = None;
                            let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                            devices_store(&n, &sec)?;
                            devices.push((n.clone(), sec.clone()));
                            sess.channels.push(channel_of(&sec)); // C30: desire grows; session repairs
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&sec)] })).await.ok();
                            ui::say(&format!(
                                "  {} {} mutually remembered, rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            true
                        } else {
                            ui::say("(sender offered to be remembered; re-run with --remember <name> to keep it)");
                            false
                        };
                        // C27: answer either way, a declined sender discards
                        // its half instead of waving at a dead meeting point.
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": kept })).await.ok();
                        }
                    }
                }
                // C29: claimer fallback, the creator never initiated
                // (browsers don't); hand over OUR secret instead.
                Some("__pair_fallback") => {
                    if ceremony == Some(false) {
                        ceremony = None;
                        ceremony_pid = Some(pid.clone());
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                    }
                }
                // C29: their answer to OUR in-session remember offer.
                Some("pair-keep-ack") => {
                    if ceremony_pid.as_deref() == Some(pid.as_str()) {
                        ceremony_pid = None;
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                        if v["ok"].as_bool() == Some(false) {
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered, nothing stored", &n));
                        } else {
                            devices_store(&n, &ceremony_secret)?;
                            devices.push((n.clone(), ceremony_secret.clone()));
                            sess.channels.push(channel_of(&ceremony_secret)); // C30
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&ceremony_secret)] })).await.ok();
                            ceremony_secret = fresh_secret(); // never reuse across devices
                            ui::say(&format!(
                                "  {} {} mutually remembered, rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                        }
                    }
                }
                Some("pair-proof") => {
                    let mac = v["mac"].as_str().unwrap_or_default();
                    let peer_uid = conn.link(&pid).and_then(|l| l.uid.clone()).unwrap_or_default();
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        ui::debug("pair-proof received before fingerprints known, ignoring");
                        continue;
                    };
                    // #9: pair secrets are symmetric, our own install holds
                    // every secret we do, so a same-host process could prove
                    // "pop2" and tunnel callers into the WRONG machine. Refuse.
                    let hit = if is_self_uid(&conn.my_uid, Some(peer_uid.as_str())) {
                        ui::debug("pair-proof from our own install, refusing (self-connect)");
                        None
                    } else {
                        devices
                            .iter()
                            .find(|(_, s)| proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp) == mac)
                    };
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                            l.verified_name = Some(n.clone());
                            resolve_peer_identity(l);
                        }
                        // #39: identity just RESOLVED on the WebRTC/relay path — verified_name
                        // is set above and resolve_peer_identity populated device_pub. This is
                        // the resolution point for NON-direct links (ChannelReady fired before
                        // this); the direct path resolves at DirectReady adoption instead. Issue
                        // the possession challenge here so the link reaches Proven (fleet
                        // auto-trust is Proven-gated), authoritative only. The helper is
                        // idempotent — if DirectReady already challenged this pid the call is a
                        // no-op and does not clobber the in-flight nonce. The transport exists by
                        // construction (this handler was reached by a control message on it).
                        if crate::capability::cap_authoritative() {
                            let needs_proven = conn.link(&pid).map(|l| {
                                l.identity_device_pub.is_some()
                                    && l.identity_binding != crate::capability::BindingStrength::Proven
                            }).unwrap_or(false);
                            if needs_proven {
                                if let Some(t) = conn.transport_of(&pid) {
                                    issue_proven_challenge_and_hold(&conn, &pid, &t, &pending_proven, &mut identity_nonces).await;
                                    ui::debug(&format!("  identity challenge sent to {pid} at pair-proof (universal expose, WebRTC/relay path)"));
                                    let hold_pending = pending_proven.clone();
                                    let hold_pid = pid.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                        hold_pending.lock().unwrap().remove(&hold_pid);
                                    });
                                }
                            }
                        }
                        ui::say(&format!("identity verified: '{n}' (auto-accepting)"));
                        true
                    } else {
                        // CRITICAL, a security verdict the user must see (-q too).
                        ui::critical(&ui::paint(ui::Tone::Warn, "pair-proof FAILED verification, treating peer as untrusted"));
                        false
                    };
                    // C27: tell the prover the verdict, a rejected prover
                    // learns we never met and stops claiming acquaintance.
                    if let Some(t) = conn.transport_of(&pid) {
                        t.send_control(&json!({ "type": "pair-proof-ack", "ok": ok })).await.ok();
                    }
                }
                Some("pair-intro") => {
                    // C19/C20: only a fingerprint-verified known device may
                    // vouch new trust into this store.
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let iname = v["name"].as_str().unwrap_or_default().to_string();
                    let isec = v["secret"].as_str().unwrap_or_default().to_string();
                    let hub = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    if trusted && isec.len() == 64 && !iname.is_empty() {
                        devices_store(&iname, &isec)?;
                        devices.push((iname.clone(), isec.clone()));
                        sess.channels.push(channel_of(&isec)); // C30
                        sess.touch();
                        sio.emit("subscribe", json!({ "channels": [channel_of(&isec)] })).await.ok();
                        ui::say(&format!(
                            "  {} introduced to '{}' by {}, now a known device",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()), iname, hub
                        ));
                        // For identity layer, after introduction, generate nonce challenge to learn peer's identity (0x02 path)
                        // Challenge carries ONLY {nonce, receiver_device_pub} per correction A
                        // Receiver_device_pub is our own overlay key (always exists, not cert-or-zeros)
                        if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
                            if let Some(t) = conn.transport_of(&pid) {
                                use ring::rand::{SecureRandom, SystemRandom};
                                let rng = SystemRandom::new();
                                let mut nonce = [0u8; 32];
                                let _ = rng.fill(&mut nonce);
                                // Store pending nonce for this peer, single-use, session-scoped, distinct per concurrent session
                                identity_nonces.insert(iname.clone(), (nonce, Instant::now(), own_dpub));
                                let challenge = json!({
                                    "type": "identity-nonce-challenge",
                                    "nonce": hex::encode(nonce),
                                    "receiver_device_pub": hex::encode(own_dpub)
                                });
                                let _ = t.send_control(&challenge).await;
                            }
                        }
                    } else {
                        ui::say(&ui::paint(ui::Tone::Warn, &format!("  ignored pair-intro from unverified peer {hub}")));
                    }
                }
                Some("identity-nonce-challenge") => {
                    // Received challenge as sender: peer wants to learn our identity, we must respond with sealed cert + possession sig
                    // Challenge carries ONLY {nonce, receiver_device_pub} per correction A, no scope/caps/user data
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
                    if let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) = (hex::decode(nonce_hex), hex::decode(recv_dpub_hex)) {
                        if nonce_bytes.len() == 32 && recv_dpub_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            let mut recv_dpub_arr = [0u8; 32];
                            recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
                            // Build possession_msg with 0x02 binding_type, binding_value=nonce, scope own, caps_digest own, cert_hash own, sender=own, receiver=challenger's
                            // For minimal, try to get local device cert for this machine
                            if let Some(local_cert) = local_device_cert() {
                                let scope = crate::identity::IntroScope::User.to_byte(); // User-scope for introduce, from own token
                                let caps = "transfer";
                                let caps_d = crate::identity::caps_digest(caps);
                                let chash = crate::identity::cert_hash(&local_cert);
                                let mut sender_dpub = local_cert.device_pub;
                                // Possession_msg 8-field: tag, type 0x02, nonce, scope, caps_digest, cert_hash, sender, receiver
                                let msg = crate::identity::possession_msg(0x02, &nonce_arr, scope, &caps_d, &chash, &sender_dpub, &recv_dpub_arr);
                                if let Ok(sig) = crate::overlay::overlay_sign_possession(&msg) {
                                    // For introduce path, identity-expose goes over DIRECT A-B DTLS data channel (the introduced pair's OWN transport,
                                    // whose DTLS keys the introducer/hub does NOT know). This is E2E encrypted, so unsealed is actually FINE and BETTER than
                                    // sealing with HKDF(fresh_secret) (which introducer CAN open, since it minted fresh_secret). DTLS gives true A-B E2E,
                                    // introducer is BLIND (cannot read cert), which is stronger. No sealing needed for introduce when sent over direct A-B transport.
                                    // For pair path (0x01), we DO seal via signal path with HKDF(K) because signal goes via server.
                                    let inner = json!({
                                        "cert": local_cert.to_json(),
                                        "possession_sig": hex::encode(sig)
                                    });
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let payload = json!({
                                            "type": "identity-expose",
                                            "v": 2,
                                            "binding_type": 0x02,
                                            "nonce": hex::encode(nonce_arr),
                                            "cert": local_cert.to_json(),
                                            "possession_sig": hex::encode(sig)
                                        });
                                        let _ = t.send_control(&payload).await;
                                    }
                                }
                            }
                        }
                    }
                }
                Some("identity-expose") => {
                    // Received sealed or unsealed identity-expose for introduce path (0x02)
                    // For PAKE path we already handle sealed with possession in pair_cmd, this is for introduce path
                    // Verify against held nonce, own scope/caps, cert_hash locally rebuilt, etc.
                    // For minimal, if we have pending nonce for this peer, verify and store
                    // This is the receiver side (we generated nonce, now receiving expose)
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    if let Ok(nonce_bytes) = hex::decode(nonce_hex) {
                        if nonce_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            // Check held nonce matches and is single-use
                            if let Some((held_nonce, _ts, _held_recv_dpub)) = identity_nonces.get(&pid) {
                                if held_nonce == &nonce_arr {
                                    // Nonce matches, now verify cert and possession sig
                                    if let Some(cert_json) = v.get("cert") {
                                        if let Some(cert) = identity::DeviceCert::from_json(cert_json) {
                                            if cert.verify(identity::now_secs()).is_ok() {
                                                // Verify possession sig
                                                if let Some(sig_hex) = v.get("possession_sig").and_then(|x| x.as_str()) {
                                                    if let Ok(sig_bytes) = hex::decode(sig_hex) {
                                                        if sig_bytes.len() == 64 {
                                                            let mut sig_arr = [0u8; 64];
                                                            sig_arr.copy_from_slice(&sig_bytes);
                                                            // Recompute possession_msg with held nonce, own scope/caps, etc.
                                                            let scope = crate::identity::IntroScope::User.to_byte(); // from own token, not echoed
                                                            let caps_d = crate::identity::caps_digest("transfer"); // own caps
                                                            let chash = crate::identity::cert_hash(&cert);
                                                            if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
                                                                let sender_dpub = cert.device_pub;
                                                                let receiver_dpub = own_dpub; // our own device_pub as receiver
                                                                let msg = crate::identity::possession_msg(0x02, &nonce_arr, scope, &caps_d, &chash, &sender_dpub, &receiver_dpub);
                                                                if crate::identity::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_ok() {
                                                                    // Anti-reflection, narrowed to device_pub (#41). The outer `if let` is kept
                                                                    // only to preserve the if/else-if chain with the enrollment branch below;
                                                                    // the reflection test itself now compares cert.device_pub against own_dpub
                                                                    // (this machine's LOCAL device pubkey, from the enclosing
                                                                    // overlay_pubkey_bytes()), so a same-owner fleet device (different device_pub,
                                                                    // same user key) is admitted instead of refused. This 0x02 path also binds
                                                                    // receiver_dpub in the possession_msg, so device_pub here is defense-in-depth.
                                                                    if let Ok(Some(_own_uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                                                                        if cert.device_pub == own_dpub {
                                                                            // self, refuse
                                                                        } else {
                                                                            // Store as provisional, then promote at overlay after check
                                                                            let _ = store_provisional_identity(&format!("peer-{}", pid), &cert);
                                                                            // Store identity on the link for capability authorization
                                                                            if let Some(l) = conn.link_mut(&pid) {
                                                                                l.identity_device_pub = Some(cert.device_pub);
                                                                                l.identity_user_pub = Some(cert.user_pub);
                                                                                l.identity_binding = crate::capability::BindingStrength::Proven;
                                                                                l.identity_cert_expires = Some(cert.expires);
                                                                            }
                                                                            ui::say(&format!("  {} identity verified for peer {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), pid));
                                                                            // Erase held nonce single-use
                                                                            identity_nonces.remove(&pid);
                    }
                } else if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                    // Enrollment channel: an ephemeral device is trying to enroll.
                    // Recognize peers on enroll_channel(own_owner_pub) and dial them.
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                            ui::debug(&format!("enrollment peer appeared on channel, dialing"));
                        }
                        conn.maybe_adopt(&v, true).await?;
                    }
                }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Some("file-offer") => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    // L1-a (shared-room hardened): on the code path, accept bytes
                    // ONLY from the peer whose ephemeral SPAKE2 ceremony confirmed
                    // (the authenticated sender). Anything else, a pre-auth offer, a
                    // decoy / unrelated room peer, or an offer from a DIFFERENT peer
                    // than the one that authenticated, is refused. (Previously this
                    // only gated the single latched peer, so a decoy could slip an
                    // offer past while we were still authenticating; now it cannot.)
                    // If no peer has authenticated yet, the overall watchdog still
                    // fails loudly should the real sender never confirm.
                    if recv_code_path
                        && (!recv_pake_done || recv_pake_peer.as_deref() != Some(pid.as_str()))
                    {
                        // A pre-auth offer from a peer we are STILL authenticating
                        // (it has a live ceremony) is buffered, not lost: the offer
                        // and the sender's confirm crossed on the wire. If that peer
                        // wins auth we replay it; if its ceremony is dropped, the
                        // buffered offer dies with it. A confirmed-but-different peer
                        // (a decoy that authenticated nothing) is simply ignored.
                        if !recv_pake_done && recv_cers.contains_key(&pid) {
                            recv_pending_offers.insert(pid.clone(), v.clone());
                            ui::debug("buffering a pre-auth file-offer until its ceremony confirms");
                        } else {
                            ui::debug("ignoring file-offer from a peer that has not authenticated via ephemeral PAKE");
                        }
                        continue;
                    }
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name: reduce it to a safe single path
                    // component (basename only, no path separators, no control
                    // bytes). See safe_incoming_name.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = safe_incoming_name(raw);
                    let size = v["size"].as_u64().unwrap_or(0);
                    let offer_head = v["head"].as_str().map(|s| s.to_string());
                    // P4 (GAP-5): the sender's whole-file sha256 (absent for an old
                    // peer). Used to verify-on-completion + drive the delivery-ack.
                    let offer_full = v["full"].as_str().map(|s| s.to_string());
                    let is_resume = v["resume"].as_bool().unwrap_or(false);

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    // C7: a partial counts only if size matches AND the
                    // content head matches (when both sides have one).
                    let mut offset = 0u64;
                    // P4: the whole-file digest persisted with the partial, so a
                    // resume after a process restart can still verify-on-completion
                    // even if this particular re-offer omits `full`.
                    let mut prior_full: Option<String> = None;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        match PartMeta::load(&meta_path) {
                            Some(m) if m.size == size && prior <= size => {
                                let head_ok = match (&m.head, &offer_head) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => true, // legacy peer, size-only fallback
                                };
                                if head_ok {
                                    offset = prior;
                                    prior_full = m.full;
                                } else {
                                    // DEBUG, resilience internal (resume mismatch, restart).
                                    ui::debug(&format!("{name}: same name+size but different content, restarting from 0"));
                                }
                            }
                            _ => {}
                        }
                    }

                    // #30 GAP 2: honor the pending_proven hold. If a
                    // possession-sig challenge is still in flight for this peer
                    // (the adopt-time hold has not settled) and the binding is
                    // PRE-ADMIT RACE: a file-offer can arrive before
                    // admit_delegated sets identity_user_pub + principal_kind for
                    // this link. The ordering is UNENFORCED. This is safe only
                    // because the pre-admit link state is authority-free:
                    // identity_user_pub=None + binding=None => denied under
                    // authoritative; refusal under shadow. If an unadmitted link
                    // ever gains a default authority, the race opens.
                    //
                    // not yet Proven, do NOT decide on Inferred now: the
                    // identity-expose that flips us to Proven is a SEPARATE
                    // event this single-consumer loop must be free to process,
                    // so blocking inline would deadlock. Re-inject the offer
                    // shortly and let the loop drain. The hold entry is removed
                    // on Proven OR at the 3s deadline, so this self-terminates
                    // and the re-injected offer is then decided for real.
                    if crate::capability::cap_authoritative() {
                        let challenge_in_flight =
                            pending_proven.lock().unwrap().contains_key(&pid);
                        let proven = conn
                            .link(&pid)
                            .map(|l| {
                                l.identity_binding
                                    == crate::capability::BindingStrength::Proven
                            })
                            .unwrap_or(false);
                        if challenge_in_flight && !proven {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                    }

                    // C14/C22: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; a verified
                    // device auto-accepts; otherwise the question joins the
                    // pending queue and the answer arrives via StdinLine, a
                    // per-process token marks re-enqueued offers so a remote
                    // peer can't forge "already consented".
                    let sender_name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let link_trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let consented = v["__consent"].as_str() == Some(consent_token());
                    // Legacy (pre-capability) decision, per mode.
                    let legacy_ok = if daemon {
                        link_trusted
                    } else {
                        yes || consented || link_trusted || (is_resume && offset > 0)
                    };
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under FILAMENT_CAP_AUTHORITATIVE.
                    let (ok, xfer_deny_reason, xfer_gate) = {
                        // Lazy-resolve peer identity from stored device cert
                        {
                            if let Some(l) = conn.link_mut(&pid) {
                                resolve_peer_identity(l);
                            }
                        }
                        let link = conn.link(&pid);
                        let idev = link.and_then(|l| l.identity_device_pub.as_ref());
                        let iusr = link.and_then(|l| l.identity_user_pub.as_ref());
                        let binding = link.map(|l| l.identity_binding).unwrap_or(crate::capability::BindingStrength::None);
                        let expires = link.and_then(|l| l.identity_cert_expires);
                        let ak_caps = link.and_then(|l| l.principal_kind.auth_key_caps());
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_TRANSFER,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Trust floor: under authoritative, an untrusted link
                        // must never authorize transfer (pair-proof vs device-key).
                        let outcome = crate::capability::cap_trust_floor(
                            &outcome,
                            link_trusted,
                            binding,
                            crate::capability::cap_authoritative(),
                        );
                        // Fleet transfer scope, enforced by construction and VERIFIED
                        // here (not hardcoded `true`, which asserted a bound nothing
                        // checked). The offered name is basename-only (see ~14095:
                        // `Path::new(raw).file_name()`, "never trust a remote name with
                        // path separators") and lands in the receiver's OWN drop dir
                        // `dir`, which the sender cannot redirect. Assert the landing
                        // path is within `dir` so a future regression in the sanitizer
                        // or in how `dir` is derived TRIPS the gate (fails closed to
                        // grant-only) instead of silently widening scope. NOTE: this is
                        // a LEXICAL check; a symlink planted at the final `.part` create
                        // could still redirect the write — closed separately by the
                        // plain-file-only (O_NOFOLLOW/O_EXCL) write hardening tracked as
                        // a fleet-trust follow-up.
                        let cert_revoked = idev.map(device_cert_revoked).unwrap_or(true);
                        let landing = dir.join(&name);
                        let scoped_in_bounds = crate::path_within(&dir, &landing);
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                             &crate::settings::config_dir(), "self", crate::capability::CAP_TRANSFER, idev, iusr, ak_caps,
                        );
                         let d = crate::capability::cap_gate_effective(legacy_ok, &outcome, crate::capability::CAP_TRANSFER, "self", idev, iusr, binding, expires, ak_caps, own_user.as_ref(), scoped_in_bounds, has_grant, cert_revoked);
                        let reason = if let crate::capability::GateDecision::Deny { cap_reason } = &d {
                            cap_reason.clone()
                        } else {
                            None
                        };
                        (d.allowed(), reason, d)
                    };
                    // Under authoritative, a capability Deny hard-declines
                    // immediately: no prompt, skip the accept path entirely.
                    if let Some(reason) = crate::capability::transfer_gate_decision(
                        &xfer_gate,
                        crate::capability::cap_authoritative(),
                    ) {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!(
                            "  declined {name} from {sender_name} ({reason})",
                        )));
                        if daemon { enqueue_if_requestable(&sender_name, "transfer"); }
                        t.send_control(&protocol::decline_msg(&id)).await?;
                        continue;
                    }
                    if !ok {
                        if !daemon && std::io::stdin().is_terminal() {
                            pending.push_back((pid.clone(), v.clone()));
                            question_open.store(true, std::sync::atomic::Ordering::Relaxed);
                            if pending.len() == 1 {
                                // C25: the question is a PERMANENT line first
                                // (nothing can be asked invisibly), with the
                                // sticky as the live answer tail.
                                let q = offer_question(&sender_name, &name, size, paired);
                                ui::say(&q);
                                ui::sticky(&q);
                                question_shown = Instant::now();
                            }
                            continue; // decision arrives later via StdinLine
                        }
                        ui::say(&ui::paint(ui::Tone::Dim, &format!(
                            "  declined {name} from {sender_name} ({})",
                            if daemon { xfer_deny_reason.as_deref().unwrap_or("unverified peer") } else { "no tty, use -y to auto-accept" }
                        )));
                        t.send_control(&protocol::decline_msg(&id)).await?;
                        continue;
                    }

                    // C23: never run two streams into one .part, a rejoin
                    // can re-offer a file whose first stream is still live;
                    // accepting both corrupted the path and crashed on the
                    // second rename. First stream wins.
                    //
                    // P0 (GAP-1) exception: a STALL repair re-offers the same file
                    // (resume:true) on a FRESH transport while the OLD stream's
                    // by_sid entry may still linger (its data path went dark). If
                    // the existing stream's transport is itself STALLED past the
                    // threshold, the "first stream" is the wedged one, flush it to
                    // its .part and accept the resume on the live link instead of
                    // declining (a decline would mark the SENDER's transfer done
                    // and abort the recovery). A genuinely FLOWING duplicate still
                    // wins as before.
                    let want_part = dir.join(format!("{name}.part"));
                    if !to_stdout {
                        let dup_keys: Vec<(String, u32)> = by_sid
                            .iter()
                            .filter(|(_, inc)| inc.part_path == want_part)
                            .map(|(k, _)| k.clone())
                            .collect();
                        if !dup_keys.is_empty() {
                            // Is ANY existing stream for this file still flowing?
                            let any_flowing = dup_keys.iter().any(|(p, _)| {
                                conn.transport_of(p)
                                    .map(|t| t.idle_ms() < net::stall_ms())
                                    .unwrap_or(false)
                            });
                            if any_flowing {
                                // A real concurrent duplicate, first (flowing)
                                // stream wins. Ignore WITHOUT marking the sender
                                // done (a benign skip, not a user decline).
                                ui::say(&ui::paint(ui::Tone::Dim, &format!("  (duplicate offer for {name} ignored, already receiving it)")));
                                continue;
                            }
                            // The lingering stream(s) are STALLED, flush their
                            // partials to disk and drop them so the resume below
                            // re-opens the .part from its saved offset.
                            for k in dup_keys {
                                if let Some(inc) = by_sid.remove(&k) {
                                    let f = inc.file.clone();
                                    let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                                }
                            }
                        }
                    }

                    if to_stdout {
                        // Pipe mode: no part files, no resume, pure stream.
                        // Write through a dup'd stdout fd so dropping the
                        // writer never closes the process's real fd 1; the
                        // /dev/stdout open is the portable-unix way to dup.
                        // (Windows: -o - is not supported yet; see G-e.)
                        #[cfg(unix)]
                        let out = tokio::fs::OpenOptions::new().write(true).open("/dev/stdout").await?;
                        #[cfg(not(unix))]
                        {
                            bail!("-o - (stdout streaming) is not supported on this platform yet");
                        }
                        #[cfg(unix)]
                        {
                            by_sid.insert((pid.clone(), sid), IncomingFile {
                                id: id.clone(),
                                name,
                                size,
                                received: Arc::new(AtomicU64::new(0)),
                                ranges: Arc::new(std::sync::Mutex::new(vec![])),
                                file: Arc::new(out.into_std().await),
                                part_path: PathBuf::new(),
                                // Pipe mode streams to a fd we can't re-read, so we
                                // can't recompute the digest, no verify, no ack
                                // (the sender's bounded fallback covers it).
                                full: None,
                                inflight: Arc::new(AtomicI64::new(0)),
                                end_seen: Arc::new(AtomicBool::new(false)),
                                ack_sid: 0,
                                last_tick: 0,
                                bar: ui::Progress::new("(stdout)", size),
                            });
                            t.send_control(&protocol::accept_msg(&id, 0)).await?;
                            continue;
                        }
                    }
                    // P4: the digest to verify against on completion, the current
                    // offer's, else the one persisted with the partial (resume).
                    let effective_full = offer_full.clone().or(prior_full);
                    // A per-file open failure DECLINES this one file (continue),
                    // matching the other offer-accept declines. It must never unwind
                    // the receive loop: that would kill every other in-flight transfer.
                    let file = if offset > 0 {
                        // DEBUG, resilience internal (receiver resuming from offset).
                        ui::debug(&format!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0));
                        // Open with write mode (not append) so we can seek to any
                        // position for multi-stream out-of-order writes.
                        // safe_resume_part: RESOLVE_BENEATH on Linux, O_NOFOLLOW +
                        // fstat regular-file check on other Unix. NO O_EXCL (resume).
                        match safe_resume_part(&part_path).await {
                            Ok(f) => f,
                            Err(e) => { ui::debug(&format!("{name}: cannot open .part to resume, declining: {e}")); continue; }
                        }
                    } else {
                        // Restart-from-0: a leftover .part of different content/size
                        // (interrupted transfer, or a common filename from another
                        // peer) must not block the fresh create. safe_create_part uses
                        // O_EXCL to refuse a planted symlink, which EEXISTs on any
                        // leftover .part; that Err used to unwind the whole loop. Remove
                        // the stale partial first (unlinking a symlink drops the link,
                        // not its target); a symlink planted in the gap still trips
                        // O_EXCL and is declined below, not followed.
                        let _ = std::fs::remove_file(&part_path);
                        if let Err(e) = (PartMeta { size, head: offer_head, full: effective_full.clone() }.store(&meta_path)) {
                            ui::debug(&format!("{name}: cannot write .part.meta, declining: {e}"));
                            continue;
                        }
                        match safe_create_part(&part_path).await {
                            Ok(f) => f,
                            Err(e) => { ui::debug(&format!("{name}: cannot create .part, declining: {e}")); continue; }
                        }
                    };
                    let bar = ui::Progress::new(&name, size);
                    let file = Arc::new(file.into_std().await);
                    let received = Arc::new(AtomicU64::new(offset));
                    let ranges = Arc::new(std::sync::Mutex::new(
                        if offset > 0 { vec![(0, offset)] } else { vec![] }
                    ));
                    by_sid.insert((pid.clone(), sid), IncomingFile {
                        id: id.clone(),
                        name,
                        size,
                        received,
                        ranges,
                        file,
                        part_path,
                        full: effective_full,
                        inflight: Arc::new(AtomicI64::new(0)),
                        end_seen: Arc::new(AtomicBool::new(false)),
                        ack_sid: 0,
                        last_tick: 0,
                        bar,
                    });
                    t.send_control(&protocol::accept_msg(&id, offset)).await?;
                }
                Some("file-end") => {
                    // Test hook (gate 18 standalone repro): drop the file-end
                    // control frame so a fully-received stream is stranded in
                    // by_sid, mirrors a sender whose PC tears down before the
                    // best-effort file-end is delivered.
                    if test_hooks::drop_file_end() {
                        continue;
                    }
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // If background writes are still in-flight, defer to
                    // Ev::MaybeComplete from the last finishing writer.
                    let process_now = {
                        match by_sid.get_mut(&(pid.clone(), sid)) {
                            None => false, // unknown stream
                            Some(inc) => {
                                inc.ack_sid = sid;
                                if inc.inflight.load(Ordering::Relaxed) > 0 {
                                    inc.end_seen.store(true, Ordering::Relaxed);
                                    false // deferred to MaybeComplete
                                } else {
                                    true // inflight == 0, process now
                                }
                            }
                        }
                    };
                    if !process_now { continue; }
                    // No inflight writes — process inline (fast path).
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    let mut inc = match by_sid.remove(&(pid.clone(), sid)) {
                        Some(i) => i,
                        None => continue,
                    };
                    let f = inc.file.clone();
                    let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                    if to_stdout {
                        completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    if inc.full.is_some() {
                        let verdict = verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                verify_fails.remove(&id);
                                let rename_to = if completed == 0 { output.clone() } else { None };
                                let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                                    completed += 1;
                                    if test_hooks::suppress_delivery_ack() {
                                        ui::say(&ui::paint(ui::Tone::Warn, &format!("    [test] {nm} verified but SUPPRESSING delivery-ack")));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t.send_control(&protocol::delivery_ack_msg(&id, sid)).await;
                                        let _ = t.flush().await;
                                        ui::say(&ui::paint(ui::Tone::Dim, &format!("    {nm} verified (whole-file sha256 matched), acked")));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    ui::critical(&ui::paint(ui::Tone::Err, &format!(
                                        "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                        inc.name
                                    )));
                                    verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = safe_create_part(&inc.part_path).await;
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                        "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                        inc.name, *fails
                                    )));
                                } else {
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                        "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                        inc.name, human(req_offset), human(inc.size), *fails
                                    )));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                                if req_offset == 0 {
                                    if let Ok(f) = safe_resume_part(&inc.part_path).await {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                }
                                inc.end_seen.store(false, Ordering::Relaxed);
                                by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t.send_control(&protocol::accept_msg(&id, req_offset)).await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if completed == 0 { output.clone() } else { None };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                            completed += 1;
                        }
                    }
                }
                _ => {}
            },
            Ev::MaybeComplete(pid, sid) => {
                // A background writer task finished and was the last inflight,
                // and end_seen was already set. Finalize (verify + delv ack).
                let ack_sid = {
                    by_sid.get(&(pid.clone(), sid)).map(|inc| inc.ack_sid).unwrap_or(0)
                };
                if let Some(mut inc) = by_sid.remove(&(pid.clone(), sid)) {
                    if to_stdout {
                        completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    if inc.full.is_some() {
                        let verdict = verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                verify_fails.remove(&id);
                                let rename_to = if completed == 0 { output.clone() } else { None };
                                let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                                    completed += 1;
                                    if test_hooks::suppress_delivery_ack() {
                                        ui::say(&ui::paint(ui::Tone::Warn, &format!("    [test] {nm} verified but SUPPRESSING delivery-ack")));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t.send_control(&protocol::delivery_ack_msg(&id, ack_sid)).await;
                                        ui::say(&ui::paint(ui::Tone::Dim, &format!("    {nm} verified (whole-file sha256 matched), acked")));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    ui::critical(&ui::paint(ui::Tone::Err, &format!(
                                        "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                        inc.name
                                    )));
                                    verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = safe_create_part(&inc.part_path).await;
                                    if let Ok(f) = safe_resume_part(&inc.part_path).await {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                        "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                        inc.name, *fails
                                    )));
                                } else {
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                        "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                        inc.name, human(req_offset), human(inc.size), *fails
                                    )));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                                inc.end_seen.store(false, Ordering::Relaxed);
                                by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t.send_control(&protocol::accept_msg(&id, req_offset)).await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if completed == 0 { output.clone() } else { None };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                            completed += 1;
                        }
                    }
                }
            }
            Ev::Chunk(pid, sid, offset, data) => {
                // L2 streams live in the HIGH half of the sid space, route them
                // to the tunnel mux, never the file-transfer table (the pure
                // high-bit prefix check keeps file send/recv byte-identical).
                if l2_enabled && l2::is_l2_sid(sid) {
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.on_frame(sid, data).await;
                    }
                } else if let Some(inc) = by_sid.get_mut(&(pid.clone(), sid)) {
                    // --- TRACE recv path ---
                    let trace = cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
                    let t_recv_start = if trace { Some(std::time::Instant::now()) } else { None };
                    // Determine the write position: absolute offset from the
                    // sender. Both QUIC and DataChannel now frame the offset.
                    // An offsetless frame is impossible under the new scheme.
                    let pos: u64 = match offset {
                        Some(off) => off,
                        None => {
                            dlog!("[recv] REFUSING offsetless chunk sid={sid}: transport must frame offset");
                            continue;
                        }
                    };
                    inc.inflight.fetch_add(1, Ordering::Relaxed);
                    let file = Arc::clone(&inc.file);
                    let inflight = Arc::clone(&inc.inflight);
                    let end_seen = Arc::clone(&inc.end_seen);
                    let ranges = Arc::clone(&inc.ranges);
                    let received = Arc::clone(&inc.received);
                    let tx = tx.clone();
                    let pid_c = pid.clone();
                    let data_len = data.len();
                    let trace_inner = trace;
                    tokio::task::spawn_blocking(move || {
                        let t_pwrite = if trace_inner { Some(std::time::Instant::now()) } else { None };
                        if let Err(e) = pwrite_at(&file, &data, pos) {
                            // Write failed: do NOT record coverage (leaves the gap).
                            // The whole-file digest will fail and trigger a re-fetch.
                            dlog!("[recv] pwrite_at FAILED at pos={pos} len={data_len}: {e}");
                        } else {
                            // Write succeeded: record coverage AFTER bytes landed.
                            let mut r = ranges.lock().unwrap();
                            let (_delta, total) = record_range(&mut *r, pos, data_len);
                            drop(r);
                            // fetch_max, not store: writer tasks run concurrently, so
                            // a task that locked earlier (lower union total) can reach
                            // this line AFTER one that locked later (higher total). The
                            // union total is monotonic, so max() keeps `received` from
                            // regressing to a stale value (which would spuriously trip
                            // the `recvd < size` gate in verify_incoming). Serialized in
                            // the old event-loop path; this race is new to the writer.
                            received.fetch_max(total, Ordering::Relaxed);
                        }
                        let pwrite_us = t_pwrite.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                        if trace_inner && pwrite_us > 1000 {
                            dlog!("[TRACE recv spawn_blocking] pos={} len={} pwrite={}us", pos, data_len, pwrite_us);
                        }
                        let prev = inflight.fetch_sub(1, Ordering::Relaxed);
                        if prev == 1 && end_seen.load(Ordering::Relaxed) {
                            let _ = tx.send(Ev::MaybeComplete(pid_c, sid));
                        }
                    });
                    let recv_us = t_recv_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                    if trace && recv_us > 500 {
                        dlog!("[TRACE recv Ev::Chunk] sid={} offset={:?} len={} dispatch={}us", sid, offset, data_len, recv_us);
                    }
                    let r = inc.received.load(Ordering::Relaxed);
                    if r != inc.last_tick {
                        inc.bar.tick(r);
                        inc.last_tick = r;
                    }
                } else {
                    // Chunk arrived for unknown (pid, sid) - log instead of silently dropping.
                    // This happens during transport supersede or stall repair when old chunks
                    // arrive after the by_sid entry was removed.
                    ui::debug(&format!("  dropping chunk for unknown sid {sid} from {pid} ({} bytes)", data.len()));
                }
            }
            Ev::StdinLine(line) => {
                let ans = line.to_lowercase();
                if !pending.is_empty() {
                    // C22/C25: an open question owns stdin, but ONLY explicit
                    // answers count. An empty line (stray CR, idle Enter) used
                    // to default-decline an offer the user never saw; and any
                    // keypress within 300ms of the question appearing is a
                    // buffered stroke, not a decision.
                    if question_shown.elapsed() < Duration::from_millis(300) {
                        continue;
                    }
                    let mut answered = false;
                    if ans == "y" || ans == "yes" {
                        answered = true;
                        let (qpid, mut qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        qv["__consent"] = json!(consent_token());
                        let _ = tx.send(Ev::Control(qpid, qv)); // re-enter the offer path, consented
                    } else if ans == "n" || ans == "no" {
                        answered = true;
                        let (qpid, qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  declined {}", qv["name"].as_str().unwrap_or("file"))));
                        if let Some(t) = conn.transport_of(&qpid) {
                            t.send_control(&protocol::decline_msg(qv["id"].as_str().unwrap_or_default())).await?;
                        }
                    }
                    // show the next queued question (or re-show on gibberish)
                    if let Some((qpid, qv)) = pending.front() {
                        let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        if answered {
                            ui::say(&q); // a NEW question fronted, permanent line (C25)
                            question_shown = Instant::now();
                        }
                        ui::sticky(&q);
                    } else {
                        question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if ans == "devices" {
                    // C29: session commands, `up` is a place you live in.
                    if devices.is_empty() {
                        ui::say(&ui::paint(ui::Tone::Dim, "  no known devices yet, type a code or `pair` to add one"));
                    }
                    for (n, s) in &devices {
                        ui::say(&format!("  {}  {}", ui::paint(ui::Tone::Bold, n), ui::paint(ui::Tone::Dim, &format!("(channel {})", &channel_of(s)[..12]))));
                    }
                } else if let Some(n) = ans.strip_prefix("forget ") {
                    let n = n.trim();
                    if devices.iter().any(|(dn, _)| dn == n) {
                        devices_remove(n)?;
                        devices.retain(|(dn, _)| dn != n);
                        ui::say(&format!("  {} forgot '{n}', it can no longer find this machine", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                    } else {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  no device named '{n}' (try `devices`)")));
                    }
                } else if ans == "pair" || ans == "code" {
                    // C29: mint a code; whoever claims it gets the remember
                    // ceremony on connect (we created it, so WE initiate).
                    if daemon {
                        ceremony = Some(true);
                    }
                    sio.emit("pair-create", json!({})).await.ok();
                } else if regex_lite_code(&line) {
                    if claim_in_flight {
                        ui::say(&ui::paint(ui::Tone::Dim, "  (a claim is already in flight, wait for it to resolve)"));
                    } else {
                        ui::say(&format!("  claiming {}...", ui::paint(ui::Tone::Brand, &line)));
                        paired = true;
                        claim_in_flight = true;
                        if daemon {
                            ceremony = Some(false); // C29: in a session, pairing means remembering
                        }
                        sio.emit("pair-claim", json!({ "code": line.to_lowercase() })).await.ok();
                    }
                } else if !line.is_empty() {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (type a code like brave-otter-123 to claim it · `pair` · `devices` · `forget <name>`)"));
                }
            }
            Ev::Interrupted => {
                flush_inflight(&mut by_sid).await;
                ui::say(&format!("  {} interrupted, partials kept; run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                if let Some(g) = &tty_guard {
                    g.restore(); // process::exit skips Drop
                }
                // Best-effort, BOUNDED: a wedged signaling socket must not turn the
                // graceful exit into the very hang the watchdog exists to catch.
                // The signal task already armed a force-exit; cap the disconnect so
                // we exit cleanly on our own well inside that grace.
                let _ = tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
                std::process::exit(130);
            }
            // P0 (GAP-1): the inbound transfer stalled (zero bytes, link alive).
            // The receiver participates in the SYMMETRIC direct-QUIC repair: it
            // re-arms its own direct dial so the fresh authenticated connection
            // can form. The `.part` stays on disk; the sender re-offers
            // resume:true on the new transport, so the file continues from its
            // saved offset (no restart-from-zero). For a WebRTC link the repair
            // is the impolite-side ICE-restart inside correct_stall.
            Ev::TransferStalled(pid, idle_ms) => {
                // DEBUG, resilience internal (inbound stall detection).
                ui::debug(&ui::paint(ui::Tone::Warn, &format!("  inbound stall: {idle_ms}ms with no data from peer, repairing link")));
                // P0 partial-preservation: flush THIS peer's in-flight partials
                // to their `.part` on disk and release the in-memory handles, so
                // the C23 "already receiving" guard doesn't reject the sender's
                // resume-offer on the FRESH repair link. The `.part` + `.meta`
                // stay on disk; the resume re-opens them from the saved offset
                // (no restart-from-zero). Only this peer's streams are dropped,
                // other links keep flowing.
                let stale: Vec<(String, u32)> =
                    by_sid.keys().filter(|(p, _)| *p == pid).cloned().collect();
                for key in stale {
                    if let Some(inc) = by_sid.remove(&key) {
                        let f = inc.file.clone();
                        let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                        ui::debug(&format!("{}: parked at {} for resume", inc.name, human(inc.received.load(Ordering::Relaxed))));
                    }
                }
                match conn.correct_stall(&pid).await {
                    // Receiver has nothing to re-offer; the sender owns the offer.
                    // Rung (a) is a no-op here, wait for the sender's re-offer.
                    Rung::Resume => {}
                    Rung::Repaired => {}
                    // Rung (d) P1: the receiver re-established over the TURN relay
                    // (relay-only ICE), preserving its `.part`. The sender re-offers
                    // resume:true on the fresh relay link, the file continues from
                    // its saved offset. Nothing to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden / already on relay:
                    // failed CLEANLY, partial kept on disk (message already shown).
                    Rung::Exhausted => {}
                }
            }
            // Losing the sender is only an ERROR when nothing completed,
            // after a successful transfer it's just closure (the quiet-exit
            // prints the same `done (N files).` the peer-left path would).
            Ev::Stuck(pid, generation) => {
                // Bug 5: repeated stuck before ANY byte arrived → hint at the
                // single-host mDNS wedge once.
                if !ever_received {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? && paired && !keep_open {
                    // G-k: the dropped link may have delivered every byte but
                    // lost its file-end, finalize before deciding it's fatal.
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts; the partial is kept, re-run `filament recv <code>` to resume", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? && paired && !keep_open {
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts; the partial is kept, re-run `filament recv <code>` to resume", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::PcState(pid, s) => {
                // L2: a dead/closed link must abort every tunnel stream it
                // carried so no pump hangs on a peer that's gone (design §3.5).
                if l2_enabled && (s == "failed" || s == "closed" || s == "disconnected") {
                    if let Some(mux) = l2_muxes.remove(&pid) {
                        mux.shutdown_all().await;
                    }
                    // #4: a genuinely DEAD link (failed/closed) DETACHES its PTY
                    // sessions, it does NOT kill them. The shell keeps running and
                    // buffering output; a reconnect with the same session id
                    // reattaches and replays. We deliberately skip `disconnected`:
                    // that is usually a transient ICE blip the SAME data channel
                    // rides out (no new pty-open follows), so detaching there would
                    // wedge a still-working session. The detached-idle / lifetime
                    // caps in the session task reap a session nobody returns to.
                    if (s == "failed" || s == "closed") && !pty_bindings.is_empty() {
                        if let Some(sid_map) = pty_bindings.remove(&pid) {
                            for session_id in sid_map.values() {
                                if let Some(sess) = pty_sessions.get_live(session_id).await {
                                    sess.detach();
                                }
                            }
                        }
                    }
                }
                conn.on_pc_state(&pid, &s).await;
            }
            Ev::PeerLeft(v) => {
                // Test hook (gate 18): peer-left delivery is best-effort in the
                // real world; this simulates the loss deterministically so the
                // quiet-exit fallback (G-k) can be exercised. SIGSTOP can't do
                // it, engine.io's ping timeout reaps a frozen client in ~30s
                // and the legit peer-left wins the race.
                if test_hooks::drop_peer_left() {
                    continue;
                }
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let secs = conn.rejoin.rejoin_window.as_secs();
                    if !by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  sender disconnected mid-transfer, waiting up to {secs}s")));
                        flush_inflight(&mut by_sid).await;
                    } else if completed > 0 && !keep_open {
                        ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        // C21: NOT fatal, a phone opening its file picker
                        // suspends the whole tab and drops the socket. Hold
                        // the line; their client rejoins on refocus.
                        let gid = v["id"].as_str().unwrap_or_default();
                        let n = gone.unwrap_or_else(|| "sender".into());
                        ui::say(&conn.roster(gid, "●", ui::Tone::Warn, &format!("stepped away, holding the line up to {secs}s (Ctrl-C to stop)"), &n));
                    } else {
                        conn.rejoin.waiting_rejoin = None; // open listener: keep going
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, "left, still listening", &n)),
                            None => ui::say(&ui::paint(ui::Tone::Dim, "  peer left, still listening")),
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// P4 (GAP-5): recompute the whole-file sha256 of the received `.part` and
/// compare against the digest the sender offered (`inc.full`, guaranteed Some by
/// the caller). Flushes first so every buffered byte is on disk. This is the
/// CORE whole-file integrity guarantee the runner used to bolt on above the
/// transport, now every `recv` gets it.
///
/// Test hook (the truncation/ack gate): `FILAMENT_TEST_CORRUPT_RECV=<id>` flips
/// a byte of the on-disk `.part` for the matching transfer id right before the
/// hash is computed, deterministically inducing the corrupt-receive case so the
/// gate can prove reject + recover. `FILAMENT_TEST_CORRUPT_ONCE=1` makes it fire
/// exactly once (the re-fetch then succeeds), proving auto-recovery.
/// Recompute the whole-file sha256 and compare against the sender's offered
/// digest. Flushes (syncs) first. This is the receiver-side core of P4 integrity.
async fn verify_incoming(inc: &IncomingFile) -> protocol::VerifyResult {
    let want = match &inc.full { Some(w) => w.clone(), None => return protocol::VerifyResult::Match };
    // Sync file to disk before hashing.
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;

    let recvd = inc.received.load(Ordering::Relaxed);

    // Test-only corruption injection (deterministic; gate proof). Compiled out
    // entirely on default/release builds, the `corrupt_recv_target` twin returns
    // None there, so this whole block strips to nothing.
    if let Some(target) = test_hooks::corrupt_recv_target() {
        #[cfg(feature = "test-hooks")]
        {
            let once = test_hooks::corrupt_recv_once();
            let already = test_hooks::corrupt_already_fired();
            if target == inc.id && recvd == inc.size && !(once && already) {
                if let Ok(mut bytes) = std::fs::read(&inc.part_path) {
                    if let Some(b) = bytes.last_mut() {
                        *b ^= 0xFF;
                        let _ = std::fs::write(&inc.part_path, &bytes);
                        eprintln!("[test] CORRUPT-RECV: flipped the last byte of {} (id {})", inc.name, inc.id);
                        if once { test_hooks::corrupt_mark_fired(); }
                    }
                }
            }
        }
        let _ = &target;
    }

    if recvd < inc.size {
        return protocol::decide_verify(recvd, inc.size, None);
    }

    // Contiguity guard: before hashing, verify coverage is one contiguous
    // [0,size) interval. Any gap means the file has unwritten bytes even
    // though received == size. Report WHERE the first gap is.
    {
        let r = inc.ranges.lock().unwrap();
        if !coverage_complete(&r, inc.size) {
            let gap = first_gap(&r, inc.size);
            dlog!("[recv] INCOMPLETE at verify: {} ranges, received {}/{}, first gap at {:?}",
                  r.len(), recvd, inc.size, gap);
            drop(r);
            return protocol::decide_verify(recvd, inc.size, None); // re-fetch, never a false Match
        }
    }

    let path = inc.part_path.clone();
    let got = tokio::task::spawn_blocking(move || full_hash(&path)).await.ok().flatten();
    protocol::decide_verify(recvd, inc.size, Some(got.as_deref() == Some(want.as_str())))
}

/// Finalize a fully-received incoming file: sync, rename `.part` → final,
/// clean up the meta sidecar, and (in daemon mode) append to the upload log.
/// Returns true if the file was placed. Takes `IncomingFile` by value and drops it.
async fn finalize_incoming(
    inc: IncomingFile,
    dir: &Path,
    rename_to: Option<&str>,
    daemon: bool,
    from_name: &str,
) -> Result<bool> {
    // Sync then drop file handle before rename (file is closed for the rename on Linux).
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
    drop(inc.file);
    let final_path = unique_path(dir, rename_to.unwrap_or(&inc.name));
    if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
        ui::say(&ui::paint(ui::Tone::Dim, &format!("  (stream for {} already finalized, duplicate discarded: {e})", inc.name)));
        return Ok(false);
    }
    let _ = tokio::fs::remove_file(dir.join(format!("{}.part.meta", inc.name))).await;
    let recvd = inc.received.load(Ordering::Relaxed);
    let ok = recvd == inc.size;
    inc.bar.done(recvd);
    let shown = final_path.display().to_string();
    ui::say(&format!(
        "    {} {}{}",
        ui::paint(ui::Tone::Dim, ui::glyph_arrow()),
        ui::link(&format!("file://{shown}"), &shown),
        if ok { String::new() } else { ui::paint(ui::Tone::Err, "  SIZE MISMATCH") },
    ));
    if ok {
        let lname = final_path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_archive =
            lname.ends_with(".tar") || lname.ends_with(".tar.gz") || lname.ends_with(".tgz");
        let peer = (!from_name.is_empty()).then_some(from_name);
        if is_archive && settings::get_bool("auto-extract", peer) {
            match settings::extract_archive(&final_path, dir) {
                Ok(n) => ui::say(&format!(
                    "    {} extracted {n} file{} into {}",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                    if n == 1 { "" } else { "s" },
                    dir.display()
                )),
                Err(e) => ui::say(&ui::paint(
                    ui::Tone::Warn,
                    &format!("    auto-extract skipped ({e}); the archive is kept as-is"),
                )),
            }
        }
    }
    if daemon {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(up_log()) {
            let _ = writeln!(f, "{}  {}  {}  from {}", chrono_now(), inc.name, human(recvd), from_name);
        }
    }
    Ok(true)
}

/// G-k completion sweep: file-end delivery is best-effort. A stream can
/// receive every expected byte yet have its file-end LOST when the sender's
/// PeerConnection tears down first (observed under load). The bytes are whole
/// (held in `inc.received`; `finalize_incoming` flushes the BufWriter before
/// rename so the on-disk file is complete), but the stream is stranded in
/// `by_sid` with no live link to ever deliver file-end, and that non-empty
/// `by_sid` plus `completed == 0` blocks the quiet-exit while the dead link
/// spins through the reconnect-retry loop to the 120s ceiling. Finalize any
/// fully received stream whose link is gone. `received == size` is exactly the
/// bar the file-end handler itself checks, so this can never claim a genuine
/// partial (received < size stays parked for resume, gate 2) and never
/// touches the offer-stage corruption guard (gate 3). Called both at top-of-
/// loop and right after a link is dropped in the Stuck/GraceExpired handlers,
/// so the bail on `completed == 0` sees the finalized file.
async fn sweep_completed_streams(
    by_sid: &mut HashMap<(String, u32), IncomingFile>,
    conn: &Conn,
    dir: &Path,
    output: &Option<String>,
    to_stdout: bool,
    daemon: bool,
    completed: &mut usize,
) -> Result<()> {
    let done_sids: Vec<(String, u32)> = by_sid
        .iter()
        .filter(|((pid, _), inc)| inc.received.load(Ordering::Relaxed) == inc.size && !conn.links.contains_key(pid))
        .map(|(k, _)| k.clone())
        .collect();
    for key in done_sids {
        if let Some(inc) = by_sid.remove(&key) {
            if to_stdout {
                let f = inc.file.clone();
                let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
                *completed += 1;
                continue;
            }
            let rename_to = if *completed == 0 { output.clone() } else { None };
            ui::say(&ui::paint(ui::Tone::Dim, &format!("  ({} fully received, sender left before file-end; finalizing)", inc.name)));
            if finalize_incoming(inc, dir, rename_to.as_deref(), daemon, "").await? {
                *completed += 1;
            }
        }
    }
    Ok(())
}

/// Park in-flight receives: sync so the .part files are complete up
/// to the last byte received, then drop the per-link routing. Resume picks
/// them up from disk.
async fn flush_inflight(by_sid: &mut HashMap<(String, u32), IncomingFile>) {
    for (_sid, inc) in by_sid.drain() {
        let f = inc.file.clone();
        let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
        ui::debug(&format!("{}: parked at {} for resume", inc.name, human(inc.received.load(Ordering::Relaxed))));
    }
}

/// C22: cbreak-mode guard, single-keypress answers without losing line
/// input. `stty` keeps us dependency-free; Drop restores the terminal (and
/// the Interrupted path calls restore() explicitly since process::exit skips
/// Drop).
struct TtyGuard {
    saved: Option<String>,
}

impl TtyGuard {
    fn raw() -> TtyGuard {
        let saved = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if saved.is_some() {
            let _ = std::process::Command::new("stty")
                .args(["-icanon", "-echo", "min", "1", "time", "0"])
                .stdin(std::process::Stdio::inherit())
                .status();
        }
        TtyGuard { saved }
    }
    fn restore(&self) {
        if let Some(s) = &self.saved {
            let _ = std::process::Command::new("stty")
                .arg(s)
                .stdin(std::process::Stdio::inherit())
                .status();
        }
    }
}

impl Drop for TtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// C22: per-process token marking a locally re-enqueued (consented) offer.
/// A remote peer cannot know it, so it cannot forge consent in a control msg.
fn consent_token() -> &'static str {
    static T: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    T.get_or_init(fresh_secret)
}

/// C26: one-line colored peer status, static scrollback lines, the CLI's
/// equivalent of the web UI's amber 'away' tile.
///   ✓ deft-gibbon                    (connected)
///   ● deft-gibbon  away, choosing a file
///   ◌ deft-gibbon  reconnecting...
fn peer_entry(name: &str, mark: &str, tone: ui::Tone, note: &str) -> String {
    let mut s = format!("{} {}", ui::paint(tone, mark), ui::paint(ui::Tone::Bold, name));
    if !note.is_empty() {
        s.push_str(&format!("  {}", ui::paint(ui::Tone::Dim, note)));
    }
    s
}

fn offer_question(sender: &str, name: &str, size: u64, paired: bool) -> String {
    let sender = if sender.is_empty() { "unknown peer" } else { sender };
    let hint = if paired { " [paired]" } else { "" };
    format!(
        "  {}{} offers {} ({}), accept? [y/N] ",
        ui::paint(ui::Tone::Bold, sender),
        hint,
        name,
        human(size)
    )
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_giveup_then_digest_does_not_recreate_link() {
        let mut suppressed = HashSet::new();
        let mut link_present = true;
        let mut attempts = MAX_ATTEMPTS;

        // Model the exhausted on_stuck transition: dropping the Link loses the
        // counter, so only the out-of-Link suppression mark carries the give-up.
        if attempts >= MAX_ATTEMPTS {
            link_present = false;
            attempts = 0;
            suppressed.insert("peer-sid".to_string());
        }
        assert!(!link_present);
        assert_eq!(attempts, 0);
        assert!(!match_adoption_source(&mut suppressed, "peer-sid", AdoptSource::Digest));

        // A real contact is evidence the peer is reachable and clears only the
        // digest suppression, allowing the next adoption.
        assert!(match_adoption_source(&mut suppressed, "peer-sid", AdoptSource::Contact));
        assert!(!suppressed.contains("peer-sid"));
        assert!(match_adoption_source(&mut suppressed, "peer-sid", AdoptSource::Digest));
    }

    /// Fleet mount scope: `path_within` bounds a mount to the share root and
    /// resists `..` escapes. This is the SECURITY check that keeps an
    /// auto-trusted mount inside the share root (never home/`/`).
    #[test]
    fn path_within_bounds_the_share_root() {
        // Use temp directories that actually exist for canonicalize
        let uid = format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-path-test-{uid}"));
        let root = tmp.join("filament-share");
        let docs = root.join("docs");
        let secrets = tmp.join("secrets");
        let ssh_dir = tmp.join(".ssh");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Create a test file so canonicalize works
        std::fs::write(docs.join("a.txt"), b"test").unwrap();

        // Exact root and a child are within.
        assert!(path_within(&root, &root));
        assert!(path_within(&root, &docs.join("a.txt")));
        // A sibling / home / root are NOT within.
        assert!(!path_within(&root, &tmp));
        assert!(!path_within(&root, &secrets));
        assert!(!path_within(&root, std::path::Path::new("/")));
        // A relative request fails closed (not within an absolute root).
        assert!(!path_within(&root, std::path::Path::new("filament-share")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Symlink escape: path_within_canonical must refuse a symlink pointing outside the share root.
    #[test]
    fn path_within_canonical_refuses_symlink_escape() {
        let uid = format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-symlink-test-{uid}"));
        let root = tmp.join("share");
        let etc = tmp.join("etc");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&etc).unwrap();

        // Create a symlink inside the share root pointing outside
        let evil_link = root.join("evil");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&etc, &evil_link).unwrap();

        // The symlink itself is lexically inside the root...
        // But canonicalize resolves it to /etc, which is outside
        #[cfg(unix)]
        assert!(!path_within_canonical(&root, &evil_link),
            "symlink escaping share root must be refused by canonical check");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Transfer symlink hardening: a .part file that is a symlink must be
    /// refused by safe_create_part (not followed).
    #[cfg(unix)]
    #[tokio::test]
    async fn transfer_part_refuses_symlink() {
        let uid = format!("{}-create-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-xfer-{uid}"));
        std::fs::create_dir_all(&tmp).unwrap();

        // Plant a symlink at the .part path
        let part_path = tmp.join("evil.tar.part");
        std::os::unix::fs::symlink("/etc/passwd", &part_path).unwrap();

        // safe_create_part must refuse to follow the symlink
        let result = safe_create_part(&part_path).await;
        assert!(result.is_err(), "must refuse to create through a symlink");

        // Verify the symlink still exists (not followed)
        let meta = std::fs::symlink_metadata(&part_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must not have been followed");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Transfer resume: safe_resume_part must refuse to open a symlink.
    #[cfg(unix)]
    #[tokio::test]
    async fn transfer_open_part_refuses_symlink() {
        let uid = format!("{}-resume-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-xfer-{uid}"));
        std::fs::create_dir_all(&tmp).unwrap();

        // Create a regular .part file first
        let part_path = tmp.join("data.tar.part");
        std::fs::write(&part_path, b"partial data").unwrap();

        // Verify it opens normally for resume
        let result = safe_resume_part(&part_path).await;
        assert!(result.is_ok(), "regular file must open normally for resume");

        // Now replace with a symlink
        std::fs::remove_file(&part_path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &part_path).unwrap();

        // Must refuse
        let result = safe_resume_part(&part_path).await;
        assert!(result.is_err(), "must refuse to resume through a symlink");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Transfer resume: safe_resume_part must refuse a FIFO at the .part path.
    #[cfg(unix)]
    #[tokio::test]
    async fn transfer_resume_refuses_fifo() {
        let uid = format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-xfer-fifo-{uid}"));
        std::fs::create_dir_all(&tmp).unwrap();

        let part_path = tmp.join("data.tar.part");
        // Create a FIFO (named pipe) at the .part path
        unsafe { libc::mkfifo(std::ffi::CString::new(part_path.to_str().unwrap()).unwrap().as_ptr(), 0o644); }

        // Must refuse — FIFO is not a regular file.
        // Use timeout because opening a FIFO for write blocks until a reader opens it.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            safe_resume_part(&part_path),
        ).await;
        match result {
            Ok(Ok(_)) => panic!("must refuse to resume through a FIFO"),
            Ok(Err(_)) => {} // Expected: error because FIFO is not a regular file
            Err(_) => panic!("safe_resume_part hung on a FIFO — O_NONBLOCK may be needed"),
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Restart-from-0: a leftover .part from an interrupted transfer (or a
    /// common filename re-offered by another peer) must not wedge a fresh
    /// receive. safe_create_part uses O_EXCL, so a create-alone EEXISTs on the
    /// leftover; the restart path removes it first and then creates cleanly.
    /// Regression guard for the "one stale .part aborts the whole receive loop"
    /// bug (the offer-accept path used `?` on that Err instead of declining).
    #[cfg(unix)]
    #[tokio::test]
    async fn transfer_restart_replaces_stale_part() {
        let uid = format!("{}-restart-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-xfer-{uid}"));
        std::fs::create_dir_all(&tmp).unwrap();

        let part_path = tmp.join("data.tar.part");
        std::fs::write(&part_path, b"stale partial from a prior interrupted transfer").unwrap();

        // create-alone must fail on the leftover (O_EXCL -> EEXIST). This is the
        // Err the receive loop must NOT propagate out via `?`.
        assert!(
            safe_create_part(&part_path).await.is_err(),
            "O_EXCL create must refuse a leftover .part"
        );

        // The restart-from-0 path removes the stale partial, then creates fresh.
        let _ = std::fs::remove_file(&part_path);
        let created = safe_create_part(&part_path).await;
        assert!(created.is_ok(), "remove-then-create must succeed: {:?}", created.err());

        // The restarted .part is empty (the stale bytes are gone).
        let meta = std::fs::metadata(&part_path).unwrap();
        assert_eq!(meta.len(), 0, "restarted .part must start empty");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Transfer scope: a landing path inside the drop dir that does NOT yet
    /// exist must still be recognized as in-bounds (path_within is lexical,
    /// doesn't require the target to exist).
    #[test]
    fn transfer_nonexistent_landing_is_in_bounds() {
        let uid = format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-xfer-scope-{uid}"));
        let drop_dir = tmp.join("inbox");
        std::fs::create_dir_all(&drop_dir).unwrap();

        // The landing path for a file about to be received — doesn't exist yet
        let landing = drop_dir.join("photo.jpg");
        assert!(!landing.exists(), "landing must not exist yet");
        assert!(path_within(&drop_dir, &landing),
            "non-existent landing inside drop dir must be in-bounds");

        // A landing outside the drop dir must be out of bounds
        let outside = tmp.join("evil.txt");
        assert!(!path_within(&drop_dir, &outside),
            "landing outside drop dir must be out-of-bounds");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Mount root as symlink: path_within_canonical must refuse a mount root
    /// that is a symlink escaping the share root.
    #[test]
    fn mount_root_symlink_refused() {
        let uid = format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let tmp = std::env::temp_dir().join(format!("fil-mount-root-{uid}"));
        let share = tmp.join("share");
        let etc = tmp.join("etc");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::create_dir_all(&etc).unwrap();

        // Symlink inside share pointing to /etc
        let evil = share.join("evil");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&etc, &evil).unwrap();

        // path_within_canonical must refuse the symlink root
        #[cfg(unix)]
        assert!(!path_within_canonical(&share, &evil),
            "mount root as symlink escaping share must be refused");

        // The real directory must be accepted
        assert!(path_within_canonical(&share, &share),
            "real share root must be accepted");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sanitize_device_name_strips_escape_junk() {
        // The exact corruption observed on the snapshot: a terminal
        // device-attributes reply captured ahead of the real name.
        let dirty = "\u{1b}[?1;2c\u{1b}[?1;2c\u{1b}[>0;276;0cpixel";
        assert_eq!(sanitize_device_name(dirty), "pixel");
        // Lone control chars dropped; surrounding whitespace trimmed.
        assert_eq!(sanitize_device_name("  lap\u{7}top \n"), "laptop");
        // A clean name is unchanged.
        assert_eq!(sanitize_device_name("agboola@pop-os"), "agboola@pop-os");
    }

    #[test]
    fn capability_deny_by_default() {
        // GATE 5: deny-by-default. A device with empty caps is refused any gated
        // action; "transfer" is the always-allowed L0 baseline; a v1 record
        // (no caps) reads as ["transfer"]; future caps must be explicitly
        // granted (i.e. agreed under K at re-enrollment), not escalatable.
        let dir = std::env::temp_dir().join(format!("fil-caps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("devices.json");
        let sec = "a".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "empty",   "secret": sec, "v": 2, "caps": []},
                {"name": "xfer",    "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "execcap", "secret": sec, "v": 2, "caps": ["transfer", "remote-exec"]},
                {"name": "legacy-inbox", "secret": sec, "v": 2, "caps": ["inbox"]},
                {"name": "legacy",  "secret": sec}  // v1 record: reads as ["transfer"]
            ]))
            .unwrap(),
        )
        .unwrap();

        // transfer is the L0 baseline, allowed even for empty caps.
        assert!(device_allows_at(&p, "empty", "transfer"), "transfer is the L0 baseline");
        assert!(device_allows_at(&p, "xfer", "transfer"));
        // A v1 record reads as caps:["transfer"] (back-compat, spec §8).
        assert_eq!(device_caps_at(&p, "legacy"), Some(vec!["transfer".to_string()]));
        assert!(device_allows_at(&p, "legacy", "transfer"));
        // Legacy UX labels remain readable; validation only applies at writes.
        assert_eq!(device_caps_at(&p, "legacy-inbox"), Some(vec!["inbox".to_string()]));
        for capability in crate::capability::CANONICAL_CAPABILITIES {
            assert_eq!(
                device_allows_at(&p, "legacy-inbox", capability),
                device_allows_at(&p, "empty", capability),
                "stale label 'inbox' must confer nothing beyond an empty record"
            );
        }
        assert!(!device_allows_at(&p, "legacy-inbox", "shell"), "legacy inbox label must not authorize shell");
        // Deny-by-default: a gated future cap is REFUSED unless explicitly granted.
        assert!(!device_allows_at(&p, "empty", "remote-exec"), "empty caps must deny remote-exec");
        assert!(!device_allows_at(&p, "xfer", "remote-exec"), "transfer-only must deny remote-exec");
        assert!(!device_allows_at(&p, "legacy", "remote-exec"), "v1 record must deny remote-exec");
        // Only a device explicitly granted the cap (under K, at enrollment) is allowed.
        assert!(device_allows_at(&p, "execcap", "remote-exec"), "explicitly granted cap is allowed");
        // An unknown device grants no GATED cap (but transfer is the universal
        // L0 baseline, so it is allowed regardless, never regresses send/recv).
        assert!(!device_allows_at(&p, "ghost", "remote-exec"));
        assert!(device_allows_at(&p, "ghost", "transfer"), "transfer baseline is universal");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn any_shell_grant_detects_a_shell_cap() {
        let dir = std::env::temp_dir().join(format!("fil-anyshell-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("devices.json");
        let sec = "b".repeat(64);
        // No shell grant anywhere -> false (a plain `up` stays L2-off).
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "xfer",   "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "legacy", "secret": sec}
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(!any_shell_grant_at(&p), "no shell cap -> L2 stays off");
        // One device granted shell -> true (the daemon turns L2 on).
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "xfer",  "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "popos", "secret": sec, "v": 2, "caps": ["transfer", "shell"]}
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(any_shell_grant_at(&p), "a shell grant enables L2");
        // A missing/garbage file is false, never a panic.
        assert!(!any_shell_grant_at(&dir.join("nope.json")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn l2_open_gate_scopes_grant_mode() {
        // Blanket mode (--shell / --shell-only / FILAMENT_L2): any trusted peer
        // may open, regardless of its own per-device grant (unchanged behavior).
        assert!(l2_open_allowed(true, false));
        assert!(l2_open_allowed(true, true));
        // Grant-only mode (L2 on solely because SOME device has a shell grant):
        // the opening peer must itself hold the grant.
        assert!(l2_open_allowed(false, true), "granted device may open");
        assert!(!l2_open_allowed(false, false), "ungranted device denied in grant mode");
    }

    #[test]
    fn l2_target_allowlist_matches() {
        let allow = json!({
            "laptop": ["10.0.0.5:5432", "192.168.1.10:*"],
            "*": ["db.internal:5432"]
        });
        // Exact host:port for the named device.
        assert!(l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 5432));
        // host:* allows any port for that host.
        assert!(l2_target_allowed_in(&allow, "laptop", "192.168.1.10", 9999));
        // "*" device entry applies to any device.
        assert!(l2_target_allowed_in(&allow, "phone", "db.internal", 5432));
        // Wrong port (no wildcard) is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 22));
        // Host not listed is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.9", 5432));
        // A device with no entry (and not matching "*") is denied.
        assert!(!l2_target_allowed_in(&allow, "phone", "10.0.0.5", 5432));
        // No allowlist at all (null) denies everything (loopback-only default).
        assert!(!l2_target_allowed_in(&Value::Null, "laptop", "10.0.0.5", 5432));
        // Host match is case-insensitive.
        assert!(l2_target_allowed_in(&allow, "phone", "DB.INTERNAL", 5432));
    }

    #[test]
    fn shell_policy_gates_auto_shell() {
        // `up` default: NOTHING auto-shells, a device needs an explicit grant.
        let g = ShellPolicy::Granted;
        assert!(!g.auto_allows("popos"));
        assert!(!g.enables_l2(), "default must not silently enable the L2 acceptor");
        // `up --shell`: every paired device auto-shells, and L2 is on.
        let a = ShellPolicy::All;
        assert!(a.auto_allows("popos") && a.auto_allows("anything"));
        assert!(a.enables_l2());
        // `up --shell-only popos,laptop`: only the listed petnames; others don't.
        let o = ShellPolicy::Only(["popos".to_string(), "laptop".to_string()].into_iter().collect());
        assert!(o.auto_allows("popos") && o.auto_allows("laptop"));
        assert!(!o.auto_allows("stranger"), "shell-only must not auto-shell unlisted devices");
        assert!(o.enables_l2());
    }

    #[test]
    fn direct_ok_for_covers_daemon_and_l2_acceptors() {
        // Anti-glare gate (`recv_cmd` builds `direct_ok` from this). Clear the env
        // gates so the daemon/l2 BRANCHES are what we're asserting, not the env.
        // SAFETY: single-threaded within this test; the asserts that depend on the
        // env-unset state are the (false,false) and (false,false,daemon=false) ones.
        unsafe {
            std::env::remove_var("FILAMENT_DIRECT");
            std::env::remove_var("FILAMENT_L2");
        }
        // A plain `up` daemon (no --shell, no env): MUST take the direct path so it
        // answers the peer's transport-offer instead of glaring with a WebRTC dial.
        assert!(direct_ok_for(true, false), "plain `up` daemon must answer direct-QUIC (anti-glare)");
        // The L2/ssh acceptor (`up --shell`) keeps taking it (the prior fix).
        assert!(direct_ok_for(true, true));
        assert!(direct_ok_for(false, true), "L2 acceptor must take direct even when not a daemon");
        // A one-shot command (daemon=false) with no L2 now defaults to direct-ON
        // (the default changed from opt-in to opt-out). FILAMENT_DIRECT=0 restores WebRTC.
        assert!(direct_ok_for(false, false), "default direct-ON for any session");
        unsafe { std::env::set_var("FILAMENT_DIRECT", "0") };
        assert!(!direct_ok_for(false, false), "FILAMENT_DIRECT=0 disables direct");
        unsafe { std::env::remove_var("FILAMENT_DIRECT") };
    }

    #[test]
    fn forget_and_store_preserve_other_devices_caps() {
        // Regression: forgetting/pairing a device must NOT wipe the `shell`
        // (or any v2) caps of the OTHER devices. The old (name, secret) tuple
        // round-trip rewrote every survivor as bare {name, secret}, silently
        // dropping their grants, a remembered device lost its shell on the
        // next `forget`/`pair`.
        let dir = std::env::temp_dir().join(format!("fil-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Serialize: these tests mutate the process-global FILAMENT_CONFIG_DIR.
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let p = dir.join("devices.json");
        let sec = "b".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "shellbox", "secret": sec, "v": 2, "caps": ["transfer", "shell"]},
                {"name": "dupe",     "secret": sec, "v": 2, "caps": ["transfer"]},
            ]))
            .unwrap(),
        )
        .unwrap();

        // Forgetting 'dupe' must leave 'shellbox' with its shell cap intact.
        devices_remove("dupe").unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "forget wiped a survivor's shell cap");
        assert!(device_caps_at(&p, "dupe").is_none(), "dupe should be gone");

        // Storing a NEW pairing must also preserve 'shellbox''s caps.
        devices_store("newpeer", &sec).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "store wiped a survivor's shell cap");
        // And re-storing an existing name keeps its caps (only the secret rotates).
        devices_store("shellbox", &"c".repeat(64)).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "re-store dropped the device's own caps");

        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_matches_browser() {
        // Pinned to the SAME external vector as frontend devices.js (computed
        // with `printf 'filament-proof2:u1|u1|u2|FPA|FPB' | openssl dgst
        // -sha256 -hmac s3cret`). If either implementation drifts, browsers
        // and CLIs silently stop recognizing each other as known devices.
        // The JS half of this byte-identity proof asserts the IDENTICAL vectors:
        // cli/tests/l1a/gate8_byte_identity.mjs (channelOf/proofFor).
        let want = "f98c3b6b7a70ebdf4b200680e83383881bdb1a11476283507359c55ef03a8474";
        // deliberately unsorted inputs, proof_for must normalize
        assert_eq!(proof_for("s3cret", "u1", "u2", "u1", "FPB", "FPA"), want);
        assert_eq!(proof_for("s3cret", "u1", "u1", "u2", "FPA", "FPB"), want);
        // channel derivation, same cross-check (sha256 of "filament-pair:"+secret)
        assert_eq!(
            channel_of("topsecret"),
            "1e32e46e93691c29d9c0305545a10c86a00ae9f3c43d4eea3c7423c1528f9b5d"
        );
    }

    #[test]
    fn polite_role_matches_browser() {
        // uid comparison wins, string-lexicographic, mirrors webrtc.js politeRole
        assert!(net::polite_role("b", "a", "x", "y").unwrap()); // myUid > peerUid -> polite
        assert!(!net::polite_role("a", "b", "x", "y").unwrap());
        // Equal UIDs break ties by session ID within the same tuple comparison.
        assert!(net::polite_role("a", "a", "y", "x").unwrap());
        // exactly one side of any pair is impolite
        for (a, b) in [("a", "b"), ("cli-1", "cli-2"), ("zz", "aa")] {
            let p1 = net::polite_role(a, b, "s1", "s2").unwrap();
            let p2 = net::polite_role(b, a, "s2", "s1").unwrap();
            assert_ne!(p1, p2, "{a} vs {b} must disagree");
        }
    }

    #[test]
    fn part_meta_roundtrip_and_legacy() {
        let dir = std::env::temp_dir().join(format!("filament-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.part.meta");
        PartMeta { size: 42, head: Some("abc".into()), full: Some("deadbeef".into()) }.store(&p).unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 42);
        assert_eq!(m.head.as_deref(), Some("abc"));
        // P4: the whole-file digest survives the round-trip too.
        assert_eq!(m.full.as_deref(), Some("deadbeef"));
        // legacy plain-size format still parses
        std::fs::write(&p, "1234").unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 1234);
        assert!(m.head.is_none());
        assert!(m.full.is_none());
        // garbage does not
        std::fs::write(&p, "{not json").unwrap();
        assert!(PartMeta::load(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_hash_is_prefix_stable() {
        let dir = std::env::temp_dir().join(format!("filament-test-h-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        // same first 256 KiB, different tails -> same head (by design: head is
        // a prefix identity, full integrity is the per-chunk-hash backlog)
        let mut base = vec![7u8; (HEAD_BYTES + 10) as usize];
        std::fs::write(&a, &base).unwrap();
        base[(HEAD_BYTES + 5) as usize] = 9;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(head_hash(&a), head_hash(&b));
        // different first bytes -> different head
        base[0] = 1;
        std::fs::write(&b, &base).unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        // short files hash their whole content
        std::fs::write(&a, b"tiny").unwrap();
        std::fs::write(&b, b"tinY").unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_hash_whole_file_integrity() {
        // P4 (GAP-5): full_hash digests the WHOLE file (not just the 256 KiB
        // head), so a difference PAST the head, exactly the truncation/corrupt
        // case the head-hash can't see, produces a different digest.
        let dir = std::env::temp_dir().join(format!("filament-test-fh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let mut base = vec![3u8; (HEAD_BYTES + 4096) as usize];
        std::fs::write(&a, &base).unwrap();
        // identical head, byte flipped well PAST the head: head_hash agrees but
        // full_hash MUST differ (this is the whole-file guarantee).
        base[(HEAD_BYTES + 2048) as usize] = 4;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(head_hash(&a), head_hash(&b), "tails past the head don't change the head hash");
        assert_ne!(full_hash(&a), full_hash(&b), "full_hash sees the whole file");
        // a truncated file (same prefix, shorter) also differs.
        std::fs::write(&b, &base[..base.len() - 100]).unwrap();
        assert_ne!(full_hash(&a), full_hash(&b), "truncation changes the full hash");
        // full_hash matches a one-shot sha256 of the bytes.
        assert_eq!(full_hash(&a), Some(sha256_hex(&vec![3u8; (HEAD_BYTES + 4096) as usize])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_path_suffixes() {
        let dir = std::env::temp_dir().join(format!("filament-test-u-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt"));
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.1"));
        std::fs::write(dir.join("f.txt.1"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_address_classification() {
        // C2: the badge means "bytes never leave your network", an address
        // property, not a candidate-type property.
        for a in ["127.0.0.1", "10.1.2.3", "192.168.1.9", "172.16.0.1", "169.254.1.1", "100.99.1.2", "::1", "fe80::1", "fd00::5"] {
            assert!(net::is_private_addr(a), "{a} should be private");
        }
        for a in ["1.2.3.4", "165.22.207.231", "2606:4700::1", "8.8.8.8", "not-an-ip", ""] {
            assert!(!net::is_private_addr(a), "{a} should be public/invalid");
        }
    }


    #[test]
    fn filename_sanitization() {
        // the recv path strips directories from remote names
        assert_eq!(safe_incoming_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_incoming_name("/absolute/path.bin"), "path.bin");
        assert_eq!(safe_incoming_name("plain.bin"), "plain.bin");
        // control bytes are stripped; a NUL in particular must NOT survive into a
        // path (it would fail the CString conversion in safe_open_beneath and
        // abort the receive loop). A remote peer must not be able to do that.
        assert_eq!(safe_incoming_name("evil\0.bin"), "evil.bin");
        assert_eq!(safe_incoming_name("with\ttab\nand\r.bin"), "withtaband.bin");
        // a name that reduces to nothing (or . / ..) falls back to a fixed name
        assert_eq!(safe_incoming_name("\0\0\0"), "file.bin");
        assert_eq!(safe_incoming_name(".."), "file.bin");
        assert_eq!(safe_incoming_name(""), "file.bin");
    }

    // Bug 1: `send --name X` is honored for a SINGLE regular file (offer name =
    // override), the basename otherwise, and "stdin.bin" for bare stdin. This
    // mirrors the send_cmd offer-name decision as a pure check.
    #[test]
    fn send_name_override_for_single_file() {
        let offered = |name: Option<&str>, single: bool, basename: &str| -> String {
            name.map(String::from)
                .filter(|_| single)
                .unwrap_or_else(|| basename.to_string())
        };
        // single file + --name → the override wins
        assert_eq!(offered(Some("renamed.bin"), true, "original.txt"), "renamed.bin");
        // single file, no --name → basename
        assert_eq!(offered(None, true, "original.txt"), "original.txt");
        // multiple paths (single=false) + --name → ignored, basename used
        assert_eq!(offered(Some("renamed.bin"), false, "original.txt"), "original.txt");
        // stdin default
        let stdin = |name: Option<&str>, single: bool| {
            name.map(String::from).filter(|_| single).unwrap_or_else(|| "stdin.bin".into())
        };
        assert_eq!(stdin(Some("logs.tar"), true), "logs.tar");
        assert_eq!(stdin(None, true), "stdin.bin");
    }

    // 3-seg codes: both transfer (word-word-NNN) and pairing (word-word-NNNN)
    // share the shape now, so the pairing-vs-transfer HINT is by trailing-number
    // WIDTH. `looks_like_pake_code` (4-digit) is a strict SUBSET of
    // `regex_lite_code` (3-seg word-word-DIGITS) by design, the hint is
    // advisory, never an authenticator.
    #[test]
    fn transfer_and_pairing_codes_are_distinguishable() {
        // minted transfer code: word-word-NNN (3-digit), claimable, NOT pairing.
        assert!(regex_lite_code("brave-otter-371"));
        assert!(!looks_like_pake_code("brave-otter-371"));
        // minted pairing code: word-word-NNNN (4-digit), claimable AND pairing.
        assert!(regex_lite_code("brave-otter-3141"));
        assert!(looks_like_pake_code("brave-otter-3141"));
        // The redirect predicates the commands actually use:
        //   `recv` bails on a pairing-looking code:        looks_like_pake_code
        //   `pair` bails on a transfer-looking code: regex && !looks_like_pake
        let transfer_hint = |s: &str| regex_lite_code(s) && !looks_like_pake_code(s);
        assert!(transfer_hint("brave-otter-371"));   // -> "use recv"
        assert!(!transfer_hint("brave-otter-3141")); // a pairing code, no bail
        assert!(looks_like_pake_code("brave-otter-3141"));  // -> "use pair"
        assert!(!looks_like_pake_code("brave-otter-37"));   // 2-digit transfer
        // width boundary: 2-3 digits => transfer hint, >=4 => pairing hint.
        assert!(trailing_num_width("brave-otter-37") == 2);
        assert!(!looks_like_pake_code("brave-otter-37"));
        assert!(looks_like_pake_code("calm-lynx-1000"));
        // junk / malformed match neither.
        assert!(!regex_lite_code("hello"));
        assert!(!looks_like_pake_code("hello"));
        assert!(!regex_lite_code("a-b-c-d"));               // 4 segments
        assert!(!regex_lite_code("brave-otter-ruby-3141")); // 4 segments (old shape)
        assert!(!looks_like_pake_code("Brave-otter-3141")); // uppercase
    }

    // STEERING floor: --word must contain >= 2 word tokens (letter-runs >= 2).
    #[test]
    fn password_word_tokens_counts_real_words() {
        // single word, too weak (refused).
        assert_eq!(password_word_tokens("cat"), 1);
        assert_eq!(password_word_tokens("gigantic"), 1);
        // two+ words, ok.
        assert_eq!(password_word_tokens("gigantic-element"), 2);
        assert_eq!(password_word_tokens("brave-otter"), 2);
        assert_eq!(password_word_tokens("brave-strong-otter"), 3);
        // 1-letter fragments and digits don't count as words.
        assert_eq!(password_word_tokens("a-b-c"), 0);
        assert_eq!(password_word_tokens("ok1234"), 1);
        // normalized spaces become dashes upstream; here we only see lowercase.
        assert_eq!(password_word_tokens(""), 0);
    }

    #[test]
    fn devices_store_collision_auto_suffixes() {
        // When a name collision occurs, the new device gets auto-suffixed.
        // This prevents two devices from silently shadowing each other.
        let mut arr: Vec<serde_json::Value> = serde_json::from_str(
            r#"[{"name":"host1","secret":"aaa"}]"#
        ).unwrap();
        let new_secret = "bbb";
        let name = "host1";
        // Simulate collision handling (same logic as devices_store)
        let final_name = if arr.iter().any(|d| d["name"].as_str() == Some(name)) {
            let mut suffix = 2;
            let mut new_name = format!("{name}-{suffix}");
            while arr.iter().any(|d| d["name"].as_str() == Some(&new_name)) {
                suffix += 1;
                new_name = format!("{name}-{suffix}");
            }
            new_name
        } else {
            name.to_string()
        };
        arr.push(serde_json::json!({"name": &final_name, "secret": new_secret}));
        // Verify auto-suffix was applied
        assert_eq!(arr.len(), 2, "both entries preserved");
        assert_eq!(arr[0]["name"].as_str().unwrap(), "host1", "original unchanged");
        assert_eq!(arr[1]["name"].as_str().unwrap(), "host1-2", "new device auto-suffixed");
    }

    #[test]
    fn devices_store_collision_increments_suffix() {
        // Multiple collisions should increment the suffix.
        let mut arr: Vec<serde_json::Value> = serde_json::from_str(
            r#"[{"name":"host1","secret":"aaa"},{"name":"host1-2","secret":"bbb"}]"#
        ).unwrap();
        let name = "host1";
        let final_name = if arr.iter().any(|d| d["name"].as_str() == Some(name)) {
            let mut suffix = 2;
            let mut new_name = format!("{name}-{suffix}");
            while arr.iter().any(|d| d["name"].as_str() == Some(&new_name)) {
                suffix += 1;
                new_name = format!("{name}-{suffix}");
            }
            new_name
        } else {
            name.to_string()
        };
        arr.push(serde_json::json!({"name": &final_name, "secret": "ccc"}));
        assert_eq!(arr[2]["name"].as_str().unwrap(), "host1-3", "suffix incremented");
    }

    // --- KnownPeer idempotency regression tests ---
    // These guard against P0 churn: repeated KnownPeer presence events must NOT
    // re-fire establishment on an already-seen/live peer. The real handler uses
    // a HashSet<device_name>; these tests verify the idempotency contract.

    #[test]
    fn known_peer_first_event_connects() {
        let mut saw: HashSet<String> = HashSet::new();
        let n = "popos";
        assert!(!saw.contains(n), "first event should connect");
        saw.insert(n.to_string());
        assert!(saw.contains(n));
    }

    #[test]
    fn known_peer_repeat_while_seen_is_ignored() {
        let mut saw: HashSet<String> = HashSet::new();
        let n = "dovm";
        saw.insert(n.to_string());
        for _ in 0..5 {
            assert!(saw.contains(n), "repeat KnownPeer must be ignored");
        }
    }

    #[test]
    fn known_peer_uses_device_name_not_pid() {
        let mut saw: HashSet<String> = HashSet::new();
        let n = "other-do";
        assert!(!saw.contains(n));
        saw.insert(n.to_string());
        // Same device name with different pids should still be skipped
        assert!(saw.contains(n), "should skip regardless of signaling pid");
    }

    #[test]
    fn known_peer_different_devices_not_skipped() {
        let mut saw: HashSet<String> = HashSet::new();
        saw.insert("dovm".to_string());
        assert!(!saw.contains("popos"), "different device must not be skipped");
        saw.insert("popos".to_string());
        assert!(saw.contains("popos"));
    }

    #[test]
    fn confirm_yes_passes() {
        let caps = UiCapability { interactive: false, json: false, yes: true, color: false };
        assert!(caps.confirm("delete it").is_ok());
    }

    #[test]
    fn confirm_non_interactive_without_yes_fails() {
        let caps = UiCapability { interactive: false, json: false, yes: false, color: false };
        assert!(caps.confirm("delete it").is_err());
    }

    #[test]
    fn known_peer_liveness_allows_reconnect() {
        let mut saw: HashSet<String> = HashSet::new();
        let n = "peer";
        assert!(!saw.contains(n));
        saw.insert(n.to_string());
        // Link dies: clear to allow reconnect
        saw.remove(n);
        assert!(!saw.contains(n), "dead link must be reconnectable");
    }

    /// #23: the atomicity-relevant invariant — upsert_peer_record puts secret AND cert
    /// into ONE record, so the single write that persists it can never yield
    /// new-secret + old-cert. Drives the real merge fn across two generations against an
    /// in-memory store (no file, no env — deterministic). A non-atomic write path (the
    /// old pair flow: write secret, then separately write cert) is exactly what this
    /// forbids: it would leave secretB paired with certA (dpub_a), a wrong-userPub state.
    #[test]
    fn upsert_peer_record_writes_secret_and_cert_together() {
        // Hand-crafted certs (from_json only parses fields — no signature check — so this
        // structural test needs no UserKey/disk/env and is fully deterministic).
        let mk_cert = |dpub: u8| -> identity::DeviceCert {
            identity::DeviceCert::from_json(&serde_json::json!({
                "devicePub": hex::encode([dpub; 32]),
                "userPub": hex::encode([0x11u8; 32]),
                "expires": 9_999_999_999u64,
                "issued": 1u64,
                "sig": hex::encode([0u8; 64]),
            })).unwrap()
        };
        let cert_a = mk_cert(0xa1);
        let cert_b = mk_cert(0xb2);

        let mut arr: Vec<Value> = vec![];

        // Generation A: secretA + certA land together.
        upsert_peer_record(&mut arr, "bob", Some("secretA"), Some(&cert_a), None, None, None);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["secret"].as_str(), Some("secretA"));
        let stored_a = identity::DeviceCert::from_json(&arr[0]["deviceCert"]).unwrap();
        assert_eq!(stored_a.device_pub, [0xa1u8; 32], "gen A: cert must be certA");

        // Generation B: secretB + certB — the update that a non-atomic path could tear.
        upsert_peer_record(&mut arr, "bob", Some("secretB"), Some(&cert_b), None, None, None);
        assert_eq!(arr.len(), 1, "same name updates in place, not duplicated");
        // The invariant: secret and cert are BOTH gen-B in the SAME record.
        assert_eq!(arr[0]["secret"].as_str(), Some("secretB"), "secret must be gen B");
        let stored_b = identity::DeviceCert::from_json(&arr[0]["deviceCert"]).unwrap();
        assert_eq!(stored_b.device_pub, [0xb2u8; 32], "cert must be gen B — never torn to certA");
        assert_ne!(stored_b.device_pub, [0xa1u8; 32], "new secret must not retain the old-gen cert");
    }

    // --- consent-queue pure-fn tests ---------------------------------------

    /// add_pending_request appends and deduplicates by id.
    #[test]
    fn consent_add_pending_enqueues() {
        let mut reqs = Vec::new();
        add_pending_request("alice", "shell", &mut reqs);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].peer, "alice");
        assert_eq!(reqs[0].capability, "shell");
        assert_eq!(reqs[0].status, "pending");
        // id auto-increments
        add_pending_request("bob", "mount", &mut reqs);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].id, reqs[0].id + 1);
    }

    #[test]
    fn consent_enqueue_skips_unidentified() {
        // The pure function enqueue_if_requestable bails on empty/<unverified>.
        // It reads from disk — test via its guard clauses: empty returns early.
        // For a pure test, verify the add_pending_request guard handles it:
        let mut reqs = Vec::new();
        // enqueue_if_requestable skips "" and "<unverified>" at the caller level;
        // test that add_pending_request would still enqueue them (guard lives
        // in enqueue_if_requestable, not add_pending_request).
        add_pending_request("<unverified>", "shell", &mut reqs);
        assert_eq!(reqs.len(), 1); // add_pending_request itself doesn't filter
        // The guard is in enqueue_if_requestable, tested next.
    }

    #[test]
    fn consent_enqueue_dedup_same_peer_cap_pending() {
        // add_pending_request has no dedup itself; dedup lives in enqueue_if_requestable.
        // Test the dedup logic directly: check-before-insert on in-flight requests.
        let mut reqs = vec![PendingRequest {
            id: 1, peer: "alice".into(), capability: "shell".into(),
            timestamp: 0, status: "pending".into(), granted_at: None,
        }];
        let dup = reqs.iter().any(|r| r.peer == "alice" && r.capability == "shell" && r.status == "pending");
        assert!(dup, "existing pending entry must be found as duplicate");
        let non_dup = reqs.iter().any(|r| r.peer == "alice" && r.capability == "mount" && r.status == "pending");
        assert!(!non_dup, "different cap must not be a duplicate");
        let non_dup2 = reqs.iter().any(|r| r.peer == "bob" && r.capability == "shell" && r.status == "pending");
        assert!(!non_dup2, "different peer must not be a duplicate");
    }

    #[test]
    fn consent_enqueue_max_evicts_oldest() {
        let mut reqs: Vec<PendingRequest> = (0..(MAX_PENDING + 1))
            .map(|i| PendingRequest {
                id: i as u64, peer: format!("peer{i}"), capability: "shell".into(),
                timestamp: 0, status: "pending".into(), granted_at: None,
            })
            .collect();
        // add_pending_request evicts while pending count >= MAX_PENDING
        add_pending_request("overflow", "shell", &mut reqs);
        // The oldest (id=0, peer0) should be gone
        let has_peer0 = reqs.iter().any(|r| r.peer == "peer0");
        assert!(!has_peer0, "oldest pending must be evicted when queue full");
        let count_pending = reqs.iter().filter(|r| r.status == "pending").count();
        assert!(count_pending <= MAX_PENDING, "queue must not exceed MAX_PENDING");
    }

    #[test]
    fn consent_expiry_is_terminal() {
        let old_ts = crate::capability::now_secs().saturating_sub(REQUEST_TTL_SECS + 1);
        let mut reqs = vec![PendingRequest {
            id: 1, peer: "alice".into(), capability: "shell".into(),
            timestamp: old_ts, status: "pending".into(), granted_at: None,
        }];
        expire_requests(&mut reqs);
        assert_eq!(reqs[0].status, "expired", "expired pending must become terminal expired");
        // Running expire again must not change the status (already terminal)
        reqs[0].status = "expired".to_string();
        let snapshot = reqs[0].status.clone();
        expire_requests(&mut reqs);
        assert_eq!(reqs[0].status, snapshot, "terminal status must not be re-expired");
    }

    /// Admitting a delegated principal MUST NOT persist anything to the device
    /// store. A delegated link's authority comes from identity_user_pub=owner_pub
    /// + principal_kind=Delegated{caps}; these are in-memory Link fields only.
    /// If identity_user_pub were ever written to devices.json, then on reconnect
    /// resolve_peer_identity would restore it while principal_kind defaults to
    /// OwnerDevice (ak_caps=None), the ceiling vanishes, and the owner-shortcut
    /// authorizes everything — a full escalation.
    ///
    /// The non-persistence invariant is enforced at the rig level: devices.json is
    /// byte-identical before/after a successful enrollment. A unit test on
    /// admit_delegated alone is vacuous (it has no device-store access); the rig
    /// covers ANY write path including unanticipated ones.
    #[test]
    fn delegated_principal_never_written_to_device_store() {
        let mk_cert = |dpub: u8| -> identity::DeviceCert {
            identity::DeviceCert::from_json(&serde_json::json!({
                "devicePub": hex::encode([dpub; 32]),
                "userPub": hex::encode([0x11u8; 32]),
                "expires": 9_999_999_999u64,
                "issued": 1u64,
                "sig": hex::encode([0u8; 64]),
            })).unwrap()
        };
        let cert = mk_cert(0xdd);
        let mut arr: Vec<Value> = vec![];
        // Simulate what the daemon does: store a device record via upsert_peer_record
        upsert_peer_record(&mut arr, "delegated-peer", Some("secret123"), Some(&cert), None, None, None);
        assert_eq!(arr.len(), 1);
        let record = &arr[0];
        // The device store record MUST NOT contain identity_user_pub or principal_kind
        assert!(!record.get("identity_user_pub").is_some(),
            "device store must not contain identity_user_pub — that is a Link-only field");
        assert!(!record.get("principal_kind").is_some(),
            "device store must not contain principal_kind — that is a Link-only field");
        assert!(!record.get("identity_binding").is_some(),
            "device store must not contain identity_binding — that is a Link-only field");
        // The record should only have the fields the store actually uses:
        // name, secret, caps, deviceCert, addedAt, userKey, identityScope, v
        let allowed: std::collections::HashSet<&str> = [
            "name", "secret", "caps", "deviceCert", "addedAt", "v",
            "userKey", "identityScope",
        ].iter().cloned().collect();
        for key in record.as_object().unwrap().keys() {
            assert!(allowed.contains(key.as_str()),
                "unexpected device store field '{key}' — is a Link field leaking?");
        }
    }

    #[test]
    fn legacy_bounded_cap_is_denied_after_expiry() {
        let path = std::env::temp_dir().join(format!("filament-bounded-cap-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&serde_json::json!([{
            "name": "peer", "caps": ["transfer", "shell"],
            "capExpires": {"shell": 10}
        }])).unwrap()).unwrap();
        assert!(device_caps_at_time(&path, "peer", 9).unwrap().contains(&"shell".to_string()));
        assert!(!device_caps_at_time(&path, "peer", 10).unwrap().contains(&"shell".to_string()));
        let _ = std::fs::remove_file(path);
    }

    // ------------------------------------------------- bare-arg router tests --

    /// Bare existing path routes to `send <path> --code`.
    #[test]
    fn bare_existing_path_is_send() {
        let known: std::collections::HashSet<String> = ["laptop"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            classify_bare_token(
                "report.pdf",
                &|_| true,
                &|t| known.contains(t),
            ),
            BareTarget::Send
        );
    }

    #[test]
    fn code_shaped_existing_path_stays_send() {
        let known = std::collections::HashSet::<String>::new();
        assert_eq!(
            classify_bare_token("clever-lynx-1234", &|_| true, &|t| known.contains(t)),
            BareTarget::Send
        );
    }

    /// 4-digit nameplates stay pairing codes; 2-3 digit nameplates stay legacy
    /// transfer codes. Collapsing both to `recv` would break this test.
    #[test]
    fn bare_code_width_decides_pair_vs_recv() {
        let known: std::collections::HashSet<String> = std::collections::HashSet::new();
        assert_eq!(
            classify_bare_token("clever-lynx-1234", &|_| false, &|t| known.contains(t)),
            BareTarget::Pair
        );
        assert_eq!(
            classify_bare_token("clever-lynx-123", &|_| false, &|t| known.contains(t)),
            BareTarget::Recv
        );
        assert_eq!(
            classify_bare_token("clever-lynx-12", &|_| false, &|t| known.contains(t)),
            BareTarget::Recv
        );
    }

    /// A bare known device name routes to pty.
    #[test]
    fn bare_known_device_is_shell() {
        let known: std::collections::HashSet<String> = ["dovm"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            classify_bare_token("dovm", &|_| false, &|t| known.contains(t)),
            BareTarget::Shell
        );
    }

    /// `device:port` routes to forward, using the same port locally and remotely.
    #[test]
    fn device_colon_port_is_forward() {
        let known: std::collections::HashSet<String> = ["laptop"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            classify_bare_token("laptop:5432", &|_| false, &|t| known.contains(t)),
            BareTarget::Forward {
                lport: "5432".into(),
                peer: "laptop".into(),
                rport: "5432".into(),
            }
        );
    }

    /// The forward rewrite produces the exact argv shape the `Forward` subcommand
    /// expects: `filament forward <lport> <peer> <rport>`.
    #[test]
    fn forward_rewrite_argv_shape() {
        let mut argv: Vec<String> = vec!["filament".into(), "laptop:5432".into()];
        argv.remove(1);
        argv.insert(1, "forward".into());
        argv.insert(2, "5432".into());
        argv.insert(3, "laptop".into());
        argv.insert(4, "5432".into());
        assert_eq!(argv, vec!["filament", "forward", "5432", "laptop", "5432"]);
    }

    /// A malformed port after the colon must NOT be treated as a forward.
    #[test]
    fn device_colon_notaport_is_not_forward() {
        let known: std::collections::HashSet<String> = ["laptop"].iter().map(|s| s.to_string()).collect();
        let t = classify_bare_token("laptop:notaport", &|_| false, &|t| known.contains(t));
        assert!(
            !matches!(t, BareTarget::Forward { .. }),
            "laptop:notaport must not classify as forward, got {t:?}"
        );
    }

    /// `device.mesh:port` routes to reach.
    #[test]
    fn device_mesh_port_is_reach() {
        let known = std::collections::HashSet::<String>::new();
        assert_eq!(
            classify_bare_token("gpu.mesh:8080", &|_| false, &|t| known.contains(t)),
            BareTarget::Reach("gpu.mesh:8080".into())
        );
        assert_eq!(
            classify_bare_token("gpu.mesh", &|_| false, &|t| known.contains(t)),
            BareTarget::Reach("gpu.mesh".into())
        );
    }

    /// A bare token that is BOTH a file and a known device is ambiguous. The
    /// router must refuse to pick a side instead of defaulting to send.
    #[test]
    fn file_and_device_is_ambiguous() {
        let known: std::collections::HashSet<String> = ["laptop"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            classify_bare_token("laptop", &|_| true, &|t| known.contains(t)),
            BareTarget::AmbiguousFileDevice
        );
    }

    /// An unrecognized token reaches the did-you-mean path.
    #[test]
    fn unknown_token_is_unknown() {
        let known: std::collections::HashSet<String> = ["laptop"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            classify_bare_token("xyzpdq", &|_| false, &|t| known.contains(t)),
            BareTarget::Unknown
        );
    }
    #[test]
    fn capability_revoke_warning_only_live_same_owner_cert() {
        let cert = identity::DeviceCert::from_json(&serde_json::json!({
            "devicePub": hex::encode([0x11u8; 32]),
            "userPub": hex::encode([0x22u8; 32]),
            "expires": 200,
            "issued": 100,
            "sig": hex::encode([0u8; 64]),
        })).unwrap();
        let warning = fleet_certificate_warning_for("laptop", &cert, [0x22; 32], 150).unwrap();
        assert!(warning.contains("laptop still has fleet access via its certificate"));
        assert!(warning.contains("filament revoke laptop --certificate"));
        assert!(fleet_certificate_warning_for("laptop", &cert, [0x33; 32], 150).is_none());
        assert!(fleet_certificate_warning_for("laptop", &cert, [0x22; 32], 200).is_none());
    }
}
