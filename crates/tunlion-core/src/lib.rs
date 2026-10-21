//! tunlion as a library any process can call.
//!
//! Android is what forced the surface into existence. It is one caller, not the
//! owner. A desktop embedding, a test, or another language binding uses the
//! same types. Slice 1 is identity in an explicit config directory.
//!
//! The engine runtime now lives in `filament_peerloop::driver::Engine`: one
//! cancellation latch, one publish-once readiness edge, one owned dispatch task
//! with `stop`/`wait`. `Core` owns that runtime per instance.
//!
//! The receive **dispatch body** moved into
//! `filament_peerloop::recv::dispatch` (feature `dispatch`); the CLI is now the
//! process adapter around it. `Core::start` composes the reduced library host
//! (`DeviceStore`, `IdentityService`, `EnrollmentService`, roster/depart and
//! fleet facts), takes the same-root `up.lock` election and runs the real
//! dispatch. It waits for the publish-once readiness edge before publishing
//! `Running`; absent PTY/exec/sshd/mount/forward/sync/proxy/wireguard endpoints
//! are named refusals. The optional fleet service is composed only with the
//! `fleet` feature. See `docs/engine-driver.md` and `docs/android-ffi.md`.

mod host;

uniffi::setup_scaffolding!();

use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use filament_id::{user_key_path, KeyStore, PendingIdentity, UserKey};
use filament_peerloop::driver::{
    Cancellation, DriverOutcome, Engine, Readiness, ReadyWatch, StopError,
};
use filament_peerloop::host::{HostServices, LogSink, NoLog};
use filament_peerloop::present::NoScreen;
use filament_peerloop::recv::dispatch::{drive, DispatchFailure, DispatchFailureKind, RecvCleanup};
use filament_peerloop::recv::identity::IdentityService;
use filament_peerloop::recv::ports::{RecvEnv, RecvPorts};
use filament_peerloop::recv::report::{RecvReport, RefusedFailure};
use filament_peerloop::recv::store::{CoreLease, DeviceStore, OverlayKey};
use filament_peerloop::send::engine::{
    CodeInfo, SendFailure, SendFailureKind, SendMode, SendPorts, SendRequest, SendSummary,
};
use filament_peerloop::shell_gate::ShellPolicy;
use filament_transport::TransportContext;
use host::{CoreDaemon, CoreHost, CoreIdentity, CorePrompt, CoreServers, CoreSettings};
use secret_write::SecretFile;

/// Build proof for the Android cdylib job. Not the app API.
#[no_mangle]
pub extern "C" fn tunlion_core_abi_version() -> u32 {
    1
}

/// One dispatch task owned by this Core. The dispatch body is supplied by the
/// embedder; the library owns the runtime, the latch, readiness and the join.
type EngineTask = Engine<Result<(), String>>;

/// Default signaling endpoint when the config does not name one.
const DEFAULT_SERVER: &str = "https://api.tunlion.autumated.com";

/// Resolve the explicit config's server. A missing key uses the compiled
/// default; an explicitly empty/whitespace value is a config error, not a
/// silent fallback. The second case is why this is a function and testable.
fn resolve_server(settings: &CoreSettings) -> Result<String, CoreError> {
    match settings.get("server") {
        None => Ok(DEFAULT_SERVER.to_string()),
        Some(raw) if raw.trim().is_empty() => Err(CoreError::Config(
            "the config has an explicit empty server".to_string(),
        )),
        Some(raw) => Ok(raw.trim().to_string()),
    }
}

/// A fresh consent token per start. The daemon path ignores the token for
/// acceptance (proven links are the consent), but a fixed/guessable token is
/// still not a secret a library should hand out.
fn new_consent_token() -> Result<String, CoreError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CoreError::Engine("consent token: entropy unavailable".to_string()))?;
    Ok(hex::encode(bytes))
}

/// The exact process snapshot a Core engine runs with. Kept as a function so
/// the daemon posture is testable without starting a network engine.
fn core_recv_env(
    display_name: String,
    uid: String,
    config_name: Option<String>,
    pid: u32,
    consent_token: String,
) -> RecvEnv {
    RecvEnv {
        display_name,
        uid,
        interactive_allowed: false,
        interactive_requested: false,
        config_name,
        consent_token,
        // A Core daemon accepts direct offers like the CLI `up` daemon; leaving
        // this false produced WebRTC glare and missed direct offers.
        direct_ok: true,
        pid,
        interactive_terminal: false,
        ..RecvEnv::default()
    }
}

/// The one engine slot a Core owns.
///
/// The states exist to keep two contracts honest under concurrency and under a
/// stop that does not finish:
///
/// - A task that finished on its own is still **unjoined**: its `JoinHandle`
///   (and therefore its `Ok`, `Err` or panic) is owned by the slot until a stop
///   joins it. Status reports `FinishedUnjoined`, never `Stopped`, in that
///   window.
/// - `Ended(_)` and `None` are the only states a fresh `start_with_dispatch`
///   may replace. `Running`, `Stopping` and `Unstopped` all refuse a new start,
///   even when `is_finished()` is already true, because replacing them would
///   drop the handle and silently discard the outcome.
enum EngineSlot {
    /// Nothing was ever started.
    None,
    /// `Core::start` has claimed this Core for startup but has not spawned the
    /// engine yet. This closes the pre-spawn window: a competing start or stop
    /// cannot observe `None` and race the task this call is about to install.
    Claimed,
    /// `Core::start` spawned the engine and is waiting for its readiness edge.
    /// The task is owned here; a concurrent start is refused and a stop may
    /// still join it.
    Starting(EngineTask),
    /// The one engine, owned by this slot. It may already have finished while
    /// still unjoined; `stop` is what joins it and records `Ended`.
    Running(EngineTask),
    /// A stop owns the settle. The task was moved into the stop future; no
    /// start or second stop may proceed until that owner records the outcome.
    Stopping,
    /// A bounded stop expired. The engine is retained here; it may still be
    /// running, or it may have finished since. Either way it is not joined, so
    /// a start is refused until a stop joins it.
    Unstopped(EngineTask),
    /// The last engine was joined. `Err` is its dispatch error (or panic), if
    /// any. A start may replace this: the task is known to have terminated and
    /// its outcome was retrieved.
    Ended(Result<(), String>),
}

/// Owns one in-flight stop claim.
///
/// The slot is moved to `Stopping` and the task is carried here while the stop
/// future awaits its bounded join. If that future is dropped before it settles
/// (a supervisor timeout, a cancelled task), `Drop` returns the task to the
/// slot as `Unstopped` — retained and still refusing a restart — rather than
/// leaving a `Stopping` slot with the task lost.
struct StopClaim<'a> {
    slot: &'a Mutex<EngineSlot>,
    engine: Option<EngineTask>,
}

impl<'a> StopClaim<'a> {
    fn take(&mut self) -> EngineTask {
        self.engine.take().expect("the stop claim is armed")
    }
}

impl Drop for StopClaim<'_> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            // No other writer can own the slot: it is `Stopping` and both
            // `start_with_dispatch` and `stop_within` refuse that state.
            if let Ok(mut slot) = self.slot.lock() {
                *slot = EngineSlot::Unstopped(engine);
            }
        }
    }
}

/// Owns the pre-spawn startup claim.
///
/// `Core::start` sets `EngineSlot::Claimed` before it reads config, builds the
/// host or creates the runtime. A stop sees a claim, not `None`, so it cannot
/// return `Ok` and let the engine appear afterwards. The guard releases the
/// claim on every early return; `install` is the one transition that hands the
/// slot to a spawned task.
struct StartClaim<'a> {
    slot: &'a Mutex<EngineSlot>,
    armed: bool,
    /// The invocation generation this claim owns. It is assigned under the
    /// engine lock at claim time, before any task exists, so a one-shot job
    /// can record the engine it was started by rather than reading whatever
    /// engine happens to own the slot later.
    generation: u64,
}

impl<'a> StartClaim<'a> {
    fn acquire(core: &'a Core) -> Result<Self, CoreError> {
        let mut slot = core
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        let blocked = match &*slot {
            EngineSlot::None | EngineSlot::Ended(_) => None,
            EngineSlot::Claimed | EngineSlot::Stopping => Some(CoreError::EngineStopping),
            EngineSlot::Starting(engine) | EngineSlot::Running(engine) => {
                Some(if engine.is_finished() {
                    CoreError::EngineNotJoined
                } else {
                    CoreError::EngineAlreadyRunning
                })
            }
            EngineSlot::Unstopped(engine) => Some(if engine.is_finished() {
                CoreError::EngineNotJoined
            } else {
                CoreError::EngineNotStopped
            }),
        };
        if let Some(error) = blocked {
            return Err(error);
        }
        *slot = EngineSlot::Claimed;
        // The generation changes with slot ownership, inside the same critical
        // section that takes the slot. A concurrent stop or settle that names
        // the previous generation can therefore never mistake the engine
        // installed here for the one it owns.
        let generation = core.engine_seq.fetch_add(1, Ordering::AcqRel) + 1;
        // A new engine replaces any stale send job from a previous engine.
        core.clear_send_job();
        Ok(Self {
            slot: &core.engine,
            armed: true,
            generation,
        })
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn install(&mut self, engine: EngineTask) -> Result<(), CoreError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        match std::mem::replace(&mut *slot, EngineSlot::Starting(engine)) {
            EngineSlot::Claimed => {
                self.armed = false;
                Ok(())
            }
            other => {
                // A claim cannot normally change underneath its owner, but if
                // it did, put the prior state back and let the guard release
                // the claim rather than installing a second task.
                *slot = other;
                Err(CoreError::Engine(
                    "the engine slot changed during startup".into(),
                ))
            }
        }
    }
}

impl Drop for StartClaim<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut slot) = self.slot.lock() {
            if matches!(&*slot, EngineSlot::Claimed) {
                *slot = EngineSlot::None;
            }
        }
    }
}

/// The host composition for one engine invocation. Both `start` and
/// `receive_code` build it through `Core::prepare_engine`, so a one-shot receive
/// cannot drift into a second host, identity or store implementation.
struct EngineParts {
    server: String,
    transport_context: TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
    ports: RecvPorts,
    /// The persistent `relay = always` policy. One-shot and daemon engines use
    /// relay-only ICE when set, exactly as the CLI does; `auto` stays direct-
    /// first with relay fallback.
    relay: bool,
}

/// The explicit-root composition for one library send.
struct SendParts {
    ports: SendPorts,
    server: String,
    display_name: String,
    uid: String,
    relay: bool,
}

impl From<SendSummary> for SendResult {
    fn from(summary: SendSummary) -> Self {
        Self {
            code: summary.code,
            expires_in_secs: summary.expires_in_secs,
            files: summary
                .files
                .into_iter()
                .map(|file| SentFile {
                    name: file.name,
                    stored_name: file.stored_name,
                    bytes: file.bytes,
                    sha256: file.sha256,
                    delivered: file.delivered,
                })
                .collect(),
            bytes: summary.bytes,
        }
    }
}

/// The fixed posture of a one-shot receive: the code is the only way in, the
/// invocation ends after the transfer, and files go to the caller's directory.
/// Kept as a value so the mapping is unit-tested without a network.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OneShotArgs {
    code: String,
    dir: PathBuf,
    yes: bool,
    timeout: Option<u64>,
    daemon: bool,
    keep_open: bool,
    output: Option<String>,
}

impl OneShotArgs {
    fn new(code: String, dir: PathBuf, yes: bool, timeout: Option<u64>) -> Self {
        Self {
            code,
            dir,
            yes,
            timeout,
            daemon: false,
            keep_open: false,
            output: None,
        }
    }
}

/// Validate and normalize a receive claim exactly like the CLI's code entry:
/// a well-formed claim is words followed by a trailing 3-5 digit nameplate
/// (`brave-otter-ruby-3141`). Malformed input never reaches the network.
fn parse_claim_code(raw: &str) -> Result<String, CoreError> {
    let normalized = filament_pair::norm_code(raw);
    let trimmed = normalized.trim_matches('-');
    let (nameplate, words) = filament_pair::split_code(trimmed);
    let nameplate_ok =
        (3..=5).contains(&nameplate.len()) && nameplate.bytes().all(|b| b.is_ascii_digit());
    if words.is_empty() || !nameplate_ok {
        return Err(CoreError::Usage(
            "that code doesn't look right, expected something like brave-otter-ruby-3141".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Turn the invocation-owned [`RecvReport`] into the small, stable FFI record.
/// Every recorded file lands in exactly one list; arrival order is preserved.
fn summarize_receive(report: &RecvReport) -> ReceiveSummary {
    let mut stored = Vec::new();
    let mut refused = Vec::new();
    for file in report.files() {
        match (file.stored_name.as_deref(), file.refusal.as_ref()) {
            (Some(stored_name), _) => stored.push(StoredFile {
                name: file.file.clone(),
                stored_name: stored_name.to_string(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
            }),
            (None, Some(refusal)) => refused.push(RefusedFile {
                name: file.file.clone(),
                reason: refusal.reason.clone(),
                message: refusal.message.clone(),
            }),
            (None, None) => refused.push(RefusedFile {
                name: file.file.clone(),
                reason: "unrecorded".to_string(),
                message: "the receiver recorded no disposition for this file".to_string(),
            }),
        }
    }
    let bytes = stored.iter().map(|file| file.bytes).sum();
    ReceiveSummary {
        stored,
        refused,
        bytes,
    }
}

/// Map the dispatch's typed failures onto the library's stable vocabulary.
/// The dispatch deliberately carries no process exit codes.
fn map_receive_error(error: anyhow::Error) -> CoreError {
    if let Some(failure) = error.downcast_ref::<DispatchFailure>() {
        return match failure.kind {
            DispatchFailureKind::Usage => CoreError::Usage(failure.message.clone()),
            DispatchFailureKind::Unreachable => CoreError::Unreachable(failure.message.clone()),
        };
    }
    if let Some(refused) = error.downcast_ref::<RefusedFailure>() {
        return CoreError::Refused(refused.message.clone());
    }
    CoreError::Engine(error.to_string())
}

fn map_send_failure(failure: SendFailure) -> CoreError {
    match failure.kind {
        SendFailureKind::Usage => CoreError::Usage(failure.message),
        SendFailureKind::Unreachable => CoreError::Unreachable(failure.message),
        SendFailureKind::Denied | SendFailureKind::Refused => CoreError::Refused(failure.message),
        SendFailureKind::Partial => CoreError::Partial(failure.message),
        SendFailureKind::Interrupted => CoreError::Cancelled,
        SendFailureKind::Engine => CoreError::Engine(failure.message),
    }
}

/// A core opened on one config directory. The directory is the app's private
/// files dir on Android. This type does not read `TUNLION_CONFIG_DIR`.
pub struct Core {
    dir: PathBuf,
    /// The same-root `up.lock` election this Core holds while an engine is
    /// running. `None` before the first start and after a joined stop.
    lease: Mutex<Option<CoreLease>>,
    /// At most one engine per Core. No process-global engine state.
    engine: Mutex<EngineSlot>,
    /// Created only when the caller is not already inside a Tokio runtime, so
    /// the engine never borrows another instance's runtime.
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    /// The completion half of a `create_code` send that is still running. The
    /// engine task itself is in `engine`; this only lets `wait_send` join and
    /// collect the summary without replacing the one-engine state machine. The
    /// generation is the engine that produced the job: a job left over from a
    /// stopped engine must never stop its successor.
    send_job: Mutex<Option<SendJob>>,
    /// Monotonic id for the engine task. Incremented whenever this Core spawns
    /// an engine; a send job carries the id it belongs to.
    engine_seq: AtomicU64,
}

/// The live completion handle for one `create_code` call.
struct SendJob {
    rx: std::sync::mpsc::Receiver<SendEvent>,
    engine_seq: u64,
}

/// The two events a code send produces: its allocated code, then its result.
enum SendEvent {
    Code(CodeInfo),
    Done(Result<SendSummary, CoreError>),
}

/// An identity that exists only in memory until `Core::commit_identity`.
pub struct UncommittedIdentity {
    pending: PendingIdentity,
}

/// Whether the peer loop is running inside this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EngineState {
    /// No engine is owned by this Core. `Core::start` has not started one (or
    /// refused before installing it). A Rust embedder that supplies its own
    /// dispatch may use `start_with_dispatch`.
    NotLinked,
    /// `Core::start` has claimed this Core and is preparing, spawning or
    /// waiting for the real dispatch's publish-once readiness edge.
    Starting,
    /// An engine dispatch started through `start_with_dispatch` is running.
    Running,
    /// A stop is in flight; the task may still be running. A start and a second
    /// stop are both refused while this holds.
    Stopping,
    /// The last engine task finished but has not been joined. Its `JoinHandle`
    /// still owns the outcome (`Ok`, `Err` or panic); status cannot call it
    /// `Stopped` or `Failed` until a stop joins it. A restart is refused until
    /// then, so the handle and outcome are never silently dropped.
    FinishedUnjoined,
    /// The last engine dispatch was joined and returned cleanly (naturally or
    /// by stop). No child process exists; this is about the in-process task.
    Stopped,
    /// The last engine dispatch was joined and returned an error, including a
    /// panic.
    Failed,
    /// A bounded stop expired and the task was retained; it may still be
    /// running. `EngineState` reports this rather than `Stopped` so a caller
    /// never mistakes "we gave up waiting" for "it stopped".
    TimedOut,
}

/// What the UI may poll. A missing identity is `fingerprint: None`, not an error.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Status {
    pub fingerprint: Option<String>,
    pub engine: EngineState,
}

/// One file a one-shot receive stored, after whole-file verification and final
/// placement.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StoredFile {
    /// The name the sender offered.
    pub name: String,
    /// The name it was actually stored under (a collision gets a suffix).
    pub stored_name: String,
    pub bytes: u64,
    /// The verified SHA-256, when the sender offered one.
    pub sha256: Option<String>,
}

/// One offered file the receive refused or the person declined.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RefusedFile {
    /// The name the sender offered.
    pub name: String,
    /// The stable typed reason token (for example `no_space`, `declined`).
    pub reason: String,
    /// The sentence both ends see.
    pub message: String,
}

/// What one `receive_code` call did. Stored files are on disk; refused files
/// are named with their reason, never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceiveSummary {
    pub stored: Vec<StoredFile>,
    pub refused: Vec<RefusedFile>,
    /// Total bytes of the stored files.
    pub bytes: u64,
}

/// A real, claimable transfer code allocated by the signaling server. The
/// Core keeps the sender engine alive after this returns, so the code stays
/// claimable until a receiver uses it or it expires; `wait_send` collects the
/// transfer result and `stop` cancels both.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedCode {
    pub code: String,
    /// Seconds until the code stops being claimable, bounded by the caller's
    /// timeout and the server's TTL.
    pub expires_in_secs: u64,
}

/// One file's send result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SentFile {
    pub name: String,
    /// The name the receiver stored it under, when it reported one.
    pub stored_name: Option<String>,
    pub bytes: u64,
    pub sha256: Option<String>,
    /// True only when the receiver's whole-file `delivery-ack` landed (or the
    /// file had no digest to verify, the legacy case).
    pub delivered: bool,
}

/// What a send did. `code` is present for code sends.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendResult {
    pub code: Option<String>,
    pub expires_in_secs: Option<u64>,
    pub files: Vec<SentFile>,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Identity(String),
    /// The explicit config directory's `config` file is unreadable or names an
    /// explicitly empty signaling server.
    #[error("{0}")]
    Config(String),
    /// The caller's input cannot be acted on, before any network work (a
    /// malformed receive code, for example).
    #[error("{0}")]
    Usage(String),
    /// The receive ran but nobody authenticated and offered a transfer within
    /// the caller's timeout. This is the library equivalent of the CLI's
    /// exit 6 ("unreachable"), and it is only returned when nothing was
    /// received.
    #[error("{0}")]
    Unreachable(String),
    /// The transfer was refused or declined. Files that were stored or refused
    /// before the end are summarized by a successful call instead; this error
    /// is for an invocation that recorded no per-file fact.
    #[error("{0}")]
    Refused(String),
    /// Some send files were confirmed and some were not. Never reported as a
    /// full success.
    #[error("{0}")]
    Partial(String),
    /// A `stop` / `stop_blocking` cancelled the receive or send. Cancellation is
    /// never reported as a successful (possibly empty) operation.
    #[error("the operation was cancelled")]
    Cancelled,
    /// The 12 words did not match the phrase this pending identity minted.
    #[error("the recovery phrase did not match")]
    PhraseMismatch,
    /// `identity.ed25519` is already in this config directory.
    #[error("an identity already exists in this config directory")]
    AlreadyExists,
    /// Another Core or CLI daemon holds this config directory's engine lease.
    #[error("another engine holds this config directory")]
    EngineLease,
    /// An engine dispatch is already running in this Core.
    #[error("an engine is already running in this core")]
    EngineAlreadyRunning,
    /// A stop is already in flight. Starting or stopping again would let two
    /// owners race the same slot, so both are refused.
    #[error("an engine stop is already in progress in this core")]
    EngineStopping,
    /// A previous stop bound expired and its task was retained. It may still be
    /// running, so a new engine is refused until it is joined.
    #[error("the previous engine has not stopped")]
    EngineNotStopped,
    /// The previous engine task has finished but was not joined, so its result
    /// (including an error or panic) is still owned by this Core. A start would
    /// drop that handle, so it is refused until `stop` / `stop_within` joins it.
    #[error("the previous engine finished but has not been joined")]
    EngineNotJoined,
    /// The dispatch returned an error string after it was started.
    #[error("{0}")]
    Engine(String),
    /// The engine did not finish within the stop bound. Its task is retained by
    /// this Core, not detached; `status().engine` is `TimedOut`.
    #[error("{0}")]
    Stop(String),
}

struct DirStore {
    root: PathBuf,
}

impl KeyStore for DirStore {
    fn write_secret(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        SecretFile::write(path, data)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn config_path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Core {
    /// Open `config_dir`, creating it if needed. Does not mint an identity.
    pub fn open(config_dir: impl AsRef<Path>) -> Result<Self, CoreError> {
        let dir = config_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(io_err)?;
        set_private_dir(&dir)?;
        Ok(Core {
            dir,
            lease: Mutex::new(None),
            engine: Mutex::new(EngineSlot::None),
            runtime: Mutex::new(None),
            send_job: Mutex::new(None),
            engine_seq: AtomicU64::new(0),
        })
    }

    pub fn config_dir(&self) -> &Path {
        &self.dir
    }

    /// Mint a phrase. Writes nothing. Fails if an identity file is already there.
    pub fn begin_identity(&self) -> Result<UncommittedIdentity, CoreError> {
        let store = self.store();
        if user_key_path(&store).exists() {
            return Err(CoreError::AlreadyExists);
        }
        let pending = PendingIdentity::generate().map_err(id_err)?;
        Ok(UncommittedIdentity { pending })
    }

    /// Persist `pending` only when `confirmed_phrase` is the same 12 words.
    /// Returns the fingerprint. A mismatch leaves the disk unchanged.
    pub fn commit_identity(
        &self,
        pending: UncommittedIdentity,
        confirmed_phrase: &str,
    ) -> Result<String, CoreError> {
        if !pending.matches(confirmed_phrase) {
            return Err(CoreError::PhraseMismatch);
        }
        let fingerprint = pending.fingerprint();
        DeviceStore::open(&self.dir).commit_pending_identity(pending.pending).map_err(id_err)?;
        Ok(fingerprint)
    }

    /// The owner fingerprint, if an identity file exists. Does not mint.
    pub fn fingerprint(&self) -> Result<Option<String>, CoreError> {
        Ok(UserKey::load(&self.store())
            .map_err(id_err)?
            .map(|key| key.fingerprint()))
    }

    pub fn status(&self) -> Result<Status, CoreError> {
        Ok(Status {
            fingerprint: self.fingerprint()?,
            engine: self.engine_state()?,
        })
    }

    /// Start the real receive engine for this config directory.
    ///
    /// Bootstraps internal identity on this mutation, validates config, takes the same-root
    /// `up.lock` election (shared with the CLI daemon), starts `recv::dispatch`
    /// on this Core's runtime and waits for its publish-once readiness edge.
    /// A failure releases the lease and joins the task unless it timed out, in
    /// which case the task is retained and a retry is refused.
    pub fn start(&self) -> Result<(), CoreError> {
        // Claim before identity/config/host/runtime work. A stop in this
        // window sees `Claimed` and returns `EngineStopping`; it can never
        // return `Ok` and then watch an engine appear behind it.
        let mut claim = StartClaim::acquire(self)?;

        let engine_dir = self.dir.join("inbox");
        let (parts, lease) = self.prepare_engine(engine_dir.clone())?;
        let EngineParts {
            server,
            transport_context,
            log,
            host,
            ports,
            relay,
        } = parts;
        let dispatch = move |stop: Cancellation, readiness: Readiness| async move {
            let mut cleanup = RecvCleanup::default();
            let outcome = drive(
                &server,
                None,
                engine_dir,
                false,
                None,
                None,
                true,
                None,
                None,
                relay,
                None,
                true,
                None,
                ShellPolicy::Granted,
                None,
                true,
                transport_context,
                log,
                host,
                ports,
                RecvReport::new(),
                &stop,
                &readiness,
                &mut cleanup,
            )
            .await;
            match outcome {
                DriverOutcome::Cancelled => Ok::<(), String>(()),
                DriverOutcome::Returned(Ok(())) => Ok(()),
                DriverOutcome::Returned(Err(error)) => Err(error.to_string()),
            }
        };

        let (handle, engine, watch) = self.spawn_engine(dispatch)?;
        claim.install(engine)?;
        self.finish_start(handle, watch, lease)
    }

    /// Receive one transfer by code, synchronously, with one-shot semantics.
    ///
    /// This runs the same `recv::dispatch::drive` the CLI `receive` adapter and
    /// `Core::start` run: same reduced `CoreHost`, ports, identity and store.
    /// The code is the only way in (`daemon: false`), the invocation ends when
    /// the transfer is done instead of serving (`keep_open: false`), and files
    /// go to the caller's `dir`. `yes` accepts matching offers without a
    /// prompt; `timeout` bounds the wait for a sender, in seconds, exactly as
    /// the CLI's `--timeout` does.
    ///
    /// The call blocks until the dispatch finishes, the sender/refusal path
    /// ends, or `stop` / `stop_blocking` cancels it. There is no readiness
    /// edge: one-shot receives have transfer-completion semantics, so this
    /// never waits for the daemon's "engine is serving" publication.
    ///
    /// A malformed code is rejected with `CoreError::Usage` before any network
    /// work. Cancellation returns `CoreError::Cancelled`, never `Ok`. A wait
    /// that ends with nothing received returns `CoreError::Unreachable` (the
    /// CLI's exit 6). Files recorded before an error are returned in the
    /// summary rather than dropped.
    ///
    /// The same-directory `up.lock` lease is taken for the duration and
    /// released on completion, refusal or error; a Core or CLI that already
    /// owns the root refuses with `EngineLease`, and a running engine in this
    /// Core refuses with `EngineAlreadyRunning`.
    pub fn receive_code(
        &self,
        code: String,
        dir: PathBuf,
        yes: bool,
        timeout: Option<u64>,
    ) -> Result<ReceiveSummary, CoreError> {
        // Parse first: a typo must cost nothing and must not touch the network,
        // the lease or a running engine.
        let code = parse_claim_code(&code)?;
        let args = OneShotArgs::new(code, dir, yes, timeout);

        let mut claim = StartClaim::acquire(self)?;
        let (parts, lease) = self.prepare_engine(args.dir.clone())?;
        let EngineParts {
            server,
            transport_context,
            log,
            host,
            ports,
            relay,
        } = parts;

        let report = RecvReport::new();
        let engine_report = report.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<ReceiveSummary, CoreError>>();
        let dispatch = move |stop: Cancellation, readiness: Readiness| async move {
            let mut cleanup = RecvCleanup::default();
            let outcome = drive(
                &server,
                Some(args.code),
                args.dir,
                args.yes,
                None,
                None,
                args.keep_open,
                args.timeout,
                None,
                relay,
                None,
                args.daemon,
                args.output,
                ShellPolicy::Granted,
                None,
                true,
                transport_context,
                log,
                host,
                ports,
                engine_report.clone(),
                &stop,
                &readiness,
                &mut cleanup,
            )
            .await;
            let result = match outcome {
                // Cancellation is its own outcome, never an empty success.
                DriverOutcome::Cancelled => Err(CoreError::Cancelled),
                DriverOutcome::Returned(result) => {
                    let summary = summarize_receive(&engine_report);
                    if summary.stored.is_empty() && summary.refused.is_empty() {
                        match result {
                            Ok(()) => Ok(summary),
                            Err(error) => Err(map_receive_error(error)),
                        }
                    } else {
                        // The per-file facts are the truth even when the
                        // dispatch also returned an error (a partial receive,
                        // or every file refused): report them, do not drop
                        // them behind one sentence.
                        Ok(summary)
                    }
                }
            };
            let _ = done_tx.send(result);
            Ok::<(), String>(())
        };

        let generation = claim.generation();
        let (_handle, engine, _watch) = self.spawn_engine(dispatch)?;
        claim.install(engine)?;
        // Publish Running and the lease in one critical section, like start.
        // A stop that won the slot already owns the join and the lease.
        let published = self.publish_one_shot(lease);
        let result = done_rx.recv().unwrap_or_else(|_| {
            Err(CoreError::Engine(
                "the receive dispatch ended without a result".into(),
            ))
        });
        let settled = self.settle_one_shot(generation);

        match result {
            // A cancelled receive is cancelled even if a concurrent stop is
            // still finishing its join; that stop owns the lease release.
            Err(CoreError::Cancelled) => Err(CoreError::Cancelled),
            other => {
                published?;
                settled?;
                other
            }
        }
    }

    /// Allocate a real, claimable transfer code and start the one-shot sender
    /// engine behind it.
    ///
    /// This is not a random words generator. The engine connects to the
    /// configured signaling server, asks it to register a v2 nameplate, keeps
    /// the socket and room alive, and returns only after the server has
    /// allocated the code. The registration stays alive in this Core's engine
    /// slot until a receiver claims it, the code expires, or `stop` cancels it.
    ///
    /// The files are resolved and hashed before the code is allocated, so a
    /// missing/unreadable local path fails without spending a code. Call
    /// `wait_send` to reap the transfer result and release the root lease.
    pub fn create_code(
        &self,
        paths: Vec<String>,
        timeout: Option<u64>,
    ) -> Result<CreatedCode, CoreError> {
        let (events, generation) =
            self.begin_send(paths, SendMode::Code { word: None }, true, timeout)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let settled = self.settle_one_shot(generation);
                settled?;
                return Err(CoreError::Engine(
                    "the server did not allocate a transfer code in time".into(),
                ));
            }
            match events.recv_timeout(left) {
                Ok(SendEvent::Code(code)) => {
                    // The job belongs to the generation claimed by THIS
                    // invocation, not whichever engine owns the slot now.
                    // Publishing is one critical section with that check, so
                    // a stop or successor start cannot leave a stale job
                    // behind that shadows the successor's.
                    self.publish_send_job(generation, events)?;
                    return Ok(CreatedCode {
                        code: code.code,
                        expires_in_secs: code.expires_in_secs,
                    });
                }
                Ok(SendEvent::Done(result)) => {
                    // The engine failed before a code existed. The typed error
                    // (Usage for a bad local path, Unreachable for an
                    // unreachable server, Cancelled for a stop) is the answer;
                    // do not replace it with a timeout. A failure to settle is
                    // itself surfaced.
                    let settled = self.settle_one_shot(generation);
                    settled?;
                    return match result {
                        Ok(_) => Err(CoreError::Engine(
                            "the send completed before allocating a code".into(),
                        )),
                        Err(error) => Err(error),
                    };
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let settled = self.settle_one_shot(generation);
                    settled?;
                    return Err(CoreError::Engine(
                        "the server did not allocate a transfer code in time".into(),
                    ));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let settled = self.settle_one_shot(generation);
                    settled?;
                    return Err(CoreError::Engine(
                        "the send dispatch ended before allocating a code".into(),
                    ));
                }
            }
        }
    }

    /// Wait for the send started by `create_code` and return its per-file
    /// result. Joins the engine and releases the same-root lease, exactly like
    /// `receive_code` does for a receive.
    pub fn wait_send(&self) -> Result<SendResult, CoreError> {
        let job = self
            .send_job
            .lock()
            .map_err(|_| CoreError::Engine("the send job lock was poisoned".into()))?
            .take()
            .ok_or_else(|| CoreError::Engine("no code send is in progress".into()))?;
        if job.engine_seq != self.engine_generation() {
            // A stopped/replaced engine left this job behind. It must not stop
            // or reap the engine that owns the slot now.
            return Err(CoreError::Engine(
                "the send job belongs to a previous engine".into(),
            ));
        }
        let generation = job.engine_seq;
        let result = loop {
            match job.rx.recv() {
                Ok(SendEvent::Done(result)) => break result,
                Ok(SendEvent::Code(_)) => continue,
                Err(_) => {
                    break Err(CoreError::Engine(
                        "the send dispatch ended without a result".into(),
                    ))
                }
            }
        };
        // Generation-tagged: if a stop and a new start landed while this call
        // was blocked on the channel, the settle is a no-op for the old
        // generation instead of joining the successor's engine.
        let settled = self.settle_one_shot(generation);
        match result {
            Err(CoreError::Cancelled) => Err(CoreError::Cancelled),
            other => {
                settled?;
                other.map(Into::into)
            }
        }
    }

    /// Send files by a code in one blocking call. The code is allocated for
    /// real and is returned in the result; callers that need the code before the
    /// transfer finishes should use `create_code` and `wait_send`.
    pub fn send_by_code(
        &self,
        paths: Vec<String>,
        timeout: Option<u64>,
    ) -> Result<SendResult, CoreError> {
        let _ = self.create_code(paths, timeout)?;
        self.wait_send()
    }

    /// Send files to an already paired device by petname. Blocking, one-shot,
    /// with the same explicit root/identity/store and lease as `start`.
    pub fn send_to_device(
        &self,
        paths: Vec<String>,
        device: String,
        timeout: Option<u64>,
    ) -> Result<SendResult, CoreError> {
        let (events, generation) =
            self.begin_send(paths, SendMode::Device { name: device }, false, timeout)?;
        let result = loop {
            match events.recv() {
                Ok(SendEvent::Done(result)) => break result,
                Ok(SendEvent::Code(_)) => continue,
                Err(_) => {
                    break Err(CoreError::Engine(
                        "the send dispatch ended without a result".into(),
                    ))
                }
            }
        };
        let settled = self.settle_one_shot(generation);
        match result {
            Err(CoreError::Cancelled) => Err(CoreError::Cancelled),
            other => {
                settled?;
                other.map(Into::into)
            }
        }
    }

    /// Claim the engine slot, build the shared sender ports and spawn the
    /// one-shot engine. `want_code` adds the code-allocation channel.
    fn begin_send(
        &self,
        paths: Vec<String>,
        mode: SendMode,
        want_code: bool,
        timeout: Option<u64>,
    ) -> Result<(std::sync::mpsc::Receiver<SendEvent>, u64), CoreError> {
        if paths.is_empty() {
            return Err(CoreError::Usage(
                "nothing to send; pass at least one regular file".into(),
            ));
        }
        let mut claim = StartClaim::acquire(self)?;
        // Claimed before the engine exists: the generation is the invocation's
        // own ownership token, not a read of whoever owns the slot when the
        // first event arrives.
        let generation = claim.generation();
        let (parts, lease) = self.prepare_send()?;
        let SendParts {
            ports,
            server,
            display_name,
            uid,
            relay,
        } = parts;
        let request = SendRequest {
            server,
            paths: paths.into_iter().map(PathBuf::from).collect(),
            name: None,
            mode,
            relay,
            timeout,
            display_name,
            uid,
        };
        let (event_tx, event_rx) = std::sync::mpsc::channel::<SendEvent>();
        let done_tx = event_tx.clone();
        let code_notify: Option<filament_peerloop::send::engine::CodeNotify> = if want_code {
            let tx = event_tx.clone();
            Some(Box::new(move |code| {
                let _ = tx.send(SendEvent::Code(code));
            }))
        } else {
            None
        };
        drop(event_tx);
        let dispatch = move |stop: Cancellation, _readiness: Readiness| async move {
            // `drive` handles cancellation itself, so its teardown always runs:
            // wrapping it in `stop.run` would DROP the future on cancel and
            // skip the socket/links cleanup. Interrupted maps to Cancelled.
            let result =
                match filament_peerloop::send::engine::drive(request, ports, code_notify, &stop)
                    .await
                {
                    Ok(summary) => Ok(summary),
                    Err(failure) => Err(map_send_failure(failure)),
                };
            let _ = done_tx.send(SendEvent::Done(result));
            Ok::<(), String>(())
        };
        let (_handle, engine, _watch) = self.spawn_engine(dispatch)?;
        claim.install(engine)?;
        let published = self.publish_one_shot(lease);
        if let Err(error) = published {
            let _ = self.settle_one_shot(generation);
            return Err(error);
        }
        Ok((event_rx, generation))
    }

    /// The explicit-root host/identity/store/transport composition for one
    /// send. The sender never reads `TUNLION_CONFIG_DIR` or spawns the CLI.
    fn prepare_send(&self) -> Result<(SendParts, CoreLease), CoreError> {
        let store = DeviceStore::open(&self.dir);
        let settings =
            CoreSettings::load(&self.dir).map_err(|e| CoreError::Config(e.to_string()))?;
        let server = resolve_server(&settings)?;
        store.ensure_identity_on_mutation().map_err(id_err)?;
        let relay = settings.relay_only();
        let lease = store
            .try_acquire_engine_lease()
            .map_err(|e| CoreError::Engine(format!("engine lease: {e}")))?
            .ok_or(CoreError::EngineLease)?;
        let display_name = settings
            .get("name")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "device".to_string());
        let uid = format!(
            "core-s-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        );
        let overlay = OverlayKey::new(self.dir.join("overlay.ed25519"));
        let log: Arc<dyn LogSink> = Arc::new(NoLog);
        let settle_ms = settings
            .u64("gate.settle_ms")
            .filter(|n| *n > 0)
            .map(|n| n.clamp(250, 5_000))
            .unwrap_or(2_000);
        let host = Arc::new(CoreHost::new(
            self.dir.clone(),
            store.clone(),
            settings.clone(),
            overlay.clone(),
        ));
        let identity = Arc::new(IdentityService::new(
            store.clone(),
            overlay,
            display_name.clone(),
            settle_ms,
            log.clone(),
        ));
        let settings_for_peer = settings.clone();
        let settings_for_membership = settings.clone();
        let transport_context = TransportContext::new(
            Some(self.dir.join("signaling-dns.json")),
            move |key, peer| settings_for_peer.setting(key, peer),
            move |peer| settings_for_membership.membership(peer),
        );
        Ok((
            SendParts {
                ports: SendPorts {
                    host,
                    identity,
                    log,
                    present: Arc::new(NoScreen),
                    transport_context,
                },
                server,
                display_name,
                uid,
                relay,
            },
            lease,
        ))
    }

    /// The host/identity/port composition both `start` and `receive_code` use.
    ///
    /// `engine_dir` is where the invocation writes: the config directory's
    /// inbox for a daemon, the caller's directory for a one-shot receive.
    fn prepare_engine(&self, engine_dir: PathBuf) -> Result<(EngineParts, CoreLease), CoreError> {
        let store = DeviceStore::open(&self.dir);
        let settings =
            CoreSettings::load(&self.dir).map_err(|e| CoreError::Config(e.to_string()))?;
        let server = resolve_server(&settings)?;
        store.ensure_identity_on_mutation().map_err(id_err)?;
        let lease = store
            .try_acquire_engine_lease()
            .map_err(|e| CoreError::Engine(format!("engine lease: {e}")))?
            .ok_or(CoreError::EngineLease)?;

        let display_name = settings
            .get("name")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "device".to_string());
        let uid = format!(
            "core-r-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        );
        let consent_token = new_consent_token()?;
        let overlay = OverlayKey::new(self.dir.join("overlay.ed25519"));
        let log: Arc<dyn LogSink> = Arc::new(NoLog);
        let settle_ms = settings
            .u64("gate.settle_ms")
            .filter(|n| *n > 0)
            .map(|n| n.clamp(250, 5_000))
            .unwrap_or(2_000);
        let identity = Arc::new(CoreIdentity::new(
            store.clone(),
            overlay.clone(),
            display_name.clone(),
            settle_ms,
            log.clone(),
        ));
        let host = Arc::new(CoreHost::new(
            self.dir.clone(),
            store.clone(),
            settings.clone(),
            overlay.clone(),
        ));
        let env = core_recv_env(
            display_name.clone(),
            uid,
            settings.get("name"),
            std::process::id(),
            consent_token,
        );
        let ports = RecvPorts::new(
            identity,
            Arc::new(store.clone()),
            Box::new(CoreServers),
            Box::new(CoreDaemon::new(self.dir.clone(), store.clone(), overlay)),
            Arc::new(CorePrompt),
            // The reduced Core profile serves receive/transfer only; a PTY open
            // is refused by name by the library before this value is consulted.
            Box::new(filament_peerloop::recv::servers::shell::UnavailablePty),
            Arc::new(NoScreen),
            env,
        );
        fs::create_dir_all(&engine_dir).map_err(io_err)?;
        let relay = settings.relay_only();
        let settings_for_peer = settings.clone();
        let settings_for_membership = settings.clone();
        let transport_context = TransportContext::new(
            Some(self.dir.join("signaling-dns.json")),
            move |key, peer| settings_for_peer.setting(key, peer),
            move |peer| settings_for_membership.membership(peer),
        );
        Ok((
            EngineParts {
                server,
                transport_context,
                log,
                host,
                ports,
                relay,
            },
            lease,
        ))
    }

    /// Publish `Running` and store the one-shot lease in one critical section.
    ///
    /// Unlike [`Core::publish_started`], a one-shot dispatch does not publish
    /// readiness, so a task that already returned is still `Running` here: its
    /// result is waiting on the completion channel and `settle_one_shot` joins
    /// it. If a stop won the slot first, this never replaces its state; it
    /// keeps the lease with the task owner so that join is the one release.
    fn publish_one_shot(&self, lease: CoreLease) -> Result<(), CoreError> {
        let mut slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        match std::mem::replace(&mut *slot, EngineSlot::None) {
            EngineSlot::Starting(engine) => {
                let mut held = self
                    .lease
                    .lock()
                    .map_err(|_| CoreError::Engine("the lease lock was poisoned".into()))?;
                *held = Some(lease);
                drop(held);
                *slot = EngineSlot::Running(engine);
                Ok(())
            }
            other => {
                *slot = other;
                if matches!(
                    &*slot,
                    EngineSlot::Starting(_)
                        | EngineSlot::Running(_)
                        | EngineSlot::Stopping
                        | EngineSlot::Unstopped(_)
                ) {
                    if let Ok(mut held) = self.lease.lock() {
                        *held = Some(lease);
                    }
                }
                Err(CoreError::Stop(
                    "the one-shot engine stopped while it was starting".into(),
                ))
            }
        }
    }

    /// Join a one-shot dispatch that has already sent its result, releasing the
    /// lease. A concurrent stop may own the join; wait (bounded) for it to
    /// settle instead of stealing its slot.
    ///
    /// The `generation` is the one this one-shot invocation claimed before it
    /// spawned. A job that outlived a stop must not reap (or erase the job of)
    /// the engine that owns the slot now; the settle is a no-op for a
    /// superseded generation.
    fn settle_one_shot(&self, generation: u64) -> Result<(), CoreError> {
        match self.stop_blocking_generation(Duration::from_secs(5), Some(generation)) {
            Ok(()) => Ok(()),
            Err(CoreError::EngineStopping) => {
                for _ in 0..5_000 {
                    match self.engine_state()? {
                        EngineState::Stopping => std::thread::sleep(Duration::from_millis(1)),
                        EngineState::Stopped | EngineState::Failed | EngineState::NotLinked => {
                            return Ok(())
                        }
                        _ => return Err(CoreError::EngineNotStopped),
                    }
                }
                Err(CoreError::EngineStopping)
            }
            Err(error) => Err(error),
        }
    }

    /// Wait for the real readiness edge, then publish Running atomically with
    /// the lease. `handle` is this Core's runtime, used to join a dispatch that
    /// finished between publishing readiness and this publication.
    fn finish_start(
        &self,
        handle: tokio::runtime::Handle,
        watch: ReadyWatch,
        lease: CoreLease,
    ) -> Result<(), CoreError> {
        self.finish_start_bounded(
            handle,
            watch,
            lease,
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
    }

    /// The same startup settle with explicit bounds. Production uses 30s
    /// readiness + 5s stop; the test-only entry point makes the timeout path
    /// deterministic without sleeping for half a minute.
    fn finish_start_bounded(
        &self,
        handle: tokio::runtime::Handle,
        watch: ReadyWatch,
        lease: CoreLease,
        readiness_bound: Duration,
        stop_bound: Duration,
    ) -> Result<(), CoreError> {
        let wait_handle = handle.clone();
        let readiness = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    wait_handle.block_on(async move {
                        let mut watch = watch;
                        watch.wait(Some(readiness_bound)).await
                    })
                })
                .join()
                .unwrap_or_else(|_| Err(filament_peerloop::driver::ReadyError::NotPublished))
        });
        match readiness {
            Ok(()) => self.publish_started(&handle, lease),
            Err(error) => {
                // Preserve the cleanup result. A timed-out cleanup is a real
                // `Stop` error with a retained task/lease, not a readiness
                // detail we can overwrite.
                let cleanup = self.stop_blocking_within(stop_bound);
                let _retained = self.retain_lease_if_task_owned(lease);
                match cleanup {
                    Ok(()) => Err(CoreError::Engine(format!(
                        "the receive engine did not become ready: {error}"
                    ))),
                    Err(error) => Err(error),
                }
            }
        }
    }

    #[cfg(test)]
    fn finish_start_for_test(
        &self,
        handle: tokio::runtime::Handle,
        watch: ReadyWatch,
        lease: CoreLease,
        readiness_bound: Duration,
        stop_bound: Duration,
    ) -> Result<(), CoreError> {
        self.finish_start_bounded(handle, watch, lease, readiness_bound, stop_bound)
    }

    /// Publish `Running` and store the lease in one engine-lock critical
    /// section. A stop cannot join and release the lease between the two.
    fn publish_started(
        &self,
        handle: &tokio::runtime::Handle,
        lease: CoreLease,
    ) -> Result<(), CoreError> {
        let mut slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        match std::mem::replace(&mut *slot, EngineSlot::None) {
            EngineSlot::Starting(engine) if engine.is_finished() => {
                // Readiness may be published by a dispatch that returns in the
                // same poll. Never publish Running (or Ok) for a dead task.
                *slot = EngineSlot::Stopping;
                drop(slot);
                let (state, error) = match handle.block_on(engine.wait()) {
                    Ok(Ok(())) => (
                        EngineSlot::Ended(Ok(())),
                        CoreError::Engine(
                            "the engine finished immediately after publishing readiness".into(),
                        ),
                    ),
                    Ok(Err(message)) => (
                        EngineSlot::Ended(Err(message.clone())),
                        CoreError::Engine(message),
                    ),
                    Err(error) => {
                        let message = format!("the engine dispatch failed: {error}");
                        (
                            EngineSlot::Ended(Err(message.clone())),
                            CoreError::Engine(message),
                        )
                    }
                };
                let mut slot = self
                    .engine
                    .lock()
                    .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
                *slot = state;
                drop(slot);
                self.release_lease();
                drop(lease);
                Err(error)
            }
            EngineSlot::Starting(engine) => {
                // Store the lease first, then publish Running, while the
                // engine lock still excludes stop. The lock order is always
                // engine -> lease.
                let mut held = self
                    .lease
                    .lock()
                    .map_err(|_| CoreError::Engine("the lease lock was poisoned".into()))?;
                *held = Some(lease);
                drop(held);
                *slot = EngineSlot::Running(engine);
                Ok(())
            }
            other => {
                // A concurrent stop won while readiness was being observed.
                // Keep the prior state (so its join/timeout owner is intact);
                // retain the local lease if any task is still owned. A Stopping
                // owner will release it on a successful join or keep it on a
                // timeout.
                *slot = other;
                if matches!(
                    &*slot,
                    EngineSlot::Starting(_)
                        | EngineSlot::Running(_)
                        | EngineSlot::Stopping
                        | EngineSlot::Unstopped(_)
                ) {
                    if let Ok(mut held) = self.lease.lock() {
                        *held = Some(lease);
                    }
                }
                Err(CoreError::Stop(
                    "the engine stopped while it was starting".into(),
                ))
            }
        }
    }

    /// Retain the startup lease when the slot still owns (or is joining) a
    /// task. The engine lock is held while the lease is stored, so a stop's
    /// settle sees the same state.
    fn retain_lease_if_task_owned(&self, lease: CoreLease) -> bool {
        let slot = match self.engine.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !matches!(
            &*slot,
            EngineSlot::Starting(_)
                | EngineSlot::Running(_)
                | EngineSlot::Stopping
                | EngineSlot::Unstopped(_)
        ) {
            return false;
        }
        match self.lease.lock() {
            Ok(mut held) => {
                *held = Some(lease);
                true
            }
            Err(poisoned) => {
                *poisoned.into_inner() = Some(lease);
                true
            }
        }
    }

    /// Start the library engine over a caller-supplied dispatch.
    ///
    /// This is the same `filament_peerloop::driver::Engine` the CLI receive/up
    /// path runs. The dispatch receives the cancellation latch and readiness
    /// publisher, and must return only after its own cleanup epilogue. It is
    /// Rust-only on purpose: a language binding cannot supply a dispatch, and
    /// `start` must not pretend it can.
    ///
    /// A Tokio runtime must be available: the caller's current one is used, or
    /// this Core creates and retains its own. The runtime is never global.
    pub fn start_with_dispatch<F, Fut>(&self, dispatch: F) -> Result<(), CoreError>
    where
        F: FnOnce(Cancellation, Readiness) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        // A new engine may replace only a slot whose prior task was joined:
        // `None` (nothing started) or `Ended` (its outcome was retrieved).
        // Every other state still owns a `JoinHandle`, even when
        // `is_finished()` is already true. Replacing those would drop the
        // handle and silently discard a natural `Err` or panic, so refuse and
        // make the caller join through `stop`.
        let blocked = match &*slot {
            EngineSlot::Claimed | EngineSlot::Stopping => Some(CoreError::EngineStopping),
            EngineSlot::Starting(engine) => Some(if engine.is_finished() {
                CoreError::EngineNotJoined
            } else {
                CoreError::EngineAlreadyRunning
            }),
            EngineSlot::Running(engine) => Some(if engine.is_finished() {
                CoreError::EngineNotJoined
            } else {
                CoreError::EngineAlreadyRunning
            }),
            EngineSlot::Unstopped(engine) => Some(if engine.is_finished() {
                CoreError::EngineNotJoined
            } else {
                CoreError::EngineNotStopped
            }),
            EngineSlot::None | EngineSlot::Ended(_) => None,
        };
        if let Some(error) = blocked {
            return Err(error);
        }
        // A new engine replaces any stale send job and bumps the generation in
        // the same critical section that takes ownership.
        self.clear_send_job();
        self.engine_seq.fetch_add(1, Ordering::AcqRel);

        let cancel = Cancellation::default();
        let engine = if tokio::runtime::Handle::try_current().is_ok() {
            Engine::start(cancel, dispatch)
        } else {
            let mut runtime = self
                .runtime
                .lock()
                .map_err(|_| CoreError::Engine("the runtime lock was poisoned".into()))?;
            if runtime.is_none() {
                *runtime = Some(
                    tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .thread_name("tunlion-core-engine")
                        .build()
                        .map_err(|error| CoreError::Engine(error.to_string()))?,
                );
            }
            let runtime = runtime.as_ref().expect("runtime inserted above");
            // `enter` sets this runtime as the ambient context for the spawn
            // inside `Engine::start`; the guard is released at the end of the
            // branch. This is the runtime's own thread, so spawning here is
            // what makes the task instance-owned rather than global.
            let _entered = runtime.enter();
            Engine::start(cancel, dispatch)
        };
        *slot = EngineSlot::Running(engine);
        Ok(())
    }

    /// Start one engine on this Core's own runtime and return its handle,
    /// task and readiness watch. The caller records the slot.
    fn spawn_engine<F, Fut>(
        &self,
        dispatch: F,
    ) -> Result<
        (
            tokio::runtime::Handle,
            EngineTask,
            filament_peerloop::driver::ReadyWatch,
        ),
        CoreError,
    >
    where
        F: FnOnce(Cancellation, Readiness) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| CoreError::Engine("the runtime lock was poisoned".into()))?;
        if runtime.is_none() {
            *runtime = Some(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("tunlion-core-engine")
                    .build()
                    .map_err(|error| CoreError::Engine(error.to_string()))?,
            );
        }
        let runtime = runtime.as_ref().expect("runtime inserted above");
        let handle = runtime.handle().clone();
        let _entered = runtime.enter();
        let cancel = Cancellation::default();
        let engine = Engine::start(cancel, dispatch);
        let watch = engine.ready_watch();
        Ok((handle, engine, watch))
    }

    fn release_lease(&self) {
        if let Ok(mut lease) = self.lease.lock() {
            *lease = None;
        }
    }

    fn clear_send_job(&self) {
        if let Ok(mut job) = self.send_job.lock() {
            *job = None;
        }
    }

    /// Publish the completion half of a code send, atomically with the engine
    /// generation that owns it.
    ///
    /// The engine lock is held across the generation check and the store, so a
    /// stop or a successor start cannot interleave between them and leave a
    /// stale job that shadows the successor's job. The slot must still own a
    /// live task; an `Ended`/`None` slot means the invocation this generation
    /// named has already been settled.
    fn publish_send_job(
        &self,
        generation: u64,
        rx: std::sync::mpsc::Receiver<SendEvent>,
    ) -> Result<(), CoreError> {
        let slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        if self.engine_generation() != generation
            || !matches!(
                &*slot,
                EngineSlot::Starting(_) | EngineSlot::Running(_) | EngineSlot::Unstopped(_)
            )
        {
            return Err(CoreError::Cancelled);
        }
        let mut job = self
            .send_job
            .lock()
            .map_err(|_| CoreError::Engine("the send job lock was poisoned".into()))?;
        *job = Some(SendJob {
            rx,
            engine_seq: generation,
        });
        Ok(())
    }

    /// Clear the send job only when it belongs to `generation`. A settle for a
    /// superseded engine must not erase the job a successor has just stored.
    fn clear_send_job_if(&self, generation: u64) {
        if let Ok(mut job) = self.send_job.lock() {
            if job.as_ref().is_some_and(|job| job.engine_seq == generation) {
                *job = None;
            }
        }
    }

    fn engine_generation(&self) -> u64 {
        self.engine_seq.load(Ordering::Acquire)
    }

    /// The synchronous form FFI uses. It runs `stop_within` on a fresh OS
    /// thread so no Tokio runtime is created or entered across the boundary.
    pub fn stop_blocking(&self) -> Result<(), CoreError> {
        self.stop_blocking_within(Duration::from_secs(5))
    }

    fn stop_blocking_within(&self, bound: Duration) -> Result<(), CoreError> {
        self.stop_blocking_generation(bound, None)
    }

    /// A bounded stop that first verifies, under the engine lock, that
    /// `generation` still owns the slot. `None` is an unconditional stop.
    fn stop_blocking_generation(
        &self,
        bound: Duration,
        generation: Option<u64>,
    ) -> Result<(), CoreError> {
        let handle = self
            .runtime
            .lock()
            .ok()
            .and_then(|runtime| runtime.as_ref().map(|runtime| runtime.handle().clone()));
        let result = match handle {
            Some(handle) => std::thread::scope(|scope| {
                scope
                    .spawn(move || handle.block_on(self.stop_within_generation(bound, generation)))
                    .join()
                    .unwrap_or_else(|_| Err(CoreError::Engine("the stop thread panicked".into())))
            }),
            None => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| CoreError::Engine(error.to_string()))?;
                std::thread::scope(|scope| {
                    scope
                        .spawn(move || {
                            runtime.block_on(self.stop_within_generation(bound, generation))
                        })
                        .join()
                        .unwrap_or_else(|_| {
                            Err(CoreError::Engine("the stop thread panicked".into()))
                        })
                })
            }
        };
        result
    }

    /// Request stop and wait, in this instance, for the dispatch to return.
    ///
    /// The dispatch's own epilogue is what is joined; work it detached is not
    /// proven stopped. A dispatch that ignores the latch is reported as
    /// `CoreError::Stop` once the bound expires, and its task is **retained**
    /// (`status().engine` is `TimedOut`), never reported as stopped and never
    /// replaced while it may still run.
    ///
    /// If the task already finished on its own, this still joins its handle and
    /// records the outcome: `FinishedUnjoined` becomes `Stopped` or `Failed`,
    /// and a natural `Err` / panic is returned instead of being discarded.
    pub async fn stop(&self) -> Result<(), CoreError> {
        self.stop_within(Duration::from_secs(5)).await
    }

    /// The bounded form of [`Core::stop`]. A caller that wants a shorter grace
    /// (a test, or a supervisor with its own deadline) uses this.
    pub async fn stop_within(&self, bound: Duration) -> Result<(), CoreError> {
        self.stop_within_generation(bound, None).await
    }

    /// Stop this invocation, not whatever engine happens to own the slot.
    ///
    /// With `Some(generation)`, the generation check and the slot claim happen
    /// in ONE critical section. A successor start bumps the generation under
    /// that same lock before installing, so a settle that names an old
    /// generation can never claim (and then stop) the successor. A generation
    /// that no longer owns the slot has already been settled by whichever stop
    /// replaced it, so this is a no-op rather than an error.
    async fn stop_within_generation(
        &self,
        bound: Duration,
        generation: Option<u64>,
    ) -> Result<(), CoreError> {
        // Phase 1, under the lock and without awaiting: claim the engine by
        // moving the slot to `Stopping`. `Stopping` both owns the settle and
        // refuses a concurrent start or stop, so no second owner can race the
        // slot while this future awaits the join below.
        let mut claim = {
            let mut slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            if let Some(expected) = generation {
                if self.engine_generation() != expected {
                    // A successor can only acquire the slot after the engine
                    // this generation named was joined (every other slot
                    // state refuses a start), so there is nothing left to
                    // settle. In particular, do not clear the successor's
                    // send job.
                    return Ok(());
                }
            }
            // A stop ends this engine's claim on any send job. A targeted
            // settle removes only the job of the generation it owns, never a
            // successor's.
            match generation {
                Some(expected) => self.clear_send_job_if(expected),
                None => self.clear_send_job(),
            }
            enum Decision {
                Settled,
                Refuse,
                Take,
            }
            let decision = match &*slot {
                EngineSlot::None | EngineSlot::Ended(_) => Decision::Settled,
                EngineSlot::Claimed | EngineSlot::Stopping => Decision::Refuse,
                EngineSlot::Starting(_) | EngineSlot::Running(_) | EngineSlot::Unstopped(_) => {
                    Decision::Take
                }
            };
            match decision {
                Decision::Refuse => return Err(CoreError::EngineStopping),
                // Already settled: the last task terminated, so stop is a no-op.
                Decision::Settled => return Ok(()),
                Decision::Take => {
                    let engine = match std::mem::replace(&mut *slot, EngineSlot::Stopping) {
                        EngineSlot::Starting(engine)
                        | EngineSlot::Running(engine)
                        | EngineSlot::Unstopped(engine) => engine,
                        _ => unreachable!("a live engine was inspected above"),
                    };
                    StopClaim {
                        slot: &self.engine,
                        engine: Some(engine),
                    }
                }
            }
        };

        // Phase 2, no lock held across the await. The engine stays inside
        // `claim`, so a future dropped here (a supervisor timeout) leaves
        // `StopClaim::drop` to return it to the slot as `Unstopped`; it is never
        // detached on the floor.
        let result = claim
            .engine
            .as_mut()
            .expect("the stop claim is armed")
            .stop_within(bound)
            .await;

        // Phase 3, under the lock: record the outcome. Every arm disarms the
        // claim first, so only the timeout arm leaves the task in the slot.
        let mut slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        match result {
            Ok(Ok(())) => {
                let _ = claim.take();
                *slot = EngineSlot::Ended(Ok(()));
                self.release_lease();
                Ok(())
            }
            Ok(Err(message)) => {
                let _ = claim.take();
                *slot = EngineSlot::Ended(Err(message.clone()));
                self.release_lease();
                Err(CoreError::Engine(message))
            }
            Err(StopError::Panicked(error)) => {
                let _ = claim.take();
                let message = format!("the engine dispatch failed: {error}");
                *slot = EngineSlot::Ended(Err(message.clone()));
                self.release_lease();
                Err(CoreError::Engine(message))
            }
            Err(StopError::TimedOut) => {
                let engine = claim.take();
                *slot = EngineSlot::Unstopped(engine);
                Err(CoreError::Stop(
                    "the engine did not stop within the bound; its task is retained".into(),
                ))
            }
        }
    }

    /// Whether this Core may still own a task whose outcome is unreaped.
    ///
    /// True for `Starting`, `Running`, `Stopping`, `FinishedUnjoined` and
    /// `TimedOut`: startup is in progress or a `JoinHandle` exists and has not
    /// been joined. False only once it is `Stopped`, `Failed` or `NotLinked`.
    pub fn is_engine_running(&self) -> Result<bool, CoreError> {
        Ok(matches!(
            self.engine_state()?,
            EngineState::Starting
                | EngineState::Running
                | EngineState::Stopping
                | EngineState::FinishedUnjoined
                | EngineState::TimedOut
        ))
    }

    fn engine_state(&self) -> Result<EngineState, CoreError> {
        let slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        Ok(match &*slot {
            EngineSlot::None => EngineState::NotLinked,
            // A start has claimed the Core but has not installed its task yet.
            // It is a real in-progress start, not an idle Core.
            EngineSlot::Claimed => EngineState::Starting,
            // A finished task is still unjoined: its result (including a
            // natural error or panic) is owned by the handle in the slot.
            // `Stopped`/`Failed` require the join `stop` performs.
            EngineSlot::Starting(engine) if engine.is_finished() => EngineState::FinishedUnjoined,
            EngineSlot::Starting(_) => EngineState::Starting,
            EngineSlot::Running(engine) if engine.is_finished() => EngineState::FinishedUnjoined,
            EngineSlot::Running(_) => EngineState::Running,
            EngineSlot::Stopping => EngineState::Stopping,
            // The same holds after a timed-out stop: finishing on its own does
            // not reap the handle.
            EngineSlot::Unstopped(engine) if engine.is_finished() => EngineState::FinishedUnjoined,
            EngineSlot::Unstopped(_) => EngineState::TimedOut,
            EngineSlot::Ended(Ok(())) => EngineState::Stopped,
            EngineSlot::Ended(Err(_)) => EngineState::Failed,
        })
    }

    fn store(&self) -> DirStore {
        DirStore {
            root: self.dir.clone(),
        }
    }
}

impl Drop for Core {
    /// Fallback shutdown, not a joined stop.
    ///
    /// `stop` / `stop_within` are the only paths that prove the dispatch's
    /// epilogue returned; `Drop` cannot await. It requests cancellation through
    /// the owned `Engine` (dropping the slot first), then takes the instance
    /// runtime and calls `shutdown_background`. `shutdown_background` is
    /// non-blocking and safe even when `Core` is dropped inside another Tokio
    /// async context, where dropping a `Runtime` directly would panic.
    ///
    /// Tasks that have not observed cancellation are abandoned with the
    /// runtime; callers that need the join must call `stop` before dropping.
    fn drop(&mut self) {
        // Drop the engine slot first so its `Engine::drop` sets the
        // cancellation latch before the runtime goes away. A poisoned lock
        // still yields the slot: Drop must not panic.
        let slot = match self.engine.get_mut() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(std::mem::replace(slot, EngineSlot::None));
        if let Ok(lease) = self.lease.get_mut() {
            drop(lease.take());
        }

        let runtime = match self.runtime.get_mut() {
            Ok(runtime) => runtime.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(runtime) = runtime {
            runtime.shutdown_background();
        }
    }
}

impl UncommittedIdentity {
    pub fn phrase(&self) -> String {
        self.pending.mnemonic().to_string()
    }

    pub fn fingerprint(&self) -> String {
        self.pending.fingerprint()
    }

    /// Whether `phrase` is the same 12 words this identity minted. Word order
    /// and a single space between words are what matter. Used to answer a
    /// mistyped confirmation WITHOUT consuming the phrase, so the caller may
    /// ask again. `commit_identity` still consumes on success.
    pub fn matches(&self, phrase: &str) -> bool {
        normalize_phrase(phrase) == normalize_phrase(&self.phrase())
    }
}

fn normalize_phrase(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn io_err(err: io::Error) -> CoreError {
    CoreError::Io(err.to_string())
}

fn id_err(err: impl ToString) -> CoreError {
    let msg = err.to_string();
    if msg.contains("already exists") {
        CoreError::AlreadyExists
    } else {
        CoreError::Identity(msg)
    }
}

mod ffi;

fn set_private_dir(dir: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir).map_err(io_err)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir, perms).map_err(io_err)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn core() -> Core {
        Core::open(tempfile::tempdir().unwrap().keep()).unwrap()
    }

    fn signaling_stub(listener: std::net::TcpListener) -> std::thread::JoinHandle<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                ws.send(Message::Text("0{}".into())).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(text) if text == "40" => {
                            ws.send(Message::Text("40{}".into())).await.unwrap();
                            ws.send(Message::Text(
                                r#"42["welcome",{"id":"stub","peers":[]}]"#.into(),
                            ))
                            .await
                            .unwrap();
                        }
                        Message::Text(text) if text.starts_with("41") => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => {}
                    }
                }
            });
        })
    }

    /// The sender obtains an auto-room over HTTP before opening Socket.IO.
    /// Accept that preflight as well as a direct WebSocket from receive/start.
    /// Otherwise the fixture mistakes GET /api/room for an upgrade request and
    /// fails before the lifecycle path under test has even started.
    async fn accept_stub_websocket(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut prefix = [0u8; 128];
            let count = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let count = socket.peek(&mut prefix).await.unwrap();
                    assert!(count != 0, "fixture request closed before its headers");
                    if count >= b"GET /api/room ".len() {
                        break count;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
                .await
                .expect("fixture HTTP request deadline");
            if !prefix[..count].starts_with(b"GET /api/room ") {
                return socket;
            }
            let mut header = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), async {
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192, "fixture request headers too large");
                    header.push(socket.read_u8().await.unwrap());
                }
                let body = r#"{"room":"core-send-fixture"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            })
            .await
            .expect("fixture room preflight deadline");
        }
    }

    fn gated_signaling_stub(
        listener: std::net::TcpListener,
        gate: std::sync::mpsc::Receiver<()>,
    ) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<()>) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let socket = accept_stub_websocket(&listener).await;
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let _ = ws.send(Message::Text("0{}".into())).await;
                // Signal only after the WebSocket handshake succeeded: a test
                // that stops the receive cannot tear down the handshake and
                // turn the stub's own unwrap into the failure under test.
                let _ = accepted_tx.send(());
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(text) if text == "40" => {
                            // Hold the welcome until the test has observed the
                            // Starting state. Readiness cannot publish before
                            // this returns, so the state is deterministic.
                            if gate.recv_timeout(Duration::from_secs(10)).is_err() {
                                break;
                            }
                            let _ = ws.send(Message::Text("40{}".into())).await;
                            let _ = ws
                                .send(Message::Text(
                                    r#"42["welcome",{"id":"stub","peers":[]}]"#.into(),
                                ))
                                .await;
                        }
                        Message::Text(text) if text.starts_with("41") => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => {}
                    }
                }
            });
        });
        (handle, accepted_rx)
    }

    /// A signaling stub that accepts the receive, sends the socket.io welcome,
    /// and reports every client event it sees. Used to prove a real dispatch ran
    /// (the code claim) without inventing a sender.
    fn claiming_signaling_stub(
        listener: std::net::TcpListener,
    ) -> (
        std::thread::JoinHandle<()>,
        std::sync::mpsc::Receiver<String>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let _ = ws.send(Message::Text("0{}".into())).await;
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(text) if text == "40" => {
                            let _ = ws.send(Message::Text("40{}".into())).await;
                            let _ = ws
                                .send(Message::Text(
                                    r#"42["welcome",{"id":"stub","peers":[]}]"#.into(),
                                ))
                                .await;
                        }
                        Message::Text(text) if text.starts_with("42") => {
                            let _ = events_tx.send(text.to_string());
                        }
                        Message::Text(text) if text.starts_with("41") => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => {}
                    }
                }
            });
        });
        (handle, events_rx)
    }

    /// A signaling stub that answers a real `pair-create` with `pair-ok` and
    /// then keeps the socket open, so `create_code` can return a claimable code.
    fn code_alloc_stub(listener: std::net::TcpListener) -> std::thread::JoinHandle<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let socket = accept_stub_websocket(&listener).await;
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let _ = ws.send(Message::Text("0{}".into())).await;
                while let Some(Ok(message)) = tokio::time::timeout(
                    Duration::from_secs(10),
                    ws.next(),
                )
                .await
                .expect("code allocation fixture: client did not send a frame or close within 10s")
                {
                    match message {
                        Message::Text(text) if text == "40" => {
                            let _ = ws.send(Message::Text("40{}".into())).await;
                            let _ = ws
                                .send(Message::Text(
                                    r#"42["welcome",{"id":"stub","peers":[]}]"#.into(),
                                ))
                                .await;
                        }
                        Message::Text(text)
                            if text.starts_with("42")
                                && text.contains("pair-create") =>
                        {
                            let nameplate = text
                                .split("\"nameplate\":\"")
                                .nth(1)
                                .and_then(|rest| rest.split('\"').next())
                                .unwrap_or("3141");
                            let reply = format!(
                                r#"42["pair-ok",{{"nameplate":"{nameplate}","ttl":600,"v":2}}]"#
                            );
                            let _ = ws.send(Message::Text(reply.into())).await;
                        }
                        Message::Text(text) if text.starts_with("41") => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => {}
                    }
                }
            });
        })
    }

    /// A Core with a committed identity, ready for the engine/receive paths.
    fn enrolled_core(dir: &std::path::Path) -> Core {
        let core = Core::open(dir).unwrap();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        core
    }

    fn configured_for(core: &Core, listener: &std::net::TcpListener) {
        let addr = listener.local_addr().unwrap();
        std::fs::write(
            core.config_dir().join("config"),
            format!("server http://{addr}\n"),
        )
        .unwrap();
    }

    #[test]
    fn core_start_reports_starting_until_the_ready_edge_then_running() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(Core::open(dir.path()).unwrap());
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(dir.path().join("config"), format!("server http://{addr}\n")).unwrap();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (server, accepted) = gated_signaling_stub(listener, gate_rx);
        let start_core = Arc::clone(&core);
        let start = std::thread::spawn(move || start_core.start());
        accepted
            .recv_timeout(Duration::from_secs(5))
            .expect("the engine reached the signaling stub");

        let mut observed = false;
        for _ in 0..10_000 {
            match core.status().unwrap().engine {
                EngineState::Starting => {
                    observed = true;
                    break;
                }
                EngineState::Running => break,
                EngineState::Failed | EngineState::Stopped => break,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert!(
            observed,
            "start must publish Starting while the readiness edge is pending"
        );
        assert_eq!(core.start(), Err(CoreError::EngineAlreadyRunning));
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineAlreadyRunning)
        );
        let _ = gate_tx.send(());
        start.join().unwrap().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        server.join().unwrap();
    }

    #[test]
    fn a_stop_during_readiness_joins_and_releases_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(Core::open(dir.path()).unwrap());
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(
            core.config_dir().join("config"),
            format!("server http://{addr}\n"),
        )
        .unwrap();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (server, accepted) = gated_signaling_stub(listener, gate_rx);
        let start_core = Arc::clone(&core);
        let start = std::thread::spawn(move || start_core.start());
        accepted
            .recv_timeout(Duration::from_secs(5))
            .expect("the engine reached the signaling stub");
        assert_eq!(core.status().unwrap().engine, EngineState::Starting);
        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        // Release the harness even though the engine is already joined.
        let _ = gate_tx.send(());
        assert!(start.join().unwrap().is_err());
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "the joined stop must release the lease exactly once"
        );
        server.join().unwrap();
    }

    #[test]
    fn readiness_and_stop_timeout_retain_the_lease_and_refuse_restart() {
        let core = core();
        let mut claim = StartClaim::acquire(&core).unwrap();
        let lease = DeviceStore::open(core.config_dir())
            .try_acquire_engine_lease()
            .unwrap()
            .expect("the test owns the root");
        let hold = Arc::new(tokio::sync::Notify::new());
        let dispatch_hold = Arc::clone(&hold);
        let (handle, engine, watch) = core
            .spawn_engine(move |_stop, _readiness| async move {
                // Ignore cancellation and never publish. Both bounds expire.
                dispatch_hold.notified().await;
                Ok::<(), String>(())
            })
            .unwrap();
        claim.install(engine).unwrap();
        let error = core
            .finish_start_for_test(
                handle,
                watch,
                lease,
                Duration::from_millis(20),
                Duration::from_millis(20),
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::Stop(_)));
        assert_eq!(core.status().unwrap().engine, EngineState::TimedOut);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_none(),
            "a retained task must retain the root lease"
        );
        assert_eq!(core.start(), Err(CoreError::EngineNotStopped));

        hold.notify_one();
        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(probe.try_acquire_engine_lease().unwrap().is_some());
    }

    #[test]
    fn concurrent_publication_and_stop_never_leaves_a_stale_lease() {
        let core = Arc::new(core());
        let mut claim = StartClaim::acquire(&core).unwrap();
        let lease = DeviceStore::open(core.config_dir())
            .try_acquire_engine_lease()
            .unwrap()
            .expect("the test owns the root");
        let (handle, engine, _watch) = core
            .spawn_engine(|stop, readiness| async move {
                readiness.publish(|| {});
                stop.run(std::future::pending::<()>()).await;
                Ok::<(), String>(())
            })
            .unwrap();
        claim.install(engine).unwrap();

        let gate = Arc::new(std::sync::Barrier::new(3));
        let publish_core = Arc::clone(&core);
        let publish_handle = handle.clone();
        let publish_gate = Arc::clone(&gate);
        let publish = std::thread::spawn(move || {
            publish_gate.wait();
            publish_core.publish_started(&publish_handle, lease)
        });
        let stop_core = Arc::clone(&core);
        let stop_gate = Arc::clone(&gate);
        let stop = std::thread::spawn(move || {
            stop_gate.wait();
            stop_core.stop_blocking()
        });
        gate.wait();
        let _ = publish.join().unwrap();
        stop.join().unwrap().unwrap();

        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "the race must release the lease exactly once"
        );
    }

    #[test]
    fn a_second_core_on_the_same_root_is_refused_by_the_engine_lease() {
        let dir = tempfile::tempdir().unwrap();
        let first = Core::open(dir.path()).unwrap();
        let pending = first.begin_identity().unwrap();
        let phrase = pending.phrase();
        first.commit_identity(pending, &phrase).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(dir.path().join("config"), format!("server http://{addr}\n")).unwrap();
        let server = signaling_stub(listener);
        first.start().unwrap();
        assert_eq!(first.status().unwrap().engine, EngineState::Running);

        let second = Core::open(dir.path()).unwrap();
        assert_eq!(second.start(), Err(CoreError::EngineLease));
        assert_eq!(second.status().unwrap().engine, EngineState::NotLinked);

        first.stop_blocking().unwrap();
        assert_eq!(first.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(dir.path());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a joined stop must release the same-root lease"
        );
        server.join().unwrap();
    }

    #[test]
    fn core_start_runs_the_real_dispatch_and_stop_joins_it() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(dir.path()).unwrap();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(dir.path().join("config"), format!("server http://{addr}\n")).unwrap();
        let server = signaling_stub(listener);
        core.start().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(dir.path());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a joined stop must not leave a stale lease"
        );
        server.join().unwrap();
    }

    #[test]
    fn one_shot_arguments_are_the_receive_posture() {
        let args = OneShotArgs::new(
            "brave-otter-ruby-3141".to_string(),
            PathBuf::from("/tmp/received"),
            true,
            Some(9),
        );
        assert_eq!(args.code, "brave-otter-ruby-3141");
        assert_eq!(args.dir, PathBuf::from("/tmp/received"));
        assert!(args.yes);
        assert_eq!(args.timeout, Some(9));
        assert!(!args.daemon, "a one-shot receive is never a daemon");
        assert!(
            !args.keep_open,
            "a one-shot receive ends after the transfer"
        );
        assert_eq!(args.output, None, "no stdout sink is part of this API");
    }

    #[test]
    fn a_claim_code_is_normalized_and_requires_words_and_a_numeric_nameplate() {
        assert_eq!(
            parse_claim_code("  Brave Otter Ruby 3141 ").unwrap(),
            "brave-otter-ruby-3141"
        );
        assert_eq!(
            parse_claim_code("brave-otter-3141").unwrap(),
            "brave-otter-3141"
        );
        for malformed in [
            "",
            "brave-otter",
            "3141",
            "brave-otter-ruby-12",
            "brave-otter-ruby-123456",
            "brave-otter-ruby-1234x",
            "-3141",
        ] {
            assert!(
                matches!(parse_claim_code(malformed), Err(CoreError::Usage(_))),
                "{malformed:?} must be refused as malformed"
            );
        }
    }

    #[test]
    fn receive_code_refuses_a_malformed_code_before_engine_or_lease_work() {
        let core = core();
        let dir = core.config_dir().join("received");
        for malformed in ["brave-otter", "3141", "brave-otter-ruby-12"] {
            assert!(matches!(
                core.receive_code(malformed.to_string(), dir.clone(), true, Some(1)),
                Err(CoreError::Usage(_))
            ));
        }
        assert_eq!(
            core.status().unwrap().engine,
            EngineState::NotLinked,
            "a malformed code must not install an engine"
        );
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a malformed code must not take the root lease"
        );
    }

    #[test]
    fn receive_code_refuses_while_an_engine_is_already_running() {
        let core = core();
        core.start_with_dispatch(|stop, _readiness| async move {
            stop.run(std::future::pending::<()>()).await;
            Ok::<(), String>(())
        })
        .unwrap();
        assert_eq!(
            core.receive_code(
                "brave-otter-ruby-3141".to_string(),
                core.config_dir().join("received"),
                true,
                Some(1),
            ),
            Err(CoreError::EngineAlreadyRunning)
        );
        core.stop_blocking().unwrap();
    }

    #[test]
    fn receive_code_runs_the_real_one_shot_and_releases_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let (server, events) = claiming_signaling_stub(listener);

        let error = core
            .receive_code(
                "brave-otter-ruby-3141".to_string(),
                dir.path().join("received"),
                true,
                Some(1),
            )
            .unwrap_err();
        assert!(
            matches!(error, CoreError::Unreachable(ref message) if message.contains("nothing arrived within 1s")),
            "a deadline with nothing received must be the typed unreachable error, got {error:?}"
        );

        // The dispatch really connected and claimed the numeric nameplate; the
        // spoken words never crossed the signaling socket.
        let claim = events
            .recv_timeout(Duration::from_secs(5))
            .expect("the receive claimed the code nameplate");
        assert!(claim.contains("pair-claim"), "{claim}");
        assert!(claim.contains("3141"), "{claim}");
        assert!(!claim.contains("brave-otter-ruby"), "{claim}");

        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a completed one-shot receive must release the root lease"
        );
        server.join().unwrap();
    }

    #[test]
    fn stop_cancels_a_receive_and_returns_cancelled_not_ok() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(enrolled_core(dir.path()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (server, accepted) = gated_signaling_stub(listener, gate_rx);

        let receive_core = Arc::clone(&core);
        let received = std::thread::spawn(move || {
            receive_core.receive_code(
                "brave-otter-ruby-3141".to_string(),
                dir.path().join("received"),
                true,
                None,
            )
        });
        accepted
            .recv_timeout(Duration::from_secs(5))
            .expect("the receive reached the signaling stub");

        core.stop_blocking().unwrap();
        assert_eq!(received.join().unwrap(), Err(CoreError::Cancelled));
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a cancelled receive must release the root lease"
        );
        let _ = gate_tx.send(());
        server.join().unwrap();
    }

    #[test]
    fn summary_construction_keeps_every_stored_and_refused_file() {
        use filament_peerloop::recv::report::RefusalClass;

        let report = RecvReport::new();
        report.note_stored("a.txt", 5, Some("ab"), "a (1).txt");
        report.note_refused(
            "p.bin",
            3_000_000,
            "no_space",
            "receiver is out of disk space",
            RefusalClass::LocalResource,
        );
        let summary = summarize_receive(&report);
        assert_eq!(
            summary.stored,
            vec![StoredFile {
                name: "a.txt".into(),
                stored_name: "a (1).txt".into(),
                bytes: 5,
                sha256: Some("ab".into()),
            }]
        );
        assert_eq!(
            summary.refused,
            vec![RefusedFile {
                name: "p.bin".into(),
                reason: "no_space".into(),
                message: "receiver is out of disk space".into(),
            }]
        );
        assert_eq!(summary.bytes, 5);
    }

    #[test]
    fn create_code_allocates_a_real_code_and_stop_releases_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let server = code_alloc_stub(listener);

        let created = core
            .create_code(vec![payload.display().to_string()], Some(30))
            .unwrap();
        assert!(created.code.contains('-'), "{}", created.code);
        assert!(created.expires_in_secs > 0);
        assert_eq!(core.status().unwrap().engine, EngineState::Running);

        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a stopped code send must release the root lease"
        );
        server.join().unwrap();
    }

    #[test]
    fn create_code_bad_local_path_is_usage_and_releases_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        let missing = dir.path().join("does-not-exist.bin");
        let error = core
            .create_code(vec![missing.display().to_string()], Some(5))
            .unwrap_err();
        assert!(
            matches!(error, CoreError::Usage(_)),
            "a bad local path must be Usage, got {error:?}"
        );
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "the failed allocation must release the root lease"
        );
    }

    #[test]
    fn create_code_unreachable_server_is_a_typed_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        std::fs::write(
            core.config_dir().join("config"),
            "server http://127.0.0.1:1
",
        )
        .unwrap();
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let error = core
            .create_code(vec![payload.display().to_string()], Some(3))
            .unwrap_err();
        assert!(
            matches!(error, CoreError::Unreachable(_) | CoreError::Refused(_)),
            "an unreachable server must be Unreachable/Refused, got {error:?}"
        );
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "the failed allocation must release the root lease"
        );
    }

    #[test]
    fn stop_during_code_allocation_returns_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(enrolled_core(dir.path()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (server, accepted) = gated_signaling_stub(listener, gate_rx);
        let receive_core = Arc::clone(&core);
        let created = std::thread::spawn(move || {
            receive_core.create_code(vec![payload.display().to_string()], Some(30))
        });
        accepted
            .recv_timeout(Duration::from_secs(5))
            .expect("the sender reached the signaling stub");
        core.stop_blocking().unwrap();
        assert!(
            matches!(created.join().unwrap(), Err(CoreError::Cancelled)),
            "a stop during allocation must be Cancelled"
        );
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a cancelled allocation must release the root lease"
        );
        let _ = gate_tx.send(());
        server.join().unwrap();
    }

    #[test]
    fn stop_clears_the_send_job_and_wait_send_never_stops_the_next_engine() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let server = code_alloc_stub(listener);
        core.create_code(vec![payload.display().to_string()], Some(30))
            .unwrap();
        core.stop_blocking().unwrap();

        // A fresh engine owns the slot. The stale send job was cleared by stop,
        // so wait_send must not consume it and stop this new engine.
        core.start_with_dispatch(|stop, _readiness| async move {
            stop.run(std::future::pending::<()>()).await;
            Ok::<(), String>(())
        })
        .unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        assert!(matches!(core.wait_send(), Err(CoreError::Engine(_))));
        assert_eq!(
            core.status().unwrap().engine,
            EngineState::Running,
            "wait_send stopped an engine it did not own"
        );
        core.stop_blocking().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn a_second_wait_send_is_refused_and_does_not_stop_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(enrolled_core(dir.path()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configured_for(&core, &listener);
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let server = code_alloc_stub(listener);
        core.create_code(vec![payload.display().to_string()], Some(30))
            .unwrap();

        let first_core = Arc::clone(&core);
        let first = std::thread::spawn(move || first_core.wait_send());
        for _ in 0..2000 {
            if core.send_job.lock().unwrap().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            matches!(core.wait_send(), Err(CoreError::Engine(_))),
            "a second wait_send must not consume or stop the first job"
        );
        core.stop_blocking().unwrap();
        assert!(matches!(
            first.join().unwrap(),
            Err(CoreError::Cancelled) | Err(CoreError::Engine(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn a_stale_wait_send_never_stops_the_engine_that_replaced_it() {
        let core = Arc::new(core());
        // Engine A owns the slot and a send job tagged with A's generation.
        let mut claim = StartClaim::acquire(&core).unwrap();
        let generation = claim.generation();
        let (_handle, engine, _watch) = core
            .spawn_engine(|stop, _readiness| async move {
                stop.run(std::future::pending::<()>()).await;
                Ok::<(), String>(())
            })
            .unwrap();
        claim.install(engine).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        *core.send_job.lock().unwrap() = Some(SendJob {
            rx: done_rx,
            engine_seq: generation,
        });

        // wait_send takes the job and blocks on its result.
        let waiting_core = Arc::clone(&core);
        let waiting = std::thread::spawn(move || waiting_core.wait_send());
        for _ in 0..2_000 {
            if core.send_job.lock().unwrap().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(core.send_job.lock().unwrap().is_none(), "job taken");

        // A stop joins A, then a successor B takes the slot. The old wait is
        // still blocked on A's channel until it delivers its final event.
        core.stop_blocking().unwrap();
        core.start_with_dispatch(|stop, _readiness| async move {
            stop.run(std::future::pending::<()>()).await;
            Ok::<(), String>(())
        })
        .unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);

        // A late Code event from A must not publish a stale job over B: the
        // publish checks the generation under the same engine lock a start
        // uses. A job left here would shadow B's job for wait_send.
        let (_old_tx, old_rx) = std::sync::mpsc::channel();
        assert!(matches!(
            core.publish_send_job(generation, old_rx),
            Err(CoreError::Cancelled)
        ));
        assert!(
            core.send_job.lock().unwrap().is_none(),
            "a superseded generation published a send job"
        );

        // A's result arrives only now. The settle names A's generation, so it
        // must not join B (the exact check-then-stop race in wait_send).
        done_tx
            .send(SendEvent::Done(Err(CoreError::Cancelled)))
            .unwrap();
        assert!(matches!(waiting.join().unwrap(), Err(CoreError::Cancelled)));
        assert_eq!(
            core.status().unwrap().engine,
            EngineState::Running,
            "a stale wait_send stopped the successor engine"
        );
        assert!(core.is_engine_running().unwrap());

        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[test]
    fn wait_send_without_create_is_refused() {
        let core = core();
        assert!(matches!(core.wait_send(), Err(CoreError::Engine(_))));
        assert!(matches!(core.wait_send(), Err(CoreError::Engine(_))));
    }

    #[test]
    fn send_to_device_unknown_is_usage_and_releases_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let core = enrolled_core(dir.path());
        let payload = dir.path().join("payload.bin");
        std::fs::write(&payload, b"payload").unwrap();
        let error = core
            .send_to_device(
                vec![payload.display().to_string()],
                "no-such-device".to_string(),
                Some(3),
            )
            .unwrap_err();
        assert!(
            matches!(error, CoreError::Usage(_)),
            "an unknown petname must be Usage, got {error:?}"
        );
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "the failed send must release the root lease"
        );
    }

    #[test]
    fn begin_writes_nothing_until_the_phrase_is_confirmed() {
        let core = core();
        let pending = core.begin_identity().unwrap();
        assert!(!core.config_dir().join("identity.ed25519").exists());
        assert_eq!(
            core.commit_identity(pending, "not the phrase"),
            Err(CoreError::PhraseMismatch)
        );
        assert!(!core.config_dir().join("identity.ed25519").exists());

        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        let fingerprint = pending.fingerprint();
        let spaced = phrase.split_whitespace().collect::<Vec<_>>().join("  ");
        assert_eq!(core.commit_identity(pending, &spaced).unwrap(), fingerprint);
        assert_eq!(
            core.fingerprint().unwrap().as_deref(),
            Some(fingerprint.as_str())
        );
        match core.begin_identity() {
            Err(CoreError::AlreadyExists) => {}
            Ok(_) => panic!("begin_identity minted a second identity"),
            Err(other) => panic!("begin_identity failed with {other:?}, want AlreadyExists"),
        }
    }

    #[test]
    fn status_reports_a_missing_identity_and_an_unlinked_engine() {
        let core = core();
        let status = core.status().unwrap();
        assert_eq!(status.fingerprint, None);
        assert_eq!(status.engine, EngineState::NotLinked);
        assert!(!core.config_dir().join("identity.ed25519").exists());
    }

    /// A dispatch that observes cancellation cooperatively and then parks until
    /// `hold` is released. `cancel_seen`, when set, reports that the latch fired
    /// (which only happens after a stop claimed the slot).
    macro_rules! cooperative_dispatch {
        ($entered:expr, $cancel_seen:expr, $hold:expr) => {
            move |stop: Cancellation, readiness: Readiness| async move {
                readiness.publish(|| {});
                let _ = $entered.send(());
                let _ = stop.run(std::future::pending::<()>()).await;
                if let Some(cancel_seen) = $cancel_seen {
                    let _ = cancel_seen.send(());
                }
                let _ = $hold.await;
                Ok::<(), String>(())
            }
        };
    }

    /// A dispatch that ignores cancellation entirely; only releasing `hold`
    /// ends it. This is the worst case a stop must not mislabel as stopped.
    macro_rules! stubborn_dispatch {
        ($entered:expr, $hold:expr) => {
            move |_stop: Cancellation, readiness: Readiness| async move {
                readiness.publish(|| {});
                let _ = $entered.send(());
                let _ = $hold.await;
                Ok::<(), String>(())
            }
        };
    }

    #[tokio::test]
    async fn core_owns_starts_and_stops_one_dispatch_task() {
        let core = core();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(cooperative_dispatch!(
            entered_tx,
            None::<tokio::sync::oneshot::Sender<()>>,
            hold_rx
        ))
        .unwrap();
        entered_rx.await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineAlreadyRunning)
        );
        // Let the cooperative dispatch finish after cancellation.
        hold_tx.send(()).unwrap();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        assert!(!core.is_engine_running().unwrap());
    }

    #[tokio::test]
    async fn a_start_is_refused_while_a_stop_is_in_flight() {
        let core = Arc::new(core());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(cooperative_dispatch!(entered_tx, Some(cancel_tx), hold_rx))
            .unwrap();
        entered_rx.await.unwrap();

        let stop_core = Arc::clone(&core);
        let stop_task = tokio::spawn(async move { stop_core.stop().await });
        // Cancellation is only requested after `stop` claimed the slot as
        // `Stopping`, so observing it proves the slot is claimed.
        cancel_rx.await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopping);
        // No concurrent start may install a second engine...
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineStopping)
        );
        // ...and no concurrent stop may claim success while the task lives.
        assert_eq!(core.stop().await, Err(CoreError::EngineStopping));

        hold_tx.send(()).unwrap();
        assert_eq!(stop_task.await.unwrap(), Ok(()));
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);

        // The old handle was not lost: a fresh start succeeds and owns the slot.
        let (entered2_tx, entered2_rx) = tokio::sync::oneshot::channel();
        let (hold2_tx, hold2_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(cooperative_dispatch!(
            entered2_tx,
            None::<tokio::sync::oneshot::Sender<()>>,
            hold2_rx
        ))
        .unwrap();
        entered2_rx.await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        hold2_tx.send(()).unwrap();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[tokio::test]
    async fn a_stop_timeout_retains_the_task_and_refuses_restart() {
        let core = core();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel();
        // Ignores cancellation entirely; only `hold` ends it.
        core.start_with_dispatch(stubborn_dispatch!(entered_tx, hold_rx))
            .unwrap();
        entered_rx.await.unwrap();

        assert!(matches!(
            core.stop_within(Duration::from_millis(20)).await,
            Err(CoreError::Stop(_))
        ));
        assert_eq!(core.status().unwrap().engine, EngineState::TimedOut);
        assert!(core.is_engine_running().unwrap());
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineNotStopped)
        );

        // The retained task can still be joined; only then is a restart allowed.
        hold_tx.send(()).unwrap();
        core.stop_within(Duration::from_secs(1)).await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        core.start_with_dispatch(|stop, _| async move {
            stop.run(std::future::pending::<()>()).await;
            Ok(())
        })
        .unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[tokio::test]
    async fn dropping_a_stop_future_retains_the_task() {
        let core = core();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(stubborn_dispatch!(entered_tx, hold_rx))
            .unwrap();
        entered_rx.await.unwrap();

        // A supervisor gives up waiting: the stop future is dropped mid-await.
        assert!(tokio::time::timeout(Duration::from_millis(20), core.stop())
            .await
            .is_err());
        // The task was retained, not lost: still not `Stopped`, restart refused.
        assert_eq!(core.status().unwrap().engine, EngineState::TimedOut);
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineNotStopped)
        );

        hold_tx.send(()).unwrap();
        core.stop_within(Duration::from_secs(1)).await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[tokio::test]
    async fn a_dispatch_error_is_recorded_as_failed() {
        let core = core();
        core.start_with_dispatch(|_stop, readiness| async move {
            readiness.publish(|| {});
            Err("boom".to_string())
        })
        .unwrap();
        assert_eq!(core.stop().await, Err(CoreError::Engine("boom".into())));
        assert_eq!(core.status().unwrap().engine, EngineState::Failed);
        // The failed task terminated, so a restart is safe.
        core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) })
            .unwrap();
    }

    #[tokio::test]
    async fn a_natural_error_is_kept_until_joined_and_not_reported_stopped() {
        let core = core();
        let (returned_tx, returned_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(move |_stop, readiness| async move {
            readiness.publish(|| {});
            let _ = returned_tx.send(());
            Err("natural-boom".to_string())
        })
        .unwrap();
        returned_rx.await.unwrap();
        // Let the runtime mark the task finished; no sleeps.
        for _ in 0..1_000 {
            if core.status().unwrap().engine == EngineState::FinishedUnjoined {
                break;
            }
            tokio::task::yield_now().await;
        }

        // It finished, but its Err is still owned by the unjoined handle.
        assert_eq!(core.status().unwrap().engine, EngineState::FinishedUnjoined);
        assert!(core.is_engine_running().unwrap());
        // Replacing the slot here would drop the handle and lose the error.
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineNotJoined)
        );

        // Explicit stop is what reaps and reports the outcome...
        assert_eq!(
            core.stop().await,
            Err(CoreError::Engine("natural-boom".into()))
        );
        assert_eq!(core.status().unwrap().engine, EngineState::Failed);
        // ...and only then is a restart allowed.
        core.start_with_dispatch(|_stop, readiness| async move {
            readiness.publish(|| {});
            Ok(())
        })
        .unwrap();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[tokio::test]
    async fn a_natural_panic_is_kept_until_joined() {
        let core = core();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(move |_stop, readiness| async move {
            readiness.publish(|| {});
            let _ = entered_tx.send(());
            (move || -> Result<(), String> { panic!("natural engine panic") })()
        })
        .unwrap();
        entered_rx.await.unwrap();
        for _ in 0..1_000 {
            if core.status().unwrap().engine == EngineState::FinishedUnjoined {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(core.status().unwrap().engine, EngineState::FinishedUnjoined);
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineNotJoined)
        );
        match core.stop().await {
            Err(CoreError::Engine(message)) => {
                assert!(
                    message.contains("panicked"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected the panic to be reported, got {other:?}"),
        }
        assert_eq!(core.status().unwrap().engine, EngineState::Failed);
        core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) })
            .unwrap();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    #[test]
    fn core_creates_its_own_runtime_outside_an_ambient_one() {
        let core = core();
        core.start_with_dispatch(|stop, readiness| async move {
            readiness.publish(|| {});
            stop.run(std::future::pending::<()>()).await;
            Ok(())
        })
        .unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(core.stop()).unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
    }

    /// Dropping `Core` inside an async context must not drop a `Runtime`
    /// directly (that panics). This test has no ambient runtime, so
    /// `start_with_dispatch` creates and retains the Core-owned multi-thread
    /// runtime; dropping Core then happens inside another runtime's
    /// `block_on`.
    #[test]
    fn dropping_core_inside_another_runtime_does_not_panic() {
        let core = core();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        core.start_with_dispatch(move |stop, readiness| async move {
            readiness.publish(|| {});
            let _ = entered_tx.send(());
            stop.run(std::future::pending::<()>()).await;
            Ok(())
        })
        .unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the dispatch entered");
        assert!(
            core.runtime.lock().unwrap().is_some(),
            "the test must exercise the Core-owned runtime"
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            // Fallback Drop: cancel, then non-blocking runtime shutdown.
            drop(core);
        });
    }

    #[tokio::test]
    async fn stop_without_a_started_engine_is_a_no_op() {
        let core = core();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn stop_and_other_starts_are_refused_while_startup_is_claimed() {
        let core = core();
        let claim = StartClaim::acquire(&core).unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Starting);
        assert_eq!(core.stop_blocking(), Err(CoreError::EngineStopping));
        assert_eq!(core.start(), Err(CoreError::EngineStopping));
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineStopping)
        );
        drop(claim);
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn a_dispatch_that_finishes_before_publication_is_not_running_or_ok() {
        let core = core();
        let mut claim = StartClaim::acquire(&core).unwrap();
        let lease = DeviceStore::open(core.config_dir())
            .try_acquire_engine_lease()
            .unwrap()
            .expect("the test owns the root");
        let (returned_tx, returned_rx) = std::sync::mpsc::channel();
        let (handle, engine, _watch) = core
            .spawn_engine(move |_stop, readiness| async move {
                readiness.publish(|| {});
                let _ = returned_tx.send(());
                Ok::<(), String>(())
            })
            .unwrap();
        returned_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the dispatch must reach its return");
        // The future has returned; let the runtime record the JoinHandle as
        // finished. This is a bounded scheduler handoff, not a sleep-based
        // synchronisation point.
        for _ in 0..10_000 {
            if engine.is_finished() {
                break;
            }
            std::thread::yield_now();
        }
        assert!(engine.is_finished(), "the test dispatch must finish");
        claim.install(engine).unwrap();
        let error = core.publish_started(&handle, lease).unwrap_err();
        assert!(matches!(error, CoreError::Engine(_)));
        assert!(matches!(
            core.status().unwrap().engine,
            EngineState::Stopped | EngineState::Failed
        ));
        let probe = DeviceStore::open(core.config_dir());
        assert!(
            probe.try_acquire_engine_lease().unwrap().is_some(),
            "a finished dispatch must not retain the lease"
        );
    }

    #[test]
    fn core_daemon_posture_accepts_direct_and_uses_a_fresh_consent_token() {
        let env = core_recv_env(
            "device".into(),
            "uid".into(),
            None,
            7,
            new_consent_token().unwrap(),
        );
        assert!(env.direct_ok, "the Core daemon must accept direct offers");
        assert!(!env.interactive_terminal);
        assert_eq!(env.consent_token.len(), 64);
        assert_ne!(env.consent_token, "core");
        let other = new_consent_token().unwrap();
        assert_ne!(env.consent_token, other);
    }

    #[test]
    fn an_explicitly_empty_server_is_a_config_error_not_a_default() {
        let core = core();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        std::fs::write(core.config_dir().join("config"), "server\n").unwrap();
        match core.start() {
            Err(CoreError::Config(message)) => assert!(message.contains("empty server")),
            other => panic!("expected Config, got {other:?}"),
        }
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn a_missing_server_uses_the_compiled_default_and_unreadable_config_fails() {
        let dir = tempfile::tempdir().unwrap();
        let settings = CoreSettings::load(dir.path()).unwrap();
        assert_eq!(resolve_server(&settings).unwrap(), DEFAULT_SERVER);

        let unreadable = tempfile::tempdir().unwrap();
        std::fs::create_dir(unreadable.path().join("config")).unwrap();
        assert!(CoreSettings::load(unreadable.path()).is_err());
    }

    #[test]
    fn engine_preparation_bootstraps_identity_without_dispatch_or_replacement() {
        let core = core();
        let (_parts, lease) = core.prepare_engine(core.dir.join("inbox")).unwrap();
        let fingerprint = core.fingerprint().unwrap().unwrap();
        drop(lease);
        let (_parts, _lease) = core.prepare_send().unwrap();
        assert_eq!(core.fingerprint().unwrap().as_deref(),Some(fingerprint.as_str()));
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn invalid_config_and_corrupt_identity_fail_without_bootstrap_replacement() {
        let core = core();
        std::fs::write(core.dir.join("config"),"server\n").unwrap();
        assert!(matches!(core.prepare_send(),Err(CoreError::Config(_))));
        assert_eq!(core.fingerprint().unwrap(),None);
        std::fs::write(core.dir.join("config"),"").unwrap();
        std::fs::write(core.dir.join("identity.ed25519"),b"corrupt existing key").unwrap();
        assert!(matches!(core.prepare_send(),Err(CoreError::Identity(_))));
        assert_eq!(std::fs::read(core.dir.join("identity.ed25519")).unwrap(),b"corrupt existing key");
    }

    #[test]
    fn a_second_open_loads_the_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(dir.path()).unwrap();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        let fingerprint = core.commit_identity(pending, &phrase).unwrap();
        let again = Core::open(dir.path()).unwrap();
        assert_eq!(
            again.fingerprint().unwrap().as_deref(),
            Some(fingerprint.as_str())
        );
        assert_eq!(again.status().unwrap().engine, EngineState::NotLinked);
    }
}
