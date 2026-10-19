//! tunlion as a library any process can call.
//!
//! Android is what forced the surface into existence. It is one caller, not the
//! owner. A desktop embedding, a test, or another language binding uses the
//! same types. Slice 1 is identity in an explicit config directory.
//!
//! The engine runtime now lives in `filament_peerloop::driver::Engine`: one
//! cancellation latch, one publish-once readiness edge, one owned dispatch task
//! with `stop`/`wait`. `Core` owns that runtime per instance. What is still not
//! library-callable is the receive **dispatch body** (`cli/src/recv_cmd.rs::
//! recv_run`), whose sectors still read CLI config/devices/mount/session state.
//! `Core::start` therefore stays honest and refuses by name; a Rust embedder
//! that has the real dispatch calls `start_with_dispatch`, the same driver the
//! CLI `up` path runs. See `docs/android-ffi.md`.

uniffi::setup_scaffolding!();

use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use filament_id::{user_key_path, KeyStore, PendingIdentity, UserKey};
use filament_peerloop::driver::{Cancellation, Engine, Readiness, StopError};
use secret_write::SecretFile;

/// Build proof for the Android cdylib job. Not the app API.
#[no_mangle]
pub extern "C" fn tunlion_core_abi_version() -> u32 {
    1
}

/// One dispatch task owned by this Core. The dispatch body is supplied by the
/// embedder; the library owns the runtime, the latch, readiness and the join.
type EngineTask = Engine<Result<(), String>>;

/// The one engine slot a Core owns.
///
/// The states exist to keep two contracts honest under concurrency and under a
/// stop that does not finish:
///
/// - If a retry observes a task that finished on its own, it may join it as
///   `Ended(_)`; if it is still alive under `Running`, it is joined by `stop`.
/// - `Ended(_)` and `None` are the only states a fresh `start_with_dispatch`
///   may replace. `Running`, `Stopping` and `Unstopped` all refuse a new start,
///   because in each of those a prior task may still be running.
enum EngineSlot {
    /// Nothing was ever started.
    None,
    /// The one live engine, owned by this slot.
    Running(EngineTask),
    /// A stop owns the settle. The task was moved into the stop future; no
    /// start or second stop may proceed until that owner records the outcome.
    Stopping,
    /// A bounded stop expired. The engine is retained here; it may still be
    /// running, so a start is refused until joining or observing it finished.
    Unstopped(EngineTask),
    /// The last engine returned. `Err` is its dispatch error, if any. A start
    /// may replace this: the task is known to have terminated.
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

/// A core opened on one config directory. The directory is the app's private
/// files dir on Android. This type does not read `TUNLION_CONFIG_DIR`.
pub struct Core {
    dir: PathBuf,
    /// At most one engine per Core. No process-global engine state.
    engine: Mutex<EngineSlot>,
    /// Created only when the caller is not already inside a Tokio runtime, so
    /// the engine never borrows another instance's runtime.
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

/// An identity that exists only in memory until `Core::commit_identity`.
pub struct UncommittedIdentity {
    pending: PendingIdentity,
}

/// Whether the peer loop is running inside this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EngineState {
    /// No engine is owned by this Core. `Core::start` has no library receive
    /// dispatch to run yet, so it returns `EngineNotLinked`. A Rust embedder
    /// that does have the dispatch uses `start_with_dispatch`.
    NotLinked,
    /// An engine dispatch started through `start_with_dispatch` is running.
    Running,
    /// A stop is in flight; the task may still be running. A start and a second
    /// stop are both refused while this holds.
    Stopping,
    /// The last engine dispatch returned cleanly (naturally or by stop). No
    /// child process exists; this is about the in-process task.
    Stopped,
    /// The last engine dispatch returned an error.
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Identity(String),
    /// The 12 words did not match the phrase this pending identity minted.
    #[error("the recovery phrase did not match")]
    PhraseMismatch,
    /// `identity.ed25519` is already in this config directory.
    #[error("an identity already exists in this config directory")]
    AlreadyExists,
    /// `start` was called and no library receive dispatch is linked yet.
    #[error("the engine is not linked")]
    EngineNotLinked,
    /// An engine dispatch is already running in this Core.
    #[error("an engine is already running in this core")]
    EngineAlreadyRunning,
    /// A stop is already in flight. Starting or stopping again would let two
    /// owners race the same slot, so both are refused.
    #[error("an engine stop is already in progress in this core")]
    EngineStopping,
    /// A previous stop bound expired and its task was retained. It may still be
    /// running, so a new engine is refused until it is joined or observed done.
    #[error("the previous engine has not stopped")]
    EngineNotStopped,
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
            engine: Mutex::new(EngineSlot::None),
            runtime: Mutex::new(None),
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
        pending.pending.commit(&self.store()).map_err(id_err)?;
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

    /// No library receive dispatch is linked yet, so there is nothing the
    /// credential-side Core can start. This never spawns a child process.
    pub fn start(&self) -> Result<(), CoreError> {
        Err(CoreError::EngineNotLinked)
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
        // A new engine may replace only a slot whose prior task is known to have
        // terminated: `None` (nothing started) or `Ended` (it returned). Every
        // other state may still have a live task, so refuse rather than install
        // a second engine or lose a handle.
        let blocked = match &*slot {
            EngineSlot::Stopping => Some(CoreError::EngineStopping),
            EngineSlot::Running(engine) if !engine.is_finished() => {
                Some(CoreError::EngineAlreadyRunning)
            }
            EngineSlot::Unstopped(engine) if !engine.is_finished() => {
                Some(CoreError::EngineNotStopped)
            }
            _ => None,
        };
        if let Some(error) = blocked {
            return Err(error);
        }
        *slot = EngineSlot::None;

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

    /// Request stop and wait, in this instance, for the dispatch to return.
    ///
    /// The dispatch's own epilogue is what is joined; work it detached is not
    /// proven stopped. A dispatch that ignores the latch is reported as
    /// `CoreError::Stop` once the bound expires, and its task is **retained**
    /// (`status().engine` is `TimedOut`), never reported as stopped and never
    /// replaced while it may still run.
    pub async fn stop(&self) -> Result<(), CoreError> {
        self.stop_within(Duration::from_secs(5)).await
    }

    /// The bounded form of [`Core::stop`]. A caller that wants a shorter grace
    /// (a test, or a supervisor with its own deadline) uses this.
    pub async fn stop_within(&self, bound: Duration) -> Result<(), CoreError> {
        // Phase 1, under the lock and without awaiting: claim the engine by
        // moving the slot to `Stopping`. `Stopping` both owns the settle and
        // refuses a concurrent start or stop, so no second owner can race the
        // slot while this future awaits the join below.
        let mut claim = {
            let mut slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            enum Decision {
                Settled,
                Refuse,
                Take,
            }
            let decision = match &*slot {
                EngineSlot::None | EngineSlot::Ended(_) => Decision::Settled,
                EngineSlot::Stopping => Decision::Refuse,
                EngineSlot::Running(_) | EngineSlot::Unstopped(_) => Decision::Take,
            };
            match decision {
                Decision::Refuse => return Err(CoreError::EngineStopping),
                // Already settled: the last task terminated, so stop is a no-op.
                Decision::Settled => return Ok(()),
                Decision::Take => {
                    let engine = match std::mem::replace(&mut *slot, EngineSlot::Stopping) {
                        EngineSlot::Running(engine) | EngineSlot::Unstopped(engine) => engine,
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
                Ok(())
            }
            Ok(Err(message)) => {
                let _ = claim.take();
                *slot = EngineSlot::Ended(Err(message.clone()));
                Err(CoreError::Engine(message))
            }
            Err(StopError::Panicked(error)) => {
                let _ = claim.take();
                let message = format!("the engine dispatch failed: {error}");
                *slot = EngineSlot::Ended(Err(message.clone()));
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

    /// Whether this Core may still own a live dispatch task.
    ///
    /// True for `Running`, `Stopping` and `TimedOut`: in each, a task exists and
    /// has not been confirmed returned. False only once it is `Stopped`,
    /// `Failed` or `NotLinked`.
    pub fn is_engine_running(&self) -> Result<bool, CoreError> {
        Ok(matches!(
            self.engine_state()?,
            EngineState::Running | EngineState::Stopping | EngineState::TimedOut
        ))
    }

    fn engine_state(&self) -> Result<EngineState, CoreError> {
        let slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        Ok(match &*slot {
            EngineSlot::None => EngineState::NotLinked,
            EngineSlot::Running(engine) if engine.is_finished() => EngineState::Stopped,
            EngineSlot::Running(_) => EngineState::Running,
            EngineSlot::Stopping => EngineState::Stopping,
            // An `Unstopped` task that has since finished is a clean stop for
            // status purposes (we cannot recover its Ok/Err without joining, and
            // a join is what `stop` is for); while it is alive it is `TimedOut`.
            EngineSlot::Unstopped(engine) if engine.is_finished() => EngineState::Stopped,
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
        assert_eq!(core.fingerprint().unwrap().as_deref(), Some(fingerprint.as_str()));
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
        assert_eq!(core.start().unwrap_err(), CoreError::EngineNotLinked);
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

    #[tokio::test]
    async fn stop_without_a_started_engine_is_a_no_op() {
        let core = core();
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn start_without_a_dispatch_stays_engine_not_linked() {
        let core = core();
        assert_eq!(core.start().unwrap_err(), CoreError::EngineNotLinked);
        // The credential-side start must not install an engine slot.
        assert_eq!(core.status().unwrap().engine, EngineState::NotLinked);
    }

    #[test]
    fn a_second_open_loads_the_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(dir.path()).unwrap();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        let fingerprint = core.commit_identity(pending, &phrase).unwrap();
        let again = Core::open(dir.path()).unwrap();
        assert_eq!(again.fingerprint().unwrap().as_deref(), Some(fingerprint.as_str()));
        assert_eq!(again.status().unwrap().engine, EngineState::NotLinked);
    }
}
