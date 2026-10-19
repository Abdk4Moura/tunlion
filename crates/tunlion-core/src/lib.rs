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
use filament_peerloop::driver::{Cancellation, Engine, Readiness};
use secret_write::SecretFile;

/// Build proof for the Android cdylib job. Not the app API.
#[no_mangle]
pub extern "C" fn tunlion_core_abi_version() -> u32 {
    1
}

/// One dispatch task owned by this Core. The dispatch body is supplied by the
/// embedder; the library owns the runtime, the latch, readiness and the join.
type EngineTask = Engine<Result<(), String>>;

/// The one engine slot a Core owns. `Stopped` is deliberately distinct from
/// `None`: "nothing was ever started" and "the last run returned" are different
/// answers, and a caller that stopped an engine must not read `NotLinked`.
enum EngineSlot {
    None,
    Running(EngineTask),
    Stopped,
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
    /// The last engine dispatch returned (normally or by stop). No child
    /// process exists; this is about the in-process task.
    Stopped,
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
    /// The dispatch returned an error string after it was started.
    #[error("{0}")]
    Engine(String),
    /// The engine did not finish within the stop bound.
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
        if matches!(&*slot, EngineSlot::Running(engine) if !engine.is_finished()) {
            return Err(CoreError::EngineAlreadyRunning);
        }
        // A finished task is retained only so `status` can say Stopped; replace
        // it with the new run.
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
    /// `CoreError::Stop` once the bound expires, not as success.
    pub async fn stop(&self) -> Result<(), CoreError> {
        // Take only a running engine; leave an already-stopped slot as Stopped
        // and never turn "was never started" into anything but NotLinked.
        let taken = {
            let mut slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            match std::mem::replace(&mut *slot, EngineSlot::None) {
                EngineSlot::Running(engine) => Some(engine),
                EngineSlot::Stopped => {
                    *slot = EngineSlot::Stopped;
                    None
                }
                EngineSlot::None => None,
            }
        };
        let Some(engine) = taken else {
            return Ok(());
        };
        let result = engine.stop_within(Duration::from_secs(5)).await;
        {
            let mut slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            *slot = EngineSlot::Stopped;
        }
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(message)) => Err(CoreError::Engine(message)),
            Err(error) => Err(CoreError::Stop(error.to_string())),
        }
    }

    /// Whether this Core currently owns a running dispatch.
    pub fn is_engine_running(&self) -> Result<bool, CoreError> {
        Ok(self.engine_state()? == EngineState::Running)
    }

    fn engine_state(&self) -> Result<EngineState, CoreError> {
        let slot = self
            .engine
            .lock()
            .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
        Ok(match &*slot {
            EngineSlot::None => EngineState::NotLinked,
            EngineSlot::Stopped => EngineState::Stopped,
            EngineSlot::Running(engine) if engine.is_finished() => EngineState::Stopped,
            EngineSlot::Running(_) => EngineState::Running,
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

    #[tokio::test]
    async fn core_owns_starts_and_stops_one_dispatch_task() {
        let core = core();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        core.start_with_dispatch(move |stop, readiness| async move {
            readiness.publish(|| {});
            let _ = entered_tx.send(());
            stop.run(std::future::pending::<()>()).await;
            Ok(())
        })
        .unwrap();
        entered_rx.await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        assert_eq!(
            core.start_with_dispatch(|_, _| async { Ok::<(), String>(()) }),
            Err(CoreError::EngineAlreadyRunning)
        );
        core.stop().await.unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        assert!(!core.is_engine_running().unwrap());
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
