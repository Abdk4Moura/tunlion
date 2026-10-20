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
//! process adapter around it. `Core::start` still refuses by name because Core
//! does not yet have a host composition for the dispatch's capability ports
//! (`RecvIdentity`, `RecvStore`, `RecvServers`, `RecvDaemon`, `RecvPrompt`).
//! Those interfaces exist and the loop calls them. `RecvStore` and the
//! proof/expose/renew and auth-key enrolment parts of `RecvIdentity` now have
//! host-neutral implementations (`recv::store::DeviceStore`,
//! `recv::identity::IdentityService` and `recv::enrollment::EnrollmentService`,
//! built from an explicit config directory and overlay-key path). Roster/depart
//! and the fleet rendezvous facts now live in `recv::roster`,
//! `recv::membership` and `recv::fleet_rv` with explicit roots/keys/routes. The
//! remaining non-CLI gap is the optional server/daemon sectors (today they
//! forward to `cli/src/daemon_ctl.rs` and the optional PTY/exec/ssh servers). A
//! Rust embedder with that composition calls `start_with_dispatch` today. See
//! `docs/engine-driver.md` and `docs/android-ffi.md`.

mod host;

uniffi::setup_scaffolding!();

use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filament_id::{now_secs, user_key_path, KeyStore, PendingIdentity, UserKey};
use filament_peerloop::driver::{Cancellation, DriverOutcome, Engine, Readiness, StopError};
use filament_peerloop::host::{LogSink, NoLog};
use filament_peerloop::present::NoScreen;
use filament_peerloop::recv::dispatch::{drive, RecvCleanup};
use filament_peerloop::recv::ports::{RecvEnv, RecvPorts};
use filament_peerloop::recv::report::RecvReport;
use filament_peerloop::recv::store::{CoreLease, DeviceStore, OverlayKey};
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
    /// `Core::start` has spawned the real dispatch and is waiting for its
    /// publish-once readiness edge.
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
    /// Retained for API compatibility; `start` now returns a concrete
    /// identity/config/lease/readiness error instead.
    #[error("the engine is not linked")]
    EngineNotLinked,
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

    /// Start the real receive engine for this config directory.
    ///
    /// Validates that an identity and config exist, takes the same-root
    /// `up.lock` election (shared with the CLI daemon), starts `recv::dispatch`
    /// on this Core's runtime and waits for its publish-once readiness edge.
    /// A failure releases the lease and joins the task unless it timed out, in
    /// which case the task is retained and a retry is refused.
    pub fn start(&self) -> Result<(), CoreError> {
        let store = DeviceStore::open(&self.dir);
        if !store.has_identity() {
            return Err(CoreError::Identity(
                "no identity in this config directory; run init or join first".into(),
            ));
        }
        let settings = CoreSettings::load(&self.dir);
        let server = settings
            .get("server")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_SERVER.to_string());
        if server.trim().is_empty() {
            return Err(CoreError::Engine(
                "the config has no signaling server".into(),
            ));
        }
        let lease = store
            .try_acquire_engine_lease()
            .map_err(|e| CoreError::Engine(format!("engine lease: {e}")))?
            .ok_or(CoreError::EngineLease)?;

        {
            let slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            match &*slot {
                EngineSlot::Stopping => return Err(CoreError::EngineStopping),
                EngineSlot::Starting(engine) => {
                    return Err(if engine.is_finished() {
                        CoreError::EngineNotJoined
                    } else {
                        CoreError::EngineAlreadyRunning
                    })
                }
                EngineSlot::Running(engine) => {
                    return Err(if engine.is_finished() {
                        CoreError::EngineNotJoined
                    } else {
                        CoreError::EngineAlreadyRunning
                    })
                }
                EngineSlot::Unstopped(engine) => {
                    return Err(if engine.is_finished() {
                        CoreError::EngineNotJoined
                    } else {
                        CoreError::EngineNotStopped
                    })
                }
                EngineSlot::None | EngineSlot::Ended(_) => {}
            }
        }

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
            display_name.clone(),
            uid.clone(),
        ));
        let ports = RecvPorts::new(
            identity,
            Arc::new(store.clone()),
            Box::new(CoreServers),
            Box::new(CoreDaemon::new(
                self.dir.clone(),
                store.clone(),
                overlay,
                display_name.clone(),
            )),
            Arc::new(CorePrompt),
            Arc::new(NoScreen),
            RecvEnv {
                display_name: display_name.clone(),
                uid: uid.clone(),
                config_name: settings.get("name"),
                consent_token: "core".to_string(),
                pid: std::process::id(),
                ..RecvEnv::default()
            },
        );
        let inbox = self.dir.join("inbox");
        fs::create_dir_all(&inbox).map_err(io_err)?;
        let settings_for_peer = settings.clone();
        let settings_for_membership = settings.clone();
        let transport_context = TransportContext::new(
            Some(self.dir.join("signaling-dns.json")),
            move |key, peer| settings_for_peer.setting(key, peer),
            move |peer| settings_for_membership.membership(peer),
        );
        let engine_dir = inbox;
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
                false,
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
        {
            let mut slot = self
                .engine
                .lock()
                .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
            *slot = EngineSlot::Starting(engine);
        }
        let readiness = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    handle.block_on(async move {
                        let mut watch = watch;
                        watch.wait(Some(Duration::from_secs(30))).await
                    })
                })
                .join()
                .unwrap_or_else(|_| Err(filament_peerloop::driver::ReadyError::NotPublished))
        });
        match readiness {
            Ok(()) => {
                let mut slot = self
                    .engine
                    .lock()
                    .map_err(|_| CoreError::Engine("the engine lock was poisoned".into()))?;
                match std::mem::replace(&mut *slot, EngineSlot::None) {
                    EngineSlot::Starting(engine) => {
                        *slot = EngineSlot::Running(engine);
                        drop(slot);
                        let mut held = self
                            .lease
                            .lock()
                            .map_err(|_| CoreError::Engine("the lease lock was poisoned".into()))?;
                        *held = Some(lease);
                        Ok(())
                    }
                    other => {
                        // A concurrent stop claimed/joined the task while the
                        // readiness edge was being observed. Put its state back
                        // and do not claim a running engine.
                        *slot = other;
                        Err(CoreError::Stop(
                            "the engine stopped while it was starting".into(),
                        ))
                    }
                }
            }
            Err(error) => {
                let _ = self.stop_blocking();
                // A timed-out stop retained the task; keep the root lease so a
                // retry cannot start a second engine over it. A joined stop
                // released it already.
                if self
                    .engine_state()
                    .is_ok_and(|state| state == EngineState::TimedOut)
                {
                    if let Ok(mut held) = self.lease.lock() {
                        *held = Some(lease);
                    }
                }
                Err(CoreError::Engine(format!(
                    "the receive engine did not become ready: {error}"
                )))
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
            EngineSlot::Stopping => Some(CoreError::EngineStopping),
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

    /// The synchronous form FFI uses. It runs `stop_within` on a fresh OS
    /// thread so no Tokio runtime is created or entered across the boundary.
    pub fn stop_blocking(&self) -> Result<(), CoreError> {
        let handle = self
            .runtime
            .lock()
            .ok()
            .and_then(|runtime| runtime.as_ref().map(|runtime| runtime.handle().clone()));
        let result = match handle {
            Some(handle) => std::thread::scope(|scope| {
                scope
                    .spawn(move || handle.block_on(self.stop_within(Duration::from_secs(5))))
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
                        .spawn(move || runtime.block_on(self.stop_within(Duration::from_secs(5))))
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
    /// True for `Running`, `Stopping`, `FinishedUnjoined` and `TimedOut`: in
    /// each, a `JoinHandle` exists and has not been joined. False only once it
    /// is `Stopped`, `Failed` or `NotLinked`.
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

    #[test]
    fn core_start_runs_the_real_dispatch_and_stop_joins_it() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(dir.path()).unwrap();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase();
        core.commit_identity(pending, &phrase).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(
            dir.path().join("config"),
            format!("server http://{addr}\n"),
        )
        .unwrap();
        let server = signaling_stub(listener);
        core.start().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Running);
        core.stop_blocking().unwrap();
        assert_eq!(core.status().unwrap().engine, EngineState::Stopped);
        server.join().unwrap();
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
        assert!(matches!(core.start().unwrap_err(), CoreError::Identity(_)));
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
    fn start_without_identity_is_refused_and_installs_no_engine() {
        let core = core();
        assert!(matches!(core.start().unwrap_err(), CoreError::Identity(_)));
        // A refused start must not install an engine slot or a lease.
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
        assert_eq!(
            again.fingerprint().unwrap().as_deref(),
            Some(fingerprint.as_str())
        );
        assert_eq!(again.status().unwrap().engine, EngineState::NotLinked);
    }
}
