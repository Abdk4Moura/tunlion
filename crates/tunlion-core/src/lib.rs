//! tunlion as a library any process can call.
//!
//! Android is what forced the surface into existence. It is one caller, not the
//! owner. A desktop embedding, a test, or another language binding uses the
//! same types. Slice 1 is identity in an explicit config directory. The peer
//! loop is still in the CLI, so `start` refuses by name. See `docs/android-ffi.md`.

uniffi::setup_scaffolding!();

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use filament_id::{user_key_path, KeyStore, PendingIdentity, UserKey};
use secret_write::SecretFile;

/// Build proof for the Android cdylib job. Not the app API.
#[no_mangle]
pub extern "C" fn tunlion_core_abi_version() -> u32 {
    1
}

/// A core opened on one config directory. The directory is the app's private
/// files dir on Android. This type does not read `TUNLION_CONFIG_DIR`.
pub struct Core {
    dir: PathBuf,
}

/// An identity that exists only in memory until `Core::commit_identity`.
pub struct UncommittedIdentity {
    pending: PendingIdentity,
}

/// Whether the peer loop is running inside this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EngineState {
    /// `Conn` and the receive loop still live in the CLI binary.
    NotLinked,
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
    /// `start` was called and the engine is not in this crate yet.
    #[error("the engine is not linked")]
    EngineNotLinked,
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
        Ok(Core { dir })
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
            engine: EngineState::NotLinked,
        })
    }

    /// The engine is not in this crate yet. This does not start a child process.
    pub fn start(&self) -> Result<(), CoreError> {
        Err(CoreError::EngineNotLinked)
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
