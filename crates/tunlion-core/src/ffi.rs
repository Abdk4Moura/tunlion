//! UniFFI surface. Same `Core` any Rust caller uses. Kotlin, Python, and
//! Swift bind to these objects. Android is one of those callers.
//!
//! The wrapper adds no policy. It exists so the phrase cannot be copied: the
//! pending identity lives behind a `Mutex<Option<..>>` and `commit_identity`
//! takes the value.

use std::sync::{Arc, Mutex};

use crate::{Core, CoreError, Status, UncommittedIdentity};

/// A core opened on a directory the caller owns.
#[derive(uniffi::Object)]
pub struct CoreSession {
    inner: Core,
}

/// A phrase that has not been written yet. Commit it, or drop it.
#[derive(uniffi::Object)]
pub struct PendingIdentity {
    inner: Mutex<Option<UncommittedIdentity>>,
}

#[uniffi::export]
impl CoreSession {
    /// Open `config_dir`, creating it if needed. Does not mint an identity.
    #[uniffi::constructor]
    pub fn open(config_dir: String) -> Result<Arc<Self>, CoreError> {
        Ok(Arc::new(Self {
            inner: Core::open(config_dir)?,
        }))
    }

    pub fn config_dir(&self) -> String {
        self.inner.config_dir().display().to_string()
    }

    pub fn begin_identity(&self) -> Result<Arc<PendingIdentity>, CoreError> {
        Ok(Arc::new(PendingIdentity {
            inner: Mutex::new(Some(self.inner.begin_identity()?)),
        }))
    }

    /// Write the key only when `confirmed_phrase` is the same 12 words.
    ///
    /// A mismatch does NOT consume the phrase: the caller may ask again. Only
    /// a match takes the value out.
    pub fn commit_identity(
        &self,
        pending: Arc<PendingIdentity>,
        confirmed_phrase: String,
    ) -> Result<String, CoreError> {
        if !pending.matches(&confirmed_phrase)? {
            return Err(CoreError::PhraseMismatch);
        }
        let uncommitted = pending.take()?;
        self.inner.commit_identity(uncommitted, &confirmed_phrase)
    }

    pub fn fingerprint(&self) -> Result<Option<String>, CoreError> {
        self.inner.fingerprint()
    }

    pub fn status(&self) -> Result<Status, CoreError> {
        self.inner.status()
    }

    /// Refuses until the peer loop lives in this crate. Does not spawn a process.
    pub fn start(&self) -> Result<(), CoreError> {
        self.inner.start()
    }
}

#[uniffi::export]
impl PendingIdentity {
    /// The 12 words, shown once. The same words that must be confirmed.
    pub fn phrase(&self) -> Result<String, CoreError> {
        let guard = self.lock()?;
        guard
            .as_ref()
            .map(UncommittedIdentity::phrase)
            .ok_or_else(already_taken)
    }

    pub fn fingerprint(&self) -> Result<String, CoreError> {
        let guard = self.lock()?;
        guard
            .as_ref()
            .map(UncommittedIdentity::fingerprint)
            .ok_or_else(already_taken)
    }
}

impl PendingIdentity {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<UncommittedIdentity>>, CoreError> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Identity("the pending identity lock was poisoned".into()))
    }

    /// Whether the typed words match, without consuming them.
    fn matches(&self, phrase: &str) -> Result<bool, CoreError> {
        Ok(self.lock()?.as_ref().is_some_and(|p| p.matches(phrase)))
    }

    /// Consume the phrase. The seed is handed to the writer, never copied.
    fn take(&self) -> Result<UncommittedIdentity, CoreError> {
        self.lock()?.take().ok_or_else(already_taken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<CoreSession> {
        CoreSession::open(tempfile::tempdir().unwrap().keep().display().to_string()).unwrap()
    }

    #[test]
    fn a_mistyped_confirmation_does_not_consume_the_phrase() {
        let core = session();
        let pending = core.begin_identity().unwrap();
        let phrase = pending.phrase().unwrap();

        assert_eq!(
            core.commit_identity(pending.clone(), "wrong".into()),
            Err(CoreError::PhraseMismatch)
        );
        // Still usable: the same phrase commits on the next attempt.
        let fingerprint = pending.fingerprint().unwrap();
        assert_eq!(
            core.commit_identity(pending.clone(), phrase).unwrap(),
            fingerprint
        );
        // And now it is gone.
        assert!(pending.phrase().is_err());
    }

    #[test]
    fn status_and_start_cross_the_boundary_without_a_child_process() {
        let core = session();
        let status = core.status().unwrap();
        assert_eq!(status.fingerprint, None);
        assert_eq!(status.engine, crate::EngineState::NotLinked);
        assert_eq!(core.start(), Err(CoreError::EngineNotLinked));
    }
}

fn already_taken() -> CoreError {
    CoreError::Identity("this phrase was already committed or dropped".into())
}
