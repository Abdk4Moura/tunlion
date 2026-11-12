//! UniFFI surface. Same `Core` any Rust caller uses. Kotlin, Python, and
//! Swift bind to these objects. Android is one of those callers.
//!
//! The wrapper adds no policy. It exists so the phrase cannot be copied: the
//! pending identity lives behind a `Mutex<Option<..>>` and `commit_identity`
//! takes the value.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::{
    ActionKind, CapabilityReceipt, Core, CoreError, CreatedCode, DevicePolicy, EnrollmentStatus,
    ReceiveSummary, RemovalReceipt, SendResult, Status, UncommittedIdentity,
};

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

    pub fn devices(&self) -> Result<Vec<crate::DeviceAccess>, CoreError> {
        self.inner.devices()
    }

    /// One device's typed local policy: relationship, admission facts,
    /// delivery state and one row per action. Read-only and local: no network
    /// work, no identity bootstrap. A corrupt store is an error, never an
    /// empty policy.
    pub fn device_policy(&self, name: String) -> Result<DevicePolicy, CoreError> {
        self.inner.device_policy(&name)
    }

    /// Forget one device on this phone: the key block is written first, its
    /// grants are revoked, and the record is removed last. Local only; the
    /// peer is not contacted and no live session is claimed to have ended.
    pub fn forget_device(&self, name: String) -> Result<RemovalReceipt, CoreError> {
        self.inner.forget_device(&name)
    }

    /// Cut one device off in place: keep the record and grants, write the
    /// revocation marker. Local only. The peer learns why on its next open.
    pub fn cut_off_device(&self, name: String) -> Result<RemovalReceipt, CoreError> {
        self.inner.cut_off_device(&name)
    }

    /// Lift this phone's refusal for one device. A record removed by a forget
    /// is not recreated; a key block left by that forget is lifted by name.
    pub fn restore_device(&self, name: String) -> Result<RemovalReceipt, CoreError> {
        self.inner.restore_device(&name)
    }

    /// Grant one action's enforcing capability to a known device. The receipt
    /// says whether an owner-signed op was written and when it expires.
    pub fn grant_capability(
        &self,
        device: String,
        action: ActionKind,
    ) -> Result<CapabilityReceipt, CoreError> {
        self.inner.grant_capability(&device, action)
    }

    /// Revoke one action's enforcing capability from a known device. A
    /// capability held by a delegated enrollment ceiling returns
    /// `NotRevocableBecauseCeiling`; a grant cannot narrow that ceiling.
    pub fn revoke_capability(
        &self,
        device: String,
        action: ActionKind,
    ) -> Result<CapabilityReceipt, CoreError> {
        self.inner.revoke_capability(&device, action)
    }

    /// Whether this build links an invitation create/join surface. The
    /// `Unsupported` reason is a fact, not an empty success.
    pub fn enrollment_status(&self) -> EnrollmentStatus {
        self.inner.enrollment_status()
    }

    /// Start the real receive engine for this config directory. Synchronous
    /// across the FFI boundary: the library owns the runtime, and readiness is
    /// observed before this returns.
    pub fn start(&self) -> Result<(), CoreError> {
        self.inner.start()
    }

    /// Stop and join the engine synchronously. No Tokio runtime crosses the
    /// FFI boundary.
    pub fn stop(&self) -> Result<(), CoreError> {
        self.inner.stop_blocking()
    }

    /// Receive one transfer by code with the real one-shot dispatch.
    ///
    /// Synchronous across the FFI boundary: this **blocks** until the transfer
    /// completes, the caller's `timeout` (seconds) expires with nothing
    /// received, the sender/refusal path ends, or `stop` cancels it. Call it
    /// off the UI thread; no Tokio runtime crosses the boundary and the
    /// library owns its runtime.
    ///
    /// A malformed code fails with `Usage` before any network work.
    /// Cancellation fails with `Cancelled`, never a fake empty success. A wait
    /// that ends with nothing received fails with `Unreachable` (the CLI's
    /// exit 6). Files stored or refused before the end are returned in the
    /// summary instead of being dropped.
    pub fn receive_code(
        &self,
        code: String,
        dir: String,
        yes: bool,
        timeout: Option<u64>,
    ) -> Result<ReceiveSummary, CoreError> {
        self.inner
            .receive_code(code, PathBuf::from(dir), yes, timeout)
    }

    /// Allocate a real, claimable transfer code and start the sender engine.
    ///
    /// Synchronous; returns once the signaling server has registered the code.
    /// The engine stays alive in this Core, so the code remains claimable until
    /// a receiver uses it, it expires, or `stop` cancels it. Call `wait_send` to
    /// collect the transfer and release the root lease. Call it off the UI
    /// thread: the allocation itself is bounded but performs real network work.
    pub fn create_code(
        &self,
        paths: Vec<String>,
        timeout: Option<u64>,
    ) -> Result<CreatedCode, CoreError> {
        self.inner.create_code(paths, timeout)
    }

    /// Wait for the code send started by `create_code`. Synchronous and
    /// blocking: it returns after the receiver acknowledges, the send fails, or
    /// `stop` cancels it. Call it off the UI thread.
    pub fn wait_send(&self) -> Result<SendResult, CoreError> {
        self.inner.wait_send()
    }

    /// Send files by a freshly allocated code in one blocking call. The result
    /// carries the code, so a caller that can show it only after the transfer
    /// should use `create_code` and `wait_send` instead.
    pub fn send_by_code(
        &self,
        paths: Vec<String>,
        timeout: Option<u64>,
    ) -> Result<SendResult, CoreError> {
        self.inner.send_by_code(paths, timeout)
    }

    /// Send files to an already paired device by petname. Synchronous and
    /// blocking; call it off the UI thread.
    pub fn send_to_device(
        &self,
        paths: Vec<String>,
        device: String,
        timeout: Option<u64>,
    ) -> Result<SendResult, CoreError> {
        self.inner.send_to_device(paths, device, timeout)
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
        std::fs::write(core.inner.config_dir().join("config"),"server\n").unwrap();
        assert!(matches!(core.start(), Err(CoreError::Config(_))));
        assert_eq!(core.status().unwrap().fingerprint,None);
    }

    #[test]
    fn stop_without_a_started_engine_is_a_synchronous_no_op() {
        let core = session();
        core.stop().unwrap();
        assert_eq!(core.status().unwrap().engine, crate::EngineState::NotLinked);
    }

    #[test]
    fn receive_code_refuses_a_malformed_code_across_the_boundary() {
        let core = session();
        assert!(matches!(
            core.receive_code("not-a-code".to_string(), core.config_dir(), true, Some(1)),
            Err(CoreError::Usage(_))
        ));
        assert_eq!(core.status().unwrap().engine, crate::EngineState::NotLinked);
    }

    #[test]
    fn lifecycle_calls_cross_the_boundary_without_network_work() {
        let core = session();
        let status = core.enrollment_status();
        assert_eq!(status.state, crate::EnrollmentSupport::Unsupported);
        assert!(status.reason.is_some());
        assert!(matches!(
            core.device_policy("ghost".to_string()),
            Err(CoreError::Usage(_))
        ));
        assert!(matches!(
            core.forget_device("ghost".to_string()),
            Err(CoreError::Usage(_))
        ));
        assert!(matches!(
            core.cut_off_device("ghost".to_string()),
            Err(CoreError::Usage(_))
        ));
        assert!(matches!(
            core.restore_device("ghost".to_string()),
            Err(CoreError::Usage(_))
        ));
        assert!(matches!(
            core.grant_capability("ghost".to_string(), crate::ActionKind::Send),
            Err(CoreError::Usage(_))
        ));
        assert!(matches!(
            core.revoke_capability("ghost".to_string(), crate::ActionKind::Send),
            Err(CoreError::Usage(_))
        ));
        assert_eq!(core.status().unwrap().engine, crate::EngineState::NotLinked);
        assert!(!core.inner.config_dir().join("devices.json").exists());
    }
}

fn already_taken() -> CoreError {
    CoreError::Identity("this phrase was already committed or dropped".into())
}
