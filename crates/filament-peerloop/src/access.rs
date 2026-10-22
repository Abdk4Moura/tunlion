//! Foreground pairwise resource agreements, independent of transport/contact storage.
//!
//! Offers must be addressed to the peer key authenticated by the existing PAKE or
//! proven-link ceremony. This module does not allocate invitation codes or enroll
//! devices. In particular, an agreement ID is not a bearer credential.
//! No restart/background persistence is promised: dropping the engine cancels all
//! operations. A future daemon adapter must acknowledge durable handoff first.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::driver::{Cancellation, DriverOutcome};
use crate::host::HostServices;

const MAX_AGREEMENTS: usize = 128;
const MAX_RESOURCES: usize = 64;
const MAX_EVENTS: usize = 256;
const MAX_OPERATIONS: usize = 256;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolderMode { #[default] ReadOnly, ReadWrite }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderAccess {
    pub id: String,
    pub path: PathBuf,
    pub mode: FolderMode,
}
impl FolderAccess {
    /// Resolve the actual host-selected directory before authenticating review.
    /// The peer never supplies a replacement root at endpoint activation.
    pub fn canonical(id: String, path: impl AsRef<std::path::Path>, mode: FolderMode) -> Result<Self, AccessError> {
        let path = path.as_ref().canonicalize().map_err(|_| AccessError::Unavailable)?;
        if !path.is_dir() { return Err(AccessError::InvalidSpec); }
        Ok(Self { id, path, mode })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceProtocol { Tcp, Udp }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccess {
    pub id: String,
    /// An exact socket, not a hostname, wildcard listener or subnet grant.
    pub target: SocketAddr,
    pub protocol: ServiceProtocol,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessSpec {
    pub folders: Vec<FolderAccess>,
    pub services: Vec<ServiceAccess>,
    pub shell: bool,
    /// Device networking is not subnet access. Currently unavailable here.
    pub device_network: bool,
}

impl AccessSpec {
    pub fn validate(&self) -> Result<(), AccessError> {
        if self.folders.len() + self.services.len() > MAX_RESOURCES {
            return Err(AccessError::Capacity);
        }
        let mut ids = BTreeSet::new();
        for id in self.folders.iter().map(|f| &f.id).chain(self.services.iter().map(|s| &s.id)) {
            if id.is_empty() || id.len() > 128 || !ids.insert(id) {
                return Err(AccessError::InvalidSpec);
            }
        }
        if self.folders.iter().any(|f| !f.path.is_absolute() || f.path.as_os_str().len() > 4096)
            || self.services.iter().any(|s| s.target.port() == 0 || s.target.ip().is_unspecified() || s.target.ip().is_multicast()) {
            return Err(AccessError::InvalidSpec);
        }
        Ok(())
    }

    /// Every retained resource is byte-for-byte identical. Changing a target or
    /// RO to RW is an addition requiring acceptance, even with the same ID.
    fn is_subset_of(&self, old: &Self) -> bool {
        self.folders.iter().all(|f| old.folders.contains(f))
            && self.services.iter().all(|s| old.services.contains(s))
            && (!self.shell || old.shell)
            && (!self.device_network || old.device_network)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifetime {
    #[default]
    UntilEnded,
    ExpiresAt(u64),
}

impl Lifetime {
    fn expired(self, now: u64) -> bool { matches!(self, Self::ExpiresAt(at) if now >= at) }
    fn no_longer_than(self, old: Self) -> bool {
        match (self, old) {
            (_, Self::UntilEnded) => true,
            (Self::ExpiresAt(a), Self::ExpiresAt(b)) => a <= b,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Relationship { Owned, External, Delegated, Temporary }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgreementState { Offered, Active, Ended, Expired, Declined }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSnapshot {
    pub id: String,
    pub revision: u64,
    pub peer: [u8; 32],
    pub host_peer: [u8; 32],
    pub name: String,
    pub relationship: Relationship,
    pub spec: AccessSpec,
    pub lifetime: Lifetime,
    pub claim_expires_at: u64,
    pub state: AgreementState,
    /// Transport status is deliberately absent: disconnect does not revoke or renew.
    pub accepted_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEvent { pub sequence: u64, pub agreement: AgreementSnapshot }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<AccessEvent>,
    pub latest: u64,
    /// Caller must reload snapshots when its cursor predates the bounded log.
    pub reset_required: bool,
}

/// Authenticated full review, returned only after purpose-bound PAKE and host
/// signature verification. Viewing is not acceptance.
#[derive(Clone, Debug)]
pub struct AuthenticatedReview(AgreementSnapshot);
impl AuthenticatedReview {
    pub fn snapshot(&self) -> &AgreementSnapshot { &self.0 }
    pub fn acceptance_message(&self) -> Result<Vec<u8>, AccessError> { acceptance_bytes(&self.0) }
    /// Review a new full revision on the established agreement without claiming
    /// another invitation. The caller retains the most recent review/cursor and
    /// must discard it when the agreement is ended; no resurrection is implied.
    pub fn review_revision(&self, snapshot: AgreementSnapshot, host_signature: [u8;64], now: u64)
        -> Result<Self, AccessError> {
        snapshot.spec.validate()?;
        if snapshot.id != self.0.id || snapshot.peer != self.0.peer || snapshot.host_peer != self.0.host_peer
            || snapshot.relationship != self.0.relationship || snapshot.name != self.0.name
            || snapshot.claim_expires_at != self.0.claim_expires_at {
            return Err(AccessError::InvalidProof);
        }
        if snapshot.revision <= self.0.revision { return Err(AccessError::StaleRevision); }
        check_revision(&snapshot, snapshot.revision)?;
        if snapshot.lifetime.expired(now) { return Err(AccessError::Expired); }
        filament_id::verify_possession_sig(&snapshot.host_peer, &review_bytes(&snapshot)?, &host_signature)
            .map_err(|_| AccessError::InvalidProof)?;
        Ok(Self(snapshot))
    }
    #[cfg(feature = "dispatch")]
    pub(crate) fn verify(binding: &crate::send::ceremony::TemporaryBinding, snapshot: AgreementSnapshot,
        signature: [u8;64], local_peer: [u8;32], now: u64) -> Result<Self, AccessError> {
        if snapshot.host_peer != binding.host_peer || snapshot.peer != local_peer
            || snapshot.peer == snapshot.host_peer || snapshot.id != binding.offer_id
            || snapshot.revision != binding.revision || snapshot.relationship != Relationship::Temporary
            || snapshot.state != AgreementState::Offered || snapshot.accepted_revision.is_some()
            || snapshot.lifetime.expired(now) || snapshot.claim_expires_at <= now
            || binding.digest_for(&snapshot.spec, snapshot.lifetime, snapshot.claim_expires_at)? != binding.offer_digest {
            return Err(AccessError::InvalidProof);
        }
        filament_id::verify_possession_sig(&binding.host_peer, &review_bytes(&snapshot)?, &signature)
            .map_err(|_| AccessError::InvalidProof)?;
        Ok(Self(snapshot))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessError {
    NotFound, InvalidSpec, Capacity, StaleRevision, NotAccepted, Ended,
    Expired, WrongPeer, InvalidProof, Unsupported, Unavailable, Poisoned,
}
impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "access: {self:?}") }
}
impl std::error::Error for AccessError {}

#[derive(Clone, PartialEq, Eq)]
enum ResourceAccess { Service(ServiceAccess), Folder(FolderAccess) }
impl ResourceAccess {
    fn retained_by(&self, spec: &AccessSpec) -> bool {
        match self { Self::Service(s) => spec.services.contains(s), Self::Folder(f) => spec.folders.contains(f) }
    }
}
struct Operation { resource: ResourceAccess, cancel: Cancellation }
#[cfg(any(feature = "forward-server", all(feature = "mount-server", target_os = "linux")))]
struct StreamCleanup { mux: Arc<crate::l2::Mux>, sid: u32, generation: u64, armed: bool }
#[cfg(any(feature = "forward-server", all(feature = "mount-server", target_os = "linux")))]
impl Drop for StreamCleanup {
    fn drop(&mut self) {
        if !self.armed { return; }
        // Cooperative end awaits cleanup. Aborting/dropping an embedding future
        // must also reap pumps without removing a newer registration's SID.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let mux=self.mux.clone(); let sid=self.sid; let generation=self.generation;
            runtime.spawn(async move { mux.drop_stream_if(sid,generation).await; });
        }
    }
}
struct Agreement { snapshot: AgreementSnapshot, operations: Vec<Operation>, claimed: bool }
#[derive(Default)]
struct State {
    agreements: BTreeMap<String, Agreement>,
    names: BTreeSet<String>,
    events: VecDeque<AccessEvent>,
    sequence: u64,
}
impl State {
    fn publish(&mut self, snapshot: AgreementSnapshot) {
        self.sequence += 1;
        self.events.push_back(AccessEvent { sequence: self.sequence, agreement: snapshot });
        if self.events.len() > MAX_EVENTS { self.events.pop_front(); }
    }
    fn terminate(&mut self, id: &str, status: AgreementState) -> Result<AgreementSnapshot, AccessError> {
        let a = self.agreements.get_mut(id).ok_or(AccessError::NotFound)?;
        if matches!(a.snapshot.state, AgreementState::Ended | AgreementState::Expired | AgreementState::Declined) {
            return Ok(a.snapshot.clone());
        }
        a.snapshot.state = status;
        a.snapshot.accepted_revision = None;
        for op in a.operations.drain(..) { op.cancel.cancel(); }
        self.names.remove(&a.snapshot.name);
        let snapshot = a.snapshot.clone();
        self.publish(snapshot.clone());
        Ok(snapshot)
    }
    fn expire(&mut self, now: u64) {
        let expired: Vec<_> = self.agreements.iter().filter(|(_, a)| {
            a.snapshot.lifetime.expired(now) || (!a.claimed && now >= a.snapshot.claim_expires_at)
        }).map(|(id, _)| id.clone()).collect();
        for id in expired { let _ = self.terminate(&id, AgreementState::Expired); }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        for a in self.agreements.values() {
            for op in &a.operations { op.cancel.cancel(); }
        }
    }
}

/// One foreground owner. There is no ambient policy, persistent device insertion,
/// label-based identity or authorization callback while the mutex is held.
pub struct AgreementEngine { state: Arc<Mutex<State>>, local_peer: [u8; 32] }

/// Identity obtained from the existing verified link, never a display-name or
/// caller supplied key. Obtaining a snapshot alone cannot manufacture this.
#[derive(Clone, Copy, Debug)]
pub struct ProvenPeer([u8; 32], Option<[u8; 32]>);
impl ProvenPeer {
    pub fn from_conn(conn: &crate::conn::Conn, pid: &str) -> Result<Self, AccessError> {
        let link = conn.link(pid).ok_or(AccessError::WrongPeer)?;
        if !link.trusted || link.identity_binding != filament_cap::capability::BindingStrength::Proven {
            return Err(AccessError::InvalidProof);
        }
        // This adapter does not replace the authoritative signed delegated ceiling.
        if matches!(link.principal_kind, filament_cap::capability::PrincipalKind::Delegated { .. }) {
            return Err(AccessError::Unsupported);
        }
        link.identity_device_pub.map(|key| Self(key, None)).ok_or(AccessError::InvalidProof)
    }
    pub fn public_key(self) -> [u8; 32] { self.0 }
    #[cfg(feature = "dispatch")]
    pub(crate) fn from_temporary_proof(key: [u8; 32], digest: [u8; 32]) -> Self { Self(key, Some(digest)) }
}

impl AgreementEngine {
    pub fn new(local_peer: [u8; 32], remembered_names: impl IntoIterator<Item = String>) -> Self {
        let mut state = State::default();
        state.names = remembered_names.into_iter().map(|s| dns_label(&s)).collect();
        Self { state: Arc::new(Mutex::new(state)), local_peer }
    }

    /// `peer` must come from an authenticated PAKE/proven-link result, not a label.
    /// The host never treats possession of the returned ID as authentication.
    pub fn offer(&self, peer: ProvenPeer, label: &str, spec: AccessSpec, lifetime: Lifetime,
                 claim_expires_at: u64, now: u64) -> Result<AgreementSnapshot, AccessError> {
        if peer.1.is_some() { return Err(AccessError::InvalidProof); }
        self.offer_with_id(peer, label, spec, lifetime, claim_expires_at, now, None)
    }

    /// Install the exact proposal authenticated by a temporary-purpose PAKE.
    /// The binding is not authority by itself: `peer` is still a sealed proof.
    #[cfg(feature = "dispatch")]
    pub fn offer_bound(&self, peer: ProvenPeer, binding: &crate::send::ceremony::TemporaryBinding,
        label: &str, spec: AccessSpec, lifetime: Lifetime, claim_expires_at: u64, now: u64)
        -> Result<AgreementSnapshot, AccessError> {
        if peer.1 != Some(binding.offer_digest) || binding.host_peer != self.local_peer || binding.revision != 1
            || binding.offer_id.len() != 64 || !binding.offer_id.bytes().all(|b| b.is_ascii_hexdigit())
            || binding.digest_for(&spec, lifetime, claim_expires_at)? != binding.offer_digest {
            return Err(AccessError::InvalidProof);
        }
        self.offer_with_id(peer, label, spec, lifetime, claim_expires_at, now, Some(binding.offer_id.clone()))
    }

    fn offer_with_id(&self, peer: ProvenPeer, label: &str, spec: AccessSpec, lifetime: Lifetime,
        claim_expires_at: u64, now: u64, bound_id: Option<String>) -> Result<AgreementSnapshot, AccessError> {
        spec.validate()?;
        if peer.0 == self.local_peer { return Err(AccessError::WrongPeer); }
        if lifetime.expired(now) || claim_expires_at <= now { return Err(AccessError::Expired); }
        let mut random = [0; 32];
        getrandom::getrandom(&mut random).map_err(|_| AccessError::Unavailable)?;
        let id = bound_id.unwrap_or_else(|| hex::encode(random));
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        if state.agreements.contains_key(&id) { return Err(AccessError::InvalidProof); }
        if state.agreements.len() >= MAX_AGREEMENTS { return Err(AccessError::Capacity); }
        let name = allocate_name(&state.names, label);
        let snapshot = AgreementSnapshot { id: id.clone(), revision: 1, peer: peer.0, host_peer: self.local_peer, name: name.clone(),
            relationship: Relationship::Temporary, spec, lifetime, claim_expires_at,
            state: AgreementState::Offered, accepted_revision: None };
        state.names.insert(name);
        state.agreements.insert(id, Agreement { snapshot: snapshot.clone(), operations: Vec::new(), claimed: false });
        state.publish(snapshot.clone());
        Ok(snapshot)
    }

    pub fn snapshot(&self, id: &str, now: u64) -> Result<AgreementSnapshot, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        Ok(state.agreements.get(id).ok_or(AccessError::NotFound)?.snapshot.clone())
    }

    pub fn snapshots(&self, now: u64) -> Result<Vec<AgreementSnapshot>, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        Ok(state.agreements.values().map(|a| a.snapshot.clone()).collect())
    }

    /// Full typed review serialized under a domain separator, never display text.
    /// Sign these bytes with the peer's existing overlay Ed25519 key only after
    /// explicit review. Byte encoding is versioned and must not be reconstructed
    /// by an adapter. No new unauthenticated wire protocol is defined here.
    pub fn acceptance_message(&self, id: &str, revision: u64, now: u64) -> Result<Vec<u8>, AccessError> {
        let snapshot = self.snapshot(id, now)?;
        check_revision(&snapshot, revision)?;
        acceptance_bytes(&snapshot)
    }

    /// Host signs this with the existing overlay key and relays the snapshot
    /// over the same authenticated transport; it is not an acceptance signature.
    pub fn review_message(&self, id: &str, revision: u64, now: u64) -> Result<Vec<u8>, AccessError> {
        let snapshot = self.snapshot(id, now)?;
        check_revision(&snapshot, revision)?;
        review_bytes(&snapshot)
    }

    pub fn accept(&self, id: &str, revision: u64, peer: ProvenPeer, signature: [u8; 64], now: u64)
        -> Result<AgreementSnapshot, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        let a = state.agreements.get_mut(id).ok_or(AccessError::NotFound)?;
        check_revision(&a.snapshot, revision)?;
        if a.snapshot.peer != peer.0 { return Err(AccessError::WrongPeer); }
        filament_id::verify_possession_sig(&peer.0, &acceptance_bytes(&a.snapshot)?, &signature)
            .map_err(|_| AccessError::InvalidProof)?;
        a.snapshot.state = AgreementState::Active;
        a.snapshot.accepted_revision = Some(revision);
        a.claimed = true;
        let snapshot = a.snapshot.clone();
        state.publish(snapshot.clone());
        Ok(snapshot)
    }

    /// Removal takes effect synchronously under the same lock as operation
    /// admission. Additions suspend new operations until the new full revision
    /// is accepted. Even retained active operations are cancelled on widening.
    pub fn revise(&self, id: &str, expected_revision: u64, spec: AccessSpec, lifetime: Lifetime, now: u64)
        -> Result<AgreementSnapshot, AccessError> {
        spec.validate()?;
        if lifetime.expired(now) { return Err(AccessError::Expired); }
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        let a = state.agreements.get_mut(id).ok_or(AccessError::NotFound)?;
        check_revision(&a.snapshot, expected_revision)?;
        let narrowed = spec.is_subset_of(&a.snapshot.spec) && lifetime.no_longer_than(a.snapshot.lifetime);
        a.operations.retain(|op| {
            let keep = narrowed && lifetime == a.snapshot.lifetime && op.resource.retained_by(&spec) && !op.cancel.is_cancelled();
            if !keep { op.cancel.cancel(); }
            keep
        });
        a.snapshot.revision += 1;
        a.snapshot.spec = spec;
        a.snapshot.lifetime = lifetime;
        if narrowed && a.snapshot.state == AgreementState::Active {
            a.snapshot.accepted_revision = Some(a.snapshot.revision);
        } else {
            a.snapshot.state = AgreementState::Offered;
            a.snapshot.accepted_revision = None;
        }
        let snapshot = a.snapshot.clone();
        state.publish(snapshot.clone());
        Ok(snapshot)
    }

    pub fn end(&self, id: &str, now: u64) -> Result<AgreementSnapshot, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        state.terminate(id, AgreementState::Ended)
    }

    pub fn decline(&self, id: &str, revision: u64, now: u64) -> Result<AgreementSnapshot, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        check_revision(&state.agreements.get(id).ok_or(AccessError::NotFound)?.snapshot, revision)?;
        state.terminate(id, AgreementState::Declined)
    }

    pub fn events(&self, after: u64, now: u64) -> Result<EventPage, AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        Ok(EventPage {
            reset_required: after > state.sequence || state.events.front().is_some_and(|e| after.saturating_add(1) < e.sequence),
            latest: state.sequence,
            events: state.events.iter().filter(|e| e.sequence > after).cloned().collect(),
        })
    }

    fn admit_tcp(&self, id: &str, revision: u64, peer: ProvenPeer, resource: &str, now: u64)
        -> Result<(ServiceAccess, Cancellation, Lifetime), AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        let a = state.agreements.get_mut(id).ok_or(AccessError::NotFound)?;
        check_revision(&a.snapshot, revision)?;
        if a.snapshot.peer != peer.0 { return Err(AccessError::WrongPeer); }
        if a.snapshot.accepted_revision != Some(revision) { return Err(AccessError::NotAccepted); }
        let service = a.snapshot.spec.services.iter().find(|s| s.id == resource).ok_or(AccessError::InvalidSpec)?.clone();
        if service.protocol != ServiceProtocol::Tcp { return Err(AccessError::Unsupported); }
        a.operations.retain(|op| !op.cancel.is_cancelled());
        if a.operations.len() >= MAX_OPERATIONS { return Err(AccessError::Capacity); }
        let cancel = Cancellation::default();
        a.operations.push(Operation { resource: ResourceAccess::Service(service.clone()), cancel: cancel.clone() });
        Ok((service, cancel, a.snapshot.lifetime))
    }

    #[cfg(all(feature = "mount-server", target_os = "linux"))]
    fn admit_folder(&self, id: &str, revision: u64, peer: ProvenPeer, resource: &str, now: u64)
        -> Result<(FolderAccess, Cancellation, Lifetime), AccessError> {
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
        let a = state.agreements.get_mut(id).ok_or(AccessError::NotFound)?;
        check_revision(&a.snapshot, revision)?;
        if a.snapshot.peer != peer.0 { return Err(AccessError::WrongPeer); }
        if a.snapshot.accepted_revision != Some(revision) { return Err(AccessError::NotAccepted); }
        let folder = a.snapshot.spec.folders.iter().find(|f| f.id == resource).ok_or(AccessError::InvalidSpec)?.clone();
        a.operations.retain(|op| !op.cancel.is_cancelled());
        if a.operations.len() >= MAX_OPERATIONS { return Err(AccessError::Capacity); }
        let cancel = Cancellation::default();
        a.operations.push(Operation { resource:ResourceAccess::Folder(folder.clone()),cancel:cancel.clone() });
        Ok((folder,cancel,a.snapshot.lifetime))
    }

    /// Serve the existing confined filesystem protocol for an accepted folder.
    /// Linux pins a directory descriptor before acknowledgement, so renaming or
    /// substituting the offered path cannot redirect a live share. Other hosts
    /// refuse until they provide equivalent pinned-root integration. This is a
    /// protocol endpoint, NOT a claim that FUSE/WinFsp has mounted a local path.
    pub async fn serve_folder(&self, id: &str, revision: u64, peer: ProvenPeer, resource: &str,
        sid: u32, mux: Arc<crate::l2::Mux>, host: Arc<dyn HostServices>) -> Result<(), AccessError> {
        #[cfg(not(all(feature = "mount-server", target_os = "linux")))]
        { let _=(id,revision,peer,resource,sid,mux,host); Err(AccessError::Unsupported) }
        #[cfg(all(feature = "mount-server", target_os = "linux"))]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            if host.delegated_access_for(&peer.0).is_some(){return Err(AccessError::Unsupported);}
            if !crate::l2::is_l2_sid(sid) { return Err(AccessError::InvalidSpec); }
            let now=host.now_secs();
            let (folder,cancel,lifetime)=self.admit_folder(id,revision,peer,resource,now)?;
            struct Finish(Cancellation);
            impl Drop for Finish { fn drop(&mut self) { self.0.cancel(); } }
            let _finish=Finish(cancel.clone());
            if folder.path.canonicalize().map_err(|_|AccessError::Unavailable)? != folder.path {
                return Err(AccessError::InvalidSpec);
            }
            let root_pin=Arc::new(std::fs::OpenOptions::new().read(true)
                .custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
                .open(&folder.path).map_err(|_|AccessError::Unavailable)?);
            let pinned_path=PathBuf::from(format!("/proc/self/fd/{}",root_pin.as_raw_fd()));
            if !pinned_path.is_dir() { return Err(AccessError::Unavailable); }
            let (rx,generation)=mux.register_access_stream(sid).await.ok_or(AccessError::Capacity)?;
            let mut cleanup=StreamCleanup { mux:mux.clone(),sid,generation,armed:true };
            let weak=Arc::downgrade(&self.state); let agreement_id=id.to_string();
            let gate_host=host.clone(); let gate_cancel=cancel.clone();
            let selected=ResourceAccess::Folder(folder.clone());
            let gate: crate::mount_proto::MountRequestAdmission=Arc::new(move || {
                // Retain the root descriptor until the server itself exits,
                // including when its owner's future is externally aborted.
                let _pin=&root_pin;
                let now=gate_host.now_secs();
                if gate_host.delegated_access_for(&peer.0).is_some(){return Err(AccessError::Unsupported.to_string());}
                if gate_host.live_session_cut(Some(&peer.0)).is_some(){return Err(AccessError::Ended.to_string());}
                if gate_cancel.is_cancelled() { return Err(AccessError::Ended.to_string()); }
                let state=weak.upgrade().ok_or_else(||AccessError::Ended.to_string())?;
                let mut state=state.lock().map_err(|_|AccessError::Poisoned.to_string())?;
                state.expire(now);
                let a=state.agreements.get(&agreement_id).ok_or_else(||AccessError::NotFound.to_string())?;
                if gate_cancel.is_cancelled() || a.snapshot.state!=AgreementState::Active
                    || a.snapshot.accepted_revision!=Some(a.snapshot.revision) || !selected.retained_by(&a.snapshot.spec) {
                    return Err(AccessError::Ended.to_string());
                }
                // This is the admission linearization point. The mutex is
                // released BEFORE filesystem/network await. An already-admitted
                // write can finish during revoke; no rollback is promised.
                Ok(())
            });
            let mut caps=crate::mount_proto::mount_caps_for_root(&pinned_path);
            let read_only=folder.mode==FolderMode::ReadOnly;
            if read_only { caps.max_write_size=0; }
            let task=crate::mount_proto::spawn_mount_server_with_admission(crate::mount_proto::MountServerConfig {
                root:pinned_path,transport:mux.transport(),sid,stream:rx,protocol_version:caps.protocol_version,
                read_only,device_pub:None,host,log:Arc::new(crate::host::NoLog),
            },Some(gate));
            struct OwnedTask(tokio::task::JoinHandle<()>);
            impl Drop for OwnedTask { fn drop(&mut self) { self.0.abort(); } }
            let mut task=OwnedTask(task);
            let deadline=async {
                match lifetime {
                    Lifetime::UntilEnded=>std::future::pending::<()>().await,
                    Lifetime::ExpiresAt(at)=>tokio::time::sleep(std::time::Duration::from_secs(at.saturating_sub(now))).await,
                }
            };
            let mut joined=false;
            let serving=async {
                mux.transport().send_control(&serde_json::json!({"type":"mount-open-ack","sid":sid,"caps":caps})).await
                    .map_err(|_|AccessError::Unavailable)?;
                let result=(&mut task.0).await;
                joined=true;
                result.map_err(|_|AccessError::Unavailable)
            };
            let result=tokio::select! {
                biased;
                _=deadline=>Err(AccessError::Expired),
                outcome=cancel.run(serving)=>match outcome {
                    DriverOutcome::Cancelled=>Err(AccessError::Ended),
                    DriverOutcome::Returned(result)=>result,
                }
            };
            if !joined { task.0.abort(); let _=(&mut task.0).await; }
            mux.drop_stream_if(sid,generation).await; cleanup.armed=false;
            let reason=result.as_ref().err().map(ToString::to_string);
            let _=mux.transport().send_control(&serde_json::json!({"type":"l2-close","sid":sid,"err":reason})).await;
            result
        }
    }

    /// Existing L2 dispatch handoff: route an authenticated temporary open here,
    /// NOT through the standing shell/forward permission gate. Only resource ID
    /// and SID come from the peer; the target is read from accepted scope. The
    /// same per-peer Mux must receive subsequent L2 frames/close messages.
    pub async fn serve_forward(&self, id: &str, revision: u64, peer: ProvenPeer,
        resource: &str, sid: u32, mux: Arc<crate::l2::Mux>, now: u64) -> Result<(), AccessError> {
        #[cfg(not(feature = "forward-server"))]
        { let _ = (id, revision, peer, resource, sid, mux, now); Err(AccessError::Unsupported) }
        #[cfg(feature = "forward-server")]
        {
            if mux.access_delegated_principal(&peer.0){return Err(AccessError::Unsupported);}
            if !crate::l2::is_l2_sid(sid) { return Err(AccessError::InvalidSpec); }
            let (service, cancel, lifetime) = self.admit_tcp(id, revision, peer, resource, now)?;
            struct Finish(Cancellation);
            impl Drop for Finish { fn drop(&mut self) { self.0.cancel(); } }
            let _finish = Finish(cancel.clone());
            let (rx, generation) = mux.register_access_stream(sid).await.ok_or(AccessError::Capacity)?;
            let mut cleanup = StreamCleanup { mux:mux.clone(),sid,generation,armed:true };
            let deadline = async {
                match lifetime {
                    Lifetime::UntilEnded => std::future::pending::<()>().await,
                    Lifetime::ExpiresAt(at) => tokio::time::sleep(std::time::Duration::from_secs(at.saturating_sub(now))).await,
                }
            };
            let result = tokio::select! {
                biased;
                _ = deadline => Err(AccessError::Expired),
                outcome = cancel.run(mux.clone().dial_and_serve(sid, service.target.ip().to_string(), service.target.port(), rx, Some(peer.0))) => match outcome {
                    DriverOutcome::Cancelled => Err(AccessError::Ended),
                    // Dial success/failure is reported by the existing mux's
                    // l2-open-ack/l2-close, never invented as an endpoint here.
                    DriverOutcome::Returned(()) => Ok(()),
                }
            };
            mux.drop_stream_if(sid, generation).await;
            cleanup.armed = false;
            if let Err(ref reason) = result {
                let _ = mux.transport().send_control(&serde_json::json!({"type":"l2-close", "sid":sid, "err":reason.to_string()})).await;
            }
            result
        }
    }

    /// Serve an already authenticated stream from the existing transport. Uses
    /// the real host dial port; no new listener, tunnel, enrollment, allowlist or
    /// global environment. Target comes from accepted scope, NEVER peer input.
    /// Returning Unsupported/Unavailable is not endpoint activation success.
    pub async fn serve_tcp<S>(&self, id: &str, revision: u64, peer: ProvenPeer, resource: &str,
        stream: &mut S, host: &dyn HostServices) -> Result<(u64, u64), AccessError>
    where S: AsyncRead + AsyncWrite + Unpin {
        #[cfg(not(feature = "forward-server"))]
        { let _ = (id, revision, peer, resource, stream, host); Err(AccessError::Unsupported) }
        #[cfg(feature = "forward-server")]
        {
            if host.delegated_access_for(&peer.0).is_some(){return Err(AccessError::Unsupported);}
            let (service, cancel, lifetime) = self.admit_tcp(id, revision, peer, resource, host.now_secs())?;
            // Cleanup cancellation also reclaims a completed operation's bounded slot.
            struct Finish(Cancellation);
            impl Drop for Finish { fn drop(&mut self) { self.0.cancel(); } }
            let _finish = Finish(cancel.clone());
            let transfer = async {
                let mut socket = host.connect_local_stream(&service.target.ip().to_string(), service.target.port()).await
                    .map_err(|e| if e.kind() == std::io::ErrorKind::Unsupported { AccessError::Unsupported } else { AccessError::Unavailable })?;
                tokio::io::copy_bidirectional(stream, &mut socket).await.map_err(|_| AccessError::Unavailable)
            };
            let deadline = async {
                match lifetime {
                    Lifetime::UntilEnded => std::future::pending::<()>().await,
                    Lifetime::ExpiresAt(at) => tokio::time::sleep(std::time::Duration::from_secs(at.saturating_sub(host.now_secs()))).await,
                }
            };
            tokio::select! {
                biased;
                _ = deadline => { cancel.cancel(); Err(AccessError::Expired) },
                outcome = cancel.run(transfer) => match outcome {
                    DriverOutcome::Cancelled => Err(AccessError::Ended),
                    DriverOutcome::Returned(result) => result,
                }
            }
        }
    }
}

// Scope signatures deliberately exclude mutable state/acceptance flags, so
// reconnect proof stays stable for the accepted revision. All scope is included.
fn acceptance_bytes(s: &AgreementSnapshot) -> Result<Vec<u8>, AccessError> {
    let mut bytes = b"tunlion/access-accept/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&(&s.id, s.revision, s.peer, s.host_peer, &s.name, s.relationship,
        &s.spec, s.lifetime, s.claim_expires_at)).map_err(|_| AccessError::InvalidSpec)?);
    Ok(bytes)
}
fn review_bytes(s: &AgreementSnapshot) -> Result<Vec<u8>, AccessError> {
    let mut bytes = b"tunlion/access-review/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(s).map_err(|_| AccessError::InvalidSpec)?);
    Ok(bytes)
}
fn check_revision(s: &AgreementSnapshot, revision: u64) -> Result<(), AccessError> {
    match s.state {
        AgreementState::Ended | AgreementState::Declined => return Err(AccessError::Ended),
        AgreementState::Expired => return Err(AccessError::Expired),
        _ => {}
    }
    if s.revision != revision { return Err(AccessError::StaleRevision); }
    Ok(())
}

/// ASCII DNS label only. This is a label, not a `.mesh` readiness claim.
pub fn dns_label(raw: &str) -> String {
    let mut label = String::new();
    for b in raw.bytes() {
        if label.len() == 63 { break; }
        if b.is_ascii_alphanumeric() { label.push((b as char).to_ascii_lowercase()); }
        else if !label.is_empty() && !label.ends_with('-') { label.push('-'); }
    }
    let label = label.trim_end_matches('-');
    if label.is_empty() { "device".to_string() } else { label.to_string() }
}
fn allocate_name(names: &BTreeSet<String>, raw: &str) -> String {
    let base = dns_label(raw);
    if !names.contains(&base) { return base; }
    for n in 1u64.. {
        let suffix = format!("-{n}");
        let stem = base[..base.len().min(63 - suffix.len())].trim_end_matches('-');
        let candidate = format!("{stem}{suffix}");
        if !names.contains(&candidate) { return candidate; }
    }
    unreachable!("bounded agreement namespace cannot exhaust numeric suffixes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};

    fn key() -> Ed25519KeyPair {
        let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
    }
    fn peer(key: &Ed25519KeyPair) -> ProvenPeer {
        ProvenPeer(key.public_key().as_ref().try_into().unwrap(), None)
    }
    fn spec() -> AccessSpec {
        AccessSpec {
            folders: vec![
                FolderAccess { id: "docs".into(), path: PathBuf::from("/docs"), mode: FolderMode::ReadOnly },
                FolderAccess { id: "work".into(), path: PathBuf::from("/work"), mode: FolderMode::ReadWrite },
            ],
            services: vec![
                ServiceAccess { id: "web".into(), target: "127.0.0.1:8080".parse().unwrap(), protocol: ServiceProtocol::Tcp },
                ServiceAccess { id: "dns".into(), target: "127.0.0.1:5353".parse().unwrap(), protocol: ServiceProtocol::Udp },
            ], shell: true, device_network: false,
        }
    }
    fn engine() -> AgreementEngine { AgreementEngine::new([7; 32], Vec::new()) }
    fn offer(e: &AgreementEngine, p: ProvenPeer) -> AgreementSnapshot {
        e.offer(p, "Alex Laptop", spec(), Lifetime::UntilEnded, 50, 10).unwrap()
    }
    fn accept(e: &AgreementEngine, s: &AgreementSnapshot, key: &Ed25519KeyPair, now: u64) -> AgreementSnapshot {
        let message = e.acceptance_message(&s.id, s.revision, now).unwrap();
        e.accept(&s.id, s.revision, peer(key), key.sign(&message).as_ref().try_into().unwrap(), now).unwrap()
    }

    #[test]
    fn mixed_review_proof_peer_revision_and_no_permanent_store() {
        let e = engine(); let k = key(); let other = key();
        let s = offer(&e, peer(&k));
        assert_eq!(s.spec, spec());
        assert_eq!(s.relationship, Relationship::Temporary);
        assert_eq!(s.name, "alex-laptop");
        assert_eq!(e.admit_tcp(&s.id, 1, peer(&k), "web", 10).err(), Some(AccessError::NotAccepted));
        let msg = e.acceptance_message(&s.id, 1, 10).unwrap();
        let sig = k.sign(&msg).as_ref().try_into().unwrap();
        assert_eq!(e.accept(&s.id, 1, peer(&other), sig, 10), Err(AccessError::WrongPeer));
        assert_eq!(e.accept(&s.id, 1, peer(&k), [0;64], 10), Err(AccessError::InvalidProof));
        let s2 = offer(&e, peer(&k));
        assert_eq!(e.accept(&s2.id, 1, peer(&k), sig, 10), Err(AccessError::InvalidProof));
        let mut wider = s.spec.clone(); wider.device_network = true;
        let revised = e.revise(&s.id, 1, wider, Lifetime::UntilEnded, 10).unwrap();
        assert_eq!(e.accept(&s.id, 1, peer(&k), sig, 10), Err(AccessError::StaleRevision));
        assert_eq!(e.accept(&s.id, 2, peer(&k), sig, 10), Err(AccessError::InvalidProof));
        let active = accept(&e, &revised, &k, 10);
        assert_eq!(active.accepted_revision, Some(2));
        assert_eq!(e.admit_tcp(&s.id, 2, peer(&k), "dns", 10).err(), Some(AccessError::Unsupported));
    }

    #[test]
    fn decline_cancel_expiry_and_reconnect_never_restore() {
        let e = engine(); let k = key();
        let declined = offer(&e, peer(&k));
        e.decline(&declined.id, 1, 10).unwrap();
        assert_eq!(e.acceptance_message(&declined.id, 1, 10), Err(AccessError::Ended));
        let cancelled = offer(&e, peer(&k));
        e.end(&cancelled.id, 10).unwrap();
        assert_eq!(e.revise(&cancelled.id, 1, spec(), Lifetime::UntilEnded, 10), Err(AccessError::Ended));
        let unclaimed = offer(&e, peer(&k));
        assert_eq!(e.acceptance_message(&unclaimed.id, 1, 50), Err(AccessError::Expired));
        let expiring = e.offer(peer(&k), "host", spec(), Lifetime::ExpiresAt(30), 20, 10).unwrap();
        accept(&e, &expiring, &k, 10);
        let (_, cancel, _) = e.admit_tcp(&expiring.id, 1, peer(&k), "web", 29).unwrap();
        assert_eq!(e.admit_tcp(&expiring.id, 1, peer(&k), "web", 30).err(), Some(AccessError::Expired));
        assert!(cancel.is_cancelled());
        let indefinite = offer(&e, peer(&k));
        accept(&e, &indefinite, &k, 10);
        assert!(e.admit_tcp(&indefinite.id, 1, peer(&k), "web", 1000).is_ok());
        // A fresh revision after claim expiry is not a fresh invitation claim.
        let mut wider = spec(); wider.device_network = true;
        let revision = e.revise(&indefinite.id, 1, wider, Lifetime::UntilEnded, 1000).unwrap();
        accept(&e, &revision, &k, 1000);
        e.end(&indefinite.id, 1001).unwrap();
        assert_eq!(e.admit_tcp(&indefinite.id, 2, peer(&k), "web", 1002).err(), Some(AccessError::Ended));
    }

    #[test]
    fn scoped_removal_cancels_only_affected_operations_and_names() {
        let e = engine(); let k = key();
        let s = offer(&e, peer(&k)); let unrelated = offer(&e, peer(&k));
        accept(&e, &s, &k, 10); accept(&e, &unrelated, &k, 10);
        let (_, removed, _) = e.admit_tcp(&s.id, 1, peer(&k), "web", 10).unwrap();
        let (_, retained, _) = e.admit_tcp(&unrelated.id, 1, peer(&k), "web", 10).unwrap();
        let mut smaller = spec(); smaller.services.clear();
        let revised = e.revise(&s.id, 1, smaller, Lifetime::UntilEnded, 10).unwrap();
        assert_eq!(revised.accepted_revision, Some(2));
        assert!(removed.is_cancelled()); assert!(!retained.is_cancelled());
        e.end(&s.id, 10).unwrap();
        assert!(!retained.is_cancelled());
        assert_eq!(e.snapshot(&unrelated.id, 10).unwrap().name, "alex-laptop-1");
        assert_eq!(offer(&e, peer(&k)).name, "alex-laptop");
    }

    #[test]
    fn ascending_stable_collision_labels_and_long_names() {
        let k = key();
        let e = AgreementEngine::new([7;32], vec!["alex-laptop".into()]);
        for n in 1..=3 {
            let s = offer(&e, peer(&k));
            assert_eq!(s.name, format!("alex-laptop-{n}"));
            accept(&e, &s, &k, 10);
            assert_eq!(e.snapshot(&s.id, 1000).unwrap().name, s.name);
        }
        assert_eq!(dns_label("  A_B..C!  "), "a-b-c");
        assert_eq!(dns_label("💻"), "device");
        let long = "a".repeat(80);
        let first = e.offer(peer(&k), &long, spec(), Lifetime::UntilEnded, 50, 10).unwrap();
        let second = e.offer(peer(&k), &long, spec(), Lifetime::UntilEnded, 50, 10).unwrap();
        assert_eq!(first.name.len(), 63); assert_eq!(second.name.len(), 63);
        assert!(second.name.ends_with("-1"));
    }

    #[test]
    fn concurrent_revision_and_revocation_are_linearized() {
        let e = Arc::new(engine()); let k = key(); let s = offer(&e, peer(&k)); accept(&e, &s, &k, 10);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let e = e.clone(); let barrier = barrier.clone(); let id = s.id.clone();
            jobs.push(std::thread::spawn(move || { barrier.wait(); e.revise(&id, 1, AccessSpec::default(), Lifetime::UntilEnded, 10) }));
        }
        barrier.wait();
        let outcomes: Vec<_> = jobs.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|r| **r == Err(AccessError::StaleRevision)).count(), 1);
        e.end(&s.id, 10).unwrap();
        assert_eq!(e.admit_tcp(&s.id, 2, peer(&k), "web", 10).err(), Some(AccessError::Ended));
    }

    #[test]
    fn concurrent_open_and_end_cannot_leave_a_live_permission() {
        let k = key(); let p = peer(&k);
        for _ in 0..32 {
            let e = Arc::new(engine()); let s = offer(&e,p); accept(&e,&s,&k,10);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let job = { let e=e.clone(); let id=s.id.clone(); let barrier=barrier.clone();
                std::thread::spawn(move || { barrier.wait(); e.admit_tcp(&id,1,p,"web",10) }) };
            barrier.wait(); e.end(&s.id,10).unwrap();
            match job.join().unwrap() {
                Ok((_,cancel,_)) => assert!(cancel.is_cancelled()),
                Err(error) => assert_eq!(error,AccessError::Ended),
            }
            assert_eq!(e.admit_tcp(&s.id,1,p,"web",10).err(),Some(AccessError::Ended));
        }
    }

    #[test]
    fn bounded_events_require_snapshot_reset_and_drop_revokes() {
        let e = engine(); let k = key(); let s = offer(&e, peer(&k)); accept(&e, &s, &k, 10);
        let (_, cancel, _) = e.admit_tcp(&s.id, 1, peer(&k), "web", 10).unwrap();
        for revision in 1..300 { e.revise(&s.id, revision, spec(), Lifetime::UntilEnded, 10).unwrap(); }
        let page = e.events(0, 10).unwrap();
        assert_eq!(page.events.len(), MAX_EVENTS); assert!(page.reset_required);
        assert!(!e.events(page.latest, 10).unwrap().reset_required);
        drop(e); assert!(cancel.is_cancelled());
    }

    #[cfg(all(feature="mount-server",target_os="linux"))]
    mod folders {
        use super::*;
        use crate::mount_proto::{MountOp,MountRequest,MountResponse,MountResult};
        use serde_json::Value;
        use tokio::sync::mpsc;

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let mut random=[0;16];getrandom::getrandom(&mut random).unwrap();
                let path=std::env::temp_dir().join(format!("access-folders-{}",hex::encode(random)));
                std::fs::create_dir(&path).unwrap(); Self(path)
            }
        }
        impl Drop for Fixture { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); } }
        struct Capture {
            controls:mpsc::UnboundedSender<Value>,frames:mpsc::UnboundedSender<Vec<u8>>,
            cut:Option<(Arc<AgreementEngine>,String)>,
        }
        #[async_trait::async_trait]
        impl filament_transport::net::Transport for Capture {
            async fn send_control(&self,msg:&Value)->anyhow::Result<()> { let _=self.controls.send(msg.clone());Ok(()) }
            async fn send_frame(&self,_:u32,_:u64,payload:&[u8])->anyhow::Result<()> {
                let _=self.frames.send(payload.to_vec());
                if let Some((engine,id))=&self.cut {
                    let (header,_)=crate::mount_proto::decode_frame(payload);
                    if serde_json::from_slice::<Value>(header).ok().is_some_and(|v|v["id"]==1) { engine.end(id,10).unwrap(); }
                }
                Ok(())
            }
            async fn flush(&self)->anyhow::Result<()> { Ok(()) }
            fn max_payload(&self)->usize { 65536 }
            fn is_dead(&self)->bool { false }
            fn is_alive(&self)->bool { true }
            fn as_any(&self)->&dyn std::any::Any { self }
        }
        fn transport(cut:Option<(Arc<AgreementEngine>,String)>)->(Arc<Capture>,mpsc::UnboundedReceiver<Value>,mpsc::UnboundedReceiver<Vec<u8>>) {
            let (controls,cr)=mpsc::unbounded_channel();let (frames,fr)=mpsc::unbounded_channel();
            (Arc::new(Capture{controls,frames,cut}),cr,fr)
        }
        async fn request(mux:&crate::l2::Mux,sid:u32,frames:&mut mpsc::UnboundedReceiver<Vec<u8>>,id:u64,op:MountOp)->MountResponse {
            request_data(mux,sid,frames,id,op).await.0
        }
        fn wire_op(mut op:MountOp)->MountOp {
            let encode=|path:&mut String|{*path=crate::mount_proto::path_encode(std::path::Path::new(path));};
            match &mut op {
                MountOp::GetAttr{path}|MountOp::ReadLink{path}|MountOp::Open{path,..}|MountOp::Create{path,..}
                |MountOp::Unlink{path}|MountOp::MkDir{path,..}|MountOp::RmDir{path}|MountOp::Truncate{path,..}=>encode(path),
                MountOp::Rename{from,to}=>{encode(from);encode(to);},
                _=>{},
            }op
        }
        async fn request_data(mux:&crate::l2::Mux,sid:u32,frames:&mut mpsc::UnboundedReceiver<Vec<u8>>,id:u64,op:MountOp)->(MountResponse,Option<Vec<u8>>) {
            let mut header=serde_json::to_vec(&MountRequest{id,bin:None,op:wire_op(op)}).unwrap();header.push(b'\n');
            mux.on_frame(sid,bytes::Bytes::from(header)).await;
            let response=tokio::time::timeout(std::time::Duration::from_secs(2),frames.recv()).await.unwrap().unwrap();
            let (header,data)=crate::mount_proto::decode_frame(&response);
            (serde_json::from_slice(header).unwrap(),data.map(|data|data.to_vec()))
        }
        fn agreement(e:&AgreementEngine,key:&Ed25519KeyPair,root:&std::path::Path,mode:FolderMode)->AgreementSnapshot {
            let spec=AccessSpec{folders:vec![FolderAccess::canonical("folder".into(),root,mode).unwrap()],..AccessSpec::default()};
            let s=e.offer(peer(key),"folder-host",spec,Lifetime::UntilEnded,50,10).unwrap();accept(e,&s,key,10);s
        }

        #[tokio::test]
        async fn folder_readonly_confines_and_root_substitution_cannot_redirect_active_share() {
            let fixture=Fixture::new();let root=fixture.0.join("root");std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("original"),b"private data").unwrap();
            let outside=fixture.0.join("outside");std::fs::write(&outside,b"outside secret").unwrap();
            std::os::unix::fs::symlink(&outside,root.join("escape")).unwrap();
            let e=Arc::new(engine());let k=key();let s=agreement(&e,&k,&root,FolderMode::ReadOnly);
            let (t,mut controls,mut frames)=transport(None);let mux=crate::l2::Mux::new(t,Arc::new(crate::host::NoHost));
            let sid=crate::l2::L2_SID_BASE|41;
            let serving={let e=e.clone();let id=s.id.clone();let mux=mux.clone();let p=peer(&k);
                tokio::spawn(async move{e.serve_folder(&id,1,p,"folder",sid,mux,Arc::new(crate::host::NoHost)).await})};
            let ack=controls.recv().await.unwrap();assert_eq!(ack["type"],"mount-open-ack");assert_eq!(ack["caps"]["max_write_size"],0);
            assert!(matches!(request(&mux,sid,&mut frames,1,MountOp::GetAttr{path:"original".into()}).await.result,MountResult::Ok(_)));
            let opened=request(&mux,sid,&mut frames,11,MountOp::Open{path:"original".into(),flags:libc::O_RDONLY}).await;
            let MountResult::Ok(opened)=opened.result else {panic!("read-only file open failed")};
            let (_,data)=request_data(&mux,sid,&mut frames,12,MountOp::Read{fh:opened["fh"].as_u64().unwrap(),offset:0,size:32}).await;
            assert_eq!(data.unwrap(),b"private data");
            for (id,op) in [
                (2,MountOp::Truncate{path:"original".into(),size:0}),
                (3,MountOp::Rename{from:"original".into(),to:"changed".into()}),
                (4,MountOp::Open{path:"escape".into(),flags:libc::O_RDONLY}),
                (5,MountOp::Open{path:"../outside".into(),flags:libc::O_RDONLY}),
            ] { assert!(matches!(request(&mux,sid,&mut frames,id,op).await.result,MountResult::Err(_))); }
            assert_eq!(std::fs::read(root.join("original")).unwrap(),b"private data");
            let moved=fixture.0.join("moved");std::fs::rename(&root,&moved).unwrap();std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("replacement-only"),b"wrong root").unwrap();
            assert!(matches!(request(&mux,sid,&mut frames,6,MountOp::GetAttr{path:"original".into()}).await.result,MountResult::Ok(_)));
            assert!(matches!(request(&mux,sid,&mut frames,7,MountOp::GetAttr{path:"replacement-only".into()}).await.result,MountResult::Err(_)));
            let other=crate::l2::L2_SID_BASE|42;let _other_rx=mux.register_stream(other).await.unwrap();
            e.end(&s.id,10).unwrap();assert_eq!(serving.await.unwrap(),Err(AccessError::Ended));
            assert!(!mux.has_stream(sid).await);assert!(mux.has_stream(other).await);mux.drop_stream(other).await;
        }

        #[tokio::test]
        async fn folder_writable_operations_work_but_cannot_escape_and_abort_reaps_task() {
            let fixture=Fixture::new();let root=fixture.0.join("root");std::fs::create_dir(&root).unwrap();
            let e=Arc::new(engine());let k=key();let s=agreement(&e,&k,&root,FolderMode::ReadWrite);
            let (t,mut controls,mut frames)=transport(None);let mux=crate::l2::Mux::new(t,Arc::new(crate::host::NoHost));
            let sid=crate::l2::L2_SID_BASE|43;
            let serving={let e=e.clone();let id=s.id.clone();let mux=mux.clone();let p=peer(&k);
                tokio::spawn(async move{e.serve_folder(&id,1,p,"folder",sid,mux,Arc::new(crate::host::NoHost)).await})};
            assert_eq!(controls.recv().await.unwrap()["type"],"mount-open-ack");
            let created=request(&mux,sid,&mut frames,1,MountOp::Create{path:"created".into(),mode:0o600,flags:libc::O_RDWR}).await;
            let MountResult::Ok(created)=created.result else{panic!("writable create failed")};
            let mut header=serde_json::to_vec(&MountRequest{id:11,bin:Some(true),op:MountOp::Write{fh:created["fh"].as_u64().unwrap(),offset:0,size:7}}).unwrap();header.push(b'\n');
            mux.on_frame(sid,bytes::Bytes::from(crate::mount_proto::encode_frame(&header,Some(b"written")))).await;
            let response=frames.recv().await.unwrap();
            let response:MountResponse=serde_json::from_slice(crate::mount_proto::decode_frame(&response).0).unwrap();
            assert!(matches!(response.result,MountResult::Ok(_)));
            assert_eq!(std::fs::read(root.join("created")).unwrap(),b"written");
            assert!(matches!(request(&mux,sid,&mut frames,2,MountOp::Rename{from:"created".into(),to:"renamed".into()}).await.result,MountResult::Ok(_)));
            assert!(root.join("renamed").exists());
            assert!(matches!(request(&mux,sid,&mut frames,3,MountOp::Rename{from:"renamed".into(),to:"../escape".into()}).await.result,MountResult::Err(_)));
            assert!(!fixture.0.join("escape").exists());
            serving.abort();assert!(serving.await.unwrap_err().is_cancelled());
            tokio::time::timeout(std::time::Duration::from_secs(2),async{while mux.has_stream(sid).await{tokio::task::yield_now().await;}}).await.unwrap();
            assert!(root.join("renamed").exists());
        }

        #[tokio::test]
        async fn buffered_requests_recheck_agreement_after_revoke_without_cadence_delay() {
            let fixture=Fixture::new();std::fs::write(fixture.0.join("keep"),b"never truncate").unwrap();
            let e=Arc::new(engine());let k=key();let s=agreement(&e,&k,&fixture.0,FolderMode::ReadWrite);
            let (_,cancel,_)=e.admit_folder(&s.id,1,peer(&k),"folder",10).unwrap();
            let (t,_controls,mut frames)=transport(Some((e.clone(),s.id.clone())));
            let (tx,rx)=mpsc::channel(4);
            let task=crate::mount_proto::spawn_mount_server_with_admission(crate::mount_proto::MountServerConfig{
                root:fixture.0.clone(),transport:t,sid:crate::l2::L2_SID_BASE|44,stream:rx,protocol_version:1,
                read_only:false,device_pub:None,host:Arc::new(crate::host::NoHost),log:Arc::new(crate::host::NoLog),
            },Some(Arc::new(move||if cancel.is_cancelled(){Err("agreement ended".into())}else{Ok(())})));
            let first=MountRequest{id:1,bin:None,op:wire_op(MountOp::GetAttr{path:"keep".into()})};
            let second=MountRequest{id:2,bin:None,op:wire_op(MountOp::Truncate{path:"keep".into(),size:0})};
            let third=MountRequest{id:3,bin:None,op:wire_op(MountOp::GetAttr{path:"keep".into()})};
            let mut batch=Vec::new();for req in [first,second,third]{batch.extend(serde_json::to_vec(&req).unwrap());batch.push(b'\n');}
            tx.send(Some(bytes::Bytes::from(batch))).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2),task).await.unwrap().unwrap();
            assert_eq!(std::fs::read(fixture.0.join("keep")).unwrap(),b"never truncate");
            let first:Value=serde_json::from_slice(crate::mount_proto::decode_frame(&frames.recv().await.unwrap()).0).unwrap();assert_eq!(first["id"],1);
            let second:Value=serde_json::from_slice(crate::mount_proto::decode_frame(&frames.recv().await.unwrap()).0).unwrap();assert_eq!(second["id"],2);assert_eq!(second["status"],"err");
            assert!(frames.try_recv().is_err());
            assert_eq!(e.snapshot(&s.id,10).unwrap().state,AgreementState::Ended);
        }

        #[cfg(feature="dispatch")]
        #[tokio::test]
        async fn authenticated_folder_async_reads_preserve_binary_bytes_over_same_mux_and_revoke() {
            use crate::send::ceremony::{Ceremony,Inbound,TemporaryBinding,TemporaryRole};
            use crate::mount_proto::{MountClient,path_encode,parse_mount_caps,DEFAULT_MOUNT_MAX_SIZE};
            use crate::driver::Cancellation;
            struct Bridge {
                peer:std::sync::Mutex<std::sync::Weak<crate::l2::Mux>>,
                controls:mpsc::UnboundedSender<Value>,
            }
            #[async_trait::async_trait]
            impl filament_transport::net::Transport for Bridge {
                async fn send_control(&self,v:&Value)->anyhow::Result<()> {
                    let _=self.controls.send(v.clone());
                    if v["type"]=="l2-close" {
                        let peer=self.peer.lock().unwrap().upgrade();
                        if let (Some(peer),Some(sid))=(peer,crate::l2::wire_sid(v)) { peer.on_close(sid,v["err"].as_str()).await; }
                    }Ok(())
                }
                async fn send_frame(&self,sid:u32,_:u64,payload:&[u8])->anyhow::Result<()> {
                    let peer=self.peer.lock().unwrap().upgrade().ok_or_else(||anyhow::anyhow!("peer mux closed"))?;
                    peer.on_frame(sid,bytes::Bytes::copy_from_slice(payload)).await;Ok(())
                }
                async fn flush(&self)->anyhow::Result<()> {Ok(())}
                fn max_payload(&self)->usize{65536}
                fn is_dead(&self)->bool{false}
                fn is_alive(&self)->bool{true}
                fn as_any(&self)->&dyn std::any::Any{self}
            }
            let fixture=Fixture::new();
            let expected:Vec<u8>=(0..DEFAULT_MOUNT_MAX_SIZE as usize*2+13).map(|n|(n%256)as u8).collect();
            std::fs::write(fixture.0.join("binary"),&expected).unwrap();std::fs::write(fixture.0.join("empty"),b"").unwrap();
            let hostkey=key();let hostpub=peer(&hostkey).public_key();let recipient=key();let recipientpub=peer(&recipient).public_key();
            let e=Arc::new(AgreementEngine::new(hostpub,Vec::new()));
            let scope=AccessSpec{folders:vec![FolderAccess::canonical("folder".into(),&fixture.0,FolderMode::ReadOnly).unwrap()],..AccessSpec::default()};
            let binding=TemporaryBinding::new(hostpub,&scope,Lifetime::UntilEnded,50).unwrap();
            let mut hostcer=Ceremony::new_temporary("folder fixture words","1234",binding.clone(),TemporaryRole::Host);
            let mut recipientcer=Ceremony::new_temporary("folder fixture words","1234",binding.clone(),TemporaryRole::Recipient);
            let hm=hostcer.msg_payload();let rm=recipientcer.msg_payload();hostcer.on_signal(&rm,None);recipientcer.on_signal(&hm,None);
            let hc=hostcer.take_confirm_payload("host-fp","recipient-fp").unwrap();let rc=recipientcer.take_confirm_payload("recipient-fp","host-fp").unwrap();
            assert!(matches!(hostcer.on_signal(&rc,Some(("host-fp","recipient-fp"))),Inbound::Consumed));
            assert!(matches!(recipientcer.on_signal(&hc,Some(("recipient-fp","host-fp"))),Inbound::Consumed));
            let msg=recipientcer.temporary_possession_message(recipientpub,hostpub).unwrap();
            let proven=hostcer.authenticate_temporary_peer(hostpub,recipientpub,recipient.sign(&msg).as_ref().try_into().unwrap()).unwrap();
            let s=e.offer_bound(proven,&binding,"folder-host",scope,Lifetime::UntilEnded,50,10).unwrap();
            let host_signature=hostkey.sign(&e.review_message(&s.id,1,10).unwrap()).as_ref().try_into().unwrap();
            let review=recipientcer.review_temporary_offer(s.clone(),host_signature,recipientpub,10).unwrap();
            e.accept(&s.id,1,proven,recipient.sign(&review.acceptance_message().unwrap()).as_ref().try_into().unwrap(),10).unwrap();

            let (control_tx,mut controls)=mpsc::unbounded_channel();
            let ht=Arc::new(Bridge{peer:std::sync::Mutex::new(std::sync::Weak::new()),controls:control_tx.clone()});
            let rt=Arc::new(Bridge{peer:std::sync::Mutex::new(std::sync::Weak::new()),controls:control_tx});
            let hmux=crate::l2::Mux::new(ht.clone(),Arc::new(crate::host::NoHost));let rmux=crate::l2::Mux::new(rt.clone(),Arc::new(crate::host::NoHost));
            *ht.peer.lock().unwrap()=Arc::downgrade(&rmux);*rt.peer.lock().unwrap()=Arc::downgrade(&hmux);
            let unrelated=crate::l2::L2_SID_BASE|50;let _unrelated_rx=rmux.register_stream(unrelated).await.unwrap();
            let sid=crate::l2::L2_SID_BASE|51;let sid2=crate::l2::L2_SID_BASE|52;
            let mut tasks=Vec::new();let mut clients=Vec::new();
            for sid in [sid,sid2] {
                let rx=rmux.register_stream(sid).await.unwrap();
                let engine=e.clone();let id=s.id.clone();let mux=hmux.clone();
                tasks.push(tokio::spawn(async move{engine.serve_folder(&id,1,proven,"folder",sid,mux,Arc::new(crate::host::NoHost)).await}));
                let ack=tokio::time::timeout(std::time::Duration::from_secs(2),controls.recv()).await.unwrap().unwrap();
                assert_eq!(ack["type"],"mount-open-ack");assert_eq!(ack["sid"],sid);
                let caps=parse_mount_caps(ack["caps"].clone()).unwrap();
                clients.push(MountClient::from_mux_v2_with_mode(rt.clone(),sid,rx,caps,review.snapshot().spec.folders[0].mode.clone()));
            }
            let mut second=clients.pop().unwrap();let mut first=clients.pop().unwrap();
            let open=|path:&str|MountOp::Open{path:path_encode(std::path::Path::new(path)),flags:libc::O_RDONLY};
            let opened=first.call(open("binary")).await.unwrap();let MountResult::Ok(opened)=opened.result else{panic!("open failed")};let fh=opened["fh"].as_u64().unwrap();
            let opened2=second.call(open("binary")).await.unwrap();let MountResult::Ok(opened2)=opened2.result else{panic!("second open failed")};let fh2=opened2["fh"].as_u64().unwrap();
            let stop=Cancellation::default();let timeout=std::time::Duration::from_secs(2);
            let (a,b)=tokio::join!(first.read_binary(fh,0,32,timeout,&stop),second.read_binary(fh2,20,32,timeout,&stop));
            assert_eq!(&a.unwrap()[..],&expected[..32]);assert_eq!(&b.unwrap()[..],&expected[20..52]);
            let mut received=Vec::new();
            loop {let chunk=first.read_binary(fh,received.len()as u64,DEFAULT_MOUNT_MAX_SIZE,timeout,&stop).await.unwrap();if chunk.is_empty(){break;}received.extend_from_slice(&chunk);}
            assert_eq!(received,expected);
            let empty=first.call(open("empty")).await.unwrap();let MountResult::Ok(empty)=empty.result else{panic!("empty open failed")};
            assert!(first.read_binary(empty["fh"].as_u64().unwrap(),0,DEFAULT_MOUNT_MAX_SIZE,timeout,&stop).await.unwrap().is_empty());
            assert!(first.call(MountOp::Truncate{path:path_encode(std::path::Path::new("binary")),size:0}).await.is_err());
            first.call(MountOp::Release{fh}).await.unwrap();
            e.end(&s.id,10).unwrap();for task in tasks{assert_eq!(task.await.unwrap(),Err(AccessError::Ended));}
            assert!(second.read_binary(fh2,0,1,timeout,&stop).await.is_err());
            assert!(rmux.has_stream(unrelated).await);rmux.drop_stream(unrelated).await;
            assert_eq!(std::fs::read(fixture.0.join("binary")).unwrap(),expected);
        }
    }

    #[cfg(all(feature = "forward-server", feature = "dispatch"))]
    #[tokio::test]
    async fn real_tcp_host_activation_and_live_end_close_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use crate::send::ceremony::{Ceremony, Inbound, TemporaryBinding, TemporaryRole};
        struct TcpHost;
        #[async_trait::async_trait]
        impl HostServices for TcpHost {
            fn now_secs(&self) -> u64 { 10 }
            fn settings_get_str(&self, _: &str) -> Option<String> { None }
            fn devices_load(&self) -> Vec<(String,String)> { vec![] }
            fn is_self_uid(&self, _: &str, _: Option<&str>) -> bool { false }
            fn rejoin_unwarned(&self) -> std::time::Duration { std::time::Duration::ZERO }
            fn relay_banner(&self) -> String { String::new() }
            fn relay_forbidden(&self) -> bool { false }
            fn channel_of(&self, _: &str) -> String { String::new() }
            fn roster_snapshot_json(&self) -> Option<String> { None }
            fn fleet_rv_present(&self) -> bool { false }
            async fn connect_local_stream(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
                tokio::net::TcpStream::connect((host, port)).await
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let host_key = key(); let host_pub = peer(&host_key).public_key();
        let e = Arc::new(AgreementEngine::new(host_pub, Vec::new())); let k = key();
        let scope = AccessSpec { services: vec![ServiceAccess { id: "echo".into(), target, protocol: ServiceProtocol::Tcp }], ..AccessSpec::default() };
        let binding = TemporaryBinding::new(host_pub, &scope, Lifetime::UntilEnded, 50).unwrap();
        let mut a = Ceremony::new_temporary("real test words", "1234", binding.clone(), TemporaryRole::Host);
        let mut b = Ceremony::new_temporary("real test words", "1234", binding.clone(), TemporaryRole::Recipient);
        let am = a.msg_payload(); let bm = b.msg_payload();
        a.on_signal(&bm,None); b.on_signal(&am,None);
        let ac = a.take_confirm_payload("host-fp","recipient-fp").unwrap();
        let bc = b.take_confirm_payload("recipient-fp","host-fp").unwrap();
        assert!(matches!(a.on_signal(&bc,Some(("host-fp","recipient-fp"))),Inbound::Consumed));
        assert!(matches!(b.on_signal(&ac,Some(("recipient-fp","host-fp"))),Inbound::Consumed));
        let possession = b.temporary_possession_message(peer(&k).public_key(), host_pub).unwrap();
        let proven = a.authenticate_temporary_peer(host_pub, peer(&k).public_key(), k.sign(&possession).as_ref().try_into().unwrap()).unwrap();
        let s = e.offer_bound(proven, &binding, "echo", scope, Lifetime::UntilEnded, 50, 10).unwrap();
        let review = b.review_temporary_offer(s.clone(), host_key.sign(&e.review_message(&s.id,1,10).unwrap()).as_ref().try_into().unwrap(),peer(&k).public_key(),10).unwrap();
        e.accept(&s.id,1,proven,k.sign(&review.acceptance_message().unwrap()).as_ref().try_into().unwrap(),10).unwrap();
        let (mut client, mut transport) = tokio::io::duplex(1024);
        let serving = { let e = e.clone(); let id = s.id.clone(); let p = peer(&k);
            tokio::spawn(async move { e.serve_tcp(&id, 1, p, "echo", &mut transport, &TcpHost).await }) };
        let (mut accepted, _) = listener.accept().await.unwrap();
        client.write_all(b"real scope").await.unwrap();
        let mut bytes = [0;10]; accepted.read_exact(&mut bytes).await.unwrap(); assert_eq!(&bytes, b"real scope");
        accepted.write_all(b"ok").await.unwrap();
        let mut reply = [0;2]; client.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"ok");
        e.end(&s.id, 10).unwrap();
        assert_eq!(serving.await.unwrap(), Err(AccessError::Ended));
        assert_eq!(accepted.read(&mut bytes).await.unwrap(), 0);
        assert_eq!(client.read(&mut reply).await.unwrap(), 0);
        // Unsupported host is not activation; no invented working endpoint.
        let s = e.offer(peer(&k), "echo", s.spec, Lifetime::UntilEnded, 50, 10).unwrap(); accept(&e, &s, &k, 10);
        let (_, mut stream) = tokio::io::duplex(64);
        assert_eq!(e.serve_tcp(&s.id, 1, peer(&k), "echo", &mut stream, &crate::host::NoHost).await, Err(AccessError::Unavailable));

        // The actual existing L2 mux is also exercised, not only a generic IO seam.
        struct Capture(tokio::sync::mpsc::UnboundedSender<serde_json::Value>, tokio::sync::mpsc::UnboundedSender<Vec<u8>>);
        #[async_trait::async_trait]
        impl filament_transport::net::Transport for Capture {
            async fn send_control(&self, msg: &serde_json::Value) -> anyhow::Result<()> { self.0.send(msg.clone()).unwrap(); Ok(()) }
            async fn send_frame(&self, _: u32, _: u64, payload: &[u8]) -> anyhow::Result<()> { self.1.send(payload.to_vec()).unwrap(); Ok(()) }
            async fn flush(&self) -> anyhow::Result<()> { Ok(()) }
            fn max_payload(&self) -> usize { 1024 }
            fn is_dead(&self) -> bool { false }
            fn is_alive(&self) -> bool { true }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }
        let (controls,mut control_rx) = tokio::sync::mpsc::unbounded_channel();
        let (frames,mut frame_rx) = tokio::sync::mpsc::unbounded_channel();
        let mux = crate::l2::Mux::new(Arc::new(Capture(controls,frames)),Arc::new(TcpHost));
        let sid = crate::l2::L2_SID_BASE | 9;
        let serving = { let e=e.clone(); let id=s.id.clone(); let mux=mux.clone();
            tokio::spawn(async move { e.serve_forward(&id,1,proven,"echo",sid,mux,10).await }) };
        let (mut socket,_) = listener.accept().await.unwrap();
        let ack = control_rx.recv().await.unwrap(); assert_eq!(ack["type"],"l2-open-ack");
        mux.on_frame(sid,bytes::Bytes::from_static(b"mux bytes")).await;
        let mut received=[0;9]; socket.read_exact(&mut received).await.unwrap(); assert_eq!(&received,b"mux bytes");
        socket.write_all(b"mux reply").await.unwrap();
        assert_eq!(frame_rx.recv().await.unwrap(),b"mux reply");
        e.end(&s.id,10).unwrap();
        assert_eq!(serving.await.unwrap(),Err(AccessError::Ended));
        assert_eq!(socket.read(&mut received).await.unwrap(),0);
        assert!(!mux.has_stream(sid).await);
        let close = control_rx.recv().await.unwrap(); assert_eq!(close["type"],"l2-close");
        // Cancellation of the embedding future also reaps pumps. Cleanup must
        // not remove another stream's SID on this same shared mux.
        let unrelated_sid = crate::l2::L2_SID_BASE | 10;
        let _unrelated_rx = mux.register_stream(unrelated_sid).await.unwrap();
        let next = e.offer(peer(&k),"echo",s.spec.clone(),Lifetime::UntilEnded,50,10).unwrap(); accept(&e,&next,&k,10);
        let aborted_sid = crate::l2::L2_SID_BASE | 11;
        let serving = { let e=e.clone(); let id=next.id.clone(); let mux=mux.clone();
            tokio::spawn(async move { e.serve_forward(&id,1,proven,"echo",aborted_sid,mux,10).await }) };
        let (mut socket,_) = listener.accept().await.unwrap();
        assert_eq!(control_rx.recv().await.unwrap()["type"],"l2-open-ack");
        serving.abort(); assert!(serving.await.unwrap_err().is_cancelled());
        assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(2),socket.read(&mut received)).await.unwrap().unwrap(),0);
        assert!(!mux.has_stream(aborted_sid).await);
        assert!(mux.has_stream(unrelated_sid).await);
        mux.drop_stream(unrelated_sid).await;
    }
}
