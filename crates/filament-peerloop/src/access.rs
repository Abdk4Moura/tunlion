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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolderMode { ReadOnly, ReadWrite }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderAccess {
    pub id: String,
    pub path: PathBuf,
    pub mode: FolderMode,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessError {
    NotFound, InvalidSpec, Capacity, StaleRevision, NotAccepted, Ended,
    Expired, WrongPeer, InvalidProof, Unsupported, Unavailable, Poisoned,
}
impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "access: {self:?}") }
}
impl std::error::Error for AccessError {}

struct Operation { resource: ServiceAccess, cancel: Cancellation }
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
pub struct ProvenPeer([u8; 32]);
impl ProvenPeer {
    pub fn from_conn(conn: &crate::conn::Conn, pid: &str) -> Result<Self, AccessError> {
        let link = conn.link(pid).ok_or(AccessError::WrongPeer)?;
        if !link.trusted { return Err(AccessError::InvalidProof); }
        link.identity_device_pub.map(Self).ok_or(AccessError::InvalidProof)
    }
    pub fn public_key(self) -> [u8; 32] { self.0 }
}

impl AgreementEngine {
    pub fn new(local_peer: [u8; 32], remembered_names: impl IntoIterator<Item = String>) -> Self {
        Self { state: Arc::new(Mutex::new(State {
            names: remembered_names.into_iter().map(|s| dns_label(&s)).collect(),
            ..State::default()
        })), local_peer }
    }

    /// `peer` must come from an authenticated PAKE/proven-link result, not a label.
    /// The host never treats possession of the returned ID as authentication.
    pub fn offer(&self, peer: ProvenPeer, label: &str, spec: AccessSpec, lifetime: Lifetime,
                 claim_expires_at: u64, now: u64) -> Result<AgreementSnapshot, AccessError> {
        spec.validate()?;
        if lifetime.expired(now) || claim_expires_at <= now { return Err(AccessError::Expired); }
        let mut random = [0; 32];
        getrandom::getrandom(&mut random).map_err(|_| AccessError::Unavailable)?;
        let id = hex::encode(random);
        let mut state = self.state.lock().map_err(|_| AccessError::Poisoned)?;
        state.expire(now);
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
            let keep = narrowed && lifetime == a.snapshot.lifetime && spec.services.contains(&op.resource) && !op.cancel.is_cancelled();
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
        a.operations.push(Operation { resource: service.clone(), cancel: cancel.clone() });
        Ok((service, cancel, a.snapshot.lifetime))
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
