//! Existing-ceremony adapter for foreground temporary agreements. All authority
//! comes from the shared PAKE proof and AgreementEngine, never a device label.
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use filament_peerloop::access::{AccessSpec, AgreementEngine, AgreementSnapshot, AgreementState, AuthenticatedReview, Lifetime, ProvenPeer};
use filament_peerloop::l2::{Mux, OpenOutcome, serve_stream};
use filament_peerloop::send::ceremony::{Ceremony, TemporaryBinding, TemporaryRole};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::mpsc;

const MAX_CONTROL_BYTES: usize = 128 * 1024;

pub(crate) struct Session {
    binding: TemporaryBinding,
    role: TemporaryRole,
    host_spec: Option<AccessSpec>,
    claim_expires: u64,
    local: Option<[u8; 32]>,
    peer: Option<ProvenPeer>,
    engine: Option<Arc<AgreementEngine>>,
    review: Option<AuthenticatedReview>,
    snapshot: Option<AgreementSnapshot>,
    sent_proof: bool,
    mux: Option<Arc<Mux>>,
    pending: Vec<Value>,
    active: bool,
    established: bool,
    ended: bool,
    proof_deadline: Option<std::time::Instant>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    endpoints: Vec<Endpoint>,
    controls: Option<mpsc::Receiver<AgreementSnapshot>>,
    stop_controls: Arc<AtomicBool>,
    review_cancel: Arc<AtomicBool>,
    review_thread: Option<std::thread::JoinHandle<()>>,
    review_result: Option<std::sync::mpsc::Receiver<Result<()>>>,
}

impl Session {
    pub(crate) fn host(spec: AccessSpec) -> Result<Self> {
        let local = crate::overlay::overlay_pubkey_bytes()?;
        let claim_expires = crate::identity::now_secs().saturating_add(600);
        let binding = TemporaryBinding::new(local, &spec, Lifetime::UntilEnded, claim_expires)?;
        let mut session = Self::new(binding, TemporaryRole::Host);
        session.local = Some(local);
        session.host_spec = Some(spec);
        session.claim_expires = claim_expires;
        session.engine = Some(Arc::new(AgreementEngine::new(local, crate::devices_load().into_iter().map(|(name, _)| name))));
        Ok(session)
    }

    pub(crate) fn recipient(binding: TemporaryBinding) -> Self { Self::new(binding, TemporaryRole::Recipient) }

    fn new(binding: TemporaryBinding, role: TemporaryRole) -> Self {
        Self { binding, role, host_spec: None, claim_expires: 0, local: None, peer: None,
            engine: None, review: None, snapshot: None, sent_proof: false, mux: None,
            pending: Vec::new(), active: false, established: false, ended: false, proof_deadline: None,
            tasks: Vec::new(), endpoints: Vec::new(), controls: None,
            stop_controls: Arc::new(AtomicBool::new(false)), review_cancel: Arc::new(AtomicBool::new(false)),
            review_thread: None, review_result: None }
    }

    pub(crate) fn ceremony(&self, password: &str, nameplate: &str) -> Ceremony {
        Ceremony::new_temporary(password, nameplate, self.binding.clone(), self.role)
    }

    pub(crate) fn is_active(&self) -> bool { self.established && !self.ended }

    fn mux(&mut self, conn: &crate::conn::Conn, pid: &str) -> Result<Arc<Mux>> {
        if let Some(mux) = &self.mux { return Ok(mux.clone()); }
        let transport = conn.transport_of(pid).ok_or_else(|| anyhow!("temporary transport unavailable"))?;
        let mux = Mux::new(transport, crate::host_impl::cli_host());
        self.mux = Some(mux.clone());
        Ok(mux)
    }

    pub(crate) async fn progress(&mut self, ceremony: &Ceremony, conn: &crate::conn::Conn, pid: &str) -> Result<bool> {
        if self.ended { return Ok(true); }
        if self.mux.as_ref().is_some_and(|mux| mux.transport().is_dead()) {
            self.shutdown().await;
            bail!("temporary transport disconnected; reconnect is unavailable in this build; no replacement code or permanent contact was created");
        }
        if ceremony.secret().is_none() || conn.transport_of(pid).is_none() { return Ok(false); }
        if !self.established {
            let deadline = self.proof_deadline.get_or_insert_with(|| std::time::Instant::now() + std::time::Duration::from_secs(120));
            if std::time::Instant::now() > *deadline { bail!("temporary proof or scope acceptance timed out; no permanent contact was created"); }
        }
        let local = *self.local.get_or_insert(crate::overlay::overlay_pubkey_bytes()?);
        let mux = self.mux(conn, pid)?;
        let pending = std::mem::take(&mut self.pending);
        for payload in pending { self.control(ceremony, conn, pid, payload).await?; }
        if !self.sent_proof && (self.role == TemporaryRole::Recipient || self.peer.is_some()) {
            let remote = self.peer.map(ProvenPeer::public_key).unwrap_or(self.binding.host_peer);
            let bytes = ceremony.temporary_possession_message(local, remote)?;
            let signature = crate::overlay::overlay_sign_possession(&bytes)?;
            let payload = ceremony.temporary_proof_payload(local, remote, signature)?;
            mux.transport().send_control(&payload).await?;
            self.sent_proof = true;
        }
        let decision = self.review_result.as_ref().and_then(|result| result.try_recv().ok());
        if let Some(decision) = decision {
            self.review_result = None;
            if let Some(thread) = self.review_thread.take() { let _ = thread.join(); }
            let review = self.review.as_ref().ok_or_else(|| anyhow!("scope review unavailable"))?;
            if let Err(error) = decision {
                mux.transport().send_control(&json!({"type":"access-decline","v":1,
                    "id":review.snapshot().id,"revision":review.snapshot().revision})).await?;
                eprintln!("  Temporary access declined: {}", crate::access_ui::terminal_label(&error.to_string()));
                self.shutdown().await;
                self.ended = true;
                return Ok(true);
            }
            let signature = crate::overlay::overlay_sign_possession(&review.acceptance_message()?)?;
            mux.transport().send_control(&json!({"type":"access-accept","v":1,
                "id":review.snapshot().id,"revision":review.snapshot().revision,"signature":hex::encode(signature)})).await?;
            eprintln!("  Waiting for the host to activate this exact scope.");
        }
        if self.role == TemporaryRole::Host && self.peer.is_some() && self.snapshot.is_none() {
            let engine = self.engine.as_ref().unwrap();
            let spec = self.host_spec.take().ok_or_else(|| anyhow!("temporary scope unavailable"))?;
            let label = conn.link(pid).map(|link| link.name.as_str()).unwrap_or("device");
            let snapshot = engine.offer_bound(self.peer.unwrap(), &self.binding, label, spec,
                Lifetime::UntilEnded, self.claim_expires, crate::identity::now_secs())?;
            send_review(engine, &snapshot, &mux).await?;
            self.snapshot = Some(snapshot);
        }
        if let Some(engine) = &self.engine {
            if self.active {
                let snapshot = engine.snapshot(&self.binding.offer_id, crate::identity::now_secs())?;
                if matches!(snapshot.state, AgreementState::Ended | AgreementState::Expired | AgreementState::Declined) {
                    mux.transport().send_control(&json!({"type":"access-end","v":1,"id":snapshot.id})).await?;
                    self.shutdown().await;
                    eprintln!("  Temporary access ended.");
                    return Ok(true);
                }
            }
        }
        if let Some(controls) = &mut self.controls {
            while let Ok(snapshot) = controls.try_recv() {
                if let Some(engine) = &self.engine {
                    if !matches!(snapshot.state, AgreementState::Ended | AgreementState::Expired | AgreementState::Declined) {
                        send_review(engine, &snapshot, &mux).await?;
                    }
                }
                self.snapshot = Some(snapshot);
            }
        }
        self.tasks.retain(|task| !task.is_finished());
        Ok(false)
    }

    pub(crate) async fn control(&mut self, ceremony: &Ceremony, conn: &crate::conn::Conn, pid: &str, payload: Value) -> Result<()> {
        bound_control(&payload)?;
        let kind = payload["type"].as_str().unwrap_or("");
        if !kind.starts_with("access-") && !matches!(kind, "l2-open-ack" | "l2-close") {
            bail!("temporary access refused an unsupported control; no standing grant exists");
        }
        if ceremony.secret().is_none() {
            if self.pending.len() >= 4 { bail!("too many temporary controls before proof"); }
            self.pending.push(payload);
            return Ok(());
        }
        let local = *self.local.get_or_insert(crate::overlay::overlay_pubkey_bytes()?);
        let mux = self.mux(conn, pid)?;
        match kind {
            "access-possession" => {
                let peer = ceremony.authenticate_temporary_payload(local, &payload)?;
                if self.peer.is_some_and(|previous| previous.public_key() != peer.public_key()) {
                    bail!("temporary peer changed during authentication");
                }
                self.peer = Some(peer);
            }
            "access-offer" if self.role == TemporaryRole::Recipient => {
                if self.peer.is_none() { bail!("temporary offer arrived before peer proof"); }
                version(&payload)?;
                bound_snapshot(&payload["snapshot"])?;
                let snapshot: AgreementSnapshot = serde_json::from_value(payload["snapshot"].clone())?;
                let signature = signature(&payload)?;
                let review = match &self.review {
                    Some(previous) => previous.review_revision(snapshot, signature, crate::identity::now_secs())?,
                    None => ceremony.review_temporary_offer(snapshot, signature, local, crate::identity::now_secs())?,
                };
                self.endpoints.retain(|endpoint| review.snapshot().spec.services.contains(&endpoint.service));
                // Pause only new local opens while the new signed scope is
                // reviewed. Retained active streams survive a narrowing.
                for endpoint in &self.endpoints { let _ = endpoint.revision.send(None); }
                self.active = false;
                self.stop_review();
                self.review_cancel = Arc::new(AtomicBool::new(false));
                let stop = self.review_cancel.clone();
                let snapshot = review.snapshot().clone();
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                self.review_thread = Some(std::thread::spawn(move || {
                    let result = crate::access_ui::review_offer(&snapshot, &stop);
                    let _ = tx.send(result);
                }));
                self.review_result = Some(rx);
                self.snapshot = Some(review.snapshot().clone());
                self.review = Some(review);
            }
            "access-accept" if self.role == TemporaryRole::Host => {
                version(&payload)?;
                let id = payload["id"].as_str().filter(|id| *id == self.binding.offer_id)
                    .ok_or_else(|| anyhow!("wrong temporary agreement"))?;
                let revision = payload["revision"].as_u64().ok_or_else(|| anyhow!("missing temporary revision"))?;
                let engine = self.engine.as_ref().unwrap();
                let snapshot = engine.accept(id, revision, self.peer.ok_or_else(|| anyhow!("peer proof unavailable"))?,
                    signature(&payload)?, crate::identity::now_secs())?;
                mux.transport().send_control(&json!({"type":"access-active","v":1,"id":snapshot.id,"revision":snapshot.revision})).await?;
                self.active = true;
                self.established = true;
                self.snapshot = Some(snapshot.clone());
                eprintln!("  Temporary access active · {} · {}", crate::access_ui::terminal_label(&snapshot.name), crate::access_ui::lifetime_label(snapshot.lifetime));
                if self.controls.is_none() {
                    let (tx, rx) = mpsc::channel(4);
                    self.controls = Some(rx);
                    crate::access_ui::spawn_host_controls(engine.clone(), snapshot.id, self.stop_controls.clone(), tx);
                }
            }
            "access-active" if self.role == TemporaryRole::Recipient => {
                version(&payload)?;
                let snapshot = self.snapshot.as_mut().ok_or_else(|| anyhow!("activation without accepted review"))?;
                if payload["id"].as_str() != Some(snapshot.id.as_str()) || payload["revision"].as_u64() != Some(snapshot.revision) {
                    bail!("activation does not match the accepted temporary scope");
                }
                if self.active { return Ok(()); }
                snapshot.state = AgreementState::Active;
                snapshot.accepted_revision = Some(snapshot.revision);
                self.active = true;
                self.established = true;
                eprintln!("  Temporary access active · {} · {}", crate::access_ui::terminal_label(&snapshot.name), crate::access_ui::lifetime_label(snapshot.lifetime));
                reconcile_services(&mut self.endpoints, snapshot, mux.clone()).await?;
                for folder in &snapshot.spec.folders {
                    eprintln!("  Folder {}: unavailable (scoped folder endpoint is not integrated).", crate::access_ui::terminal_label(&folder.id));
                }
            }
            "access-open" if self.role == TemporaryRole::Host => {
                version(&payload)?;
                let sid = filament_peerloop::l2::wire_sid(&payload).ok_or_else(|| anyhow!("invalid temporary stream ID"))?;
                if !self.active {
                    mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"temporary scope not accepted"})).await?;
                    return Ok(());
                }
                if self.tasks.len() >= 8 {
                    mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"temporary stream capacity reached"})).await?;
                    return Ok(());
                }
                let id = payload["id"].as_str().filter(|id| *id == self.binding.offer_id)
                    .ok_or_else(|| anyhow!("wrong temporary agreement"))?.to_string();
                let revision = payload["revision"].as_u64().ok_or_else(|| anyhow!("missing temporary revision"))?;
                let resource = payload["resource"].as_str().filter(|id| id.len() <= 128)
                    .ok_or_else(|| anyhow!("invalid temporary resource ID"))?.to_string();
                let engine = self.engine.as_ref().unwrap().clone();
                let peer = self.peer.ok_or_else(|| anyhow!("peer proof unavailable"))?;
                self.tasks.push(tokio::spawn(async move {
                    if let Err(error) = engine.serve_forward(&id, revision, peer, &resource, sid, mux.clone(), crate::identity::now_secs()).await {
                        let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;
                    }
                }));
            }
            "l2-open-ack" => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) { mux.on_open_ack(sid).await; }
            }
            "l2-close" => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) { mux.on_close(sid, payload["err"].as_str()).await; }
            }
            "access-decline" if self.role == TemporaryRole::Host => {
                version(&payload)?;
                if payload["id"].as_str() != Some(self.binding.offer_id.as_str()) { bail!("wrong temporary agreement"); }
                let revision = payload["revision"].as_u64().ok_or_else(|| anyhow!("missing temporary revision"))?;
                self.engine.as_ref().unwrap().decline(&self.binding.offer_id, revision, crate::identity::now_secs())?;
                self.shutdown().await;
                self.ended = true;
                eprintln!("  Temporary access declined by the other device.");
            }
            "access-end" => {
                version(&payload)?;
                if payload["id"].as_str() != Some(self.binding.offer_id.as_str()) { bail!("wrong temporary agreement"); }
                self.shutdown().await;
                self.ended = true;
                eprintln!("  Temporary access ended by the host.");
            }
            _ => bail!("temporary access control is unavailable or invalid"),
        }
        Ok(())
    }

    pub(crate) async fn chunk(&mut self, sid: u32, data: Bytes) {
        if let Some(mux) = &self.mux { mux.on_frame(sid, data).await; }
    }

    pub(crate) async fn shutdown(&mut self) {
        self.stop_controls.store(true, Ordering::Release);
        self.stop_review();
        if let Some(engine) = &self.engine { let _ = engine.end(&self.binding.offer_id, crate::identity::now_secs()); }
        self.endpoints.clear();
        if let Some(mux) = &self.mux { mux.shutdown_all().await; }
        for mut task in self.tasks.drain(..) {
            if tokio::time::timeout(std::time::Duration::from_secs(1), &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        self.active = false;
    }

    fn stop_review(&mut self) {
        self.review_cancel.store(true, Ordering::Release);
        if let Some(thread) = self.review_thread.take() { let _ = thread.join(); }
        self.review_result = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop_controls.store(true, Ordering::Release);
        self.stop_review();
        let _ = crossterm::terminal::disable_raw_mode();
        if let Some(engine) = &self.engine { let _ = engine.end(&self.binding.offer_id, crate::identity::now_secs()); }
        for task in &self.tasks { task.abort(); }
        self.endpoints.clear();
    }
}

fn version(payload: &Value) -> Result<()> {
    if payload["v"].as_u64() != Some(1) { bail!("unsupported temporary access version"); }
    Ok(())
}

fn signature(payload: &Value) -> Result<[u8; 64]> {
    let encoded = payload["signature"].as_str().filter(|value| value.len() == 128)
        .ok_or_else(|| anyhow!("invalid temporary signature"))?;
    hex::decode(encoded)?.try_into().map_err(|_| anyhow!("invalid temporary signature"))
}

async fn send_review(engine: &AgreementEngine, snapshot: &AgreementSnapshot, mux: &Arc<Mux>) -> Result<()> {
    let bytes = engine.review_message(&snapshot.id, snapshot.revision, crate::identity::now_secs())?;
    let signature = crate::overlay::overlay_sign_possession(&bytes)?;
    mux.transport().send_control(&json!({"type":"access-offer","v":1,"snapshot":snapshot,"signature":hex::encode(signature)})).await?;
    Ok(())
}

struct Endpoint {
    service: filament_peerloop::access::ServiceAccess,
    revision: tokio::sync::watch::Sender<Option<u64>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Endpoint { fn drop(&mut self) { self.task.abort(); } }

async fn reconcile_services(endpoints: &mut Vec<Endpoint>, snapshot: &AgreementSnapshot, mux: Arc<Mux>) -> Result<()> {
    endpoints.retain(|endpoint| snapshot.spec.services.contains(&endpoint.service));
    for endpoint in endpoints.iter() { let _ = endpoint.revision.send(Some(snapshot.revision)); }
    for service in &snapshot.spec.services {
        if endpoints.iter().any(|endpoint| endpoint.service == *service) { continue; }
        if service.protocol != filament_peerloop::access::ServiceProtocol::Tcp {
            eprintln!("  Service {}: unavailable (unsupported protocol).", crate::access_ui::terminal_label(&service.id));
            continue;
        }
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => { eprintln!("  Service {}: unavailable ({error}).", crate::access_ui::terminal_label(&service.id)); continue; }
        };
        let address = listener.local_addr()?;
        eprintln!("  Local service {} at {address} -> {}", crate::access_ui::terminal_label(&service.id), service.target);
        let id = snapshot.id.clone();
        let (revision_tx, revision_rx) = tokio::sync::watch::channel(Some(snapshot.revision));
        let resource = service.id.clone();
        let mux = mux.clone();
        let task = tokio::spawn(async move {
            let mut streams = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((socket, _)) = incoming else { break; };
                        let Some(revision) = *revision_rx.borrow() else { drop(socket); continue; };
                        if streams.len() >= 64 { drop(socket); continue; }
                        let (mux, id, resource) = (mux.clone(), id.clone(), resource.clone());
                        streams.spawn(async move {
                            let sid = mux.alloc_sid();
                            let Some(pipe) = mux.register_stream(sid).await else { return; };
                            let ack = mux.arm_open_ack(sid).await;
                            if mux.transport().send_control(&json!({"type":"access-open","v":1,"id":id,"revision":revision,"resource":resource,"sid":sid})).await.is_err() {
                                mux.drop_stream(sid).await;
                                return;
                            }
                            match tokio::time::timeout(std::time::Duration::from_secs(10), ack).await {
                                Ok(Ok(OpenOutcome::Opened(_))) => serve_stream(mux, sid, socket, pipe, true, None, None).await,
                                outcome => {
                                    let reason = match outcome {
                                        Ok(Ok(OpenOutcome::Refused(reason))) => reason,
                                        Ok(Ok(OpenOutcome::ClosedWithoutAck)) => "host closed without activation".into(),
                                        _ => "host did not acknowledge activation".into(),
                                    };
                                    eprintln!("  Temporary service unavailable: {}", crate::access_ui::terminal_label(&reason));
                                    mux.drop_stream(sid).await;
                                }
                            }
                        });
                    }
                    _ = streams.join_next(), if !streams.is_empty() => {}
                }
            }
        });
        endpoints.push(Endpoint { service: service.clone(), revision: revision_tx, task });
    }
    Ok(())
}

fn bound_control(value: &Value) -> Result<()> {
    fn visit(value: &Value, remaining: &mut usize, depth: usize) -> bool {
        if depth > 32 { return false; }
        let size = match value { Value::String(text) => text.len(), Value::Object(_) | Value::Array(_) => 1, _ => 32 };
        let Some(left) = remaining.checked_sub(size) else { return false; };
        *remaining = left;
        match value {
            Value::Array(values) => values.iter().all(|value| visit(value, remaining, depth + 1)),
            Value::Object(values) => values.iter().all(|(key, value)| {
                let Some(left) = remaining.checked_sub(key.len()) else { return false; };
                *remaining = left;
                visit(value, remaining, depth + 1)
            }),
            _ => true,
        }
    }
    let mut remaining = MAX_CONTROL_BYTES;
    if !visit(value, &mut remaining, 0) { bail!("temporary control exceeds size or nesting limit"); }
    Ok(())
}

fn bound_snapshot(snapshot: &Value) -> Result<()> {
    let folders = snapshot["spec"]["folders"].as_array().ok_or_else(|| anyhow!("missing folders"))?;
    let services = snapshot["spec"]["services"].as_array().ok_or_else(|| anyhow!("missing services"))?;
    if folders.len().saturating_add(services.len()) > 64 { bail!("too many temporary resources"); }
    for resource in folders.iter().chain(services) {
        if resource["id"].as_str().is_none_or(|id| id.is_empty() || id.len() > 128) { bail!("invalid temporary resource ID"); }
    }
    for folder in folders {
        if folder["path"].as_str().is_none_or(|path| path.len() > 4096) { bail!("invalid temporary folder path"); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_bounded_before_typed_snapshot_allocation() {
        assert!(bound_control(&json!({"type":"access-open","id":"x","resource":"service-0","sid":2147483648u64})).is_ok());
        assert!(bound_control(&json!({"data":"x".repeat(MAX_CONTROL_BYTES + 1)})).is_err());
        let mut nested = Value::Null;
        for _ in 0..34 { nested = Value::Array(vec![nested]); }
        assert!(bound_control(&nested).is_err());
        let resource = json!({"id":"f","path":"/tmp"});
        assert!(bound_snapshot(&json!({"spec":{"folders":vec![resource.clone();65],"services":[]}})).is_err());
        assert!(bound_snapshot(&json!({"spec":{"folders":[{"id":"f","path":"x".repeat(4097)}],"services":[]}})).is_err());
        assert!(bound_snapshot(&json!({"spec":{"folders":[resource],"services":[]}})).is_ok());
    }

    #[test]
    fn signatures_and_versions_do_not_accept_ambiguous_inputs() {
        assert!(version(&json!({"v":1})).is_ok());
        for value in [json!({}), json!({"v":"1"}), json!({"v":2})] { assert!(version(&value).is_err()); }
        assert!(signature(&json!({"signature":"00".repeat(64)})).is_ok());
        for value in ["00".repeat(65), "00".repeat(63), "gg".repeat(64)] {
            assert!(signature(&json!({"signature":value})).is_err());
        }
    }
}
