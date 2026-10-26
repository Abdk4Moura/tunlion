//! Existing-ceremony adapter for foreground temporary agreements. All authority
//! comes from the shared PAKE proof and AgreementEngine, never a device label.
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use filament_peerloop::access::{AccessSpec, AgreementEngine, AgreementSnapshot, AgreementState, AuthenticatedReview, Lifetime, ProvenPeer};
use filament_peerloop::l2::{Mux, OpenOutcome, serve_stream};
use filament_peerloop::send::ceremony::{Ceremony, TemporaryBinding, TemporaryRole};
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
    end_exchange: crate::access_end::Exchange,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    endpoints: Vec<Endpoint>,
    pending_opens: PendingOpens,
    folder_controls: Option<crate::folder_access::Controls>,
    folder_jobs: Vec<FolderJob>,
    terminal: Option<crate::terminal_access::TerminalJob>,
    /// The host's existing process/PTY primitives, composed once for this
    /// temporary session. `None` means this build/platform cannot serve a
    /// shell, and the endpoint refuses instead of advertising it.
    shell: Option<filament_peerloop::access_session::ShellRuntime>,
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
        session.shell = shell_runtime();
        Ok(session)
    }

    pub(crate) fn recipient(binding: TemporaryBinding) -> Self { Self::new(binding, TemporaryRole::Recipient) }

    fn new(binding: TemporaryBinding, role: TemporaryRole) -> Self {
        Self { binding, role, host_spec: None, claim_expires: 0, local: None, peer: None,
            engine: None, review: None, snapshot: None, sent_proof: false, mux: None,
            pending: Vec::new(), active: false, established: false, ended: false, proof_deadline: None, end_exchange: crate::access_end::Exchange::default(),
            tasks: Vec::new(), endpoints: Vec::new(), pending_opens: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())), controls: None,
            folder_controls: None, folder_jobs: Vec::new(), terminal: None, shell: None,
            stop_controls: Arc::new(AtomicBool::new(false)), review_cancel: Arc::new(AtomicBool::new(false)),
            review_thread: None, review_result: None }
    }

    pub(crate) fn ceremony(&self, password: &str, nameplate: &str) -> Ceremony {
        Ceremony::new_temporary(password, nameplate, self.binding.clone(), self.role)
    }

    pub(crate) fn is_active(&self) -> bool { self.established && !self.ended }

    pub(crate) fn poll_interval(&self) -> std::time::Duration {
        if self.terminal.is_some() { crate::terminal_access::POLL_ACTIVE }
        else if self.end_exchange.is_ending() { std::time::Duration::from_millis(100) }
        else { std::time::Duration::from_secs(2) }
    }

    fn mux(&mut self, conn: &crate::conn::Conn, pid: &str) -> Result<Arc<Mux>> {
        if let Some(mux) = &self.mux { return Ok(mux.clone()); }
        let transport = conn.transport_of(pid).ok_or_else(|| anyhow!("temporary transport unavailable"))?;
        let mux = Mux::new(transport, crate::host_impl::cli_host());
        self.mux = Some(mux.clone());
        Ok(mux)
    }

    pub(crate) async fn progress(&mut self, ceremony: &Ceremony, conn: &crate::conn::Conn, pid: &str) -> Result<bool> {
        if self.ended { return Ok(true); }
        if self.end_exchange.is_ending() { return Ok(self.advance_end().await); }
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
                let decline = json!({"type":"access-decline","v":1,
                    "id":review.snapshot().id,"revision":review.snapshot().revision});
                crate::ui::say(&format!("  Temporary access declined: {}", crate::access_ui::terminal_label(&error.to_string())));
                self.shutdown().await;
                mux.transport().send_control(&decline).await?;
                drain_final_control(&mux).await;
                self.ended = true;
                return Ok(true);
            }
            let signature = crate::overlay::overlay_sign_possession(&review.acceptance_message()?)?;
            mux.transport().send_control(&json!({"type":"access-accept","v":1,
                "id":review.snapshot().id,"revision":review.snapshot().revision,"signature":hex::encode(signature)})).await?;
            crate::ui::say("  Waiting for the host to activate this exact scope.");
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
                    self.shutdown().await;
                    self.end_exchange.begin_local(std::time::Instant::now());
                    crate::ui::say("  Temporary access ended here; waiting for peer acknowledgement.");
                    return Ok(self.advance_end().await);
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
        if self.active {
            while let Some(control) = self.folder_controls.as_mut().and_then(|controls| controls.try_request()) {
                match control {
                    crate::folder_access::Control::Folder(request) => {
                        let snapshot = self.snapshot.as_ref().ok_or_else(|| anyhow!("folder scope unavailable"))?;
                        if !snapshot.spec.folders.contains(&request.folder) || self.folder_jobs.len() >= 4 {
                            let _ = request.reply.send(Err("folder scope is no longer available or operation capacity reached".into()));
                            continue;
                        }
                        let (snapshot, mux, pending) = (snapshot.clone(), mux.clone(), self.pending_opens.clone());
                        let folder = request.folder.clone();
                        let cancel = filament_peerloop::driver::Cancellation::default();
                        let stopped = cancel.clone();
                        let task = tokio::spawn(async move {
                            let result = read_folder(&snapshot, &request, mux, pending, &stopped).await.map_err(|error| error.to_string());
                            let _ = request.reply.send(result);
                        });
                        self.folder_jobs.push(FolderJob { folder, cancel, task });
                    }
                    crate::folder_access::Control::Terminal { reply } => {
                        if self.terminal.is_some() {
                            let _ = reply.send(Err("a shared terminal is already open".into()));
                            continue;
                        }
                        let snapshot = self.snapshot.clone().ok_or_else(|| anyhow!("terminal scope unavailable"))?;
                        match crate::terminal_access::TerminalJob::begin(mux.clone(), &snapshot).await {
                            Ok(mut job) => { job.set_reply(reply); self.terminal = Some(job); },
                            Err(error) => { let _ = reply.send(Err(error.to_string())); },
                        }
                    }
                }
            }
        }
        if let Some(job) = self.terminal.as_mut() {
            if job.poll().await.is_some() { self.terminal = None; }
        }
        self.folder_jobs.retain(|job| !job.task.is_finished());
        self.tasks.retain(|task| !task.is_finished());
        Ok(false)
    }

    pub(crate) async fn control(&mut self, ceremony: &Ceremony, conn: &crate::conn::Conn, pid: &str, payload: Value) -> Result<()> {
        bound_control(&payload)?;
        let kind = payload["type"].as_str().unwrap_or("");
        if !supported_control(kind) {
            bail!("temporary access refused an unsupported control ({}); no standing grant exists", crate::access_ui::terminal_label(kind));
        }
        if ceremony.secret().is_none() {
            if self.pending.len() >= 4 { bail!("too many temporary controls before proof"); }
            self.pending.push(payload);
            return Ok(());
        }
        let local = *self.local.get_or_insert(crate::overlay::overlay_pubkey_bytes()?);
        let mux = self.mux(conn, pid)?;
        if let Some(message) = crate::access_end::Message::parse(kind) {
            version(&payload)?;
            if payload["id"].as_str() != Some(self.binding.offer_id.as_str()) { bail!("wrong temporary agreement"); }
            if message == crate::access_end::Message::End && !self.end_exchange.is_ending() {
                // Revoke/close before issuing a receipt. This also cancels an
                // in-progress scope review and any queued acceptance decision.
                self.shutdown().await;
            }
            self.end_exchange.receive(message, std::time::Instant::now());
            self.advance_end().await;
            return Ok(());
        }
        if self.end_exchange.is_ending() && kind != "l2-close" {
            // Late acceptance, offer, activation, or ack cannot restart scope.
            if kind == "access-open" {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) {
                    let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"temporary access ended"})).await;
                }
            }
            return Ok(());
        }
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
                self.folder_controls = None;
                if !review.snapshot().spec.shell { self.terminal = None; }
                self.folder_jobs.retain(|job| review.snapshot().spec.folders.contains(&job.folder));
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
                let snapshot = match engine.accept(id, revision, self.peer.ok_or_else(|| anyhow!("peer proof unavailable"))?,
                    signature(&payload)?, crate::identity::now_secs()) {
                    Ok(snapshot) => snapshot,
                    Err(filament_peerloop::access::AccessError::Ended | filament_peerloop::access::AccessError::Expired) => {
                        self.shutdown().await;
                        self.end_exchange.begin_local(std::time::Instant::now());
                        self.advance_end().await;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                };
                mux.transport().send_control(&json!({"type":"access-active","v":1,"id":snapshot.id,"revision":snapshot.revision})).await?;
                self.active = true;
                self.established = true;
                self.snapshot = Some(snapshot.clone());
                // The host's running controls print "Sharing with <name>" next;
                // a second "active" line here only repeated it.
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
                crate::ui::say(&format!("  \u{2713} Connected \u{b7} {}", crate::access_ui::lifetime_label_recipient(snapshot.lifetime)));
                reconcile_services(&mut self.endpoints, snapshot, mux.clone(), self.pending_opens.clone()).await?;
                let shell = snapshot.spec.shell;
                if !snapshot.spec.folders.is_empty() || shell {
                    self.folder_controls = Some(crate::folder_access::Controls::start(snapshot, shell));
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
                let engine = self.engine.as_ref().unwrap().clone();
                let peer = self.peer.ok_or_else(|| anyhow!("peer proof unavailable"))?;
                match payload["kind"].as_str().unwrap_or("tcp") {
                    "pty" => {
                        if payload["resume"].as_bool().unwrap_or(false) || payload["resume_from"].is_u64() {
                            mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"temporary pty does not support resume"})).await?;
                            return Ok(());
                        }
                        let Some(runtime) = self.shell.clone() else {
                            mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"pty is not available in this build"})).await?;
                            return Ok(());
                        };
                        let Some(backend) = runtime.pty.clone() else {
                            mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"pty is not available in this build"})).await?;
                            return Ok(());
                        };
                        let request = filament_peerloop::shell::admit::parse_pty_open_fields(&payload);
                        self.tasks.push(tokio::spawn(async move {
                            let result = engine.serve_pty(&id, revision, peer, sid, request,
                                mux.clone(), crate::host_impl::cli_host(), backend).await;
                            if let Err(error) = result {
                                let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;
                            }
                        }));
                    }
                    "shell" => {
                        #[cfg(feature = "exec-server")]
                        {
                            let Some(runtime) = self.shell.clone() else {
                                mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"exec shell is not available in this build"})).await?;
                                return Ok(());
                            };
                            let Some(process) = runtime.process.clone() else {
                                mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"exec shell is not available in this build"})).await?;
                                return Ok(());
                            };
                            let request = filament_peerloop::shell::exec::parse_exec_open(&payload)
                                .ok_or_else(|| anyhow!("invalid temporary shell request"))?;
                            self.tasks.push(tokio::spawn(async move {
                                let result = engine.serve_shell(&id, revision, peer, sid, request,
                                    mux.clone(), crate::host_impl::cli_host(), process, runtime.log).await;
                                if let Err(error) = result {
                                    let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;
                                }
                            }));
                        }
                        #[cfg(not(feature = "exec-server"))]
                        {
                            mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"exec shell is not available in this build"})).await?;
                        }
                    }
                    kind @ ("tcp" | "folder") => {
                        let resource = payload["resource"].as_str().filter(|id| id.len() <= 128)
                            .ok_or_else(|| anyhow!("invalid temporary resource ID"))?.to_string();
                        let folder = kind == "folder";
                        self.tasks.push(tokio::spawn(async move {
                            let result = if folder {
                                engine.serve_folder(&id, revision, peer, &resource, sid, mux.clone(), crate::host_impl::cli_host()).await
                            } else {
                                engine.serve_forward(&id, revision, peer, &resource, sid, mux.clone(), crate::identity::now_secs()).await
                            };
                            if let Err(error) = result {
                                let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;
                            }
                        }));
                    }
                    _ => {
                        mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"unsupported temporary resource kind"})).await?;
                    }
                }
            }
            "l2-open-ack" | "mount-open-ack" => {
                if self.role == TemporaryRole::Recipient {
                    if let (Some(snapshot), Some(sid)) = (self.snapshot.as_ref(), filament_peerloop::l2::wire_sid(&payload)) {
                        complete_open_ack(&mux, &self.pending_opens, snapshot, self.active, sid, &payload).await;
                    }
                }
            }
            "mount-cap-ack" if self.role == TemporaryRole::Host => {
                // Protocol acknowledgement only. The engine selected the exact
                // root/mode and already owns the same-Mux serving task.
            }
            "pty-open-ack" if self.role == TemporaryRole::Recipient => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) {
                    if self.terminal.as_ref().is_some_and(|job| job.sid() == sid) {
                        if let Some(waiter) = mux.take_open_ack(sid).await {
                            let _ = waiter.send(OpenOutcome::Opened(payload.clone()));
                        }
                    }
                }
            }
            "pty-resize" if self.role == TemporaryRole::Host => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) {
                    let cols = payload["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = payload["rows"].as_u64().unwrap_or(24) as u16;
                    mux.resize_pty(sid, cols, rows).await;
                }
            }
            "exec-open-ack" if self.role == TemporaryRole::Recipient => {
                // This adapter opens the interactive terminal form only; an
                // exec-class initiator open is not offered by this UI.
            }
            "exec-close" | "exec-alive-ack" if self.role == TemporaryRole::Recipient => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) {
                    mux.on_exec_initiator_frame(sid, payload.clone()).await;
                }
            }
            "exec-alive" | "exec-signal" if self.role == TemporaryRole::Host => {
                // A host serving the exec-class form gets the existing
                // heartbeat/signal path over this same authenticated Mux.
                if let (Some(sid), Some(message)) = (filament_peerloop::l2::wire_sid(&payload),
                    filament_peerloop::l2::mux::ExecCtl::from_frame(&payload)) {
                    let live = mux.exec_control(sid, message).await;
                    if live && message == filament_peerloop::l2::mux::ExecCtl::Alive {
                        let _ = mux.transport().send_control(&json!({"type":"exec-alive-ack","sid":sid})).await;
                    }
                }
            }
            "l2-close" => {
                if let Some(sid) = filament_peerloop::l2::wire_sid(&payload) { mux.on_close(sid, payload["err"].as_str()).await; }
            }
            // Transport liveness probe (see Conn::link_alive). It carries no
            // grant and is never answered with authority; ignoring it keeps a
            // long foreground folder/read session from being torn down.
            "ping" | "pong" => {}
            "access-decline" if self.role == TemporaryRole::Host => {
                version(&payload)?;
                if payload["id"].as_str() != Some(self.binding.offer_id.as_str()) { bail!("wrong temporary agreement"); }
                let revision = payload["revision"].as_u64().ok_or_else(|| anyhow!("missing temporary revision"))?;
                self.engine.as_ref().unwrap().decline(&self.binding.offer_id, revision, crate::identity::now_secs())?;
                self.shutdown().await;
                self.ended = true;
                crate::ui::say("  Temporary access declined by the other device.");
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
        self.terminal = None;
        self.folder_controls = None;
        self.folder_jobs.clear();
        if let Some(engine) = &self.engine { let _ = engine.end(&self.binding.offer_id, crate::identity::now_secs()); }
        self.endpoints.clear();
        if let Some(mux) = &self.mux { mux.shutdown_all().await; }
        let join_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        for mut task in self.tasks.drain(..) {
            if tokio::time::timeout_at(join_deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        self.active = false;
    }

    async fn advance_end(&mut self) -> bool {
        let transport = self.mux.as_ref().map(|mux| mux.transport());
        let connected = transport.as_ref().is_some_and(|transport| transport.is_alive() && !transport.is_dead());
        let step = self.end_exchange.poll(std::time::Instant::now(), connected);
        let mut failed = false;
        for message in step.messages {
            let Some(transport) = &transport else { failed = true; break; };
            let frame = json!({"type":message.wire(),"v":1,"id":self.binding.offer_id});
            if !matches!(tokio::time::timeout(std::time::Duration::from_secs(1), transport.send_control(&frame)).await, Ok(Ok(()))) {
                failed = true;
                break;
            }
        }
        let outcome = step.outcome.or_else(|| if failed {
            self.end_exchange.poll(std::time::Instant::now(), false).outcome
        } else { None });
        let Some(outcome) = outcome else { return false; };
        if !failed {
            if let Some(mux) = &self.mux { drain_final_control(mux).await; }
        }
        self.ended = true;
        match outcome {
            crate::access_end::Outcome::PeerAcknowledged => crate::ui::critical("  Temporary access ended · peer acknowledged."),
            crate::access_end::Outcome::Confirmed => crate::ui::critical("  Temporary access ended by the host."),
            crate::access_end::Outcome::TimedOut => crate::ui::critical("  Temporary access ended here; peer acknowledgement unavailable."),
            crate::access_end::Outcome::Disconnected => crate::ui::critical("  Temporary access ended here; peer disconnected before final receipt."),
        }
        true
    }

    fn stop_review(&mut self) {
        self.review_cancel.store(true, Ordering::Release);
        if let Some(thread) = self.review_thread.take() { let _ = thread.join(); }
        self.review_result = None;
    }
}

/// Compose the CLI's existing process primitive and platform PTY backend for
/// agreement-scoped shell serving. The PTY half is `CliPty` — the same backend
/// the standing receive loop uses — but this instance owns a fresh session map
/// for this foreground temporary agreement. The host match arm below calls
/// `AgreementEngine::serve_pty`/`serve_shell` directly, with the accepted
/// revision and proven peer; it never enters standing shell admission.
#[cfg(feature = "pty-server")]
fn shell_runtime() -> Option<filament_peerloop::access_session::ShellRuntime> {
    use filament_peerloop::access_session::ShellRuntime;
    if !crate::platform::temporary_shell_supported() {
        return None;
    }
    use filament_peerloop::recv::servers::shell::PtyBackend;
    let log: Arc<dyn filament_peerloop::host::LogSink> =
        Arc::new(filament_peerloop::host::NoLog);
    let sessions = crate::l2::PtySessions::new();
    let pty = Arc::new(crate::recv_ports::CliPty { sessions }) as Arc<dyn PtyBackend>;
    #[cfg(feature = "exec-server")]
    {
        Some(ShellRuntime::new(Arc::new(crate::exec_recv::CliExecProcess), log).with_pty(pty))
    }
    #[cfg(not(feature = "exec-server"))]
    {
        Some(ShellRuntime::pty_only(pty, log))
    }
}

#[cfg(not(feature = "pty-server"))]
fn shell_runtime() -> Option<filament_peerloop::access_session::ShellRuntime> { None }

impl Drop for Session {
    fn drop(&mut self) {
        self.stop_controls.store(true, Ordering::Release);
        self.stop_review();
        self.terminal = None;
        self.folder_controls = None;
        self.folder_jobs.clear();
        let _ = crossterm::terminal::disable_raw_mode();
        if let Some(engine) = &self.engine { let _ = engine.end(&self.binding.offer_id, crate::identity::now_secs()); }
        for task in &self.tasks { task.abort(); }
        self.endpoints.clear();
    }
}

fn supported_control(kind: &str) -> bool {
    kind.starts_with("access-")
        || matches!(kind, "l2-open-ack" | "l2-close" | "mount-open-ack" | "mount-cap-ack"
            | "pty-open-ack" | "pty-resize" | "exec-open-ack" | "exec-close"
            | "exec-alive" | "exec-alive-ack" | "exec-signal" | "ping" | "pong")
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

async fn drain_final_control(mux: &Arc<Mux>) {
    let transport = mux.transport();
    match tokio::time::timeout(std::time::Duration::from_secs(3), transport.drain_finish()).await {
        Ok(Ok(())) => {},
        Ok(Err(error)) => crate::ui::debug(&format!("temporary final-control drain failed: {}", crate::access_ui::terminal_label(&error.to_string()))),
        Err(_) => crate::ui::debug("temporary final-control drain timed out; local endpoints are closed"),
    }
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

struct FolderJob {
    folder: filament_peerloop::access::FolderAccess,
    cancel: filament_peerloop::driver::Cancellation,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for FolderJob { fn drop(&mut self) { self.cancel.cancel(); self.task.abort(); } }

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenKind { Tcp, Folder }
#[derive(Clone)]
struct PendingOpen { generation: u64, revision: u64, resource: String, kind: OpenKind }
type PendingOpens = Arc<tokio::sync::Mutex<BTreeMap<u32, PendingOpen>>>;

// A timed-out/aborted open cannot leave its waiter or SID available for a late
// ack. Generation-qualified cleanup cannot tear down a replacement stream.
struct OpenRegistration { mux: Arc<Mux>, pending: PendingOpens, sid: u32, generation: u64 }
impl Drop for OpenRegistration {
    fn drop(&mut self) {
        let (mux, pending, sid, generation) = (self.mux.clone(), self.pending.clone(), self.sid, self.generation);
        tokio::spawn(async move {
            let mut entries = pending.lock().await;
            if entries.get(&sid).is_some_and(|entry| entry.generation == generation) { entries.remove(&sid); }
            drop(entries);
            if mux.stream_generation(sid).await == Some(generation) {
                mux.drop_stream_if(sid, generation).await;
                let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid})).await;
            }
        });
    }
}

async fn complete_open_ack(mux: &Arc<Mux>, pending: &PendingOpens, snapshot: &AgreementSnapshot,
    active: bool, sid: u32, payload: &Value) -> bool {
    if !active || snapshot.state != AgreementState::Active || snapshot.accepted_revision != Some(snapshot.revision)
        || !filament_peerloop::l2::is_l2_sid(sid) { return false; }
    let mut entries = pending.lock().await;
    let Some(open) = entries.get(&sid) else { return false; };
    let in_scope = match open.kind {
        OpenKind::Tcp => payload["type"].as_str() == Some("l2-open-ack") && snapshot.spec.services.iter().any(|service| service.id == open.resource),
        OpenKind::Folder => payload["type"].as_str() == Some("mount-open-ack") && snapshot.spec.folders.iter().any(|folder| folder.id == open.resource),
    };
    if open.revision != snapshot.revision || !in_scope
        || mux.stream_generation(sid).await != Some(open.generation) { return false; }
    entries.remove(&sid);
    let Some(waiter) = mux.take_open_ack(sid).await else { return false; };
    // Unlike warm-forward probing, this path waits on an explicit oneshot, not
    // a pipe liveness marker. No marker or duplicate ack reaches user TCP data.
    waiter.send(OpenOutcome::Opened(payload.clone())).is_ok()
}

async fn read_folder(snapshot: &AgreementSnapshot, request: &crate::folder_access::Request,
    mux: Arc<Mux>, pending: PendingOpens, cancel: &filament_peerloop::driver::Cancellation) -> Result<crate::folder_access::Output> {
    let operation = async {
        let sid = mux.alloc_sid();
        let (pipe, generation) = mux.register_access_stream(sid).await.ok_or_else(|| anyhow!("folder stream capacity reached"))?;
        let _registration = OpenRegistration { mux: mux.clone(), pending: pending.clone(), sid, generation };
        pending.lock().await.insert(sid, PendingOpen { generation, revision: snapshot.revision, resource: request.folder.id.clone(), kind: OpenKind::Folder });
        let ack = mux.arm_open_ack(sid).await;
        mux.transport().send_control(&json!({"type":"access-open","v":1,"id":snapshot.id,
            "revision":snapshot.revision,"resource":request.folder.id,"kind":"folder","sid":sid})).await?;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), ack).await
            .map_err(|_| anyhow!("folder endpoint activation timed out"))?.map_err(|_| anyhow!("folder activation channel closed"))?;
        let frame = match outcome {
            OpenOutcome::Opened(frame) => frame,
            OpenOutcome::Refused(reason) => bail!("folder endpoint refused: {}", crate::access_ui::terminal_label(&reason)),
            OpenOutcome::ClosedWithoutAck => bail!("folder endpoint closed without activation"),
        };
        let caps = filament_peerloop::mount_proto::parse_mount_caps(frame["caps"].clone())?;
        if caps.protocol_version < 2 || caps.max_read_size == 0 { bail!("folder byte-preserving read is unavailable on this endpoint"); }
        let read_limit = caps.max_read_size.min(filament_peerloop::mount_proto::DEFAULT_MOUNT_MAX_SIZE);
        mux.transport().send_control(&json!({"type":"mount-cap-ack","sid":sid,"binary_frames":true})).await?;
        let mut client = filament_peerloop::mount_proto::MountClient::from_mux_v2_with_mode(
            mux.transport(), sid, pipe, caps, request.folder.mode.clone());
        crate::folder_access::perform(&mut client, request, cancel, read_limit).await
    };
    match cancel.run(operation).await {
        filament_peerloop::driver::DriverOutcome::Returned(result) => result,
        filament_peerloop::driver::DriverOutcome::Cancelled => bail!("folder operation cancelled; no local file was published"),
    }
}

async fn reconcile_services(endpoints: &mut Vec<Endpoint>, snapshot: &AgreementSnapshot, mux: Arc<Mux>, pending: PendingOpens) -> Result<()> {
    endpoints.retain(|endpoint| snapshot.spec.services.contains(&endpoint.service));
    for endpoint in endpoints.iter() { let _ = endpoint.revision.send(Some(snapshot.revision)); }
    for service in &snapshot.spec.services {
        if endpoints.iter().any(|endpoint| endpoint.service == *service) { continue; }
        if service.protocol != filament_peerloop::access::ServiceProtocol::Tcp {
            crate::ui::say(&format!("  Service {}: unavailable (unsupported protocol).", crate::access_ui::terminal_label(&service.id)));
            continue;
        }
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => { crate::ui::say(&format!("  Service {}: unavailable ({error}).", crate::access_ui::terminal_label(&service.id))); continue; }
        };
        let address = listener.local_addr()?;
        crate::ui::say(&format!("  \u{2713} {} is now at {address}", crate::access_ui::service_label(&service.target)));
        let id = snapshot.id.clone();
        let (revision_tx, revision_rx) = tokio::sync::watch::channel(Some(snapshot.revision));
        let resource = service.id.clone();
        let mux = mux.clone();
        let pending = pending.clone();
        let task = tokio::spawn(async move {
            let mut streams = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((socket, _)) = incoming else { break; };
                        let Some(revision) = *revision_rx.borrow() else { drop(socket); continue; };
                        if streams.len() >= 64 { drop(socket); continue; }
                        let (mux, id, resource, pending) = (mux.clone(), id.clone(), resource.clone(), pending.clone());
                        streams.spawn(async move {
                            let sid = mux.alloc_sid();
                            let Some((pipe, generation)) = mux.register_access_stream(sid).await else { return; };
                            let _registration = OpenRegistration { mux: mux.clone(), pending: pending.clone(), sid, generation };
                            pending.lock().await.insert(sid, PendingOpen { generation, revision, resource: resource.clone(), kind: OpenKind::Tcp });
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
                                    crate::ui::say(&format!("  Temporary service unavailable: {}", crate::access_ui::terminal_label(&reason)));
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
    fn liveness_and_scoped_acks_are_the_only_non_access_controls() {
        for kind in ["access-open", "access-active", "l2-open-ack", "l2-close", "mount-open-ack", "mount-cap-ack",
            "pty-open-ack", "pty-resize", "exec-open-ack", "exec-close", "exec-alive", "exec-alive-ack", "exec-signal", "ping", "pong"] {
            assert!(supported_control(kind), "{kind}");
        }
        for kind in ["", "l2-open", "mount-open", "pty-open", "exec-open", "pake-msg", "enrol-offer"] {
            assert!(!supported_control(kind), "{kind}");
        }
    }

    struct AckTransport;
    #[async_trait::async_trait]
    impl filament_transport::net::Transport for AckTransport {
        async fn send_control(&self, _: &Value) -> Result<()> { Ok(()) }
        async fn send_frame(&self, _: u32, _: u64, _: &[u8]) -> Result<()> { Ok(()) }
        async fn flush(&self) -> Result<()> { Ok(()) }
        fn max_payload(&self) -> usize { 1024 }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    fn ack_fixture() -> (Arc<Mux>, PendingOpens, AgreementSnapshot) {
        let mux = Mux::new(Arc::new(AckTransport), Arc::new(filament_peerloop::host::NoHost));
        let pending = Arc::new(tokio::sync::Mutex::new(BTreeMap::new()));
        let mut spec = AccessSpec::default();
        spec.services.push(filament_peerloop::access::ServiceAccess {
            id: "service-0".into(), target: "127.0.0.1:3000".parse().unwrap(),
            protocol: filament_peerloop::access::ServiceProtocol::Tcp,
        });
        let snapshot = AgreementSnapshot { id: "test-only-not-an-invitation".into(), revision: 1,
            peer: [2;32], host_peer: [1;32], name: "test".into(),
            relationship: filament_peerloop::access::Relationship::Temporary,
            spec, lifetime: Lifetime::UntilEnded, claim_expires_at: 100,
            state: AgreementState::Active, accepted_revision: Some(1) };
        (mux, pending, snapshot)
    }

    #[tokio::test]
    async fn temporary_ack_wakes_once_without_inserting_user_bytes() {
        let (mux, pending, snapshot) = ack_fixture();
        let sid = mux.alloc_sid();
        let (mut pipe, generation) = mux.register_access_stream(sid).await.unwrap();
        let ack = mux.arm_open_ack(sid).await;
        pending.lock().await.insert(sid, PendingOpen { generation, revision: 1, resource: "service-0".into(), kind: OpenKind::Tcp });
        let payload = json!({"type":"l2-open-ack","sid":sid});
        assert!(!complete_open_ack(&mux, &pending, &snapshot, false, sid, &payload).await, "inactive agreement acknowledged");
        assert!(complete_open_ack(&mux, &pending, &snapshot, true, sid, &payload).await);
        assert!(matches!(tokio::time::timeout(std::time::Duration::from_millis(50), ack).await.unwrap().unwrap(), OpenOutcome::Opened(_)));
        assert!(!complete_open_ack(&mux, &pending, &snapshot, true, sid, &payload).await, "duplicate acknowledgement");
        assert!(matches!(pipe.try_recv(), Err(mpsc::error::TryRecvError::Empty)), "liveness marker leaked into user pipe");
        mux.drop_stream_if(sid, generation).await;
    }

    #[tokio::test]
    async fn refusal_timeout_and_late_ack_cannot_resurrect_streams() {
        let (mux, pending, snapshot) = ack_fixture();
        let sid = mux.alloc_sid();
        let (_pipe, generation) = mux.register_access_stream(sid).await.unwrap();
        let ack = mux.arm_open_ack(sid).await;
        pending.lock().await.insert(sid, PendingOpen { generation, revision: 1, resource: "service-0".into(), kind: OpenKind::Tcp });
        mux.on_close(sid, Some("target refused")).await;
        assert!(matches!(ack.await.unwrap(), OpenOutcome::Refused(reason) if reason == "target refused"));
        let payload = json!({"type":"l2-open-ack","sid":sid});
        assert!(!complete_open_ack(&mux, &pending, &snapshot, true, sid, &payload).await);
        let (_pipe, next_generation) = mux.register_access_stream(sid).await.unwrap();
        let mut next_ack = mux.arm_open_ack(sid).await;
        assert!(!complete_open_ack(&mux, &pending, &snapshot, true, sid, &payload).await, "stale generation acknowledged replacement");
        assert!(matches!(next_ack.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
        assert!(tokio::time::timeout(std::time::Duration::from_millis(1), next_ack).await.is_err());
        mux.drop_stream_if(sid, next_generation).await;
        pending.lock().await.remove(&sid);
        assert!(!complete_open_ack(&mux, &pending, &snapshot, true, sid, &payload).await);
        assert_eq!(mux.live_streams().await, 0);
    }

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
