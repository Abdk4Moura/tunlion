//! Plain code pairing over the LAN: the server-independent carrier.
//!
//! This is deliberately narrower than the signaling `pair` command. It carries
//! only the plain pairing result: a mutual pair secret, `transfer` capability,
//! and (when the peer holds one) its existing device certificate as evidence.
//! It never loads the owner key, never issues a certificate and never answers
//! an enrolment offer. Owner enrolment is a separate, reviewed feature.
//!
//! The ceremony is the same `Ceremony` the signaling path uses. Its confirmation
//! MAC is bound to this QUIC session through the `filament-pair-v1` exporter and
//! to a role suffix, so a replay on another session or the other role fails.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use filament_transport::lan::{
    pair_read, pair_write, LanService, Options, PairLink, PAIR_MAX_FRAME,
};

use crate::identity::{self, DeviceCert};
use crate::pake_ceremony::{pair_v2_caps, Ceremony, Inbound as PakeInbound};
use crate::pair_code::{Begin, Carrier, PairCode, CODE_TTL};
use crate::ui;

const FRAME_TYPES: &[&str] = &[
    "pake-msg",
    "pake-confirm",
    "identity-expose",
    "identity-expose-ack",
    "pair-name",
];

/// What a confirmed LAN ceremony hands to the coordinator. The coordinator is
/// the only place that confirms the code and stores the record.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub token: u64,
    pub peer_name: String,
    pub secret: String,
    pub cert: Option<DeviceCert>,
}

#[derive(Debug)]
pub enum HostEvent {
    Outcome(Outcome),
    Failed { token: u64, why: String },
}

fn binding(km: &[u8; 32], role: &str) -> String {
    format!("{}|{role}", hex::encode(km))
}

fn opposite(role: &str) -> &'static str {
    if role == "host" { "joiner" } else { "host" }
}

fn frame_type(v: &Value) -> &str {
    v["type"].as_str().unwrap_or("")
}

/// Run the plain-pair ceremony over one pairing link. Returns the peer's
/// display name (sent only after mutual confirmation) and its certificate when
/// it presented one that verified. No store happens here.
pub async fn run_ceremony(link: &mut PairLink, words: &str, nameplate: &str, role: &'static str) -> Result<(String, String, Option<DeviceCert>)> {
    let caps = pair_v2_caps();
    let scope = crate::identity::IntroScope::Device.to_byte();
    let mut cer = Ceremony::new(words, nameplate, caps.clone(), scope);
    let my_cert = crate::local_device_cert();
    cer.set_exposes(my_cert.is_some());
    let my_fp = binding(&link.keying_material, role);
    let their_fp = binding(&link.keying_material, opposite(role));
    let fps = (my_fp.as_str(), their_fp.as_str());
    let deadline = Instant::now() + crate::pair_code::CEREMONY_BUDGET;

    let msg = cer.take_msg_payload().ok_or_else(|| anyhow!("pairing ceremony did not produce an element"))?;
    pair_write(&mut link.send, &msg).await?;

    let mut sent_confirm = false;
    let mut sent_name = false;
    let mut sent_expose = false;
    let mut our_expose_nonce: Option<String> = None;
    let mut our_expose_acked = false;
    let mut peer_name: Option<String> = None;
    let mut peer_cert: Option<DeviceCert> = None;

    loop {
        if Instant::now() >= deadline {
            bail!("pairing ceremony did not finish in {} s", crate::pair_code::CEREMONY_BUDGET.as_secs());
        }
        if let Some(sec) = cer.secret() {
            let _ = sec;
            if !sent_confirm {
                if let Some(payload) = cer.take_confirm_payload(&my_fp, &their_fp) {
                    pair_write(&mut link.send, &payload).await?;
                    sent_confirm = true;
                }
            }
            if !sent_name {
                pair_write(&mut link.send, &json!({"type": "pair-name", "v": 1, "name": crate::display_name()})).await?;
                sent_name = true;
            }
            if !sent_expose {
                if let Some(cert) = my_cert.as_ref() {
                    let sign = |m: &[u8]| crate::overlay::overlay_sign_possession(m).ok();
                    if let Some(payload) = crate::pair_cmd::build_identity_expose(
                        cer.k().map(|k| k.as_slice()).unwrap_or(&[]),
                        &my_fp,
                        &their_fp,
                        cer.caps_canon(),
                        scope,
                        cert,
                        &sign,
                    ) {
                        our_expose_nonce = payload["nonce"].as_str().map(str::to_string);
                        pair_write(&mut link.send, &payload).await?;
                    }
                }
                sent_expose = true;
            }
            let peer_will = cer.peer_will_expose();
            let peer_acks = cer.peer_acks_expose();
            let ours_done = my_cert.is_none() || !peer_acks || our_expose_acked;
            let theirs_done = !peer_will || peer_cert.is_some();
            if peer_name.is_some() && ours_done && theirs_done {
                break;
            }
        }

        let frame = pair_read(&mut link.recv).await.context("pairing frame")?;
        let kind = frame_type(&frame);
        if kind.is_empty() || !FRAME_TYPES.contains(&kind) {
            bail!("pairing REFUSED: unsupported frame type '{}'", if kind.is_empty() { "(missing)" } else { kind });
        }
        match kind {
            "pake-msg" | "pake-confirm" => match cer.on_signal(&frame, Some(fps)) {
                PakeInbound::Consumed => {}
                PakeInbound::Abort(why) => bail!("pairing REFUSED: {why}"),
                PakeInbound::Ignored => bail!("pairing REFUSED: unexpected non-PAKE frame"),
                PakeInbound::Reply(reply) => pair_write(&mut link.send, &reply).await?,
            },
            "pair-name" => {
                if cer.secret().is_none() {
                    bail!("pairing REFUSED: a name arrived before key confirmation");
                }
                let n = frame["name"].as_str().unwrap_or("").trim();
                if n.is_empty() || n.len() > 128 {
                    bail!("pairing REFUSED: invalid peer name");
                }
                peer_name = Some(n.to_string());
            }
            "identity-expose" => {
                let Some(k) = cer.k() else {
                    bail!("pairing REFUSED: a certificate arrived before key confirmation");
                };
                let own = crate::overlay::overlay_pubkey_bytes().ok();
                let cert = crate::pair_cmd::open_identity_expose(
                    &frame,
                    k,
                    Some(fps),
                    cer.caps_canon(),
                    scope,
                    own,
                    identity::now_secs(),
                )
                .map_err(|why| anyhow!("pairing REFUSED: {why}"))?;
                peer_cert = Some(cert);
                if cer.peer_acks_expose() {
                    if let Some(of) = frame["nonce"].as_str() {
                        if let Some(ack) = crate::pair_cmd::seal_expose_ack(k, of) {
                            pair_write(&mut link.send, &ack).await?;
                        }
                    }
                }
            }
            "identity-expose-ack" => {
                let Some(k) = cer.k() else { continue };
                if let Some(of) = crate::pair_cmd::open_expose_ack(k, &frame) {
                    if our_expose_nonce.as_deref() == Some(of.as_str()) {
                        our_expose_acked = true;
                    }
                }
            }
            _ => unreachable!("allowlist checked"),
        }
    }

    let name = peer_name.ok_or_else(|| anyhow!("pairing REFUSED: the peer sent no name"))?;
    let secret = cer.secret().cloned().ok_or_else(|| anyhow!("pairing REFUSED: no secret"))?;
    Ok((crate::devices_store::sanitize_device_name(&name), secret, peer_cert))
}

/// The single plain-pair store path. Used by both carriers after `confirm`.
/// It never issues a certificate, never loads the owner key and never lifts a
/// revocation. It refuses a blocked peer before writing anything.
pub fn persist_plain(outcome: &Outcome) -> Result<()> {
    let name = crate::devices_store::sanitize_device_name(&outcome.peer_name);
    let caps = pair_v2_caps();
    let scope = crate::identity::IntroScope::Device.to_byte();
    let now = identity::now_secs();
    if let Some(cert) = outcome.cert.as_ref() {
        cert.verify(now).map_err(|e| anyhow!("the peer certificate does not verify: {e}"))?;
        if crate::fleet_support::device_key_revoked(&cert.device_pub, now) {
            bail!("{name} paired, but its key is refused here (forgotten earlier). To let it back in: tunlion promote {name}");
        }
    }
    if crate::device_view::device_record_revoked(&name) {
        bail!("{name} paired, but it is REVOKED on this device, so it stays refused. To let it back in: tunlion promote {name}");
    }
    match outcome.cert.as_ref() {
        Some(cert) => {
            crate::devices_upsert_atomic(
                &name,
                Some(&outcome.secret),
                Some(cert),
                Some(&caps),
                Some(scope),
                None,
                None,
                true,
            )
            .context("store pairing secret and certificate")?;
            crate::store_provisional_identity(&name, cert).context("store provisional identity")?;
        }
        None => {
            if let Ok(raw) = std::fs::read_to_string(crate::devices_path()) {
                if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                    identity::check_fail_closed(&arr, &name, None)?;
                }
            }
            crate::devices_store_v2(&name, &outcome.secret, &caps).context("store pairing secret")?;
        }
    }
    ui::say(&format!(
        "  {} {} connected \u{b7} remembered on both devices",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        ui::paint(ui::Tone::Bold, &name),
    ));
    ui::say(&ui::paint(ui::Tone::Dim, &format!("  next: tunlion send <file> --to {name}")));
    Ok(())
}

fn service_options(serve: bool, pairing: Option<[u8; 16]>, listen: bool) -> Options {
    let mut opts = Options { serve, listen_discovery: listen, pairing, ..Default::default() };
    if let Ok(ctx) = crate::transport_context::for_root(&crate::settings::config_dir()) {
        opts.skip = filament_transport::lan::skip(&ctx);
    }
    opts
}

fn lan_enabled() -> bool {
    crate::transport_context::for_root(&crate::settings::config_dir())
        .map(|ctx| filament_transport::lan::enabled(&ctx))
        .unwrap_or(false)
}

fn random_id() -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| anyhow!("no secure random: {e}"))?;
    Ok(id)
}

fn spawn_ev_drain(mut rx: mpsc::UnboundedReceiver<crate::net::Ev>) {
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}

/// A host session owned by the signaling pair command. It advertises the same
/// code over LAN and returns the first confirmed outcome to the coordinator.
pub struct HostHandle {
    pub events: mpsc::UnboundedReceiver<HostEvent>,
    svc: LanService,
    task: tokio::task::JoinHandle<()>,
}

impl HostHandle {
    pub async fn shutdown(&mut self) {
        self.svc.shutdown().await;
        self.task.abort();
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        let svc = self.svc.clone();
        tokio::spawn(async move { svc.shutdown().await });
    }
}

/// Start advertising `code` over LAN for a signaling-created code. The label is
/// printed by the caller, which owns the code screen.
pub async fn spawn_host(code: PairCode, words: String, nameplate: String) -> Result<HostHandle> {
    if !lan_enabled() {
        bail!("local discovery is off (network.transports)");
    }
    let id = code.pairing_id();
    let (pair_tx, mut pair_rx) = mpsc::channel::<PairLink>(2);
    let (ev_tx, ev_rx) = mpsc::unbounded_channel::<crate::net::Ev>();
    spawn_ev_drain(ev_rx);
    let svc = LanService::start(
        &crate::settings::config_dir(),
        service_options(true, Some(id), false),
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        Some(pair_tx),
        ev_tx,
    )
    .await?;
    let (out_tx, out_rx) = mpsc::unbounded_channel::<HostEvent>();
    let task = tokio::spawn(async move {
        while !code.is_closed() {
            let Some(mut link) = pair_rx.recv().await else { return };
            let now = Instant::now();
            let token = match code.begin(Carrier::Lan, now) {
                Begin::Started(t) => t,
                Begin::Busy => {
                    ui::debug("lan pairing: another ceremony is active; refusing this connection");
                    continue;
                }
                Begin::Closed => return,
            };
            match run_ceremony(&mut link, &words, &nameplate, "host").await {
                Ok((peer_name, secret, cert)) => {
                    let _ = out_tx.send(HostEvent::Outcome(Outcome { token, peer_name, secret, cert }));
                    return;
                }
                Err(e) => {
                    code.fail(token, Instant::now());
                    let _ = out_tx.send(HostEvent::Failed { token, why: format!("{e:#}") });
                }
            }
        }
    });
    Ok(HostHandle { events: out_rx, svc, task })
}

/// Host a plain code with no server. Stores the outcome itself.
pub async fn host_standalone(words: String, nameplate: String) -> Result<()> {
    if !lan_enabled() {
        bail!("local discovery is off (network.transports); turn on lan or use the server");
    }
    let id = random_id()?;
    let code = PairCode::new(id, Instant::now());
    let full = format!("{words}-{nameplate}");
    ui::say("");
    ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &full.to_uppercase())));
    ui::say(&format!("  nearby: {}  (compare with the other screen)", code.label()));
    ui::say(&ui::paint(ui::Tone::Dim, "  waiting for the other device... Ctrl-C cancels"));

    let (pair_tx, mut pair_rx) = mpsc::channel::<PairLink>(2);
    let (ev_tx, ev_rx) = mpsc::unbounded_channel::<crate::net::Ev>();
    spawn_ev_drain(ev_rx);
    let svc = LanService::start(
        &crate::settings::config_dir(),
        service_options(true, Some(id), false),
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        Some(pair_tx),
        ev_tx,
    )
    .await?;

    let result = async {
        let mut link = tokio::time::timeout(CODE_TTL, pair_rx.recv())
            .await
            .map_err(|_| anyhow!("the code expired before another device connected"))?
            .ok_or_else(|| anyhow!("LAN service stopped"))?;
        let token = match code.begin(Carrier::Lan, Instant::now()) {
            Begin::Started(t) => t,
            other => bail!("pairing could not start: {other:?}"),
        };
        let (peer_name, secret, cert) = run_ceremony(&mut link, &words, &nameplate, "host").await.inspect_err(|_| {
            code.fail(token, Instant::now());
        })?;
        if !code.confirm(token, Instant::now()) {
            bail!("this code was already used");
        }
        persist_plain(&Outcome { token, peer_name, secret, cert })?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    svc.shutdown().await;
    result
}

/// Join a plain code over the LAN. Interactive use asks before dialing; a
/// non-interactive run must have said `--nearby` at the command line.
pub async fn join_standalone(code: &str, name: Option<String>, nearby: bool) -> Result<()> {
    if !lan_enabled() {
        bail!("local discovery is off (network.transports); turn on lan or use the server");
    }
    let normalized = crate::pake::norm_code(code);
    let (nameplate, words) = crate::pake::split_code(&normalized);
    if nameplate.is_empty() || words.is_empty() {
        bail!("that code doesn't look right, expected something like brave-otter-ruby-3141");
    }
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<crate::net::Ev>();
    let svc = LanService::start(
        &crate::settings::config_dir(),
        service_options(false, None, true),
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        None,
        ev_tx,
    )
    .await?;
    let result = async {
        let deadline = Instant::now() + CODE_TTL;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("no nearby pairing device appeared within 10 minutes");
            }
            let ev = match tokio::time::timeout(left.min(Duration::from_secs(2)), ev_rx.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => bail!("LAN service stopped"),
                Err(_) => continue,
            };
            let crate::net::Ev::Lan(filament_transport::lan::LanEvent::PairingNearby { addr, label }) = ev else { continue };
            let key = format!("{addr}|{label}");
            if !seen.insert(key) {
                continue;
            }
            ui::say(&format!("Found nearby pairing {label} at {addr}"));
            if !nearby {
                if !crate::interactive_allowed() {
                    bail!("nearby pairing needs --nearby when stdin is not a terminal");
                }
                ui::say(&ui::paint(ui::Tone::Dim, "  compare this label with the screen showing the code"));
                let picked = crate::codeentry::pick_opts(
                    "",
                    &["Yes, use this device".to_string(), "No".to_string()],
                    crate::codeentry::PickOpts { initial: 1, ..Default::default() },
                )?;
                if !matches!(picked, crate::codeentry::Picked::Item(0)) {
                    continue;
                }
            }
            let mut link = tokio::time::timeout(Duration::from_secs(6), svc.pair_dial(vec![addr])).await
                .map_err(|_| anyhow!("pairing dial timed out"))??;
            let token = 0;
            let (peer_name, secret, cert) = run_ceremony(&mut link, &words, &nameplate, "joiner").await?;
            let peer_name = name.clone().unwrap_or(peer_name);
            persist_plain(&Outcome { token, peer_name, secret, cert })?;
            return Ok::<(), anyhow::Error>(());
        }
    }
    .await;
    svc.shutdown().await;
    result
}

/// Frame size guard used by unit tests and by the carrier's read path.
pub const _FRAME_GUARD: usize = PAIR_MAX_FRAME;
