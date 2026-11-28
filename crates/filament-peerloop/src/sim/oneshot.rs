//! A one-shot fleet dialer: a short-lived client (`tunlion shell <sibling>`,
//! `exec`, `reach` from a device with no daemon broker) that dials a fleet
//! sibling once over the fleet secret and must be answered.
//!
//! It drives the same transport primitives the CLI's fleet one-shot does
//! (`cli/src/l2.rs`, `bring_up_to_known` in fleet mode): connect signaling,
//! join, subscribe to the fleet meeting point on welcome, take the target's
//! presence as the candidate, advertise direct candidates with a
//! `transport-offer` that names no `ch` (a one-shot's offer, never a daemon's),
//! and race direct QUIC on the target's own offer with the fleet secret.
//! It never dials on presence; the daemon has to answer.
//!
//! The dialer writes its milestones to the network trace:
//! `oneshot:start:<dialer>:<target>`, `oneshot:candidate:<dialer>:<target>`,
//! `oneshot:answered:<dialer>:<target>` and `oneshot:gaveup:<dialer>:<target>:<why>`.
//! The oracle reads them (`assertions::one_shot_violations`).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use filament_transport::clock;
use filament_transport::net::{AttemptId, Ev};
use serde_json::json;
use tokio::sync::mpsc;

use crate::sim::net::SimNetwork;

/// How long a one-shot keeps a candidate that has not given it a direct link:
/// the CLI's per-candidate hard bound (`CandidateBound`, `net::WATCHDOG_SECS`).
/// Past it the dialer rotates away, which for the only real target is the
/// user-visible "couldn't reach" of #757.
pub const CANDIDATE_BOUND: Duration =
    Duration::from_secs(filament_transport::net::WATCHDOG_SECS);

/// The re-subscribe cadence while no candidate is known (l2.rs `resubscribe`).
const RESUBSCRIBE: Duration = Duration::from_millis(2_000);

pub struct OneShot {
    pub name: String,
    pub uid: String,
    pub target: String,
    pub fleet_rv: String,
}

pub async fn dial(net: Arc<SimNetwork>, d: OneShot) {
    let started = clock::now();
    net.record_trace(format!("oneshot:start:{}:{}", d.name, d.target));
    net.register_node_identity(&d.name, &d.uid);
    let ctx = net.node_context(&d.name);
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sig = match filament_transport::net::connect_signaling_owned(&ctx, "http://sim.local", tx.clone()).await {
        Ok(s) => s,
        Err(_) => {
            net.record_trace(format!("oneshot:gaveup:{}:{}:signaling", d.name, d.target));
            return;
        }
    };
    let channel = crate::recv::store::channel_of(&d.fleet_rv);
    let _ = sig
        .emit("join", json!({ "room": format!("solo-{}", d.uid), "uid": d.uid, "name": d.name }))
        .await;
    let mut my_id: Option<String> = None;
    // The candidate: (sid, uid) and when it was dialed.
    let mut candidate: Option<(String, String, clock::Instant)> = None;
    let mut racing = false;
    // Offers from a sid that is not (yet) the candidate are held, as the CLI's
    // fleet dial holds them, and replayed when that sid becomes the candidate.
    let mut held: Vec<serde_json::Value> = Vec::new();
    let mut answered: Option<Arc<dyn filament_transport::net::Transport>> = None;
    let (won_tx, mut won_rx) = mpsc::unbounded_channel::<Option<filament_transport::direct::UnreadTransport>>();
    let mut resubscribe = tokio::time::interval(RESUBSCRIBE);
    resubscribe.tick().await;
    let overall = started + CANDIDATE_BOUND + CANDIDATE_BOUND;
    let why = loop {
        if let Some((_, _, at)) = &candidate {
            if clock::now() >= *at + CANDIDATE_BOUND {
                break "candidate-bound";
            }
        } else if clock::now() >= overall {
            break "no-candidate";
        }
        let deadline = match &candidate {
            Some((_, _, at)) => *at + CANDIDATE_BOUND,
            None => overall,
        };
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => break "signaling-closed",
            },
            won = won_rx.recv() => {
                match won.flatten() {
                    Some(t) => {
                        answered = Some(t.transport().clone());
                        break "answered";
                    }
                    None => {
                        // The race found no partner in its budget; a later
                        // offer from the candidate may start another.
                        racing = false;
                        continue;
                    }
                }
            }
            _ = resubscribe.tick() => {
                if my_id.is_some() && candidate.is_none() {
                    filament_transport::net::subscribe_with_ack(sig.client(), vec![channel.clone()], tx.clone()).await;
                }
                continue;
            }
            _ = tokio::time::sleep_until(deadline) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(str::to_string);
                filament_transport::net::subscribe_with_ack(sig.client(), vec![channel.clone()], tx.clone()).await;
            }
            Ev::KnownPeer(v) => {
                if candidate.is_some() || v["channel"].as_str() != Some(channel.as_str()) {
                    continue;
                }
                // The dialer asked for the target by name; a sibling answering
                // to another name is not this dial's candidate.
                if v["name"].as_str() != Some(d.target.as_str()) {
                    continue;
                }
                let (Some(pid), Some(uid)) = (v["id"].as_str(), v["uid"].as_str()) else {
                    continue;
                };
                if Some(pid) == my_id.as_deref() || uid == d.uid {
                    continue;
                }
                candidate = Some((pid.to_string(), uid.to_string(), clock::now()));
                net.record_trace(format!("oneshot:candidate:{}:{}", d.name, d.target));
                for h in held.drain(..) {
                    if h["from"].as_str() == Some(pid) {
                        let _ = tx.send(Ev::Signal(h));
                    }
                }
                // Advertise our direct candidates. A one-shot's offer has no
                // `ch`: that is how a daemon tells it from a sibling daemon.
                if let Ok((_ep, port)) = filament_transport::direct::bind_endpoint_with_context(&ctx) {
                    let (addrs, _) =
                        filament_transport::direct::gather_candidates(&ctx, "http://sim.local", port).await;
                    let offer = json!({ "type": "transport-offer", "v": 1, "proto": 2, "addrs": addrs });
                    let _ = sig.emit("signal", json!({ "to": pid, "data": offer })).await;
                }
            }
            Ev::Signal(v) => {
                let data = &v["data"];
                if data["type"].as_str() != Some("transport-offer") || racing {
                    continue;
                }
                let Some((pid, peer_uid, _)) = candidate.clone() else {
                    if held.len() < 16 {
                        held.push(v.clone());
                    }
                    continue;
                };
                if v["from"].as_str() != Some(pid.as_str()) {
                    continue;
                }
                let Some(me) = my_id.clone() else { continue };
                let Ok((ep, _)) = filament_transport::direct::bind_endpoint_with_context(&ctx) else {
                    continue;
                };
                racing = true;
                let peer_cands: Vec<String> = data["addrs"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let exchange = data["proto"].as_u64().unwrap_or(1) >= 2;
                let (ctx2, rv, uid, won) = (ctx.clone(), d.fleet_rv.clone(), d.uid.clone(), won_tx.clone());
                let ev_tx = tx.clone();
                tokio::spawn(async move {
                    let t = filament_transport::direct::race_connect_labeled(
                        &ctx2,
                        ep,
                        peer_cands,
                        &rv,
                        pid,
                        AttemptId::next(),
                        uid,
                        peer_uid,
                        me,
                        ev_tx,
                        "direct-quic",
                        exchange,
                        None,
                        Arc::new(AtomicBool::new(false)),
                    )
                    .await;
                    let _ = won.send(t);
                });
            }
            _ => {}
        }
    };
    if why == "answered" {
        net.record_trace(format!("oneshot:answered:{}:{}", d.name, d.target));
    } else {
        net.record_trace(format!("oneshot:gaveup:{}:{}:{why}", d.name, d.target));
    }
    // The command is done (or gave up): the process exits, closing its link and
    // its signaling connection.
    if let Some(t) = answered {
        t.force_close();
    }
    sig.shutdown().await;
}
