//! The pairing command (`tunlion pair`), lifted out of `main.rs`.
//!
//! Drives the L1-a PAKE ceremony at the terminal: mint a spoken code or claim
//! one, show the join screen, and hand the agreed secret to the device store.
//! Three pair-specific helpers live here because this module is their only
//! caller: `malformed_entry_banner`, `persist_mesh_grant` and
//! `invitation_not_a_code_msg` (the latter also drives a unit test, which
//! imports it back under `#[cfg(test)]`).
//!
//! `looks_like_pake_code` deliberately did NOT come with it: it has eleven call
//! sites outside pairing, so it stays in the crate root and is imported.
//! Two `tokio::spawn`s and one `test_hooks` call travel with `pair_cmd`; there
//! are no cfg branches here.
use crate::conn::{AdoptSource, Conn, Presence};
use crate::net::{self, Ev};
use crate::pake_ceremony::{Ceremony, Inbound as PakeInbound, pair_v2_caps};
use crate::pair_code::{Begin, Carrier as PairCarrier, PairCode};
use crate::{
    cancelled, codeentry, devices_path, devices_store_v2,
    devices_upsert_atomic, direct, display_name, fleet, fleet_ui, fresh_secret, identity,
    interactive_allowed, load_owner_key, local_device_cert, local_device_cert_path,
    looks_like_pake_code, merge_owner_cap_ops, mesh_enrolment, mk_uid, regex_lite_code, session,
    shutdown, store_provisional_identity, test_hooks, ui,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Store an owner-signed enrolment received over the pairing ceremony.
///
/// VERIFIES BEFORE IT STORES. The grant arrives sealed under the PAKE key, so
/// only the party we completed the ceremony with could have sent it, but that
/// says who sent it and nothing about whether it is well-formed. A certificate
/// that does not name OUR device key, or does not verify, is refused rather than
/// written: the whole value of the certificate is that it names one key.
fn persist_mesh_grant(grant: &Value) -> Result<()> {
    if local_device_cert_path().exists() {
        bail!("this device already holds a certificate; refusing to overwrite it");
    }
    let our_pub = crate::overlay::overlay_pubkey_bytes()
        .map_err(|e| anyhow!("cannot read this device's key: {e}"))?;
    let cert = identity::DeviceCert::from_json(&grant["device_cert"])
        .ok_or_else(|| anyhow!("the enrolment carried no certificate"))?;
    if cert.device_pub != our_pub {
        bail!("the certificate names a different device; refusing it");
    }
    cert.verify(identity::now_secs())
        .map_err(|e| anyhow!("the certificate does not verify: {e}"))?;
    let owner_name = grant["owner_name"].as_str().unwrap_or("owner");
    crate::platform::SecretFile::write_str(
        &local_device_cert_path(),
        &serde_json::to_string_pretty(&json!({ "name": owner_name, "cert": cert.to_json() }))?,
    )?;
    // The meeting point, and the owner-signed policy that makes it useful. Each
    // op is verified against the owner key in the header, so this is a relay of
    // the owner's decisions rather than trust in whoever transmitted them.
    if let Some(rv) = grant["fleet_rv"].as_str() {
        if let Err(e) = fleet::store_rv(rv) {
            ui::debug(&format!("fleet rendezvous secret not stored: {e}"));
        }
    }
    if let Some(hdr) = grant["cap_header"].as_object() {
        let dir = crate::settings::config_dir();
        let mut store = crate::capability::load_cap_store(&dir);
        let already = store.iter().any(|e| {
            e.get("type").and_then(|x| x.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        });
        if !already {
            store.push(Value::Object(hdr.clone()));
            let _ = crate::capability::save_cap_store(&dir, &store);
        }
    }
    if let Some(ops) = grant.get("cap_ops").and_then(|v| v.as_array()) {
        let added = merge_owner_cap_ops(ops);
        ui::debug(&format!("mesh grant: merged {added} owner-signed ops"));
    }
    Ok(())
}

/// The one-line dim banner shown right before we open the guided entry on a
/// MALFORMED arg, so the user knows WHY the prompt appeared and how to make it
/// fail fast in scripts.
fn malformed_entry_banner(arg: &str) {
    ui::say(&ui::paint(
        ui::Tone::Dim,
        &format!(
            "couldn't parse '{arg}', opening guided entry · set TUNLION_NONINTERACTIVE=1 to fail fast in scripts"
        ),
    ));
}

/// Set by `add --for person` before the ceremony: the operator asked for a
/// person, so a peer that turns out to hold this identity is reported as kept,
/// not silently re-filed.
pub(crate) static FOR_PERSON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the "filed as EXTERNAL" notice applies: only when this side asked
/// for one of its own devices and the peer turned out to hold a different
/// identity. Pure.
pub(crate) fn external_notice_applies(
    asked_for_own_device: bool,
    same_person: bool,
    joined_mesh: bool,
    issued_cert: bool,
    peer_has_identity: bool,
) -> bool {
    asked_for_own_device && !same_person && !joined_mesh && !issued_cert && peer_has_identity
}

/// Does `records` hold a device named `who` certified by `owner_pub`? Pure.
pub(crate) fn names_own_device(records: &[Value], who: &str, owner_pub: &[u8; 32]) -> bool {
    records.iter().any(|r| {
        r["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(who))
            && identity::DeviceCert::from_json(&r["deviceCert"]).is_some_and(|c| &c.user_pub == owner_pub)
    })
}

/// `add --for person --name <who>` where <who> is already one of this
/// identity's devices: the refusal, or None when it is not.
pub(crate) fn person_names_own_device(who: &str) -> Option<String> {
    let owner = load_owner_key()
        .map(|k| k.public_key_bytes())
        .or_else(|| local_device_cert().map(|c| c.user_pub))?;
    let records: Vec<Value> = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    names_own_device(&records, who, &owner).then(|| person_own_device_msg(who))
}

/// The refusal text. Pure.
pub(crate) fn person_own_device_msg(who: &str) -> String {
    let w = crate::refusal::word(who);
    format!(
        "'{who}' is already one of your devices (it holds your identity's certificate), so it cannot be added as a person. \
         To pair it as your device:  tunlion add {w}. To make it someone else's, remove it from your fleet first:  \
         tunlion devices forget {w} -y  (then on it: tunlion down --yes && tunlion reset)"
    )
}

#[cfg(test)]
mod relationship_tests {
    use super::*;

    /// Eval item 3: on a `--for person` pairing both sides printed "filed as
    /// EXTERNAL ... tunlion down --yes && tunlion reset" although EXTERNAL is
    /// what was asked for. The notice is for an asked-for OWN device only.
    #[test]
    fn the_external_notice_is_only_for_an_own_device_that_was_not() {
        assert!(external_notice_applies(true, false, false, false, true));
        // --for person, a plain add, and the claiming side never asked for theirs.
        assert!(!external_notice_applies(false, false, false, false, true));
        // Same identity, joined, or certified by us: not external at all.
        assert!(!external_notice_applies(true, true, false, false, true));
        assert!(!external_notice_applies(true, false, true, false, true));
        assert!(!external_notice_applies(true, false, false, true, true));
    }

    /// `add --for person --name u2-a` where u2-a holds our certificate is
    /// refused up front with the reason and the commands that do apply.
    #[test]
    fn a_person_pairing_cannot_name_one_of_your_devices() {
        let owner = [7u8; 32];
        let cert = |user: [u8; 32]| {
            serde_json::json!({
                "devicePub": hex::encode([1u8; 32]),
                "userPub": hex::encode(user),
                "sig": hex::encode([0u8; 64]),
                "expires": 10u64,
                "issued": 0u64,
            })
        };
        let records = vec![
            serde_json::json!({"name": "u2-a", "deviceCert": cert(owner)}),
            serde_json::json!({"name": "carol", "deviceCert": cert([8u8; 32])}),
            serde_json::json!({"name": "plain"}),
        ];
        assert!(names_own_device(&records, "u2-a", &owner));
        assert!(names_own_device(&records, "U2-A", &owner));
        assert!(!names_own_device(&records, "carol", &owner));
        assert!(!names_own_device(&records, "plain", &owner));
        assert!(!names_own_device(&records, "nobody", &owner));
        let msg = person_own_device_msg("u2-a");
        assert!(msg.contains("already one of your devices"), "{msg}");
        assert!(msg.contains("tunlion add u2-a"), "{msg}");
    }
}

/// How long a certless device waits once the owner said a person is deciding
/// whether it is one of theirs (`enrol-hold`). Bounded by the code's lifetime.
const ENROL_HOLD_WAIT: Duration = Duration::from_secs(300);
/// How long the owner waits for the device to confirm it stored the
/// certificate issued after that question, before keeping it a pairing.
const ENROL_ACK_WAIT: Duration = Duration::from_secs(15);

/// How often a certless device re-sends its key offer until the other side
/// answers it (hold, grant or decline). A single send was lost exactly like the
/// PAKE messages #597 fixed, and then the device silently stayed a pairing.
const ENROL_OFFER_RESEND: Duration = Duration::from_millis(1000);
/// How long an owner that was asked for "one of my devices" waits, after the
/// key exchange, for a certless device's offer before saying it did not come.
const ENROL_OFFER_WAIT: Duration = Duration::from_secs(20);

/// The sealed `enrol-offer` a certless device sends: its device key, proven by
/// a signature over this ceremony's confirmation MAC (so it cannot be replayed
/// into another ceremony), sealed under the PAKE key. `sign` signs with the
/// device key. Pure over its inputs.
pub(crate) fn build_enrol_offer(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    device_pub: [u8; 32],
    name: &str,
    sign: &dyn Fn(&[u8]) -> Option<[u8; 64]>,
) -> Option<Value> {
    let cmv: [u8; 32] = crate::pake::our_confirm(k, my_fp, their_fp, caps_canon, scope).try_into().ok()?;
    let pmsg = identity::possession_msg(
        0x01,
        &cmv,
        scope,
        &identity::caps_digest(caps_canon),
        &[0u8; 32],
        &device_pub,
        &[0u8; 32],
    );
    let psig = sign(&pmsg)?;
    let inner = json!({
        "device_pub": hex::encode(device_pub),
        "possession_sig": hex::encode(psig),
        "name": name,
    });
    let (n, sealed) = identity::seal_plaintext(&identity::sealing_key_from_k(k), inner.to_string().as_bytes()).ok()?;
    Some(json!({"type": "enrol-offer", "v": 1, "hold": true, "nonce": hex::encode(n), "sealed": hex::encode(sealed)}))
}

/// What a finished pairing did about "one of my devices", from either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrolOutcome {
    /// Nothing to report: enrolled, already the same owner's, or never asked.
    Fine,
    /// OWNER SIDE, asked for one of its devices: the peer did not become one.
    OwnerNotEnrolled { offer_seen: bool, failed_proof: bool },
    /// OWNER SIDE, asked for one of its devices, but the peer identified itself
    /// as a browser: the pairing is real (files and shell), the fleet
    /// enrolment is impossible and is not a failure.
    OwnerBrowserNotFleet,
    /// OWNER SIDE: certified, but the device never said it stored it.
    OwnerUnconfirmed,
    /// DEVICE SIDE: offered its key, nobody answered.
    DeviceNoAnswer,
    /// DEVICE SIDE: a certificate arrived and was refused.
    DeviceGrantRefused(String),
}

#[derive(Debug, Clone)]
pub(crate) struct EnrolOutcomeInputs {
    pub owner_asked_own: bool,
    pub certified_here: bool,
    pub already_same_owner: bool,
    pub peer_presented_cert: bool,
    /// The PAKE partner announced, on its transport hint, that it is a browser.
    /// Advisory device-kind evidence only: it can explain why a pairing is not
    /// a fleet enrolment, never admit one or excuse a failed key proof.
    pub peer_is_browser: bool,
    pub offer_seen: bool,
    pub offer_failed_proof: bool,
    pub unconfirmed_grant: bool,
    pub offered_here: bool,
    pub joined_here: bool,
    pub declined: bool,
    pub grant_refused: Option<String>,
}

/// Pure. A peer that already holds another identity is the EXTERNAL notice's
/// case (`external_notice_applies`), not this one.
pub(crate) fn enrolment_outcome(i: EnrolOutcomeInputs) -> EnrolOutcome {
    if i.owner_asked_own && !i.certified_here && !i.already_same_owner && !i.peer_presented_cert {
        // A browser has no device key to offer, so "no offer" is its normal
        // outcome, not a failed enrolment. Only the explicit browser marker
        // earns this; a missing or malformed key offer from any other peer
        // stays the failure below.
        if i.peer_is_browser && !i.offer_seen && !i.offer_failed_proof && !i.joined_here {
            return EnrolOutcome::OwnerBrowserNotFleet;
        }
        return EnrolOutcome::OwnerNotEnrolled {
            offer_seen: i.offer_seen,
            failed_proof: i.offer_failed_proof,
        };
    }
    if i.certified_here && i.unconfirmed_grant {
        return EnrolOutcome::OwnerUnconfirmed;
    }
    if i.offered_here && !i.joined_here {
        if let Some(why) = i.grant_refused {
            return EnrolOutcome::DeviceGrantRefused(why);
        }
        if !i.declined {
            return EnrolOutcome::DeviceNoAnswer;
        }
    }
    EnrolOutcome::Fine
}

/// Whether this signal is the browser's explicit device-kind hint. The hint is
/// advisory and unauthenticated (it arrives before PAKE); it is used ONLY to
/// word the outcome of a completed pairing, never to admit a device. `direct`
/// alone is a transport fact, not a kind: a native peer may run without direct.
/// Pure.
pub(crate) fn browser_hint(data: &Value) -> bool {
    data["type"].as_str() == Some("transport-hint")
        && data["client"].as_str() == Some("browser")
}

/// Say the outcome. Returns the error to exit with when what was asked for
/// did not happen (exit 1), None otherwise.
fn report_enrolment_outcome(o: &EnrolOutcome, peer: &str) -> Option<anyhow::Error> {
    let w = crate::refusal::word(peer);
    match o {
        EnrolOutcome::Fine => None,
        EnrolOutcome::OwnerNotEnrolled { offer_seen, failed_proof } => {
            let why = if *failed_proof {
                format!("{peer} offered its key, but the offer did not prove it holds that key, so nothing was signed")
            } else if *offer_seen {
                format!("{peer} offered its key, but it was not certified")
            } else {
                format!("{peer} never offered its device key (it may run an older tunlion, or the connection dropped)")
            };
            ui::caution(
                &format!("{peer} is paired, but it did NOT become one of your devices"),
                Some(why.as_str()),
                &[format!("update tunlion on {peer}, then run `tunlion add {w}` here and `tunlion join <code>` on {peer}")],
            );
            Some(crate::exit_codes::reported_because(
                crate::exit_codes::ExitKind::Other,
                format!("{peer} is paired, but it did not become one of your devices"),
            ))
        }
        EnrolOutcome::OwnerBrowserNotFleet => {
            // A browser pairing is a success. Say what it is and what it is
            // not, in one line, instead of the native "did NOT become" failure.
            ui::say(&format!(
                "  {peer} is paired \u{b7} browsers pair for files and shell, but cannot join your fleet, so it is not one of your devices"
            ));
            None
        }
        EnrolOutcome::OwnerUnconfirmed => {
            ui::caution(
                &format!("{peer} was certified here, but it did not confirm it stored the certificate"),
                Some("if `tunlion devices` on it does not list this device under your devices, add it again"),
                &[format!("`tunlion add {w}` here, then `tunlion join <code>` on {peer}")],
            );
            None
        }
        EnrolOutcome::DeviceNoAnswer => {
            ui::caution(
                &format!("{peer} did not answer whether this device is one of its owner's devices, so this is only a pairing"),
                None,
                &[format!("to make it one: on {peer} run `tunlion add <this device>`, then `tunlion join <code>` here")],
            );
            None
        }
        EnrolOutcome::DeviceGrantRefused(why) => {
            ui::caution(
                &format!("{peer} sent a certificate this device could not accept, so this is only a pairing"),
                Some(why.as_str()),
                &[format!("on {peer}: `tunlion add <this device>`, then `tunlion join <code>` here")],
            );
            Some(crate::exit_codes::reported_because(
                crate::exit_codes::ExitKind::Other,
                format!("{peer} sent a certificate this device could not accept"),
            ))
        }
    }
}

/// A capability list in the words a person uses. Pure.
pub(crate) fn plain_caps(caps: &[String]) -> String {
    let words: Vec<String> = caps
        .iter()
        .map(|c| match c.as_str() {
            "transfer" | "send" => "send you files".to_string(),
            "mount" => "open your shared folder".to_string(),
            "shell" => "open a shell here (it acts as you)".to_string(),
            other => other.to_string(),
        })
        .collect();
    match words.len() {
        0 => "do nothing yet".to_string(),
        1 => words[0].clone(),
        n => format!("{} and {}", words[..n - 1].join(", "), words[n - 1]),
    }
}

/// The line under the code that says what the other device becomes. Pure.
pub(crate) fn code_screen_promise(
    name: Option<&str>,
    will_certify: bool,
    for_person: bool,
    owner_can_ask: bool,
    caps: &[String],
) -> String {
    let who = name.map(|n| ui::paint(ui::Tone::Bold, n)).unwrap_or_else(|| "The device that joins".to_string());
    let (head, detail) = if will_certify {
        (
            format!("{who} will be one of {} devices", ui::paint(ui::Tone::Bold, "YOUR")),
            format!("certified with your owner key \u{b7} it may {}", plain_caps(caps)),
        )
    } else if for_person {
        (format!("{who} will be a person's device, not one of yours"), "you can send each other files".to_string())
    } else if owner_can_ask {
        (format!("{who} will be paired"), "you can send each other files \u{b7} if it is yours, you will be asked here".to_string())
    } else {
        (format!("{who} will be paired"), "you can send each other files".to_string())
    };
    format!("  {head}\n  {}", ui::paint(ui::Tone::Dim, &detail))
}

/// One step of a pairing, as `  ✓ Step`. Pure.
pub(crate) fn step_line(text: &str) -> String {
    format!("  {} {text}", ui::paint(ui::Tone::Ok, ui::glyph_ok()))
}

/// What the owner device does with a certless device's offer of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrolOfferDecision {
    /// The operator already said "one of mine" (`add <name>`, `--for device`).
    Certify,
    /// Ask the person at THIS (owner) device, once.
    Ask,
    /// Refuse: an ordinary pairing.
    Decline,
}

/// The facts the decision rests on, named so a test can state each rule.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnrolOfferInputs {
    /// This device holds the owner key, so only it can sign.
    pub owner_here: bool,
    /// The operator said "a device of mine" before the code was shown.
    pub operator_said_own: bool,
    /// The operator said "someone else" (`--for person`).
    pub operator_said_person: bool,
    /// The offer opened under this ceremony's key AND its possession proof
    /// verified: it came from the ceremony partner, for a key that partner holds.
    pub offer_opened: bool,
    /// The device can wait for a person to answer (`hold`).
    pub peer_can_hold: bool,
    /// A person is here to ask: a terminal, not a script or `--json`.
    pub can_ask: bool,
    /// This ceremony already asked or certified once.
    pub already_asked: bool,
}

/// The one rule for turning a pairing into "one of your devices". The owner
/// key signs only on an explicit owner decision made on the owner device: said
/// up front, or answered here. Never from what the other side claims, never in
/// a script, never twice per ceremony. Pure.
pub(crate) fn enrol_offer_decision(i: EnrolOfferInputs) -> EnrolOfferDecision {
    if !i.owner_here || !i.offer_opened {
        return EnrolOfferDecision::Decline;
    }
    if i.operator_said_own {
        return if i.already_asked { EnrolOfferDecision::Decline } else { EnrolOfferDecision::Certify };
    }
    if i.operator_said_person || !i.peer_can_hold || !i.can_ask || i.already_asked {
        return EnrolOfferDecision::Decline;
    }
    EnrolOfferDecision::Ask
}

/// Open a certless device's sealed `enrol-offer` and check that it proves
/// possession of the key it offers, bound to THIS ceremony (the confirmation
/// MAC over K and both link fingerprints). Returns the proven device key.
/// Refuses our own key (a reflection) and fails closed when our own key is
/// unknown. Pure over its inputs.
pub(crate) fn open_enrol_offer(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    data: &Value,
    own_device_pub: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    let nonce = hex::decode(data.get("nonce")?.as_str()?).ok()?;
    let sealed = hex::decode(data.get("sealed")?.as_str()?).ok()?;
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    let pt = identity::open_sealed(&identity::sealing_key_from_k(k), &nonce, &sealed).ok()?;
    let inner: Value = serde_json::from_slice(&pt).ok()?;
    let dpub: [u8; 32] = hex::decode(inner.get("device_pub")?.as_str()?).ok()?.try_into().ok()?;
    let sig: [u8; 64] = hex::decode(inner.get("possession_sig")?.as_str()?).ok()?.try_into().ok()?;
    let (lo, hi) = crate::pake::sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = crate::pake::confirm_dirs(my_fp, lo);
    let expected: [u8; 32] = crate::pake::confirm_mac(k, expect_dir, lo, hi, caps_canon, scope).try_into().ok()?;
    let msg = identity::possession_msg(
        0x01,
        &expected,
        scope,
        &identity::caps_digest(caps_canon),
        &[0u8; 32],
        &dpub,
        &[0u8; 32],
    );
    identity::verify_possession_sig(&dpub, &msg, &sig).ok()?;
    match own_device_pub {
        Some(own) if own != dpub => Some(dpub),
        _ => None,
    }
}

/// Open a peer's sealed `identity-expose` and check everything it claims: the
/// seal (only this ceremony's K opens it), the certificate's own signature and
/// lifetime, the possession signature over this session's confirmation MAC,
/// and that it is not our own device key reflected back. `Err` names the check
/// that refused it. Pure: the caller supplies the link's fingerprints and our
/// device key (`None` when it could not be read, which refuses).
pub(crate) fn open_identity_expose(
    data: &Value,
    k: &[u8],
    fps: Option<(&str, &str)>,
    caps_canon: &str,
    scope: u8,
    own_dpub: Option<[u8; 32]>,
    now: u64,
) -> std::result::Result<identity::DeviceCert, &'static str> {
    let nonce = data["nonce"].as_str().and_then(|h| hex::decode(h).ok()).ok_or("nonce missing")?;
    let nonce: [u8; 12] = nonce.as_slice().try_into().map_err(|_| "nonce is not 12 bytes")?;
    let sealed = data["sealed"].as_str().and_then(|h| hex::decode(h).ok()).ok_or("sealed body missing")?;
    let plain = identity::open_sealed(&identity::sealing_key_from_k(k), &nonce, &sealed)
        .map_err(|_| "seal does not open under this ceremony's key")?;
    let inner: Value = serde_json::from_slice(&plain).map_err(|_| "sealed body is not JSON")?;
    let cert = identity::DeviceCert::from_json(&inner["cert"]).ok_or("no certificate in it")?;
    cert.verify(now).map_err(|_| "certificate does not verify")?;
    let sig = inner["possession_sig"].as_str().and_then(|h| hex::decode(h).ok()).ok_or("possession signature missing")?;
    let sig: [u8; 64] = sig.as_slice().try_into().map_err(|_| "possession signature is not 64 bytes")?;
    // Session-bound: the MAC binds K, both DTLS fingerprints, caps and scope.
    let (my_fp, their_fp) = fps.ok_or("this link's fingerprints are not known")?;
    let (lo, hi) = crate::pake::sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = crate::pake::confirm_dirs(my_fp, lo);
    let mac = crate::pake::confirm_mac(k, expect_dir, lo, hi, caps_canon, scope);
    let cmv: [u8; 32] = mac.as_slice().try_into().map_err(|_| "confirmation MAC is not 32 bytes")?;
    // Reconstruct cert_hash locally from parsed cert fields (never hash a
    // sender-framed blob). For the PAKE path receiver_device_pub MUST be zeros.
    let msg = identity::possession_msg(
        0x01,
        &cmv,
        scope,
        &identity::caps_digest(caps_canon),
        &identity::cert_hash(&cert),
        &cert.device_pub,
        &[0u8; 32],
    );
    identity::verify_possession_sig(&cert.device_pub, &msg, &sig)
        .map_err(|_| "possession signature does not verify for this session")?;
    // Anti-reflection, narrowed to device_pub (#41). LOAD-BEARING on this 0x01
    // (PAKE) path: receiver_device_pub is zeroed in the possession message, so
    // message binding does NOT carry the receiver identity, and THIS comparison
    // is the only thing preventing a reflection. Do not remove it as redundant.
    // A same-owner fleet device has a DIFFERENT device_pub under the same user
    // key, so it is correctly admitted. Fail closed without our own key.
    match own_dpub {
        Some(own) if own == cert.device_pub => Err("it is this device's own key, reflected back"),
        Some(_) => Ok(cert),
        None => Err("this device's own key could not be read, so a reflection cannot be ruled out"),
    }
}

/// Our sealed `identity-expose`: this device's certificate and a possession
/// signature over this ceremony's confirmation MAC, sealed under the PAKE key.
/// `sign` signs with the device key. Pure over its inputs; the caller builds it
/// once and every copy it sends is these bytes.
pub(crate) fn build_identity_expose(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    cert: &identity::DeviceCert,
    sign: &dyn Fn(&[u8]) -> Option<[u8; 64]>,
) -> Option<Value> {
    let cmv: [u8; 32] = crate::pake::our_confirm(k, my_fp, their_fp, caps_canon, scope).try_into().ok()?;
    let dpub = cert.device_pub;
    let pmsg = identity::possession_msg(
        0x01,
        &cmv,
        scope,
        &identity::caps_digest(caps_canon),
        &identity::cert_hash(cert),
        &dpub,
        &[0u8; 32],
    );
    let psig = sign(&pmsg)?;
    let inner = json!({"cert": cert.to_json(), "possession_sig": hex::encode(psig), "device_pub": hex::encode(dpub)});
    let (n, sealed) = identity::seal_plaintext(&identity::sealing_key_from_k(k), inner.to_string().as_bytes()).ok()?;
    Some(json!({"type": "identity-expose", "v": 2, "nonce": hex::encode(n), "sealed": hex::encode(sealed)}))
}

// PROTOCOL LITERAL: frozen, do not rename (sealed body of identity-expose-ack).
const EXPOSE_ACK_PLAIN: &str = "tunlion-identity-expose-ack-v1:";

/// The acknowledgement of the peer's `identity-expose` whose nonce is `of`,
/// sealed under this ceremony's key so only the peer can read it and the
/// server cannot make one up. Built once per pairing.
pub(crate) fn seal_expose_ack(k: &[u8], of: &str) -> Option<Value> {
    let (n, sealed) = identity::seal_plaintext(
        &identity::sealing_key_from_k(k),
        format!("{EXPOSE_ACK_PLAIN}{of}").as_bytes(),
    )
    .ok()?;
    Some(json!({
        "type": filament_peerloop::expose::ACK_TYPE,
        "v": 1,
        "nonce": hex::encode(n),
        "sealed": hex::encode(sealed),
    }))
}

/// Open an `identity-expose-ack`: the nonce of the frame it acknowledges, or
/// `None` when it does not open under this ceremony's key.
pub(crate) fn open_expose_ack(k: &[u8], data: &Value) -> Option<String> {
    let nonce: [u8; 12] = hex::decode(data["nonce"].as_str()?).ok()?.as_slice().try_into().ok()?;
    let sealed = hex::decode(data["sealed"].as_str()?).ok()?;
    let plain = identity::open_sealed(&identity::sealing_key_from_k(k), &nonce, &sealed).ok()?;
    String::from_utf8(plain).ok()?.strip_prefix(EXPOSE_ACK_PLAIN).map(str::to_string)
}

/// A refusal from [`open_identity_expose`] as the exchange sees it: the two
/// that only mean "not yet" are checked again on a later copy; every other
/// one would refuse every copy, since every copy is the same bytes.
pub(crate) fn expose_verdict_for_refusal(why: &str) -> filament_peerloop::expose::Verdict {
    use filament_peerloop::expose::Verdict;
    match why {
        "no key exchange yet" | "this link's fingerprints are not known" => Verdict::NotYet,
        other => Verdict::Refused(other.to_string()),
    }
}

/// What a pairing that could not deliver or receive a certificate says. It
/// failed, on this side: nothing was stored here.
pub(crate) fn expose_unmet_msg(unmet: &filament_peerloop::expose::Unmet, peer: &str) -> String {
    use filament_peerloop::expose::Unmet;
    match unmet {
        Unmet::CertMissing => format!(
            "pairing did not finish: {peer} said it would send its device certificate, and it never arrived. \
             Nothing was stored; run the pairing again with a FRESH code"
        ),
        Unmet::CertRefused(why) => format!(
            "pairing REFUSED: {peer}'s device certificate did not verify ({why}). \
             Nothing was stored; ask for a FRESH code"
        ),
        Unmet::NotAcknowledged => format!(
            "pairing did not finish: {peer} never confirmed it received this device's certificate. \
             Nothing was stored here; run the pairing again with a FRESH code"
        ),
    }
}

/// After a pairing succeeded on this side, keep answering the peer's re-sent
/// `identity-expose` with the same acknowledgement: our first answer may have
/// been lost, and without it the peer fails at its deadline. Ends when the peer
/// leaves, or after a quiet spell with no copy (see `expose::LINGER_QUIET`).
async fn linger_answering_expose(
    sio: &filament_signal::Client,
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    x: &mut filament_peerloop::expose::ExposeExchange,
    peer: Option<&str>,
    ack: Option<&Value>,
) {
    let (Some(peer), Some(ack)) = (peer, ack) else { return };
    let since = Instant::now();
    while !x.linger_over(Instant::now(), since) {
        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Some(Ev::Signal(v))) => {
                if v["from"].as_str() == Some(peer) && v["data"]["type"].as_str() == Some("identity-expose") {
                    x.note_copy(Instant::now());
                    sio.emit("signal", json!({ "to": peer, "data": ack })).await.ok();
                }
            }
            Ok(Some(Ev::PeerLeft(v))) if v["id"].as_str() == Some(peer) => break,
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
}

/// Certify `dpub` with the owner key and seal the grant under this ceremony's
/// key, ready to send as the `data` of a signal.
fn seal_enrol_grant(
    k: &[u8],
    owner_key: &identity::UserKey,
    dpub: [u8; 32],
    caps: &[String],
    enrol_ttl: Option<u64>,
) -> Option<(identity::DeviceCert, Value)> {
    let expires = identity::now_secs().saturating_add(enrol_ttl.unwrap_or(identity::CERT_TTL_SECS));
    let (cert, mut grant) = match mesh_enrolment(owner_key, dpub, caps, expires, true) {
        Ok(v) => v,
        Err(e) => {
            ui::debug(&format!("enrol grant failed: {e}"));
            return None;
        }
    };
    grant["type"] = json!("enrol-grant");
    grant["owner_name"] = json!(display_name());
    let sk = identity::sealing_key_from_k(k);
    let (gn, gs) = identity::seal_plaintext(&sk, grant.to_string().as_bytes()).ok()?;
    Some((
        cert,
        json!({"type": "enrol-grant", "v": 1, "nonce": hex::encode(gn), "sealed": hex::encode(gs)}),
    ))
}

/// The final line of a pairing that made the peer one of your devices: on the
/// owner side (we certified it) or on the device that was certified. Pure.
pub(crate) fn enrolled_final_line(peer: &str, this_device_joined: bool) -> String {
    let p = ui::paint(ui::Tone::Bold, peer);
    if this_device_joined {
        format!("Done. This device and {p} are your devices")
    } else {
        format!("Done. {p} is one of your devices")
    }
}

/// The question, its stakes, and the two answers. Pure, so the wording is pinned.
pub(crate) fn own_device_question(name: &str) -> (String, String, Vec<String>) {
    (
        format!("Is {name} one of your devices?"),
        "Yes certifies it with your owner key. A code only proves someone typed it, not whose device it is.".to_string(),
        vec![format!("Yes, {name} is mine"), "No, just pair (files only)".to_string()],
    )
}

/// Ask at the owner device whether the peer is one of its devices. Enter
/// alone keeps the safe answer (No); Esc and Ctrl-C mean No too.
fn ask_is_own_device(name: &str) -> bool {
    let (question, stakes, items) = own_device_question(name);
    ui::say("");
    ui::say(&format!("  {}", ui::paint(ui::Tone::Bold, &question)));
    ui::say(&ui::paint(ui::Tone::Dim, &format!("  {stakes}")));
    matches!(
        codeentry::pick_opts("", &items, codeentry::PickOpts { initial: 1, ..Default::default() }),
        Ok(codeentry::Picked::Item(0))
    )
}

pub(crate) fn invitation_not_a_code_msg() -> String {
    "that is an invitation, not a pairing code.\n  \
     Run `tunlion join` and paste it at the prompt; it is cleared from the terminal after reading.\n  \
     If you saved it to a file: `tunlion join --invite-file <path>`.\n  \
     Invitation material is deliberately never read from the command line, where it would land in `ps` output and shell history."
        .to_string()
}

/// The default enrolment ceiling for a device added over a spoken code when
/// `--allow` was not given: the same transfer+mount the invitation path gives a
/// device. Shell is owner-equivalent and stays a deliberate `--allow ...shell`,
/// because pairing alone never yields a shell.
pub(crate) fn default_device_ceiling() -> Vec<String> {
    vec!["transfer".to_string(), "mount".to_string()]
}

/// `--expires` for the spoken-code path, parsed and bounded exactly like the
/// invitation path (`add --out`). `enrols` is false for a pairing that issues
/// no certificate (a person, or an ordinary pair): there is nothing for the
/// value to bound, so it is refused rather than silently ignored.
pub(crate) fn code_enrolment_ttl(expires: Option<&str>, enrols: bool) -> Result<Option<u64>> {
    let Some(raw) = expires else {
        return Ok(None);
    };
    if !enrols {
        bail!(
            "--expires bounds an invitation or an enrolment certificate, and this pairing issues neither. Use `--out <file>` for a bounded invitation, or `--for device` to enrol one of your devices."
        );
    }
    let ttl = crate::file_io::parse_mint_ttl(raw)?;
    if ttl == 0 || ttl > 30 * 24 * 3600 {
        bail!("invitations must expire between 1 second and 30 days");
    }
    Ok(Some(ttl))
}

/// What `tunlion grant <device> <capability>` does about a device's enrolment
/// ceiling. Only a DELEGATED device has one (`principal_ceiling_for` is None
/// for every other record), and for it a grant can neither widen the ceiling
/// nor add what it already holds. `grant` decides with this, and the pairing
/// hint below asks the same question, so the hint cannot name a command that
/// `grant` would then refuse.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantVsCeiling {
    /// No ceiling binds this device: proceed.
    Proceed,
    /// The ceiling already holds it; a bare grant would add nothing.
    AlreadyCovered,
    /// Outside the ceiling (or resource-scoped under one): only a new
    /// invitation carrying it can add it.
    OutsideCeiling,
}

pub(crate) fn grant_vs_ceiling(
    ceiling: Option<&[String]>,
    capability: &str,
    resource_scoped: bool,
) -> GrantVsCeiling {
    match ceiling {
        None => GrantVsCeiling::Proceed,
        Some(c) if !resource_scoped && c.iter().any(|x| x == capability) => {
            GrantVsCeiling::AlreadyCovered
        }
        Some(_) => GrantVsCeiling::OutsideCeiling,
    }
}

/// The one line printed after enrolling a device without shell: how to give it
/// one, as a command that parses AND that `grant` accepts for this device.
/// `caps` is what the enrolment recorded; `ceiling` is what binds it
/// (`principal_ceiling_for`): None for an owner's own device, which takes a
/// plain `grant` (a first-time-user test was told to re-add a device that
/// `tunlion grant p5-b shell` served at once). Only a delegated device whose
/// ceiling excludes shell is sent to a new invitation.
pub(crate) fn shell_not_granted_hint(
    name: &str,
    caps: &[String],
    ceiling: Option<&[String]>,
) -> Option<String> {
    if caps.iter().any(|c| c == "shell") {
        return None;
    }
    match grant_vs_ceiling(ceiling, "shell", false) {
        GrantVsCeiling::AlreadyCovered => None,
        GrantVsCeiling::Proceed => Some(format!(
            "shell was not granted; to allow a terminal later:  tunlion grant {} shell",
            crate::refusal::word(name)
        )),
        GrantVsCeiling::OutsideCeiling => {
            let mut allow: Vec<String> = ceiling.unwrap_or(caps).to_vec();
            allow.push("shell".to_string());
            let allow = allow.join(",");
            Some(format!(
                "shell was not granted, and a grant cannot widen this device's ceiling; to allow a terminal later, re-add it with shell:  tunlion add {} --allow {allow}",
                crate::refusal::word(name)
            ))
        }
    }
}

/// `internal` means: issue the peer an owner-signed certificate and admit it to
/// this mesh. `posture` is the ceiling to grant it, empty meaning the
/// same-person default. Both are decided by the operator at the moment of
/// adding, because that is when they know what the machine is for.
pub(crate) async fn pair_cmd(
    server: &str,
    mut code: Option<String>,
    name: Option<String>,
    mut word: Option<String>,
    relay: bool,
    internal: bool,
    posture: Vec<String>,
    // `--expires`, already parsed and bounded (`code_enrolment_ttl`): the
    // lifetime of the certificate an `internal` pairing issues. None keeps the
    // default certificate lifetime.
    enrol_ttl: Option<u64>,
    // `add <name>` on a terminal: the person has said who, and nothing else is
    // worth asking before the code is on screen. Skips the guided "choose words"
    // entry (Enter there only ever meant "generate them") and puts the file
    // alternative on the code screen instead, where it is relevant.
    quick: bool,
    // `--nearby`: use the LAN carrier only, with no signaling attempt.
    nearby: bool,
) -> Result<()> {
    pair_with_purpose(server, code, name, word, relay, internal, posture, enrol_ttl, quick, None, nearby).await
}

pub(crate) async fn temporary_cmd(server: &str, spec: filament_peerloop::access::AccessSpec, relay: bool) -> Result<()> {
    spec.validate()?;
    pair_with_purpose(server, None, None, None, relay, false, Vec::new(), None, true, Some(spec), false).await
}

#[allow(clippy::too_many_arguments)]
async fn pair_with_purpose(
    server: &str,
    mut code: Option<String>,
    name: Option<String>,
    mut word: Option<String>,
    relay: bool,
    internal: bool,
    posture: Vec<String>,
    enrol_ttl: Option<u64>,
    quick: bool,
    temporary_spec: Option<filament_peerloop::access::AccessSpec>,
    nearby: bool,
) -> Result<()> {
    if code.is_none() && word.is_none() && !interactive_allowed() {
        let (message, exit_code) = fleet_ui::pair_ui::err_pair_interactive();
        eprintln!("{message}");
        std::process::exit(exit_code);
    }
    // INTERACTIVE GATE (scripts safe by default, see `interactive_allowed`).
    //   * `pair` with no code AND no --word -> guided CREATE entry. Empty submit
    //     falls back to today's auto-mint; typed words become the chosen password.
    //   * `pair <malformed>` (a positional that isn't a valid claim shape) ->
    //     banner, then guided CLAIM entry PRE-FILLED with the normalized input.
    // When the gate is closed we keep EXACTLY today's behavior below.
    //
    // If the guided CREATE entry runs, it mints the nameplate ONCE here and shows
    // it in the preview; we carry it forward so the code we actually create uses
    // the SAME number the user saw (no shown-one-number, got-another mismatch).
    let mut preview_nameplate: Option<String> = None;
    if word.is_none() && interactive_allowed() {
        let malformed = code.as_deref().filter(|c| {
            // A "valid claim shape" is words + a trailing dash-group; anything that
            // split_code can't peel into (nameplate, non-empty words) is malformed.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            pw.is_empty() || np.is_empty()
        });
        match (&code, malformed) {
            // `add <name>`: generated words, no entry. --word still chooses them.
            (None, _) if quick => {}
            // No code at all -> CREATE entry.
            (None, _) => {
                let auto_np = crate::pake::words::mint_pair_nameplate();
                match codeentry::run(
                    "  add / choose words  ",
                    codeentry::Mode::Create,
                    "",
                    &auto_np,
                )? {
                    codeentry::Outcome::Submitted(words) => {
                        word = Some(words);
                        // Reuse the SAME nameplate we just previewed, so the code
                        // we mint matches the number the user saw.
                        preview_nameplate = Some(auto_np);
                    }
                    // They typed a code they were GIVEN. Accept it, exactly as
                    // `join <code>` does, instead of minting a second code from
                    // its words that nobody on the other side is waiting on.
                    codeentry::Outcome::Claim(given) => {
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  accepting the code you were given:  tunlion join {given}"),
                        ));
                        code = Some(given);
                    }
                    // Empty submit -> fall through to auto-mint, but still keep the
                    // previewed nameplate so an empty (auto-words) create reuses it.
                    codeentry::Outcome::Empty => preview_nameplate = Some(auto_np),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                    codeentry::Outcome::Interrupted => {
                        crate::exit_codes::interrupted_exit(crate::exit_codes::INTERRUPTED)
                    }
                }
            }
            // Malformed positional -> banner + prefilled CLAIM entry.
            (Some(raw), Some(_)) => {
                malformed_entry_banner(raw);
                let prefill = crate::pake::norm_code(raw);
                match codeentry::run("  add / code  ", codeentry::Mode::Claim, &prefill, "")? {
                    codeentry::Outcome::Submitted(c) | codeentry::Outcome::Claim(c) => code = Some(c),
                    // Empty submit on a claim-fix means "give up on this code".
                    codeentry::Outcome::Empty => return Err(cancelled()),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                    codeentry::Outcome::Interrupted => {
                        crate::exit_codes::interrupted_exit(crate::exit_codes::INTERRUPTED)
                    }
                }
            }
            // A well-formed positional -> no prompt, proceed as today.
            (Some(_), None) => {}
        }
    }
    // STEERING: --word lets the creator choose the SPAKE2 password. The positional
    // `code` arg still means "claim", so --word + a code is contradictory.
    if word.is_some() && code.is_some() {
        bail!(
            "--word chooses your OWN pairing words (creator); it can't be combined with a code to claim. Drop one."
        );
    }
    // A custom phrase must clear the password gate (Decision #3) BEFORE we touch
    // the network. Normalize with the SHARED norm_code so the echoed/created code
    // is exactly what SPAKE2 will hash, then validate against the blocklist.
    let custom_words: Option<String> = match &word {
        Some(w) => {
            let (words, _np) = crate::pake::split_chosen_code(&crate::pake::norm_code(w));
            if let Err(why) = crate::pake::words::validate_chosen_password(&words, &display_name())
            {
                bail!("'{w}' is too weak: {why}");
            }
            Some(words)
        }
        None => None,
    };
    // Debug lines (ICE, link adoption, source locations) are not part of a
    // pairing's output; when a SAVED setting turned them on, say so once.
    if let Some(note) = ui::saved_debug_note() {
        ui::say(&note);
    }
    if internal {
        // Action-first setup: use the existing atomic, owner-only key store.
        // Guided cancellation and invalid input above cannot mint an identity.
        crate::identity_flow::ensure_user_key(false)?;
    }
    let my_uid = mk_uid("p");
    let transport_context = crate::transport_context::for_root(&crate::settings::config_dir())?;
    // The home screen may already have opened this connection while the
    // person was choosing (preconnect.rs); otherwise connect now, as always.
    // `--nearby` never touches the server. A plain code also falls back to the
    // LAN carrier when signaling is unreachable; owner enrolment and temporary
    // access stay server-only because this carrier issues neither.
    if nearby {
        if internal || temporary_spec.is_some() || FOR_PERSON.load(std::sync::atomic::Ordering::Relaxed) {
            bail!("--nearby carries a plain pairing only; this operation needs the server");
        }
        return match &code {
            Some(c) => crate::lan_pair::join_standalone(c, name, true).await,
            None => {
                let words = custom_words.clone().unwrap_or_else(crate::pake::words::mint_words);
                let np = preview_nameplate.clone().unwrap_or_else(crate::pake::words::mint_pair_nameplate);
                crate::lan_pair::host_standalone(words, np).await
            }
        };
    }
    let (sio, tx, mut rx) = match crate::preconnect::take(server).await {
        Some(warm) => warm,
        None => {
            let (tx, rx) = mpsc::unbounded_channel::<Ev>();
            match net::connect_signaling(&transport_context, server, tx.clone()).await {
                Ok(sio) => (sio, tx, rx),
                Err(e) if !internal && temporary_spec.is_none() && !FOR_PERSON.load(std::sync::atomic::Ordering::Relaxed) => {
                    ui::say(&ui::paint(ui::Tone::Dim, &format!("  server unreachable ({e:#}); trying the local network")));
                    return match &code {
                        Some(c) => crate::lan_pair::join_standalone(c, name, false).await,
                        None => {
                            let words = custom_words.clone().unwrap_or_else(crate::pake::words::mint_words);
                            let np = preview_nameplate.clone().unwrap_or_else(crate::pake::words::mint_pair_nameplate);
                            crate::lan_pair::host_standalone(words, np).await
                        }
                    };
                }
                Err(e) => return Err(e),
            }
        }
    };
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick), the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    // C30: the session repairs the solo-room membership/lease if the join dies.
    //
    // Only the CREATOR desires its solo room. A claimer leaves it the moment
    // `pair-matched` arrives, and its first tick runs right after `pair-claim`
    // goes out, so desiring the solo room here put a `sync` naming it on the
    // wire behind the claim. When the server handled that sync after the
    // claimer's `join` of the creator's room, it moved the claimer back out:
    // the creator saw the claimer leave and drop its link, and every SPAKE2
    // message in that window came back `signal-refused`. Windows CI hit that
    // ordering on most runs. The claimer's desire is set when `pair-matched`
    // names the room, as the code-claim receive path already does.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    if code.is_none() {
        sess.room = Some(solo.clone());
    }
    sess.emit(
        &sio,
        "join",
        json!({ "room": solo, "name": display_name(), "uid": my_uid }),
    )
    .await;
    // A code that looks like a one-time TRANSFER code (word-word-NNN, 2-3 digit
    // trailing) typed into `pair`, which runs the PAKE pairing ceremony,
    // redirect clearly before the handshake stalls against a peer that isn't
    // pairing. ADVISORY only (by trailing-number width); PAKE still authenticates.
    if let Some(c) = &code {
        if regex_lite_code(c) && !looks_like_pake_code(c) {
            bail!(
                "'{c}' looks like a one-time TRANSFER code (from `tunlion send --code`), not a pairing code.\n  \
                 To receive that transfer: run `tunlion receive {c}`\n  \
                 An add code ends in a 4-digit number, e.g. `brave-otter-3141`."
            );
        }
    }
    let creator = code.is_none();
    // L1-a: the spoken code is split CLIENT-SIDE into (nameplate, password). The
    // password (words) NEVER leaves this process; only the nameplate is sent.
    let mut my_words; // the password (creator mints; claimer types)
    let mut my_nameplate;
    match &code {
        Some(c) => {
            // An INVITATION is not a pairing code, and pasting one here is the
            // obvious mistake: `add --for` prints the token on screen beside a
            // QR, so the natural next move is to paste it into the verb that
            // just produced it. Without this the token is sent as a nameplate,
            // the server rejects it, and the user is told "codes burn after one
            // use" about a token that was never claimed, with a remedy
            // (`re-run tunlion add`) that mints a code and cannot help.
            // PROTOCOL LITERAL: frozen, do not rename (shared constant).
            if c.starts_with(crate::file_io::INVITE_PREFIX) {
                bail!("{}", invitation_not_a_code_msg());
            }
            // Claimer: normalize the typed code, split, send ONLY the nameplate.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!(
                    "that code doesn't look right, expected something like brave-otter-ruby-3141"
                );
            }
            my_words = pw;
            my_nameplate = np.clone();
            ui::say(&format!("  Joining with code {}", ui::paint(ui::Tone::Brand, &crate::pake::norm_code(c))));
            // Each step below is one line, ending in one line that says what
            // this device became.
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 }))
                .await
                .ok();
        }
        None => {
            // Creator: use the user's chosen words (--word) or mint them; the
            // nameplate is ALWAYS machine-minted. Ask the server to allocate ONLY
            // the nameplate. The full code is displayed from our own words when
            // pair-ok arrives (the server never echoes any words).
            my_words = custom_words
                .clone()
                .unwrap_or_else(crate::pake::words::mint_words);
            // Reuse the nameplate the guided entry already previewed (if any), so
            // the created code matches what the user saw; otherwise mint fresh.
            my_nameplate = preview_nameplate
                .clone()
                .unwrap_or_else(crate::pake::words::mint_pair_nameplate);
            // STEERING: echo the normalized code we're about to create so the
            // creator sees EXACTLY what their peer must type (== what SPAKE2 hashes).
            if custom_words.is_some() {
                ui::say(&format!(
                    "  using your words: {}",
                    ui::paint(ui::Tone::Brand, &format!("{my_words}-{my_nameplate}"))
                ));
            }
            sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 }))
                .await
                .ok();
        }
    }

    let mut conn = Conn::for_command(
        transport_context,
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,                    // relay_only
        None,                     // to_filter
        false,                    // warm_standby default (pair is one-shot)
        direct::direct_enabled(), // direct_ok: env gate only (no L2 acceptor here)
        crate::host_impl::cli_log(),
        crate::host_impl::cli_host(),
    );
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Bounded force-exit guarantee: the Interrupted bail unwinds and drops
            // the peers, and a webrtc/quinn drop can itself deadlock. Arm a
            // watchdog so Ctrl-C always exits promptly regardless.
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut prompted = false;
    // True when the petname came from the peer's own name rather than --name, so
    // the success line can say how to change it.
    let mut named_by_default = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)

    // ---- L1-a PAKE state (shared ceremony) ----------------------------------
    // The agreed pinned secret (HKDF(K)); set ONLY after key confirmation passes.
    // `pair` PERSISTS it (a known device); the transfer path runs the SAME
    // ceremony but DISCARDS it. The ceremony state machine lives in
    // `pake_ceremony::Ceremony` and is driven identically by both flows.
    let mut agreed_secret: Option<String> = None;
    // Peer identity cert received via identity-expose inside the authed PAKE channel.
    // The flow exposes EXACTLY ONE device + its cert; privacy test asserts on actual wire payload.
    let mut peer_identity_cert: Option<identity::DeviceCert> = None;
    // A certless device offers its device key once, so an owner running
    // `add --internal` has something to certify.
    let mut sent_enrol_offer = false;
    // The certificate this side ISSUED to a certless peer, held until the
    // ceremony completes so it can be stored together with the pair secret.
    let mut issued_cert: Option<(identity::DeviceCert, Vec<String>)> = None;
    // Set once the owner's answer has been handled. A device that OFFERED its key
    // must not finish the ceremony before the answer lands: the owner sends the
    // grant only after seeing the offer, so completing on the pairing result alone
    // exits first and the certificate is never stored. That is exactly what left
    // `add --internal` reporting success on the owner side while the device stayed
    // EXTERNAL.
    let mut enrol_settled = false;
    // Set when the owner's enrol-grant was persisted: this device JOINED the
    // owner's mesh, so the peer is not someone else's device after all.
    let mut joined_mesh = false;
    let mut enrol_deadline: Option<Instant> = None;
    // OWNER SIDE of "Is <device> one of your devices?": the question in flight
    // (off the event loop), and the offer it is about (peer sid, device key).
    let mut own_prompt: Option<tokio::task::JoinHandle<bool>> = None;
    let mut pending_offer: Option<(String, [u8; 32])> = None;
    // After a "yes": the device must say it stored the certificate before our
    // record says it is ours.
    let mut ack_deadline: Option<Instant> = None;
    // OFFER SIDE: the owner said a person is deciding.
    let mut got_hold = false;
    // Peers whose transport hint explicitly named `client: browser`, kept per
    // sid so a bystander in the room cannot label the PAKE partner. Advisory
    // only: the outcome below trusts it only for the exact ceremony partner,
    // and never against a certificate or a key offer.
    let mut browser_peers: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // OFFER SIDE: this device holds no certificate, so it offers its key (and
    // re-sends it until answered) and waits, bounded, for the answer.
    let certless_at_start = local_device_cert().is_none();
    let mut offer_resend_at: Option<Instant> = None;
    let mut enrol_declined = false;
    // OWNER SIDE: the operator asked for one of its devices, so a certless
    // peer's offer is waited for, and its absence is reported, never silent.
    let mut offer_seen = false;
    let mut offer_wait_until: Option<Instant> = None;
    // Our answer to the offer, re-sent verbatim when the offer is re-sent.
    let mut offer_answer: Option<Value> = None;
    // The offer arrived but did not open or prove its key: said plainly.
    let mut offer_failed_proof = false;
    let mut unconfirmed_grant = false;
    // OFFER SIDE: a certificate arrived but did not verify for this device.
    let mut grant_refused: Option<String> = None;
    // "Verified end to end" is printed once, when key confirmation passes.
    let mut verified_shown = false;
    // Delivery of our identity-expose and receipt of the peer's (see
    // `filament_peerloop::expose`), and our acknowledgement of the peer's,
    // built once so every copy is the same bytes.
    let mut expose_x = filament_peerloop::expose::ExposeExchange::new();
    let mut expose_ack: Option<Value> = None;
    let mut identity_exchange_window: Option<std::time::Instant> = None;
    // Peer signaling sid we run the PAKE with (set when the link is adopted).
    let mut pake_peer: Option<String> = None;
    let caps = pair_v2_caps();
    // Start our SPAKE2 ceremony immediately: identity = nameplate, password =
    // words. Both sides MUST pass identical password AND nameplate (spec §3.1).
    // Fixed convention for plain pair: Device-scoped (device-to-device). Scope byte is derived from the authenticated introduction token, not a local guess. Both sides must pass same scope or confirmation fails.
    let scope = crate::identity::IntroScope::Device.to_byte();
    let mut temporary = temporary_spec.map(crate::temporary_session::Session::host).transpose()?;
    let mut cer = match temporary.as_ref() {
        Some(session) => session.ceremony(&my_words, &my_nameplate),
        None => Ceremony::new(&my_words, &my_nameplate, caps.clone(), scope),
    };
    // Say in our PAKE payloads whether we will send a certificate, so a peer
    // that acknowledges identity-expose knows to wait for it.
    let exposes_at_start = temporary.is_none() && local_device_cert().is_some();
    cer.set_exposes(exposes_at_start);
    if exposes_at_start {
        expose_x.promise();
    }
    // A joining client waits for the host's first element so the authenticated
    // purpose can choose temporary access without ever entering permanent pairing.
    let mut host_element_received = creator;
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL
    // The pairing peer left before the ceremony finished. Give a short grace
    // for a transient reconnect, then FAIL FAST, don't orphan in the room
    // for the full 10-min TTL (the D3/D5 divergence the monitor kept
    // catching: creator's connect failed, it quit, claimer sat silent).
    // Once the code is CLAIMED, the ceremony must finish in seconds. Bound it:
    // if it hasn't completed within this budget, the peer disconnected or could
    // never connect, fail fast instead of orphaning in the room for the full
    // 600s TTL (the D3/D5 divergence the monitor kept catching). 60s is generous
    // (covers a slow cross-NAT WebRTC with its 3×15s establishment retries);
    // TUNLION_PAIR_GRACE_SECS shortens it for gate 17b.
    let ceremony_budget = Duration::from_secs(
        std::env::var("TUNLION_PAIR_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let mut ceremony_deadline: Option<Instant> = None;
    // Gate 17b hook: connect but never complete, so the ceremony budget fires
    // deterministically (same-machine pairs otherwise finish in ~1s).
    let stall = test_hooks::pair_stall();
    // The LAN carrier shares this code's one-winner state with signaling.
    let mut pair_code: Option<PairCode> = None;
    let mut lan_host: Option<crate::lan_pair::HostHandle> = None;
    let mut signaling_token: Option<u64> = None;
    let mut signaling_blocked = false;

    let result = async {
    loop {
        // A LAN ceremony that confirmed hands its outcome here, where the one
        // store call and the one code decision live.
        let lan_event = lan_host.as_mut().and_then(|h| h.events.try_recv().ok());
        if let Some(ev) = lan_event {
            match ev {
                crate::lan_pair::HostEvent::Outcome(out) => {
                    let won = pair_code.as_ref().is_some_and(|c| c.confirm(out.token, Instant::now()));
                    if won {
                        crate::lan_pair::persist_plain(&out)?;
                        if let Some(mut h) = lan_host.take() { h.shutdown().await; }
                        return Ok(());
                    }
                }
                crate::lan_pair::HostEvent::Failed { why, .. } => {
                    ui::debug(&format!("lan pairing attempt failed: {why}"));
                }
            }
        }

        // OFFER SIDE: offer this device's key once the key exchange is done,
        // and keep offering until the other side answers. Nothing is conferred
        // by offering: the owner device decides (see `enrol_offer_decision`).
        if temporary.is_none()
            && certless_at_start
            && agreed_secret.is_some()
            && !enrol_settled
            && offer_resend_at.is_none_or(|t| Instant::now() >= t)
            && enrol_deadline.is_none_or(|dl| Instant::now() < dl)
        {
            if let (Some(pid2), Some(k)) = (pake_peer.clone(), cer.k()) {
                let fps = match conn.link(&pid2) {
                    Some(l) => match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    },
                    None => None,
                };
                let dpub = crate::overlay::overlay_pubkey_bytes().ok();
                if let (Some((my_fp, their_fp)), Some(dpub)) = (fps, dpub) {
                    let sign = |m: &[u8]| crate::overlay::overlay_sign_possession(m).ok();
                    if let Some(payload) = build_enrol_offer(
                        k, &my_fp, &their_fp, cer.caps_canon(), cer.scope(), dpub, &display_name(), &sign,
                    ) {
                        sio.emit("signal", json!({ "to": pid2, "data": payload })).await.ok();
                        if !sent_enrol_offer {
                            enrol_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(15));
                        }
                        sent_enrol_offer = true;
                        offer_resend_at = Some(Instant::now() + ENROL_OFFER_RESEND);
                    }
                }
            }
        }
        // OWNER SIDE: asked for one of its devices, the key exchange is done,
        // and the peer presented no certificate: its offer is due.
        if internal && agreed_secret.is_some() && offer_wait_until.is_none() && temporary.is_none() {
            offer_wait_until = Some(Instant::now() + ENROL_OFFER_WAIT);
        }
        // The owner answered the question (owner side, see `enrol-offer`).
        if own_prompt.as_ref().is_some_and(|h| h.is_finished()) {
            let yes = own_prompt.take().expect("checked").await.unwrap_or(false);
            if let Some((to, dpub)) = pending_offer.take() {
                let owner_key = load_owner_key();
                let caps = default_device_ceiling();
                let sealed = match (yes, cer.k(), owner_key.as_ref()) {
                    (true, Some(k), Some(owner_key)) => seal_enrol_grant(k, owner_key, dpub, &caps, None),
                    _ => None,
                };
                match sealed {
                    Some((cert, payload)) => {
                        sio.emit("signal", json!({ "to": to, "data": payload.clone() })).await.ok();
                        offer_answer = Some(payload);
                        issued_cert = Some((cert, caps.clone()));
                        ack_deadline = Some(Instant::now() + ENROL_ACK_WAIT);
                        ui::say(&step_line(&format!(
                            "Certified with your owner key \u{b7} it may {}",
                            plain_caps(&caps)
                        )));
                    }
                    None => {
                        let decline = json!({"type": "enrol-decline", "v": 1});
                        sio.emit("signal", json!({ "to": to, "data": decline.clone() })).await.ok();
                        offer_answer = Some(decline);
                        ui::say(&ui::paint(ui::Tone::Dim, "  \u{b7} kept as a pairing: files only, no owner certificate"));
                    }
                }
            }
        }
        // The owner's decision stands either way (the certificate names only
        // that device's key); what is unknown is whether it was stored there,
        // and that is said rather than guessed.
        if ack_deadline.is_some_and(|dl| Instant::now() >= dl) {
            ack_deadline = None;
            unconfirmed_grant = true;
        }
        // Done when the petname is settled AND the PAKE agreed a secret (key
        // confirmation passed). The secret is HKDF(K), never transmitted, the
        // same on both sides; it drops straight into devices.json.
        if temporary.is_none() {
        if let Some(n) = petname.clone() {
            if let Some(sec) = agreed_secret.clone() {
                // The peer's certificate, and the acknowledgement of ours, are
                // waited for here. A peer that acknowledges identity-expose
                // (`expose_ack`) said whether it will send one, so the wait is
                // exact: until its certificate verified and ours was
                // acknowledged, bounded by the ceremony deadline below. A peer
                // that does not (0.9.1, the browser) gets the old short window.
                //
                // A device that holds NO certificate yet still has a device key,
                // and that key is the thing an owner must certify: the
                // certless device's key offer is sent (and re-sent) by the
                // block at the top of the loop, outside this wait.
                let legacy_window = !cer.peer_acks_expose()
                    && identity_exchange_window.map_or(false, |dl| std::time::Instant::now() < dl)
                    && peer_identity_cert.is_none();
                if legacy_window || expose_x.waiting(cer.peer_acks_expose(), cer.peer_will_expose()) {
                    // Fall through to the event loop: the frames being waited
                    // for are read there.
                } else {
                    // We offered our device key and the owner has not answered yet.
                    // Wait, bounded: if no grant arrives we finish as an ordinary
                    // pair, which is the pre-existing behaviour, so waiting can only
                    // add an outcome and never remove one.
                    // NOT `continue`: that jumps to the top of the loop and skips the
                    // event processing further down, so the ceremony would spin here
                    // for the whole window without ever READING the grant it is
                    // waiting for. Measured exactly that way: the owner logged the
                    // grant, the claimer logged "no grant arrived", and no signal was
                    // processed in between. Fall through to the event loop instead and
                    // re-enter this block on the next pass.
                    // Owner side: a question on screen, or a "yes" not yet
                    // confirmed, holds completion like an unanswered offer does.
                    let owner_deciding = own_prompt.is_some() || pending_offer.is_some() || ack_deadline.is_some();
                    // Asked for one of my devices, and a certless peer has not
                    // offered its key yet: wait for it (bounded), never finish
                    // as a plain pairing while it may still arrive.
                    let owner_expects_offer = internal
                        && !offer_seen
                        && peer_identity_cert.is_none()
                        && load_owner_key().is_some()
                        && offer_wait_until.is_some_and(|dl| Instant::now() < dl);
                    let awaiting_enrolment = owner_deciding || owner_expects_offer || certless_at_start && !enrol_settled && {
                        let dl = *enrol_deadline
                            .get_or_insert_with(|| Instant::now() + Duration::from_secs(15));
                        if Instant::now() >= dl {
                            ui::debug("enrol: no grant arrived; completing as an ordinary pair");
                            false
                        } else {
                            true
                        }
                    };
                    if !awaiting_enrolment {
                        // The peer said it would send its certificate and the
                        // one that came did not verify: never a pairing with an
                        // uncertified device. Nothing has been stored yet.
                        if let Some(unmet) = expose_x.unmet(cer.peer_acks_expose(), cer.peer_will_expose()) {
                            bail!("{}", expose_unmet_msg(&unmet, &n));
                        }
                        let same_person = peer_identity_cert
                            .as_ref()
                            .and_then(|cert| {
                                load_owner_key()
                                    .map(|owner| owner.public_key_bytes() == cert.user_pub)
                            })
                            .unwrap_or(false);
                        // External pairs currently receive only the baseline transfer
                        // capability. Do not render render_someone_else_banner or
                        // render_inter_user_form: pair has no bounded per-cap grant
                        // contract, so those surfaces would claim choices it ignores.
                        // Do not render render_pake_words: the pair code is not a
                        // transcript-derived SAS; showing it as trust would invert the
                        // MITM check. A real SAS belongs in the crypto gate.
                        // Fail-closed: check BEFORE any write if peer previously had identity and now does NOT expose
                        if same_person {
                            ui::say(&fleet_ui::pair_ui::render_same_person_banner(&n));
                        }
                        if peer_identity_cert.is_none() {
                            ui::debug("pair: completing without the peer's certificate");
                            let p = devices_path();
                            if let Ok(raw) = std::fs::read_to_string(&p) {
                                if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                                    if let Err(e) = identity::check_fail_closed(&arr, &n, None) {
                                        bail!("fail-closed: {}", e);
                                    }
                                }
                            }
                            // No cert: store secret only (legacy or first-pair no identity)
                            if let (Some(token), Some(code)) = (signaling_token, pair_code.as_ref()) {
                                if !code.confirm(token, Instant::now()) {
                                    bail!("this code was already used by a nearby device");
                                }
                            }
                            devices_store_v2(&n, &sec, &caps)?;
                            // ...unless WE certified them during this ceremony. Then the
                            // secret and the certificate belong in one record: the owner
                            // dials on the secret and judges on the certificate, and a
                            // row holding only one of them is either unreachable or
                            // "uncertified, trusted in full".
                            if let Some((cert, caps)) = issued_cert.as_ref() {
                                // allow_reanchor: the local user accepted this
                                // pairing ceremony, which is the owner decision
                                // that permits re-anchoring (e.g. reinstall).
                                // An explicit `--expires` is an END, not a cert
                                // lifetime to renew forever: record the device
                                // as a delegated principal with that end, the
                                // same record `join` produces for an invitation,
                                // so the gate, renewal and every live session
                                // enforce it. Without --expires the device is an
                                // ordinary fleet member and renews indefinitely.
                                let lifetime = cert.expires.saturating_sub(cert.issued);
                                let bounded = enrol_ttl
                                    .is_some()
                                    .then_some((caps.as_slice(), cert.expires, lifetime, lifetime));
                                if let Err(e) = devices_upsert_atomic(
                                    &n,
                                    Some(&sec),
                                    Some(cert),
                                    Some(caps),
                                    Some(identity::IntroScope::Device.to_byte()),
                                    None,
                                    bounded,
                                    true,
                                ) {
                                    ui::debug(&format!(
                                        "enrol: could not record the certificate: {e}"
                                    ));
                                }
                                let ceiling = crate::principal_ceiling_for(&n);
                                if let Some(hint) =
                                    shell_not_granted_hint(&n, caps, ceiling.as_deref())
                                {
                                    ui::say(&ui::paint(ui::Tone::Dim, &format!("  {hint}")));
                                }
                            }
                        } else {
                            // #23: atomic (secret,cert) together in ONE write, not separate writes.
                            // devices_store_v2 writes secret, store_provisional writes cert to temp file.
                            // If process crashes between them, cap_authorize sees new-secret + old-cert (or no cert)
                            // yielding wrong userPub. Fix: devices_upsert_atomic writes both fields together.
                            let pcert = peer_identity_cert.as_ref().unwrap();
                            if let (Some(token), Some(code)) = (signaling_token, pair_code.as_ref()) {
                                if !code.confirm(token, Instant::now()) {
                                    bail!("this code was already used by a nearby device");
                                }
                            }
                            // allow_reanchor: same accepted ceremony as above.
                            devices_upsert_atomic(
                                &n,
                                Some(&sec),
                                Some(pcert),
                                Some(&caps),
                                Some(scope),
                                None,
                                None,
                                true,
                            )
                            .context("atomic store secret+cert")?;
                            // Also store provisional for overlay check: on overlay failure, REMOVE the durable anchor
                            store_provisional_identity(&n, pcert).context("store provisional")?;
                        }
                        // A pairing between two DIFFERENT identities files the peer
                        // as EXTERNAL (someone else's, time-boxed, deny-by-default).
                        // That used to happen silently, even for `add <device>`,
                        // which reads as "make it one of mine". Say so, on both
                        // ends, and name the real path to one identity.
                        // Eval item 3: printed on BOTH sides of every pairing
                        // between two identities, including `--for person`,
                        // where EXTERNAL is exactly what was asked for. It is a
                        // surprise only when this side asked for one of ITS OWN
                        // devices (`internal`) and got a different identity.
                        if external_notice_applies(
                            internal,
                            same_person,
                            joined_mesh,
                            issued_cert.is_some(),
                            peer_identity_cert.is_some(),
                        ) {
                            let (headline, detail, steps) =
                                external_pairing_notice(&n, &display_name(), internal);
                            ui::caution(&headline, Some(detail.as_str()), &steps);
                        }
                        // Eval item 2: a device forgotten earlier and added again
                        // printed "joined your fleet" while the forget's key block
                        // still refused every send. On the OWNER side, a completed
                        // pairing the operator started is consent to lift that
                        // block; say so. A device REVOKED in place (record kept,
                        // `demote --to cut`) is not re-admitted by a pairing: say
                        // that openly and fail, never print "joined".
                        if load_owner_key().is_some() {
                            let peer_key = peer_identity_cert
                                .as_ref()
                                .map(|c| c.device_pub)
                                .or_else(|| issued_cert.as_ref().map(|(c, _)| c.device_pub));
                            if let Some(key) = peer_key {
                                match crate::fleet_support::lift_key_revocation(&key) {
                                    Ok(lifted) => {
                                        if let Some((_, at, _)) = lifted.first() {
                                            ui::say(&format!(
                                                "  {} {}",
                                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                                crate::fleet_support::readmit_line(&n, *at)
                                            ));
                                            let _ = crate::revocation_live::tell_daemon().await;
                                        }
                                    }
                                    Err(e) => bail!(
                                        "{n} paired, but it was forgotten earlier and its key is still refused here: {e}"
                                    ),
                                }
                            }
                            if crate::device_view::device_record_revoked(&n) {
                                bail!(
                                    "{n} paired, but it is REVOKED on this device, so it stays refused. \
                                     To let it back in:  tunlion promote {}",
                                    crate::refusal::word(&n)
                                );
                            }
                        }
                        // A member pairing with another device of the SAME
                        // identity (its owner, or a sibling) holds no owner key,
                        // so `same_person` is false here; it used to fall through
                        // to the EXTERNAL notice while the owner side said
                        // "joined your fleet". Both sides now report one
                        // relationship.
                        let same_identity_member = !same_person
                            && peer_identity_cert.as_ref().is_some_and(|c| {
                                local_device_cert().is_some_and(|mine| mine.user_pub == c.user_pub)
                            });
                        if same_person && FOR_PERSON.load(std::sync::atomic::Ordering::Relaxed) {
                            ui::caution(
                                &format!("'{n}' is one of your own devices, so it was kept as one, not filed as a person"),
                                Some(
                                    "it holds your identity's certificate, and pairing cannot make your own device someone else's",
                                ),
                                &[format!("tunlion devices forget {} -y", crate::refusal::word(&n))],
                            );
                        }
                        if same_person {
                            ui::say(&fleet_ui::pair_ui::render_same_person_success(&n));
                        } else if issued_cert.is_some() || joined_mesh {
                            // The one line that says what you got.
                            ui::say(&step_line(&enrolled_final_line(&n, joined_mesh)));
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                &format!("  next: tunlion send <file> --to {} \u{b7} tunlion devices", crate::refusal::word(&n)),
                            ));
                        } else if same_identity_member {
                            ui::say(&format!(
                                "  {} {} connected \u{b7} your devices",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                        } else {
                            ui::say(&format!(
                                "  {} {} connected \u{b7} remembered on both devices",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            if named_by_default {
                                ui::say(&ui::paint(
                                    ui::Tone::Dim,
                                    &format!("  saved as '{n}' \u{b7} rename any time: {}", rename_hint(&n)),
                                ));
                            }
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                &format!("  next: tunlion send <file> --to {}", crate::refusal::word(&n)),
                            ));
                            // What THIS device became, said plainly: the other
                            // side holds an identity and chose a pairing.
                            if certless_at_start && enrol_declined && peer_identity_cert.is_some() {
                                ui::say(&ui::paint(
                                    ui::Tone::Dim,
                                    &format!("  this device is paired with {n}, not one of its owner's devices"),
                                ));
                            }
                        }
                        // Never a silent downgrade: if "one of my devices" was the
                        // intent on either side and it did not happen, say so.
                        let peer_is_browser = pake_peer
                            .as_deref()
                            .is_some_and(|p| browser_peers.contains(p));
                        let outcome = enrolment_outcome(EnrolOutcomeInputs {
                            owner_asked_own: internal && load_owner_key().is_some(),
                            certified_here: issued_cert.is_some(),
                            already_same_owner: same_person || same_identity_member,
                            peer_presented_cert: peer_identity_cert.is_some(),
                            peer_is_browser,
                            offer_seen,
                            offer_failed_proof,
                            unconfirmed_grant,
                            offered_here: certless_at_start && sent_enrol_offer,
                            joined_here: joined_mesh,
                            declined: enrol_declined,
                            grant_refused: grant_refused.clone(),
                        });
                        let failed = report_enrolment_outcome(&outcome, &n);
                        if expose_x.should_linger() {
                            // We acknowledged the peer's certificate, and that
                            // acknowledgement may be lost: answer re-sent copies
                            // until the peer leaves or stops sending.
                            linger_answering_expose(&sio, &mut rx, &mut expose_x, pake_peer.as_deref(), expose_ack.as_ref()).await;
                        } else {
                            tokio::time::sleep(Duration::from_millis(300)).await; // let acks flush
                        }
                        let _ = sio.disconnect().await;
                        if let Some(e) = failed {
                            return Err(e);
                        }
                        if let Some(mut h) = lan_host.take() {
                            h.shutdown().await;
                        }
                        offer_background_after_pairing();
                        return Ok(());
                    } // close: not awaiting an enrolment answer
                } // close identity_exchange_window else
            }
        }
        }
        if let Some(session) = temporary.as_mut() {
            if let Some(pid) = pake_peer.as_deref() {
                if session.progress(&cer, &conn, pid).await? {
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
        }
        let active_temporary = temporary.as_ref().is_some_and(|session| session.is_active());
        if !active_temporary && Instant::now() > deadline {
            bail!("timed out, the code was never used (codes expire after 10 minutes)");
        }
        // Fail fast: the code was claimed but the ceremony didn't finish in
        // time, the peer disconnected or never connected.
        // A person deciding "is this one of mine" is not a stalled ceremony:
        // the key exchange is done, so the fail-fast budget does not apply.
        let person_deciding = agreed_secret.is_some()
            && (own_prompt.is_some() || pending_offer.is_some() || ack_deadline.is_some() || (got_hold && !enrol_settled));
        if let Some(dl) = ceremony_deadline.filter(|_| !person_deciding && !active_temporary && !(temporary.is_some() && cer.secret().is_some())) {
            if Instant::now() > dl {
                if agreed_secret.is_some() {
                    if let Some(unmet) = expose_x.unmet(cer.peer_acks_expose(), cer.peer_will_expose()) {
                        let who = petname.clone().unwrap_or_else(|| "the other device".into());
                        bail!("{}", expose_unmet_msg(&unmet, &who));
                    }
                }
                bail!(
                    "the other device disconnected before setup finished; keep `tunlion add` running on one device while the other runs `tunlion join <code>`, then try again"
                );
            }
        }
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead

        // ---- L1-a PAKE progression (runs every iteration) ------------------
        // 1) Once we know the peer's signaling sid, send our SPAKE2 element over
        //    the opaque `signal` relay (the server cannot read it).
        if let Some(pid) = pake_peer.clone() {
            // gate 17b (TUNLION_TEST_PAIR_STALL): never send our SPAKE2 element,
            // so the exchange can't complete on either side and the ceremony's
            // fail-fast `ceremony_deadline` fires, proving the no-10-min-orphan
            // guard. Test-only: `stall` is set solely by that env var.
            if !stall && host_element_received {
                if let Some(data) = cer.take_msg_payload() {
                    sio.emit("signal", json!({ "to": pid, "data": data }))
                        .await
                        .ok();
                }
            }
            // 2) Once K is derived AND both DTLS fingerprints are known, send the
            //    key-confirmation MAC over K + sorted fingerprints + caps. The MAC
            //    is gated on the fingerprints so a server that substitutes a DTLS
            //    cert produces a different fingerprint → the peer's verify fails.
            //    The confirmation carries our element too, so gate 17b's stall
            //    withholds it as well.
            if !stall && cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
            // Identity expose: after PAKE confirmation and secret agreed, if we have a local
            // device cert, send EXACTLY ONE device + its cert sealed under K-derived key
            // with possession signature, inside the authed channel. Server never sees
            // user key (sealed) and cannot substitute (possession sig binds to session).
            // Built once; a peer that acknowledges it gets the same frame again on the
            // #597 backoff until it does (see `filament_peerloop::expose`). Facing such
            // a peer only a certificate advertised at the start is sent: a device
            // certified during this ceremony was certified BY the peer, which holds it.
            if temporary.is_none()
                && agreed_secret.is_some()
                && !expose_x.offered()
                && (exposes_at_start || !cer.peer_acks_expose())
            {
                if let (Some(local_cert), Some(k)) = (local_device_cert(), cer.k()) {
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    if let Some((my_fp, their_fp)) = fps {
                        let sign = |m: &[u8]| crate::overlay::overlay_sign_possession(m).ok();
                        if let Some(payload) =
                            build_identity_expose(k, &my_fp, &their_fp, cer.caps_canon(), cer.scope(), &local_cert, &sign)
                        {
                            expose_x.offer(payload);
                        }
                    }
                }
            }
            let peer_acks = cer.peer_acks_expose();
            if let Some(payload) = expose_x.take_due(Instant::now(), peer_acks) {
                let ack_note = if peer_acks { "" } else { " (peer does not acknowledge)" };
                if test_hooks::drop_identity_expose() {
                    ui::debug(&format!("pair: identity-expose to {pid} dropped by the test hook{ack_note}"));
                } else {
                    sio.emit("signal", json!({"to": pid, "data": payload})).await.ok();
                    ui::debug(&format!("pair: identity-expose sent to {pid}{ack_note}"));
                }
            }
        }

        let poll_interval = temporary.as_ref().map_or(Duration::from_secs(2), |session| session.poll_interval());
        // A ceremony in flight re-sends its current message on a sub-second
        // backoff from the progression block above, so tick at that cadence.
        let expose_pending = expose_x.waiting(cer.peer_acks_expose(), cer.peer_will_expose());
        let poll_interval = if (pake_peer.is_some() && agreed_secret.is_none()) || own_prompt.is_some() || ack_deadline.is_some() || expose_pending {
            poll_interval.min(Duration::from_millis(100))
        } else {
            poll_interval
        };
        let ev = match tokio::time::timeout(poll_interval, rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                sess.invalidate(); // C30: fresh sid, re-assert next tick
            }
            // C30 phase 2: same reconciliation as the Welcome arm above. Pairing
            // waits on the peer arriving in the room, so a dropped `peer-joined`
            // would otherwise strand the ceremony until the deadline.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                }
            }
            Ev::PairOk(_v) => {
                // L1-a: the server allocated our nameplate. Display the FULL code
                // from OUR OWN local mint (the server never echoed any words).
                let full = format!("{my_words}-{my_nameplate}");
                ui::timing("pairing code shown");
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!(
                    "      {}",
                    ui::paint(ui::Tone::Brand, &full.to_uppercase())
                ));
                ui::say("");
                // The prototype's code screen: the code, where to type it, keep
                // this open. Everything else fits on one dim line.
                // What the other device will BECOME, before anyone types the
                // code: the wrong outcome must not be the easy one to miss.
                let caps = if posture.is_empty() { default_device_ceiling() } else { posture.clone() };
                ui::say(&code_screen_promise(
                    petname.as_deref(),
                    internal && load_owner_key().is_some(),
                    FOR_PERSON.load(std::sync::atomic::Ordering::Relaxed),
                    load_owner_key().is_some() && interactive_allowed(),
                    &caps,
                ));
                ui::say("  On the other device: tunlion join");
                ui::say("  Enter this code there. Keep this window open.");
                if interactive_allowed() {
                    ui::say(&ui::qr_or_text(&full, 6));
                }
                // The HOW question was skipped to get here in one step, so its
                // other answer is offered here instead: the file path was once
                // reachable only by a flag nobody was told about.
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    if quick {
                        "  works once \u{b7} 10 min \u{b7} not both here? tunlion add --via file"
                    } else {
                        "  works once \u{b7} 10 min \u{b7} or scan it in the Tunlion app"
                    },
                ));
                // The same code is visible on the LAN while it is on screen.
                let mut id = [0u8; 16];
                if getrandom::getrandom(&mut id).is_ok() {
                    let code_state = PairCode::new(id, Instant::now());
                    ui::say(&format!("  nearby: {}  (compare with the other screen)", code_state.label()));
                    match crate::lan_pair::spawn_host(code_state.clone(), my_words.clone(), my_nameplate.clone()).await {
                        Ok(h) => lan_host = Some(h),
                        Err(e) => ui::debug(&format!("lan pairing unavailable: {e:#}")),
                    }
                    pair_code = Some(code_state);
                }
            }
            Ev::PairCode(v) => {
                // v1 server (shouldn't happen for a v2 create, but be safe): a
                // legacy server-minted code means the peer can't PAKE-pair.
                let c = v["code"].as_str().unwrap_or("?");
                let _ = c;
                bail!(
                    "this server returned a legacy code. Update the server (or the peer) to pair securely."
                );
            }
            Ev::PairUsed(_) => {
                ui::say(&step_line("Code claimed"));
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                if let Some(code) = pair_code.as_ref() {
                    match code.begin(PairCarrier::Signaling, Instant::now()) {
                        Begin::Started(t) => signaling_token = Some(t),
                        Begin::Busy => {
                            signaling_blocked = true;
                            ui::say("  another device is pairing with this code; this claim cannot proceed");
                        }
                        Begin::Closed => {
                            signaling_blocked = true;
                            ui::say("  this code was already used; this claim cannot proceed");
                        }
                    }
                }
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                ui::say(&step_line("Code accepted"));
                sess.room = Some(room.clone()); // C30: desire moves with us
                sess.touch();
                sess.emit(
                    &sio,
                    "join",
                    json!({ "room": room, "name": display_name(), "uid": my_uid }),
                )
                .await;
            }
            Ev::PairError(v) => {
                // Creator nameplate collision: re-mint a FRESH nameplate (and
                // fresh words) and retry, never reuse a burned code.
                if creator && v["error"].as_str() == Some("taken") {
                    // Re-mint a FRESH nameplate; KEEP the creator's chosen words
                    // (--word), only mint fresh words when we minted them.
                    if custom_words.is_none() {
                        my_words = crate::pake::words::mint_words();
                    }
                    my_nameplate = crate::pake::words::mint_pair_nameplate();
                    cer.restart(&my_words, &my_nameplate);
                    sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 }))
                        .await
                        .ok();
                    continue;
                }
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => {
                        "that code's creator already left, ask them for a fresh one".to_string()
                    }
                    _ => format!(
                        "{}, codes burn after one use; a failed setup needs a FRESH code (re-run `tunlion add`)",
                        v["error"].as_str().unwrap_or("?")
                    ),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // The browser names its kind on the transport hint it sends
                // before any SDP. Record it per sid; the outcome only uses it
                // when this sid is the PAKE partner.
                if browser_hint(&data) {
                    browser_peers.insert(from.clone());
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Branch them
                // OUT of the WebRTC signal path (SDP/ICE) into the shared ceremony.
                // A `pake-confirm` verify ⇒ wrong password OR a server that
                // substituted a DTLS cert OR rewrote caps ⇒ ABORT, agree NOTHING.
                if matches!(
                    data["type"].as_str(),
                    Some("pake-msg") | Some("pake-confirm")
                ) {
                    if signaling_blocked {
                        continue;
                    }
                    match crate::pake_ceremony::partner_for(
                        pake_peer.as_deref(),
                        &from,
                        data["type"].as_str() == Some("pake-msg"),
                        crate::pake_ceremony::addressed_to(&data, &my_nameplate),
                        cer.has_k(),
                    ) {
                        crate::pake_ceremony::Partner::Ours => {}
                        crate::pake_ceremony::Partner::Switch => {
                            ui::debug(&format!(
                                "pair: {from} runs this code's ceremony; the first link was a bystander"
                            ));
                            pake_peer = Some(from.clone());
                            cer.rearm_msg();
                            // The default name was taken from the bystander's
                            // link: take it from the partner's own instead (its
                            // link is known by now, or its ChannelReady settles it).
                            if named_by_default {
                                petname = conn.link(&from).map(|l| l.name.clone());
                                if petname.is_none() {
                                    named_by_default = false;
                                    prompted = false;
                                }
                            }
                        }
                        crate::pake_ceremony::Partner::Ignore => continue,
                    }
                    pake_peer.get_or_insert(from.clone());
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    if !creator && !host_element_received && data["type"].as_str() == Some("pake-msg") {
                        use filament_peerloop::send::ceremony::inspect_temporary_binding;
                        if let Some(binding) = inspect_temporary_binding(&data)? {
                            let session = crate::temporary_session::Session::recipient(binding);
                            cer = session.ceremony(&my_words, &my_nameplate);
                            temporary = Some(session);
                            // Temporary access sends and expects no identity frames.
                            expose_x = filament_peerloop::expose::ExposeExchange::new();
                        }
                        host_element_received = true;
                    }
                    match cer.on_signal(&data, fp_ref) {
                        PakeInbound::Consumed => {
                            if let Some(sec) = cer.secret() {
                                agreed_secret = Some(sec.clone());
                                // Key confirmation passed: nobody in between
                                // (the server included) learned the code.
                                if !verified_shown && temporary.is_none() {
                                    verified_shown = true;
                                    ui::say(&step_line("Verified end to end"));
                                }
                                identity_exchange_window = Some(
                                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                                );
                            }
                        }
                        PakeInbound::Abort(why) => {
                            bail!(
                                "pairing REFUSED: {why}. Nothing was stored; ask for a FRESH code."
                            );
                        }
                        PakeInbound::Ignored => {}
                        // Our confirmation was lost: answer the peer's re-send.
                        PakeInbound::Reply(reply) => {
                            sio.emit("signal", json!({ "to": from, "data": reply }))
                                .await
                                .ok();
                        }
                    }
                    continue;
                }
                if temporary.is_some() && matches!(data["type"].as_str(), Some("enrol-offer" | "enrol-grant" | "enrol-decline" | "identity-expose")) {
                    bail!("temporary access refused an enrollment frame; no device was remembered");
                }
                // Identity expose: sealed cert + possession signature, inside authed PAKE channel.
                // Fixes holes A (confidentiality+integrity via K-derived seal, server never sees user_pub)
                // and B (replayable bearer: possession signature over session-bound confirm MAC, bound to device key).
                // A certless peer offered its device key. Certify it ONLY when the
                // operator asked for --internal: completing a pairing code proves a
                // human meant to pair, never that the machine is one of ours, and
                // this is the step that would otherwise turn "typed the code" into
                // "member of the mesh".
                // ALWAYS answer an offer, even to refuse it. Staying silent makes
                // the other side wait out its whole window before completing as an
                // ordinary pair, which put 15s on EVERY pairing where the peer is
                // certless and the operator did not ask to enrol. That is most of
                // them, and it regressed a gate that times the ceremony.
                if data["type"].as_str() == Some("enrol-offer") {
                    // A pairing code proves a human meant to PAIR, never that
                    // the other machine is theirs. So the owner key signs only on
                    // an explicit owner decision made on THIS device: `add <name>`
                    // / `--for device` said so before the code was shown, or the
                    // person answers "yes" to the question below, asked here and
                    // only here, on the device that holds the owner key.
                    // A re-sent offer gets the answer already given, verbatim:
                    // asking twice, or certifying twice, is never right.
                    if pake_peer.as_deref() != Some(from.as_str()) {
                        continue;
                    }
                    offer_seen = true;
                    if pending_offer.is_some() || own_prompt.is_some() {
                        sio.emit("signal", json!({ "to": from, "data": {"type": "enrol-hold", "v": 1} })).await.ok();
                        continue;
                    }
                    if let Some(answer) = offer_answer.clone() {
                        sio.emit("signal", json!({ "to": from, "data": answer })).await.ok();
                        continue;
                    }
                    let owner_key = load_owner_key();
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let opened = match (cer.k(), fps.as_ref(), owner_key.as_ref()) {
                        (Some(k), Some((my_fp, their_fp)), Some(_)) => open_enrol_offer(
                            k,
                            my_fp,
                            their_fp,
                            cer.caps_canon(),
                            cer.scope(),
                            &data,
                            crate::overlay::overlay_pubkey_bytes().ok(),
                        ),
                        _ => None,
                    };
                    let owner_here_now = owner_key.is_some();
                    let decide = enrol_offer_decision(EnrolOfferInputs {
                        owner_here: owner_key.is_some(),
                        operator_said_own: internal,
                        operator_said_person: FOR_PERSON.load(std::sync::atomic::Ordering::Relaxed),
                        offer_opened: opened.is_some(),
                        peer_can_hold: data["hold"].as_bool() == Some(true),
                        can_ask: interactive_allowed() && !crate::exit_codes::json_mode(),
                        already_asked: own_prompt.is_some() || pending_offer.is_some() || issued_cert.is_some(),
                    });
                    match (decide, opened, owner_key) {
                        (EnrolOfferDecision::Certify, Some(dpub), Some(owner_key)) => {
                            let caps: Vec<String> =
                                if posture.is_empty() { default_device_ceiling() } else { posture.clone() };
                            if let Some((cert, payload)) =
                                seal_enrol_grant(cer.k().map(|k| k.as_slice()).unwrap_or(&[]), &owner_key, dpub, &caps, enrol_ttl)
                            {
                                // Remember what we issued; the RECORD is written at
                                // ceremony completion, where the pair secret also
                                // exists (a row with a cert and no secret was never
                                // subscribed to, so `send --to` found nobody).
                                issued_cert = Some((cert, caps.clone()));
                                sio.emit("signal", json!({ "to": from, "data": payload.clone() })).await.ok();
                                offer_answer = Some(payload);
                                // A device that can say it stored the certificate
                                // is waited for, so a lost grant is re-sent.
                                if data["hold"].as_bool() == Some(true) {
                                    ack_deadline = Some(Instant::now() + ENROL_ACK_WAIT);
                                }
                                ui::say(&step_line(&format!(
                                    "Certified with your owner key \u{b7} it may {}",
                                    plain_caps(&caps)
                                )));
                            }
                        }
                        (EnrolOfferDecision::Ask, Some(dpub), Some(_)) => {
                            // Tell the device to wait for a person, then ask. The
                            // question runs off the event loop so the link stays
                            // serviced while it is on screen.
                            sio.emit("signal", json!({ "to": from, "data": {"type": "enrol-hold", "v": 1} }))
                                .await
                                .ok();
                            let who = petname
                                .clone()
                                .or_else(|| conn.link(&from).map(|l| l.name.clone()))
                                .unwrap_or_else(|| "this device".to_string());
                            pending_offer = Some((from.clone(), dpub));
                            own_prompt = Some(tokio::task::spawn_blocking(move || ask_is_own_device(&who)));
                        }
                        // Refused, or not ours to decide. ALWAYS answer an offer,
                        // even to refuse it: silence makes the other side wait
                        // out its window (15s on every such pairing, which
                        // regressed a timed gate).
                        _ => {
                            if opened.is_none() {
                                ui::debug("enrol: offer did not open or its possession proof failed; declined");
                                offer_failed_proof = owner_here_now;
                            }
                            let decline = json!({"type": "enrol-decline", "v": 1});
                            sio.emit("signal", json!({ "to": from, "data": decline.clone() })).await.ok();
                            offer_answer = Some(decline);
                        }
                    }
                    continue;
                }
                // The owner is deciding: keep waiting (bounded) instead of
                // completing as an ordinary pair after the short window.
                if data["type"].as_str() == Some("enrol-hold") {
                    if sent_enrol_offer && !enrol_settled {
                        got_hold = true;
                        enrol_deadline = Some((Instant::now() + ENROL_HOLD_WAIT).min(deadline));
                        let owner = conn.link(&from).map(|l| l.name.clone()).unwrap_or_else(|| "the other device".into());
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  \u{b7} waiting for {owner} to confirm this is one of its owner's devices"),
                        ));
                    }
                    continue;
                }
                // The device stored the certificate we issued after the
                // question: only now does our record say so.
                if data["type"].as_str() == Some("enrol-ack") {
                    if ack_deadline.is_some() && pake_peer.as_deref() == Some(from.as_str()) {
                        ack_deadline = None;
                    }
                    continue;
                }
                // The owner certified us. Persist exactly what `join` persists, so a
                // device enrolled by code is indistinguishable from one enrolled by
                // invitation: same certificate, same meeting point, same policy.
                // Refused, or the peer is not enrolling. Settle at once rather
                // than sitting out the window: the answer has arrived, it is just
                // "no", and an ordinary pair is exactly what happens next.
                if data["type"].as_str() == Some("enrol-decline") {
                    if !enrol_settled && pake_peer.as_deref() == Some(from.as_str()) {
                        enrol_settled = true;
                        enrol_declined = true;
                    }
                    continue;
                }
                // A re-sent grant after ours is stored: say "stored" again.
                if data["type"].as_str() == Some("enrol-grant") && joined_mesh {
                    sio.emit("signal", json!({ "to": from, "data": {"type": "enrol-ack", "v": 1} })).await.ok();
                    continue;
                }
                if data["type"].as_str() == Some("enrol-grant") {
                    if let Some(k) = cer.k() {
                        if let (Some(nh), Some(sh)) = (
                            data.get("nonce").and_then(|v| v.as_str()),
                            data.get("sealed").and_then(|v| v.as_str()),
                        ) {
                            if let (Ok(nb), Ok(sb)) = (hex::decode(nh), hex::decode(sh)) {
                                if nb.len() == 12 {
                                    let mut na = [0u8; 12];
                                    na.copy_from_slice(&nb);
                                    let sk = identity::sealing_key_from_k(k);
                                    if let Ok(pt) = identity::open_sealed(&sk, &na, &sb) {
                                        if let Ok(grant) = serde_json::from_slice::<Value>(&pt) {
                                            enrol_settled = true;
                                            match persist_mesh_grant(&grant) {
                                                Ok(()) => {
                                                    joined_mesh = true;
                                                    // The owner asked a person first and
                                                    // records the certificate only once we
                                                    // say we stored it.
                                                    {
                                                        sio.emit("signal", json!({
                                                            "to": from,
                                                            "data": {"type": "enrol-ack", "v": 1}
                                                        })).await.ok();
                                                    }
                                                    ui::say(&step_line(&format!(
                                                        "Certified by {}'s owner key",
                                                        ui::paint(
                                                            ui::Tone::Bold,
                                                            grant["owner_name"].as_str().unwrap_or("the owner")
                                                        )
                                                    )));
                                                }
                                                Err(e) => {
                                                    grant_refused = Some(e.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if data["type"].as_str() == Some("identity-expose") {
                    // Every way this frame can fail to yield a certificate used to
                    // be a silent fall-through, so a pairing that completed without
                    // the peer's certificate (filed NEEDS REVIEW, "no certificate")
                    // left no trace of why. Each refusal now says which check.
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let opened = match cer.k() {
                        Some(k) => open_identity_expose(
                            &data,
                            k,
                            fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
                            cer.caps_canon(),
                            cer.scope(),
                            crate::overlay::overlay_pubkey_bytes().ok(),
                            identity::now_secs(),
                        ),
                        None => Err("no key exchange yet"),
                    };
                    let verdict = match opened {
                        Ok(cert) => {
                            ui::debug(&format!("pair: identity-expose from {from} accepted"));
                            peer_identity_cert = Some(cert);
                            filament_peerloop::expose::Verdict::Accepted
                        }
                        Err(why) => {
                            ui::debug(&format!("pair: identity-expose from {from} refused: {why}"));
                            expose_verdict_for_refusal(why)
                        }
                    };
                    // Only the ceremony's partner is answered, and only a peer
                    // that acknowledges (a 0.9.1 CLI would misroute the type).
                    let partner = pake_peer.as_deref() == Some(from.as_str());
                    if partner && expose_x.on_peer_frame(Instant::now(), verdict, cer.peer_acks_expose()) {
                        if expose_ack.is_none() {
                            expose_ack = cer.k().and_then(|k| data["nonce"].as_str().and_then(|of| seal_expose_ack(k, of)));
                        }
                        if let Some(ack) = expose_ack.clone() {
                            sio.emit("signal", json!({ "to": from, "data": ack })).await.ok();
                        }
                    }
                    continue;
                }
                // The peer says our certificate arrived. Sealed under K, so the
                // server cannot claim it for the peer. Never answered.
                if data["type"].as_str() == Some(filament_peerloop::expose::ACK_TYPE) {
                    if pake_peer.as_deref() == Some(from.as_str()) {
                        if let Some(of) = cer.k().and_then(|k| open_expose_ack(k, &data)) {
                            if expose_x.on_ack(&of) {
                                ui::debug(&format!("pair: identity-expose acknowledged by {from}"));
                            }
                        }
                    }
                    continue;
                }
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                let display = match conn.link_mut(&pid) {
                    Some(l) => {
                        l.transport = Some(t.clone());
                        l.presence = Presence::Ready;
                        l.name.clone()
                    }
                    None => continue,
                };
                // The petname when one is settled (`add <name>`, `--name`): the
                // name the user chose, not the peer's broadcast `user@host`.
                ui::say(&step_line(&format!(
                    "Connected to {}",
                    // A default name is the PARTNER's name: every other link
                    // (a bystander in the room) is shown as itself.
                    ui::paint(
                        ui::Tone::Bold,
                        petname.as_deref().filter(|_| !named_by_default).unwrap_or(&display)
                    )
                )));
                peer = Some((pid.clone(), display.clone()));
                let _ = &t; // transport not used on the v2 path (no secret over DC)
                if stall {
                    continue; // gate 17b: connected, but deliberately never complete
                }
                // L1-a: the link is up and SDP fingerprints exist. Mark this peer
                // as our PAKE counterpart; the progression block (top of the loop)
                // sends our SPAKE2 element and, once K + fingerprints are known,
                // the key-confirmation MAC. NO secret is sent over the DataChannel.
                pake_peer.get_or_insert(pid.clone());
                // A claimer shares the creator's room with everyone else on that
                // network, so this link may be a bystander. Until the creator
                // has spoken (its element names our nameplate and rebinds us, see
                // `partner_for`), offer our element to each peer that comes up:
                // only the creator can use it, and a bystander ignores a
                // nameplate that is not its own.
                if !creator && host_element_received && temporary.is_none() && !cer.has_k() && pake_peer.as_deref() != Some(pid.as_str()) && !stall {
                    sio.emit("signal", json!({ "to": pid, "data": cer.msg_payload() }))
                        .await
                        .ok();
                }
                // Settle the petname: --name wins; otherwise their own name, NOW.
                //
                // This used to stop and ask "remember this device as [..]:" on a
                // terminal. Pairing then completed on the OTHER side, which
                // printed "joined ... mutually remembered", while this side sat on
                // the prompt; a first-time-user test read the other side's
                // success as the end and never noticed this one was still
                // waiting. Their own name is a sensible default, and renaming is
                // one command (`devices rename`), which the success line names.
                // Only from the ceremony's partner: in a shared room the first
                // link up can be a bystander (see `partner_for`).
                if petname.is_none() && !prompted && pake_peer.as_deref() == Some(pid.as_str()) {
                    prompted = true;
                    petname = Some(display.clone());
                    named_by_default = true;
                }
            }
            Ev::StdinLine(line) => {
                if petname.is_none() && prompted {
                    let n = if line.is_empty() {
                        peer.as_ref()
                            .map(|(_, d)| d.clone())
                            .unwrap_or_else(|| "device".into())
                    } else {
                        line
                    };
                    petname = Some(n);
                }
            }
            Ev::Control(pid, v) if stall => {
                let _ = (pid, v); // gate 17b: connected, but ignore all ceremony control
            }
            Ev::Control(pid, v) if temporary.is_some() => {
                if pake_peer.as_deref() != Some(pid.as_str()) { continue; }
                temporary.as_mut().unwrap().control(&cer, &conn, &pid, v).await?;
            }
            Ev::Chunk(pid, sid, _offset, data) if temporary.is_some() => {
                if pake_peer.as_deref() == Some(pid.as_str()) {
                    temporary.as_mut().unwrap().chunk(sid, data).await;
                }
            }
            Ev::Control(_pid, v) => match v["type"].as_str() {
                // L1-a downgrade-refusal (spec §6.1): a v2 client NEVER stores a
                // secret handed over the DataChannel. Receiving a `pair-keep` means
                // the PEER is a legacy v1 client. We refuse, pairing securely
                // requires v2 on both ends. A malicious server stripping `v:2`
                // cannot exploit this: there is no path here that stores a
                // server-readable secret.
                Some("pair-keep") => {
                    bail!(
                        "the other device uses an older version and can't pair securely. Update it (or this CLI) so first-pairing runs the encrypted handshake. Nothing was stored."
                    );
                }
                _ => {}
            },
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::RetryLink(pid, g) => {
                conn.on_retry_due(&pid, g).await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                // A faster, friendlier signal than the ceremony budget when it
                // arrives: the pairing peer left the room. (The budget is the
                // hard backstop, server peer-left can lag behind a hard kill.)
                let gone = v["id"]
                    .as_str()
                    .and_then(|p| conn.link(p))
                    .map(|l| l.name.clone());
                conn.on_peer_left(&v);
                let n = gone.unwrap_or_else(|| "the other device".into());
                // Debug only. In a SUCCESSFUL pairing the other side leaves on
                // purpose: its one-shot join connection hands off to its daemon,
                // and a first-time-user test saw this line twice right before
                // "paired". When the leave is real, the ceremony deadline says
                // so in plain words ("the other device disconnected before setup
                // finished"), so nothing is lost at normal verbosity.
                ui::debug(&format!(
                    "  {n} disconnected, waiting briefly in case it reconnects..."
                ));
            }
            Ev::Interrupted => {
                if let Some(session) = temporary.as_mut() { session.shutdown().await; }
                bail!("interrupted");
            }
            _ => {}
        }
    }
    }.await;
    if let Some(session) = temporary.as_mut() { session.shutdown().await; }
    result
}

#[cfg(test)]
mod promise_tests {
    use super::*;

    // `add <device>` over a spoken code: --allow omitted must mean the
    // documented transfer+mount, never shell ("pairing alone never yields a
    // shell", `grant` help).
    #[test]
    fn code_path_default_ceiling_has_no_shell() {
        let caps = default_device_ceiling();
        assert_eq!(caps, vec!["transfer", "mount"]);
        assert!(!caps.iter().any(|c| c == "shell"));
    }

    // --expires reaches the enrolment, parsed and bounded like `add --out`.
    #[test]
    fn code_path_expires_is_parsed_and_bounded() {
        assert_eq!(code_enrolment_ttl(None, true).unwrap(), None);
        assert_eq!(code_enrolment_ttl(Some("2h"), true).unwrap(), Some(7200));
        assert_eq!(
            code_enrolment_ttl(Some("30d"), true).unwrap(),
            Some(30 * 24 * 3600)
        );
        assert!(code_enrolment_ttl(Some("31d"), true).is_err());
        assert!(code_enrolment_ttl(Some("0"), true).is_err());
        assert!(code_enrolment_ttl(Some("soon"), true).is_err());
        // A pairing that issues no certificate refuses the flag, not ignores it.
        assert!(code_enrolment_ttl(Some("2h"), false).is_err());
        assert_eq!(code_enrolment_ttl(None, false).unwrap(), None);
    }

    // The printed remedy must be a command that parses AND one `grant` would
    // carry out for that device: a plain grant for a device no ceiling binds,
    // a re-add (keeping the ceiling, adding shell) only where the ceiling
    // truly excludes shell.
    #[test]
    fn the_suggested_shell_command_parses_and_grant_accepts_it() {
        use clap::Parser;
        let parse = |hint: &str, verb: &str| -> Vec<String> {
            let start = hint.find(verb).expect("the hint names a command");
            let cmd = hint[start..].trim();
            let argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
            assert!(
                crate::Cli::try_parse_from(&argv).is_ok(),
                "suggested command does not parse: {cmd}"
            );
            argv
        };
        let caps = default_device_ceiling();

        // An owner's own device: no ceiling binds it, so `grant` proceeds and
        // the hint says exactly that command.
        let hint = shell_not_granted_hint("p5-b", &caps, None).expect("a hint is printed");
        let argv = parse(&hint, "tunlion grant");
        assert_eq!(argv, ["tunlion", "grant", "p5-b", "shell"]);
        assert_eq!(grant_vs_ceiling(None, "shell", false), GrantVsCeiling::Proceed);

        // A delegated device whose ceiling excludes shell: `grant` refuses,
        // so the hint is the re-add, and it keeps the ceiling it had.
        let hint = shell_not_granted_hint("laptop", &caps, Some(caps.as_slice())).expect("a hint");
        assert!(!hint.contains("tunlion grant"), "{hint}");
        let argv = parse(&hint, "tunlion add");
        assert_eq!(argv.last().map(String::as_str), Some("transfer,mount,shell"));
        assert_eq!(
            grant_vs_ceiling(Some(caps.as_slice()), "shell", false),
            GrantVsCeiling::OutsideCeiling
        );

        // Shell already there, by the enrolment or by the ceiling: no hint.
        let with_shell = vec!["transfer".to_string(), "shell".to_string()];
        assert!(shell_not_granted_hint("laptop", &with_shell, None).is_none());
        assert!(shell_not_granted_hint("laptop", &caps, Some(with_shell.as_slice())).is_none());
    }

    /// The serving-off refusal lives in the library now and decides "outside
    /// the ceiling" with its own one-line containment. `pair_cmd`'s
    /// `grant_vs_ceiling` is the CLI's rule for the same question (which
    /// command to suggest), so pin them together: a future edit to either
    /// must fail here rather than let the refusal and the remedy disagree.
    #[test]
    fn the_serving_off_ceiling_rule_matches_grant_vs_ceiling() {
        use filament_peerloop::shell::off::ceiling_excludes;
        let covered = vec!["transfer".to_string(), "shell".to_string()];
        let outside = vec!["transfer".to_string()];
        for ceiling in [None, Some(&covered[..]), Some(&outside[..]), Some(&[][..])] {
            let cli =
                grant_vs_ceiling(ceiling, "shell", false) == GrantVsCeiling::OutsideCeiling;
            assert_eq!(
                ceiling_excludes(ceiling, "shell"),
                cli,
                "library and pair_cmd disagree for {ceiling:?}"
            );
        }
    }
}

/// The rename hint printed after a pairing saved a device under a default
/// name, with the name quoted so it pastes as ONE argument: a browser called
/// `Abdul's iPad` used to print `tunlion devices rename Abdul's iPad <name>`,
/// which a shell reads as an unterminated quote. Pure.
pub(crate) fn rename_hint(name: &str) -> String {
    format!("tunlion devices rename {} <name>", crate::refusal::word(name))
}

/// What to say when a pairing filed the peer as EXTERNAL because the two
/// devices already hold DIFFERENT identities. `asked_to_own` is `add <device>`
/// (`--internal`): the operator meant "one of mine", so the steps make the PEER
/// join this identity; otherwise they make THIS device join the peer's.
/// Every step is a command the CLI accepts (pinned by the test below).
pub(crate) fn external_pairing_notice(
    peer: &str,
    me: &str,
    asked_to_own: bool,
) -> (String, String, Vec<String>) {
    let peer_w = crate::refusal::word(peer);
    let me_w = crate::refusal::word(me);
    let headline = format!("'{peer}' was filed as EXTERNAL, not as one of your devices");
    let detail = if asked_to_own {
        format!(
            "'{peer}' already has its own identity, different from this device's, so pairing could not make it yours. External devices are someone else's: time-boxed and deny-by-default."
        )
    } else {
        format!(
            "'{peer}' and this device have different identities, so each is EXTERNAL to the other: time-boxed and deny-by-default."
        )
    };
    let steps = if asked_to_own {
        vec![
            format!("if '{peer}' is yours, on '{peer}' run: tunlion down --yes && tunlion reset"),
            format!("then here: tunlion devices forget {peer_w} -y && tunlion add {peer_w} (and do what it prints on '{peer}')"),
        ]
    } else {
        vec![
            format!("if this device should be one of '{peer}'s, run here: tunlion down --yes && tunlion reset"),
            format!("then on '{peer}': tunlion add {me_w} (and do what it prints here)"),
        ]
    };
    (headline, detail, steps)
}

#[cfg(test)]
mod hint_quoting_tests {
    use super::rename_hint;

    /// What a POSIX shell makes of a hint line: its argv, `<name>` filled in.
    /// Unix only, by a runtime check (the hints use PowerShell quoting on
    /// Windows, and platform cfg blocks belong in platform/).
    fn sh_argv(line: &str) -> Vec<String> {
        let line = line.replace("<name>", "NewName");
        let out = crate::platform::command("sh")
            .arg("-c")
            .arg(format!("set -- {line}; for a; do printf '%s\\0' \"$a\"; done"))
            .output()
            .expect("sh runs");
        assert!(out.status.success(), "sh refused: {line}");
        String::from_utf8_lossy(&out.stdout).split('\0').filter(|a| !a.is_empty()).map(str::to_string).collect()
    }

    /// The pairing's rename hint pastes as the exact stored name, one
    /// argument, for every name a browser can send, and still parses.
    #[test]
    fn the_rename_hint_pastes_as_the_exact_name() {
        use clap::Parser;
        if !cfg!(unix) {
            return;
        }
        for name in ["Abdul's iPad", "laptop", "Kabir Laptop", "it's \"x\"", "$HOME;rm"] {
            let hint = rename_hint(name);
            let argv = sh_argv(&hint);
            assert_eq!(argv, ["tunlion", "devices", "rename", name, "NewName"], "{hint}");
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "does not parse: {hint}");
        }
        assert_eq!(rename_hint("laptop"), "tunlion devices rename laptop <name>");
        assert!(!rename_hint("Abdul's iPad").contains("Abduls"));
    }

    /// The quoting rule itself: a real `sh` reads every name back intact, as
    /// one argument, however hostile.
    #[test]
    fn a_quoted_name_round_trips_through_sh() {
        if !cfg!(unix) {
            return;
        }
        for name in ["Abdul's iPad", "it's", "two  spaces", "a\"b", "$HOME `x` \\ ;|&", "Zo\u{eb}'s", "''", "plain-name"] {
            let argv = sh_argv(&format!("x {}", crate::refusal::word(name)));
            assert_eq!(argv, ["x", name], "{name}");
        }
    }

    /// Every other hint that prints a device name in a command keeps it
    /// intact and quoted the same way.
    #[test]
    fn device_name_hints_quote_the_name() {
        if !cfg!(unix) {
            return;
        }
        let n = "Abdul's iPad";
        let w = crate::refusal::word(n);
        let lines = [
            crate::reset_hints::offline_hint(n, None),
            crate::reset_hints::offline_hint(n, Some("Abdul's iPad 2")),
            crate::reset_hints::name_taken_note(n, None),
            crate::enrollment::renamed_note("Abdul's Mac", "abdul-s-mac-2").unwrap_or_default(),
        ];
        for l in &lines {
            assert!(!l.contains("forget Abdul's iPad -y"), "unquoted: {l}");
            assert!(!l.contains("Abduls"), "apostrophe dropped: {l}");
        }
        assert!(lines[0].contains(&format!("tunlion devices forget {w} -y")), "{}", lines[0]);
        assert!(lines[0].contains(&format!("tunlion add {w}")), "{}", lines[0]);
        assert!(lines[1].contains(&format!("tunlion devices rename {} {w}", crate::refusal::word("Abdul's iPad 2"))), "{}", lines[1]);
        assert!(lines[2].contains(&format!("tunlion devices forget {w} -y")), "{}", lines[2]);
        // Each backticked command reads back as the exact name.
        for l in &lines {
            for (i, seg) in l.split('`').enumerate() {
                if i % 2 == 1 && seg.starts_with("tunlion ") {
                    for cmd in seg.split(" && ") {
                        let argv = sh_argv(cmd);
                        assert!(argv.iter().all(|a| !a.contains("Abduls")), "{cmd} -> {argv:?}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod external_notice_tests {
    use super::external_pairing_notice;

    /// The commands in the steps parse, so a copy-paste never meets clap's
    /// "unexpected argument".
    #[test]
    fn the_steps_name_commands_that_parse() {
        use clap::Parser;
        for own in [true, false] {
            let (headline, _, steps) = external_pairing_notice("p1-b", "p1-a", own);
            assert!(headline.contains("EXTERNAL"), "{headline}");
            for step in steps {
                let Some(start) = step.find("tunlion ") else { continue };
                let tail = &step[start..];
                let tail = tail.split(" (").next().unwrap_or(tail);
                for cmd in tail.split(" && ") {
                    let argv: Vec<&str> = cmd.split_whitespace().collect();
                    assert!(
                        crate::Cli::try_parse_from(&argv).is_ok(),
                        "does not parse: {cmd}"
                    );
                }
            }
        }
    }
}

/// Right after a pairing is the one moment "will this device be reachable?"
/// matters, and the answer is usually "only while this window is open": shells,
/// sends and forwards to it need something listening, and they start cold
/// without the background service. So ask once, here, instead of showing a
/// check mark that fails later. Never in a script, never when a daemon already
/// serves this config dir, and "Not now" leaves the command to type later.
fn offer_background_after_pairing() {
    if !interactive_allowed() || crate::daemon_alive().is_some() {
        return;
    }
    ui::say("");
    ui::say("  Keep this device reachable when this window is closed?");
    let choices = vec!["Yes, run in the background".to_string(), "Not now".to_string()];
    match codeentry::pick("", &choices) {
        Ok(Some(0)) => {
            let started = std::env::current_exe().ok().and_then(|exe| {
                crate::platform::command(exe).args(["up", "--install"]).status().ok()
            });
            if !started.is_some_and(|status| status.success()) {
                ui::say(&ui::paint(ui::Tone::Dim, "  That did not finish. Try again with: tunlion up --install"));
            }
        }
        _ => ui::say(&ui::paint(ui::Tone::Dim, "  Later: tunlion up --install")),
    }
}

#[cfg(test)]
mod enrol_flow_tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn base() -> EnrolOfferInputs {
        EnrolOfferInputs {
            owner_here: true,
            operator_said_own: false,
            operator_said_person: false,
            offer_opened: true,
            peer_can_hold: true,
            can_ask: true,
            already_asked: false,
        }
    }

    /// The owner key signs only on an owner decision made on the owner device.
    #[test]
    fn only_the_owner_device_decides_and_only_once() {
        // Said up front: certify.
        assert_eq!(enrol_offer_decision(EnrolOfferInputs { operator_said_own: true, ..base() }), EnrolOfferDecision::Certify);
        // Not said: ask the person here.
        assert_eq!(enrol_offer_decision(base()), EnrolOfferDecision::Ask);
        // A device WITHOUT the owner key can never certify or ask, whatever the
        // operator said: a stranger's pairing with a member stays a pairing.
        for own in [true, false] {
            assert_eq!(
                enrol_offer_decision(EnrolOfferInputs { owner_here: false, operator_said_own: own, ..base() }),
                EnrolOfferDecision::Decline
            );
        }
        // An offer that did not open under this ceremony or prove its key.
        for own in [true, false] {
            assert_eq!(
                enrol_offer_decision(EnrolOfferInputs { offer_opened: false, operator_said_own: own, ..base() }),
                EnrolOfferDecision::Decline
            );
        }
        // "Someone else's device" was said: never asked, never certified.
        assert_eq!(enrol_offer_decision(EnrolOfferInputs { operator_said_person: true, ..base() }), EnrolOfferDecision::Decline);
        // No person to ask (script, --json): no silent elevation.
        assert_eq!(enrol_offer_decision(EnrolOfferInputs { can_ask: false, ..base() }), EnrolOfferDecision::Decline);
        // A device that cannot wait for an answer is not asked.
        assert_eq!(enrol_offer_decision(EnrolOfferInputs { peer_can_hold: false, ..base() }), EnrolOfferDecision::Decline);
        // Once per ceremony.
        assert_eq!(enrol_offer_decision(EnrolOfferInputs { already_asked: true, ..base() }), EnrolOfferDecision::Decline);
        assert_eq!(
            enrol_offer_decision(EnrolOfferInputs { already_asked: true, operator_said_own: true, ..base() }),
            EnrolOfferDecision::Decline
        );
    }

    struct Dev {
        kp: Ed25519KeyPair,
    }
    impl Dev {
        fn new() -> Dev {
            let rng = ring::rand::SystemRandom::new();
            let pk = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Dev { kp: Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap() }
        }
        fn public(&self) -> [u8; 32] {
            self.kp.public_key().as_ref().try_into().unwrap()
        }
        fn sign(&self, m: &[u8]) -> Option<[u8; 64]> {
            self.kp.sign(m).as_ref().try_into().ok()
        }
    }

    const CAPS: &str = "transfer";
    // The two ends of one link see the fingerprints the other way round.
    const OWNER_FP: &str = "AA:11";
    const DEVICE_FP: &str = "BB:22";

    fn offer(k: &[u8], dev: &Dev, key: [u8; 32]) -> Value {
        build_enrol_offer(k, DEVICE_FP, OWNER_FP, CAPS, 1, key, "pop-os", &|m| dev.sign(m)).unwrap()
    }

    #[test]
    fn an_offer_proves_the_key_it_offers_for_this_ceremony() {
        let k = [7u8; 32];
        let dev = Dev::new();
        let owner_own = Dev::new().public();
        let data = offer(&k, &dev, dev.public());
        assert_eq!(data["hold"], json!(true));
        assert_eq!(
            open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 1, &data, Some(owner_own)),
            Some(dev.public())
        );
        // Another ceremony's key: does not open.
        assert_eq!(open_enrol_offer(&[8u8; 32], OWNER_FP, DEVICE_FP, CAPS, 1, &data, Some(owner_own)), None);
        // Another link (a relayed / substituted channel): the proof is bound to
        // these fingerprints, so it fails.
        assert_eq!(open_enrol_offer(&k, OWNER_FP, "CC:33", CAPS, 1, &data, Some(owner_own)), None);
        // Other capabilities or scope than the ceremony agreed: fails.
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, "transfer,shell", 1, &data, Some(owner_own)), None);
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 2, &data, Some(owner_own)), None);
        // Our own key offered back (a reflection), or our key unknown: refused.
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 1, &data, Some(dev.public())), None);
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 1, &data, None), None);
    }

    /// The partner offering a key it does NOT hold (a third device's) cannot
    /// get the owner to certify it.
    #[test]
    fn an_offer_for_a_key_the_sender_does_not_hold_is_refused() {
        let k = [9u8; 32];
        let attacker = Dev::new();
        let victim = Dev::new();
        let data = offer(&k, &attacker, victim.public());
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 1, &data, Some(Dev::new().public())), None);
        // Tampered ciphertext.
        let mut bad = offer(&k, &attacker, attacker.public());
        let sealed = bad["sealed"].as_str().unwrap().to_string();
        let flipped = format!("{}{}", if sealed.starts_with('0') { "1" } else { "0" }, &sealed[1..]);
        bad["sealed"] = json!(flipped);
        assert_eq!(open_enrol_offer(&k, OWNER_FP, DEVICE_FP, CAPS, 1, &bad, Some(Dev::new().public())), None);
    }

    fn out() -> EnrolOutcomeInputs {
        EnrolOutcomeInputs {
            owner_asked_own: false,
            certified_here: false,
            already_same_owner: false,
            peer_presented_cert: false,
            peer_is_browser: false,
            offer_seen: false,
            offer_failed_proof: false,
            unconfirmed_grant: false,
            offered_here: false,
            joined_here: false,
            declined: false,
            grant_refused: None,
        }
    }

    /// Owner report: "Another device I own" + a code ended as a plain pairing
    /// and nothing said so. Every way that can happen is now named.
    #[test]
    fn a_failed_own_device_enrolment_is_never_silent() {
        assert_eq!(
            enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, ..out() }),
            EnrolOutcome::OwnerNotEnrolled { offer_seen: false, failed_proof: false }
        );
        assert_eq!(
            enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, offer_seen: true, offer_failed_proof: true, ..out() }),
            EnrolOutcome::OwnerNotEnrolled { offer_seen: true, failed_proof: true }
        );
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, certified_here: true, ..out() }), EnrolOutcome::Fine);
        assert_eq!(
            enrolment_outcome(EnrolOutcomeInputs { certified_here: true, unconfirmed_grant: true, ..out() }),
            EnrolOutcome::OwnerUnconfirmed
        );
        // Already the same owner's, or another identity (the EXTERNAL notice).
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, already_same_owner: true, ..out() }), EnrolOutcome::Fine);
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, peer_presented_cert: true, ..out() }), EnrolOutcome::Fine);
        // Device side.
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { offered_here: true, ..out() }), EnrolOutcome::DeviceNoAnswer);
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { offered_here: true, declined: true, ..out() }), EnrolOutcome::Fine);
        assert_eq!(enrolment_outcome(EnrolOutcomeInputs { offered_here: true, joined_here: true, ..out() }), EnrolOutcome::Fine);
        assert_eq!(
            enrolment_outcome(EnrolOutcomeInputs { offered_here: true, grant_refused: Some("x".into()), ..out() }),
            EnrolOutcome::DeviceGrantRefused("x".into())
        );
        // A plain pairing nobody asked to enrol says nothing extra.
        assert_eq!(enrolment_outcome(out()), EnrolOutcome::Fine);
    }

    /// Only the explicit browser marker turns "asked for a device, no key
    /// offer" into a successful pairing. A native peer that merely lacks the
    /// direct transport is still a FAILED enrolment, and a browser marker never
    /// hides an offer that arrived but did not prove its key.
    #[test]
    fn a_browser_pairing_exits_zero_but_a_missing_native_key_does_not() {
        // The browser: no certificate, no key offer, explicit marker.
        let browser = enrolment_outcome(EnrolOutcomeInputs {
            owner_asked_own: true,
            peer_is_browser: true,
            ..out()
        });
        assert_eq!(browser, EnrolOutcome::OwnerBrowserNotFleet);
        assert!(
            report_enrolment_outcome(&browser, "iPad").is_none(),
            "a browser pairing is a success (exit 0)"
        );
        // Native peer with no offer: still a failure (exit 1).
        let native = enrolment_outcome(EnrolOutcomeInputs { owner_asked_own: true, ..out() });
        assert_eq!(
            native,
            EnrolOutcome::OwnerNotEnrolled { offer_seen: false, failed_proof: false }
        );
        assert!(
            report_enrolment_outcome(&native, "laptop").is_some(),
            "a native device that never offered its key must still fail"
        );
        // A browser marker must not excuse a key offer that failed its proof.
        let bad_offer = enrolment_outcome(EnrolOutcomeInputs {
            owner_asked_own: true,
            peer_is_browser: true,
            offer_seen: true,
            offer_failed_proof: true,
            ..out()
        });
        assert_eq!(
            bad_offer,
            EnrolOutcome::OwnerNotEnrolled { offer_seen: true, failed_proof: true }
        );
        assert!(report_enrolment_outcome(&bad_offer, "iPad").is_some());
    }

    /// `direct:false` is a transport capability, not device-kind evidence.
    #[test]
    fn only_the_explicit_browser_marker_classifies_a_peer() {
        assert!(browser_hint(&json!({
            "type": "transport-hint", "direct": false, "client": "browser"
        })));
        assert!(!browser_hint(&json!({
            "type": "transport-hint", "direct": false
        })));
        assert!(!browser_hint(&json!({
            "type": "transport-hint", "direct": false, "client": "native"
        })));
        assert!(!browser_hint(&json!({
            "type": "description", "direct": false, "client": "browser"
        })));
    }

    #[test]
    fn the_code_screen_says_what_the_device_will_become() {
        let caps = default_device_ceiling();
        let own = ui::strip_ansi(&code_screen_promise(Some("pop-os"), true, false, true, &caps));
        assert!(own.contains("pop-os will be one of YOUR devices"), "{own}");
        assert!(own.contains("send you files and open your shared folder"), "{own}");
        let person = code_screen_promise(None, false, true, true, &caps);
        assert!(person.contains("a person's device, not one of yours"), "{person}");
        let plain = code_screen_promise(None, false, false, true, &caps);
        assert!(plain.contains("you will be asked here"), "{plain}");
        let member = code_screen_promise(None, false, false, false, &caps);
        assert!(!member.contains("asked"), "{member}");
        for s in [own, person, plain, member] {
            assert!(!s.contains('\u{2014}'), "no em dashes: {s}");
        }
    }

    #[test]
    fn the_question_names_the_device_and_the_stakes() {
        let (q, stakes, items) = own_device_question("pop-os");
        assert_eq!(q, "Is pop-os one of your devices?");
        assert!(stakes.contains("owner key"), "{stakes}");
        assert_eq!(items.len(), 2);
        assert!(items[0].starts_with("Yes"), "{items:?}");
        assert!(items[1].starts_with("No"), "{items:?}");
    }

    #[test]
    fn capabilities_read_as_words() {
        assert_eq!(plain_caps(&default_device_ceiling()), "send you files and open your shared folder");
        assert_eq!(plain_caps(&[]), "do nothing yet");
        assert!(plain_caps(&["shell".into()]).contains("acts as you"));
    }
}

#[cfg(test)]
mod identity_expose_tests {
    use super::*;
    use ring::signature::KeyPair as _;

    /// The sender half exactly as the ceremony builds it (pair_with_purpose):
    /// the possession signature over our_confirm(K, my_fp, their_fp).
    fn expose(k: &[u8], my_fp: &str, their_fp: &str, caps: &str, scope: u8) -> (Value, [u8; 32]) {
        let seed = [9u8; 32];
        let dev = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let dpub: [u8; 32] = dev.public_key().as_ref().try_into().unwrap();
        let owner = identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let cert = identity::DeviceCert::certify(&owner, dpub, identity::now_secs(), identity::CERT_TTL_SECS).unwrap();
        let cmv: [u8; 32] = crate::pake::our_confirm(k, my_fp, their_fp, caps, scope).as_slice().try_into().unwrap();
        let msg = identity::possession_msg(0x01, &cmv, scope, &identity::caps_digest(caps), &identity::cert_hash(&cert), &dpub, &[0u8; 32]);
        let sig = dev.sign(&msg);
        let inner = json!({"cert": cert.to_json(), "possession_sig": hex::encode(sig.as_ref()), "device_pub": hex::encode(dpub)});
        let (n, s) = identity::seal_plaintext(&identity::sealing_key_from_k(k), inner.to_string().as_bytes()).unwrap();
        (json!({"type": "identity-expose", "v": 2, "nonce": hex::encode(n), "sealed": hex::encode(s)}), dpub)
    }

    /// What the receiver used to check in one silent nest of if-lets: the same
    /// frame is accepted, and each way it can fail is refused with its reason.
    #[test]
    fn an_identity_expose_opens_only_for_this_session_and_says_why_not() {
        let k = [5u8; 32];
        let (a, b) = ("AA:11", "BB:22");
        let (frame, dpub) = expose(&k, a, b, "transfer", 0x01);
        let now = identity::now_secs();
        let mine = Some([1u8; 32]);
        // The receiver sees the fingerprints the other way round.
        let cert = open_identity_expose(&frame, &k, Some((b, a)), "transfer", 0x01, mine, now).expect("accepted");
        assert_eq!(cert.device_pub, dpub);
        let why = |r: std::result::Result<identity::DeviceCert, &'static str>| r.err().unwrap();
        assert_eq!(why(open_identity_expose(&frame, &[6u8; 32], Some((b, a)), "transfer", 0x01, mine, now)), "seal does not open under this ceremony's key");
        assert_eq!(why(open_identity_expose(&frame, &k, None, "transfer", 0x01, mine, now)), "this link's fingerprints are not known");
        assert_eq!(why(open_identity_expose(&frame, &k, Some((b, "CC:33")), "transfer", 0x01, mine, now)), "possession signature does not verify for this session");
        assert_eq!(why(open_identity_expose(&frame, &k, Some((b, a)), "transfer,shell", 0x01, mine, now)), "possession signature does not verify for this session");
        assert_eq!(why(open_identity_expose(&frame, &k, Some((b, a)), "transfer", 0x01, Some(dpub), now)), "it is this device's own key, reflected back");
        assert!(why(open_identity_expose(&frame, &k, Some((b, a)), "transfer", 0x01, None, now)).contains("reflection"));
        let mut torn = frame.clone();
        torn["nonce"] = json!("00");
        assert_eq!(why(open_identity_expose(&torn, &k, Some((b, a)), "transfer", 0x01, mine, now)), "nonce is not 12 bytes");
    }

    /// The frame the ceremony now builds (`build_identity_expose`) is the one
    /// the receiver opens; the acknowledgement opens only under the same K.
    #[test]
    fn the_built_frame_opens_and_the_ack_is_bound_to_k() {
        let k = [5u8; 32];
        let (a, b) = ("AA:11", "BB:22");
        let dev = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let dpub: [u8; 32] = dev.public_key().as_ref().try_into().unwrap();
        let owner = identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let cert = identity::DeviceCert::certify(&owner, dpub, identity::now_secs(), identity::CERT_TTL_SECS).unwrap();
        let sign = |m: &[u8]| dev.sign(m).as_ref().try_into().ok();
        let frame = build_identity_expose(&k, a, b, "transfer", 0x01, &cert, &sign).unwrap();
        let got = open_identity_expose(&frame, &k, Some((b, a)), "transfer", 0x01, Some([1u8; 32]), identity::now_secs()).unwrap();
        assert_eq!(got.device_pub, dpub);
        let of = frame["nonce"].as_str().unwrap();
        let ack = seal_expose_ack(&k, of).unwrap();
        assert_eq!(ack["type"], json!("identity-expose-ack"));
        assert_eq!(open_expose_ack(&k, &ack).as_deref(), Some(of));
        assert_eq!(open_expose_ack(&[6u8; 32], &ack), None, "the server cannot make one up");
        let mut forged = ack.clone();
        forged["sealed"] = json!("00");
        assert_eq!(open_expose_ack(&k, &forged), None);
        assert!(!ack.to_string().contains(of), "the acknowledged nonce rides sealed");
    }

    /// Both sides of a pairing where `a` holds a certificate, over a signaling
    /// relay that drops the first `drop` copies of a's identity-expose (all of
    /// them for usize::MAX) and the first `drop_acks` acknowledgements. Real
    /// frames, real checks, real acknowledgements; only the wire is simulated.
    /// Returns what each side still lacks at the deadline, and whether b holds
    /// a's certificate.
    fn pair_over_lossy_relay(drop: usize, drop_acks: usize) -> (Option<filament_peerloop::expose::Unmet>, Option<filament_peerloop::expose::Unmet>, bool) {
        use filament_peerloop::expose::ExposeExchange;
        let k = [5u8; 32];
        let (a_fp, b_fp) = ("AA:11", "BB:22");
        let dev = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let dpub: [u8; 32] = dev.public_key().as_ref().try_into().unwrap();
        let owner = identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let cert = identity::DeviceCert::certify(&owner, dpub, identity::now_secs(), identity::CERT_TTL_SECS).unwrap();
        let sign = |m: &[u8]| dev.sign(m).as_ref().try_into().ok();
        // a advertised `exposes: true`, b did not; both acknowledge.
        let (peer_acks, a_will, b_will) = (true, true, false);
        let mut ax = ExposeExchange::new();
        let mut bx = ExposeExchange::new();
        ax.offer(build_identity_expose(&k, a_fp, b_fp, "transfer", 0x01, &cert, &sign).unwrap());
        let mut b_cert = None;
        let mut b_ack: Option<Value> = None;
        let (mut copies, mut acks) = (0usize, 0usize);
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(60);
        let mut t = t0;
        while t < deadline && (ax.waiting(peer_acks, b_will) || bx.waiting(peer_acks, a_will)) {
            if let Some(f) = ax.take_due(t, peer_acks) {
                copies += 1;
                if copies > drop {
                    let opened = open_identity_expose(&f, &k, Some((b_fp, a_fp)), "transfer", 0x01, Some([1u8; 32]), identity::now_secs());
                    let verdict = match opened {
                        Ok(c) => {
                            b_cert = Some(c);
                            filament_peerloop::expose::Verdict::Accepted
                        }
                        Err(why) => expose_verdict_for_refusal(why),
                    };
                    if bx.on_peer_frame(t, verdict, peer_acks) {
                        let ack = b_ack.get_or_insert_with(|| seal_expose_ack(&k, f["nonce"].as_str().unwrap()).unwrap()).clone();
                        acks += 1;
                        if acks > drop_acks {
                            if let Some(of) = open_expose_ack(&k, &ack) {
                                ax.on_ack(&of);
                            }
                        }
                    }
                }
            }
            t += Duration::from_millis(10);
        }
        (ax.unmet(peer_acks, b_will), bx.unmet(peer_acks, a_will), b_cert.is_some_and(|c| c.device_pub == dpub))
    }

    #[test]
    fn the_certificate_lands_when_the_first_identity_expose_frames_are_lost() {
        for drop in [0, 1, 2, 3, 5, 10] {
            assert_eq!(pair_over_lossy_relay(drop, 0), (None, None, true), "first {drop} frames lost");
        }
        // The acknowledgement lost too: the next copy is answered again.
        assert_eq!(pair_over_lossy_relay(2, 3), (None, None, true));
    }

    #[test]
    fn every_identity_expose_frame_lost_fails_both_sides() {
        use filament_peerloop::expose::Unmet;
        let (a, b, landed) = pair_over_lossy_relay(usize::MAX, 0);
        assert_eq!(a, Some(Unmet::NotAcknowledged), "the sender must not report success");
        assert_eq!(b, Some(Unmet::CertMissing), "the receiver must not report success");
        assert!(!landed);
        let said = expose_unmet_msg(&Unmet::CertMissing, "laptop");
        assert!(said.contains("laptop said it would send its device certificate") && said.contains("Nothing was stored"), "{said}");
        let said = expose_unmet_msg(&Unmet::NotAcknowledged, "laptop");
        assert!(said.contains("never confirmed it received"), "{said}");
    }

    #[test]
    fn only_a_transient_refusal_waits_for_another_copy() {
        use filament_peerloop::expose::Verdict;
        assert_eq!(expose_verdict_for_refusal("no key exchange yet"), Verdict::NotYet);
        assert_eq!(expose_verdict_for_refusal("this link's fingerprints are not known"), Verdict::NotYet);
        assert_eq!(
            expose_verdict_for_refusal("seal does not open under this ceremony's key"),
            Verdict::Refused("seal does not open under this ceremony's key".into())
        );
    }
}
