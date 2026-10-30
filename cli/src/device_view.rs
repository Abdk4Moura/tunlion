//! The read side of the device model.
//!
//! Lookups and views used across the CLI: resolving a pubkey or a device record
//! to a certificate, checking whether a cert is still valid or revoked, finding a
//! device by its public key, touching activity, sweeping lapsed devices, the caps
//! summary, the countdown line and the `devices` list renderer.
//!
//! Moved as FIFTEEN separate blocks -- they are scattered through main.rs from
//! L880 to L2959 and nothing between them is part of this module. None of the
//! fifteen has a cfg attribute, a spawn, a nested fn or a function-local use.
//! The fourteen that other files call are `pub(crate)` here because anyhow::{ Result };
use crate::delegated_device_state;
use crate::device_caps::effective_device_caps;
use crate::devices_store::{devices_path, devices_upsert_atomic};
use crate::fleet_ui;
use crate::identity;
use crate::load_owner_key;
use crate::local_device_cert;
use crate::ui;
use crate::warm_device_names;
use anyhow::Result;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// Store a pair secret received over the network as a NEW record, returning
/// the name it landed under (suffixed when `name` is taken). Never re-keys an
/// existing record: see `devices_store::devices_store_new`.
pub(crate) fn devices_store(name: &str, secret: &str) -> Result<String> {
    crate::devices_store::devices_store_new(name, secret, None)
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// `caps` is deny-by-default; "transfer" is the L0 baseline. The on-disk shape
/// grows `v` and `caps` but the existing `{name, secret}` fields are unchanged,
/// so the reconnect path (`devices_load`, which reads only name+secret) keeps
/// working byte-for-byte, no regression.
///
/// Owner re-pair: the ONLY caller is the owner-run `tunlion add` ceremony
/// (pair_cmd.rs), where the local user ran the command and the PAKE confirmed
/// the peer. That is the owner decision that may re-key an existing record of
/// the same name, so this passes `allow_reanchor`. A secret that arrives over
/// the network without that decision goes through `devices_store` instead,
/// which never overwrites.
pub(crate) fn devices_store_v2(name: &str, secret: &str, caps: &[String]) -> Result<()> {
    // Delegate to atomic upsert: secret + caps together, preserve cert
    devices_upsert_atomic(
        name,
        Some(secret),
        None,
        Some(caps),
        None,
        None,
        None,
        true,
    )?;
    Ok(())
}

/// Read the device cert (if any) for a named device.
/// The certificate STORED for `name`, valid or not.
///
/// #266: this deliberately does NOT check expiry, and most of its callers want
/// exactly that, because they are asking "is there a record" or are about to run
/// their own `verify`. The name does not say so, which is the trap: a gate
/// written as `device_cert_for(..).is_none()` closes when the first certificate
/// is stored and never reopens when that certificate dies. Use
/// [`device_cert_valid_for`] for any decision that should reopen on expiry.
pub(crate) fn device_cert_for(name: &str) -> Option<identity::DeviceCert> {
    crate::devices_store::store().device_cert_for(name)
}

/// The certificate stored for `name` IF it is still valid right now.
///
/// #266: the expiry-aware half of [`device_cert_for`]. A gate meaning "do we
/// already have a usable identity for this device" must ask this one, or an
/// expired certificate wedges the record: unusable everywhere that verifies,
/// still present to anything that only checks existence, with `devices forget`
/// as the sole exit.
pub(crate) fn device_cert_valid_for(name: &str) -> Option<identity::DeviceCert> {
    crate::devices_store::store().device_cert_valid_for(name)
}

/// Is `name` a device we hold an INDEX entry for but no pair secret?
///
/// That is exactly a fleet sibling: recorded so `tunlion devices` can show the
/// fleet, deliberately without a secret so it never becomes a dial target. The
/// distinction matters for error copy, because such a name is simultaneously
/// "listed" and "not reachable by this verb".
/// Does a device record exist at all, secret or not?
///
/// `devices_load()` filter-maps on `secret`, so every check written against it
/// silently means "devices I can DIAL", not "devices I know". A fleet sibling is
/// indexed without a secret, so those checks answer "no device named X" while
/// `tunlion devices` is listing X on the next line. For `revoke` that is worse
/// than confusing: a device you can SEE but cannot revoke.
pub(crate) fn device_record_exists(name: &str) -> bool {
    crate::devices_store::store().device_record_exists(name)
}

pub(crate) fn device_name_for_pub(device_pub: &[u8; 32]) -> Option<String> {
    crate::devices_store::store().device_name_for_pub(device_pub)
}

/// Is this device record revoked (the certificate marker, or a durable device
/// revoke)? The one test `devices`, `send` and `forget` share. Pure.
pub(crate) fn record_is_revoked(record: &Value) -> bool {
    filament_peerloop::recv::store::record_is_revoked(record)
}

/// Is the stored record named `name` revoked? False when there is no record.
pub(crate) fn device_record_revoked(name: &str) -> bool {
    crate::devices_store::store().device_record_revoked(name)
}

pub(crate) fn device_cert_revoked(device_pub: &[u8; 32]) -> bool {
    // The store checks the separate revoked-key list first, then the record,
    // and fails closed on damage. One implementation, in the library.
    crate::devices_store::store().device_cert_revoked(device_pub)
}

/// The full record for a device identified by its cert's device_pub, if any.
/// Used by the enrollment path to decide revive (lapsed) vs refuse (revoked).
pub(crate) fn devices_find_by_device_pub(device_pub: &[u8; 32]) -> Option<Value> {
    crate::devices_store::store().devices_find_by_device_pub(device_pub)
}

/// Sweep the device store for lapsed delegated records. Called periodically by
/// the daemon. Returns how many records newly lapsed.
pub(crate) fn devices_sweep_lapsed(now: u64) -> usize {
    crate::devices_store::store().devices_sweep_lapsed(now)
}

/// Update the `lastSeen` timestamp and overlay addresses for a known device.
/// Called on each connect so `tunlion addr <device>` can show recency and addresses.
pub(crate) fn devices_touch(
    name: &str,
    v6: Option<std::net::Ipv6Addr>,
    v4: Option<std::net::Ipv4Addr>,
) {
    crate::devices_store::store().devices_touch(name, v6, v4);
}

/// Clock-injectable form of `devices_touch` so the liveness tests can advance
/// time without sleeping. The production call site passes the real wall clock.
pub(crate) fn devices_touch_at(
    name: &str,
    v6: Option<std::net::Ipv6Addr>,
    v4: Option<std::net::Ipv4Addr>,
    now: u64,
) -> Result<()> {
    crate::devices_store::store().devices_touch_at(name, v6, v4, now)
}

/// Read the `lastSeen` timestamp and overlay addresses for a known device.
pub(crate) fn devices_info(name: &str) -> Option<(u64, Option<String>, Option<String>)> {
    crate::devices_store::store().devices_info(name)
}

/// How long this device's certificate has left, in the words of what actually
/// happens to it.
///
/// #236: Fleet used to get "renews in 87d", and an already-expired Fleet cert
/// got "renews until <a date in the past>" while External got "expired" for the
/// same condition. Nothing renews. `DeviceCert::certify` is reached only from
/// init, recover, enrollment/join and pairing cert storage: no timer, no
/// opportunistic-on-connect path, no verb. The wording came from
/// docs/design-pairing-ux.md rule 2, "auto-renewed by a primary while the device
/// is in good standing", which was designed and never built, so the string was
/// describing a security model the product does not have. Meanwhile the gate
/// fails the cert at exactly the moment the screen said it would renew.
///
/// The tier no longer changes the sentence, because the tier does not change
/// the fact. If renewal is ever built, this is where the distinction earns its
/// way back, and not before.
/// What a roster row says about a sibling. A roster entry under THIS
/// device's own name but another key is this device before a reset: the owner
/// still lists the old key until it forgets it. It was shown as an ordinary
/// sibling ("p9-b  known via owner") on p9-b itself. Pure.
/// Is this roster entry already a row from the local store? By device KEY (a
/// renamed record is the same device), then by name, case-insensitively as the
/// store compares names. Reads RAW records. Pure.
pub(crate) fn roster_entry_listed(records: &[Value], petname: &str, device_pub_hex: Option<&str>) -> bool {
    records.iter().any(|r| {
        device_pub_hex.is_some_and(|k| {
            crate::identity::DeviceCert::from_json(&r["deviceCert"])
                .is_some_and(|c| hex::encode(c.device_pub).eq_ignore_ascii_case(k))
        }) || r["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(petname))
    })
}

#[cfg(test)]
mod roster_dedupe_tests {
    use super::roster_entry_listed;
    use serde_json::json;

    /// Eval item 7: a fleet sibling indexed WITHOUT a secret was listed twice,
    /// once from the store and once from the roster.
    #[test]
    fn a_secretless_fleet_record_hides_its_roster_twin() {
        let recs = vec![json!({"name": "u2-a", "caps": []})]; // no secret, as fleet-hello indexes it
        assert!(roster_entry_listed(&recs, "u2-a", Some(&"cd".repeat(32))));
        assert!(roster_entry_listed(&recs, "U2-A", None));
        assert!(!roster_entry_listed(&recs, "u2-b", Some(&"cd".repeat(32))));
    }
}

pub(crate) fn roster_row_label(petname: &str, my_name: &str) -> &'static str {
    if !my_name.is_empty() && petname.eq_ignore_ascii_case(my_name) {
        "a previous identity of this device (the owner can forget it)"
    } else {
        "known via owner"
    }
}

/// THE device-expiry sentence. `devices` and `devices --caps` both print it,
/// so one device never reads "cert expires in 90d" on one screen and "no
/// expiry" on the other. Pure.
pub(crate) fn cert_expiry_text(cert_expires: Option<u64>, now: u64) -> String {
    let Some(expires) = cert_expires else {
        return "no certificate".to_string();
    };
    if expires <= now {
        let date = chrono::DateTime::from_timestamp(expires as i64, 0)
            .map(|at| at.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "expired".to_string());
        return format!("expired {date}");
    }
    format!("cert expires in {}", remaining_span(expires - now))
}

pub(crate) fn device_countdown(
    tier: fleet_ui::devices::DeviceTier,
    cert: Option<&identity::DeviceCert>,
) -> String {
    // A paired device's certificate is ITS OWNER's business, not a clock on
    // anything this device allowed: showing "cert expires in 77d" read as a
    // deadline on the pairing, which has none.
    if tier == fleet_ui::devices::DeviceTier::Paired {
        return String::new();
    }
    // #240: no certificate means there is no expiry to count down to, and
    // nothing is blocked, so the column says what is true ("no certificate").
    // "cert expires in", the words the delegated rows use for the same clock.
    cert_expiry_text(cert.map(|c| c.expires), identity::now_secs())
}

/// A time remaining (`secs` until something expires), rounded UP to the
/// nearest whole unit, so a cert issued for 90 days reads "90d", not
/// "129600m" or a figure a few seconds short of the day. EVERY countdown to an
/// expiry goes through here: `id` floored the same certificate that `devices`
/// rounded up, and printed "valid 90d" and "valid 89d" seconds apart. Pure.
pub(crate) fn remaining_span(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d", secs.div_ceil(86400))
    } else if secs >= 3600 {
        format!("{}h", secs.div_ceil(3600))
    } else if secs >= 60 {
        format!("{}m", secs.div_ceil(60))
    } else {
        format!("{secs}s")
    }
}

fn device_caps_summary(caps: &[String], tier: fleet_ui::devices::DeviceTier) -> String {
    let mut labels = Vec::new();
    for cap in caps {
        let label = match (tier, cap.as_str()) {
            (fleet_ui::devices::DeviceTier::External, "transfer") => "can send you files",
            (fleet_ui::devices::DeviceTier::Paired, "transfer" | "send") => "files",
            (_, "transfer") => "inbox",
            (_, "shell") => "OWNER-EQUIVALENT shell",
            (_, "mount") => "mount",
            (_, "send") => "can send you files",
            (_, "read") => "read ~/share",
            _ => cap.as_str(),
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        "(none)".to_string()
    } else {
        labels.join(" ")
    }
}

/// The key that identifies "same mesh as me": my own owner key if I have one,
/// else the issuer key held in my own device certificate (the owner I joined
/// under). A device whose cert chains to THIS key is fleet, not external; so
/// a spoke stops filing its owner under "other people". Shared by `devices`
/// and `devices --caps` so the two cannot disagree on who is fleet.
pub(crate) fn same_owner_key() -> Option<[u8; 32]> {
    load_owner_key()
        .map(|key| key.public_key_bytes())
        .or_else(|| local_device_cert().map(|c| c.user_pub))
        // Display only: after this device's own access ended its certificate
        // no longer verifies, and the owner it joined was relabelled
        // "EXTERNAL / other people". It is still that owner.
        .or_else(|| own_cert_ignoring_expiry().map(|c| c.user_pub))
}

/// This device's own certificate as stored, WITHOUT the expiry check: for
/// saying "your access expired" truthfully, never for authorizing anything.
pub(crate) fn own_cert_ignoring_expiry() -> Option<identity::DeviceCert> {
    let overlay_pub = crate::overlay::overlay_pubkey_bytes().ok()?;
    crate::devices_store::store().own_cert_ignoring_expiry(&overlay_pub)
}

/// The row label for the owner this device joined, once this device's own
/// access has ended. Pure.
pub(crate) fn own_access_expired_label(expired_at: u64) -> String {
    format!("your access expired {}", crate::format_approval_expiry(expired_at))
}

/// The tier `devices` renders TODAY from a stored certificate. Deliberately
/// takes `device_cert_for`'s output, which skips expiry, so an expired cert
/// still files as FLEET here; the caps view says "cert expired" beside it
/// rather than silently re-tiering (docs/design-relationship-ux.md §2.2 is
/// the planned change, not this).
/// A record the owner invited as a PERSON (`add --for person`) holds an
/// owner-signed certificate like a device's, and is still someone else's: it
/// files as EXTERNAL, never as one of the owner's devices.
pub(crate) fn tier_for(
    cert: Option<&identity::DeviceCert>,
    same_owner: Option<&[u8; 32]>,
    invited_as_person: bool,
) -> fleet_ui::devices::DeviceTier {
    match cert {
        None => fleet_ui::devices::DeviceTier::NeedsReview,
        Some(_) if invited_as_person => fleet_ui::devices::DeviceTier::External,
        Some(cert) if same_owner == Some(&cert.user_pub) => fleet_ui::devices::DeviceTier::Fleet,
        Some(_) => fleet_ui::devices::DeviceTier::External,
    }
}

/// The tier the `devices` LIST shows. A device with no identity of its own
/// (paired by code, never joined anyone) has nobody to call "other people",
/// so a peer that holds an identity is simply paired there.
/// The capability view (`devices --caps`) keeps `tier_for`. Pure.
pub(crate) fn list_tier(
    cert: Option<&identity::DeviceCert>,
    same_owner: Option<&[u8; 32]>,
    invited_as_person: bool,
) -> fleet_ui::devices::DeviceTier {
    // The peer holds an identity (someone's device) and this one holds none:
    // "other people, deny-by-default" was the label, for the owner that paired
    // it. An uncertified peer keeps NEEDS REVIEW and its one-line fix.
    if same_owner.is_none() && cert.is_some() && !invited_as_person {
        return fleet_ui::devices::DeviceTier::Paired;
    }
    tier_for(cert, same_owner, invited_as_person)
}

pub(crate) fn device_entries(warm: Option<&Value>) -> Vec<fleet_ui::devices::DeviceEntry> {
    let warm_names = warm_device_names(warm);
    let same_owner = same_owner_key();
    // This device joined someone and its own access has ended: the rows of
    // that owner's devices say so instead of listing what it may no longer do.
    let own_ended = if load_owner_key().is_none() {
        own_cert_ignoring_expiry().filter(|c| c.expires <= identity::now_secs())
    } else {
        None
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let records: Vec<Value> = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
        .unwrap_or_default();
    // The roster closure below is `move`; it dedupes against these.
    let known = records.clone();

    // Iterate the RAW records, not devices_load(): that helper requires a pair
    // secret, and a fleet sibling is indexed without one, so listing through it
    // would hide exactly the devices this surface exists to show.
    records
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .map(|name| {
            let cert = device_cert_for(&name);
            let invited_as_person = records
                .iter()
                .find(|r| r["name"].as_str() == Some(name.as_str()))
                .is_some_and(|r| r["invitedAs"].as_str() == Some("person"));
            let tier = list_tier(cert.as_ref(), same_owner.as_ref(), invited_as_person);
            let caps = effective_device_caps(&name);
            let (last_seen, stored_v6, stored_v4) = devices_info(&name).unwrap_or((0, None, None));
            let address = stored_v6.or(stored_v4);
            let last_seen = (last_seen > 0).then(|| {
                let ago = now.saturating_sub(last_seen);
                if ago < 60 {
                    "just now".to_string()
                } else if ago < 3600 {
                    format!("{}m ago", ago / 60)
                } else if ago < 86400 {
                    format!("{}h ago", ago / 3600)
                } else {
                    format!("{}d ago", ago / 86400)
                }
            });
            // #240: this tier is reached whenever a device has no stored
            // certificate, which every code-flow pairing does. The row used to
            // say "promote to continue" and print `tunlion devices promote
            // <name>` underneath. Three things wrong at once: the verb does not
            // exist (#191), nothing is blocked (a transfer to such a device
            // works immediately, verified between two machines), and the tier
            // heading blamed "paired before scoped trust" for a pairing made
            // minutes earlier on the current build.
            //
            // So the row now states the condition and prescribes nothing. What
            // is TRUE is that the peer's identity was never certified, so it is
            // trusted in full rather than scoped. The tier's own design is #191
            // and #195 and is not settled here; this only stops the screen
            // asserting a blocked state and an impossible remedy.
            // A revoked device has no access, whatever its record still lists:
            // the row used to read "idle  inbox mount ... revoked", offering
            // capabilities the gate refuses.
            let revoked = records.iter().any(|r| {
                r["name"].as_str() == Some(name.as_str()) && record_is_revoked(r)
            });
            // An expired delegated device has no access either: its row used
            // to sit under FLEET with an "OWNER-EQUIVALENT shell" badge next
            // to "lapsed", while devices --json said caps [] and the gate
            // refused it.
            // Same state word `devices --json` reports.
            let ended = records
                .iter()
                .find(|r| r["name"].as_str() == Some(name.as_str()))
                .map(|r| crate::device_caps::device_access_json(r, now)["state"].as_str().unwrap_or("").to_string())
                .filter(|st| st == "expired" || st == "lapsed");
            let own_ended_here = own_ended
                .as_ref()
                .filter(|own| cert.as_ref().is_some_and(|c| c.user_pub == own.user_pub));
            // A fleet SIBLING: certified by our owner, never paired here (no
            // pair secret). Its kind implies transfer and nothing else; any
            // other capability is this device's own grant or an owner-signed
            // grant about this device. The owner's roster dropping it is a
            // revocation (DeviceStore::device_cert_revoked).
            let sibling_pub = records
                .iter()
                .find(|r| r["name"].as_str() == Some(name.as_str()))
                .filter(|r| r["secret"].as_str().is_none_or(str::is_empty))
                .and(cert.as_ref())
                .filter(|c| same_owner.as_ref() == Some(&c.user_pub) && load_owner_key().is_none())
                .map(|c| c.device_pub);
            let caps_summary = if revoked {
                "no access (revoked)".to_string()
            } else if sibling_pub.is_some_and(|p| crate::devices_store::store().device_cert_revoked(&p)) {
                "no access (removed by your owner)".to_string()
            } else if let Some(p) = sibling_pub {
                let mut sib_caps = vec!["transfer".to_string()];
                sib_caps.extend(caps.iter().cloned());
                // Owner grants: only those this device's fleet.owner_grants lets
                // apply count; the rest are named as held but not applied.
                let store = crate::devices_store::store();
                let (applied, held_only) = store.fleet_grant_caps_split(&p, now);
                sib_caps.extend(applied);
                let mut row = format!("your device · {}", device_caps_summary(&sib_caps, tier));
                if !held_only.is_empty() {
                    row.push_str(&format!(
                        " · {} not applied: fleet.owner_grants={}",
                        held_only.join(", "),
                        store.owner_grant_policy().as_str()
                    ));
                }
                row
            } else if let Some(own) = own_ended_here {
                own_access_expired_label(own.expires)
            } else if let Some(st) = &ended {
                format!("no access ({st})")
            } else if tier == fleet_ui::devices::DeviceTier::NeedsReview {
                format!("uncertified · {}", device_caps_summary(&caps, tier))
            } else {
                device_caps_summary(&caps, tier)
            };
            let caps_summary = match address {
                Some(address) => format!("{caps_summary}  {address}"),
                None => caps_summary,
            };
            fleet_ui::devices::DeviceEntry {
                name: name.clone(),
                tier,
                // #217: online is authoritative only when the warm-link reply is
                // present. On a platform with no control channel (or no daemon)
                // `warm` is None and the row omits the status instead of
                // rendering "offline" for every device always.
                online: warm.map(|_| warm_names.contains(&name)),
                route: crate::warm_device_route(warm, &name),
                caps_summary,
                countdown: match delegated_device_state(&name, cert.as_ref(), now, &records) {
                    Some((text, tone)) => ui::paint(tone, &text),
                    None => device_countdown(tier, cert.as_ref()),
                },
                last_seen,
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .chain(
            crate::roster::stored_roster()
                .and_then(|r| r["devices"].as_array().cloned())
                .map(|arr| {
                    let self_pub = crate::overlay::overlay_pubkey_bytes().ok();
                    let my_name = crate::display_name();
                    arr.into_iter()
                        .filter_map(move |d| {
                            let name = d["petname"].as_str()?.to_string();
                            // Skip a sibling that is ALREADY a row from the local store.
                            // Against the RAW records: a fleet sibling is indexed
                            // without a secret, so the old `devices_load()` check
                            // missed it and the same device was listed twice
                            // ("[fleet] u2-a" and "[mesh] u2-a known via owner").
                            if roster_entry_listed(&known, &name, d["device_pub"].as_str()) {
                                return None;
                            }
                            // Skip MYSELF: the roster lists the owner's devices, and on a
                            // spoke that includes this device's own key, which must never
                            // render as its own sibling.
                            if let (Some(self_pub), Some(hex_pub)) =
                                (self_pub.as_ref(), d["device_pub"].as_str())
                            {
                                if let Ok(decoded) = hex::decode(hex_pub) {
                                    if decoded.as_slice() == self_pub {
                                        return None;
                                    }
                                }
                            }
                            let caps_summary = roster_row_label(&name, &my_name).to_string();
                            Some(fleet_ui::devices::DeviceEntry {
                                name,
                                tier: fleet_ui::devices::DeviceTier::MeshRoster,
                                online: None, // unknown liveness (#217), never idle/offline
                                route: None,
                                caps_summary,
                                countdown: String::new(),
                                last_seen: None,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .collect()
}

#[cfg(test)]
mod span_tests {
    use super::remaining_span;

    /// A 90-day certificate reads 90d for its whole first day, whichever
    /// command shows it; it only reads 89d once less than 89 days remain.
    #[test]
    fn a_countdown_rounds_up_and_is_stable_for_seconds() {
        let ninety = 90 * 86400;
        assert_eq!(remaining_span(ninety), "90d");
        assert_eq!(remaining_span(ninety - 5), "90d");
        assert_eq!(remaining_span(ninety - 86399), "90d");
        assert_eq!(remaining_span(89 * 86400), "89d");
        assert_eq!(remaining_span(3600 * 5 - 1), "5h");
        assert_eq!(remaining_span(61), "2m");
        assert_eq!(remaining_span(59), "59s");
    }
}

#[cfg(test)]
mod roster_row_label_tests {
    use super::roster_row_label;

    #[test]
    fn this_devices_old_key_is_named_as_such() {
        assert!(roster_row_label("p9-b", "p9-b").contains("previous identity of this device"));
        assert!(roster_row_label("P9-B", "p9-b").contains("previous identity"));
        assert_eq!(roster_row_label("alpha", "p9-b"), "known via owner");
        assert_eq!(roster_row_label("alpha", ""), "known via owner");
    }
}

#[cfg(test)]
mod person_tier_tests {
    use super::{list_tier, tier_for};
    use crate::fleet_ui::devices::DeviceTier;

    /// Launch matrix: a person admitted by `add --for person` holds an
    /// owner-signed certificate exactly like a device, and `devices` filed them
    /// under FLEET, "your devices". The invited kind decides.
    #[test]
    fn a_person_invited_by_the_owner_is_external_not_fleet() {
        let owner = [7u8; 32];
        let cert = crate::identity::DeviceCert { device_pub: [1u8; 32], user_pub: owner, expires: u64::MAX, issued: 0, sig: [0u8; 64] };
        assert_eq!(tier_for(Some(&cert), Some(&owner), false), DeviceTier::Fleet);
        assert_eq!(tier_for(Some(&cert), Some(&owner), true), DeviceTier::External);
        assert_eq!(tier_for(None, Some(&owner), true), DeviceTier::NeedsReview);
        // No identity here: whatever the peer holds, the list says paired.
        assert_eq!(list_tier(Some(&cert), None, false), DeviceTier::Paired);
        assert_eq!(list_tier(None, None, false), DeviceTier::NeedsReview);
        assert_eq!(list_tier(Some(&cert), Some(&owner), false), DeviceTier::Fleet);
    }
}
