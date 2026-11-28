//! Owner-signed fleet grant sets (see `filament_cap::fleet_grants`).

use super::DeviceStore;
use anyhow::Result;
use filament_id::{DeviceCert, UserKey};
use serde_json::{json, Value};

/// Owner side: grants the owner made FOR another fleet device. Local, plain.
pub const FLEET_GRANTS_AUTHORED_FILE: &str = "fleet-grants.json";
/// Owner side: per-target mint state, so an unchanged set keeps its epoch.
pub const FLEET_GRANTS_STATE_FILE: &str = "fleet-grants-state.json";
/// Receiver side: the newest accepted set about THIS device, as received.
/// Never merged into the capability store.
pub const FLEET_GRANTS_HELD_FILE: &str = "fleet-grants-held.json";
/// The `config` line key that holds `fleet.owner_grants` (the CLI's typed
/// settings registry writes it; `cli/src/settings.rs` pins the same string).
/// Written only by a local `tunlion set`; no network message reaches it.
pub const OWNER_GRANT_POLICY_STORE_KEY: &str = "fleet_owner_grants";

impl DeviceStore {
    fn json_array_at(&self, file: &str) -> Vec<Value> {
        std::fs::read_to_string(self.root.join(file))
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .unwrap_or_default()
    }

    /// The grants this OWNER device has made for other fleet devices.
    pub fn fleet_grants_authored(&self) -> Vec<Value> {
        self.json_array_at(FLEET_GRANTS_AUTHORED_FILE)
    }

    /// Record (or replace) "`subject` may `cap` on `target`", owner side.
    /// `expires` 0 means no grant-level expiry.
    pub fn fleet_grant_add(
        &self,
        target_pub: &[u8; 32],
        subject_pub: &[u8; 32],
        cap: &str,
        expires: u64,
    ) -> Result<()> {
        let mut all = self.fleet_grants_authored();
        let (t, s) = (hex::encode(target_pub), hex::encode(subject_pub));
        all.retain(|g| !(g["target_pub"] == t && g["subject_pub"] == s && g["cap"] == cap));
        all.push(json!({"target_pub": t, "subject_pub": s, "cap": cap, "expires": expires}));
        secret_write::SecretFile::write_str(
            &self.root.join(FLEET_GRANTS_AUTHORED_FILE),
            &serde_json::to_string_pretty(&all)?,
        )?;
        Ok(())
    }

    /// Remove "`subject` may `cap` on `target`". Returns whether one existed.
    pub fn fleet_grant_remove(&self, target_pub: &[u8; 32], subject_pub: &[u8; 32], cap: &str) -> Result<bool> {
        let mut all = self.fleet_grants_authored();
        let (t, s) = (hex::encode(target_pub), hex::encode(subject_pub));
        let before = all.len();
        all.retain(|g| !(g["target_pub"] == t && g["subject_pub"] == s && g["cap"] == cap));
        let removed = all.len() != before;
        if removed {
            secret_write::SecretFile::write_str(
                &self.root.join(FLEET_GRANTS_AUTHORED_FILE),
                &serde_json::to_string_pretty(&all)?,
            )?;
        }
        Ok(removed)
    }

    /// Has this owner ever authored a grant for `target_pub` (now, or in a set
    /// it minted before)? A device that never had one is sent nothing.
    pub fn fleet_grants_ever_for(&self, target_pub: &[u8; 32]) -> bool {
        let t = hex::encode(target_pub);
        self.fleet_grants_authored()
            .iter()
            .any(|g| g["target_pub"].as_str() == Some(t.as_str()))
            || std::fs::read_to_string(self.root.join(FLEET_GRANTS_STATE_FILE))
                .ok()
                .and_then(|r| serde_json::from_str::<Value>(&r).ok())
                .is_some_and(|v| v.get(&t).is_some())
    }

    /// Mint and sign the current set about `target_pub`, owner side.
    ///
    /// A subject the owner has revoked is left out, so the next push withdraws
    /// its grants everywhere (the receivers' revocation checks deny it anyway;
    /// this keeps the signed statement honest). The epoch bumps only when the
    /// content changes; `valid_until` refreshes once half the TTL has passed.
    pub fn mint_fleet_grant_set(
        &self,
        owner: &UserKey,
        target_pub: &[u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<Value> {
        let t = hex::encode(target_pub);
        let mut grants: Vec<filament_id::FleetGrant> = self
            .fleet_grants_authored()
            .iter()
            .filter(|g| g["target_pub"].as_str() == Some(t.as_str()))
            .filter_map(|g| {
                let subject_pub: [u8; 32] = hex::decode(g["subject_pub"].as_str()?).ok()?.try_into().ok()?;
                let expires = g["expires"].as_u64().unwrap_or(0);
                if self.device_cert_revoked(&subject_pub) || (expires != 0 && expires <= now) {
                    return None;
                }
                Some(filament_id::FleetGrant { subject_pub, cap: g["cap"].as_str()?.to_string(), expires })
            })
            .collect();
        grants.sort_by(|a, b| (a.subject_pub, a.cap.as_str()).cmp(&(b.subject_pub, b.cap.as_str())));
        let hash = {
            use sha2::{Digest, Sha256};
            let probe = filament_id::FleetGrantSet {
                owner_pub: owner.public_key_bytes(),
                target_pub: *target_pub,
                epoch: 0,
                valid_until: 0,
                grants: grants.clone(),
            };
            let mut h = Sha256::new();
            h.update(probe.canonical_bytes());
            h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let state_path = self.root.join(FLEET_GRANTS_STATE_FILE);
        let mut state: serde_json::Map<String, Value> = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default();
        let prev = state.get(&t).cloned().unwrap_or(Value::Null);
        let (pe, ph, pu) = (
            prev["epoch"].as_u64().unwrap_or(0),
            prev["hash"].as_str().unwrap_or("").to_string(),
            prev["valid_until"].as_u64().unwrap_or(0),
        );
        let epoch = if pe == 0 || ph != hash { pe + 1 } else { pe };
        let valid_until = if ph == hash && pu > now.saturating_add(ttl_secs / 2) {
            pu
        } else {
            now.saturating_add(ttl_secs)
        };
        if epoch != pe || valid_until != pu {
            state.insert(t.clone(), json!({"epoch": epoch, "hash": hash, "valid_until": valid_until}));
            secret_write::SecretFile::write_str(&state_path, &serde_json::to_string_pretty(&state)?)?;
        }
        let set = filament_id::FleetGrantSet {
            owner_pub: owner.public_key_bytes(),
            target_pub: *target_pub,
            epoch,
            valid_until,
            grants,
        };
        let sig = set.sign(owner.keypair())?;
        let mut blob = set.to_json();
        blob["sig"] = json!(hex::encode(sig));
        Ok(blob)
    }

    fn parse_signed_set(blob: &Value) -> Option<(filament_id::FleetGrantSet, bool)> {
        let set = filament_id::FleetGrantSet::from_json(blob)?;
        let sig: [u8; 64] = hex::decode(blob["sig"].as_str()?).ok()?.try_into().ok()?;
        let ok = set.verify(&sig).is_ok();
        Some((set, ok))
    }

    fn held_fleet_grants_raw(&self) -> Option<Value> {
        std::fs::read_to_string(self.root.join(FLEET_GRANTS_HELD_FILE))
            .ok()
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
    }

    /// Receiver side: judge a pushed set and store it on `Accept`. A malformed
    /// set is an error; every other outcome is the pure judgement.
    pub fn verify_and_store_fleet_grants(
        &self,
        blob: &Value,
        my_owner: &[u8; 32],
        my_device: &[u8; 32],
        now: u64,
    ) -> Result<filament_cap::fleet_grants::GrantSetJudgement> {
        use filament_cap::fleet_grants::{judge_grant_set_under, GrantSetHeader, GrantSetJudgement};
        let Some((set, sig_ok)) = Self::parse_signed_set(blob) else {
            anyhow::bail!("malformed fleet grant set");
        };
        let held = self
            .held_fleet_grants_raw()
            .and_then(|h| Some((h["epoch"].as_u64()?, h["valid_until"].as_u64()?)));
        let h = GrantSetHeader {
            owner_pub: set.owner_pub,
            target_pub: set.target_pub,
            epoch: set.epoch,
            valid_until: set.valid_until,
        };
        let j = judge_grant_set_under(self.owner_grant_policy(), &h, sig_ok, my_owner, my_device, now, held);
        if j == GrantSetJudgement::Accept {
            let mut keep = set.to_json();
            keep["sig"] = blob["sig"].clone();
            keep["received_at"] = json!(now);
            secret_write::SecretFile::write_str(
                &self.root.join(FLEET_GRANTS_HELD_FILE),
                &serde_json::to_string_pretty(&keep)?,
            )?;
        }
        Ok(j)
    }

    /// This device's `fleet.owner_grants`, read from its own `config` file on
    /// every call (so a `tunlion set` applies to the next decision, with no
    /// restart). Absent means the default (`files`); unreadable means `off`.
    pub fn owner_grant_policy(&self) -> filament_cap::fleet_grants::OwnerGrantPolicy {
        let raw = std::fs::read_to_string(self.root.join("config")).ok();
        let v = raw.as_deref().and_then(|r| {
            r.lines().find_map(|l| {
                let (k, v) = l.split_once(char::is_whitespace)?;
                (k == OWNER_GRANT_POLICY_STORE_KEY).then(|| v.trim().to_string())
            })
        });
        filament_cap::fleet_grants::OwnerGrantPolicy::from_stored(v.as_deref())
    }

    /// Receiver side, what the gates ask: does the held set grant `subject` the
    /// `action` now, AND does this device's `fleet.owner_grants` let an owner
    /// grant of that kind apply? The policy is read at this moment, so a set
    /// accepted under `all` stops granting shell the instant the device's owner
    /// narrows it to `files`.
    pub fn fleet_grant_applies(&self, subject: &[u8; 32], action: &str, now: u64) -> bool {
        self.owner_grant_policy().applies(action) && self.fleet_grant_held(subject, action, now)
    }

    /// Receiver side: does the held set grant `subject` the `action` now?
    /// (Held and valid; whether it APPLIES is [`DeviceStore::fleet_grant_applies`].)
    ///
    /// The held file is re-verified on every read (signature, owner, target):
    /// a file that was edited, or that predates a change of owner, grants
    /// nothing. Only meaningful on a joined device; the owner holds none.
    pub fn fleet_grant_held(&self, subject: &[u8; 32], action: &str, now: u64) -> bool {
        use filament_cap::fleet_grants::{grant_set_allows, HeldGrant};
        let Some(raw) = self.held_fleet_grants_raw() else {
            return false;
        };
        let Some((set, sig_ok)) = Self::parse_signed_set(&raw) else {
            return false;
        };
        let Some(owner) = self.owner_pub_for_resources(None) else {
            return false;
        };
        let Some(me) = self.local_device_cert_record().and_then(|r| DeviceCert::from_json(&r["cert"])) else {
            return false;
        };
        if !sig_ok || set.owner_pub != owner || set.target_pub != me.device_pub {
            return false;
        }
        let grants: Vec<HeldGrant> = set
            .grants
            .iter()
            .map(|g| HeldGrant { subject_pub: g.subject_pub, cap: g.cap.clone(), expires: g.expires })
            .collect();
        grant_set_allows(set.valid_until, &grants, subject, action, now)
    }

    /// Receiver side, for display: the held, valid owner grants for `subject`,
    /// split into those that apply under this device's `fleet.owner_grants` and
    /// those held but not applied.
    pub fn fleet_grant_caps_split(&self, subject: &[u8; 32], now: u64) -> (Vec<String>, Vec<String>) {
        let policy = self.owner_grant_policy();
        self.fleet_grant_caps_for(subject, now)
            .into_iter()
            .partition(|c| policy.applies(c))
    }

    /// Receiver side: the capabilities the held set grants `subject` now, for
    /// display (`devices`). Same checks as [`DeviceStore::fleet_grant_held`];
    /// the local policy is not applied here (see `fleet_grant_caps_split`).
    pub fn fleet_grant_caps_for(&self, subject: &[u8; 32], now: u64) -> Vec<String> {
        let Some(raw) = self.held_fleet_grants_raw() else {
            return Vec::new();
        };
        let Some(set) = filament_id::FleetGrantSet::from_json(&raw) else {
            return Vec::new();
        };
        let mut caps: Vec<String> = set
            .grants
            .iter()
            .filter(|g| g.subject_pub == *subject)
            .map(|g| g.cap.clone())
            .filter(|c| self.fleet_grant_held(subject, c, now))
            .collect();
        caps.sort();
        caps.dedup();
        caps
    }
}

