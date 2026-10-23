//! The local commit boundary for `join`.
//!
//! A join touches four pieces of local state: the overlay key (the key the
//! owner certifies), the owner record in `devices.json`, this device's
//! certificate, and the display name. They used to be written one after the
//! other with the certificate FIRST, so a failure while writing `devices.json`
//! left a device holding a certificate and an overlay key but no store. The
//! owner had already certified that key, and the next command could not tell a
//! half-join from a clean device: `up` refused "no identity yet, and no paired
//! devices", and a retry could generate a different overlay key that the owner
//! had never certified.
//!
//! This module makes the accepted acknowledgement a small JOURNAL:
//!
//! 1. [`JoinState::accept`] writes `join.pending.json` with the signed local
//!    certificate and the owner record (both already validated against the
//!    invitation) and the device key. This is the commit point.
//! 2. The owner record is upserted into `devices.json`.
//! 3. The local certificate file is written LAST.
//! 4. The journal is removed.
//!
//! A crash or an I/O failure between any two steps leaves the journal, and
//! [`JoinState::resume`] completes the missing writes on the next `join` or
//! `up`. A retry against the owner is also safe because the owner re-sends the
//! same acknowledgement instead of consuming the invitation again.
//!
//! Every inspection is read-only except `resume`/`accept`: looking must never
//! mint an overlay key, which is exactly how a mismatch got created before.

use anyhow::{Context, Result, bail};
use filament_peerloop::recv::store::DeviceStore;
use serde_json::{Value, json};
use std::path::PathBuf;

use crate::identity::DeviceCert;

pub(crate) const PENDING_FILE: &str = "join.pending.json";
pub(crate) const OVERLAY_KEY_FILE: &str = "overlay.ed25519";
pub(crate) const DEVICES_FILE: &str = "devices.json";
pub(crate) const DEVICES_BACKUP_FILE: &str = "devices.json.bak";

/// Files a successful join creates or may leave behind are listed in
/// `mount_cmd::RESET_STATE`; there is one list because a reset that misses one
/// calls itself a clean slate while a half-join survives.
#[derive(Clone, Debug)]
pub(crate) struct JoinState {
    root: PathBuf,
}

impl JoinState {
    pub(crate) fn current() -> Self {
        Self::at(crate::settings::config_dir())
    }

    pub(crate) fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn pending_path(&self) -> PathBuf {
        self.root.join(PENDING_FILE)
    }

    fn local_cert_path(&self) -> PathBuf {
        self.root.join("identity/device-cert.json")
    }

    fn overlay_path(&self) -> PathBuf {
        self.root.join(OVERLAY_KEY_FILE)
    }

    fn devices_path(&self) -> PathBuf {
        self.root.join(DEVICES_FILE)
    }

    fn devices_backup_path(&self) -> PathBuf {
        self.root.join(DEVICES_BACKUP_FILE)
    }

    fn store(&self) -> DeviceStore {
        DeviceStore::open(&self.root)
    }

    pub(crate) fn pending(&self) -> Result<Option<Value>> {
        let path = self.pending_path();
        let Some(raw) = self.read_regular(&path, "join.pending.json")? else {
            return Ok(None);
        };
        let value = serde_json::from_str(&raw).map_err(|e| {
            anyhow::anyhow!(
                "join.pending.json at {} cannot be parsed ({e}); repair: `tunlion down -y`, \
                 then `tunlion reset -y`, then join again with a fresh invitation.",
                path.display()
            )
        })?;
        Ok(Some(value))
    }

    /// Read a small state file through a no-follow handle. `Ok(None)` is
    /// absence; a symlink, non-regular file, unreadable or non-UTF8 file is an
    /// error (never "empty").
    fn read_regular_bytes(&self, path: &std::path::Path, what: &str) -> Result<Option<Vec<u8>>> {
        let relative = path.strip_prefix(&self.root).unwrap_or(path);
        match crate::platform::read_regular_nofollow_beneath(&self.root, relative) {
            Ok(value) => Ok(value),
            Err(e) => Err(anyhow::anyhow!(
                "{} at {} is not usable ({e}); repair: `tunlion down -y`, then \
                 `tunlion reset -y`, then join again with a fresh invitation",
                what,
                path.display()
            )),
        }
    }

    fn read_regular(&self, path: &std::path::Path, what: &str) -> Result<Option<String>> {
        let Some(bytes) = self.read_regular_bytes(path, what)? else {
            return Ok(None);
        };
        let text = String::from_utf8(bytes).map_err(|_| {
            anyhow::anyhow!(
                "{} at {} is not UTF-8; repair: `tunlion down -y`, then `tunlion reset -y`, \
                 then join again with a fresh invitation",
                what,
                path.display()
            )
        })?;
        Ok(Some(text))
    }

    /// This device's owner public key, if it holds one. Read no-follow and
    /// parsed, so a symlink or corrupt file cannot masquerade as "owner".
    fn owner_identity_pub(&self) -> Result<Option<[u8; 32]>> {
        let path = self.root.join("identity.ed25519");
        let Some(bytes) = self.read_regular_bytes(&path, "owner identity key")? else {
            return Ok(None);
        };
        let key = crate::identity::UserKey::from_encoded(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "owner identity key at {} is corrupt ({e}); repair: `tunlion down -y`, \
                 then `tunlion reset -y`, then init or join again",
                path.display()
            )
        })?;
        Ok(Some(key.public_key_bytes()))
    }

    fn overlay_pub_strict(&self) -> Result<Option<[u8; 32]>> {
        let path = self.overlay_path();
        let Some(bytes) = self.read_regular_bytes(&path, "overlay key")? else {
            return Ok(None);
        };
        filament_peerloop::recv::store::OverlayKey::public_key_bytes_from_pkcs8(&bytes)
            .map(Some)
            .map_err(|e| {
                anyhow::anyhow!(
                    "overlay key at {} is corrupt ({e}); repair: `tunlion down -y`, \
                     then `tunlion reset -y`, then join again with a fresh invitation",
                    path.display()
                )
            })
    }

    /// The local certificate, read strictly. Absent is `Ok(None)`; present but
    /// unreadable, unparseable or missing its `cert` is an ERROR. Treating that
    /// as "no certificate" made `up`/`addr` fail open on a corrupt identity.
    fn read_local_cert(&self) -> Result<Option<DeviceCert>> {
        let path = self.local_cert_path();
        let Some(raw) = self.read_regular(&path, "this device's certificate")? else {
            return Ok(None);
        };
        let record: Value = serde_json::from_str(&raw).with_context(|| {
            format!(
                "this device's certificate record at {} cannot be parsed; repair: \
                 `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                path.display()
            )
        })?;
        let cert = DeviceCert::from_json(&record["cert"]).ok_or_else(|| {
            anyhow::anyhow!(
                "this device's certificate record at {} has no valid `cert`; repair: \
                 `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                path.display()
            )
        })?;
        // Structural parsing is not validity. An expired certificate or a
        // signature that does not chain to its user key is exactly what the
        // fleet rejects later; refuse it here with the repair path instead of
        // presenting it as a transport problem.
        cert.verify(crate::identity::now_secs()).map_err(|e| {
            anyhow::anyhow!(
                "this device's certificate at {} is not valid ({e}); repair: \
                 `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                path.display()
            )
        })?;
        Ok(Some(cert))
    }

    /// The overlay public key on disk, without generating one. Best-effort
    /// form for display/tests; security checks use `overlay_pub_strict`.
    pub(crate) fn overlay_pub(&self) -> Option<[u8; 32]> {
        self.overlay_pub_strict().ok().flatten()
    }

    fn write_pending(&self, value: &Value) -> Result<()> {
        crate::platform::SecretFile::write_str(
            &self.pending_path(),
            &serde_json::to_string_pretty(value)?,
        )
        .with_context(|| format!("write {}", self.pending_path().display()))
    }

    fn clear_pending(&self) -> Result<()> {
        match std::fs::remove_file(self.pending_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("remove join.pending.json"),
        }
    }

    fn set_name(&self, name: &str) -> Result<()> {
        let p = self.root.join("config");
        let mut lines: Vec<String> = std::fs::read_to_string(&p)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.split_whitespace().next() != Some("name"))
            .map(|l| l.to_string())
            .collect();
        lines.push(format!("name {name}"));
        crate::platform::SecretFile::write_str(&p, &(lines.join("\n") + "\n"))
            .context("write config name")
    }

    /// Record a join that is ABOUT to send an enrollment request. The device
    /// key is pinned here before the owner ever sees it, so a later overlay key
    /// cannot silently replace the key the owner might certify.
    pub(crate) fn begin(
        &self,
        device_pub: [u8; 32],
        owner_name: &str,
        issuer_fp: &[u8],
    ) -> Result<()> {
        if let Some(pending) = self.pending()? {
            let pinned = pending["devicePub"].as_str().unwrap_or_default();
            if !pinned.is_empty() && pinned != hex::encode(device_pub) {
                bail!(
                    "a previous join started with overlay key {pinned}, but this device now has {}. \
                     That enrollment cannot be completed here: the owner would certify a key this \
                     device no longer holds. Repair: `tunlion down -y`, then `tunlion reset -y`, \
                     then join again with a fresh invitation from the owner. Do not copy \
                     overlay.ed25519 from another machine.",
                    hex::encode(device_pub)
                );
            }
        }
        self.write_pending(&json!({
            "version": 1,
            "devicePub": hex::encode(device_pub),
            "ownerName": owner_name,
            "issuerFp": hex::encode(issuer_fp),
            "startedAt": crate::identity::now_secs(),
        }))
    }

    /// Commit an ACCEPTED acknowledgement. Validation against the invitation is
    /// the caller's job; this writes the journal then applies it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept(
        &self,
        assigned_name: &str,
        device_pub: [u8; 32],
        local_cert: &DeviceCert,
        owner_name: &str,
        owner_cert: &DeviceCert,
        secret: &str,
        caps: &[String],
        scope: u8,
    ) -> Result<String> {
        let pending = match self.pending()? {
            Some(pending) => pending,
            None => json!({
                "version": 1,
                "devicePub": hex::encode(device_pub),
                "ownerName": owner_name,
                "startedAt": crate::identity::now_secs(),
            }),
        };
        let mut pending = pending;
        pending["devicePub"] = json!(hex::encode(device_pub));
        pending["ownerName"] = json!(owner_name);
        pending["accepted"] = json!({
            "name": assigned_name,
            "localCert": { "name": assigned_name, "cert": local_cert.to_json() },
            "ownerName": owner_name,
            "ownerCert": owner_cert.to_json(),
            "secret": secret,
            "caps": caps,
            "scope": scope,
        });
        self.write_pending(&pending)?;
        // The journal is durable before either half of the identity is visible.
        self.apply_pending()
    }

    /// Finish an accepted join whose journal is still on disk. `Some(name)`
    /// means the identity is now committed; `None` means the journal exists but
    /// the owner has not accepted (no certificate in it yet).
    pub(crate) fn resume(&self) -> Result<Option<String>> {
        let Some(pending) = self.pending()? else {
            return Ok(None);
        };
        if pending.get("accepted").is_none() {
            return Ok(None);
        }
        self.apply_pending().map(Some)
    }

    fn apply_pending(&self) -> Result<String> {
        let pending = self.pending()?.ok_or_else(|| {
            anyhow::anyhow!("join.pending.json disappeared before it could be applied")
        })?;
        let accepted = pending
            .get("accepted")
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no accepted acknowledgement"))?;
        if self.owner_identity_pub()?.is_some() {
            bail!(
                "a join journal exists, but this device now holds an OWNER identity. Refusing to                  write a joined certificate over it. Run `tunlion reset -y` if this machine should be                  the joined device instead, then join again with a fresh invitation."
            );
        }
        let device_hex = pending["devicePub"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no device key"))?;
        let device_pub: [u8; 32] = hex::decode(device_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has an invalid device key"))?;
        let overlay = self.overlay_pub_strict()?;
        match overlay {
            Some(local) if hex::encode(local) == device_hex => {}
            Some(local) => bail!(
                "the accepted join is for overlay key {device_hex}, but the local overlay key is {}. \
                 Refusing to write an identity the owner did not certify. Repair: `tunlion down -y`, \
                 then `tunlion reset -y`, then join again with a fresh invitation.",
                hex::encode(local)
            ),
            None => bail!(
                "the accepted join is for overlay key {device_hex}, but overlay.ed25519 is missing. \
                 Restore that file, or run `tunlion reset -y` and join again with a fresh invitation."
            ),
        }
        let local = &accepted["localCert"];
        let cert = DeviceCert::from_json(&local["cert"]).ok_or_else(|| {
            anyhow::anyhow!("join.pending.json carries an invalid local certificate")
        })?;
        // The journal is untrusted input until verified. Resuming used to write
        // an expired or bad-signature certificate and report success, while the
        // next `up`/`addr` refused it.
        cert.verify(crate::identity::now_secs()).map_err(|e| {
            anyhow::anyhow!(
                "join.pending.json carries a local certificate that is not valid ({e}); repair: \
                 `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation"
            )
        })?;
        if cert.device_pub != device_pub {
            bail!(
                "join.pending.json's certificate names a different device key; refusing to commit it. \
                 Run `tunlion reset -y` and join again with a fresh invitation."
            );
        }
        let owner_cert = DeviceCert::from_json(&accepted["ownerCert"]).ok_or_else(|| {
            anyhow::anyhow!("join.pending.json carries an invalid owner certificate")
        })?;
        owner_cert
            .verify(crate::identity::now_secs())
            .map_err(|e| {
                anyhow::anyhow!(
                    "join.pending.json carries an owner certificate that is not valid ({e}); \
                     repair: `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh \
                     invitation from the owner"
                )
            })?;
        let name = accepted["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no device name"))?;
        let owner_name = accepted["ownerName"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no owner name"))?;
        let secret = accepted["secret"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no reconnect secret"))?;
        let caps: Vec<String> = accepted["caps"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("join.pending.json has no ceiling"))?
            .iter()
            .map(|c| {
                c.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("join.pending.json ceiling has a non-string"))
            })
            .collect::<Result<_>>()?;
        let scope = accepted["scope"].as_u64().unwrap_or(0) as u8;

        // devices.json first, certificate last. A failure at either step leaves
        // the journal, so the next `join`/`up` can finish rather than start
        // from a machine that looks unjoined while holding an identity.
        self.set_name(name)?;
        self.store()
            .devices_store_joined_owner(owner_name, secret, &owner_cert, &caps, scope)
            .context("record the owner in devices.json")?;
        self.store()
            .write_local_device_cert_record(&json!({ "name": name, "cert": cert.to_json() }))
            .context("write this device's joined certificate")?;
        self.clear_pending()?;
        Ok(name.to_string())
    }

    /// Refuse a state where the key this device would present is not the key
    /// its certificate (or an accepted join) names. Named repair path, never a
    /// transport-looking "unreachable".
    pub(crate) fn check_key_binding(&self) -> Result<()> {
        let overlay = self.overlay_pub_strict()?;
        if let Some(pending) = self.pending()? {
            if let Some(pinned) = pending["devicePub"].as_str() {
                if !pinned.is_empty() {
                    match overlay {
                        Some(local) if hex::encode(local) != pinned => bail!(
                            "a join started with overlay key {pinned}, but this device's overlay key is now {}. \
                             The owner would have certified a key this device cannot present. Repair: \
                             `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh \
                             invitation from the owner.",
                            hex::encode(local)
                        ),
                        None => bail!(
                            "a join started with overlay key {pinned}, but overlay.ed25519 is missing. \
                             Restore that file, or run `tunlion reset -y` and join again with a fresh invitation."
                        ),
                        _ => {}
                    }
                }
            }
        }
        let Some(cert) = self.read_local_cert()? else {
            return Ok(());
        };
        let enrolled = hex::encode(cert.device_pub);
        match overlay {
            Some(local) if hex::encode(local) != enrolled => bail!(
                "this device's certificate is for overlay key {enrolled}, but the local overlay key is {}. \
                 A peer that certified {enrolled} cannot reach this address, and starting `up` here would \
                 present a key the fleet never approved. Repair: `tunlion down -y`, then `tunlion reset -y`, \
                 then join again with a fresh invitation from the owner, or ask the owner to approve this \
                 device again.",
                hex::encode(local)
            ),
            None => bail!(
                "this device's certificate is for overlay key {enrolled}, but overlay.ed25519 is missing. \
                 Restore that key, or run `tunlion reset -y` and join again with a fresh invitation."
            ),
            _ => {}
        }
        Ok(())
    }

    /// Read and validate `devices.json` whenever it exists.
    ///
    /// A store that is a directory, unparseable, not an array, or holds a
    /// non-object/nameless record is a broken device store for every device,
    /// with or without a certificate. `up_refused_for_identity` treats
    /// unparseable text as "not empty", which used to let a keyless device
    /// start on top of a corrupt store.
    fn read_store_records(&self) -> Result<Option<Vec<Value>>> {
        let devices = self.devices_path();
        let Some(raw) = self.read_regular(&devices, "this device's store")? else {
            return Ok(None);
        };
        let records: Vec<Value> = serde_json::from_str(&raw).map_err(|e| {
            anyhow::anyhow!(
                "this device's store at {} cannot be parsed ({e}); repair: \
                 `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                devices.display()
            )
        })?;
        for (index, record) in records.iter().enumerate() {
            let Some(obj) = record.as_object() else {
                bail!(
                    "this device's store at {} has a non-object record at index {index}; repair: \
                     `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                    devices.display()
                );
            };
            if obj
                .get("name")
                .and_then(Value::as_str)
                .map_or(true, |n| n.trim().is_empty())
            {
                bail!(
                    "this device's store at {} has a record without a name at index {index}; repair: \
                     `tunlion down -y`, then `tunlion reset -y`, then join again with a fresh invitation",
                    devices.display()
                );
            }
            let has_secret = match obj.get("secret") {
                None => false,
                Some(secret) => {
                    let Some(secret) = secret.as_str() else {
                        bail!(
                            "this device's store at {} has a non-string pair secret at index {index}; \
                             repair: `tunlion down -y`, then `tunlion reset -y`, then join again with a \
                             fresh invitation",
                            devices.display()
                        );
                    };
                    if hex::decode(secret).map(|b| b.len()).ok() != Some(32) {
                        bail!(
                            "this device's store at {} has an invalid pair secret at index {index}; \
                             repair: `tunlion down -y`, then `tunlion reset -y`, then join again with a \
                             fresh invitation",
                            devices.display()
                        );
                    }
                    true
                }
            };
            let has_cert = match obj.get("deviceCert") {
                None => false,
                Some(cert) => {
                    let Some(cert) = DeviceCert::from_json(cert) else {
                        bail!(
                            "this device's store at {} has an invalid device certificate at index \
                             {index}; repair: `tunlion down -y`, then `tunlion reset -y`, then join \
                             again with a fresh invitation",
                            devices.display()
                        );
                    };
                    cert.verify(crate::identity::now_secs()).map_err(|e| {
                        anyhow::anyhow!(
                            "this device's store at {} has an invalid or expired device certificate \
                             at index {index} ({e}); repair: `tunlion down -y`, then \
                             `tunlion reset -y`, then join again with a fresh invitation",
                            devices.display()
                        )
                    })?;
                    true
                }
            };
            if !has_secret && !has_cert {
                bail!(
                    "this device's store at {} has a record with no usable credential at index \
                     {index}; repair: `tunlion down -y`, then `tunlion reset -y`, then join again \
                     with a fresh invitation",
                    devices.display()
                );
            }
        }
        Ok(Some(records))
    }

    /// A joined device must hold the owner record its certificate names: the
    /// same owner user key, a different device key (the owner's), a usable pair
    /// secret and a name. A syntactically valid `[]` is not a joined store.
    fn check_owner_record(&self, cert: &DeviceCert, records: &[Value]) -> Result<()> {
        let owner_user = hex::encode(cert.user_pub);
        let has_owner = records.iter().any(|record| {
            let Some(owner) = DeviceCert::from_json(&record["deviceCert"]) else {
                return false;
            };
            if owner.verify(crate::identity::now_secs()).is_err() {
                return false;
            }
            owner.user_pub == cert.user_pub
                && owner.device_pub != cert.device_pub
                && record["name"]
                    .as_str()
                    .is_some_and(|name| !name.trim().is_empty())
                && record["secret"]
                    .as_str()
                    .is_some_and(|s| hex::decode(s).map(|b| b.len()).ok() == Some(32))
        });
        if has_owner {
            return Ok(());
        }
        bail!(
            "the join did not finish: this device's certificate names owner {owner_user}, but \
             devices.json has no owner record for that identity. Repair: `tunlion down -y`, then \
             `tunlion reset -y`, then join again with a fresh invitation from the owner."
        )
    }

    /// Validate the local identity and the device store together.
    ///
    /// The store is inspected whenever it exists, even with no certificate (a
    /// keyless pair store) or on an owner device: a directory, invalid JSON,
    /// a non-array or a nameless record is never a healthy store. A JOINED
    /// certificate additionally needs its owner record and a key binding, so a
    /// valid certificate plus `[]`, `[1]` or `[{}]` is refused.
    pub(crate) fn check_complete_join(&self) -> Result<()> {
        let cert = self.read_local_cert()?;
        let records = self.read_store_records()?;
        let Some(cert) = cert else {
            return Ok(());
        };
        // An owner device legitimately has no paired devices yet, but only when
        // the owner key is the one THIS certificate chains to. A valid owner
        // key for a DIFFERENT user must not turn a joined certificate into an
        // owner device and skip the owner-record check.
        if self.owner_identity_pub()? == Some(cert.user_pub) {
            return Ok(());
        }
        match records {
            Some(records) => self.check_owner_record(&cert, &records),
            None if self.devices_backup_path().is_file() => bail!(
                "the join did not finish: this device has a joined certificate but no devices.json. \
                 A backup is at {}. Restore it only if it is this device's own store \
                 (`cp {0} {1}`); otherwise run `tunlion reset -y` and join again with a fresh invitation. \
                 `tunlion up` will not start a half-joined device.",
                self.devices_backup_path().display(),
                self.devices_path().display()
            ),
            None => bail!(
                "the join did not finish: this device has a joined certificate but no devices.json, so it \
                 holds no record of the owner it joined. Run `tunlion reset -y`, then join again with a fresh \
                 invitation. `tunlion up` will not start a half-joined device."
            ),
        }
    }

    /// A read-only command must not print an address for a join whose accepted
    /// acknowledgement is still sitting in the journal: the certificate (the
    /// identity) has not been committed yet.
    pub(crate) fn check_pending_accepted_not_committed(&self) -> Result<()> {
        let Some(pending) = self.pending()? else {
            return Ok(());
        };
        if pending.get("accepted").is_some() && self.read_local_cert()?.is_none() {
            bail!(
                "a join the owner already accepted is still pending locally (the certificate was \
                 not written). Run `tunlion up` (or `tunlion join`) to finish it before `addr`; \
                 do not treat the overlay address as a joined identity yet."
            );
        }
        Ok(())
    }

    /// What `up` should say when a join was started but no acknowledgement ever
    /// arrived. This is not "no identity yet": the overlay key is live and the
    /// owner may have certified it, so a reset before checking would make the
    /// mismatch worse.
    pub(crate) fn check_pending_for_up(&self) -> Result<()> {
        let Some(pending) = self.pending()? else {
            return Ok(());
        };
        if pending.get("accepted").is_some() {
            return Ok(());
        }
        let owner = pending["ownerName"].as_str().unwrap_or("the owner");
        bail!(
            "a join to '{owner}' was started but has not been accepted here yet (no certificate). \
             Run `tunlion join` again with the same invitation: an owner that already certified this \
             key re-sends the receipt without using the invitation again. If the invitation is gone, \
             ask {owner} for a fresh one. Do not delete overlay.ed25519 or run `up` until the join reports success."
        )
    }
}

/// `join` calls this before minting/sending anything. Read-only.
pub(crate) fn preflight_join() -> Result<()> {
    let state = JoinState::current();
    state.check_key_binding()?;
    state.check_complete_join()
}

/// `up` calls this before it decides there is no identity. A complete journal
/// is applied first (the owner already accepted); any mismatch is a named
/// refusal.
pub(crate) fn prepare_up() -> Result<Option<String>> {
    let state = JoinState::current();
    let resumed = state.resume()?;
    state.check_key_binding()?;
    state.check_complete_join()?;
    state.check_pending_for_up()?;
    Ok(resumed)
}

/// `addr` must not present an address the certificate does not name, or one
/// whose joined device store is missing.
pub(crate) fn check_for_readout() -> Result<()> {
    let state = JoinState::current();
    state.check_key_binding()?;
    state.check_complete_join()?;
    state.check_pending_accepted_not_committed()?;
    state.check_pending_for_up()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tunlion-join-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cert_for(seed: u8, device: [u8; 32], ttl: u64) -> DeviceCert {
        let user = crate::identity::UserKey::from_seed(&[seed; 32]).unwrap();
        DeviceCert::certify(&user, device, crate::identity::now_secs(), ttl).unwrap()
    }

    fn write_overlay(root: &Path) {
        filament_peerloop::recv::store::OverlayKey::new(root.join(OVERLAY_KEY_FILE))
            .load_pkcs8()
            .unwrap();
    }

    #[test]
    fn a_certificate_for_another_overlay_key_is_refused_with_the_repair_path() {
        let root = temp("mismatch");
        write_overlay(&root);
        let cert = cert_for(3, [7u8; 32], 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        let err = JoinState::at(&root)
            .check_key_binding()
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlay key"), "{err}");
        assert!(err.contains("tunlion reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_joined_certificate_without_devices_json_is_refused_not_called_healthy() {
        let root = temp("half");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let cert = cert_for(3, overlay, 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        let err = JoinState::at(&root)
            .check_complete_join()
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish"), "{err}");
        assert!(err.contains("reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unrelated_owner_key_does_not_skip_the_owner_record() {
        let root = temp("unrelated-owner");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        // A valid owner identity for a DIFFERENT user.
        filament_id::UserKey::generate(&filament_peerloop::recv::store::RootKeyStore::new(
            root.clone(),
        ))
        .unwrap();
        // A joined certificate chaining to user 3, not the generated owner.
        let cert = cert_for(3, overlay, 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        write_store(&root, json!([]));
        let err = JoinState::at(&root)
            .check_complete_join()
            .unwrap_err()
            .to_string();
        assert!(err.contains("no owner record"), "{err}");

        // The same joined certificate IS complete once its actual owner record
        // is present, even though an unrelated owner key is on disk.
        let owner_cert = cert_for(3, [9u8; 32], 3600);
        write_store(
            &root,
            json!([{
                "name": "owner",
                "secret": "11".repeat(32),
                "deviceCert": owner_cert.to_json()
            }]),
        );
        JoinState::at(&root).check_complete_join().unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn owner_device_with_no_devices_json_is_not_a_half_join() {
        let root = temp("owner");
        write_overlay(&root);
        let owner = filament_id::UserKey::generate(
            &filament_peerloop::recv::store::RootKeyStore::new(root.clone()),
        )
        .unwrap();
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let cert = DeviceCert::certify(&owner, overlay, crate::identity::now_secs(), 3600).unwrap();
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "owner", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        JoinState::at(&root).check_complete_join().unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_accepted_journal_commits_both_files_and_is_then_idempotent() {
        let root = temp("resume");
        write_overlay(&root);
        let state = JoinState::at(&root);
        let overlay = state.overlay_pub().unwrap();
        let user = crate::identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let owner_cert =
            DeviceCert::certify(&user, overlay, crate::identity::now_secs(), 3600).unwrap();
        let local = DeviceCert::certify(&user, overlay, crate::identity::now_secs(), 3600).unwrap();
        state.begin(overlay, "owner", &[1, 2, 3, 4]).unwrap();
        let name = state
            .accept(
                "joined",
                overlay,
                &local,
                "owner",
                &owner_cert,
                &"11".repeat(32),
                &["transfer".to_string()],
                1,
            )
            .unwrap();
        assert_eq!(name, "joined");
        assert!(root.join(DEVICES_FILE).exists());
        assert!(root.join("identity/device-cert.json").exists());
        assert!(state.pending().unwrap().is_none());
        // A second resume is a no-op, not a second write.
        assert_eq!(state.resume().unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pending_key_that_no_longer_matches_the_overlay_key_is_refused() {
        let root = temp("pending-key");
        write_overlay(&root);
        let state = JoinState::at(&root);
        state.begin([9u8; 32], "owner", &[1, 2]).unwrap();
        let err = state.check_key_binding().unwrap_err().to_string();
        assert!(err.contains("a join started with overlay key"), "{err}");
        assert!(err.contains("reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_corrupt_certificate_is_refused_not_treated_as_absent() {
        let root = temp("corrupt-cert");
        write_overlay(&root);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            r#"{"name":"joined","cert":{}}"#,
        )
        .unwrap();
        let state = JoinState::at(&root);
        let err = state.check_key_binding().unwrap_err().to_string();
        assert!(err.contains("certificate record"), "{err}");
        assert!(err.contains("tunlion reset"), "{err}");
        let err = state.check_complete_join().unwrap_err().to_string();
        assert!(err.contains("tunlion reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_devices_json_directory_is_not_a_joined_store() {
        let root = temp("devices-dir");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let cert = cert_for(3, overlay, 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        std::fs::create_dir(root.join(DEVICES_FILE)).unwrap();
        let err = JoinState::at(&root)
            .check_complete_join()
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a regular file"), "{err}");
        assert!(err.contains("tunlion reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_accepted_journal_without_a_certificate_blocks_the_readout() {
        let root = temp("accepted-journal");
        write_overlay(&root);
        let state = JoinState::at(&root);
        let overlay = hex::encode(state.overlay_pub().unwrap());
        crate::platform::SecretFile::write_str(
            &root.join(PENDING_FILE),
            &json!({
                "version": 1,
                "devicePub": overlay,
                "ownerName": "owner",
                "startedAt": 1,
                "accepted": { "name": "joined" }
            })
            .to_string(),
        )
        .unwrap();
        let err = state
            .check_pending_accepted_not_committed()
            .unwrap_err()
            .to_string();
        assert!(err.contains("still pending locally"), "{err}");
        assert!(err.contains("tunlion up"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
    fn write_store(root: &Path, value: Value) {
        crate::platform::SecretFile::write_str(
            &root.join(DEVICES_FILE),
            &serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn a_joined_certificate_needs_a_real_owner_record_not_just_valid_json() {
        let root = temp("owner-record");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let cert = cert_for(3, overlay, 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        let state = JoinState::at(&root);
        let owner_cert = cert_for(3, [9u8; 32], 3600);
        let secret = "11".repeat(32);

        for (label, store, needle) in [
            ("empty array", json!([]), "no owner record"),
            ("scalar record", json!([1]), "non-object record"),
            ("nameless record", json!([{}]), "without a name"),
            (
                "no owner certificate",
                json!([{ "name": "owner", "secret": secret }]),
                "no owner record",
            ),
            (
                "different owner user key",
                json!([{
                    "name": "owner",
                    "secret": secret,
                    "deviceCert": cert_for(4, [9u8; 32], 3600).to_json()
                }]),
                "no owner record",
            ),
        ] {
            write_store(&root, store);
            let err = state.check_complete_join().unwrap_err().to_string();
            assert!(err.contains(needle), "{label}: {err}");
        }

        write_store(
            &root,
            json!([{
                "name": "owner",
                "secret": secret,
                "deviceCert": owner_cert.to_json()
            }]),
        );
        state
            .check_complete_join()
            .expect("a real owner record for the certificate's owner is complete");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bad_store_is_refused_even_without_a_certificate() {
        let root = temp("bad-store-keyless");
        let state = JoinState::at(&root);
        crate::platform::SecretFile::write_str(&root.join(DEVICES_FILE), "{garbage").unwrap();
        let err = state.check_complete_join().unwrap_err().to_string();
        assert!(err.contains("cannot be parsed"), "{err}");

        write_store(&root, json!([1]));
        let err = state.check_complete_join().unwrap_err().to_string();
        assert!(err.contains("non-object record"), "{err}");

        let _ = std::fs::remove_file(root.join(DEVICES_FILE));
        std::fs::create_dir(root.join(DEVICES_FILE)).unwrap();
        let err = state.check_complete_join().unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");

        // An empty array with no identity is a legitimate empty pair store.
        std::fs::remove_dir(root.join(DEVICES_FILE)).unwrap();
        write_store(&root, json!([]));
        state
            .check_complete_join()
            .expect("a keyless empty store is not corruption");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bad_signature_or_expired_certificate_is_refused() {
        let root = temp("cert-validity");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let mut cert = cert_for(3, overlay, 3600);
        cert.sig[0] ^= 0xFF;
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        let err = JoinState::at(&root)
            .check_key_binding()
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid"), "{err}");
        assert!(err.contains("tunlion reset"), "{err}");

        let user = crate::identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let expired = DeviceCert::certify(
            &user,
            overlay,
            crate::identity::now_secs().saturating_sub(7200),
            3600,
        )
        .unwrap();
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": expired.to_json()}).to_string(),
        )
        .unwrap();
        let err = JoinState::at(&root)
            .check_key_binding()
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "{err}");
        assert!(err.contains("tunlion reset"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_record_with_no_credential_or_a_non_string_secret_is_refused() {
        let root = temp("credential-shape");
        write_overlay(&root);
        let overlay = JoinState::at(&root).overlay_pub().unwrap();
        let cert = cert_for(3, overlay, 3600);
        crate::platform::SecretFile::write_str(
            &root.join("identity/device-cert.json"),
            &json!({"name": "joined", "cert": cert.to_json()}).to_string(),
        )
        .unwrap();
        let state = JoinState::at(&root);
        let mut bad_cert = cert_for(3, [9u8; 32], 3600);
        bad_cert.sig[0] ^= 0xFF;
        let expired_cert = DeviceCert::certify(
            &crate::identity::UserKey::from_seed(&[3u8; 32]).unwrap(),
            [9u8; 32],
            crate::identity::now_secs().saturating_sub(7200),
            3600,
        )
        .unwrap();
        for (label, record, needle) in [
            (
                "non-string secret",
                json!([{"name": "x", "secret": 123}]),
                "non-string pair secret",
            ),
            (
                "null secret",
                json!([{"name": "x", "secret": null}]),
                "non-string pair secret",
            ),
            ("name only", json!([{"name": "x"}]), "no usable credential"),
            (
                "invalid cert",
                json!([{"name": "x", "deviceCert": {}}]),
                "invalid device certificate",
            ),
            (
                "bad-signature store cert",
                json!([{"name": "x", "deviceCert": bad_cert.to_json()}]),
                "invalid or expired device certificate",
            ),
            (
                "expired store cert",
                json!([{"name": "x", "deviceCert": expired_cert.to_json()}]),
                "invalid or expired device certificate",
            ),
        ] {
            write_store(&root, record);
            let err = state.check_complete_join().unwrap_err().to_string();
            assert!(err.contains(needle), "{label}: {err}");
        }
        // A valid owner plus an extra malformed record is still a malformed store.
        let owner_cert = cert_for(3, [9u8; 32], 3600);
        write_store(
            &root,
            json!([
                {"name": "owner", "secret": "11".repeat(32), "deviceCert": owner_cert.to_json()},
                {"name": "extra"}
            ]),
        );
        let err = state.check_complete_join().unwrap_err().to_string();
        assert!(err.contains("no usable credential"), "{err}");

        // A valid shape but an owner certificate that does not verify (bad
        // signature or expired) is not an owner record either.
        for invalid in [bad_cert, expired_cert] {
            write_store(
                &root,
                json!([{
                    "name": "owner",
                    "secret": "11".repeat(32),
                    "deviceCert": invalid.to_json()
                }]),
            );
            let err = state.check_complete_join().unwrap_err().to_string();
            assert!(
                err.contains("invalid or expired device certificate"),
                "{err}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resuming_an_expired_or_bad_signature_journal_is_refused() {
        let root = temp("resume-invalid");
        write_overlay(&root);
        let state = JoinState::at(&root);
        let overlay = state.overlay_pub().unwrap();
        let user = crate::identity::UserKey::from_seed(&[3u8; 32]).unwrap();
        let owner_cert = cert_for(3, [9u8; 32], 3600);
        let now = crate::identity::now_secs();
        let expired = DeviceCert::certify(&user, overlay, now.saturating_sub(7200), 3600).unwrap();
        let mut bad = DeviceCert::certify(&user, overlay, now, 3600).unwrap();
        bad.sig[0] ^= 0xFF;
        for (label, local_cert, needle) in [
            ("expired", expired, "expired"),
            ("bad signature", bad, "not valid"),
        ] {
            crate::platform::SecretFile::write_str(
                &root.join(PENDING_FILE),
                &json!({
                    "version": 1,
                    "devicePub": hex::encode(overlay),
                    "ownerName": "owner",
                    "startedAt": 1,
                    "accepted": {
                        "name": "joined",
                        "localCert": {"name": "joined", "cert": local_cert.to_json()},
                        "ownerCert": owner_cert.to_json(),
                        "secret": "11".repeat(32),
                        "caps": ["transfer"],
                        "scope": 1
                    }
                })
                .to_string(),
            )
            .unwrap();
            let err = state.resume().unwrap_err().to_string();
            assert!(err.contains(needle), "{label}: {err}");
            assert!(
                !root.join(DEVICES_FILE).exists(),
                "{label}: store must not be written"
            );
            assert!(
                !root.join("identity/device-cert.json").exists(),
                "{label}: certificate must not be written"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
