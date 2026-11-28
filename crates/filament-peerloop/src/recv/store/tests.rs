use super::*;


#[test]
fn identity_bootstrap_is_mutating_serialized_and_never_replaces_existing_state() {
    let root = std::env::temp_dir().join(format!("fil-identity-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&root).unwrap();
    let store = DeviceStore::open(&root);
    assert!(!store.has_identity());
    assert!(!root.join("identity.ed25519").exists());
    let workers: Vec<_> = (0..4).map(|_| {
        let root=root.clone();
        std::thread::spawn(move || {
            let store=DeviceStore::open(&root);
            store.ensure_identity_on_mutation().unwrap();
            store.owner_pub_from_keystore().unwrap()
        })
    }).collect();
    let keys: Vec<_> = workers.into_iter().map(|w|w.join().unwrap()).collect();
    assert!(keys.iter().all(|key|key==&keys[0]));
    std::fs::write(root.join("identity.ed25519"),b"corrupt existing key").unwrap();
    assert!(store.ensure_identity_on_mutation().is_err());
    assert_eq!(std::fs::read(root.join("identity.ed25519")).unwrap(),b"corrupt existing key");
    std::fs::remove_file(root.join("identity.ed25519")).unwrap();
    std::fs::create_dir_all(root.join("identity")).unwrap();
    std::fs::write(store.local_device_cert_path(),b"existing joined state").unwrap();
    store.ensure_identity_on_mutation().unwrap();
    assert!(!root.join("identity.ed25519").exists());
    // Only this test's unique fixture directory, not production state.
    std::fs::remove_file(store.local_device_cert_path()).unwrap();
    std::fs::remove_dir(root.join("identity")).unwrap();
    std::fs::remove_file(root.join("identity.lock")).unwrap();
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn stale_provisional_identities_are_collected_and_fresh_ones_kept() {
    let dir = std::env::temp_dir().join(format!("fil-st-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).unwrap();
    let now = 10_000_000u64;
    let write = |name: &str, at: u64| {
        std::fs::write(
            dir.join(format!("provisional_{name}.json")),
            serde_json::json!({"name": name, "storedAt": at}).to_string(),
        )
        .unwrap();
    };
    write("peer-old", now - PROVISIONAL_TTL_SECS - 1);
    write("peer-older", 1);
    write("peer-fresh", now - 5);
    std::fs::write(dir.join("devices.json"), b"[]").unwrap();
    assert_eq!(sweep_stale_provisional(&dir, now), 2);
    assert!(
        dir.join("provisional_peer-fresh.json").exists(),
        "a live session keeps its record"
    );
    assert!(!dir.join("provisional_peer-old.json").exists());
    assert!(
        dir.join("devices.json").exists(),
        "only provisional records are swept"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_is_rooted_at_its_instance_directory() {
    let dir = std::env::temp_dir().join(format!("fil-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = DeviceStore::open(&dir);
    store
        .devices_upsert_atomic(
            "alpha",
            Some(&"a".repeat(64)),
            None,
            Some(&["transfer".to_string()]),
            None,
            None,
            None,
            false,
        )
        .unwrap();
    assert_eq!(
        store.devices_load(),
        vec![("alpha".to_string(), "a".repeat(64))]
    );
    assert_eq!(store.device_name_for_pub(&[0u8; 32]), None);
    let other = DeviceStore::open(dir.join("other"));
    assert!(
        other.devices_load().is_empty(),
        "instances do not share a root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sanitize_device_name_strips_escape_junk() {
    let dirty = "\u{1b}[?1;2c\u{1b}[?1;2c\u{1b}[>0;276;0cpixel";
    assert_eq!(sanitize_device_name(dirty), "pixel");
    assert_eq!(sanitize_device_name("  lap\u{7}top \n"), "laptop");
    assert_eq!(sanitize_device_name("agboola@pop-os"), "agboola@pop-os");
}

#[cfg(test)]
mod receive_history_tests {
    use super::super::*;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("receive-history-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn receipt(index: u64) -> ReceivedFileRecord {
        ReceivedFileRecord {
            time: index, peer: Some("sender".into()), file: "offered.txt".into(),
            stored: Some("/inbox/offered.1.txt".into()), bytes: 42,
            sha256: Some("ab".repeat(32)), ok: true,
        }
    }

    #[test]
    fn verified_receive_facts_are_bounded_and_preserve_stored_name_and_digest() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.path());
        assert!(!root.path().join("transfers.json").exists());
        for index in 0..201 { store.record_received_file(&receipt(index)).unwrap(); }
        let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(root.path().join("transfers.json")).unwrap()).unwrap();
        assert_eq!(rows.len(), 200);
        assert_eq!(rows[0]["time"], 1);
        assert_eq!(rows[199]["stored"], "/inbox/offered.1.txt");
        assert_eq!(rows[199]["sha256"], "ab".repeat(32));
        assert_eq!(rows[199]["bytes"], 42);
        assert_eq!(rows[199]["direction"], "in");
        assert!(!root.path().join("overlay.ed25519").exists());
    }

    #[test]
    fn corrupt_history_is_preserved_and_error_is_not_a_successful_receipt() {
        let root = TestRoot::new();
        let path = root.path().join("transfers.json");
        std::fs::write(&path, "[").unwrap();
        assert!(DeviceStore::open(root.path()).record_received_file(&receipt(1)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[");
    }

    #[test]
    fn revocation_snapshot_is_fail_closed_and_prunes_only_absent_secrets() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.path());
        assert_eq!(
            store.revocation_snapshot(),
            Some((String::new(), String::new()))
        );
        // A missing store is empty content, so every held secret loses trust:
        // fail closed, never keep a secret a deleted store cannot vouch for.
        let mut held = vec![("a".into(), "s-a".into()), ("b".into(), "s-b".into())];
        assert_eq!(store.prune_held(&mut held).len(), 2);
        assert!(held.is_empty());

        std::fs::write(
            root.path().join("devices.json"),
            r#"[{"name":"a","secret":"s-a"}]"#,
        )
        .unwrap();
        let mut held = vec![("a".into(), "s-a".into()), ("b".into(), "s-b".into())];
        assert_eq!(
            store.prune_held(&mut held),
            ["s-b".to_string()]
                .into_iter()
                .collect::<std::collections::HashSet<String>>()
        );
        assert_eq!(held, vec![("a".to_string(), "s-a".to_string())]);

        // A rename of the same secret follows the current name; it is not a
        // removal and must not leave the old name authorizing the new record.
        std::fs::write(
            root.path().join("devices.json"),
            r#"[{"name":"renamed","secret":"s-a"}]"#,
        )
        .unwrap();
        let mut held = vec![("a".into(), "s-a".into())];
        assert!(store.prune_held(&mut held).is_empty());
        assert_eq!(held, vec![("renamed".to_string(), "s-a".to_string())]);

        std::fs::write(root.path().join("devices.json"), "not-json").unwrap();
        let mut held = vec![("a".into(), "s-a".into())];
        assert_eq!(store.revocation_snapshot(), None);
        assert!(store.prune_held(&mut held).is_empty());
        assert_eq!(held.len(), 1, "an unreadable store must remove nothing");
    }
}


#[cfg(test)]
mod store_guards {
    use super::super::*;
    use super::super::invitations::invitation_use_lock_path;
    use filament_cap::ephemeral::Reuse;
    use std::collections::HashSet;
    use serde_json::{json, Value};
    use std::sync::{Arc, Barrier};

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-guard-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn competing_writers_lose_no_update() {
        let root = unique("writers");
        let store = DeviceStore::open(&root);
        store
            .with_devices_mut(|arr| {
                arr.push(json!({"name": "base", "secret": "s0"}));
                Ok(())
            })
            .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for i in 0..2 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .with_devices_mut(|arr| {
                        arr.push(json!({"name": format!("w{i}"), "secret": format!("s{i}")}));
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let names: Vec<String> = store
            .devices_records()
            .iter()
            .filter_map(|d| d["name"].as_str().map(str::to_string))
            .collect();
        assert!(names.contains(&"base".to_string()));
        assert!(names.contains(&"w0".to_string()));
        assert!(names.contains(&"w1".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_store_is_refused_and_never_overwritten() {
        let root = unique("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join(DEVICES_FILE);
        let garbage = b"{garbage";
        std::fs::write(&p, garbage).unwrap();
        let store = DeviceStore::open(&root);
        let error = store.devices_remove("alpha").unwrap_err();
        assert!(error.downcast_ref::<CorruptStore>().is_some());
        assert_eq!(std::fs::read(&p).unwrap(), garbage);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A declined `--remember` and `devices forget` both remove a record; the
    /// backup written beside that removal held the removed secret, so the
    /// known-device gate's "nothing stored" was false on disk.
    #[test]
    fn a_removed_secret_does_not_survive_in_the_devices_backup() {
        let root = unique("devbak");
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        let p = store.devices_path();
        let (gone, kept) = ("ab".repeat(32), "cd".repeat(32));
        std::fs::write(&p, serde_json::to_string(&json!([
            {"name": "declinedev", "secret": gone},
            {"name": "laptop", "secret": kept},
            {"name": "browser-only"},
        ])).unwrap()).unwrap();
        store.devices_remove("declinedev").unwrap();
        let bak = std::fs::read_to_string(backup_path(&p)).unwrap();
        assert!(!bak.contains(&gone) && !bak.contains("declinedev"), "{bak}");
        assert!(bak.contains(&kept) && bak.contains("browser-only"), "the rest is still the last good copy: {bak}");
        // A rename keeps the secret, so the record stays restorable.
        store.with_devices_mut(|arr| { arr[0]["name"] = json!("laptop-2"); Ok(()) }).unwrap();
        let bak = std::fs::read_to_string(backup_path(&p)).unwrap();
        assert!(bak.contains(&kept) && bak.contains("\"laptop\""), "{bak}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cap_store_keeps_a_backup_and_refuses_to_write_over_damage() {
        let root = unique("caps");
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        let p = store.cap_store_path();
        std::fs::write(&p, br#"[{"a":1}]"#).unwrap();
        store.save_cap_store(&[json!({"b": 2})]).unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"b\""));
        assert!(std::fs::read_to_string(backup_path(&p))
            .unwrap()
            .contains("\"a\""));

        let garbage = b"{garbage";
        std::fs::write(&p, garbage).unwrap();
        assert!(store.save_cap_store(&[json!({"c": 3})]).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), garbage);

        // A failed backup is best effort and never blocks the write it protects.
        std::fs::write(&p, br#"[{"ok":true}]"#).unwrap();
        let bak = backup_path(&p);
        let _ = std::fs::remove_file(&bak);
        std::fs::create_dir(&bak).unwrap();
        assert!(store.save_cap_store(&[json!({"d": 4})]).is_ok());
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"d\""));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn armed_state_needs_a_key_id_and_does_not_cross_instances() {
        let root = unique("armed");
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let future = cap_now_secs() + 600;
        std::fs::write(
            a.join("armed.json"),
            json!([{"key_id": "aa".repeat(32), "expires": future}]).to_string(),
        )
        .unwrap();
        let store_a = DeviceStore::open(&a);
        let store_b = DeviceStore::open(&b);
        assert!(store_a.is_armed());
        assert!(!store_b.is_armed());

        std::fs::write(
            a.join("armed.json"),
            json!([{"expires": future}]).to_string(),
        )
        .unwrap();
        assert!(
            !store_a.is_armed(),
            "an entry without a key id is not armed"
        );
        std::fs::write(
            a.join("armed.json"),
            json!([{"key_id": "aa".repeat(32), "expires": cap_now_secs() - 1}]).to_string(),
        )
        .unwrap();
        assert!(!store_a.is_armed(), "an expired entry is not armed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn owner_pub_falls_back_to_the_local_certificate_issuer() {
        let root = unique("owner-fallback");
        let store = DeviceStore::open(&root);
        let user = UserKey::from_seed(&[7u8; 32]).unwrap();
        let cert = DeviceCert::certify(&user, [7u8; 32], now_secs(), 60).unwrap();
        store
            .write_local_device_cert_record(&json!({"name": "joined", "cert": cert.to_json()}))
            .unwrap();
        assert_eq!(
            store.owner_pub_for_resources(None),
            Some(user.public_key_bytes()),
            "a broken/unreadable overlay key must not hide the certificate issuer"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_engine_lease_per_root_and_a_dropped_lease_can_be_retaken() {
        let root = unique("lease");
        let a = DeviceStore::open(&root);
        let b = DeviceStore::open(&root);
        let held = a.try_acquire_engine_lease().unwrap().expect("first lease");
        assert!(b.try_acquire_engine_lease().unwrap().is_none());
        drop(held);
        assert!(b.try_acquire_engine_lease().unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_durable_invitation_use_survives_a_fresh_store() {
        let root = unique("invitation-use");
        let first = DeviceStore::open(&root);
        first
            .record_invitation_use("key", &Reuse::Once, 1_000, 10)
            .unwrap();
        // A restart is a fresh store over the same root: nothing in memory.
        let second = DeviceStore::open(&root);
        assert_eq!(
            second.record_invitation_use("key", &Reuse::Once, 1_000, 11),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(
            second.record_invitation_use("other", &Reuse::Once, 1_000, 11),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_used_invitation_file_fails_closed() {
        let root = unique("invitation-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(USED_INVITATIONS_FILE), b"{garbage").unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("key", &Reuse::Once, 1_000, 10),
            Err(InvitationRefusal::Unverifiable)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------ invitation withdrawal --

    #[test]
    fn a_withdrawn_reusable_invitation_is_refused_and_stays_refused_after_a_restart() {
        let root = unique("withdraw-reusable");
        let store = DeviceStore::open(&root);
        // `--reuse forever`: no count can ever run out, so only withdrawal
        // stops it. One claim first, the shape the owner reported.
        assert_eq!(store.record_invitation_use("k", &Reuse::Reusable, 10_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("k", 10_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 10_000, 102),
            Err(InvitationRefusal::Withdrawn)
        );
        // A restart is a fresh store over the same root: nothing in memory.
        let reopened = DeviceStore::open(&root);
        assert_eq!(reopened.invitation_withdrawn("k", 103), Ok(true));
        assert_eq!(
            reopened.record_invitation_use("k", &Reuse::Reusable, 10_000, 103),
            Err(InvitationRefusal::Withdrawn)
        );
        // The use already counted is kept, not reset by the withdrawal.
        let ledger = reopened.invitation_ledger(104);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].uses, 1);
        assert!(ledger[0].withdrawn);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_withdrawn_bounded_invitation_is_refused_with_uses_left_and_before_any_use() {
        let root = unique("withdraw-bounded");
        let store = DeviceStore::open(&root);
        assert_eq!(store.record_invitation_use("n", &Reuse::N(20), 10_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("n", 10_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("n", &Reuse::N(20), 10_000, 102),
            Err(InvitationRefusal::Withdrawn)
        );
        // Never claimed at all: the withdrawal writes a line of its own.
        assert_eq!(store.invitation_withdrawn("fresh", 100), Ok(false));
        assert_eq!(store.withdraw_invitation("fresh", 10_000, 100), Ok(()));
        assert_eq!(
            store.record_invitation_use("fresh", &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::Withdrawn)
        );
        // Another invitation is unaffected.
        assert_eq!(store.record_invitation_use("other", &Reuse::Once, 10_000, 101), Ok(()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_withdrawal_lasts_to_the_signed_end_and_is_never_shortened() {
        let root = unique("withdraw-expiry");
        let store = DeviceStore::open(&root);
        // A use recorded with the signed expiry, then a withdrawal that names a
        // SHORTER one (a stale or wrong local copy): the line keeps the later
        // end, so the refusal cannot lapse while the invitation still verifies.
        assert_eq!(store.record_invitation_use("k", &Reuse::Reusable, 5_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("k", 1_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 5_000, 4_999),
            Err(InvitationRefusal::Withdrawn),
            "one second before the signed end it is still refused"
        );
        assert_eq!(store.invitation_withdrawn("k", 4_999), Ok(true));
        // At the end the invitation itself no longer verifies (the enrolment
        // path checks that first), and the line is pruned like a count.
        assert_eq!(store.invitation_withdrawn("k", 5_000), Ok(false));
        assert!(store.invitation_ledger(5_000).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn counting_another_invitation_keeps_a_withdrawal() {
        let root = unique("withdraw-keep");
        let store = DeviceStore::open(&root);
        assert_eq!(store.withdraw_invitation("gone", 10_000, 100), Ok(()));
        // Every use rewrites the file; the rewrite must carry the flag along.
        for t in 0..3 {
            assert_eq!(store.record_invitation_use("live", &Reuse::Reusable, 10_000, 101 + t), Ok(()));
        }
        assert_eq!(
            store.record_invitation_use("gone", &Reuse::Reusable, 10_000, 200),
            Err(InvitationRefusal::Withdrawn)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn withdrawal_fails_closed_on_an_unreadable_file() {
        let root = unique("withdraw-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(USED_INVITATIONS_FILE), b"{garbage").unwrap();
        let store = DeviceStore::open(&root);
        // The withdrawal says it did not happen and leaves the file alone.
        assert_eq!(
            store.withdraw_invitation("k", 10_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        assert_eq!(
            std::fs::read(root.join(USED_INVITATIONS_FILE)).unwrap(),
            b"{garbage"
        );
        // And the in-flight check refuses rather than admits.
        assert_eq!(
            store.invitation_withdrawn("k", 100),
            Err(InvitationRefusal::Unverifiable)
        );
        // A `withdrawn` this store cannot read is not "not withdrawn".
        std::fs::write(
            root.join(USED_INVITATIONS_FILE),
            br#"[{"keyId":"k","uses":0,"expires":10000,"withdrawn":"yes"}]"#,
        )
        .unwrap();
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 10_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_root_has_nothing_withdrawn() {
        let root = unique("withdraw-none");
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(DeviceStore::open(&root).invitation_withdrawn("k", 1), Ok(false));
    }

    #[test]
    fn a_withdrawal_racing_claims_is_ordered_by_the_lock() {
        // Many claimers over separate stores on one root (separate processes
        // in production), one withdrawal in the middle. Every claim that
        // returned Ok counted BEFORE the withdrawal: none is admitted after it.
        let root = unique("withdraw-race");
        std::fs::create_dir_all(&root).unwrap();
        let mut handles = Vec::new();
        for i in 0..16u64 {
            let root = root.clone();
            handles.push(std::thread::spawn(move || {
                let store = DeviceStore::open(&root);
                store.record_invitation_use("race", &Reuse::Reusable, 10_000, 100 + i)
            }));
        }
        {
            let store = DeviceStore::open(&root);
            store.withdraw_invitation("race", 10_000, 100).unwrap();
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count() as u64;
        let ledger = DeviceStore::open(&root).invitation_ledger(0);
        assert_eq!(ledger.len(), 1);
        assert!(ledger[0].withdrawn);
        assert_eq!(ledger[0].uses, ok, "every admitted claim is counted, and none after the withdrawal");
        for r in &results {
            assert!(matches!(r, Ok(()) | Err(InvitationRefusal::Withdrawn)), "{r:?}");
        }
        assert_eq!(
            DeviceStore::open(&root).record_invitation_use("race", &Reuse::Reusable, 10_000, 500),
            Err(InvitationRefusal::Withdrawn)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_empty_directory_path_is_a_noop() {
        create_private_dir_all(Path::new("")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nested_roots_are_private_and_existing_ancestors_are_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let root = unique("perms");
        let deep = root.join("a").join("b").join("c");
        create_private_dir_all(&deep).unwrap();
        for path in [root.join("a"), root.join("a").join("b"), deep] {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700,
                "{} must be owner-only",
                path.display()
            );
        }
        let existing = root.join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        let child = existing.join("child");
        create_private_dir_all(&child).unwrap();
        assert_eq!(
            std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing ancestor's mode is the user's choice"
        );
        assert_eq!(
            std::fs::metadata(&child).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    const CHILD_ROOT_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_ROOT";
    const CHILD_GATE_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_GATE";
    const CHILD_READY_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_READY";
    const CHILD_RESULT_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_RESULT";
    const CHILD_KEY_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_KEY";

    fn durable_uses(root: &Path, key: &str) -> Option<u64> {
        let raw = std::fs::read_to_string(root.join(USED_INVITATIONS_FILE)).ok()?;
        let entries: Vec<Value> = serde_json::from_str(&raw).ok()?;
        entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some(key))
            .and_then(|entry| entry["uses"].as_u64())
    }

    fn durable_entry_count(root: &Path) -> usize {
        std::fs::read_to_string(root.join(USED_INVITATIONS_FILE))
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .map_or(0, |entries| entries.len())
    }

    #[test]
    fn concurrent_stores_admit_a_once_invitation_exactly_once() {
        let root = unique("invitation-once-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for _ in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("shared-key", &Reuse::Once, 10_000, 100)
            }));
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for thread in threads {
            match thread.join().unwrap() {
                Ok(()) => admitted += 1,
                Err(InvitationRefusal::AlreadyUsed) => refused += 1,
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
        assert_eq!(admitted, 1, "exactly one concurrent writer may admit");
        assert_eq!(refused, writers - 1);
        assert_eq!(durable_uses(&root, "shared-key"), Some(1));
        // A fresh instance proves the refusal is the durable count, not memory.
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use("shared-key", &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(durable_uses(&root, "shared-key"), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_stores_never_exceed_a_bounded_budget() {
        let root = unique("invitation-bounded-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 16;
        let budget = 4;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for _ in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("bounded-key", &Reuse::N(4), 10_000, 100)
            }));
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for thread in threads {
            match thread.join().unwrap() {
                Ok(()) => admitted += 1,
                Err(InvitationRefusal::UseLimitReached) => refused += 1,
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
        assert_eq!(admitted, budget, "the durable budget must not be exceeded");
        assert_eq!(refused, writers - budget);
        assert_eq!(durable_uses(&root, "bounded-key"), Some(budget as u64));
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use("bounded-key", &Reuse::N(4), 10_000, 101),
            Err(InvitationRefusal::UseLimitReached)
        );
        assert_eq!(durable_uses(&root, "bounded-key"), Some(budget as u64));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_distinct_keys_do_not_lose_updates() {
        let root = unique("invitation-distinct-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 12;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for i in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let key = format!("key-{i}");
                barrier.wait();
                let outcome = store.record_invitation_use(&key, &Reuse::Once, 10_000, 100);
                (key, outcome)
            }));
        }
        let mut keys = Vec::new();
        for thread in threads {
            let (key, outcome) = thread.join().unwrap();
            assert_eq!(outcome, Ok(()), "distinct key {key} must be admitted");
            keys.push(key);
        }
        assert_eq!(
            durable_entry_count(&root),
            writers,
            "no distinct-key update may be lost"
        );
        for key in keys {
            assert_eq!(durable_uses(&root, &key), Some(1));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn independent_roots_do_not_share_the_use_lock() {
        let first = unique("invitation-root-first");
        let second = unique("invitation-root-second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for root in [first.clone(), second.clone()] {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("same-key", &Reuse::Once, 10_000, 100)
            }));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap(), Ok(()));
        }
        assert_eq!(durable_uses(&first, "same-key"), Some(1));
        assert_eq!(durable_uses(&second, "same-key"), Some(1));
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    fn wait_for_file(path: &Path, deadline: std::time::Instant) -> bool {
        while !path.exists() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    fn wait_for_child(
        child: &mut std::process::Child,
        deadline: std::time::Instant,
    ) -> Option<std::process::ExitStatus> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return child.wait().ok();
                    }
                    std::thread::yield_now();
                }
                Err(_) => {
                    let _ = child.kill();
                    return child.wait().ok();
                }
            }
        }
    }

    #[test]
    fn used_invitation_lock_child() {
        let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
            // Ordinary test runs only collect this helper; the parent test
            // below spawns this same binary with the environment set.
            return;
        };
        let gate = PathBuf::from(std::env::var_os(CHILD_GATE_ENV).expect("child gate env"));
        let ready = PathBuf::from(std::env::var_os(CHILD_READY_ENV).expect("child ready env"));
        let result = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).expect("child result env"));
        let key = std::env::var(CHILD_KEY_ENV).expect("child key env");
        // Announce that this independent process is alive and waiting BEFORE
        // the parent releases the gate, so the callers race and do not merely
        // run one after another.
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !gate.exists() {
            if std::time::Instant::now() > deadline {
                panic!("parent did not release the process gate");
            }
            std::thread::yield_now();
        }
        let outcome = DeviceStore::open(PathBuf::from(root)).record_invitation_use(
            &key,
            &Reuse::Once,
            10_000,
            100,
        );
        let text = match outcome {
            Ok(()) => "ok".to_string(),
            Err(InvitationRefusal::AlreadyUsed) => "err:AlreadyUsed".to_string(),
            Err(other) => format!("err:unexpected:{other:?}"),
        };
        std::fs::write(result, text).unwrap();
    }

    #[test]
    fn the_use_lock_is_shared_by_independent_processes() {
        let root = unique("invitation-process-lock");
        std::fs::create_dir_all(&root).unwrap();
        let gate = root.join("start.gate");
        let exe = std::env::current_exe().unwrap();
        let key = "process-shared-key";
        let writers = 8usize;
        let mut children: Vec<(usize, std::process::Child, PathBuf, PathBuf)> = Vec::new();
        for i in 0..writers {
            let ready = root.join(format!("child-{i}.ready"));
            let result = root.join(format!("child-{i}.result"));
            let mut command = std::process::Command::new(&exe);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                command.creation_flags(CREATE_NO_WINDOW);
            }
            command
                .arg("--nocapture")
                .arg("--test-threads=1")
                .arg("used_invitation_lock_child")
                .env(CHILD_ROOT_ENV, &root)
                .env(CHILD_GATE_ENV, &gate)
                .env(CHILD_READY_ENV, &ready)
                .env(CHILD_RESULT_ENV, &result)
                .env(CHILD_KEY_ENV, key);
            match command.spawn() {
                Ok(child) => children.push((i, child, ready, result)),
                Err(e) => {
                    // Never leave already-spawned helpers spinning.
                    let _ = std::fs::write(&gate, b"go");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    for (_, mut child, _, _) in children {
                        let _ = wait_for_child(&mut child, deadline);
                    }
                    panic!("spawn lock helper {i}: {e}");
                }
            }
        }
        let pids: HashSet<u32> = children.iter().map(|(_, child, _, _)| child.id()).collect();
        assert_eq!(
            pids.len(),
            writers,
            "the helpers must be independent processes"
        );

        // Wait until every independent process has announced readiness, then
        // release them together. The deadline keeps a broken helper from
        // hanging the suite forever.
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut not_ready = Vec::new();
        for (i, _, ready, _) in &children {
            if !wait_for_file(ready, ready_deadline) {
                not_ready.push(*i);
            }
        }
        // Always release the gate: even a child that never announced still
        // has its own deadline, and the parent must reap every one.
        let gate_released = std::fs::write(&gate, b"go").is_ok();

        let run_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut admitted = 0usize;
        let mut already_used = 0usize;
        let mut failures = Vec::new();
        if !gate_released {
            failures.push("could not release the process gate".to_string());
        }
        for (i, mut child, _, result_path) in children {
            let status = wait_for_child(&mut child, run_deadline);
            let result = std::fs::read_to_string(&result_path).unwrap_or_default();
            let clean = status.as_ref().is_some_and(|status| status.success());
            if !clean {
                failures.push(format!(
                    "child {i} did not exit cleanly (status {status:?}, result {result:?})"
                ));
            }
            match result.as_str() {
                "ok" => admitted += 1,
                "err:AlreadyUsed" => already_used += 1,
                other => failures.push(format!("child {i} returned {other:?}")),
            }
        }
        if !not_ready.is_empty() || !failures.is_empty() {
            let _ = std::fs::remove_dir_all(&root);
            panic!("not ready: {not_ready:?}; failures: {failures:?}");
        }
        assert_eq!(
            admitted, 1,
            "exactly one process may admit a once-only invitation"
        );
        assert_eq!(
            already_used,
            writers - 1,
            "every loser must report the exact AlreadyUsed refusal"
        );
        assert_eq!(durable_uses(&root, key), Some(1));
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use(key, &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(durable_uses(&root, key), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_use_lock_that_cannot_be_taken_refuses_and_never_writes() {
        let root = unique("invitation-lock-fail");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        assert_eq!(
            invitation_use_lock_path(&data),
            root.join(USED_INVITATIONS_LOCK_FILE),
            "the sidecar name must match the published lock path"
        );
        let original = br#"[{"keyId":"key","uses":0,"expires":10000,"lastUsed":1}]"#;
        std::fs::write(&data, original).unwrap();
        // A directory at the sidecar path makes the exclusive open fail.
        std::fs::create_dir(root.join(USED_INVITATIONS_LOCK_FILE)).unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("key", &Reuse::Once, 10_000, 100),
            Err(InvitationRefusal::Unverifiable),
            "a lock that cannot be taken must fail closed"
        );
        assert_eq!(std::fs::read(&data).unwrap(), original);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn semantically_corrupt_use_entries_fail_closed_and_are_not_overwritten() {
        let root = unique("invitation-semantic-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        let corrupt = [
            // No key id.
            r#"[{}]"#,
            // Missing or wrongly-typed uses (the old code read these as 0).
            r#"[{"keyId":"k","expires":10000}]"#,
            r#"[{"keyId":"k","uses":"1","expires":10000}]"#,
            r#"[{"keyId":"k","uses":-1,"expires":10000}]"#,
            r#"[{"keyId":"k","uses":1.5,"expires":10000}]"#,
            // Wrongly-typed key id / expiry.
            r#"[{"keyId":7,"uses":1,"expires":10000}]"#,
            r#"[{"keyId":"k","uses":1}]"#,
            r#"[{"keyId":"k","uses":1,"expires":"later"}]"#,
            // Not an object.
            r#"[1]"#,
            // Two counts for one invitation are ambiguous.
            r#"[{"keyId":"k","uses":0,"expires":10000},{"keyId":"k","uses":0,"expires":10000}]"#,
        ];
        let store = DeviceStore::open(&root);
        for body in corrupt {
            std::fs::write(&data, body).unwrap();
            assert_eq!(
                store.record_invitation_use("k", &Reuse::Once, 20_000, 100),
                Err(InvitationRefusal::Unverifiable),
                "semantically corrupt body {body}"
            );
            assert_eq!(
                std::fs::read_to_string(&data).unwrap(),
                body,
                "semantically corrupt body {body} must not be rewritten"
            );
        }
        // A valid u64 that would overflow the increment is also refused.
        let overflow = r#"[{"keyId":"k","uses":18446744073709551615,"expires":10000}]"#;
        std::fs::write(&data, overflow).unwrap();
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 20_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        assert_eq!(std::fs::read_to_string(&data).unwrap(), overflow);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_normal_legacy_use_file_is_read_and_kept_in_the_same_format() {
        let root = unique("invitation-legacy");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        let legacy = r#"[
            {"keyId":"old","uses":2,"expires":10000,"lastUsed":5,"extra":"keep"},
            {"uses":0,"expires":20000,"keyId":"other"}
        ]"#;
        std::fs::write(&data, legacy).unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("other", &Reuse::N(2), 20_000, 100),
            Ok(())
        );
        let raw = std::fs::read_to_string(&data).unwrap();
        let entries: Vec<Value> = serde_json::from_str(&raw).unwrap();
        let old = entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some("old"))
            .expect("the untouched entry stays");
        assert_eq!(old["uses"].as_u64(), Some(2));
        assert_eq!(old["expires"].as_u64(), Some(10_000));
        assert_eq!(old["extra"].as_str(), Some("keep"));
        let other = entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some("other"))
            .expect("the used entry stays");
        assert_eq!(other["uses"].as_u64(), Some(1));
        assert_eq!(other["expires"].as_u64(), Some(20_000));
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod sibling_roster_revocation {
    //! Fleet auto-mesh revocation on a JOINED device: the owner's signed roster
    //! is the only voice that can withdraw a sibling, and it can only narrow.
    use super::super::*;
    use filament_id::{DeviceCert, UserKey};
    use serde_json::json;

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-sib-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Joined {
        root: PathBuf,
        store: DeviceStore,
        owner: UserKey,
        sib: [u8; 32],
    }

    /// A joined device: its own certificate from `owner`, and one sibling
    /// indexed the way a verified fleet-hello writes it (no pair secret).
    fn joined(tag: &str) -> Joined {
        let root = unique(tag);
        let store = DeviceStore::open(&root);
        let owner = UserKey::from_seed(&[21u8; 32]).unwrap();
        let now = now_secs();
        let me = DeviceCert::certify(&owner, [1u8; 32], now, 3600).unwrap();
        store
            .write_local_device_cert_record(&json!({"name": "me", "cert": me.to_json()}))
            .unwrap();
        let sib = [2u8; 32];
        let sib_cert = DeviceCert::certify(&owner, sib, now, 3600).unwrap();
        std::fs::write(
            store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "sib", "deviceCert": sib_cert.to_json(), "caps": []},
            ]))
            .unwrap(),
        )
        .unwrap();
        Joined { root, store, owner, sib }
    }

    fn write_roster(j: &Joined, owner_pub: [u8; 32], listed: &[[u8; 32]]) {
        let devices: Vec<Value> = listed
            .iter()
            .map(|d| json!({"device_pub": hex::encode(d), "petname": "x"}))
            .collect();
        std::fs::write(
            j.root.join("roster.json"),
            serde_json::to_string(&json!({
                "owner_pub": hex::encode(owner_pub),
                "epoch": 3, "valid_until": 1, "received_at": 0,
                "devices": devices,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn listed_sibling_is_admissible_and_not_revoked() {
        let j = joined("listed");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        assert!(j.store.sibling_admissible(&j.sib));
        assert!(!j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_sibling_the_owner_delisted_is_refused_and_reads_revoked() {
        let j = joined("delisted");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(!j.store.sibling_admissible(&j.sib));
        assert!(j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn no_roster_means_no_sibling_admission() {
        // Fail closed: with no roster there is no way a revocation could
        // reach this device, so a sibling is not admitted.
        let j = joined("none");
        assert!(!j.store.sibling_admissible(&j.sib));
        assert!(j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_roster_from_another_owner_lists_no_one() {
        let j = joined("foreign");
        let other = UserKey::from_seed(&[22u8; 32]).unwrap();
        write_roster(&j, other.public_key_bytes(), &[j.sib]);
        assert!(!j.store.sibling_admissible(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn paired_and_cross_owner_records_are_never_governed_by_the_roster() {
        let j = joined("exempt");
        write_roster(&j, j.owner.public_key_bytes(), &[]);
        let now = now_secs();
        // A device we PAIRED with (it has a pair secret): our own decision.
        let paired_pub = [3u8; 32];
        let paired = DeviceCert::certify(&j.owner, paired_pub, now, 3600).unwrap();
        // A device certified by a DIFFERENT owner, no secret.
        let other = UserKey::from_seed(&[23u8; 32]).unwrap();
        let foreign_pub = [4u8; 32];
        let foreign = DeviceCert::certify(&other, foreign_pub, now, 3600).unwrap();
        std::fs::write(
            j.store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "paired", "secret": "ab".repeat(32), "deviceCert": paired.to_json()},
                {"name": "foreign", "deviceCert": foreign.to_json()},
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(!j.store.device_cert_revoked(&paired_pub));
        assert!(!j.store.device_cert_revoked(&foreign_pub));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn the_owner_device_is_never_governed_by_a_roster() {
        let j = joined("owner");
        UserKey::generate(&j.store.keystore()).unwrap();
        // Even with no roster at all, the owner admits by its own records.
        assert!(j.store.sibling_admissible(&j.sib));
        assert!(!j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    fn names(store: &DeviceStore) -> Vec<String> {
        store
            .devices_records()
            .iter()
            .filter_map(|r| r["name"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn a_sibling_the_owner_delisted_is_removed_from_the_list() {
        let j = joined("prune-delisted");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert_eq!(j.store.devices_sweep_lapsed(now_secs()), 1);
        assert!(names(&j.store).is_empty(), "a delisted sibling must not stay listed");
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn removing_a_delisted_sibling_record_keeps_its_revocation() {
        let j = joined("prune-tombstone");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(j.store.device_cert_revoked(&j.sib), "delisted while the record is present");
        assert_eq!(j.store.devices_sweep_lapsed(now_secs()), 1);
        assert!(names(&j.store).is_empty(), "the record itself is still removed");
        // The decision point: no record, and the key is STILL refused.
        assert!(
            j.store.device_cert_revoked(&j.sib),
            "removing a delisted sibling's record erased its revocation"
        );
        // A second sweep keeps the entry (idempotent), and an unrelated
        // unknown key is not refused by it.
        assert_eq!(j.store.devices_sweep_lapsed(now_secs()), 0);
        assert!(j.store.device_cert_revoked(&j.sib));
        assert!(!j.store.device_cert_revoked(&[9u8; 32]));
        // Positive control: the owner lists it again, and the entry lifts.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        assert!(!j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    fn write_delisted(j: &Joined, entries: &Value) {
        std::fs::write(
            j.root.join(DELISTED_SIBLINGS_FILE),
            serde_json::to_string(entries).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn tombstone_is_visible_for_known_paired_key_without_changing_global_pair_policy() {
        let j = joined("tomb-known-pair");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        let mut records = j.store.devices_records();
        records[0]["secret"] = json!("held-pair-secret");
        std::fs::write(j.store.devices_path(), serde_json::to_string(&records).unwrap()).unwrap();
        write_delisted(&j, &json!([{
            "devicePub": hex::encode(j.sib),
            "ownerPub": hex::encode(j.owner.public_key_bytes()),
            "certExpires": now_secs() + 3600,
        }]));
        assert!(j.store.delisted_sibling_tombstoned(&j.sib));
        assert!(!j.store.device_cert_revoked(&j.sib), "global pair policy changed");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        assert!(!j.store.delisted_sibling_tombstoned(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn an_unparseable_delisted_store_refuses_unknown_keys_only_and_says_so() {
        let j = joined("tomb-corrupt");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        std::fs::write(j.root.join(DELISTED_SIBLINGS_FILE), "{garbage").unwrap();
        // Unknown key: fail closed. Known (recorded, listed) key: its record
        // decides, the damaged file does not.
        assert!(j.store.device_cert_revoked(&[9u8; 32]));
        assert!(!j.store.device_cert_revoked(&j.sib));
        let why = j.store.delisted_siblings_problem().expect("a damaged store is reported");
        assert!(why.contains(DELISTED_SIBLINGS_FILE), "{why}");
        // And it is never written over: a sweep that would add an entry
        // fails, keeping the record, and leaves the damage for a person.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert_eq!(j.store.devices_sweep_lapsed(now_secs()), 0);
        assert_eq!(names(&j.store), vec!["sib"], "the record stays when its revocation cannot be kept");
        assert_eq!(
            std::fs::read_to_string(j.root.join(DELISTED_SIBLINGS_FILE)).unwrap(),
            "{garbage"
        );
        // The failed write is reported too, for this store's path.
        let why = j.store.delisted_siblings_problem().unwrap();
        assert!(why.contains("could not be kept"), "{why}");
        assert!(why.contains("cannot be parsed"), "{why}");
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn delisted_recovery_names_the_backup_when_there_is_one() {
        let j = joined("tomb-recovery");
        let p = j.root.join(DELISTED_SIBLINGS_FILE);
        let none = delisted_recovery(&p);
        assert!(none.contains("move it aside"), "{none}");
        assert!(!none.contains("cp "), "{none}");
        std::fs::write(backup_path(&p), "[]").unwrap();
        let with = delisted_recovery(&p);
        assert!(with.contains("cp ") && with.contains(".bak"), "{with}");
        assert!(with.contains(&p.display().to_string()), "{with}");
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn only_a_settled_file_may_be_served_from_the_cache() {
        let now = SystemTime::now();
        assert!(!delisted_cache_trusted(None, now));
        assert!(!delisted_cache_trusted(Some(now), now), "written in the same tick as the read");
        assert!(delisted_cache_trusted(
            Some(now - std::time::Duration::from_secs(60)),
            now
        ));
    }

    fn set_mtime(path: &Path, t: SystemTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn a_rewritten_delisted_store_is_read_again_even_at_the_same_length() {
        let j = joined("tomb-rewrite");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        let (a, b) = ([8u8; 32], [9u8; 32]);
        let expires = now_secs() + 3600;
        let owner_hex = hex::encode(j.owner.public_key_bytes());
        let entry = |k: [u8; 32]| {
            json!([{"devicePub": hex::encode(k), "ownerPub": owner_hex, "certExpires": expires}])
        };
        let path = j.root.join(DELISTED_SIBLINGS_FILE);
        write_delisted(&j, &entry(a));
        let m0 = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert!(j.store.device_cert_revoked(&a) && !j.store.device_cert_revoked(&b));
        // Rewritten at the same length, and the mtime PINNED back to the first
        // write's: (mtime, length) cannot tell the two apart, so this passes
        // only because a recently written file is never served from the cache.
        write_delisted(&j, &entry(b));
        set_mtime(&path, m0);
        assert_eq!(std::fs::metadata(&path).unwrap().len() as usize, entry(a).to_string().len());
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), m0);
        assert!(!j.store.device_cert_revoked(&a) && j.store.device_cert_revoked(&b));
        // A settled file is cached; an external in-place rewrite lands on a
        // later mtime, so it is read again rather than served stale.
        set_mtime(&path, SystemTime::now() - std::time::Duration::from_secs(60));
        assert!(j.store.device_cert_revoked(&b));
        write_delisted(&j, &entry(a));
        assert!(j.store.device_cert_revoked(&a), "a stale cache kept the old entry");
        assert!(!j.store.device_cert_revoked(&b));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    /// The cache-hit path, observed: a SETTLED file whose (mtime, length) are
    /// unchanged is served from the cache without a read. This also pins the
    /// documented limit: content rewritten under a preserved old mtime and the
    /// same length is not seen until the file changes again.
    #[test]
    fn a_settled_unchanged_delisted_store_is_served_from_the_cache() {
        let j = joined("tomb-cache-hit");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        let (a, b) = ([8u8; 32], [9u8; 32]);
        let expires = now_secs() + 3600;
        let owner_hex = hex::encode(j.owner.public_key_bytes());
        let entry = |k: [u8; 32]| {
            json!([{"devicePub": hex::encode(k), "ownerPub": owner_hex, "certExpires": expires}])
        };
        let path = j.root.join(DELISTED_SIBLINGS_FILE);
        let old = SystemTime::now() - std::time::Duration::from_secs(60);
        write_delisted(&j, &entry(a));
        set_mtime(&path, old);
        // First read fills a trusted entry (settled for 60s).
        assert!(j.store.device_cert_revoked(&a));
        // Same length, same (preserved) mtime: served from the cache.
        write_delisted(&j, &entry(b));
        set_mtime(&path, old);
        assert!(j.store.device_cert_revoked(&a), "the hit path re-read the file");
        assert!(!j.store.device_cert_revoked(&b));
        // Any mtime change ends the hit.
        set_mtime(&path, old + std::time::Duration::from_secs(1));
        assert!(j.store.device_cert_revoked(&b));
        assert!(!j.store.device_cert_revoked(&a));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_roster_listed_sibling_is_recognized_without_its_index_record() {
        let j = joined("recognized");
        let k = [9u8; 32];
        // Neither recorded nor listed: not recognized (fails closed).
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(!j.store.sibling_recognized(&k));
        // Listed by the owner's roster, no index record (a failed index
        // write): recognized, so a proof keeps its sibling kind.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], k]);
        assert!(j.store.sibling_recognized(&k));
        // Recorded (the fixture's sibling), whatever the roster says.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(j.store.sibling_recognized(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn on_the_owner_device_only_a_record_makes_a_sibling_recognized() {
        let j = joined("recognized-owner");
        let k = [9u8; 32];
        // Even a roster listing the key does not stand in for a record here.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], k]);
        // Control: as a joined device the listing recognizes it.
        assert!(j.store.sibling_recognized(&k));
        UserKey::generate(&j.store.keystore()).unwrap();
        // The owner admits every key (`sibling_admissible`), and that must not
        // make an unrecorded key a recognized sibling.
        assert!(j.store.sibling_admissible(&k));
        assert!(!j.store.sibling_recognized(&k), "no record on the owner means not recognized");
        assert!(j.store.sibling_recognized(&j.sib), "a recorded key still is");
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn the_owner_device_ignores_delisted_entries() {
        let j = joined("tomb-owner");
        let k = [9u8; 32];
        write_delisted(
            &j,
            &json!([{"devicePub": hex::encode(k), "ownerPub": hex::encode(j.owner.public_key_bytes()), "certExpires": now_secs() + 3600}]),
        );
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        // Control: on the joined device the entry refuses the key.
        assert!(j.store.device_cert_revoked(&k));
        UserKey::generate(&j.store.keystore()).unwrap();
        assert!(!j.store.device_cert_revoked(&k), "the owner's own records decide");
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn an_expired_delisted_entry_refuses_nothing() {
        let j = joined("tomb-expired");
        let k = [9u8; 32];
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        write_delisted(
            &j,
            &json!([{"devicePub": hex::encode(k), "ownerPub": hex::encode(j.owner.public_key_bytes()), "certExpires": now_secs() - 1}]),
        );
        // The roster still omits the key, and the certificate behind the entry
        // has run out: not revoked (the expired certificate is refused anyway).
        assert!(!j.store.device_cert_revoked(&k));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_delisted_entry_from_an_earlier_owner_lifts_when_the_current_owner_lists_the_key() {
        let j = joined("tomb-owner-change");
        let k = [9u8; 32];
        let earlier = UserKey::from_seed(&[44u8; 32]).unwrap();
        write_delisted(
            &j,
            &json!([{"devicePub": hex::encode(k), "ownerPub": hex::encode(earlier.public_key_bytes()), "certExpires": now_secs() + 3600}]),
        );
        // Control: the current owner's roster omits it, so it is refused.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(j.store.device_cert_revoked(&k));
        // The current owner lists it: lifted, whatever the entry's owner was.
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], k]);
        assert!(!j.store.device_cert_revoked(&k));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_listed_sibling_stays_and_one_whose_cert_expired_goes() {
        let j = joined("prune-expired");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        let now = now_secs();
        // The positive control: listed and certified, so it stays.
        assert_eq!(j.store.devices_sweep_lapsed(now), 0);
        assert_eq!(names(&j.store), vec!["sib"]);
        // Its certificate (3600 s) has run out: listed or not, it is gone.
        assert_eq!(j.store.devices_sweep_lapsed(now + 3601), 1);
        assert!(names(&j.store).is_empty());
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn without_a_roster_nothing_is_pruned_for_delisting() {
        // No roster means "not heard yet", not "delisted": keep the record.
        let j = joined("prune-noroster");
        assert_eq!(j.store.devices_sweep_lapsed(now_secs()), 0);
        assert_eq!(names(&j.store), vec!["sib"]);
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn paired_revoked_and_owner_side_records_are_never_pruned_as_siblings() {
        let j = joined("prune-exempt");
        write_roster(&j, j.owner.public_key_bytes(), &[]);
        let now = now_secs();
        let paired = DeviceCert::certify(&j.owner, [3u8; 32], now, 3600).unwrap();
        let revoked = DeviceCert::certify(&j.owner, [5u8; 32], now, 3600).unwrap();
        std::fs::write(
            j.store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "paired", "secret": "ab".repeat(32), "deviceCert": paired.to_json()},
                {"name": "revoked", "deviceCert": revoked.to_json(), "certRevoked": true},
            ]))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(j.store.devices_sweep_lapsed(now), 0);
        assert_eq!(names(&j.store), vec!["paired", "revoked"]);
        // On the OWNER device its own records decide; nothing is a sibling.
        UserKey::generate(&j.store.keystore()).unwrap();
        let sib = DeviceCert::certify(&j.owner, j.sib, now, 3600).unwrap();
        std::fs::write(
            j.store.devices_path(),
            serde_json::to_string(&json!([{"name": "sib", "deviceCert": sib.to_json()}])).unwrap(),
        )
        .unwrap();
        assert_eq!(j.store.devices_sweep_lapsed(now), 0);
        assert_eq!(names(&j.store), vec!["sib"]);
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn the_roster_file_name_matches_the_roster_module() {
        #[cfg(feature = "dispatch")]
        assert_eq!(crate::recv::roster::ROSTER_FILE, "roster.json");
    }
}

#[cfg(test)]
mod fleet_grant_set_security {
    //! Owner-signed fleet grant sets, end to end through the store: an owner
    //! mints, a joined device judges and holds, the gate asks. Each test is one
    //! attack or failure the design must survive.
    use super::super::*;
    use filament_cap::fleet_grants::{GrantSetJudgement, GrantSetRefusal};
    use filament_id::{DeviceCert, FleetGrant, FleetGrantSet, UserKey};
    use serde_json::json;

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-fg-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ME: [u8; 32] = [0x21; 32];
    const BRAVO: [u8; 32] = [0x22; 32];

    /// A joined device certified by `owner`, plus the owner's own store with
    /// both devices on record.
    fn fleet(tag: &str) -> (UserKey, DeviceStore, DeviceStore, PathBuf, PathBuf) {
        let owner = UserKey::from_seed(&[0x41; 32]).unwrap();
        let now = now_secs();
        let oroot = unique(&format!("{tag}-owner"));
        let ostore = DeviceStore::open(&oroot);
        let me_cert = DeviceCert::certify(&owner, ME, now, 3600).unwrap();
        let b_cert = DeviceCert::certify(&owner, BRAVO, now, 3600).unwrap();
        std::fs::write(
            ostore.devices_path(),
            serde_json::to_string(&json!([
                {"name": "charlie", "secret": "aa".repeat(32), "deviceCert": me_cert.to_json()},
                {"name": "bravo", "secret": "bb".repeat(32), "deviceCert": b_cert.to_json()},
            ]))
            .unwrap(),
        )
        .unwrap();
        let jroot = unique(&format!("{tag}-joined"));
        let jstore = DeviceStore::open(&jroot);
        jstore
            .write_local_device_cert_record(&json!({"name": "charlie", "cert": me_cert.to_json()}))
            .unwrap();
        (owner, ostore, jstore, oroot, jroot)
    }

    fn cleanup(a: PathBuf, b: PathBuf) {
        let _ = std::fs::remove_dir_all(a);
        let _ = std::fs::remove_dir_all(b);
    }

    #[test]
    fn an_owner_grant_reaches_its_target_and_grants_only_what_it_says() {
        let (owner, ostore, jstore, a, b) = fleet("happy");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        let j = jstore
            .verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now)
            .unwrap();
        assert_eq!(j, GrantSetJudgement::Accept);
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", now));
        assert!(!jstore.fleet_grant_held(&BRAVO, "mount", now), "no cap it does not list");
        assert!(!jstore.fleet_grant_held(&[0x99; 32], "shell", now), "no third party");
        assert!(!jstore.load_cap_store().iter().any(|_| true), "never written into the cap store");
        cleanup(a, b);
    }

    #[test]
    fn a_compromised_sibling_cannot_author_a_set() {
        let (owner, _ostore, jstore, a, b) = fleet("forge");
        let now = now_secs();
        let sibling = UserKey::from_seed(&[0x42; 32]).unwrap();
        let set = FleetGrantSet {
            owner_pub: owner.public_key_bytes(), // claims to be the owner's
            target_pub: ME,
            epoch: 1,
            valid_until: now + 600,
            grants: vec![FleetGrant { subject_pub: BRAVO, cap: "shell".into(), expires: 0 }],
        };
        let mut blob = set.to_json();
        blob["sig"] = json!(hex::encode(set.sign(sibling.keypair()).unwrap()));
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::BadSignature)
        );
        // Honestly signed with its own key instead: another owner, refused.
        let mut honest = set.clone();
        honest.owner_pub = sibling.public_key_bytes();
        let mut blob = honest.to_json();
        blob["sig"] = json!(hex::encode(honest.sign(sibling.keypair()).unwrap()));
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherOwner)
        );
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn a_set_relayed_from_another_device_or_another_fleet_is_refused() {
        let (owner, ostore, jstore, a, b) = fleet("relay");
        let now = now_secs();
        // A genuine owner set about BRAVO, relayed to charlie by bravo.
        ostore.fleet_grant_add(&BRAVO, &ME, "shell", 0).unwrap();
        let for_bravo = ostore.mint_fleet_grant_set(&owner, &BRAVO, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&for_bravo, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherTarget)
        );
        // A genuine set from ANOTHER owner, about a device with our key bytes.
        let other = UserKey::from_seed(&[0x43; 32]).unwrap();
        let (_o2, o2store, _j2, a2, b2) = fleet("relay-other");
        o2store.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let foreign = o2store.mint_fleet_grant_set(&other, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&foreign, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherOwner)
        );
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
        cleanup(a2, b2);
    }

    #[test]
    fn replay_is_a_no_op_and_an_older_set_cannot_win_back_a_revoked_grant() {
        let (owner, ostore, jstore, a, b) = fleet("replay");
        let now = now_secs();
        let op = owner.public_key_bytes();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let granted = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Stale);
        // The owner withdraws it: a newer epoch without the grant.
        assert!(ostore.fleet_grant_remove(&ME, &BRAVO, "shell").unwrap());
        let withdrawn = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert!(withdrawn["epoch"].as_u64() > granted["epoch"].as_u64());
        assert_eq!(jstore.verify_and_store_fleet_grants(&withdrawn, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        // A sibling replays the OLD set that still granted it: refused as stale.
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Stale);
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn an_expired_set_is_never_applied_and_a_held_one_lapses() {
        let (owner, ostore, jstore, a, b) = fleet("expiry");
        let now = now_secs();
        let op = owner.public_key_bytes();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 60).unwrap();
        let until = blob["valid_until"].as_u64().unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &op, &ME, until).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::Expired)
        );
        assert_eq!(jstore.verify_and_store_fleet_grants(&blob, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", until - 1));
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", until), "owner offline past validity: lapsed");
        cleanup(a, b);
    }

    #[test]
    fn a_revoked_subject_is_left_out_of_the_next_set() {
        let (owner, ostore, jstore, a, b) = fleet("revoked");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore
            .with_devices_mut(|arr| {
                for d in arr.iter_mut() {
                    if d["name"] == "bravo" {
                        d["certRevoked"] = json!(true);
                    }
                }
                Ok(())
            })
            .unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert!(blob["grants"].as_array().unwrap().is_empty());
        jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap();
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn a_tampered_held_file_grants_nothing() {
        let (owner, ostore, jstore, a, b) = fleet("tamper");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "transfer", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap();
        let p = jstore.root().join(FLEET_GRANTS_HELD_FILE);
        let raw = std::fs::read_to_string(&p).unwrap().replace("\"transfer\"", "\"shell\"");
        std::fs::write(&p, raw).unwrap();
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        assert!(!jstore.fleet_grant_held(&BRAVO, "transfer", now));
        cleanup(a, b);
    }

    fn set_policy(store: &DeviceStore, v: &str) {
        std::fs::write(store.root().join("config"), format!("name charlie\n{OWNER_GRANT_POLICY_STORE_KEY} {v}\n")).unwrap();
    }

    #[test]
    fn under_the_default_files_policy_an_owner_shell_grant_is_held_but_not_applied() {
        use filament_cap::fleet_grants::OwnerGrantPolicy;
        let (owner, ostore, jstore, a, b) = fleet("pol-files");
        let now = now_secs();
        assert_eq!(jstore.owner_grant_policy(), OwnerGrantPolicy::Files, "no config: the default");
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", now), "the signed set is kept whole");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "files: shell never applies");
        assert!(jstore.fleet_grant_applies(&BRAVO, "mount", now), "files: mount applies");
        assert_eq!(
            jstore.fleet_grant_caps_split(&BRAVO, now),
            (vec!["mount".to_string()], vec!["shell".to_string()])
        );
        cleanup(a, b);
    }

    #[test]
    fn an_incoming_set_cannot_set_or_widen_the_local_owner_grant_policy() {
        use filament_cap::fleet_grants::OwnerGrantPolicy;
        let (owner, ostore, jstore, a, b) = fleet("pol-net");
        let now = now_secs();
        set_policy(&jstore, "files");
        let cfg = jstore.root().join("config");
        let before = std::fs::read(&cfg).unwrap();
        // A genuine owner-signed set carrying shell, with every spelling of the
        // setting a hostile or confused owner could add riding along. The
        // signature covers the set's own fields only; nothing else is read.
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let mut blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        blob["fleet.owner_grants"] = json!("all");
        blob[OWNER_GRANT_POLICY_STORE_KEY] = json!("all");
        blob["settings"] = json!({"fleet.owner_grants": "all", "fleet_owner_grants": "all"});
        blob["policy"] = json!("all");
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert_eq!(std::fs::read(&cfg).unwrap(), before, "config untouched");
        assert_eq!(jstore.owner_grant_policy(), OwnerGrantPolicy::Files);
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "a set carrying shell is not applied under files");
        // The other network paths that write local state: the fleet-policy
        // relay (revocations only) and a roster. Neither touches the setting.
        assert_eq!(jstore.merge_owner_cap_ops(&[json!({"fleet.owner_grants": "all"})]), 0);
        assert_eq!(std::fs::read(&cfg).unwrap(), before);
        // And where the device never set it, receiving sets does not create it.
        let (owner2, ostore2, jstore2, a2, b2) = fleet("pol-net-none");
        ostore2.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let mut blob2 = ostore2.mint_fleet_grant_set(&owner2, &ME, now, 600).unwrap();
        blob2["fleet.owner_grants"] = json!("all");
        jstore2.verify_and_store_fleet_grants(&blob2, &owner2.public_key_bytes(), &ME, now).unwrap();
        assert!(!jstore2.root().join("config").exists());
        assert_eq!(jstore2.owner_grant_policy(), OwnerGrantPolicy::Files);
        assert!(!jstore2.fleet_grant_applies(&BRAVO, "shell", now));
        cleanup(a, b);
        cleanup(a2, b2);
    }

    #[test]
    fn under_off_every_owner_set_is_refused_and_nothing_is_kept() {
        let (owner, ostore, jstore, a, b) = fleet("pol-off");
        let now = now_secs();
        set_policy(&jstore, "off");
        ostore.fleet_grant_add(&ME, &BRAVO, "transfer", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OwnerGrantsOff)
        );
        assert!(!jstore.root().join(FLEET_GRANTS_HELD_FILE).exists());
        for c in ["transfer", "mount", "shell"] {
            assert!(!jstore.fleet_grant_applies(&BRAVO, c, now), "{c}");
        }
        cleanup(a, b);
    }

    #[test]
    fn narrowing_the_policy_applies_at_once_to_a_set_already_held() {
        let (owner, ostore, jstore, a, b) = fleet("pol-narrow");
        let now = now_secs();
        set_policy(&jstore, "all");
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert!(jstore.fleet_grant_applies(&BRAVO, "shell", now), "all: shell applies");
        // No new set arrives; only the local setting changes.
        set_policy(&jstore, "files");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "files: shell stops at once");
        assert!(jstore.fleet_grant_applies(&BRAVO, "mount", now));
        set_policy(&jstore, "off");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "mount", now), "off: the held set grants nothing");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now));
        // An unreadable value is the narrowest, not the widest.
        set_policy(&jstore, "everything");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "mount", now));
        cleanup(a, b);
    }

    #[test]
    fn the_network_relay_merges_revocations_only_never_grants() {
        // The old `fleet-policy` relay was the capability store's one network
        // write. A grant op signed by the owner must no longer enter it.
        let owner = UserKey::from_seed(&[0x44; 32]).unwrap();
        let root = unique("relay-merge");
        let store = DeviceStore::open(&root).with_owner_pub(Some(owner.public_key_bytes()));
        let mut op = filament_cap::capability::CapOp {
            op: filament_cap::capability::CapOpKind::Grant,
            grantor: owner.public_key_bytes(),
            target_kind: 0x01,
            target: BRAVO,
            resource: "self".into(),
            permissions: vec!["shell".into()],
            expires: now_secs() + 3600,
            issued_at: now_secs(),
            version: 1,
            sig: [0u8; 64],
        };
        op.sig = filament_cap::capability::sign_cap_op(&op, owner.keypair());
        assert_eq!(store.merge_owner_cap_ops(&[op.to_json()]), 0);
        assert!(store.load_cap_store().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod ephemeral_records {
    //! An ephemeral device (runner invitation) exists while it is present: the
    //! owner removes its record, rather than keeping it as evidence, once its
    //! lease or offline budget ends or it departs.
    use super::super::*;
    use filament_id::{DeviceCert, UserKey};
    use serde_json::json;

    fn owner_store(tag: &str) -> (PathBuf, DeviceStore, UserKey) {
        let root = std::env::temp_dir().join(format!(
            "fil-eph-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        let owner = UserKey::generate(&store.keystore()).unwrap();
        (root, store, owner)
    }

    /// Enrol `name` the way the enrolment handler records a runner: delegated,
    /// access ending at `lease_end`, offline budget `max_offline`, marked
    /// ephemeral. With `ephemeral` false it is the same record for a device.
    #[allow(clippy::too_many_arguments)]
    fn enrol(
        store: &DeviceStore,
        owner: &UserKey,
        name: &str,
        key: u8,
        now: u64,
        lease_end: u64,
        max_offline: u64,
        ephemeral: bool,
    ) -> [u8; 32] {
        let device_pub = [key; 32];
        let cert = DeviceCert::certify(owner, device_pub, now, lease_end - now).unwrap();
        let caps = vec!["transfer".to_string(), "shell".to_string()];
        store
            .devices_upsert_atomic(
                name,
                Some(&"cd".repeat(32)),
                Some(&cert),
                Some(&caps),
                Some(0x01),
                None,
                Some((&caps, lease_end, max_offline, max_offline)),
                false,
            )
            .unwrap();
        if ephemeral {
            store.devices_mark_ephemeral(name, now).unwrap();
        }
        device_pub
    }

    fn names(store: &DeviceStore) -> Vec<String> {
        store
            .devices_records()
            .iter()
            .filter_map(|r| r["name"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn an_ephemeral_device_is_removed_when_its_lease_ends_and_kept_before() {
        let (root, store, owner) = owner_store("lease");
        let now = now_secs();
        enrol(&store, &owner, "worker", 7, now, now + 600, 900, true);
        // The same shape for a persistent device: lapses, but is KEPT.
        enrol(&store, &owner, "laptop", 8, now, now + 600, 900, false);
        assert_eq!(store.devices_sweep_lapsed(now + 599), 0);
        assert_eq!(names(&store), vec!["worker", "laptop"]);
        store.devices_sweep_lapsed(now + 601);
        assert_eq!(names(&store), vec!["laptop"], "the lease is over: the worker is gone");
        let laptop = store.devices_records().into_iter().next().unwrap();
        assert_eq!(laptop["principalState"].as_str(), Some(PRINCIPAL_STATE_LAPSED));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_ephemeral_device_offline_past_its_budget_is_removed() {
        let (root, store, owner) = owner_store("budget");
        let now = now_secs();
        enrol(&store, &owner, "worker", 7, now, now + 6 * 3600, 900, true);
        // Seen 10 minutes ago: inside the 15 minute budget.
        store.devices_touch_at("worker", None, None, now).unwrap();
        assert_eq!(store.devices_sweep_lapsed(now + 600), 0);
        assert_eq!(names(&store), vec!["worker"]);
        // Unseen for 15 minutes: the cancelled job is forgotten.
        store.devices_sweep_lapsed(now + 901);
        assert!(names(&store).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_departing_ephemeral_device_is_removed_and_a_persistent_one_kept() {
        let (root, store, owner) = owner_store("depart");
        let now = now_secs();
        let worker = enrol(&store, &owner, "worker", 7, now, now + 600, 900, true);
        let laptop = enrol(&store, &owner, "laptop", 8, now, now + 600, 900, false);
        assert_eq!(store.mark_lapsed_now(&worker).as_deref(), Some("worker"));
        assert_eq!(store.mark_lapsed_now(&laptop).as_deref(), Some("laptop"));
        assert_eq!(names(&store), vec!["laptop"]);
        // Removal is "stop renewing": no record, no renewal.
        assert!(store.devices_find_by_device_pub(&worker).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_revoked_ephemeral_record_is_the_owners_decision_and_stays() {
        let (root, store, owner) = owner_store("revoked");
        let now = now_secs();
        enrol(&store, &owner, "worker", 7, now, now + 600, 900, true);
        store
            .with_devices_mut(|arr| {
                arr[0]["certRevoked"] = json!(true);
                Ok(())
            })
            .unwrap();
        store.devices_sweep_lapsed(now + 601);
        assert_eq!(names(&store), vec!["worker"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod forget_admission_precedence {
    //! The admission side of the forget write window, against a REAL store.
    //! `forget` writes the key block before it drops the record, so an open can
    //! meet both at once. The block is FORGOTTEN even though
    //! `device_cert_revoked` folds it in and still denies the open; a kept
    //! record marked certRevoked (ordinary `devices revoke` / `demote --to cut`)
    //! stays a revocation.
    use super::super::*;
    use crate::refusal::{Code, Refusal};
    use serde_json::json;

    fn unique(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-forget-admit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_forget_block_with_the_record_still_present_is_unrecognized_at_admission() {
        let root = unique("window");
        let store = DeviceStore::open(&root);
        let key = [0x5au8; 32];
        let now = now_secs();
        std::fs::write(
            store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "guest", "deviceCert": {"devicePub": hex::encode(key)}, "caps": []},
            ]))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            store.key_revocations_path(),
            serde_json::to_string(&json!([
                {"devicePub": hex::encode(key), "certExpires": now + 3600, "revokedAt": now, "name": "guest"},
            ]))
            .unwrap(),
        )
        .unwrap();

        let forgotten = store.device_key_revoked(&key, now);
        let revoked = store.device_cert_revoked(&key);
        assert!(forgotten, "the block names the key");
        assert!(
            revoked,
            "the record is still present and the block folds in, so the open is still denied"
        );
        let r = Refusal::from_shell_gate(forgotten, revoked, false, None, Some("guest".into()));
        assert_eq!(
            r.code,
            Code::Unrecognized,
            "the block is a forget, even mid-write: {}",
            r.reason
        );
        assert!(r.reason.contains("not recognized"), "{}", r.reason);

        // Ordinary revoke / demote --to cut: the record stays, marked
        // certRevoked, and no block is written. That is still a revocation.
        std::fs::remove_file(store.key_revocations_path()).unwrap();
        std::fs::write(
            store.devices_path(),
            serde_json::to_string(&json!([
                {
                    "name": "guest",
                    "deviceCert": {"devicePub": hex::encode(key)},
                    "certRevoked": true,
                    "caps": [],
                },
            ]))
            .unwrap(),
        )
        .unwrap();
        let forgotten = store.device_key_revoked(&key, now);
        let revoked = store.device_cert_revoked(&key);
        assert!(!forgotten, "no block was written");
        assert!(revoked, "the kept record is marked revoked");
        let r = Refusal::from_shell_gate(forgotten, revoked, false, None, Some("guest".into()));
        assert_eq!(r.code, Code::CertRevoked);
        assert_eq!(r.reason, "device revoked");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod remembered_store_tests {
    use super::super::*;

    #[test]
    fn a_repeated_remember_secret_is_idempotent_but_a_new_secret_is_a_new_record() {
        let root = std::env::temp_dir().join(format!(
            "fil-remember-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        let one = "a".repeat(64);
        let two = "b".repeat(64);
        let first = store.devices_store_remembered("boxa", &one).unwrap();
        let repeated = store.devices_store_remembered("boxa", &one).unwrap();
        assert_eq!(first, repeated, "a retried pair-keep must not mint a suffix");
        assert_eq!(
            store
                .devices_records()
                .iter()
                .filter(|d| d["secret"].as_str() == Some(one.as_str()))
                .count(),
            1
        );
        let other = store.devices_store_remembered("boxa", &two).unwrap();
        assert_ne!(
            first, other,
            "a different secret is a different device and still gets its own record"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod invitation_store_tests {
    use super::super::*;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "invitation-store-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn armed(key: &str, name: &str, expires: u64) -> ArmedInvitation {
        ArmedInvitation {
            key_id: key.repeat(32),
            expires,
            name: Some(name.into()),
            kind: Some("device".into()),
            allow: Some(vec!["transfer".into(), "mount".into()]),
            reuse: Some(json!(20)),
            created: Some(10),
        }
    }

    #[test]
    fn arm_list_disarm_and_expiry_share_one_locked_store() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.0.clone());
        let now = cap_now_secs();
        store
            .arm_invitation(armed("aa", "beta", now + 1_000), now)
            .unwrap();
        store
            .arm_invitation(armed("bb", "old", now.saturating_sub(50)), now)
            .unwrap();
        let listed = store.armed_invitations(now).unwrap();
        assert_eq!(listed.len(), 1, "expired entries are not listed");
        assert_eq!(listed[0].label(), "beta");
        assert_eq!(store.invitee_name(&"aa".repeat(32)).as_deref(), Some("beta"));
        assert!(store.is_armed());

        // Re-arming one key replaces its record instead of duplicating it.
        store
            .arm_invitation(armed("aa", "beta-2", now + 1_000), now)
            .unwrap();
        let listed = store.armed_invitations(now).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label(), "beta-2");

        store.disarm_invitation(&"aa".repeat(32)).unwrap();
        assert!(store.armed_invitations(now).unwrap().is_empty());
        assert!(!store.is_armed());
    }

    #[test]
    fn a_corrupt_armed_file_is_reported_and_not_replaced() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.0.clone());
        std::fs::write(root.0.join("armed.json"), "{").unwrap();
        assert!(store.armed_invitations(100).is_err());
        assert!(store.arm_invitation(armed("aa", "beta", 1_000), 100).is_err());
        assert_eq!(std::fs::read_to_string(root.0.join("armed.json")).unwrap(), "{");
    }

    #[test]
    fn config_name_writes_keep_other_keys() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.0.clone());
        store.set_config("server", "http://127.0.0.1:1").unwrap();
        store.set_device_name("phone").unwrap();
        assert_eq!(store.device_name().as_deref(), Some("phone"));
        assert_eq!(
            store.config_value("server").as_deref(),
            Some("http://127.0.0.1:1")
        );
        assert_eq!(
            std::fs::read_to_string(root.0.join("config")).unwrap(),
            "server http://127.0.0.1:1\nname phone\n"
        );
    }

    #[test]
    fn a_legacy_self_header_is_verified_over_its_signed_resource_id() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.0.clone());
        let seed = [4u8; 32];
        let owner = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        use ring::signature::KeyPair;
        let owner_pub: [u8; 32] = owner.public_key().as_ref().try_into().unwrap();
        let nonce = [9u8; 32];
        let mut header = filament_cap::capability::CapHeader {
            resource: filament_cap::capability::self_resource_id(&owner_pub),
            epoch: 0,
            owner_pub,
            nonce,
            floors: Vec::new(),
            issued_at: 10,
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        header.sig = filament_cap::capability::sign_cap_header(&header, &owner);
        let mut stored = header.to_json();
        stored["resource"] = json!("self");
        assert!(store.store_owner_cap_header(&stored, &owner_pub).unwrap());
        assert!(!store.store_owner_cap_header(&stored, &owner_pub).unwrap());
        assert!(store.owner_cap_header().is_some());
        let _ = std::fs::remove_dir_all(&root.0);
    }

    #[test]
    fn an_invalid_owner_header_never_reaches_the_store() {
        let root = TestRoot::new();
        let store = DeviceStore::open(root.0.clone());
        let owner = [7u8; 32];
        let header = json!({
            "type": "cap_header",
            "resource": "self",
            "epoch": 0,
            "owner_pub": hex::encode(owner),
            "nonce": hex::encode([1u8; 32]),
            "floors": [],
            "issued_at": 10,
            "prev_owner_pub": null,
            "prev_header_hash": null,
            "sig": hex::encode([0u8; 64]),
        });
        assert!(store.store_owner_cap_header(&header, &owner).is_err());
        assert!(!store.cap_store_path().exists());
    }
}
