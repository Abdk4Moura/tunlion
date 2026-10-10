

// ------------------------------------------------- hostile-environment fixes --

#[test]
fn a_typed_refusal_reaches_the_sender_in_the_receivers_words() {
    use crate::send_cmd::refusal_text;
    // A refusal: the reason token marks it, the sentence is shown.
    let v = protocol::refuse_msg("id1", "no_space", "receiver is out of disk space for a.bin (needs 3.0 MB, has 2.0 MB)");
    assert_eq!(
        refusal_text(&v).as_deref(),
        Some("receiver is out of disk space for a.bin (needs 3.0 MB, has 2.0 MB)")
    );
    // A plain decline is a person saying no, not a refusal.
    assert_eq!(refusal_text(&protocol::decline_msg("id1")), None);
    // Peer-supplied text is bounded and has no control characters.
    let hostile = protocol::refuse_msg("id1", "io", &format!("bad\x1b[2Jthing{}", "x".repeat(1000)));
    let shown = refusal_text(&hostile).unwrap();
    assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
    assert!(shown.chars().count() <= 300);
    // A reason with no sentence still says something true.
    let bare = serde_json::json!({ "type": "file-decline", "id": "x", "reason": "io" });
    assert!(refusal_text(&bare).is_some());
}

#[test]
fn a_full_disk_is_named_with_both_sizes_never_called_corruption() {
    let (token, msg) = crate::recv_files::storage_refusal(
        Some(platform::StorageFailure::NoSpace),
        "big.iso",
        "",
        Some(3 * 1024 * 1024),
        Some(2 * 1024 * 1024),
    );
    assert_eq!(token, "no_space");
    assert!(msg.contains("out of disk space"), "{msg}");
    assert!(msg.contains("needs") && msg.contains("has"), "{msg}");
    assert!(!msg.contains("checksum") && !msg.contains("corrupt"), "{msg}");
    let (token, msg) = crate::recv_files::storage_refusal(
        Some(platform::StorageFailure::NameTooLong),
        "x.bin",
        "File name too long (os error 36)",
        None,
        None,
    );
    assert_eq!(token, "name_too_long");
    assert!(msg.contains("refuses the name"), "{msg}");
    let (token, _) = crate::recv_files::storage_refusal(None, "x", "boom", None, None);
    assert_eq!(token, "io");
}

#[test]
fn the_no_peer_hint_names_who_we_were_waiting_for() {
    use crate::send_cmd::no_peer_hint;
    // CLI to CLI: a device is another tunlion, never "the page".
    let to_dev = no_peer_hint(Some("laptop"), false, None);
    assert!(to_dev.contains("'laptop'") && to_dev.contains("tunlion up"), "{to_dev}");
    assert!(!to_dev.contains("page"), "{to_dev}");
    // Only a code can be opened in a browser.
    let code = no_peer_hint(None, true, None);
    assert!(code.contains("code"), "{code}");
    let room = no_peer_hint(None, false, Some("r1"));
    assert!(room.contains("'r1'"), "{room}");
    assert!(!no_peer_hint(None, false, None).contains("page"));
}

#[test]
fn a_detached_up_never_follows_its_own_log() {
    // Source pin, because the race this guards needs a real fork to exercise
    // (cli/tests/hostile-env-gates.sh runs it): up_cmd decides "headless" from
    // the console being daemon.log or the detach marker, and a headless loser
    // exits instead of following the log it is writing into.
    let src = include_str!("up_logs.rs");
    let body = &src[src.find("pub(crate) async fn up_cmd").unwrap()..];
    let body = &body[..body.find("\n}\n").unwrap()];
    assert!(body.contains("stdio_is_file(&console_log)"), "headless must compare the console with daemon.log");
    assert!(body.contains("InstanceLock::try_acquire"), "the election must be the lock, not the pidfile");
    let lock_at = body.find("InstanceLock::try_acquire").unwrap();
    let pid_at = body.find("write_pidfile()").unwrap();
    assert!(lock_at < pid_at, "the lock must be taken before the pidfile is written");
    let logs = &src[src.find("pub(crate) async fn logs_cmd").unwrap()..];
    assert!(logs.contains("stdio_is_file(&console)"), "logs -f must refuse to follow its own output file");
}

#[test]
fn the_reenrolment_advice_is_complete_and_keeps_the_ceiling() {
    let s = crate::identity_state::reenrol_steps(
        "delta",
        "alpha",
        "shell",
        &["transfer".to_string(), "mount".to_string()],
    );
    for must in [
        "on alpha:",
        "tunlion devices forget delta",
        "tunlion add --for delta --allow transfer,mount,shell --out delta-invite.txt",
        "on delta:",
        "tunlion down",
        "tunlion reset -y",
        "tunlion join --invite-file delta-invite.txt --name delta",
    ] {
        assert!(s.contains(must), "missing {must:?} in:\n{s}");
    }
    // The order is the order they must run in.
    let at = |needle: &str| s.find(needle).unwrap();
    assert!(at("devices forget") < at("add --for") && at("add --for") < at("reset -y"));
    assert!(at("reset -y") < at("join --invite-file"));
    // A capability already in the ceiling is not listed twice.
    let again = crate::identity_state::reenrol_steps("d", "o", "mount", &["mount".to_string()]);
    assert!(again.contains("--allow mount --out"), "{again}");
}
