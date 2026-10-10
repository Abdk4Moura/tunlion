

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
