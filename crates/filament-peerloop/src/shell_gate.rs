//! The single shell gate shared by pty-open, exec-open and ssh-sign.
//!
//! Moved out of `cli/src/shell_gate.rs` (issue #465 slice 3). Both paths resolve
//! the same inputs (link trust, device naming, legacy store checks, capability
//! inputs) and then the same verdict: the capability engine's
//! `granted.allowed()`, unconditionally -- no shadow / authoritative split, no
//! legacy fallback. Under the old split a revoked certificate was still allowed
//! whenever legacy checks passed, so exec could be MORE permissive than a shell;
//! the engine itself already denies revoked certs absolutely (both modes), the
//! split only hid it.
//!
//! WHAT IS INJECTED. The gate touches the machine only through `HostServices`:
//! the capability store and its clock, the device store's deny/grant reads and
//! its delegated-access record, the revocation decision, the enrolment ceiling,
//! and the one policy site (`cap_gate_effective`) that owns the mode, counters
//! and diagnostics. `filament-cap` supplies the pure evaluators over the store
//! slice the host hands back. There is no path from here into the CLI.
//!
//! WHAT MOVED WITH IT. `ShellPolicy` and `PeerAuthz` were CLI types whose only
//! non-CLI users are these inputs, so they moved too; the CLI re-exports both
//! under their old names. `exec_gate_decision` and `pty_gate_decision` remain
//! deliberately separate one-line entry points over one core: the cross-path
//! equivalence test calls both for every matrix cell, so any future per-path
//! divergence (the exact regression that motivated this module) turns red
//! instead of shipping silently.

use std::collections::HashSet;

use crate::conn::Conn;
use crate::host::{CapGate, HostServices};
use crate::identity::resolve_peer_identity;
use filament_cap::capability::{
    BindingStrength, CapOutcome, GateDecision, PrincipalKind, authorize_in, fleet_inputs_in,
};

/// Auto-shell policy for the `up`/`recv` acceptor: which proof-verified devices
/// may `tunlion shell --ssh` in WITHOUT a per-device `grant`. Trust (pair-proof) is
/// always enforced separately, this is purely the capability side.
#[derive(Clone, Debug)]
pub enum ShellPolicy {
    /// Default: only devices explicitly `grant`ed the `shell` cap.
    Granted,
    /// `up --shell`: any paired device. M-2: this INTENTIONALLY grants every
    /// proof-verified paired device, including ones introduced later via
    /// pair-intro. Use `Only`/`--shell-only` to scope it.
    All,
    /// `up --shell-only a,b`: only these petnames auto-shell; others need a grant.
    Only(HashSet<String>),
}

impl ShellPolicy {
    pub fn auto_allows(&self, name: &str) -> bool {
        match self {
            ShellPolicy::Granted => false,
            ShellPolicy::All => true,
            ShellPolicy::Only(set) => set.contains(name),
        }
    }

    /// #244: the posture this daemon is actually serving, for `cap-status`.
    ///
    /// Reported by the RUNNING daemon rather than derived from settings by the
    /// asking process. `up --shell` sets the policy from a launch flag that
    /// never touches the settings file, so a settings-derived answer would be
    /// true about the config and wrong about the daemon, which is precisely the
    /// gap that lets `revoke <device> shell` report success while the policy
    /// keeps handing out the shell.
    pub fn label(&self) -> &'static str {
        match self {
            ShellPolicy::Granted => "granted",
            ShellPolicy::All => "all",
            ShellPolicy::Only(_) => "only",
        }
    }

    /// The petnames this policy auto-shells regardless of any per-device grant.
    /// Empty for `Granted`; `Only`'s set; `All` answers for every peer, so the
    /// caller must read `label() == "all"` rather than look for a name here.
    pub fn auto_names(&self) -> Vec<String> {
        match self {
            ShellPolicy::Only(set) => {
                let mut v: Vec<String> = set.iter().cloned().collect();
                v.sort();
                v
            }
            _ => Vec::new(),
        }
    }

    /// Active policy implies the L2 tunnel acceptor is on (you can't ssh without it).
    pub fn enables_l2(&self) -> bool {
        !matches!(self, ShellPolicy::Granted)
    }
}

/// Everything the capability gate needs to know about a peer, resolved once.
///
/// This preamble was written FIVE times in the daemon, identically: lazy-resolve
/// the peer's identity from its stored certificate, then read binding, expiry,
/// revocation and the auth-key ceiling off the link. Five copies of the inputs
/// to an authorization decision. It moved here with the gate that consumes it.
pub struct PeerAuthz {
    pub idev: Option<[u8; 32]>,
    pub iusr: Option<[u8; 32]>,
    pub binding: BindingStrength,
    pub expires: Option<u64>,
    pub cert_revoked: bool,
    pub ak_caps: Option<Vec<String>>,
}

impl PeerAuthz {
    /// The gate's arguments in the order every call site uses them.
    ///
    /// Returned as one tuple because the alternative was five identical lines of
    /// destructuring at five call sites, which is the duplication this struct
    /// was extracted to remove, reintroduced one layer up.
    pub fn parts(
        &self,
    ) -> (
        Option<&[u8; 32]>,
        Option<&[u8; 32]>,
        BindingStrength,
        Option<u64>,
        bool,
        Option<&[String]>,
    ) {
        (
            self.idev.as_ref(),
            self.iusr.as_ref(),
            self.binding,
            self.expires,
            self.cert_revoked,
            self.ak_caps.as_deref(),
        )
    }
}

/// Resolve the gate's per-peer inputs from the live link and the host's stores.
pub fn peer_authz(conn: &mut Conn, pid: &str) -> PeerAuthz {
    if let Some(l) = conn.link_mut(pid) {
        resolve_peer_identity(l);
    }
    let host = conn.host.clone();
    let link = conn.link(pid);
    let idev = link.and_then(|l| l.identity_device_pub);
    let iusr = link.and_then(|l| l.identity_user_pub);
    let mut expires = link.and_then(|l| l.identity_cert_expires);
    let mut ak_caps = link
        .and_then(|l| l.principal_kind.auth_key_caps())
        .map(|c| c.to_vec());
    // A DELEGATED device's deadline and ceiling are read FRESH from its record
    // at every gate, never trusted from what the link cached when its identity
    // first resolved. The cached copy is how an invited guest kept access past
    // its invitation end: the link was resolved while the invitation was live,
    // nothing re-read it, and a later proof re-bound it from the presented
    // (renewed) certificate. The record is the owner's own statement, kept in
    // step by renewal, and it carries the invitation end.
    if let Some(access) = idev
        .as_ref()
        .and_then(|d| host.delegated_access_for(d))
    {
        expires = Some(access.deadline);
        if access.expired(host.now_secs()) {
            ak_caps = Some(Vec::new());
        } else if ak_caps.is_none() {
            // A delegated record never authorizes as an owner device, whatever
            // the link's principal says.
            ak_caps = Some(access.ceiling.clone());
        }
    }
    PeerAuthz {
        binding: link
            .map(|l| l.identity_binding)
            .unwrap_or(BindingStrength::None),
        expires,
        cert_revoked: host.cert_revoked_for(idev.as_ref()),
        ak_caps,
        idev,
        iusr,
    }
}

/// Gathered gate inputs: link-derived + store-derived + policy, pre-decision.
/// Plain data (no Conn), so the matrix test can fabricate every cell.
pub struct ShellGateInputs {
    pub trusted: bool,
    pub denied: bool,
    pub policy_allows: bool,
    pub store_allows: bool,
    pub outcome: CapOutcome,
    pub idev: Option<[u8; 32]>,
    pub iusr: Option<[u8; 32]>,
    pub binding: BindingStrength,
    pub expires: Option<u64>,
    pub ak_caps: Option<Vec<String>>,
    pub own_user: Option<[u8; 32]>,
    pub has_grant: bool,
    pub cert_revoked: bool,
    /// The gated action, threaded from gather through decide so no shell
    /// literal can drift between callers. All current callers pass CAP_SHELL.
    pub action: String,
    /// Whether the peer's persisted, owner-signed enrolment ceiling covers
    /// the gated action. Gathered fresh (never cached) via
    /// `ceiling_covers_action`, keyed by verified device identity. Feeds the
    /// engine's `ceiling_authorizes`, which decides only under authoritative
    /// mode (shadow must decide exactly as it did before this feature).
    pub ceiling_covers: bool,
    /// The SCOPE-DEFAULT class for this open (transfer into the drop dir,
    /// forward to an exposed port, and a shell from the owner's own device when
    /// this device accepts owned shells, see `owned_shell_class`). Distinct from
    /// the ceiling: this class auto-authorizes same-owner Proven devices in BOTH
    /// modes, through the policy site's guards.
    pub scoped_default: bool,
}

/// Gather from live state. Both call sites use this; nothing gate-relevant
/// is resolved anywhere else, so the three paths cannot drift in inputs.
pub fn gather_shell_gate_inputs(
    conn: &mut Conn,
    pid: &str,
    shell_policy: &ShellPolicy,
    action: &str,
) -> (Option<String>, ShellGateInputs) {
    // Eval item 4: a fleet sibling (met by fleet-hello, no pair secret) is
    // born `trusted: false` and stays so, so `grant <sibling> shell` on a
    // member recorded a grant the fold could never honour while the caps
    // view (which assumes an authenticated link) said EFFECTIVE yes. A
    // proven fleet link satisfies the record-grant term; the blanket
    // `--shell` policy still speaks for PAIRED devices only.
    let (pair_trusted, fleet_proven) = conn
        .link(pid)
        .map(|l| (l.trusted, l.fleet_proven()))
        .unwrap_or((false, false));
    let trusted = pair_trusted || fleet_proven;
    let dev = conn.link(pid).and_then(|l| l.verified_name.clone());
    let host = conn.host.clone();
    let (denied, policy_allows, store_allows) = match dev.as_deref() {
        Some(n) => (
            host.device_capability_denied(n, action),
            pair_trusted && shell_policy.auto_allows(n),
            host.device_allows(n, action),
        ),
        None => (false, false, false),
    };
    let az = peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let store = host.cap_store();
    let now = host.now_secs();
    let outcome = authorize_in(&store, "self", action, idev, iusr, ak_caps, now);
    let raw_ceiling = host.ceiling_covers_action(idev, action);
    let (own_user, has_grant) = fleet_inputs_in(&store, "self", action, idev, iusr, ak_caps, now);
    // Owned-device shell (docs/owned-shell-default.md): when this device
    // accepts owned shells, the shell action joins the SCOPE-DEFAULT class for
    // this open, so the policy site's existing Proven-gated same-owner
    // auto-trust decides it (same owner, Proven, not revoked, not denied, not
    // expired). A delegated principal (auth-key ceiling present) never gets it:
    // its signed ceiling stays the whole of its authority.
    // Review ruling F1(a): the owner-signed enrolment ceiling is a HARD ceiling
    // for shell, and local acceptance gates BOTH ways a shell can be
    // authorized without a grant: the owned class and the ceiling path.
    let (scoped_default, ceiling_covers) =
        shell_gate_classes(action, ak_caps.is_some(), host.owned_shell_accepted(), raw_ceiling);
    let inputs = ShellGateInputs {
        trusted,
        denied,
        policy_allows,
        store_allows,
        outcome,
        idev: idev.copied(),
        iusr: iusr.copied(),
        binding,
        expires,
        ak_caps: ak_caps.map(|s| s.to_vec()),
        own_user,
        has_grant,
        cert_revoked,
        ceiling_covers,
        scoped_default,
        action: action.to_string(),
    };
    (dev, inputs)
}

impl ShellGateInputs {
    /// Admitted ONLY because it is the owner's own device and this device
    /// accepts owned shells: no explicit grant, no legacy grant, no `--shell`
    /// policy behind it. A live session admitted this way must end as soon as
    /// this device stops accepting owned shells; every other population keeps
    /// the authority it was admitted under.
    ///
    /// For a non-delegated device this covers BOTH no-grant ways in (the owned
    /// class and the signed ceiling), since local acceptance gates both for
    /// the owner's own devices. A delegated principal is never in it: the
    /// toggle does not touch delegated authority (review clarification).
    pub fn admitted_via_owned_shell(&self) -> bool {
        (self.scoped_default || self.ceiling_covers)
            && self.action == filament_cap::capability::CAP_SHELL
            && self.ak_caps.is_none()
            && !self.has_grant
            && !self.store_allows
            && !self.policy_allows
    }
}

/// Is this open in the owned-device shell class? Pure, so the matrix pins it.
/// Only the shell action, only a non-delegated principal, only when this device
/// accepts owned shells, and only when the owner-signed enrolment ceiling
/// covers shell (review ruling F1(a): pairing never exceeds what was signed).
/// The same-owner / Proven / revocation / deny / expiry conditions are NOT
/// checked here: the policy site applies them to every scoped default, and
/// checking them twice in two places is how they drift.
pub fn owned_shell_class(action: &str, delegated: bool, accepted_here: bool, ceiling_covers: bool) -> bool {
    action == filament_cap::capability::CAP_SHELL && !delegated && accepted_here && ceiling_covers
}

/// The two no-grant classes the gate receives, `(scoped_default,
/// ceiling_covers)`. For the owner's OWN (non-delegated) devices, local
/// `own-devices-shell` acceptance gates BOTH for shell: a signed ceiling alone
/// never runs a shell on a device that has not accepted owned shells. For a
/// DELEGATED principal the toggle changes nothing: its signed auth-key ceiling
/// behaves exactly as before (review clarification; MESH-INTENT: delegated
/// devices remain bounded by signed authority). Other actions pass the ceiling through untouched and are not
/// scoped defaults here (the forward path sets its own expose-list bound).
pub fn shell_gate_classes(action: &str, delegated: bool, accepted_here: bool, raw_ceiling: bool) -> (bool, bool) {
    let is_shell = action == filament_cap::capability::CAP_SHELL;
    let scoped = owned_shell_class(action, delegated, accepted_here, raw_ceiling);
    let ceiling = raw_ceiling && (!is_shell || delegated || accepted_here);
    (scoped, ceiling)
}

#[cfg(test)]
mod owned_shell_tests {
    use super::{owned_shell_class, shell_gate_classes};
    use filament_cap::capability::{CAP_MOUNT, CAP_SHELL, CAP_TRANSFER};

    #[test]
    fn own_device_shell_needs_acceptance_and_a_signed_shell_ceiling() {
        // positive: own device, accepted here, ceiling signed with shell
        assert!(owned_shell_class(CAP_SHELL, false, true, true));
        // negative: no signed shell in the enrolment ceiling
        assert!(!owned_shell_class(CAP_SHELL, false, true, false), "pairing must not exceed the signed ceiling");
        // negative: this device has not accepted owned shells
        assert!(!owned_shell_class(CAP_SHELL, false, false, true), "a signed ceiling alone is not acceptance");
        // negative: delegated principals keep only their signed caps
        assert!(!owned_shell_class(CAP_SHELL, true, true, true), "a delegated principal never rides the owned class");
        for other in [CAP_TRANSFER, CAP_MOUNT, "route", "exec"] {
            assert!(!owned_shell_class(other, false, true, true), "{other} must not ride the owned-shell class");
        }
    }

    #[test]
    fn local_acceptance_gates_an_own_devices_ceiling_path_for_shell_too() {
        // own device, shell ceiling signed, device NOT accepting: neither path
        assert_eq!(shell_gate_classes(CAP_SHELL, false, false, true), (false, false));
        // own device, accepted: both paths
        assert_eq!(shell_gate_classes(CAP_SHELL, false, true, true), (true, true));
        // no signed shell ceiling: nothing, accepted or not
        assert_eq!(shell_gate_classes(CAP_SHELL, false, true, false), (false, false));
        assert_eq!(shell_gate_classes(CAP_SHELL, false, false, false), (false, false));
    }

    #[test]
    fn the_toggle_never_alters_delegated_authority() {
        for accepted in [false, true] {
            // the delegated signed-ceiling path is identical with the toggle on or off
            assert_eq!(shell_gate_classes(CAP_SHELL, true, accepted, true), (false, true), "accepted={accepted}");
            // a missing signed shell cap still denies, toggle or not
            assert_eq!(shell_gate_classes(CAP_SHELL, true, accepted, false), (false, false), "accepted={accepted}");
        }
        // other actions: ceiling untouched, never a scoped default here
        assert_eq!(shell_gate_classes(CAP_TRANSFER, false, false, true), (false, true));
        assert_eq!(shell_gate_classes(CAP_MOUNT, false, true, false), (false, false));
    }
}
