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
    /// forward to an exposed port). Distinct from the ceiling: this class has
    /// always auto-authorized same-owner Proven devices in BOTH modes.
    /// False for the shell-class paths, which are deliberate-tier.
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
            policy_trusted(pair_trusted, fleet_proven, n, host.as_ref())
                && shell_policy.auto_allows(n),
            host.device_allows(n, action),
        ),
        None => (false, false, false),
    };
    let az = peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let store = host.cap_store();
    let now = host.now_secs();
    let outcome = authorize_in(&store, "self", action, idev, iusr, ak_caps, now);
    let ceiling_covers = host.ceiling_covers_action(idev, action);
    let (own_user, has_grant) = fleet_inputs_in(&store, "self", action, idev, iusr, ak_caps, now);
    // FleetSibling: an owner-signed grant about this device counts as a grant
    // (the receiver's own record grant already does, via store_allows), and a
    // local deny was read above and outranks both.
    let sib = sibling_facts(conn, pid, action);
    let (_, has_grant) = sibling_gate_inputs(&sib, action, false, has_grant);
    let store_allows = store_allows || (sib.is_sibling && sib.owner_grant);
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
        scoped_default: false,
        action: action.to_string(),
    };
    (dev, inputs)
}

/// May the `--shell`/`--shell-only` policy speak for this link's device?
///
/// The policy names PAIRED devices, and the reference is the direct dial: a
/// fresh CLI connection proves the pair secret, so the link is `trusted` and
/// the policy applies to the record that secret belongs to. The same device
/// reached over the daemon's warm link may instead be a fleet link, verified
/// by fleet-hello: its `verified_name` is the record its PROVEN certificate key
/// resolves to, but it is never pair-`trusted`. Reading pair trust alone made
/// `up --shell-only dovm` refuse dovm over the warm link while the direct dial
/// was admitted.
///
/// A proven fleet link counts here only when the record it resolves to is a
/// paired one (it holds a pair secret), which is exactly the record a direct
/// dial would have proven. A fleet sibling known only through fleet-hello has
/// no pair secret, so a direct dial could never earn the policy for it, and it
/// does not earn it here either.
pub fn policy_trusted(
    pair_trusted: bool,
    fleet_proven: bool,
    name: &str,
    host: &dyn HostServices,
) -> bool {
    pair_trusted
        || (fleet_proven
            && host
                .devices_load()
                .iter()
                .any(|(n, secret)| n == name && !secret.is_empty()))
}

/// What a gate needs to know about a fleet SIBLING on this link, for one action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiblingFacts {
    /// The link's principal is `FleetSibling`: a same-owner device admitted on
    /// its certificate over the fleet channel (or a one-shot on a meeting place
    /// it brokered), never paired here.
    pub is_sibling: bool,
    /// THIS machine's own record grants the proven sibling the action
    /// (`tunlion grant <sibling> <cap>` here). Keyed by the name resolved from
    /// the proven key, never a claimed one.
    pub local_grant: bool,
    /// An owner-signed grant set held here grants the sibling's proven device
    /// key the action (`tunlion grant <sibling> <cap> --on <this device>` on the
    /// owner), and this device's `fleet.owner_grants` lets it apply.
    pub owner_grant: bool,
    /// This machine's record DENIES the action to the sibling. Outranks both
    /// grant sources.
    pub denied: bool,
}

/// Read the sibling facts for `pid` and `action`. Anything that is not a fleet
/// sibling reads as all-false, so every gate it feeds is unchanged for it.
pub fn sibling_facts(conn: &Conn, pid: &str, action: &str) -> SiblingFacts {
    let Some(l) = conn.link(pid) else {
        return SiblingFacts::default();
    };
    // A paired link that also carries the fleet principal is NOT a sibling
    // (see `Link::is_sibling_link`): its pair secret governs it.
    if !l.is_sibling_link() || !l.fleet_proven() {
        return SiblingFacts {
            is_sibling: l.is_sibling_link(),
            ..SiblingFacts::default()
        };
    }
    let name = l.verified_name.as_deref();
    SiblingFacts {
        is_sibling: true,
        local_grant: name.is_some_and(|n| conn.host.device_record_grants(n, action)),
        owner_grant: l
            .identity_device_pub
            .as_ref()
            .is_some_and(|d| conn.host.fleet_grant_applies(d, action)),
        denied: name.is_some_and(|n| conn.host.device_capability_denied(n, action)),
    }
}

/// Apply the `FleetSibling` kind to a gate's `(scoped_in_bounds,
/// has_explicit_grant)`. See `filament_cap::fleet_grants::fleet_sibling_inputs`.
pub fn sibling_gate_inputs(
    f: &SiblingFacts,
    action: &str,
    scoped_in_bounds: bool,
    has_grant: bool,
) -> (bool, bool) {
    filament_cap::fleet_grants::fleet_sibling_inputs(
        f.is_sibling,
        action,
        scoped_in_bounds,
        has_grant,
        f.local_grant,
        f.owner_grant,
    )
}

/// Pure predicate behind `Link::fleet_proven`: a same-owner fleet device whose
/// identity is Proven and whose local name came from that proven key. The RULE
/// itself lives in `crate::host` (written once, shared with the peer loop);
/// this is the enum-shaped wrapper so the callers and tests here keep their
/// signatures.
pub fn fleet_link_proven(
    kind: &PrincipalKind,
    binding: BindingStrength,
    has_device_pub: bool,
    has_verified_name: bool,
) -> bool {
    crate::host::fleet_link_proven(
        matches!(kind, PrincipalKind::FleetSibling),
        binding == BindingStrength::Proven,
        has_device_pub,
        has_verified_name,
    )
}

/// Shared verdict core: legacy folds trust the same way for both paths, then
/// the capability verdict decides alone. Returns the engine's cap reason
/// when it names one; each call site applies its own fallback wording for
/// the reason-less case (pty and exec historically differ there, preserved).
fn decide(
    inputs: &ShellGateInputs,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    decide_with_legacy(
        inputs,
        inputs.trusted && !inputs.denied && (inputs.policy_allows || inputs.store_allows),
        host,
    )
}

/// Verdict core with a caller-supplied legacy fold. exec/pty/ssh-sign use
/// the shell fold above; the forward path passes its own blanket fold
/// (blanket L2 mode admits trusted peers with no shell policy behind it,
/// which the shell fold cannot express -- dropping it would newly deny
/// default setups in shadow). Same engine, same inputs otherwise.
fn decide_with_legacy(
    inputs: &ShellGateInputs,
    legacy_ok: bool,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    // Two auto-trust classes travel separately: `scoped_default` (mode
    // independent, pre-existing) and `ceiling_covers` (authoritative-only
    // for the decision; counted as would-allow in shadow so the ceiling
    // population is not mistaken for breakage).
    let granted = host.cap_gate_effective(CapGate {
        legacy_allowed: legacy_ok,
        outcome: &inputs.outcome,
        action: inputs.action.as_str(),
        resource: "self",
        device_pub: inputs.idev.as_ref(),
        user_pub: inputs.iusr.as_ref(),
        binding: inputs.binding,
        cert_expires: inputs.expires,
        auth_key_caps: inputs.ak_caps.as_deref(),
        own_user_pub: inputs.own_user.as_ref(),
        scoped_in_bounds: inputs.scoped_default,
        has_explicit_grant: inputs.has_grant,
        cert_revoked: inputs.cert_revoked,
        denied: inputs.denied,
        ceiling_authorizes: inputs.ceiling_covers,
    });
    match granted {
        GateDecision::Allow => Ok(()),
        GateDecision::Deny { cap_reason } => Err(cap_reason),
    }
}

/// Exec-open's entry point: delegates to the shared core (no local logic).
pub fn exec_gate_decision(
    inputs: &ShellGateInputs,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    decide(inputs, host)
}

/// Pty-open's entry point: delegates to the shared core (no local logic).
pub fn pty_gate_decision(
    inputs: &ShellGateInputs,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    decide(inputs, host)
}

/// Forward-open's entry point: same shared core, but the caller supplies
/// the legacy fold (see above) and overrides `ceiling_covers` with its
/// expose.json bound before calling. A forward --stdio to an exposed sshd
/// is shell-equivalent in reach.
pub fn forward_gate_decision(
    inputs: &ShellGateInputs,
    legacy_ok: bool,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    decide_with_legacy(inputs, legacy_ok, host)
}

/// SSH-sign's entry point: the certificate signer asks the same gate before
/// signing (a cert is B's statement about A, so the shell grant gates it
/// like any shell-class open). Delegates to the shared core (no local logic).
pub fn ssh_gate_decision(
    inputs: &ShellGateInputs,
    host: &dyn HostServices,
) -> Result<(), Option<String>> {
    decide(inputs, host)
}
