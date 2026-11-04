//! The owner-side invitation policy, shared by the CLI and Core.
//!
//! One mint, one preview, one outstanding list and one withdrawal. The CLI is
//! an adapter over these functions, and Android calls the Core functions that
//! call them, so neither client parses a token or decides what a ceiling means.
//!
//! An invitation is a signed ceiling plus a possession key. This module owns
//! the bounds around that artifact:
//!
//! * a lifetime of 1 second to 30 days;
//! * `Reuse::N(n)` with `1..=250`, or `Reusable`;
//! * `route` only with one or more explicit, normalised `route:<cidr>` scopes;
//! * a non-empty, control-free owner name that fits the signed name field;
//! * `shell` and `all-ports` only when the caller deliberately confirmed that
//!   remote authority;
//! * every capability must be one this core can express in the signed format.
//!
//! The preview never claims the requested authority was granted. It reports
//! the exact signed ceiling (`EnrollmentReview`), so a UI cannot show less
//! than the invitation asks for.

use anyhow::{bail, Result};
use filament_cap::capability::{normalize_cidr, CAP_ROUTE};
use filament_cap::ephemeral::{
    canonical_invitation_capability, Invitation, Reuse, INVITE_PREFIX_V2,
};
use filament_id::enrollment::{EnrollmentReview, Relationship};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};

use crate::recv::store::{ArmedInvitation, DeviceStore, InvitationLedgerEntry};

/// The longest an invitation may live: 30 days.
pub const MAX_INVITATION_SECS: u64 = 30 * 24 * 3600;
/// A runner's offline budget: long enough for a restart, short enough that a
/// cancelled job does not linger in the device list.
pub const RUNNER_MAX_OFFLINE_SECS: u64 = 15 * 60;
/// A persistent device's offline budget.
pub const DEVICE_MAX_OFFLINE_SECS: u64 = 30 * 24 * 3600;
/// The highest bounded reuse count the invitation wire can carry.
pub const MAX_REUSE: u32 = 250;

/// What the owner intends the invitation to add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationKind {
    /// The owner's own device: fleet membership, inbox transfer by default.
    Device,
    /// Another person: transfer by default, no fleet membership.
    Person,
    /// A temporary box: transfer only by default, ephemeral, short offline.
    Runner,
}

impl InvitationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Person => "person",
            Self::Runner => "runner",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "device" => Ok(Self::Device),
            "person" => Ok(Self::Person),
            "runner" => Ok(Self::Runner),
            other => bail!("unknown invitation kind '{other}' (valid: device, person, runner)"),
        }
    }

    pub fn relationship(self) -> Relationship {
        match self {
            Self::Device => Relationship::OwnDevice,
            Self::Person => Relationship::OtherPerson,
            Self::Runner => Relationship::TemporaryWorker,
        }
    }
}

/// What an owner asks to mint. Capabilities are the requested ceiling, not an
/// effective-access claim.
#[derive(Debug, Clone)]
pub struct InvitationRequest {
    pub owner_name: String,
    pub invitee_name: Option<String>,
    pub kind: InvitationKind,
    /// Empty means the kind's current default (inbox transfer only).
    /// Mount is an explicit opt-in; see `default_capabilities`.
    pub capabilities: Vec<String>,
    /// A relative lifetime in seconds, measured from the mint.
    pub expires_secs: u64,
    pub reuse: Reuse,
    /// `runner` is ephemeral regardless; this lets a caller mint an ephemeral
    /// invitation for another kind only through the same validated path.
    pub ephemeral: bool,
    /// Prefixes for a `route` ceiling. Required iff the ceiling names `route`.
    pub routes: Vec<String>,
    /// The deliberate confirmation for OWNER-EQUIVALENT authority.
    pub confirm_remote_authority: bool,
}

/// The exact signed request, ready to display before anything is minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationPreview {
    pub owner_name: String,
    pub relationship: Relationship,
    pub review: EnrollmentReview,
    /// The normalised, scoped ceiling; equal to `review.requested_capabilities`.
    pub capabilities: Vec<String>,
    pub expires: u64,
    pub max_offline: u64,
    pub reuse: Reuse,
    pub ephemeral: bool,
    pub routes: Vec<String>,
    pub expired: bool,
}

/// A minted invitation. The token is a credential: never log it, never put it
/// in an argument list, and never return the possession seed separately.
#[derive(Clone)]
pub struct MintedInvitation {
    pub invitation: Invitation,
    pub token: Vec<u8>,
    pub preview: InvitationPreview,
}

impl MintedInvitation {
    /// The text token with the released v2 prefix. This is what a file holds.
    pub fn token_text(&self) -> String {
        let mut text = String::with_capacity(INVITE_PREFIX_V2.len() + self.token.len());
        text.push_str(INVITE_PREFIX_V2);
        use base64::Engine;
        text.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.token));
        text
    }
}

/// The current default ceiling for a kind. The device default is inbox
/// transfer only; mount is an explicit opt-in. Existing enrolled devices keep
/// the ceiling they already hold.
pub fn default_capabilities(kind: InvitationKind) -> Vec<String> {
    match kind {
        InvitationKind::Device | InvitationKind::Person | InvitationKind::Runner => {
            vec!["transfer".into()]
        }
    }
}

/// The capabilities this core can carry in a signed invitation and enforce as
/// a ceiling. This is a capability vocabulary, not a claim that every server
/// backend (a mount daemon, a PTY) is compiled into this process.
pub fn servable_capabilities() -> Vec<String> {
    let mut caps: Vec<String> = filament_cap::capability::CANONICAL_CAPABILITIES
        .iter()
        .map(|c| (*c).to_string())
        .collect();
    // `all-ports` shapes an invitation but is not a cap-store action; it is
    // deliberately absent from CANONICAL_CAPABILITIES.
    caps.push("all-ports".to_string());
    caps.sort();
    caps.dedup();
    caps
}

fn validate_owner_name(name: &str) -> Result<String> {
    let clean = name.trim();
    if clean.is_empty() {
        bail!("an invitation needs a non-empty owner name");
    }
    if clean.len() > 128 {
        bail!("an invitation owner name must be at most 128 bytes");
    }
    if clean.chars().any(char::is_control) {
        bail!("an invitation owner name must not contain control characters");
    }
    Ok(clean.to_string())
}

fn validate_reuse(reuse: &Reuse) -> Result<()> {
    match reuse {
        Reuse::Once | Reuse::Reusable => Ok(()),
        Reuse::N(0) => bail!("an invitation must admit at least one use"),
        Reuse::N(n) if *n > MAX_REUSE => bail!(
            "an invitation may admit at most {MAX_REUSE} uses; use the reusable form for more"
        ),
        Reuse::N(_) => Ok(()),
    }
}

/// Normalise and validate a request without minting. This is the one place a
/// default is applied, so preview and mint cannot disagree.
pub fn preview_request(request: &InvitationRequest, now: u64) -> Result<InvitationPreview> {
    let owner_name = validate_owner_name(&request.owner_name)?;
    if request.expires_secs == 0 || request.expires_secs > MAX_INVITATION_SECS {
        bail!("invitations must expire between 1 second and 30 days");
    }
    let expires = now
        .checked_add(request.expires_secs)
        .ok_or_else(|| anyhow::anyhow!("invitation expiry overflows the clock"))?;
    validate_reuse(&request.reuse)?;

    let mut requested = if request.capabilities.is_empty() {
        default_capabilities(request.kind)
    } else {
        request.capabilities.clone()
    };
    let mut caps = Vec::with_capacity(requested.len());
    for cap in requested.drain(..) {
        caps.push(canonical_invitation_capability(&cap)?);
    }
    caps.sort();
    caps.dedup();

    if caps.iter().any(|c| c == "shell" || c == "all-ports")
        && !request.confirm_remote_authority
    {
        bail!(
            "this invitation asks for owner-equivalent remote authority (shell or all-ports); confirm it deliberately"
        );
    }

    let wants_route = caps.iter().any(|c| c == CAP_ROUTE);
    if wants_route && request.routes.is_empty() {
        bail!(
            "a 'route' invitation must name the prefixes it allows, e.g. --allow route:10.0.0.0/24"
        );
    }
    if !request.routes.is_empty() && !wants_route {
        bail!("route prefixes were given without the 'route' capability");
    }
    let mut routes = Vec::with_capacity(request.routes.len());
    for route in &request.routes {
        let normalized = normalize_cidr(route)?;
        if !routes.contains(&normalized) {
            routes.push(normalized);
        }
    }

    let ephemeral = request.kind == InvitationKind::Runner || request.ephemeral;
    let max_offline = if ephemeral {
        RUNNER_MAX_OFFLINE_SECS
    } else {
        DEVICE_MAX_OFFLINE_SECS
    };

    // The downstream vocabulary expands `route` to its prefixes. The review is
    // the exact authority a joining client must show.
    let scoped: Vec<String> = caps
        .iter()
        .flat_map(|c| {
            if c == CAP_ROUTE {
                routes.iter().map(|r| format!("route:{r}")).collect::<Vec<_>>()
            } else {
                vec![c.clone()]
            }
        })
        .collect();
    let mut scoped = scoped;
    scoped.sort();
    scoped.dedup();
    let review = EnrollmentReview::new(request.kind.relationship(), &scoped);

    Ok(InvitationPreview {
        owner_name,
        relationship: request.kind.relationship(),
        review,
        capabilities: scoped,
        expires,
        max_offline,
        reuse: request.reuse.clone(),
        ephemeral,
        routes,
        expired: false,
    })
}

/// Preview an already-signed invitation token. Expiry is reported, not
/// hidden: a UI may show an expired invitation honestly and refuse to join it.
pub fn preview_invitation(invitation: &Invitation, now: u64) -> InvitationPreview {
    // The signed wire records authority and ephemerality, not the owner's
    // display intent. A non-ephemeral token with mount is necessarily an
    // owner-device posture; without mount it is ambiguous between a device
    // default and a person, so do not guess.
    let relationship = if invitation.ephemeral {
        Relationship::TemporaryWorker
    } else if invitation.caps.iter().any(|c| c == "mount") {
        Relationship::OwnDevice
    } else {
        Relationship::Unknown
    };
    let scoped = invitation.scoped_caps();
    InvitationPreview {
        owner_name: invitation.owner_name.clone(),
        relationship,
        review: EnrollmentReview::new(relationship, &scoped),
        capabilities: scoped,
        expires: invitation.expires,
        max_offline: invitation.max_offline,
        reuse: invitation.reuse.clone(),
        ephemeral: invitation.ephemeral,
        routes: invitation.routes.clone(),
        expired: now >= invitation.expires,
    }
}

/// Mint and arm an invitation in one step. The seed is generated here, used
/// only by `Invitation::mint`, and never returned separately or logged.
pub fn mint_armed(
    store: &DeviceStore,
    owner_key: &ring::signature::Ed25519KeyPair,
    request: &InvitationRequest,
    now: u64,
) -> Result<MintedInvitation> {
    let preview = preview_request(request, now)?;
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("invitation possession key: entropy unavailable"))?;
    // The request's normalised ability names, without the scoped spelling:
    // Invitation::mint carries the route prefixes in their own signed field.
    let mut caps: Vec<String> = preview
        .capabilities
        .iter()
        .filter(|c| !c.starts_with("route:"))
        .cloned()
        .collect();
    if !preview.routes.is_empty() {
        caps.push(CAP_ROUTE.to_string());
    }
    caps.sort();
    caps.dedup();
    let invitation = Invitation::mint(
        owner_key,
        seed,
        caps,
        preview.expires,
        preview.max_offline,
        preview.reuse.clone(),
        preview.ephemeral,
        preview.owner_name.clone(),
        preview.routes.clone(),
    )?;
    let token = invitation.to_token();
    store.arm_invitation(
        ArmedInvitation {
            key_id: hex::encode(invitation.enroll_pub),
            expires: preview.expires,
            name: request.invitee_name.clone(),
            kind: Some(request.kind.as_str().to_string()),
            allow: Some(preview.capabilities.clone()),
            reuse: Some(reuse_json(&preview.reuse)),
            created: Some(now),
        },
        now,
    )?;
    Ok(MintedInvitation {
        invitation,
        token,
        preview,
    })
}

fn reuse_json(reuse: &Reuse) -> Value {
    match reuse {
        Reuse::Once => json!("once"),
        Reuse::N(n) => json!(n),
        Reuse::Reusable => json!("forever"),
    }
}

fn reuse_total(v: Option<&Value>) -> Result<Option<u64>, ()> {
    match v {
        Some(Value::String(s)) if s == "once" => Ok(Some(1)),
        Some(Value::String(s)) if s == "forever" => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or(()),
        _ => Err(()),
    }
}

/// An invitation that can still be claimed: unexpired, not withdrawn, and
/// with claims left. This is the owner-facing listing, never admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outstanding {
    pub key_id: String,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub allow: Option<Vec<String>>,
    pub uses: u64,
    /// `Some(Some(n))` admits n claims, `Some(None)` any number until it
    /// expires, `None` unknown (minted before the limit was recorded).
    pub total: Option<Option<u64>>,
    pub expires: u64,
    pub created: Option<u64>,
}

impl Outstanding {
    pub fn id(&self) -> &str {
        &self.key_id[..self.key_id.len().min(12)]
    }

    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("({})", self.id()))
    }

    pub fn uses_phrase(&self) -> String {
        match self.total {
            Some(Some(t)) => format!("{} of {t} left", t.saturating_sub(self.uses)),
            Some(None) if self.uses == 0 => "any number, not used yet".to_string(),
            Some(None) => format!("any number, {} used", self.uses),
            None => format!("{} used", self.uses),
        }
    }

    pub fn to_json(&self) -> Value {
        let (max, left) = match self.total {
            Some(Some(t)) => (json!(t), json!(t.saturating_sub(self.uses))),
            Some(None) => (json!("forever"), Value::Null),
            None => (Value::Null, Value::Null),
        };
        json!({
            "id": self.id(),
            "name": self.name,
            "kind": self.kind,
            "allow": self.allow,
            "uses": self.uses,
            "maxUses": max,
            "usesLeft": left,
            "expires": self.expires,
            "created": self.created,
        })
    }
}

fn outstanding_from(
    entries: &[ArmedInvitation],
    ledger: &[InvitationLedgerEntry],
    now: u64,
) -> Vec<Outstanding> {
    let mut out: Vec<Outstanding> = entries
        .iter()
        .filter(|e| e.expires > now)
        .filter_map(|e| {
            let line = ledger.iter().find(|l| l.key_id == e.key_id);
            if line.is_some_and(|l| l.withdrawn) {
                return None;
            }
            let uses = line.map_or(0, |l| l.uses);
            let total = reuse_total(e.reuse.as_ref()).ok();
            if let Some(Some(t)) = total {
                if uses >= t {
                    return None;
                }
            }
            Some(Outstanding {
                key_id: e.key_id.clone(),
                name: e.name.clone().filter(|n| !n.trim().is_empty()),
                kind: e.kind.clone(),
                allow: e.allow.clone(),
                uses,
                total,
                expires: e.expires,
                created: e.created,
            })
        })
        .collect();
    out.sort_by(|a, b| a.created.cmp(&b.created).then(a.expires.cmp(&b.expires)));
    out
}

/// Every invitation that can still be claimed on this device, oldest first.
pub fn outstanding(store: &DeviceStore, now: u64) -> Vec<Outstanding> {
    let ledger = store.invitation_ledger(now);
    let entries = store.armed_invitations(now).unwrap_or_default();
    outstanding_from(&entries, &ledger, now)
}

/// Which outstanding invitations a selector names: every one with that name,
/// or the one whose id starts with it (6 hex digits at least).
pub fn select<'a>(all: &'a [Outstanding], selector: &str) -> Vec<&'a Outstanding> {
    let sel = selector.trim();
    if sel.is_empty() {
        return Vec::new();
    }
    let by_name: Vec<_> = all.iter().filter(|o| o.name.as_deref() == Some(sel)).collect();
    if !by_name.is_empty() {
        return by_name;
    }
    let hex = sel.trim_start_matches('(').trim_end_matches(')').to_ascii_lowercase();
    if hex.len() >= 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return all.iter().filter(|o| o.key_id.starts_with(&hex)).collect();
    }
    Vec::new()
}

/// Withdraw one invitation durably. The armed entry is intentionally kept
/// until expiry so a late claimer hears "withdrawn" instead of waiting on a
/// silent room.
pub fn withdraw(
    store: &DeviceStore,
    invitation: &Outstanding,
    now: u64,
) -> std::result::Result<(), crate::recv::store::InvitationRefusal> {
    store.withdraw_invitation(&invitation.key_id, invitation.expires, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    fn owner() -> ring::signature::Ed25519KeyPair {
        let seed = [3u8; 32];
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()
    }

    fn request(kind: InvitationKind) -> InvitationRequest {
        InvitationRequest {
            owner_name: "alice".into(),
            invitee_name: Some("beta".into()),
            kind,
            capabilities: Vec::new(),
            expires_secs: 3600,
            reuse: Reuse::Once,
            ephemeral: false,
            routes: Vec::new(),
            confirm_remote_authority: false,
        }
    }

    #[test]
    fn the_device_default_is_inbox_transfer_only() {
        let preview = preview_request(&request(InvitationKind::Device), 100).unwrap();
        assert_eq!(preview.capabilities, vec!["transfer".to_string()]);
        assert!(!preview.review.requests("mount"));
        assert!(!preview.review.requests("shell"));
    }

    #[test]
    fn a_lifetime_is_bounded_on_both_ends() {
        let mut r = request(InvitationKind::Person);
        r.expires_secs = 0;
        assert!(preview_request(&r, 100).is_err());
        r.expires_secs = MAX_INVITATION_SECS + 1;
        assert!(preview_request(&r, 100).is_err());
        r.expires_secs = MAX_INVITATION_SECS;
        assert!(preview_request(&r, 100).is_ok());
    }

    #[test]
    fn reuse_is_bounded_to_the_wire_limit() {
        let mut r = request(InvitationKind::Runner);
        r.reuse = Reuse::N(0);
        assert!(preview_request(&r, 100).is_err());
        r.reuse = Reuse::N(MAX_REUSE + 1);
        assert!(preview_request(&r, 100).is_err());
        r.reuse = Reuse::N(MAX_REUSE);
        assert!(preview_request(&r, 100).is_ok());
        r.reuse = Reuse::Reusable;
        assert!(preview_request(&r, 100).is_ok());
    }

    #[test]
    fn a_route_needs_an_explicit_scope_and_never_defaults_to_everything() {
        let mut r = request(InvitationKind::Device);
        r.capabilities = vec!["route".into()];
        assert!(preview_request(&r, 100).is_err());
        r.routes = vec!["10.0.0.5/24".into()];
        let preview = preview_request(&r, 100).unwrap();
        assert_eq!(preview.capabilities, vec!["route:10.0.0.0/24".to_string()]);
        assert!(preview.review.requests("route:10.0.0.0/24"));
        assert!(!preview.review.requests("route"));

        let mut no_cap = request(InvitationKind::Device);
        no_cap.routes = vec!["10.0.0.0/24".into()];
        assert!(preview_request(&no_cap, 100).is_err());
    }

    #[test]
    fn owner_equivalent_authority_needs_a_deliberate_confirmation() {
        let mut r = request(InvitationKind::Device);
        r.capabilities = vec!["transfer".into(), "shell".into()];
        assert!(preview_request(&r, 100).is_err());
        r.confirm_remote_authority = true;
        assert!(preview_request(&r, 100).is_ok());
    }

    #[test]
    fn a_runner_is_ephemeral_and_has_a_short_offline_budget() {
        let preview = preview_request(&request(InvitationKind::Runner), 100).unwrap();
        assert!(preview.ephemeral);
        assert_eq!(preview.max_offline, RUNNER_MAX_OFFLINE_SECS);
        assert_eq!(preview.relationship, Relationship::TemporaryWorker);
    }

    #[test]
    fn the_preview_reports_the_scoped_signed_authority() {
        let mut r = request(InvitationKind::Device);
        r.capabilities = vec!["transfer".into(), "route".into(), "mount".into()];
        r.routes = vec!["10.2.0.0/16".into()];
        let preview = preview_request(&r, 100).unwrap();
        assert_eq!(
            preview.review.requested_capabilities,
            vec![
                "mount".to_string(),
                "route:10.2.0.0/16".to_string(),
                "transfer".to_string()
            ]
        );
        assert_eq!(preview.capabilities, preview.review.requested_capabilities);
    }

    #[test]
    fn minting_arms_the_public_key_and_does_not_return_a_separate_seed() {
        let root = std::env::temp_dir().join(format!(
            "invitation-mint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let store = DeviceStore::open(&root);
        let owner = owner();
        let minted = mint_armed(&store, &owner, &request(InvitationKind::Device), 100).unwrap();
        let listed = outstanding(&store, 101);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key_id, hex::encode(minted.invitation.enroll_pub));
        assert_eq!(listed[0].name.as_deref(), Some("beta"));
        assert_eq!(
            minted.preview.capabilities,
            minted.invitation.scoped_caps()
        );
        assert!(minted.token_text().starts_with(INVITE_PREFIX_V2));
        let parsed = filament_cap::ephemeral::parse_invitation(&minted.token_text()).unwrap();
        let owner_pub: [u8; 32] = owner.public_key().as_ref().try_into().unwrap();
        assert!(parsed.verify_against_owner(&owner_pub));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_listing_hides_used_up_withdrawn_and_expired_invitations() {
        use crate::recv::store::InvitationLedgerEntry;
        let entry = |key: &str, name: &str, reuse: Option<Value>, expires: u64| ArmedInvitation {
            key_id: key.repeat(32),
            expires,
            name: Some(name.into()),
            kind: Some("device".into()),
            allow: Some(vec!["transfer".into()]),
            reuse,
            created: Some(10),
        };
        let line = |key: &str, uses: u64, withdrawn: bool| InvitationLedgerEntry {
            key_id: key.repeat(32),
            uses,
            expires: 1_000,
            withdrawn,
        };
        let entries = vec![
            entry("aa", "fresh", Some(json!(20)), 1_000),
            entry("bb", "spent", Some(json!("once")), 1_000),
            entry("cc", "pulled", Some(json!("forever")), 1_000),
            entry("dd", "old", Some(json!(5)), 50),
            entry("ee", "legacy", None, 1_000),
            entry("ff", "forever", Some(json!("forever")), 1_000),
        ];
        let ledger = vec![
            line("aa", 3, false),
            line("bb", 1, false),
            line("cc", 1, true),
            line("ee", 2, false),
            line("ff", 7, false),
        ];
        let out = outstanding_from(&entries, &ledger, 100);
        let names: Vec<_> = out.iter().map(|o| o.label()).collect();
        assert_eq!(names, ["fresh", "legacy", "forever"]);
        assert_eq!(out[0].uses_phrase(), "17 of 20 left");
        assert_eq!(out[0].to_json()["usesLeft"], json!(17));
        assert_eq!(out[1].uses_phrase(), "2 used", "an old entry does not guess its limit");
        assert_eq!(out[1].to_json()["maxUses"], Value::Null);
        assert_eq!(out[2].uses_phrase(), "any number, 7 used");
        assert_eq!(out[2].to_json()["maxUses"], json!("forever"));
    }

    #[test]
    fn a_selector_is_a_name_or_an_id_prefix() {
        let entry = |key: &str, name: &str, expires: u64| ArmedInvitation {
            key_id: key.repeat(32),
            expires,
            name: Some(name.into()),
            kind: Some("device".into()),
            allow: Some(vec!["transfer".into()]),
            reuse: Some(json!(20)),
            created: Some(1),
        };
        let entries = vec![
            entry("ab", "ci", 1_000),
            entry("cd", "ci", 1_000),
            entry("ef", "laptop", 1_000),
        ];
        let out = outstanding_from(&entries, &[], 100);
        assert_eq!(select(&out, "ci").len(), 2, "a name names every invitation made for it");
        assert_eq!(select(&out, "laptop").len(), 1);
        assert_eq!(select(&out, &"cd".repeat(4)).len(), 1);
        assert_eq!(select(&out, &format!("({})", "ef".repeat(3))).len(), 1);
        assert!(select(&out, "abab").is_empty(), "too short to be an id");
        assert!(select(&out, "nobody").is_empty());
        assert!(select(&out, "").is_empty());
    }

    #[test]
    fn withdrawal_removes_it_from_the_listing_but_keeps_the_room_armed() {
        let root = std::env::temp_dir().join(format!(
            "invitation-withdraw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let store = DeviceStore::open(&root);
        let minted = mint_armed(&store, &owner(), &request(InvitationKind::Person), 100).unwrap();
        let listed = outstanding(&store, 101);
        assert_eq!(listed.len(), 1);
        withdraw(&store, &listed[0], 101).unwrap();
        assert!(outstanding(&store, 102).is_empty());
        assert!(store.is_armed(), "the receiver must answer a late claimer");
        assert_eq!(
            store.record_invitation_use(
                &hex::encode(minted.invitation.enroll_pub),
                &Reuse::Once,
                minted.preview.expires,
                102
            ),
            Err(crate::recv::store::InvitationRefusal::Withdrawn)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
