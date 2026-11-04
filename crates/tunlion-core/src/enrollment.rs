//! Invitation APIs: one shared policy, no client-side parsing.
//!
//! The types in this module are the UniFFI records Android binds. They carry no
//! possession seed and no recovery words: an invitation token is returned as
//! opaque bytes, and a preview reports the exact signed ceiling.
//!
//! `join_invitation` runs the real `filament_peerloop::recv::join::drive` on
//! this Core's engine slot. It deliberately does NOT bootstrap an owner
//! identity: a blank device must be able to join, and joining must not make the
//! device an owner.

use crate::{Core, CoreError};
use filament_cap::ephemeral::Reuse;
use filament_id::UserKey;
use filament_peerloop::invitation::{
    self as policy, InvitationKind, InvitationRequest, Outstanding,
};
use filament_peerloop::recv::join::{JoinFailure, JoinRequest, JOIN_BUDGET};
use filament_peerloop::recv::store::{sanitize_device_name, DeviceStore, OverlayKey};
use filament_peerloop::recv::store::CoreLease;
use filament_peerloop::host::{HostServices, LogSink, NoLog};
use filament_peerloop::driver::Cancellation;
use filament_transport::TransportContext;
use std::sync::Arc;
use std::time::Duration;

use crate::host::{CoreHost, CoreSettings};

/// The shared relationship vocabulary, mirrored as a UniFFI enum so Kotlin
/// never invents a second classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EnrollmentRelationship {
    OrdinaryPair,
    OwnDevice,
    OtherPerson,
    TemporaryWorker,
}

impl From<filament_id::enrollment::Relationship> for EnrollmentRelationship {
    fn from(value: filament_id::enrollment::Relationship) -> Self {
        match value {
            filament_id::enrollment::Relationship::OrdinaryPair => Self::OrdinaryPair,
            filament_id::enrollment::Relationship::OwnDevice => Self::OwnDevice,
            filament_id::enrollment::Relationship::OtherPerson => Self::OtherPerson,
            filament_id::enrollment::Relationship::TemporaryWorker => Self::TemporaryWorker,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CoreInvitationKind {
    Device,
    Person,
    Runner,
}

impl From<CoreInvitationKind> for InvitationKind {
    fn from(value: CoreInvitationKind) -> Self {
        match value {
            CoreInvitationKind::Device => Self::Device,
            CoreInvitationKind::Person => Self::Person,
            CoreInvitationKind::Runner => Self::Runner,
        }
    }
}

/// How many claims an invitation admits. `reusable` means no numeric limit;
/// otherwise `max_uses` is the limit (1 for a single use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CoreInvitationReuse {
    pub max_uses: Option<u32>,
    pub reusable: bool,
}

impl CoreInvitationReuse {
    fn to_policy(self) -> Result<Reuse, CoreError> {
        if self.reusable {
            if self.max_uses.is_some() {
                return Err(CoreError::Usage(
                    "an invitation cannot be both reusable and numerically limited".into(),
                ));
            }
            return Ok(Reuse::Reusable);
        }
        match self.max_uses {
            None | Some(1) => Ok(Reuse::Once),
            Some(n) => Ok(Reuse::N(n)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreInvitationInput {
    pub owner_name: String,
    pub invitee_name: Option<String>,
    pub kind: CoreInvitationKind,
    /// Empty means the kind's current default (inbox transfer only). Mount is
    /// an explicit opt-in. The requested ceiling, never an effective access
    /// claim.
    pub capabilities: Vec<String>,
    pub expires_secs: u64,
    pub reuse: CoreInvitationReuse,
    pub ephemeral: bool,
    /// `route:<cidr>` prefixes; required iff the ceiling names `route`.
    pub routes: Vec<String>,
    /// The deliberate confirmation for shell/all-ports.
    pub confirm_remote_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreInvitationPreview {
    pub owner_name: String,
    pub relationship: EnrollmentRelationship,
    /// The exact signed ceiling, with `route` expanded to `route:<cidr>`.
    pub requested_capabilities: Vec<String>,
    pub expires: u64,
    pub max_offline: u64,
    pub max_uses: Option<u32>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub expired: bool,
}

fn reuse_fields(reuse: &Reuse) -> (Option<u32>, bool) {
    match reuse {
        Reuse::Once => (Some(1), false),
        Reuse::N(n) => (Some(*n), false),
        Reuse::Reusable => (None, true),
    }
}

fn preview_from_policy(preview: policy::InvitationPreview) -> CoreInvitationPreview {
    let (max_uses, reusable) = reuse_fields(&preview.reuse);
    CoreInvitationPreview {
        owner_name: preview.owner_name,
        relationship: preview.relationship.into(),
        requested_capabilities: preview.review.requested_capabilities,
        expires: preview.expires,
        max_offline: preview.max_offline,
        max_uses,
        reusable,
        ephemeral: preview.ephemeral,
        expired: preview.expired,
    }
}

fn input_to_policy(input: CoreInvitationInput) -> Result<InvitationRequest, CoreError> {
    Ok(InvitationRequest {
        owner_name: input.owner_name,
        invitee_name: input.invitee_name,
        kind: input.kind.into(),
        capabilities: input.capabilities,
        expires_secs: input.expires_secs,
        reuse: input.reuse.to_policy()?,
        ephemeral: input.ephemeral,
        routes: input.routes,
        confirm_remote_authority: input.confirm_remote_authority,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreOutstandingInvitation {
    pub id: String,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub allow: Option<Vec<String>>,
    pub uses: u64,
    pub max_uses: Option<u64>,
    pub unlimited: bool,
    pub uses_left: Option<u64>,
    pub expires: u64,
    pub created: Option<u64>,
}

fn outstanding_row(value: &Outstanding) -> CoreOutstandingInvitation {
    let (max_uses, unlimited, uses_left) = match value.total {
        Some(Some(total)) => (
            Some(total),
            false,
            Some(total.saturating_sub(value.uses)),
        ),
        Some(None) => (None, true, None),
        None => (None, false, None),
    };
    CoreOutstandingInvitation {
        id: value.id().to_string(),
        name: value.name.clone(),
        kind: value.kind.clone(),
        allow: value.allow.clone(),
        uses: value.uses,
        max_uses,
        unlimited,
        uses_left,
        expires: value.expires,
        created: value.created,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreJoinResult {
    pub name: String,
    pub owner_name: String,
    /// The device public key, hex. Never a private key.
    pub device_pub: String,
    pub ceiling: Vec<String>,
    pub expires: u64,
    pub ephemeral: bool,
}

impl Core {
    /// Preview an invitation token. The bytes are the text file's contents
    /// (`filament-invite:v2:...`); UTF-8 input is required.
    pub fn preview_invitation(&self, bytes: Vec<u8>) -> Result<CoreInvitationPreview, CoreError> {
        let text = String::from_utf8(bytes)
            .map_err(|_| CoreError::Usage("invitation is not UTF-8 text".into()))?;
        let invitation = filament_cap::ephemeral::parse_invitation(&text)
            .map_err(|e| CoreError::Usage(format!("{e:#}")))?;
        Ok(preview_from_policy(policy::preview_invitation(
            &invitation,
            filament_id::now_secs(),
        )))
    }

    /// Preview exactly what a create request would ask for, before minting.
    pub fn preview_invitation_request(
        &self,
        request: CoreInvitationInput,
    ) -> Result<CoreInvitationPreview, CoreError> {
        let request = input_to_policy(request)?;
        let preview = policy::preview_request(&request, filament_id::now_secs())
            .map_err(|e| CoreError::Usage(format!("{e:#}")))?;
        Ok(preview_from_policy(preview))
    }

    /// Mint and arm an invitation. Only the owner identity can do this; a
    /// joined device has no owner key and is refused by name.
    pub fn create_invitation(
        &self,
        request: CoreInvitationInput,
    ) -> Result<Vec<u8>, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let owner = UserKey::load(&store.keystore())
            .map_err(|e| CoreError::Identity(format!("{e:#}")))?
            .ok_or_else(|| {
                CoreError::Identity(
                    "this device has no owner identity; create one before minting an invitation"
                        .into(),
                )
            })?;
        let request = input_to_policy(request)?;
        let minted = policy::mint_armed(&store, owner.keypair(), &request, filament_id::now_secs())
            .map_err(|e| CoreError::Usage(format!("{e:#}")))?;
        Ok(minted.token_text().into_bytes())
    }

    /// Every invitation that can still be claimed on this device.
    pub fn invitations(&self) -> Result<Vec<CoreOutstandingInvitation>, CoreError> {
        let store = DeviceStore::open(&self.dir);
        Ok(policy::outstanding(&store, filament_id::now_secs())
            .iter()
            .map(outstanding_row)
            .collect())
    }

    /// Withdraw invitations by name or id prefix. Returns the labels it
    /// withdrew; an unmatched selector is a usage error, not a silent success.
    pub fn withdraw_invitation(&self, selector: String) -> Result<Vec<String>, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let now = filament_id::now_secs();
        let all = policy::outstanding(&store, now);
        let selected = policy::select(&all, &selector);
        if selected.is_empty() {
            return Err(CoreError::Usage(format!(
                "no outstanding invitation matches '{selector}'"
            )));
        }
        let mut withdrawn = Vec::with_capacity(selected.len());
        for invitation in selected {
            policy::withdraw(&store, invitation, now).map_err(|refusal| {
                CoreError::Config(format!(
                    "could not withdraw {}: {refusal:?}",
                    invitation.label()
                ))
            })?;
            withdrawn.push(invitation.label());
        }
        Ok(withdrawn)
    }

    /// The capability vocabulary this core can express in a signed invitation
    /// and enforce as a ceiling. It is not a claim that every serving backend
    /// (a mount daemon, a PTY) is compiled into this profile.
    pub fn servable_capabilities(&self) -> Vec<String> {
        policy::servable_capabilities()
    }

    /// The device name recorded in this config directory's `config` file.
    pub fn device_name(&self) -> Option<String> {
        DeviceStore::open(&self.dir).device_name()
    }

    /// Set the local device name under the config lock.
    pub fn set_device_name(&self, name: String) -> Result<(), CoreError> {
        let clean = sanitize_device_name(&name);
        if clean.is_empty() {
            return Err(CoreError::Usage("a device name cannot be empty".into()));
        }
        DeviceStore::open(&self.dir)
            .set_device_name(&clean)
            .map_err(|e| CoreError::Config(format!("{e:#}")))
    }

    /// Join an owner's fleet with an invitation file's bytes.
    ///
    /// Blocking, like `receive_code`: the caller's `timeout` is the whole join
    /// budget and defaults to the CLI's 60 seconds. It runs the real shared
    /// join driver on this Core's runtime. A blank config directory is expected
    /// and is NOT turned into an owner: no owner key is minted, and the join
    /// acknowledgement is refused if one appears before it is stored.
    pub fn join_invitation(
        &self,
        bytes: Vec<u8>,
        name: String,
        timeout: Option<u64>,
    ) -> Result<CoreJoinResult, CoreError> {
        let text = String::from_utf8(bytes)
            .map_err(|_| CoreError::Usage("invitation is not UTF-8 text".into()))?;
        let invitation = filament_cap::ephemeral::parse_invitation(&text)
            .map_err(|e| CoreError::Usage(format!("{e:#}")))?;
        if filament_id::now_secs() >= invitation.expires {
            return Err(CoreError::Usage("this invitation has expired".into()));
        }
        let proposed_name = sanitize_device_name(&name);
        if proposed_name.is_empty() {
            return Err(CoreError::Usage("a device name cannot be empty".into()));
        }
        let timeout = timeout.unwrap_or(JOIN_BUDGET.as_secs()).max(1);

        let mut claim = crate::StartClaim::acquire(self)?;
        let (parts, lease) = self.prepare_join(&proposed_name)?;
        let JoinParts {
            server,
            relay,
            transport_context,
            log,
            host,
            store,
            overlay,
        } = parts;

        let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<CoreJoinResult, CoreError>>();
        let dispatch = move |stop: Cancellation, _readiness: filament_peerloop::driver::Readiness| async move {
            let request = JoinRequest {
                server,
                invitation,
                proposed_name,
                peer_name: None,
                relay,
                lease: None,
                timeout: Duration::from_secs(timeout),
                quiet: true,
            };
            let result = filament_peerloop::recv::join::drive(
                request,
                &store,
                &overlay,
                transport_context,
                log,
                host,
                &stop,
            )
            .await;
            let mapped = match result {
                Ok(outcome) => Ok(CoreJoinResult {
                    name: outcome.name,
                    owner_name: outcome.owner_name,
                    device_pub: hex::encode(outcome.device_pub),
                    ceiling: outcome.ceiling,
                    expires: outcome.expires,
                    ephemeral: outcome.ephemeral,
                }),
                Err(JoinFailure::Cancelled) => Err(CoreError::Cancelled),
                Err(JoinFailure::Usage(text)) => Err(CoreError::Usage(text)),
                Err(JoinFailure::Timeout(text)) => Err(CoreError::Unreachable(text)),
                Err(JoinFailure::Denied(text)) => Err(CoreError::Refused(text)),
                Err(JoinFailure::Signaling(text)) | Err(JoinFailure::Storage(text)) => {
                    Err(CoreError::Engine(text))
                }
            };
            let _ = done_tx.send(mapped);
            Ok::<(), String>(())
        };

        let generation = claim.generation();
        let (_handle, engine, _watch) = self.spawn_engine(dispatch)?;
        claim.install(engine)?;
        let published = self.publish_one_shot(lease);
        let result = done_rx.recv().unwrap_or_else(|_| {
            Err(CoreError::Engine(
                "the join dispatch ended without a result".into(),
            ))
        });
        let settled = self.settle_one_shot(generation);
        match result {
            Err(CoreError::Cancelled) => Err(CoreError::Cancelled),
            other => {
                published?;
                settled?;
                other
            }
        }
    }

    fn prepare_join(&self, proposed_name: &str) -> Result<(JoinParts, CoreLease), CoreError> {
        let store = DeviceStore::open(&self.dir);
        let settings =
            CoreSettings::load(&self.dir).map_err(|e| CoreError::Config(e.to_string()))?;
        let server = crate::resolve_server(&settings)?;
        // NO identity bootstrap here. A blank device joining is the normal
        // case; `persist_join_ack` is what refuses a config that gained an
        // owner key while the join was in flight.
        let lease = store
            .try_acquire_engine_lease()
            .map_err(|e| CoreError::Engine(format!("engine lease: {e}")))?
            .ok_or(CoreError::EngineLease)?;
        let display_name = settings
            .get("name")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| proposed_name.to_string());
        let overlay = OverlayKey::new(self.dir.join("overlay.ed25519"));
        let log: Arc<dyn LogSink> = Arc::new(NoLog);
        let host: Arc<dyn HostServices> = Arc::new(CoreHost::new(
            self.dir.clone(),
            store.clone(),
            settings.clone(),
            overlay.clone(),
        ));
        let settings_for_peer = settings.clone();
        let settings_for_membership = settings.clone();
        let transport_context = TransportContext::new(
            Some(self.dir.join("signaling-dns.json")),
            move |key, peer| settings_for_peer.setting(key, peer),
            move |peer| settings_for_membership.membership(peer),
        );
        Ok((
            JoinParts {
                server,
                relay: settings.relay_only(),
                transport_context,
                log,
                host,
                store,
                overlay,
            },
            lease,
        ))
    }
}

struct JoinParts {
    server: String,
    relay: bool,
    transport_context: TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
    store: DeviceStore,
    overlay: OverlayKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: CoreInvitationKind) -> CoreInvitationInput {
        CoreInvitationInput {
            owner_name: "alice".into(),
            invitee_name: Some("beta".into()),
            kind,
            capabilities: Vec::new(),
            expires_secs: 3600,
            reuse: CoreInvitationReuse {
                max_uses: Some(1),
                reusable: false,
            },
            ephemeral: false,
            routes: Vec::new(),
            confirm_remote_authority: false,
        }
    }

    #[test]
    fn a_preview_reports_the_exact_default_ceiling_without_minting() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        let preview = core.preview_invitation_request(input(CoreInvitationKind::Device)).unwrap();
        assert_eq!(preview.requested_capabilities, vec!["transfer".to_string()]);
        assert_eq!(preview.relationship, EnrollmentRelationship::OwnDevice);
        assert!(preview.max_uses == Some(1));
        assert!(!root.path().join("armed.json").exists());
        assert!(!root.path().join("identity.ed25519").exists());
    }

    #[test]
    fn creating_requires_an_owner_identity_and_returns_opaque_bytes() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        assert!(core.create_invitation(input(CoreInvitationKind::Device)).is_err());
        let store = DeviceStore::open(root.path());
        UserKey::generate(&store.keystore()).unwrap();
        let token = core.create_invitation(input(CoreInvitationKind::Device)).unwrap();
        let preview = core.preview_invitation(token).unwrap();
        assert_eq!(preview.owner_name, "alice");
        assert_eq!(preview.requested_capabilities, vec!["transfer".to_string()]);
        assert_eq!(core.invitations().unwrap().len(), 1);
        assert!(!preview.requested_capabilities.iter().any(|c| c == "shell"));
    }

    #[test]
    fn a_route_preview_names_its_prefix_and_never_widens() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        let mut request = input(CoreInvitationKind::Device);
        request.capabilities = vec!["route".into()];
        assert!(core.preview_invitation_request(request.clone()).is_err());
        request.routes = vec!["10.0.0.5/24".into()];
        let preview = core.preview_invitation_request(request).unwrap();
        assert_eq!(
            preview.requested_capabilities,
            vec!["route:10.0.0.0/24".to_string()]
        );
    }

    #[test]
    fn joining_a_malformed_invitation_costs_no_engine_or_identity() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        let error = core
            .join_invitation(b"not an invitation".to_vec(), "phone".into(), Some(1))
            .unwrap_err();
        assert!(matches!(&error, CoreError::Usage(_)), "{error:?}");
        assert!(!root.path().join("identity.ed25519").exists());
        assert!(!root.path().join("identity/device-cert.json").exists());
    }

    #[test]
    fn the_device_name_round_trips_through_the_config_lock() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        assert_eq!(core.device_name(), None);
        core.set_device_name("phone".into()).unwrap();
        assert_eq!(core.device_name().as_deref(), Some("phone"));
        assert!(core.set_device_name("  ".into()).is_err());
    }
}
