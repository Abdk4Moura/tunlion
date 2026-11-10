//! Browser-facing device identity.
//!
//! This is a thin, host-free wrapper around the primitives that already exist
//! in `filament-id`: an Ed25519 seed key, a device certificate, the possession
//! message, and the certificate verifier. It adds no crypto of its own.
//!
//! Storage and randomness are injected. The native CLI passes its 0600 key
//! file and ring CSPRNG; a browser passes IndexedDB/localStorage and
//! `crypto.getRandomValues`. The crate itself never opens a file or reads a
//! clock.

use crate::frame::{EnrolOffer, IdentityExpose};
use crate::grant::{
    open_enrol_grant as open_grant_frame, seal_enrol_grant as seal_grant_frame, verify_cert_chain,
    verify_mesh_grant, VerifiedMeshGrant,
};
use crate::offer::{build_enrol_offer, open_enrol_offer};
use crate::expose::{build_identity_expose, open_identity_expose};
use crate::{EnrolError, Result};
use filament_id::{DeviceCert, UserKey};
use serde_json::Value;
use zeroize::Zeroizing;

/// Host-provided seed persistence. The implementation owns the file, the
/// browser storage key or the secure enclave; this crate only asks for the
/// 32-byte Ed25519 seed.
pub trait SeedStore {
    fn load_seed(&self) -> Result<Option<[u8; 32]>>;
    fn store_seed(&self, seed: &[u8; 32]) -> Result<()>;
}

/// Host-provided randomness. A native caller forwards to its OS CSPRNG; a
/// browser forwards to `crypto.getRandomValues`.
pub trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

/// One device's long-term Ed25519 key, its certificate and the owner key it is
/// pinned to.
///
/// `UserKey` is the existing seed-key primitive in `filament-id`; here it holds
/// the DEVICE key. The owner key is never loaded into this type, only pinned as
/// a public key for verification.
pub struct DeviceIdentity {
    key: UserKey,
    device_pub: [u8; 32],
    cert: Option<DeviceCert>,
    pinned_owner: Option<[u8; 32]>,
}

impl DeviceIdentity {
    /// Build an identity from a seed. If a certificate is supplied it must name
    /// this seed's public key; its lifetime is checked when it is used.
    pub fn from_seed(
        seed: &[u8; 32],
        cert: Option<DeviceCert>,
        pinned_owner: Option<[u8; 32]>,
    ) -> Result<Self> {
        let key = UserKey::from_seed(seed).map_err(|err| EnrolError::SeedInvalid(err.to_string()))?;
        let device_pub = key.public_key_bytes();
        if let Some(ref cert) = cert {
            if cert.device_pub != device_pub {
                return Err(EnrolError::WrongDeviceKey {
                    expected: device_pub,
                    got: cert.device_pub,
                });
            }
        }
        Ok(Self {
            key,
            device_pub,
            cert,
            pinned_owner,
        })
    }

    /// Load an existing seed. `Ok(None)` means there is no identity yet, not a
    /// failure: call [`DeviceIdentity::generate`] or
    /// [`DeviceIdentity::load_or_generate`].
    pub fn load(
        store: &dyn SeedStore,
        cert: Option<DeviceCert>,
        pinned_owner: Option<[u8; 32]>,
    ) -> Result<Option<Self>> {
        match store.load_seed()? {
            Some(seed) => {
                let seed = Zeroizing::new(seed);
                Self::from_seed(&seed, cert, pinned_owner).map(Some)
            }
            None => Ok(None),
        }
    }

    /// Generate a fresh 32-byte Ed25519 seed, persist it through the injected
    /// store, and return the identity for it. The seed never leaves this
    /// function unzeroized except through the store's own copy.
    pub fn generate(
        store: &dyn SeedStore,
        rng: &mut dyn RandomSource,
        cert: Option<DeviceCert>,
        pinned_owner: Option<[u8; 32]>,
    ) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut seed[..])?;
        let identity = Self::from_seed(&seed, cert, pinned_owner)?;
        store.store_seed(&seed)?;
        Ok(identity)
    }

    /// Load the stored seed or generate and persist one on first use.
    pub fn load_or_generate(
        store: &dyn SeedStore,
        rng: &mut dyn RandomSource,
        cert: Option<DeviceCert>,
        pinned_owner: Option<[u8; 32]>,
    ) -> Result<Self> {
        if let Some(identity) = Self::load(store, cert.clone(), pinned_owner)? {
            return Ok(identity);
        }
        Self::generate(store, rng, cert, pinned_owner)
    }

    pub fn device_pub(&self) -> [u8; 32] {
        self.device_pub
    }

    pub fn cert(&self) -> Option<&DeviceCert> {
        self.cert.as_ref()
    }

    pub fn pinned_owner(&self) -> Option<[u8; 32]> {
        self.pinned_owner
    }

    /// Sign an arbitrary possession message with this device's key. Prefer the
    /// higher-level [`DeviceIdentity::identity_expose`], which builds the exact
    /// session-bound message the protocol verifies.
    pub fn sign_possession(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.key.keypair().sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// Build this device's sealed offer for one ceremony.
    pub fn enrol_offer(
        &self,
        k: &[u8],
        my_fp: &str,
        their_fp: &str,
        caps_canon: &str,
        scope: u8,
        name: &str,
        nonce: [u8; 12],
    ) -> Result<EnrolOffer> {
        build_enrol_offer(
            k,
            my_fp,
            their_fp,
            caps_canon,
            scope,
            self.device_pub,
            name,
            nonce,
            &|msg| Some(self.sign_possession(msg)),
        )
    }

    /// Build this device's sealed identity-expose for one ceremony. Requires a
    /// certificate: a device with no certificate has nothing to expose.
    pub fn identity_expose(
        &self,
        k: &[u8],
        my_fp: &str,
        their_fp: &str,
        caps_canon: &str,
        scope: u8,
        nonce: [u8; 12],
    ) -> Result<IdentityExpose> {
        let cert = self
            .cert
            .as_ref()
            .ok_or(EnrolError::NoCertificateInExpose)?;
        build_identity_expose(
            k,
            my_fp,
            their_fp,
            caps_canon,
            scope,
            cert,
            nonce,
            &|msg| Some(self.sign_possession(msg)),
        )
    }

    /// Open and verify a grant: the certificate must name THIS device's key and
    /// chain to the pinned owner (when one is pinned) at `now`.
    pub fn open_enrol_grant(
        &self,
        k: &[u8],
        frame: &crate::frame::EnrolGrant,
        now: u64,
    ) -> Result<VerifiedMeshGrant> {
        let payload = open_grant_frame(k, frame)?;
        verify_mesh_grant(&payload, self.device_pub, self.pinned_owner, now)
    }

    /// Verify a peer's certificate against the pinned owner, refusing our own
    /// key reflected back. This is the check a state machine should run before
    /// treating a peer as a fleet sibling.
    pub fn verify_peer_cert(&self, cert: &DeviceCert, now: u64) -> Result<()> {
        if cert.device_pub == self.device_pub {
            return Err(EnrolError::OwnKeyReflected);
        }
        verify_cert_chain(cert, self.pinned_owner, now)
    }

    /// Open a peer's identity-expose and verify it. Convenience over
    /// [`open_identity_expose`] that uses this device's key for the reflection
    /// check.
    pub fn open_peer_expose(
        &self,
        frame: &IdentityExpose,
        k: &[u8],
        fps: Option<(&str, &str)>,
        caps_canon: &str,
        scope: u8,
        now: u64,
    ) -> Result<DeviceCert> {
        open_identity_expose(
            frame,
            k,
            fps,
            caps_canon,
            scope,
            Some(self.device_pub),
            now,
        )
    }

    /// Open a peer's offer. Convenience over [`open_enrol_offer`] that uses this
    /// device's key for the reflection check.
    pub fn open_peer_offer(
        &self,
        frame: &EnrolOffer,
        k: &[u8],
        my_fp: &str,
        their_fp: &str,
        caps_canon: &str,
        scope: u8,
    ) -> Result<[u8; 32]> {
        open_enrol_offer(
            k,
            my_fp,
            their_fp,
            caps_canon,
            scope,
            frame,
            Some(self.device_pub),
        )
    }

    /// Seal an owner-built grant payload under a ceremony key. Exposed here so
    /// an owner-side browser can produce the same frame the CLI does.
    pub fn seal_grant(
        &self,
        k: &[u8],
        payload: Value,
        owner_name: &str,
        nonce: [u8; 12],
    ) -> Result<crate::frame::EnrolGrant> {
        seal_grant_frame(k, payload, owner_name, nonce)
    }
}
