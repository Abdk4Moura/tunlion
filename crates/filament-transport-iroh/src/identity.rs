//! One identity, not two: tunlion's Ed25519 device key -> an iroh endpoint key.
//!
//! # The rule
//!
//! iroh authenticates a connection against an Ed25519 public key called the
//! `EndpointId` (formerly `NodeId`). tunlion already has an Ed25519 device key
//! that the roster, the device certificate and the L3 announce all speak. This
//! module makes the iroh key a *function* of that device key, never a new key to
//! enrol:
//!
//! ```text
//!                      HKDF-SHA256
//! device seed ─────────────────────────► iroh node seed ──► EndpointId
//!      │                                                        │
//!      └──────────── sign(domain || device_pub || EndpointId) ──┘
//!                              IrohBinding
//! ```
//!
//! The [`IrohBinding`] is exchanged as the first framed message on the iroh
//! bidirectional stream (see `transport.rs`), *inside* the iroh-authenticated
//! channel. A relay cannot swap it: it cannot forge the iroh handshake for the
//! node key, and it cannot forge the device signature over the node key.
//!
//! # Why not always reuse the seed directly?
//!
//! [`NodeKeyMode::Direct`] does exactly that: the iroh node key *is* the device
//! key, so `EndpointId == device_pub` and no mapping is needed. It is the
//! simplest possible binding and it is available here for tests and for a host
//! that has decided cross-protocol key reuse is acceptable.
//!
//! The default, [`NodeKeyMode::Derived`], derives a separate Ed25519 key with a
//! domain-separated HKDF. That avoids presenting the same signing key to two
//! protocol stacks with different transcript rules, at the cost of one signed
//! record. Either way the *authorization* root is the device key: a receiver
//! must still check the device public key against the existing certificate /
//! roster, which this module deliberately does not duplicate.
//!
//! # What is deliberately absent
//!
//! There is no `IrohIdentity` file, no key generated on first use and no
//! separate revocation path. If the device key is rotated or revoked, the
//! derived node key and the binding record become worthless with it, because
//! the binding stops verifying. That is the property this module exists to
//! preserve.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use iroh::{EndpointId, PublicKey, SecretKey, Signature};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separation for the derived node key. Changing this changes every
/// derived `EndpointId`, so it is versioned in the string.
pub const NODE_KEY_DOMAIN: &[u8] = b"filament/iroh/node-key/v1";
const NODE_KEY_INFO: &[u8] = b"ed25519-iroh-endpoint";

/// Domain separation for the signed device -> node record.
pub const BINDING_DOMAIN: &[u8] = b"filament/iroh/node-binding/v1";
/// Wire version of [`IrohBinding`].
pub const BINDING_VERSION: u8 = 1;

/// How the iroh node key relates to the device key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKeyMode {
    /// `node_seed = HKDF(device_seed)`, plus a signed mapping. Default.
    Derived,
    /// `node_seed = device_seed`, so `EndpointId == device_pub`.
    Direct,
}

impl NodeKeyMode {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Derived => 1,
            Self::Direct => 2,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Direct => "direct",
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Derived),
            2 => Some(Self::Direct),
            _ => None,
        }
    }
}

/// The device half of the identity: a 32-byte Ed25519 seed and the two keys
/// derived from it.
///
/// The seed is held in [`Zeroizing`], so dropping the identity wipes it. The
/// iroh [`SecretKey`] is constructed on demand rather than stored, so there is
/// one place the secret material can leak from and it is short-lived.
pub struct DeviceIdentity {
    seed: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the seed. The public half is the useful debugging value.
        f.debug_struct("DeviceIdentity")
            .field("device_pub", &hex::encode(self.device_public()))
            .field(
                "node_pub",
                &self.node_public(NodeKeyMode::Derived).to_string(),
            )
            .finish()
    }
}

impl DeviceIdentity {
    /// From the raw 32-byte Ed25519 seed (the same bytes `ring` takes in
    /// `Ed25519KeyPair::from_seed_unchecked`).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
        }
    }

    /// From a PKCS#8 DER document (what `overlay.ed25519` and
    /// `identity.ed25519` hold on disk).
    ///
    /// `ring`'s `Ed25519KeyPair` does not export its seed, so a host that holds
    /// only an in-memory ring keypair cannot call this. That is an honest API
    /// gap, recorded in the design note: the host must load the DER bytes it
    /// wrote, not a keypair it generated and forgot the bytes of.
    ///
    /// Accepts both encodings seen in the tree:
    /// - PKCS#8 v1/v2 with the RFC 8410 nested `OCTET STRING` (`04 20 <seed>`);
    /// - a bare 32-byte private key OCTET STRING.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let seed = parse_pkcs8_seed(der)
            .ok_or_else(|| anyhow!("not an Ed25519 PKCS#8 private key (no 32-byte seed)"))?;
        Ok(Self::from_seed(&seed))
    }

    /// The Ed25519 device public key, 32 bytes. This is the value the roster and
    /// device certificate already name.
    pub fn device_public(&self) -> [u8; 32] {
        SecretKey::from_bytes(&self.seed)
            .public()
            .as_bytes()
            .to_owned()
    }

    /// The Ed25519 device key as an iroh [`PublicKey`].
    pub fn device_public_key(&self) -> PublicKey {
        PublicKey::from_bytes(&self.device_public()).expect("a derived Ed25519 public key")
    }

    /// The iroh node secret for `mode`.
    ///
    /// `Direct` intentionally returns the device seed; see the module docs for
    /// the trade-off.
    pub fn node_secret(&self, mode: NodeKeyMode) -> SecretKey {
        match mode {
            NodeKeyMode::Direct => SecretKey::from_bytes(&self.seed),
            NodeKeyMode::Derived => {
                let hk = Hkdf::<Sha256>::new(Some(NODE_KEY_DOMAIN), self.seed.as_ref());
                let mut out = Zeroizing::new([0u8; 32]);
                hk.expand(NODE_KEY_INFO, out.as_mut())
                    .expect("32 bytes is a valid HKDF-SHA256 output length");
                SecretKey::from_bytes(&out)
            }
        }
    }

    /// The iroh [`EndpointId`] this device presents in `mode`.
    pub fn node_public(&self, mode: NodeKeyMode) -> EndpointId {
        self.node_secret(mode).public()
    }

    /// Build the signed device -> node record for `mode`.
    pub fn binding(&self, mode: NodeKeyMode) -> IrohBinding {
        let mut binding = IrohBinding {
            version: BINDING_VERSION,
            mode,
            device_pub: self.device_public(),
            endpoint_id: self.node_public(mode),
            created: now_secs(),
            sig: [0u8; 64],
        };
        let canonical = binding.canonical();
        let sig = self.node_secret(NodeKeyMode::Direct).sign(&canonical);
        binding.sig = sig.to_bytes();
        binding
    }
}

/// A signed statement: "device `device_pub` presents iroh endpoint
/// `endpoint_id`".
///
/// The signature is made with the DEVICE key. The record itself is not a
/// credential to authorize anything: it only says which node key belongs to
/// which device. Authorization stays where it already is (device certificate /
/// roster / capability checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohBinding {
    pub version: u8,
    pub mode: NodeKeyMode,
    pub device_pub: [u8; 32],
    pub endpoint_id: EndpointId,
    pub created: u64,
    pub sig: [u8; 64],
}

impl IrohBinding {
    /// Bytes that are signed. Field order, width and endianness are fixed here
    /// and mirrored by the tests; a verifier in another language signs exactly
    /// this.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BINDING_DOMAIN.len() + 2 + 32 + 32 + 8);
        out.extend_from_slice(BINDING_DOMAIN);
        out.push(self.version);
        out.push(self.mode.as_byte());
        out.extend_from_slice(&self.device_pub);
        out.extend_from_slice(self.endpoint_id.as_bytes());
        out.extend_from_slice(&self.created.to_le_bytes());
        out
    }

    /// Verify the device signature and the record's shape.
    ///
    /// This does NOT check whether the device is trusted, certified or enrolled.
    /// The caller must do that with `device_pub` through the existing identity
    /// layer.
    pub fn verify(&self) -> Result<()> {
        if self.version != BINDING_VERSION {
            bail!(
                "unsupported iroh binding version {} (expected {})",
                self.version,
                BINDING_VERSION
            );
        }
        if NodeKeyMode::from_byte(self.mode.as_byte()).is_none() {
            bail!("invalid iroh binding key mode");
        }
        let device = PublicKey::from_bytes(&self.device_pub)
            .map_err(|_| anyhow!("iroh binding names an invalid device public key"))?;
        let signature = Signature::from_bytes(&self.sig);
        device
            .verify(&self.canonical(), &signature)
            .map_err(|_| anyhow!("iroh binding signature does not verify"))
    }

    /// Verify the signature AND that this record is the one `identity` would
    /// produce: same device key, same derived node id, same mode.
    ///
    /// Used by the owner's own tests and by any local check that still has the
    /// seed. A peer without the seed uses [`Self::verify`] only.
    pub fn verify_for(&self, identity: &DeviceIdentity) -> Result<()> {
        self.verify()?;
        if self.device_pub != identity.device_public() {
            bail!("iroh binding names a different device key");
        }
        if self.endpoint_id != identity.node_public(self.mode) {
            bail!("iroh binding endpoint id does not match the derived node key");
        }
        Ok(())
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "v": self.version,
            "mode": self.mode.as_str(),
            "devicePub": hex::encode(self.device_pub),
            "endpointId": self.endpoint_id.to_string(),
            "created": self.created,
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let v = value
            .get("v")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("iroh binding: missing v"))?;
        // Reject before narrowing: `v as u8` would turn 257 into a pass.
        if v != BINDING_VERSION as u64 {
            bail!("iroh binding: unsupported version {v} (expected {BINDING_VERSION})");
        }
        let mode = match value.get("mode").and_then(|v| v.as_str()) {
            Some("derived") => NodeKeyMode::Derived,
            Some("direct") => NodeKeyMode::Direct,
            other => bail!("iroh binding: unknown mode {other:?}"),
        };
        let device_pub = fixed_hex::<32>(value, "devicePub")?;
        let endpoint_id: EndpointId = value
            .get("endpointId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("iroh binding: missing endpointId"))?
            .parse()
            .context("iroh binding: endpointId is not an iroh public key")?;
        let created = value
            .get("created")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("iroh binding: missing created"))?;
        let sig = fixed_hex::<64>(value, "sig")?;
        Ok(Self {
            version: v as u8,
            mode,
            device_pub,
            endpoint_id,
            created,
            sig,
        })
    }
}

fn fixed_hex<const N: usize>(value: &serde_json::Value, field: &str) -> Result<[u8; N]> {
    let text = value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("iroh binding: missing {field}"))?;
    let bytes = hex::decode(text).with_context(|| format!("iroh binding: {field} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("iroh binding: {field} is not {N} bytes"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --------------------------------------------------------------- PKCS#8/DER --

/// Minimal DER walker for the one structure we need. It accepts:
///
/// ```text
/// SEQUENCE {
///   INTEGER 0
///   SEQUENCE { OID 1.3.101.112 }        -- Ed25519
///   OCTET STRING { OCTET STRING seed }  -- RFC 8410
///   [1] BIT STRING public             -- optional (v2)
/// }
/// ```
///
/// Rejecting anything that is not Ed25519 matters: silently treating a P-256 or
/// RSA key's bytes as a seed would produce a valid-looking identity with no
/// relationship to the device the user enrolled.
fn parse_pkcs8_seed(der: &[u8]) -> Option<[u8; 32]> {
    let (tag, seq, _) = read_tlv(der, 0)?;
    if tag != 0x30 || seq.len() < 3 {
        return None;
    }

    // Outer fields.
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < seq.len() {
        let (tag, content, next) = read_tlv(seq, offset)?;
        fields.push((tag, content));
        offset = next;
    }

    // fields[1] is the AlgorithmIdentifier; require the Ed25519 OID.
    let (alg_tag, alg) = *fields.get(1)?;
    if alg_tag != 0x30 {
        return None;
    }
    let (oid_tag, oid, _) = read_tlv(alg, 0)?;
    if oid_tag != 0x06 || oid != [0x2b, 0x65, 0x70] {
        return None;
    }

    // fields[2] is the privateKey OCTET STRING.
    let (pk_tag, pk) = *fields.get(2)?;
    if pk_tag != 0x04 {
        return None;
    }
    if pk.len() == 32 {
        return pk.try_into().ok();
    }
    // RFC 8410: OCTET STRING wrapping CurvePrivateKey (a 32-byte OCTET STRING).
    let (inner_tag, inner, _) = read_tlv(pk, 0)?;
    if inner_tag == 0x04 && inner.len() == 32 {
        return inner.try_into().ok();
    }
    None
}

/// Read one DER TLV. Returns `(tag, content, next_offset)`.
fn read_tlv(buf: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.get(offset)?;
    let first_len = *buf.get(offset + 1)?;
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *buf.get(offset + 2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let start = offset.checked_add(header)?;
    let end = start.checked_add(len)?;
    let content = buf.get(start..end)?;
    Some((tag, content, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST VECTOR ONLY — a freshly generated key used by no deployment.
    /// DER: 302e020100300506032b657004220420<seed>
    const TEST_SEED: [u8; 32] = [
        0x1f, 0x56, 0x84, 0x3c, 0x36, 0x16, 0x72, 0x86, 0x2e, 0x25, 0x95, 0x40, 0x81, 0xb8, 0x88,
        0xf7, 0x92, 0x1f, 0x08, 0x8b, 0x53, 0xec, 0xb6, 0x43, 0xdb, 0x6a, 0xdb, 0xe7, 0xcb, 0xb3,
        0x12, 0xe5,
    ];
    const TEST_DEVICE_PUB: [u8; 32] = [
        0x15, 0x72, 0x0a, 0x1f, 0xcb, 0x5f, 0xdd, 0x97, 0xcb, 0x18, 0x11, 0x7c, 0x20, 0xb2, 0xbe,
        0x51, 0x45, 0xb1, 0x06, 0x8e, 0xf3, 0x5f, 0xa9, 0x2c, 0xe3, 0x0e, 0x0a, 0xcc, 0x2b, 0xd6,
        0x4e, 0x19,
    ];

    fn test_der() -> Vec<u8> {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(&TEST_SEED);
        der
    }

    #[test]
    fn seed_derivation_matches_openssl_public_key() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        assert_eq!(id.device_public(), TEST_DEVICE_PUB);
    }

    #[test]
    fn pkcs8_round_trips_the_same_identity() {
        let from_der = DeviceIdentity::from_pkcs8_der(&test_der()).unwrap();
        assert_eq!(from_der.device_public(), TEST_DEVICE_PUB);
        assert_eq!(
            from_der.node_public(NodeKeyMode::Derived),
            DeviceIdentity::from_seed(&TEST_SEED).node_public(NodeKeyMode::Derived)
        );
    }

    #[test]
    fn pkcs8_rejects_a_non_ed25519_algorithm() {
        // Same shape, wrong OID (1.2.840.10045.2.1, ecPublicKey).
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        // flip the OID to 2a8648ce3d0201 is a different length; instead corrupt
        // the Ed25519 OID's first byte so it no longer matches.
        der[11] = 0x2a;
        der.extend_from_slice(&TEST_SEED);
        assert!(DeviceIdentity::from_pkcs8_der(&der).is_err());
    }

    #[test]
    fn derived_node_key_is_not_the_device_key() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        assert_ne!(
            id.node_public(NodeKeyMode::Derived).as_bytes(),
            &TEST_DEVICE_PUB
        );
    }

    #[test]
    fn direct_mode_endpoint_id_is_the_device_key() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        assert_eq!(
            id.node_public(NodeKeyMode::Direct).as_bytes(),
            &TEST_DEVICE_PUB
        );
        assert!(!id.binding(NodeKeyMode::Direct).canonical().is_empty());
    }

    #[test]
    fn binding_verifies_and_tampering_fails() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        for mode in [NodeKeyMode::Derived, NodeKeyMode::Direct] {
            let binding = id.binding(mode);
            binding.verify().unwrap();
            binding.verify_for(&id).unwrap();

            let mut tampered = binding.clone();
            tampered.endpoint_id =
                DeviceIdentity::from_seed(&[7u8; 32]).node_public(NodeKeyMode::Derived);
            assert!(tampered.verify().is_err(), "endpoint id swap must fail");

            let mut tampered = binding.clone();
            tampered.created ^= 1;
            assert!(tampered.verify().is_err(), "created swap must fail");

            let mut tampered = binding.clone();
            tampered.device_pub = [9u8; 32];
            assert!(tampered.verify().is_err(), "device swap must fail");
        }
    }

    #[test]
    fn binding_survives_the_json_wire_and_still_verifies() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        let binding = id.binding(NodeKeyMode::Derived);
        let wire = binding.to_json();
        let back = IrohBinding::from_json(&wire).unwrap();
        assert_eq!(binding, back);
        back.verify().unwrap();
    }

    #[test]
    fn binding_version_is_not_narrowed_to_a_pass() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        let mut wire = id.binding(NodeKeyMode::Derived).to_json();
        // 257 would become 1 under a `as u8`, so it must be rejected as-is.
        wire["v"] = serde_json::json!(257);
        assert!(IrohBinding::from_json(&wire).is_err());
        wire["v"] = serde_json::json!(0);
        assert!(IrohBinding::from_json(&wire).is_err());
    }

    #[test]
    fn binding_created_is_a_plausible_unix_time() {
        let id = DeviceIdentity::from_seed(&TEST_SEED);
        let binding = id.binding(NodeKeyMode::Derived);
        // 2020-01-01 .. 2200-01-01; catches a seconds/millis mix-up without
        // depending on the wall clock being right.
        assert!((1_577_836_800..7_258_118_400).contains(&binding.created));
    }
}
