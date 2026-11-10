//! The three wire frames of the enrolment ceremony.
//!
//! These are the exact JSON objects the CLI already emits and consumes. They
//! are serde types here so a browser and the CLI cannot drift on field names,
//! and so a frame can be round-tripped through `serde_json::Value` at the
//! signal boundary.

use crate::{EnrolError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every frame the shared ceremony understands. The tag is the `type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameKind {
    #[serde(rename = "enrol-offer")]
    EnrolOffer,
    #[serde(rename = "enrol-grant")]
    EnrolGrant,
    #[serde(rename = "identity-expose")]
    IdentityExpose,
}

impl FrameKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FrameKind::EnrolOffer => "enrol-offer",
            FrameKind::EnrolGrant => "enrol-grant",
            FrameKind::IdentityExpose => "identity-expose",
        }
    }
}

/// A certless device's sealed offer of its device key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolOffer {
    #[serde(rename = "type")]
    pub kind: FrameKind,
    #[serde(default = "offer_version")]
    pub v: u8,
    #[serde(default)]
    pub hold: bool,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub sealed: String,
}

fn offer_version() -> u8 {
    1
}

impl EnrolOffer {
    pub const KIND: FrameKind = FrameKind::EnrolOffer;

    pub fn new(nonce: [u8; 12], sealed: &[u8]) -> Self {
        Self {
            kind: Self::KIND,
            v: 1,
            hold: true,
            nonce: hex::encode(nonce),
            sealed: hex::encode(sealed),
        }
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        let frame: Self = serde_json::from_value(value.clone())
            .map_err(|_| EnrolError::OfferMalformed)?;
        frame.ensure_kind()?;
        Ok(frame)
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| EnrolError::OfferMalformed)
    }

    pub fn ensure_kind(&self) -> Result<()> {
        if self.kind == Self::KIND {
            Ok(())
        } else {
            Err(EnrolError::FrameKind {
                expected: Self::KIND.as_str(),
                got: self.kind.as_str().to_string(),
            })
        }
    }

    pub fn nonce_bytes(&self) -> Result<[u8; 12]> {
        decode_nonce(&self.nonce)
    }

    pub fn sealed_bytes(&self) -> Result<Vec<u8>> {
        decode_sealed(&self.sealed)
    }
}

/// The owner's sealed answer: a device certificate plus the fleet artefacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolGrant {
    #[serde(rename = "type")]
    pub kind: FrameKind,
    #[serde(default = "grant_version")]
    pub v: u8,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub sealed: String,
}

fn grant_version() -> u8 {
    1
}

impl EnrolGrant {
    pub const KIND: FrameKind = FrameKind::EnrolGrant;

    pub fn new(nonce: [u8; 12], sealed: &[u8]) -> Self {
        Self {
            kind: Self::KIND,
            v: 1,
            nonce: hex::encode(nonce),
            sealed: hex::encode(sealed),
        }
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        let frame: Self = serde_json::from_value(value.clone())
            .map_err(|_| EnrolError::GrantMalformed)?;
        frame.ensure_kind()?;
        Ok(frame)
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| EnrolError::GrantMalformed)
    }

    pub fn ensure_kind(&self) -> Result<()> {
        if self.kind == Self::KIND {
            Ok(())
        } else {
            Err(EnrolError::FrameKind {
                expected: Self::KIND.as_str(),
                got: self.kind.as_str().to_string(),
            })
        }
    }

    pub fn nonce_bytes(&self) -> Result<[u8; 12]> {
        decode_nonce(&self.nonce)
    }

    pub fn sealed_bytes(&self) -> Result<Vec<u8>> {
        decode_sealed(&self.sealed)
    }
}

/// A device's certificate and possession proof, sealed under the PAKE key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityExpose {
    #[serde(rename = "type")]
    pub kind: FrameKind,
    #[serde(default = "expose_version")]
    pub v: u8,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub sealed: String,
}

fn expose_version() -> u8 {
    2
}

impl IdentityExpose {
    pub const KIND: FrameKind = FrameKind::IdentityExpose;

    pub fn new(nonce: [u8; 12], sealed: &[u8]) -> Self {
        Self {
            kind: Self::KIND,
            v: 2,
            nonce: hex::encode(nonce),
            sealed: hex::encode(sealed),
        }
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        let frame: Self = serde_json::from_value(value.clone())
            .map_err(|_| EnrolError::ExposeMalformed)?;
        frame.ensure_kind()?;
        Ok(frame)
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| EnrolError::ExposeMalformed)
    }

    pub fn ensure_kind(&self) -> Result<()> {
        if self.kind == Self::KIND {
            Ok(())
        } else {
            Err(EnrolError::FrameKind {
                expected: Self::KIND.as_str(),
                got: self.kind.as_str().to_string(),
            })
        }
    }

    pub fn nonce_bytes(&self) -> Result<[u8; 12]> {
        decode_nonce(&self.nonce)
    }

    pub fn sealed_bytes(&self) -> Result<Vec<u8>> {
        decode_sealed(&self.sealed)
    }
}

pub(crate) fn decode_nonce(text: &str) -> Result<[u8; 12]> {
    if text.is_empty() {
        return Err(EnrolError::NonceMissing);
    }
    let bytes = hex::decode(text).map_err(|_| EnrolError::NonceMissing)?;
    bytes.try_into().map_err(|_| EnrolError::NonceLength)
}

pub(crate) fn decode_sealed(text: &str) -> Result<Vec<u8>> {
    if text.is_empty() {
        return Err(EnrolError::SealedMissing);
    }
    hex::decode(text).map_err(|_| EnrolError::SealedMissing)
}
