use std::fmt;

/// Why the enrolment ceremony refused a frame or a certificate.
///
/// The variants carry the facts needed to decide what to do next, while
/// [`EnrolError::code`] gives vectors and a browser harness a stable string to
/// match on. `Display` keeps the CLI's existing operator-facing wording for the
/// checks that used to be inline in the pairing command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolError {
    /// The PAKE confirmation MAC was not the expected 32 bytes.
    MacLength,
    /// The injected device-key signer returned no signature.
    SigningRefused,
    /// The AEAD seal failed (the key was unusable, or the RNG was not injected).
    SealFailed,
    /// The offer did not open under this ceremony's key.
    OfferSealed,
    /// The offer body was not the expected JSON shape.
    OfferMalformed,
    /// The grant did not open under this ceremony's key.
    GrantSealed,
    /// The grant body was not a JSON object.
    GrantMalformed,
    /// The identity-expose did not open under this ceremony's key.
    ExposeSealed,
    /// The identity-expose body was not the expected JSON shape.
    ExposeMalformed,
    /// A frame's `type` tag did not name the frame being parsed.
    FrameKind {
        expected: &'static str,
        got: String,
    },
    /// The frame's nonce field was absent or empty.
    NonceMissing,
    /// The frame's nonce was not 12 bytes.
    NonceLength,
    /// The frame's sealed field was absent, empty or not hex.
    SealedMissing,
    /// The possession signature did not verify under the offered device key.
    PossessionProofInvalid,
    /// The offer or expose was this device's own key reflected back.
    OwnKeyReflected,
    /// Our own device key could not be read, so a reflection cannot be ruled out.
    OwnKeyUnknown,
    /// This link's DTLS fingerprints were not known yet.
    FingerprintsUnknown,
    /// The grant carried no device certificate.
    NoCertificateInGrant,
    /// The identity-expose carried no device certificate.
    NoCertificateInExpose,
    /// The certificate names a device key other than this device's.
    WrongDeviceKey {
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// The certificate chains to a different owner key than the pinned one.
    WrongOwner {
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// The certificate's lifetime has ended.
    CertExpired { now: u64, expires: u64 },
    /// The certificate signature did not verify.
    CertInvalid(String),
    /// The injected seed store failed.
    SeedStore(String),
    /// The injected random source failed.
    Random(String),
    /// The store held no seed.
    SeedMissing,
    /// The seed was not a valid Ed25519 seed.
    SeedInvalid(String),
    /// A grant payload was not a JSON object.
    GrantPayloadMalformed,
}

impl EnrolError {
    /// A stable identifier for vectors and browser tests. These strings are
    /// wire-visible to the shared `testdata/enrol_vectors.json` fixture.
    pub fn code(&self) -> &'static str {
        match self {
            EnrolError::MacLength => "confirmation-mac-length",
            EnrolError::SigningRefused => "signing-refused",
            EnrolError::SealFailed => "seal-failed",
            EnrolError::OfferSealed => "offer-sealed",
            EnrolError::OfferMalformed => "offer-malformed",
            EnrolError::GrantSealed => "grant-sealed",
            EnrolError::GrantMalformed => "grant-malformed",
            EnrolError::ExposeSealed => "expose-sealed",
            EnrolError::ExposeMalformed => "expose-malformed",
            EnrolError::FrameKind { .. } => "frame-kind",
            EnrolError::NonceMissing => "nonce-missing",
            EnrolError::NonceLength => "nonce-length",
            EnrolError::SealedMissing => "sealed-missing",
            EnrolError::PossessionProofInvalid => "possession-proof-invalid",
            EnrolError::OwnKeyReflected => "own-key-reflected",
            EnrolError::OwnKeyUnknown => "own-key-unknown",
            EnrolError::FingerprintsUnknown => "fingerprints-unknown",
            EnrolError::NoCertificateInGrant => "no-certificate-in-grant",
            EnrolError::NoCertificateInExpose => "no-certificate-in-expose",
            EnrolError::WrongDeviceKey { .. } => "wrong-device-key",
            EnrolError::WrongOwner { .. } => "wrong-owner",
            EnrolError::CertExpired { .. } => "cert-expired",
            EnrolError::CertInvalid(_) => "cert-invalid",
            EnrolError::SeedStore(_) => "seed-store",
            EnrolError::Random(_) => "random",
            EnrolError::SeedMissing => "seed-missing",
            EnrolError::SeedInvalid(_) => "seed-invalid",
            EnrolError::GrantPayloadMalformed => "grant-payload-malformed",
        }
    }
}

impl fmt::Display for EnrolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrolError::MacLength => write!(f, "confirmation MAC is not 32 bytes"),
            EnrolError::SigningRefused => write!(f, "the device key refused to sign"),
            EnrolError::SealFailed => write!(f, "could not seal the frame under this ceremony's key"),
            EnrolError::OfferSealed => write!(f, "seal does not open under this ceremony's key"),
            EnrolError::OfferMalformed => write!(f, "enrol offer body is not the expected JSON shape"),
            EnrolError::GrantSealed => write!(f, "seal does not open under this ceremony's key"),
            EnrolError::GrantMalformed => write!(f, "enrol grant body is not the expected JSON shape"),
            EnrolError::ExposeSealed => write!(f, "seal does not open under this ceremony's key"),
            EnrolError::ExposeMalformed => write!(f, "sealed body is not JSON"),
            EnrolError::FrameKind { expected, got } => {
                write!(f, "expected a {expected} frame, got {got}")
            }
            EnrolError::NonceMissing => write!(f, "nonce missing"),
            EnrolError::NonceLength => write!(f, "nonce is not 12 bytes"),
            EnrolError::SealedMissing => write!(f, "sealed body missing"),
            EnrolError::PossessionProofInvalid => {
                write!(f, "possession signature does not verify for this session")
            }
            EnrolError::OwnKeyReflected => write!(f, "it is this device's own key, reflected back"),
            EnrolError::OwnKeyUnknown => write!(
                f,
                "this device's own key could not be read, so a reflection cannot be ruled out"
            ),
            EnrolError::FingerprintsUnknown => {
                write!(f, "this link's fingerprints are not known")
            }
            EnrolError::NoCertificateInGrant => {
                write!(f, "the enrolment carried no certificate")
            }
            EnrolError::NoCertificateInExpose => write!(f, "no certificate in it"),
            EnrolError::WrongDeviceKey { expected, got } => write!(
                f,
                "the certificate names a different device; refusing it (wanted {}, got {})",
                hex::encode(expected),
                hex::encode(got)
            ),
            EnrolError::WrongOwner { expected, got } => write!(
                f,
                "device cert chains to a different user key (pinned {}, got {})",
                hex::encode(expected),
                hex::encode(got)
            ),
            EnrolError::CertExpired { now, expires } => {
                write!(f, "device cert expired (now {now}, expired at {expires})")
            }
            EnrolError::CertInvalid(why) => write!(f, "{why}"),
            EnrolError::SeedStore(why) => write!(f, "seed store failed: {why}"),
            EnrolError::Random(why) => write!(f, "random source failed: {why}"),
            EnrolError::SeedMissing => write!(f, "no device seed is stored"),
            EnrolError::SeedInvalid(why) => write!(f, "device seed is invalid: {why}"),
            EnrolError::GrantPayloadMalformed => write!(f, "enrol grant payload is not a JSON object"),
        }
    }
}

impl std::error::Error for EnrolError {}

pub type Result<T> = std::result::Result<T, EnrolError>;
