//! Join's typed boundary: select the raw input category before code cleanup.
//! Failed invitation/file handling never retries the input as a spoken code.

use std::path::PathBuf;
use zeroize::Zeroizing;

const CODE_LIMIT: usize = 48;

#[derive(PartialEq, Eq)]
pub(crate) struct PairingCode(String);

impl PairingCode {
    pub(crate) fn into_string(self) -> String { self.0 }

    /// An explicitly code-only surface (e.g. --word). No invitation routing or
    /// filesystem probing is possible here, but recognizable material is refused.
    pub(crate) fn checked_text(raw: &str) -> Result<String, CodeError> {
        if invitation_material(raw) { return Err(CodeError::ReservedMaterial); }
        if reserved_code_path(raw) { return Err(CodeError::ReservedPath); }
        let normalized = Self::normalize(raw);
        if normalized.len() > CODE_LIMIT { return Err(CodeError::TooLong); }
        Ok(normalized)
    }

    /// Code-only presentation cleanup. No truncation, file lookup or token parsing.
    /// Keeping a trailing separator is useful while editing between words.
    pub(crate) fn format_partial(raw: &str) -> String {
        crate::pake::format_code_input(raw)
    }

    pub(crate) fn normalize(raw: &str) -> String {
        crate::pake::canonical_code_input(raw)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct TransferCode(String);

pub(crate) struct InvitationMaterial(Zeroizing<String>);

impl InvitationMaterial {
    pub(crate) fn into_secret(self) -> Zeroizing<String> { self.0 }
}

impl PartialEq for InvitationMaterial {
    fn eq(&self, other: &Self) -> bool { self.0.as_str() == other.0.as_str() }
}
impl Eq for InvitationMaterial {}

#[derive(PartialEq, Eq)]
pub(crate) struct InvitationPath(PathBuf);

impl InvitationPath {
    pub(crate) fn into_path(self) -> PathBuf { self.0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodeError { TooLong, ReservedMaterial, ReservedPath }

impl CodeError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::TooLong => "Codes are limited to 48 characters after normalization; nothing was truncated. Shorten the code.",
            Self::ReservedMaterial => "That is invitation material, not a spoken code. Use tunlion join with a file or hidden input.",
            Self::ReservedPath => "That is a path or URL, not a spoken code. Use tunlion join with an invitation file.",
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) enum JoinInput {
    Code(PairingCode),
    TransferCode(TransferCode),
    File(InvitationPath),
    Invitation(InvitationMaterial),
    InvalidCode(CodeError),
    Unknown,
}

impl std::fmt::Debug for JoinInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Code(_) => "Code(<hidden>)",
            Self::TransferCode(_) => "TransferCode(<hidden>)",
            Self::File(_) => "File(<hidden>)",
            Self::Invitation(_) => "Invitation(<hidden>)",
            Self::InvalidCode(_) => "InvalidCode(<hidden>)",
            Self::Unknown => "Unknown",
        })
    }
}

pub(crate) fn trim_input(raw: &str) -> &str {
    raw.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}').trim_end()
}

/// This is a routing reservation, not a claim that a credential is valid.
/// In particular malformed/unsupported JSON and old token forms stay here.
pub(crate) fn invitation_material(raw: &str) -> bool {
    let t = trim_input(raw);
    // Copy/paste wrappers must not let a reserved token/JSON become a code.
    // Do not strip path/URI syntax or JSON openers while probing the category.
    let probe = t.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()
        && !matches!(c, '/' | '\\' | '~' | ':' | '.' | '{' | '[' | '"'));
    let prefix = |p: &str| [t, probe].iter().any(|s|
        s.get(..p.len()).is_some_and(|s| s.eq_ignore_ascii_case(p)));
    prefix("filament-") || prefix("tlninv") || prefix("tunlion-invite")
        || t.starts_with(['{', '[', '"']) || probe.starts_with(['{', '[', '"'])
}

fn known_credential_extension(text: &str) -> bool {
    text.rsplit_once('.').is_some_and(|(stem, extension)| {
        !stem.is_empty()
            && !extension.is_empty()
            && extension.len() <= 12
            && matches!(extension.to_ascii_lowercase().as_str(),
                "txt" | "json" | "inv" | "invite" | "key" | "pem" | "crt" | "yaml" | "yml" |
                "toml" | "conf" | "cfg" | "env" | "token" | "cred" | "credential")
    })
}

/// Path syntax, not every dot: `brave.otter.3141` is a code whose separators the
/// code boundary cleans, while `./x`, `dir/x`, a drive/UNC path or a credential
/// filename is unambiguously a file. An existing file is also a path (checked by
/// the caller). Missing files stay in this category and never retry as a code.
pub(crate) fn invitation_path(raw: &str) -> bool {
    let t = trim_input(raw);
    t.contains('/') || t.contains('\\') || t.starts_with('~') || known_credential_extension(t)
}

/// Explicit code-only readers must also reserve a bare colon (key/value or URL).
pub(crate) fn reserved_code_path(raw: &str) -> bool {
    invitation_path(raw) || trim_input(raw).contains(':')
}

pub(crate) fn classify_join_input(raw: &str, is_file: &dyn Fn(&str) -> bool) -> JoinInput {
    let t = trim_input(raw);
    if t.is_empty() { return JoinInput::Unknown; }
    if invitation_material(t) {
        return JoinInput::Invitation(InvitationMaterial(Zeroizing::new(t.to_string())));
    }
    // URI/key syntax is not a spoken code. A Windows drive path is handled as
    // a path below, but a scheme URL must not be opened as an invitation file.
    if t.contains("://") || t.starts_with("//") {
        return JoinInput::Unknown;
    }
    if is_file(t) || invitation_path(t) {
        return JoinInput::File(InvitationPath(PathBuf::from(t)));
    }
    if t.contains(':') { return JoinInput::Unknown; }
    let normalized = PairingCode::normalize(t);
    if normalized.len() > CODE_LIMIT {
        return JoinInput::InvalidCode(CodeError::TooLong);
    }
    if crate::token_is_pairing_code(&normalized) {
        return JoinInput::Code(PairingCode(normalized));
    }
    if crate::regex_lite_code(&normalized) {
        return JoinInput::TransferCode(TransferCode(normalized));
    }
    JoinInput::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_code_candidates_receive_separator_cleanup() {
        for raw in ["brave otter 3141", "brave__otter!3141", "---BRAVE@@otter---3141--"] {
            match classify_join_input(raw, &|_| false) {
                JoinInput::Code(code) => assert_eq!(code.into_string(), "brave-otter-3141"),
                other => panic!("expected a code, got {other:?}"),
            }
        }
        assert_eq!(PairingCode::format_partial("brave___"), "brave-");
    }

    #[test]
    fn malformed_credentials_cannot_fall_through_to_a_code() {
        for raw in ["filament-invite:brave-otter-3141", "FILAMENT-broken-otter-3141",
                    "TLNINV-brave-otter-3141", "tunlion-invite-brave-otter-3141",
                    "[\"brave-otter-3141\"]", "{brave-otter-3141}", "\"brave-otter-3141\"",
                    "`[\"brave-otter-3141\"]`", "'TLNINV-brave-otter-3141'"] {
            let result = classify_join_input(raw, &|_| panic!("credential must precede file lookup"));
            match result {
                JoinInput::Invitation(material) => assert_eq!(material.into_secret().as_str(), raw),
                other => panic!("credential crossed categories: {other:?}"),
            }
        }
    }

    #[test]
    fn missing_paths_never_become_codes_and_existing_names_win() {
        for path in ["./brave-otter-3141", "brave/otter/3141", "invite.txt",
                     "/brave-otter-3141", "C:\\brave-otter-3141", "~/brave-otter-3141"] {
            match classify_join_input(path, &|_| false) {
                JoinInput::File(file) => assert_eq!(file.into_path(), PathBuf::from(path)),
                other => panic!("missing path crossed categories: {other:?}"),
            }
        }
        // A dotted code is cleaned as a code, not mistaken for a missing file.
        match classify_join_input("brave.otter.3141", &|_| false) {
            JoinInput::Code(code) => assert_eq!(code.into_string(), "brave-otter-3141"),
            other => panic!("dotted code crossed categories: {other:?}"),
        }
        assert!(matches!(classify_join_input("brave-otter-3141", &|_| true), JoinInput::File(_)));
    }

    #[test]
    fn code_limit_is_after_cleanup_without_truncation() {
        let code = format!("{}-{}-1234", "a".repeat(20), "b".repeat(22));
        assert_eq!(code.len(), 48);
        assert!(matches!(classify_join_input(&format!("--{code}--"), &|_| false), JoinInput::Code(_)));
        assert!(matches!(classify_join_input(&format!("x{code}"), &|_| false), JoinInput::InvalidCode(CodeError::TooLong)));
        // Never truncate a final digit into a transfer-code suffix.
        assert!(matches!(classify_join_input(&format!("{code}9"), &|_| false), JoinInput::InvalidCode(_)));
    }

    #[test]
    fn typed_payloads_and_debug_do_not_reveal_material() {
        for raw in ["filament-invite:v2:hidden", "[\"brave-otter-3141\"]", "brave-otter-3141",
                    "brave-otter-314", "./brave-otter-3141"] {
            assert!(!format!("{:?}", classify_join_input(raw, &|_| false)).contains(raw));
        }
        assert!(matches!(classify_join_input("https://host/brave-otter-3141", &|_| false), JoinInput::Unknown));
        assert!(matches!(classify_join_input("key:brave-otter-3141", &|_| false), JoinInput::Unknown));
    }

    #[test]
    fn explicit_code_only_surfaces_reserve_material_and_paths_before_cleanup() {
        assert_eq!(PairingCode::checked_text("brave.otter!3141").unwrap(), "brave-otter-3141");
        for raw in ["./brave-otter-3141", "brave/otter/3141", "secret.key", "https://host/token"] {
            assert_eq!(PairingCode::checked_text(raw), Err(CodeError::ReservedPath));
        }
        for raw in ["[\"brave-otter-3141\"]", "filament-invite:brave-otter-3141"] {
            assert_eq!(PairingCode::checked_text(raw), Err(CodeError::ReservedMaterial));
        }
        assert_eq!(PairingCode::checked_text(&"a".repeat(49)), Err(CodeError::TooLong));
    }
}
