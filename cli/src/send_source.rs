//! CLI adapter over `filament_peerloop::send::source`.
//!
//! The source facts (regular-file rule, whole-file digest, the mid-transfer read
//! marker and the cancel frame) live in the library so the Core sender and the
//! CLI cannot disagree about what is offerable. This file only maps the
//! library's typed refusal to the CLI's usage exit and re-exports the pure
//! helpers under their old names.

use crate::exit_codes::{self, ExitKind};
use anyhow::Result;

pub(crate) use filament_peerloop::send::source::{
    SourceRead, as_source_read, cancel_msg, digest_reader, source_read,
};

/// The whole-file SHA-256 of a source about to be offered. A library refusal is
/// a usage error (exit 2): the local input is wrong, nothing has been contacted.
pub(crate) fn source_digest(
    path: &str,
    meta: &std::fs::Metadata,
) -> Result<String> {
    filament_peerloop::send::source::source_digest(path, meta)
        .map_err(|failure| exit_codes::err(ExitKind::Usage, failure.message))
}

pub(crate) fn unreadable_input(path: &str, e: &std::io::Error) -> anyhow::Error {
    let failure = filament_peerloop::send::source::unreadable_input(path, e);
    exit_codes::err(ExitKind::Usage, failure.message)
}

pub(crate) fn not_regular_input(path: &str) -> anyhow::Error {
    let failure = filament_peerloop::send::source::not_regular_input(path);
    exit_codes::err(ExitKind::Usage, failure.message)
}

/// How a send that ended without a delivery-ack for some file exits. Nothing
/// confirmed at all is "the receiver is gone or never answered" (6); exit 8
/// ("partial") is for when some files were confirmed and others were not.
pub(crate) fn unconfirmed_kind(confirmed: usize, unconfirmed: usize) -> ExitKind {
    if filament_peerloop::send::source::unconfirmed_is_partial(confirmed, unconfirmed) {
        ExitKind::Partial
    } else {
        ExitKind::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_regular_source_is_a_usage_error_naming_the_path() {
        let d = std::env::temp_dir().join(format!("tunlion-src-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let meta = std::fs::metadata(&d).unwrap();
        let e = source_digest(d.to_str().unwrap(), &meta).unwrap_err();
        assert_eq!(exit_codes::classify(&e).code(), 2);
        assert!(e.to_string().contains("not a regular file"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unconfirmed_is_6_unless_something_was_confirmed() {
        assert_eq!(unconfirmed_kind(0, 1).code(), 6);
        assert_eq!(unconfirmed_kind(2, 1).code(), 8);
    }
}
