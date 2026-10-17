//! Reading an auth key without putting it in argv.
//!
//! `tunlion add --for runner --out key` still works, and a file on disk is the
//! right answer when a secret manager mounts one. The friction is that a CI box
//! has to receive the file before it can join, so the one command people expect
//! (`tailscale up --authkey=...`) has no tunlion equivalent. Reading the same
//! material from an environment variable or a file (including stdin) gives that
//! command without making the key an argument: argv lands in `ps` output and in
//! shell history, and env vars do not.
//!
//! Precedence: an explicit `--authkey-file` (or `-` for stdin) wins, then
//! `TUNLION_AUTHKEY`, then `TUNLION_INVITE` (the name the CI workflow already
//! uses). The value is trimmed and held in `Zeroizing` so it does not linger in
//! a freed buffer.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Environment variables checked when no file is named, in order.
pub(crate) const ENV_VARS: [&str; 2] = ["TUNLION_AUTHKEY", "TUNLION_INVITE"];

/// The material, if any, from the explicit path (or stdin for `-`), else from
/// the environment. `Ok(None)` means "no key was offered", not an error.
pub(crate) fn from_env_or_file(explicit: Option<&Path>) -> Result<Option<Zeroizing<String>>> {
    if let Some(path) = explicit {
        let raw = if path == Path::new("-") {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("read the auth key from stdin")?;
            s
        } else {
            std::fs::read_to_string(path)
                .with_context(|| format!("read the auth key from {}", path.display()))?
        };
        return Ok(Some(clean(raw)?));
    }
    for var in ENV_VARS {
        if let Ok(raw) = std::env::var(var) {
            if !raw.trim().is_empty() {
                return Ok(Some(clean(raw)?));
            }
        }
    }
    Ok(None)
}

/// Trim, refuse empties, and hold the result in `Zeroizing`. Pure so the shape
/// is testable without touching the environment.
pub(crate) fn clean(raw: String) -> Result<Zeroizing<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("the auth key is empty");
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn a_key_is_trimmed_and_zeroized_on_drop() {
        let key = clean("  filament-invite:v2:abc\n".to_string()).unwrap();
        assert_eq!(&*key, "filament-invite:v2:abc");
    }

    #[test]
    fn an_empty_key_is_refused_rather_than_sent_as_a_join() {
        let err = clean("   \n".to_string()).unwrap_err().to_string();
        assert!(err.contains("empty"), "{err}");
    }
}
