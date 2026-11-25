// Shared between `build.rs` (which stamps TUNLION_BUILD_PROFILE) and the
// binary's unit tests (which pin the layouts below). Keep it dependency free.

use std::path::Path;

/// Derive the cargo profile name from a build script's OUT_DIR.
///
/// Cargo does not expose a custom profile name as a stable variable, so we
/// read it from the path. The layout has changed across cargo releases:
///
///   * classic:   `<target>/<profile>/build/<pkg>-<hash>/out`
///   * build-dir: `<target>/<profile>/build/<pkg>/<hash>/out`
///   * cross:     `<target>/<triple>/<profile>/build/...` (either shape)
///
/// Counting a fixed number of ancestors broke when the extra `<hash>` level
/// appeared (the profile came out as `build`). Instead, find the innermost
/// component literally named `build` and return its parent's name. Innermost
/// matters: the checkout itself may live under a directory called `build`.
#[allow(dead_code)]
pub fn profile_from_out_dir(out_dir: &Path) -> Option<String> {
    for dir in out_dir.ancestors() {
        if dir.file_name().is_some_and(|name| name == "build") {
            return dir
                .parent()
                .and_then(|profile| profile.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .filter(|name| !name.is_empty() && name != "build");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::profile_from_out_dir;
    use std::path::PathBuf;

    fn p(parts: &[&str]) -> PathBuf {
        parts.iter().collect()
    }

    #[test]
    fn classic_layout() {
        let out = p(&["/w", "target", "release", "build", "tunlion-0123abcd", "out"]);
        assert_eq!(profile_from_out_dir(&out).as_deref(), Some("release"));
    }

    #[test]
    fn build_dir_layout_with_hash_level() {
        let out = p(&[
            "/w", "target", "release", "build", "tunlion", "0123abcd", "out",
        ]);
        assert_eq!(profile_from_out_dir(&out).as_deref(), Some("release"));
    }

    #[test]
    fn cross_target_and_custom_profile() {
        let out = p(&[
            "/w",
            "target",
            "x86_64-pc-windows-msvc",
            "dist",
            "build",
            "tunlion-ab",
            "out",
        ]);
        assert_eq!(profile_from_out_dir(&out).as_deref(), Some("dist"));
    }

    #[test]
    fn checkout_under_a_build_directory() {
        let out = p(&[
            "/build", "src", "target", "debug", "build", "tunlion", "ab", "out",
        ]);
        assert_eq!(profile_from_out_dir(&out).as_deref(), Some("debug"));
    }

    #[test]
    fn no_build_component() {
        assert_eq!(profile_from_out_dir(&p(&["/w", "out"])), None);
    }
}
