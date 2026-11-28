// #184 guard: `env::var("HOME")` is UNIX-only. On Windows it is unset and a
// read falls back to a literal "." (or a literal "~"), which has twice now
// produced a real bug: the inbox and the share root relocated to the working
// directory, and every Windows device was named "cli". The rule: HOME must
// only be read inside a cfg that excludes Windows. Route platform home
// through Paths::home_dir() (USERPROFILE on Windows) instead.
//
// This test scans the CLI source and fails any `env::var("HOME")` that is not
// inside a unix-only cfg. It is a source-scan heuristic (a windowed look-back
// for the cfg attribute), not a parser: good enough to catch the class, which
// a lint rule must be.

use std::path::Path;

#[test]
fn no_env_home_outside_unix_cfg() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest).join("src");
    let mut offenders: Vec<String> = Vec::new();

    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                check_file(&path, out);
            }
        }
    }

    fn check_file(path: &Path, out: &mut Vec<String>) {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            if line.contains("env::var(\"HOME\")") {
                // The cfg attribute must be within the preceding lines.
                let window_start = idx.saturating_sub(12);
                let window: String = content
                    .lines()
                    .skip(window_start)
                    .take(idx - window_start + 1)
                    .collect::<Vec<_>>()
                    .join("\n");
                let guarded = ["#[cfg(unix)]", "cfg(target_os = \"linux\"", "cfg(target_os = \"macos\""]
                    .iter()
                    .any(|attr| window.contains(attr));
                if !guarded {
                    out.push(format!("{}:{}", path.display(), idx + 1));
                }
            }
        }
    }

    walk(&src, &mut offenders);

    assert!(
        offenders.is_empty(),
        "env::var(\"HOME\") outside a unix-only cfg (breaks Windows):\n  {}",
        offenders.join("\n  ")
    );
}
