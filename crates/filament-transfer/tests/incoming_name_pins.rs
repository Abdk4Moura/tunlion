//! `safe_incoming_name` decides where a peer's file lands. Found by the
//! mutation probe (.github/workflows/mutants.yml): the dot-name and
//! empty-name refusals could be weakened with every test green, because no
//! test reached them through a name that only BECOMES "." or ".." (or empty)
//! after control bytes are stripped. `Path::file_name` already rejects a bare
//! "..", so the stripping step is the only way to produce one, and it is the
//! case a hostile sender would use.

use filament_transfer::safe_incoming_name;

/// A name that is "." or ".." once control bytes are removed would make the
/// receiver write to its drop directory itself or to the directory ABOVE it.
#[test]
fn names_that_strip_to_dot_or_dotdot_are_replaced() {
    assert_eq!(safe_incoming_name("..\u{7}"), "file.bin", "strips to '..' (parent directory)");
    assert_eq!(safe_incoming_name("\u{1}.\u{1}.\u{1}"), "file.bin");
    assert_eq!(safe_incoming_name(".\u{7}"), "file.bin", "strips to '.' (the drop directory)");
    assert_eq!(safe_incoming_name("x/..\u{0}"), "file.bin");
}

/// A name made only of control bytes must not become the empty string, which
/// joined onto the drop directory names the directory itself.
#[test]
fn names_that_strip_to_nothing_are_replaced() {
    assert_eq!(safe_incoming_name("\u{1}\u{2}\u{3}"), "file.bin");
    assert_eq!(safe_incoming_name("dir/\u{7f}"), "file.bin");
}

/// Ordinary names, including ones that merely contain dots, are kept.
#[test]
fn ordinary_dotted_names_are_kept() {
    assert_eq!(safe_incoming_name("...txt"), "...txt");
    assert_eq!(safe_incoming_name(".bashrc"), ".bashrc");
    assert_eq!(safe_incoming_name("a\u{7}b.txt"), "ab.txt");
}
