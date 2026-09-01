// Refusal microcopy for capabilities a key may not carry.
//
// This module used to render a guided `filament mint` form with three key types
// (Fleet / External / CI) and its own capability toggles. That verb is gone:
// minting collapsed into `filament ephemeral mint`, and the guided flow lives in
// `interactive_mint_options` in main.rs, next to the code that actually mints.
//
// The form was never wired into the Commands enum, so when the verb went away
// roughly 400 lines kept rendering a UI for a command clap no longer accepted,
// including the strings `printed_hints_name_verbs_that_exist` failed CI on.
// Rewriting those strings would have kept dead code and made it read as current,
// which is the more expensive mistake, so the form is deleted and only the one
// reachable function remains.
//
// The deleted tests went with the form they described. One asserted the form's
// emitted capabilities were a subset of CANONICAL_CAPABILITIES; that check now
// lives where capabilities are actually parsed (`mint_capability` in main.rs),
// and it is a DIFFERENT namespace besides: ephemeral auth-key capabilities
// include `all-ports`, which is not a canonical device capability.

use crate::ui::{self, Tone};

/// Non-TTY error: mesh is not a grantable capability.
///
/// The refusal happens at the verifier, not at argument parsing, so this text is
/// the user-facing half of a rule that holds regardless of who signed the key.
pub fn err_mesh_not_grantable() -> (String, i32) {
    (
        format!(
            "{err}\n{fix}",
            err = ui::paint(Tone::Err, &format!("{} mesh is never grantable by a key / a runner or borrower can't join your L3 overlay.", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "(Refused at the verifier regardless of signature. Not a flag; there's no override.)"),
        ),
        super::EXIT_REFUSED,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn err_mesh_not_grantable_exit_code() {
        let (msg, code) = err_mesh_not_grantable();
        assert!(msg.contains("mesh"), "must mention mesh");
        assert_eq!(code, 1, "refused-by-model = exit 1");
    }
}
