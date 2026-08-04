//! Speakable pairing wordlists: CLIENT-SIDE minting (spec SS2.0, the
//! load-bearing change). The server NEVER sees or generates these words; it
//! only allocates/matches the numeric nameplate.
//!
//! Entropy: 256 adjectives x 256 animals = 65,536 = 2^16 passwords.
//! Online single-guess = 1/65,536 under burn-on-claim.
//! Words curated for phonetic distinctness (EFF/PGP-style).
//! These lists MUST be byte-identical to frontend/src/lib/words.js.

use rand_core::RngCore;

pub const ADJ: [&str; 256] = [
    "amber", "bold", "brave", "brisk", "calm", "cheery", "chill", "civil",
    "clever", "cosy", "crisp", "daring", "deft", "dewy", "eager", "early",
    "fancy", "fiery", "fleet", "fond", "frank", "free", "fresh", "gentle",
    "giddy", "glad", "golden", "grand", "happy", "hardy", "hasty", "honest",
    "humble", "jolly", "keen", "kind", "lively", "loyal", "lucky", "lunar",
    "mellow", "merry", "mighty", "misty", "neat", "noble", "perky", "plucky",
    "polar", "proud", "quick", "quiet", "rapid", "rosy", "royal", "shiny",
    "snappy", "solid", "spry", "stout", "sunny", "tidy", "witty", "able",
    "actual", "adept", "agile", "alert", "aloft", "ample", "apt", "ardent",
    "avid", "aware", "basic", "blithe", "bonny", "bouncy", "breezy", "bright",
    "bubbly", "buxom", "candid", "chunky", "classy", "comfy", "comic", "composed",
    "cordial", "craggy", "cuddly", "curly", "dainty", "dapper", "dazzling", "decent",
    "dense", "distant", "dopey", "drowsy", "dry", "elegant", "elite", "faint",
    "feeble", "festive", "fickle", "flaky", "flimsy", "fluffy", "foamy", "focused",
    "frosty", "frothy", "frugal", "furry", "fuzzy", "gaudy", "gawky", "genuine",
    "giant", "gifted", "gleaming", "gloomy", "glossy", "glum", "grainy", "greedy",
    "green", "grimy", "gritty", "groggy", "groovy", "grouchy", "grumpy", "gusty",
    "hairy", "hale", "handy", "hearty", "hefty", "hip", "hoarse", "icy",
    "ideal", "idle", "jazzy", "jovial", "joyful", "keenly", "kooky", "lanky",
    "lax", "leafy", "lean", "leery", "legal", "light", "limber", "lime",
    "limp", "livid", "lofty", "loose", "lousy", "lucid", "lumpy", "lurid",
    "lush", "lusty", "mad", "major", "mangy", "manic", "mere", "messy",
    "mild", "milky", "minimal", "minor", "mint", "mod", "moist", "moody",
    "muddy", "muggy", "mundane", "murky", "mushy", "musty", "mute", "narrow",
    "nasty", "naughty", "nervy", "nimble", "nippy", "noisy", "nosy", "novel",
    "oily", "ornate", "pale", "palmy", "peppy", "pesky", "petite", "picky",
    "pithy", "placid", "plump", "plush", "poised", "presto", "prim", "prime",
    "prompt", "pure", "quirky", "ragged", "randy", "rash", "raw", "ready",
    "remote", "ridged", "right", "rigid", "ripe", "risky", "ritzy", "robust",
    "rocky", "roomy", "rough", "round", "rowdy", "rude", "rustic", "rusty",
    "sandy", "saucy", "savvy", "sharp", "sheer", "shifty", "short", "showy",
    "shrewd", "shy", "silken", "silky", "silly", "sleek", "sleepy", "slender",
];

pub const ANIMAL: [&str; 256] = [
    "otter", "panda", "falcon", "lynx", "koala", "heron", "fox", "ibex",
    "marten", "tapir", "badger", "beaver", "bison", "bongo", "camel", "civet",
    "condor", "crane", "dingo", "dove", "eland", "ermine", "ferret", "finch",
    "gecko", "gibbon", "hare", "hawk", "hyrax", "jackal", "kestrel", "kiwi",
    "lemur", "llama", "macaw", "magpie", "mole", "moose", "murre", "newt",
    "ocelot", "okapi", "oriole", "osprey", "owl", "pika", "plover", "puffin",
    "quokka", "rabbit", "raven", "robin", "seal", "shrew", "skink", "sparrow",
    "stoat", "swan", "tern", "toucan", "vole", "wombat", "wren", "zebra",
    "aardvark", "agouti", "akita", "alpaca", "anchovy", "antelope", "armadillo", "baboon",
    "barracuda", "basilisk", "bass", "bat", "beagle", "bee", "bengal", "blenny",
    "boar", "bobcat", "bonobo", "bonito", "boxer", "bronco", "budgie", "buffalo",
    "bulldog", "bullfrog", "bunting", "burro", "butterfly", "buzzard", "calf", "canary",
    "capybara", "caribou", "carp", "catbird", "catfish", "chameleon", "cheetah", "chickadee",
    "chihuahua", "chipmunk", "chow", "cicada", "clam", "clownfish", "cobra", "cockatoo",
    "collie", "conch", "coot", "corgi", "cormorant", "cougar", "cowbird", "coyote",
    "crab", "crayfish", "cricket", "crow", "cuckoo", "curlew", "cuttle", "dachshund",
    "damsel", "darter", "deer", "devil", "dhole", "dikdik", "dipper", "doberman",
    "dogfish", "dolphin", "donkey", "dormouse", "dragonfly", "drake", "dunlin", "eagle",
    "echidna", "eel", "egret", "elephant", "elk", "emu", "fallow", "fennec",
    "firefly", "flamingo", "flounder", "fossa", "frog", "gar", "gazelle", "gerbil",
    "giraffe", "gnat", "gnu", "goat", "goldfinch", "goose", "gopher", "gorilla",
    "gosling", "greyhound", "grouse", "gull", "guppy", "hamster", "hedgehog", "hen",
    "hermit", "hippo", "hornet", "horse", "hound", "hummingbird", "hyena", "iguana",
    "impala", "jackrabbit", "jaguar", "jay", "jellyfish", "jerboa", "junco", "kakapo",
    "kangaroo", "katydid", "kingfisher", "kinkajou", "kite", "kitten", "koi", "krill",
    "lab", "ladybug", "lamb", "lamprey", "lemming", "leopard", "liger", "lion",
    "lizard", "lobster", "locust", "loon", "loris", "louse", "macaque", "mackerel",
    "maggot", "mallard", "maltese", "manatee", "mandrill", "manta", "mare", "marmoset",
    "marmot", "mastiff", "meerkat", "mink", "minnow", "monarch", "mongoose", "monkey",
    "moth", "mouse", "mule", "muskox", "mussel", "mustang", "narwhal", "nautilus",
    "nightjar", "numbat", "nuthatch", "octopus", "olm", "opossum", "orangutan", "orca",
    "oryx", "ostrich", "ox", "oyster", "panther", "parrot", "partridge", "peacock",
];

pub const EXTRA: [&str; 16] = [
    "azure", "cobalt", "coral", "crimson", "emerald", "hazel", "indigo", "ivory",
    "jade", "lilac", "olive", "rose", "ruby", "scarlet", "teal", "violet",
];

/// CSPRNG-uniform pick (rejection-free since all list lengths are powers of two:
/// 256 and 16 are powers of two, so masking is exact and unbiased).
fn pick<'a>(rng: &mut impl RngCore, list: &[&'a str]) -> &'a str {
    let n = list.len() as u32;
    debug_assert!(n.is_power_of_two(), "lists must be powers of two for unbiased pick");
    let mask = n - 1;
    list[(rng.next_u32() & mask) as usize]
}

/// Mint the WORDS half of a spoken code (the password): `adj-animal`.
/// 2^16 (65,536). Uses the OS CSPRNG. The full minted code is `adj-animal-NNN`
/// (3 segments) once the nameplate is appended.
pub fn mint_words() -> String {
    let mut rng = super::os_rng();
    format!("{}-{}", pick(&mut rng, &ADJ), pick(&mut rng, &ANIMAL))
}

/// Mint with a caller RNG (tests/interop only).
pub fn mint_words_with(rng: &mut impl RngCore) -> String {
    format!("{}-{}", pick(rng, &ADJ), pick(rng, &ANIMAL))
}

/// Mint a 3-digit nameplate (the routing suffix the server sees).
/// 100..=999 (900 slots, spec Decision #5). This is the ONLY part of the code
/// that ever reaches the server.
pub fn mint_nameplate() -> String {
    let mut rng = super::os_rng();
    format!("{}", 100 + (rng.next_u32() % 900))
}

/// Mint the four-digit nameplate used by pairing codes. Transfer codes use
/// `mint_nameplate` and must retain their three-digit routing shape.
pub fn mint_pair_nameplate() -> String {
    let mut rng = super::os_rng();
    format!("{}", 1000 + (rng.next_u32() % 9000))
}

/// Assemble the full spoken code the user reads aloud: `<words>-<nameplate>`.
pub fn mint_spoken_code() -> String {
    format!("{}-{}", mint_words(), mint_nameplate())
}

/// Validate a user-chosen password (Decision #3). Rejects if:
///   - Fewer than 2 words (needs at least `adj-animal` shape)
///   - Both words are identical (e.g., "test-test")
///   - It is a known predictable phrase from a small blocklist
///   - It contains the user's own device name or the literal name "anonymous"
///
/// The bar is LOW: burn-on-claim limits the attacker to ~1 online guess, so we
/// only reject the obvious bullseyes. No zxcvbn/comprehensive password check.
/// `raw` is the normalized password (through `norm_code`), `user_name` is the
/// local petname or device name (may be empty). Returns Ok(()) on acceptance or
/// an Err with a user-facing reason to try again.
pub fn validate_chosen_password(raw: &str, user_name: &str) -> Result<(), String> {
    let trimmed = raw.trim_matches('-');
    let parts: Vec<&str> = trimmed.split('-').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 {
        return Err("at least two distinct words (e.g. happy-dolphin or bold-panda)".to_string());
    }
    // Identical words (e.g. test-test, cat-cat): the attacker's first guess is
    // always the repeat, so reject it.
    let words: Vec<&str> = parts.iter().copied().filter(|w| *w != "and" && *w != "the").collect();
    if words.len() < 2 {
        return Err("at least two distinct words; try a different phrase".to_string());
    }
    // Check for any identical pair among the non-filler words.
    for i in 0..words.len() {
        for j in (i + 1)..words.len() {
            if words[i].eq_ignore_ascii_case(words[j]) {
                return Err(format!(
                    "the word '{}' appears twice; pick two different words",
                    words[i]
                ));
            }
        }
    }
    // Small blocklist of the obvious bullseyes (Decision #3).
    let lower = trimmed.to_lowercase();
    for &blocked in BLOCKLIST {
        if lower == blocked {
            return Err(format!("'{raw}' is too predictable; try a less obvious phrase"));
        }
    }
    // Reject if the password contains the user's own name (case-insensitive).
    let name_lower = user_name.trim().to_lowercase();
    if !name_lower.is_empty() && name_lower != "anonymous" {
        for w in &words {
            if w.eq_ignore_ascii_case(&name_lower) {
                return Err(format!(
                    "don't use your own device name ('{name_lower}') in the code; anyone who knows your name would guess it first"
                ));
            }
        }
    }
    Ok(())
}

/// Blocklisted phrases that are too predictable even for single-guess.
/// Hand-curated: obvious bullseyes, common keyboard test strings and bigrams.
static BLOCKLIST: &[&str] = &[
    "hello-world", "let-me-in", "test-test", "test-test-test",
    "open-says-me", "abracadabra", "sesame-open", "trust-no-one",
    "top-secret", "secret-code", "secret-sauce", "no-secret",
    "my-code", "my-password", "the-code", "the-password",
    "pass-word", "enter-now", "let-me", "come-in",
    "good-morning", "good-evening", "good-night", "good-afternoon",
    "thank-you", "you-are-welcome", "how-are-you", "i-am-fine",
    "nice-to-meet-you", "see-you-later", "take-care", "have-fun",
    "love-you", "miss-you", "happy-birthday", "merry-christmas",
    "happy-new-year", "happy-holidays", "best-wishes", "good-luck",
    "one-two", "two-three", "three-four", "four-five",
    "alpha-beta", "beta-gamma", "foo-bar", "baz-qux",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_unique_and_sized() {
        use std::collections::HashSet;
        assert_eq!(ADJ.len(), 256);
        assert_eq!(ANIMAL.len(), 256);
        // 256x256 = 65536 = 2^16, the minted password entropy.
        assert_eq!(ADJ.len() * ANIMAL.len(), 1 << 16);
        let adj_set: HashSet<_> = ADJ.iter().collect();
        let animal_set: HashSet<_> = ANIMAL.iter().collect();
        assert_eq!(adj_set.len(), 256, "ADJ has duplicates");
        assert_eq!(animal_set.len(), 256, "ANIMAL has duplicates");
        // No word appears in both lists (cross-list ambiguity).
        let overlap: Vec<_> = adj_set.intersection(&animal_set).collect();
        assert!(overlap.is_empty(), "words in both lists: {overlap:?}");
    }

    #[test]
    fn nameplate_is_3_digits() {
        for _ in 0..100 {
            let np = mint_nameplate();
            assert!(np.len() == 3, "nameplate not 3 digits: {np}");
            assert!(np.parse::<u32>().unwrap() >= 100);
        }
    }

    #[test]
    fn pair_nameplate_is_4_digits() {
        for _ in 0..100 {
            let np = mint_pair_nameplate();
            assert_eq!(np.len(), 4, "pair nameplate not 4 digits: {np}");
            assert!(np.parse::<u32>().unwrap() >= 1000);
        }
    }

    #[test]
    fn minted_words_are_two_parts() {
        let w = mint_words();
        let parts: Vec<&str> = w.split('-').collect();
        assert_eq!(parts.len(), 2, "adj-animal");
        let full = mint_spoken_code();
        assert_eq!(full.split('-').count(), 3, "adj-animal-NNN");
    }

    #[test]
    fn password_gate_rejects_bullseyes() {
        assert!(validate_chosen_password("hello-world", "").is_err());
        assert!(validate_chosen_password("let-me-in", "").is_err());
        assert!(validate_chosen_password("test-test", "").is_err());
        assert!(validate_chosen_password("foo-bar", "").is_err());
    }

    #[test]
    fn password_gate_rejects_identical_words() {
        assert!(validate_chosen_password("cat-cat", "").is_err());
        assert!(validate_chosen_password("dog-and-dog", "").is_err());
    }

    #[test]
    fn password_gate_rejects_own_name() {
        assert!(validate_chosen_password("brave-otter", "brave").is_err());
        assert!(validate_chosen_password("fleet-moose", "moose").is_err());
    }

    #[test]
    fn password_gate_accepts_good_password() {
        assert!(validate_chosen_password("brave-otter", "").is_ok());
        assert!(validate_chosen_password("bold-panda", "my-laptop").is_ok());
        assert!(validate_chosen_password("gentle-dolphin", "").is_ok());
    }

    #[test]
    fn password_gate_rejects_single_word() {
        assert!(validate_chosen_password("brave", "").is_err());
    }
    /// The file MINUS this test module.
    ///
    /// `include_str!` pulls in the whole file, tests included, so a guard that
    /// scans it matches its own assertion strings and its own explanatory
    /// comments. Both tests below failed on their first run for exactly that
    /// reason: one reported "something constructs a SpokenSas" and quoted a
    /// COMMENT of its own, the other reported the field had become pub because
    /// its own error message contains the pattern it searches for.
    ///
    /// That is the same self-matching defect as a `pgrep -f` pattern matching
    /// the command line of the pgrep that ran it. A detector whose input
    /// contains the detector will report itself.
    fn production_source() -> String {
        let src = include_str!("words.rs");
        let start = src
            .find("#[cfg(test)]")
            .expect("test module marker moved; this guard would scan itself");
        // The module ends at the next top-level closing brace. Everything AFTER
        // it is production too: SpokenSas is DEFINED below this module, which is
        // why an earlier version of this helper truncated at the marker and
        // discarded the very type it guards.
        let rel = src[start..]
            .find("\n}\n")
            .expect("test module has no top-level close; guard cannot delimit itself");
        format!("{}{}", &src[..start], &src[start + rel + 3..])
    }

    // ---- the no-constructor property, ASSERTED rather than merely intended ---
    //
    // cli/src/fleet_ui/pair_ui.rs states that render_pake_words cannot be called
    // because SpokenSas has no constructor, and describes that property as
    // "enforced by the compiler and asserted in filament-pair". The compiler
    // half was true. The assertion did not exist. This is it.
    //
    // Why it matters more than its size: render_pake_words shows three words and
    // tells the user their peer must hear the SAME three. If a SpokenSas could be
    // built from the PAIRING CODE, the screen would present a shared handshake
    // password as if it were a transcript-derived short authentication string,
    // and a middleman who knows the code passes the check. That INVERTS the MITM
    // guard rather than weakening it: the user is told they verified when they
    // did not.
    //
    // The field is private, so today only this crate can construct one, and
    // nothing here does. But `pub fn new`, a `pub` on the field, or a derive that
    // synthesizes construction would each silently reopen it, and the type system
    // cannot warn about a constructor that does not exist yet.
    //
    // So this reads the source and fails when one appears. Brittle to renames,
    // deliberately: a rename produces a loud false alarm, never silent erosion of
    // a security guard. Same shape as the deleted-transition guard in
    // proofs/transport_upgrade_model.py.
    #[test]
    fn spoken_sas_has_no_constructor() {
        let src = production_source();
        let src = src.as_str();
        let start = src.find("pub struct SpokenSas").expect("SpokenSas moved or was renamed");
        let end = src[start..].find("\n}").map(|o| start + o).unwrap_or(src.len());
        let block_start = src[..start].rfind("\n\n").unwrap_or(0);
        let region = &src[block_start..end];

        assert!(
            !region.contains("pub struct SpokenSas(pub "),
            "SpokenSas field became pub: the pairing code can now be rendered as a \
             transcript SAS, which INVERTS the MITM check"
        );

        // The impl block: `words()` is the only method that may exist.
        let impl_start = src.find("impl SpokenSas {").expect("impl SpokenSas moved");
        let impl_end = src[impl_start..].find("\n}").map(|o| impl_start + o).unwrap_or(src.len());
        let imp = &src[impl_start..impl_end];
        for forbidden in ["pub fn new", "pub fn from", "pub const fn", "pub fn try_"] {
            assert!(
                !imp.contains(forbidden),
                "SpokenSas gained a public constructor ({forbidden}). render_pake_words \
                 becomes callable, and if its input can be built from the pairing code \
                 the MITM check is inverted. Derive the SAS from the completed PAKE \
                 transcript, or leave this type unconstructible."
            );
        }
    }

    #[test]
    fn nothing_in_this_crate_constructs_a_spoken_sas() {
        // Even a private constructor inside this crate is enough: the field is
        // crate-visible, so `SpokenSas(v)` compiles anywhere in filament-pair.
        // mint_words() returns exactly the shape that would be wrong to pass.
        let src = production_source();
        let src = src.as_str();
        let uses: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("SpokenSas(") && !l.contains("pub struct"))
            .collect();
        assert!(
            uses.is_empty(),
            "something constructs a SpokenSas: {uses:?}. If this is the transcript \
             derivation finally landing, delete this test and add one that asserts \
             the input comes from the transcript, never from mint_words."
        );
    }

}

// ── Word kinds that must never be confused ──────────────────────────────────
//
// This module mints PAIRING CODES: `adj-animal` plus a nameplate, e.g.
// "brave-otter-42". They are transient SPAKE2 passwords. They are shared over
// the channel being established, they authenticate nothing on their own, and
// they are discarded once the handshake completes.
//
// Two other surfaces in this product also want words, and both are documented
// in docs/ux-copy-final.md. Neither may be built from the vocabulary above:
//
//   SURFACE 2d  spoken words compared aloud AFTER the handshake, to detect a
//               machine in the middle. The copy states "the words are the
//               trust".
//   SURFACE 4a  a 12-word recovery phrase, the copy's "only way back if you
//               LOSE every device".
//
// Wiring either to `mint_words` produces something that looks right and is
// catastrophic, so each gets a newtype with NO public constructor. Passing a
// pairing code where one is expected is a type error, not a plausible screen.
// The types are deliberately uninhabitable until the real derivations exist.

/// Words spoken aloud after a completed handshake so two humans can detect a
/// machine in the middle (docs/ux-copy-final.md SURFACE 2d).
///
/// NOT the pairing code. A pairing code renders IDENTICALLY on both sides under
/// an attacker who knows it, because both sides ran their handshake against that
/// attacker using the same password. Showing it here would have the user confirm
/// a match the attacker guaranteed, under copy telling them those words are what
/// protects them: an undetected MITM converted into a confirmed-safe one.
///
/// There is deliberately NO constructor. The only legitimate one derives from
/// the completed transcript, and that derivation has not been designed. When it
/// is, add `from_transcript(...)` here and nowhere else. Constraints recorded by
/// the security reviewer: a dedicated derivation label rather than reusing
/// `confirm_mac`'s output; direction-independent, since both honest sides must
/// agree; bound to the PAKE key and both fingerprints; the wordlist SIZE stated
/// in the spec, not only the word count, because the security parameter is the
/// collision probability; and the wordlist VISIBLY DISTINCT from the pairing
/// vocabulary, so a wrong wiring does not look identical to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpokenSas(Vec<String>);

impl SpokenSas {
    /// The words, in the order they must be spoken.
    pub fn words(&self) -> &[String] {
        &self.0
    }
}

/// The recovery phrase a user writes down (docs/ux-copy-final.md SURFACE 4a).
///
/// NOT a pairing code. The copy calls this "the only way back if you LOSE every
/// device". A pairing code is a transient handshake password that is never
/// persisted, so building this from `mint_words` hands the user a phrase that
/// recovers nothing, is discovered only when they need it, and cannot be
/// recovered from at that point.
///
/// There is deliberately NO constructor. Identity recovery does not exist yet:
/// `IdentityAction` is Init, Show and Certify only, with no restore, rotate,
/// revoke, guardians or freeze, and there is no phrase generator anywhere in the
/// tree. This type exists BEFORE that surface so the nearest-function reflex
/// fails at compile time rather than in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhrase(Vec<String>);

impl RecoveryPhrase {
    /// The phrase, in order.
    pub fn words(&self) -> &[String] {
        &self.0
    }
}
