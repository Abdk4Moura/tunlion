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
}
