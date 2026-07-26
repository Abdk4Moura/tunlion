"""V2 pairing tests: nameplate-only allocation, burn-on-claim, gate verifications.

These exist because the v2-only cutover (Decision #1) removed the server's
word-minting path. The server now only allocates/matches numeric nameplates;
the password NEVER reaches the server (relay-blind). Every test here guards a
security property of the PAKE v2 protocol.

Run:  python -m unittest backend.tests.test_pair_codes
"""
import io
import json as _json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

# Reference client-side wordlist (mirrors pake/words.rs + words.js).
# Used only for leak-checking: the server must NEVER see any of these.
# The words live client-side and the server never mints or receives them.
_PAKE_ADJ = frozenset([
    "amber",
    "bold",
    "brave",
    "brisk",
    "calm",
    "cheery",
    "chill",
    "civil",
    "clever",
    "cosy",
    "crisp",
    "daring",
    "deft",
    "dewy",
    "eager",
    "early",
    "fancy",
    "fiery",
    "fleet",
    "fond",
    "frank",
    "free",
    "fresh",
    "gentle",
    "giddy",
    "glad",
    "golden",
    "grand",
    "happy",
    "hardy",
    "hasty",
    "honest",
    "humble",
    "jolly",
    "keen",
    "kind",
    "lively",
    "loyal",
    "lucky",
    "lunar",
    "mellow",
    "merry",
    "mighty",
    "misty",
    "neat",
    "noble",
    "perky",
    "plucky",
    "polar",
    "proud",
    "quick",
    "quiet",
    "rapid",
    "rosy",
    "royal",
    "shiny",
    "snappy",
    "solid",
    "spry",
    "stout",
    "sunny",
    "tidy",
    "witty",
    "able",
    "actual",
    "adept",
    "agile",
    "alert",
    "aloft",
    "ample",
    "apt",
    "ardent",
    "avid",
    "aware",
    "basic",
    "blithe",
    "bonny",
    "bouncy",
    "breezy",
    "bright",
    "bubbly",
    "buxom",
    "candid",
    "chunky",
    "classy",
    "comfy",
    "comic",
    "composed",
    "cordial",
    "craggy",
    "cuddly",
    "curly",
    "dainty",
    "dapper",
    "dazzling",
    "decent",
    "dense",
    "distant",
    "dopey",
    "drowsy",
    "dry",
    "elegant",
    "elite",
    "faint",
    "feeble",
    "festive",
    "fickle",
    "flaky",
    "flimsy",
    "fluffy",
    "foamy",
    "focused",
    "frosty",
    "frothy",
    "frugal",
    "furry",
    "fuzzy",
    "gaudy",
    "gawky",
    "genuine",
    "giant",
    "gifted",
    "gleaming",
    "gloomy",
    "glossy",
    "glum",
    "grainy",
    "greedy",
    "green",
    "grimy",
    "gritty",
    "groggy",
    "groovy",
    "grouchy",
    "grumpy",
    "gusty",
    "hairy",
    "hale",
    "handy",
    "hearty",
    "hefty",
    "hip",
    "hoarse",
    "icy",
    "ideal",
    "idle",
    "jazzy",
    "jovial",
    "joyful",
    "keenly",
    "kooky",
    "lanky",
    "lax",
    "leafy",
    "lean",
    "leery",
    "legal",
    "light",
    "limber",
    "lime",
    "limp",
    "livid",
    "lofty",
    "loose",
    "lousy",
    "lucid",
    "lumpy",
    "lurid",
    "lush",
    "lusty",
    "mad",
    "major",
    "mangy",
    "manic",
    "mere",
    "messy",
    "mild",
    "milky",
    "minimal",
    "minor",
    "mint",
    "mod",
    "moist",
    "moody",
    "muddy",
    "muggy",
    "mundane",
    "murky",
    "mushy",
    "musty",
    "mute",
    "narrow",
    "nasty",
    "naughty",
    "nervy",
    "nimble",
    "nippy",
    "noisy",
    "nosy",
    "novel",
    "oily",
    "ornate",
    "pale",
    "palmy",
    "peppy",
    "pesky",
    "petite",
    "picky",
    "pithy",
    "placid",
    "plump",
    "plush",
    "poised",
    "presto",
    "prim",
    "prime",
    "prompt",
    "pure",
    "quirky",
    "ragged",
    "randy",
    "rash",
    "raw",
    "ready",
    "remote",
    "ridged",
    "right",
    "rigid",
    "ripe",
    "risky",
    "ritzy",
    "robust",
    "rocky",
    "roomy",
    "rough",
    "round",
    "rowdy",
    "rude",
    "rustic",
    "rusty",
    "sandy",
    "saucy",
    "savvy",
    "sharp",
    "sheer",
    "shifty",
    "short",
    "showy",
    "shrewd",
    "shy",
    "silken",
    "silky",
    "silly",
    "sleek",
    "sleepy",
    "slender",
])
_PAKE_ANIMAL = frozenset([
    "otter",
    "panda",
    "falcon",
    "lynx",
    "koala",
    "heron",
    "fox",
    "ibex",
    "marten",
    "tapir",
    "badger",
    "beaver",
    "bison",
    "bongo",
    "camel",
    "civet",
    "condor",
    "crane",
    "dingo",
    "dove",
    "eland",
    "ermine",
    "ferret",
    "finch",
    "gecko",
    "gibbon",
    "hare",
    "hawk",
    "hyrax",
    "jackal",
    "kestrel",
    "kiwi",
    "lemur",
    "llama",
    "macaw",
    "magpie",
    "mole",
    "moose",
    "murre",
    "newt",
    "ocelot",
    "okapi",
    "oriole",
    "osprey",
    "owl",
    "pika",
    "plover",
    "puffin",
    "quokka",
    "rabbit",
    "raven",
    "robin",
    "seal",
    "shrew",
    "skink",
    "sparrow",
    "stoat",
    "swan",
    "tern",
    "toucan",
    "vole",
    "wombat",
    "wren",
    "zebra",
    "aardvark",
    "agouti",
    "akita",
    "alpaca",
    "anchovy",
    "antelope",
    "armadillo",
    "baboon",
    "barracuda",
    "basilisk",
    "bass",
    "bat",
    "beagle",
    "bee",
    "bengal",
    "blenny",
    "boar",
    "bobcat",
    "bonobo",
    "bonito",
    "boxer",
    "bronco",
    "budgie",
    "buffalo",
    "bulldog",
    "bullfrog",
    "bunting",
    "burro",
    "butterfly",
    "buzzard",
    "calf",
    "canary",
    "capybara",
    "caribou",
    "carp",
    "catbird",
    "catfish",
    "chameleon",
    "cheetah",
    "chickadee",
    "chihuahua",
    "chipmunk",
    "chow",
    "cicada",
    "clam",
    "clownfish",
    "cobra",
    "cockatoo",
    "collie",
    "conch",
    "coot",
    "corgi",
    "cormorant",
    "cougar",
    "cowbird",
    "coyote",
    "crab",
    "crayfish",
    "cricket",
    "crow",
    "cuckoo",
    "curlew",
    "cuttle",
    "dachshund",
    "damsel",
    "darter",
    "deer",
    "devil",
    "dhole",
    "dikdik",
    "dipper",
    "doberman",
    "dogfish",
    "dolphin",
    "donkey",
    "dormouse",
    "dragonfly",
    "drake",
    "dunlin",
    "eagle",
    "echidna",
    "eel",
    "egret",
    "elephant",
    "elk",
    "emu",
    "fallow",
    "fennec",
    "firefly",
    "flamingo",
    "flounder",
    "fossa",
    "frog",
    "gar",
    "gazelle",
    "gerbil",
    "giraffe",
    "gnat",
    "gnu",
    "goat",
    "goldfinch",
    "goose",
    "gopher",
    "gorilla",
    "gosling",
    "greyhound",
    "grouse",
    "gull",
    "guppy",
    "hamster",
    "hedgehog",
    "hen",
    "hermit",
    "hippo",
    "hornet",
    "horse",
    "hound",
    "hummingbird",
    "hyena",
    "iguana",
    "impala",
    "jackrabbit",
    "jaguar",
    "jay",
    "jellyfish",
    "jerboa",
    "junco",
    "kakapo",
    "kangaroo",
    "katydid",
    "kingfisher",
    "kinkajou",
    "kite",
    "kitten",
    "koi",
    "krill",
    "lab",
    "ladybug",
    "lamb",
    "lamprey",
    "lemming",
    "leopard",
    "liger",
    "lion",
    "lizard",
    "lobster",
    "locust",
    "loon",
    "loris",
    "louse",
    "macaque",
    "mackerel",
    "maggot",
    "mallard",
    "maltese",
    "manatee",
    "mandrill",
    "manta",
    "mare",
    "marmoset",
    "marmot",
    "mastiff",
    "meerkat",
    "mink",
    "minnow",
    "monarch",
    "mongoose",
    "monkey",
    "moth",
    "mouse",
    "mule",
    "muskox",
    "mussel",
    "mustang",
    "narwhal",
    "nautilus",
    "nightjar",
    "numbat",
    "nuthatch",
    "octopus",
    "olm",
    "opossum",
    "orangutan",
    "orca",
    "oryx",
    "ostrich",
    "ox",
    "oyster",
    "panther",
    "parrot",
    "partridge",
    "peacock",
])
_PAKE_WORDS = _PAKE_ADJ | _PAKE_ANIMAL | {
    "azure", "cobalt", "coral", "crimson", "emerald", "hazel", "indigo",
    "ivory", "jade", "lilac", "olive", "rose", "ruby", "scarlet", "teal", "violet",
}


class PakeV2Nameplate(unittest.TestCase):
    """L1-a: v2-only nameplate allocation. The server only sees the numeric
    nameplate and NEVER the password words."""

    def _server(self):
        from flask import Flask
        from flask_socketio import SocketIO
        app = Flask(__name__)
        sio = SocketIO(app, async_mode="threading")
        import os
        os.environ["FIL_CLAIM_LIMIT"] = "1000000"
        signaling.register(sio, signaling._MemRegistry())
        return app, sio

    def test_v2_create_allocates_nameplate_no_words(self):
        app, sio = self._server()
        c = sio.test_client(app)
        c.get_received()
        c.emit("join", {"room": "solo-x", "name": "a", "uid": "ua"})
        c.get_received()
        c.emit("pair-create", {"nameplate": "4242", "v": 2})
        evs = [e for e in c.get_received()]
        names = {e["name"] for e in evs}
        self.assertIn("pair-ok", names, f"v2 create must ack pair-ok, got {names}")
        ok = next(e for e in evs if e["name"] == "pair-ok")["args"][0]
        self.assertEqual(ok["nameplate"], "4242")
        self.assertNotIn("code", ok, "v2 ack must not echo any code/words")

    def test_v2_create_rejects_words_in_nameplate(self):
        app, sio = self._server()
        c = sio.test_client(app)
        c.get_received()
        c.emit("join", {"room": "solo-y", "name": "a", "uid": "ua"})
        c.get_received()
        c.emit("pair-create", {"nameplate": "brave-otter-314", "v": 2})
        errs = [e["args"][0]["error"] for e in c.get_received() if e["name"] == "pair-error"]
        self.assertEqual(errs, ["bad-nameplate"], "non-numeric nameplate must be refused")

    def test_v2_claim_relay_blind(self):
        """Gate #2 foundation (ledger NEGATIVE rule): across a full v2 create+claim
        the WORDS never reach the server in any received event or TEL telemetry."""
        app, sio = self._server()
        buf = io.StringIO()
        with redirect_stdout(buf):
            creator = sio.test_client(app)
            creator.get_received()
            creator.emit("join", {"room": "solo-z", "name": "creator", "uid": "uc"})
            creator.get_received()
            creator.emit("pair-create", {"nameplate": "5151", "v": 2})
            creator_evs = creator.get_received()

            claimer = sio.test_client(app)
            claimer.get_received()
            claimer.emit("join", {"room": "claimer-solo", "name": "claimer", "uid": "uk"})
            claimer.get_received()
            claimer.emit("pair-claim", {"nameplate": "5151", "v": 2})
            claimer_evs = claimer.get_received()
            creator_evs2 = creator.get_received()

        creator_evs = creator_evs + creator_evs2
        cl_names = [e["name"] for e in claimer_evs]
        self.assertIn("pair-matched", cl_names, f"claimer should be matched, got {cl_names}")
        self.assertIn("pair-used", {e["name"] for e in creator_evs}, "creator told code was used")

        server_saw = buf.getvalue() + _json.dumps(creator_evs) + _json.dumps(claimer_evs)
        leaked = sorted(w for w in _PAKE_WORDS if w in server_saw)
        self.assertEqual(leaked, [], f"PASSWORD LEAKED to the server: {leaked}")
        self.assertNotRegex(server_saw, r"[a-z]{3,10}-[a-z]{3,10}-[0-9]{3,5}",
                            "a full minted code (words+nameplate) leaked server-side")

    def test_v2_burn_once(self):
        app, sio = self._server()
        creator = sio.test_client(app)
        creator.get_received()
        creator.emit("join", {"room": "rs", "name": "creator", "uid": "uc"})
        creator.get_received()
        creator.emit("pair-create", {"nameplate": "6262", "v": 2})
        creator.get_received()
        a = sio.test_client(app); a.get_received()
        a.emit("join", {"room": "as", "name": "a", "uid": "ua"}); a.get_received()
        a.emit("pair-claim", {"nameplate": "6262", "v": 2})
        self.assertIn("pair-matched", {e["name"] for e in a.get_received()})
        b = sio.test_client(app); b.get_received()
        b.emit("join", {"room": "bs", "name": "b", "uid": "ub"}); b.get_received()
        b.emit("pair-claim", {"nameplate": "6262", "v": 2})
        errs = [e["args"][0]["error"] for e in b.get_received() if e["name"] == "pair-error"]
        self.assertEqual(errs, ["invalid"], "a burned nameplate must not re-match")

    def test_v1_refused(self):
        """Decision #1: non-v2 clients receive 'update-required'."""
        app, sio = self._server()
        c = sio.test_client(app)
        c.get_received()
        c.emit("pair-create", {"code": "brave-otter-123"})
        errs_cr = [e["args"][0] for e in c.get_received() if e["name"] == "pair-error"]
        self.assertTrue(any(e.get("error") == "update-required" for e in errs_cr),
                        f"v1 create must be refused, got {errs_cr}")
        d = sio.test_client(app)
        d.get_received()
        d.emit("pair-claim", {"code": "brave-otter-123"})
        errs_cl = [e["args"][0] for e in d.get_received() if e["name"] == "pair-error"]
        self.assertTrue(any(e.get("error") == "update-required" for e in errs_cl),
                        f"v1 claim must be refused, got {errs_cl}")


class Gate3BurnAndNoRetry(unittest.TestCase):
    """Gate #3 (burn-on-claim + no-retry): THE load-bearing dependency. A wrong
    password / confirmation MUST consume the nameplate (GETDEL) and force the
    creator to re-mint fresh words, never retry the same code. The single-online-
    guess bound rests entirely on this."""

    def _server(self):
        from flask import Flask
        from flask_socketio import SocketIO
        app = Flask(__name__)
        sio = SocketIO(app, async_mode="threading")
        import os
        os.environ["FIL_CLAIM_LIMIT"] = "1000000"
        signaling.register(sio, signaling._MemRegistry())
        return app, sio

    def test_burn_after_claim_forces_re_mint(self):
        """A claimed nameplate is consumed atomically. After the first claim,
        any attempt to claim the SAME nameplate returns 'invalid'. The creator
        must re-mint a FRESH nameplate and re-run pair-create."""
        app, sio = self._server()
        # Creator mints a nameplate locally and creates it on the server.
        creator = sio.test_client(app)
        creator.get_received()
        creator.emit("join", {"room": "solo-g3", "name": "creator", "uid": "uc"})
        creator.get_received()
        creator.emit("pair-create", {"nameplate": "777", "v": 2})
        cr_evs = creator.get_received()
        self.assertIn("pair-ok", {e["name"] for e in cr_evs}, "nameplate allocated")

        # FIRST claim: must succeed (consume the nameplate atomically).
        claimer = sio.test_client(app)
        claimer.get_received()
        claimer.emit("join", {"room": "cl-g3", "name": "claimer", "uid": "uk"})
        claimer.get_received()
        claimer.emit("pair-claim", {"nameplate": "777", "v": 2})
        cl_evs = claimer.get_received()
        self.assertIn("pair-matched", {e["name"] for e in cl_evs},
                      "first claim must match (nameplate consumed)")
        # Creator is notified that the code was used.
        cr_evs2 = creator.get_received()
        self.assertTrue(any(e["name"] == "pair-used" for e in cr_evs2),
                        "creator must be told pair-used")

        # SECOND claim (same nameplate): MUST fail with 'invalid'.
        # This proves the burn: a wrong-password claimer that retries the same
        # code would find it already consumed.
        claimer2 = sio.test_client(app)
        claimer2.get_received()
        claimer2.emit("join", {"room": "cl2-g3", "name": "claimer2", "uid": "u2"})
        claimer2.get_received()
        claimer2.emit("pair-claim", {"nameplate": "777", "v": 2})
        errs = [e["args"][0]["error"] for e in claimer2.get_received() if e["name"] == "pair-error"]
        self.assertEqual(errs, ["invalid"],
                        "Gate #3 BROKEN: burned nameplate still matchable; a wrong guesser could retry")

        # Creator re-mints FRESH nameplate. This MUST succeed (the old one is burned).
        creator.emit("pair-create", {"nameplate": "888", "v": 2})
        re_evs = creator.get_received()
        self.assertIn("pair-ok", {e["name"] for e in re_evs},
                      "Gate #3: re-mint with a fresh nameplate must succeed")

    def test_nameplate_collision_is_retryable(self):
        """A nameplate collision (unlikely but possible under 900 slots) is NOT
        a burn: the server returns 'taken', the creator re-mints, and the
        second attempt succeeds."""
        app, sio = self._server()
        a = sio.test_client(app); a.get_received()
        a.emit("join", {"room": "sa", "name": "a", "uid": "ua"}); a.get_received()
        a.emit("pair-create", {"nameplate": "101", "v": 2})
        a.get_received()
        # Second creator tries the same nameplate: collision.
        b = sio.test_client(app); b.get_received()
        b.emit("join", {"room": "sb", "name": "b", "uid": "ub"}); b.get_received()
        b.emit("pair-create", {"nameplate": "101", "v": 2})
        errs = [e["args"][0]["error"] for e in b.get_received() if e["name"] == "pair-error"]
        self.assertEqual(errs, ["taken"], "collision must return 'taken' (retryable)")
        # Re-mint with fresh nameplate: success.
        b.emit("pair-create", {"nameplate": "102", "v": 2})
        ok = [e for e in b.get_received() if e["name"] == "pair-ok"]
        self.assertTrue(ok, "re-mint after collision must succeed")


class NameplateNormalization(unittest.TestCase):
    def test_nameplate_regex_accepts_3_to_5_digits(self):
        pat = signaling._NAMEPLATE_RE
        self.assertTrue(pat.match("123"))
        self.assertTrue(pat.match("9999"))
        self.assertTrue(pat.match("10000"))
        self.assertFalse(pat.match("12"))
        self.assertFalse(pat.match("123456"))
        self.assertFalse(pat.match("abc"))
        self.assertFalse(pat.match("12a"))

    def test_norm_code(self):
        self.assertEqual(signaling._norm_code("  Brave  Otter 123 "), "brave-otter-123")
        self.assertEqual(signaling._norm_code("CLEVER-LYNX-63!"), "clever-lynx-63")
        self.assertEqual(signaling._norm_code(None), "")
        self.assertEqual(len(signaling._norm_code("x" * 500)), 48)

    def test_registry_burn_once_atomic(self):
        reg = signaling._MemRegistry()
        self.assertTrue(reg.pair_create("333", "sid-a", ttl=600))
        self.assertFalse(reg.pair_create("333", "sid-b", ttl=600), "NX: duplicate create must fail")
        self.assertEqual(reg.pair_claim("333"), "sid-a")
        self.assertIsNone(reg.pair_claim("333"), "second claim must find nothing (burned)")


if __name__ == "__main__":
    unittest.main()
