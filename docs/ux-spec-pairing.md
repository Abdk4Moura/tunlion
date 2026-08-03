# filament — pairing / auth-key / fleet-trust UX spec

Status: design (UX pass). Companion to `design-pairing-ux.md` (the model) and
`design-command-surface.md` (the verbs). Built on the real `ui.rs` tokens so these
surfaces read as one product. Security model is LOCKED by adversarial review; this makes
working within it effortless, never looser.

## Grounding (tokens reused, not reinvented)

- Tones: `Brand` teal `#7cf6c8`, `Ok` green, `Warn` amber, `Err` red, `Dim`, `Bold`.
- Glyphs: `✓`/`ok`, `✗`/`x`, `↳` (the codebase's "equivalent command" echo), `•`, `→`.
- Env contract honored: `NO_COLOR`, `TERM=dumb`, `FILAMENT_COLOR`, unicode→ascii fallback.
- Interactivity gate exists: TTY & not opted out → guided; non-TTY / `--no-interactive` /
  `FILAMENT_NONINTERACTIVE` → pure flags, fail loud, never block.
- Voice: lowercase, terse, honest, teach-the-flags, consequence-framed not scary-vague.

## The design language (one grammar across mint / pair / devices / requests)

Four primitives reused everywhere; a fifth is a smell.

1. **Tier dot** — every principal leads with a mark for *what kind of trust*:

| tier | glyph | color | ascii | meaning |
|---|---|---|---|---|
| Fleet (same user) | `●` | Brand | `[fleet]` | your device, permissive within scope |
| External (inter-user) | `○` | Dim | `[extern]` | someone else, deny-by-default, time-boxed |
| Needs-review (legacy) | `◐` | Warn | `[review]` | predates tiers, one-command promote |
| Delegated (auth-key) | `▷` | Dim | `[key]` | enrolled via a key, capped ceiling, ephemeral |

2. **The clock** — trust is always time-bounded, and its *shape* tells you the tier:
   fleet → a calm renewal countdown (`renews in 9m`); external → an expiry deadline
   (`expires in 4m`, amber under 5m). Never a bare timestamp where a human is deciding.

3. **The "this can… / it cannot…" sentence** — every mint/pair/grant shows a live
   plain-English capability sentence before commit; the negative space ("It cannot…") is
   load-bearing (a policy is understood by what it forbids). Always show both halves.

4. **The `↳` echo** — any interactive completion prints the exact headless command that
   reproduces it. The wizard is a teacher, not a crutch.

Restraint: one accent (Brand) for the primary action; amber ONLY for deliberate/danger;
red ONLY for denied/error; everything else dim. One border, around the single
"Deliberate access" region. Color is punctuation, not decoration.

## The danger-communication pattern

**Danger costs exactly one keystroke that names the thing — never a lecture, never a tax
on the safe path.** Three cap tiers, three treatments:

1. **Safe (scoped fleet defaults):** transfer→inbox, reach→exposed ports, read-only mount
   of the share root. Pre-selected, green `✓`, zero friction. Enter-through mints them.
2. **Deliberate (`shell`, write-mount, reach-all-ports):** a separate amber-bordered
   region, off by default. Turning one on requires **typing its name** (wizard) or an
   explicit **`--allow shell`** (headless — a bare `--shell` is *rejected* with a teach).
3. **Structural / never (`mesh`):** not a toggle; refused with the reason.

Modifiers `reusable` / `no-expiry` are treated as deliberate (amber, off by default,
`--allow reuse`; past the hard TTL ceiling it's impossible by construction).

**`--yes` confirms; it never escalates** — it can accept safe defaults but can't invent a
deliberate cap; deliberate caps must be named on the command line.

Encoding: every deliberate element carries color **and** `⚠`/`!` **and** the literal
word "DELIBERATE" — survives `NO_COLOR`, colorblindness, and a screen reader.

## Ranked friction fixes (summary)

F1 one verb `mint` (not N key-commands). F2 the same-vs-other branch is unmissable
(banner + color + glyph + ceremony). F3 danger never nags the safe 90%. F4 best-effort
reuse labeled honestly + the `--audience` upgrade offered inline. F5 wizards print the
`↳` equivalent (teach the flags). F6 `devices` names itself a local index, not truth.
F7 `requests` is a first-class pull queue (no tray needed). F8 legacy → needs-review +
one-command promote. F9 `init` force-saves a recovery phrase + pushes ≥2 primaries. F10
degraded "no primary" state is calm + dated. F11 danger encoded three ways (a11y).

## Mocks

### `filament mint` (guided, TTY)
```
  filament mint — a key that lets a machine join, scoped and expiring
  What is this key for?
   ● (o) A device in my fleet     ( ) An external share   ( ) A CI / automation runner
  ── Access ─────────────────────────────────────────
   ✓ drop files in my inbox        (fleet default)
   ✓ reach my exposed ports        (fleet default)
   ✓ read-only ~/share             (fleet default)
  ┌ ⚠ DELIBERATE ACCESS — off unless you turn it on ──────────────┐
  │  [ ] open a shell     [ ] write to mounted dirs   [ ] reach ALL ports │
  └───────────────────────────────────────────────────────────────┘
  Expires in: [ 1h ] ◀──●─────▶ (max 24h)    Reuse: (o) once ( ) 5× ( ) reusable ⚠
  ── This key can ───────────────────────────────────
   ✓ drop files in your inbox · reach exposed ports · read ~/share
   ✗ open a shell · write to disk · join your mesh
        [ Mint key ]   [ Cancel ]
```
Enabling a deliberate item requires an intent keystroke (`type SHELL to confirm`). On
mint, prints the join code + `↳ filament mint --fleet --ttl 1h --reuse once --allow shell`.

### `filament mint` (headless)
```
$ filament mint --fleet --ttl 1h --reuse once
filament join clever-lynx-63-brave-otter    # ● fleet · once · expires in 1h

$ filament mint --fleet --ttl 1h --shell
✗ --shell is not a flag. Shell is deliberate access.
  To grant it on purpose:  filament mint --fleet --ttl 1h --allow shell

$ filament mint --fleet --ttl 1h --yes --reusable
✗ --yes will not enable a deliberate option you didn't name.
  Say it explicitly:  filament mint --fleet --ttl 1h --allow reuse --yes

$ filament mint --external bob --ttl 30d --allow reach
✗ external keys expire within 24h (this key type's ceiling). Pick a shorter --ttl.
```

### `filament pair` (the unmissable branch)
SAME PERSON: a Brand banner "● SAME PERSON · this is you", one "Add to my fleet" confirm,
scoped defaults, no per-cap ceremony. SOMEONE ELSE: an amber banner "○ SOMEONE ELSE · not
your identity", the spoken-words PAKE ("say these three words: amber · lantern · ferry —
do they match?"), fingerprint behind `[compare]` (informational), THEN deny-by-default
directional time-boxed caps. The two share only the frame — different color, glyph, word,
ceremony.

### `filament devices` (three tiers)
```
  ● FLEET — your devices, permissive within scope, self-renewing
     ● pixel-7    online   shell reach:8080 inbox   renews in 9m
     ● studio-mac offline  shell reach inbox mount  renews in 3m (last seen 2h ago)
  ○ EXTERNAL — other people, time-boxed, deny-by-default
     ○ carol      online   send→you                 expires in 4m
  ◐ NEEDS REVIEW — paired before scoped trust; promote to sort into a tier
     ◐ old-laptop offline  (full legacy trust)       promote to continue
       ↳ filament devices promote old-laptop
  2 requests waiting · filament requests
  This is a local index; each device's own capability list is authoritative.
```

### `filament requests` (pull queue, no tray)
```
  2 waiting
  1  ○ carol wants to send you files       [ approve 1 ] [ deny 1 ]
  2  ○ dave  wants to open a shell ⚠        [ filament requests approve 2 ] [ deny 2 ]
  Nothing pushes to you yet — check `filament requests`, or wire a hook:
    filament requests --notify 'notify-send %s'
```
A deliberate request can't be approved by a bare `approve` (must name + bound it).

### Recovery
`filament init` force-saves a 12-word phrase ("Write these down. This is the only way
back if every device is lost. We will not show them again.") + nudges ≥2 primaries.
`filament restore` recovers on a new device with a 7-day pending-activation anti-theft
freeze. `revoke`/`rotate` are self-lockout-guarded ("pixel-7 is your only online
primary — rotating now could lock you out"). Degraded state changes the clock's shape:
`renews in 6m` → `renews until Aug 3 (in 5 days) — bring a primary online before then`.

## Microcopy library (actual strings)

- Danger: shell = "a real terminal on this machine, running as you"; write-mount = "can
  change or delete your files"; reach-all = "not just the ports you chose to expose —
  everything listening"; reusable-unpinned = "the reuse limit is best-effort hygiene, not
  a guarantee — a copied key can be claimed again at a peer that never saw the count";
  no-expiry = "keys always expire; long-lived trust is a device you pair, not a key you mint".
- Honesty footers: "This is a local index; each device's own capability list is
  authoritative." · "No global kill-switch exists — expiry is the boundary, by design." ·
  "Fingerprint … [compare] — informational; the spoken words are the trust."

## References (specific lesson from each)

- **age** — one command, keys are values; don't grow a command per key variety.
- **gh** — quiet tables, sentence-like verbs, `--json` on everything; guided flow prints
  the flags it used.
- **Stripe CLI** — extreme color restraint; alignment does the work color would.
- **charm.sh Gum / Huh** — single-screen forms with a live summary + inline validation
  (stay out of the alt-screen for a 5-field form).
- **1Password / wallet seed** — force the backup at creation, show once, require ack.
- **Signal safety numbers** — fingerprint is a compare affordance, not the trust act.
- **Argent social-recovery** — pending-activation + old-key freeze window.
- **git/cargo hints** — every error names the exact next command (the codebase's `↳`).
