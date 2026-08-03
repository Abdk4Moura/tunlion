# Fleet-trust UX — final buildable copy (drop-in)

Source: adversarially-refined UX pass (2026-07-15). All copy below is FINAL and drop-in.
Design model: `docs/design-pairing-ux.md`; surface spec: `docs/ux-spec-pairing.md`; command
surface: `docs/design-command-surface.md`.

## Tone/token contract (applies to all surfaces)
- Tokens: `Brand`=header/accent, `Ok`=safe caps, `Warn`=deliberate, `Err`=denied/refused,
  `Dim`=meta/echo, `Bold`=action.
- Glyphs (ascii fallback for `NO_COLOR`/no-unicode): `✓`/`ok`, `✗`/`x`, `⚠`/`!`,
  `●`/`[fleet]`, `○`/`[extern]`, `◐`/`[review]`, `↳`/`->` (equivalent-command echo, already in
  `ui.rs`), `→`/`->` (direction).
- `●` fleet=`Brand` · `○` external/nudge=`Warn`(action) or `Dim`(listing) · `◐` needs-review=`Warn`.
- Countdown shape carries meaning: `renews in Nm`=healthy self-maintaining (`Dim`);
  `expires in Nm`=a deadline (`Dim`, → `Warn` under 5m); `renews until <date>`=degraded, no
  signer (`Warn`, date `Bold`).
- Danger encoded THREE ways always (color + `⚠`/`!` glyph + literal word DELIBERATE / ⚠-cap),
  never color alone — survives NO_COLOR, colorblindness, screen readers.
- `--yes` confirms, never escalates; deliberate caps must be named; non-TTY never opens a form
  and fails loud (exit 2 bad-arg, 1 refused-by-model).

## Confirm-token strings (exact)
`SHELL`, `WRITE`, `ALL-PORTS`, `REUSE`. Mistype → row reverts, non-blocking inline
`⚠ didn't match "SHELL" — left off.`

## `--allow` accepts
`shell`, `write`, `all-ports`, `reuse`, `no-expiry`(rejected → over-TTL error). Bare
`--shell`/`--reusable`/`--write` → "not a flag" error per token.

## Exit codes
missing-arg / bad-flag = 2; refused-by-model (mesh, over-TTL) = 1.

## Implementation note (command enum prerequisite)
`mint`, `requests`, `join`, and `identity {restore,rotate,revoke,guardians}` are NOT yet in the
`main.rs` `Commands` enum. These surfaces assume those variants get added per the command spec.
Build the rendering + form logic as self-contained modules first; the enum wiring is a separate
integration step (owner: orchestrator, after the security core lands).

---

# SURFACE 1 — `filament mint` guided form + danger microcopy

### 1a. Header (all key types)
```
  filament mint — a key that lets a machine join, scoped and expiring   [Brand]
```

### 1b. Key-type picker (first screen)
```
  What is this key for?
   ● (o) A device in my fleet       my own laptop / box / CI — permissive within scope   [Brand ●]
     ( ) An external share          give someone else narrow, time-boxed access
     ( ) A CI / automation runner   single-use, pinned to one machine, then forgotten
```

### 1c. "This key can… / cannot…" live summary (above the buttons)
`✓` lines=`Ok`, `⚠` lines=`Warn`, `✗` lines=`Err`, meta line=`Dim`.

Fleet (defaults, nothing deliberate on):
```
  ── This key can ──
   ✓ drop files in your inbox · reach your exposed ports · read ~/share
   ✗ open a shell · write to disk · join your mesh
   once · expires in 1h · adds the device to your fleet (Proven required)
```
Fleet with a deliberate cap on (e.g. shell):
```
  ── This key can ──
   ✓ drop files in your inbox · reach your exposed ports · read ~/share
   ⚠ open a shell — a real terminal on this machine, running as you
   ✗ write to disk · join your mesh
   once · expires in 1h · adds the device to your fleet (Proven required)
```
External share:
```
  ── This key can ──
   ✓ send you files                    (the only thing on, until you add more)
   ✗ read your files · open a shell · reach any port · join your mesh
   one-way (them → you) · expires in 1h · no auto-renew · not your fleet
```
CI / automation runner:
```
  ── This key can ──
   ✓ run one job on ci-box, then vanish
   ✗ persist · open a shell · reach other ports · join your mesh
   single-use · pinned to ci-box · expires in 15m · ephemeral (no identity left behind)
```

### 1d. Deliberate-access region + type-to-confirm
Border + label = `Warn`.
```
  ┌ ⚠ DELIBERATE ACCESS — off unless you turn it on ─────────────────────────┐   [Warn]
  │  [ ] open a shell          a real terminal on this machine, running as you │
  │  [ ] write to mounted dirs can change or delete your files                 │
  │  [ ] reach ALL ports       not just the ports you chose to expose          │
  └────────────────────────────────────────────────────────────────────────────┘
```
On toggle (confirm token = cap UPPERCASE name):
```
  │  [x] open a shell          type SHELL to keep it on:  [ SHELL▌ ]           │   [Warn row]
```

### 1e. Lifetime block
```
  ── Lifetime ──
   Expires in:  [ 1h ]  ◀────●───────▶   (max 24h for this key type)             [Dim caption]
   Reuse:       (o) once   ( ) 5 times   ( ) reusable ⚠                          [Warn on "reusable ⚠"]
```
Best-effort honesty (shown only when reuse ≠ once and no audience pinned):
```
  ⚠ "5 times" is best-effort hygiene, not a guarantee — a copied key can be
     claimed again at a peer that never saw the count.
     To make single-use real, pin the machine:  --audience ci-box  → enforced there.
```

### 1f. Completion / teach-the-flags
```
  ✓ Minted. Share this with the machine that's joining:                          [Ok]

       filament join clever-lynx-63-brave-otter                                  [Bold]

  ● fleet key · once · expires 14:38 (in 1h) · shell                             [Dim]
  ↳ filament mint --fleet --ttl 1h --reuse once --allow shell                    [Dim]
```

### 1g. Headless / non-TTY errors (all `Err` glyph, fix line `Dim`)
```
✗ --shell is not a flag. Shell is deliberate access.
  To grant it on purpose:  filament mint --fleet --ttl 1h --allow shell
```
```
✗ mint needs a key type in non-interactive mode.
  filament mint --fleet | --external <peer> | --ci
  (add --ttl; for external, at least one --allow)
```
```
✗ --yes will not enable a deliberate option you didn't name.
  Say it explicitly:  filament mint --fleet --ttl 1h --allow reuse --yes
```
```
✗ external keys expire within 24h (this key type's ceiling).
  Pick a shorter --ttl, or re-mint when it lapses. Long-lived trust is `pair`, not a key.
```
```
✗ mesh is never grantable by a key — a runner or borrower can't join your L3 overlay.
  (Refused at the verifier regardless of signature. Not a flag; there's no override.)
```

---

# SURFACE 2 — `pair` same-vs-inter-user flows

### 2a. Code entry (shared prefix)
```
  Enter the code from the other device:  brave-otter-42▌                         [prompt]
```

### 2b. SAME-PERSON banner + fleet add (full-width rules + text = `Brand`)
```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ●  SAME PERSON  ·  this is you
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  "pixel-7" is signed by your identity. Adding it to your fleet.

  This device will:  send/receive with your fleet · reach exposed ports · read ~/share   [Ok row]
  It will not:       open a shell · write to disk   (grant those later if you want)       [Dim]
  ● fleet · certs auto-renew · Proven                                                     [Dim]

        [ Add to my fleet ]   [ Cancel ]                                                  [Bold / Dim]
```
Success:
```
  ✓ pixel-7 joined your fleet.                                                    [Ok]
  ↳ filament pair --fleet --name pixel-7                                          [Dim]
```

### 2c. SOMEONE-ELSE banner (full-width rules + text = `Warn`)
```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ○  SOMEONE ELSE  ·  not your identity
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  This is not you. Nothing is shared yet — you decide exactly what, and for how long.   [Dim]
```

### 2d. PAKE spoken-words screen (words=`Bold`, compare line=`Dim`)
```
  Say these three words out loud. They must hear the SAME three, in this order.

        amber · lantern · ferry                                                  [Bold]

   Do they hear exactly these?
        [ Yes, they match ]        [ No / stop ]                                 [Bold / Err]

  Fingerprint 7f3a 9c21 4b…  [compare]  — informational; the words are the trust. [Dim]
```
Mismatch (`No / stop`) — `Err` glyph, calm:
```
  ✗ Stopped. If the words didn't match, someone may be in the middle — don't retry
    on the same channel. Get a fresh code from them and try again.
```

### 2e. Inter-user per-cap + direction + expiry form (after "Yes, they match")
```
  ✓ Words matched. What may "carol" do, and for how long?                        [Ok]

   [ ] send me files            [ ] reach my port [ 8080 ]
   [ ] read-only ~/share        [ ] open a shell ⚠                               [Warn on shell row]
   Direction:  (o) carol → me only    ( ) both ways
   Ends in:    [ 1h ]  ◀──●─────▶   (max 24h)                                     [Dim caption]

  ── This grant ──
   ✓ carol → you: send files                                                     [Ok]
   ✗ you → carol: nothing · carol cannot shell, mount, or reach other ports      [Err]
   ○ external · one-way · expires 14:41 (in 1h) · no auto-renew                   [Dim]

        [ Grant ]   [ Cancel ]
```
Shell row reuses the type-`SHELL`-to-confirm interaction from 1d. Success:
```
  ✓ carol can send you files until 14:41 (1h). It ends on its own — no cleanup needed.  [Ok]
   (No replay command: this is a directional transfer permission.)
```

### 2f. Non-TTY `pair` (must not open a form)
```
✗ pair is interactive (it needs the spoken-words step). For automation, mint a key instead:
  filament mint --external carol --ttl 1h --allow transfer
```

---

# SURFACE 3 — `devices` + `requests`

### 3a. `devices` — full/normal
```
  ● FLEET  — your devices, permissive within scope, self-renewing               [Brand]
     ● pixel-7        online     shell reach:8080 inbox     renews in 9m
     ● ci-box         online     inbox                      renews in 6m
     ● studio-mac     offline    shell reach inbox mount    renews in 3m  (last seen 2h ago)  [Dim tail]

  ○ EXTERNAL  — other people, time-boxed, deny-by-default                        [Dim]
     ○ carol          online     send→you                   expires in 4m        [Warn on countdown]
     ○ dave           offline    read ~/share               expires in 6h

  ◐ NEEDS REVIEW  — paired before scoped trust; promote to sort into a tier      [Warn]
     ◐ old-laptop     offline    (full legacy trust)        promote to continue
       ↳ filament devices promote old-laptop                                     [Dim]

  2 requests waiting · filament requests                                         [Dim]
  This is a local index; each device's own capability list is authoritative.     [Dim]
```

### 3b. `devices` — empty
```
  No devices yet.
  Add your own:     filament pair             (run on both, same identity)
   Let someone in:   filament mint --external <them> --ttl 1h --allow transfer
```

### 3c. `devices` — degraded / no-primary-online (calm + dated)
```
  ○ No primary online. Your devices keep working and auto-renew                  [Warn]
     until Aug 3 (in 5 days). Bring a primary online before then to keep them fresh.  [Bold date]
     Primaries: pixel-7 (offline 5d), studio-mac (offline 2d)                     [Dim]

  ● FLEET                                                                         [Brand]
     ● ci-box     online   inbox    renews until Aug 3   ← was "renews in 6m"     [Warn countdown]
```

### 3d. `devices` — a device falling out (cert past renewal)
```
     ● ci-box     online   inbox    ⚠ expires Aug 3, not renewing (no signer)     [Warn]
```
Once lapsed (dimmed "left" line, not deleted, for one listing):
```
     · ci-box     —        —        left: cert expired Aug 3 · re-pair to restore  [Dim]
```

### 3e. `devices promote`
```
  ◐ old-laptop was paired before scoped trust. Sort it in:                       [Warn]
     (o) fleet — my own device, permissive within scope
     ( ) external — someone else, pick caps + an expiry
        [ Promote ]   [ Cancel ]

  ✓ old-laptop is now a fleet device. Certs will auto-renew.                     [Ok]
```

### 3f. `requests` — full (stands alone, no tray)
```
  2 waiting                                                    updated just now   [Bold / Dim]

  1   ○ carol  wants to  send you files                                          [Dim index / Warn ○]
         asked 3m ago · via one-time word "amber-lantern-ferry"
         fingerprint 7f3a 9c21… [compare]
         [ filament requests approve 1 ]   [ filament requests deny 1 ]

  2   ○ dave   wants to  open a shell ⚠                                          [Warn on the cap]
         asked 18m ago · introduced by carol
         ⚠ this is deliberate access — a real terminal on this machine           [Warn]
          [ filament requests approve 2 ]   [ deny 2 ]

  Nothing pushes to you yet — check `filament requests`, or wire a hook:          [Dim]
    filament requests --notify 'notify-send %s'   (also: webhook, email)
```

### 3g. `requests` — empty
```
  Nothing waiting. Requests from other people show up here (pull — no tray needed yet).  [Dim]
```

### 3h. `requests approve` — deliberate guard
```
✗ request 2 asks for shell — deliberate access. Name it and bound it:
  filament requests approve 2
```
Safe approve success:
```
  ✓ carol can send you files until 15:12 (1h).                                   [Ok]
```
Deny:
```
  ✓ Denied. carol was told nothing was shared. No trace kept.                    [Ok]
```

---

# SURFACE 4 — Recovery: `init` phrase + `restore` loss-vs-theft + guardians

### 4a. `init` — recovery-phrase screen with forced ack
```
  ✓ Identity created. This is you — devices come and go, this is what they trust.  [Ok]

  Write these 12 words down. This is the only way back if you LOSE every device.   [Bold]
  We will not show them again.                                                     [Warn]

     1  harbor     2  velvet     3  cinder     4  meadow
     5  quartz     6  tunnel     7  ...        8  ...
     9  ...       10  ...       11  ...       12  cobalt

   [ I've written them down ]   ← required to continue                            [Bold]
```
Skip / Ctrl-C attempt:
```
  ⚠ Without the phrase, a lost device is a lost identity. Skip anyway? [y/N]      [Warn]
```
After ack — ≥2-primaries nudge (consequence-framed, non-blocking):
```
  ✓ Saved. Now make sure you're never one dead device from lockout:              [Ok]
     ✓ this device (primary)
     ○ add a second primary:  filament pair --fleet   (strongly recommended)     [Warn ○ / Dim]
```

### 4b. `restore` — loss-vs-theft honesty, user CHOOSES posture (load-bearing)
```
  filament restore — recover your identity from your 12 words                     [Brand]

  Enter your 12 recovery words:  harbor velvet cinder …▌

  ✓ Words verified. Before we finish, which happened?                            [Ok]

     (o) I LOST my devices        (phone gone, laptop died, nothing was stolen)
     ( ) A device was STOLEN      (someone may have my old key right now)
```
If LOST:
```
  ✓ Recovering. Your new device is now a primary.                               [Ok]
  7-day pending window: if an old device is still out there, it can object.       [Dim]
  Bring any old primary online to confirm instantly.
  ↳ filament identity rotate   (optional — replaces the old key sooner)          [Dim]
```
If STOLEN — the honest truth:
```
  ⚠ Read this. The phrase recovers you from LOSS, not from THEFT.                [Warn]

    Your 12 words rebuild your identity — but they do NOT disable a key a thief
    already holds. There is no server to phone; no global kill-switch exists (by design).

    What you CAN do right now:
      • filament revoke <device>   tell your OTHER devices to stop trusting the stolen one
                                   (takes effect as each one is reached; bounded by cert expiry)
      • filament identity rotate   move to a new key; devices re-verify on next contact

    What actually closes the door: guardians. If you'd set 3-of-5 guardians, they
    could co-sign a revocation the thief can't stop. Without them, revoke + rotate
    is best-effort and races the thief until the old certs expire.
```
Posture choice (user OWNS it):
```
  Choose your posture going forward:
     (o) Accept the race     backup-only — simplest, and a stolen key races you until expiry
     ( ) Add guardians       3-of-5 people co-sign recovery/revocation — wins the theft race
                             (set up now; takes a few minutes)
```

### 4c. Guardians — revoke / install split (for when we add it)
Install is easy + reversible; a guardian ACTING is slow + loud.
```
  filament identity guardians — people who can co-sign your recovery              [Brand]

  ● Installed  (3 of 5 — tolerates 2 offline)                                     [Brand]
     ● bff        added in person        ● sister     added in person
     ● coworker   introduced by bff
     ○ add two more for a 3-of-5 set                                              [Dim]

  Installing a guardian: one confirm, reversible anytime — they hold no power     [Dim]
  until 3 of them together co-sign a recovery. No single guardian can act alone.
```
Guardian ACTING (recovery request) — deliberately slow + notified:
```
  ⚠ A recovery for YOUR identity was requested from a new device.                [Warn]
     Started: Aug 3 · Activates: Aug 10 (7-day hold) unless you cancel.
     Not you?  filament identity freeze   — stops it cold; the new device gets nothing.
     It's you? Ask your guardians to co-sign, or bring an old primary online.
```
Removing a guardian:
```
  ✓ Removed coworker as a guardian. Your threshold is now 3-of-4.                [Ok]
  ⚠ Below your target of 3-of-5 — add one to restore your margin.               [Warn]
```
Duress path (documented; SILENT by design — NO on-screen string):
```
  # Entering the duress PIN at any recovery/rotate prompt SILENTLY aborts or delays.
  # It must look identical to success on screen. Never render a "duress detected" line.
```
