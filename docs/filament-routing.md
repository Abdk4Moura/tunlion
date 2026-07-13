# filament-routing(7) — how filament chooses a network path

> Source for the `filament man routing` entry / the routing man page. This
> documents the TARGET model; ship each section as the matching feature lands
> (mode-over-iface label, avoid/only, prefer + hard/soft). Written to be shown
> verbatim to users — reference, but readable.

## THE ROUTE

Every connection filament makes has a **route**, shown as **`<mode> over <interface>`**:

- **mode** — *how* the bytes travel:
  - `direct` — peer-to-peer, straight to the other device.
  - `relay` — through a relay server, used only when no direct path can be made.
- **interface** — the actual network interface the bytes ride: `eth0`, `wl1`,
  `tailscale0`, `docker0`, `lo`, …

So `direct over wl1` is a peer-to-peer connection over your Wi‑Fi; `relay over eth0`
is a relayed connection over your wired interface.

**Overlays (e.g. Tailscale).** If both devices are on the same Tailscale tailnet,
filament may connect over the `tailscale0` interface (a `100.64.0.0/10` address).
That shows as **`direct over tailscale0`** — a real, working, direct path that rides
the overlay. It is *not* "local"; the bytes still cross the internet, via Tailscale.

## VOCABULARY

filament uses one word per concept, and **the word it prints is the word you type
back**:

- **peer** / **device** — a machine you connect to (`dovm`, `ipad`).
- **route** — the path used, printed as *mode over interface*.
- **mode** — `direct` or `relay`.
- **interface** — a network interface: `eth0`, `wl1`, `tailscale0`, … (friendly
  groups: `wifi`, `ethernet`).
- **avoid** / **only** (alias **include**) — *which* interfaces are eligible.
- **prefer** — the *order* among the eligible interfaces.

## CHOOSING INTERFACES — membership vs arrangement

Two independent controls: *which* interfaces may be used, and *in what order*.

### Membership — which interfaces are eligible (`avoid` / `only`)

`avoid` and `only` are two ways of expressing the **same** eligibility set:

- **`filament set avoid tailscale`** — use everything **except** tailscale. This is
  an **open** rule: an interface you plug in later is eligible unless you avoid it
  too.
- **`filament set only eth0,wl1`** — use **only** eth0 and wl1 (alias: `include`).
  This is a **closed** rule: an interface you plug in later is **not** eligible
  unless you add it.

They are complements — on a given machine, `avoid X` and `only (everything‑but‑X)`
select the same interfaces. filament keeps this as a **single** setting: setting
`avoid` replaces `only`, and vice versa.

Values may be:

- an **interface name** — `eth0`, `wl1`, `tailscale0`, `docker0`
- a **friendly group** — `wifi` (all `wl*`), `ethernet`/`wired` (all `eth*`),
  `tailscale`, `docker`
- a **subnet (CIDR)** — `100.64.0.0/10`, `172.17.0.0/16`

### Arrangement — the order among the eligible (`prefer`)

`prefer` **ranks** the eligible interfaces; it never includes or excludes.

- **`filament set prefer wl1,eth0`** — use wl1 first, then eth0, then the rest.
- When `prefer` is **unset**, filament orders paths by **measured speed** — the
  fastest path wins, automatically.
- **Strength** — `prefer` obeys one of two strengths:
  - **`soft`** (default) — use your order *unless another path is much faster*.
  - **`hard`** — *always* use your order when it connects, even if slower.

  Set it with `--hard` / `--soft`:

  ```
  filament set prefer wl1,eth0            # soft (default)
  filament set prefer wl1,eth0 --hard     # hard
  ```

filament applies **membership first** (drop ineligible interfaces), **then
arrangement** (order the survivors).

## SCOPE — global or per‑peer

Any of these apply globally, or to one peer via `--peer`:

```
filament set avoid tailscale              # global
filament set avoid tailscale --peer dovm  # only when connecting to dovm
```

Per‑peer is the common case. Example: **dovm** has a public IP, so the Tailscale
overlay is a slower detour for it — avoid it just for dovm:

```
filament set avoid tailscale --peer dovm
```

## THREE WAYS, SAME THING — interactive, flags, JSON

Every setting can be driven three ways, all carrying identical information:

- **Interactive** (a terminal) — `filament set avoid` opens a checklist of your
  interfaces (with the current ones pre‑checked); `filament set prefer` lets you
  reorder and toggle hard/soft with a keypress. The picker renders inline and
  leaves your scrollback intact.
- **Flags** (scripts) — `filament set avoid tailscale --peer dovm`,
  `filament set prefer wl1 --hard`.
- **JSON** (agents) — `filament set --json` prints the settings, valid values, and
  current state; an incomplete command prints machine‑readable guidance and exits
  non‑zero.

Nothing you can do interactively is un‑sayable on the command line: whatever you
click, filament can also be *told* — and after an interactive edit it prints the
equivalent flat command so you learn it.

## EXAMPLES

```
filament set avoid tailscale --peer dovm   # dovm: skip the Tailscale overlay
filament set only wifi                      # only ever use Wi‑Fi interfaces
filament set prefer eth0 --hard             # always use wired when it's up
filament set relay never --peer dovm        # dovm: direct only, never relay
filament set avoid --peer dovm              # (terminal) pick interfaces to avoid, for dovm
filament get avoid                          # show the current membership
filament unset avoid --peer dovm            # clear dovm's override
```

## SEE ALSO

`filament-set(1)`, `filament(1)`, `docs/env-vars.md`.
