# filament — command-surface wiring plan

Status: analysis (no code edits). Companion to `design-command-surface.md` (the
simplification spec) and `ux-copy-final.md` (the buildable copy). Owner: orchestrator,
after the security core lands.

---

## 1. Current `Cmd` enum → disposition mapping

| # | Current variant | Line | Disposition | After | Guardrail / citation |
|---|---|---|---|---|---|
| 1 | `Send` | 398 | positional + keep | `filament <file>` sends; `send` stays explicit | design line 36 |
| 2 | `Recv` | 426 | positional + keep | `filament <code>` receives; `recv` stays explicit | design line 37 |
| 3 | `Pair` | 459 | keep (everyday) | `filament pair` | design line 49 |
| 4 | `Devices` (sub: Forget, Rename) | 472 | keep + absorb | `filament devices` (+ `promote`, `vouch`) | design line 50 |
| 5 | `Up` | 479 | keep (everyday) | `filament up` | design line 54; "up is everyday; namespacing the most common daemon action to hide two rare siblings is backwards" (line 165) |
| 6 | `Status` | 517 | keep + absorb | absorbs `ping`, `cap-status`, `addr --json` | design line 56 |
| 7 | `Down` | 524 | keep | `filament down` | design line 55 |
| 8 | `Introduce` (hidden) | 527 | alias→devices vouch | `filament devices vouch <a> <b>`; `introduce` = hidden deprecated alias | design line 51 |
| 9 | `Set` | 534 | keep + absorb | `set K V` write; `set K` read; `set K --unset` reset; absorbs `get` and `unset` | design line 60 |
| 10 | `Addr` | 571 | keep (thin) | `filament addr`; device-info → `devices <name>` | design line 59 |
| 11 | `Get` (hidden) | 580 | alias→set | `filament set <k>`; `get` = hidden alias (bare stdout preserved) | design line 61 |
| 12 | `Unset` (hidden) | 597 | flag→set | `filament set <k> --unset`; `unset` = hidden alias | design line 62 |
| 13 | `ServeTun` (hidden) | 611 | ns:net | `filament net serve-tun`; alias kept | design line 48, design line 162 |
| 14 | `Config` (hidden) | 634 | alias | hidden raw escape hatch stays | design line 63 |
| 15 | `Update` | 637 | keep (tail) | `filament update` | design line 65 |
| 16 | `Completions` (hidden) | 646 | keep hidden | plumbing | design line 66 |
| 17 | `Man` (hidden) | 651 | keep hidden | plumbing | design line 66 |
| 18 | `Netcat` (hidden) | 656 | alias→reach | `filament reach <dev>:<rport>`; `netcat` = hidden alias | design line 40 |
| 19 | `Dial` | 668 | alias→reach | `filament reach <dev>:<port>`; `dial` = hidden alias | design line 41 |
| 20 | `Pty` (hidden) | 677 | alias→shell | folded into `shell`; `pty` = hidden alias | design line 39 |
| 21 | `Forward` | 686 | keep + positional | `filament <dev>:<rport>` (persistent listener); verb stays | design line 42 |
| 22 | `Expose` | 700 | keep | `filament expose <port>` (`--list`, `--peer`, `--off`) | design line 44 |
| 23 | `Unexpose` | 714 | flag→expose | `filament expose <port> --off`; `unexpose` = hidden alias | design line 45 |
| 24 | `Proxy` | 724 | flag→reach | `filament reach --socks [--port]`; `proxy` = hidden alias | design line 43 |
| 25 | `Ssh` | 736 | alias→shell | `filament shell <dev>` / bare `filament <dev>`; `ssh` = hidden alias (arg passthrough preserved) | design line 38, design line 159 |
| 26 | `Ping` (hidden) | 748 | merge→status/doctor | `filament status <dev>` / `doctor <dev>`; alias kept | design line 57 |
| 27 | `Doctor` (hidden) | 768 | keep (everyday) | `filament doctor [dev]` | design line 58 |
| 28 | `TagBind` (hidden) | 900 | remove | tags superseded by scoped-trust design | design line 69 (identity group absorbs) |
| 29 | `Grant` (hidden) | 910 | keep | `filament grant <dev> <cap>` | design line 148; NOT merged with revoke |
| 30 | `Revoke` (hidden) | 922 | keep (first-class) | `filament revoke <dev> <cap>` — NOT `grant --off` | design lines 53, 150-153 |
| 31 | `Mount` | 937 | keep | `filament mount <dev>:<dir> <mnt>` (`--off`) | design line 46 |
| 32 | `Unmount` | 975 | flag→mount | `filament mount --off <mnt>`; `unmount` = hidden alias | design line 47 |
| 33 | `CapStatus` | 986 | merge→status | `filament status` absorbs cap-status | design line 56 |
| 34 | `Backup` | 991 | keep (tail) | `filament backup` | design line 64 |
| 35 | `Requests` (sub: List, Approve, Deny) | 1015 | keep (everyday) | `filament requests` | design line 68 |
| 36 | `Identity` (sub: Init, Show, Certify) | 7471 | keep + expand | `filament identity {init,show,restore,rotate,revoke,guardians,certify}` | design line 69 |

**Legend:** **keep** — stays as-is. **positional** — `filament <thing>` shortcut. **alias→X** — hidden deprecated alias. **flag→X** — folded into a flag. **ns:X** — namespaced under X. **merge→X** — absorbed into X. **remove** — deleted.

---

## 2. Target enum — exact variant names + clap attributes

```rust
#[derive(Subcommand)]
enum Cmd {
    // === Positional (filament <thing> resolves by shape) ===
    Send {
        paths: Vec<String>,
        #[arg(long)] code: bool,
        #[arg(long)] word: Option<String>,
        #[arg(long)] remember: Option<String>,
        #[arg(long)] room: Option<String>,
        #[arg(long)] to: Option<String>,
        #[arg(long)] name: Option<String>,
    },
    Recv {
        code: Option<String>,
        #[arg(long, default_value = ".")] dir: PathBuf,
        #[arg(long, short = 'y')] yes: bool,
        #[arg(long)] room: Option<String>,
        #[arg(long)] to: Option<String>,
        #[arg(long)] keep_open: bool,
        #[arg(long)] remember: Option<String>,
        #[arg(long, short = 'o')] output: Option<String>,
    },

    // === Everyday verbs ===
    Pair {
        code: Option<String>,
        #[arg(long)] name: Option<String>,
        #[arg(long)] word: Option<String>,
    },
    Devices {
        #[command(subcommand)] action: Option<DevicesAction>,
        #[arg(long)] json: bool,
    },
    Up {
        #[arg(long)] install: bool,
        #[arg(long)] system: bool,
        #[arg(long)] userspace: bool,
        #[arg(long)] dir: Option<PathBuf>,
        #[arg(long)] shell: bool,
        #[arg(long, value_name = "DEVICES")] shell_only: Option<String>,
        #[arg(long, value_name = "USER")] shell_user: Option<String>,
    },
    Mint {
        #[arg(long)] fleet: bool,
        #[arg(long)] external: Option<String>,
        #[arg(long)] ci: bool,
        #[arg(long)] ttl: Option<String>,
        #[arg(long)] reuse: Option<String>,
        #[arg(long, value_delimiter = ',')] allow: Vec<String>,
        #[arg(long)] audience: Option<String>,
        #[arg(long)] yes: bool,
    },
    Requests {
        #[command(subcommand)] action: Option<RequestsAction>,
    },
    Doctor {
        device: Option<String>,
        #[arg(long)] watch: bool,
        #[arg(long)] repeat: Option<u32>,
        #[arg(long)] json: bool,
    },

    // === Reach cluster (4 verbs, not 8) ===
    Shell {
        peer: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)] args: Vec<String>,
    },
    Reach {
        dev: Option<String>,
        port: Option<u16>,
        #[arg(long)] socks: bool,
        #[arg(long, default_value_t = 1080)] socks_port: u16,
        #[arg(long, default_value = "127.0.0.1")] bind: String,
        #[arg(long, default_value_t = 0)] http_port: u16,
    },
    Forward {
        lport: u16,
        peer: String,
        rport: u16,
    },
    Expose {
        port: Option<u16>,
        #[arg(long)] to: Option<String>,
        #[arg(long, value_delimiter = ',')] peer: Vec<String>,
        #[arg(long)] list: bool,
        #[arg(long)] off: bool,
    },
    Mount {
        peer: Option<String>,
        remote: Option<String>,
        local: Option<String>,
        #[arg(long)] read_only: bool,
        #[arg(long)] options: Option<String>,
        #[arg(long)] foreground: bool,
        #[arg(long)] save_auto: bool,
        #[arg(long)] list: bool,
        #[arg(long, value_name = "PATH")] check: Option<String>,
        #[arg(long = "save-profile", alias = "save", value_name = "NAME")] save_profile: Option<String>,
        #[arg(long = "apply-profile", alias = "apply", value_name = "NAME")] apply_profile: Option<String>,
        #[arg(long)] profiles: bool,
        #[arg(long, value_name = "NAME")] delete_profile: Option<String>,
        #[arg(long, value_name = "PATH")] off: Option<String>,
    },

    // === Admin ===
    Grant {
        device: String,
        capability: String,
        #[arg(long)] tag: Option<String>,
    },
    Revoke {
        device: String,
        capability: String,
    },
    Status {
        device: Option<String>,
        #[arg(long)] json: bool,
    },
    Down,
    Addr {
        device: Option<String>,
        #[arg(long)] v4: bool,
    },
    Set {
        key: Option<String>,
        value: Option<String>,
        #[arg(long, value_delimiter = ',')] peer: Vec<String>,
        #[arg(long)] dry_run: bool,
        #[arg(long)] reset: bool,
        #[arg(long)] unset: bool,
        #[arg(long)] yes: bool,
        #[arg(long)] json: bool,
        #[arg(long)] show_origin: bool,
        #[arg(long, value_name = "VALUE")] default: Option<String>,
    },
    Identity {
        #[command(subcommand)] action: IdentityAction,
    },
    Backup {
        peer: String,
        source: String,
        dest: String,
        #[arg(long)] exclude: Vec<String>,
        #[arg(long)] dry_run: bool,
        #[arg(long)] delete: bool,
        #[arg(long)] options: Option<String>,
    },
    Net {
        #[command(subcommand)] action: NetAction,
    },
    Update {
        #[arg(long)] check: bool,
        #[arg(long)] beta: bool,
    },

    // === Hidden plumbing ===
    #[command(hide = true)]
    Completions { shell: clap_complete::Shell },
    #[command(hide = true)]
    Man,
    #[command(hide = true)]
    Config { key: Option<String>, value: Option<String> },

    // === Deprecated aliases (hidden, still work, print stderr note) ===
    #[command(hide = true)]
    Ssh { peer: String, #[arg(trailing_var_arg = true, allow_hyphen_values = true)] args: Vec<String> },
    #[command(hide = true)]
    Pty { peer: String, #[arg(trailing_var_arg = true, allow_hyphen_values = true)] cmd: Vec<String> },
    #[command(hide = true)]
    Netcat { peer: String, rport: u16 },
    #[command(hide = true)]
    Dial { peer: String, port: u16 },
    #[command(hide = true)]
    Proxy { #[arg(long, default_value_t = 1080)] port: u16, #[arg(long, default_value = "127.0.0.1")] bind: String, #[arg(long, default_value_t = 0)] http_port: u16 },
    #[command(hide = true)]
    Unexpose { port: u16 },
    #[command(hide = true)]
    Unmount { path: String },
    #[command(hide = true)]
    Get { key: String, #[arg(long)] peer: Option<String>, #[arg(long)] show_origin: bool, #[arg(long, value_name = "VALUE")] default: Option<String>, #[arg(long)] json: bool },
    #[command(hide = true)]
    Unset { key: String, #[arg(long, value_delimiter = ',')] peer: Vec<String> },
    #[command(hide = true)]
    Ping { peer: String, #[arg(long, default_value_t = 1)] count: u32, #[arg(long)] json: bool },
    #[command(hide = true)]
    CapStatus { #[arg(long)] json: bool },
    #[command(hide = true)]
    Introduce { a: String, b: String },
    #[command(hide = true)]
    ServeTun {
        #[arg(long, value_name = "CIDR")] tun_addr: String,
        #[arg(long, value_name = "BIND", conflicts_with = "connect")] listen: Option<String>,
        #[arg(long, value_name = "HOST:PORT")] connect: Option<String>,
        #[arg(long)] psk: String,
        #[arg(long, default_value = "filament0")] dev: String,
        #[arg(long, default_value_t = 1280)] mtu: u32,
    },
}

#[derive(Subcommand)]
enum DevicesAction {
    Forget { name: String },
    Rename { old: String, new: String },
    Promote { device: String, #[arg(long)] fleet: bool, #[arg(long)] external: bool },
    Vouch { a: String, b: String },
}

#[derive(Subcommand)]
enum RequestsAction {
    List { #[arg(long)] all: bool, #[arg(long)] notify: Option<String> },
    Approve { id: u64, #[arg(long, value_delimiter = ',')] allow: Vec<String>, #[arg(long, value_name = "DURATION")] for_duration: Option<String> },
    Deny { id: u64 },
}

#[derive(Subcommand)]
enum IdentityAction {
    Init,
    Show,
    Restore,
    Rotate,
    Revoke { device: String },
    Guardians { #[command(subcommand)] action: Option<GuardiansAction> },
    Certify { device: String },
}

#[derive(Subcommand)]
enum GuardiansAction {
    List,
    Add { person: String },
    Remove { person: String },
    Threshold { n: u32, of: u32 },
}

#[derive(Subcommand)]
enum NetAction {
    ServeTun {
        #[arg(long, value_name = "CIDR")] tun_addr: String,
        #[arg(long, value_name = "BIND", conflicts_with = "connect")] listen: Option<String>,
        #[arg(long, value_name = "HOST:PORT")] connect: Option<String>,
        #[arg(long)] psk: String,
        #[arg(long, default_value = "filament0")] dev: String,
        #[arg(long, default_value_t = 1280)] mtu: u32,
    },
}
```

**Exit codes:** missing-arg / bad-flag = 2; refused-by-model (mesh, over-TTL) = 1.

**`--allow` values:** `shell`, `write`, `all-ports`, `reuse`, `no-expiry` (rejected → over-TTL error).

**Confirm tokens (exact):** `SHELL`, `WRITE`, `ALL-PORTS`, `REUSE`. Mistype → row reverts, non-blocking inline `⚠ didn't match "SHELL" — left off.`

---

## 3. Back-compat aliases

Every renamed verb becomes a `#[command(hide = true)]` alias that still runs, prints one dim stderr line teaching the new form, and exits with the same status it always did:

```
note: `filament netcat` is now `filament reach`. Same behavior.
↳ filament reach laptop:5432
```

**Rules:** stderr only (stdout stays script-clean), once per invocation, suppressible with `FILAMENT_NO_DEPRECATION=1`, never changes exit code or output, `--json` consumers never see it. Aliases live the whole 0.x line; earliest removal is a 1.0 major with a migration note.

**Alias map:**

| Old invocation | New invocation | Stderr note |
|---|---|---|
| `filament ssh <dev>` | `filament shell <dev>` | `filament ssh` is now `filament shell` |
| `filament pty <dev>` | `filament shell <dev>` | `filament pty` is now `filament shell` |
| `filament netcat <dev> <rport>` | `filament reach <dev>:<rport>` | `filament netcat` is now `filament reach` |
| `filament dial <dev> <port>` | `filament reach <dev>:<port>` | `filament dial` is now `filament reach` |
| `filament proxy --port <p>` | `filament reach --socks --port <p>` | `filament proxy` is now `filament reach --socks` |
| `filament unexpose <port>` | `filament expose <port> --off` | `filament unexpose` is now `filament expose --off` |
| `filament unmount <mnt>` | `filament mount --off <mnt>` | `filament unmount` is now `filament mount --off` |
| `filament get <k>` | `filament set <k>` | `filament get` is now `filament set` |
| `filament unset <k>` | `filament set <k> --unset` | `filament unset` is now `filament set --unset` |
| `filament ping <dev>` | `filament status <dev>` | `filament ping` is now `filament status` |
| `filament cap-status` | `filament status` | `filament cap-status` is now `filament status` |
| `filament introduce <a> <b>` | `filament devices vouch <a> <b>` | `filament introduce` is now `filament devices vouch` |
| `filament serve-tun` | `filament net serve-tun` | `filament serve-tun` is now `filament net serve-tun` |

---

## 4. Dispatch skeleton

For each new/renamed variant, the one-line call into the fleet_ui render module + the capability/identity call it needs:

```rust
match cli.cmd {
    // === Positional router (shape-based) ===
    None if looks_like_path(&arg) => send_cmd(path),
    None if looks_like_code(&arg) => recv_cmd(code),
    None if looks_like_device_colon_port(&arg) => forward_cmd(dev, rport),
    None if looks_like_device_mesh(&arg) => reach_cmd(dev, port),
    None if looks_like_device(&arg) => shell_cmd(dev, vec![]),
    None if is_tty() => guided_picker(),
    None => { eprintln!("usage: ..."); std::process::exit(2) },

    // === Everyday ===
    Some(Cmd::Mint { fleet, external, ci, ttl, reuse, allow, audience, yes }) =>
        fleet_ui::mint::run(fleet, external, ci, ttl, reuse, allow, audience, yes),
    Some(Cmd::Requests { action }) => match action {
        Some(RequestsAction::List { all, notify }) => fleet_ui::requests::list(all, notify),
        Some(RequestsAction::Approve { id, allow, for_duration }) =>
            fleet_ui::requests::approve(id, allow, for_duration),
        Some(RequestsAction::Deny { id }) => fleet_ui::requests::deny(id),
        None => fleet_ui::requests::list(false, None),
    },

    // === Reach cluster ===
    Some(Cmd::Shell { peer, args }) => l2::ssh_cmd(&server, &peer, &args, relay),
    Some(Cmd::Reach { dev, port, socks, socks_port, bind, http_port }) => {
        if socks { l2::proxy_cmd(&server, &bind, socks_port, http_port, relay) }
        else if let (Some(d), Some(p)) = (dev, port) { l2::dial_cmd(&d, p).await }
        else { print_reach_help(); exit(2) }
    },
    Some(Cmd::Expose { port, to, peer, list, off }) => {
        if off { expose::unexpose_cmd(port.unwrap()).await }
        else { expose::expose_cmd(port, to, peer, list).await }
    },
    Some(Cmd::Mount { off: Some(path), .. }) => mount::unmount_cmd(&path),
    Some(Cmd::Mount { .. }) => mount::mount_cmd(/* all fields */),

    // === Devices ===
    Some(Cmd::Devices { action, json }) => match action {
        Some(DevicesAction::Forget { name }) => devices::forget(&name),
        Some(DevicesAction::Rename { old, new }) => devices::rename(&old, &new),
        Some(DevicesAction::Promote { device, fleet, external }) =>
            fleet_ui::devices::promote(&device, fleet, external),
        Some(DevicesAction::Vouch { a, b }) => introduce_cmd(&server, &a, &b, relay).await,
        None => devices::list(json),
    },

    // === Identity ===
    Some(Cmd::Identity { action }) => match action {
        IdentityAction::Init => identity::init(),
        IdentityAction::Show => identity::show(),
        IdentityAction::Restore => fleet_ui::recovery::restore(),
        IdentityAction::Rotate => identity::rotate(),
        IdentityAction::Revoke { device } => identity::revoke(&device),
        IdentityAction::Guardians { action } => fleet_ui::recovery::guardians(action),
        IdentityAction::Certify { device } => identity::certify(&device),
    },

    // === Admin (absorb) ===
    Some(Cmd::Status { device: Some(dev), json }) => status_device_cmd(&dev, json),
    Some(Cmd::Status { json, .. }) => status_cmd(json),
    Some(Cmd::Set { key: Some(k), unset: true, .. }) => settings::run_unset(&k, &peer),
    Some(Cmd::Set { key: Some(k), value: None, show_origin, default, json, .. }) =>
        settings::run_get(&k, &peer, show_origin, default, json),
    Some(Cmd::Set { key, value, .. }) => settings::run_set(key, value, peer, dry_run, reset, yes, json),

    // === Deprecated aliases ===
    Some(Cmd::Ssh { peer, args }) => {
        eprintln!("note: `filament ssh` is now `filament shell`. Same behavior.\n↳ filament shell {peer}");
        l2::ssh_cmd(&server, &peer, &args, relay).await
    },
    Some(Cmd::Netcat { peer, rport }) => {
        eprintln!("note: `filament netcat` is now `filament reach`. Same behavior.\n↳ filament reach {peer}:{rport}");
        l2::netcat_cmd(&server, &peer, rport, relay).await
    },
    Some(Cmd::Dial { peer, port }) => {
        eprintln!("note: `filament dial` is now `filament reach`. Same behavior.\n↳ filament reach {peer}:{port}");
        l2::dial_cmd(&peer, port).await
    },
    Some(Cmd::Proxy { port, bind, http_port }) => {
        eprintln!("note: `filament proxy` is now `filament reach --socks`. Same behavior.\n↳ filament reach --socks --port {port}");
        l2::proxy_cmd(&server, &bind, port, http_port, relay).await
    },
    Some(Cmd::Unexpose { port }) => {
        eprintln!("note: `filament unexpose` is now `filament expose {port} --off`. Same behavior.");
        expose::unexpose_cmd(port).await
    },
    Some(Cmd::Unmount { path }) => {
        eprintln!("note: `filament unmount` is now `filament mount --off {path}`. Same behavior.");
        mount::unmount_cmd(&path)
    },
    Some(Cmd::Get { key, peer, show_origin, default, json }) => {
        eprintln!("note: `filament get` is now `filament set {key}`. Same behavior.");
        settings::run_get(&key, &peer, show_origin, default, json)
    },
    Some(Cmd::Unset { key, peer }) => {
        eprintln!("note: `filament unset` is now `filament set {key} --unset`. Same behavior.");
        settings::run_unset(&key, &peer)
    },
    Some(Cmd::Ping { peer, count, json }) => {
        eprintln!("note: `filament ping` is now `filament status {peer}` or `filament doctor {peer}`. Same behavior.");
        ping::ping_cmd(&server, &peer, count, json, relay).await
    },
    Some(Cmd::CapStatus { json }) => {
        eprintln!("note: `filament cap-status` is now `filament status`. Same behavior.");
        cap_status_cmd(json).await
    },
    Some(Cmd::Introduce { a, b }) => {
        eprintln!("note: `filament introduce` is now `filament devices vouch`. Same behavior.");
        introduce_cmd(&server, &a, &b, relay).await
    },
    Some(Cmd::ServeTun { .. }) => {
        eprintln!("note: `filament serve-tun` is now `filament net serve-tun`. Same behavior.");
        serve_tun_cmd(/* fields */)
    },
    Some(Cmd::Pty { peer, cmd }) => {
        eprintln!("note: `filament pty` is now `filament shell`. Same behavior.");
        l2::pty_cmd(&server, &peer, relay, cmd).await
    },

    // === Keep (unchanged) ===
    Some(Cmd::Send { .. }) => send_cmd(),
    Some(Cmd::Recv { .. }) => recv_cmd(),
    Some(Cmd::Pair { .. }) => pair_cmd(),
    Some(Cmd::Up { .. }) => up_cmd(),
    Some(Cmd::Doctor { .. }) => doctor_cmd(),
    Some(Cmd::Forward { lport, peer, rport }) => l2::forward_cmd(&server, lport, &peer, rport, relay).await,
    Some(Cmd::Grant { .. }) => grant_cmd(),
    Some(Cmd::Revoke { device, capability }) => revoke_cmd(&device, &capability),
    Some(Cmd::Down) => down_cmd(),
    Some(Cmd::Addr { .. }) => addr_cmd(),
    Some(Cmd::Backup { .. }) => backup_cmd(),
    Some(Cmd::Update { .. }) => update_cmd(),
    Some(Cmd::Net { action }) => match action {
        NetAction::ServeTun { .. } => serve_tun_cmd(),
    },
    Some(Cmd::Completions { shell }) => completions_cmd(shell),
    Some(Cmd::Man) => man_cmd(),
    Some(Cmd::Config { key, value }) => config_cmd(key, value),
}
```

---

## Design-vs-copy conflicts

1. **`promote` placement.** `design-command-surface.md` line 69 lists `promote` under
   `identity {init,restore,rotate,revoke,certify,promote}`, but `ux-copy-final.md` Surface
   3e shows `filament devices promote old-laptop`. Recommend: `promote` stays under
   `devices` — it's about sorting a device into fleet/external, not identity key admin.

2. **`requests --notify` flag.** `ux-copy-final.md` Surface 3f shows
   `filament requests --notify 'notify-send %s'` (also webhook, email). The current
   `RequestsAction::List` has no `--notify` flag. This is a new addition needed for the
   notification surface.

3. **`grant --tag` vs `revoke`.** Current `Grant` has a `--tag` flag (line 918) but
   `Revoke` does not. The design doc keeps both as first-class but doesn't mention
   tag-scoped revoke. Need to decide: add `--tag` to `Revoke` or leave device-only.

4. **`identity revoke` vs top-level `revoke`.** The design doc has both: top-level
   `revoke <device> <cap>` (capability revocation) and `identity revoke` (certificate
   revocation). These are different verbs with different semantics. The dispatch must
   route correctly — `filament revoke laptop shell` is capability, `filament identity
   revoke laptop` is cert.
