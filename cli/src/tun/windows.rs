//! Windows Wintun backend for the `tun` module: create a Wintun adapter (the same
//! userspace TUN driver WireGuard/Tailscale use) via `wintun.dll`, and set
//! addr/mtu/route through `netsh`.
//!
//! Wintun's ring API is blocking and Windows has no `AsyncFd`, so a dedicated
//! reader thread drains `receive_blocking()` into a channel that the async `recv`
//! awaits; `send` allocates from the ring and is effectively non-blocking. Wintun
//! packets are bare IP (no framing), like Linux with IFF_NO_PI, so callers exchange
//! plain packets. Requires Administrator (adapter creation) and `wintun.dll` beside
//! filament.exe.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// A Wintun adapter session plus the async plumbing. Dropping it shuts the session
/// down (unblocking the reader thread) and removes the adapter.
pub struct Tun {
    session: Arc<wintun::Session>,
    name: String,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    _reader: std::thread::JoinHandle<()>,
}

impl Tun {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open (or create) the `name` adapter, assign `cidr`, set `mtu`, and start
    /// pumping. Needs Administrator + wintun.dll.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<Tun> {
        let wintun = load_wintun().context("load wintun.dll (bundle it beside filament.exe)")?;
        let adapter = wintun::Adapter::open(&wintun, name)
            .or_else(|_| wintun::Adapter::create(&wintun, name, "Filament", None))
            .map_err(|e| {
                anyhow::anyhow!(
                    "create Wintun adapter '{name}': {e}. L3 on Windows needs Administrator and wintun.dll."
                )
            })?;
        let session =
            Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).context("start Wintun session")?);

        // Blocking ring -> channel: a reader thread feeds recv() so the overlay's
        // async loop never blocks. shutdown() (on Drop) makes receive_blocking()
        // return an error, so the thread exits cleanly.
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let rsess = session.clone();
        let reader = std::thread::spawn(move || loop {
            match rsess.receive_blocking() {
                Ok(pkt) => {
                    if tx.send(pkt.bytes().to_vec()).is_err() {
                        break; // receiver dropped (Tun gone)
                    }
                }
                Err(_) => break, // session shut down or adapter removed
            }
        });

        // Configure addr/mtu via netsh (route for the overlay prefix is add_route's
        // job, called by l3.rs with the device name).
        let (addr, prefixlen) = split_cidr(cidr);
        let proto = if addr.contains(':') { "ipv6" } else { "ipv4" };
        // `set address` first (idempotent for an existing adapter), then `add`.
        let addr_spec = format!("address={addr}/{prefixlen}");
        let iface = format!("interface={name}");
        netsh(&["interface", proto, "set", "address", &iface, &addr_spec])
            .or_else(|_| netsh(&["interface", proto, "add", "address", &iface, &addr_spec]))
            .with_context(|| format!("netsh set address {addr}/{prefixlen} on {name}"))?;
        // MTU is best-effort (a Wintun default is fine if this fails).
        let _ = netsh(&["interface", proto, "set", "subinterface", name, &format!("mtu={mtu}"), "store=active"]);

        Ok(Tun { session, name: name.to_string(), rx: Mutex::new(rx), _reader: reader })
    }

    /// Await one IP packet from the reader thread's channel.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => bail!("wintun reader stopped"),
        }
    }

    /// Send one IP packet: allocate from the ring, copy, transmit (non-blocking).
    pub async fn send(&self, packet: &[u8]) -> Result<usize> {
        let len = packet.len();
        let mut p = self
            .session
            .allocate_send_packet(len as u16)
            .map_err(|e| anyhow::anyhow!("wintun allocate_send_packet: {e}"))?;
        p.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(p);
        Ok(len)
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        // Unblock the reader thread's receive_blocking() so it exits; the adapter is
        // removed when the last Arc<Session>/Adapter drops.
        let _ = self.session.shutdown();
    }
}

/// Load wintun.dll from a TRUSTED absolute path only: beside filament.exe, else
/// System32. Both are admin-writable-only locations.
///
/// SECURITY: we deliberately never fall back to the loader's ambient search
/// (`wintun::load()`, which probes the CWD and PATH). This process runs elevated,
/// so honoring CWD/PATH would be a classic DLL-planting privilege-escalation
/// vector - an attacker drops a malicious `wintun.dll` and gets code execution as
/// Administrator. Refuse to run instead.
fn load_wintun() -> Result<wintun::Wintun> {
    let exe = std::env::current_exe().context("resolve current exe")?;
    let beside = exe.parent().context("exe directory")?.join("wintun.dll");
    let system32 = {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        std::path::PathBuf::from(root).join("System32\\wintun.dll")
    };
    let dll = if beside.exists() {
        beside
    } else if system32.exists() {
        system32
    } else {
        bail!(
            "wintun.dll not found next to filament.exe or in System32; refusing to search CWD/PATH \
             (DLL-hijack guard). Reinstall filament, or place WireGuard's signed wintun.dll beside filament.exe."
        );
    };
    unsafe { wintun::load_from_path(&dll) }.map_err(|e| anyhow::anyhow!("load {}: {e}", dll.display()))
}

/// Split `addr/prefixlen`; a bare address defaults to a host route (/128 or /32).
fn split_cidr(cidr: &str) -> (String, String) {
    match cidr.split_once('/') {
        Some((a, p)) => (a.to_string(), p.to_string()),
        None => (cidr.to_string(), if cidr.contains(':') { "128".into() } else { "32".into() }),
    }
}

/// Route `cidr` at `dev` (the overlay prefix -> the Wintun adapter). An existing
/// identical route ("already exists") is treated as success.
pub fn add_route(cidr: &str, dev: &str) -> Result<()> {
    let proto = if cidr.contains(':') { "ipv6" } else { "ipv4" };
    let out = std::process::Command::new("netsh")
        .args(["interface", proto, "add", "route", cidr, &format!("interface={dev}")])
        .output()
        .context("exec netsh")?;
    if !out.status.success() {
        // netsh writes diagnostics to stdout, so check both streams.
        let msg = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !msg.to_lowercase().contains("already exists") {
            bail!("netsh add route {cidr} interface={dev}: {}", msg.trim());
        }
    }
    Ok(())
}

/// Windows has no capability model; Wintun adapter creation needs Administrator.
/// We can't self-elevate, so guide; the real check is the adapter-create error.
pub fn ensure_net_admin_for_l3() -> bool {
    eprintln!("  L3 on Windows needs Administrator and wintun.dll beside filament.exe.");
    true
}

/// The Windows daemon runs elevated (Wintun requires it), so the hosts file is
/// writable for MagicDNS. Nothing to grant.
pub fn ensure_hosts_writable() {}

fn netsh(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("netsh").args(args).output().context("exec netsh")?;
    if !out.status.success() {
        let msg = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        bail!("netsh {}: {}", args.join(" "), msg.trim());
    }
    Ok(())
}
