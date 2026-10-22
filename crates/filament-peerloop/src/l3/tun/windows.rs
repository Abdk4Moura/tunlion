//! Windows Wintun backend for the `tun` module: create a Wintun adapter (the same
//! userspace TUN driver WireGuard/Tailscale use) via `wintun.dll`, and set
//! addr/mtu/route through `netsh`.
//!
//! Wintun's ring API is blocking and Windows has no `AsyncFd`, so a dedicated
//! reader thread drains `receive_blocking()` into a channel that the async `recv`
//! awaits; `send` allocates from the ring and is effectively non-blocking. Wintun
//! packets are bare IP (no framing), like Linux with IFF_NO_PI, so callers exchange
//! plain packets. Requires Administrator (adapter creation) and `wintun.dll` beside
//! tunlion.exe.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use super::{WINTUN_DLL_ABSENT, WINTUN_NOT_ELEVATED};

/// Is this process running with an elevated token? (Same query the CLI's
/// platform layer used; kept here so the backend is self-contained.)
fn process_is_elevated() -> bool {
    unsafe {
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn OpenProcessToken(h: isize, access: u32, tok: *mut isize) -> i32;
            fn GetTokenInformation(
                tok: isize,
                cls: u32,
                buf: *mut u8,
                len: u32,
                ret: *mut u32,
            ) -> i32;
            fn CloseHandle(h: isize) -> i32;
        }
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ELEVATION: u32 = 20;
        let mut tok: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut elevated: u32 = 0;
        let mut ret: u32 = 0;
        let ok = GetTokenInformation(
            tok,
            TOKEN_ELEVATION,
            &mut elevated as *mut u32 as *mut u8,
            std::mem::size_of::<u32>() as u32,
            &mut ret,
        );
        CloseHandle(tok);
        ok != 0 && elevated != 0
    }
}

/// A Wintun adapter session plus the async plumbing. Dropping it shuts the session
/// down (unblocking the reader thread) and removes the adapter.
pub struct KernelTun {
    session: Arc<wintun::Session>,
    name: String,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    _reader: std::thread::JoinHandle<()>,
}

impl KernelTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open (or create) the `name` adapter, assign `cidr`, set `mtu`, and start
    /// pumping. Needs Administrator + wintun.dll.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<KernelTun> {
        let wintun = load_wintun()?;
        // Wintun 0.5 does not surface GetLastError: every adapter/session
        // failure is "Failed to create adapter" / "WintunStartSession failed".
        // The token state is therefore the only reliable separator between the
        // not-elevated case and a genuinely unrelated adapter error.
        let elevated = process_is_elevated();
        let adapter = wintun::Adapter::open(&wintun, name)
            .or_else(|_| wintun::Adapter::create(&wintun, name, "Tunlion", None))
            .map_err(|e| {
                wintun_error(&format!("create Wintun adapter '{name}'"), &e, elevated)
            })?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| {
                    wintun_error(&format!("start Wintun session on '{name}'"), &e, elevated)
                })?,
        );

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

        Ok(KernelTun { session, name: name.to_string(), rx: Mutex::new(rx), _reader: reader })
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

// Expose the Wintun device through the overlay's device seam (fully-qualified
// inherent calls: no ambiguity with the trait methods, no accidental recursion).
#[async_trait::async_trait]
impl crate::l3::tun::TunDevice for KernelTun {
    fn name(&self) -> &str {
        KernelTun::name(self)
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        KernelTun::recv(self, buf).await
    }
    async fn send(&self, packet: &[u8]) -> Result<usize> {
        KernelTun::send(self, packet).await
    }
}

impl Drop for KernelTun {
    fn drop(&mut self) {
        // Unblock the reader thread's receive_blocking() so it exits; the adapter is
        // removed when the last Arc<Session>/Adapter drops.
        let _ = self.session.shutdown();
    }
}

/// Load wintun.dll from a TRUSTED absolute path only: beside tunlion.exe, else
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
            "{WINTUN_DLL_ABSENT}; refusing to search CWD/PATH (DLL-hijack guard)"
        );
    };
    unsafe { wintun::load_from_path(&dll) }.map_err(|e| anyhow::anyhow!("load {}: {e}", dll.display()))
}

/// Turn a Wintun adapter/session error into the text `l3` classifies.
///
/// The classifier itself (`tun::classify_wintun_failure`) lives one module up,
/// so its three-way mapping is unit-tested on every runner; this backend's job
/// is to emit the elevation marker accurately.
///
/// Wintun 0.5 discards the Win32 error behind `WintunCreateAdapter` and
/// `WintunStartSession` ("Failed to create adapter"), so an `ERROR_ACCESS_DENIED`
/// string is not available to match on. The process token is: a failure while
/// not elevated is the elevation case, and a failure while elevated keeps its
/// own text rather than being dressed up as a cause we did not identify.
fn wintun_error(context: &str, e: &dyn std::fmt::Display, elevated: bool) -> anyhow::Error {
    let text = e.to_string();
    if elevated {
        anyhow::anyhow!("{context}: {text}")
    } else {
        anyhow::anyhow!("{context}: {text}. The {WINTUN_NOT_ELEVATED}.")
    }
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
    let out = crate::l3::command("netsh")
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

/// Withdraw a route previously installed by `add_route`.
///
/// A route that is already gone is SUCCESS, not an error: reconciliation runs on
/// every advertisement, and a peer that withdraws a prefix twice must not turn
/// into a stream of failures.
pub fn del_route(cidr: &str, dev: &str) -> Result<()> {
    let proto = if cidr.contains(':') { "ipv6" } else { "ipv4" };
    let out = crate::l3::command("netsh")
        .args(["interface", proto, "delete", "route", cidr, &format!("interface={dev}")])
        .output()
        .context("exec netsh delete route")?;
    if !out.status.success() {
        // netsh writes diagnostics to stdout, so check both streams.
        let msg = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !msg.contains("Element not found") && !msg.contains("not found") {
            bail!("netsh {proto} delete route {cidr}: {}", msg.trim());
        }
    }
    Ok(())
}

/// Assign an ADDITIONAL address `cidr` to `dev` (the node's v4 overlay address
/// alongside the primary v6 ULA). `set` first (idempotent for an existing adapter),
/// then `add`, mirroring `open`.
pub fn add_addr(cidr: &str, dev: &str) -> Result<()> {
    let (addr, prefixlen) = split_cidr(cidr);
    let proto = if addr.contains(':') { "ipv6" } else { "ipv4" };
    let addr_spec = format!("address={addr}/{prefixlen}");
    let iface = format!("interface={dev}");
    netsh(&["interface", proto, "set", "address", &iface, &addr_spec])
        .or_else(|_| netsh(&["interface", proto, "add", "address", &iface, &addr_spec]))
        .with_context(|| format!("netsh add address {addr}/{prefixlen} on {dev}"))
}

/// Windows has no capability model; Wintun adapter creation needs Administrator.
/// We can't self-elevate, so guide; the real check is the adapter-create error.
pub fn ensure_net_admin_for_l3() -> bool {
    eprintln!(
        "  L3 on Windows needs Administrator (adapter creation) and wintun.dll beside tunlion.exe. \
         For the always-on service run `tunlion up --install`; for a kernel adapter run this shell \
         as Administrator."
    );
    true
}

/// No one-time grant exists on Windows (Wintun needs an elevated daemon), so
/// there is nothing to offer at `init`.
pub fn l3_grant_pending() -> Option<String> {
    None
}

/// Nothing on Windows blocks the kernel overlay in a way a grant could not
/// address; the daemon's own privilege decides it.
pub fn l3_blocker() -> Option<String> {
    None
}

/// The Windows daemon runs elevated (Wintun requires it), so the hosts file is
/// writable for MagicDNS. Nothing to grant.
pub fn ensure_hosts_writable() {}

fn netsh(args: &[&str]) -> Result<()> {
    let out = crate::l3::command("netsh").args(args).output().context("exec netsh")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::tun::{classify_wintun_failure, WintunFailure};

    /// The backend has to emit the marker the cross-platform classifier keys
    /// on. Wintun gives no Win32 detail, so the token state is the signal.
    #[test]
    fn a_non_elevated_process_emits_the_not_elevated_marker() {
        let denied = wintun_error(
            "create Wintun adapter 'tunlion0'",
            &"Failed to create adapter",
            false,
        );
        assert_eq!(
            classify_wintun_failure(&denied.to_string()),
            Some(WintunFailure::NotElevated),
            "{denied}"
        );
        assert!(denied.to_string().contains(WINTUN_NOT_ELEVATED), "{denied}");
    }

    /// An elevated process that still fails is NOT an elevation problem: the
    /// OS text is what the operator needs, even when it is only Wintun's
    /// unhelpful "Failed to create adapter".
    #[test]
    fn an_elevated_adapter_error_stays_other() {
        let e = wintun_error(
            "create Wintun adapter 'tunlion0'",
            &"Failed to create adapter",
            true,
        );
        assert_eq!(classify_wintun_failure(&e.to_string()), Some(WintunFailure::Other));
        assert!(!e.to_string().contains(WINTUN_NOT_ELEVATED), "{e}");
    }

    /// The absent-DLL error text is the marker itself.
    #[test]
    fn a_missing_dll_is_classified_as_absent() {
        let raw = format!("{WINTUN_DLL_ABSENT}; refusing to search CWD/PATH (DLL-hijack guard)");
        assert_eq!(classify_wintun_failure(&raw), Some(WintunFailure::DllAbsent));
    }
}
