//! Linux TUN backend for the `tun` module: open `/dev/net/tun`, hand back an async
//! read/write handle so the overlay pump can move raw IP packets between the kernel
//! and a filament link's QUIC datagrams.
//!
//! Deliberately dependency-light, matching the rest of the CLI: one `TUNSETIFF`
//! ioctl via `libc`, the device's addr/mtu/up set through `iproute2` (no netlink
//! crate), and the fd wrapped in tokio's `AsyncFd` for readiness-driven async IO.
//! With IFF_NO_PI there is no per-packet framing, so `recv`/`send` exchange bare
//! IP packets directly (the macOS backend adds/strips a 4-byte header to match).

use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

/// CAP_NET_ADMIN bit index (from <linux/capability.h>): needed to create a TUN.
const CAP_NET_ADMIN: u64 = 12;

/// True if this process can create a TUN: running as root, or the binary carries
/// CAP_NET_ADMIN (which every exec of it, including this one, gets effectively).
pub fn have_net_admin() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("CapEff:")).map(|l| l.to_string()))
        .and_then(|l| u64::from_str_radix(l["CapEff:".len()..].trim(), 16).ok())
        .map(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
        .unwrap_or(false)
}

/// Raise CAP_NET_ADMIN into this process's AMBIENT set so the `ip` child processes
/// that configure the overlay (addr/mtu/up/route) inherit it. A file capability
/// (setcap) is Permitted+Effective in THIS process but is NOT passed to children
/// across exec unless it is ambient, so without this a non-root daemon opens the
/// TUN fine (in-process ioctl) yet `ip addr add` fails "permission denied". The
/// `setcap ...+eip` grant puts the cap in Permitted+Inheritable; we raise it into
/// the ambient set here. Best-effort + harmless for a root daemon (already has it).
pub fn raise_net_admin_ambient() {
    const CAP_NET_ADMIN: u32 = 12;
    const VER3: u32 = 0x2008_0522; // _LINUX_CAPABILITY_VERSION_3
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // After a normal user execs a setcap'd binary, CAP_NET_ADMIN is in Permitted+
    // Effective but Inheritable is EMPTY (a user's inheritable set is empty, and a
    // file +i bit only carries if the PROCESS already had it inheritable). Ambient
    // raise needs Permitted AND Inheritable, so we must first promote it into
    // Inheritable (allowed because it is in Permitted). Then children we exec (the
    // `ip` commands) inherit it. libc lacks capget/capset, so use raw syscalls.
    unsafe {
        let mut hdr = Hdr { version: VER3, pid: 0 };
        let mut data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
        if libc::syscall(libc::SYS_capget, &mut hdr as *mut Hdr, data.as_mut_ptr()) == 0
            && data[0].permitted & (1 << CAP_NET_ADMIN) != 0
        {
            data[0].inheritable |= 1 << CAP_NET_ADMIN;
            let _ = libc::syscall(libc::SYS_capset, &hdr as *const Hdr, data.as_ptr());
        }
        let _ = libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN as libc::c_ulong, 0, 0);
    }
}

/// The one-time command that lets a NON-root daemon open the tunnel device.
pub fn cap_grant_cmd() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "filament".into());
    format!("sudo setcap cap_net_admin+eip {exe}")
}

/// True if this process could write the MagicDNS block into /etc/hosts: root
/// always can; a non-root daemon needs write on the file itself (e.g. a per-file
/// ACL). Note the file being writable is necessary but the atomic temp+rename in
/// l3.rs also needs the /etc directory writable, so the writer falls back to an
/// in-place write when only the file is granted.
fn hosts_writable() -> bool {
    unsafe {
        libc::geteuid() == 0
            || libc::access(b"/etc/hosts\0".as_ptr() as *const libc::c_char, libc::W_OK) == 0
    }
}

/// The one-time command that lets a NON-root daemon write the MagicDNS block in
/// root-owned /etc/hosts. A per-file ACL for the daemon user is the narrowest
/// grant possible: only this user, only this file, only rw. No capability
/// escalation on the binary, unlike cap_dac_override.
pub fn hosts_grant_cmd() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "$(whoami)".into());
    format!("sudo setfacl -m u:{user}:rw /etc/hosts")
}

/// Best-effort: let a non-root daemon publish MagicDNS names (`<peer>.mesh`) by
/// granting it write on /etc/hosts via a per-file ACL. Interactive => one sudo
/// prompt; non-interactive => print the command. The overlay works by IP with or
/// without this, so a failure here is never fatal.
pub fn ensure_hosts_writable() {
    if hosts_writable() {
        return;
    }
    let Ok(user) = std::env::var("USER") else { return };
    let cmd = hosts_grant_cmd();
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        eprintln!("  MagicDNS names (<peer>.mesh) need write access to root-owned /etc/hosts.");
        eprintln!("  granting a per-file ACL now: {cmd}");
        let ok = std::process::Command::new("sudo")
            .args(["setfacl", "-m", &format!("u:{user}:rw"), "/etc/hosts"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            eprintln!("  done. peer names will resolve after the next announce (overlay already works by IP).");
        } else {
            eprintln!("  could not grant automatically (install the `acl` package, or run it yourself):\n    {cmd}");
            eprintln!("  overlay still works by IP without this.");
        }
    } else {
        eprintln!("  MagicDNS names need /etc/hosts write; run once:\n    {cmd}\n  overlay still works by IP without this.");
    }
}

/// Make L3 work for a non-root daemon with as few steps as possible: if we lack
/// CAP_NET_ADMIN and we're at a terminal, run the one-time `setcap` now (a single
/// sudo prompt) so a later `filament up` just works; otherwise print the exact
/// command. Also grants /etc/hosts write for MagicDNS names. A no-op for each
/// grant already in place. Returns true if the capability is present or granted.
pub fn ensure_net_admin_for_l3() -> bool {
    ensure_hosts_writable();
    if have_net_admin() {
        return true;
    }
    let cmd = cap_grant_cmd();
    // Only self-grant interactively (a daemon has no tty to answer a sudo prompt).
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        eprintln!("  L3 needs a one-time capability so a non-root daemon can open the tunnel device (like WireGuard).");
        eprintln!("  granting now: {cmd}");
        let granted = std::env::current_exe()
            .ok()
            .and_then(|exe| {
                std::process::Command::new("sudo")
                    .args(["setcap", "cap_net_admin+eip"])
                    .arg(exe)
                    .status()
                    .ok()
            })
            .map(|s| s.success())
            .unwrap_or(false);
        if granted {
            eprintln!("  done. restart the daemon (or run `filament up`) to bring up the overlay.");
        } else {
            eprintln!("  could not grant automatically; run it yourself, then restart the daemon:\n    {cmd}");
        }
        granted
    } else {
        eprintln!("  L3 needs a one-time capability for a non-root daemon; run it, then restart:\n    {cmd}");
        false
    }
}

// From <linux/if_tun.h> / <net/if.h>. `libc::Ioctl` is the platform's ioctl
// request type: c_ulong on glibc but c_int on musl, so use the alias (a bare
// c_ulong fails to compile for the musl release target).
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000; // no 4-byte packet-info prefix; raw IP

/// `struct ifreq` (40 bytes on Linux): a 16-byte name then a union we only use
/// the leading `short` flags field of. The trailing pad keeps the size/layout
/// the kernel expects for the ioctl.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// A TUN device plus an async handle on its fd. Dropping it closes the fd; the
/// kernel removes the interface once the last fd is gone.
pub struct KernelTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl KernelTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open `name` as a TUN (IFF_TUN | IFF_NO_PI), then assign `cidr`, set `mtu`,
    /// and bring it up via iproute2. `name` must be < 16 bytes.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<KernelTun> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            bail!("tun name '{name}' must be 1..15 bytes");
        }
        // O_RDWR|O_NONBLOCK so AsyncFd drives readiness instead of blocking reads.
        let raw = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                bail!(
                    "open /dev/net/tun: permission denied. L3 needs CAP_NET_ADMIN; grant it once:\n    {}\nthen restart the daemon (or run the daemon as root).",
                    cap_grant_cmd()
                );
            }
            bail!("open /dev/net/tun: {e}");
        }
        // OwnedFd from here on, so any early return below closes the fd.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut req: IfReq = unsafe { std::mem::zeroed() };
        for (i, &b) in name.as_bytes().iter().enumerate() {
            req.name[i] = b as libc::c_char;
        }
        req.flags = IFF_TUN | IFF_NO_PI;
        let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                bail!(
                    "TUNSETIFF {name}: permission denied. L3 needs CAP_NET_ADMIN; grant it once:\n    {}\nthen restart the daemon.",
                    cap_grant_cmd()
                );
            }
            bail!("TUNSETIFF {name}: {e}");
        }

        // Configure via iproute2: robust across distros and avoids a second round
        // of ioctl/netlink. The interface exists now (the ioctl created it). Raise
        // CAP_NET_ADMIN ambient first so these `ip` children inherit it (a non-root
        // daemon's file cap does not cross exec on its own).
        raise_net_admin_ambient();
        ip(&["addr", "add", cidr, "dev", name]).with_context(|| format!("ip addr add {cidr} dev {name}"))?;
        ip(&["link", "set", "dev", name, "mtu", &mtu.to_string()]).context("ip link set mtu")?;
        ip(&["link", "set", "dev", name, "up"]).context("ip link set up")?;

        let fd = AsyncFd::new(owned).context("register tun fd with the reactor")?;
        Ok(KernelTun { fd, name: name.to_string() })
    }

    /// Read one IP packet from the kernel (one packet per read for IFF_NO_PI TUN).
    /// Errors only on a real fd error; EWOULDBLOCK is handled by the reactor.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res.map_err(Into::into),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet to the kernel. A short write should not happen for a
    /// single packet on a TUN; we surface the count and let the caller decide.
    pub async fn send(&self, packet: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.as_raw_fd(), packet.as_ptr() as *const libc::c_void, packet.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res.map_err(Into::into),
                Err(_would_block) => continue,
            }
        }
    }
}

// Expose the kernel TUN through the overlay's device seam. Fully-qualified inherent
// calls (no `self.recv(..)`) so there is zero ambiguity with the trait methods and
// no chance of accidental recursion.
#[async_trait::async_trait]
impl crate::tun::TunDevice for KernelTun {
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

/// Route `cidr` at the given device (the overlay prefix -> the TUN, so the kernel
/// hands every overlay packet to userspace for per-peer demux). Idempotent-ish: a
/// pre-existing identical route is treated as success.
pub fn add_route(cidr: &str, dev: &str) -> Result<()> {
    let fam = if cidr.contains(':') { "-6" } else { "-4" };
    let out = std::process::Command::new("ip")
        .args([fam, "route", "replace", cidr, "dev", dev])
        .output()
        .context("exec ip route")?;
    if !out.status.success() {
        bail!("ip {fam} route replace {cidr} dev {dev}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Assign an ADDITIONAL address `cidr` to `dev` (the node's v4 overlay address on
/// top of the primary v6 ULA, so the kernel delivers inbound v4 overlay packets
/// locally). CAP_NET_ADMIN ambient is already raised by `KernelTun::open`, so the
/// child `ip` inherits it. An existing identical address ("File exists") is success.
pub fn add_addr(cidr: &str, dev: &str) -> Result<()> {
    let fam = if cidr.contains(':') { "-6" } else { "-4" };
    let out = std::process::Command::new("ip")
        .args([fam, "addr", "add", cidr, "dev", dev])
        .output()
        .context("exec ip addr")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("File exists") {
            bail!("ip {fam} addr add {cidr} dev {dev}: {}", err.trim());
        }
    }
    Ok(())
}

/// Run an `ip` (iproute2) command, mapping a non-zero exit to an error with the
/// captured stderr so a misconfig is legible.
fn ip(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("ip")
        .args(args)
        .output()
        .context("exec ip (iproute2 not installed?)")?;
    if !out.status.success() {
        bail!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
