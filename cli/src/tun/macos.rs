//! macOS utun backend for the `tun` module: create a `utun` interface via a
//! PF_SYSTEM control socket (the same mechanism WireGuard-go uses), wrap its fd in
//! tokio's `AsyncFd`, and set addr/mtu/route through `ifconfig`/`route`.
//!
//! Two macOS specifics are hidden here so `l3.rs` stays portable:
//! - utun devices are kernel-named `utunN` and cannot be renamed, so the requested
//!   name (`filament0`) is ignored and the real name is reported by `name()`.
//! - each packet on a utun carries a 4-byte address-family header; `recv`/`send`
//!   strip/prepend it with readv/writev so callers exchange bare IP packets.
//!
//! Dependency-light, matching the Linux backend: just `libc` plus the system CLI.

use anyhow::{bail, Context, Result};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

/// The kernel control name for the utun family (from <net/if_utun.h>).
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
/// getsockopt option (level SYSPROTO_CONTROL) to read back the assigned ifname.
const UTUN_OPT_IFNAME: libc::c_int = 2;

/// A utun device plus an async handle on its fd. Dropping it closes the fd; the
/// kernel removes the interface once the last fd is gone.
pub struct KernelTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl KernelTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create a utun (kernel picks `utunN`), assign `cidr`, set `mtu`, bring it up.
    /// `requested` is ignored (utun devices can't be named); use `name()` after.
    pub fn open(_requested: &str, cidr: &str, mtu: u32) -> Result<KernelTun> {
        let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                bail!("open utun control socket: permission denied. L3 on macOS needs root; run the daemon with sudo.");
            }
            bail!("open utun control socket: {e}");
        }
        // OwnedFd from here on, so any early return closes the fd.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        // Resolve the utun kernel-control id by name.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (i, &b) in UTUN_CONTROL_NAME.iter().enumerate() {
            info.ctl_name[i] = b as libc::c_char;
        }
        if unsafe { libc::ioctl(owned.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
            bail!("CTLIOCGINFO utun: {}", std::io::Error::last_os_error());
        }

        // connect() with sc_unit = 0 asks the kernel for the next free utunN.
        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0;
        let rc = unsafe {
            libc::connect(
                owned.as_raw_fd(),
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                bail!("create utun: permission denied. L3 on macOS needs root; run the daemon with sudo.");
            }
            bail!("create utun: {e}");
        }

        // Read back the assigned interface name (utunN).
        let mut name_buf = [0u8; 32];
        let mut name_len = name_buf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut libc::c_void,
                &mut name_len,
            )
        };
        if rc < 0 {
            bail!("read utun name: {}", std::io::Error::last_os_error());
        }
        let end = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
        let name = String::from_utf8_lossy(&name_buf[..end]).into_owned();

        // Non-blocking so AsyncFd drives readiness instead of blocking reads.
        unsafe {
            let flags = libc::fcntl(owned.as_raw_fd(), libc::F_GETFL, 0);
            libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        // Configure via ifconfig/route (robust, avoids a second syscall dance). The
        // interface exists now (connect created it).
        let (addr_str, prefixlen) = split_cidr(cidr);
        let fam = if addr_str.contains(':') { "inet6" } else { "inet" };
        ifconfig(&[&name, fam, &addr_str, "prefixlen", &prefixlen, "up"])
            .with_context(|| format!("ifconfig {name} {fam} {addr_str}"))?;
        // MTU is best-effort: a utun default (1500/2000) is fine if this fails.
        let _ = ifconfig(&[&name, "mtu", &mtu.to_string()]);

        let fd = AsyncFd::new(owned).context("register utun fd with the reactor")?;
        Ok(KernelTun { fd, name })
    }

    /// Read one IP packet. utun prepends a 4-byte address-family word; readv lands
    /// the AF in a scratch and the IP packet directly in `buf`, so the caller sees
    /// a bare packet. Returns the packet length (excluding the 4-byte header).
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let mut af = [0u8; 4];
                let iov = [
                    libc::iovec { iov_base: af.as_mut_ptr() as *mut libc::c_void, iov_len: 4 },
                    libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() },
                ];
                let n = unsafe { libc::readv(inner.as_raw_fd(), iov.as_ptr(), 2) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok((n as usize).saturating_sub(4))
                }
            }) {
                Ok(res) => return res.map_err(Into::into),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet, prepending the 4-byte AF header (network byte order)
    /// that utun requires, chosen from the IP version. Returns bytes of packet sent.
    pub async fn send(&self, packet: &[u8]) -> Result<usize> {
        let af: u32 = match packet.first().map(|b| b >> 4) {
            Some(6) => libc::AF_INET6 as u32,
            _ => libc::AF_INET as u32,
        };
        let hdr = af.to_be_bytes();
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let iov = [
                    libc::iovec { iov_base: hdr.as_ptr() as *mut libc::c_void, iov_len: 4 },
                    libc::iovec { iov_base: packet.as_ptr() as *mut libc::c_void, iov_len: packet.len() },
                ];
                let n = unsafe { libc::writev(inner.as_raw_fd(), iov.as_ptr(), 2) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok((n as usize).saturating_sub(4))
                }
            }) {
                Ok(res) => return res.map_err(Into::into),
                Err(_would_block) => continue,
            }
        }
    }
}

// Expose the kernel utun through the overlay's device seam (fully-qualified inherent
// calls: no ambiguity with the trait methods, no accidental recursion).
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

/// Split `addr/prefixlen`; a bare address defaults to a host route (/128 or /32).
fn split_cidr(cidr: &str) -> (String, String) {
    match cidr.split_once('/') {
        Some((a, p)) => (a.to_string(), p.to_string()),
        None => (cidr.to_string(), if cidr.contains(':') { "128".into() } else { "32".into() }),
    }
}

/// Route `cidr` at `dev` (the overlay prefix -> the utun, for per-peer demux).
/// A pre-existing identical route ("File exists") is treated as success.
pub fn add_route(cidr: &str, dev: &str) -> Result<()> {
    let fam = if cidr.contains(':') { "-inet6" } else { "-inet" };
    let out = std::process::Command::new("route")
        .args(["-q", "-n", "add", fam, cidr, "-interface", dev])
        .output()
        .context("exec route")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("File exists") {
            bail!("route add {cidr} -interface {dev}: {}", err.trim());
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
    let fam = if cidr.contains(':') { "-inet6" } else { "-inet" };
    let out = std::process::Command::new("route")
        .args(["-q", "-n", "delete", fam, cidr, "-interface", dev])
        .output()
        .context("exec route delete")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("not in table") && !err.contains("No such process") {
            bail!("route delete {cidr} -interface {dev}: {}", err.trim());
        }
    }
    Ok(())
}

/// Assign an ADDITIONAL (alias) address `cidr` to `dev` (the node's v4 overlay
/// address alongside the primary v6 ULA). Best-effort second family for the dual-
/// stack overlay; an already-present alias is treated as success.
pub fn add_addr(cidr: &str, dev: &str) -> Result<()> {
    let (addr, prefixlen) = split_cidr(cidr);
    let fam = if addr.contains(':') { "inet6" } else { "inet" };
    let out = std::process::Command::new("ifconfig")
        .args([dev, fam, &format!("{addr}/{prefixlen}"), "alias"])
        .output()
        .context("exec ifconfig")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("File exists") && !err.to_lowercase().contains("already") {
            bail!("ifconfig {dev} {fam} {addr} alias: {}", err.trim());
        }
    }
    Ok(())
}

/// macOS has no capability model; creating a utun needs root. Report clearly.
pub fn ensure_net_admin_for_l3() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    eprintln!("  L3 on macOS needs root to create a utun device; run the daemon with sudo.");
    false
}

/// The macOS daemon runs as root (utun requires it), so /etc/hosts is already
/// writable for MagicDNS. Nothing to grant.
pub fn ensure_hosts_writable() {}

fn ifconfig(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("ifconfig")
        .args(args)
        .output()
        .context("exec ifconfig")?;
    if !out.status.success() {
        bail!("ifconfig {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
