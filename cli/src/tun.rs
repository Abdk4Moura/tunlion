//! L3 TUN device (Linux): open `/dev/net/tun`, hand back an async read/write
//! handle so the `serve_tun` pump can move raw IP packets between the kernel and
//! a filament link's QUIC datagrams.
//!
//! Deliberately dependency-light, matching the rest of the CLI: one `TUNSETIFF`
//! ioctl via `libc`, the device's addr/mtu/up set through `iproute2` (no netlink
//! crate), and the fd wrapped in tokio's `AsyncFd` for readiness-driven async IO.
//! Linux-only; the module is `cfg(unix)` and `serve_tun` is gated accordingly so
//! Windows still compiles (it has no `/dev/net/tun`).

use anyhow::{bail, Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

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
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl Tun {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open `name` as a TUN (IFF_TUN | IFF_NO_PI), then assign `cidr`, set `mtu`,
    /// and bring it up via iproute2. `name` must be < 16 bytes.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<Tun> {
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
            bail!("open /dev/net/tun: {} (need CAP_NET_ADMIN / root)", std::io::Error::last_os_error());
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
            bail!("TUNSETIFF {name}: {}", std::io::Error::last_os_error());
        }

        // Configure via iproute2: robust across distros and avoids a second round
        // of ioctl/netlink. The interface exists now (the ioctl created it).
        ip(&["addr", "add", cidr, "dev", name]).with_context(|| format!("ip addr add {cidr} dev {name}"))?;
        ip(&["link", "set", "dev", name, "mtu", &mtu.to_string()]).context("ip link set mtu")?;
        ip(&["link", "set", "dev", name, "up"]).context("ip link set up")?;

        let fd = AsyncFd::new(owned).context("register tun fd with the reactor")?;
        Ok(Tun { fd, name: name.to_string() })
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
