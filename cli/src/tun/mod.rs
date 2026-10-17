//! Cross-platform L3 TUN device + privilege/route helpers.
//!
//! The overlay data plane (`l3.rs`) is written against one small surface and never
//! sees OS specifics: the `Tun` type (`open`/`name`/`recv`/`send`, moving raw IP
//! packets), `add_route` (point the overlay prefix at the device), and the
//! privilege helpers (`ensure_net_admin_for_l3`, `ensure_hosts_writable`). Each OS
//! supplies a backend that implements exactly that surface:
//!
//! - Linux (`linux`):  `/dev/net/tun` + `TUNSETIFF` ioctl, iproute2, CAP_NET_ADMIN.
//! - macOS (`macos`):  `utun` via a PF_SYSTEM control socket, `ifconfig`/`route`, root.
//! - Windows (`windows`): Wintun (`wintun.dll`), the IP Helper API, Administrator.
//!
//! `recv`/`send` always exchange bare IP packets with `l3.rs`; any per-OS framing
//! (macOS prepends a 4-byte address-family header, Linux with IFF_NO_PI does not)
//! is added/stripped inside the backend so the overlay logic stays portable.

/// The overlay's packet endpoint, abstracted so `l3.rs` is agnostic to HOW bare IP
/// packets reach the wire. `KernelTun` (below) is the privileged backend that hands
/// packets to the OS stack via a kernel TUN; a userspace smoltcp `NetstackTun`
/// (added later) implements the same surface with ZERO privilege. `recv` yields an
/// OUTBOUND packet the local stack wants sent to a peer (l3.rs routes it by dest IP
/// to that peer's datagram transport); `send` injects a peer's INBOUND packet into
/// the local stack. Byte-exact bare IP in both directions (per-OS framing, e.g.
/// macOS's 4-byte AF header, is added/stripped inside the backend).
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    /// The interface name (Linux honors `tunlion0`; macOS assigns `utunN`).
    fn name(&self) -> &str;
    /// Await the next OUTBOUND bare IP packet the local stack wants on the wire.
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize>;
    /// Inject one INBOUND bare IP packet (received from a peer) into the local stack.
    async fn send(&self, packet: &[u8]) -> anyhow::Result<usize>;
}

/// Why the Windows Wintun backend could not start.
///
/// Classified from the backend's error text only, so the mapping is pure and
/// unit-tested on every runner rather than only on windows-latest. The Windows
/// backend (`tun::windows`) emits [`WINTUN_DLL_ABSENT`] or
/// [`WINTUN_NOT_ELEVATED`]; `l3::diagnose_tun_failure` turns the variant into
/// the operator's next command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WintunFailure {
    /// No wintun.dll beside tunlion.exe and none in System32.
    DllAbsent,
    /// The DLL is present, but adapter creation/session start was denied
    /// because the process is not elevated.
    NotElevated,
    /// Wintun failed for some other reason. Its own error text is the whole
    /// story and must be kept verbatim.
    Other,
}

/// Marker in the load error: neither trusted location has a wintun.dll.
pub const WINTUN_DLL_ABSENT: &str = "wintun.dll not found next to tunlion.exe or in System32";
/// Marker in the adapter error: Windows refused because the process is not
/// elevated. Matched case-insensitively by [`classify_wintun_failure`].
pub const WINTUN_NOT_ELEVATED: &str = "process is not elevated";

impl WintunFailure {
    /// What went wrong, without advice.
    pub fn cause(self) -> &'static str {
        match self {
            Self::DllAbsent => {
                "wintun.dll is missing: it is not beside tunlion.exe and not in System32"
            }
            Self::NotElevated => {
                "wintun.dll is present, but Windows refused to create the adapter because the \
                 process is not elevated"
            }
            Self::Other => "Wintun could not create the adapter",
        }
    }

    /// The exact next step. `Other` has none: the OS error is the actionable
    /// text, and inventing a cause we did not identify would be worse.
    pub fn advice(self) -> String {
        match self {
            Self::DllAbsent => format!(
                "Place WireGuard's signed wintun.dll beside tunlion.exe, or reinstall from the \
                 official release: {}",
                self.command().unwrap_or("")
            ),
            Self::NotElevated => format!(
                "Run `{}` for the always-on service, or run this shell as Administrator and retry",
                self.command().unwrap_or("")
            ),
            Self::Other => String::new(),
        }
    }

    /// The copyable command from [`advice`](Self::advice), when the fix has one.
    pub fn command(self) -> Option<&'static str> {
        match self {
            Self::DllAbsent => Some("irm https://tunlion.autumated.com/install.ps1 | iex"),
            Self::NotElevated => Some("tunlion up --install"),
            Self::Other => None,
        }
    }
}

/// Classify a Windows kernel-backend error from its text. Returns `None` for
/// errors that are not Wintun failures, so the other platform diagnoses in
/// `l3::diagnose_tun_failure` are untouched.
pub fn classify_wintun_failure(err: &str) -> Option<WintunFailure> {
    let e = err.to_ascii_lowercase();
    if !e.contains("wintun") {
        return None;
    }
    if e.contains(&WINTUN_DLL_ABSENT.to_ascii_lowercase()) {
        Some(WintunFailure::DllAbsent)
    } else if e.contains(&WINTUN_NOT_ELEVATED.to_ascii_lowercase()) {
        Some(WintunFailure::NotElevated)
    } else {
        Some(WintunFailure::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Case (a): no DLL in either trusted location. The fix is a file, not a
    /// privilege, so the command is the official reinstall.
    #[test]
    fn a_missing_dll_points_at_the_signed_dll_or_reinstall() {
        let raw = format!(
            "load wintun.dll: {WINTUN_DLL_ABSENT}; refusing to search CWD/PATH (DLL-hijack guard)"
        );
        let w = classify_wintun_failure(&raw).expect("a wintun error");
        assert_eq!(w, WintunFailure::DllAbsent);
        assert!(w.cause().contains("not beside tunlion.exe"), "{}", w.cause());
        assert_eq!(
            w.command(),
            Some("irm https://tunlion.autumated.com/install.ps1 | iex")
        );
        assert!(w.advice().contains("signed wintun.dll"), "{}", w.advice());
        assert!(w.advice().contains("install.ps1"), "{}", w.advice());
    }

    /// Case (b): the DLL is there, adapter creation was denied. Bundling the
    /// DLL again would not help; the operator needs elevation or the service.
    #[test]
    fn a_denied_adapter_points_at_the_service_or_an_admin_shell() {
        let raw = format!(
            "create Wintun adapter 'tunlion0': Failed to create adapter. The \
             {WINTUN_NOT_ELEVATED}."
        );
        let w = classify_wintun_failure(&raw).expect("a wintun error");
        assert_eq!(w, WintunFailure::NotElevated);
        assert!(w.cause().contains("not elevated"), "{}", w.cause());
        assert_eq!(w.command(), Some("tunlion up --install"));
        assert!(w.advice().contains("tunlion up --install"), "{}", w.advice());
        assert!(w.advice().contains("Administrator"), "{}", w.advice());
        // The one thing it must NOT say is "the DLL is missing".
        assert!(!w.advice().contains("wintun.dll is missing"), "{}", w.advice());
    }

    /// Case (c): an unrelated adapter error. Keep the OS text and invent no fix.
    #[test]
    fn an_unrelated_adapter_error_keeps_its_os_text() {
        let raw = "create Wintun adapter 'tunlion0': Failed to create adapter";
        let w = classify_wintun_failure(raw).expect("a wintun error");
        assert_eq!(w, WintunFailure::Other);
        assert_eq!(w.command(), None);
        assert_eq!(w.advice(), "");
    }

    /// The classifier is also called from the non-Windows diagnosis path, so a
    /// Linux error must never be claimed as a Wintun failure.
    #[test]
    fn a_non_wintun_error_is_not_classified() {
        assert_eq!(
            classify_wintun_failure("open /dev/net/tun: No such file or directory"),
            None
        );
        assert_eq!(classify_wintun_failure("TUNSETIFF: Operation not permitted"), None);
    }
}

// Userspace (zero-privilege) overlay backend. Platform-independent (pure smoltcp,
// no OS device). Selected by l3.rs when there is no kernel TUN.
mod netstack;
pub use netstack::{NetstackListener, NetstackStream, NetstackTun};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{add_addr, add_route, del_route, ensure_hosts_writable, ensure_net_admin_for_l3, l3_blocker, l3_grant_pending, KernelTun};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{add_addr, add_route, del_route, ensure_hosts_writable, ensure_net_admin_for_l3, l3_blocker, l3_grant_pending, KernelTun};

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::{add_addr, add_route, del_route, ensure_hosts_writable, ensure_net_admin_for_l3, l3_blocker, l3_grant_pending, KernelTun};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_addr, add_route, del_route, ensure_hosts_writable, ensure_net_admin_for_l3, l3_blocker, l3_grant_pending, KernelTun};
