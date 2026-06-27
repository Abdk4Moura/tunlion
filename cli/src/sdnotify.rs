//! Minimal sd_notify (systemd readiness + liveness watchdog), no dependency.
//!
//! Why this exists: the `up` daemon already self-heals a SEVERED signaling link
//! (the in-core reconnect loop). What it could NOT recover from is the event loop
//! itself WEDGING — alive but stuck — because the same stall that freezes the loop
//! also freezes the reconnect code, so the daemon silently drops off presence and
//! only a manual restart brings it back. systemd's watchdog closes that gap: the
//! loop pings `WATCHDOG=1` every tick; if those stop for `WatchdogSec`, systemd
//! kills + restarts us. `READY=1` lets `Type=notify` mark the unit active only
//! once the loop is actually serving, and `STATUS=` surfaces signaling health in
//! `systemctl status` (the visibility that was missing when a node fell off).
//!
//! Every call is a NO-OP when `NOTIFY_SOCKET` is unset (a manual `filament up`,
//! non-systemd, or non-unix), so it is always safe to call.

#[cfg(unix)]
pub fn notify(state: &str) {
    use std::os::unix::net::UnixDatagram;
    let path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    // systemd uses either a filesystem path or, on system services, an abstract
    // socket whose name systemd passes with a leading '@'. Try the filesystem
    // path first (the common `--user` case), fall back to abstract on Linux.
    if let Some(name) = path.strip_prefix('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
                let _ = sock.send_to_addr(state.as_bytes(), &addr);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = name;
    } else {
        let _ = sock.send_to(state.as_bytes(), &path);
    }
}

#[cfg(not(unix))]
pub fn notify(_state: &str) {}

/// Tell systemd the daemon is up and serving (gates `Type=notify` activation).
pub fn ready() {
    notify("READY=1");
}

/// Liveness ping; absence for `WatchdogSec` makes systemd restart us. Cheap
/// enough to send every event-loop tick.
pub fn watchdog() {
    notify("WATCHDOG=1");
}

/// One-line human status shown by `systemctl --user status filament`.
pub fn status(s: &str) {
    notify(&format!("STATUS={s}"));
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    // One test (not several) because NOTIFY_SOCKET is process-global env state and
    // cargo runs tests concurrently in-process; splitting would race.
    #[test]
    fn notify_protocol_and_noop() {
        // No-op path: unset socket must never panic. (env mutation is `unsafe`
        // in edition 2024; this test is single-threaded over NOTIFY_SOCKET.)
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        ready();
        watchdog();
        status("x");

        // Send path: bind a datagram listener, point NOTIFY_SOCKET at it, assert
        // the exact wire strings systemd expects arrive.
        let path = std::env::temp_dir().join(format!("fil-sdnotify-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixDatagram::bind(&path).expect("bind notify listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        unsafe { std::env::set_var("NOTIFY_SOCKET", &path) };

        ready();
        watchdog();
        status("up — serving");

        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        for _ in 0..3 {
            let n = listener.recv(&mut buf).expect("recv datagram");
            got.push(String::from_utf8_lossy(&buf[..n]).to_string());
        }
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let _ = std::fs::remove_file(&path);

        assert!(got.contains(&"READY=1".to_string()), "got: {got:?}");
        assert!(got.contains(&"WATCHDOG=1".to_string()), "got: {got:?}");
        assert!(
            got.iter().any(|s| s == "STATUS=up — serving"),
            "got: {got:?}"
        );
    }
}
