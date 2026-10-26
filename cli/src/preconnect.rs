//! Start the signaling connection while a person is still choosing.
//!
//! A pairing code cannot appear until this device is connected to the
//! signaling server and has been given a nameplate. Started only after the
//! choice, that connect (DNS, TLS, the socket.io handshake) is the pause between
//! picking "Another device I own" and seeing a code, which the prototype does
//! not have. So the home screen starts the connect the moment it draws, and the
//! pairing ceremony takes the already-open connection if it is for the same
//! server. Nothing is joined or announced: an unused connection is simply
//! dropped at exit.
//!
//! Correctness never depends on it. A failed or mismatched pre-connect returns
//! nothing and the ceremony connects exactly as it always did, with the same
//! errors. `TUNLION_NO_PRECONNECT=1` turns it off.

use std::sync::Mutex;
use tokio::sync::mpsc;

/// An open signaling client and the channel its events already flow into.
pub(crate) type Warm = (
    filament_signal::Client,
    mpsc::UnboundedSender<crate::net::Ev>,
    mpsc::UnboundedReceiver<crate::net::Ev>,
);

static SLOT: Mutex<Option<(String, tokio::task::JoinHandle<Option<Warm>>)>> = Mutex::new(None);

/// The server a bare launch would use, resolved the way the dispatcher does
/// (`TUNLION_SERVER`, else the configured `server`, else the default).
pub(crate) fn default_server() -> String {
    let flag = std::env::var("TUNLION_SERVER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| crate::DEFAULT_SERVER.to_string());
    let server = if flag == crate::DEFAULT_SERVER {
        crate::config_get("server").unwrap_or(flag)
    } else {
        flag
    };
    server.trim_end_matches('/').to_string()
}

/// Begin connecting in the background. Only on a multi-threaded runtime: on a
/// current-thread one the task could not run while a menu blocks on a key.
pub(crate) fn start(server: String) {
    if std::env::var_os("TUNLION_NO_PRECONNECT").is_some() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return;
    }
    let target = server.clone();
    let task = handle.spawn(async move {
        let context = crate::transport_context::for_root(&crate::settings::config_dir()).ok()?;
        let (tx, rx) = mpsc::unbounded_channel::<crate::net::Ev>();
        let client = crate::net::connect_signaling(&context, &target, tx.clone()).await.ok()?;
        crate::ui::timing("signaling pre-connected");
        Some((client, tx, rx))
    });
    if let Ok(mut slot) = SLOT.lock() {
        if let Some((_, old)) = slot.replace((server, task)) {
            old.abort();
        }
    }
}

/// Take the pre-opened connection for `server`, if there is one. Waiting on a
/// connect that is still in flight is never slower than starting a new one:
/// it already has a head start.
pub(crate) async fn take(server: &str) -> Option<Warm> {
    let (target, task) = SLOT.lock().ok()?.take()?;
    if target != server.trim_end_matches('/') {
        task.abort();
        return None;
    }
    task.await.ok().flatten()
}
