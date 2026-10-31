//! Local discovery for one-shot commands (`send --to <paired device>`): no
//! listener, no beacons; it queries the network and dials the target's
//! remembered addresses directly, so a send works with the server unreachable.

use std::sync::Arc;

use filament_peerloop::lan_glue::Ownership;
use filament_transport::lan::{LanKey, LanService, Options};
use filament_transport::net::Ev;
use tokio::sync::mpsc::UnboundedSender;

pub(crate) async fn start(context: &filament_transport::TransportContext, tx: UnboundedSender<Ev>) -> anyhow::Result<LanService> {
    let opts = Options { serve: false, skip: filament_transport::lan::skip(context), ..Default::default() };
    LanService::start(&crate::settings::config_dir(), opts, Arc::new(Vec::<LanKey>::new), None, None, tx).await
}

/// The circular-route guard for a one-shot: every paired device's recorded
/// overlay addresses (the daemon's live table is not ours to read).
pub(crate) fn ownership(_target: &str) -> Ownership {
    let stored = crate::devices_store::devices_load().into_iter().map(|(n, _)| {
        let (_, v6, v4) = crate::device_view::devices_info(&n).unwrap_or((0, None, None));
        (n, v6, v4)
    });
    Ownership::build(stored, Vec::new())
}

pub(crate) fn dial_now(svc: &LanService, name: &str, secret: &str) {
    let addrs = tunlion_lan::record::not_circular(name, svc.store.dial_order(name), &ownership(name));
    if !addrs.is_empty() {
        svc.dial(LanKey { name: name.to_string(), secret: secret.to_string(), fleet: false }, addrs);
    }
}
