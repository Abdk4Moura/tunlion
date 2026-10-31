//! The `lan` block of `tunlion doctor`: local discovery as this machine sees
//! it now (interfaces by capability, the setting) and as the running daemon
//! reports it (`lan-state.json`: listener, counters, remembered devices).

use serde_json::{json, Value};

use crate::ui::Tone;

/// A daemon snapshot older than this is not trusted as current.
const STALE_SECS: u64 = 60;

pub(crate) fn facts(context: &filament_transport::TransportContext) -> Value {
    let on = filament_transport::lan::enabled(context);
    let skip = filament_transport::lan::skip(context);
    let ifaces: Vec<Value> = filament_transport::lan::interfaces()
        .into_iter()
        .map(|mut i| {
            let opted = skip.matches(&i);
            i.opted_out = opted;
            let class = tunlion_lan::iface::classify(&i.flags);
            let plan = tunlion_lan::iface::plan(&i, &[]);
            json!({
                "name": i.name,
                "class": class.as_str(),
                "multicast": plan.multicast_v4 || plan.multicast_v6,
                "broadcast": !plan.broadcast.is_empty(),
                "sweep": plan.sweep.len(),
                "off": opted.then_some("opted out"),
            })
        })
        .collect();
    let now = filament_id::now_secs();
    let daemon = std::fs::read_to_string(crate::settings::config_dir().join("lan-state.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(|v| v["at"].as_u64().is_some_and(|t| now.saturating_sub(t) <= STALE_SECS));
    json!({
        "on": on,
        "interfaces": ifaces,
        "daemon": daemon,
    })
}

/// (tone, word, detail) for the human row, plus at most one blocking cause.
pub(crate) fn row(v: &Value) -> (Tone, String, String, Option<String>) {
    if v["on"] != json!(true) {
        return (Tone::Dim, "off".into(), "network.transports leaves out lan".into(), None);
    }
    let ifs = v["interfaces"].as_array().cloned().unwrap_or_default();
    let shown: Vec<String> = ifs
        .iter()
        .filter(|i| i["class"] != "loopback")
        .map(|i| {
            let how = if i["off"].is_string() {
                "off".to_string()
            } else if i["class"] == "shared" {
                match (i["multicast"].as_bool() == Some(true), i["broadcast"].as_bool() == Some(true)) {
                    (true, true) => "multicast+broadcast".into(),
                    (true, false) => "multicast".into(),
                    (false, true) => "broadcast".into(),
                    _ => "remembered only".into(),
                }
            } else if i["sweep"].as_u64().unwrap_or(0) > 0 {
                format!("probe {} hosts", i["sweep"])
            } else {
                "remembered only".into()
            };
            format!("{} {how}", i["name"].as_str().unwrap_or("?"))
        })
        .collect();
    let mut cause = None;
    let d = &v["daemon"];
    let (tone, word, mut detail) = if d.is_null() {
        (Tone::Warn, "on".to_string(), "the daemon is not running local discovery right now".to_string())
    } else {
        let remembered = d["remembered"].as_array().map(|a| a.iter().filter(|r| r["addrs"].as_u64().unwrap_or(0) > 0).count()).unwrap_or(0);
        if let Some(e) = d["errors"].as_array().and_then(|a| a.first()).and_then(|e| e.as_str()) {
            cause = Some(e.to_string());
        }
        (
            if cause.is_some() { Tone::Warn } else { Tone::Ok },
            "on".to_string(),
            format!(
                "listener udp/{}, {} beacons sent, {} recognized, {} devices remembered",
                d["listen_port"], d["beacons_sent"], d["recognized"], remembered
            ),
        )
    };
    if !shown.is_empty() {
        detail.push_str(&format!(" · {}", shown.join(", ")));
    }
    if cause.is_none() && !ifs.iter().any(|i| i["class"] != "loopback") {
        cause = Some("no interface with an address is up".into());
    }
    (tone, word, detail, cause)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_row_names_the_setting() {
        let (_, word, detail, _) = row(&json!({"on": false}));
        assert_eq!(word, "off");
        assert!(detail.contains("network.transports"));
    }

    #[test]
    fn on_row_shows_interfaces_by_capability_and_the_daemon_counters() {
        let v = json!({
            "on": true,
            "interfaces": [
                {"name": "lo", "class": "loopback", "multicast": false, "broadcast": false, "sweep": 0, "off": null},
                {"name": "eth0", "class": "shared", "multicast": true, "broadcast": true, "sweep": 0, "off": null},
                {"name": "wg0", "class": "p2p", "multicast": false, "broadcast": false, "sweep": 253, "off": null},
            ],
            "daemon": {"listen_port": 47821, "beacons_sent": 12, "recognized": 3, "remembered": [{"name": "laptop", "addrs": 2}], "errors": []},
        });
        let (tone, word, detail, cause) = row(&v);
        assert_eq!(word, "on");
        assert!(matches!(tone, Tone::Ok));
        assert!(detail.contains("eth0 multicast+broadcast"), "{detail}");
        assert!(detail.contains("wg0 probe 253 hosts"), "{detail}");
        assert!(detail.contains("1 devices remembered"), "{detail}");
        assert!(!detail.contains("lo "), "{detail}");
        assert!(cause.is_none());
    }
}
