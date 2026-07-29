// Surface 3f-3h: `requests` — full/empty/approve-guard/deny.
//
// Pure render functions for the consent request listing.

use crate::ui::{self, Tone};
use super::{echo_cmd, meta, rule};

/// A pending request entry for rendering.
#[derive(Debug, Clone)]
pub struct RequestEntry {
    pub id: u64,
    pub peer: String,
    pub capability: String,
    pub ago: String,           // e.g. "3m ago"
    pub via: String,           // e.g. "via one-time word \"amber-lantern-ferry\""
    pub fingerprint: Option<String>,
    pub is_deliberate: bool,
}

/// Render the full requests list.
pub fn render_requests(requests: &[RequestEntry]) -> String {
    if requests.is_empty() {
        return render_empty();
    }

    let count = requests.len();
    let mut lines = vec![
        format!(
            "  {} {}",
            ui::paint(Tone::Bold, &format!("{count}")),
            ui::paint(Tone::Dim, if count == 1 { "waiting" } else { "waiting" }),
        ),
        format!("  {}", ui::paint(Tone::Dim, "updated just now")),
        String::new(),
    ];

    for (i, r) in requests.iter().enumerate() {
        let idx = i + 1;
        let cap_display = if r.is_deliberate {
            format!("{} {}", r.capability, ui::paint(Tone::Warn, ui::glyph_warn()))
        } else {
            r.capability.clone()
        };

        lines.push(format!(
            "  {idx}   {} {} wants to  {cap_display}",
            ui::paint(Tone::Warn, ui::glyph_extern()),
            ui::paint(Tone::Warn, &r.peer),
        ));
        lines.push(format!("         asked {} · {}", r.ago, r.via));

        if let Some(ref fp) = r.fingerprint {
            lines.push(format!("         fingerprint {fp} [compare]"));
        }

        if r.is_deliberate {
            lines.push(format!(
                "         {} this is deliberate access — a real terminal on this machine",
                ui::paint(Tone::Warn, ui::glyph_warn())
            ));
            lines.push(format!(
                "         [ {} ]   [ {} ]",
                ui::paint(Tone::Bold, &format!("filament requests approve {} --allow {} --for 1h", r.id, r.capability)),
                ui::paint(Tone::Dim, &format!("deny {}", r.id)),
            ));
        } else {
            lines.push(format!(
                "         [ {} ]   [ {} ]",
                ui::paint(Tone::Bold, &format!("filament requests approve {}", r.id)),
                ui::paint(Tone::Dim, &format!("filament requests deny {}", r.id)),
            ));
        }
        lines.push(String::new());
    }

    lines.push(ui::paint(Tone::Dim, "  Nothing pushes to you yet — check `filament requests`, or wire a hook:"));
    lines.push(ui::paint(Tone::Dim, "    filament requests --notify 'notify-send %s'   (also: webhook, email)"));

    lines.join("\n")
}

/// Render the empty requests list.
pub fn render_empty() -> String {
    ui::paint(Tone::Dim, "  Nothing waiting. Requests from other people show up here (pull — no tray needed yet).")
}

/// Render the approve guard for deliberate access.
pub fn render_approve_guard(request_id: u64, cap: &str) -> String {
    format!(
        "{err} request {request_id} asks for {cap} — deliberate access. Name it and bound it:\n  {fix}",
        err = ui::paint(Tone::Err, ui::glyph_err()),
        fix = format!("filament requests approve {request_id} --allow {cap} --for 1h"),
    )
}

/// Render the approve success message.
pub fn render_approve_success(peer_name: &str, cap: &str, expiry: &str) -> String {
    format!(
        "{ok} {peer_name} can {cap} until {expiry}.",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
    )
}

/// Render the deny success message.
pub fn render_deny_success(peer_name: &str) -> String {
    format!(
        "{ok} Denied. {peer_name} was told nothing was shared. No trace kept.",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_requests() {
        let s = render_empty();
        assert!(s.contains("Nothing waiting"), "must show empty message");
        assert!(s.contains("pull"), "must mention pull model");
    }

    #[test]
    fn full_request_list() {
        let requests = vec![
            RequestEntry {
                id: 1,
                peer: "carol".into(),
                capability: "send files".into(),
                ago: "3m ago".into(),
                via: "via one-time word \"amber-lantern-ferry\"".into(),
                fingerprint: Some("7f3a 9c21...".into()),
                is_deliberate: false,
            },
            RequestEntry {
                id: 2,
                peer: "dave".into(),
                capability: "open a shell".into(),
                ago: "18m ago".into(),
                via: "introduced by carol".into(),
                fingerprint: None,
                is_deliberate: true,
            },
        ];
        let s = render_requests(&requests);
        assert!(s.contains("carol"), "must show first peer");
        assert!(s.contains("dave"), "must show second peer");
        assert!(s.contains("send files"), "must show capability");
        assert!(s.contains("deliberate access"), "must flag deliberate");
        assert!(s.contains("approve 1"), "must show approve for id 1");
        assert!(s.contains("deny 2"), "must show deny for id 2");
    }

    #[test]
    fn request_with_fingerprint() {
        let requests = vec![
            RequestEntry {
                id: 1,
                peer: "carol".into(),
                capability: "send files".into(),
                ago: "3m ago".into(),
                via: "via one-time word".into(),
                fingerprint: Some("7f3a 9c21...".into()),
                is_deliberate: false,
            },
        ];
        let s = render_requests(&requests);
        assert!(s.contains("7f3a 9c21"), "must show fingerprint");
        assert!(s.contains("[compare]"), "must show compare hint");
    }

    #[test]
    fn deliberate_request_warns() {
        let requests = vec![
            RequestEntry {
                id: 2,
                peer: "dave".into(),
                capability: "shell".into(),
                ago: "18m ago".into(),
                via: "introduced by carol".into(),
                fingerprint: None,
                is_deliberate: true,
            },
        ];
        let s = render_requests(&requests);
        assert!(s.contains("deliberate access"), "must flag deliberate");
        assert!(s.contains("real terminal"), "must explain what shell means");
        assert!(s.contains("--allow shell"), "must show --allow in approve command");
    }

    #[test]
    fn approve_guard() {
        let s = render_approve_guard(2, "shell");
        assert!(s.contains("request 2"), "must show request id");
        assert!(s.contains("shell"), "must show capability");
        assert!(s.contains("deliberate"), "must flag deliberate");
        assert!(s.contains("--for 1h"), "must require --for");
    }

    #[test]
    fn approve_success() {
        let s = render_approve_success("carol", "send files", "15:12 (1h)");
        assert!(s.contains("carol"), "must show peer name");
        assert!(s.contains("send files"), "must show capability");
    }

    #[test]
    fn deny_success() {
        let s = render_deny_success("carol");
        assert!(s.contains("carol"), "must show peer name");
        assert!(s.contains("Denied"), "must confirm denial");
        assert!(s.contains("No trace kept"), "must confirm no trace");
    }
}
