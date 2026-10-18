//! CLI boundary: resolve the root once, then keep live reads bound to that root.
use std::path::Path;
use filament_transport::TransportContext;

pub(crate) fn for_root(root: &Path) -> std::io::Result<TransportContext> {
    let root = if root.is_absolute() { root.to_path_buf() } else { std::env::current_dir()?.join(root) };
    let membership_root = root.clone();
    Ok(TransportContext::new(
        Some(root.join("signaling-dns.json")),
        move |key, peer| crate::settings::get_str_at(&root, key, peer),
        move |peer| crate::settings::raw_membership_at(&membership_root, peer),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_root(tag: &str) -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tunlion-context-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, name: &str, body: &str) {
        std::fs::write(root.join(name), body).unwrap();
    }

    #[test]
    fn explicit_roots_keep_live_settings_and_membership_reads_separate() {
        let a = temp_root("a");
        let b = temp_root("b");
        write(
            &a,
            "config",
            "interfaces {\"m\":\"only\",\"i\":\"10.0.0.0/8\"}\n\
             prefer {\"o\":\"10.0.0.0/8\",\"s\":\"soft\"}\n",
        );
        write(
            &b,
            "config",
            "interfaces {\"m\":\"only\",\"i\":\"192.168.0.0/16\"}\n\
             prefer {\"o\":\"192.168.0.0/16\",\"s\":\"soft\"}\n",
        );
        let ca = for_root(&a).unwrap();
        let cb = for_root(&b).unwrap();

        assert_eq!(ca.membership(None), "{\"m\":\"only\",\"i\":\"10.0.0.0/8\"}");
        // The transport receives the decoded order list, not the raw
        // `{"o":...}` JSON store. A regression back to raw JSON fails here.
        assert_eq!(
            ca.setting("prefer", None).as_deref(),
            Some("10.0.0.0/8")
        );
        assert_eq!(
            cb.membership(None),
            "{\"m\":\"only\",\"i\":\"192.168.0.0/16\"}"
        );
        assert_eq!(
            cb.setting("prefer", None).as_deref(),
            Some("192.168.0.0/16")
        );

        // A live write is visible to A's next read and never to B.
        write(
            &a,
            "config",
            "interfaces {\"m\":\"only\",\"i\":\"172.16.0.0/12\"}\n\
             prefer {\"o\":\"172.16.0.0/12\",\"s\":\"soft\"}\n",
        );
        assert_eq!(
            ca.membership(None),
            "{\"m\":\"only\",\"i\":\"172.16.0.0/12\"}"
        );
        assert_eq!(
            ca.setting("prefer", None).as_deref(),
            Some("172.16.0.0/12")
        );
        assert_eq!(
            cb.membership(None),
            "{\"m\":\"only\",\"i\":\"192.168.0.0/16\"}"
        );

        // Per-peer overrides come from the same explicit root.
        write(
            &a,
            "peerconf",
            "{\"dovm\":{\"interfaces\":\"{\\\"m\\\":\\\"only\\\",\\\"i\\\":\\\"192.168.1.0/24\\\"}\",\
             \"prefer\":\"{\\\"o\\\":\\\"192.168.1.0/24\\\",\\\"s\\\":\\\"soft\\\"}\"}}",
        );
        // Re-read from scratch so the peer fixture is not affected by the
        // adapter's existing closure state (callbacks are intentionally live).
        let ca = for_root(&a).unwrap();
        assert_eq!(
            ca.membership(Some("dovm")),
            "{\"m\":\"only\",\"i\":\"192.168.1.0/24\"}"
        );
        assert_eq!(
            ca.setting("prefer", Some("dovm")).as_deref(),
            Some("192.168.1.0/24")
        );

        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
