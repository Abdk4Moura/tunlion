//! What a transfer says about itself when it resumes, writes to a stream, or
//! loses its peer. Each sentence here replaced one a blind tester found false:
//! a receiver that said "the partial is kept, re-run `tunlion receive <code>`
//! to resume" with nothing kept and a code that had already burned, and a
//! resumed send that looked exactly like a fresh one. The decisions are pure
//! (apart from reading partial sizes off disk) so each is tested directly.

use crate::human;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A file-accept that asks for one in-order stream (`receive -o -`): the
/// sender then streams on its primary link only, never split across workers.
pub(crate) fn accept_is_sequential(accept: &Value) -> bool {
    accept["sequential"].as_bool() == Some(true)
}

/// The sender's line when the receiver accepted from a kept partial.
pub(crate) fn resume_line(name: &str, offset: u64, size: u64) -> String {
    format!(
        "  {name}: resuming at {} of {} (the receiver kept the first part)",
        human(offset),
        human(size)
    )
}

/// A partial this receive started: its name, where it lives, its full size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionPart {
    pub(crate) name: String,
    pub(crate) part: PathBuf,
    pub(crate) size: u64,
}

/// Remember a partial this receive opened (once per path).
pub(crate) fn note_part(parts: &mut Vec<SessionPart>, name: &str, part: &Path, size: u64) {
    if parts.iter().any(|p| p.part == part) {
        return;
    }
    parts.push(SessionPart {
        name: name.to_string(),
        part: part.to_path_buf(),
        size,
    });
}

/// A partial that is really on disk, with how much of it is there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeptPartial {
    pub(crate) name: String,
    pub(crate) part: PathBuf,
    pub(crate) have: u64,
    pub(crate) size: u64,
}

/// The partials this receive leaves behind, read off disk. One that holds no
/// bytes is junk (an empty `.part` and its `.meta` resume nothing) and is
/// removed here, so a receive that got nothing leaves nothing behind.
pub(crate) fn kept_partials(parts: &[SessionPart]) -> Vec<KeptPartial> {
    let mut kept = Vec::new();
    for p in parts {
        match std::fs::metadata(&p.part) {
            Ok(m) if m.is_file() && m.len() > 0 => kept.push(KeptPartial {
                name: p.name.clone(),
                part: p.part.clone(),
                have: m.len(),
                size: p.size,
            }),
            Ok(m) if m.is_file() => crate::recv_files::discard_partial(&p.part),
            _ => {}
        }
    }
    kept
}

/// What a one-shot receive says when its sender is gone for good. `why` is the
/// first sentence (how it was decided the sender is gone; it says
/// "unreachable", which the exit-code taxonomy maps to 6). The rest says what
/// is on disk and the one way to continue that can actually work.
pub(crate) fn sender_gone_message(why: &str, kept: &[KeptPartial], dir: &Path, by_code: bool) -> String {
    let mut msg = format!("{why}.");
    if kept.is_empty() {
        msg.push_str(" Nothing was received, so nothing was kept.");
        if by_code {
            msg.push_str(" The code works only once: ask the sender to start a new send.");
        } else {
            msg.push_str(" Ask the sender to send again.");
        }
        return msg;
    }
    let list: Vec<String> = kept
        .iter()
        .map(|k| {
            let file = k
                .part
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("{}.part", k.name));
            format!("{file} ({} of {})", human(k.have), human(k.size))
        })
        .collect();
    msg.push_str(&format!(" Kept in {}: {}.", dir.display(), list.join(", ")));
    if by_code {
        msg.push_str(
            " The code works only once, so receiving with it again cannot resume: ask the sender \
             to run the same `tunlion send` again (it gets a new code) and receive that into this \
             folder; it continues from the kept bytes.",
        );
    } else {
        msg.push_str(
            " Ask the sender to send it again to this folder; it continues from the kept bytes.",
        );
    }
    msg.push_str(" To discard it instead, delete the .part and .part.meta files.");
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sequential_accept_is_recognised_and_an_old_one_is_not() {
        assert!(accept_is_sequential(&serde_json::json!({"type":"file-accept","sequential":true})));
        assert!(!accept_is_sequential(&serde_json::json!({"type":"file-accept","offset":0})));
    }

    #[test]
    fn the_resume_line_names_the_offset_and_the_size() {
        let l = resume_line("big.bin", 20 * 1024 * 1024, 80 * 1024 * 1024);
        assert!(l.contains("big.bin: resuming at "), "{l}");
        assert!(l.contains(&human(20 * 1024 * 1024)) && l.contains(&human(80 * 1024 * 1024)), "{l}");
    }

    /// The tester's case: a code receive whose sender was SIGKILLed before any
    /// byte landed. It used to promise a kept partial and a resume by the
    /// (burned) code. Nothing was kept, and the way on is a new send.
    #[test]
    fn nothing_kept_says_so_and_never_offers_the_burned_code() {
        let dir = std::env::temp_dir();
        let m = sender_gone_message("the sender is unreachable: x", &[], &dir, true);
        assert!(m.contains("unreachable"), "{m}");
        assert!(m.contains("nothing was kept"), "{m}");
        assert!(m.contains("new send"), "{m}");
        assert!(!m.contains("receive <code>") && !m.contains("partial is kept"), "{m}");
    }

    #[test]
    fn a_kept_partial_is_named_with_its_size_and_the_way_to_resume() {
        let dir = Path::new("/home/u/rx");
        let kept = vec![KeptPartial {
            name: "big.bin".into(),
            part: dir.join("big.bin.part"),
            have: 10 * 1024 * 1024,
            size: 80 * 1024 * 1024,
        }];
        let m = sender_gone_message("the sender is unreachable: x", &kept, dir, true);
        assert!(m.contains("/home/u/rx"), "{m}");
        assert!(m.contains("big.bin.part"), "{m}");
        assert!(m.contains(&human(10 * 1024 * 1024)), "{m}");
        assert!(m.contains("new code") && m.contains("continues from the kept bytes"), "{m}");
        assert!(m.contains("delete the .part"), "{m}");
        let room = sender_gone_message("the sender is unreachable: x", &kept, dir, false);
        assert!(!room.contains("code"), "{room}");
    }

    /// An empty `.part` (and its `.meta`) resumes nothing: it is removed, not
    /// reported as kept. A partial holding bytes stays and is reported.
    #[test]
    fn an_empty_partial_is_cleaned_and_a_real_one_is_kept() {
        let dir = std::env::temp_dir().join(format!("tunlion-kept-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("unread.part");
        std::fs::write(&empty, b"").unwrap();
        std::fs::write(dir.join("unread.part.meta"), b"{}").unwrap();
        let real = dir.join("big.bin.part");
        std::fs::write(&real, vec![1u8; 4096]).unwrap();
        let mut parts = Vec::new();
        note_part(&mut parts, "unread", &empty, 7);
        note_part(&mut parts, "big.bin", &real, 8192);
        note_part(&mut parts, "big.bin", &real, 8192); // once per path
        assert_eq!(parts.len(), 2);
        let kept = kept_partials(&parts);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(kept[0].have, 4096);
        assert!(!empty.exists(), "the empty .part is junk and is removed");
        assert!(!dir.join("unread.part.meta").exists(), "and its .meta with it");
        assert!(real.exists(), "a partial holding bytes is kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
