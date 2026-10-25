//! Allocation bounds before parsing transport control metadata. Binary bulk
//! frames retain their separate limits. This does not make the legacy event
//! channel bounded: a stalled consumer still needs a bounded producer/receiver
//! migration, not a second downstream queue advertised as backpressure.

use serde_json::Value;

/// Matches the existing advertised DataChannel message budget. Apply before
/// allocating a direct control body and before JSON/decryption/base64 handling.
pub const MAX_CONTROL_BYTES: usize = 256 * 1024;
pub const MAX_CONTROL_DEPTH: usize = 32;

/// Scan structure without allocating a JSON tree. Brackets inside strings and
/// escaped quotes are data, not nesting. Syntax validation remains serde's job.
pub fn raw_control_within_limits(raw: &[u8]) -> bool {
    if raw.len() > MAX_CONTROL_BYTES { return false; }
    let mut depth = 0usize;
    let mut string = false;
    let mut escaped = false;
    for &byte in raw {
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
            continue;
        }
        match byte {
            b'"' => string = true,
            b'[' | b'{' => { depth += 1; if depth > MAX_CONTROL_DEPTH { return false; } }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

pub fn decode_control(raw: &[u8]) -> Option<Value> {
    if !raw_control_within_limits(raw) { return None; }
    serde_json::from_slice(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_size_and_depth_are_rejected_before_json_tree_allocation() {
        assert!(decode_control(&vec![b' ';MAX_CONTROL_BYTES+1]).is_none());
        let deep=format!("{}0{}","[".repeat(MAX_CONTROL_DEPTH+1),"]".repeat(MAX_CONTROL_DEPTH+1));
        assert!(!raw_control_within_limits(deep.as_bytes()));
        let boundary=format!("{}0{}","[".repeat(MAX_CONTROL_DEPTH),"]".repeat(MAX_CONTROL_DEPTH));
        assert!(decode_control(boundary.as_bytes()).is_some());
        assert!(decode_control(br#"{"type":"access-offer","quoted":"\\\"[[[[{{{{"}"#).is_some());
        assert!(decode_control(br#"{"type":"pake-msg","msg":"bounded encoded material"}"#).is_some());
        assert!(decode_control(br#"{malformed}"#).is_none());
    }
}
