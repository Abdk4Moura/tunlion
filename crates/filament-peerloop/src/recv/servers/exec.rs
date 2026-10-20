//! The receive dispatch's `exec-open` entry point.
//!
//! With `exec-server` on, this is a thin call into the one protocol state
//! machine in `crate::shell::exec_server`; there is no second serve loop
//! here. With the feature off, a reduced build answers a well-formed open with
//! a NAMED `l2-close` instead of silence, exactly like the reduced sync
//! receiver. No process backend is compiled in that profile.
//!
//! The reduced arm deliberately runs BEFORE admission: it has no serving gate
//! or transport lookup beyond the link's transport, so it answers only a
//! syntactically valid L2-half sid. A low-half or oversized sid is ignored,
//! never coerced into an L2 stream; every other serving-off/denial rule stays
//! in the full state machine's `admit_exec_open`.

use crate::conn::Conn;
#[cfg(feature = "exec-server")]
use crate::l2::Mux;
#[cfg(feature = "exec-server")]
use crate::recv::dispatch::ParkedOpen;
#[cfg(feature = "exec-server")]
use crate::shell_gate::ShellPolicy;
use serde_json::{json, Value};
#[cfg(feature = "exec-server")]
use std::collections::HashMap;
#[cfg(feature = "exec-server")]
use std::sync::Arc;

/// The named refusal a build without `exec-server` sends.
pub const EXEC_SERVER_UNAVAILABLE: &str = "exec receive is not available in this build";

/// The honest close for a reduced build that admitted the frame vocabulary but
/// has no exec state machine. Testable without a Conn.
pub fn exec_unavailable_close(v: &Value) -> Option<(u32, Value)> {
    let sid = crate::l2::wire_sid(v)?;
    // Parity with the mount/sync reduced refusals: only a valid L2-half sid
    // names a stream this build could have opened. A low-half or wrapped value
    // is not an exec stream and must not be echoed into an `l2-close`.
    if !crate::l2::is_l2_sid(sid) {
        return None;
    }
    Some((
        sid,
        json!({
            "type": "l2-close",
            "sid": sid,
            "err": EXEC_SERVER_UNAVAILABLE,
        }),
    ))
}

/// Admission-free named refusal for a build with `exec-server` off.
pub async fn open_exec_unavailable(conn: &Conn, pid: &str, v: &Value) {
    if let (Some((_, close)), Some(t)) = (exec_unavailable_close(v), conn.transport_of(pid)) {
        let _ = t.send_control(&close).await;
    }
}

/// Accept one `exec-open` frame into the library state machine.
#[cfg(feature = "exec-server")]
#[allow(clippy::too_many_arguments)]
pub async fn open_exec(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    policy: &ShellPolicy,
    shell_user: &Option<String>,
    muxes: &mut HashMap<String, Arc<Mux>>,
    l2_enabled: bool,
    parked: &mut Vec<ParkedOpen>,
    process: Arc<dyn crate::shell::exec::ExecProcess>,
) {
    crate::shell::exec_server::handle_exec_open(
        conn, pid, v, policy, shell_user, muxes, l2_enabled, parked, process,
    )
    .await
}

#[cfg(all(test, not(feature = "exec-server")))]
mod reduced_tests {
    use super::*;

    #[test]
    fn reduced_exec_open_closes_with_a_named_unavailable_error() {
        let (sid, close) = exec_unavailable_close(&json!({
            "type": "exec-open",
            "sid": 0x8000_0101u32,
            "err_sid": 0x8000_0102u32,
            "argv": ["true"],
        }))
        .expect("a well-formed exec-open gets an explicit close");
        assert_eq!(sid, 0x8000_0101u32);
        assert_eq!(close["type"], "l2-close");
        assert_eq!(close["sid"], 0x8000_0101u32);
        assert!(close["err"]
            .as_str()
            .unwrap()
            .contains("exec receive is not available in this build"));
    }

    #[test]
    fn reduced_exec_open_ignores_a_non_l2_sid() {
        for sid in [7u64, 0u64, u32::MAX as u64 + 1] {
            assert!(
                exec_unavailable_close(&json!({
                    "type": "exec-open",
                    "sid": sid,
                    "err_sid": 0x8000_0102u32,
                    "argv": ["true"],
                }))
                .is_none(),
                "sid {sid} is not a valid L2-half stream"
            );
        }
    }
}
