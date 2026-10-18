//! Link liveness and route predicates.
//!
//! Pure over booleans the caller has already read off a peer or a transport: this
//! module never touches a `Transport`, a socket or a terminal, so each decision is
//! one expression, unit-testable, and identical at every call site. Before these
//! were named functions the same expressions were retyped per call site, and a
//! transcription error in one of them is exactly how #246's livelock survived.
//!
//! [`RevokeRecheck`] is the request-shaped form of the same question: a serving
//! loop that answers one request at a time does not own a ticker, so it asks the
//! host at most once per interval. The mechanism lives here; the verdict is still
//! [`HostServices::live_session_cut`], and the interval is still
//! [`HostServices::revoke_recheck_interval`], so the CLI's env knob and its
//! revocation store stay the single source.

use std::time::{Duration, Instant};

use crate::host::{HostServices, LiveCut};

/// #246: a link is dead only when nothing is serving AND its WebRTC peer is
/// not still making progress. `peer_live` is `Peer::is_live` (anything but
/// Failed/Closed); `transport_dead` and `workers_all_dead` describe the direct
/// transports. A WebRTC link that just finished `establish` is
/// (peer_live=true, transport dead, workers empty) and therefore alive: it has
/// no transport or workers YET, but its ICE agent is working. Named as a
/// function so the decision is one expression, unit-testable, and stable
/// across call sites.
pub fn link_dead_for(peer_live: bool, transport_dead: bool, workers_all_dead: bool) -> bool {
    !peer_live && transport_dead && workers_all_dead
}

/// #246: a link counts as live when any transport serves, any worker serves,
/// or the WebRTC peer is still making progress. The peer clause is what lets a
/// Normal re-dial yield to an establish that is still underway instead of
/// arming a fresh direct attempt (whose fallback timer would then tear the
/// establish down).
pub fn link_has_live_for(peer_live: bool, primary_ok: bool, workers_ok: bool) -> bool {
    peer_live || primary_ok || workers_ok
}

/// Whether an establish may proceed on STUN alone when the config API is slow.
/// Not under a forced relay, which needs the TURN credentials only the API has.
pub fn ice_fallback_allowed(relay_only: bool) -> bool {
    !relay_only
}

/// `--relay` promises to hide this machine's address from the peer. Direct
/// transport cannot keep that promise: its `transport-offer` carries our host
/// and public candidates, and dialing the peer's candidates hands it our source
/// address. So a relay-mode session never takes direct, whatever else asked for
/// it (env gate, L2 acceptor, daemon anti-glare). Decided here once, at Conn
/// construction, and `direct_ok` is never widened afterwards, so send, receive,
/// pair and the `up` daemon all inherit it. Runtime escalation to relay
/// (`relay_only` set later) is a different thing and is not this flag.
pub fn direct_permitted(relay_only: bool, direct_ok: bool) -> bool {
    direct_ok && !relay_only
}

/// The rate-limited live-session re-check a request-shaped serving loop uses.
///
/// A mount server answers one request at a time and has no ticker; asking the
/// host's store on every operation would re-read the device store per read
/// (#235). This keeps the cadence in one place: the interval is the host's
/// ([`HostServices::revoke_recheck_interval`]) and the verdict is the host's
/// ([`HostServices::live_session_cut`]), exactly as the ticker-driven loops ask
/// them.
pub struct RevokeRecheck {
    last: Instant,
    interval: Duration,
}

impl RevokeRecheck {
    pub fn new(interval: Duration) -> Self {
        Self { last: Instant::now(), interval }
    }

    /// The re-check interval this instance was built with.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// None while the interval runs; otherwise the host's live-cut verdict.
    /// The interval bound keeps a per-request cadence cheap.
    pub fn cut(
        &mut self,
        host: &dyn HostServices,
        device_pub: Option<&[u8; 32]>,
    ) -> Option<LiveCut> {
        if self.last.elapsed() < self.interval {
            return None;
        }
        self.last = Instant::now();
        host.live_session_cut(device_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostServices, LiveCutCause};

    /// A host whose verdict is fixed; the only state under test is the interval.
    struct CutHost {
        cut: Option<LiveCut>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl HostServices for CutHost {
        fn settings_get_str(&self, _key: &str) -> Option<String> {
            None
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            Vec::new()
        }
        fn is_self_uid(&self, _my_uid: &str, _peer_uid: Option<&str>) -> bool {
            false
        }
        fn rejoin_unwarned(&self) -> Duration {
            Duration::from_secs(1)
        }
        fn relay_banner(&self) -> String {
            String::new()
        }
        fn relay_forbidden(&self) -> bool {
            false
        }
        fn channel_of(&self, _secret: &str) -> String {
            String::new()
        }
        fn roster_snapshot_json(&self) -> Option<String> {
            None
        }
        fn fleet_rv_present(&self) -> bool {
            false
        }
        fn live_session_cut(&self, _idev: Option<&[u8; 32]>) -> Option<LiveCut> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.cut.clone()
        }
    }

    #[test]
    fn a_healthy_host_is_never_cut_and_is_not_asked_before_the_interval() {
        let host = CutHost { cut: None, calls: Default::default() };
        let mut recheck = RevokeRecheck::new(Duration::from_secs(60));
        assert!(recheck.cut(&host, None).is_none());
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn an_elapsed_interval_returns_the_hosts_verdict_verbatim() {
        let host = CutHost {
            cut: Some(LiveCut {
                cause: LiveCutCause::Expired,
                reason: "access expired at 2025-10-13 19:39:23 UTC".into(),
            }),
            calls: Default::default(),
        };
        let mut recheck = RevokeRecheck::new(Duration::ZERO);
        let cut = recheck.cut(&host, None).expect("an elapsed interval asks the host");
        assert_eq!(cut.cause, LiveCutCause::Expired);
        assert_eq!(cut.reason, "access expired at 2025-10-13 19:39:23 UTC");
        assert_eq!(recheck.interval(), Duration::ZERO);
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
