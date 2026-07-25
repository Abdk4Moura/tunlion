# Design: Adaptive Transport Portfolio (provably link-maximizing throughput)

Status: DRAFT for review. Goal: a single, principled mechanism that provably
drives any filament transfer toward the maximum throughput the link can give,
generalizing every ad-hoc transport decision in the codebase.

## 1. Why (the empirical motivation)

Measured on a real DO sister-pair (do-vm <-> other-do, 2026-07-24):

| Transport / path | Throughput | Note |
|---|---|---|
| Raw TCP (single or 8 streams) | 2.0 Gbps | policer caps here; parallel does NOT aggregate |
| Raw UDP (paced 1.8-2.5 Gbps offered) | 1.0-1.3 Gbps, 3-8% loss | UDP deprioritized ~1.7x vs TCP |
| filament direct-quic (QUIC = UDP) | 1.3 Gbps (162 MB/s) | already at the UDP ceiling |
| filament DataChannel (old default) | 5-9 MB/s | SCTP flow-control bound |
| Same host (LocalTransport / channel-writer) | 1.2 GB/s | different regime entirely |

Conclusions that force a general solution:
- **No single transport is optimal across links.** UDP-throttled -> TCP wins;
  NAT-restricted -> only QUIC/relay connect; same host -> local dwarfs both.
- **The optimum is unknown a priori and time-varying** (policers, congestion,
  path/time-of-day, peer mobility).
- **Striping only helps across independent bottlenecks.** On a shared bottleneck
  (one policer) parallel streams/connections add nothing (iperf `-P` proved it);
  across genuinely independent paths (two NICs, LAN+WAN) it sums.

So "maximize any link" cannot be a hardcoded rule. It must be **measured and
converged to**, with a bound on how far from optimal we ever are.

## 2. The generalization: a portfolio + a no-regret selector

Model transport choice as an **online decision problem** over a portfolio of
*arms*:

```
arms  =  { local, direct-tcp, direct-quic, webrtc, relay-tcp, relay-quic }
         x  { K parallel connections : K in 1..Kmax }
         x  { stripe-subsets of independent paths }
```

Each arm `i` has an unknown, time-varying goodput `g_i(t)` (bytes/sec actually
delivered + acked). We want the transfer's average throughput to approach
`max_i avg g_i` (or, for independent paths, the sum over a stripe-subset).

The control loop, per active transfer:

1. **Feasibility filter.** Establish, in parallel, every arm that *can* connect
   for this peer (NAT/firewall/reachability). This is a superset of today's
   direct-vs-relay race. Arms that cannot establish within a budget are dropped.
2. **In-band measurement.** Measure each live arm's goodput *from the real
   transfer* - no separate benchmark. (We already emit per-transport byte
   counters from the multi-connection work; feed those into an EWMA of goodput.)
3. **No-regret selection.** Route the payload to the best-measured arm, spending
   a small, bounded fraction of bandwidth exploring the others (see section 3).
4. **Independence-aware striping.** For arms that survive, test whether using two
   together keeps each near its solo rate. If yes -> independent bottlenecks ->
   stripe for the *sum*. If combining depresses each -> shared bottleneck -> keep
   only the single best. This is *measured*, not assumed.
5. **Continuous adaptation.** Re-probe on a schedule and on drift signals (a
   sustained goodput drop). The optimum moves; the selector tracks it.

This subsumes the existing decisions: the direct-vs-WebRTC race (a 2-arm special
case), relay fallback, local-vs-mesh, and K>1 striping all become one mechanism.

## 3. The mathematical guarantee

Treat each arm as an expert with reward = measured goodput. Use a **no-regret
online-learning** selector:

- **Drifting / adversarial rewards** (policers, congestion): **EXP3** over the
  arms. For K arms over a horizon of T decision rounds,
  ```
  E[ sum_t g_{a_t} ]  >=  max_i sum_t g_i(t)  -  O( sqrt( T K log K ) )
  ```
  i.e. average-throughput regret is `O( sqrt( K log K / T ) )` per round, which
  **-> 0 as T grows**. For any transfer long enough to matter, filament converges
  to the throughput of the **best available arm**, with a bounded, shrinking gap.
- **Slowly-varying rewards** (typical): **sliding-window UCB** gives the same
  asymptotic optimality with better constants, by trusting recent measurements.
- **Independent-path striping**: let the "arm" be a *subset* S of independent
  paths; its reward is `sum_{i in S} g_i` (only valid when independence holds).
  The same no-regret bound over subsets converges to the best combination, so on
  a machine with genuinely independent links the guarantee targets the **sum**,
  not any single path.

**Statement.** Under a no-regret selector, filament's realized average throughput
is within a vanishing additive gap of the best achievable by any single arm (or
any independent-path stripe-subset). That is the precise sense in which we
"maximize any link": *bounded regret => asymptotically optimal transport
selection*, with the regret term quantifying (and bounding) the cost of the
exploration needed to discover the optimum.

**Honest bounds (what it does NOT promise):**
- It cannot exceed what the *best available transport physically delivers*. On a
  UDP-policed link, QUIC's ceiling is real; the win requires an arm that beats it
  (direct-TCP). The selector *finds* that arm; it does not create throughput.
- Exploration has a cost. That cost *is* the regret term - bounded and tunable
  (e.g. cap exploration at 5% of bandwidth). No free lunch, but a bounded lunch.
- Striping across a *shared* bottleneck yields nothing; the independence test
  prevents wasting effort there.
- Guarantees are asymptotic in transfer length T; very short transfers finish
  before the selector converges (fine - use the winning arm from the connection
  race and skip exploration below some size threshold).

## 4. The concrete missing arm: a direct-TCP transport

Today filament's direct mesh path is QUIC-over-UDP only. On UDP-throttled links
(common: cloud DDoS policies) that caps us ~1.7x below TCP. The portfolio needs a
**direct-TCP arm**:

- Reuse the existing high-throughput TCP machinery (the channel-writer that
  benchmarks ~1200 MB/s; `LocalTransport` framing).
- Establish a direct TCP connection to the peer via **TCP hole-punching**
  (simultaneous-open) using the same candidate exchange the QUIC direct path
  already does; fall back to relay-TCP if hole-punch fails.
- Run filament's existing frame/auth layer over the `TcpStream` (the framing is
  already transport-generic - `serve_stream<S: AsyncRead+AsyncWrite>`).
- It enters the portfolio as just another arm; the selector uses it when (and
  only when) it measures faster than QUIC on that link.

This is the single highest-value addition, because it is the arm that beats the
UDP policer we hit.

## 5. How it composes with existing filament

- **Establishment**: extend the current direct-vs-WebRTC race (Option A,
  `start_direct` post-PAKE) into an N-arm race. The `worker-ports` /
  candidate-exchange plumbing already exists.
- **Framing / bridge**: unchanged - `serve_stream` / `socket_to_dc` /
  `dc_to_socket` are already `S: AsyncRead+AsyncWrite` generic, so any arm
  (TcpStream, QUIC stream, DataChannel) plugs in.
- **Reassembly**: `pwrite_at` positional writes already allow out-of-order,
  multi-source delivery - required for striping. Keep the drain-accurate
  received-counter (received_written) so a mid-transfer arm switch resumes
  correctly (the seam we hardened for Bug 2).
- **Recovery**: the Bug 2 stall-ladder becomes per-arm; losing one arm drops it
  from the portfolio and the selector reweights - no hard failure.
- **Congestion control** stays per-QUIC-arm (BBR default); the selector operates
  *above* CC, choosing among transports, not tuning one.

## 6. Implementation plan (phased, each independently shippable)

1. **Direct-TCP arm** (biggest single win). TCP hole-punch + existing framing.
   Gate behind a flag initially; measure vs QUIC cross-machine.
2. **Goodput measurement + a 2-arm selector** (direct-quic vs direct-tcp): the
   minimal portfolio. Prove it picks TCP on the policed link, QUIC elsewhere.
3. **Generalize the selector to N arms** (add local, webrtc, relay) + the
   feasibility race. EXP3/UCB with a bounded exploration budget.
4. **Independence-aware striping** across measured-independent paths (multi-NIC /
   LAN+WAN); reuse the striping reassembly, add the independence probe.
5. **Continuous adaptation** (re-probe schedule, drift detection).

Ship 1-2 first (they already cover the concrete problem we hit); 3-5 are the full
generalization.

## 7. Open questions for review

- Decision granularity: per-transfer, per-file, or per-window? (Bandit round = ?)
- Exploration budget: fixed 5%, or size/duration-adaptive?
- Cross-transfer memory: cache the winning arm per-peer to skip cold exploration
  on the next transfer (warm-start the bandit)? For how long is it valid?
- Independence test cost vs benefit on typical single-homed hosts (often only one
  real path -> skip striping, just single-arm select).
- Fairness/congestion when we DO stripe multiple QUIC arms on near-independent
  paths that later converge.

## 8. Summary

One mechanism - **a portfolio of transports selected by a no-regret online
learner, with a direct-TCP arm added and independence-aware striping** - gives a
provable guarantee: filament converges to the throughput of the best available
transport (or the best independent-path combination) on any link, within a
bounded and vanishing gap. It turns "which transport?" from a pile of heuristics
into one adaptive, measured, mathematically-grounded decision.
