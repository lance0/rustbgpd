# ADR-0078: Inbound transport→RIB backpressure — block, never drop

**Status:** Accepted
**Date:** 2026-06-10

## Context

Session tasks deliver parsed inbound work to the single-task RIB manager
(ADR-0013) over one bounded mpsc channel. Today that channel has two
inconsistent delivery policies:

- `RoutesReceived` (announces + withdraws, all families) uses
  `try_send` — a full channel **silently drops the batch**. The drop is
  invisible (no counter) and unrecoverable (BGP is incremental; the peer
  will not re-send), and the transport side has already committed its
  bookkeeping (`known_paths`, max-prefix accounting, the import-explain
  cache, permit/deny counters) before the enqueue, so every observable
  surface claims the routes were accepted. A dropped announce is a
  permanently missing route; a dropped withdraw is a permanently stale
  route — a black hole that survives until session reset or an operator
  refresh.
- Lifecycle messages (`PeerUp`, `EndOfRib`, route-refresh markers, ORF
  updates) use blocking `send().await` — a full channel **parks the
  session task** inside a `select!` arm, which stops the loop from
  servicing its own hold/keepalive timers. A sufficiently long RIB stall
  can therefore starve our KEEPALIVE emission and induce the *peer* to
  expire its hold timer.

Production implementations were surveyed before deciding (FRR, BIRD,
GoBGP, OpenBGPD — source-verified). The consensus is unambiguous:
**no production BGP implementation ever drops an inbound UPDATE.** The
standard shape is FRR's: a bounded per-peer input queue; when it fills,
the daemon **stops reading the TCP socket** so kernel receive-window
backpressure pushes back to the sender, and liveness machinery is
decoupled so the backlog cannot expire either side's hold timer (FRR
runs a dedicated keepalive thread, and its own hold timer treats
queued-but-unprocessed input as proof of peer liveness and re-arms).
BIRD 3's "cork" mechanism is the same answer ("the corked socket is
simply not checked for received packets"); BIRD 2 got it implicitly from
synchronous import. GoBGP instead buffers unboundedly, and its
documented failure mode (issue #2096: multi-minute stalls, unbounded
RSS, hold-timer expiries at scale) is the cautionary tale for the
staging-queue alternative. The "BGP zombies" measurement literature
(Fontugne et al., PAM 2019) quantifies the operational harm of exactly
the lost-withdraw failure mode our current `try_send` creates.

## Decision

Adopt the consensus contract: **inbound work is never dropped; a full
RIB channel stops the session task from reading its socket; liveness is
decoupled from processing.**

1. **`RoutesReceived` switches from `try_send` to `send().await`.** The
   bounded RIB channel becomes the FRR `inq_limit` analog: when it is
   full the session task parks, stops reading its TCP stream, and the
   kernel receive window backpressures the sender. The sender's own
   update pacing absorbs the load — overload is shed to the party that
   can actually slow down, instead of being converted into silent state
   corruption (drop) or unbounded memory (staging).
2. **KEEPALIVE emission must not share fate with RIB delivery.** The
   ADR-0051 writer task (which already owns TCP writes) takes ownership
   of the keepalive timer, so a session task parked on the RIB channel
   keeps feeding the peer's hold timer. This is the FRR
   dedicated-keepalive-thread invariant in our two-task shape.
3. **Pending input counts as peer liveness.** While the session task is
   parked on RIB delivery (or has unprocessed bytes buffered), our hold
   timer for the peer is re-armed rather than expired — when we are the
   bottleneck, the peer's silence is our fault (FRR's
   `bgp_holdtime_timer` re-arm rule).
4. **Transport bookkeeping commits only after a successful enqueue.**
   With blocking sends the ordering is natural, and the
   counters/explain-cache/`known_paths` can no longer claim acceptance
   for work the RIB never saw.
5. **Saturation is observable.** A per-peer counter/gauge records
   blocked-send occurrences (channel-full events), so a chronically
   undersized channel or a pathological RIB stall shows up in Prometheus
   instead of in mystery convergence latency.

### Alternatives rejected

- **Honest lossy + Route Refresh resync** (drop, count, self-issue a
  refresh once the channel drains). Protocol-legal thanks to RFC 2918 /
  RFC 7313, but no surveyed implementation uses loss as its primary
  contract, the stale window leaves black holes live until a full
  re-flood, the refresh costs a full per-peer table re-send *exactly
  when overloaded* (positive feedback), and peers without Route Refresh
  degrade to session reset — a worse feedback loop.
- **Per-peer unbounded staging queue** (the inbound mirror of the
  ADR-0051 writer split). Production precedent exists (GoBGP, and
  OpenBGPD's session-engine→RDE pipe), but it converts overload into
  RSS growth plus latency with a global failure mode, and it only buys
  time — the bound has to exist somewhere. Revisit only if soak/scale
  evidence shows the blocking contract starving interactive RIB work;
  any such queue must come with pacing, fairness, and memory accounting.

## Consequences

- A slow RIB no longer corrupts state — it slows ingestion, visibly.
  Convergence under overload degrades gracefully (sender-paced) instead
  of catastrophically (silent stale routes).
- The session task may now legitimately park; every admin-path
  round-trip into session tasks must keep its existing bounded deadline
  (`query_state_timeout`, policy hot-apply deadlines) — those patterns
  stay mandatory.
- The keepalive-ownership move touches the transport timer wiring and
  needs interop coverage (hold-timer survival under an artificially
  stalled RIB) — this is the riskiest slice and ships first with tests.
  That coverage is proven by the M63 containerlab job
  (`test-m63-stalled-rib-hold-timer.sh`, `interop` CI): the RIB manager
  is stalled per `RoutesReceived` batch via
  `RUSTBGPD_TEST_RIB_INGEST_STALL_MS` with the channel shrunk via
  `RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY`, an FRR flood saturates it, and
  the session survives parks longer than the negotiated hold time on
  both ends — with `bgp_inbound_rib_backpressure_total` > 0, the exact
  injected route count in the RIB (never-drop), and zero flaps as
  receipts.
- The RIB channel capacity becomes a meaningful tuning knob (today its
  overflow behavior made it a correctness cliff); its default should be
  revisited against the bench-suite convergence shapes.
- Outbound (RIB→session) delivery is unchanged: that direction already
  has the `dirty_peers` resync contract and a slow *peer* must not be
  able to stall the RIB.
