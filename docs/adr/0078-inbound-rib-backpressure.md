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

## Amendments

### 2026-11-03 — A parked session keeps servicing outbound, timers and closes

Rule 1 parked the whole session task on `send().await`. While it was
parked, the task also stopped draining its RIB→session outbound queue and
admitting frames to its writer, left its hold timer and writer-exit arms
unpolled, and did not act on operator commands. Under a saturated RIB every
session parks at once, so every per-peer outbound queue fills to its bound
and a closing session's Cease waits for the RIB.

The blocking send is replaced by a per-session FIFO of held RIB-bound
messages. A message that finds the channel full is held, and every later
RIB-bound message from that session queues behind it; the run loop delivers
the FIFO in order through a channel reservation that keeps its place among
waiting senders. While anything is held, the session reads nothing more
from its socket and decodes no further buffered PDU, so rule 1's TCP
backpressure and the per-session order the RIB sees are unchanged. The
session task delivers everything held before it returns, sending the head
through its queued reservation first.

While parked, the run loop:

- drains outbound into the writer under the existing writer admission,
  including envelopes that span many writer slots;
- polls the hold timer and observes writer exit, including RFC 9687
  send-hold expiry;
- answers state snapshots;
- runs Shutdown, Stop, purge reset and BFD down at once, whether they
  arrive on the command channel or were deferred by an owned wait, and an
  administrative reset when it closes an Established session.

Other commands, any command queued behind one of them, a reset with no
Established session to close, the reconnect a close schedules, and the
refresh-accounting timer wait until the held messages are delivered, as
before. Repeated resets therefore queue at most one `PeerDown` behind the
held messages.

Refresh-accounting state that rule 4 ties to channel acceptance (BoRR,
EoRR, refresh timeout) changes when the held message is admitted, and no
buffered PDU is decoded while such a message is held. If the connection
goes down first, the held markers still reach the RIB in order, but their
local effects are dropped with that connection's windows.

Being parked no longer suspends hold expiry by itself. The held batch
restarts the hold timer when it is held, at the start of the park, not
when the RIB admits it. At expiry, a complete frame that cannot be
processed yet (rule 3's pending input) renews the hold time once; a further
renewal needs bytes received since that renewal, found by one bounded
socket read. A peer that goes silent is therefore expired within two hold
times even while parked, as RFC 4271 section 6.5 requires, while a peer
whose input keeps arriving stays up. A frame larger than our receive window
(possible with RFC 8654) cannot complete while the socket is unread, so a
live peer sending only such frames could be expired during a park longer
than the hold time.

These waits remain inside their handlers, as existing exceptions to the
servicing above; the whole session waits on channel admission:

- an ORF update, which awaits admission and then its RIB reply;
- an export-policy update, which reserves a slot before acknowledging the
  peer manager;
- the runtime-config IPv6 unicast unlock, which is acknowledged the same
  way;
- an operator replay's `ReplayPeerOutbound`, which runs only with nothing
  held, waits under the replay deadline and answers state snapshots
  meanwhile.

Draining outbound while parked bounds the writer queue by its existing
limits: 4096 frames, at most 16 MiB of standard messages or just under
256 MiB with RFC 8654. That is a bound on frames and their bytes, not a cap
on the total outbound heap: the RIB→session envelope queue and an envelope
being encoded still hold workload-sized route payloads.
