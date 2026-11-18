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

Being parked no longer suspends hold expiry indefinitely. While input is
deliberately left unprocessed, it cannot prove the peer's liveness, so the
deferral is bounded as a local-overload policy rather than inferred. The
budget counts deferrals since the last peer message processed; a wait that
our own message starts (a revalidation chunk, a refresh timeout) does not
restore it. A held batch restarts the hold timer when it is held.

- The first hold expiry is deferred for the wait itself, even when only
  part of a frame is buffered.
- The second is deferred only for newly read bytes, from one probe of at
  most 4 KiB, or for a read buffer already full of unprocessed input. A
  socket read cannot tell fresh arrivals from data that was already
  queued; that leniency is acceptable only because both the renewals and
  the bytes they may read are bounded.
- The third closes the session with Cease/Out of Resources (RFC 4486
  subcode 8), logged as RIB admission stalled past the local budget. Under
  RFC 8538 this is a NOTIFICATION teardown: a graceful-restart peer keeps
  its routes only when Notification GR was negotiated.

A session whose RIB admission stays blocked for about three hold times
since the last processed peer message is therefore closed deliberately, as
a local overload, not because the peer's messages went missing. Probes
never take the unprocessed read buffer past two maximum-size messages
(8 KiB, or 128 KiB with RFC 8654), whatever the number of waits. The rule 3
pending-input re-arm still applies outside a wait. A frame larger than our
receive window (possible with RFC 8654) cannot complete while the socket is
unread; the first deferral covers one hold time of that, not more.

Operational risk: the threshold scales with the hold time. With short hold
times (3 to 9 s), a session whose RIB admission stays blocked for about
three hold times, 9 to 27 s, during heavy but progressing convergence is
closed with Cease/8, and its re-establishment re-floods its routes into the
same saturated RIB. `bgp_notifications_sent_total{code="6",subcode="8"}`
counts these closes; `bgp_hold_timer_rearmed_pending_input_total` counts
the deferrals before them, and `bgp_inbound_rib_backpressure_total` the
waits.

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

### 2026-11-18 — A per-session ingest budget bounds one source's share of the queue

The decision above bounds the shared channel, not any one source. A session
that reads as fast as its peer writes can put a whole burst into the channel
ahead of every other session's updates: 150,000 routes sent at once toward
150 private receivers made an unrelated peer's update wait for the entire
burst, about 15 s in the transport harness, although the channel never
filled. This is the starvation
evidence the rejected per-peer queue alternative asked for, and the answer is
the bounded per-source input the Context names as the standard shape, kept at
the source instead of in a queue.

Each session charges every route-bearing message of every family to its own
ingest budget, one route per announced or withdrawn entry. When 1,536 of its
routes are unfinished in the RIB the session reads nothing more from its
socket and processes no further buffered PDU; it resumes at 1,024. A full
standard 4,096-byte IPv4 UPDATE carries about 1,008 routes, so two of them
close the gate and the return of one reopens it: the RIB has one message in
progress and the session's next one decoded and queued. A stop mark of two
whole windows (2,048) would admit a third such message. The 512 routes
between the marks keep a stream of small messages from stopping and resuming
once per message. Nothing
already read is held for budget, so a message larger than the whole budget
is admitted whenever the gate is open, and End-of-RIB, route-refresh markers
and session ends are sent in stream order without waiting. The shared
channel, its bound and rules 1 to 5 are unchanged; the RIB's actor loop,
timer cutoffs and message order are unchanged.

The charge is a permit carried by the message. The RIB returns it by
dropping the message: after the distribution pass that covers its routes,
including a pass shared with later messages and a fan-out continued over
several turns; at once for a family applied within its own turn; and on every
discard, namely a peer-down purge, a message from a replaced or unregistered
session, shutdown and a closed channel. There are no release calls to miss.
A session end starts a fresh budget, so routes of an ended connection never
pace the next one. Selection deferral does not hold a permit: the routes are
ingested and the batch finished.

A hold expiry behind a spent budget alone does not use the bounded policy of
a full channel (2026-11-03). The channel has room, so liveness is judged from
the peer's input: the expiry admits one complete frame, already buffered or
readable from the socket, past the gate, and the hold timer restarts from it
as from any received message. The overdraft is at most one PDU per hold time
per session. With no complete frame to admit the peer has been silent, and
the session sends Hold Timer Expired. When messages are also held for a full
channel, the full-channel policy applies unchanged.

Frames already received do not show that the peer is still there: a peer
that sent many complete frames and then went away would stay Established for
one hold time per frame, and a socket receive buffer holds thousands. The
admissions are therefore bounded at eight consecutive hold expiries with the
gate never reopening. From the ninth the wait uses the full-channel policy:
no further frame is admitted, and the session is closed with Cease/Out of
Resources after at most two more deferrals, the second only for new bytes
from the peer. A gate that reopens starts the count again. Eight hold times
is 12 minutes at hold time 90 and 24 s at hold time 3. A bound near three was
rejected: one local RIB stall of a few hold times would then close every
session waiting behind its gate, which is the failure the per-frame rule
exists to avoid. A session is closed for the RIB's pace alone only after
about ten hold times behind one closed gate.

While the gate stays closed the session does not read its socket, so a
NOTIFICATION or a close from the peer is acted on when the gate reopens, or
when a hold expiry reaches it: at once if nothing complete is pending ahead
of it, otherwise after one hold time per pending frame, up to the eight
above. With hold time 0
there is no expiry and it is acted on when the gate reopens. KEEPALIVEs to
the peer come from the writer task and do not depend on the gate.

A hold expiry that finds the connection closed or failed, with no complete
frame ahead of the close, ends the session as that TCP failure and sends no
NOTIFICATION. It is not a hold expiry: for a peer with Graceful Restart and
without the Notification bit, RFC 4724 retains its routes after a TCP
failure, while a hold expiry flushes them (RFC 8538). The full-channel
policy does the same when its probe reaches the close; before, it sent
Cease/Out of Resources there. A peer with the connection open and nothing
complete to read still gets Hold Timer Expired.

Under the full-channel policy, complete frames can be buffered ahead of the
close the probe finds. They are processed first, all of them and in order,
past the gate and behind the messages already held, as the read loop would
have processed them before it saw the end of the stream. A NOTIFICATION
among them therefore ends the session as a received NOTIFICATION, not as a
TCP failure: the peer's routes are deleted unless the Notification bit was
exchanged, and after a Hard Reset in every case (RFC 4724, RFC 8538).
UPDATEs ahead of the NOTIFICATION or of the close reach the RIB before the
session end, so routes retained as stale are the peer's last advertisements.
Scanning for the NOTIFICATION alone and dropping the UPDATEs was rejected:
retained routes would then include ones the peer had withdrawn. The frames
processed this way are bounded by the read buffer (two maximum-size messages
under the probes), once per connection.

A close is found only once everything ahead of it has been read. Under the
full-channel policy the probes stop at two maximum-size messages, so a close
behind more unread data than that is not found, and the wait ends with
Cease/Out of Resources, which deletes a restarting peer's routes unless the
Notification bit was exchanged. The socket does report such a close without
reading the data, but acting on it was rejected: the unread data can hold
withdrawals and a NOTIFICATION, and retaining routes without having read
them is the error described above, while reading it all would admit a whole
receive buffer past the budget.

Consequences:

- An unrelated peer's update waits behind a bounded number of a bursting
  source's route entries, not behind a burst: up to 1,536 unfinished, plus
  the one message that crosses the mark. The limit counts route entries,
  not messages or passes. At roughly 1,000 routes per UPDATE that is about
  two messages and two distribution passes. Smaller unicast UPDATEs are
  coalesced by the RIB's distribution window, which closes at 256 messages,
  1,024 distinct prefixes or 5 ms, so the same entries take about two passes
  down to a few routes per UPDATE and up to six smaller ones at one route
  per UPDATE (1,536 messages), more if windows close on time. The window
  takes unicast-only input; a message of another family is distributed on
  its own, so there the count of passes follows the count of messages,
  still within 1,536 entries. The wait still grows with the number of
  sources bursting at the same time.
- Timer cutoffs cover received input only, and the budget shrinks what is
  received ahead of the RIB from up to the whole channel to about 1,536
  route entries per source. Input a peer sent before a graceful-restart,
  long-lived or refresh deadline that is still unread in its socket is not
  applied before the sweep.
- Route input that does not come from a session (injection, local
  origination, MRT replay) carries no permit and is bounded only by the
  shared channel.
