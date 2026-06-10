# ADR-0079: Kernel-state crash-restart reconciliation via adoption sweeps

**Status:** Accepted
**Date:** 2026-06-10

## Context

rustbgpd programs four kinds of Linux kernel state: unicast FIB routes
(ADR-0061/0066), RFC 7999 blackhole discard routes, EVPN L2 state
(single-dst FDB entries and ADR-0059 nexthop-group/FDB rows), and EVPN
symmetric-IRB L3 state (VRF routes, permanent neighbors, L3VXLAN FDB).
Only the unicast FIB survives an **unclean** restart correctly: it
persists an owned-state JSON file and re-adopts/reaps on startup.
Everything else tracks ownership in memory only, so after a SIGKILL or
crash:

- a blackhole route installed for a since-ended attack keeps discarding
  the victim's traffic forever, invisible to every status surface, and
  the preflight rejects re-owning the still-desired row as
  `foreign_route_exists`;
- an L3 tenant route whose Type 5 was withdrawn while the daemon was
  down keeps steering traffic into a dead VXLAN tunnel;
- single-dst `extern_learn` FDB rows for moved/withdrawn MACs persist
  (the kernel deliberately never ages or flushes them — that is what
  `extern_learn` is for).

The kernel guarantees the *survival* of this state, not its cleanup:
`rtm_protocol` values ≥ `RTPROT_STATIC` are userspace ownership tags the
kernel ignores; `NDA_PROTOCOL` is the same convention for FDB/neigh;
`NTF_EXT_LEARNED` entries are exempt from GC (with one exception —
carrier-down flushes ext-learned *neighbor* entries, so state can also
go missing while the daemon is dead, not just stale).

Prior art (source-verified): both mature implementations reconcile by
**startup adoption sweep, not persisted files**. FRR zebra flags
kernel routes whose proto is in its set as self-routes at the startup
dump, keeps them forwarding, and `rib_sweep_table` reaps whatever no
client re-claimed — immediately by default, or after a deferral window
(`-K`, default 500 s) with a per-object "refreshed since startup"
exemption; its client-GR layer sweeps per-client on an explicit
update-complete signal. FRR extended exactly this pattern to EVPN
FDB/neigh in January 2026 (PR #19778), keyed on
`NTF_EXT_LEARNED + NDA_PROTOCOL`. BIRD's kernel protocol scans and
prunes own-proto (`RTPROT_BIRD`) routes, and gates the first prune on
initial-feed completion (`p->ready`) — convergence-gated reaping. Our
unicast JSON file is the outlier among surveyed implementations, and a
file has a structural blind spot a sweep does not: it can only describe
what the daemon last knew, so it drifts when the kernel itself mutates
(carrier-down neigh flush) and it quarantine-freezes on any signature
mismatch.

## Decision

**New crash-restart reconciliation uses startup adoption sweeps keyed on
kernel-preserved ownership markers, with reaping deferred until the
owning subsystem has reconverged.** No new persisted owned-state files.

Per subsystem, the ownership discriminator (all already written by our
install paths today):

| State | Marker | Status |
|---|---|---|
| Blackhole discard routes | `RTPROT_BGP` + `RTN_BLACKHOLE` (table main) | Implemented |
| EVPN L3 VRF routes | `RTPROT_BGP` + onlink, in a configured `[[evpn_ip_vrfs]]` `table_id` | Implemented |
| EVPN L3 neighbors | `NUD_PERMANENT` + `NTF_EXT_LEARNED` on managed L3VXLAN devices | Implemented |
| EVPN FDB (single-dst + L3VXLAN) | `extern_learn` on managed VXLAN devices (non-NHG; NHG-tagged rows already have the ADR-0059 drift sweep) | Implemented |

Sweep semantics, shared across subsystems:

1. **Adopt at startup**: dump kernel state, recognize own markers, treat
   matching objects as owned — they keep forwarding and they no longer
   block re-installation as "foreign".
2. **Re-claim is implicit**: the daemon re-installing the same identity
   refreshes/replaces the adopted object (FRR's uptime-exemption
   equivalent: anything re-claimed after startup is exempt from reaping).
3. **Reap only after reconvergence**: the sweep that removes
   adopted-but-unclaimed objects fires when the owning subsystem reaches
   its converged-intent point (the BIRD `p->ready` analog — e.g. the
   blackhole reconciler's first full desired-set pass; the EVPN actors'
   first committed intent publication), with a bounded deadline as
   backstop. Reaping at startup before BGP reconverges is the known
   traffic-gap failure mode and is explicitly not the default.
4. **Idempotent under repeated crash**: a second crash inside the
   deferral window re-adopts harmlessly; sweeps never depend on state
   from the previous process.
5. **Handle missing as well as stale**: reconciliation must also
   re-install owned objects the kernel lost while the daemon was down
   (carrier-down neigh flush) — which the level-triggered reconcilers
   already do once ownership is adopted rather than refused.

For the EVPN L3 sweep specifically, re-claim required no diff change at
all: `compute_l3_diff` is purely desired-vs-owned and every L3 add
(`ip route replace`, neighbor replace, FDB replace) applies with
netlink replace semantics, so after a crash the empty owned state makes
the diff re-emit installs for everything still desired and the
re-install over the leftover row *is* the claim. The L3 reap also
orders its removals most-dependent first — routes before the neighbor
and L3VXLAN FDB resolution rows their forwarding depends on (the
inverse of the install pipeline's resolution-before-route ordering) —
so an unclaimed route never briefly forwards through torn-down
resolution state mid-reap.

The **unicast FIB keeps its persisted owned-state file** — it ships, it
works, and its value-match adoption discipline is stricter than a proto
sweep. Two refinements are folded into this decision: the owned-state
signature comparison becomes per-table and set-based — shipped:
previously any `[[fib_tables]]` edit across an unclean restart, even
stanza reordering, quarantined the whole file and froze stale routes
as `foreign_route_exists`; now only the edited or removed table's
routes drop out of ownership, with a `.stale` evidence copy preserved
beside the still-live file — and convergence of the unicast path onto
the sweep model is left as a future simplification, not a requirement.

### Operational hazards recorded (not solved here)

- **`RTPROT_BGP` is contested.** FRR zebra's `is_selfroute()` claims
  proto 186 as its own: a co-resident zebra will adopt and sweep
  rustbgpd's routes (immediately, in zebra's default mode). Likewise an
  operator's `ip route add ... proto bgp` is indistinguishable from
  daemon state. Our configured-table+metric discipline scopes unicast
  FIB ownership; configured VRF table/device/onlink shape scopes EVPN L3
  ownership. Co-residency with another proto-186 daemon is unsupported
  and now documented as such.
- **systemd-networkd reaps "foreign" state** (`ManageForeignRoutes`,
  `ManageForeignNextHops` default to yes and have deleted other daemons'
  NHGs in the wild). Deployment docs must require `ManageForeign*=no`
  on rustbgpd hosts.
- **NHG reap cascades**: deleting one group can invalidate dependents
  mid-iteration; the existing ADR-0059 sweep's restart-after-delete
  discipline carries over to any new NHG-adjacent reaping.

## Consequences

- A crashed daemon no longer leaves permanent invisible kernel state:
  the scariest case (blackhole discarding production traffic with zero
  observability) becomes a bounded window ending at the
  post-reconvergence sweep.
- Sweeps add a startup kernel dump per subsystem — cheap, and the
  blackhole reconciler's presence checks are batched into one dump per
  pass at the same time (replacing today's one full-table dump per
  candidate per pass).
- Ship order: blackhole first (smallest surface, worst failure mode),
  then single-dst FDB (extends the existing drift sweep), then L3
  (largest). Each slice needs a kill-and-restart test proving
  stale-state reaping and still-desired re-adoption. All three slices
  have shipped. The FDB slice is proven by the M60 containerlab job
  (`test-m60-evpn-adoption-sweep.sh`, hosted `kernel-dataplane` CI):
  SIGKILL with the netns surviving, one MAC withdrawn while the
  daemon is down, restart with a short deferral via
  `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS` — still-desired row
  held continuously, unclaimed row reaped, foreign rows untouched.
  The blackhole and L3 kill-and-restart proofs are still open.
- The per-table set-based unicast signature ends the
  quarantine-freeze-on-edit class without weakening the value-match
  adoption rule.
