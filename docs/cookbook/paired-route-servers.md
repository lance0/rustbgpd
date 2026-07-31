# Paired route servers — staggered updates and maintenance windows

**When this is you:** your exchange runs (or should run) two route
servers, every member peers with both, and you want the operational
discipline that makes the pair actually redundant: independent
instances, staggered config rollout, a mechanical inter-RS consistency
check, and a drain flow for maintenance.

## Why two, and why members peer with both

A route server is a single point of failure for multilateral peering:
when it goes down, members lose every route learned through it. The
standard remedy is two route servers on separate hosts (ideally
separate power/switch domains), with every member holding a session to
each. Both carry the same policy and advertise the same routes, so a
member losing RS1 converges onto identical paths already learned from
RS2 — the fabric forwards through the same next hops throughout
(RFC 7947 transparency: the route server is not in the data path).
Redundancy only holds if members actually configure both sessions;
make dual sessions part of member onboarding, not an option.

## Independence rules

- **Two instances, two hosts, zero shared runtime state.** The
  instances never talk to each other; consistency comes from feeding
  both the same policy inputs, not from synchronization.
- **One policy source, two renders.** With the
  [IXP filter pipeline](ixp-filter-pipeline.md), both route servers
  render from the same arouteserver `general.yml` / `clients.yml` —
  run the render per host (or distribute one render's output), and
  keep each host's `rustbgpd --check --strict` gate local so a corrupt
  copy cannot pass.
- **Distinct `router_id`s**, same ASN, same member ACLs. Members see
  two ordinary sessions to one route-server AS.
- **Independent RPKI feeds.** Point each instance at the RTR
  cache set directly ([`[rpki]`](../CONFIGURATION.md#rpki) takes
  multiple `cache_servers`); do not proxy one instance's view through
  the other's host.

## Staggered config updates

Never reload both route servers in the same step — the second instance
is your rollback while the first proves the change. Per update:

1. **Validate everywhere first:** `rustbgpd --check --strict` on the
   candidate config on both hosts (exit 0 or stop), and check the
   [reload matrix](../reload-matrix.md) for whether any touched field
   is restart-required.
2. **Reload RS1 only** (SIGHUP; parse-then-swap — a rejected candidate
   leaves the running config untouched).
3. **Verify RS1:** sessions established (`rbgp summary`), spot-check a
   member's view (`rbgp rib sent <member>`), no alert movement.
4. **Soak** for an operator-chosen window (long enough for a full
   member announcement cycle and your monitoring interval).
5. **Reload RS2**, re-verify, then run the consistency check below.

The same stagger applies to daemon upgrades, with the
[maintenance drain](#maintenance-window-flow) around each restart.

## Inter-RS consistency: `rbgp diff advertised`

Two independently rendered route servers can drift — a stale render on
one host, a reload that never happened, a member session down on one
side. The check is mechanical and fail-closed
([`docs/ribdiff.md`](../ribdiff.md)): snapshot what RS2 advertises,
compare RS1's live Adj-RIB-Out against it, gate on the exit code.

Capture RS2's advertised view from its own BMP feed — wire-true,
including attributes no CLI view renders. Enable the RFC 8671
post-policy stream on RS2 (restart-required, so make it part of the
standing config rather than a per-check toggle; see
[`[bmp]`](../CONFIGURATION.md#bmp)):

```toml
[[bmp.collectors]]
address = "192.0.2.100:11019"          # your capture/collector host
monitor = ["rib_out_post"]
```

Then, on the capture host:

```bash
# Capture from BMP session start (Peer Ups carry the negotiated OPENs),
# stop after every peer's dump completes, then convert and compare:
nc -l 11019 > rs2-adjout.bmp
rbgp diff snapshot from-bmp rs2-adjout.bmp > rs2.ndjson
rbgp diff advertised --against rs2.ndjson    # pointed at RS1's gRPC socket
echo $?   # 0 in sync, 1 divergent (listed), 2 comparison refused
```

Run it after every staggered rollout completes, and on a schedule
between rollouts; archive the `--json` report. Expected divergence,
not a finding: a member session down on exactly one instance makes
that member's routes one-sided everywhere. Anything else is drift —
diff the two hosts' render receipts and reload timestamps first.

## Maintenance-window flow

Taking RS1 down (upgrade, host maintenance) without a member-visible
routing gap — RFC 8326 graceful shutdown, initiator side (full
semantics and verification in
[OPERATIONS.md](../OPERATIONS.md#rfc-8326-graceful-shutdown-community-planned-maintenance)):

1. **Confirm RS2 is healthy and consistent** (the diff above, all
   member sessions established). Two-instance redundancy means never
   starting maintenance while the survivor is degraded.
2. **Drain RS1:** `rbgp gshut` (all peers). Outbound paths get the
   `GRACEFUL_SHUTDOWN` community; members honoring it demote those
   paths, so the RS2-learned copies win *before* anything closes.
3. **Wait for the shift** (operator-defined; verify on a member:
   the RS1-learned paths show demoted preference, best paths point at
   RS2-learned copies).
4. **Do the maintenance.** Members stay converged via RS2.
5. **Restore RS1**, wait for sessions and full table
   (`rbgp summary`, `rbgp rib sent <member> --count` plausible).
6. **Clear the drain:** `rbgp gshut --clear` (the toggle does not
   persist across restart by design — after a restart-type
   maintenance, step 6 is a no-op, but run it when the daemon kept
   running). Re-run the consistency check.

The honest caveat: the drain only moves members that honor
`GRACEFUL_SHUTDOWN` (rustbgpd receivers opt in via
`honor_graceful_shutdown`; support varies across member stacks).
Members that ignore it still reconverge onto RS2 when the sessions
close — the drain turns that reconvergence from break-before-make into
make-before-break for everyone who participates.
