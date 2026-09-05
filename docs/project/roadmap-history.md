# Roadmap history

Completed roadmap records moved from [ROADMAP.md](roadmap.md) are preserved
here in their original wording and order. Current work remains in
[ROADMAP.md](roadmap.md), and shipped behavior is recorded in
[CHANGELOG.md](../../CHANGELOG.md).

## Archived roadmap sections

### Strategic direction — the operational frontier (2026-07-17)

A discovery pass (IXP route-server + iBGP route-reflector + internal-quality)
landed one conclusion: **rustbgpd's protocol and control-plane are already
ahead of the open-source field.** The BMP 7854+8671+9069 trio, role-aware
ASPA, RFC 9234 Roles/OTC, ORR (first OSS), per-client-best path-hiding, the
export-explain trilogy, and the `.rpol` language with live-RIB dry-run and
per-term hit counters are a stack no other OSS daemon ships together. So the
path to best-in-class RS/RR is **not** more protocol breadth — it is closing
the *operational* gap between "great control-plane guts" and "a daemon an
operator actually puts in production." This is the same technical-merit-first,
in-niche posture as above: every item deepens the existing identity, and none
adds PE/MPLS/dataplane breadth. Three tracks:

**1. Route-server adoption pipeline.** What keeps IXPs on BIRD+arouteserver is
the data-driven filtering/tooling wrapper, not the daemon.
- IRR/PeeringDB-driven prefix filtering — MANRS Action 1, the #1 adoption
  blocker. **Direction decided (ADR-0110, 2026-07-17; now Accepted with
  phase 1 shipped and differential-proven):** hybrid — an external
  renderer consuming `arouteserver template-context` output feeds the existing
  parse-then-swap reload seam (inherits the whole industry ingest pipeline, no
  upstream gate); native ingestion demand-gated. The phase-1 renderer is
  **Shipped (#986)** as `tools/rs-config-render` — template-context ingestion
  is fingerprint-pinned with fail-stale refusal, and the emitted config is
  verified by a real `rustbgpd --check`. The phase-1 differential is also
  **shipped (M90):** one site input produces arouteserver/BIRD and
  `rs-config-render`/rustbgpd policy, with 11/11 accept/reject parity, generated
  explain-term attribution, and a policy mutation proven to make the lab red.
  The origin-as accessor gap claimed at drafting was stale — already shipped
  (LAN-467, umbrella).
- ~~RFC 7947/8195 community-based announcement control~~ **Shipped (#968):**
  per-target announce / announce-only / announce-to-none / prepend via
  standard + large control communities, egress scrub, rs-client-default knob
  (LAN-466).
- ~~Reject-reason retention → Alice-LG looking glass~~ **Shipped (#981,
  #984):** bounded per-peer reject-reason retention behind
  `PolicyService.ListRejectedRoutes` and `rbgp rib received <peer> --rejected`,
  and the birdwatcher adapter now serves its filtered-route views from it
  (reject reasons mapped to large communities under `64496:65520:*`; the
  noexport view has since shipped too, from the export-explain surface)
  (LAN-472).
- ~~Ship ADR-0107 NEXT_HOP self-consistency~~ **Shipped (#964):**
  `next_hop_ownership = "strict_peer"` fail-closed ingress gate; ADR-0107
  Accepted; same-AS mode stays deferred behind the fleet inventory (LAN-473).

**2. Route-reflector robustness + fanout observability.**
- ~~General RFC 7606 treat-as-withdraw~~ **Shipped (#965):** malformed
  attributes now treat-as-withdraw / attribute-discard per §7 across all
  families with the session staying Established; session reset only where the
  NLRI is untrustworthy. Adversarially reviewed pre-merge (LAN-465).
  **Per-disposition counters + malformed-UPDATE interop proof shipped
  ([#1014](https://github.com/lance0/rustbgpd/pull/1014)):**
  `bgp_update_malformed_total{peer,disposition}` records
  `attribute_discard`, `treat_as_withdraw`, and `session_reset`, and M91 drives
  all three through a raw-speaker lab.
- **Shipped:** settlement-owned policy reloads distinguish session timeout from
  task loss, retry the first timeout once inside a shared two-second window,
  and compensate explicit non-Established or unprovable state. Exact RIB
  rollback is one reverse-order, receipt-bearing batch whose late repair stays
  owned and whose pending debt clears only from validated acknowledgements.
- Fanout-observability trio: ~~per-update-group / queue-depth metrics~~
  **Shipped (#962)** (`bgp_peer_outbound_queue_depth`, `bgp_peer_update_group`)
  → ~~slow-peer detection~~ **Shipped (#967)** (threshold+duration detector,
  `bgp_peer_slow`, neighbor-state flag, opt-in own-group isolation via a
  `SlowPeer` membership) → ~~gNMI dial-out~~ **Shipped (#982)**
  (`[gnmi_dialout]` streaming push to central collectors, LAN-471). The
  operator triage chain "which client is slow, which group is it in, is it
  isolated" now exists end-to-end and streams to a collector.

**3. Release hygiene (timing-critical).** ~~Absorb `#[non_exhaustive]` onto
the growing wire/fsm protocol enums~~ **Shipped (#983):** the
registry-tracking enums are marked ahead of the in-flight 0.15.0 breaking cut,
with fail-safe wildcard arms across consumers, so the
`Capability::PathsLimit` pattern no longer forces a breaking bump per variant
as IANA/RFC registries grow (LAN-468).

Deliberately *not* on this frontier (verified already-shipped or hard-deferred):
RPKI/ASPA, Roles/OTC, graceful-shutdown, blackhole, Prefix-ORF, the BMP trio,
Add-Path send (shipped, several ahead of the field — keep ASPA
conformance-current, it is a moat); AIGP, conditional advertisement, Add-Path
update-group scaling (ADR-0099), send-side ORF (ROADMAP-tracked / demand-shaped).

### Operator experience (2026-07-17)

A discovery pass over the operator journey — first contact through production —
found the operator surface largely *built* but *under-discoverable*:
compiler-grade config diagnostics, `--check`/`config diff` with reload-class
annotations, commit-confirmed transactions, `rbgp doctor`, the explain
trilogy, and an importable Grafana dashboard plus a tested alert pack all
exist, while no incumbent daemon ships native JSON output, a transactional
config workflow, or span-and-suggestion config errors at all. **The gap is
not features — it is discoverability, first-30-minutes friction, and
migration-in.** Three tracks, ranked:

**1. Discoverability of shipped differentiators.** ~~A landing page for the
explain trilogy plus README positioning (LAN-478); an end-to-end
arouteserver → rs-config-render → looking-glass tutorial and docs-index
wiring for `tools/` (LAN-479).~~ **Shipped (#989):** `docs/explain.md`
explain/introspection catalog with README positioning, and the
`docs/cookbook/ixp-filter-pipeline.md` end-to-end tutorial with docs-index
wiring for `tools/`.

**2. First-30-minutes friction.** ~~A pre-built-binary install path~~
**Shipped (#989):** checksum-verified release-tarball install ahead of
`cargo build` in the quickstart (LAN-480); ~~`rbgp doctor` first-deploy
environment checks~~ **Shipped (#992):** BGP listener bound, RTR/BMP
reachability, run-context detection, state-dir disk probes (LAN-482).

**3. Fewer footguns, smoother migration in.** ~~Did-you-mean suggestions for
unknown config keys~~ **Shipped (#993):** unknown-key config errors now carry
a did-you-mean line inside the existing diagnostic frame, ranked by the same
Levenshtein machinery as the `.rpol` suggestions (LAN-481);
~~config version history + `rollback N`~~ **Shipped (#1016):** retained applied
versions and rollback share the same transaction/validation path, completing
the check/compare/confirm/rollback workflow for TOML-complete snapshots
(LAN-483). ADR-0121 v2 provenance recording, exact external-source
verification, and restore are **shipped**. Since v0.65, legacy TOML history is
ignored and retained rather than listed or restored.
**Shipped (LAN-798):** commit-confirm v2 now journals that same immutable prior
snapshot behind a config-adjacent locator. Crash boot restore verifies and
directly adopts the accepted prior snapshot; live abort and timeout reuse the
same prior object through the normal planner and apply path. Locator removal is
the durable terminal point. V3 is now the sole commit-confirm authority;
retired v1/v2 artifacts fail boot untouched with rustbgpd v0.64.0 recovery guidance.
Provenance is audit and verification evidence, not authority to adopt
external-policy state. #1370 fences every full-snapshot
external-input rollback; its only exceptions remain a true no-op and a targeted
pure-`[[fib_tables]]` transaction whose external inputs are unchanged;
~~a bounded
BIRD/FRR/GoBGP config importer~~ **Shipped (#1015):** structure-only conversion
with a fail-stop unsupported-directive report and shadow-trial workflow
(LAN-484).

Deliberately *not* here: a web UI, Terraform/Ansible providers (maintenance
surface without demonstrated demand — revisit on operator pull), and
BIRD-filter-language translation (the importer stops at structure).
- ~~Positioning: frame the published matrix receipt against the documented
  market history in COMPARISON.md~~ **Shipped (#991):** "Why reload behavior
  decided this market" — reload/convergence history, the blank-config reload
  failure class vs the validate-then-apply transaction model, and the
  config-converter vacuum, externally verifiable and citation-backed
  (LAN-485).

### Completed: post-v0.50 audit remediation (2026-07-09)

A repository-wide read-only audit at `155b24c2` found the workspace test,
Clippy, formatting, and doc gates green, but adversarial lifecycle and
failure-path review exposed correctness gaps that the happy-path suites did
not exercise. This remediation tranche took priority over new protocol
breadth and the research-shaped queue below; every item below has since
landed. The section stays as the audit-finding record.

**Release blockers (all landed):**

- [x] **Commit-confirm recovery state machine.** Preserve the pre-transaction
  journal whenever apply completion is ambiguous (post-persist finalization,
  reply loss, or compound rollback failure); do not clear the mutation fence
  after failed abort/auto-revert while that journal can still boot-revert later
  accepted intent. Add post-persist, failed-rollback, second-mutation, and boot
  recovery tests (`src/config_transaction_control.rs`).
- [x] **Fail-closed release publication.** Require tag/version equality and a
  named pre-release test/audit/package gate before publishing binaries or the
  container image; include `LICENSE-MIT` and `LICENSE-APACHE` in release
  archives and the runtime image, with artifact-content assertions.
- [x] **Restore dependency-audit green.** Update dev-only
  `crossbeam-epoch 0.9.18` to a graph resolving `>= 0.9.20` for
  RUSTSEC-2026-0204; keep the advisory gate fail-closed rather than adding an
  ignore for a fixable dependency.
- [x] **Repair vacuous operational proofs.** Make M37 distinguish FRR query
  failure from valid route absence; require numeric Gate 8b DF-counter samples
  before restart monotonicity can pass; make M33 reject missing CSV columns.
  Re-run or explicitly downgrade only the affected proof claims — the archived
  Gate 8b memory/flip-cycle evidence and complete M33 receipt remain valid.

**Correctness tranche 1 — highest-impact runtime work:**

- [x] **Transport saturation teardown.** After a bounded writer queue fills,
  make Cease the final frame, close without draining queued UPDATEs, and drive
  `TcpConnectionFails`/RIB/session cleanup from the real run loop. Add an
  end-to-end regression that does not manually inject the FSM event.
- [x] **RTR/RPKI transaction state.** Model `(protocol version, session ID,
  serial)` as one per-cache epoch; retain usable cache data through reconnect
  until expiry/full replacement; validate Cache Response/EoD identity; correct
  ASPA replacement and empty-provider withdrawal semantics; bound each RTR
  transaction by deadline, expiry, PDU/record/byte budgets. Describe the
  supported 8210bis subset honestly until the complete contract is proven.
- [x] **LLGR per-AFI/SAFI lifecycle.** Preserve the original LLST through
  reconnect, retain LLGR-stale routes across consecutive resets until that
  timer expires, and represent/sweep deadlines per AFI/SAFI. Prove mixed LLSTs
  and reconnect-before-expiry across all supported families.
- [x] **Linux dataplane foreign-state ownership.** Preflight exact-key foreign
  routes, neighbors, and FDB rows before any `replace`; relinquish cached L2/L3
  ownership when a live snapshot shows a foreign replacement; revalidate
  ownership before withdrawal, NotReady, or shutdown deletion. Pin same-key
  foreign-state survival in in-memory and privileged netns tests.
- [x] **Failed `.rpol` reload consistency.** Do not publish the candidate rpol
  registry as the runtime snapshot when `SyncRpolPolicies` rolls back or
  rejects; keep existing and newly created sessions on one registry and retain
  the failed candidate only as desired/config-file intent.

**Correctness tranche 2 — bounded follow-through:**

- [x] **BFD receive and coupling bounds.** Cap socket packets/work per actor
  turn so timers and shutdown cannot starve; bound or coalesce the state-change
  channel; publish coupling-level changes when remote `AdminDown` changes even
  if the local BFD state remains `Down`.
- [x] **Reload and listener truth.** Classify and pin `[security.grpc]`,
  `[event_history]`, and `[managed_netdevs]` restart-only edits; bound the two
  remaining PeerManager-to-RIB reply waits; make BGP bind failure visible in
  readiness or fatal; turn readiness red and stop mutating/BGP admission at the
  beginning of coordinated shutdown.
- [x] **EVPN mobility wrap policy.** Implement an RFC 7432-compliant policy for
  a received MAC Mobility sequence of `u32::MAX` in MAC-only and MAC+IP
  origination. Do not substitute unchecked or naive `wrapping_add`; pin all
  first-learn and contender-update cases.
- [x] **RIB/API bounded reads.** Move filtering/pagination into bounded,
  resumable RIB actor queries with cancellation; stop `rbgp best`, `received`,
  and `advertised` from silently truncating at 100 rows; skip canceled MRT
  requests before snapshot/encoding/file creation.
- [x] **FlowSpec policy context.** Represent a legal FlowSpec rule without a
  destination-prefix component as `prefix = None`, never fabricated IPv4
  `0.0.0.0/0`, and prove IPv4/IPv6 import/export policy behavior.
- [x] **BMP connection-generation synchronization.** Fence/cancel stale dump
  tasks on collector reconnect and serialize initial Loc-RIB dump versus live
  changes so an older dump announcement cannot follow a newer withdrawal.

**Contained hardening and design follow-ups:**

- [x] Bound rpol `apply()` DAG depth, expansion, and evaluation work; remove the
  unconditional policy-name allocation from the non-attributed hot path.
- [x] Make managed-netdev partial creation converge: roll back known in-process
  pre-stamp failures, retry safely stamped incomplete bindings, and prune stale
  managed/NHG permanent-suppression entries after intent withdrawal.
- [x] Make Type-1/2/4 EVPN origination acknowledgement-aware, with explicit
  desired/pending/confirmed state and idempotent retry. Separately bound
  unmatched pending IP bindings; design a safe-forget contract before pruning
  MAC-mobility ratchet history.
- [x] Define NHID ownership authority. Numeric ranges plus `NHA_FDB` are not
  kernel-enforced proof against arbitrary co-resident writers; either document
  and validate a single-writer reserved-range deployment contract or stamp and
  verify `nh_protocol` with a fail-closed fallback.
- [x] Correct Extended Message directionality and custom-limit encoding for
  NOTIFICATION/ROUTE-REFRESH; rustbgpd's advertised capability controls inbound
  acceptance, while the peer's capability controls outbound size.
- [x] Add CI compilation for transport `bench-internals`; make fuzz target
  discovery fail on errors/zero targets and align public PR-smoke claims with
  the actual workflow.

The hosted-runner VRF/TCP-AO **skip-with-notice** behavior remains an accepted,
documented availability contract, not an audit defect. A green conditional job
does not claim a skipped receipt ran; coverage resumes automatically when the
host capability is available.

### Recently shipped (2026-07-01/03, condensed — details in CHANGELOG/ADRs)

- **Export-side explain completion (the GoBGP-demand item)** —
  `ExplainAdvertisedRoute` / `rbgp rib advertised <peer> --explain` now
  answers "why did/didn't route X go to peer Y" with the full export
  gate ladder in live evaluation order (split horizon, RFC 4456
  reflection, family, RFC 9494 LLGR, RFC 5291 ORF + initial-ORF gate,
  export policy with `.rpol` per-term labels, Adj-RIB-Out
  staged-vs-in-sync diff), plus a `--rd` VPN form adding the RFC 4684
  RT-membership gate. Truthful by construction: a read-only dry run of
  the same staging body live export executes (`ExportTarget::Explain`),
  update-grouped peers included (grouped-vs-ungrouped verdict equality
  is test-pinned); explain never skews policy counters. Later exports
  on the wire via the BMPv4 path-marking TLV.

- **The BMP arc (ADR-0097, #660–#665 + M81)** — the full monitoring
  trio on one exporter with per-collector view selection: RFC 8671
  post-policy Adj-RIB-Out tapped at the transport byte funnel
  (byte-exact wire PDUs, O+L flags, stats 15/17) and RFC 9069 Loc-RIB
  synthesized at the recompute seams (peer type 3 instance peer,
  fabricated OPEN, `"global"` table name) with a chunked non-blocking
  collector-connect table dump + per-family EoR — **no other
  open-source daemon ships the trio**. Plus the first router-side
  BMPv4 implementation: per-collector `version = 3|4` (default 3,
  v3 byte-identical, all draft code points in one module for the
  pre-IANA renumber) and the Path Marking TLV on Loc-RIB (Best/Stale
  bits only, reason re-derived best-vs-runner-up from the explain
  ladder, unmappable reasons omitted). M81 proves it against pmacct +
  gobmp + tshark at once, with v4 code points byte-pinned against the
  drafts' wire figures (no shipped collector decodes tlv-20 yet — two
  pmacct upstream findings recorded). Deferred: REL (zero collectors
  decode it), BMPv4 optional TLVs, path-marking statistics,
  Nonselected/Add-Path marking.
- **The `.rpol` typed compiled policy language (ADR-0096, #654–#658 +
  M80)** — public typed IR with indexed match sets behind the unchanged
  engine (set-heavy matching ~270× faster; golden decision-parity corpus
  vs the legacy walker), the `.rpol` frontend (named prefix/community
  sets, parameterized policies monomorphized at load, `apply()`
  composition, in-language `test` blocks, ariadne diagnostics), daemon
  integration (`[policy] rpol_files`, mixed TOML/rpol chains, SIGHUP
  hot-apply scoped to peers whose resolved chains changed), and the
  explain surfaces (per-term traces in `policy explain`, the
  `rbgp policy test` live-RIB dry run, `rbgp policy stats` live per-term
  hit counters). M80 proves route-for-route parity against FRR
  route-maps expressing the same intent, plus refresh-scoping on an
  `.rpol` edit under traffic. The import-side `GetPolicyStats` /
  `rbgp policy stats --direction import|both` read shipped in #761 with
  session-local install generations; its fleet collection now shares one
  500 ms deadline and fails without partial rows (#1205).
- **Optimal Route Reflection (RFC 9107)** — per-client best paths
  via SPF over the BGP-LS-sourced topology; typed topology accessors, graph +
  hand-rolled Dijkstra + NH-cost resolution, `orr_vantage` config, the
  interior-cost tiebreak at RFC 4271's step-(e) slot, `rbgp topology`/`rbgp
  orr`. The SPF graph is default-topology-only: non-default/malformed inputs
  are isolated before graph insertion, with aggregate API/CLI/metric/explain
  diagnostics; Flex-Algorithm data is inert. M76 proves live divergent bests,
  topology-driven flips with zero churn to unaffected clients, and clean
  fallback. **No other open-source BGP daemon ships ORR.** The M76 lab also
  surfaced and fixed a latent
  negotiation bug: implicit IPv4 unicast was added against explicit MP
  capability sets, leaking classic NLRI onto linkstate/VPN/RTC-only
  sessions (#632; capability-less-legacy-peers-only now).
- **RT-Constrain (RFC 4684)** and **VPNv4/v6 route-reflection (RFC
  4364/4659)** — see the address-family arc below and the ADR-0077
  amendment (M74/M75 receipts; strict per-peer VPN filtering; the M75 lab
  caught the missing-AS_PATH default-origination bug pre-CI).

- **Config transaction coverage + OpenConfig bridge** *(complete —
  ADR-0076).* Native gRPC now has validate-only planning,
  optimistic snapshot tokens, commit/apply/confirm/abort/status, persistence
  acknowledgement, and rollback for the v1 committable families. **Done:**
  established dynamic peers now keep the canonical longest-prefix-match range
  that accepted them, pure dynamic-range policy moves now reuse the
  resolved-policy live executor with Route Refresh gating and captured rollback
  state, and static peer-group/session reshapes now rebuild affected sessions
  with captured prior configs. **Done:** the gNMI `Set` bridge now maps
  supported OpenConfig changes into candidate TOML and feeds this transaction
  model rather than inventing a parallel commit primitive; it provides redacted
  audit summaries, delete / replace / update normalization, response shaping,
  daemon hook wiring, and a first static numbered BGP neighbor subset for
  `neighbor-address` / `peer-as` / `description` / `peer-group`; the standard
  gNMI commit-confirmed extension now maps `commit` / `confirm` / `cancel`
  onto ADR-0076's confirmed transaction lifecycle. **Done:** peer-group object
  Set can now create/update/delete native peer-group catalog entries for the
  OpenConfig leaves with exact rustbgpd mappings (`peer-group-name`,
  `auth-password`, `remove-private-as`, and `timers/config/hold-time`); leaves
  without a native inherited model stay `UNIMPLEMENTED`. **Done:**
  dynamic-neighbor prefix Set maps OpenConfig `prefix` + `peer-group` ranges to
  native `[[dynamic_neighbors]]` with `remote_asn = 0` and native validation
  gates. M54 now proves the supported Set and commit-confirmed flows with
  `gnmic` over mTLS. Exit: atomic commit
  where supported, explicit restart-required/rejected surfaces,
  rollback/receipt model, no partial silent drift. Gated by ADR-0064 tier authz.
- **Operational proof / scale automation** *(parallel priority, small slices).*
  Re-stand the proof loop that makes the v0.x posture credible: a continuous
  churn/soak shape, easy-to-trigger Criterion comparisons
  (`bench/compare-criterion.sh`), and a fixed high-N memory harness for
  regressions. **Done:** the EVPN single-active failover + ES
  drain/undrain soak shape now exists as the M67 link-driven drain churn
  harness under `tests/soak/`: it repeats the real carrier-loss trigger and
  analyzes route withdrawal/return, DF-role gauges, drain reasons, AC-gate
  state, blackout/release timing, restart counters, and RSS. Its archived 24 h
  receipt is
  [docs/soaks/soak-m67-link-drain-24h-evpn-leak.md](../soaks/soak-m67-link-drain-24h-evpn-leak.md)
  — 960 link-drain failover cycles under live MAC-mobility churn, all six RSS
  gates flat, blackout max 300 ms. **Done:** bounded
  `bgp_config_transaction_lifecycle_total{operation,outcome}` exposes confirmed
  transaction confirm / abort / auto-revert failures without unbounded labels
  (`confirm_id`, candidate content, and error text stay out of Prometheus).
  **Done:** the ignored high-N RIB structural memory profile now emits
  machine-readable rows for Adj-RIB-In, Full-RIB, and RR/route-server fanout
  shapes at 100k/500k/900k prefixes, and `bench/compare-rib-memory.sh` produces
  A/B CSV + Markdown receipts under the shared bench/soak host mutex.
  **Done:** `docs/OPERATIONAL_PROOF.md` now consolidates CI interop, hosted
  kernel dataplane, benchmark, high-N memory, and archived 24 h soak receipts
  into one operator-facing proof index. The precommitted soak acceptance
  gates
  ([docs/soaks/soak-acceptance-gates.md](../soaks/soak-acceptance-gates.md))
  named eight guarantees with no soak injection; two are now closed by the
  route-server flagship scenario 10 — the SIGHUP policy-file reload path and
  the max-prefix trip / timed-restart cycle — each proven by an archived 24 h
  receipt. RPKI cache withdrawal, the sub-minute peer flap storm, plain-path
  daemon SIGKILL, listener kill, transport-level disturbance, and BMP/BFD
  duration coverage stay explicitly deferred.
  Exit: one repeatable soak result operators can inspect, bench comparison
  receipts for perf PRs, and memory tracking that covers full-table scale
  without relying only on bgperf2.
- **MPLS / VPN / BGP-LS address-family arc** *(BGP-LS receive + reflection +
  API-export, VPNv4/v6 route-reflection, RT-Constrain, and IPv4/IPv6
  labeled-unicast route-reflection shipped — the ADR-0077 family quartet is
  complete).*
  ADR-0077 draws the address-family-expansion boundaries while the
  substrate is still small: a control-plane AFI/SAFI route-key model for
  VPNv4/v6 (RFC 4364 / RFC 4659), labeled-unicast (RFC 8277), Route Target
  Constraints (RFC 4684), and BGP-LS (RFC 9552, which obsoletes RFC 7752), with
  BGP-LS *receive/API export plus reflection* and route-reflector-only VPN/MPLS
  families as the on-identity entry points (controller-feed / RR, not a
  forwarding plane). RFC 9857 type-5 NLRI currently rides that opaque SAFI-71
  path, but typed SR Policy state remains demand-gated by ADR-0116.
  **Done:** the BGP-LS wire/RIB/API tranche accepts `linkstate` /
  `linkstate_vpn`, decodes BGP-LS and BGP-LS VPN MP_REACH/MP_UNREACH, stores
  learned topology objects in typed Adj-RIB-In / Loc-RIB tables, and exposes
  opaque NLRI/TLV bytes through `RibService.ListBgpLsRoutes` and
  `rbgp rib bgpls`. **Done:** BGP-LS routes now flow through initial table
  dumps, outbound reflection/export, route-refresh replay, and dirty
  Adj-RIB-Out resync for eligible negotiated peers; M73 proves the SAFI 71
  reflection and withdrawal path with a GoBGP 4.6.0 route source and sink. GR
  entry now conservatively withdraws BGP-LS routes and Enhanced Route Refresh
  sweeps omitted BGP-LS objects instead of reporting stale controller-feed data
  as live; BGP-LS Add-Path and BGP-LS VPN
  interop, and local topology production remain deferred.
  **Done:** the VPNv4/VPNv6 (AFI 1/2, SAFI 128) route-reflector slice shipped
  end-to-end as four stacked tranches: typed RIB substrate (RD + prefix route
  key with the MPLS label stack as route data, Add-Path path-id reserved),
  receive + read-only API (`l3vpn_ipv4_unicast` / `l3vpn_ipv6_unicast`
  families, `RibService.ListVpnRoutes`, `rbgp rib vpn`, RFC 8277 §2.4
  withdraw-mode compatibility-field codec, RFC 4364/4659 RD-prefixed
  next-hops incl. the 48-byte link-local form), RFC 4456 reflection with RD /
  label-stack / next-hop / Route-Target preservation (same-peer relabels
  re-advertise; every ineligibility branch withdraws), and the Enhanced Route
  Refresh stale lifecycle (BoRR/EoRR sweep, family-isolated, intern-GC-safe).
  GR entry conservatively withdraws SAFI-128 routes (no stale preservation);
  Add-Path and next-hop rewriting stay rejected/inert per ADR-0077 §6. M74
  proves VPNv4 and VPNv6 reflection on shared RDs, family+peer-scoped API and
  sink identity, same-path RFC 4456 attributes, family-isolated withdrawals,
  and no dataplane install with a GoBGP source and sink.
  **Done:** RT-Constrain (RFC 4684, AFI 1 / SAFI 132) shipped as the VPN RR
  scalability companion: RTC NLRI codec with RFC-faithful 96-bit prefix
  matching (GoBGP-divergence documented in the ADR-0077 amendment), full
  receive/reflect/API slice (`rtc` family, `ListRtcRoutes`, `rbgp rib rtc`),
  self-originated default membership, and strict per-peer VPN reflection
  filtering with RFC-minimal announce/withdraw deltas on membership change —
  driven through the same dirty-restage machinery as export-policy
  replacement. Enhanced Route Refresh sweeps re-derive membership and restage
  VPN. Deferred (ADR-0077 amendment): §3.2(ii) non-client attribute-swap, §6
  60s EoR delay, eBGP RTC subtleties, RTC×ORF, Add-Path. M75 proves strict
  filtering, widen/narrow-without-reset, RTC reflection, and the unfiltered
  non-RTC-peer path against GoBGP.
  **Done:** IPv4/IPv6 labeled-unicast (RFC 8277, AFI 1/2, SAFI 4) closed the
  quartet as one complete slice: typed RIB substrate + announce/withdraw
  codec (the §2.4 withdraw-compatibility field on transmit, label-stack
  withdraws survived on receive), receive/reflect with label stack and
  next-hop preserved verbatim, GR/LLGR stale preservation, ORR, Add-Path,
  `ipv4_labeled_unicast` / `ipv6_labeled_unicast` families,
  `RibService.ListLabeledRoutes`, and `rbgp rib labeled`. M79 proves
  reflection (incl. a multi-label stack and a v6 next-hop over the v4
  session), relabel implicit replace, multi-label withdraw with zero session
  flap, the GR window + EoR sweep, and no dataplane install against GoBGP.
  **Explicit non-goal, stated up front: rustbgpd does not install MPLS labels
  in the dataplane** — these are BGP-carried families, not a step toward a full
  MPLS router (see Non-goals). The ADR also preserves the ORF Address-Prefix
  guard: only IPv4/IPv6 unicast entries are parsed today, and future
  VPN/MPLS-family ORF support must be family-specific. Follow-up substrate work
  must either remain unreachable from peers/operators or ship a complete typed
  family slice; constant-only negotiation or config-only "support" is
  explicitly out of scope.

## Completed engineering velocity / tech debt

- [x] **Compatibility-debt removal schedule (ADR-0122, Accepted).**
  [docs/adr/0122-compatibility-debt-inventory.md](../adr/0122-compatibility-debt-inventory.md)
  is the single inventory of retained compat shims under the alpha
  posture, grouped by surface with per-item removal releases and
  mechanics. The remove-now items — the two v0.51.0 retired-key
  migration pointers and the redundant example-config UDS authorization
  ceremony made unnecessary by #1429 — landed in v0.63.0 (#1435).
  The frozen legacy commit-confirm/history readers and v2 authority reader
  and the dead `enforcement = "legacy"` enum variant were removed during v0.65
  development. The `rbgp rib diff` older-daemon fallbacks and
  `AddNeighborRequest.config` were also removed during v0.65 development. The three hidden
  `--from-file` aliases on `config diff|plan|apply` and the raw Paths-Limit cap
  were removed during v0.65 development. Unary
  Plan/Apply is retained permanently as the small-candidate path; streaming
  remains additive and outside the initial v1 freeze. `RouteEvent.event_id`
  is also retained: it is the sole process-local, restart-reset cursor on bare
  route-event surfaces and drives `rbgp events watch --backfill` history/live
  dedup; only durable `SubscribeFromEvent` makes `BgpEvent.event_id`
  authoritative. New
  compat retentions add a row to the ADR in the PR that introduces them.

- [x] **Legacy GR/LLGR RFC gaps in unicast/FlowSpec/EVPN — RESOLVED.**
  The RR families (VPN/BGP-LS/RTC, #636–#638) implement the strict
  semantics; the pre-existing paths had three documented divergences,
  all now closed: (1) consecutive-restart deletes already-stale routes
  instead of re-marking them in place (RFC 4724 §4.1); (2) the EoR arms
  sweep non-readvertised stale/LLGR-stale routes before clearing flags
  on the re-advertised remainder (RFC 4724 §4.1 / RFC 9494 §4.2) —
  including the re-establish-during-LLGR path, all families; and
  (3) the RFC 9494 §4.4 LLGR-stale export restriction, repo-wide: every
  family's Adj-RIB-Out staging suppresses (withdraw-if-present)
  LLGR-stale routes toward eBGP peers that didn't advertise the LLGR
  capability for the family (receiver capabilities plumbed from session
  negotiation via `PeerUp`), while non-LLGR iBGP peers take the §4.6
  intra-AS exception — NO_EXPORT attached and LOCAL_PREF zeroed in
  transport's per-peer attribute rewrite, LLGR_STALE community riding
  unchanged.

- [x] **EVPN origination cross-actor seam audit — RESOLVED** (2026-06-12,
  PR #477). The seam inventory (drain vs. replay, withdrawal ordering,
  drained-set GC, bias/AC-gate coherence, DF-flip fanout, startup
  first-probe, apply-lock serialization, two-actor rollback) is enumerated
  in the PR and each holding invariant is pinned at the coordinator level:
  `evpn_es_drain.rs` (drain/undrain through the primitive against BOTH real
  actors with exact-replay assertions, reverse-publish-order convergence,
  apply-lock serialization, originator-failure rollback),
  `evpn_segment.rs` (GC'd re-added ESI starts undrained, exhaustive
  bias-eligibility ⇒ gate-not-Blocked matrix, DF flip republishing bias +
  AC gate together), `evpn_es_link_drain.rs` (down-at-boot convergence of
  drain state + bias + gate against a real segment actor), and
  `evpn_runtime_converger.rs` (an unrelated L2VNI add preserves an
  operator drain on every actor). Known bounded transients, by design and
  documented at the seams: the segment actor's first bias/gate publish does
  not wait for the carrier monitor's first probe (a bound dead-AC ES is
  bias-eligible for one fanout chain at boot; M67 measured the whole drain
  chain at 100-300 ms), and the two dataplane snapshots ride separate watch
  channels (one supervisor wake of skew). Single-ownership consolidation
  evaluated and not justified — see the PR's proposal section.
- [x] **Drain-GC split-state on a failed ES-delete apply — RESOLVED**
  (2026-06-12). `publish_ethernet_segment_runtime_snapshot` /
  `converge_tenant_teardown` GC'd the coordinator's drain entries BEFORE
  the actor publishes; on a mid-converge publish failure the rollback
  (per ADR-0084, deliberately) did not restore the GC'd entry — and the
  segment actor's drained-set mirror was never updated either, so the ES
  stayed withdrawn while the coordinator (gauge, RPC reasons) reported it
  undrained, and an operator undrain was an idempotent no-op. Fixed with
  GC-after-success: both paths now GC + push the GC'd set only after the
  last fallible actor publish succeeded, so a failed converge leaves the
  entry intact on both sides (still drained, still agreeing) and there is
  nothing for the rollback to restore — ADR-0084's no-restore stance is
  preserved by construction. Invariant pinned at the converger level
  (failed publish ⇒ coordinator state + actor mirror agree, and a
  subsequent undrain fans out) for both the ES-delete and tenant-teardown
  paths; the ADR-0084 annotation is updated to resolved.
- [x] **Poll-cadence tail sweep.** The dataplane intent recompute went
  event-driven with the 5 s poll demoted to a backstop, and segment
  re-election subscribes to the EVPN event broadcast with a 10 s backstop
  tick. The sweep found the originator RIB repoll already converted (RIB
  broadcast + local-MAC netlink observations; its 5 s tick is the backstop
  plus the duplicate-MAC quarantine recovery sweep, whose ≤5 s tail on a
  minutes-long quarantine window isn't worth a deadline timer) and the
  reconcile actor already event-driven for intent and custom-table route
  changes — what was missing was kernel-side drift eventing: programmed
  remote-MAC rows flushed off a managed VXLAN port and bridge-port
  flag/state drift (BUM-filter / AC-gate surface) repaired only on the
  60 s periodic dump. **Converted:** the notify task now wakes the
  reconcile actor on `AF_BRIDGE` FDB deletes on managed VXLAN ports and on
  classified `RTNLGRP_LINK` events (port flags/state, VXLAN/managed-bridge
  topology, enslavement), repairing within the 50 ms coalesce window; the
  periodic dump stays as the backstop. **Stays on cadence, deliberately:**
  BMP statistics (RFC 7854 interval reporting), BFD protocol timers, MRT
  dump rotation, and the retained backstop ticks themselves. **Follow-up
  (done):** the FIB runtime and blackhole reconcilers bounded *kernel*-side
  drift at 30 s — RIB-side changes were already event-driven — and now
  subscribe their own NETLINK_ROUTE connections to `RTNLGRP_IPV4/6_ROUTE`
  (`src/kernel_route_notify.rs`), surfaced through the `UnicastFib` /
  `BlackholeFib` seams: a delete of an owned-signature row (`proto bgp` in
  a configured table identity / the ADR-0079 blackhole marker in `main`)
  or a foreign replace on an owned identity wakes a coalesced reconcile
  (200 ms debounce, shared with the RIB-event path); install echoes and
  unrelated host churn stay silent, and the 30 s pass remains the
  backstop.

- [x] **Doc-collision discipline for `ROADMAP.md` / `CHANGELOG.md` /
  `docs/evpn-alpha-soak.md` / `docs/evpn-enablement.md`.** Multi-PR batches keep
  conflicting on the same handful of rows. The lightweight convention is now
  documented in `CONTRIBUTING.md`, prompted in the PR template, and checked in
  `docs/RELEASE_CHECKLIST.md`: append `[Unreleased]` entries within their
  subsection, keep one roadmap row per concern, and update exact tracking-doc
  gates instead of rewriting unrelated summary prose. A generated manifest stays
  deferred unless this process guidance fails to reduce drift.
- [x] **Test fixture extraction into a shared `test-support` surface.** Helpers
  like `route_event`, `session_event`, `policy_event`, `lifecycle_event`, and
  the per-test config builders had drifted across `crates/api`, `crates/cli`,
  `crates/rib`, and `src/`; a field addition (e.g. `event_id`) forced touching
  three or four copies. Resolved as private per-crate `#[cfg(test)]
  test_support` modules (a shared `rustbgpd-test-support` crate was rejected —
  it would force `pub` visibility and dependency edges). `crates/api` covers
  the service-test `PeerInfo`/metrics/event-stream fixtures and fake harnesses;
  `crates/cli` already shared its mock-server fixtures; `crates/rib` now
  centralizes the `Route` / `FlowSpecRoute` unit-test constructors; the daemon
  bin centralizes the EVPN (`vni`/`rd`/`mac`/instance) and FIB
  (table/key/route/route-event) builders. Deliberately left local: bench and
  integration-test helpers (separate compilation units — sharing would require
  new public surface) and intentionally divergent fixtures (the blackhole
  community-route builder, the EVPN MAC/IP route family, per-module
  minimal-config TOML snippets).
- [x] **`unwrap()` audit on daemon-runtime paths.** Effectively resolved
  (2026-07-17 re-measure): real daemon-runtime `.unwrap()` outside test
  modules is now ~0 — the two remaining non-test sites are an ADR spike
  prototype (`docs/adr/0103-rpol-execution-model-spike/`) and a `pub`
  test-fake dataplane used only by test harnesses (`crates/evpn-linux/src/
  in_memory.rs`), neither on a daemon-runtime path. The prior startup /
  poisoned-lock / defensive-parse sites, prefix-map conversions, BFD socket
  and timer-pop sites, and EVPN nexthop encode conversions were all cleaned
  up. Keep the discipline as a forcing function for future invariants.
- [x] **`panic!` → typed-error sweep on the one production site.**
  `crates/bfd/src/discriminator.rs` now returns a typed discriminator-exhaustion
  error instead of panicking. The daemon logs and refuses to install the new BFD
  session if the 32-bit non-zero discriminator space is ever exhausted.
- [x] **Stringly command errors → typed errors where API status depends on
  class.** PR #334 introduced `DynamicRangeError` so
  `AddDynamicNeighbor` / `DeleteDynamicNeighbor` can map duplicate, not-found,
  and invalid-input failures to stable gRPC status codes without parsing error
  strings. ADR-0076 transaction planning uses a typed stale-snapshot /
  invalid-candidate error for gRPC status mapping. Static-peer
  lifecycle/admin replies and policy/catalog replies (policy definitions,
  neighbor sets, peer groups, global named chains, and per-neighbor
  policy/peer-group membership) now also use typed errors where callers need
  status-class distinctions. The transport
  peer-session command ACK surface (`SendRouteRefresh`, live import/export
  policy updates, and graceful-shutdown toggles) now uses typed errors while
  preserving the existing peer-manager operator text. Remaining
  `Result<_, String>` replies are intentional one-status or internal-
  orchestration surfaces; keep them until a caller needs multiple API-visible
  status classes.
- [x] **RTR encode length conversions → checked typed errors.** The
  clippy-reason ratchet documented a few pre-existing RTR encode-path casts
  from `usize` to `u32`. They are not peer-reachable today — the encoder is fed
  rustbgpd-controlled/bounded records — but converting them to checked
  conversions with typed encode errors removes the remaining theoretical
  silent-truncation edge and makes the documented invariant executable.
- [x] **Catalog mutator persistence + lock convergence** *(from the 2026-06
  deep audit — shipped).* All 16 policy/peer-group gRPC mutators now follow
  the `AddNeighbor`/FIB-CRUD/`ApplyConfigTransaction` contract: detached-task
  shield, runtime-config coordinator lock with the mutation gate checked
  inside it, acked persist before lock release, and capture-prior runtime
  rollback on persist failure (peer-group rollback restores the unredacted
  stored secret). Confirmed-transaction abort/auto-revert also now treat a
  non-committable rollback re-apply as a rollback failure instead of
  reporting success.
- [x] **`SetPolicy` fan-out atomicity** *(remaining slice of the catalog
  convergence item).* The peer manager's direct `SetPolicy` apply fanned out
  per-peer runtime-policy updates in a loop; a mid-loop failure left
  already-updated peers on the new chains while later peers kept the old
  ones. The catalog fan-out (`apply_policy_change`, shared by all 12 policy
  / neighbor-set / chain mutators) now resolves every affected peer's chains
  first, then commits the set through the resolved-policy-snapshot primitive
  (`ApplyResolvedPolicySnapshot`, the live-impact transaction executor's
  capturing mechanism): a mid-fanout failure restores the already-updated
  peers to their captured priors and `current_config` does not advance.
  Peer-group reshapes (session teardown/rebuild) remain a separate deferral.
- [x] **Config transaction live-impact policy / peer-group executor.**
  Policy definitions, `neighbor_sets`, `peer_groups`, and global named
  policy-chain edits that move existing static neighbors' or accepted dynamic
  peers' resolved import/export policy chains now commit as transactions: stage
  the candidate snapshot, re-apply resolved chains to affected live sessions
  with captured priors, persist with ack, and restore live chains plus the
  snapshot on failure.
- [x] **Config transaction peer-group/session reshape executor.**
  Peer-group field edits and static-neighbor peer-group reassignments that
  reshape existing static sessions now commit as transactions: stage the
  candidate snapshot, reconfigure affected peers with captured prior configs,
  persist with ack, and restore live peers plus the snapshot on failure.
  Dynamic-range session reshapes shipped in v0.39.0 (ADR-0086): after a
  successful persist, the executor gracefully resets the live dynamic sessions
  accepted by an affected range (Cease + RFC 8203 shutdown communication);
  each remote's reconnect is re-accepted under the committed config and the
  accept-slot accounting stays owned by the normal `BackToIdle` reaping.
  Dynamic-range peer-group *reassignments* stay outside the reshape family (a
  `[[dynamic_neighbors]]` record edit; sessions accepted under the old group
  cannot be live-reassigned).
- [x] **Config transaction commit-confirmed core.**
  `ApplyConfigTransaction` can now enter a singleton pending-confirm state with
  `confirm_id` and a bounded confirm timer. Confirm makes the change permanent;
  abort or timer expiry rolls back by applying the captured pre-commit runtime
  snapshot through the same transaction executor. Persisted runtime config
  mutators are fenced while a confirmed transaction is applying or pending.
- [x] **Persisted runtime-config settlement watchdog (ADR-0127).**
  Every transaction, SIGHUP, Neighbor4, FIB2, PeerGroup4, and Policy12 owner has
  one typed phase-aware settlement record, bounded telemetry, and an independent
  30-minute-plus-five-second exit-70 fail-stop. Repeated real-daemon recovery
  proofs cover client detach, queued-owner rejection, persistence authority,
  commit-confirm restart, and supervised shutdown.
- [x] **`rbgp` commit-confirmed workflow.**
  The CLI can now run safe deploys end to end: `config apply --confirm-id
  --confirm-timeout`, `config status`, `config confirm`, and `config abort`
  expose the confirmed transaction lifecycle with text and JSON output.
- [x] **Config transaction catalog snapshot executor.** ADR-0076 can now commit
  catalog-only policy definitions, policy `neighbor_sets`, `peer_groups`, and
  global named policy-chain assignments under the same
  reserve/stage/persist-ack/rollback ordering used by full-snapshot
  dynamic-neighbor transactions, while routing pure resolved-policy impact to
  the live-policy executor and rejecting broader inheritance/session impact.
- [x] **Config transaction static-neighbor resolution scaling.**
  Static-neighbor add/modify transactions now resolve only the touched
  `[[neighbors]]` entries through the same single-neighbor inheritance path,
  instead of resolving the full candidate neighbor set and then selecting the
  added or changed peers.
- [x] **Peer-manager add-without-start path for disabled reconfigure.**
  Static-neighbor modify, SIGHUP changed-peer reconcile, and peer-group
  hot-apply now rebuild a disabled peer as disabled, without transient session
  start. Enabled peers still start immediately unless strict BFD withholds them.
- [x] **SIGHUP baseline from live runtime snapshot.** SIGHUP now reads the peer
  manager's current runtime snapshot after taking the runtime-config coordinator
  lock, so a reload queued behind a committed transaction starts from the
  transaction-updated baseline instead of main.rs' stale process-local copy.
- [x] **SIGHUP reconcile for `[[dynamic_neighbors]]` TOML edits (#338).**
  `ReplaceConfigSnapshot` rebuilds the live accept matcher, `--diff` classifies
  direct TOML edits as reload-applied, and runtime dynamic-neighbor CRUD shares
  the runtime-config coordinator lock with SIGHUP through config-persistence
  acknowledgement. Persistence rejection rolls the runtime matcher back instead
  of letting it drift ahead of disk.
- [x] **Static neighbor CRUD persistence/SIGHUP serialization.**
  `AddNeighbor` / `DeleteNeighbor` now share the runtime-config coordinator
  lock with SIGHUP through config-persistence acknowledgement. Persistence
  rejection rolls the accepted runtime mutation back, completing the same
  lock/ack/rollback invariant used by FIB-table and dynamic-neighbor CRUD.
- [x] **`clippy::too_many_lines` suppressions are `expect`, not `allow`.**
  Across the production source trees the clippy-reason ratchet covers, every
  suppression of this lint is now `#[expect(...)]` and none is
  `#[allow(...)]`. That is the half that matters for rot: an `expect` fails
  the build the moment the lint stops firing, so a suppression that outlives
  the function it was written for reports itself, while an `allow` goes
  stale in silence. Three `#[allow(clippy::too_many_lines)]` remain outside
  that fence by design — `bench/scale/reloadstall` and
  `bench/scale/rrharness` (standalone harness crates, not workspace members)
  and `tests/config_persistence_lifecycle.rs` (an integration-test target,
  which the production-source contract deliberately excludes).
- [x] **`#[allow(clippy::result_large_err)]` audit.** The 2026-07-17 inventory
  found 15 suppressions spread across six files. Fourteen stale API suppressions
  have since been removed: tonic 0.14's `Status` is an 8-byte handle to an
  already-boxed inner value, so those sites no longer return a large error. The
  one event-history suppression is intentionally retained: its public
  `TrySendError<EventEnvelope>` preserves ownership of the rejected event
  without adding an overload-path allocation. The evidence did not justify
  changing that API or introducing a shared boxed-error abstraction.
- [x] **CI gate: `#[allow(clippy::*)]` / `#[expect(clippy::*)]` requires
  `reason = "..."`.** The original ratchet covered 14 statically named crate
  source trees. It now derives every production workspace source root from
  Cargo metadata, including the daemon, crates, tools, and workspace benchmark
  packages as they are added; test, bench, and example targets remain
  deliberately outside this production-source contract. CI runs both the
  checker and mutation tests that prove an unreasoned suppression in a newly
  added workspace package fails without another maintained path list.
- [x] **`cargo deny` for license / dependency / advisory audit.** Done: the
  dependabot + cargo-audit half of the stale branch had already landed;
  `deny.toml` now gates `cargo deny check advisories bans licenses sources`
  (permissive-license allowlist, path-wildcard exemption for the deliberately
  unversioned `rustbgpd-wire` path dep, duplicate-version warnings kept
  visible but non-blocking) and runs as a second job in
  `.github/workflows/audit.yml` alongside `cargo audit`. The two ignore lists
  deliberately differ: cargo-deny warns (not fails) on unsound-class
  advisories, so only the unmaintained `paste` entry needs a deny.toml
  ignore while `.cargo/audit.toml` also carries the rand unsoundness entry.
- [x] **Upgrade the released rtnetlink pair.** Done: rustbgpd now uses
  `rtnetlink 0.22.0` with its coherent `netlink-packet-route 0.32.1` dependency,
  with one resolved copy of each crate and no git patch or compatibility shim.
  The obsolete Dependabot ignore for `netlink-packet-route >= 0.31` is removed.
  Upstream release-preparation PR rust-netlink/rtnetlink#173 was closed unmerged
  after the maintainer published 0.22.0 directly, so the old intermediate proof
  PR #538 was closed rather than revived. Validation on the released crates
  covers locked workspace check/test/Clippy, strict `rustbgpd-evpn-linux`
  rustdoc, no-default/all-feature builds, and the privileged FDB-NHG,
  FIB-runtime, BFD-runtime, VLAN-aware FDB,
  MAC+IP/VLAN attribution, SVD FDB/VNI, managed SVD VXLAN, and managed IP-VRF
  netns selectors. The raw `NDA_NH_ID`, `RT_TABLE_COMPAT`, and nested
  `IFLA_PROTINFO` escape hatches remain because 0.32.1 still does not expose the
  required typed kernel encodings. LAN-643 records the completion; closed
  Dependabot PR #452 remains the historical duplicate-version proof.
- [x] **Coordinate the next netlink-family upgrade.** Done: LAN-1159 moves the
  workspace coherently to `rtnetlink 0.23`, `netlink-packet-route 0.33`,
  `netlink-packet-core 0.9`, `netlink-sys 0.9`, and transitive
  `netlink-proto 0.13`, removes the obsolete direct `netlink-packet-utils`
  dependency, and groups future Dependabot netlink updates. Runtime behavior
  and the raw `NDA_NH_ID`, `RT_TABLE_COMPAT`, and nested `IFLA_PROTINFO`
  escape hatches are unchanged because the released family still has no typed
  nexthop API. Locked workspace validation and the privileged netns selector
  suite provide the upgrade proof.
- [x] **Workspace `cargo doc` warning posture.** `.github/workflows/ci.yml` runs
  `cargo doc --workspace --lib --no-deps` with
  `RUSTDOCFLAGS="-D warnings"`; keep that as the standing local pre-flight
  expectation so broken intra-doc links surface on the developer machine rather
  than at PR time. `--lib` keeps the root daemon bin out of the doc target set
  (avoiding the lib/bin same-name collision); Cargo's default job parallelism is
  intentionally left enabled so rustdoc does not serialize the whole workspace.
- **Mega-module posture.** Prior concern and test-module extraction waves are
  complete (inventory refresh: #1552). Further splits are not planned; revisit
  only when measured conflict frequency or review cost demonstrates demand.
- [x] **Doc-precision + lint-policy consistency sweep (v0.41.0 review).** A
  whole-codebase review found no correctness or security defects; the residue was
  documentation/policy drift, all low-risk. The documentation and lint-policy
  sub-items are closed:
  - ARCHITECTURE.md design-invariant #3 re-enumerates the intentional
    unbounded-channel set (collision notifications, the transport writer's priority channel, BFD
    state-change fan-out), so the invariant reads as a usable review gate.
  - The ARCHITECTURE.md ownership table is trued up against the actors at HEAD:
    the BLACKHOLE reconciler, EVPN runtime converger, EVPN dataplane supervisor,
    BMP manager, and event-history manager have rows; the FIB runtime's scope is
    stated as the configured `[[fib_tables]]` rather than all netlink route
    programming; and the EVPN originator's by-design `Arc<RwLock>` generation
    counters are noted as outside the RIB hot-path "no locks" invariant.
  - `#![deny(unsafe_code)]` is on every workspace crate root — the last four
    (`examples/event-bridge`, `examples/birdwatcher-adapter`, and both
    `tools/rs-config-render` roots) landed with this item, so CONTRIBUTING.md's
    "every crate" is now literally true.
  - SECURITY.md states the actual posture: the `crates/transport` `socket_opts`
    FFI allow, the daemon binary's `cfg_attr` gate under the `jemalloc` /
    `dhat-heap` allocator features, and the test/bench targets that carry
    justified `unsafe` outside any shipped path.
  - LAN-1162 tranche A bounds the peer-manager private command lane and the
    config-bridge replacement lane at capacity one with lossless FIFO sends.
    LAN-1162 B1 adds daemon-lifetime current/high-water depth accounting around
    `session_notify` without changing delivery semantics. LAN-1162 B2 records
    a sealed one-host 700-session/400,400-prefix, three-round flap receipt: all
    ten accounting checkpoints drained to zero and daemon-lifetime high-water
    rose from 8 to 30 with zero parse/send/correctness errors. This is dequeue
    accounting only, not a per-round peak, capacity, latency, memory, bound, or
    optimization claim. `session_notify` remains intentionally unbounded for
    the `QueryState` collision-resolution deadlock constraint.

  Dependency-hygiene note, not a work item: the lockfile resolves both
  `thiserror` 1.x and 2.x. Every first-party crate that derives with it
  declares `thiserror = "2"` via the workspace dependency; the 1.x copy is
  transitive only, pulled by `protobuf` (the `prometheus` text-format
  dependency). It clears when `protobuf` moves to
  2.x; re-check with `cargo tree -i thiserror@1` at a dependency refresh.
- [x] **Retire `rustbgpctl` in favor of `rbgp` (single CLI name).** The CLI
  crate now ships only the `rbgp` binary. The old `include!` alias/shim and
  long-form binary are removed; supported docs, package artifacts, generated
  completions, first-party scripts, and tests use `rbgp`.

Current priorities remain in [ROADMAP.md](roadmap.md).
