# Early S2 source confounders: read-only inventory

Interval: `370e211b95ec3e4a7b07556146e31dd02f391ea6` to `481e0187d873dd8e7715033224be0fe90cb7d4e2`, 26 commits. Reused the already-audited early-S2 provenance (700 peers, 400,400 IPv4 prefixes, 3 processes and 12 reloads per arm). This note does not re-estimate the 574 to 486 ms actor result or attribute its difference. No builds, tests, labs, source edits, or timestamp changes were performed.

## Clock and direct path

All source anchors below refer to endpoint `481e0187d873dd8e7715033224be0fe90cb7d4e2`. The timer boundaries and clean transition machinery are unchanged across the interval; changes in manager/mod.rs are bench-only EOR counters.

- `crates/rib/src/manager/distribution/mod.rs:663-686`: PendingCleanPolicyTransition::new starts a Tokio Instant; elapsed is wall time, including time parked/yielding, not actor CPU time and not only CommitMembers.
- `crates/rib/src/manager/mod.rs:4563-4572,4649-4652`: transition polls fence primary updates, route chunks, timers and resync; readiness/general-query service and yield boundaries remain within the clock.
- `crates/rib/src/manager/distribution/mod.rs:2208-2225`: CommitMembers commits membership and sends the reserved outbound permit, carrying shared_group_encode. Wire encoding can start concurrently; it is not synchronously awaited by the actor.
- `crates/rib/src/manager/mod.rs:4589-4598`: the committed result samples done.elapsed before done.retire_inputs; completion logging itself is at 2749-2763. The timer is not the later settlement/publication span.

## Production changes

| Full commit | Mechanism and relation to measured actor |
| --- | --- |
| `2a5b299ebcfd1659b12ff0f2df7a3aad34954d0b` | Direct changed retirement mechanism; separately measured in the default-shape ABBA. FamilyPrefixMap::retire_with batches 32 prefixes per iterator startup, preserving per-value checkpoints (`crates/rib/src/prefix_map.rs:112-130`). Call chain: CommitMembers -> commit_clean_policy_transition_member (`manager/update_groups/policy_transition.rs:488-499`) -> leave_group_without_gauge_refresh -> last member removes group (`manager/update_groups.rs:2087-2110`) -> GroupRibOut::retire_with (`:658-660`) -> AdjRibOut::retire_with (`adj_rib_out.rs:391-393`) -> prefix map retirement. This runs before the actor clock ends. Parent is `2c55425547bb1fddcb0a4bc30937f26474751020`. |
| `178371665f54f8c4168149d1207d2785174f3bce` | Possible scheduling context, not demonstrated actor overlap or measured cause. HTTP /metrics and gRPC GetMetrics change from inline gather/encode on Tokio workers to a process-serialized spawn_blocking render (`src/metrics_server.rs:200`, `crates/api/src/control_service.rs:143`, `crates/api/src/metrics_render.rs:22-38`). This changes worker availability if rendering overlaps a yielded actor. It is not called by CommitMembers. Retained scheduling evidence below sharply limits the overlap claim. |
| `0bf9f3de486eac4094767cc950ca380bd9abf401` | AttrGroupIndex avoids first pointer-map insertion for a value-group opener (`crates/transport/src/session/outbound.rs:523-588`, callers within send_route_update at :709,916-946,1019-1064). Excluded from the successful clean shared encoder: handle_outbound_route_update -> prepare_shared_group (:221-224; `shared_group.rs:472-503`) -> encode_and_send_shared_group (:519-560) -> encode_shared_unicast_slice (:302-311), which uses a separate HashMap<SharedGroupKey,usize>. A non-eligible/failed shared encoding can fall back to ordinary per-session encoding (shared_group.rs:23-38,475-501); unrelated ordinary outbound work can also run concurrently. Those are conditional indirect exposure, not evidence that this commit shortened the clean actor. |
| `17461a35abd24d46b7bca692c73d912a6d366187` | AdjRibIn::finish_gr_family combines stale sweeps/tag cleanup for active GR End-of-RIB (`adj_rib_in.rs:684`; `manager/route_refresh.rs:150-169,262-274`). No call from clean transition; EOR primary work is fenced until terminal result. Normal established SIGHUP without GR does not enter this active-GR branch. Excluded from the actor path. |
| `481e0187d873dd8e7715033224be0fe90cb7d4e2` | Ipv6Prefix Hash changes to address octets plus prefix length (`crates/wire/src/nlri.rs:162-179`). IPv4 Hash is unchanged. Excluded for retained IPv4-only S2; dual-family results would require separate treatment. Added fast_hash.rs content is tests only. |
| `326dc11218f70f75d1a9a103118682d3ab0b1a5a` | Changes only PolicyChainTooLarge's displayed error text in production (`src/config/schema.rs:3363`); accompanying policy_admin diff is a test. Valid accepted policy reloads do not construct this error. Excluded. |

No other changed production algorithm in this 26-commit interval is on the clean IPv4 transition path.

## Non-production and other-workload exclusions

- `7d088c280d3878b4571012922ff73fce6421fc5b` and `8f86cd7185e5b8cf81e7d581560cbcd577a27dbc`: GR-EOR attribution fields/timers are cfg(feature = "bench-internals") plus benchmark changes, not a release-daemon clean transition optimization.
- `2ff3f51847b1947768550d806c796069c8b3cc9f` and `ea5f19939f189166581217cff87c9336a11b9cd6`: add jemalloc to benchmark targets/rrharness and dev dependencies. They do not change the existing rustbgpd daemon allocator or reloadstall runtime source. Cargo.lock additions are dependency membership, not versions.
- `55841b34cb7c3b04ffde760c7d765a4eff638399`: tests/soak management-read scheduling; not the retained matrix/reloadstall runner.
- `e5732a81d67c293ac339c4a2b6e51a5f8ca3cf11`, `17648787d3e49816d1e512aae72af56f5f094d5a`: rebaseline CSV/DHAT receipt classification, not daemon or S2 driver code.
- `2c55425547bb1fddcb0a4bc30937f26474751020`, `01da7e69f0a2095ceba6e1dcac4a2b662b3faa35`, `b273bf82b7c2fadd401bf740feb6d659b0d05354`: archive/CI/interop tooling. `1531ca860cd91bf5a8f3c6a8e6d8ce313336c73d`: FlowSpec lab scripts/config/evidence. None changes this runtime path.
- Remaining nine commits are documentation/artifact edits: `8377e88e0dd1adde56e538522e30d6a5d61a2bed`, `202e0f1bf6f12631be7425e917988f80f3d2472c`, `9affd77dbd63f4c66b318180aa214050661e88d0`, `8c1701307b344e52d9a45f8d765453c2e27c4fd9`, `1b9b9170f84c5d1294bbd689e9a241c37a7ee9ec`, `70da47367def1c8c0a5f1fb7a177c90f3941ba2a`, `207302a8c1bede8fd192e8c50e7649c4c643b82c`, `445dad0a8d1b2b1b02a12a10fe6a3ad5a281b845`, `35ef840d84b4f3f39124d1c3d5e2ad4753f885a0`.

## Retained /metrics scheduling evidence

Sources: the retained `headline-jem-night` S2 daemon, harness and provenance files, identified by the original-file hashes in [pre2952-provenance.json](pre2952-provenance.json). Signal timestamps are the retained `SIGHUP wall_us`; commit timestamps and integer elapsed_ms are the existing daemon events. No per-request /metrics start/end timestamps or HTTP access trace is retained.

Runner `bench/scale/matrix/run-matrix.sh:543-549` starts gRPC health/query loops only when PROBE_PREFIXES is nonempty. All six retained provenance files have PROBE_PREFIXES=""; no separate gRPC probes are involved. Lines 570-576 enable HTTP settlement scraping. reloadstall's `fetch_reload_outcomes` (:501-504) uses fetch_metrics -> HTTP /metrics, not gRPC GetMetrics.

The native loop sleeps 100 ms before its first settlement scrape (`bench/scale/reloadstall/src/main.rs:4730-4743`). After that response it sets the next scrape eligibility to now + 1 s, checked on subsequent 100 ms loop ticks. Thus first request >=100 ms after signal (plus scheduling); second request >=1100 ms after signal PLUS first response duration and scheduling. Neither request has an upper-bound timestamp in these receipts. A delayed first scrape could overlap the actor, but that is not demonstrated.

The nominal first 100 ms scrape is before every inferred actor start (~508-593ms). All 12 main actor windows end before the second request's earliest 1100 ms lower bound. Five of 12 base windows also end before 1100 ms; the other seven leave at most 1.808-62.895ms between 1100 ms and the actor log, before accounting for first scrape duration/scheduling. This does NOT prove overlap on any base reload, much less all reloads. The rightmost column below is only nominal room after the earliest second-poll bound, not measured scrape overlap or attributable time.

Actor start is reconstructed as log timestamp minus integer elapsed_ms: it is approximate (millisecond truncation plus logging delay), not a sampled exact actor entry. All units below are milliseconds after the harness signal timestamp.

| Arm | Process/reload | Approx actor start | Actor commit log | Room after 1100 ms |
| --- | --- | ---: | ---: | ---: |
| base | 1/1 | 513.332 | 1093.332 | 0.000 |
| base | 1/2 | 527.808 | 1101.808 | 1.808 |
| base | 1/3 | 531.496 | 1109.496 | 9.496 |
| base | 1/4 | 508.079 | 1068.079 | 0.000 |
| base | 2/1 | 524.254 | 1098.254 | 0.000 |
| base | 2/2 | 532.154 | 1097.154 | 0.000 |
| base | 2/3 | 548.514 | 1112.514 | 12.514 |
| base | 2/4 | 511.337 | 1082.337 | 0.000 |
| base | 3/1 | 592.895 | 1162.895 | 62.895 |
| base | 3/2 | 540.057 | 1118.057 | 18.057 |
| base | 3/3 | 544.109 | 1124.109 | 24.109 |
| base | 3/4 | 534.510 | 1111.510 | 11.510 |
| main | 1/1 | 546.098 | 1031.098 | 0.000 |
| main | 1/2 | 558.413 | 1045.413 | 0.000 |
| main | 1/3 | 538.369 | 1023.369 | 0.000 |
| main | 1/4 | 547.776 | 1039.776 | 0.000 |
| main | 2/1 | 539.992 | 1028.992 | 0.000 |
| main | 2/2 | 549.952 | 1038.952 | 0.000 |
| main | 2/3 | 515.429 | 1003.429 | 0.000 |
| main | 2/4 | 550.942 | 1034.942 | 0.000 |
| main | 3/1 | 577.508 | 1062.508 | 0.000 |
| main | 3/2 | 579.752 | 1063.752 | 0.000 |
| main | 3/3 | 564.343 | 1047.343 | 0.000 |
| main | 3/4 | 532.293 | 1021.293 | 0.000 |

Interpretation: source proves one direct changed clean-transition mechanism (prefix retirement) and a possible scheduling change (metrics rendering) whose overlap is unproven. Successful shared encoding bypasses the other outbound optimization. Nothing here allocates any portion of the historical 88 ms difference or any residual to a specific commit; the separate [isolated default-shape ABBA](../../policy-transition-release-followup-2026-10-10.md#isolated-prefix-retirement-step) measures its own effect without assigning this historical interval.
