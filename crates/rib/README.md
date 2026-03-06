# rustbgpd-rib

RIB data structures and best-path selection for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Architecture

Single-task ownership — `RibManager` runs as one tokio task with no
`Arc<RwLock>`. All RIB mutations flow through an `mpsc` channel as
`RibUpdate` messages.

## Features

- **Adj-RIB-In** — per-peer inbound route storage with stale marking
  (GR/LLGR), refresh-stale tracking (Enhanced Route Refresh), and
  per-prefix Add-Path support
- **Loc-RIB** — best-path selection per RFC 4271 section 9.1.2 with
  extensions: RPKI validation (step 0.5), stale demotion (step 0),
  deterministic MED (always-compare), route reflector tiebreakers
- **Adj-RIB-Out** — per-peer outbound route tracking with split horizon,
  iBGP suppression, route reflector reflection rules
- **FlowSpec** — parallel storage for FlowSpec rules (SAFI 133)
- **Multi-path** — Add-Path multi-candidate distribution with
  rank-based path ID assignment
- **Graceful Restart** — stale route preservation, per-family EoR
  tracking, timer-based sweep, LLGR two-phase promotion

## Key types

- **`RibManager`** — event loop processing `RibUpdate` messages
- **`AdjRibIn`** — per-peer inbound route table
- **`Route`** — prefix + attributes + metadata (path_id, validation_state, stale flags)
- **`best_path_cmp()`** — standalone comparison function (not `Ord` on `Route`)

## License

MIT OR Apache-2.0
