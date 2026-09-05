# Format and version namespaces

> **Document class: REFERENCE.** This maintained page defines a contract, specification, or reusable procedure; follow any stated version scope.

rustbgpd does not have one global "v1/v2/v3" format lineage. Each durable or
machine-readable surface below owns an independent version namespace with its
own compatibility rules. None of these numbers is comparable with the product
SemVer version, the protobuf package `rustbgpd.v1`, the frozen v1
stable-surface inventory ([v1-stable-surface.json](v1-stable-surface.json)),
or one another.

| Surface | Current marker | What the number means | Compatibility owner |
|---------|----------------|-----------------------|---------------------|
| Commit-confirm authority | v3 (`VERSION = 3`, [`src/confirm_journal/v3.rs`](../../src/confirm_journal/v3.rs)) | Current durable pending-authority format. A retired journal (locator-free or v2) refuses boot with the artifact untouched instead of being decoded. | [ADR-0076 amendment](../adr/0076-config-transaction-model.md), [ADR-0122](../adr/0122-compatibility-debt-inventory.md) rows D1/D3 |
| Config history | v2 (`VERSION = 2`, [`src/config_history/v2.rs`](../../src/config_history/v2.rs)) | Current JSON history codec. Retired TOML history is ignored and retained. | [ADR-0122](../adr/0122-compatibility-debt-inventory.md) row D1 |
| Runtime snapshot token | `kv1:` / `kv2:` prefix ([`src/config/mod.rs`](../../src/config/mod.rs)) | Keyed, process-local change-detector tokens minted by one algorithm. The prefix discriminates whether live runtime context is bound into the preimage — `kv1:` config only, `kv2:` config plus the live update-group snapshot identity — not successive format generations. Production planning always binds context, so live tokens carry `kv2:`; callers compare tokens opaquely and re-plan after a daemon restart. | [ADR-0076](../adr/0076-config-transaction-model.md) |
| Streamed config frame | `FRAME_VERSION = 1` ([`crates/api/src/config_service/stream.rs`](../../crates/api/src/config_service/stream.rs)) | Exact version of the streamed Plan/Apply ingress frames. Independent of unary API versioning and outside the initial v1 frozen inventory (ADR-0125 DR6). | [ADR-0125](../adr/0125-v1-stability-contract.md) |
| Support bundle | manifest `format: 2` (`support-bundle-manifest/2`) | Frozen machine-readable doctor bundle layout with additive-fields-only evolution. Not a config-transaction format. | [v1-stable-surface.json](v1-stable-surface.json) |
| General FIB owned state | v5 current, loads v1–v5 ([`src/fib_runtime.rs`](../../src/fib_runtime.rs)) | Crash-restart ownership receipt: v1 single next-hop scalar, v2 equal-cost set, v3 per-next-hop weights, v4/v5 link-local ifindexes (landed together; no standalone v4 shipped). One serde model plus an on-load upgrader, not parallel readers. | [ADR-0066](../adr/0066-unicast-multipath-ecmp-fib.md), [ADR-0068](../adr/0068-weighted-multipath.md), [ADR-0069](../adr/0069-bgp-unnumbered.md), [ADR-0079](../adr/0079-kernel-state-crash-restart-reconciliation.md) |
| GR restart marker | v3 current, accepts v1–v3 (`gr-restart.toml`, [`src/main.rs`](../../src/main.rs)) | Planned-restart marker: v1 carries the wall-clock expiry only, v2 binds the warm-checkpoint generation, v3 adds the restart clock domain (boot id, time namespace, boottime offsets and boottime expiry). The writer emits v3 and degrades to v2/v1 when clock sampling fails; the validator accepts each version only with its exact field set. | [ADR-0040](../adr/0040-gr-restarting-speaker.md), [ADR-0104](../adr/0104-shutdown-warm-checkpoint-publication.md) |

## Why the compatibility behaviors differ

The namespaces deliberately do not share one policy:

- **Refuse retired authority** (commit-confirm journal): when interpreting an
  old format could corrupt recovery, boot refuses with the artifact untouched
  rather than guessing.
- **Load and upgrade** (FIB owned state): when refusal would orphan live
  kernel state — misclassifying rustbgpd's own programmed routes as foreign —
  old receipts are upgraded on load, and only versions newer than the build
  understands are quarantined.
- **Opaque equality values** (runtime snapshot tokens): tokens are keyed and
  process-local; the only supported operation is passing one back verbatim
  for equality comparison. Never parse a token or depend on its prefix, and
  re-plan after a daemon restart.
- **Additive frozen formats** (support bundle, streamed frame): frozen public
  machine formats evolve additively under the stable-surface inventory.

Changing a reader floor, a token algorithm, the frozen bundle format, or the
streamed frame version is a separately reviewed behavior change owned by the
ADR or machine inventory linked above. This page records the map; it creates
no new compatibility policy.
