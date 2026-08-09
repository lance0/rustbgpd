# Authoritative policy replacement cursor feasibility (2026-07)

## Result

**NO-GO at ADR-0111 Gate 1.** The current all-family route representation does
not support a borrow-free, exact-once continuation with bounded polls and
bounded retirement. Gate 2 (owned exact-export send/commit) was not started,
and no production behavior changed.

This is an algorithmic feasibility receipt, not a throughput or latency claim.
It records source topology, compiler results, and exact visit counts. No soak or
reload-stall campaign was run.

## Frozen baseline and constraints

- repository commit: `4e1c4d4cb391de44a7a8cdb045c26fe879262d70`
- compiler: repository MSRV `rustc 1.95.0 (59807616e 2026-04-14)`
- cursor budget considered: 64 complete identities per poll, as specified by
  ADR-0111
- prohibited escapes: O(table) key snapshots, eager hot-path indexes,
  consume-and-rebuild route storage, a lock or worker around canonical RIB
  state, a scheduler, broad sharding, and unicast-only continuation

General RIB mutations remain fenced during an authoritative replacement, but
readiness must continue to observe the complete canonical Loc-RIB. A cursor
therefore cannot make route bodies temporarily disappear from canonical
lookups.

## Route-source audit

`distribute_changes_inner` builds one complete deduplicated identity set per
dirty or forced peer before it emits anything. A resumable replacement must
cover every source below; handling only the Loc-RIB bests is not equivalent.

| Family | Identity sources in the authoritative resync | Current cursor substrate |
| --- | --- | --- |
| Unicast | Loc-RIB, group table and tombstones, regroup baseline, every Adj-RIB-In for Add-Path/per-client-best, Adj-RIB-Out, extra withdrawals, OTC residue | Prefix tries exist for Adj-RIB-In/Out; Loc-RIB's lazy ordered index may perform a full rebuild; baseline and residue are raw hash stores |
| FlowSpec | Loc-RIB and Adj-RIB-Out | raw `FxHashMap` |
| EVPN | Loc-RIB and Adj-RIB-Out | raw `FxHashMap` |
| BGP-LS | Loc-RIB and Adj-RIB-Out | raw `FxHashMap` |
| VPNv4/v6 | Loc-RIB, group table and tombstones, regroup baseline, every Adj-RIB-In for Add-Path, Adj-RIB-Out, extra withdrawals | route maps and secondary indexes are raw `FxHashMap`; tombstones are `HashSet` |
| Labeled unicast | Loc-RIB, every Adj-RIB-In for Add-Path, Adj-RIB-Out | route maps and secondary indexes are raw `FxHashMap` |
| RT-Constrain | Loc-RIB and Adj-RIB-Out | raw `FxHashMap` |

This table audits the essential route-identity unions, not the whole
seven-phase feasibility surface. One raw canonical family map is sufficient to
fail the borrow-free all-family gate, but a production continuation would also
have to externalize these non-family walks and cleanup tails:

- the O(peers) `outbound_peers.keys().collect()` workset and the outer
  `ribs.values()` Add-Path candidate scans
  (`distribution/mod.rs:3545` and `:3616/:3755/:3788`);
- update-group registry/table traversal and per-group state;
- `peer_unexportable`, pending OTC, policy-filtered, regroup-baseline, and
  extra-withdraw overlays, including the per-peer collect-before-remove in
  `manager/mod.rs:3872-3900`; and
- the O(groups + members-with-residue) gauge refresh in
  `update_groups.rs:1583-1601`, plus last-group composite retirement.

Those additional surfaces reinforce the stop decision, but the generic probes
below do not claim to prove every future design impossible. They prove that the
predeclared borrow-free cursor strategies do not cover the essential raw-map
source without a prohibited mechanism.

The route-source anchors are:

- all-family union construction:
  `crates/rib/src/manager/distribution/mod.rs:3597-3821`;
- Loc-RIB raw family maps and lazy full-index rebuild:
  `crates/rib/src/loc_rib.rs:42-78` and `:177-188`;
- Adj-RIB-In raw non-unicast maps:
  `crates/rib/src/adj_rib_in.rs:67-87`;
- Adj-RIB-Out raw non-unicast maps:
  `crates/rib/src/adj_rib_out.rs:36-55`;
- regroup baseline and group residue:
  `crates/rib/src/manager/update_groups.rs:833-905`; and
- synchronous last-member group removal:
  `crates/rib/src/manager/update_groups.rs:2851-2864`.

## Candidate 1: retain a borrowed hash iterator

An actor-owned continuation would have to own both a canonical map and the
iterator borrowing that map. This minimal safe-Rust prototype:

```rust
use std::collections::{hash_map::Iter, HashMap};

struct ActorOwnedCursor<'a> {
    canonical: HashMap<u64, u64>,
    cursor: Iter<'a, u64, u64>,
}

impl ActorOwnedCursor<'_> {
    fn new(canonical: HashMap<u64, u64>) -> Self {
        let cursor = canonical.iter();
        Self { canonical, cursor }
    }
}

fn main() {}
```

fails under `rustc --edition=2024` with E0515 (returning a value referencing
the local `canonical`) and E0505 (moving `canonical` while borrowed). That is a
limit of an explicit concrete owner, not of safe Rust generally.

A compiler-generated pinned async future **can** retain an immutable
`HashMap::Iter` across a yield while updating a disjoint readiness-observation
field. The retained positive probe compiles on the MSRV without user unsafe
code. This means an immutable borrowed-future inner loop is a real alternative
design, not an impossibility.

It does not supply the cursor this resync needs. Per-peer Adj-RIB-Out and the
residue/overlay maps are both identity sources and post-send mutation targets.
The paired async probe retains `adj_rib_out.iter()` across a pending point and
then removes the just-sent key before resuming. It fails E0502 because the
immutable iterator remains live when the same map needs a mutable borrow.
Dropping the iterator before commit loses its bucket position. Deferring
commits stores O(table) keys, consuming/rebuilding creates split storage, and
reconstructing the iterator falls into Candidate 3's O(capacity)-per-poll
restart. The grouped route table is read-only in this empty dirty-resync pass;
its remaining Gate 1 problem is bounded traversal and last-member retirement,
not the specific same-map mutation proven here.

The future therefore fails the predeclared **borrow-free** Gate 1 and the
same-source post-send mutation boundary. This does not rule out every possible
inner event-loop design; such a design would need a new feasibility proof for
all-family mutation and retirement rather than being treated as this owned
cursor.

`drain` and `extract_if` do not bridge the post-send boundary: their iterator
types mutably borrow and remove from the map before an asynchronous send has
succeeded. Reinserting on failure or committing another same-map change still
requires dropping the cursor or deferring table-sized state.

## Candidate 2: consume into an owned iterator

`HashMap::into_iter` is borrow-free and exact-once, but only by consuming the
map. The complete passing probe is:

```rust
use std::collections::HashMap;

fn main() {
    let mut canonical = HashMap::from([(7, 70), (9, 90)]);
    let cursor = std::mem::take(&mut canonical).into_iter();
    assert!(canonical.get(&7).is_none());
    assert_eq!(cursor.len(), 2);
}
```

The standard library documents `IntoKeys`/`IntoValues` the same way: the map
cannot be used after creating the consuming iterator. An `IntoIter` has no
keyed lookup for its unconsumed entries. Restoring canonical lookup therefore
requires either:

1. rebuilding processed entries into a second map while teaching every reader
   to query both the rebuilt map and a non-indexed iterator; or
2. cloning keys or route bodies into a separate table-sized inventory before
   consuming the original.

The first is a broad split-storage rewrite and still cannot look up the
unconsumed iterator by key; the second is the prohibited O(table) inventory.
This candidate is useful only for state already detached from the canonical
RIB.

## Candidate 3: restart from a scalar key

A raw hash map exposes no seek operation. Finding the next 64 keys after a
scalar cursor requires restarting the iterator and scanning the table. The
official [`HashMap::iter` documentation](https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.iter)
states that a full iteration currently costs O(capacity), including empty
buckets.

A deterministic probe using 4,096 integer keys and a 64-key poll limit counted
every key visit while selecting the next ordered batch:

```text
rows=4096 batch=64 visits=266240 amplification=65.0x
```

The exact relation is `rows * (ceil(rows / batch) + 1)`: 65 full scans,
including the terminal empty scan. This avoids a snapshot but makes every poll
O(table) and the complete walk superlinear, violating ADR-0111's cooperation
bound. Using an ordinal with `.skip()` has the same restart cost and also relies
on arbitrary hash iteration order remaining stable.

The exact standalone sources are retained with this receipt under
[`artifacts/authoritative-policy-replacement-cursor-feasibility-2026-07/`](artifacts/authoritative-policy-replacement-cursor-feasibility-2026-07/).
They were run without repository dependencies or feature flags:

```console
$ rustup run 1.95 rustc --edition=2024 borrowed_hash_cursor.rs
error[E0515]: cannot return value referencing function parameter `canonical`
error[E0505]: cannot move out of `canonical` because it is borrowed
$ rustup run 1.95 rustc --edition=2024 borrowed_async_cursor.rs
$ rustup run 1.95 rustc --edition=2024 borrowed_async_cursor_mutation.rs
error[E0502]: cannot borrow `self.adj_rib_out` as mutable because it is also borrowed as immutable
$ rustup run 1.95 rustc --edition=2024 owned_hash_cursor.rs && ./owned_hash_cursor
$ rustup run 1.95 rustc --edition=2024 restart_scan_cursor.rs -O && ./restart_scan_cursor
rows=4096 batch=64 visits=266240 amplification=65.0x
```

`SHA256SUMS` seals the five sources. Run `sha256sum -c SHA256SUMS` from
the artifact directory before reproducing the commands.

## Retirement audit

Detaching a raw map and retaining its `IntoIter` can bound entry destruction if
the owner drains a fixed number per poll and never drops the iterator early.
That local fact does not pass Gate 1:

- canonical traversal already failed above;
- `GroupRibOut` embeds `AdjRibOut`, whose unicast bodies are in `RouteSlab` and
  whose prefix identities are in `FamilyPrefixMap`; neither type exposes an
  owned incremental drain; and
- last-member removal currently drops the complete `GroupRibOut` synchronously,
  including route bodies, secondary indexes, policy residue, tombstones, and
  member bookkeeping.

Adding owned-drain state for that entire composite is a storage-lifecycle
change, not a narrow cursor seam, and it still would not provide seekable
canonical all-family iteration.

## Decision boundary

Every candidate lands on an explicit ADR-0111 stop condition:

- concrete borrowed cursor: cannot coexist with the same-source post-send
  mutation; the compiler-generated immutable future is safe but is not the
  required borrow-free cursor and fails that mutation probe;
- owned iterator: requires consuming/rebuilding canonical storage or an
  O(table) second inventory;
- scalar cursor: leaves an O(table) scan in every actor poll; and
- maintained indexes: require an eager all-family hot-path index or a broad
  storage rewrite, with existing repository evidence that such changes can
  regress Loc-RIB recompute.

Gate 1 is therefore NO-GO on the current representation. Do not implement Gate
2 or a partial/unicast-only continuation. A future attempt must begin with a
separate, controlled route-storage measurement and show that an all-family seek
cursor pays for itself on the convergence hot path before reopening ADR-0111.

## Load-bearing validation

N/A for repository tests and gates: this change is documentation only and does
not add or modify executable repository validation. The compiler and visit-count
probes above are feasibility evidence, not a shipped gate. Their guarded breaks
are direct: making the concrete owner compile would invalidate its ownership
finding; the positive async probe guards against overclaiming safe-Rust
impossibility; making the same-map async mutation compile without dropping the
cursor would invalidate Candidate 1; preserving canonical lookup after
`mem::take` would invalidate Candidate 2; and reducing the recorded restart
visits below the stated formula would invalidate Candidate 3.
