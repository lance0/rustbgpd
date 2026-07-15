# Compact known-path accounting — July 2026

## Result

Plain IPv4/IPv6 unicast sessions now keep one `HashSet<Prefix>` entry per
accepted prefix. Only families that negotiated Add-Path receive keep
`(prefix, path_id)` identities plus per-prefix refcounts. The selection is made
from the negotiated per-family receive direction; a wire path ID of zero never
selects the compact representation.

The change passed both memory gates on a fresh `main` control and the exact
candidate patch:

| Gate | `main` | Candidate | Change | Required |
|---|---:|---:|---:|---:|
| Transport known-path live bytes | 15,204,416 | 4,980,768 | **-67.24%** | at least -40% |
| Whole tracked live heap | 210,602,454 | 200,073,124 | **-5.00%** | at least -3% |

The measured shape was two real BIRD peers announcing 100,000 unique IPv4
prefixes each to a real rustbgpd daemon, with one real GoBGP monitor receiving
200,000 routes. The generated scenario and daemon config contain no Add-Path
receive capability. Both DHAT runs converged 200,000/200,000 with zero tester
errors. bgperf2's BIRD timeout field is structurally zero, so this receipt does
not claim an independently measured tester-timeout count.

## Release-build control

Release images used the same source snapshots and pinned bgperf2 adapter as the
DHAT images. The fixed admitted order was B1, C1, C2, B2, B3, C3:

| Run | Variant | Convergence (s) | Total (s) | Peak RSS (bytes) |
|---|---|---:|---:|---:|
| B1 | `main` | 3 | 12.34 | 251,789,312 |
| C1 | candidate | 3 | 12.19 | 239,202,304 |
| C2 | candidate | 3 | 12.22 | 242,790,400 |
| B2 | `main` | 3 | 12.26 | 252,059,648 |
| B3 | `main` | 3 | 12.20 | 254,681,088 |
| C3 | candidate | 3 | 12.21 | 240,840,704 |

Every admitted run reached 200,000/200,000 with zero tester errors and the same
no-Add-Path config. The structurally zero BIRD timeout field is retained as
schema, not independent timeout evidence. Mean total time was 12.267 seconds
on `main` and 12.207 seconds on the candidate, a 0.49% candidate decrease. All
convergence values were identical, so there is no confirmed 3% throughput
regression. The median release RSS decreased 4.45% (252,059,648 to 240,840,704
bytes).

The pinned BIRD helper counts a normal BGP connection-collision `RMT` record as
a tester error. Two C1 attempts and two B3 attempts were rejected for that
startup nondeterminism and are not included above. A pre-recovery B1 warm-up was
also excluded because it had one collision record and lacked a retained final
result row. No rejected attempt was substituted into the admitted matrix.

## Re-run recipe

The committed artifacts are the audit surface; this recipe rebuilds the same
behavioral control from clean checkouts. It deliberately uses the exact pinned
bgperf2 adapter and no-cache builds. The candidate commit contains the measured
four-file code diff byte-for-byte; its later documentation files do not enter
that code-diff hash.

```bash
BASE_DIR=/tmp/rustbgpd-known-path-base
CANDIDATE_DIR=/tmp/rustbgpd-known-path-candidate
BGPERF_DIR=/tmp/bgperf2-known-path

git worktree add --detach "$BASE_DIR" f9b762db4f9ccec85040bb68136e818ff8ba53fd
git fetch origin pull/908/head:refs/remotes/origin/pr-908
git worktree add --detach "$CANDIDATE_DIR" refs/remotes/origin/pr-908
CANDIDATE_SHA=$(git -C "$CANDIDATE_DIR" rev-parse HEAD)
git clone https://github.com/lance0/bgperf2.git "$BGPERF_DIR"
git -C "$BGPERF_DIR" checkout fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9

(cd "$BGPERF_DIR" && RUSTBGPD_SOURCE="$BASE_DIR" \
  python3 bgperf2.py update rustbgpd -c f9b762db4f9ccec85040bb68136e818ff8ba53fd \
  -n --profile release --tag bgperf/rustbgpd:known-path-base-release)
(cd "$BGPERF_DIR" && RUSTBGPD_SOURCE="$CANDIDATE_DIR" \
  python3 bgperf2.py update rustbgpd -c "$CANDIDATE_SHA" \
  -n --profile release --tag bgperf/rustbgpd:known-path-candidate-release)
(cd "$BGPERF_DIR" && RUSTBGPD_SOURCE="$BASE_DIR" \
  python3 bgperf2.py update rustbgpd -c f9b762db4f9ccec85040bb68136e818ff8ba53fd \
  -n --profile dhat --tag bgperf/rustbgpd:known-path-base-dhat)
(cd "$BGPERF_DIR" && RUSTBGPD_SOURCE="$CANDIDATE_DIR" \
  python3 bgperf2.py update rustbgpd -c "$CANDIDATE_SHA" \
  -n --profile dhat --tag bgperf/rustbgpd:known-path-candidate-dhat)
```

Run the release matrix in the fixed B1, C1, C2, B2, B3, C3 order below. Reject
and repeat a slot if the pinned BIRD error scan finds an `RMT` connection-
collision record; never substitute a rejected result into another slot.

```bash
cd "$BGPERF_DIR"
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-base-release \
  -n 2 -p 100000 -o /tmp/release-b1.raw.csv
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-candidate-release \
  -n 2 -p 100000 -o /tmp/release-c1.raw.csv
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-candidate-release \
  -n 2 -p 100000 -o /tmp/release-c2.raw.csv
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-base-release \
  -n 2 -p 100000 -o /tmp/release-b2.raw.csv
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-base-release \
  -n 2 -p 100000 -o /tmp/release-b3.raw.csv
python3 bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:known-path-candidate-release \
  -n 2 -p 100000 -o /tmp/release-c3.raw.csv
```

Run one DHAT control and candidate with the same `-n 2 -p 100000` arguments.
After each benchmark returns, stop `bgperf_rustbgpd_target` normally so DHAT
writes `/root/dhat-heap.json`, copy that file out, then apply the classifier and
CSV validation commands in the artifact README. The rebuilt image digests will
differ because the provenance label names a commit instead of the measured
pre-commit snapshot; the manifest retains the immutable measured digests and
source/archive hashes.

## Correctness and load-bearing proofs

The optimized representation is selected only for families without negotiated
Add-Path receive. The measured scenario has no Add-Path capability, while
`negotiated_receive_direction_selects_unicast_accounting_storage` asserts in
code that absent/Send modes populate only the plain set and Receive/Both modes
populate only the identity/refcount stores. The production insertion path also
debug-asserts that a plain prefix never leaks into Add-Path accounting.

Each changed invariant has a mutation-red regression:

- selecting storage from `path_id != 0`, or treating absent/Send as receive,
  fails the negotiated-direction storage test;
- removing Add-Path identity deduplication or prematurely dropping its prefix
  refcount fails the duplicate/partial-withdrawal tests, including path ID zero;
- counting only one representation fails the mixed IPv4/IPv6 family test;
- collapsing Enhanced Route Refresh snapshots to one untyped representation
  fails the plain omission, Add-Path partial replay, timeout, and staggered
  family-window tests;
- failing to clear either store on session down leaves the reset test nonempty;
- routing plain prefixes back through identity/refcount accounting makes the
  focused compact-storage assertion fail.

These mutations were applied to the production logic, observed red, restored,
and rerun green before measurement.

## Provenance and limits

The control is `main` commit
`f9b762db4f9ccec85040bb68136e818ff8ba53fd`. The measured four-file code diff
SHA-256 is `47fdbb8473822bfd14b1a66080966ffdfc86f8f42119e6f05cfb4609f835d8a5`;
the deterministic candidate source archive SHA-256 is
`ba9109228441312521c7d35462fdb5beb9a48033d80f44f34ae9243c43dc125e`.
The release and DHAT image digests and all pinned builder/runtime identities are
in the [artifact manifest](artifacts/known-path-accounting-2026-07/manifest.json).

This receipt measures the dominant route-server/reflector case: unique plain
IPv4 unicast paths from two peers. It does not claim an Add-Path memory win;
Add-Path deliberately retains exact path identities and refcounts. Absolute
times and RSS are host-specific. The DHAT candidate's sampled process RSS was
2.2% above its single DHAT control even though tracked live heap fell 5.0%; the
counterbalanced release matrix is the throughput/RSS control, and DHAT is used
for structural attribution.

Raw DHAT JSON, raw bgperf samples, daemon logs, and rejected-run captures remain
outside the repository because they contain unbounded paths and host-specific
fields. The committed artifacts retain lossless sanitized DHAT derivatives,
classified tables, bounded result rows, exact config/scenario, and the admitted
BIRD logs.
