# Loc-RIB unchanged-winner artifact index

These are sanitized retained outputs for
[`loc-rib-unchanged-winner-2026-07.md`](../../loc-rib-unchanged-winner-2026-07.md).

| File | Contents |
|---|---|
| `same-sha-summary.md` | Six-attempt control at `35b33a5d` versus itself |
| `immediate-parent-summary.md` | Six-attempt `35b33a5d` versus `80b34f3a` A/B |
| `environment.txt` | Pinning, toolchain, host class, commands, and checksums |
| `control-benchmark.patch` | Permanent-base-to-control benchmark patch |
| `candidate.patch` | Control-to-rejected-candidate production patch |

The generated target directories and Criterion HTML are intentionally omitted.
The retained summaries contain the point-estimate aggregate used for the
verdict, while `environment.txt` pins the inputs needed to reproduce it.
The retained patches reconstruct the measured source trees from the permanent
mainline base even if the original topic branch has been deleted after a squash
merge.

## Reconstruct the measured trees

Run from the repository root:

```console
REPO=$(git rev-parse --show-toplevel)
ARTIFACTS="$REPO/docs/perf/artifacts/loc-rib-unchanged-winner-2026-07"
TMP=$(mktemp -d)
cp "$ARTIFACTS/control-benchmark.patch" "$TMP/"
cp "$ARTIFACTS/candidate.patch" "$TMP/"
git -C "$REPO" worktree add --detach "$TMP/repro" \
    aea3d4133047bb06cce5813658bf619e5c11b829
cd "$TMP/repro"

git apply "$TMP/control-benchmark.patch"
git add crates/rib/benches/rib_ops.rs
git commit -m benchmark-control
CONTROL=$(git rev-parse HEAD)

git apply "$TMP/candidate.patch"
git add crates/rib/src/loc_rib.rs
git commit -m rejected-candidate
TARGET=$(git rev-parse HEAD)

bench/compare-criterion.sh \
    --base "$CONTROL" --head "$CONTROL" \
    --package rustbgpd-rib --bench rib_ops \
    --filter loc_rib_recompute/no_change \
    --core 5 --attempts 6 --require-performance \
    --out-dir "$TMP/same-sha"

bench/compare-criterion.sh \
    --base "$CONTROL" --head "$TARGET" \
    --package rustbgpd-rib --bench rib_ops \
    --filter loc_rib_recompute/no_change \
    --core 5 --attempts 6 --require-performance \
    --out-dir "$TMP/immediate-parent"

cd "$REPO"
git -C "$REPO" worktree remove "$TMP/repro"
echo "Retained comparison artifacts: $TMP"
```

The local commit IDs will differ from the historical topic-branch IDs because
commit metadata differs. The patched source trees and benchmark bytes are the
measured inputs. The caller's current branch and worktree are not changed.
