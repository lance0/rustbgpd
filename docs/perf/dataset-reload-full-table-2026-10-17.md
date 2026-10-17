# Full-table dataset reload (17 October 2026)

> **Verdict: PASS** at `4877d84efde0794b37aaea3b07e8a789ac648f8c`: a content-only
> dataset swap plus SIGHUP on a full table completes, stays ready and folds
> exactly in all three cells. The affected-keys pass takes 63–509 ms; the
> group-level full pass takes 4.4–4.6 s. Two earlier runs of the same
> instrument, before the group-level pass, are retained as **FAIL**.

## Shape

The hosted `dataset-reload` mode of `bench/scale/reloadstall/run-recovery-mass-dirty.sh`
ran one cell per fresh `ubuntu-24.04` GitHub-hosted runner. Each cell is one
release-built daemon pinned to CPUs 0–1, with the harness on CPUs 2–3
(rustc 1.99.1).

- **Table:** one source announces 1,000,000 IPv4 + 230,000 IPv6 keys, as
  unicast (`full-uc`) or VPN (`full-vpn`), and never changes them.
- **Receivers:** 12, with identical export policy. They form one update
  group; the source sits alone in a second group.
- **Operation `b`:** an atomic rename of the origin-AS dataset that changes the
  export verdict of 12,320 keys (10,000 IPv4 + 2,320 IPv6, 1.0%), then SIGHUP.
  **Operation `a`** restores the file, then SIGHUP.
- **`dataset-delta`** expects the affected-keys path (`mode=delta`).
- **`dataset-full`** also swaps a community-set dataset read through
  `route.communities in`. That probe cannot be bounded, so the daemon must take
  the full pass (`mode=full full_pass=group`).

## Bars

These were frozen in the driver's manifest and checker before any run:

- **Fail-stop:** no daemon exit, including exit 70, through both reloads.
- **Applied:** each SIGHUP adds exactly one `complete` reload outcome, and
  `rbgp config last-reload` reports `complete` with nothing unapplied.
- **Exact fold:** every receiver reaches the table a fresh start would send,
  with no wrong verdict, reversal, withdrawal or session loss.
- **Readiness:** every `/readyz` sample (4 Hz, 1 s deadline) is 200.
- **Path:** the re-evaluation log matches the cell's path; otherwise INVALID.

SIGHUP→complete, SIGHUP→fold, RIB pass time, affected keys and the daemon
cgroup peak are reported, not gated.

## Results

Each row shows operation `b` / operation `a`. RIB pass is the logged
`dataset export re-evaluation complete` `elapsed_ms`.

| Run | Source | Cell | Path | Affected keys | RIB pass | SIGHUP→fold | Unchanged re-sends | `/readyz` non-200 | cgroup peak | Exit | Verdict |
|---|---|---|---|---:|---:|---:|---:|---|---:|---:|---|
| [39048263987](https://github.com/lance0/rustbgpd/actions/runs/39048263987) | `4877d84e` | full-uc delta | `delta` | 12,320 | 63 / 64 ms | 0.085 / 0.085 s | 0 | 0 of 3 | 962 MiB | 0 | PASS |
| 39048263987 | `4877d84e` | full-vpn delta | `delta` | 12,320 VPN | 491 / 509 ms | 0.512 / 0.531 s | 0 | 0 of 6 | 2,359 MiB | 0 | PASS |
| 39048263987 | `4877d84e` | full-uc full | `full`, `group` | all | 4,604 / 4,434 ms | 4.614 / 4.452 s | 0 | 0 of 38 | 1,100 MiB | 0 | PASS |
| [39015807823](https://github.com/lance0/rustbgpd/actions/runs/39015807823) | `07fe76cb` | full-uc full | `full`, per member | all | 35,772 / 35,362 ms | 35.92 / 35.51 s | 14.61M / 14.61M | 44 of 288 (5.75, 5.25 s) | 1,667 MiB | 0 | **FAIL** |
| [39015812391](https://github.com/lance0/rustbgpd/actions/runs/39015812391) | `07fe76cb` | full-uc full | `full`, per member | all | 33,000 / 33,028 ms | 32.96 / 32.99 s | 14.61M / 14.61M | 24 of 266 (3.00, 3.00 s) | 1,681 MiB | 0 | **FAIL** |

In every row, each operation added one `complete` outcome, folded exactly and
kept all 12 sessions. Each passing operation sent 147,840 announcements: the
12,320 changed routes to each of 12 receivers.

**Per group, not per member.** The `07fe76cb` rows are the hosted instrument
on its pre-merge branch, before the group-level pass existed. That pass
resynced every member separately and re-sent about 14.61M unchanged routes per
operation. Its 33–36 s pass crossed the RIB's 30 s policy-transition readiness
limit, giving the 503 windows shown. At `4877d84e`, the full pass re-evaluates
once per update group (two groups for 13 peers), and each receiver gets only
the changed routes. The two sources differ, so this is a descriptive
comparison, not a controlled one.

**Before.** Hosted run [38685916775](https://github.com/lance0/rustbgpd/actions/runs/38685916775)
at `7ac10d60` ran an earlier instrument on the same table, with 12 or 24
receivers for unicast and VPN. All four cells failed before any operation
completed: `dataset export RIB acknowledgement timed out` at about 5 s, a
`known_divergence` fence, then exit 70. No reload completed, so there is no
like-for-like time to compare.

The wire-churn mass-dirty qualification is a separate check. At the same
commit, its runs [39048268495](https://github.com/lance0/rustbgpd/actions/runs/39048268495)
and [39048273227](https://github.com/lance0/rustbgpd/actions/runs/39048273227)
passed 8/8 cells; they are not dataset-reload evidence.

## Scope

- **One shape, one runner class.** Twelve receivers with identical policy, one
  leg (swap and revert) per cell. Times are single samples, not latency
  distributions. The 4 Hz probe cannot see a window shorter than 250 ms, and
  the delta cells recorded only 3 and 6 samples in total.
- **Full pass is unicast only here.** No hosted `full-vpn` full cell ran. On
  the group path, VPN still evaluates once per group but encodes per session.
- **Fallbacks keep the per-member pass.** When any receiver also exports EVPN,
  labeled unicast, FlowSpec, BGP-LS or RT-Constrain routes, the full pass stays
  per member, as it does under deferred VPN selection or conditional
  advertisement.
- **Bounded probes.** Only `route.prefix in` and `route.origin-as in` take the
  affected-keys path; other dataset probes take the full pass.
- **Not a release qualification.** This is not a release-candidate soak, and it
  says nothing about other receiver counts or heterogeneous policies.

## Evidence

[`comparison.json`](artifacts/dataset-reload-full-table-2026-10-17/comparison.json)
holds the curated per-cell verdicts, paths, timings, fold results, readiness
counts, group membership and cgroup peaks for all five cells. Raw logs, metrics
and build provenance stay in each run's `update-group-recovery-*` artifacts.

```json
{"run": 39048263987, "profile": "full-uc", "cohort": "dataset-full", "status": "PASS",
 "mode": "full", "full_pass": "group", "rib_pass_ms": 4604, "unchanged_announcements": 0}
```
