# Selection-deferral release fanout — v0.68.0

Two retained campaigns measured timer-triggered selection-deferral release at
700 route-server peers and 400,400 routes. The baseline is commit
`52034e2bc839548206c2be3e40c201f49039f040`; the candidate is
`ba5717b4ad8f921e85a96168b51e0e9169585271`, an ancestor of exact v0.68.0
commit `d3e6c3571116261c47039b603ec64db14100ea0e`. The harness and relevant RIB
manager sources are unchanged between the candidate and the release commit.

| Mode | Baseline n=5 median | Candidate n=5 median | Median ratio |
| --- | ---: | ---: | ---: |
| IPv4, one gate | 53.613148786 s | 0.811169760 s | 66.09x faster |
| IPv4 + IPv6, two gates | 51.642288118 s | 1.169882940 s | 44.14x faster |
| Seven gates, IPv4 + IPv6 sendable | 51.861180646 s | 1.447364142 s | 35.83x faster |

Every normal row released the expected gates, cleared the ledger, delivered
all 400,400 routes, completed the expected 700 or 1,400 EoR markers, and left
the sentinel query behind no queued work. Both candidate controls recorded
zero release work and a sentinel latency below 8 us. The one candidate
overflow row withdrew both families, released both gates, recorded two
overflows, delivered no route payload, and completed 1,400 EoR markers in
39.326905169 s. It is a correctness observation, not part of the speedup.

## Scope

This is the harness's fully reusable homogeneous wire-encoding case. It is an
in-process RIB-manager measurement, not whole-daemon convergence or policy
reload timing. Production forms separate compatible cohorts for different
wire encodings and retains exact per-member fallback for ineligible source
flips, lanes, withdrawals, export rejection, and prefix-limit filtering. The
speedup therefore does not describe mixed-capability fleets or those fallback
paths.

The baseline and candidate were separate campaigns, not a counterbalanced A/B.
The candidate campaign counterbalanced its modes, used no retries, and retained
two controls. [`results.tsv`](results.tsv) contains every normalized row used
above; [`provenance.txt`](provenance.txt) records the source identities and
input-set digests; [`SHA256SUMS`](SHA256SUMS) seals this compact publication.

## Reproduce and recompute

At either measured commit, build the fixed harness and run its self-test:

```sh
cargo test --release --locked -p rustbgpd-rib --features bench-internals \
  --bench selection_deferral_release --no-run
target/release/deps/selection_deferral_release-<hash> --self-test
```

Run the candidate sequence below with a 120-second per-row timeout and no
retry. Run `ipv4`, `dual`, and `seven` five times each for the baseline, with a
control before and after:

```text
control ipv4 dual seven dual seven ipv4 seven ipv4 dual ipv4 seven dual dual ipv4 seven overflow control
```

The first element of each JSON `release` array is the timed release interval in
nanoseconds. The medians and ratios can be recomputed directly from the compact
TSV with Python's `statistics.median`; group `release_ns` by `source` and
`mode`, excluding the single overflow row and the controls.
