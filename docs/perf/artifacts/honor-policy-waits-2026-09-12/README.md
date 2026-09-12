# Honor-policy waits at 1,000 peers — 2026-09-12

> **Document class: HISTORICAL.** Two bounded local cells at the candidate revision below.

Both honor-only SIGHUP edits completed across 1,000 healthy eBGP peers.
The dense cell served 27 CLI calls that started and finished inside the
observed owner spans in 11.684–23.225 ms, including 13 stats replies containing
mixed old/new import generations. All 1,223 dense-cell calls met the 2-second
budget. The earlier sparse cell also passed every call and reload outcome,
but its cadence missed the short owner windows.

## Shape and identity

Both cells used clean `bb27ca009e39cba9980648617e4b914ebbd16e98`, Rust/Cargo
1.98.1, and default-feature release builds. This measured revision is distinct
from subsequent integration and merge heads. Exact source, executable and
harness hashes, build commands and exit codes are in [summary.json](summary.json).

The native `reloadstall` engine established 1,000 loopback route-server peers,
each advertising Route Refresh and 400 base IPv4 prefixes. Every peer's remote
ASN differed from the daemon's ASN; explicit import and export policies were
present. No unsupported peer or synthetic stall was used. Engine control churn
continued around the 400,000-prefix base; the retained inventories record the
transient additional prefixes. The daemon ran on CPUs 2–3 with two Tokio
workers, the engine on CPUs 4–7, and CLI probes on CPUs 8–15.

Each fresh cell changed only `global.honor_graceful_shutdown` from false to
true, then only `global.honor_blackhole` from false to true. Policies, datasets,
neighbor definitions and generation membership remained unchanged. Both
reloads classified as sequential. Each produced exactly one `complete` outcome,
zero other outcome deltas, and 1,000 distinct IPv4-unicast Route Refresh sends.
Every import generation advanced once: 0 → 1 → 2. All before/after inventories
and every neighbor probe contained 1,000 Established sessions; every stats
reply contained all 1,000 import rows.

## Measured windows and reads

There is no setter-entry timestamp. The first Route Refresh send occurs inside
the owning command; the classifier precedes its enqueue. First-refresh-to-owner-
completion therefore supplies a lower duration bound, and classifier-to-owner-
completion supplies an upper bound. The brackets below are not exact actor
entry measurements. CLI phase membership uses wall timestamps; elapsed CLI
latency uses a monotonic clock and includes process launch, RPC and JSON output.

| Cell / honor setting | Owner duration bracket (ms) | Strict interior neighbor / stats calls | Interior mixed-generation stats |
| --- | ---: | ---: | ---: |
| Sparse / graceful shutdown | 83.833–85.167 | 0 / 0 | 0 |
| Sparse / blackhole | 84.209–85.576 | 0 / 0 | 0 |
| Dense / graceful shutdown | 149.407–157.566 | 7 / 7 | 7 |
| Dense / blackhole | 148.858–157.653 | 7 / 6 | 6 |

The sparse cell used two 30-second probe waves, waiting 200 ms after each
completion. Its 552 calls all passed in 8.615–42.019 ms. The coverage checker
failed because no call started and finished strictly inside either walk;
that is a sampling failure, not a daemon failure.

The dense follow-up used two 5-second waves with back-to-back calls. Both
cells had independent `neighbor` and `policy stats --direction both` streams,
at most one call in flight per stream, and a 5-second driver cap. Dense-cell
calls all passed in 8.434–81.053 ms. This higher probe load accompanied longer
walks; the two cells are not a controlled overhead or speedup comparison.
Strict interior means both call endpoints lie after the first refresh and
before owner completion. Mixed-generation replies completed before that
completion independently confirm service during the serial walk.

Process RSS was sampled every 100 ms. The sparse graceful-shutdown walk had
no sample; other sampled values are retained in the summary. These samples
cannot identify policy allocation bytes or guarantee a transient peak. The
per-peer 500 ms acknowledgement budget multiplied by 1,000 yields a theoretical
500-second ACK-only ceiling; it is neither the healthy elapsed time above nor
a total bound including other waits.

Both cells emitted one startup warning for inherited legacy RFC 8212 posture;
the fixture had explicit policy chains. There were no warnings or errors
between the first and last probe. After the final probe, owned teardown
produced outbound-resync/writer warnings (4,737/373 sparse; 99,537/58 dense),
plus one bounded peer-shutdown timeout in the dense cell. Both daemons exited
zero; all owned children were reaped and listening ports released. An earlier
pre-trigger attempt interrupted for build overlap is excluded and retained
locally. This receipt establishes healthy timing and read service at this
shape, without a baseline failure reproduction or soak qualification.

## Evidence

Compressed files retain every per-call row, selected owner markers and all
refresh sends, before/after fleet and import-generation inventories, reload
outcome counters, and nearby RSS samples. One filtered mixed-generation body
per dense wave is retained with its original response hash. Initial configs
match after removing only runtime-directory and socket paths.
[original-raw-hashes.json](original-raw-hashes.json) identifies the complete
local inputs; [SHA256SUMS](SHA256SUMS) covers the published artifacts.
