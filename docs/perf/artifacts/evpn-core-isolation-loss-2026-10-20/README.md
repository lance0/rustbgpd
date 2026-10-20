# EVPN core-isolation loss artifacts (2026-10-20)

These files are the evidence for the
[EVPN core-isolation transition-loss receipt](../../evpn-core-isolation-loss-2026-10-20.md).

| Path | Contents |
|---|---|
| `ab-summary.txt` | 2026-10-20 action-arm A/B: per-image distributions (min, p25, median, p75, max) of the loss window, frames lost and cut timings, the first-cycle/later-cycle split, per-block medians and the verdict line |
| `ab-blocks.txt` | The twelve 2026-10-20 deployment blocks in run order, with image, exit code and duration |
| `control-night-summary.txt` | 2026-10-19 summary for both arms on `090022493`, including the censored control arm and the invalid-cycle reasons |
| `harness-v2.patch` | The loss-bound harness as run on 2026-10-20, as a patch against the M121 harness at `0900224939ced8bb662aaed10c49d305837dc901`. The 2026-10-19 run used the same patch without the `M121_LOSS_ARMS` arm filter, so both arms ran |

Local directory paths and private tracker references are removed from the
summaries and patch comments. Per-cycle rows, packet captures and daemon logs
are retained privately and not published.
