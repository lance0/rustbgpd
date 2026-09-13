# Isolated import-counter publication diagnostic

This receipt records the 2026-09-13 isolated-generator control of the native
diagnostic at commit `5d0a49cea7f2e80885b296e8edb57c33e31d0848`.
It reuses the original clean build
and binaries and changes only generator CPU placement: the daemon remains on
CPUs 2–3, the generator moves from CPUs 2–3 to CPUs 4–5, and observers remain
on CPUs 8–15. It is a comparison under the observed phase and delivered load,
not a scheduler-cause proof, equal-pressure experiment, general performance
claim, soak qualification, or release gate.

The cell retains 1,000 peers with 400 IPv4 prefixes each, 12 reloads and
two operator calls per reload. The daemon uses two worker threads and the
generator 24. All 24 calls and their actual commit-relative offsets are
retained against the original two-second external criterion and minimum six
complete pairs in the −220 to 0 ms band.

| Configuration | Calls | In-band pairs | Calls over 2 s | Policy stats | Neighbor bodies | Stale rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original co-pinned P | 24 | 12 | 19 | 11/12 failed | 2/12 failed | 370–649 |
| Isolated generator control | 24 | 12 | 0 | 0/12 failed | 0/12 failed | 1–93 in 8 bodies; zero in 4 |

The isolated control returned all 1,000 import and 1,000 export rows for every
policy-statistics call. Calls completed in 301–492 ms. All 12 pairs began in
the required commit-relative band (actual starts −121.107 to −72.318 ms).
Both configurations retain their original **failed strict diagnostic verdict**:
the isolated control failed solely on explicitly stale neighbor observations.
Every reply retained 1,000 neighbors, and the endpoint checks retained 1,000
established sessions. The original P result remains the co-pinned receipt; this
control does not erase its 19/24 late calls or 11/12 failed statistics calls.
The zero-stale criterion is retained as diagnostic evidence, not a new release
gate.

The comparison is limited by different phase timing and delivered pressure:
the whole-capture UPDATE delta changed from 34,582 to 33,221, and median
delivery p50 from 4.079 to 2.667 seconds.
It cannot attribute a scheduler cause, establish equal per-collision work, or
separate manager admission, publication collection, and response delivery.
Counter availability does not establish session progress or an atomic numeric
snapshot. No retry, timing change, acceptance exemption, or extra runtime
knob was introduced.

The complete isolated result is in [native-summary.json](native-summary.json).
The original co-pinned result and its limits are retained in the related
[installed import-counter evidence](../installed-import-counters-2026-09-13/README.md).
