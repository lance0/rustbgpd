# Snapshot-churn recovery memory evidence (14 October 2026)

Status: **PASS**, 10/10 cells, 80/80 legs. Nine selected cells are from attempt 1; full-VPN widening is from attempt 2.

[comparison.json](comparison.json) contains phase observations and paired summaries. [provenance.json](provenance.json) records source/build/binary/frozen hashes, statuses, sanitized ownership summaries and raw-file digests. The [receipt](../../update-group-recovery-snapshot-churn-2026-10-14.md) gives the workload and limits. Complete archives are retained separately; this compact extract cannot replay original path-based ownership checks.

All eleven original/retry archives were downloadable after the rerun; each downloaded original digest matched its retained archive. This is an observation at 2026-10-14 20:01Z, not a permanent retention guarantee.

| Profile | Cell | Attempt | Original GitHub artifact | ZIP SHA-256 |
| --- | --- | --- | --- | --- |
| full-uc | dataset-reevaluate | 1 | [11913974099](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11913974099) | `087de775f704ade20c8b561adaca5cc0c245db738c57f1c0a28f8dde2476dbcc` |
| full-uc | peer-down | 1 | [11915158399](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11915158399) | `3fd6d5b149459a0b1f38d9c94a6658cbdf78013c762b5feea49a8aed01e17ef6` |
| full-uc | unsynchronized-dirty | 1 | [11914871690](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11914871690) | `5ab61514c65c3e9e3dabc638ed1d7c1b98464bf0bf5122d1e4df959be8a2f7a2` |
| full-vpn | dataset-reevaluate | 1 | [11916027822](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11916027822) | `705df30a08654d6a5ccaa691ecad2a3b062ef14e2d1e0a9e326d916d2d72c040` |
| full-vpn | peer-down | 1 | [11915850865](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11915850865) | `2a89a0a681014f9c8d5591ade79d7f9281530b4a4442903507897dcf40300fb8` |
| full-vpn | unsynchronized-dirty | 1 | [11915837187](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11915837187) | `b61d88f8139bd57eae5dfc339095804fee48385e809398b99267152a617f6e16` |
| full-vpn | widen | 2 | [11924841770](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11924841770) | `b0caf06aea432a51142dc1b0b0ccb4ed7f45480963144893d694ac1275e5b410` |
| ipv4-100k | dataset-reevaluate | 1 | [11912658172](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11912658172) | `6ac768ed1c0109a44d8d2966772e85e80a8e7bf1a821045d653c5f3bff49ee58` |
| ipv4-100k | peer-down | 1 | [11910784815](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11910784815) | `46fe64b877886f43cdd8f2eca59c25fdf55ee11ef8a8e4ee7d1e1a1a07401d53` |
| mixed-widen | widen | 1 | [11917035170](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11917035170) | `a004b492c43069e570405772e19059715fd509a617e126d2b1638ce48760613a` |

The first full-VPN widening attempt is **not qualified**: outer invocation exit 124, seven complete legs and one incomplete final control; no OOM or swap was observed. It is retained separately in both compact JSONs, without a full-cell ratio. The unchanged-head retry passed all eight legs.

Failed original: [11918368676](https://github.com/lance0/rustbgpd/actions/runs/38597855188/artifacts/11918368676), ZIP SHA-256 `b10a5b4e088ca37a7cc816f3e24076b775c88e5dd7bebbfcd22669fb80c00df0`. Its hosted ZIP remained downloadable after the retry.

The measured commit is `be0e13b20321118ed0a15b05c3be0fca589b5d69`. Later containing-main changes are not newly measured or claimed byte-equivalent. Exact run, per-cell attempt/job/artifact identity, seven frozen inputs and raw file digests are in provenance.json. comparison.json contains all 80 qualifying legs / 320 phase samples / 1,600 actual OLD barriers and the separate 31 failed-attempt phase samples.

Peak ratios compare only the two candidate legs paired with that comparator. Baseline absent proof/reset/fallback gauges remain absent. Logical charged bytes are separate from whole-scope cgroup peaks. These data qualify manager-direct unicast/VPN recovery only; private/regroup remains bounded flat fallback, sparse additions remain receiver-proportional, and no whole-daemon, TCP, EVPN, timing or deployment claim is made.
