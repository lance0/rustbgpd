# Recovery capture scan evidence (15 October 2026)

**PASS — component qualification at recorded source.** Measured source: `5b905336750ee5a8fb9a4e411f2d8d94249a7d7f`. [Run 38659117804](https://github.com/lance0/rustbgpd/actions/runs/38659117804), started at `2026-10-15T00:16:52Z`, supplied all 18 cells and 72 timed legs; all three outer invocations exited zero and all three measured profile jobs succeeded. This does not measure containing main or qualify production activation.

- [rows.jsonl](rows.jsonl) preserves the exact 72 extracted rows, byte for byte. SHA-256: `1ec0d8579021cdaaf7503b1557d14c4a2058b3e5255c578a6d6b3caa490e9396`.
- [comparison.json](comparison.json) contains every 18-cell summary, both samples per arm, CPU zero/null values and exact logical credit.
- [provenance.json](provenance.json) preserves source/build/binary/instrumentation hashes, all 216 original file digests, sampled ownership/safety summaries, the separate failed premeasurement attempt and the valid intermediate measurement.
- The [receipt](../../update-group-recovery-capture-scans-2026-10-15.md) explains workload, phase boundaries and limits.

Each leg captures one target beside one anchor; all other records are empty. These are component scans and complete captures, not actor/fleet, readiness, final-wire, daemon, soak or activation evidence. Logical credit is not RSS. CPU ticks resolve only 10 ms; zero samples and null ratios are intentional. Callback/comparison counts cover only the separate shape pass; complete-capture timings include reservation, population, sealing and their per-key search costs without counting their comparisons.

## Measured archives

| Profile | Original GitHub artifact | ZIP SHA-256 |
| --- | --- | --- |
| full-uc | [11937647682](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11937647682) | `1aaa65b3118a93cbe38d07a14fbc8aed39ddb25798567682c86456f67e11e3ef` |
| full-vpn | [11938506460](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11938506460) | `b5c5e891dc4d763b89914b295c3ffe61c8016506c7a3e0c2c585a94863665957` |
| evpn-soak | [11938486727](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11938486727) | `234e3fc14b826b4725f9ae4a6f77ec4a5af08ca9dc8181fd95370cbcfcde2eb8` |

Original archives were checksum-verified and are retained separately. Hosted links use 30-day retention and can expire. Compact summaries cannot replay original path-based ownership checks; source paths in provenance are repository-relative and raw file paths are archive-relative.

## Failed premeasurement history

The source `5cc4646a255f627a7e1a34fc8ee854f179e93940` [run 38654266292](https://github.com/lance0/rustbgpd/actions/runs/38654266292) obtained no timing samples: builds passed, then all three scans rejected missing hosted identity after privilege/environment sanitization. It is not pooled with the measured rows and supplies no header-size or cost claim.

| Profile | Preserved original artifact | ZIP SHA-256 |
| --- | --- | --- |
| full-vpn | [11935874041](https://github.com/lance0/rustbgpd/actions/runs/38654266292/artifacts/11935874041) | `845506858b8f2878a81c4b7b95b1223511c518b82e28b59cd0733c7a402ad847` |
| full-uc | [11936272226](https://github.com/lance0/rustbgpd/actions/runs/38654266292/artifacts/11936272226) | `77c244fa3cf77ff406e0f33bcd799e2b4a5a7fc7904a1a495b51e479af58b237` |
| evpn-soak | [11935749296](https://github.com/lance0/rustbgpd/actions/runs/38654266292/artifacts/11935749296) | `397c32ca26e75a478450644773b9c99fafe394177a157f5969fd8831e21d0dad` |

## Valid intermediate history

The independently verified `1b26a0a11130f25305788662a81adb0982284362` [run 38654928836](https://github.com/lance0/rustbgpd/actions/runs/38654928836) passed 18 cells and 72 timed legs. Two later harness failure-path fixes required the fresh final-head run above. Its samples are excluded from every current numeric summary and from rows.jsonl; the original data and archives remain separate, without a measured-equivalence claim.

| Profile | Preserved original artifact | ZIP SHA-256 |
| --- | --- | --- |
| full-uc | [11937080396](https://github.com/lance0/rustbgpd/actions/runs/38654928836/artifacts/11937080396) | `fcdb445b3333bd1654edb24775825a8ed7319664a82d21a6064b43d1a192b402` |
| full-vpn | [11937055257](https://github.com/lance0/rustbgpd/actions/runs/38654928836/artifacts/11937055257) | `b96ea044a220b700fafda99e3643389b04f53bd1b8114a2935750386d315748a` |
| evpn-soak | [11936064447](https://github.com/lance0/rustbgpd/actions/runs/38654928836/artifacts/11936064447) | `23b4a379768e33a381ea2d92545784768592c412f974ef4d21aa6192599fd1a3` |
