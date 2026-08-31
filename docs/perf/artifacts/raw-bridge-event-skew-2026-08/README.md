# Raw bridge event-skew observations

Measured 2026-08-31 at source `fda556c7bc6f4a80eea1918e9b5c8b3864482f69`.

This is one descriptive 4,000-pair run for each of six pinned
kernel/profile tuples. Every run completed all 2,000 IPv4 and 2,000 IPv6
pairs. Every pair was FDB-first, with zero missing FDB or neighbor events,
duplicates, wrong-tenant events, ambiguous identities, or late FDB events.

Absolute FDB-to-neighbor inter-arrival values are shown below. Every signed
`neighbor-minus-fdb` value was positive.

| Profile | Guest kernel | Family | p50 | p95 | largest observed |
| --- | --- | --- | ---: | ---: | ---: |
| serial-1 | Jammy Linux 5.15 | IPv4 | 29.344 µs | 53.771 µs | 123.095 µs |
| serial-1 | Jammy Linux 5.15 | IPv6 | 1.281 ms | 3.758 ms | 7.378 ms |
| serial-1 | Noble Linux 6.8 | IPv4 | 44.537 µs | 2.002 ms | 2.422 ms |
| serial-1 | Noble Linux 6.8 | IPv6 | 10.236 ms | 11.489 ms | 14.434 ms |
| burst-8 | Jammy Linux 5.15 | IPv4 | 20.250 µs | 176.555 µs | 458.127 µs |
| burst-8 | Jammy Linux 5.15 | IPv6 | 6.698 ms | 12.478 ms | 120.296 ms |
| burst-8 | Noble Linux 6.8 | IPv4 | 11.117 µs | 138.367 µs | 2.145 ms |
| burst-8 | Noble Linux 6.8 | IPv6 | 13.476 ms | 16.116 ms | 19.040 ms |
| burst-32 | Jammy Linux 5.15 | IPv4 | 9.504 µs | 56.655 µs | 1.969 ms |
| burst-32 | Jammy Linux 5.15 | IPv6 | 21.269 ms | 41.684 ms | 61.014 ms |
| burst-32 | Noble Linux 6.8 | IPv4 | 15.473 µs | 161.542 µs | 2.324 ms |
| burst-32 | Noble Linux 6.8 | IPv6 | 23.149 ms | 33.421 ms | 40.119 ms |

The post-freeze late-neighbor/delete diagnostics were serial-1 Jammy 1/3998,
serial-1 Noble 1/3998, burst-8 Jammy 8/3984, burst-8 Noble 8/3981, burst-32
Jammy 32/3936, and burst-32 Noble 32/3922; late FDB remained zero. These events
occur after samples freeze and do not change the measured denominator.

The compact [`results.json`](results.json) embeds the exact reports, request,
host, guest, observer, and content-hash provenance for all six runs.
[`SHA256SUMS`](SHA256SUMS) seals `README.md` and `results.json`. The raw VM
receipts remain outside the repository.

One run per tuple does not establish variance, a worst-case bound, a freshness
window, a kernel regression, or production behavior. No acceptance threshold
was defined for this descriptive campaign.
