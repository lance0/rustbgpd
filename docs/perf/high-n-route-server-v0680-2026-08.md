# High-N route-server v0.68.0 receipt — 2026-08-30

Two exact-source runs extended the route-server session/convergence envelope
beyond the routine 1,000-peer receipt. Both completed with the release daemon
built from v0.68.0 commit
`d3e6c3571116261c47039b603ec64db14100ea0e` and the AS_TRANS-capable scale
harness at `1d14149b`.

| Peers | Sessions established | Convergence | Settled daemon RSS | Peak daemon + harness RSS |
|---:|---:|---:|---:|---:|
| 2,500 | 3.5 s | 33.2 s | 607,228 KiB | 1,152,796 KiB |
| 5,000 | 9.6 s | 150.9 s | 932,416 KiB | 2,278,576 KiB |

The [compact artifacts](artifacts/high-n-route-server-v0680-2026-08/README.md)
retain pass status, event timing, settled RSS summaries, and provenance.

These are one-run absolute observations on one host, not scaling-law inputs.
They do not justify interpolation or extrapolation, and the harness process is
a material part of the combined RSS figure. The original daemon binary is not
bundled; its recorded hash preserves the measured identity.
