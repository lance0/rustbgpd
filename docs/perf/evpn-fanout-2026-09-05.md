# EVPN reflector fanout baseline — 2026-09-05

A synthetic Type 2 reflector workload passed at 8–480 receiving peers, with
10,000 selected routes and a separate ten-second churn phase. This receipt
measures commit `e7b78d617f7ee30a6888686bd0d3ea43619d5c0d`; it is an absolute
baseline, not an optimization comparison or a throughput ceiling.

## Results

Each row reports the range across independent runs. Initial convergence is
the slowest receiver's time from its own session establishment to its first
full table. CPU is cumulative daemon user plus system time over the complete
observation window; RSS is sampled daemon memory, in decimal MB.

| Receiving peers | Runs | Slowest initial convergence (s) | Daemon CPU (s) | Peak RSS (MB) |
|---:|---:|---:|---:|---:|
| 8 | 2 | 0.130–0.133 | 0.44–0.47 | 69.1–74.3 |
| 64 | 2 | 0.517–0.522 | 2.02–2.18 | 269.3–275.6 |
| 128 | 2 | 0.959–0.967 | 3.85–4.02 | 479.2–484.7 |
| 256 | 2 | 1.833–1.940 | 7.64–7.89 | 893.4–895.9 |
| 480 | 3 | 3.359–3.769 | 14.70–15.53 | 1627.6–1632.3 |

Every receiver in every accepted run finished with 10,000 distinct keys,
observed exactly 10,000 withdrawals, and reported no parse error or timeout.
All receivers reached their initial full table before either originator
started churn. Both originator sessions remained Established at the final
check, and the daemon's selected table contained exactly the expected RD/MAC
identities. Receiver reports retain distinct-key counts; they do not export
the entire received key set for identity comparison.

## Workload and environment

- Two synthetic iBGP originators, each advertising 5,000 MAC-only Type 2
  routes under its own RD, plus the receiving peers shown above. All peers
  are reflector clients in AS 65000; Ethernet Tag is zero and label is 100.
- Initial injection is unpaced in batches of 40. Each originator waits ten
  seconds, then generates 1,000 route events per second for ten seconds.
  Withdrawal and reannouncement each count as one event: the combined
  expected withdrawal count is 10,000 per receiver.
- No export policy, kernel EVPN instance, or third-party peer is configured.
  The daemon and synthetic peers use the same in-tree wire codec.
- Release daemon with jemalloc, Rust 1.98.0, on an AMD Ryzen Threadripper
  7970X. The Ubuntu 24.04 container was restricted to logical CPUs 16–47,
  64 GiB memory, a PID limit of 4,096, and 65,536 file descriptors. All traffic
  used container loopback; no host ports were published.
- The daemon has eight Tokio workers and each load peer has one. Builds and
  other benchmark runs were held during the measurements; the host was not
  an otherwise empty dedicated benchmark machine.

The CPU observation lasts approximately 31–35 seconds. It includes injection,
the delay, churn, idle time, and receiver-disconnect cleanup while other
receivers still run. It excludes the synthetic peers' CPU and the final CLI
queries. RSS is sampled every 200 ms; short peaks between samples may be
missed. These quantities do not isolate policy evaluation, encoding, route
selection, or churn CPU.

## Interpretation

CPU and memory rise approximately with receiver count in this shape. The
existing per-peer EVPN path completes this workload at hundreds of peers;
the result does not establish thousands of VTEPs, VTEP dataplane scale,
heterogeneous export policies, overlapping originators, or behavior at a
saturation limit. It also does not price the much larger per-peer route
tables in the separate historical M33 workload.

The source still scans peer input tables during selection and keeps per-peer
outbound EVPN state. Selection deferral already coalesces work while active,
and unchanged winners and outbound rows suppress redundant distribution.
Ordinary nondeferred input chunks retain per-key selection and per-destination
policy/encoding work. This baseline supplies a repeatable shape for measuring
an announcer index or further coalescing; it does not isolate either as the
dominant cost or justify changing the update-group scope by itself.

## Reproduction and raw evidence

The [fanout runner](../../bench/evpn-load/README.md) documents the release build
and isolated container invocation. Run the default workload twice for each
receiver count and a third time at 480. The generator adds only an optional
`--churn-delay-sec` wait, defaulting to zero; daemon behavior is unchanged.

The [raw archive](../artifacts/evpn-fanout-2026-09-05.tar.gz) contains the exact
measurement script, generator patch, source and binary hashes, all accepted
run configurations, individual receiver reports and logs, daemon logs, final
CLI snapshots, metrics, and CPU/RSS samples. Its SHA-256 is
`84705c8fc1d0ac8192a5bc2cad77018c3bf9e03269bd5e12113dd7d2e50dfbdb`.
The maintained runner adds stricter input validation and exact selected-key
checks; those checks were also applied to all saved measurements.

An exploratory run overlapped initial loading and churn at 480 receivers.
It ended at the expected table size but some receivers saw fewer withdrawals,
so it was excluded. A run interrupted during a concurrent image build was
also excluded. Neither contributes timing or correctness claims here.
