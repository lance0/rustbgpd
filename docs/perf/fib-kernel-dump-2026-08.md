# Linux FIB kernel-dump scaling receipt (August 2026)

**Measured on:** 2026-08-30 UTC at exact v0.68.0.

## Result

Linux 6.17 strict table filtering changes the kernel-dump cost from the size of
the host IPv4 FIB to the number of requested tables and returned rows. The
measured p50 crossover moved from 2 tables with no unrelated routes to 16 at
1,000 unrelated routes; filtered requests remained faster through all 64
tables at 5,000 and 20,000 unrelated routes.

This table shows the directly comparable `K=64` cell; timings are p50/p95:

| Unrelated rows | Returned global/strict | Global IPv4 dump | 64 strict table dumps | Largest faster strict K (p50) |
|---:|---:|---:|---:|---:|
| 0 | 128 / 128 | 0.136 / 0.180 ms | 2.224 / 2.452 ms | 2 |
| 1,000 | 1,128 / 128 | 0.925 / 1.072 ms | 2.185 / 2.325 ms | 16 |
| 5,000 | 5,128 / 128 | 4.132 / 4.189 ms | 1.975 / 2.104 ms | 64 |
| 20,000 | 20,128 / 128 | 16.311 / 16.901 ms | 2.104 / 2.137 ms | 64 |

All 28 cells, including exact returned counts and p50/p95 nanoseconds, are in
[`results.json`](artifacts/fib-kernel-dump-2026-08/results.json). Exact host,
toolchain, image, harness, and result hashes are in
[`metadata.txt`](artifacts/fib-kernel-dump-2026-08/metadata.txt).

## Measurement contract

The raw Python standard-library harness creates a fresh `CLONE_NEWNET`
namespace and refuses to write results unless it starts with zero IPv4 routes.
It installs one `RTPROT_BGP` and one foreign `RTPROT_STATIC` blackhole `/32` in
each of 64 managed tables, then 0/1,000/5,000/20,000 static `/32`s in unrelated
table 2000. For each foreign size it compares one global IPv4 `RTM_GETROUTE`
dump with sequential strict dumps of K=1/2/4/8/16/32/64 managed tables.

Each cell has 3 warmups and 25 alternating-order timed passes. Percentiles use
nearest rank over `time.perf_counter_ns`. Every pass must return exactly
`128 + unrelated` global rows and `2 * K` filtered rows. Before timing, the
harness also proves that a non-strict table request sees all 128 rows, while a
strict request sees only its two rows and carries `NLM_F_DUMP_FILTERED`; any
netlink error, truncated reply, cardinality mismatch, or `NLM_F_DUMP_INTR`
aborts without output. The namespace and its routes disappear with the
harness process, so no host route is mutated.

The retained run used exact v0.68.0 source
`d3e6c3571116261c47039b603ec64db14100ea0e`, AMD Ryzen Threadripper 7970X,
Linux 6.17.0-35-generic, Python 3.13.5, and rustc 1.98.0. The Linux
[`NETLINK_GET_STRICT_CHK` documentation](https://docs.kernel.org/userspace-api/netlink/intro.html#strict-checking)
defines the opt-in strict-validation contract exercised here.

## Boundary and reproduction

This is a kernel scaling receipt, not a whole reconcile latency or shipped-code
speedup claim. It measures IPv4 blackhole `/32`s without nexthops, payload
attributes, concurrent route churn, or userspace projection. Production uses
one AF_UNSPEC request per managed table and retains the legacy IPv4 plus IPv6
global fallback, so these absolute timings must not be substituted for daemon
latency or generalized to IPv6 and realistic unicast route shapes.

From an exact checkout, with Docker permission and no other host benchmark:

```bash
image=rustbgpd-netns-tests@sha256:f0633621795e369df02a69802a74dc11aa3ecf46a225c72254b4942dac699e64
out="$PWD/docs/perf/artifacts/fib-kernel-dump-2026-08"
mkdir -p "$out"
docker run --rm --privileged --network none \
  -v "$PWD:/repo:ro" -v "$out:/out" "$image" \
  python3 /repo/bench/run-fib-kernel-dump.py \
  --output /out/results.json --metadata-output /out/metadata.txt \
  --source-sha d3e6c3571116261c47039b603ec64db14100ea0e \
  --provenance "$image" --rust-toolchain "$(rustc --version)"
```
