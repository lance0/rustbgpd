# EVPN fanout runner

`fanout.py` measures one rustbgpd route reflector with two synthetic Type 2
originators and 1–480 receiving peers in an isolated Linux network namespace.
It uses Python 3.11 or newer and the standard library.

## Build and run

Build the daemon, CLI, and load tools from the same revision on Linux with a
glibc compatible with Ubuntu 24.04. The default release build uses jemalloc;
do not substitute a debug or `--no-default-features` build when comparing runs.

```bash
cargo build --locked --release -p rustbgpd -p rustbgpctl -p rustbgpd-evpn-load --bins

# Prepare the small runner image before measuring.
docker build -t rustbgpd-evpn-fanout - <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends python3 libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE

mkdir -p fanout-results
docker run --rm --network none --ulimit nofile=65536:65536 \
  -v "$PWD/target/release:/load-bin:ro" \
  -v "$PWD/bench/evpn-load/fanout.py:/runner/fanout.py:ro" \
  -v "$PWD/fanout-results:/results" \
  rustbgpd-evpn-fanout \
  python3 /runner/fanout.py --bin-dir /load-bin \
    --receivers 8 --routes 5000 --churn-seconds 10 \
    --churn-delay-seconds 10 --out /results/receivers-8-run-1
```

The container has loopback only, with no published host ports. All BGP and
metrics addresses are in `127.77.0.0/16`; gRPC uses a Unix socket in the run
directory. The container's default root user can bind the peers' port 179.
No privileged container or host networking is needed. Run only one case per
container, and choose a new output directory each time; an existing directory
is rejected. Mount a snapshot of the binaries if other work could rebuild them.
The default `--bin-dir` is `target/release` relative to the working directory
when running the script directly in an already isolated namespace.

For a short correctness smoke, use `--receivers 2 --routes 40
--churn-seconds 2`; use `--churn-seconds 0` for injection only. Run repeated
cases at receiver counts such as 8, 64, 128, 256, and 480 with otherwise
identical arguments. Avoid concurrent builds or other benchmarks, and retain
the source revision, binary checksums, container image ID, CPU, memory, and
run arguments alongside any published results.

## Workload and correctness

The two originators use distinct IPv4-based RDs and deterministic MAC-only
Type 2 keys, Ethernet Tag 0, label 100, and AS 65000. Every peer is an iBGP RR
client. Initial injection is unpaced, in batches of 40 routes. Each source
then waits the configured delay and optionally churns at 1,000 route events
per second: a withdrawal and reannouncement each consume one event. The
reflector has eight Tokio workers; each synthetic peer has one.

The runner deliberately accepts only this workload shape:

- `--receivers`: 1–480.
- `--routes`: a positive multiple of 40 within the tester's 24-bit unique MAC
  space, starting at 40. The default is 5,000 per originator, or 10,000 total.
- `--churn-seconds`: zero or a positive multiple of two. Together with full
  batches, this makes the exact expected withdrawal count per receiver
  `1000 * churn_seconds`, summed across both originators.
- `--churn-delay-seconds`: a nonnegative integer, default 10. Increase it if
  the initial table does not finish before either source starts churn.

A successful run requires every monitor to exit successfully, converge, avoid
timeout and UPDATE parse failures, retain exactly twice the per-originator
route count as distinct final keys, and receive the exact withdrawal count
(including zero for injection-only runs). For churn runs, each receiver's first
full-table timestamp must precede both sources' churn start timestamps. This
check combines monitor convergence durations with the peers' timestamped logs;
it is a verification after the run, not a synchronization barrier.

The final CLI checks require both source sessions to be `Established` and the
reflector's selected table to contain exactly the expected RD/MAC keys, all
MAC-only Type 2 with Ethernet Tag 0. Monitors deliberately disconnect after
their observation windows; their final neighbor state is not required to be
`Established`. The monitor reports distinct-key counts rather than exporting
its complete key set, so the full identity comparison applies to the
reflector's selected table. These checks are a synthetic control-plane test,
not proof of remote kernel installation or traffic forwarding.

## Measurements and artifacts

Each monitor allows 180 seconds for convergence, requires one second of
stability, then observes for `churn_delay_seconds + churn_seconds + 10` seconds.
The runner samples the daemon's Linux `/proc` CPU time and RSS every 200 ms
until all monitors exit. It terminates and reaps its remaining processes on
success or failure.

`cpu_sec` is cumulative daemon user plus system CPU time over the whole
observation window. It includes initial injection, the delay, churn, idle
time, and monitor-disconnect cleanup that occurs while other monitors still
run. It is **not churn-only CPU**, and it does not include the testers' or
monitors' CPU. `peak_rss_bytes` is sampled daemon RSS, not combined workload
memory. Initial convergence is measured separately for each receiver from
its own session establishment to its first full table. None of these values
is a sustained throughput ceiling or evidence for thousands of VTEPs.

The new output directory contains:

- `summary.json`: shape, correctness, convergence range, withdrawal range,
  whole-window CPU/elapsed time, and peak sampled RSS; also printed to stdout.
- `monitor-*.json` and `monitor-*.log`: individual wire-observer reports and logs.
- `tester-*.log`, `daemon.log`, and their stdout files: process diagnostics.
- `selected.json`, `neighbors.json`, `metrics.txt`, and `samples.json`: final
  CLI snapshots, metrics, and raw resource samples. CLI stderr is retained
  in `neighbors.stderr` and `selected.stderr`.
- `config.toml` and `state/`: generated configuration and runtime state.

Any failed check exits nonzero. Process or parsing failures write a failed
summary with an error and retain the available raw artifacts; preserve those
logs when diagnosing the failure. Move load-bearing raw evidence into
`docs/artifacts/` when writing a dated performance receipt; generated run
directories do not belong in Git.
