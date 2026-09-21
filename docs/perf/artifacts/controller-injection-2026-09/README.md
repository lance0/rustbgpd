# Controller injection measurement artifacts

These files support the [controller injection receipt](../../controller-injection-2026-09.md).

The retained results distinguish unary RPC completion from receiver completion.
Each cell records exact UPDATE, announcement and withdrawal counts from a passive
BGP receiver, plus full paginated reconciliation through
`ListReceivedRoutes(neighbor_address="0.0.0.0")`. The metrics snapshots independently
retain the daemon's message counters and global attribute-intern table size.

- [Results](results.json) contain all eight completed cells; the
  [compressed evidence](results.tar.gz) preserves their original result,
  reconciliation, metrics and driver-output files. Only configuration directory
  paths are normalized. High-volume daemon logs are represented by original
  hashes and severity counts rather than duplicating hundreds of megabytes.
  Successful mutation authorization audits are counted separately from other WARNs.
- [Provenance](provenance.json) separates baseline and corrected binary hashes;
  [the runtime patch](runtime.patch) identifies the measured production change.
- [Host metadata](host.json) and [contention samples](contention.json.gz) retain CPU
  affinity, preflight utilization, background build classes and CPU-accounting
  samples. They do not establish exclusive access to those cores.
- [Checksums](SHA256SUMS) cover these evidence files and the reproduction driver.

`measure.py` is the receipt's reproduction driver, not an installed controller or
a supported load-generation interface. Run it from the repository root. It reuses
the existing membership receiver and strict UPDATE parser. Its public copy resolves
the checkout from the working directory instead of the measurement machine's path,
removes an unused import and explicitly captures awaited loop predicates; workload,
deadlines and checks are unchanged.

## Reproduce

Use Python 3.11 or newer, a release daemon built from the selected source and Linux
loopback networking. Use an idle lab and do not overlap CLI doctor or workspace tests
that discover running daemons. CPU numbers below must be adapted to the host's
physical-core topology; affinity alone does not isolate background processes.

```bash
cargo build --locked --release --bin rustbgpd
python3 -m venv .venv-controller
.venv-controller/bin/pip install -r examples/python-client/requirements.txt
run_root=$(mktemp -d)
chmod 700 "$run_root"
.venv-controller/bin/python -m grpc_tools.protoc -I proto \
  --python_out="$run_root" --grpc_python_out="$run_root" proto/rustbgpd.proto
cp docs/perf/artifacts/controller-injection-2026-09/measure.py "$run_root/"
taskset -c 12-13 .venv-controller/bin/python "$run_root/measure.py" \
  --daemon "$(realpath target/release/rustbgpd)" --daemon-cpus 4-11 \
  --output "$run_root/distinct-100000" --count 100000 --distinct \
  --peers 1 --phase-cap 180
```

Omit `--distinct` for the shared-attribute case. Use fresh output directories for
100-, 10,000- and 100,000-route cells. The driver rejects existing directories,
uses five-second per-RPC deadlines and caps each mutation phase at 180 seconds.
It validates every route and community after each phase and reaps its daemon.
It does not acquire the repository host lock itself: coordinate the lab before use.
