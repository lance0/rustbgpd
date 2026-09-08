# Dual-stack policy-reload reduction artifacts

These public copies support the [dated receipt](../../ixp-dualstack-policy-noops-2026-09.md). The 200-member filtering run passed the unchanged v2 operating gate after the redundant-policy update fix. The single 700-member run completed all receiver reloads but failed that gate on 12 health timeouts and two warning records. Earlier failed measurements remain in the [historical artifact directory](../ixp-dualstack-2026-09-08/README.md).

Each of `200-50-F/` and `700-50-F/` retains the exact wrapper, gate, driver/gate exits, binary checks, source provenance, generated inputs, full receiver and daemon logs, accepted quiet samples, health stderr and CSVs, RIB-query CSV, RSS samples, and VmHWM. Runtime persistence and config-history files are omitted because they are not measurement instruments. No warning or measurement rows are removed. Root `wrapper.exit` records the 200-member wrapper result; `700-50-F/wrapper.exit` records the failed 700-member wrapper result.

`build/daemon/` records the actual ordinary daemon build at `8264351811a80301e747ad217d751942056c0b3c`, including the complete compressed Cargo JSON output, selected executable artifact, command, environment, source snapshots, toolchain, and exits. `build/reused-tools/` retains the original f2 build records for the CLI and harness. That earlier release artifact inventory also includes the old daemon; the measured new daemon is identified exclusively by `build/daemon/` and the cell's binary hashes. `200-50-F/reused-binaries.json` states which binaries were reused and which source paths were compared.

`phase-comparison.json` preserves the four phase records from the earlier 200-member diagnostic and the four new records. It reports medians across reloads within each run, not independent trials. The baseline raw daemon log remains in `../ixp-dualstack-2026-09-08/diagnostic-200-50-F/rustbgpd/daemon.log.gz`.

`phase-comparison-700.json` contains the one completed old generation and all four new generations, with original log hashes and public log locations. It does not synthesize missing baseline cycles.

Private source, build, toolchain-home, preparation, output, and host-lock roots are replaced with distinct neutral paths under `/tmp/policy-noops-*` and `/tmp/measurement-user`; the host name becomes `measurement-host`. Generic workload paths such as `/tmp/ixp-rustbgpd` remain unchanged. Timestamps, addresses, counts, warning text, source/executable hashes, and measurements are retained. Daemon logs, gate evidence, and Cargo JSON output use gzip with a zero timestamp.

`original-sha256.json` identifies original local bytes before path replacement or compression, keyed by exported relative filename. For gzip files the original hash covers the uncompressed original. `SHA256SUMS` covers exported public bytes. Hashes embedded in original build/provenance records continue to identify original source or executable bytes; they are not public-copy checksums.

For a fresh measurement, use a clean source checkout at `/tmp/policy-noops-source`, place the bound regular executable files at the three paths expected by the matrix driver, and copy the retained `run.sh`, `gate.py`, and `reused-binaries.json` to `/tmp/policy-noops-prep`. Run that wrapper only when `/tmp/policy-noops-200-50-F` is absent. The 700-member wrapper uses `/tmp/policy-noops-700-prep` and a fresh `/tmp/policy-noops-700-50-F` directory with its recorded larger workload. It preserves the existing host admission and cooldown and applies a 900-second outer abort ceiling. An interrupted runner needs explicit owned-process cleanup; no success is inferred from a timeout.

To replay only the retained analysis, copy this directory to a temporary location and decompress both `200-50-F/rustbgpd/daemon.log.gz` and `700-50-F/rustbgpd/daemon.log.gz` there. From the copied directory:

```sh
python3 200-50-F/gate.py 200-50-F 200 114400 57200 170 32
```

This reads the retained instruments; it does not start a daemon or repeat a measurement. Expected result: `pass=true`, empty `errors`, exit 0. Replay the 700-member analysis separately:

```sh
python3 700-50-F/gate.py 700-50-F 700 400400 200200 600 32
```

Expected result: `pass=false`, exit 1, with the three errors quoted in the receipt. Both full results include retained warning classifications. Do not treat the 700-member native driver zero exit as operating acceptance.
