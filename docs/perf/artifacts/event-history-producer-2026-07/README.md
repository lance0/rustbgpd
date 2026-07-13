# LAN-393 machine-artifact manifest

This directory is intentionally receipt-only. Generated measurements are not
present until the host is clear and the exact commands in
`docs/perf/event-history-producer-2026-07.md` have completed.

Expected baseline files:

- `environment.txt` — commit, dirty state, compiler, kernel, CPU topology, and
  filesystem/mount details;
- `rustbgpd-baseline-source.tar.gz`, `candidate-environment.txt`, and
  `rustbgpd-candidate-source.tar.gz` — exact clean baseline/candidate identities
  and reconstructable source trees. The candidate identity also proves the
  recorded baseline is its ancestor;
- `source-sha256.txt` — relative-path hashes for the baseline and, once it
  exists, candidate rustbgpd source archives. The full-daemon bgperf2 hash is
  kept in the separate phase-specific source manifest below;
- `microbench-{baseline,candidate}-toolchain.txt` — byte-identical retained
  `rustc -Vv`, `cargo -Vv`, and `protoc --version` identity. Candidate setup
  fails before building if it differs from the baseline;
- `microbench-{baseline,candidate}-host-preflight.tsv` — every load,
  all-CPU-governor, and competing-process poll immediately preceding a
  retained Criterion group while the shared host lock is held;
- `microbench-{baseline,candidate}-perf-environment.txt` and
  `microbench-{baseline,candidate}-perf-host-preflight.tsv` — exact clean phase
  commit/source/toolchain/binary identity plus the fixed load/governor/process
  fence immediately before the retained `perf stat` and `perf record` runs,
  with the shared lock held across both;
- `criterion/lan393_manager_self_time/**/{benchmark,estimates,sample}.json`;
- `criterion/lan393_sqlite_end_to_end/**/{benchmark,estimates,sample}.json`;
- `criterion-comparison/**/new/estimates.json` — candidate estimates;
- `criterion-comparison/**/change/estimates.json` — candidate versus the
  retained `origin-main` baseline;
- `microbench-{baseline,candidate}-perf-bench-build.jsonl` — Cargo
  compiler-artifact messages that identify the exact hashed benchmark
  executable;
- `microbench-{baseline,candidate}-perf-stat.csv` — machine-readable CPU
  counters;
- `microbench-{baseline,candidate}-perf.data` and
  `microbench-{baseline,candidate}-perf-report.txt` — raw sampled profile and
  inspectable symbol attribution;
- `microbench-{baseline,candidate}-perf-completion.txt` and
  `microbench-{baseline,candidate}-perf-SHA256SUMS` — the phase success sentinel
  and aggregate relative-path binding for its identity, preflight, Cargo,
  counter, profile, toolchain, and exact source-archive receipts.

Expected full-daemon proceed-gate files:

- `full-daemon-baseline-environment.txt` — the recorded/current rustbgpd
  baseline, pinned bgperf2 commit, clean states, exact base images, and profiling
  image content digest;
- `bgperf2-source-fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9.tar.gz` — exact
  source tree for the pinned profiling adapter;
- `full-daemon-baseline-image-inspect.json` plus
  `full-daemon-baseline-{identity-validation,builder-provenance,
  runtime-provenance,binary-sha256,image-validation,running-image}.txt` —
  build/run identity, compiler/Cargo/protoc/package provenance, exact OCI
  revision/base labels, and proof that the running container used the validated
  image digest;
- `full-daemon-baseline-source-sha256.txt` — relative-path hashes for the exact
  baseline rustbgpd archive and pinned bgperf2 archive (the candidate phase adds
  its distinct rustbgpd archive). The selected rustbgpd archive is also the
  Docker build context; the mutable checkout is never copied into the image;
- `full-daemon-baseline-host-preflight.tsv` — the retained idle/load,
  all-CPU-governor, and competing-process fence before the build and again
  before bgperf starts, under the shared host lock;
- `full-daemon-baseline-config.toml` plus
  `full-daemon-baseline-{event-history-config,profile-ready,
  processes-pre-attach}.txt` — the generated daemon config, explicit
  EHM-enabled excerpt, and stopped pre-exec profiler barrier;
- `full-daemon-baseline-scenario.yaml`, raw `bgperf.log` and time series,
  normalized `bgperf-result.csv`, and `bgperf-validation.txt` — the generated
  scenario plus fail-closed proof of exactly 2 BIRD peers x 100k prefixes and
  `required=received=200000`;
- `full-daemon-baseline-tester-logs/{10.10.0.3,10.10.0.4}.log` — copies from
  this exact custom bgperf run. The validator requires the source directory's
  complete `*.log` inventory to contain exactly those two regular, non-symlink
  names, verifies the copies are byte-identical, and records their hashes. Any
  case-sensitive `RMT` line other than a `NEXT_HOP` diagnostic fails the
  receipt. The adapter's tester-error value remains in the raw log and is
  recorded as ignored in validator output because it can describe stale
  `/tmp/bgperf2` logs; the normalized CSV contains the run-scoped verdict. The
  pinned BIRD adapter exposes no timeout detector, so its structural zero
  timeout field is retained but is not claimed as evidence. The run receipt,
  tester directories, and source/retained scenario paths reject symlink
  components, and the scenario copy is byte-bound to the exact run;
- `full-daemon-baseline-{metrics,docker-stats}.txt` and
  `full-daemon-baseline-rustbgpd.log` — post-drain outbox integrity/health and
  resource snapshot;
- `full-daemon-baseline-ehm.perf.data`,
  `full-daemon-baseline-ehm.perf-report.txt`, and
  `full-daemon-baseline-ehm.perf-script.txt` — raw and inspectable daemon
  profiles used for the 5% RIB-actor attribution gate.
- `full-daemon-baseline-completion.txt` and
  `full-daemon-baseline-SHA256SUMS` — the success sentinel written only after
  all convergence, outbox, resource, and perf checks, plus an aggregate
  relative-path manifest for every phase-prefixed file and exact source
  archive. Both are required for a complete receipt.

The later offload measurement uses the same manifest with
`full-daemon-candidate-` prefixes. It is not a proceed-gate baseline and the
driver rejects it unless its recorded commit differs from the baseline.

Do not add hand-written result JSON here. Criterion and perf outputs are the
source of truth; the Markdown receipt only summarizes them.
