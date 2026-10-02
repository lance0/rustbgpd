# Prefix-index retirement counters (October 2026)

Small batches of prefix keys reduced retirement instructions by **62.4%** and
CPU cycles by **47.0%** in a 400,400-entry fixture measured on 2026-10-02.
This measures `FamilyPrefixMap::retire_with`, including its checkpoint cost.
It does not establish an end-to-end policy reload or IRR refresh improvement.

## Change and fixture

The baseline restarts a trie iterator for every prefix and then traverses the
trie again to remove that prefix. The candidate collects up to 32 keys on the
stack per iterator. It checkpoints each collected key and retains the existing
checkpoints before and after every removal. Trie branches are still pruned
incrementally; consuming the trie iterator would defer structural cleanup to
the final destructor.

The fixture inserts 400,400 distinct IPv4 `/24` prefixes starting at
`10.0.0.0/24`, advancing the network address by 256. Each index value is a
`SmallVec<[(u32, u32); 1]>` containing one path/slot pair. The checkpoint takes
a mutex, reads a monotonic clock, and updates its service timestamp after
25 ms. It models checkpoint bookkeeping, without queued operator requests.
Population and final empty-table destruction are outside the enabled counters.
Control acknowledgements bracket retirement; minimal pipe synchronization
inside those boundaries is included.

The baseline is `326dc11218f70f75d1a9a103118682d3ab0b1a5a`. The candidate is
the `crates/rib/src/prefix_map.rs` change accompanying this receipt. Its full
source SHA-256 is `a6d853606ccbbe738fe54e70ed62be327073fab5fb242db36b22e4aea7222362`;
the baseline source hash is
`69e11c2e580dab1634a4a45897e5f16c9ff8b695124f38116eeba3cae967c160`.

## Results

All six cases exited 0. Both hardware events had 100.00% running coverage in
every case, with no multiplexing adjustment. The launcher, measurement process,
and fixture inherited affinity to CPU 31. Runs were serialized under the
existing benchmark lock, with no concurrent local build or daemon lab.

| Run | Arm | Instructions | CPU cycles | Checkpoints |
|---|---|---:|---:|---:|
| 1 | Baseline | 1,951,109,408 | 477,288,497 | 800,800 |
| 2 | Candidate | 733,567,229 | 253,662,018 | 1,201,200 |
| 3 | Candidate | 733,566,905 | 252,471,110 | 1,201,200 |
| 4 | Baseline | 1,951,109,108 | 476,496,625 | 800,800 |
| 5 | Baseline | 1,951,109,130 | 476,097,283 | 800,800 |
| 6 | Candidate | 733,567,160 | 252,514,148 | 1,201,200 |

Median instructions were 1,951,109,130 versus 733,567,160; median cycles were
476,496,625 versus 252,514,148. These are separate counter comparisons, not
elapsed-time measurements. IPv6, Add-Path spill values, real readiness queue
service, and whole-daemon reloads are outside this fixture's scope.

The first launcher attempt rejected a NUL-terminated control acknowledgement
before starting retirement. After correcting acknowledgement parsing, the six
retained cases completed. That startup failure contributes no counter row.

## Environment and reproduction

The CPU was an AMD Ryzen Threadripper 7970X (32 cores, 64 threads), running
Linux `7.0.0-30-generic` and `perf 7.0.12`. Compilation used
`rustc 1.99.0 (b940084d7 2026-09-28)`, LLVM 23.1.1, edition 2024 and `-O`.
The fixture links the actual wire, prefix-trie, ipnet, and smallvec libraries.
The standalone fixture uses Rust's default system allocator.
[Provenance](artifacts/prefix-retirement-2026-10/provenance.json) records compiler
flags, normalized input paths, and source, dependency and binary hashes.
Dependency artifacts came from a `release-prof` daemon build at
`370e211b95ec3e4a7b07556146e31dd02f391ea6`; that profile inherits release LTO
and one codegen unit, retains symbols, and sets debug information to level 1.

Use a scratch directory for generated files. Extract `prefix_map.rs` at the
baseline revision as `baseline.rs` and copy the matching candidate source as
`candidate.rs`. Copy the saved [fixture](artifacts/prefix-retirement-2026-10/fixture.rs)
to `baseline-main.rs`; replace its `baseline.rs` module path with `candidate.rs`
to create `candidate-main.rs`. Verify their hashes against the provenance file.
No production module copy is checked into the receipt.

Build the pinned dependencies in an isolated checkout with
`cargo build --locked --profile release-prof --bin rustbgpd`. Set `PROBE_DEPS`
to that checkout's `target/release-prof/deps`, then compile both fixtures from
the scratch directory:

```python
import os
import pathlib
import subprocess

deps = pathlib.Path(os.environ["PROBE_DEPS"])
for arm in ["baseline", "candidate"]:
    command = ["rustc", "--edition=2024", "-O", "-A", "dead_code",
               "--crate-name", "prefix_retirement_probe",
               "-L", f"dependency={deps}"]
    for name in ["ipnet", "prefix_trie", "rustbgpd_wire", "smallvec"]:
        matches = list(deps.glob(f"lib{name}-*.rlib"))
        assert len(matches) == 1, matches
        command.extend(["--extern", f"{name}={matches[0]}"])
    command.extend([f"{arm}-main.rs", "-o", arm])
    subprocess.run(command, check=True)
```

Copy [measure.py](artifacts/prefix-retirement-2026-10/measure.py) into the same
scratch directory and run `python3 measure.py` when CPU 31 is available and
other local benchmarks, builds and labs have stopped. It uses
`/tmp/rustbgpd-bench.lock`, enables `instructions:u,cycles:u` after population,
and disables them after retirement. Compare the generated records with the
retained [counter rows](artifacts/prefix-retirement-2026-10/counters.csv).
Fresh build hashes can differ with checkout paths; retain their provenance
and verify the source hashes before interpreting a new measurement.
