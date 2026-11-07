# Writer admission comparison data

Curated final results for [complete-frame writer admission](../../writer-byte-budget-2026-11-07.md): all 30 timing cells, allocation rows, artifact provenance and scope. This local record has no hosted Actions run; raw logs are retained separately.

| File | Contents | SHA-256 |
|---|---|---|
| `comparison.json` | Final timing and allocation comparison; accepted correctness cost | 1b832acb7fe6a53d7dae2e49254c6f0ee3a097a49d908ab7b7295b77e6593ee5 |

Build both timed arms with the common harness using `cargo bench --locked -p rustbgpd-transport --features bench-internals --bench outbound_encode --no-run`. Run the immutable executables on CPU 5 with `--bench --sample-size 30 --warm-up-time 1 --measurement-time 2 --save-baseline LABEL` in the eight-leg order recorded in the JSON, with the host lock and canonical quiet gate before each leg. All 30 outbound cells run.

Allocation fixtures use identical local System-wrapper instrumentation on both arms; that instrumentation is absent from production. Source commits and executable hashes identify the measured artifacts. Historical timing failures remain failures; acceptance records the correctness tradeoff.
