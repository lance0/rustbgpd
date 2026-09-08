# Dual-stack operating receipt artifacts (2026-09-08)

These public copies support the [operating receipt](../../ixp-dualstack-2026-09-08.md). Four 200-member cells are exported: accepted 90/10 P and F, accepted-after-review 50/50 P, and failed 50/50 F. The acceptance campaign stopped after the fourth cell; its eight planned 700-member cells were not run. The fourth cell retains its failed analysis: two of 1,805 health commands exited 1, despite successful route-delivery and RIB-query results. Command stderr was not captured in that acceptance cell. A separate diagnostic run captured three RIB-manager 200 ms probe timeouts; its evidence is exported separately under `diagnostic-200-50-F/`. The initial preflight rejection is retained separately in `preflight-symlink-rejected/`; the missing status reported by its analysis reflects an attempt that stopped before a daemon started.

Each cell retains driver exit/log, gate evidence, binary verification, and the matrix runner's `rustbgpd/` directory: status, harness log, compressed daemon log, provenance, accepted quiet samples, RSS/VmHWM, query/probe CSVs and generated configuration/policy inputs. Runtime config-history and persistence files are omitted; they are not campaign instruments. No warning or measurement rows are removed.

`build-binding.json` records the three executable identities and profiles. `binaries.sha256` identifies executable bytes; it is not a checksum list for this directory. `original-sha256.json` records the SHA-256 of each original local file before replacement or compression, keyed by its exported relative name. For every `.gz` file, that original digest covers the uncompressed original file. `SHA256SUMS` covers exported public bytes; these digests intentionally differ when content was sanitized or compressed.

Private path roots and the host name are replaced. The exported regression script additionally uses its own directory for `PREP` and the adjacent third-cell directory for `SOURCE`, so its inputs resolve within this receipt. Its original and adapted hashes are recorded separately. Distinct build source, build output, campaign source, immutable binary, preparation and output roots remain distinct under `/tmp/dualstack-*`; the host is `measurement-host`. The host-lock path becomes `/tmp/dualstack-host.lock`. Generic scenario paths such as `/tmp/ixp-rustbgpd` are workload configuration and remain unchanged. Timestamps, route addresses, counts, source/executable hashes, warning text and measurements are retained. Daemon logs and all `evidence*.json` files use gzip with a zero timestamp.

To reproduce, place the recorded source at `/tmp/dualstack-source`, install matching regular executables at the three paths in `run.sh`, and place `run.sh` and `gate.py` in `/tmp/dualstack-campaign-prep`. Use a fresh output directory:

```sh
CAMPAIGN_ARTIFACTS=/tmp/dualstack-campaign bash /tmp/dualstack-campaign-prep/run.sh 200-validation-90-P
```

The retained `plan.tsv` records the original plan, not a completed campaign or a queue of approved runs. The runner requires each previous cell to pass before continuing. That condition failed on the fourth 200-member cell, so none of the eight planned 700-member acceptance cells ran. The published hashes describe the measured binaries; rebuilding can produce different hashes and must receive fresh provenance. A preflight symlink rejection is separate from measured cell failure.

## Analysis revision

`gate-v1.py` preserves the original classifier; `gate.py` is v2. `gate-revision.json` records their original hashes, the review identity and negative-check results. `test_gate_v2.py` and `gate-v2-tests.json` retain the regression exercise. This is analysis-checker validation, not an additional measured cell. The retained revision reason compresses two different intervals: warnings followed final delivery completion by more than 20 seconds, but followed their own peer-down events by only 0.024–3.980 ms, as recorded in `warning-review.json`.

Each of the first three cells preserves the original and reviewed analyses as `evidence-v1.json.gz` and `evidence-v2.json.gz`. `evidence.json.gz` contains the current v2 result. In the third cell, `wrapper-v1.exit` is 1: the first analysis rejected 102 teardown writer warnings. The warning review retains their raw events and matching peer-down events. V2 only accepts `BrokenPipe` after teardown begins and after the same peer is down. The original driver exit and measured logs are unchanged; no benchmark was rerun.

The first two cells were reanalyzed without changing their acceptance. Their initial exported `evidence.json` bytes are now retained under `evidence-v1.json.gz`; checksums identify the revised inventory. Hashes inside the warning review and gate-revision metadata refer to original local bytes, before public path substitution. Public-file verification uses `SHA256SUMS` instead.

## Replay the analysis regression

Copy this artifact directory to a temporary directory before replay. Decompress logs and evidence in the copy; the published compressed files remain unchanged:

```sh
find . -name '*.gz' -exec gzip -dk {} +
python3 test_gate_v2.py
```

The test imports the preserved `gate-v1.py` and current `gate.py`, verifies the actual third-cell classification, and checks the three negative cases. To use the campaign runner's previous-cell gate with an exported cell, likewise decompress its `evidence.json.gz` first.

## Diagnostic exports

`diagnostic-200-startup-failed/` preserves the inherited-umask startup refusal: the runtime directory was group-writable, the daemon rejected it before harness launch, and the driver was terminated during cooldown (exit 143). Its metadata and logs establish a preparation failure without reload measurements.

`diagnostic-200-50-F/` records a completed diagnostic with the same pinned ordinary binaries and a driver-only stderr-capture change. Driver/harness succeeded, but frozen gate v2 failed on 3 of 1,801 health commands; all 846 RIB queries succeeded. Every failed health call reports `RIB manager probe timed out (200ms deadline)`. The driver diff, executable identities, all instruments and compressed failed analysis are retained.

`diagnostic-700-50-F/` records the single larger characterization. Only reload 1 completed receiver delivery. The daemon ignored reload 2's SIGHUP while its first generation remained in flight; the harness then failed its native 600-second no-progress watchdog with 0/600 changed observers complete. Health failed 111/9,835 times with the RIB 200 ms timeout; all 4,378 RIB commands exited 0. The instruments, driver diff and binary binding are exported. The outer driver exited 0 after cooldown; this is distinct from the failed per-cell status and harness exit of 1. `binary-check-after.log` verifies all three binaries remained unchanged. The unchanged v2 checker exited 1 and retained its full result in `evidence.json.gz`.

These diagnostics preserve the acceptance failure; they do not replace it or establish a completed 700-member acceptance result. The diagnostic driver diff is explicit because it differs from the clean acceptance runner. Original hashes cover the source files; exported checksums cover their public copies. The 200-member gate analysis used a temporary directory linking the original instruments and copying the preserved driver log/exit to the filenames required by the unchanged checker.

The 700-member frozen-gate failure contains all eight findings:

- `harness status`
- `harness exit receipt`
- `dual reload sequence`
- `main reload sequence`
- `overlap reload sequence`
- `SIGHUP count`
- `probes.csv failure`
- `unclassified/active WARN: SIGHUP received while previous reload still in flight; ignoring`

Only one dual-stack row and one churn-overlap row exist. No missing reload results were synthesized, and the outer driver's zero exit was not treated as acceptance.
