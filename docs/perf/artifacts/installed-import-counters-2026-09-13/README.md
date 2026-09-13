# Installed import-counter publication evidence

This receipt measures construction, publication, reader ownership, and release of installed import-counter descriptors at revision `5d0a49cea7f2e80885b296e8edb57c33e31d0848`. The single release integration-test invocation passed: one test, zero failures, zero filtered tests, exit 0.

[measurements.json](measurements.json) contains all 164 original measurement windows, exact source/binary identities, toolchain, release profile, and a command with the build-cache path normalized. [The probe source](private_import_publication_cost.rs) is the exact executed file, including its preparation-time header. [SHA256SUMS](SHA256SUMS) covers these files and this README. The historical binary hash identifies the measured executable; a fresh build is not promised to reproduce its bytes.

The reference reload scenario uses 1,000 peers with one `member-in` import policy and two terms, `drop-blocked` and `default`. Those labels contain 9, 12, and 7 bytes. A second case keeps the same predicate/actions and uses three 256-byte ASCII labels; this is a chosen diagnostic shape, not a configuration limit. Each shape runs with cold and warm per-chain caches, with four distinct installed generations and two independent reader pins per peer/generation. The reference scenario's reloads changed export policy while leaving import unchanged; four fresh import installations here are a separate retention stress case.

Each table row describes one 1,000-peer descriptor-construction window. Counts and requested bytes were identical across the four generations; the timing column gives their exact observed range. Cold constructor windows include lazy compiled-policy and counter initialization. Warm cases initialize those caches in separate measured windows. This is an ordered, instrumented diagnostic, not a cold/warm speedup comparison.

| Labels | Caches | Allocation operations | Requested bytes allocated | Requested bytes retired | Elapsed range (ns) |
| --- | --- | ---: | ---: | ---: | ---: |
| 9/12/7 bytes | Cold | 16,000 | 1,248,000 | 9,000 | 656,194–1,455,182 |
| 9/12/7 bytes | Warm | 6,000 | 196,000 | 0 | 72,949–174,792 |
| 256/256/256 bytes | Cold | 16,000 | 2,968,000 | 256,000 | 555,974–2,180,159 |
| 256/256/256 bytes | Warm | 6,000 | 936,000 | 0 | 92,930–433,650 |

Warm compiled initialization used 7,000 allocation operations per generation: 892,000 requested bytes with 9,000 retired for native labels, or 1,872,000 with 256,000 retired for long labels. Counter initialization used 3,000 operations and 160,000 requested bytes in either shape. Creating 1,000 watch channels used 1,000 allocations and 344,000 requested bytes. Publication, reader capture, and Weak capture allocated zero in every measured window. These publication windows retain old values through reader pins and have no waiting tasks or concurrent reader contention.

The ownership assertions verified 4,000 distinct descriptors and counter sets per case. Dropping chain owners left the counters owned by their descriptors; dropping one reader cohort preserved all generations. Releasing the last old reader pins made old descriptor/counter Weak upgrades fail. Closed watch channels retained the current value until receivers were dropped, after which the final current reader pin was its sole owner. Releasing that pin made current descriptor/counter Weak upgrades fail. Final Weak disposal freed 768,000 requested bytes across 8,000 entire Arc backing allocations, including former inline payload storage; this is not a control-header-only size.

Each complete case recorded 73,000 allocation and 73,000 retirement operations. Native-label cases allocated and retired 5,628,000 requested bytes; long-label cases allocated and retired 13,496,000. All four signed net balances were zero, with no accounting events between recorded windows. These observations establish the exercised ownership lifecycle, not general leak freedom or a global current-plus-previous retention bound.

Accounting wraps `System` and records requested layout sizes on one thread. Successful realloc records the new requested size and retires the original layout size, including in-place resize; failed realloc records neither. Negative release-window nets are expected. Configured shared policy bodies, parsing, preallocated harness storage, and result formatting are excluded. This does not measure RSS, usable allocation sizes, allocator residency, the daemon's jemalloc behavior, RPC latency, asynchronous cancellation, actor scheduling, or fleet deadlines. Timings include accounting overhead and have no benchmark-distribution claim.

To verify the retained files, run `sha256sum -c SHA256SUMS` from this artifact directory. To reproduce, use a clean checkout of the recorded revision and the recorded Rust/Cargo toolchain. Copy this artifact directory outside that checkout before switching revisions, and set `COST_PROBE_ARTIFACTS` to that copy's absolute path. From the repository root:

```sh
(
    set -eu
    set -C
    : "${COST_PROBE_ARTIFACTS:?Set COST_PROBE_ARTIFACTS to the artifact copy}"
    cost_probe_test=crates/transport/tests/private_import_publication_cost.rs
    cost_probe_log="$COST_PROBE_ARTIFACTS/reproduction.log"
    cost_probe_status="$COST_PROBE_ARTIFACTS/reproduction.exit"
    test "$(git rev-parse HEAD)" = 5d0a49cea7f2e80885b296e8edb57c33e31d0848
    test -f "$COST_PROBE_ARTIFACTS/private_import_publication_cost.rs"
    for cost_probe_path in "$cost_probe_test" "$cost_probe_log" "$cost_probe_status"; do
        test ! -e "$cost_probe_path"
        test ! -L "$cost_probe_path"
    done
    : > "$cost_probe_test"
    trap 'rm -- "$cost_probe_test"' EXIT
    cat -- "$COST_PROBE_ARTIFACTS/private_import_publication_cost.rs" >> "$cost_probe_test"
    cost_probe_exit=0
    CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=target cargo test --locked --release -p rustbgpd-transport --test private_import_publication_cost -j2 -- --exact private_import_publication_cost --nocapture --test-threads=1 > "$cost_probe_log" 2>&1 || cost_probe_exit=$?
    printf '%s\n' "$cost_probe_exit" > "$cost_probe_status"
    exit "$cost_probe_exit"
)
```

Retain the new output and exit status even if compilation or an assertion fails. Reproduction uses the existing transport integration-test dependency graph; it starts no daemon or reload workload. Each window retains its integer nanoseconds in the JSON; scope totals include ownership assertions between operation windows. Timing variation across fresh executions requires separate interpretation.

## Native collision diagnostic

[native-summary.json](native-summary.json) retains all 24 scheduled call outcomes,
12 reloads, commit-relative offsets, inventory checks, API stage records and
executable identities from the same source revision. Call durations and phase
offsets are rounded to 0.001 ms; stage records retain their original integer
milliseconds. Source/build hashes identify the original retained evidence.

The two-worker daemon and 24-worker generator share two physical CPUs; probes
run on separate CPUs. With 1,000 peers and 400 IPv4 prefixes per peer, all 12
pairs fall inside the original -220 to 0 ms band (minimum six). The unchanged
strict diagnostic fails: 19 of 24 calls exceed two seconds, 11 of 12 statistics
requests fail in the import stage, and two neighbor requests fail. The successful
statistics body contains exactly 1,000 import and 1,000 export rows. Ten successful
neighbor bodies contain all 1,000 peers, with 370–649 explicitly stale rows.
Routing and live endpoint checks retain all 1,000 sessions, with no runtime or
parse errors. All owned processes are reaped and ports released.

Import stage timing includes manager admission, collection and reply observation;
it does not locate an individual scheduler wait. Neighbor reads keep separate
peer-manager and RIB budgets. Their successful completion above two seconds may
follow the API contract while failing this stricter external criterion. The
inherited diagnostic also checks stale rows; its failure is preserved without
making zero stale an additional release gate. This is one configuration-specific
observation, not a speedup claim, a universal daemon limit or release qualification.
