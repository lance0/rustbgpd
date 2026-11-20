# First-group build registration comparison data

Measured 2026-11-19. Curated results for the [paced first-group build during registration](../../first-group-build-registration-2026-11.md): all 16 scale cells (400,000 and 1,000,000 routes), the six 16,384-route control cells, memory ratios, source commits and executable hashes. This local campaign has no hosted Actions run; raw logs, quiet-host samples and binaries are retained separately.

| File | Contents | SHA-256 |
|---|---|---|
| `comparison.json` | Per-cell raw timestamps, work counters and derived intervals; ABBA means; memory ratios; verdict | 9fb3ce5a0e5e04d5bfc65d140fede3d9e833750c41cebb36ab354cbd92fe325c |
| `parent-harness.patch` | Harness mode and instrumentation applied to the parent commit | cbcabc8738a4cb26d44db9edfac3bb67e230b0d5bed1e3d5cd17a7b8248b0f83 |
| `candidate-harness.patch` | The same harness mode and instrumentation, plus paced-build counters, applied to the candidate commit | c86f3c35b3b727e75d6a25b8ffbc46ec4105b01d23f45378617b9fd632c7d770 |

To rebuild an arm, check out its commit from the JSON, apply its patch, and run `cargo build --locked --profile scale -p rrharness`. One cell is `rrharness first-registration ROWS cold parent|candidate` in a fresh process, inside a memory scope with swap disabled, under the host lock and the quiet-host gate. The cell order per scale is in the JSON.

The patches are measurement-only and are not in the repository; the harness mode and its timestamps are absent from production builds. Both arms were built as optimized non-test binaries, so test-only counters are compiled out of both.
