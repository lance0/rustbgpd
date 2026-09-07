# Fuzzing

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

rustbgpd fuzzes untrusted decode surfaces with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). There are
six fuzz crates, one per fuzzed workspace crate:

- `crates/bfd/fuzz` — the BFD control-packet codec (`rustbgpd-bfd`)
- `crates/wire/fuzz` — the BGP wire codec (`rustbgpd-wire`)
- `crates/policy/fuzz` — the `.rpol` policy-language frontend
  (`rustbgpd-policy`)
- `crates/evpn/fuzz` — EVPN route-target parsing (`rustbgpd-evpn`)
- `crates/mrt/fuzz` — the MRT snapshot and warm-bundle readers
  (`rustbgpd-mrt`)
- `crates/rpki/fuzz` — the RTR PDU codec (`rustbgpd-rpki`)

BMP (`crates/bmp`) is encode-only — rustbgpd never decodes BMP from the
network — so it has no fuzz surface.

## Targets

| Target | Crate | Covers | Property |
|---|---|---|---|
| `decode_bfd_control` | bfd | RFC 5880 mandatory control-packet section and discard rules | decoder never panics; inputs are capped at 256 bytes |
| `decode_message` | wire | Full message framing: header, marker, per-type dispatch (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) | never panics |
| `decode_update` | wire | UPDATE body + path attributes, incl. MP_REACH/MP_UNREACH for every family (unicast, VPNv4/v6 RD+label stacks, EVPN, BGP-LS NLRI + attr 29 TLVs, RTC, FlowSpec, labeled-unicast), 2/4-octet AS_PATH, Add-Path across all families | never panics |
| `decode_open` | wire | OPEN body + the full optional-parameter/capability codec (MP-BGP, Add-Path, ORF, unknown caps) | lossless round-trip |
| `decode_route_refresh` | wire | ROUTE-REFRESH body, RFC 7313 subtypes, RFC 5291 ORF section (Address-Prefix entries, raw/malformed group preservation) | lossless round-trip |
| `decode_flowspec` | wire | RFC 8955/8956 FlowSpec NLRI, both AFIs | never panics |
| `decode_evpn` | wire | RFC 7432 EVPN route types 1–5 | value round-trip |
| `encode_evpn` | wire | Constructor-space EVPN encode (inputs the decoder alone cannot reach) | encode is a function |
| `encode_update` | wire | Bounded canonical structured IPv4 UPDATEs with encoder-admitted path attributes and NLRI | full encode length is exact; decode consumes all bytes with no malformed attributes; canonical value and re-encoding are stable |
| `decode_bgpls` | wire | RFC 9552 BGP-LS NLRI (+ VPN flavor) and attr-29 TLVs | value round-trip (the M73 byte-fidelity promise, generalized) |
| `decode_vpn` | wire | VPNv4/VPNv6 NLRI: RD, label stacks, RFC 8277 §2.4 withdraw compatibility parsing | value round-trip (preserve-verbatim promise) |
| `decode_labeled` | wire | RFC 8277 labeled-unicast (SAFI 4), announce + withdraw, legacy + Add-Path | announce: lossless round-trip; withdraw: second-generation idempotence (the encoder normalizes to the 0x800000 compatibility field by design) |
| `decode_rtc` | wire | RFC 4684 RT-Constrain NLRI (AFI 1/SAFI 132), default + 32..96-bit prefixes | lossless round-trip |
| `parse_rd` | wire | Route Distinguisher `FromStr` | Display→FromStr lossless |
| `rpol_compile` | policy | `.rpol` lexer, parser, typechecker, lowering, and the in-language `test`-block runner (eval engine on fuzzer-authored programs) | returns `Diagnostics`, never panics/aborts/hangs |
| `dataset_parse` | policy | operator-fed prefix, ASN, and community dataset text, including comments and malformed lines | returns a result, never panics/aborts/hangs |
| `compile_chain` | policy | bounded valid mixed TOML and `.rpol` chains with indexed sets, regexes, and datasets | compilation returns and every recursively remapped ID resolves in the merged tables |
| `explain_walk` | policy | bounded valid mixed TOML and `.rpol` chains plus owned route recipes | trace length is bounded by the walkable policies, Deny is terminal, and the trace verdict agrees with live evaluation |
| `parse_rt` | evpn | Route Target `FromStr` over arbitrary UTF-8 | Display→FromStr lossless |
| `snapshot_reader_drain` | mrt | arbitrary MRT framing plus arbitrary records after a valid empty peer-index table | reader construction and full iteration never panic |
| `warm_bundle_manifest` | mrt | real owner-checked `manifest.json` load through JSON decoding, V1 structure, boot identity, freshness, and safe snapshot lookup/error handling | loader never panics |
| `decode_rtr_pdu` | rpki | RFC 8210 / 8210bis PDU framing and all supported payloads | decoder never panics; campaign inputs are capped at 65,535 bytes |

"Round-trip" targets assert the promise the interop labs pin for specific
bytes (M73 BGP-LS byte fidelity, M74 VPN preserve-verbatim) over the whole
reachable input space: decode → encode → decode must reproduce the value.

## Running locally

Requires the reviewed nightly and cargo-fuzz release
(`cargo install cargo-fuzz --version 0.13.2 --locked`). Install the toolchain
named by `fuzz/rust-nightly.txt` before running these commands.

```sh
export RUSTUP_TOOLCHAIN="$(cat fuzz/rust-nightly.txt)"
cd crates/wire
cargo fuzz list
cargo fuzz run encode_update fuzz/corpus/encode_update fuzz/seeds/encode_update -- -max_total_time=300 -max_len=4096
```

Run the same `list`/`run` flow from `crates/bfd`, `crates/policy`,
`crates/evpn`, `crates/mrt`, or `crates/rpki`, choosing a target and length
bound for that crate.

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay it with
`cargo fuzz run <target> fuzz/artifacts/<target>/<file>` with the pinned
toolchain still selected.

## Corpus layout

- `fuzz/seeds/<target>/` — small, hand-pinned seed inputs, **tracked in git**
  (golden wire bytes from the test suite, `.rpol` files from the interop
  configs). Fix any fuzzer-found bug by adding its minimized reproducer here
  as a regression seed.
- `fuzz/corpus/<target>/` — the growing machine-generated corpus,
  **gitignored**; local runs grow their own from the seeds. The nightly wire
  campaign installs either a validated prior `main` bundle or an exact copy of
  the tracked wire seeds before running.
- `crates/wire/fuzz/bgp.dict` — reviewed BGP marker, message, attribute, and
  AFI/SAFI byte tokens. Nightly and hosted builders pass it to the 12 binary
  wire targets; the textual `parse_rd` target does not use it.

The nightly wire bundle is an availability optimization, not a source of
truth. `scripts/fuzz_corpus_cache.py` restores it into runner-temporary staging
and accepts only the exact 13 target directories, one level of regular files,
each target's reviewed `max_len`, a byte-matching sorted SHA-256 manifest, at
most 20,000 files, and at most 16 MiB. A miss or cache-service outage is
reported and falls back to tracked seeds. If a matched bundle is incomplete,
unexpected, over a bound, or does not match its manifest, the campaign stops
before installing it. After a successful run, the same helper seals a fresh
staging bundle; a corpus crossing either aggregate cap simply skips saving.
Only scheduled or manually dispatched runs on `main` can save, and save-service
availability does not change the result of the completed test campaign.

## CI

`.github/workflows/fuzz.yml` runs nightly (04:00 UTC) and on manual
dispatch: every target in all six fuzz crates for 120 seconds each, starting
from tracked seeds or the validated prior wire corpus. The job has a 90-minute
bound, does not cancel an older lineage writer, and retains failure artifacts
for 14 days. Budget choice:
all targets briefly rather than a rotating subset — every surface gets
nightly coverage and the whole job stays bounded by per-target timers.

`.github/workflows/fuzz.yml` is the sole scheduled fuzz campaign.
`.github/workflows/clusterfuzzlite.yml` is an on-demand integration receipt:
manual dispatch runs the official address-sanitized `code-change` actions with
a 300-second total fuzzing budget and a 180-minute cold-start job bound. It does
not run on pull requests and is not a required merge check. No external storage
repository or long-lived PAT is configured.

That split is based on the PR #1061 commissioning receipt, not an estimate.
[Run 29855791034](https://github.com/lance0/rustbgpd/actions/runs/29855791034)
at head `ee41f8f3` was intentionally cancelled after 40m42s: runner acquisition
took 12s, the exact inventory took about 2s, the address-sanitized build passed
in 14m14s, and `run_fuzzers` listed all 17 targets but completed only three and
was waiting for the fourth target's corpus when the job was cancelled after a
further 25m38s. Each completed target spent about 6m42s waiting for its absent
corpus artifact before roughly 18s of fuzzing. ClusterFuzzLite's 300 seconds is
a total engine budget, not a job wall-clock budget; targets run sequentially
and corpus, setup, and cleanup sit outside it. A cold extrapolation is about
134 minutes for the 14-minute build, 17 artifact waits, and five total fuzzing
minutes, so the manual job uses a conservative 180-minute bound. That observed
cost rejected ClusterFuzzLite as a PR critical-path check. No crash was
deliberately injected into a PR: crash injection is not required to establish
that scheduling decision. Manual runs retain ClusterFuzzLite's SARIF output and
crash-artifact handling.

Scheduled ClusterFuzzLite batch/prune operation remains out of scope. Its
GitHub artifact backend treats corpus download and upload failures as non-fatal,
which cannot meet rustbgpd's fail-closed corpus-reuse rule. ClusterFuzzLite's
Rust integration also documents AddressSanitizer as the only supported
sanitizer, so the manual workflow does not claim unsupported coverage mode.

`scripts/check_fuzz_target_inventory.py` gates the exact 22-target inventory in
the ordinary PR/push `CI / check` job, before a manual ClusterFuzzLite build,
and again inside the shared fuzzer build path. It compares cargo metadata and
`fuzz_targets/*.rs` against an explicit globally-unique inventory, including
both MRT targets. Its mutation tests remove every manifest target and every
source target one at a time and inject empty, failed, and source-redirected
enumeration, an unexpected fuzz crate, and a cross-crate target-name collision,
so the fail-closed behavior is itself CI-proved. The same gate pins the complete
wire seed path and byte inventory, dictionary bytes and target enrollment, and
the cache's branch guard, staging, versioned keys, caps, manifest validation,
step order, and outage behavior.

## When the nightly goes red

The nightly steps run in order — wire, policy, EVPN, MRT, BFD, RTR — and the
first failing step ends the job. **Every later crate is skipped and the wire
corpus is not sealed**, so a red night costs coverage well beyond the target
that actually failed. Triage it rather than waiting to see whether it clears.

### Read the run

```sh
gh run list --workflow fuzz.yml --limit 10
gh run view <run-id> --log-failed
```

The failing step names the crate. Inside it, find the line that says what
stopped:

- `panicked at fuzz_targets/<target>.rs:<line>` followed by
  `ERROR: libFuzzer: deadly signal` — a crash, with a reproducer.
- `ERROR: libFuzzer: out-of-memory` or `ERROR: libFuzzer: timeout` — investigate
  the reproducer, target bounds, and runner load. These can reveal excessive
  resource use in the library or harness; they do not by themselves establish
  a network-reachable defect.
- Build or launch errors — inspect the compiler diagnostics, command exit, and
  libFuzzer startup output. A missing `Running fuzz/target/...` line alone does
  not prove no target ran: output can differ or a target can fail early.

A crash prints its input twice: as `Test unit written to
fuzz/artifacts/<target>/crash-<sha1>` and as a `Base64:` line. The run's
`fuzz-crashes` artifact holds the same files for 14 days.

### Separate an environment failure from a finding

`fuzz/rust-nightly.txt` pins the toolchain, so an upstream compiler regression
cannot reach the campaign on its own — it arrives only with a deliberate pin
bump. Unchanged source can still fail on newly generated inputs. Use the failing
step and build/launch evidence to distinguish a finding from a runner, install,
or cache failure; do not infer the cause from the absence of a code change.
A corpus cache miss or cache-service outage is not a failure at all: the
campaign reports it and falls back to tracked seeds by design.

### Reproduce it locally

Recover the input from the log or download the artifact. Starting at the
repository root, replay it in the owning crate (wire in this example):

```sh
printf '%s' '<the Base64: value>' | base64 -d > /tmp/crash-input
export RUSTUP_TOOLCHAIN="$(cat fuzz/rust-nightly.txt)"
cd crates/wire
cargo fuzz run <target> /tmp/crash-input
cargo fuzz tmin <target> /tmp/crash-input   # minimize before pinning
```

`just fuzz-list` enumerates every target across the fuzz crates, and
`just fuzz <crate> <target>` runs one target's campaign when you want to search
near a finding instead of replaying a single input.

### Decide what kind of bug it is

Read the panic text, not just the target name.

- **The message is one of the harness's own `expect` or `assert` strings.**
  Trace the input and the asserted contract. The generator may have built an
  invalid value, or the assertion may expose an encoder/decoder contract bug.
  Fix the generator only after confirming the library correctly rejects the
  value; preserve assertions that catch valid-input failures.
- **The panic comes from library code** — an index out of bounds, an `unwrap`
  on `None`, a slice range, an arithmetic overflow. Trace the library contract
  and fix the defect there when the input is admitted. Establish network
  reachability separately: constructor targets also exercise structured values.

Either way, check every sibling site that shares the constraint before closing
it. In September 2026 the `encode_update` harness generated AS 0, which the
encoder rejects under RFC 7607; one night surfaced the `AS_PATH` site and the
next surfaced `AGGREGATOR` from the same root cause. One commit closed both
([#2239](https://github.com/lance0/rustbgpd/pull/2239)), but the second red
night was avoidable.

### Land the fix

Add the minimized reproducer to `fuzz/seeds/<target>/` so every later campaign
starts from it, and add an ordinary Rust regression test beside the code for a
library bug. The seed proves the input no longer crashes; the test states the
behavior now expected. For wire seeds, also update the existing path and byte/hash
inventory in `scripts/check_fuzz_target_inventory.py`, then run that checker and
its companion `scripts/test_check_fuzz_target_inventory.py` tests.

### File, or note and move on

File an issue when the finding is in library code, when it is reachable from
network bytes, or when the same failure returns after a fix. Note the run ID
and the resolving commit and move on when the red was an infrastructure
cancellation, a cache outage, or a failure that a commit already on `main`
resolves. Record the outcome either way: an unrecorded red night looks
identical to one nobody noticed, and it hides the crates that never ran.

## OSS-Fuzz eligibility outcome and shared build

The standard OSS-Fuzz project files are staged in `fuzz/oss-fuzz/`
(`project.yaml`, `Dockerfile`, `build.sh`). OSS-Fuzz and ClusterFuzzLite both
delegate to `fuzz/build-fuzzers.sh`, which validates and builds all six fuzz
crates with `cargo fuzz build -O --debug-assertions`. The crates share one
Cargo target directory so compatible sanitizer build-std and dependency
artifacts can be reused across crate builds. The integration ships each
`fuzz/seeds/<target>/` directory as a `<target>_seed_corpus.zip`.
Both hosted builders install the reviewed nightly named by
`fuzz/rust-nightly.txt`; this avoids depending on the older compiler bundled
in the upstream Rust builder image and must remain at or above the workspace
MSRV. They also install cargo-fuzz 0.13.2 explicitly because the Ubuntu 24.04
Rust builder does not bundle it.

The shared build uses one explicit Cargo target directory for all six fuzz
crates and fails unless every expected executable exists before copying it to
the integration output. Per-target libFuzzer options travel with the binaries,
and the reviewed BGP dictionary travels with all 12 binary wire targets, so
hosted campaigns enforce the same input bounds and token set as the
in-repository harnesses and nightly commands. This is a build-layout invariant,
not a wall-clock performance claim; this change carries no retained benchmark
harness or quantitative build-speed assertion.

[google/oss-fuzz#15874](https://github.com/google/oss-fuzz/pull/15874) was
closed on eligibility, not build correctness: upstream targets projects that
already have a wide user base and judged rustbgpd not mature enough yet. Its
17-target address-sanitized OSS-Fuzz build and check had passed before that
decision. ClusterFuzzLite is the current on-demand hosted fuzzing path; the
OSS-Fuzz files remain ready for a future resubmission if adoption clears the
upstream threshold.

Adding or removing a target now requires deliberately updating the explicit
inventory and its documentation. A new fuzz crate also requires updating the
shared build loop and both integration Dockerfiles.
