# Fuzzing

rustbgpd fuzzes untrusted decode surfaces with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). There are
four fuzz crates, one per fuzzed workspace crate:

- `crates/wire/fuzz` — the BGP wire codec (`rustbgpd-wire`)
- `crates/policy/fuzz` — the `.rpol` policy-language frontend
  (`rustbgpd-policy`)
- `crates/evpn/fuzz` — EVPN route-target parsing (`rustbgpd-evpn`)
- `crates/mrt/fuzz` — the MRT snapshot and warm-bundle readers
  (`rustbgpd-mrt`)

BMP (`crates/bmp`) is encode-only — rustbgpd never decodes BMP from the
network — so it has no fuzz surface.

## Targets

| Target | Crate | Covers | Property |
|---|---|---|---|
| `decode_message` | wire | Full message framing: header, marker, per-type dispatch (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) | never panics |
| `decode_update` | wire | UPDATE body + path attributes, incl. MP_REACH/MP_UNREACH for every family (unicast, VPNv4/v6 RD+label stacks, EVPN, BGP-LS NLRI + attr 29 TLVs, RTC, FlowSpec, labeled-unicast), 2/4-octet AS_PATH, Add-Path across all families | never panics |
| `decode_open` | wire | OPEN body + the full optional-parameter/capability codec (MP-BGP, Add-Path, ORF, unknown caps) | lossless round-trip |
| `decode_route_refresh` | wire | ROUTE-REFRESH body, RFC 7313 subtypes, RFC 5291 ORF section (Address-Prefix entries, raw/malformed group preservation) | lossless round-trip |
| `decode_flowspec` | wire | RFC 8955/8956 FlowSpec NLRI, both AFIs | never panics |
| `decode_evpn` | wire | RFC 7432 EVPN route types 1–5 | value round-trip |
| `encode_evpn` | wire | Constructor-space EVPN encode (inputs the decoder alone cannot reach) | encode is a function |
| `decode_bgpls` | wire | RFC 9552 BGP-LS NLRI (+ VPN flavor) and attr-29 TLVs | value round-trip (the M73 byte-fidelity promise, generalized) |
| `decode_vpn` | wire | VPNv4/VPNv6 NLRI: RD, label stacks, RFC 8277 §2.4 withdraw compatibility parsing | value round-trip (preserve-verbatim promise) |
| `decode_labeled` | wire | RFC 8277 labeled-unicast (SAFI 4), announce + withdraw, legacy + Add-Path | announce: lossless round-trip; withdraw: second-generation idempotence (the encoder normalizes to the 0x800000 compatibility field by design) |
| `decode_rtc` | wire | RFC 4684 RT-Constrain NLRI (AFI 1/SAFI 132), default + 32..96-bit prefixes | lossless round-trip |
| `parse_rd` | wire | Route Distinguisher `FromStr` | Display→FromStr lossless |
| `rpol_compile` | policy | `.rpol` lexer, parser, typechecker, lowering, and the in-language `test`-block runner (eval engine on fuzzer-authored programs) | returns `Diagnostics`, never panics/aborts/hangs |
| `parse_rt` | EVPN | Route Target `FromStr` over arbitrary UTF-8 | Display→FromStr lossless |
| `snapshot_reader_drain` | MRT | arbitrary MRT framing plus arbitrary records after a valid empty peer-index table | reader construction and full iteration never panic |
| `warm_bundle_manifest` | MRT | real owner-checked `manifest.json` load through JSON decoding, V1 structure, boot identity, freshness, and safe snapshot lookup/error handling | loader never panics |

"Round-trip" targets assert the promise the interop labs pin for specific
bytes (M73 BGP-LS byte fidelity, M74 VPN preserve-verbatim) over the whole
reachable input space: decode → encode → decode must reproduce the value.

## Running locally

Requires nightly and cargo-fuzz (`cargo install cargo-fuzz`).

```sh
cd crates/wire
cargo +nightly fuzz list
cargo +nightly fuzz run decode_update fuzz/corpus/decode_update fuzz/seeds/decode_update -- -max_total_time=300 -max_len=4096
```

Run the same `list`/`run` flow from `crates/policy`, `crates/evpn`, or
`crates/mrt`, choosing a target and length bound for that crate.

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

## Corpus layout

- `fuzz/seeds/<target>/` — small, hand-pinned seed inputs, **tracked in git**
  (golden wire bytes from the test suite, `.rpol` files from the interop
  configs). Fix any fuzzer-found bug by adding its minimized reproducer here
  as a regression seed.
- `fuzz/corpus/<target>/` — the growing machine-generated corpus,
  **gitignored**; CI and OSS-Fuzz grow their own from the seeds.

## CI

`.github/workflows/fuzz.yml` runs nightly (04:00 UTC) and on manual
dispatch: every target in all four fuzz crates for 120 seconds each, starting
from the tracked seeds. Crash artifacts upload on failure. Budget choice:
all targets briefly rather than a rotating subset — every surface gets
nightly coverage and the whole job stays bounded by per-target timers.

## OSS-Fuzz onboarding

The standard OSS-Fuzz project files are staged in `fuzz/oss-fuzz/`
(`project.yaml`, `Dockerfile`, `build.sh`). `build.sh` builds all four fuzz
crates with `cargo fuzz build -O --debug-assertions` and ships each
`fuzz/seeds/<target>/` directory as a `<target>_seed_corpus.zip`.

Remaining manual steps (maintainer-submitted):

1. Fork <https://github.com/google/oss-fuzz>, create
   `projects/rustbgpd/`, and copy the three files from `fuzz/oss-fuzz/`.
2. Verify locally from the oss-fuzz checkout:
   ```sh
   python infra/helper.py build_image rustbgpd
   python infra/helper.py build_fuzzers --sanitizer address rustbgpd
   python infra/helper.py check_build rustbgpd
   python infra/helper.py run_fuzzer rustbgpd decode_update
   ```
3. Open the PR against google/oss-fuzz. The `primary_contact`
   (lancey3@gmail.com) must be a Google-account email able to access the
   ClusterFuzz dashboard; add any `auto_ccs` in `project.yaml` at that
   point.
4. After the first build goes green, confirm crash notifications arrive
   and mirror any OSS-Fuzz-found reproducers into `fuzz/seeds/` as
   regression seeds.

Keep `fuzz/oss-fuzz/` in sync when adding fuzz crates: `build.sh` discovers
targets per crate automatically, but a new fuzz *directory* must be added to
its `FUZZ_DIRS` list.
