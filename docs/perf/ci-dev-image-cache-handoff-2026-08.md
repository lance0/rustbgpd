# CI dev-image cache handoff — 2026-08

Status: measured NO-GO. The first source-only treatment missed the predeclared
hard gate, so the candidate stops without a second treatment and does not
merge.

## Boundary and acceptance

The Interop and Kernel Dataplane workflows already share the fixed
`rustbgpd-dev` GitHub Actions cache scope. On an ephemeral runner, however, the
old Dockerfile restored the `cargo chef cook` step metadata while the mounted
`/build/target` contents were absent. A source build therefore restarted at
third-party crates such as `proc-macro2`.

Four cold controls with byte-identical Dockerfiles and Cargo locks took 516,
521, 533, and 540 seconds for the full primer job, a 527-second median. The
predeclared candidate gate is at most 316.2 seconds for that same job boundary
in each of two source-only treatments, a 40% reduction. The seed is excluded.
Both treatments must also execute the workspace build, compile at least one
workspace crate and zero external crates, keep every consumer and the full
Interop and Kernel rosters green, and avoid more than a 5% paired compute
regression.

The four controls and their primer-action durations are retained in the CSV.
They are runs [30781164576](https://github.com/lance0/rustbgpd/actions/runs/30781164576)
(516/500 seconds job/action),
[30830805082](https://github.com/lance0/rustbgpd/actions/runs/30830805082)
(521/500),
[30815272336](https://github.com/lance0/rustbgpd/actions/runs/30815272336)
(533/513), and
[30833927940](https://github.com/lance0/rustbgpd/actions/runs/30833927940)
(540/522). The 521-second run's primer job passed even though a later workflow
job failed; only the independently successful primer job is part of this
baseline.

The implementation follows Docker's ordinary-layer cache model: the cooked
dependency target is part of `builder-deps`, while only registry and git
downloads remain cache mounts. See Docker's [cache storage
documentation](https://docs.docker.com/build/cache/) and [GitHub Actions cache
backend](https://docs.docker.com/build/cache/backends/gha/).

## Identity and equivalence

The final candidate Dockerfile SHA-256 is
`acff6dd05af795e378bdbce74498d18b5d237a7298129dbb1e35052b1c4a861a`;
the unchanged `Cargo.lock` SHA-256 is
`d20b5fde3bf984ba4da5225f3a41a94b043672f2b6844d0777d3f8fe76593e18`.
The old Dockerfile hash is
`72ed4cc1436b9cfedce959e007dcdc505a9cc49aa3b03a27e6ca2c63be896529`.
The clean-control Dockerfile hashes to
`ba6994a68e807f2c3a780d6f535e8971b47d33e3cf6a5020c548129d46a4b571`:
it differs from the old file only by adding
`id=lan856-exact-clean-control` to its two `/build/target` cache mounts. It was
built from the control head with
`docker buildx build --target dev --load -t rustbgpd:lan856-clean-control .`.

An exact-source rerun built the old and final Dockerfiles from the same Rust
tree. The first old-Dockerfile build reused its ordinary shared target cache.
It produced `rustbgpd` SHA-256 `46c4136dca9c679351ce5b9e1d6c46f81c1455923a3fae6951ceda4552fc4176`
while the other three binaries matched, so the result is retained as an
excluded stale-cache diagnostic. Repeating the old build with the isolated,
initially empty target identity forced the source step to compile the full
dependency and workspace roster rather than returning a stale Cargo result.
That clean control and the exact-source final candidate then produced the same
runtime roster digest
`1e7fa7480d3ff518305bc4a2799fd1d5d77cc14e2af8bf0fdc393410f1f16e2f`
and byte-identical shipped binaries:

| binary | SHA-256 on both images |
|---|---|
| `rustbgpd` | `e3c4c59c65290309bc96200cbdbe199809aff0777c16a1b93385aed72f70b011` |
| `rbgp` | `217c5a88da59be7ce0f8c92a3866ac307fd2aa930621c62d03e213bc8956b3ee` |
| `evpn-tester` | `004962790d8bca4e408bd0b045975c680a28d7294b6dee489dd5bd7402de7580` |
| `evpn-monitor` | `a3b05084005d934a26107ec88a9de5d2e6411c439e9719d4cf8cda5146b059ed` |

The exact final candidate restored the dependency cook, compiled 20 workspace
packages and zero external packages, and spent 59.4 seconds in the source-build
step. The earlier external-cache consumer measured 59.5 seconds and its
`mode=max` cache export occupied 973,452,960 bytes. The CSV retains normalized
compile counts, the clean-control and exact-candidate BuildKit-log digests,
cache-manifest digest, cache size, binary digests, the excluded dirty-control
hashes, and roster digest rather than relying on local Docker tags or `/tmp`.
This equivalence proof covers Docker's `dev` target only. The release builder's
separate target-cache mount is outside this change.

## Hosted rows

| row | run / job | head | primer job / action | dependency cook | source build | compile roster | cache export | verdict |
|---|---|---|---:|---|---:|---|---:|---|
| seed | [30844189627 / 91788297406](https://github.com/lance0/rustbgpd/actions/runs/30844189627/job/91788297406) | `c906aab9` | 469 / 442 s | cold, 138.4 s | 207.8 s | 20 workspace, 0 external | 57.5 s; preparation 25.2 s | excluded, establishes the new graph |
| treatment 1 | [30847178451 / 91798212885](https://github.com/lance0/rustbgpd/actions/runs/30847178451/job/91798212885) | `5b84eea3` | 525 / 490 s | remote layer restore, 192.4 s | 269.8 s | 20 workspace, 0 external | 6.5 s; preparation 3.8 s | **NO-GO**, exceeds 316.2 s |

The seed finished successfully in a 469-second job. It cold-built the ordinary
dependency layer by design, then proved that the source step itself contained
only workspace compilation.

Treatment 1 changed only the receipt and CSV; its Dockerfile and Cargo metadata
were byte-identical to the seed. Restoring the 296.38 MB cooked layer stalled at
171.97 MB, hit a TCP read timeout, retried, and consumed 192.4 seconds. The
source step then compiled the expected 20 workspace packages and no external
packages, but took 269.8 seconds. The 525-second full job is effectively the
527-second control median, not the required 40% reduction. This is a hard
failure of the predeclared acceptance contract, independent of the transient
network timeout: removing the entire 192.4-second restore would still leave a
332.6-second job above the 316.2-second limit.

## Cache-capacity risk

Immediately before the seed, GitHub's repository-usage endpoint reported
10,734,256,008 active cache bytes across 1,054 entries against a configured
10 GB limit. The candidate therefore cannot fit without eviction. GitHub's
[documented policy](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#usage-limits-and-eviction-policy)
saves the new cache and evicts entries from least recently accessed to most
recently accessed; it explicitly warns this can cause cache thrashing.

The final verdict must compare the post-seed inventory, verify that hot mainline
caches and every consumer remain effective, and disclose any eviction. A fast
primer that merely transfers work to other jobs does not pass.

After treatment 1, the repository reported 10,755,266,918 active cache bytes
across 1,002 entries: 52 fewer entries than the pre-seed inventory while active
bytes remained above the configured 10 GB limit. Other concurrent workflows
mean that delta is not attributable solely to this candidate, but it confirms
that the capacity risk was live rather than theoretical. The failed hard timing
gate is sufficient for the NO-GO; no eviction attribution is needed to reject
the change.

## Retained artifact

The machine-readable rows are in
[`artifacts/ci-dev-image-cache-handoff-2026-08.csv`](artifacts/ci-dev-image-cache-handoff-2026-08.csv).
The structural checker and BuildKit-log validator are load-bearing: restoring a
dev target mount, breaking stage ancestry, removing the cook or source build,
moving cleanup before the binary copies, aliasing `#1` with `#10`, accepting an
all-cached source step, or recompiling an external crate makes a focused test or
validator invocation fail.
