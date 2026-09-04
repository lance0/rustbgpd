# Contributing

## Development Setup

- Rust 1.95+ (edition 2024 — workspace MSRV; raised to 1.95 because the bundled SQLite build (libsqlite3-sys) uses the `cfg_select!` macro stabilized in Rust 1.95)
- `protobuf-compiler` (`apt-get install protobuf-compiler` on Debian/Ubuntu)
- Linux x86_64 for native daemon/runtime CI; Linux aarch64 is cross-built
- Non-Linux work is limited to portable components; see the
  [platform support contract](SUPPORT.md#platform-support)
- Docker + [containerlab](https://containerlab.dev/) for interop tests

## Building

```bash
git clone https://github.com/lance0/rustbgpd
cd rustbgpd
cargo build --workspace          # builds rustbgpd + rbgp
cargo test --workspace
```

## Code Style

```bash
cargo fmt                          # Format
cargo clippy -- -D warnings        # Lint with warnings as errors
cargo test --workspace             # All tests
```

All PRs must pass (enforced by CI in `.github/workflows/ci.yml`):
- `cargo fmt --check`
- `python3 scripts/check-clippy-reasons.py`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Documentation changes additionally pass
`python3 scripts/check_public_tracker_ids.py`, enforced by
`.github/workflows/public-docs-contract.yml` because the main lane ignores
Markdown. Published docs name the thing directly, link the ADR, or cite the
GitHub PR number — never a private issue-tracker ID an external reader
cannot resolve.

### Optional local task runner

The repository includes an optional [`just`](https://just.systems/) task
runner for a curated local baseline. It does not add a build dependency, and
the recipes are not a full CI or pre-merge replica. The contract checks require
Python 3.11 or newer. Install `just` outside the repository if you want the
shortcuts:

```bash
cargo install --locked just
just --list
```

The recipes intentionally expose their direct commands:

- `just gate` runs formatting, lightweight repository contracts, strict
  workspace Clippy, the full workspace tests, and library docs (private items
  included) and binary docs.
  This is the broad local baseline and can take several minutes on a cold
  target directory.
- `just gate-rib` compiles the feature-gated RIB, transport, and API benchmark
  surfaces that the default workspace build cannot see, including the root
  FIB projection and both API feature combinations.
- `just gate-deps` tests the standalone scale-harness workspace under
  `bench/scale` in one invocation. That workspace has its own
  `bench/scale/Cargo.lock`, separate from the root lockfile, and can add
  substantial cold-build time.
- `just gate-contract` executes every Criterion benchmark body once without
  collecting timings, with locked dependency resolution and fail-fast local
  behavior. The harness is Linux/GNU-Bash oriented and requires the same local
  toolchain and system libraries as those benches.
- `just fix` applies safe Clippy suggestions before formatting. Cargo's normal
  refusal to modify dirty or staged worktrees remains in force.

Hosted checks remain authoritative and cover more than these recipes: the
declared MSRV, platform and workflow contracts, receipt classifiers, and
privileged interoperability lanes. In particular, the exact v0.64 migration
test only runs when `RUSTBGPD_V064_VALIDATOR` points to the verified v0.64
binary that CI prepares. Privileged network-namespace tests require Linux,
`EVPN_LINUX_NETNS=1`, and `CAP_NET_ADMIN` plus `CAP_SYS_ADMIN`; use
`crates/evpn-linux/tests/docker/run-netns-tests.sh` as documented in that
harness's README. Neither prerequisite is installed or enabled by `just gate`.

Treat the `justfile` as a convenient reviewed snapshot, not a single source of
truth. Check the applicable workflows when changing CI or preparing a merge.

### Comparison documentation

Describe every project by capability and scope, pin the compared release, and
cite the primary in-tree or upstream source. Do not publish hand-maintained
counts of external tests, targets, features, or RFCs. Apply the same rule to
rustbgpd: a current project count is acceptable only when a machine check keeps
it current.
RFC-defined enumerations, immutable dated receipts, and historical milestones
are not volatile census claims. Keep `Yes` / `Partial` / `No` verdicts, with
notes or footnotes that state the exact scope behind each verdict.

### Replaying update-group faults

The PR-sized parameterized fixed-scenario corpus compares the grouped manager
path with the forced-per-peer oracle under bounded channel saturation, dirty
policy regroup, stale and replacement session generations, RT-Constrain/ORF
membership churn, and Add-Path cap changes. One fixed schedule deliberately
combines saturation, a dirty regroup, and current/superseded session traffic
rather than testing only those faults in isolation:

```bash
cargo test -p rustbgpd-rib deterministic_fault_corpus -- --nocapture
```

Failure output includes the scenario name, seed, comparison mode, original
operation indices, and ordered operation log. To run the hard-capped 24-seed
corpus used by the weekly GitHub-hosted workflow:

```bash
cargo test -p rustbgpd-rib deterministic_fault_corpus_extended -- --ignored --nocapture
```

Seeds vary valid fixture identities; they do not randomize operation ordering
or scenario length. The defaults are seed start `0x35700000`, 24 fixture sets,
and at most 64 operations per schedule. Replay one exact failing scenario and
its original operation indices with:

```bash
RUSTBGPD_UPDATE_GROUP_SEED_START=0x35700007 \
RUSTBGPD_UPDATE_GROUP_SEED_COUNT=1 \
RUSTBGPD_UPDATE_GROUP_MAX_OPS=64 \
RUSTBGPD_UPDATE_GROUP_SCENARIO=dirty-policy-regroup-transitions \
RUSTBGPD_UPDATE_GROUP_OP_INDICES=0,1,2,7,8 \
cargo test -p rustbgpd-rib --lib \
  manager::tests::update_groups_fault_corpus::deterministic_fault_corpus_extended \
  -- --ignored --exact --nocapture
```

Indices always refer to the original fixed schedule, even after operations are
removed. `RUSTBGPD_UPDATE_GROUP_OP_INDICES=none` explicitly selects an empty
retained set; an empty set is useful for exact replay/serialization but is
rejected as a minimizer candidate because it omits required session setup.
Omit `RUSTBGPD_UPDATE_GROUP_OP_INDICES` to retain the full named scenario.

To shrink a reproduced failure, add `RUSTBGPD_UPDATE_GROUP_MINIMIZE=1` to that
exact seed/scenario command. The reducer is capped at 64 candidate evaluations
by default; set `RUSTBGPD_UPDATE_GROUP_MINIMIZE_EVALUATIONS` to `1..=256` to
change the cap. Each baseline/candidate runs as a separate invocation of the
current test executable with a 20-second wall-clock deadline, so a hung
operation or detached manager task is killed and reaped before the next case.
Only the same normalized failure classification is accepted. Session-start
boundaries and assertion prerequisites are retained to avoid shrinking into a
different, structurally invalid fixture. Output always prints the best replay,
the evaluation count, and whether a complete single-deletion pass established
that no remaining removable operation preserves the failure.

On failure, the weekly workflow extracts the exact seed/scenario marker,
appends the bounded minimizer run to `update-group-fault.log`, uploads that log
as a failure-only artifact, and then exits with the original corpus status.

`RUSTBGPD_UPDATE_GROUP_SEED_COUNT` must be `1..=64`; max operations must be
`18..=64`, where 18 is the longest fixed schedule and is test-ratcheted when a
schedule changes. Every path must finish with the terminal sentinel in the
current transport generation; equal empty, truncated, or predecessor-session
streams fail before grouped/per-peer equality is considered. Invalid values,
unknown scenarios, out-of-range operation indices, and overflowing seed ranges
fail before a manager starts. The corpus uses virtual time and hard caps; it is
not a replacement for a live or multi-day soak.

The clippy-reason ratchet discovers every production source tree in the Cargo
workspace through `cargo metadata`, including the daemon, crates, tools, and
workspace benchmark packages. Any `#[allow(clippy::...)]` or
`#[expect(clippy::...)]` there must include `reason = "..."` explaining why
the escape hatch is intentional. New workspace packages are covered without
maintaining a second crate list.

### Developer lint gate

The developer-tooling gate uses actionlint 1.7.12 and Ruff 0.16.0. On Linux
amd64, install those exact binaries once into a new local directory, prove the
negative fixtures, and run the live checks with:

```bash
tools="${XDG_DATA_HOME:-$HOME/.local/share}/rustbgpd/developer-linters-1.7.12-ruff-0.16.0"
.github/scripts/install-developer-linters.sh "$tools"
PATH="$tools:$PATH" python3 scripts/check_developer_tooling.py --self-test
PATH="$tools:$PATH" python3 scripts/check_developer_tooling.py
```

The installer rejects an existing destination instead of partially updating
it. After the first install, reuse the final two commands. The checker rejects
any other tool versions, runs Ruff from the repository root, and lets
actionlint discover every workflow under `.github/workflows/`.

The initial Ruff boundary targets Python 3.11, keeps the 100-character line
length setting, and enables only `E9`, `F`, and `B`. `B904` and `B905` are
temporarily ignored so enabling lint does not bundle exception-chaining or
`zip(strict=...)` behavior changes. The two exact per-file migration exceptions
are recorded in `pyproject.toml`; new blanket or directory-wide exceptions are
not part of this boundary. actionlint runs with its ShellCheck and Pyflakes
integrations disabled; the existing explicitly scoped ShellCheck commands
remain responsible for shell scripts.

### Pre-commit hooks

We ship a `.pre-commit-config.yaml` that runs `cargo fmt` and
`cargo clippy --locked --workspace --all-targets -- -D warnings` on every
commit and `cargo test --locked --workspace --lib` on every push. The
hooks are a fast local subset, not an exact CI mirror or a guarantee that a
pull request is ready. `cargo test` is gated to pre-push (not pre-commit) so
commits stay fast.

Set it up once:

```bash
# Recommended: prek (fast Rust port, drop-in compatible)
cargo install --locked prek

# Or via standalone installer (no Rust toolchain needed)
curl -LsSf https://github.com/j178/prek/releases/latest/download/prek-installer.sh | sh

# Both prek installation methods use the configured hook types
prek install

# Or with the original Python pre-commit
pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

After install, hooks run automatically. To run them manually
against staged files: `prek run` (or `pre-commit run`).

Run `just links` to check links between tracked Markdown files without network
access. It requires lychee 0.24.2 and prints the pinned install command when the
binary is missing or has a different version. Hosted pull-request checks use
the same offline boundary; a weekly lane checks external destinations.

### Conventions

- No `unsafe` code without a `SAFETY` comment and strong justification
- Keep lines under 100 characters when possible
- `#![deny(unsafe_code)]` on every crate — this is enforced, not advisory

### Postmortem artifacts

Any postmortem doc that cites raw data — soak runs, scale tests,
interop captures — copies the load-bearing artifacts into
`docs/artifacts/<topic>/<run-id>/` and references them by
repo-relative path. The doc body either inlines the load-bearing
numbers or links the in-repo files; it must not depend on machine-
specific paths or "preserved on host X" language. Host-side run
trees (e.g., `tests/soak/runs/...`) stay gitignored — they're
per-machine working directories, not the published record. A
`README.md` next to the artifacts explains what each file is and
points back at the postmortem.

## Commit Messages

- Start with a verb: Add, Fix, Update, Remove, Refactor, Bump
- Keep the first line under 72 characters
- Use the body for context when needed

Examples:
```
Add NOTIFICATION encode/decode to wire crate
Fix hold time negotiation edge case for zero values
Update FRR interop topology to 10.3.1
Refactor FSM event dispatch to use match exhaustiveness
```

Version bumps:
```
Bump version to v0.1.0
```

Roadmap/docs updates:
```
roadmap: add M1 exit criteria
docs: update interop matrix for BIRD 2.16
```

## Project Structure

```
src/main.rs              # Binary entry point — config, wiring, shutdown
src/config/              # TOML config types, loading, validation
src/metrics_server.rs    # Prometheus /metrics HTTP endpoint
crates/
  wire/                  # BGP codec — zero internal deps, independently publishable
  fsm/                   # RFC 4271 state machine — pure, no I/O
  bfd/                   # RFC 5880 BFD: control-packet codec + sans-IO session state machine (single-hop / multihop encapsulation lives in the daemon actor)
  transport/             # Tokio TCP glue — session runtime, BMP event emission
  rib/                   # RIB data structures, best-path selection, route distribution
  policy/                # Match + modify + filter engine: prefix, community, AS_PATH regex, RPKI
  rpki/                  # RPKI origin validation: RTR client (RFC 8210), VRP table
  bmp/                   # BMP exporter (RFC 7854): codec, per-collector client, manager
  mrt/                   # MRT dump export (RFC 6396): codec, writer, manager
  evpn/                  # EVPN local VTEP domain model (RFC 7432 / RFC 8365 / RFC 9136): EvpnInstance, IpVrf, RouteTarget, origination + projection state machines (kernel-free)
  evpn-linux/            # Linux kernel dataplane for EVPN VTEP mode (#[cfg(target_os = "linux")]): rtnetlink reconciler, FDB / link / IP-VRF dumps, RTNLGRP_NEIGH classifier, RTNLGRP_IPV4_ROUTE / RTNLGRP_IPV6_ROUTE route observer (Gate 9 slice 6), L3 FIB programming (Gate 9 slice 6 PR B), nexthop_raw raw-netlink FDB-NHG primitive + group_state refcount + nh_id_alloc tag bits (ADR-0059 aliasing-ECMP)
  api/                   # gRPC server (tonic) — thirteen services (twelve native rustbgpd.v1 + vendored gnmi.gNMI)
  telemetry/             # Prometheus metrics + structured tracing
  event-history/         # Durable local event outbox (ADR-0072): SQLite WAL store + broadcast
  cli/                   # rbgp — gRPC CLI with human-readable and JSON output
proto/                   # gRPC proto definitions (rustbgpd.v1)
tests/interop/           # Containerlab topologies and configs
docs/                    # Design doc, RFC notes, interop results, ADRs
```

### Dependency Rules

These are not guidelines — they are enforced invariants:

- `wire` depends on nothing internal — it is a pure codec library
- `fsm` depends only on `wire` types
- `fsm` never imports tokio, never touches I/O
- `policy` depends only on `wire`
- `rpki` depends only on `wire`
- `telemetry` has no internal dependencies; `bmp` depends on `wire` and `telemetry`
- `rib` depends on `wire`, `policy`, `telemetry`, `rpki`, and `bmp`
- `transport` owns BGP peer session I/O and drives the FSM — it depends on `wire`, `fsm`, `rib`, `policy`, `rpki`, `telemetry`, and `bmp`
- `evpn` is the local-VTEP domain crate — depends only on `wire`, never on `rib` or `transport`, never programs the kernel
- `evpn-linux` is the Linux kernel dataplane for EVPN VTEP mode — depends only on `evpn`, never on `rib` or `transport`
- `cli` depends only on `wire` and `policy` (client-only proto stubs; dev tests also use `api`, `evpn`, and `bmp`)

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make changes, ensure all checks pass
4. Submit PR with a clear description

### What to Include

- **Bug fixes:** Steps to reproduce, how you verified the fix
- **New protocol behavior:** RFC citation and proposed interop test
- **New features:** Update CHANGELOG.md and relevant docs

### Documentation Update Discipline

Multi-PR batches often touch the same release and roadmap files. Keep doc
updates low-conflict and reviewable:

- **CHANGELOG.md `[Unreleased]`:** append new entries to the bottom of the
  relevant subsection (`Added`, `Changed`, `Fixed`, etc.) instead of rewriting
  existing entries or resorting the whole block. Prefer one compact entry per
  PR concern.
- **ROADMAP.md:** use one row or checkbox per concern. When a PR ships one
  slice of a broader item, update that row in place with a short "shipped /
  remaining" sentence instead of rewriting surrounding roadmap prose.
- **Feature tracking docs:** in `docs/evpn-alpha-soak.md`,
  `docs/evpn-enablement.md`, and similar matrices, update the exact gate or row
  your PR owns. Avoid broad summary rewrites unless the feature state actually
  changed across the whole page.
- **Process-only docs PRs:** do not add a CHANGELOG entry unless the process
  change affects users or operators. The PR description should explain the
  intentional no-op.

### What Requires Discussion First

- Architectural changes (open an issue)
- New protocol extensions (open an issue with RFC citation)
- Changes to design constraints (these are non-negotiable — read DESIGN.md)

## Interop Testing

Every protocol feature must be validated against real peers in containerlab.
Unit tests are necessary but not sufficient.

```bash
# Deploy a test topology
containerlab deploy -t tests/interop/m0-frr.clab.yml

# Tear down
containerlab destroy -t tests/interop/m0-frr.clab.yml
```

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT/Apache-2.0, without any additional terms or conditions.
