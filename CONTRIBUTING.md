# Contributing

## Development Setup

- Rust 1.95+ (edition 2024 — workspace MSRV; raised to 1.95 because the bundled SQLite build (libsqlite3-sys) uses the `cfg_select!` macro stabilized in Rust 1.95)
- `protobuf-compiler` (`apt-get install protobuf-compiler` on Debian/Ubuntu)
- Linux x86_64 or aarch64 (primary targets)
- macOS works for development but is not CI-tested
- Docker + [containerlab](https://containerlab.dev/) for interop tests

## Building

```bash
git clone https://github.com/lance0/rustbgpd
cd rustbgpd
cargo build --workspace          # builds rustbgpd + rustbgpctl
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

The clippy-reason ratchet currently covers `crates/rib/src`. Any
`#[allow(clippy::...)]` or `#[expect(clippy::...)]` in a ratcheted path must
include `reason = "..."` explaining why the escape hatch is intentional.
When another crate is backfilled, add it to `DEFAULT_PATHS` in
`scripts/check-clippy-reasons.py`.

### Pre-commit hooks

We ship a `.pre-commit-config.yaml` that runs `cargo fmt` and
`cargo clippy --workspace --all-targets -- -D warnings` on every
commit and `cargo test --workspace --lib` on every push. The
clippy invocation matches CI exactly so a clean commit is a clean
PR. `cargo test` is gated to pre-push (not pre-commit) so commits
stay fast.

Set it up once:

```bash
# Recommended: prek (fast Rust port, drop-in compatible)
cargo install --locked prek
prek install

# Or via standalone installer (no Rust toolchain needed)
curl -LsSf https://github.com/j178/prek/releases/latest/download/prek-installer.sh | sh

# Or with the original Python pre-commit
pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

After install, hooks run automatically. To run them manually
against staged files: `prek run` (or `pre-commit run`).

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
  transport/             # Tokio TCP glue — session runtime, BMP event emission
  rib/                   # RIB data structures, best-path selection, route distribution
  policy/                # Match + modify + filter engine: prefix, community, AS_PATH regex, RPKI
  rpki/                  # RPKI origin validation: RTR client (RFC 8210), VRP table
  bmp/                   # BMP exporter (RFC 7854): codec, per-collector client, manager
  mrt/                   # MRT dump export (RFC 6396): codec, writer, manager
  evpn/                  # EVPN local VTEP domain model (RFC 7432 / RFC 8365 / RFC 9136): EvpnInstance, IpVrf, RouteTarget, origination + projection state machines (kernel-free)
  evpn-linux/            # Linux kernel dataplane for EVPN VTEP mode (#[cfg(target_os = "linux")]): rtnetlink reconciler, FDB / link / IP-VRF dumps, RTNLGRP_NEIGH classifier, RTNLGRP_IPV4_ROUTE / RTNLGRP_IPV6_ROUTE route observer (Gate 9 slice 6), L3 FIB programming (Gate 9 slice 6 PR B), nexthop_raw raw-netlink FDB-NHG primitive + group_state refcount + nh_id_alloc tag bits (ADR-0059 aliasing-ECMP)
  api/                   # gRPC server (tonic) — 11 services
  telemetry/             # Prometheus metrics + structured tracing
  cli/                   # rustbgpctl — gRPC CLI with human-readable and JSON output
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
- `bmp` and `telemetry` have no internal dependencies
- `rib` depends on `wire`, `policy`, `telemetry`, and `rpki`
- `transport` owns BGP peer session I/O and drives the FSM — it depends on `wire`, `fsm`, `rib`, `policy`, `telemetry`, and `bmp`
- `evpn` is the local-VTEP domain crate — depends only on `wire`, never on `rib` or `transport`, never programs the kernel
- `evpn-linux` is the Linux kernel dataplane for EVPN VTEP mode — depends only on `evpn`, never on `rib` or `transport`
- `cli` has no internal crate dependencies (client-only proto stubs)

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
