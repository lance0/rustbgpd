# Contributing

## Development Setup

- Rust 1.87+ (edition 2024)
- Linux x86_64 or aarch64 (primary targets)
- macOS works for development but is not CI-tested
- Docker + [containerlab](https://containerlab.dev/) for interop tests

## Building

```bash
git clone https://github.com/lance0/rustbgpd
cd rustbgpd
cargo build
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
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

### Conventions

- No `unsafe` code without a `SAFETY` comment and strong justification
- Keep lines under 100 characters when possible
- `#![deny(unsafe_code)]` on every crate — this is enforced, not advisory

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
src/config.rs            # TOML config types, loading, validation
src/metrics_server.rs    # Prometheus /metrics HTTP endpoint
crates/
  wire/                  # BGP codec — zero internal deps
  fsm/                   # RFC 4271 state machine — pure, no I/O
  transport/             # Tokio TCP glue — the only async crate
  rib/                   # RIB data structures and best-path
  policy/                # Prefix filters, max-prefix enforcement
  api/                   # gRPC server (tonic)
  telemetry/             # Prometheus metrics + structured tracing
proto/                   # gRPC proto definitions (rustbgpd.v1)
tests/interop/           # Containerlab topologies and configs
docs/                    # Design doc, RFC notes, interop results
```

### Dependency Rules

These are not guidelines — they are enforced invariants:

- `wire` depends on nothing internal
- `fsm` depends only on `wire` types
- `fsm` never imports tokio, never touches I/O
- `transport` is the only crate that does async I/O

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make changes, ensure all checks pass
4. Submit PR with a clear description

### What to Include

- **Bug fixes:** Steps to reproduce, how you verified the fix
- **New protocol behavior:** RFC citation and proposed interop test
- **New features:** Update CHANGELOG.md and relevant docs

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
