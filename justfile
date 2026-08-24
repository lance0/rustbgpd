# Optional, curated local checks. Hosted CI remains the source of truth.

# Show the available local checks.
default:
    just --list

# Run the broad local correctness baseline in diagnostic order.
gate:
    cargo fmt --all -- --check
    python3 -m unittest -v scripts/test_check_clippy_reasons.py
    python3 scripts/check-clippy-reasons.py
    python3 scripts/check-v1-stable-surface.py
    python3 scripts/reflow-release-notes.py --selftest
    python3 -m unittest -v scripts/test_check_public_tracker_ids.py
    python3 scripts/check_public_tracker_ids.py
    python3 -m unittest -v scripts/test_check_ixp_manager_docs.py
    python3 scripts/check_ixp_manager_docs.py
    python3 -m unittest -v scripts/test_check_release_checklist_paths.py
    python3 scripts/check_release_checklist_paths.py
    python3 -m unittest -v scripts/test_check_metric_consumers.py
    python3 scripts/check-metric-consumers.py
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo test --locked --workspace
    cargo doc --locked --workspace --lib --no-deps

# Compile the feature-gated RIB, transport, and API bench surfaces.
gate-rib:
    cargo check --locked -p rustbgpd-rib --features bench-internals --benches
    cargo check --locked -p rustbgpd-transport --features bench-internals --benches
    cargo check --locked -p rustbgpd-api --features bench-internals --benches

# Test the four standalone scale-harness manifests used by CI.
gate-deps:
    cargo test --manifest-path bench/scale/rrharness/Cargo.toml --locked
    cargo test --manifest-path bench/scale/rrtransport/Cargo.toml --locked
    cargo test --manifest-path bench/scale/reloadstall/Cargo.toml --locked
    cargo test --manifest-path bench/scale/enhanced-route-refresh/Cargo.toml --locked

# Execute every Criterion benchmark body once without collecting timings.
gate-contract:
    bash bench/smoke-benches.sh

# Apply safe Clippy suggestions, then format the workspace.
fix:
    cargo clippy --fix --locked --workspace --all-targets -- -D warnings
    cargo fmt --all
