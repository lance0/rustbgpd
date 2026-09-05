# Optional, curated local checks. Hosted CI remains the source of truth.

# Show the available local checks.
default:
    just --list

# Run a guided local lab (up, verify, break, explain, down).
[positional-arguments]
lab name phase:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
        quickstart|ixp|rr) exec bash "labs/$1/lab.sh" "$2" ;;
        *) echo "unknown lab: $1 (available: quickstart, ixp, rr)" >&2; exit 2 ;;
    esac

# Run the broad local correctness baseline in diagnostic order.
gate:
    just links
    just check-devtools
    just check-fast
    just check-contracts
    just check-clippy
    cargo test --locked --workspace
    just docs

# Check the pinned developer tooling versions.
check-devtools:
    python3 scripts/check_developer_tooling.py --self-test
    python3 scripts/check_developer_tooling.py

# Check formatting and the cheap repository contracts (seconds, no compilation).
check-fast:
    cargo fmt --all -- --check
    python3 -m unittest -v scripts/test_check_clippy_reasons.py
    python3 scripts/check-clippy-reasons.py
    python3 scripts/check-v1-stable-surface.py
    python3 scripts/reflow-release-notes.py --selftest

# Check the slower repository contracts: public tracker ids, documentation paths, and metric consumers (minutes, no compilation).
check-contracts:
    python3 -m unittest -v scripts/test_check_public_tracker_ids.py
    python3 scripts/check_public_tracker_ids.py
    python3 -m unittest -v scripts/test_check_ixp_manager_docs.py
    python3 scripts/check_ixp_manager_docs.py
    python3 -m unittest -v scripts/test_check_release_checklist_paths.py
    python3 scripts/check_release_checklist_paths.py
    python3 -m unittest -v scripts/test_check_metric_consumers.py
    python3 scripts/check-metric-consumers.py

# Lint every workspace target with warnings denied.
check-clippy:
    cargo clippy --locked --workspace --all-targets -- -D warnings

# Run the library unit tests of every workspace crate (the daemon's unit tests live in its binary; see test-bins).
test-crates:
    cargo test --locked --workspace --lib

# Run the unit tests of every binary target: the daemon, rbgp, the example packages under examples/, and the tools.
test-bins:
    cargo test --locked --workspace --bins

# Two root-crate test targets carry required-features, and a `--test` glob
# refuses those instead of skipping them, so the root package is selected
# with `--tests`; that runs the daemon's binary unit tests again.

# Run every integration test binary in the workspace (no library unit tests or doctests).
test-integration:
    cargo test --locked --workspace --exclude rustbgpd --test '*'
    cargo test --locked -p rustbgpd --tests

# Build the library docs (private items included) and both binary docs.
docs:
    cargo doc --locked --workspace --lib --no-deps --document-private-items
    cargo doc --locked -p rustbgpd --bin rustbgpd --no-deps
    cargo doc --locked -p rustbgpctl --bin rbgp --no-deps

# Check links between tracked Markdown files without making network requests.
links:
    #!/usr/bin/env bash
    set -euo pipefail
    expected="lychee 0.24.2"
    if ! command -v lychee >/dev/null 2>&1; then
        echo "${expected} is required; install it with:" >&2
        echo "  cargo install lychee --version 0.24.2 --locked" >&2
        exit 127
    fi
    actual="$(lychee --version)"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "expected ${expected}, found ${actual}" >&2
        echo "install the pinned version with:" >&2
        echo "  cargo install lychee --version 0.24.2 --locked" >&2
        exit 1
    fi
    git ls-files '*.md' | lychee --files-from - --offline --include-fragments=none --no-progress

# Compile the feature-gated RIB, transport, and API bench surfaces.
gate-rib:
    cargo check --locked -p rustbgpd --features bench-internals --benches
    cargo check --locked -p rustbgpd-rib --features bench-internals --benches
    cargo check --locked -p rustbgpd-transport --features bench-internals --benches
    cargo check --locked -p rustbgpd-api --features bench-internals --benches
    cargo check --locked -p rustbgpd-api --features bench-internals,vpn-query-allocation --bench vpn_query_allocation

# Test the standalone scale-harness workspace used by CI.
gate-deps:
    cargo test --manifest-path bench/scale/Cargo.toml --workspace --locked

# Execute every Criterion benchmark body once without collecting timings.
gate-contract:
    bash bench/smoke-benches.sh --locked --fail-fast

# Apply safe Clippy suggestions, then format the workspace.
fix:
    cargo clippy --fix --locked --workspace --all-targets -- -D warnings
    cargo fmt --all

# Compile and run the feature-gated surfaces hosted CI checks beyond the default workspace build.
test-feature-gated:
    cargo clippy --locked -p rustbgpd-wire --all-targets --features tokio-codec -- -D warnings
    just gate-rib
    just gate-contract
    cargo test --locked -p rustbgpd-rib --features bench-internals --bench selection_deferral_release -- --self-test
    cargo test --locked -p rustbgpd-mrt --bench snapshot_allocation -- timing --candidate --smoke
    cargo test --locked -p rustbgpd-mrt --features snapshot-allocation-diagnostics --bench snapshot_allocation -- diagnostic --candidate --smoke
    cargo check --locked -p rustbgpd --all-features --lib
    cargo test --locked -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation shared_set_batch_allocations_do_not_scale_per_peer -- --exact
    cargo check --locked -p rustbgpd --no-default-features --all-targets
    cargo test --locked -p rustbgpd-wire --features tokio-codec
    cargo doc --locked -p rustbgpd-wire --lib --no-deps --features tokio-codec

# Excluded ignored tests: the TCP-AO kernel receipts (transport listener and
# socket_opts) need CONFIG_TCP_AO and privileges; the four config persistence
# probes assert a release build; `unicast_prefix_peers_memory` needs its
# announcer-count environment variable; `policy_set_store_dhat` needs the
# `dhat-heap` feature and an output-file environment variable;
# `minimizer_timeout_fixture` is a child-process fixture, not a test.

# Run the ignored receipts that need no privileges, extra environment, or release build (under a minute warm; allocates a few hundred MB).
test-ignored:
    cargo test --locked -p rustbgpd-rib --test export_fanout_attr_memo -- --ignored
    cargo test --locked -p rustbgpd-rib --test route_data_sharing_profile -- --ignored
    RUSTBGPD_RIB_MEMORY_PROFILE=quick cargo test --locked -p rustbgpd-rib --features bench-internals --test memory_profile memory_profile_high_n -- --ignored --exact
    cargo test --locked -p rustbgpd-rib --lib manager::tests::update_groups_fault_corpus::deterministic_fault_corpus_extended -- --ignored --exact
    cargo test --locked -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation -- --ignored
    cargo test --locked -p rustbgpd --test quickstart_dynamic_neighbor -- --ignored
    cargo test --locked -p rustbgpctl --lib ribdiff::tests::scale_receipt_1m_routes -- --ignored --exact

# Run the privileged network-namespace tests in Docker; selectors are listed in crates/evpn-linux/tests/docker/run-netns-tests.sh.
netns selector='all':
    bash crates/evpn-linux/tests/docker/run-netns-tests.sh "{{selector}}"
