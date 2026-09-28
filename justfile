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
        quickstart|ixp|rr|monitoring) exec bash "labs/$1/lab.sh" "$2" ;;
        *) echo "unknown lab: $1 (available: quickstart, ixp, rr, monitoring)" >&2; exit 2 ;;
    esac

# Run the broad local correctness baseline in diagnostic order.
gate:
    bash scripts/build-lock.sh just _gate

# The gate body. `gate` runs it under the build lock so a concurrent commit or
# push waits instead of compiling the same workspace at the same time.
_gate:
    just links
    just check-devtools
    just check-fast
    just check-contracts
    just check-clippy
    cargo test --locked --workspace
    just docs

# `gate-ci` is the local superset of hosted CI's `ci.yml` checks that need no
# privileges: `gate` runs the core formatting, lint, workspace test, and
# rustdoc commands; `test-feature-gated` the feature-gated Cargo commands;
# `gate-ci-steps` every other named script step of the core and scale/receipt
# jobs, read from the workflow; and `gate-msrv` the msrv job. What stays
# outside it: the exact v0.64 migration test (it needs the validator binary CI
# prepares), the privileged kernel job (`just netns` runs it in Docker), and
# every other workflow, including the interop and kernel labs. The recipes run
# one after another because `test-feature-gated` includes the Criterion smoke;
# never start another gate beside it.

# Run `gate` plus the rest of hosted CI's unprivileged `ci.yml` checks, one after another (tens of minutes).
gate-ci:
    just gate
    just test-feature-gated
    just gate-ci-steps
    just gate-msrv

# prek's shim also runs `.git/hooks/<hook>.legacy`, so a hook script left by an
# earlier setup keeps running alongside the configured hooks forever. This
# repository's leftover was an older `cargo fmt --check` plus `cargo clippy`
# script — the two checks .pre-commit-config.yaml already runs — so every commit
# paid for them twice. `--overwrite` removes it.

# Install the prek commit and push hooks, clearing any superseded legacy hook.
hooks:
    prek install --overwrite

# Check the pinned developer tooling versions.
check-devtools:
    python3 scripts/check_developer_tooling.py --self-test
    python3 scripts/check_developer_tooling.py

# Check formatting and the cheap repository contracts (seconds, no compilation).
check-fast:
    cargo fmt --all -- --check
    rustfmt --check --edition 2024 crates/*/fuzz/fuzz_targets/*.rs
    python3 -m unittest -v scripts/test_build_lock.py
    python3 -m unittest -v scripts/test_run_ci_steps.py
    python3 -m unittest -v scripts/test_check_ci_scale_split_contract.py
    python3 scripts/check_ci_scale_split_contract.py
    python3 -m unittest -v scripts/test_check_clippy_reasons.py
    python3 scripts/check-clippy-reasons.py
    python3 scripts/check-v1-stable-surface.py
    python3 -m unittest -v scripts/test_check_sighup_architecture.py
    python3 scripts/check_sighup_architecture.py
    python3 scripts/reflow-release-notes.py --selftest
    python3 -m unittest -v scripts/test_check_bench_inventory.py
    python3 scripts/check_bench_inventory.py

# Check the slower repository contracts: public tracker ids, documentation paths, and metric consumers (minutes, no compilation).
check-contracts:
    python3 -m unittest -v scripts/test_check_public_tracker_ids.py
    python3 scripts/check_public_tracker_ids.py
    python3 -m unittest -v scripts/test_check_ixp_manager_docs.py
    python3 scripts/check_ixp_manager_docs.py
    python3 -m unittest -v scripts/test_check_release_checklist_paths.py
    python3 scripts/check_release_checklist_paths.py
    python3 -m unittest -v scripts/test_check_markdown_test_pins.py
    python3 scripts/check_markdown_test_pins.py
    python3 -m unittest -v scripts/test_check_markdown_claims.py
    python3 scripts/check_markdown_claims.py
    python3 -m unittest -v scripts/test_check_metric_consumers.py
    python3 scripts/check-metric-consumers.py
    python3 -m unittest -v scripts/test_check_release_preflight.py
    just check-changelog-fragments

# Check the pending release notes under changelog.d/ assemble cleanly into CHANGELOG.md (seconds, no compilation).
check-changelog-fragments:
    python3 -m unittest -v scripts/test_assemble_changelog.py
    python3 scripts/assemble-changelog.py --check

# Merge the changelog.d/ fragments into the CHANGELOG.md `[Unreleased]` section and delete them (release preparation).
assemble-changelog:
    python3 scripts/assemble-changelog.py

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

# The library and binary docs are selected together so the binary docs reuse
# the same private library docs.

# Build the library docs (private items included) and both binary docs.
docs:
    cargo doc --locked --workspace --lib --bin rustbgpd --bin rbgp --no-deps --document-private-items

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
    git ls-files '*.md' | lychee --files-from - --offline --include-fragments=anchor-only --no-progress

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

# Run hosted CI's named script steps from the core and scale/receipt jobs, read from ci.yml; needs shellcheck and ripgrep (`--dry-run` lists the steps).
gate-ci-steps *args:
    bash scripts/build-lock.sh python3 scripts/run_ci_steps.py {{args}}

# Check every workspace target on the Cargo.toml `rust-version` toolchain, as hosted CI's msrv job does.
gate-msrv:
    #!/usr/bin/env bash
    set -euo pipefail
    msrv="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)"
    if [[ ! "${msrv}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
        echo "expected one workspace rust-version in Cargo.toml, found '${msrv}'" >&2
        exit 1
    fi
    toolchains="$(rustup toolchain list 2>/dev/null || true)"
    version_pattern="${msrv//./[.]}"
    if [[ "${msrv}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        version_pattern+='([.][0-9]+)?'
    fi
    toolchain="$(awk -v pattern="^${version_pattern}-" '$1 ~ pattern {print $1; exit}' <<<"${toolchains}")"
    if [[ -z "${toolchain}" ]]; then
        echo "Rust ${msrv} (the workspace rust-version) is required; install it with:" >&2
        echo "  rustup toolchain install ${msrv} --profile minimal" >&2
        exit 127
    fi
    # A separate target directory keeps the two toolchains' artifacts apart,
    # as CI's separate MSRV cache does.
    exec bash scripts/build-lock.sh \
        env CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/msrv-${msrv}" \
        cargo "+${toolchain}" check --locked --workspace --all-targets

# The release-only checks are skipped, and listed, while the root CHANGELOG
# `[Unreleased]` section still has entries or a changelog.d/ fragment is
# pending; `--mode release` forces them, and then refuses a leftover fragment.
# `--heavy` adds `cargo audit`, the release build, and the multi-package
# publish dry-run.

# Run the checks that otherwise first fail on a release commit: metric release notes, changelog fragments, crate changelogs, and the root changelog section.
gate-release *args:
    python3 -m unittest -v scripts/test_check_release_preflight.py
    python3 scripts/check_release_preflight.py {{args}}

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

# Fuzz targets are built and run from the crate that owns their
# `fuzz/Cargo.toml`; cargo-fuzz finds no targets from the repository root.
# `scripts/check_fuzz_target_inventory.py` is the fail-closed inventory, so
# both recipes read the crate/target pairs from it instead of keeping a
# second list that can drift.

# List every cargo-fuzz crate and target as '<crate> <target>' rows.
fuzz-list:
    python3 scripts/check_fuzz_target_inventory.py --print-targets

# Run one cargo-fuzz target from its owning crate; extra arguments reach libFuzzer.
[positional-arguments]
fuzz crate target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    crate="crates/${1#crates/}"
    target="$2"
    shift 2
    if ! python3 scripts/check_fuzz_target_inventory.py --print-targets \
        | grep -qxF "${crate} ${target}"; then
        echo "unknown fuzz target: ${crate} ${target}" >&2
        echo "run 'just fuzz-list' for the inventory" >&2
        exit 2
    fi
    RUSTUP_TOOLCHAIN="$(cat fuzz/rust-nightly.txt)"
    export RUSTUP_TOOLCHAIN
    cd "${crate}"
    exec cargo fuzz run "${target}" "$@"

# Every `bench-*` recipe measures, or smokes, a benchmark on this host. None is
# reachable from `gate`, `gate-ci`, or another check recipe, so nothing
# measures by accident. They are thin wrappers: each driver keeps its own host
# lock, quiet gate, provenance, clean-tree refusal, and thresholds, and its
# exit status passes through unchanged (75 when the host lock or a quiet gate
# says the host is busy). A recipe that runs a bare harness takes the shared
# host lock itself, through tests/soak/host-lock.sh, at
# ${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}.
#
# Single timing runs pin to RUSTBGPD_BENCH_CORE and refuse to start without
# it: receipts have used cores 2, 5, 8, 15, and 63, so there is no portable
# default. The A/B drivers receive it as `--core` when it is set and keep
# their own default otherwise. bench/scale is a separate workspace with its
# own lockfile, so its harnesses build with `--manifest-path`, outside any
# CARGO_TARGET_DIR override, where the scale drivers look for them.

# Print '<package> <target> [features]' for every Cargo bench target, read from cargo metadata.
_bench-targets:
    @cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json, sys; [print(p["name"], t["name"], ",".join(t.get("required-features") or [])) for p in json.load(sys.stdin)["packages"] for t in p["targets"] if "bench" in t["kind"]]' | LC_ALL=C sort

# List every Cargo bench target with its required features, then each benchmark driver and the recipe that runs it (measures nothing).
bench-list:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Cargo bench targets ('just bench <package> <target>'; required features in brackets):"
    just _bench-targets | awk '{ if ($3 == "") printf "  %-18s %s\n", $1, $2; else printf "  %-18s %-28s [%s]\n", $1, $2, $3 }'
    cat <<'EOF'

    Benchmark drivers:
      bench-compare                 bench/compare-criterion.sh (Criterion A/B)
      bench-rib-memory              RIB structural memory profile, one tree
      bench-compare-rib-memory      bench/compare-rib-memory.sh
      bench-compare-route-paging    bench/compare-route-paging.sh
      bench-rrharness               bench/scale/rrharness (flood, churn, late-join)
      bench-compare-rrharness       bench/scale/compare-rrharness.sh
      bench-rrtransport-smoke       rrtransport smoke (correctness only)
      bench-rrtransport             bench/scale/rrtransport/run-receipt.sh
      bench-ixp-matrix              bench/scale/matrix/run-matrix.sh
      bench-policy-stats            bench/scale/reloadstall/policy_stats_cell.sh
      bench-route-server-1000       bench/scale/route-server-1000/run-receipt.sh
      bench-enhanced-route-refresh  bench/scale/enhanced-route-refresh/run-receipt.sh
      bench-irr-reload              bench/scale/irrreload/run-irr-reload.sh
      bench-vpn-query               bench/run-vpn-query-campaign.sh
      bench-headline                bench/scale/headline/run-campaign.sh (multi-arm headline campaign)
      bench-headline-summary        bench/scale/headline/summarize.py (extraction only)
      gate-contract                 bench/smoke-benches.sh (smoke only, no measurement)

    Drivers without a recipe (run directly; see their headers):
      bench/scale/irrreload/run-bmp-buffer-receipt.sh
      bench/scale/irrreload/run-memory-attribution.sh
      bench/scale/reloadstall/failover_cell.sh
      bench/netns-calibration/run-vm.sh
      bench/evpn-load/fanout.py
      bench/run-fib-kernel-dump.py
      bench/run-mrt-attribute-scratch-campaign.py
      docs/perf/run-lean-daemon-build-flavors.sh
      docs/perf/run-explain-cache-variant.sh
    EOF

# Measure one Cargo bench target pinned to RUSTBGPD_BENCH_CORE under the host lock; required features come from its manifest and extra arguments reach the harness.
[positional-arguments]
bench package target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    core="${RUSTBGPD_BENCH_CORE:-}"
    if [[ ! $core =~ ^[0-9]+$ ]]; then
        echo "set RUSTBGPD_BENCH_CORE to the CPU core this timing run is pinned to" >&2
        exit 2
    fi
    read -r package target features < <(just _bench-targets \
        | awk -v p="$1" -v t="$2" '($1 == p || $1 == "rustbgpd-" p) && $2 == t') || true
    if [[ -z ${package:-} ]]; then
        echo "unknown bench target: $1 $2" >&2
        echo "run 'just bench-list' for the inventory" >&2
        exit 2
    fi
    shift 2
    feature_args=()
    [[ -z ${features:-} ]] || feature_args=(--features "$features")
    source tests/soak/host-lock.sh
    acquire_rustbgpd_host_lock || exit $?
    # Build unpinned first so only the measurement runs on the pinned core.
    cargo bench --locked -p "$package" "${feature_args[@]}" --bench "$target" --no-run
    exec taskset -c "$core" \
        cargo bench --locked -p "$package" "${feature_args[@]}" --bench "$target" -- "$@"

# A/B one Criterion target between two refs with compare-criterion.sh: four alternating attempts, pinned to RUSTBGPD_BENCH_CORE on the performance governor; later flags override these defaults.
[positional-arguments]
bench-compare package target base head *args:
    #!/usr/bin/env bash
    set -euo pipefail
    read -r package target features < <(just _bench-targets \
        | awk -v p="$1" -v t="$2" '($1 == p || $1 == "rustbgpd-" p) && $2 == t') || true
    if [[ -z ${package:-} ]]; then
        echo "unknown bench target: $1 $2" >&2
        echo "run 'just bench-list' for the inventory" >&2
        exit 2
    fi
    base="$3"
    head="$4"
    shift 4
    no_taskset=0
    has_core=0
    for arg in "$@"; do
        case "$arg" in
            --no-taskset) no_taskset=1 ;;
            --core) has_core=1 ;;
        esac
    done
    defaults=(--attempts 4)
    if [[ ${no_taskset} -eq 1 ]]; then
        : # mechanics only: no pin, so no governor requirement either
    elif [[ -n ${RUSTBGPD_BENCH_CORE:-} ]]; then
        defaults+=(--core "${RUSTBGPD_BENCH_CORE}" --require-performance)
    elif [[ ${has_core} -eq 1 ]]; then
        defaults+=(--require-performance)
    else
        echo "set RUSTBGPD_BENCH_CORE (or pass --core N) to pin both refs; --no-taskset is mechanics only" >&2
        exit 2
    fi
    feature_args=()
    [[ -z ${features:-} ]] || feature_args=(--features "$features")
    exec bash bench/compare-criterion.sh --base "$base" --head "$head" \
        --package "$package" --bench "$target" "${feature_args[@]}" "${defaults[@]}" "$@"

# Measure the high-N RIB structural memory profile of this tree (quick: 10k and 100k prefixes; full: 100k to 900k) under the host lock.
[positional-arguments]
bench-rib-memory profile='quick':
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
        quick|full) ;;
        *) echo "unknown profile: $1 (available: quick, full)" >&2; exit 2 ;;
    esac
    source tests/soak/host-lock.sh
    acquire_rustbgpd_host_lock || exit $?
    RUSTBGPD_RIB_MEMORY_PROFILE="$1" exec cargo test --locked -p rustbgpd-rib \
        --features bench-internals --test memory_profile memory_profile_high_n \
        -- --ignored --exact --nocapture

# A/B the RIB structural memory profile between two refs with compare-rib-memory.sh (its default profile is quick).
[positional-arguments]
bench-compare-rib-memory base head *args:
    #!/usr/bin/env bash
    set -euo pipefail
    exec bash bench/compare-rib-memory.sh --base "$1" --head "$2" "${@:3}"

# A/B route paging between the driver's two pinned commits with compare-route-paging.sh, pinned to RUSTBGPD_BENCH_CORE when set.
[positional-arguments]
bench-compare-route-paging base head *args:
    #!/usr/bin/env bash
    set -euo pipefail
    core_args=()
    [[ -z ${RUSTBGPD_BENCH_CORE:-} ]] || core_args=(--core "${RUSTBGPD_BENCH_CORE}")
    exec bash bench/compare-route-paging.sh --base "$1" --head "$2" "${core_args[@]}" "${@:3}"

# Measure one rrharness flood, churn, or late-join run pinned to RUSTBGPD_BENCH_CORE under the host lock; arguments are in bench/scale/rrharness/README.md.
[positional-arguments]
bench-rrharness mode *args:
    #!/usr/bin/env bash
    set -euo pipefail
    core="${RUSTBGPD_BENCH_CORE:-}"
    if [[ ! $core =~ ^[0-9]+$ ]]; then
        echo "set RUSTBGPD_BENCH_CORE to the CPU core this timing run is pinned to" >&2
        exit 2
    fi
    source tests/soak/host-lock.sh
    acquire_rustbgpd_host_lock || exit $?
    env -u CARGO_TARGET_DIR cargo build --release --locked \
        --manifest-path bench/scale/rrharness/Cargo.toml
    exec taskset -c "$core" bench/scale/target/release/rrharness "$@"

# A/B the fixed rrharness flood/churn matrix between two refs with compare-rrharness.sh, pinned to RUSTBGPD_BENCH_CORE when set.
[positional-arguments]
bench-compare-rrharness base head *args:
    #!/usr/bin/env bash
    set -euo pipefail
    core_args=()
    [[ -z ${RUSTBGPD_BENCH_CORE:-} ]] || core_args=(--core "${RUSTBGPD_BENCH_CORE}")
    exec bash bench/scale/compare-rrharness.sh --base "$1" --head "$2" "${core_args[@]}" "${@:3}"

# Run the fixed four-source rrtransport correctness smoke (checks exact routes; measures nothing).
bench-rrtransport-smoke:
    cargo run --manifest-path bench/scale/rrtransport/Cargo.toml --locked -- smoke

# Measure the three-attempt rrtransport rr1000 campaign into OUTPUT, a new absolute path outside the repository (`--real-smoke DIR` runs the tiny fixture instead).
[positional-arguments]
bench-rrtransport *args:
    #!/usr/bin/env bash
    set -euo pipefail
    exec bash bench/scale/rrtransport/run-receipt.sh "$@"

# The daemon is built with the IRR runner's three-package command, so one
# source gives the same daemon hash under either driver. Both recipes take
# the host lock before building, so a busy host refuses with 75 before any
# compile. run-matrix.sh takes the lock itself, and a second open of the same
# lock file conflicts even within one process tree, so bench-ixp-matrix
# releases it after the build; policy_stats_cell.sh takes none, so
# bench-policy-stats keeps holding it.

# Measure IXP reload-stall matrix cells with run-matrix.sh (default: rustbgpd bird openbgpd) after building the daemon and reloadstall; N_PEERS, FLAPSTORM, ARTIFACTS_DIR and the other knobs in its header pass through.
[positional-arguments]
bench-ixp-matrix *cells:
    #!/usr/bin/env bash
    set -euo pipefail
    source tests/soak/host-lock.sh
    acquire_rustbgpd_host_lock || exit $?
    env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
        -p rustbgpd -p rustbgpctl -p rs-config-render
    env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
        --manifest-path bench/scale/reloadstall/Cargo.toml
    # The membership cell needs more descriptors (bench/scale/reloadstall/README.md).
    [[ ${RELOADSTALL_MEMBERSHIP_CHURN:-0} != 1 ]] || ulimit -n 65536
    flock -u "$RUSTBGPD_HOST_LOCK_FD"
    exec {RUSTBGPD_HOST_LOCK_FD}>&-
    exec bash bench/scale/matrix/run-matrix.sh "$@"

# Measure the GetPolicyStats reload cell into RUN_DIR, a new directory, under the host lock; PEERS, PREFIXES, RELOADS and the CPU sets in its header pass through.
[positional-arguments]
bench-policy-stats run_dir:
    #!/usr/bin/env bash
    set -euo pipefail
    source tests/soak/host-lock.sh
    acquire_rustbgpd_host_lock || exit $?
    env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
        -p rustbgpd -p rustbgpctl -p rs-config-render
    env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
        --manifest-path bench/scale/reloadstall/Cargo.toml
    exec bash bench/scale/reloadstall/policy_stats_cell.sh \
        target/release bench/scale/target/release/reloadstall "$1"

# Measure the fixed 1,000-client route-server retained receipt (no smoke mode; needs a clean tree).
bench-route-server-1000:
    bash bench/scale/route-server-1000/run-receipt.sh

# Measure the fixed one-peer x 100,000-prefix enhanced route refresh receipt (no smoke mode; needs a clean tree).
bench-enhanced-route-refresh:
    bash bench/scale/enhanced-route-refresh/run-receipt.sh

# Measure IRR-scale reload cells with run-irr-reload.sh; SMOKE=1 is its tiny pipeline check, and N_MEMBERS, OVERLAP_FRACTION, ARTIFACTS_DIR and the other knobs in its header pass through.
[positional-arguments]
bench-irr-reload *cells:
    #!/usr/bin/env bash
    set -euo pipefail
    exec bash bench/scale/irrreload/run-irr-reload.sh "$@"

# Measure the VPN query campaign into OUTPUT, a new directory, pinned to RUSTBGPD_BENCH_CORE unless --cpu is given; `--smoke` and `--retry` come first.
[positional-arguments]
bench-vpn-query output *args:
    #!/usr/bin/env bash
    set -euo pipefail
    output="$1"
    shift
    cpu_args=()
    if [[ " $* " != *" --cpu "* && -n ${RUSTBGPD_BENCH_CORE:-} ]]; then
        cpu_args=(--cpu "${RUSTBGPD_BENCH_CORE}")
    fi
    exec bash bench/run-vpn-query-campaign.sh "$@" "${cpu_args[@]}" "$output"

# Run the headline campaign (IXP matrix S2 and S3, IRR reload, RR1000) across arms given as LABEL=REF into OUT_DIR, rotating the arm order each run; CELLS, RUNS, SMOKE=1 and DRY_RUN=1 are described in bench/scale/headline/run-campaign.sh.
[positional-arguments]
bench-headline out_dir +arms:
    #!/usr/bin/env bash
    set -euo pipefail
    exec bash bench/scale/headline/run-campaign.sh "$@"

# Re-extract summary.csv, establishment-span.csv and report.md from a headline campaign or receipt bundle without running anything (`--out DIR` for a bundle, `--exclude GLOB` to drop legs).
[positional-arguments]
bench-headline-summary source *args:
    #!/usr/bin/env bash
    set -euo pipefail
    exec python3 bench/scale/headline/summarize.py "$@"
