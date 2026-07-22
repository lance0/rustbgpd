#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091
set -euo pipefail
BASELINE_COMMIT=86bff61fe5f3a033842335c72d54bb8fa1cac836
TOOLCHAIN=1.95.0
TARGET=x86_64-unknown-linux-gnu
JOBS=${LAN548_JOBS:-4}
RUNS=${LAN548_RUNS:-3}
EXTENDED_RUNS=5
SOURCE=${RUSTBGPD_SOURCE:-$PWD}
ARTIFACT_DIR=${LAN548_ARTIFACT_DIR:-$SOURCE/docs/perf/artifacts/lean-daemon-build-flavors-2026-07}
PATCH=$ARTIFACT_DIR/prototype-features.patch
EVALUATOR=$ARTIFACT_DIR/evaluate.py
RUN_ROOT=${LAN548_RUN_ROOT:-/tmp/rustbgpd-lean-build-flavors}
[[ $RUNS -eq 3 ]] || {
    printf 'LAN548_RUNS must remain at the predeclared value 3\n' >&2
    exit 2
}
[[ $(git -C "$SOURCE" rev-parse "$BASELINE_COMMIT^{commit}") == "$BASELINE_COMMIT" ]] || {
    printf 'missing exact baseline commit %s\n' "$BASELINE_COMMIT" >&2
    exit 1
}
[[ -f $PATCH && ! -L $PATCH && -f $EVALUATOR && ! -L $EVALUATOR ]] || {
    printf 'missing static input: %s or %s\n' "$PATCH" "$EVALUATOR" >&2
    exit 1
}
mkdir -p "$ARTIFACT_DIR" "$RUN_ROOT"
TIMINGS=$ARTIFACT_DIR/timings.csv
SMOKES=$ARTIFACT_DIR/config-smokes.txt
GRAPHS=$ARTIFACT_DIR/dependency-graphs.txt.gz
AARECEIPT=$ARTIFACT_DIR/full-workspace-vs-selected-aa.txt
FRESH=$ARTIFACT_DIR/warm-artifact-freshness.txt
CONTRACT_DIGESTS=$ARTIFACT_DIR/public-contract-digests.txt
PAYLOADS=$ARTIFACT_DIR/release-payloads.csv
RESULTS=$ARTIFACT_DIR/result-summary.txt
INVENTORY=$ARTIFACT_DIR/receipt-inventory.txt
MUTATIONS=$ARTIFACT_DIR/assertion-mutations.txt
RUNNER_PATH=$SOURCE/docs/perf/run-lean-daemon-build-flavors.sh
RUNNER_SHA256=$(sha256sum "$RUNNER_PATH" | awk '{print $1}')
EVALUATOR_SHA256=$(sha256sum "$EVALUATOR" | awk '{print $1}')
PATCH_SHA256=$(sha256sum "$PATCH" | awk '{print $1}')
assert_runner_unchanged() {
    local current
    current=$(sha256sum "$RUNNER_PATH" | awk '{print $1}')
    [[ $current == "$RUNNER_SHA256" \
        && $(sha256sum "$EVALUATOR" | awk '{print $1}') == "$EVALUATOR_SHA256" \
        && $(sha256sum "$PATCH" | awk '{print $1}') == "$PATCH_SHA256" ]] || {
        printf 'runner changed during measurement: started=%s current=%s\n' \
            "$RUNNER_SHA256" "$current" >&2
        exit 1
    }
}
assertion_failed() {
    local id=$1 message=$2
    printf 'LAN548_EXPECTED_RED:%s: %s\n' "$id" "$message" >&2
    return 1
}
features_for() {
    case "$1" in
        full) printf '%s\n' 'rustbgpd/jemalloc' ;;
        no-history) printf '%s\n' 'rustbgpd/jemalloc,rustbgpd/linux-dataplane' ;;
        control-plane) printf '%s\n' 'rustbgpd/jemalloc,rustbgpd/event-history' ;;
        combined) printf '%s\n' 'rustbgpd/jemalloc' ;;
        *) printf 'unknown variant: %s\n' "$1" >&2; exit 2 ;;
    esac
}
worktree_for() {
    printf '%s/source-%s\n' "$RUN_ROOT" "$1"
}
prepare_worktree() {
    local variant=$1 worktree
    worktree=$(worktree_for "$variant")
    if [[ -e $worktree ]]; then
        git -C "$SOURCE" worktree remove --force "$worktree"
    fi
    git -C "$SOURCE" worktree add --detach "$worktree" "$BASELINE_COMMIT" >/dev/null
    if [[ $variant != full ]]; then
        git -C "$worktree" apply --check "$PATCH"
        git -C "$worktree" apply "$PATCH"
    fi
}
cargo_args() {
    local variant=$1
    printf '%s\0' \
        +"$TOOLCHAIN" build --locked \
        -p rustbgpd -p rustbgpctl -p rs-config-render \
        --release --target "$TARGET" --jobs "$JOBS" --timings \
        --no-default-features --features "$(features_for "$variant")"
}
run_build() {
    local variant=$1 target_dir=$2 json=$3 time_log=$4 worktree
    worktree=$(worktree_for "$variant")
    local -a args=()
    while IFS= read -r -d '' arg; do args+=("$arg"); done < <(cargo_args "$variant")
    assert_runner_unchanged
    (
        cd "$worktree"
        CARGO_TARGET_DIR=$target_dir CARGO_INCREMENTAL=0 \
            /usr/bin/time -v cargo "${args[@]}" --message-format=json-render-diagnostics \
            >"$json" 2>"$time_log"
    )
    assert_runner_unchanged
}
elapsed_seconds() {
    python3 - "$1" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"Elapsed \(wall clock\) time.*: (?:(\d+):)?(\d+):(\d+(?:\.\d+)?)", text)
if not match:
    raise SystemExit("missing /usr/bin/time elapsed value")
hours = int(match.group(1) or 0)
minutes = int(match.group(2))
seconds = float(match.group(3))
print(f"{hours * 3600 + minutes * 60 + seconds:.2f}")
PY
}
time_value() {
    local label=$1 file=$2
    sed -n "s/^[[:space:]]*$label: //p" "$file" | tail -1
}
record_timing() {
    local phase=$1 round=$2 order=$3 variant=$4 target_dir=$5 json=$6 time_log=$7
    local fresh elapsed user system max_rss timing_html timing_hash
    fresh=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "rustbgpd" and .executable != null) | .fresh' \
        "$json" | tail -1)
    [[ $fresh == false ]] || {
        printf '%s/%s rustbgpd artifact was not rebuilt (fresh=%s)\n' "$phase" "$variant" "$fresh" >&2
        exit 1
    }
    elapsed=$(elapsed_seconds "$time_log")
    user=$(time_value 'User time (seconds)' "$time_log")
    system=$(time_value 'System time (seconds)' "$time_log")
    max_rss=$(time_value 'Maximum resident set size (kbytes)' "$time_log")
    timing_html=$target_dir/cargo-timings/cargo-timing.html
    [[ -f $timing_html ]] || { printf 'missing Cargo timing HTML\n' >&2; exit 1; }
    timing_hash=$(sha256sum "$timing_html" | awk '{print $1}')
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$phase" "$round" "$order" "$variant" "$elapsed" "$user" "$system" "$max_rss" "$timing_hash" \
        >>"$TIMINGS"
    printf '%s round=%s order=%s variant=%s fresh=%s\n' \
        "$phase" "$round" "$order" "$variant" "$fresh" >>"$FRESH"
}
sanitize_tree() {
    sed -E \
        -e 's#\(/[^)]*/rustbgpd-lean-build-flavors/source-[^)]+\)#(<WORKTREE>)#g' \
        -e 's#/home/[^/[:space:]]+#<HOME>#g'
}
write_graphs() {
    local graph_text=$RUN_ROOT/dependency-graphs.txt
    : >"$graph_text"
    local variant worktree features tree_file
    for variant in full no-history control-plane combined; do
        worktree=$(worktree_for "$variant")
        features=$(features_for "$variant")
        tree_file=$RUN_ROOT/tree-$variant.txt
        (
            cd "$worktree"
            cargo +"$TOOLCHAIN" tree --locked -p rustbgpd --target "$TARGET" \
                -e normal,build,features --no-default-features --features "$features"
        ) >"$tree_file"
        {
            printf '===== %s =====\n' "$variant"
            sanitize_tree <"$tree_file"
        } >>"$graph_text"
    done
    check_graphs
    gzip -9 -n -c "$graph_text" >"$GRAPHS"
}
check_graphs() {
    GRAPH_MUTATIONS=()
    assert_graph_present() {
        local id=$1 file=$2 package=$3
        local needle=$package
        GRAPH_MUTATIONS+=("$id")
        if [[ ${LAN548_ASSERTION_MUTATION:-} == "$id" ]]; then
            needle=lan548-intentionally-missing-package
        fi
        rg -q --fixed-strings "$needle v" "$file" ||
            assertion_failed "$id" "expected $package in dependency graph"
    }
    assert_graph_absent() {
        local id=$1 file=$2 package=$3
        local needle=$package
        GRAPH_MUTATIONS+=("$id")
        if [[ ${LAN548_ASSERTION_MUTATION:-} == "$id" ]]; then
            needle=bytes
        fi
        ! rg -q --fixed-strings "$needle v" "$file" ||
            assertion_failed "$id" "expected $package to be absent from dependency graph"
    }
    local sqlite_package netlink_package
    for sqlite_package in rusqlite libsqlite3-sys; do
        assert_graph_present "graph-full-present-$sqlite_package" "$RUN_ROOT/tree-full.txt" "$sqlite_package"
        assert_graph_absent "graph-no-history-absent-$sqlite_package" "$RUN_ROOT/tree-no-history.txt" "$sqlite_package"
        assert_graph_present "graph-control-plane-present-$sqlite_package" "$RUN_ROOT/tree-control-plane.txt" "$sqlite_package"
        assert_graph_absent "graph-combined-absent-$sqlite_package" "$RUN_ROOT/tree-combined.txt" "$sqlite_package"
    done
    for netlink_package in \
        rtnetlink netlink-packet-route netlink-packet-core \
        netlink-packet-utils netlink-proto netlink-sys
    do
        assert_graph_present "graph-full-present-$netlink_package" "$RUN_ROOT/tree-full.txt" "$netlink_package"
        assert_graph_present "graph-no-history-present-$netlink_package" "$RUN_ROOT/tree-no-history.txt" "$netlink_package"
        assert_graph_absent "graph-control-plane-absent-$netlink_package" "$RUN_ROOT/tree-control-plane.txt" "$netlink_package"
        assert_graph_absent "graph-combined-absent-$netlink_package" "$RUN_ROOT/tree-combined.txt" "$netlink_package"
    done
}
expect_config_ok() {
    local binary=$1 config=$2 label=$3
    local log=$RUN_ROOT/smoke-$label.log
    SMOKE_MUTATIONS+=("accept-$label")
    if [[ ${LAN548_ASSERTION_MUTATION:-} == accept-$label ]]; then
        case "$label" in
            full-*) config=$RUN_ROOT/lan548-does-not-exist.toml ;;
            no-history-*) config=$RUN_ROOT/gnmi-on-change-host.toml ;;
            control-plane-*) config=$(worktree_for control-plane)/examples/evpn-vtep-leaf/config.toml ;;
            combined-*) config=$RUN_ROOT/gnmi-on-change-host.toml ;;
        esac
    fi
    if ! "$binary" --check "$config" >"$log" 2>&1; then
        cat "$log" >&2
        assertion_failed "accept-$label" "$label unexpectedly rejected"
    fi
    printf 'PASS %s\n' "$label" >>"$SMOKES"
}
expect_config_rejected() {
    local binary=$1 config=$2 label=$3 log=$RUN_ROOT/smoke.log omission='Linux dataplane writers'
    SMOKE_MUTATIONS+=("reject-$label")
    if [[ ${LAN548_ASSERTION_MUTATION:-} == reject-$label ]]; then
        config=$(worktree_for control-plane)/examples/rr-evpn-fabric/config.toml
    fi
    if "$binary" --check "$config" >"$log" 2>&1; then
        assertion_failed "reject-$label" "$label unexpectedly accepted"
    fi
    case "$label" in no-history|gnmi-on-change|combined-no-history|combined-gnmi-on-change) omission='durable event history' ;; esac
    if ! rg -q --fixed-strings "build omits $omission" "$log"; then
        cat "$log" >&2
        assertion_failed "reject-$label" "$label failed for the wrong reason"
    fi
    printf 'PASS %s: %s\n' "$label" "$(tr '\n' ' ' <"$log" | sed -E 's#/[^ ]+#<PATH>#g')" >>"$SMOKES"
}
run_smokes() {
    : >"$SMOKES"
    SMOKE_MUTATIONS=()
    local no_history_source control_source full_source config
    no_history_source=$(worktree_for no-history)
    control_source=$(worktree_for control-plane)
    full_source=$(worktree_for full)
    config=$RUN_ROOT/event-history-enabled.toml
    cp "$no_history_source/examples/rr-evpn-fabric/config.toml" "$config"
    printf '\n[event_history]\nenabled = true\n' >>"$config"
    local event_history_disabled=$RUN_ROOT/event-history-disabled.toml
    cp "$no_history_source/examples/rr-evpn-fabric/config.toml" "$event_history_disabled"
    printf '\n[event_history]\nenabled = false\n' >>"$event_history_disabled"
    local all_families=$RUN_ROOT/all-rr-families.toml
    sed 's/families = \["l2vpn_evpn"\]/families = ["ipv4_unicast", "ipv6_unicast", "ipv4_flowspec", "ipv6_flowspec", "linkstate", "linkstate_vpn", "l2vpn_evpn", "l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast", "ipv4_labeled_unicast", "ipv6_labeled_unicast", "rtc"]/g' \
        "$full_source/examples/rr-evpn-fabric/config.toml" >"$all_families"
    local gnmi_on_change=$RUN_ROOT/gnmi-on-change-host.toml
    sed -e 's/^\[global.telemetry.grpc_tcp\]$/[global.telemetry.grpc_uds]/' \
        -e 's#^address = "0.0.0.0:50051"$#path = "/tmp/rustbgpd-lean-gnmi.sock"\nprincipal = "rustbgpd://operator/ci"#' \
        -e '/^tls_.*_file = /d' \
        "$full_source/tests/interop/configs/rustbgpd-m56-gnmi-onchange.toml" >"$gnmi_on_change"
    hostify_token_fixture() {
        sed -e 's/^\[global.telemetry.grpc_tcp\]$/[global.telemetry.grpc_uds]/' \
            -e 's#^address = "0.0.0.0:50051"$#path = "/tmp/rustbgpd-lean-config-check.sock"#' \
            -e '/^token_file = /d' \
            "$1" >"$2"
    }
    local injector_host=$RUN_ROOT/injector-host.toml
    hostify_token_fixture \
        "$full_source/tests/interop/configs/rustbgpd-m45-injector.toml" "$injector_host"
    local blackhole_host=$RUN_ROOT/blackhole-host.toml
    hostify_token_fixture \
        "$full_source/tests/interop/configs/rustbgpd-m62-blackhole.toml" "$blackhole_host"
    local managed_netdev=$RUN_ROOT/managed-netdev.toml
    cp "$control_source/examples/rr-evpn-fabric/config.toml" "$managed_netdev"
    cat >>"$managed_netdev" <<'TOML'
[managed_netdevs]
owner_token = "lean-smoke"
[[managed_netdevs.bridges]]
name = "br-lean-smoke"
vlan_filtering = false
TOML
    local expectation variant fixture label source binary fixture_path
    while read -r expectation variant fixture label; do
        source=$(worktree_for "$variant")
        binary=$RUN_ROOT/target-$variant-clean-3/$TARGET/release/rustbgpd
        [[ $variant != combined ]] || binary=$RUN_ROOT/target-combined-marginal-clean-3/$TARGET/release/rustbgpd
        [[ $variant != combined || -x $binary ]] || continue
        case "$fixture" in
            route-server) fixture_path=$source/examples/route-server/config.toml ;;
            evpn-rr) fixture_path=$source/examples/rr-evpn-fabric/config.toml ;;
            all-families) fixture_path=$all_families ;;
            injector) fixture_path=$injector_host ;;
            event-disabled) fixture_path=$event_history_disabled ;;
            event-enabled) fixture_path=$config ;;
            gnmi) fixture_path=$gnmi_on_change ;;
            fib) fixture_path=$source/examples/linux-edge-fib/config.toml ;;
            blackhole) fixture_path=$blackhole_host ;;
            vtep) fixture_path=$source/examples/evpn-vtep-leaf/config.toml ;;
            irb) fixture_path=$source/tests/interop/configs/rustbgpd-m39-pe1.toml ;;
            managed) fixture_path=$managed_netdev ;;
            ddos) fixture_path=$source/examples/ddos-mitigation/config.toml ;;
        esac
        if [[ $variant == combined && $expectation == reject \
            && $fixture != event-enabled && $fixture != gnmi ]]; then
            cp "$fixture_path" "$RUN_ROOT/combined-$fixture.toml"
            printf '\n[event_history]\nenabled = false\n' >>"$RUN_ROOT/combined-$fixture.toml"
            fixture_path=$RUN_ROOT/combined-$fixture.toml
        fi
        if [[ $expectation == accept ]]; then
            expect_config_ok "$binary" "$fixture_path" "$label"
        else
            expect_config_rejected "$binary" "$fixture_path" "$label"
        fi
    done <<'CASES'
accept full gnmi full-gnmi-on-change-history
accept full fib full-fib
accept full blackhole full-blackhole
accept full vtep full-local-evpn-vtep-bum
accept full irb full-irb
accept full managed full-managed-netdev
accept full all-families full-all-rr-families
accept no-history route-server no-history-route-server
accept no-history evpn-rr no-history-evpn-rr
accept no-history all-families no-history-all-rr-families
accept no-history injector no-history-controller-injection
accept no-history event-disabled no-history-explicit-disabled
accept no-history fib no-history-fib
accept no-history blackhole no-history-blackhole
accept no-history vtep no-history-local-evpn-vtep-bum
accept no-history irb no-history-irb
accept no-history managed no-history-managed-netdev
accept control-plane route-server control-plane-route-server
accept control-plane evpn-rr control-plane-evpn-rr
accept control-plane all-families control-plane-all-rr-families
accept control-plane injector control-plane-controller-injection
accept control-plane ddos control-plane-honor-blackhole-no-install
accept control-plane event-disabled control-plane-event-history-disabled
accept control-plane gnmi control-plane-gnmi-on-change-history
reject no-history event-enabled no-history
reject no-history gnmi gnmi-on-change
reject control-plane fib fib
reject control-plane blackhole blackhole
reject control-plane vtep local-evpn-vtep-bum
reject control-plane irb irb
reject control-plane managed managed-netdev
accept combined route-server combined-route-server
accept combined evpn-rr combined-evpn-rr
accept combined all-families combined-all-rr-families
accept combined injector combined-controller-injection
accept combined event-disabled combined-event-history-disabled
accept combined ddos combined-honor-blackhole-no-install
reject combined event-enabled combined-no-history
reject combined gnmi combined-gnmi-on-change
reject combined fib combined-fib
reject combined blackhole combined-blackhole
reject combined vtep combined-local-evpn-vtep-bum
reject combined irb combined-irb
reject combined managed combined-managed-netdev
CASES
}
run_contract_digests() {
    : >"$CONTRACT_DIGESTS"
    CONTRACT_MUTATIONS=()
    local full_source variant source release_dir id actual expected
    local -a variants=(no-history control-plane)
    full_source=$(worktree_for full)
    [[ ! -x $RUN_ROOT/target-combined-marginal-clean-3/$TARGET/release/rustbgpd ]] ||
        variants+=(combined)
    contract_source_digest() {
        find "$1/proto" -type f -name '*.proto' -print0 | sort -z |
            xargs -0 sha256sum | sed -E 's#  .*/proto/#  proto/#' |
            sha256sum | awk '{print $1}'
    }
    help_digest() { "$1" --help | sha256sum | awk '{print $1}'; }
    local proto_full daemon_full rbgp_full
    proto_full=$(contract_source_digest "$full_source")
    daemon_full=$(help_digest "$RUN_ROOT/target-full-clean-3/$TARGET/release/rustbgpd")
    rbgp_full=$(help_digest "$RUN_ROOT/target-full-clean-3/$TARGET/release/rbgp")
    for variant in "${variants[@]}"; do
        source=$(worktree_for "$variant")
        if [[ $variant == combined ]]; then
            release_dir=$RUN_ROOT/target-combined-marginal-clean-3/$TARGET/release
        else
            release_dir=$RUN_ROOT/target-$variant-clean-3/$TARGET/release
        fi
        for id in protobuf daemon-help rbgp-help; do
            CONTRACT_MUTATIONS+=("contract-$variant-$id")
            case "$id" in
                protobuf) actual=$(contract_source_digest "$source"); expected=$proto_full ;;
                daemon-help) actual=$(help_digest "$release_dir/rustbgpd"); expected=$daemon_full ;;
                rbgp-help) actual=$(help_digest "$release_dir/rbgp"); expected=$rbgp_full ;;
            esac
            [[ ${LAN548_ASSERTION_MUTATION:-} != contract-$variant-$id ]] || actual=mutation
            [[ $actual == "$expected" ]] ||
                assertion_failed "contract-$variant-$id" "$id contract changed"
        done
    done
    printf 'protobuf_sha256=%s\nrustbgpd_help_sha256=%s\nrbgp_help_sha256=%s\n' \
        "$proto_full" "$daemon_full" "$rbgp_full" >"$CONTRACT_DIGESTS"
}

selected_build() {
    local source=$1 target_dir=$2
    (
        cd "$source"
        CARGO_TARGET_DIR=$target_dir CARGO_INCREMENTAL=0 \
            cargo +"$TOOLCHAIN" build --locked \
            -p rustbgpd -p rustbgpctl -p rs-config-render \
            --release --target "$TARGET" --jobs "$JOBS" \
            --no-default-features \
            --features rustbgpd/jemalloc
    )
}
workspace_build() {
    local source=$1 target_dir=$2
    (
        cd "$source"
        CARGO_TARGET_DIR=$target_dir CARGO_INCREMENTAL=0 \
            cargo +"$TOOLCHAIN" build --locked --workspace \
            --release --target "$TARGET" --jobs "$JOBS" \
            --no-default-features \
            --features rustbgpd/jemalloc
    )
}
run_aa() {
    local source selected_target workspace_target selected workspace same_target
    local selected_tree workspace_tree workspace_json same_target_fresh
    local selected_gzip workspace_gzip
    source=$(worktree_for full)
    selected_target=$RUN_ROOT/target-aa-selected
    workspace_target=$RUN_ROOT/target-aa-workspace
    rm -rf "$selected_target" "$workspace_target"
    # Separate targets expose LTO nondeterminism; workspace is the size control.
    selected_build "$source" "$selected_target"
    selected=$RUN_ROOT/aa-selected.stripped
    cp "$selected_target/$TARGET/release/rustbgpd" "$selected"
    strip --strip-all "$selected"
    selected_gzip=$RUN_ROOT/aa-selected.stripped.gz
    gzip -9 -n -c "$selected" >"$selected_gzip"
    workspace_build "$source" "$workspace_target"
    workspace=$RUN_ROOT/aa-workspace.stripped
    cp "$workspace_target/$TARGET/release/rustbgpd" "$workspace"
    strip --strip-all "$workspace"
    workspace_gzip=$RUN_ROOT/aa-workspace.stripped.gz
    gzip -9 -n -c "$workspace" >"$workspace_gzip"
    # Same-target Cargo JSON reveals feature rebuild vs a fresh artifact.
    workspace_json=$RUN_ROOT/aa-workspace-same-target.json
    (
        cd "$source"
        CARGO_TARGET_DIR=$selected_target CARGO_INCREMENTAL=0 \
            cargo +"$TOOLCHAIN" build --locked --workspace \
            --release --target "$TARGET" --jobs "$JOBS" \
            --no-default-features --features rustbgpd/jemalloc \
            --message-format=json-render-diagnostics >"$workspace_json"
    )
    same_target=$RUN_ROOT/aa-workspace-same-target.stripped
    cp "$selected_target/$TARGET/release/rustbgpd" "$same_target"
    strip --strip-all "$same_target"
    same_target_fresh=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "rustbgpd" and .executable != null) | .fresh' \
        "$workspace_json" | tail -1)
    [[ $same_target_fresh == true || $same_target_fresh == false ]] || {
        printf 'missing same-target rustbgpd Cargo artifact receipt\n' >&2
        exit 1
    }
    assert_aa_equivalence
    selected_tree=$RUN_ROOT/aa-selected-tree.txt
    workspace_tree=$RUN_ROOT/aa-workspace-tree.txt
    (
        cd "$source"
        cargo +"$TOOLCHAIN" tree --locked -p rustbgpd --target "$TARGET" \
            -e normal,build,features --no-default-features --features rustbgpd/jemalloc \
            | sanitize_tree
    ) >"$selected_tree"
    (
        cd "$source"
        cargo +"$TOOLCHAIN" tree --locked --workspace --target "$TARGET" \
            -e normal,build,features --no-default-features --features rustbgpd/jemalloc \
            | sanitize_tree
    ) >"$workspace_tree"
    {
        printf 'baseline_commit=%s\n' "$BASELINE_COMMIT"
        printf 'selected_separate_target_raw_bytes=%s\n' "$(stat -c %s "$selected_target/$TARGET/release/rustbgpd")"
        printf 'selected_separate_target_stripped_bytes=%s\n' "$(stat -c %s "$selected")"
        printf 'selected_separate_target_gzip_bytes=%s\n' "$(stat -c %s "$selected_gzip")"
        printf 'workspace_separate_target_raw_bytes=%s\n' "$(stat -c %s "$workspace_target/$TARGET/release/rustbgpd")"
        printf 'workspace_separate_target_stripped_bytes=%s\n' "$(stat -c %s "$workspace")"
        printf 'workspace_separate_target_gzip_bytes=%s\n' "$(stat -c %s "$workspace_gzip")"
        printf 'selected_separate_target_sha256=%s\n' "$(sha256sum "$selected" | awk '{print $1}')"
        printf 'selected_separate_target_gzip_sha256=%s\n' "$(sha256sum "$selected_gzip" | awk '{print $1}')"
        printf 'workspace_separate_target_sha256=%s\n' "$(sha256sum "$workspace" | awk '{print $1}')"
        printf 'workspace_separate_target_gzip_sha256=%s\n' "$(sha256sum "$workspace_gzip" | awk '{print $1}')"
        printf 'separate_target_binary_equal=%s\n' "$(cmp -s "$selected" "$workspace" && printf true || printf false)"
        printf 'same_target_workspace_artifact_fresh=%s\n' "$same_target_fresh"
        printf 'same_target_selected_then_workspace_sha256=%s\n' "$(sha256sum "$same_target" | awk '{print $1}')"
        printf 'same_target_binary_equal=%s\n' "$(cmp -s "$selected" "$same_target" && printf true || printf false)"
        printf 'selected_graph_sha256=%s\n' "$(sha256sum "$selected_tree" | awk '{print $1}')"
        printf 'workspace_graph_sha256=%s\n' "$(sha256sum "$workspace_tree" | awk '{print $1}')"
        printf 'note=workspace size is the shipped-artifact control; target-dir hash divergence is recorded but never aborts; all timed shapes use identical selected-package invocations\n'
    } >"$AARECEIPT"
}
assert_aa_equivalence() {
    local right=$RUN_ROOT/aa-workspace-same-target.stripped
    [[ ${LAN548_ASSERTION_MUTATION:-} != aa-same-target-equivalence ]] || right=$PATCH
    cmp -s "$RUN_ROOT/aa-selected.stripped" "$right" || \
        assertion_failed aa-same-target-equivalence 'selected/workspace same-target binary mismatch'
}
release_dir_for() {
    case "$1" in
        full) printf '%s/%s/release\n' "$RUN_ROOT/target-aa-workspace" "$TARGET" ;;
        no-history|control-plane) printf '%s/%s/release\n' \
            "$RUN_ROOT/target-$1-clean-$RUNS" "$TARGET" ;;
        combined) printf '%s/%s/release\n' \
            "$RUN_ROOT/target-combined-marginal-clean-$RUNS" "$TARGET" ;;
        *) printf 'unknown payload variant: %s\n' "$1" >&2; exit 2 ;;
    esac
}
record_release_payload() {
    local variant=$1 label=${2:-$1} release_dir=${3:-} source stage archive file
    local -a entries=(
        rustbgpd rbgp rs-config-render LICENSE-MIT LICENSE-APACHE
        rustbgpd.schema.json share
    )
    source=$(worktree_for "$variant")
    [[ -n $release_dir ]] || release_dir=$(release_dir_for "$variant")
    stage=$RUN_ROOT/payload-$label
    archive=$RUN_ROOT/payload-$label.tar.gz
    rm -rf "$stage"
    mkdir -p "$stage/share/man/man1" "$stage/share/man/man8" "$stage/share/completions"
    for file in rustbgpd rbgp rs-config-render; do
        [[ -x $release_dir/$file ]] || {
            printf 'missing payload binary: %s\n' "$release_dir/$file" >&2
            exit 1
        }
        cp "$release_dir/$file" "$stage/$file"
    done
    cp "$source/LICENSE-MIT" "$source/LICENSE-APACHE" "$stage/"
    cp "$source/docs/rustbgpd.schema.json" "$stage/"
    "$release_dir/rbgp" man >"$stage/share/man/man1/rbgp.1"
    "$release_dir/rustbgpd" --man >"$stage/share/man/man8/rustbgpd.8"
    for file in bash zsh fish; do
        "$release_dir/rbgp" completions "$file" >"$stage/share/completions/rbgp.$file"
    done
    find "$stage" -type d -exec chmod 0755 {} +
    find "$stage" -type f -exec chmod 0644 {} +
    chmod 0755 "$stage/rustbgpd" "$stage/rbgp" "$stage/rs-config-render"
    for file in \
        rustbgpd rbgp rs-config-render LICENSE-MIT LICENSE-APACHE \
        rustbgpd.schema.json share/man/man1/rbgp.1 share/man/man8/rustbgpd.8 \
        share/completions/rbgp.bash share/completions/rbgp.zsh \
        share/completions/rbgp.fish
    do
        [[ -s $stage/$file ]] || {
            printf 'empty release payload member: %s/%s\n' "$variant" "$file" >&2
            exit 1
        }
    done
    LC_ALL=C tar -C "$stage" --sort=name --mtime=@0 --owner=0 --group=0 \
        --numeric-owner -cf - "${entries[@]}" | gzip -9 -n >"$archive"
    printf '%s,%s,%s\n' "$label" "$(stat -c %s "$archive")" \
        "$(sha256sum "$archive" | awk '{print $1}')" >>"$PAYLOADS"
}
write_primary_payloads() {
    printf 'variant,normalized_release_payload_gzip_bytes,sha256\n' >"$PAYLOADS"
    local variant
    for variant in full no-history control-plane; do
        record_release_payload "$variant"
    done
}
initialize_measurements() {
    printf 'phase,round,order,variant,elapsed_seconds,user_seconds,system_seconds,max_rss_kib,cargo_timing_sha256\n' >"$TIMINGS"
    : >"$FRESH"
}
run_primary_rounds() {
    local first_round=$1 last_round=$2
    local -a order
    local round position variant target_dir json time_log
    for ((round = first_round; round <= last_round; round++)); do
        case $(( (round - 1) % 3 )) in
            0) order=(full no-history control-plane) ;;
            1) order=(no-history control-plane full) ;;
            2) order=(control-plane full no-history) ;;
        esac
        position=0
        for variant in "${order[@]}"; do
            position=$((position + 1))
            target_dir=$RUN_ROOT/target-$variant-clean-$round
            json=$RUN_ROOT/$variant-clean-$round.json
            time_log=$RUN_ROOT/$variant-clean-$round.time
            rm -rf "$target_dir"
            run_build "$variant" "$target_dir" "$json" "$time_log"
            record_timing clean "$round" "$position" "$variant" "$target_dir" "$json" "$time_log"
            if [[ $round -eq "$RUNS" ]]; then
                gzip -9 -n -c "$target_dir/cargo-timings/cargo-timing.html" \
                    >"$ARTIFACT_DIR/cargo-timing-$variant.html.gz"
            fi
        done
    done
    # Reuse clean round three so extensions do not change cache population.
    for ((round = first_round; round <= last_round; round++)); do
        case $(( (round - 1) % 3 )) in
            0) order=(full no-history control-plane) ;;
            1) order=(no-history control-plane full) ;;
            2) order=(control-plane full no-history) ;;
        esac
        position=0
        for variant in "${order[@]}"; do
            position=$((position + 1))
            target_dir=$RUN_ROOT/target-$variant-clean-$RUNS
            json=$RUN_ROOT/$variant-warm-$round.json
            time_log=$RUN_ROOT/$variant-warm-$round.time
            touch "$(worktree_for "$variant")/src/main.rs"
            run_build "$variant" "$target_dir" "$json" "$time_log"
            record_timing warm "$round" "$position" "$variant" "$target_dir" "$json" "$time_log"
        done
    done
}
run_combined_pair_rounds() {
    local winner=$1 first_round=$2 last_round=$3
    local -a order
    local round position variant target_dir json time_log
    for ((round = first_round; round <= last_round; round++)); do
        if (( round % 2 == 1 )); then
            order=("$winner" combined)
        else
            order=(combined "$winner")
        fi
        position=0
        for variant in "${order[@]}"; do
            position=$((position + 1))
            target_dir=$RUN_ROOT/target-$variant-marginal-clean-$round
            json=$RUN_ROOT/$variant-marginal-clean-$round.json
            time_log=$RUN_ROOT/$variant-marginal-clean-$round.time
            rm -rf "$target_dir"
            run_build "$variant" "$target_dir" "$json" "$time_log"
            record_timing marginal-clean "$round" "$position" "$variant" \
                "$target_dir" "$json" "$time_log"
            if [[ $variant == combined && $round -eq "$RUNS" ]]; then
                gzip -9 -n -c "$target_dir/cargo-timings/cargo-timing.html" \
                    >"$ARTIFACT_DIR/cargo-timing-combined.html.gz"
            fi
        done
    done
    for ((round = first_round; round <= last_round; round++)); do
        if (( round % 2 == 1 )); then
            order=("$winner" combined)
        else
            order=(combined "$winner")
        fi
        position=0
        for variant in "${order[@]}"; do
            position=$((position + 1))
            target_dir=$RUN_ROOT/target-$variant-marginal-clean-$RUNS
            json=$RUN_ROOT/$variant-marginal-warm-$round.json
            time_log=$RUN_ROOT/$variant-marginal-warm-$round.time
            touch "$(worktree_for "$variant")/src/main.rs"
            run_build "$variant" "$target_dir" "$json" "$time_log"
            record_timing marginal-warm "$round" "$position" "$variant" \
                "$target_dir" "$json" "$time_log"
        done
    done
}
write_environment() {
    local output=$ARTIFACT_DIR/environment.txt
    {
        printf 'baseline_commit=%s\n' "$BASELINE_COMMIT"
        printf 'prototype_patch_sha256=%s\n' "$PATCH_SHA256"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA256"
        printf 'evaluator_sha256=%s\n' "$EVALUATOR_SHA256"
        printf 'toolchain=%s\n' "$TOOLCHAIN"
        printf 'target=%s\n' "$TARGET"
        printf 'profile=release\nallocator=jemalloc\njobs=%s\nincremental=0\n' "$JOBS"
        printf 'kernel=%s\n' "$(uname -srm)"
        printf 'architecture=%s\n' "$(uname -m)"
        printf 'cpu_model=%s\n' "$(awk -F: '/model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)"
        printf 'logical_cpus=%s\n' "$(getconf _NPROCESSORS_ONLN)"
        printf 'memory_bytes=%.0f\n' "$(awk '/MemTotal:/ { print $2 * 1024 }' /proc/meminfo)"
        cargo +"$TOOLCHAIN" --version
        rustc +"$TOOLCHAIN" -vV | sed 's#^host:.*#host: <BENCH_HOST>#'
        printf 'linker=%s\n' "$(cc --version | head -1)"
        printf 'strip=%s\n' "$(strip --version | head -1)"
        printf 'gzip=%s\n' "$(gzip --version | head -1)"
    } >"$output"
}
evaluate_results() {
    python3 "$EVALUATOR" "$TIMINGS" "$PAYLOADS" "$RESULTS" \
        "$RUN_ROOT/evaluation-state.env" "${LAN548_EVALUATOR_SELF_TEST:-0}"
}
reset_generated_artifacts() {
    local path name
    [[ -z $(find "$ARTIFACT_DIR" -mindepth 1 -type d -print -quit) ]] || { printf 'unexpected artifact subdirectory\n' >&2; exit 1; }
    while IFS= read -r -d '' path; do
        name=${path##*/}
        if [[ $name == prototype-features.patch || $name == evaluate.py ]]; then
            continue
        fi
        expected_artifacts | rg -qxF "$name" || {
            printf 'unknown artifact refuses automatic deletion: %s\n' "$path" >&2
            exit 1
        }
        rm "$path"
    done < <(find "$ARTIFACT_DIR" -maxdepth 1 -type f -print0)
}
expected_artifacts() {
    printf '%s\n' \
        prototype-features.patch evaluate.py environment.txt dependency-graphs.txt.gz \
        config-smokes.txt timings.csv release-payloads.csv \
        full-workspace-vs-selected-aa.txt warm-artifact-freshness.txt \
        public-contract-digests.txt assertion-mutations.txt result-summary.txt \
        receipt-inventory.txt cargo-timing-full.html.gz \
        cargo-timing-no-history.html.gz cargo-timing-control-plane.html.gz
    if [[ -f $ARTIFACT_DIR/cargo-timing-combined.html.gz ]]; then
        printf '%s\n' cargo-timing-combined.html.gz
    fi
    printf '%s\n' SHA256SUMS
}
assert_artifact_inventory() {
    local include_checksum=$1 actual=$RUN_ROOT/artifacts-actual.txt
    local expected=$RUN_ROOT/artifacts-expected.txt
    [[ -z $(find "$ARTIFACT_DIR" -mindepth 1 -type d -print -quit) ]] || { printf 'unexpected artifact subdirectory\n' >&2; exit 1; }
    find "$ARTIFACT_DIR" -maxdepth 1 -type f -printf '%f\n' | sort >"$actual"
    expected_artifacts | if [[ $include_checksum == false ]]; then
        sed '/^SHA256SUMS$/d'
    else
        cat
    fi | sort >"$expected"
    if ! diff -u "$expected" "$actual"; then
        printf 'artifact inventory differs from the sealed schema\n' >&2
        exit 1
    fi
}
write_inventory() {
    {
        printf 'runner_sha256=%s\n' "$RUNNER_SHA256"
        printf 'prototype_patch_sha256=%s\n' "$PATCH_SHA256"
        printf 'evaluator_sha256=%s\n' "$EVALUATOR_SHA256"
        printf 'selected_packages=rustbgpd,rustbgpctl,rs-config-render\n'
        printf 'full=sqlite-present,netlink-present\n'
        printf 'no-history=sqlite-absent,netlink-present\n'
        printf 'control-plane=sqlite-present,netlink-absent\n'
        printf 'combined=sqlite-absent,netlink-absent;timing-conditional\n'
        printf 'no-history_removed_native_build_unit=libsqlite3-sys bundled SQLite C compilation\n'
        printf 'control-plane_removed_compile_units=rtnetlink and netlink protocol crates\n'
        printf 'native_toolchain_still_required=jemalloc and TLS build units remain\n'
        printf 'artifacts:\n'
        expected_artifacts | sed 's/^/  /'
    } >"$INVENTORY"
}
write_checksums() {
    assert_runner_unchanged
    assert_artifact_inventory false
    (
        cd "$ARTIFACT_DIR"
        find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
            | sort -z \
            | xargs -0 sha256sum
    ) >"$ARTIFACT_DIR/SHA256SUMS"
    assert_artifact_inventory true
}
self_test_assertions() {
    local mutation expected_rc=0 mutation_log=$RUN_ROOT/assertion-mutation.log
    local log=$RUN_ROOT/assertion-mutations.txt
    local -a mutations=()
    : >"$log"
    write_graphs
    run_smokes
    run_contract_digests
    mutations+=("${GRAPH_MUTATIONS[@]}" "${SMOKE_MUTATIONS[@]}" "${CONTRACT_MUTATIONS[@]}")
    mutations+=(
        aa-same-target-equivalence
    )
    for mutation in "${mutations[@]}"; do
        set +e
        case "$mutation" in
            aa-*) (set -e; LAN548_ASSERTION_MUTATION=$mutation assert_aa_equivalence) >"$mutation_log" 2>&1 ;;
            graph-*) (set -e; LAN548_ASSERTION_MUTATION=$mutation check_graphs) >"$mutation_log" 2>&1 ;;
            contract-*) (set -e; LAN548_ASSERTION_MUTATION=$mutation run_contract_digests) >"$mutation_log" 2>&1 ;;
            *) (set -e; LAN548_ASSERTION_MUTATION=$mutation run_smokes) >"$mutation_log" 2>&1 ;;
        esac
        expected_rc=$?
        set -e
        [[ $expected_rc -ne 0 ]] || {
            printf 'assertion mutation stayed green: %s\n' "$mutation" >&2
            exit 1
        }
        rg -q --fixed-strings "LAN548_EXPECTED_RED:$mutation:" "$mutation_log" || {
            printf 'mutation failed without its expected sentinel: %s\n' "$mutation" >&2
            cat "$mutation_log" >&2
            exit 1
        }
        printf 'RED %s exit=%s\n' "$mutation" "$expected_rc" >>"$log"
    done
    LAN548_EVALUATOR_SELF_TEST=1 evaluate_results >>"$log"
    cp "$log" "$MUTATIONS"
    write_graphs
    run_smokes
    run_contract_digests
}
run_all() {
    local variant additional_primary winner additional_combined
    reset_generated_artifacts
    for variant in full no-history control-plane combined; do
        prepare_worktree "$variant"
    done
    assert_runner_unchanged
    write_environment
    write_graphs
    run_aa
    initialize_measurements
    run_primary_rounds 1 "$RUNS"
    write_primary_payloads
    evaluate_results
    source "$RUN_ROOT/evaluation-state.env"
    if [[ $additional_primary == true ]]; then
        run_primary_rounds 4 "$EXTENDED_RUNS"
        evaluate_results
        source "$RUN_ROOT/evaluation-state.env"
    fi
    if [[ $winner != none ]]; then
        run_combined_pair_rounds "$winner" 1 "$RUNS"
        record_release_payload "$winner" "marginal-$winner" \
            "$RUN_ROOT/target-$winner-marginal-clean-$RUNS/$TARGET/release"
        record_release_payload combined
        evaluate_results
        source "$RUN_ROOT/evaluation-state.env"
        if [[ $additional_combined == true ]]; then
            run_combined_pair_rounds "$winner" 4 "$EXTENDED_RUNS"
            evaluate_results
            source "$RUN_ROOT/evaluation-state.env"
        fi
    fi
    self_test_assertions
    write_inventory
    write_checksums
    assert_runner_unchanged
}
case ${1:-all} in
    all) run_all ;;
    evaluator-self-test) LAN548_EVALUATOR_SELF_TEST=1 evaluate_results ;;
    *)
        printf 'usage: %s [all|evaluator-self-test]\n' "$0" >&2
        exit 2
        ;;
esac
