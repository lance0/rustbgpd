#!/usr/bin/env bash
# Reproducible LAN-393 full-daemon baseline/candidate profile receipt.
set -euo pipefail

usage() {
    printf 'usage: %s baseline|candidate\n' "$0" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
PHASE=$1
case "$PHASE" in
    baseline | candidate) ;;
    *) usage ;;
esac

RUSTBGPD_SOURCE=${RUSTBGPD_SOURCE:-$PWD}
ARTIFACT_DIR=${ARTIFACT_DIR:-$RUSTBGPD_SOURCE/docs/perf/artifacts/event-history-producer-2026-07}
BGPERF2_REMOTE=https://github.com/lance0/bgperf2.git
BGPERF2_COMMIT=fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9
BGPERF2_DIR=${BGPERF2_DIR:-/tmp/lan393-bgperf2-$BGPERF2_COMMIT}
BGPERF_RUN_DIR=${BGPERF_RUN_DIR:-/tmp/lan393-bgperf-$PHASE}
BENCH_NAME=lan393-$PHASE
PROFILE_IMAGE=${PROFILE_IMAGE:-bgperf/rustbgpd:lan393-$PHASE-ehm-prof}
TARGET_CONTAINER=${TARGET_CONTAINER:-bgperf_rustbgpd_target}
VALIDATOR=$RUSTBGPD_SOURCE/docs/perf/validate-lan393-receipt.py
WRAPPER=$RUSTBGPD_SOURCE/docs/perf/bgperf-rustbgpd-ehm-wrapper.sh
HOST_FENCE=$RUSTBGPD_SOURCE/docs/perf/lan393-host-fence.sh
PREFIX=$ARTIFACT_DIR/full-daemon-$PHASE
BASELINE_ENV=$ARTIFACT_DIR/environment.txt
CANDIDATE_ENV=$ARTIFACT_DIR/candidate-environment.txt
RUST_BUILDER_IMAGE='rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1'
DEBIAN_RUNTIME_IMAGE='debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
BUILD_CONTEXT=''
BGPERF_PID=''
TARGET_PID=''

cleanup() {
    if [[ -n "$TARGET_PID" ]]; then
        sudo kill -CONT "$TARGET_PID" 2>/dev/null || true
    fi
    if [[ -n "$BGPERF_PID" ]]; then
        kill "$BGPERF_PID" 2>/dev/null || true
    fi
    if [[ -n "$BUILD_CONTEXT" ]]; then
        rm -rf -- "$BUILD_CONTEXT"
    fi
}
trap cleanup EXIT

read_receipt_value() {
    local file=$1
    local key=$2
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; found = 1 } END { if (!found) exit 1 }' "$file"
}

require_clean_source() {
    RUSTBGPD_STATUS=$(git -C "$RUSTBGPD_SOURCE" status \
        --porcelain=v1 --untracked-files=all \
        -- . \
        ':(exclude)docs/perf/artifacts/event-history-producer-2026-07')
    if [[ -n "$RUSTBGPD_STATUS" ]]; then
        printf '%s\n' "refusing dirty rustbgpd source tree:" >&2
        printf '%s\n' "$RUSTBGPD_STATUS" >&2
        exit 1
    fi
}

require_new_phase_receipt() {
    local existing
    existing=$(find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 \
        -name "full-daemon-$PHASE-*" -print -quit 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        printf 'refusing existing %s receipt: %s\n' "$PHASE" "$existing" >&2
        exit 1
    fi
}

mkdir -p "$ARTIFACT_DIR"
[[ -f "$BASELINE_ENV" ]] || {
    printf 'missing baseline identity: %s\n' "$BASELINE_ENV" >&2
    exit 1
}
[[ -x "$VALIDATOR" ]] || {
    printf 'validator is not executable: %s\n' "$VALIDATOR" >&2
    exit 1
}
[[ -x "$WRAPPER" ]] || {
    printf 'wrapper is not executable: %s\n' "$WRAPPER" >&2
    exit 1
}

RECORDED_BASELINE_COMMIT=$(read_receipt_value "$BASELINE_ENV" baseline_commit)
RECORDED_BASELINE_REF_COMMIT=$(read_receipt_value "$BASELINE_ENV" baseline_ref_commit)
[[ "$RECORDED_BASELINE_COMMIT" == "$RECORDED_BASELINE_REF_COMMIT" ]] || {
    printf 'recorded baseline/ref mismatch: %s != %s\n' \
        "$RECORDED_BASELINE_COMMIT" "$RECORDED_BASELINE_REF_COMMIT" >&2
    exit 1
}
[[ "$(git -C "$RUSTBGPD_SOURCE" rev-parse "$RECORDED_BASELINE_COMMIT^{commit}")" == \
    "$RECORDED_BASELINE_COMMIT" ]] || {
    printf 'recorded baseline is not an exact local commit: %s\n' \
        "$RECORDED_BASELINE_COMMIT" >&2
    exit 1
}

RUSTBGPD_COMMIT=$(git -C "$RUSTBGPD_SOURCE" rev-parse HEAD)
case "$PHASE" in
    baseline)
        [[ "$RUSTBGPD_COMMIT" == "$RECORDED_BASELINE_COMMIT" ]] || {
            printf 'baseline profile HEAD %s does not match recorded baseline %s\n' \
                "$RUSTBGPD_COMMIT" "$RECORDED_BASELINE_COMMIT" >&2
            exit 1
        }
        ;;
    candidate)
        [[ -f "$CANDIDATE_ENV" ]] || {
            printf 'missing candidate identity: %s\n' "$CANDIDATE_ENV" >&2
            exit 1
        }
        RECORDED_CANDIDATE_COMMIT=$(read_receipt_value "$CANDIDATE_ENV" candidate_commit)
        CANDIDATE_BASELINE_COMMIT=$(read_receipt_value \
            "$CANDIDATE_ENV" recorded_baseline_commit)
        [[ "$CANDIDATE_BASELINE_COMMIT" == "$RECORDED_BASELINE_COMMIT" ]] || {
            printf 'candidate receipt baseline %s does not match recorded baseline %s\n' \
                "$CANDIDATE_BASELINE_COMMIT" "$RECORDED_BASELINE_COMMIT" >&2
            exit 1
        }
        [[ "$RECORDED_CANDIDATE_COMMIT" != "$RECORDED_BASELINE_COMMIT" ]] || {
            printf 'candidate commit matches recorded baseline: %s\n' \
                "$RECORDED_CANDIDATE_COMMIT" >&2
            exit 1
        }
        git -C "$RUSTBGPD_SOURCE" merge-base --is-ancestor \
            "$RECORDED_BASELINE_COMMIT" "$RECORDED_CANDIDATE_COMMIT" || {
            printf 'recorded baseline is not an ancestor of candidate: %s !<= %s\n' \
                "$RECORDED_BASELINE_COMMIT" "$RECORDED_CANDIDATE_COMMIT" >&2
            exit 1
        }
        [[ "$RUSTBGPD_COMMIT" == "$RECORDED_CANDIDATE_COMMIT" ]] || {
            printf 'candidate profile HEAD %s does not match recorded candidate %s\n' \
                "$RUSTBGPD_COMMIT" "$RECORDED_CANDIDATE_COMMIT" >&2
            exit 1
        }
        ;;
esac

require_clean_source
require_new_phase_receipt
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$HOST_FENCE"
lan393_acquire_host_lock
HOST_PREFLIGHT=$PREFIX-host-preflight.tsv
lan393_init_host_preflight_log "$HOST_PREFLIGHT"
lan393_wait_for_idle "$PHASE-before-build" "$HOST_PREFLIGHT"
rm -rf "$BGPERF_RUN_DIR"

# Rebuild the baseline archive from the receipt's exact commit. Baseline runs
# replace it; candidate runs prove the retained archive is byte-identical.
BASELINE_ARCHIVE=$ARTIFACT_DIR/rustbgpd-baseline-source.tar.gz
BASELINE_ARCHIVE_TMP=$(mktemp "$ARTIFACT_DIR/.baseline-source.XXXXXX.tar.gz")
git -C "$RUSTBGPD_SOURCE" archive --format=tar.gz \
    --output "$BASELINE_ARCHIVE_TMP" "$RECORDED_BASELINE_COMMIT"
if [[ "$PHASE" == baseline ]]; then
    mv "$BASELINE_ARCHIVE_TMP" "$BASELINE_ARCHIVE"
else
    [[ -f "$BASELINE_ARCHIVE" ]] || {
        printf 'candidate profile requires retained baseline archive: %s\n' \
            "$BASELINE_ARCHIVE" >&2
        rm -f "$BASELINE_ARCHIVE_TMP"
        exit 1
    }
    cmp --silent "$BASELINE_ARCHIVE_TMP" "$BASELINE_ARCHIVE" || {
        printf '%s\n' 'retained baseline archive does not match recorded commit' >&2
        rm -f "$BASELINE_ARCHIVE_TMP"
        exit 1
    }
    rm -f "$BASELINE_ARCHIVE_TMP"
fi

if [[ "$PHASE" == candidate ]]; then
    CANDIDATE_ARCHIVE=$ARTIFACT_DIR/rustbgpd-candidate-source.tar.gz
    git -C "$RUSTBGPD_SOURCE" archive --format=tar.gz \
        --output "$CANDIDATE_ARCHIVE" "$RUSTBGPD_COMMIT"
    BUILD_ARCHIVE=$CANDIDATE_ARCHIVE
else
    BUILD_ARCHIVE=$BASELINE_ARCHIVE
fi

# Docker and the receipt validator consume only the retained exact-commit
# archive. The mutable checkout is identity input, never build input.
BUILD_CONTEXT=$(mktemp -d /tmp/lan393-rustbgpd-build.XXXXXX)
tar -xzf "$BUILD_ARCHIVE" -C "$BUILD_CONTEXT"
VALIDATOR=$BUILD_CONTEXT/docs/perf/validate-lan393-receipt.py
[[ -x "$VALIDATOR" ]] || {
    printf 'archived validator is not executable: %s\n' "$VALIDATOR" >&2
    exit 1
}

IDENTITY_ARGS=(
    identity
    --phase "$PHASE"
    --source-head "$RUSTBGPD_COMMIT"
    --baseline-commit "$RECORDED_BASELINE_COMMIT"
    --baseline-ref-commit "$RECORDED_BASELINE_REF_COMMIT"
)
if [[ "$PHASE" == candidate ]]; then
    IDENTITY_ARGS+=(
        --candidate-commit "$RECORDED_CANDIDATE_COMMIT"
        --candidate-baseline-ancestor true
    )
fi
python3 "$VALIDATOR" "${IDENTITY_ARGS[@]}" >"$PREFIX-identity-validation.txt"

rm -rf "$BGPERF2_DIR"
git clone --no-checkout "$BGPERF2_REMOTE" "$BGPERF2_DIR"
git -C "$BGPERF2_DIR" checkout --detach "$BGPERF2_COMMIT"
[[ "$(git -C "$BGPERF2_DIR" rev-parse HEAD)" == "$BGPERF2_COMMIT" ]]
BGPERF2_STATUS=$(git -C "$BGPERF2_DIR" status --porcelain=v1 --untracked-files=all)
[[ -z "$BGPERF2_STATUS" ]] || {
    printf '%s\n' "refusing dirty bgperf2 source tree:" >&2
    printf '%s\n' "$BGPERF2_STATUS" >&2
    exit 1
}
BGPERF2_ARCHIVE=$ARTIFACT_DIR/bgperf2-source-$BGPERF2_COMMIT.tar.gz
git -C "$BGPERF2_DIR" archive --format=tar.gz \
    --output "$BGPERF2_ARCHIVE" "$BGPERF2_COMMIT"

SOURCE_HASHES=$PREFIX-source-sha256.txt
(
    cd "$ARTIFACT_DIR"
    if [[ "$PHASE" == baseline ]]; then
        sha256sum "$(basename "$BASELINE_ARCHIVE")" \
            "$(basename "$BGPERF2_ARCHIVE")"
    else
        sha256sum "$(basename "$BASELINE_ARCHIVE")" \
            "$(basename "$CANDIDATE_ARCHIVE")" \
            "$(basename "$BGPERF2_ARCHIVE")"
    fi
) >"$SOURCE_HASHES"

docker build --no-cache \
    --build-arg "RUSTBGPD_COMMIT=$RUSTBGPD_COMMIT" \
    --build-arg "BGPERF2_COMMIT=$BGPERF2_COMMIT" \
    --build-arg "PROFILE_PHASE=$PHASE" \
    --file - \
    --tag "$PROFILE_IMAGE" \
    "$BUILD_CONTEXT" <<DOCKERFILE
FROM $RUST_BUILDER_IMAGE AS builder
ARG RUSTBGPD_COMMIT
ARG BGPERF2_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --workspace --profile release-prof --locked
RUN mkdir -p /build-provenance \
    && { \
        echo "rustbgpd_commit=\$RUSTBGPD_COMMIT"; \
        echo "bgperf2_commit=\$BGPERF2_COMMIT"; \
        echo "builder_base=$RUST_BUILDER_IMAGE"; \
        rustc --version --verbose; \
        cargo --version --verbose; \
        protoc --version; \
        dpkg-query -W -f='\${Package}=\${Version}\\n' | sort; \
    } >/build-provenance/builder.txt

FROM $DEBIAN_RUNTIME_IMAGE
ARG RUSTBGPD_COMMIT
ARG BGPERF2_COMMIT
ARG PROFILE_PHASE
LABEL org.opencontainers.image.revision="\$RUSTBGPD_COMMIT"
LABEL org.rustbgpd.bgperf2.revision="\$BGPERF2_COMMIT"
LABEL org.opencontainers.image.base.name="$DEBIAN_RUNTIME_IMAGE"
LABEL org.opencontainers.image.base.digest="${DEBIAN_RUNTIME_IMAGE##*sha256:}"
LABEL org.rustbgpd.bgperf2.builder-base.digest="${RUST_BUILDER_IMAGE##*sha256:}"
LABEL org.rustbgpd.bgperf2.rust-toolchain="1.95"
LABEL org.rustbgpd.lan393.profile-phase="\$PROFILE_PHASE"
WORKDIR /root
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release-prof/rustbgpd /usr/local/bin/rustbgpd.real
COPY --from=builder /build/target/release-prof/rbgp /usr/local/bin/rustbgpctl
COPY --from=builder /build-provenance/builder.txt /usr/local/share/rustbgpd-builder-provenance.txt
COPY docs/perf/bgperf-rustbgpd-ehm-wrapper.sh /usr/local/bin/rustbgpd
RUN chmod 0755 /usr/local/bin/rustbgpd \
    && mkdir -p /var/lib/rustbgpd \
    && { \
        echo "rustbgpd_commit=\$RUSTBGPD_COMMIT"; \
        echo "bgperf2_commit=\$BGPERF2_COMMIT"; \
        echo "runtime_base=$DEBIAN_RUNTIME_IMAGE"; \
        dpkg-query -W -f='\${Package}=\${Version}\\n' | sort; \
    } >/usr/local/share/rustbgpd-runtime-provenance.txt
DOCKERFILE

IMAGE_INSPECT=$PREFIX-image-inspect.json
BUILDER_PROVENANCE=$PREFIX-builder-provenance.txt
RUNTIME_PROVENANCE=$PREFIX-runtime-provenance.txt
BINARY_HASHES=$PREFIX-binary-sha256.txt
IMAGE_VALIDATION=$PREFIX-image-validation.txt
docker image inspect "$PROFILE_IMAGE" >"$IMAGE_INSPECT"
PROVENANCE_CONTAINER=$(docker create "$PROFILE_IMAGE")
docker cp \
    "$PROVENANCE_CONTAINER:/usr/local/share/rustbgpd-builder-provenance.txt" \
    "$BUILDER_PROVENANCE"
docker cp \
    "$PROVENANCE_CONTAINER:/usr/local/share/rustbgpd-runtime-provenance.txt" \
    "$RUNTIME_PROVENANCE"
docker rm "$PROVENANCE_CONTAINER" >/dev/null
docker run --rm --entrypoint sha256sum "$PROFILE_IMAGE" \
    /usr/local/bin/rustbgpd.real /usr/local/bin/rustbgpctl >"$BINARY_HASHES"
python3 "$VALIDATOR" image \
    --inspect "$IMAGE_INSPECT" \
    --builder-provenance "$BUILDER_PROVENANCE" \
    --runtime-provenance "$RUNTIME_PROVENANCE" \
    --source-commit "$RUSTBGPD_COMMIT" \
    --bgperf2-commit "$BGPERF2_COMMIT" \
    --phase "$PHASE" >"$IMAGE_VALIDATION"

PROFILE_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PROFILE_IMAGE")
{
    printf 'profile_phase=%s\n' "$PHASE"
    printf 'recorded_baseline_commit=%s\n' "$RECORDED_BASELINE_COMMIT"
    printf 'rustbgpd_commit=%s\n' "$RUSTBGPD_COMMIT"
    printf 'rustbgpd_remote=%s\n' \
        "$(git -C "$RUSTBGPD_SOURCE" remote get-url origin)"
    printf 'rustbgpd_status=%s\n' "$RUSTBGPD_STATUS"
    printf 'rustbgpd_build_context=exact_commit_archive\n'
    printf 'bgperf2_commit=%s\n' "$BGPERF2_COMMIT"
    printf 'bgperf2_remote=%s\n' \
        "$(git -C "$BGPERF2_DIR" remote get-url origin)"
    printf 'bgperf2_status=%s\n' "$BGPERF2_STATUS"
    printf 'builder_base=%s\n' "$RUST_BUILDER_IMAGE"
    printf 'runtime_base=%s\n' "$DEBIAN_RUNTIME_IMAGE"
    printf 'profile_image_tag=%s\n' "$PROFILE_IMAGE"
    printf 'profile_image_id=%s\n' "$PROFILE_IMAGE_ID"
    printf 'host_lock=%s\n' "$LAN393_HOST_LOCK_PATH"
    printf 'host_lock_acquired=1\n'
    printf 'host_preflight=%s\n' "$(basename "$HOST_PREFLIGHT")"
    printf 'load_one_max=%s\n' "$LAN393_REQUIRED_LOAD_ONE_MAX"
    printf 'preflight_wait_seconds=%s\n' "${LAN393_PREFLIGHT_WAIT_SECONDS:-120}"
    printf 'required_governor=performance\n'
} >"$PREFIX-environment.txt"

lan393_wait_for_idle "$PHASE-before-bgperf" "$HOST_PREFLIGHT"
(
    cd "$BGPERF2_DIR"
    env -u RUSTBGPD_EVENT_HISTORY \
        -u RUSTBGPD_EVENT_HISTORY_OFF \
        python3 bgperf2.py \
        --bench-name "$BENCH_NAME" \
        --dir "$BGPERF_RUN_DIR" \
        bench \
        --target rustbgpd \
        --image "$PROFILE_IMAGE" \
        --tester-type bird \
        --neighbor-num 2 \
        --prefix-num 100000 \
        --output "$PREFIX-bgperf-timeseries.csv"
) >"$PREFIX-bgperf.log" 2>&1 &
BGPERF_PID=$!

for _ in $(seq 1 300); do
    TARGET_PID=$(docker top "$TARGET_CONTAINER" -eo pid,stat,args 2>/dev/null \
        | awk '$2 ~ /^T/ && /\/usr\/local\/bin\/rustbgpd \/root\/config\/config.toml/ { print $1 }' \
        || true)
    [[ -z "$TARGET_PID" ]] || break
    sleep 0.1
done
[[ -n "$TARGET_PID" ]]
docker top "$TARGET_CONTAINER" -eo pid,stat,args \
    >"$PREFIX-processes-pre-attach.txt"

RUNNING_IMAGE_ID=$(docker inspect --format '{{.Image}}' "$TARGET_CONTAINER")
[[ "$RUNNING_IMAGE_ID" == "$PROFILE_IMAGE_ID" ]] || {
    printf 'running container image %s does not match built image %s\n' \
        "$RUNNING_IMAGE_ID" "$PROFILE_IMAGE_ID" >&2
    exit 1
}
printf 'running_container_image_id=%s\n' "$RUNNING_IMAGE_ID" \
    >"$PREFIX-running-image.txt"

docker cp "$TARGET_CONTAINER:/root/config/config.toml" "$PREFIX-config.toml"
docker cp \
    "$TARGET_CONTAINER:/root/config/lan393-profile-ready" \
    "$PREFIX-profile-ready.txt"
grep -A6 '^\[event_history\]$' "$PREFIX-config.toml" \
    >"$PREFIX-event-history-config.txt"
grep -q '^enabled = true$' "$PREFIX-event-history-config.txt"
grep -q '^required = true$' "$PREFIX-event-history-config.txt"
grep -q '^synchronous = "full"$' "$PREFIX-event-history-config.txt"

sudo perf buildid-cache --add \
    "/proc/$TARGET_PID/root/usr/local/bin/rustbgpd.real"
sudo perf record \
    --freq 997 \
    --call-graph dwarf \
    --pid "$TARGET_PID" \
    --output "$PREFIX-ehm.perf.data" \
    -- sleep 30 &
PERF_PID=$!
sleep 1
sudo kill -CONT "$TARGET_PID"
TARGET_PID=''
wait "$PERF_PID"

# bgperf2 can encode a failed benchmark in its output and still exit zero.
# Its pinned BIRD error helper also reads /tmp/bgperf2/tester regardless of
# --dir/--bench-name, and its BIRD timeout helper is a constant zero. Retain and
# validate the actual run-scoped tester logs instead of trusting those fields.
# The validator inventories every source *.log entry (including symlinks and
# special files) and byte-binds these copies to the two expected regular logs.
wait "$BGPERF_PID"
BGPERF_PID=''
RUN_RECEIPT_DIR=$BGPERF_RUN_DIR/$BENCH_NAME
TESTER_SOURCE_DIR=$RUN_RECEIPT_DIR/tester
TESTER_LOG_DIR=$PREFIX-tester-logs
[[ -d "$TESTER_SOURCE_DIR" ]]
mkdir "$TESTER_LOG_DIR"
for PEER in 10.10.0.3 10.10.0.4; do
    SOURCE_LOG=$TESTER_SOURCE_DIR/$PEER.log
    [[ -f "$SOURCE_LOG" && ! -L "$SOURCE_LOG" ]] || {
        printf 'missing regular run-scoped BIRD log: %s\n' "$SOURCE_LOG" >&2
        exit 1
    }
    cp -- "$SOURCE_LOG" "$TESTER_LOG_DIR/$PEER.log"
    cmp --silent "$SOURCE_LOG" "$TESTER_LOG_DIR/$PEER.log"
done
SOURCE_SCENARIO=$RUN_RECEIPT_DIR/scenario.yaml
[[ -f "$SOURCE_SCENARIO" && ! -L "$SOURCE_SCENARIO" ]] || {
    printf 'missing regular run-scoped scenario: %s\n' "$SOURCE_SCENARIO" >&2
    exit 1
}
cp -- "$SOURCE_SCENARIO" "$PREFIX-scenario.yaml"
cmp --silent "$SOURCE_SCENARIO" "$PREFIX-scenario.yaml"
python3 "$VALIDATOR" bgperf \
    --log "$PREFIX-bgperf.log" \
    --scenario "$PREFIX-scenario.yaml" \
    --phase "$PHASE" \
    --bench-name "$BENCH_NAME" \
    --run-receipt-dir "$RUN_RECEIPT_DIR" \
    --source-scenario "$SOURCE_SCENARIO" \
    --source-tester-log-dir "$TESTER_SOURCE_DIR" \
    --tester-log-dir "$TESTER_LOG_DIR" \
    --result "$PREFIX-bgperf-result.csv" \
    >"$PREFIX-bgperf-validation.txt"

TARGET_IP=$(docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$TARGET_CONTAINER")
for _ in $(seq 1 100); do
    curl --fail --silent --show-error \
        "http://$TARGET_IP:9179/metrics" >"$PREFIX-metrics.txt"
    if ! awk '/^bgp_event_outbox_queue_depth/ && $NF != 0 { found = 1 } END { exit found }' \
        "$PREFIX-metrics.txt"; then
        sleep 0.1
        continue
    fi
    sleep 1
    curl --fail --silent --show-error \
        "http://$TARGET_IP:9179/metrics" >"$PREFIX-metrics.txt"
    break
done

awk '
  /^bgp_event_outbox_committed_total/ { committed += $NF }
  /^bgp_event_outbox_dropped_total/ && $NF != 0 { bad = 1 }
  /^bgp_event_outbox_queue_depth/ && $NF != 0 { bad = 1 }
  /^bgp_event_outbox_latest_event_id / { latest = $NF }
  /^bgp_event_outbox_degraded / && $NF != 0 { bad = 1 }
  /^bgp_event_outbox_cursor_gap_total / && $NF != 0 { bad = 1 }
  END {
    if (committed == 0 || latest != committed || bad) exit 1
  }
' "$PREFIX-metrics.txt"

docker cp "$TARGET_CONTAINER:/root/config/rustbgpd.log" "$PREFIX-rustbgpd.log"
docker stats --no-stream "$TARGET_CONTAINER" >"$PREFIX-docker-stats.txt"
sudo perf report --stdio --children \
    --input "$PREFIX-ehm.perf.data" \
    | tee "$PREFIX-ehm.perf-report.txt" >/dev/null
sudo perf script \
    --input "$PREFIX-ehm.perf.data" \
    | tee "$PREFIX-ehm.perf-script.txt" >/dev/null
sudo chown "$(id -u):$(id -g)" "$PREFIX-ehm.perf.data"

# The completion sentinel is written only after convergence validation,
# outbox-health checks, resource capture, and both inspectable perf derivatives
# succeed. The phase manifest then binds every phase-prefixed receipt plus the
# exact source archives it names.
{
    printf 'profile_phase=%s\n' "$PHASE"
    printf 'recorded_baseline_commit=%s\n' "$RECORDED_BASELINE_COMMIT"
    printf 'rustbgpd_commit=%s\n' "$RUSTBGPD_COMMIT"
    printf 'run_utc_complete=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'phase_complete=1\n'
} >"$PREFIX-completion.txt"

MANIFEST=$PREFIX-SHA256SUMS
MANIFEST_TMP=$(mktemp "$ARTIFACT_DIR/.full-daemon-$PHASE-SHA256SUMS.XXXXXX")
(
    cd "$ARTIFACT_DIR"
    {
        find . -type f \
            \( -name "full-daemon-$PHASE-*" \
               -o -path "./full-daemon-$PHASE-*/*" \) \
            ! -name "full-daemon-$PHASE-SHA256SUMS" -print0
        printf './%s\0' "$(basename "$BASELINE_ARCHIVE")" \
            "$(basename "$BGPERF2_ARCHIVE")"
        if [[ "$PHASE" == candidate ]]; then
            printf './%s\0' "$(basename "$CANDIDATE_ARCHIVE")"
        fi
    } | sort -zu | xargs -0 sha256sum
) >"$MANIFEST_TMP"
mv "$MANIFEST_TMP" "$MANIFEST"
(
    cd "$ARTIFACT_DIR"
    sha256sum --check "$(basename "$MANIFEST")" >/dev/null
)
