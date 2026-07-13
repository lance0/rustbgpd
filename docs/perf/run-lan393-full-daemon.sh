#!/usr/bin/env bash
# Reproducible LAN-393 full-daemon baseline/candidate profile receipt.
set -euo pipefail

usage() {
    printf 'usage: %s baseline-enabled|baseline-disabled|candidate-enabled|candidate-disabled\n' "$0" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
PROFILE=$1
case "$PROFILE" in
    baseline-enabled | baseline-disabled | candidate-enabled | candidate-disabled) ;;
    *) usage ;;
esac
SOURCE_PHASE=${PROFILE%%-*}
EHM_MODE=${PROFILE##*-}

RUSTBGPD_SOURCE=${RUSTBGPD_SOURCE:-$PWD}
ARTIFACT_DIR=${ARTIFACT_DIR:-$RUSTBGPD_SOURCE/docs/perf/artifacts/event-history-producer-2026-07}
BGPERF2_REMOTE=https://github.com/lance0/bgperf2.git
BGPERF2_COMMIT=fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9
BGPERF2_DIR=${BGPERF2_DIR:-/tmp/lan393-bgperf2-$BGPERF2_COMMIT}
BGPERF_RUN_DIR=${BGPERF_RUN_DIR:-/tmp/lan393-bgperf-$PROFILE}
BENCH_NAME=lan393-$PROFILE
PROFILE_IMAGE=${PROFILE_IMAGE:-bgperf/rustbgpd:lan393-$PROFILE-prof}
TARGET_CONTAINER=${TARGET_CONTAINER:-bgperf_rustbgpd_target}
VALIDATOR=$RUSTBGPD_SOURCE/docs/perf/validate-lan393-receipt.py
WRAPPER=$RUSTBGPD_SOURCE/docs/perf/bgperf-rustbgpd-ehm-wrapper.sh
HOST_FENCE=$RUSTBGPD_SOURCE/docs/perf/lan393-host-fence.sh
PREFIX=$ARTIFACT_DIR/full-daemon-$PROFILE
BASELINE_ENV=$ARTIFACT_DIR/microbench-baseline-environment.txt
CANDIDATE_ENV=$ARTIFACT_DIR/microbench-candidate-environment.txt
RUST_BUILDER_IMAGE='rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1'
DEBIAN_RUNTIME_IMAGE='debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
BUILD_CONTEXT=''
BGPERF_PID=''
TARGET_PID=''
PRIVATE_PERF_DIR=${LAN393_PRIVATE_PERF_DIR:-$RUSTBGPD_SOURCE/target/lan393-private-perf}
PRIVATE_PERF_DATA=$PRIVATE_PERF_DIR/full-daemon-$PROFILE.perf.data
PRIVATE_PROFILE_READY=$PRIVATE_PERF_DIR/full-daemon-$PROFILE.profile-ready

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

write_host_fingerprint() {
    local output=$1 cpu_model physical_cores logical_cpus memory_bytes
    cpu_model=$(awk -F: '/model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)
    logical_cpus=$(getconf _NPROCESSORS_ONLN)
    physical_cores=$(lscpu -p=CORE,SOCKET | awk '
        !/^#/ { seen[$1 FS $2]=1 }
        END { for (key in seen) count++; print count + 0 }
    ')
    memory_bytes=$(awk '/MemTotal:/ { print $2 * 1024 }' /proc/meminfo)
    {
        printf 'schema=1\n'
        printf 'kernel=%s\n' "$(uname -srm)"
        printf 'architecture=%s\n' "$(uname -m)"
        printf 'cpu_model=%s\n' "$cpu_model"
        printf 'physical_cores=%s\n' "$physical_cores"
        printf 'logical_cpus=%s\n' "$logical_cpus"
        printf 'memory_bytes=%.0f\n' "$memory_bytes"
        printf 'repo_fs=%s\n' "$(findmnt -n -T "$RUSTBGPD_SOURCE" -o FSTYPE)"
        printf 'tmp_fs=%s\n' "$(findmnt -n -T /tmp -o FSTYPE)"
    } >"$output"
}

write_host_toolchain() {
    local output=$1 package_hash
    package_hash=$(python3 -m pip list --format=freeze 2>/dev/null | LC_ALL=C sort | sha256sum | awk '{print $1}')
    {
        python3 --version
        docker --version
        perf --version
        printf 'python_packages_sha256=%s\n' "$package_hash"
    } >"$output"
}

compare_provenance_without_source_commit() {
    local reference=$1 candidate=$2 label=$3 left right
    left=$(mktemp /tmp/lan393-provenance-reference.XXXXXX)
    right=$(mktemp /tmp/lan393-provenance-candidate.XXXXXX)
    sed '/^rustbgpd_commit=/d' "$reference" >"$left"
    sed '/^rustbgpd_commit=/d' "$candidate" >"$right"
    if ! cmp --silent "$left" "$right"; then
        diff -u "$left" "$right" >&2 || true
        rm -f "$left" "$right"
        printf '%s provenance differs from baseline-enabled\n' "$label" >&2
        exit 1
    fi
    rm -f "$left" "$right"
}

privacy_check() {
    python3 - "$ARTIFACT_DIR" "$PROFILE" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
profile = sys.argv[2]
private = re.compile(r"(?:/home/[^/\s]+|/Users/[^/\s]+|https?://[^/\s:@]+:[^/\s@]+@|git@)")
for path in root.rglob(f"full-daemon-{profile}-*"):
    if not path.is_file() or path.is_symlink():
        continue
    if path.suffix not in {".txt", ".tsv", ".json", ".csv", ".toml", ".log", ".yaml"} and "SHA256SUMS" not in path.name:
        continue
    text = path.read_text(encoding="utf-8", errors="strict")
    match = private.search(text)
    if match:
        raise SystemExit(f"private host material in {path.name}: {match.group(0)!r}")
PY
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
        -name "full-daemon-$PROFILE-*" -print -quit 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        printf 'refusing existing %s receipt: %s\n' "$PROFILE" "$existing" >&2
        exit 1
    fi
}

[[ ! -L "$ARTIFACT_DIR" ]] || {
    printf 'artifact directory must not be a symlink: %s\n' "$ARTIFACT_DIR" >&2
    exit 1
}
mkdir -p "$ARTIFACT_DIR"
[[ -f "$BASELINE_ENV" && ! -L "$BASELINE_ENV" ]] || {
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
RECORDED_BASELINE_REF_COMMIT=$RECORDED_BASELINE_COMMIT
[[ "$(git -C "$RUSTBGPD_SOURCE" rev-parse "$RECORDED_BASELINE_COMMIT^{commit}")" == \
    "$RECORDED_BASELINE_COMMIT" ]] || {
    printf 'recorded baseline is not an exact local commit: %s\n' \
        "$RECORDED_BASELINE_COMMIT" >&2
    exit 1
}

RUSTBGPD_COMMIT=$(git -C "$RUSTBGPD_SOURCE" rev-parse HEAD)
case "$SOURCE_PHASE" in
    baseline)
        [[ "$RUSTBGPD_COMMIT" == "$RECORDED_BASELINE_COMMIT" ]] || {
            printf 'baseline profile HEAD %s does not match recorded baseline %s\n' \
                "$RUSTBGPD_COMMIT" "$RECORDED_BASELINE_COMMIT" >&2
            exit 1
        }
        ;;
    candidate)
        [[ -f "$CANDIDATE_ENV" && ! -L "$CANDIDATE_ENV" ]] || {
            printf 'missing candidate identity: %s\n' "$CANDIDATE_ENV" >&2
            exit 1
        }
        RECORDED_CANDIDATE_COMMIT=$(read_receipt_value "$CANDIDATE_ENV" source_commit)
        CANDIDATE_BASELINE_COMMIT=$(read_receipt_value "$CANDIDATE_ENV" baseline_commit)
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

if [[ "$SOURCE_PHASE" == candidate ]]; then
    python3 - "$ARTIFACT_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
requirements = (
    (root / "microbench-candidate-verdict.json", "candidate_acceptance_pass"),
    (root / "full-daemon-baseline-disabled-overall-verdict.json", "overall_proceed_pass"),
)
for path, key in requirements:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"missing required prior verdict: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get(key) is not True:
        raise SystemExit(f"prior verdict did not pass: {path.name}:{key}")
PY
fi

(
    cd "$ARTIFACT_DIR"
    sha256sum --check "microbench-$SOURCE_PHASE-SHA256SUMS" >/dev/null
)
if [[ "$PROFILE" != baseline-enabled ]]; then
    (
        cd "$ARTIFACT_DIR"
        sha256sum --check full-daemon-baseline-enabled-SHA256SUMS >/dev/null
    )
fi
if [[ "$SOURCE_PHASE" == candidate ]]; then
    (
        cd "$ARTIFACT_DIR"
        sha256sum --check full-daemon-baseline-disabled-SHA256SUMS >/dev/null
    )
fi
if [[ "$PROFILE" == candidate-disabled ]]; then
    (
        cd "$ARTIFACT_DIR"
        sha256sum --check full-daemon-candidate-enabled-SHA256SUMS >/dev/null
    )
fi

require_clean_source
require_new_phase_receipt
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$HOST_FENCE"
lan393_acquire_host_lock
HOST_PREFLIGHT=$PREFIX-host-preflight.tsv
lan393_init_host_preflight_log "$HOST_PREFLIGHT"
HOST_FINGERPRINT=$PREFIX-host-fingerprint.txt
HOST_TOOLCHAIN=$PREFIX-host-toolchain.txt
write_host_fingerprint "$HOST_FINGERPRINT"
write_host_toolchain "$HOST_TOOLCHAIN"
cmp --silent "$ARTIFACT_DIR/microbench-$SOURCE_PHASE-host-fingerprint.txt" "$HOST_FINGERPRINT" || {
    printf '%s\n' 'full-daemon host differs from its microbenchmark phase' >&2
    exit 1
}
if [[ "$PROFILE" != baseline-enabled ]]; then
    cmp --silent "$ARTIFACT_DIR/full-daemon-baseline-enabled-host-toolchain.txt" "$HOST_TOOLCHAIN" || {
        printf '%s\n' 'full-daemon host tools differ from baseline-enabled' >&2
        exit 1
    }
fi
lan393_wait_for_idle "$PROFILE-before-build" "$HOST_PREFLIGHT"
rm -rf "$BGPERF_RUN_DIR"

# Criterion establishes each exact source archive. Every full-daemon profile
# regenerates it into a temporary file and proves byte identity without
# mutating prior manifests.
BASELINE_ARCHIVE=$ARTIFACT_DIR/rustbgpd-baseline-source.tar.gz
[[ ! -L "$BASELINE_ARCHIVE" ]] || {
    printf 'baseline source archive must not be a symlink: %s\n' "$BASELINE_ARCHIVE" >&2
    exit 1
}
BASELINE_ARCHIVE_TMP=$(mktemp "$ARTIFACT_DIR/.baseline-source.XXXXXX.tar.gz")
git -C "$RUSTBGPD_SOURCE" archive --format=tar.gz \
    --output "$BASELINE_ARCHIVE_TMP" "$RECORDED_BASELINE_COMMIT"
[[ -f "$BASELINE_ARCHIVE" ]] || {
    printf 'profile requires retained microbenchmark baseline archive: %s\n' \
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

if [[ "$SOURCE_PHASE" == candidate ]]; then
    CANDIDATE_ARCHIVE=$ARTIFACT_DIR/rustbgpd-candidate-source.tar.gz
    [[ ! -L "$CANDIDATE_ARCHIVE" ]] || {
        printf 'candidate source archive must not be a symlink: %s\n' "$CANDIDATE_ARCHIVE" >&2
        exit 1
    }
    CANDIDATE_ARCHIVE_TMP=$(mktemp "$ARTIFACT_DIR/.candidate-source.XXXXXX.tar.gz")
    git -C "$RUSTBGPD_SOURCE" archive --format=tar.gz \
        --output "$CANDIDATE_ARCHIVE_TMP" "$RUSTBGPD_COMMIT"
    [[ -f "$CANDIDATE_ARCHIVE" ]] || {
        printf 'profile requires retained microbenchmark candidate archive: %s\n' \
            "$CANDIDATE_ARCHIVE" >&2
        rm -f "$CANDIDATE_ARCHIVE_TMP"
        exit 1
    }
    cmp --silent "$CANDIDATE_ARCHIVE_TMP" "$CANDIDATE_ARCHIVE" || {
        printf '%s\n' 'retained candidate archive does not match recorded commit' >&2
        rm -f "$CANDIDATE_ARCHIVE_TMP"
        exit 1
    }
    rm -f "$CANDIDATE_ARCHIVE_TMP"
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
    --phase "$SOURCE_PHASE"
    --source-head "$RUSTBGPD_COMMIT"
    --baseline-commit "$RECORDED_BASELINE_COMMIT"
    --baseline-ref-commit "$RECORDED_BASELINE_REF_COMMIT"
)
if [[ "$SOURCE_PHASE" == candidate ]]; then
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
BGPERF2_ARCHIVE_TMP=$(mktemp "$ARTIFACT_DIR/.bgperf2-source.XXXXXX.tar.gz")
git -C "$BGPERF2_DIR" archive --format=tar.gz \
    --output "$BGPERF2_ARCHIVE_TMP" "$BGPERF2_COMMIT"
if [[ "$PROFILE" == baseline-enabled ]]; then
    mv "$BGPERF2_ARCHIVE_TMP" "$BGPERF2_ARCHIVE"
else
    [[ -f "$BGPERF2_ARCHIVE" ]] || {
        printf 'profile requires retained bgperf2 archive: %s\n' "$BGPERF2_ARCHIVE" >&2
        rm -f "$BGPERF2_ARCHIVE_TMP"
        exit 1
    }
    cmp --silent "$BGPERF2_ARCHIVE_TMP" "$BGPERF2_ARCHIVE" || {
        printf '%s\n' 'retained bgperf2 archive does not match pinned commit' >&2
        rm -f "$BGPERF2_ARCHIVE_TMP"
        exit 1
    }
    rm -f "$BGPERF2_ARCHIVE_TMP"
fi

SOURCE_HASHES=$PREFIX-source-sha256.txt
(
    cd "$ARTIFACT_DIR"
    if [[ "$SOURCE_PHASE" == baseline ]]; then
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
    --build-arg "PROFILE_PHASE=$SOURCE_PHASE" \
    --build-arg "EVENT_HISTORY_MODE=$EHM_MODE" \
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
ARG EVENT_HISTORY_MODE
LABEL org.opencontainers.image.revision="\$RUSTBGPD_COMMIT"
LABEL org.rustbgpd.bgperf2.revision="\$BGPERF2_COMMIT"
LABEL org.opencontainers.image.base.name="$DEBIAN_RUNTIME_IMAGE"
LABEL org.opencontainers.image.base.digest="${DEBIAN_RUNTIME_IMAGE##*sha256:}"
LABEL org.rustbgpd.bgperf2.builder-base.digest="${RUST_BUILDER_IMAGE##*sha256:}"
LABEL org.rustbgpd.bgperf2.rust-toolchain="1.95"
LABEL org.rustbgpd.lan393.profile-phase="\$PROFILE_PHASE"
LABEL org.rustbgpd.lan393.event-history-mode="\$EVENT_HISTORY_MODE"
ENV LAN393_EVENT_HISTORY_MODE="\$EVENT_HISTORY_MODE"
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
if [[ "$PROFILE" != baseline-enabled ]]; then
    compare_provenance_without_source_commit \
        "$ARTIFACT_DIR/full-daemon-baseline-enabled-builder-provenance.txt" \
        "$BUILDER_PROVENANCE" builder
    compare_provenance_without_source_commit \
        "$ARTIFACT_DIR/full-daemon-baseline-enabled-runtime-provenance.txt" \
        "$RUNTIME_PROVENANCE" runtime
fi
docker run --rm --entrypoint sha256sum "$PROFILE_IMAGE" \
    /usr/local/bin/rustbgpd.real /usr/local/bin/rustbgpctl >"$BINARY_HASHES"
if [[ "$EHM_MODE" == disabled ]]; then
    cmp --silent \
        "$ARTIFACT_DIR/full-daemon-$SOURCE_PHASE-enabled-binary-sha256.txt" \
        "$BINARY_HASHES" || {
        printf '%s\n' 'enabled/disabled images contain different rustbgpd binaries' >&2
        exit 1
    }
fi
python3 "$VALIDATOR" image \
    --inspect "$IMAGE_INSPECT" \
    --builder-provenance "$BUILDER_PROVENANCE" \
    --runtime-provenance "$RUNTIME_PROVENANCE" \
    --source-commit "$RUSTBGPD_COMMIT" \
    --bgperf2-commit "$BGPERF2_COMMIT" \
    --phase "$SOURCE_PHASE" \
    --mode "$EHM_MODE" >"$IMAGE_VALIDATION"

PROFILE_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PROFILE_IMAGE")
{
    printf 'profile_phase=%s\n' "$SOURCE_PHASE"
    printf 'event_history_mode=%s\n' "$EHM_MODE"
    printf 'recorded_baseline_commit=%s\n' "$RECORDED_BASELINE_COMMIT"
    printf 'rustbgpd_commit=%s\n' "$RUSTBGPD_COMMIT"
    printf 'repository=lance0/rustbgpd\n'
    printf 'rustbgpd_status=%s\n' "$RUSTBGPD_STATUS"
    printf 'rustbgpd_build_context=exact_commit_archive\n'
    printf 'bgperf2_commit=%s\n' "$BGPERF2_COMMIT"
    printf 'bgperf2_repository=lance0/bgperf2\n'
    printf 'bgperf2_status=%s\n' "$BGPERF2_STATUS"
    printf 'builder_base=%s\n' "$RUST_BUILDER_IMAGE"
    printf 'runtime_base=%s\n' "$DEBIAN_RUNTIME_IMAGE"
    printf 'profile_image_tag=%s\n' "$PROFILE_IMAGE"
    printf 'profile_image_id=%s\n' "$PROFILE_IMAGE_ID"
    printf 'host_lock_policy=rustbgpd-shared-user-lock\n'
    printf 'host_lock_acquired=1\n'
    printf 'host_preflight=%s\n' "$(basename "$HOST_PREFLIGHT")"
    printf 'load_one_max=%s\n' "$LAN393_REQUIRED_LOAD_ONE_MAX"
    printf 'preflight_wait_seconds=%s\n' "${LAN393_PREFLIGHT_WAIT_SECONDS:-120}"
    printf 'required_governor=performance\n'
} >"$PREFIX-environment.txt"

lan393_wait_for_idle "$PROFILE-before-bgperf" "$HOST_PREFLIGHT"
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
TARGET_NAMESPACE_PID=$(awk '
    $1 == "NSpid:" { print $NF; found = 1 }
    END { if (!found) exit 1 }
' "/proc/$TARGET_PID/status")
[[ "$TARGET_NAMESPACE_PID" =~ ^[1-9][0-9]*$ ]] || {
    printf 'stopped target has malformed namespace PID: %s\n' \
        "$TARGET_NAMESPACE_PID" >&2
    exit 1
}
docker top "$TARGET_CONTAINER" -eo pid,stat,args \
    | awk 'NR == 1 { print "state command"; next } { command=$3; sub(/^.*\//, "", command); print $2, command }' \
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
mkdir -p "$PRIVATE_PERF_DIR"
[[ ! -e "$PRIVATE_PROFILE_READY" && ! -L "$PRIVATE_PROFILE_READY" ]] || {
    printf 'refusing existing private profile barrier: %s\n' "$PRIVATE_PROFILE_READY" >&2
    exit 1
}
docker cp \
    "$TARGET_CONTAINER:/root/config/lan393-profile-ready" \
    "$PRIVATE_PROFILE_READY"
python3 "$VALIDATOR" barrier \
    --raw "$PRIVATE_PROFILE_READY" \
    --expected-pid "$TARGET_NAMESPACE_PID" \
    --output "$PREFIX-profile-ready.txt"
if [[ "$EHM_MODE" == enabled ]]; then
    grep -A6 '^\[event_history\]$' "$PREFIX-config.toml" \
        >"$PREFIX-event-history-config.txt"
    grep -q '^enabled = true$' "$PREFIX-event-history-config.txt"
    grep -q '^required = true$' "$PREFIX-event-history-config.txt"
    grep -q '^path = "/var/lib/rustbgpd/events.db"$' "$PREFIX-event-history-config.txt"
    grep -q '^synchronous = "full"$' "$PREFIX-event-history-config.txt"
    grep -q '^queue_capacity = 262144$' "$PREFIX-event-history-config.txt"
else
    if grep -q '^\[event_history\]$' "$PREFIX-config.toml"; then
        printf '%s\n' 'disabled profile unexpectedly contains event_history config' >&2
        exit 1
    fi
    printf 'event_history_mode=disabled\nevent_history_block=absent\n' \
        >"$PREFIX-event-history-config.txt"
fi

[[ ! -e "$PRIVATE_PERF_DATA" ]] || {
    printf 'refusing existing private perf capture: %s\n' "$PRIVATE_PERF_DATA" >&2
    exit 1
}
sudo perf buildid-cache --add \
    "/proc/$TARGET_PID/root/usr/local/bin/rustbgpd.real"
sudo perf record \
    --freq 997 \
    --call-graph dwarf \
    --pid "$TARGET_PID" \
    --output "$PRIVATE_PERF_DATA" \
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
    --phase "$SOURCE_PHASE" \
    --mode "$EHM_MODE" \
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

awk -v mode="$EHM_MODE" '
  /^bgp_event_outbox_committed_total/ { committed += $NF; seen_committed = 1 }
  /^bgp_event_outbox_dropped_total/ && $NF != 0 { bad = 1 }
  /^bgp_event_outbox_queue_depth/ { seen_queue = 1; if ($NF != 0) bad = 1 }
  /^bgp_event_outbox_latest_event_id / { latest = $NF; seen_latest = 1 }
  /^bgp_event_outbox_degraded / { seen_degraded = 1; if ($NF != 0) bad = 1 }
  /^bgp_event_outbox_cursor_gap_total / { seen_gap = 1; if ($NF != 0) bad = 1 }
  END {
    if (bad || !seen_latest || !seen_degraded || !seen_gap) exit 1
    if (mode == "enabled" && (!seen_committed || !seen_queue || committed == 0 || latest != committed)) exit 1
    if (mode == "disabled" && (committed != 0 || latest != 0)) exit 1
  }
' "$PREFIX-metrics.txt"

docker cp "$TARGET_CONTAINER:/root/config/rustbgpd.log" "$PREFIX-rustbgpd.log"
docker stats --no-stream "$TARGET_CONTAINER" >"$PREFIX-docker-stats.txt"
sudo perf report --stdio --children \
    --input "$PRIVATE_PERF_DATA" \
    | sed -E 's#/home/[^ /]+#<host-home>#g; s#/Users/[^ /]+#<host-home>#g' \
    >"$PREFIX-perf-report.txt"
sudo perf script \
    --input "$PRIVATE_PERF_DATA" \
    | python3 -c 'import re,sys
for line in sys.stdin:
    line=re.sub(r"^([^\n]*?)\s+[0-9]+(?:/[0-9]+)?\s+\[[0-9]+\]\s+[0-9.]+:", r"\1 PID/TID [CPU] TIME:", line)
    line=re.sub(r"/(?:home|Users)/[^ /)]+", "<host-home>", line)
    sys.stdout.write(line)' \
    >"$PREFIX-perf-script.txt"
python3 "$BUILD_CONTEXT/docs/perf/validate-lan393-perf.py" \
    --input "$PREFIX-perf-script.txt" \
    --phase "$SOURCE_PHASE" \
    --mode "$EHM_MODE" \
    --output "$PREFIX-perf-attribution.json" \
    >"$PREFIX-perf-validation.txt"
sudo sha256sum "$PRIVATE_PERF_DATA" \
    | awk '{ print $1 "  private-perf.data" }' \
    >"$PREFIX-private-perf-sha256.txt"
sudo chown "$(id -u):$(id -g)" "$PRIVATE_PERF_DATA"

# The completion sentinel is written only after convergence validation,
# outbox-health checks, resource capture, and both inspectable perf derivatives
# succeed. The phase manifest then binds every phase-prefixed receipt plus the
# exact source archives it names.
privacy_check
{
    printf 'profile_phase=%s\n' "$SOURCE_PHASE"
    printf 'event_history_mode=%s\n' "$EHM_MODE"
    printf 'recorded_baseline_commit=%s\n' "$RECORDED_BASELINE_COMMIT"
    printf 'rustbgpd_commit=%s\n' "$RUSTBGPD_COMMIT"
    printf 'run_utc_complete=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'phase_complete=1\n'
} >"$PREFIX-completion.txt"

if [[ "$EHM_MODE" == disabled ]]; then
    python3 "$BUILD_CONTEXT/docs/perf/validate-lan393-full-comparison.py" \
        --artifact-dir "$ARTIFACT_DIR" \
        --phase "$SOURCE_PHASE" \
        --output "$PREFIX-overall-verdict.json" \
        >"$PREFIX-overall-validation.txt"
fi

privacy_check

MANIFEST=$PREFIX-SHA256SUMS
MANIFEST_TMP=$(mktemp "$ARTIFACT_DIR/.full-daemon-$PROFILE-SHA256SUMS.XXXXXX")
(
    cd "$ARTIFACT_DIR"
    {
        find . -type f \
            \( -name "full-daemon-$PROFILE-*" \
               -o -path "./full-daemon-$PROFILE-*/*" \) \
            ! -name "full-daemon-$PROFILE-SHA256SUMS" -print0
        printf './%s\0' "$(basename "$BASELINE_ARCHIVE")" \
            "$(basename "$BGPERF2_ARCHIVE")"
        if [[ "$SOURCE_PHASE" == candidate ]]; then
            printf './%s\0' "$(basename "$CANDIDATE_ARCHIVE")"
        fi
    } | sort -zu | xargs -0 sha256sum
) >"$MANIFEST_TMP"
mv "$MANIFEST_TMP" "$MANIFEST"
(
    cd "$ARTIFACT_DIR"
    sha256sum --check "$(basename "$MANIFEST")" >/dev/null
)
