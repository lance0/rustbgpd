#!/usr/bin/env bash
# Offline proof for the shared library's image source-id guard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
log="$stubs/docker.log"
lab=clab-source-id-guard

# scripts/source-id.sh runs `docker run` in its own process, so the stub is an
# executable on PATH rather than a shell function. STUB_CONTAINERS lists the
# lab's containers as name|config-image|image-id, where a config image of `!`
# makes inspect fail; STUB_IDS maps an image id to the source-id recorded in
# it as image-id=source-id. STUB_PS_FAIL=1 makes the lab listing fail.
cat >"$stubs/docker" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
case "$1" in
    ps)
        [ -z "$STUB_PS_FAIL" ] || exit 1
        [ "$3" = label=containerlab=source-id-guard ] || exit 0
        for c in $STUB_CONTAINERS; do echo "${c%%|*}"; done
        ;;
    inspect)
        for name; do :; done
        for c in $STUB_CONTAINERS; do
            [ "${c%%|*}" = "$name" ] || continue
            rest=${c#*|}
            [ "${rest%%|*}" != '!' ] || exit 1
            case "$3" in
                "{{.Config.Image}}") echo "${rest%%|*}" ;;
                "{{.Image}}") echo "${rest#*|}" ;;
            esac
            exit 0
        done
        exit 1
        ;;
    exec)
        # Soak runners exec into the daemon container once the guard passes.
        exit 97
        ;;
    run)
        for i in $STUB_IDS; do
            [ "${i%%=*}" = "$3" ] && echo "${i#*=}" && exit 0
        done
        exit 1
        ;;
esac
EOF
chmod +x "$stubs/docker"
# test-lib's preflight requires grpcurl on PATH; hosted runners lack it.
printf '#!/bin/sh\nexit 0\n' >"$stubs/grpcurl"
chmod +x "$stubs/grpcurl"

# Source the library as an interop script would. CI and GITHUB_ACTIONS are
# cleared so source-id.sh compares ids instead of skipping under CI.
# Usage: [STUB_PS_FAIL=1] source_lib "<containers>" "<image ids>"
source_lib() {
    : >"$log"
    env -u CI -u GITHUB_ACTIONS PATH="$stubs:$PATH" STUB_LOG="$log" \
        STUB_CONTAINERS="$1" STUB_IDS="$2" STUB_PS_FAIL="${STUB_PS_FAIL:-}" \
        bash -c 'TOPO=source-id-guard; source tests/interop/scripts/test-lib.sh' 2>"$stubs/stderr"
}
fail() {
    echo "FAIL: $*" >&2
    cat "$stubs/stderr" >&2
    exit 1
}
ran() { grep -q "^run --rm $1 " "$log"; }

tree_id=$(scripts/source-id.sh)
dev="$lab-rustbgpd|rustbgpd:dev|sha256:dev"
released="$lab-rustbgpd|ghcr.io/lance0/rustbgpd@sha256:pinned|sha256:released"
current="$lab-rustbgpd-current|rustbgpd:dev|sha256:current"

# A rustbgpd:dev container built from another tree stops the run, and the
# check reads the container's image id, not the movable tag.
source_lib "$dev" sha256:dev=other-tree-id && fail 'mismatched rustbgpd:dev container was accepted'
ran sha256:dev || fail 'image id was not checked'
! ran rustbgpd:dev || fail 'source-id check read the tag instead of the image id'
grep -q other-tree-id "$stubs/stderr" || fail 'mismatch did not name the image id'
grep -q "$tree_id" "$stubs/stderr" || fail 'mismatch did not name the tree id'

# The same container built from this tree passes.
source_lib "$dev" "sha256:dev=$tree_id" || fail 'matching rustbgpd:dev container was rejected'
ran sha256:dev || fail 'matching image id was not checked'

# Containers from other images are not checked.
source_lib "$released" sha256:released=other-tree-id || fail 'released container was rejected'
! grep -q '^run' "$log" || fail 'source-id check ran for a non-dev container'

# An unreadable image id fails instead of skipping the check.
source_lib "$lab-rustbgpd|rustbgpd:dev|" '' && fail 'empty image id was accepted'
grep -q 'cannot read the image id' "$stubs/stderr" || fail 'empty image id was not reported'

# Mixed-version labs: the rustbgpd:dev container beside the pinned $RUSTBGPD
# is checked too.
source_lib "$released $current" sha256:current=other-tree-id \
    && fail 'mismatched rustbgpd:dev container beside a released one was accepted'
ran sha256:current || fail 'second container was not checked'
source_lib "$released $current" "sha256:current=$tree_id" \
    || fail 'matching rustbgpd:dev container beside a released one was rejected'
! ran sha256:released || fail 'released container was checked'

# A lab that is not deployed is left to preflight, which fails it.
source_lib '' '' && fail 'undeployed lab was accepted'
grep -q 'not running' "$stubs/stderr" || fail 'preflight did not report the undeployed lab'
! grep -q '^source-id:' "$stubs/stderr" || fail 'source-id guard reported an undeployed lab'

# A listed container that cannot be inspected fails instead of being skipped,
# whether it is $RUSTBGPD or a secondary container.
source_lib "$released $lab-rustbgpd-current|!|" '' \
    && fail 'uninspectable labelled container was accepted'
grep -q "cannot inspect $lab-rustbgpd-current" "$stubs/stderr" \
    || fail 'uninspectable labelled container was not reported'
source_lib "$lab-rustbgpd|!|" '' && fail 'uninspectable listed rustbgpd container was accepted'
grep -q "cannot inspect $lab-rustbgpd" "$stubs/stderr" \
    || fail 'uninspectable listed rustbgpd container was not reported'

# A failed lab listing fails instead of falling back to $RUSTBGPD alone.
STUB_PS_FAIL=1 source_lib "$dev" "sha256:dev=$tree_id" && fail 'failed lab listing was accepted'
grep -q 'cannot list the containers of lab source-id-guard' "$stubs/stderr" \
    || fail 'failed lab listing was not reported'

# Soak runners that do not source test-lib call the same guard after their
# own deployment checks and before the soak starts. The hot-reload runner
# stands for them: its first step after the guard is a docker exec into the
# daemon container, which the stub fails with 97.
# Usage: run_soak "<containers>" "<image ids>"
run_soak() {
    : >"$log"
    env -u CI -u GITHUB_ACTIONS PATH="$stubs:$PATH" STUB_LOG="$log" \
        STUB_CONTAINERS="$1" STUB_IDS="$2" STUB_PS_FAIL= TOPO=source-id-guard \
        RUSTBGPD_HOST_LOCK="$stubs/host.lock" RUN_DIR_OVERRIDE="$stubs/soak-run" \
        bash tests/soak/run-soak-hot-reload.sh 2>&1 | cat >"$stubs/stderr"
}
frr="$lab-frr|quay.io/frrouting/frr:10.3.1|sha256:frr"

status=0
run_soak "$dev $frr" "sha256:dev=$tree_id" || status=$?
[ "$status" = 97 ] || fail "matching soak lab did not reach the soak start (exit $status)"
ran sha256:dev || fail 'soak runner did not check the image id'
grep -q '^exec ' "$log" || fail 'soak runner did not start the daemon after the guard'

status=0
run_soak "$dev $frr" sha256:dev=other-tree-id || status=$?
[ "$status" = 2 ] || fail "mismatched soak container did not stop the runner (exit $status)"
grep -q other-tree-id "$stubs/stderr" || fail 'soak mismatch did not name the image id'
! grep -q '^exec ' "$log" || fail 'soak started after a source-id mismatch'

status=0
run_soak "$dev $frr $lab-extra|!|" "sha256:dev=$tree_id" || status=$?
[ "$status" = 2 ] || fail "uninspectable soak container did not stop the runner (exit $status)"
grep -q "cannot inspect $lab-extra" "$stubs/stderr" \
    || fail 'uninspectable soak container was not reported'
! grep -q '^exec ' "$log" || fail 'soak started after an inspect failure'

status=0
run_soak "$lab-rustbgpd|rustbgpd:dev| $frr" '' || status=$?
[ "$status" = 2 ] || fail "unreadable soak image id did not stop the runner (exit $status)"
grep -q "cannot read the image id of $lab-rustbgpd" "$stubs/stderr" \
    || fail 'unreadable soak image id was not reported'
! grep -q '^exec ' "$log" || fail 'soak started after an unreadable image id'

echo 'shared source-id guard: PASS'
