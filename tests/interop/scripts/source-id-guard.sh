#!/usr/bin/env bash
# Image source-id guard shared by the interop test-lib and the soak runners.
#
# Source this file, then call check_lab_source_ids after the lab is deployed
# and before any measured work starts:
#
#   check_lab_source_ids LAB [CONTAINER...] || exit 1
#
# It refuses a deployed rustbgpd:dev container whose image was not built from
# this tree (a reused BuildKit context can keep a stale COPY). Every container
# labelled containerlab=LAB is checked, because mixed-version labs run the tree
# under test beside pinned releases under other names; the named CONTAINERs are
# checked too. Each is checked by its image id, not the tag, which a later
# build may move. Any docker failure fails closed, except a named CONTAINER
# that is not in the lab listing and does not exist: that lab is not deployed,
# and the caller's own deployment check reports it. scripts/source-id.sh skips
# the comparison when CI or GITHUB_ACTIONS is set.

_SOURCE_ID_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scripts/source-id.sh"

check_lab_source_ids() {
    local lab=${1:?lab name required} listed name config image
    shift
    if ! listed=$(docker ps --filter "label=containerlab=$lab" --format '{{.Names}}'); then
        echo "source-id: cannot list the containers of lab $lab" >&2
        return 1
    fi
    while read -r name; do
        [ -n "$name" ] || continue
        if ! config=$(docker inspect -f '{{.Config.Image}}' "$name" 2>/dev/null); then
            case $'\n'"$listed"$'\n' in
                *$'\n'"$name"$'\n'*) ;;
                *) continue ;;
            esac
            echo "source-id: cannot inspect $name" >&2
            return 1
        fi
        [ "$config" = rustbgpd:dev ] || continue
        image=$(docker inspect -f '{{.Image}}' "$name" 2>/dev/null || true)
        if [ -z "$image" ]; then
            echo "source-id: cannot read the image id of $name" >&2
            return 1
        fi
        echo "source-id: checking $name (rustbgpd:dev)" >&2
        "$_SOURCE_ID_SCRIPT" --check "$image" </dev/null || return 1
    done < <(printf '%s\n' "$@" "$listed" | sort -u)
}
