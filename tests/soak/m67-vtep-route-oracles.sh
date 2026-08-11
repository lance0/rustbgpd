#!/usr/bin/env bash
# Source-only route-observation helpers for the standalone M67 soak.

vtep_routes() {
    local route_type=${1:?} peer=${2:?} raw routes
    if ! raw=$(vtep_ctl evpn --route-type "$route_type" --peer "$peer" -j 2>/dev/null); then
        printf 'ERROR: VTEP route observation failed for route type %s peer %s\n' \
            "$route_type" "$peer" >&2
        return 2
    fi
    if ! routes=$(printf '%s\n' "$raw" | jq -ces '
        if length == 1 and
           (.[0] | type == "array" and all(.[]; type == "object"))
        then .[0]
        else error("expected exactly one array of objects")
        end
    ' 2>/dev/null); then
        printf 'ERROR: unusable VTEP route JSON for route type %s peer %s\n' \
            "$route_type" "$peer" >&2
        return 2
    fi
    printf '%s\n' "$routes"
}

vtep_route_count() {
    local route_type=${1:?} peer=${2:?} predicate=${3:-true} routes count
    if ! routes=$(vtep_routes "$route_type" "$peer"); then
        return 2
    fi
    if ! count=$(printf '%s\n' "$routes" \
        | jq -er "[.[] | select(${predicate})] | length" 2>/dev/null); then
        printf 'ERROR: VTEP route filter failed for route type %s peer %s\n' \
            "$route_type" "$peer" >&2
        return 2
    fi
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        printf 'ERROR: non-integer VTEP route count for route type %s peer %s\n' \
            "$route_type" "$peer" >&2
        return 2
    fi
    printf '%s\n' "$count"
}

wait_vtep_routes_at_least() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?} want=${4:?} attempts=${5:-90}
    local got last_rc=1
    for _ in $(seq 1 "$attempts"); do
        if got=$(vtep_route_count "$route_type" "$peer" "$predicate"); then
            last_rc=1
        else
            last_rc=2
            sleep 1
            continue
        fi
        if [ "$got" -ge "$want" ]; then
            return 0
        fi
        sleep 1
    done
    return "$last_rc"
}

wait_vtep_routes_gone() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?} attempts=${4:-90}
    local got last_rc=1
    for _ in $(seq 1 "$attempts"); do
        if got=$(vtep_route_count "$route_type" "$peer" "$predicate"); then
            last_rc=1
        else
            last_rc=2
            sleep 1
            continue
        fi
        if [ "$got" -eq 0 ]; then
            return 0
        fi
        sleep 1
    done
    return "$last_rc"
}
