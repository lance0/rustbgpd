#!/usr/bin/env bash
# M102 — OpenBGPD 9.2 dual-stack route-server member proof (exact 32/0).
# shellcheck disable=SC2015 # assertion chains deliberately record ok/fail ledger rows
set -euo pipefail

TOPO=m102-routeserver-openbgpd92
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1; export INTEROP_TEST_OPERATOR_AUTH
OPENBGPD="clab-${TOPO}-openbgpd"; FRR="clab-${TOPO}-frr"
OPENBGPD_IMAGE="openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9"
FRR_IMAGE="quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c"
CAPTURE_IMAGE=bmpsink:m102
CAPTURE_CONTAINER=m102-raw-capture
CAPTURE_VOLUME=m102-raw-capture-data
OPENBGPD_ADDR=10.102.1.2; FRR_ADDR=10.102.2.2; RS_FRR_ADDR=10.102.2.1
OPEN_V4=192.0.2.0/24; OPEN_V6=2001:db8:1102::/48
FRR_V4=198.18.102.0/24; FRR_V6=2001:db8:2102::/48
IMPORT_DENY=198.51.102.0/24; EXPORT_DENY=203.0.102.0/24
OPEN_STATE_BEFORE=""; FRR_STATE_BEFORE=""
DIAGNOSTICS_DUMPED=0
OPEN_COMMUNITY_OBS=""; FRR_COMMUNITY_OBS=""

die() { echo "ERROR: $*" >&2; exit 1; }
stop_capture_container() {
    local running wait_status rc=0
    docker container inspect "$CAPTURE_CONTAINER" >/dev/null 2>&1 || return 0
    running=$(docker inspect -f '{{.State.Running}}' "$CAPTURE_CONTAINER" 2>/dev/null || true)
    if [ "$running" = true ]; then
        timeout 10 docker kill --signal=SIGINT "$CAPTURE_CONTAINER" >/dev/null 2>&1 || rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        if wait_status=$(timeout 10 docker wait "$CAPTURE_CONTAINER" 2>/dev/null); then
            case "$wait_status" in 0|130) ;; *) rc=1;; esac
        else
            rc=$?
        fi
    fi
    if ! timeout 10 docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1; then
        [ "$rc" -ne 0 ] || rc=1
    fi
    return "$rc"
}
cleanup_capture() {
    local rc=0
    stop_capture_container || rc=$?
    if docker container inspect "$CAPTURE_CONTAINER" >/dev/null 2>&1 \
      && ! timeout 10 docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1; then
        [ "$rc" -ne 0 ] || rc=1
    fi
    if docker volume inspect "$CAPTURE_VOLUME" >/dev/null 2>&1 \
      && ! timeout 10 docker volume rm -f "$CAPTURE_VOLUME" >/dev/null 2>&1; then
        [ "$rc" -ne 0 ] || rc=1
    fi
    return "$rc"
}
on_exit() {
    local status=$? capture_status=0
    trap - EXIT INT TERM HUP; set +e
    cleanup_capture || capture_status=$?
    rm -f "$PAYLOADS"
    _cleanup_on_exit
    [ "$status" -eq 0 ] && [ "$capture_status" -ne 0 ] && status=$capture_status
    exit "$status"
}

rs_ctl() { docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null; }
rs_state() { grpcurl_call -d "{\"address\": \"$1\"}" "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null; }
wait_for() {
    local label=$1; shift
    for _ in $(seq 1 60); do "$@" >/dev/null 2>&1 && return; sleep 1; done
    diagnostic_die "timeout: $label"
}
import_explain_names_m102_import() {
    local output
    output=$(rs_ctl policy explain --neighbor "$OPENBGPD_ADDR" --prefix "$IMPORT_DENY") \
      || return 1
    [[ "$output" == *m102-import* ]]
}
wait_import_explain_ready() {
    wait_for "$IMPORT_DENY import explain decision" import_explain_names_m102_import
}
open_session_json_valid() {
    local json=$1
    jq -e '
      try (
        (type == "object")
        and ((.neighbors | type) == "array")
        and ((.neighbors | length) == 1)
        and ((.neighbors[0] | type) == "object")
        and (.neighbors[0].remote_addr == "10.102.1.1")
        and (.neighbors[0].state == "Established")
      ) catch false
    ' <<<"$json" >/dev/null
}
open_prefix_json_valid() {
    local json=$1 prefix=$2
    jq -e --arg p "$prefix" '
      try (
        (type == "object")
        and ((.rib | type) == "array")
        and ((.rib | length) == 1)
        and ((.rib[0] | type) == "object")
        and (.rib[0].prefix == $p)
        and (.rib[0].valid == true)
      ) catch false
    ' <<<"$json" >/dev/null
}
open_route_json_valid() {
    local json=$1 prefix=$2 aspath=$3 exit_nexthop=$4
    jq -e --arg p "$prefix" --arg path "$aspath" --arg nh "$exit_nexthop" '
      try (
        (type == "object")
        and ((.rib | type) == "array")
        and ((.rib | length) == 1)
        and ((.rib[0] | type) == "object")
        and (.rib[0].prefix == $p)
        and (.rib[0].valid == true)
        and (.rib[0].aspath == $path)
        and (.rib[0].exit_nexthop == $nh)
      ) catch false
    ' <<<"$json" >/dev/null
}
open_absence_json_valid() {
    local json=$1 prefix=$2
    jq -e --arg p "$prefix" '
      try (
        (type == "object")
        and (
          ((keys | length) == 0)
          or (
            (keys == ["rib"])
            and
            ((.rib | type) == "array")
            and all(.rib[];
              (type == "object") and ((.prefix | type) == "string"))
            and all(.rib[]; .prefix != $p)
          )
        )
      ) catch false
    ' <<<"$json" >/dev/null
}
open_communities_json_valid() {
    local json=$1 prefix=$2 standard=$3 large=$4
    jq -e --arg p "$prefix" --arg standard "$standard" --arg large "$large" '
      def tokens: split(" ") | map(select(length > 0)) | sort | unique;
      try (
        (type == "object")
        and ((.rib | type) == "array")
        and ((.rib | length) == 1)
        and ((.rib[0] | type) == "object")
        and (.rib[0].prefix == $p)
        and (.rib[0].valid == true)
        and ((.rib[0].communities | type) == "array")
        and all(.rib[0].communities[]; type == "string")
        and ((.rib[0].communities | sort | unique) == ($standard | tokens))
        and ((.rib[0].large_communities | type) == "array")
        and all(.rib[0].large_communities[]; type == "string")
        and ((.rib[0].large_communities | sort | unique) == ($large | tokens))
      ) catch false
    ' <<<"$json" >/dev/null
}
rs_presence_json_valid() {
    local json=$1 prefix=$2
    jq -e --arg p "$prefix" '
      def valid_row:
        if type != "object" then false
        else ((.prefix | type) == "string")
        end;
      try (
        (type == "array")
        and all(.[]; valid_row)
        and (([.[] | select(.prefix == $p)] | length) == 1)
      ) catch false
    ' <<<"$json" >/dev/null
}
rs_absence_json_valid() {
    local json=$1 prefix=$2
    jq -e --arg p "$prefix" '
      def valid_row:
        if type != "object" then false
        else ((.prefix | type) == "string")
        end;
      try (
        (type == "array")
        and all(.[]; valid_row)
        and (([.[] | select(.prefix == $p)] | length) == 0)
      ) catch false
    ' <<<"$json" >/dev/null
}
neighbor_state_json_valid() {
    local json=$1 expected_asn=$2
    jq -e --argjson expected_asn "$expected_asn" '
      try (
        (type == "object")
        and ((.config | type) == "object")
        and (.config.remoteAsn == $expected_asn)
        and (.roleNegotiated == true)
      ) catch false
    ' <<<"$json" >/dev/null
}
frr_communities_json_valid() {
    local json=$1 standard=$2 large=$3
    jq -e --arg standard "$standard" --arg large "$large" '
      def tokens: split(" ") | map(select(length > 0)) | sort | unique;
      try (
        (type == "object")
        and ((.paths | type) == "array")
        and ((.paths | length) == 1)
        and ((.paths[0] | type) == "object")
        and ((.paths[0].community | type) == "object")
        and ((.paths[0].community.string | type) == "string")
        and ((.paths[0].community.string | tokens) == ($standard | tokens))
        and ((.paths[0].largeCommunity | type) == "object")
        and ((.paths[0].largeCommunity.string | type) == "string")
        and ((.paths[0].largeCommunity.string | tokens) == ($large | tokens))
      ) catch false
    ' <<<"$json" >/dev/null
}
frr_absence_json_valid() {
    local json=$1
    jq -e '
      try (
        (type == "object")
        and (
          ((keys | length) == 0)
          or (
            (keys == ["paths"])
            and ((.paths | type) == "array")
            and ((.paths | length) == 0)
          )
        )
      ) catch false
    ' <<<"$json" >/dev/null
}
frr_inventory_json_valid() {
    local json=$1 expected
    shift
    expected=$(jq -cn '$ARGS.positional' --args "$@")
    jq -se --argjson expected "$expected" '
      try (
        (length == 2)
        and all(.[];
          (type == "object") and ((.routes | type) == "object"))
        and (([.[].routes | keys[]] | sort) == ($expected | sort))
      ) catch false
    ' <<<"$json" >/dev/null
}
neighbor_state_projection() {
    local json=$1 projection
    if projection=$(jq -c '
      try {
        root_type: type,
        config_type: (.config | type),
        config_remoteAsn: .config.remoteAsn,
        roleNegotiated: .roleNegotiated
      } catch {shape: "invalid"}
    ' <<<"$json" 2>/dev/null); then
        printf '%s' "${projection:0:1024}"
    else
        printf '%s' '<unavailable-or-invalid-json>'
    fi
}
emit_session_mismatch() {
    local open_json=$1 frr_json=$2 open_actual frr_actual
    open_actual=$(neighbor_state_projection "$open_json")
    frr_actual=$(neighbor_state_projection "$frr_json")
    printf '%s\n' \
      'M102 session expected: open={config.remoteAsn:4200000201,roleNegotiated:true} frr={config.remoteAsn:4200000202,roleNegotiated:true}' \
      "M102 session actual: open=$open_actual frr=$frr_actual" >&2
}
open_community_projection() {
    local json=$1 projection
    if projection=$(jq -c '
      try {
        rib_count: (.rib | length),
        prefix: .rib[0].prefix,
        valid: .rib[0].valid,
        communities_count: (.rib[0].communities | length),
        communities: (.rib[0].communities | sort | unique | .[0:16]),
        large_communities_count: (.rib[0].large_communities | length),
        large_communities: (.rib[0].large_communities | sort | unique | .[0:16])
      } catch {shape: "invalid"}
    ' <<<"$json" 2>/dev/null); then
        printf '%s' "${projection:0:2048}"
    else
        printf '%s' '<unavailable-or-invalid-json>'
    fi
}
frr_community_projection() {
    local json=$1 projection
    if projection=$(jq -c '
      try {
        paths_count: (.paths | length),
        community_string: (.paths[0].community.string | .[0:512]),
        large_community_string: (.paths[0].largeCommunity.string | .[0:512])
      } catch {shape: "invalid"}
    ' <<<"$json" 2>/dev/null); then
        printf '%s' "${projection:0:2048}"
    else
        printf '%s' '<unavailable-or-invalid-json>'
    fi
}
emit_community_mismatch() {
    local open_actual frr_actual
    open_actual=$(open_community_projection "$OPEN_COMMUNITY_OBS")
    frr_actual=$(frr_community_projection "$FRR_COMMUNITY_OBS")
    printf '%s\n' \
      'M102 communities expected: open={standard:[64512:202],large:[4200000202:102:1]} frr={standard:[64512:102],large:[4200000201:102:1]}' \
      "M102 communities actual: open=$open_actual frr=$frr_actual" >&2
}
emit_inventory_mismatch() {
    local surface=$1 expected=$2 actual=$3
    expected=${expected//$'\n'/,}
    actual=${actual//$'\n'/,}
    expected=${expected:0:1024}
    actual=${actual:0:1024}
    printf 'M102 inventory mismatch: surface=%s expected=[%s] actual=[%s]\n' \
      "$surface" "$expected" "$actual" >&2
}
rs_inventory_prefixes() {
    local json=$1
    jq -er '
      if (type == "array")
        and all(.[];
          (type == "object") and ((.prefix | type) == "string"))
      then [.[].prefix] | sort | .[]
      else error("invalid rust inventory JSON")
      end
    ' <<<"$json"
}
open_inventory_prefixes() {
    local json=$1
    jq -er '
      if (type == "object")
        and ((.rib | type) == "array")
        and all(.rib[];
          (type == "object") and ((.prefix | type) == "string"))
      then [.rib[].prefix] | sort | .[]
      else error("invalid OpenBGPD inventory JSON")
      end
    ' <<<"$json"
}
frr_inventory_prefixes() {
    local json=$1
    jq -ser '
      if (length == 2)
        and all(.[];
          (type == "object") and ((.routes | type) == "object"))
      then [.[].routes | keys[]] | sort | .[]
      else error("invalid FRR inventory JSON")
      end
    ' <<<"$json"
}
open_established() {
    local output
    output=$(timeout 5 docker exec "$OPENBGPD" bgpctl -j show) || return 1
    open_session_json_valid "$output"
}
open_has() {
    local prefix=$1 output
    output=$(timeout 5 docker exec "$OPENBGPD" bgpctl -j show rib "$prefix") || return 1
    open_prefix_json_valid "$output" "$prefix"
}
open_route_matches() {
    local prefix=$1 aspath=$2 exit_nexthop=$3 output
    output=$(timeout 5 docker exec "$OPENBGPD" bgpctl -j show rib "$prefix") || return 1
    open_route_json_valid "$output" "$prefix" "$aspath" "$exit_nexthop"
}
open_communities_exact() {
    local prefix=$1 standard=$2 large=$3
    OPEN_COMMUNITY_OBS=""
    OPEN_COMMUNITY_OBS=$(timeout 5 docker exec "$OPENBGPD" \
      bgpctl -j show rib detail "$prefix" 2>/dev/null) || return 1
    open_communities_json_valid "$OPEN_COMMUNITY_OBS" "$prefix" "$standard" "$large"
}
frr_json() { docker exec "$FRR" vtysh -c "show bgp $1 unicast $2 json" 2>/dev/null; }
frr_has() { frr_json "$1" "$2" | jq -e '.paths|length == 1' >/dev/null; }
frr_communities_exact() {
    local family=$1 prefix=$2 standard=$3 large=$4
    FRR_COMMUNITY_OBS=""
    FRR_COMMUNITY_OBS=$(frr_json "$family" "$prefix") || return 1
    frr_communities_json_valid "$FRR_COMMUNITY_OBS" "$standard" "$large"
}
open_absent() {
    local prefix=$1 output
    output=$(timeout 5 docker exec "$OPENBGPD" bgpctl -j show rib) || return 1
    open_absence_json_valid "$output" "$prefix"
}
frr_absent() {
    local family=$1 prefix=$2 output
    output=$(timeout 5 docker exec "$FRR" vtysh \
      -c "show bgp $family unicast $prefix json" 2>/dev/null) || return 1
    frr_absence_json_valid "$output"
}
wait_open_absent() {
    local label=$1 prefix=$2
    for _ in $(seq 1 45); do open_absent "$prefix" && return; sleep 1; done
    diagnostic_die "still present or uninspectable: $label"
}
wait_frr_absent() {
    local label=$1 family=$2 prefix=$3
    for _ in $(seq 1 45); do frr_absent "$family" "$prefix" && return; sleep 1; done
    diagnostic_die "still present or uninspectable: $label"
}
rs_received() {
    local peer=$1 family=$2 prefix=$3 output
    output=$(rs_ctl rib received "$peer" -a "$family" -j) || return 1
    rs_presence_json_valid "$output" "$prefix"
}
rs_received_absent() {
    local peer=$1 family=$2 prefix=$3 output
    output=$(rs_ctl rib received "$peer" -a "$family" -j) || return 1
    rs_absence_json_valid "$output" "$prefix"
}
rs_loc() {
    local prefix=$1 output
    output=$(rs_ctl rib --prefix "$prefix" -j) || return 1
    rs_presence_json_valid "$output" "$prefix"
}
rs_loc_absent() {
    local prefix=$1 output
    output=$(rs_ctl rib --prefix "$prefix" -j) || return 1
    rs_absence_json_valid "$output" "$prefix"
}
rs_advertised() {
    local peer=$1 family=$2 prefix=$3 output
    output=$(rs_ctl rib advertised "$peer" -a "$family" -j) || return 1
    rs_presence_json_valid "$output" "$prefix"
}
rs_advertised_absent() {
    local peer=$1 family=$2 prefix=$3 output
    output=$(rs_ctl rib advertised "$peer" -a "$family" -j) || return 1
    rs_absence_json_valid "$output" "$prefix"
}
rs_inventory_exact() {
 local mode=$1 peer=$2 family=$3 output actual expected
 shift 3
 expected=$(printf '%s\n' "$@" | LC_ALL=C sort)
 if ! output=$(rs_ctl rib "$mode" "$peer" -a "$family" -j 2>/dev/null); then
  emit_inventory_mismatch "rust-$mode-$peer-$family" "$expected" '<command-failed>'
  return 1
 fi
 if ! actual=$(rs_inventory_prefixes "$output" 2>/dev/null); then
  emit_inventory_mismatch "rust-$mode-$peer-$family" "$expected" '<invalid-json>'
  return 1
 fi
 [ "$actual" = "$expected" ] && return 0
 emit_inventory_mismatch "rust-$mode-$peer-$family" "$expected" "$actual"
 return 1
}
rs_loc_inventory_exact() {
 local output actual expected
 expected=$(printf '%s\n' "$@" | LC_ALL=C sort)
 if ! output=$(rs_ctl rib -j 2>/dev/null); then
  emit_inventory_mismatch rust-loc-rib "$expected" '<command-failed>'
  return 1
 fi
 if ! actual=$(rs_inventory_prefixes "$output" 2>/dev/null); then
  emit_inventory_mismatch rust-loc-rib "$expected" '<invalid-json>'
  return 1
 fi
 [ "$actual" = "$expected" ] && return 0
 emit_inventory_mismatch rust-loc-rib "$expected" "$actual"
 return 1
}
frr_established() { docker exec "$FRR" vtysh -c "show bgp neighbors $RS_FRR_ADDR json" | jq -e --arg p "$RS_FRR_ADDR" '.[$p].bgpState=="Established"' >/dev/null; }
open_updates_accounted() { rs_state "$OPENBGPD_ADDR" | jq -e '.updatesReceived >= 4' >/dev/null; }
open_inventory_exact() {
 local output actual expected
 expected=$(printf '%s\n' "$@" | LC_ALL=C sort)
 if ! output=$(timeout 5 docker exec "$OPENBGPD" bgpctl -j show rib 2>/dev/null); then
  emit_inventory_mismatch openbgpd "$expected" '<command-failed>'
  return 1
 fi
 if ! actual=$(open_inventory_prefixes "$output" 2>/dev/null); then
  emit_inventory_mismatch openbgpd "$expected" '<invalid-json>'
  return 1
 fi
 [ "$actual" = "$expected" ] && return 0
 emit_inventory_mismatch openbgpd "$expected" "$actual"
 return 1
}
frr_inventory_exact() {
 local output actual expected
 expected=$(printf '%s\n' "$@" | LC_ALL=C sort)
 if ! output=$(timeout 10 docker exec "$FRR" vtysh \
   -c 'show bgp ipv4 unicast json' -c 'show bgp ipv6 unicast json' 2>/dev/null); then
  emit_inventory_mismatch frr "$expected" '<command-failed>'
  return 1
 fi
 if ! frr_inventory_json_valid "$output" "$@"; then
  if ! actual=$(frr_inventory_prefixes "$output" 2>/dev/null); then
   actual='<invalid-json>'
  fi
  emit_inventory_mismatch frr "$expected" "$actual"
  return 1
 fi
 return 0
}

preflight_identities_and_configs() {
    for b in docker python3 jq timeout; do command -v "$b" >/dev/null || die "host $b missing"; done
    local configured local_id container_id command runtime tshark_version
    docker image inspect "$CAPTURE_IMAGE" >/dev/null 2>&1 || die "$CAPTURE_IMAGE missing"
    tshark_version=$(docker run --rm "$CAPTURE_IMAGE" tshark --version)
    case "$tshark_version" in 'TShark (Wireshark) 4.4.'*) ;; *) die "capture tshark is not 4.4.x";; esac
    configured=$(docker inspect -f '{{.Config.Image}}' "$OPENBGPD"); local_id=$(docker image inspect -f '{{.Id}}' "$OPENBGPD_IMAGE")
    container_id=$(docker inspect -f '{{.Image}}' "$OPENBGPD"); command=$(docker inspect -f '{{json .Config.Cmd}}' "$OPENBGPD")
    [ "$configured" = "$OPENBGPD_IMAGE" ] && [ "$container_id" = "$local_id" ] && [ "$command" = '["sleep","infinity"]' ] || die "OpenBGPD identity drift"
    runtime=$(docker exec "$OPENBGPD" bgpd -V 2>&1); [ "$runtime" = 'OpenBGPD 9.2' ] || die "OpenBGPD runtime drift"
    docker exec "$OPENBGPD" bgpd -n -f /etc/bgpd.conf >/dev/null 2>&1 || die "OpenBGPD config rejected"
    configured=$(docker inspect -f '{{.Config.Image}}' "$FRR"); local_id=$(docker image inspect -f '{{.Id}}' "$FRR_IMAGE"); container_id=$(docker inspect -f '{{.Image}}' "$FRR")
    [ "$configured" = "$FRR_IMAGE" ] && [ "$container_id" = "$local_id" ] || die "FRR identity drift"
    [ "$(docker exec "$FRR" /usr/lib/frr/bgpd --version 2>&1 | sed -n 1p)" = 'bgpd version 10.3.1_git' ] || die "FRR runtime drift"
    docker exec "$FRR" /usr/lib/frr/bgpd -C -f /etc/frr/frr.conf >/dev/null 2>&1 || die "FRR config rejected"
    docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml >/dev/null 2>&1 || die "rustbgpd config rejected"
}

start_capture() {
    if docker container inspect "$CAPTURE_CONTAINER" >/dev/null 2>&1; then
        timeout 10 docker rm -f "$CAPTURE_CONTAINER" >/dev/null || die "stale capture sidecar cleanup failed"
    fi
    if docker volume inspect "$CAPTURE_VOLUME" >/dev/null 2>&1; then
        timeout 10 docker volume rm -f "$CAPTURE_VOLUME" >/dev/null || die "stale capture volume cleanup failed"
    fi
    docker volume create --label rustbgpd.interop.milestone=M102 "$CAPTURE_VOLUME" >/dev/null
    docker run -d --name "$CAPTURE_CONTAINER" \
      --label rustbgpd.interop.milestone=M102 \
      --network "container:$RUSTBGPD" \
      --cap-add=NET_ADMIN --cap-add=NET_RAW \
      --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture" \
      "$CAPTURE_IMAGE" tshark -p -i any \
      -f 'tcp port 179 and net 10.102.0.0/16' -w /capture/m102.pcap >/dev/null
    for _ in $(seq 1 20); do
        [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE_CONTAINER" 2>/dev/null || true)" = true ] \
          && docker logs "$CAPTURE_CONTAINER" 2>&1 | grep -q 'Capturing on' && return
        sleep .25
    done
    die "tshark readiness timeout"
}
stop_capture() {
    stop_capture_container || die "tshark status failure"
    docker run --rm \
      --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture,readonly" \
      "$CAPTURE_IMAGE" sh -ec '
        test -s /capture/m102.pcap
        exec tshark -r /capture/m102.pcap -Y "tcp.len > 0" -T fields -E "separator=/t" \
          -e tcp.stream -e ip.src -e ip.dst -e tcp.seq_raw -e tcp.payload
      ' >"$PAYLOADS"
    [ -s "$PAYLOADS" ] || die "no payload rows"
    timeout 10 docker volume rm "$CAPTURE_VOLUME" >/dev/null || die "capture volume cleanup failed"
}

dump_m102_control_plane_diagnostics() {
    printf '%s\n' '--- M102 diagnostics: OpenBGPD log (tail 120) ---' >&2
    timeout 5 docker exec "$OPENBGPD" sh -c 'tail -n 120 /tmp/m102-bgpd.log' \
      2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M102 diagnostics: OpenBGPD process and control socket ---' >&2
    # shellcheck disable=SC2016 # expanded by the container shell
    timeout 5 docker exec "$OPENBGPD" sh -c '
      pid=$(cat /tmp/m102-bgpd.pid 2>/dev/null || true)
      printf "recorded_pid=%s\n" "$pid"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        printf "recorded_pid_alive=yes\n"
      else
        printf "recorded_pid_alive=no\n"
      fi
      ls -la /run/bgpd 2>&1 || true
      ps w 2>&1 || true
    ' 2>&1 | head -n 120 >&2 || true
    timeout 5 docker exec "$OPENBGPD" bgpctl show 2>&1 | head -n 120 >&2 || true
    timeout 5 docker exec "$OPENBGPD" bgpctl show neighbor 10.102.1.1 \
      2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M102 diagnostics: rustbgpd log (tail 120) ---' >&2
    timeout 5 docker exec "$RUSTBGPD" sh -c 'tail -n 120 /tmp/m102-rustbgpd.log' \
      2>&1 | head -n 120 >&2 || true
    printf '%s\n' '--- M102 diagnostics: rustbgpd process and neighbor state ---' >&2
    timeout 5 docker top "$RUSTBGPD" 2>&1 | head -n 80 >&2 || true
    grpcurl_call -max-time 5 -d "{\"address\": \"$OPENBGPD_ADDR\"}" \
      "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState \
      2>&1 | head -n 120 >&2 || true
    grpcurl_call -max-time 5 -d "{\"address\": \"$FRR_ADDR\"}" \
      "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState \
      2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M102 diagnostics: FRR neighbor state ---' >&2
    timeout 5 docker top "$FRR" 2>&1 | head -n 80 >&2 || true
    timeout 5 docker exec "$FRR" vtysh -c "show bgp neighbors $RS_FRR_ADDR" \
      2>&1 | head -n 120 >&2 || true

    local container
    for container in "$RUSTBGPD" "$OPENBGPD" "$FRR"; do
        printf '%s\n' "--- M102 diagnostics: $container addresses and routes ---" >&2
        timeout 5 docker exec "$container" sh -c \
          'ip -brief address; ip route show; ip -6 route show' \
          2>&1 | head -n 120 >&2 || true
    done
}

dump_m102_capture_diagnostics() {
    printf '%s\n' '--- M102 diagnostics: bounded BGP capture summary ---' >&2
    if ! docker volume inspect "$CAPTURE_VOLUME" >/dev/null 2>&1; then
        printf '%s\n' 'capture volume is not available' >&2
        return 0
    fi
    if ! stop_capture_container; then
        printf '%s\n' 'capture sidecar did not stop cleanly; decoding retained volume' >&2
    fi
    timeout 15 docker run --rm \
      --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture,readonly" \
      "$CAPTURE_IMAGE" sh -ec '
        if [ ! -s /capture/m102.pcap ]; then
          printf "%s\n" "capture file is absent or empty"
          exit 0
        fi
        printf "%s\n" "packet summary (first 80 BGP TCP packets)"
        tshark -r /capture/m102.pcap -Y "tcp.port == 179" -c 80 -T fields \
          -E "header=y" -E "separator=," \
          -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
          -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.len -e _ws.col.Info
        printf "%s\n" "TCP conversation summary"
        tshark -r /capture/m102.pcap -q -z conv,tcp
      ' 2>&1 | head -n 220 >&2 || true
    printf '%s\n' 'capture volume retained for idempotent trap cleanup' >&2
}

dump_m102_diagnostics() {
    [ "$DIAGNOSTICS_DUMPED" -eq 0 ] || return 0
    DIAGNOSTICS_DUMPED=1
    dump_m102_control_plane_diagnostics
    dump_m102_capture_diagnostics
}

diagnostic_die() {
    local message=$*
    dump_m102_diagnostics
    die "$message"
}

raw_oracle() {
python3 - "$1" <<'PY'
import collections,sys
rows=collections.defaultdict(list)
for raw in open(sys.argv[1]):
 f=raw.rstrip().split("\t")
 if len(f)==5 and f[4] and f[1]=="10.102.1.2" and f[2]=="10.102.1.1":
  rows[tuple(f[:3])].append((int(f[3]),bytes.fromhex(f[4].replace(":",""))))
def need(v,m):
 if not v: raise SystemExit(m)
def reasm(parts):
 cur=min(s for s,_ in parts); out=bytearray()
 for seq,pay in sorted(parts):
  need(seq<=cur,f"TCP gap {cur}->{seq}"); overlap=max(0,cur-seq)
  need(pay[:overlap] == out[seq-min(s for s,_ in parts):seq-min(s for s,_ in parts)+overlap],"conflicting TCP overlap")
  if overlap<len(pay): out+=pay[overlap:]; cur=seq+len(pay)
 return bytes(out)
def msgs(data):
 out=[]; p=0
 while p<len(data):
  need(len(data)-p>=19,"unexplained trailing partial BGP bytes")
  need(data[p:p+16]==b"\xff"*16,"BGP marker is not at stream cursor")
  n=int.from_bytes(data[p+16:p+18],"big"); need(19<=n<=4096,"bad BGP length")
  need(p+n<=len(data),"unexplained trailing partial BGP message")
  out.append(data[p:p+n]); p+=n
 return out
def open_proof(m):
 need(m[18]==1 and int.from_bytes(m[20:22],"big")==23456,"OPEN lacks AS_TRANS")
 d=m[29:29+m[28]]; p=0; caps={}
 while p<len(d):
  need(d[p]==2,"unexpected OPEN parameter"); n=d[p+1]; v=d[p+2:p+2+n]; p+=2+n; q=0
  while q<len(v): code=v[q]; size=v[q+1]; caps.setdefault(code,[]).append(v[q+2:q+2+size]); q+=2+size
 need(caps.get(65)==[(4200000201).to_bytes(4,"big")],"capability 65 ASN mismatch")
 need(caps.get(9)==[b"\x02"],"role capability 9 mismatch")
 need(b"\x00\x01\x00\x01" in caps.get(1,[]),"IPv4 MP tuple absent")
 need(b"\x00\x02\x00\x01" in caps.get(1,[]),"IPv6 MP tuple absent")
def update(m):
 b=m[19:]; w=int.from_bytes(b[:2],"big"); p=2+w; n=int.from_bytes(b[p:p+2],"big"); a=b[p+2:p+2+n]; nlri=b[p+2+n:]; p=0; path=None
 nh=None; community=None; large=None
 while p<len(a):
  flags,code=a[p],a[p+1]; p+=2
  if flags&16: size=int.from_bytes(a[p:p+2],"big"); p+=2
  else: size=a[p]; p+=1
  v=a[p:p+size]; p+=size
  if code==2: need(v[:2]==b"\x02\x01" and len(v)==6,"AS_PATH shape"); path=int.from_bytes(v[2:6],"big")
  if code==3: nh=v
  if code==8: community=v
  if code==32: large=v
 return path,nh,community,large,nlri
def has_nlri(raw): return raw==b"\x18\xc0\x00\x02"
need(len(rows)==1,"expected exactly one OpenBGPD-to-rustbgpd TCP stream")
allm=msgs(reasm(next(iter(rows.values())))); opens=[m for m in allm if m[18]==1]
need(len(opens)==1,"expected exactly one OpenBGPD OPEN"); open_proof(opens[0])
want_community=(64512).to_bytes(2,"big")+(102).to_bytes(2,"big")
want_large=(4200000201).to_bytes(4,"big")+(102).to_bytes(4,"big")+(1).to_bytes(4,"big")
proofs=[update(m) for m in allm if m[18]==2]
need(any(p==4200000201 and nh==bytes([10,102,1,2]) and c==want_community and lc==want_large and has_nlri(n)
 for p,nh,c,lc,n in proofs),"exact UPDATE attributes absent")
print("as_trans cap65_asn role9 mp_v4_v6 update_path_nexthop update_communities")
PY
}

self_test_oracle() {
    local mutation=${1:-positive} f; f=$(mktemp /tmp/m102-oracle.XXXXXX.tsv)
    python3 - "$f" "$mutation" <<'PY'
import sys
mutation=sys.argv[2]; mk=b"\xff"*16
caps=b"\x41\x04"+(4200000201).to_bytes(4,"big")+b"\x09\x01\x02\x01\x04\x00\x01\x00\x01\x01\x04\x00\x02\x00\x01"
if mutation=="capability": caps=caps.replace(b"\x09\x01\x02",b"\x09\x01\x03")
cap=b"\x02"+bytes([len(caps)])+caps
op=mk+(29+len(cap)).to_bytes(2,"big")+b"\x01\x04"+(23456).to_bytes(2,"big")+b"\x00\x5a\x00\x00\x00\x01"+bytes([len(cap)])+cap
a=b"\x40\x01\x01\x00\x40\x02\x06\x02\x01"+(4200000201).to_bytes(4,"big")+b"\x40\x03\x04\x0a\x66\x01\x02"+b"\xc0\x08\x04\xfc\x00\x00\x66"+b"\xc0\x20\x0c"+(4200000201).to_bytes(4,"big")+(102).to_bytes(4,"big")+(1).to_bytes(4,"big")
if mutation=="update": a=a.replace(b"\x0a\x66\x01\x02",b"\x0a\x66\x01\x03")
u=mk+(23+len(a)+4).to_bytes(2,"big")+b"\x02\x00\x00"+len(a).to_bytes(2,"big")+a+b"\x18\xc0\x00\x02"; d=op+u; c=31
if mutation=="trailing": d+=b"\xff"
if mutation=="marker": d=b"\x00"+d
with open(sys.argv[1],"w") as f:
 first=d[:c]
 if mutation=="conflict": conflict=bytearray(first); conflict[-1]^=1; conflict=bytes(conflict)
 else: conflict=first
 tail_seq=100+c+(1 if mutation=="gap" else 0)
 f.write(f"0\t10.102.1.2\t10.102.1.1\t100\t{first.hex()}\n0\t10.102.1.2\t10.102.1.1\t100\t{conflict.hex()}\n0\t10.102.1.2\t10.102.1.1\t{tail_seq}\t{d[c:].hex()}\n")
PY
    if [ "$mutation" = positive ]; then raw_oracle "$f" >/dev/null
    elif raw_oracle "$f" >/dev/null 2>&1; then rm -f "$f"; die "oracle accepted $mutation mutation"; fi
    rm -f "$f"
}

json_expect_accept() {
    local label=$1; shift
    "$@" >/dev/null || die "JSON fixture unexpectedly rejected: $label"
}
json_expect_reject() {
    local label=$1; shift
    if "$@" >/dev/null 2>&1; then
        die "JSON fixture unexpectedly accepted: $label"
    fi
}
self_test_import_explain_readiness() {
    local attempts count count_file
    count_file=$(mktemp /tmp/m102-import-explain.XXXXXX)
    printf '0\n' >"$count_file"
    # shellcheck disable=SC2317 # wait_for invokes this stub indirectly
    rs_ctl() {
        read -r count <"$count_file"
        count=$((count + 1))
        printf '%s\n' "$count" >"$count_file"
        if [ "$count" -lt 3 ]; then
            printf 'outcome: not_seen\n'
        else
            printf 'policy:  m102-import\n'
        fi
    }
    sleep() { :; }
    diagnostic_die() { return 1; }

    if ! wait_import_explain_ready; then
        rm -f "$count_file"
        echo "import-explain readiness did not converge" >&2
        return 1
    fi
    read -r attempts <"$count_file"
    rm -f "$count_file"
    if [ "$attempts" -ne 3 ]; then
        echo "import-explain readiness accepted attempt $attempts, expected 3" >&2
        return 1
    fi
    echo "M102 import-explain readiness self-test: 3 attempts"
}
self_test_openbgpd_json() {
    local session route inventory
    session='{"neighbors":[{"remote_addr":"10.102.1.1","state":"Established"}]}'
    json_expect_accept "session exact neighbor" open_session_json_valid "$session"
    json_expect_reject "session non-object root" open_session_json_valid '[]'
    json_expect_reject "session missing neighbors" open_session_json_valid '{}'
    json_expect_reject "session zero neighbors" open_session_json_valid '{"neighbors":[]}'
    json_expect_reject "session duplicate neighbors" open_session_json_valid \
      '{"neighbors":[{"remote_addr":"10.102.1.1","state":"Established"},{"remote_addr":"10.102.1.1","state":"Established"}]}'
    json_expect_reject "session malformed neighbor" open_session_json_valid '{"neighbors":["Established"]}'
    json_expect_reject "session wrong peer" open_session_json_valid \
      '{"neighbors":[{"remote_addr":"10.102.9.9","state":"Established"}]}'
    json_expect_reject "session wrong state" open_session_json_valid \
      '{"neighbors":[{"remote_addr":"10.102.1.1","state":"Active"}]}'
    json_expect_reject "session malformed JSON" open_session_json_valid '{'

    json_expect_accept "neighbor state nested ASN ignores top-level decoy" \
      neighbor_state_json_valid \
      '{"remoteAsn":1,"config":{"remoteAsn":4200000201},"roleNegotiated":true}' \
      4200000201
    json_expect_reject "neighbor state missing config" neighbor_state_json_valid \
      '{"remoteAsn":4200000201,"roleNegotiated":true}' 4200000201
    json_expect_reject "neighbor state wrong nested ASN despite top-level decoy" \
      neighbor_state_json_valid \
      '{"remoteAsn":4200000201,"config":{"remoteAsn":4200000999},"roleNegotiated":true}' \
      4200000201
    json_expect_reject "neighbor state false role" neighbor_state_json_valid \
      '{"config":{"remoteAsn":4200000201},"roleNegotiated":false}' 4200000201
    json_expect_reject "neighbor state missing role" neighbor_state_json_valid \
      '{"config":{"remoteAsn":4200000201}}' 4200000201
    json_expect_reject "neighbor state non-numeric nested ASN" neighbor_state_json_valid \
      '{"config":{"remoteAsn":"4200000201"},"roleNegotiated":true}' 4200000201
    json_expect_reject "neighbor state malformed config" neighbor_state_json_valid \
      '{"config":[],"roleNegotiated":true}' 4200000201
    json_expect_reject "neighbor state non-object root" neighbor_state_json_valid '[]' 4200000201
    json_expect_reject "neighbor state malformed JSON" neighbor_state_json_valid '{' 4200000201

    route='{"rib":[{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000202","exit_nexthop":"10.102.2.2"}]}'
    json_expect_accept "route exact tuple" open_route_json_valid "$route" \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_accept "prefix exact valid row" open_prefix_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true}]}' 198.18.102.0/24
    json_expect_reject "prefix invalid row" open_prefix_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":false}]}' 198.18.102.0/24
    json_expect_reject "route non-object root" open_route_json_valid '[]' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route missing rib" open_route_json_valid '{}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route zero rows" open_route_json_valid '{"rib":[]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route duplicate rows" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000202","exit_nexthop":"10.102.2.2"},{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000202","exit_nexthop":"10.102.2.2"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route malformed row" open_route_json_valid '{"rib":["198.18.102.0/24"]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route wrong prefix" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.103.0/24","valid":true,"aspath":"4200000202","exit_nexthop":"10.102.2.2"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route invalid flag" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":false,"aspath":"4200000202","exit_nexthop":"10.102.2.2"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route wrong AS path" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000999","exit_nexthop":"10.102.2.2"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route wrong exit nexthop" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000202","exit_nexthop":"10.102.2.3"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route nonexistent nexthop field" open_route_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"aspath":"4200000202","nexthop":"10.102.2.2"}]}' \
      198.18.102.0/24 4200000202 10.102.2.2
    json_expect_reject "route malformed JSON" open_route_json_valid '{' \
      198.18.102.0/24 4200000202 10.102.2.2

    json_expect_accept "absence missing rib" open_absence_json_valid '{}' 198.18.102.0/24
    json_expect_accept "absence empty rib" open_absence_json_valid '{"rib":[]}' 198.18.102.0/24
    json_expect_accept "absence unrelated route" open_absence_json_valid \
      '{"rib":[{"prefix":"198.18.103.0/24"}]}' 198.18.102.0/24
    json_expect_reject "absence error-only object" open_absence_json_valid \
      '{"error":"query failed"}' 198.18.102.0/24
    json_expect_reject "absence failed status object" open_absence_json_valid \
      '{"status":"FAILED"}' 198.18.102.0/24
    json_expect_reject "absence empty rib plus error" open_absence_json_valid \
      '{"rib":[],"error":"query failed"}' 198.18.102.0/24
    json_expect_reject "absence arbitrary extra key" open_absence_json_valid \
      '{"rib":[],"metadata":{}}' 198.18.102.0/24
    json_expect_reject "absence target present" open_absence_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24"}]}' 198.18.102.0/24
    json_expect_reject "absence non-object root" open_absence_json_valid '[]' 198.18.102.0/24
    json_expect_reject "absence null rib" open_absence_json_valid '{"rib":null}' 198.18.102.0/24
    json_expect_reject "absence malformed rib" open_absence_json_valid '{"rib":"empty"}' 198.18.102.0/24
    json_expect_reject "absence malformed row" open_absence_json_valid '{"rib":[42]}' 198.18.102.0/24
    json_expect_reject "absence missing prefix" open_absence_json_valid '{"rib":[{}]}' 198.18.102.0/24
    json_expect_reject "absence non-string prefix" open_absence_json_valid '{"rib":[{"prefix":42}]}' 198.18.102.0/24
    json_expect_reject "absence malformed JSON" open_absence_json_valid '{' 198.18.102.0/24

    json_expect_accept "rust presence exact row" rs_presence_json_valid \
      '[{"prefix":"192.0.2.0/24"}]' 192.0.2.0/24
    json_expect_accept "rust presence with valid unrelated row" rs_presence_json_valid \
      '[{"prefix":"198.51.100.0/24"},{"prefix":"192.0.2.0/24"}]' 192.0.2.0/24
    json_expect_reject "rust presence missing target" rs_presence_json_valid '[]' 192.0.2.0/24
    json_expect_reject "rust presence non-array root" rs_presence_json_valid '{}' 192.0.2.0/24
    json_expect_reject "rust presence duplicate target" rs_presence_json_valid \
      '[{"prefix":"192.0.2.0/24"},{"prefix":"192.0.2.0/24"}]' 192.0.2.0/24
    json_expect_reject "rust presence malformed row" rs_presence_json_valid '[42]' 192.0.2.0/24
    json_expect_reject "rust presence non-string prefix" rs_presence_json_valid \
      '[{"prefix":42}]' 192.0.2.0/24
    json_expect_reject "rust presence malformed JSON" rs_presence_json_valid '[' 192.0.2.0/24
    json_expect_accept "rust absence empty array" rs_absence_json_valid '[]' 192.0.2.0/24
    json_expect_accept "rust absence unrelated row" rs_absence_json_valid \
      '[{"prefix":"198.51.100.0/24"}]' 192.0.2.0/24
    json_expect_reject "rust absence target present" rs_absence_json_valid \
      '[{"prefix":"192.0.2.0/24"}]' 192.0.2.0/24
    json_expect_reject "rust absence non-array root" rs_absence_json_valid '{}' 192.0.2.0/24
    json_expect_reject "rust absence malformed row" rs_absence_json_valid '[{}]' 192.0.2.0/24
    json_expect_reject "rust absence non-string prefix" rs_absence_json_valid \
      '[{"prefix":42}]' 192.0.2.0/24
    json_expect_reject "rust absence malformed JSON" rs_absence_json_valid '[' 192.0.2.0/24

    json_expect_accept "FRR absence exact empty object" frr_absence_json_valid '{}'
    json_expect_accept "FRR absence exact empty paths" frr_absence_json_valid '{"paths":[]}'
    json_expect_reject "FRR absence error-only object" frr_absence_json_valid \
      '{"error":"query failed"}'
    json_expect_reject "FRR absence failed status object" frr_absence_json_valid \
      '{"status":"FAILED"}'
    json_expect_reject "FRR absence empty paths plus error" frr_absence_json_valid \
      '{"paths":[],"error":"query failed"}'
    json_expect_reject "FRR absence arbitrary extra key" frr_absence_json_valid \
      '{"paths":[],"metadata":{}}'
    json_expect_reject "FRR absence nonempty paths" frr_absence_json_valid \
      '{"paths":[{"prefix":"192.0.2.0/24"}]}'
    json_expect_reject "FRR absence malformed paths" frr_absence_json_valid \
      '{"paths":"empty"}'
    json_expect_reject "FRR absence malformed JSON" frr_absence_json_valid '{'

    inventory='{"routes":{"192.0.2.0/24":{"prefix":"bogus-nested-v4"},"2001:db8:1102::/48":{"nested":{"prefix":"bogus-nested-v6"}}}}
{"routes":{"198.18.102.0/24":{"prefix":"another-decoy"},"2001:db8:2102::/48":{"prefix":"final-decoy"}}}'
    json_expect_accept "FRR inventory exact dual documents ignores nested decoys" \
      frr_inventory_json_valid "$inventory" \
      192.0.2.0/24 2001:db8:1102::/48 198.18.102.0/24 2001:db8:2102::/48
    json_expect_reject "FRR inventory one document" frr_inventory_json_valid \
      '{"routes":{"192.0.2.0/24":{}}}' 192.0.2.0/24
    json_expect_reject "FRR inventory three documents" frr_inventory_json_valid \
      $'{"routes":{}}\n{"routes":{}}\n{"routes":{}}' 192.0.2.0/24
    json_expect_reject "FRR inventory missing routes" frr_inventory_json_valid \
      $'{}\n{"routes":{}}'
    json_expect_reject "FRR inventory non-object routes" frr_inventory_json_valid \
      $'{"routes":[]}\n{"routes":{}}'
    json_expect_reject "FRR inventory wrong keys" frr_inventory_json_valid \
      $'{"routes":{"192.0.2.0/24":{},"2001:db8:1102::/48":{}}}\n{"routes":{"198.18.103.0/24":{},"2001:db8:2102::/48":{}}}' \
      192.0.2.0/24 2001:db8:1102::/48 198.18.102.0/24 2001:db8:2102::/48
    json_expect_reject "FRR inventory missing key" frr_inventory_json_valid \
      $'{"routes":{"192.0.2.0/24":{},"2001:db8:1102::/48":{}}}\n{"routes":{"198.18.102.0/24":{}}}' \
      192.0.2.0/24 2001:db8:1102::/48 198.18.102.0/24 2001:db8:2102::/48
    json_expect_reject "FRR inventory extra key" frr_inventory_json_valid \
      $'{"routes":{"192.0.2.0/24":{},"2001:db8:1102::/48":{},"203.0.113.0/24":{}}}\n{"routes":{"198.18.102.0/24":{},"2001:db8:2102::/48":{}}}' \
      192.0.2.0/24 2001:db8:1102::/48 198.18.102.0/24 2001:db8:2102::/48
    json_expect_reject "FRR inventory non-object root" frr_inventory_json_valid \
      $'[]\n{"routes":{}}'
    json_expect_reject "FRR inventory malformed JSON" frr_inventory_json_valid \
      $'{"routes":{}}\n{'

    json_expect_accept "Open communities normalized exact sets" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["64512:103","64512:102","64512:103"],"large_communities":["4200000202:102:2","4200000202:102:1","4200000202:102:2"]}]}' \
      198.18.102.0/24 '64512:102 64512:103' '4200000202:102:1 4200000202:102:2'
    json_expect_reject "Open communities standard extra" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["64512:102","64512:999"],"large_communities":["4200000202:102:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities large extra" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["64512:102"],"large_communities":["4200000202:102:1","4200000202:999:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities substring token" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["164512:102"],"large_communities":["4200000202:102:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities wrong schema" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":"64512:102","large_communities":["4200000202:102:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities non-string item" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":[42],"large_communities":["4200000202:102:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities missing standard array" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"large_communities":["4200000202:102:1"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities missing large array" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["64512:102"]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1
    json_expect_reject "Open communities non-string large item" open_communities_json_valid \
      '{"rib":[{"prefix":"198.18.102.0/24","valid":true,"communities":["64512:102"],"large_communities":[42]}]}' \
      198.18.102.0/24 64512:102 4200000202:102:1

    json_expect_accept "FRR communities normalized exact sets" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"64512:103  64512:102 64512:103"},"largeCommunity":{"string":"4200000201:102:2 4200000201:102:1 4200000201:102:2"}}]}' \
      '64512:102 64512:103' '4200000201:102:1 4200000201:102:2'
    json_expect_reject "FRR communities standard extra" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"64512:102 64512:999"},"largeCommunity":{"string":"4200000201:102:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities large extra" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"64512:102"},"largeCommunity":{"string":"4200000201:102:1 4200000201:999:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities substring token" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"164512:102"},"largeCommunity":{"string":"4200000201:102:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities wrong schema" frr_communities_json_valid \
      '{"paths":[{"community":["64512:102"],"largeCommunity":{"string":"4200000201:102:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities duplicate paths" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"64512:102"},"largeCommunity":{"string":"4200000201:102:1"}},{"community":{"string":"64512:102"},"largeCommunity":{"string":"4200000201:102:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities zero paths" frr_communities_json_valid \
      '{"paths":[]}' 64512:102 4200000201:102:1
    json_expect_reject "FRR communities missing standard string" frr_communities_json_valid \
      '{"paths":[{"community":{},"largeCommunity":{"string":"4200000201:102:1"}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities missing large string" frr_communities_json_valid \
      '{"paths":[{"community":{"string":"64512:102"},"largeCommunity":{}}]}' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities non-object root" frr_communities_json_valid '[]' \
      64512:102 4200000201:102:1
    json_expect_reject "FRR communities malformed JSON" frr_communities_json_valid '{' \
      64512:102 4200000201:102:1
    printf '%s\n' 'M102 OpenBGPD JSON self-test passed'
}

start_openbgpd() {
    if ! timeout 5 docker exec "$OPENBGPD" sh -c '
      mkdir -p /run/bgpd
      rm -f /tmp/m102-bgpd.pid /tmp/m102-bgpd.log \
        /run/bgpd/bgpd.sock.* /run/bgpd/bgpd.rsock /run/bgpd/bgpd.rsock.*
      : > /tmp/m102-bgpd.log
      bgpd -d -f /etc/bgpd.conf >>/tmp/m102-bgpd.log 2>&1 &
      printf "%s\n" "$!" > /tmp/m102-bgpd.pid
    '; then
        return 1
    fi
    for _ in $(seq 1 20); do
        # shellcheck disable=SC2016 # expanded by the container shell
        if ! timeout 5 docker exec "$OPENBGPD" sh -ec '
          pid=$(cat /tmp/m102-bgpd.pid)
          [ -n "$pid" ]
          kill -0 "$pid"
        ' >/dev/null 2>&1; then
            return 1
        fi
        if timeout 5 docker exec "$OPENBGPD" bgpctl show >/dev/null 2>&1; then
            return 0
        fi
        sleep .25
    done
    return 1
}
start_peers() {
    if ! timeout 15 docker exec "$FRR" /usr/lib/frr/frrinit.sh start >/dev/null; then
        diagnostic_die "FRR startup failed"
    fi
    if ! start_openbgpd; then
        diagnostic_die "OpenBGPD startup or control-socket readiness failed"
    fi
}
start_m102_rustbgpd() {
    if ! (
      trap - EXIT INT TERM HUP
      start_rustbgpd "/usr/local/bin/start-rustbgpd.sh >/tmp/m102-rustbgpd.log 2>&1"
    ); then
        diagnostic_die "rustbgpd gRPC startup failed"
    fi
    # start_rustbgpd records the shared gRPC readiness PASS in the subshell.
    # Restore that one ledger increment in the parent without printing it twice.
    pass=$((pass + 1))
}
inject_open() { for p in "$OPEN_V4" "$OPEN_V6" "$IMPORT_DENY" "$EXPORT_DENY"; do docker exec "$OPENBGPD" bgpctl network add "$p" >/dev/null; done; }
withdraw_open() { for p in "$OPEN_V4" "$OPEN_V6" "$IMPORT_DENY" "$EXPORT_DENY"; do docker exec "$OPENBGPD" bgpctl network delete "$p" >/dev/null; done; }
withdraw_frr() {
 docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 4200000202' \
  -c 'address-family ipv4 unicast' -c "no network $FRR_V4 route-map M102-ORIGIN" \
  -c 'address-family ipv6 unicast' -c "no network $FRR_V6 route-map M102-ORIGIN" >/dev/null
}

assert_sessions() {
 local os="" fs="" os_rc=0 fs_rc=0
 os=$(rs_state "$OPENBGPD_ADDR" 2>/dev/null) || os_rc=$?
 fs=$(rs_state "$FRR_ADDR" 2>/dev/null) || fs_rc=$?
 open_established && ok "OpenBGPD member is Established" || fail "OpenBGPD not Established"
 frr_established && ok "FRR member is Established" || fail "FRR not Established"
 if [ "$os_rc" -eq 0 ] && [ "$fs_rc" -eq 0 ] \
   && neighbor_state_json_valid "$os" 4200000201 \
   && neighbor_state_json_valid "$fs" 4200000202; then
  ok "rustbgpd reports exact remote ASNs and negotiated Roles"
 else
  emit_session_mismatch "$os" "$fs"
  fail "rustbgpd ASN/Role state mismatch"
 fi
}
assert_forward() {
 rs_received "$OPENBGPD_ADDR" ipv4 "$OPEN_V4" && ok "Rust Adj-RIB-In contains OpenBGPD IPv4" || fail "Rust Adj-RIB-In Open v4 missing"
 rs_received "$OPENBGPD_ADDR" ipv6 "$OPEN_V6" && ok "Rust Adj-RIB-In contains OpenBGPD IPv6" || fail "Rust Adj-RIB-In Open v6 missing"
 rs_loc "$OPEN_V4" && ok "Rust Loc-RIB contains OpenBGPD IPv4" || fail "Rust Loc-RIB Open v4 missing"
 rs_loc "$OPEN_V6" && ok "Rust Loc-RIB contains OpenBGPD IPv6" || fail "Rust Loc-RIB Open v6 missing"
 frr_json ipv4 "$OPEN_V4" | jq -e '.paths|length==1 and .[0].aspath.string=="4200000201" and .[0].nexthops[0].ip=="10.102.1.2"' >/dev/null \
  && ok "FRR IPv4 has exact OpenBGPD AS_PATH/NEXT_HOP" || fail "FRR Open v4 tuple mismatch"
 frr_json ipv6 "$OPEN_V6" | jq -e '.paths|length==1 and .[0].aspath.string=="4200000201" and .[0].nexthops[0].ip=="2001:db8:102:1::2"' >/dev/null \
  && ok "FRR IPv6 has exact OpenBGPD AS_PATH/NEXT_HOP" || fail "FRR Open v6 tuple mismatch"
}
community_row_matches() {
 local rc=0
 frr_communities_exact ipv4 "$OPEN_V4" 64512:102 4200000201:102:1 || rc=1
 open_communities_exact "$FRR_V4" 64512:202 4200000202:102:1 || rc=1
 return "$rc"
}
assert_reverse() {
 open_route_matches "$FRR_V4" 4200000202 10.102.2.2 \
  && ok "OpenBGPD IPv4 has exact FRR AS_PATH/NEXT_HOP" || fail "Open FRR v4 tuple mismatch"
 open_route_matches "$FRR_V6" 4200000202 2001:db8:102:2::2 \
  && ok "OpenBGPD IPv6 has exact FRR AS_PATH/NEXT_HOP" || fail "Open FRR v6 tuple mismatch"
 if community_row_matches; then
  ok "standard and Large Communities survive both directions"
 else
  emit_community_mismatch
  fail "bidirectional communities missing"
 fi
}
assert_policy() {
 rs_loc_absent "$IMPORT_DENY" && ok "global import policy denies its prefix" || fail "import deny leaked"
 import_explain_names_m102_import && ok "import explain names m102-import" || fail "import explain missing"
 rs_loc "$EXPORT_DENY" && ok "export-denied route remains in Loc-RIB" || fail "export source missing"
 rs_advertised_absent "$FRR_ADDR" ipv4 "$EXPORT_DENY" && ok "FRR advertised view omits export deny" || fail "export deny advertised"
 rs_ctl rib --prefix "$EXPORT_DENY" advertised "$FRR_ADDR" --explain | grep m102-export-to-frr >/dev/null && ok "export explain names m102-export-to-frr" || fail "export explain missing"
 frr_has ipv4 "$OPEN_V4" && open_has "$FRR_V4" && ok "policy positive controls pass both directions" || fail "policy positive control missing"
}
assert_wire() {
 local result; result=$(raw_oracle "$PAYLOADS")
 grep -qw as_trans <<<"$result" && ok "raw OPEN uses AS_TRANS" || fail "AS_TRANS missing"
 grep -qw cap65_asn <<<"$result" && ok "raw capability 65 carries ASN 4200000201" || fail "capability 65 mismatch"
 grep -qw role9 <<<"$result" && ok "raw capability 9 carries rs-client role" || fail "role capability mismatch"
 grep -qw mp_v4_v6 <<<"$result" && ok "raw OPEN carries exact IPv4/IPv6 MP tuples" || fail "MP tuples mismatch"
 grep -qw update_path_nexthop <<<"$result" && ok "raw UPDATE has exact AS_PATH/NEXT_HOP" || fail "UPDATE path/next-hop mismatch"
 grep -qw update_communities <<<"$result" && ok "raw UPDATE has exact standard/Large Communities" || fail "UPDATE communities mismatch"
}
inventory_row_matches() {
 local rc=0
 rs_inventory_exact received "$OPENBGPD_ADDR" ipv4 "$OPEN_V4" "$EXPORT_DENY" || rc=1
 rs_inventory_exact received "$OPENBGPD_ADDR" ipv6 "$OPEN_V6" || rc=1
 rs_inventory_exact received "$FRR_ADDR" ipv4 "$FRR_V4" || rc=1
 rs_inventory_exact received "$FRR_ADDR" ipv6 "$FRR_V6" || rc=1
 rs_inventory_exact advertised "$FRR_ADDR" ipv4 "$OPEN_V4" || rc=1
 rs_inventory_exact advertised "$FRR_ADDR" ipv6 "$OPEN_V6" || rc=1
 rs_inventory_exact advertised "$OPENBGPD_ADDR" ipv4 "$FRR_V4" || rc=1
 rs_inventory_exact advertised "$OPENBGPD_ADDR" ipv6 "$FRR_V6" || rc=1
 rs_loc_inventory_exact "$OPEN_V4" "$OPEN_V6" "$FRR_V4" "$FRR_V6" "$EXPORT_DENY" || rc=1
 open_inventory_exact "$OPEN_V4" "$OPEN_V6" "$IMPORT_DENY" "$EXPORT_DENY" "$FRR_V4" "$FRR_V6" || rc=1
 frr_inventory_exact "$OPEN_V4" "$OPEN_V6" "$FRR_V4" "$FRR_V6" || rc=1
 return "$rc"
}
assert_inventory() {
 if inventory_row_matches; then
  ok "OpenBGPD, FRR, and Rust inventories are exact with no extras"
 else
  fail "initial inventory drifted"
 fi
}
assert_withdrawals() {
 wait_frr_absent "$OPEN_V4 at FRR" ipv4 "$OPEN_V4"; rs_received_absent "$OPENBGPD_ADDR" ipv4 "$OPEN_V4" && rs_loc_absent "$OPEN_V4" && ok "OpenBGPD IPv4 leaves Rust Adj-RIB-In/Loc-RIB and FRR" || fail "Open v4 withdrawal incomplete"
 wait_frr_absent "$OPEN_V6 at FRR" ipv6 "$OPEN_V6"; rs_received_absent "$OPENBGPD_ADDR" ipv6 "$OPEN_V6" && rs_loc_absent "$OPEN_V6" && ok "OpenBGPD IPv6 leaves Rust Adj-RIB-In/Loc-RIB and FRR" || fail "Open v6 withdrawal incomplete"
 wait_open_absent "$FRR_V4 at OpenBGPD" "$FRR_V4"; rs_received_absent "$FRR_ADDR" ipv4 "$FRR_V4" && rs_loc_absent "$FRR_V4" && ok "FRR IPv4 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD" || fail "FRR v4 withdrawal incomplete"
 wait_open_absent "$FRR_V6 at OpenBGPD" "$FRR_V6"; rs_received_absent "$FRR_ADDR" ipv6 "$FRR_V6" && rs_loc_absent "$FRR_V6" && ok "FRR IPv6 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD" || fail "FRR v6 withdrawal incomplete"
 local oa fa; oa=$(rs_state "$OPENBGPD_ADDR"); fa=$(rs_state "$FRR_ADDR")
 open_established && jq -en --argjson b "$OPEN_STATE_BEFORE" --argjson a "$oa" '($b.flapCount//0|tonumber)==($a.flapCount//0|tonumber)' >/dev/null \
  && ok "OpenBGPD remains Established without a flap" || fail "Open continuity changed"
 frr_established && jq -en --argjson b "$FRR_STATE_BEFORE" --argjson a "$fa" '($b.flapCount//0|tonumber)==($a.flapCount//0|tonumber)' >/dev/null \
  && ok "FRR remains Established without a flap" || fail "FRR continuity changed"
}

main() {
 preflight; preflight_identities_and_configs; resolve_grpc_addr; start_capture
 start_m102_rustbgpd
 start_peers
 wait_for "OpenBGPD session" open_established; wait_for "FRR session" frr_established
 OPEN_STATE_BEFORE=$(rs_state "$OPENBGPD_ADDR"); FRR_STATE_BEFORE=$(rs_state "$FRR_ADDR")
 assert_sessions; inject_open
 wait_for "$OPEN_V4 local" open_has "$OPEN_V4"; wait_for "$OPEN_V6 local" open_has "$OPEN_V6"
 wait_for "$IMPORT_DENY local" open_has "$IMPORT_DENY"; wait_for "$EXPORT_DENY local" open_has "$EXPORT_DENY"
 wait_for "all OpenBGPD UPDATEs accounted" open_updates_accounted; wait_for "$EXPORT_DENY in Loc-RIB" rs_loc "$EXPORT_DENY"
 wait_import_explain_ready
 wait_for "$OPEN_V4 at FRR" frr_has ipv4 "$OPEN_V4"; wait_for "$OPEN_V6 at FRR" frr_has ipv6 "$OPEN_V6"
 wait_for "$FRR_V4 at OpenBGPD" open_route_matches "$FRR_V4" 4200000202 10.102.2.2
 wait_for "$FRR_V6 at OpenBGPD" open_route_matches "$FRR_V6" 4200000202 2001:db8:102:2::2
 assert_forward; assert_reverse; assert_policy; assert_inventory; stop_capture; assert_wire
 withdraw_open; withdraw_frr; assert_withdrawals
 # shellcheck disable=SC2154
 [ "$pass" -eq 32 ] && [ "$fail" -eq 0 ] || die "M102 ledger drifted: $pass/$fail"
 print_summary
}
case "${1:-}" in
 --self-test-oracle) self_test_oracle positive; exit 0;;
 --self-test-oracle-conflict) self_test_oracle conflict; exit 0;;
 --self-test-oracle-gap) self_test_oracle gap; exit 0;;
 --self-test-oracle-capability) self_test_oracle capability; exit 0;;
 --self-test-oracle-update) self_test_oracle update; exit 0;;
 --self-test-oracle-trailing) self_test_oracle trailing; exit 0;;
 --self-test-oracle-marker) self_test_oracle marker; exit 0;;
 --self-test-import-explain-readiness) self_test_import_explain_readiness; exit 0;;
 --self-test-openbgpd-json) self_test_openbgpd_json; exit 0;;
esac
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"
PAYLOADS="$(mktemp /tmp/m102.XXXXXX.tsv)"
trap on_exit EXIT INT TERM HUP
main "$@"
