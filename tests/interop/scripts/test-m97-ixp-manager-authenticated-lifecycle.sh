#!/usr/bin/env bash
# M97: pinned IXP Manager v7.4 authenticated lifecycle and MD5 FRR continuity.
# This tranche proves two packaged per-handle deployment identities.

set -euo pipefail
umask 077

RUNTIME_ROOT=/var/lib/rustbgpd
HOST_STATE=/var/lib/rustbgpd/ixp-manager-host

# This file is copied into the rustbgpd container as the activation helper.
if [ "${1:-}" = internal-activate ]; then
    [ "$#" -eq 3 ] && [ "$3" = barrier ] || exit 64
    handle=$2
    runtime=$RUNTIME_ROOT/$handle
    state=$runtime/activation
    pidfile=/tmp/m97-$handle.pid
    touch "/tmp/m97-activation-entered-$handle"
    sleep 4
    if [ -s "$pidfile" ] && pid=$(cat "$pidfile") && kill -0 "$pid" 2>/dev/null; then
        kill -HUP "$pid"
    else
        mkdir -p /var/lib/rustbgpd
        nohup /usr/local/bin/rustbgpd "$state/current/config.toml" \
            >/dev/null 2>&1 </dev/null &
        printf '%s\n' "$!" >"$pidfile"
    fi
    exit 0
fi

TOPO=m97-ixp-manager-lifecycle
RUST=clab-${TOPO}-rustbgpd
IXP=clab-${TOPO}-ixp-manager
MYSQL=clab-${TOPO}-mysql
FRR=clab-${TOPO}-frr
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TOPOLOGY=$ROOT/tests/interop/m97-ixp-manager-authenticated-lifecycle.clab.yml
ORIGIN=http://127.0.0.1:18080
HANDLE=b2-rs1-lan1-ipv4
HANDLE4=$HANDLE
HANDLE6=b2-rs1-lan1-ipv6
EXPECTED_COMMIT=300b7e0ba9adb0aaac975899e45fc8bcbc0ca37d
TARGET=$ROOT/target/x86_64-unknown-linux-musl/debug/rs-config-render
BIN=/usr/local/bin/rs-config-render
ACT=/usr/local/bin/m97-activate
KEY_FILE=/var/lib/m97-api-key
WRONG_KEY_FILE=/var/lib/m97-wrong-api-key
PEER4=10.1.0.36
PEER6=2001:db8:1::10
PREFIX4=31.135.128.0/19
PREFIX6=2001:678:20::/48
MD5=mcWsqMdzGwTKt67g
MD56=N7rX2SdfbRsyBLTm
WORK=$(mktemp -d)
LIFECYCLE_PID=

cleanup() {
    if [ -n "$LIFECYCLE_PID" ]; then
        kill "$LIFECYCLE_PID" >/dev/null 2>&1 || true
    fi
    containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

fail() { printf 'M97 FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'M97 PASS: %s\n' "$*"; }

for container in "$RUST" "$IXP" "$MYSQL" "$FRR"; do
    docker inspect "$container" >/dev/null 2>&1 || fail "$container is not running"
done

for _ in $(seq 1 90); do
    if docker exec "$MYSQL" mysqladmin ping --host 127.0.0.1 --silent \
        >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$MYSQL" mysqladmin ping --host 127.0.0.1 --silent >/dev/null \
    || fail "MySQL did not become ready"

manifest=$ROOT/tests/compat/ixp-manager-birdseye/contract.json
commit=$(jq -r .ixp_manager_commit "$manifest")
[ "$commit" = "$EXPECTED_COMMIT" ] || fail "pinned IXP Manager commit drifted"
git clone --quiet --filter=blob:none --no-checkout \
    https://github.com/inex/IXP-Manager.git "$WORK/ixp-manager"
git -C "$WORK/ixp-manager" fetch --quiet --depth=1 origin "$commit"
git -C "$WORK/ixp-manager" checkout --quiet --detach FETCH_HEAD
[ "$(git -C "$WORK/ixp-manager" rev-parse HEAD)" = "$EXPECTED_COMMIT" ] \
    || fail "IXP Manager checkout is not v7.4.0 commit 300b7e0"

docker exec "$IXP" mkdir -p /opt/ixp-manager
docker cp "$WORK/ixp-manager/." "$IXP:/opt/ixp-manager"
if ! docker exec "$IXP" composer install --working-dir=/opt/ixp-manager \
    --no-dev --no-interaction --no-progress --prefer-dist --no-scripts \
    >"$WORK/composer.output" 2>&1; then
    cat "$WORK/composer.output" >&2
    fail "pinned IXP Manager Composer install failed"
fi
docker exec "$IXP" cp /opt/ixp-manager/.env.ci /opt/ixp-manager/.env
skin=/opt/ixp-manager/resources/skins/rustbgpd-lifecycle/api/v4/router/server/rustbgpd
docker exec "$IXP" mkdir -p "$skin"
docker cp \
    "$ROOT/integrations/ixp-manager/gpl-2.0-only/api/v4/router/server/rustbgpd/json.foil.php" \
    "$IXP:$skin/json.foil.php"

docker exec -i "$MYSQL" mysql --user root ixp_ci \
    <"$WORK/ixp-manager/data/ci/ci_test_db.sql"
docker exec -i "$MYSQL" mysql --user root ixp_ci <<'SQL'
UPDATE routers SET template='api/v4/router/server/rustbgpd/json',
  last_update_started=NULL, last_updated=NULL, pause_updates=0, quarantine=0
  WHERE handle='b2-rs1-lan1-ipv4';
UPDATE routers SET template='api/v4/router/server/rustbgpd/json',
  last_update_started=NULL, last_updated=NULL, pause_updates=0, quarantine=0
  WHERE handle='b2-rs1-lan1-ipv6';
UPDATE route_server_filters_prod SET enabled=0;
UPDATE vlaninterface SET rsclient=0 WHERE id<>3;
UPDATE vlaninterface SET rsclient=1, ipv4enabled=0, ipv6enabled=1 WHERE id=1;
UPDATE vlaninterface SET ipv6enabled=0 WHERE id=3;
DELETE FROM irrdb_asn WHERE customer_id=3 AND protocol=4 AND asn<>42;
DELETE FROM irrdb_prefix
  WHERE customer_id=3 AND protocol=4 AND prefix<>'31.135.128.0/19';
DELETE FROM irrdb_asn WHERE customer_id=2 AND protocol=6 AND asn<>1213;
DELETE FROM irrdb_prefix
  WHERE customer_id=2 AND protocol=6 AND prefix<>'2001:678:20::/48';
SQL

docker exec "$RUST" sh -ec \
    "umask 077; od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >'$KEY_FILE';
     printf '%s' definitely-wrong-m97-key >'$WRONG_KEY_FILE';
     chmod 600 '$KEY_FILE' '$WRONG_KEY_FILE'"
{
    printf "UPDATE api_keys SET api_key='"
    docker exec "$RUST" cat "$KEY_FILE"
    printf "', expires='2099-12-31 23:59:59' WHERE id=1;\n"
} | docker exec -i "$MYSQL" mysql --user root ixp_ci
docker exec "$RUST" cat "$KEY_FILE" | docker exec -i "$IXP" sh -ec \
    'umask 077; cat >/tmp/m97-api-key; chmod 600 /tmp/m97-api-key'

docker exec -d "$IXP" sh -c \
    'cd /opt/ixp-manager && exec php -d display_errors=0 -d log_errors=1 \
      -S 127.0.0.1:18080 -t public public/index.php \
      >/tmp/m97-server.log 2>&1'
for _ in $(seq 1 60); do
    if docker exec "$IXP" php -r \
        '$s=@fsockopen("127.0.0.1",18080); exit($s ? 0 : 1);' \
        >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$IXP" php -r \
    '$s=@fsockopen("127.0.0.1",18080); exit($s ? 0 : 1);' \
    || { docker exec "$IXP" cat /tmp/m97-server.log >&2; fail "IXP Manager API did not start"; }

api() {
    docker exec "$IXP" php -d display_errors=0 -r '
        $method = $argv[1]; $url = $argv[2]; $keyMode = $argv[3]; $output = $argv[4];
        $header = "";
        if ($keyMode === "valid") {
            $key = trim(file_get_contents("/tmp/m97-api-key"));
            $header = "X-IXP-Manager-API-Key: " . $key . "\r\n";
        } elseif ($keyMode === "wrong") {
            $header = "X-IXP-Manager-API-Key: definitely-wrong-m97-key\r\n";
        }
        $context = stream_context_create(["http" => [
            "method" => $method, "header" => $header, "ignore_errors" => true,
        ]]);
        $body = @file_get_contents($url, false, $context);
        $line = $http_response_header[0] ?? "";
        if (!preg_match("/ ([0-9]{3}) /", $line, $match)) { exit(70); }
        if ($output === "body") {
            if ($match[1] !== "200" || $body === false) { exit(71); }
            fwrite(STDOUT, $body);
        } else { fwrite(STDOUT, $match[1]); }
    ' "$1" "$ORIGIN/admin/api/v4/router/$2/$3" "$4" "$5"
}

[ "$(api POST get-update-lock "$HANDLE4" none status)" = 401 ] \
    || fail "real IXP Manager accepted a request without an API key"
[ "$(api POST get-update-lock "$HANDLE4" wrong status)" = 401 ] \
    || fail "real IXP Manager accepted a wrong API key"
api GET gen-config "$HANDLE4" valid body >"$WORK/foil.json"
# This lab intentionally seeds the legacy single-client PCH document. Project
# that exact oracle into the additive v2 envelope instead of comparing against
# the shared multi-client UI-filter fixture.
jq -S . "$WORK/foil.json" >"$WORK/foil-actual.json" \
    || fail "real v7.4 Foil API response was not valid JSON"
jq -S '
    .schema = "rustbgpd.ixp-manager.router-config/v2"
    | .ui_filters = []
    | .complete.ui_filter_count = 0
' "$ROOT/tools/rs-config-render/tests/fixtures/ixp-manager-v1-supported.json" \
    >"$WORK/foil-expected.json" \
    || fail "pinned legacy PCH oracle could not be projected to v2"
if ! cmp -s "$WORK/foil-actual.json" "$WORK/foil-expected.json"; then
    jq -nr --slurpfile actual "$WORK/foil-actual.json" \
        --slurpfile expected "$WORK/foil-expected.json" '
        [($actual[0] | paths(scalars)), ($expected[0] | paths(scalars))]
        | unique[] as $path
        | select(($actual[0] | getpath($path)) != ($expected[0] | getpath($path)))
        | $path | map(tostring) | join(".")
    ' >&2 || true
    fail "real v7.4 Foil API capture drifted from the exact PCH v2 projection"
fi
ok "pinned v7.4 API authentication and exact PCH v2 projection"

cargo +1.98.0 build --locked --target x86_64-unknown-linux-musl \
    -p rs-config-render
docker cp "$TARGET" "$RUST:$BIN"
docker cp "$0" "$RUST:$ACT"
docker exec "$RUST" sh -ec \
    "umask 077; chmod 700 '$BIN' '$ACT'; rm -rf '$RUNTIME_ROOT' \
       /var/lib/m97-candidate-* /tmp/m97-activation-entered-* /tmp/m97-*.pid;
     mkdir -m 700 -p '$HOST_STATE' '$RUNTIME_ROOT/$HANDLE4/activation' \
       '$RUNTIME_ROOT/$HANDLE6/activation';
     chmod 700 '$RUNTIME_ROOT' '$RUNTIME_ROOT/$HANDLE4' \
       '$RUNTIME_ROOT/$HANDLE6'"

lifecycle() {
    local handle=$1 candidate=$2 key=$3
    shift 3
    local runtime=$RUNTIME_ROOT/$handle
    docker exec "$RUST" "$BIN" ixp-manager-lifecycle run \
        --ixp-origin "$ORIGIN" --allow-http-loopback \
        --router-handle "$handle" --api-key-file "$key" \
        --candidate-dir "$candidate" --runtime-state-dir "$runtime" \
        --state-dir "$runtime/activation" --host-state-dir "$HOST_STATE" \
        --check-with /usr/local/bin/rustbgpd \
        --max-prefix-restart-seconds 300 \
        --rbgp /usr/local/bin/rbgp --rbgp-addr "unix://$runtime/grpc.sock" \
        --settle-seconds 20 --request-timeout-seconds 30 \
        --activation-command "$ACT" --activation-arg internal-activate \
        --activation-arg "$handle" --activation-arg barrier "$@"
}

set +e
lifecycle "$HANDLE4" /var/lib/m97-candidate-wrong "$WRONG_KEY_FILE" \
    --initial >"$WORK/wrong.output" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || fail "wrong-key lifecycle exited $status, expected 2"
docker exec "$RUST" test ! -e "$RUNTIME_ROOT/$HANDLE4/activation/ixp-manager-lifecycle.json" \
    || fail "wrong-key refusal retained a lifecycle journal"
[ "$(docker exec "$MYSQL" mysql --batch --skip-column-names --user root ixp_ci \
    -e "SELECT IF(last_update_started IS NULL AND last_updated IS NULL,1,0) FROM routers WHERE handle='$HANDLE4'")" = 1 ] \
    || fail "wrong-key request changed router timestamps"
ok "wrong API key was definitely refused without acquiring a lock"

sql() {
    docker exec "$MYSQL" mysql --batch --skip-column-names --user root ixp_ci \
        -e "$1"
}
neighbor() {
    docker exec "$RUST" /usr/local/bin/rbgp \
        --addr "unix://$RUNTIME_ROOT/$1/grpc.sock" --json neighbor "$2"
}
has_route() {
    docker exec "$RUST" /usr/local/bin/rbgp \
        --addr "unix://$RUNTIME_ROOT/$1/grpc.sock" --json \
        rib received "$2" 2>/dev/null \
        | jq -e --arg prefix "$3" \
            '[.[] | select(.prefix == $prefix)] | length == 1' >/dev/null
}
wait_for() {
    local label=$1
    shift
    for _ in $(seq 1 40); do
        if "$@"; then ok "$label"; return; fi
        sleep 1
    done
    fail "$label did not converge"
}
session_ready() {
    neighbor "$1" "$2" 2>/dev/null | jq -e '.state == "Established"' >/dev/null
}

activate_initial() {
    local handle=$1 other=$2 peer=$3 prefix=$4 label=$5 other_mode=$6
    local candidate=/var/lib/m97-candidate-$label-initial
    local marker=/tmp/m97-activation-entered-$handle
    docker exec "$RUST" rm -f "$marker" "/tmp/m97-activation-entered-$other"
    lifecycle "$handle" "$candidate" "$KEY_FILE" --initial \
        >"$WORK/$label-initial.output" 2>&1 &
    LIFECYCLE_PID=$!
    wait_for "$label activation barrier entered with upstream lock held" \
        docker exec "$RUST" test -e "$marker"
    [ "$(sql "SELECT IF(last_update_started IS NOT NULL AND last_updated IS NULL,1,0) FROM routers WHERE handle='$handle'")" = 1 ] \
        || fail "$label database lock was not visible"
    [ "$(api POST get-update-lock "$handle" valid status)" = 423 ] \
        || fail "$label competing authenticated update was not HTTP 423"
    docker exec "$RUST" cat "$HOST_STATE/ixp-manager-host-fence.json" \
        >"$WORK/$label-fence.json"
    set +e
    wait "$LIFECYCLE_PID"
    status=$?
    set -e
    LIFECYCLE_PID=
    [ "$status" -eq 0 ] || { cat "$WORK/$label-initial.output" >&2; fail "$label lifecycle exited $status"; }
    [ "$(cat "$WORK/$label-initial.output")" = 'IXP Manager lifecycle activated' ] \
        || fail "$label lifecycle output changed"
    [ "$(sql "SELECT IF(last_update_started IS NOT NULL AND last_updated>=last_update_started,1,0) FROM routers WHERE handle='$handle'")" = 1 ] \
        || fail "$label updated callback was not visible"
    docker exec "$RUST" test ! -e "$RUNTIME_ROOT/$handle/activation/ixp-manager-lifecycle.json" \
        || fail "$label successful callback retained a journal"
    jq -e --arg h "$handle" --arg r "$RUNTIME_ROOT/$handle" --arg s "$RUNTIME_ROOT/$handle/activation" --arg hs "$HOST_STATE" --arg a "unix://$RUNTIME_ROOT/$handle/grpc.sock" \
        --slurpfile rr <(docker exec "$RUST" cat "$candidate/render-receipt.json") --slurpfile ar <(docker exec "$RUST" cat "$RUNTIME_ROOT/$handle/activation/activation-receipt.json") '
        . == {router_handle:$h,runtime_state_dir:$r,activation_state_dir:$s,host_state_dir:$hs,rbgp_addr:$a}
        and $rr[0].input.router_handle == $h and $rr[0].host == {router_handle:$h,runtime_state_dir:$r}
        and $ar[0].host == .' "$WORK/$label-fence.json" >/dev/null \
        || fail "$label fence/render/activation receipts do not match the exact handle binding"
    docker exec "$RUST" test ! -e "$HOST_STATE/ixp-manager-host-fence.json" \
        || fail "$label terminal callback retained its host fence"
    docker cp "$WORK/$label-fence.json" "$RUST:/tmp/$label-fence.json" >/dev/null
    docker exec "$RUST" sh -ec \
        "install -m 600 '/tmp/$label-fence.json' '$HOST_STATE/ixp-manager-host-fence.json'; sync -f '$HOST_STATE'"
    other_before=$(sql "SELECT CONCAT(IFNULL(last_update_started,'NULL'),'|',IFNULL(last_updated,'NULL')) FROM routers WHERE handle='$other'")
    extra=()
    [ "$other_mode" = initial ] && extra=(--initial)
    set +e
    lifecycle "$other" "/var/lib/m97-candidate-$label-host-refused" \
        "$KEY_FILE" "${extra[@]}" >"$WORK/$label-host-refused.output" 2>&1
    host_status=$?
    set -e
    [ "$host_status" -eq 5 ] || fail "$other escaped the durable shared fence with exit $host_status"
    grep -qxF 'rs-config-render: IXP Manager lifecycle: manual recovery required; upstream lock retained' \
        "$WORK/$label-host-refused.output" \
        || fail "$other shared-fence recovery diagnostic changed"
    [ "$other_before" = "$(sql "SELECT CONCAT(IFNULL(last_update_started,'NULL'),'|',IFNULL(last_updated,'NULL')) FROM routers WHERE handle='$other'")" ] \
        || fail "$other reached IXP Manager behind the shared host fence"
    docker exec "$RUST" test ! -e "/tmp/m97-activation-entered-$other" \
        || fail "$other activated behind the shared host fence"
    docker exec "$RUST" test ! -e "$RUNTIME_ROOT/$other/activation/ixp-manager-lifecycle.json" \
        || fail "$other wrote a lifecycle journal behind the shared fence"
    docker exec "$RUST" test ! -e "/var/lib/m97-candidate-$label-host-refused" \
        || fail "$other rendered a candidate behind the shared fence"
    docker exec "$RUST" sh -ec \
        "rm '$HOST_STATE/ixp-manager-host-fence.json'; sync -f '$HOST_STATE'"
    wait_for "$label MD5 session Established" session_ready "$handle" "$peer"
    wait_for "$label pinned prefix accepted" has_route "$handle" "$peer" "$prefix"
}

activate_initial "$HANDLE4" "$HANDLE6" "$PEER4" "$PREFIX4" ipv4 initial
activate_initial "$HANDLE6" "$HANDLE4" "$PEER6" "$PREFIX6" ipv6 existing
ok "both sequential lifecycles held the shared fence and paired HTTP 423 locks"

STATE4=$RUNTIME_ROOT/$HANDLE4/activation
STATE6=$RUNTIME_ROOT/$HANDLE6/activation
prior_link4=$(docker exec "$RUST" readlink "$STATE4/current")
prior_link6=$(docker exec "$RUST" readlink "$STATE6/current")
docker exec "$RUST" sh -c \
    "find -L '$STATE4/current' '$STATE6/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/prior-files"
docker exec "$RUST" cat "$STATE4/activation-receipt.json" \
    >"$WORK/activation-receipt-ipv4.json"
docker exec "$RUST" cat "$STATE6/activation-receipt.json" \
    >"$WORK/activation-receipt-ipv6.json"
receipt_before=$(docker exec "$RUST" sha256sum "$STATE4/activation-receipt.json" "$STATE6/activation-receipt.json")
pid_before=$(docker exec "$RUST" cat "/tmp/m97-$HANDLE4.pid" "/tmp/m97-$HANDLE6.pid")
session4_before=$(neighbor "$HANDLE4" "$PEER4")
session6_before=$(neighbor "$HANDLE6" "$PEER6")
last_updated=$(sql "SELECT DATE_FORMAT(last_updated,'%Y-%m-%d %H:%i:%s') FROM routers WHERE handle='$HANDLE4'")
[ -n "$last_updated" ] || fail "updated timestamp was empty"
# Foil exports this router mode directly, and the v2 renderer refuses it before
# activation independently of the supported UI-filter action set.
sql "UPDATE routers SET quarantine=1 WHERE handle='$HANDLE4'" >/dev/null
[ "$(sql "SELECT IF(quarantine=1,1,0) FROM routers WHERE handle='$HANDLE4'")" = 1 ] \
    || fail "IPv4 quarantine refusal fixture was not installed"
docker exec "$RUST" rm -f "/tmp/m97-activation-entered-$HANDLE4"
set +e
lifecycle "$HANDLE4" /var/lib/m97-candidate-ipv4-refused "$KEY_FILE" \
    >"$WORK/refused.output" 2>&1
status=$?
set -e
sql "UPDATE routers SET quarantine=0 WHERE handle='$HANDLE4'" >/dev/null
[ "$(sql "SELECT IF(quarantine=0,1,0) FROM routers WHERE handle='$HANDLE4'")" = 1 ] \
    || fail "IPv4 quarantine refusal fixture was not restored"
[ "$status" -eq 2 ] || { cat "$WORK/refused.output" >&2; fail "refusal exited $status"; }
grep -qxF 'rs-config-render: IXP Manager lifecycle: IXP Manager candidate was refused' \
    "$WORK/refused.output" \
    || fail "quarantine refusal diagnostic changed"
docker exec "$RUST" test ! -e "/tmp/m97-activation-entered-$HANDLE4" \
    || fail "pre-activation refusal invoked the activation command"
if [ "$(docker exec "$RUST" readlink "$STATE4/current")" != "$prior_link4" ] \
    || [ "$(docker exec "$RUST" readlink "$STATE6/current")" != "$prior_link6" ]; then
    fail "one-handle refusal moved either current link"
fi
docker exec "$RUST" sh -c \
    "find -L '$STATE4/current' '$STATE6/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/after-refusal-files"
cmp -s "$WORK/prior-files" "$WORK/after-refusal-files" \
    || fail "pre-activation refusal changed prior runtime bytes"
[ "$receipt_before" = "$(docker exec "$RUST" sha256sum "$STATE4/activation-receipt.json" "$STATE6/activation-receipt.json")" ] \
    || fail "one-handle refusal rewrote either activation receipt"
[ "$(docker exec "$RUST" cat "/tmp/m97-$HANDLE4.pid" "/tmp/m97-$HANDLE6.pid")" = "$pid_before" ] \
    || fail "either rustbgpd PID changed across one-handle refusal"
release_pair=$(sql "SELECT CONCAT(DATE_FORMAT(last_update_started,'%Y-%m-%d %H:%i:%s'),'|',DATE_FORMAT(last_updated,'%Y-%m-%d %H:%i:%s')) FROM routers WHERE handle='$HANDLE4'")
[ "$release_pair" = "$last_updated|$last_updated" ] \
    || fail "release callback did not restore the prior database timestamp"
docker exec "$RUST" test ! -e "$STATE4/ixp-manager-lifecycle.json" \
    || fail "delivered release callback retained a lifecycle journal"
session4_after=$(neighbor "$HANDLE4" "$PEER4")
session6_after=$(neighbor "$HANDLE6" "$PEER6")
session_stable() {
    local before=$1 after=$2 label=$3
    jq -n --argjson before "$before" --argjson after "$after" '
        $before.state == "Established" and $after.state == "Established"
        and (($before.flap_count // 0) == ($after.flap_count // 0))
        and (($after.uptime_seconds // 0) >= ($before.uptime_seconds // 0))' \
        >/dev/null || fail "$label MD5 session flapped across refusal"
}
session_stable "$session4_before" "$session4_after" IPv4
session_stable "$session6_before" "$session6_after" IPv6
wait_for "IPv4 route preserved after release" has_route "$HANDLE4" "$PEER4" "$PREFIX4"
wait_for "IPv6 route preserved during IPv4 refusal" has_route "$HANDLE6" "$PEER6" "$PREFIX6"
ok "one-handle failure released its DB lock and preserved both runtimes/sessions"

docker exec "$RUST" bash -ec \
    "pid4=\$(cat '/tmp/m97-$HANDLE4.pid'); pid6=\$(cat '/tmp/m97-$HANDLE6.pid');
     test \"\$pid4\" != \"\$pid6\"; kill -0 \"\$pid4\"; kill -0 \"\$pid6\";
     test -S '$RUNTIME_ROOT/$HANDLE4/grpc.sock';
     test -S '$RUNTIME_ROOT/$HANDLE6/grpc.sock';
     test ! -e '$HOST_STATE/ixp-manager-host-fence.json';
     test \"\$(stat -c %a '$HOST_STATE')\" = 700;
     test \"\$(stat -c %a '$HOST_STATE/ixp-manager-host.lock')\" = 600;
     test \"\$(stat -c %a '$KEY_FILE')\" = 600;
     for state in '$STATE4' '$STATE6'; do
       test \"\$(stat -c %a \"\$state\")\" = 700;
       test \"\$(stat -c %a \"\$state/ixp-manager-lifecycle.lock\")\" = 600;
       test \"\$(stat -c %a \"\$state/activation.lock\")\" = 600;
       test \"\$(stat -c %a \"\$state/activation-receipt.json\")\" = 600;
       test -L \"\$state/current\";
       ! find \"\$state/generations\" -type d ! -perm 700 -print -quit | grep -q .;
       ! find \"\$state/generations\" -type f ! -perm 600 -print -quit | grep -q .;
     done"
listeners=$(docker exec "$RUST" ss -Hlnpt 'sport = :179')
[ "$(printf '%s\n' "$listeners" | wc -l)" -eq 2 ] \
    || fail "expected exactly two TCP/179 listeners"
printf '%s\n' "$listeners" | grep -F "192.0.2.18:179" | grep -F "pid=$(docker exec "$RUST" cat "/tmp/m97-$HANDLE4.pid")" >/dev/null \
    || fail "IPv4 listener is not owned by its handle PID"
printf '%s\n' "$listeners" | grep -F "[2001:db8::8]:179" | grep -F "pid=$(docker exec "$RUST" cat "/tmp/m97-$HANDLE6.pid")" >/dev/null \
    || fail "IPv6 listener is not owned by its handle PID"
for handle in "$HANDLE4" "$HANDLE6"; do
    config=$RUNTIME_ROOT/$handle/activation/current/config.toml
    docker exec "$RUST" grep -qxF "runtime_state_dir = \"$RUNTIME_ROOT/$handle\"" "$config" \
        || fail "$handle config is not bound to its packaged runtime path"
    docker exec "$RUST" grep -qxF "path = \"$RUNTIME_ROOT/$handle/grpc.sock\"" "$config" \
        || fail "$handle config is not bound to its exact UDS"
done
if docker exec "$RUST" cat "$KEY_FILE" \
    | grep -RFl -f - "$WORK" >/dev/null 2>&1; then
    fail "API key escaped into retained host artifacts"
fi
docker exec "$RUST" sh -ec \
    "! grep -RFl -f '$KEY_FILE' '$RUNTIME_ROOT' /var/lib/m97-candidate-* \
       >/dev/null 2>&1"
docker exec "$IXP" sh -ec \
    '! grep -F -f /tmp/m97-api-key /tmp/m97-server.log >/dev/null 2>&1'
if printf '%s\n%s\n' "$MD5" "$MD56" | grep -Fl -f - \
    "$WORK/wrong.output" "$WORK/ipv4-initial.output" \
    "$WORK/ipv4-host-refused.output" "$WORK/ipv6-initial.output" \
    "$WORK/ipv6-host-refused.output" "$WORK/refused.output" \
    "$WORK/activation-receipt-ipv4.json" \
    "$WORK/activation-receipt-ipv6.json" >/dev/null; then
    fail "MD5 secret escaped into lifecycle output or receipt"
fi
docker exec "$FRR" vtysh -c 'show bgp neighbors 192.0.2.18 json' \
    | jq -e '.["192.0.2.18"].bgpState == "Established"' >/dev/null \
    || fail "FRR does not report the authenticated session Established"
docker exec "$FRR" vtysh -c 'show bgp neighbors 2001:db8::8 json' \
    | jq -e '.["2001:db8::8"].bgpState == "Established"' >/dev/null \
    || fail "FRR does not report the IPv6 authenticated session Established"
ok "M97 two-handle listeners, private state, cleanup, and redaction complete"
