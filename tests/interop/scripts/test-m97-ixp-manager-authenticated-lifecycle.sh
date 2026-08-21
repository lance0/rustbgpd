#!/usr/bin/env bash
# M97: pinned IXP Manager v7.4 authenticated lifecycle and MD5 FRR continuity.

set -euo pipefail
umask 077

STATE=/var/lib/m97-lifecycle

# This file is copied into the rustbgpd container as the activation helper.
if [ "${1:-}" = internal-activate ]; then
    [ "$#" -eq 2 ] && [ "$2" = barrier ] || exit 64
    touch /tmp/m97-activation-entered
    sleep 4
    if pid=$(pidof -s rustbgpd 2>/dev/null); then
        kill -HUP "$pid"
    else
        mkdir -p /var/lib/rustbgpd
        nohup /usr/local/bin/rustbgpd "$STATE/current/config.toml" \
            >/dev/null 2>&1 </dev/null &
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
EXPECTED_COMMIT=300b7e0ba9adb0aaac975899e45fc8bcbc0ca37d
TARGET=$ROOT/target/x86_64-unknown-linux-musl/debug/rs-config-render
BIN=/usr/local/bin/rs-config-render
ACT=/usr/local/bin/m97-activate
KEY_FILE=/var/lib/m97-api-key
WRONG_KEY_FILE=/var/lib/m97-wrong-api-key
ADDR=unix:///var/lib/rustbgpd/grpc.sock
MD5=mcWsqMdzGwTKt67g
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
  last_update_started=NULL, last_updated=NULL, pause_updates=0
  WHERE handle='b2-rs1-lan1-ipv4';
UPDATE route_server_filters_prod SET enabled=0;
UPDATE vlaninterface SET rsclient=0 WHERE id<>3;
DELETE FROM irrdb_asn WHERE customer_id=3 AND protocol=4 AND asn<>42;
DELETE FROM irrdb_prefix
  WHERE customer_id=3 AND protocol=4 AND prefix<>'31.135.128.0/19';
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
    ' "$1" "$ORIGIN/admin/api/v4/router/$2/$HANDLE" "$3" "$4"
}

[ "$(api POST get-update-lock none status)" = 401 ] \
    || fail "real IXP Manager accepted a request without an API key"
[ "$(api POST get-update-lock wrong status)" = 401 ] \
    || fail "real IXP Manager accepted a wrong API key"
api GET gen-config valid body >"$WORK/foil.json"
cmp -s "$WORK/foil.json" \
    "$ROOT/tests/compat/ixp-manager-birdseye/fixtures/ixp-manager-v7.4-rustbgpd.json" \
    || fail "real v7.4 Foil API capture drifted from the pinned oracle"
ok "pinned v7.4 API authentication and exact Foil capture"

cargo +1.98.0 build --locked --target x86_64-unknown-linux-musl \
    -p rs-config-render
docker cp "$TARGET" "$RUST:$BIN"
docker cp "$0" "$RUST:$ACT"
docker exec "$RUST" sh -ec \
    "chmod 700 '$BIN' '$ACT'; rm -rf '$STATE' /var/lib/m97-wrong-state \
       /var/lib/m97-initial-candidate /var/lib/m97-refused-candidate;
     mkdir -m 700 '$STATE' /var/lib/m97-wrong-state"

lifecycle() {
    local candidate=$1 state=$2 key=$3
    shift 3
    docker exec "$RUST" "$BIN" ixp-manager-lifecycle run \
        --ixp-origin "$ORIGIN" --allow-http-loopback \
        --router-handle "$HANDLE" --api-key-file "$key" \
        --candidate-dir "$candidate" --state-dir "$state" \
        --check-with /usr/local/bin/rustbgpd \
        --max-prefix-restart-seconds 300 \
        --rbgp /usr/local/bin/rbgp --rbgp-addr "$ADDR" \
        --settle-seconds 20 --request-timeout-seconds 30 \
        --activation-command "$ACT" --activation-arg internal-activate \
        --activation-arg barrier "$@"
}

set +e
lifecycle /var/lib/m97-wrong-candidate /var/lib/m97-wrong-state \
    "$WRONG_KEY_FILE" --initial >"$WORK/wrong.output" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || fail "wrong-key lifecycle exited $status, expected 2"
docker exec "$RUST" test ! -e /var/lib/m97-wrong-state/ixp-manager-lifecycle.json \
    || fail "wrong-key refusal retained a lifecycle journal"
[ "$(docker exec "$MYSQL" mysql --batch --skip-column-names --user root ixp_ci \
    -e "SELECT IF(last_update_started IS NULL AND last_updated IS NULL,1,0) FROM routers WHERE handle='$HANDLE'")" = 1 ] \
    || fail "wrong-key request changed router timestamps"
ok "wrong API key was definitely refused without acquiring a lock"

sql() {
    docker exec "$MYSQL" mysql --batch --skip-column-names --user root ixp_ci \
        -e "$1"
}
neighbor() {
    docker exec "$RUST" /usr/local/bin/rbgp --addr "$ADDR" --json \
        neighbor 10.1.0.36
}
has_route() {
    docker exec "$RUST" /usr/local/bin/rbgp --addr "$ADDR" --json \
        rib received 10.1.0.36 2>/dev/null \
        | jq -e --arg prefix "$1" \
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
    neighbor 2>/dev/null | jq -e '.state == "Established"' >/dev/null
}

docker exec "$RUST" rm -f /tmp/m97-activation-entered
lifecycle /var/lib/m97-initial-candidate "$STATE" "$KEY_FILE" --initial \
    >"$WORK/initial.output" 2>&1 &
LIFECYCLE_PID=$!
wait_for "activation barrier entered while the upstream lock is held" \
    docker exec "$RUST" test -e /tmp/m97-activation-entered
[ "$(sql "SELECT IF(last_update_started IS NOT NULL AND last_updated IS NULL,1,0) FROM routers WHERE handle='$HANDLE'")" = 1 ] \
    || fail "database did not expose the acquired update lock"
[ "$(api POST get-update-lock valid status)" = 423 ] \
    || fail "a competing authenticated update was not refused with HTTP 423"
set +e
wait "$LIFECYCLE_PID"
status=$?
set -e
LIFECYCLE_PID=
[ "$status" -eq 0 ] || { cat "$WORK/initial.output" >&2; fail "initial lifecycle exited $status"; }
[ "$(cat "$WORK/initial.output")" = 'IXP Manager lifecycle activated' ] \
    || fail "initial lifecycle output changed"
[ "$(sql "SELECT IF(last_update_started IS NOT NULL AND last_updated>=last_update_started,1,0) FROM routers WHERE handle='$HANDLE'")" = 1 ] \
    || fail "updated callback was not visible in the real database"
docker exec "$RUST" test ! -e "$STATE/ixp-manager-lifecycle.json" \
    || fail "successful updated callback retained a lifecycle journal"
docker exec "$RUST" test -s /var/lib/m97-initial-candidate/render-receipt.json \
    || fail "real Foil capture was not rendered and checked"
wait_for "MD5 FRR session Established" session_ready
wait_for "pinned IXP prefix accepted" has_route 31.135.128.0/19
ok "real lock transition, competing 423, activation, and updated callback"

prior_link=$(docker exec "$RUST" readlink "$STATE/current")
docker exec "$RUST" sh -c \
    "find -L '$STATE/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/prior-files"
docker exec "$RUST" cat "$STATE/activation-receipt.json" \
    >"$WORK/activation-receipt.json"
receipt_before=$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")
pid_before=$(docker exec "$RUST" pidof -s rustbgpd)
session_before=$(neighbor)
last_updated=$(sql "SELECT DATE_FORMAT(last_updated,'%Y-%m-%d %H:%i:%s') FROM routers WHERE handle='$HANDLE'")
[ -n "$last_updated" ] || fail "updated timestamp was empty"
sql "UPDATE route_server_filters_prod SET customer_id=3, enabled=1 WHERE id=31" \
    >/dev/null
docker exec "$RUST" rm -f /tmp/m97-activation-entered
set +e
lifecycle /var/lib/m97-refused-candidate "$STATE" "$KEY_FILE" \
    >"$WORK/refused.output" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { cat "$WORK/refused.output" >&2; fail "refusal exited $status"; }
docker exec "$RUST" test ! -e /tmp/m97-activation-entered \
    || fail "pre-activation refusal invoked the activation command"
[ "$(docker exec "$RUST" readlink "$STATE/current")" = "$prior_link" ] \
    || fail "pre-activation refusal moved current"
docker exec "$RUST" sh -c \
    "find -L '$STATE/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/after-refusal-files"
cmp -s "$WORK/prior-files" "$WORK/after-refusal-files" \
    || fail "pre-activation refusal changed prior runtime bytes"
[ "$receipt_before" = "$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")" ] \
    || fail "pre-activation refusal rewrote the activation receipt"
[ "$(docker exec "$RUST" pidof -s rustbgpd)" = "$pid_before" ] \
    || fail "rustbgpd PID changed across pre-activation refusal"
release_pair=$(sql "SELECT CONCAT(DATE_FORMAT(last_update_started,'%Y-%m-%d %H:%i:%s'),'|',DATE_FORMAT(last_updated,'%Y-%m-%d %H:%i:%s')) FROM routers WHERE handle='$HANDLE'")
[ "$release_pair" = "$last_updated|$last_updated" ] \
    || fail "release callback did not restore the prior database timestamp"
docker exec "$RUST" test ! -e "$STATE/ixp-manager-lifecycle.json" \
    || fail "delivered release callback retained a lifecycle journal"
session_after=$(neighbor)
jq -n --argjson before "$session_before" --argjson after "$session_after" '
    $before.state == "Established" and $after.state == "Established"
    and (($before.flap_count // 0) == ($after.flap_count // 0))
    and (($after.uptime_seconds // 0) >= ($before.uptime_seconds // 0))' \
    >/dev/null || fail "MD5 session flapped across pre-activation refusal"
wait_for "route preserved after release" has_route 31.135.128.0/19
ok "pre-activation refusal released the DB lock and preserved prior runtime/session"

docker exec "$RUST" bash -ec \
    "test \"\$(stat -c %a '$STATE')\" = 700;
     test \"\$(stat -c %a '$STATE/ixp-manager-lifecycle.lock')\" = 600;
     test \"\$(stat -c %a '$STATE/activation.lock')\" = 600;
     test \"\$(stat -c %a '$STATE/activation-receipt.json')\" = 600;
     test \"\$(stat -c %a '$KEY_FILE')\" = 600;
     test -L '$STATE/current';
     ! find '$STATE/generations' -type d ! -perm 700 -print -quit | grep -q .;
     ! find '$STATE/generations' -type f ! -perm 600 -print -quit | grep -q ."
if docker exec "$RUST" cat "$KEY_FILE" \
    | grep -RFl -f - "$WORK" >/dev/null 2>&1; then
    fail "API key escaped into retained host artifacts"
fi
docker exec "$RUST" sh -ec \
    "! grep -RFl -f '$KEY_FILE' '$STATE' /var/lib/m97-initial-candidate \
       /var/lib/m97-refused-candidate >/dev/null 2>&1"
docker exec "$IXP" sh -ec \
    '! grep -F -f /tmp/m97-api-key /tmp/m97-server.log >/dev/null 2>&1'
if printf '%s' "$MD5" | grep -Fl -f - "$WORK/initial.output" \
    "$WORK/refused.output" "$WORK/activation-receipt.json" >/dev/null; then
    fail "MD5 secret escaped into lifecycle output or receipt"
fi
docker exec "$FRR" vtysh -c 'show bgp neighbors 192.0.2.18 json' \
    | jq -e '.["192.0.2.18"].bgpState == "Established"' >/dev/null \
    || fail "FRR does not report the authenticated session Established"
ok "M97 authenticated lifecycle, private modes, cleanup, and redaction complete"
