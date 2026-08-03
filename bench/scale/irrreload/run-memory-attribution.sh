#!/usr/bin/env bash
# Fresh-process IRR route-server memory attribution: private/grouped/grouped/private.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
GEN=${GENERATOR:-$REPO/bench/scale/reloadstall/gen-irr-scenario.py}
CLASSIFIER=$REPO/bench/scale/rebaseline/classify_dhat.py
PROTOCOL=(private grouped grouped private)
PATH_HIDING=(true false false true)
RSS_LIMIT_KIB=$((100 * 1024 * 1024))
START_TIMEOUT=${START_TIMEOUT:-60}
SETTLE_TIMEOUT=${SETTLE_TIMEOUT:-10}
LEG_TIMEOUT=${LEG_TIMEOUT:-600}
PORT=${PORT:-1790}
METRICS_PORT=${METRICS_PORT:-9179}

die() { echo "$*" >&2; exit 1; }
uint() { [[ $1 =~ ^[0-9]+$ ]]; }
hash_file() { sha256sum -- "$1" | awk '{print $1}'; }
dirty_hash() {
    local stream untracked path
    stream=$(mktemp) || return 1; untracked=$(mktemp) || { rm -f "$stream"; return 1; }
    git -C "$REPO" status --porcelain=v1 -z >"$stream" || { rm -f "$stream" "$untracked"; return 1; }
    git -C "$REPO" diff --binary HEAD -- >>"$stream" || { rm -f "$stream" "$untracked"; return 1; }
    git -C "$REPO" ls-files --others --exclude-standard -z >"$untracked" || { rm -f "$stream" "$untracked"; return 1; }
    # shellcheck disable=SC2094 # distinct mktemp files; ShellCheck cannot infer that.
    while IFS= read -r -d '' -u 3 path; do printf 'untracked %s\0' "$path" >>"$stream"; (cd "$REPO" && sha256sum -- "$path") >>"$stream" || { rm -f "$stream" "$untracked"; return 1; }; done 3<"$untracked"
    sha256sum "$stream" | awk '{print $1}'; local rc=${PIPESTATUS[0]}; rm -f "$stream" "$untracked"; return "$rc"
}
capture_source_identity() {
    COMMIT=$(git -C "$REPO" rev-parse 'HEAD^{commit}') && DIRTY_STATE_SHA256=$(dirty_hash)
}
full_source_admission() {
    GIT_TERMINAL_PROMPT=0 timeout -k 5 60 git -C "$REPO" fetch origin '+refs/heads/main:refs/remotes/origin/main' >/dev/null 2>&1 || return 1
    local head remote status; head=$(git -C "$REPO" rev-parse 'HEAD^{commit}') || return 1
    remote=$(git -C "$REPO" rev-parse 'refs/remotes/origin/main^{commit}') || return 1
    status=$(git -C "$REPO" status --porcelain=v1) || return 1
    [[ $head == "$remote" && -z $status ]] || return 1
    capture_source_identity
}
source_admission() {
    if [[ $1 == full ]]; then full_source_admission; else capture_source_identity; fi
}
monotonic() { awk '{print $1}' /proc/uptime; }
validate_protocol() {
    [[ $# == 4 && $1 == private && $2 == grouped && $3 == grouped && $4 == private ]]
}

validate_scrapes() {
    python3 - "$@" <<'PY'
import math, pathlib, re, sys
mode, peers_text, total_text, allocator_text, config, *paths = sys.argv[1:]
peers, total, allocator = int(peers_text), int(total_text), allocator_text == "true"
if len(paths) != 3:
    raise SystemExit("exactly three consecutive scrapes are required")
metric_name = re.compile(r'[A-Za-z_:][A-Za-z0-9_:]*')
label_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
float_value = re.compile(r'(?:[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|NaN|[+-]Inf)')
int64_timestamp = re.compile(r'[+-]?[0-9]+')
watched = ("bgp_rib_", "bgp_peer_", "bgp_update_group", "jemalloc_")
def quoted(text, pos):
    if pos >= len(text) or text[pos] != '"': raise ValueError("expected quoted string")
    chars, pos = [], pos + 1
    while pos < len(text):
        char, pos = text[pos], pos + 1
        if char == '"': return ''.join(chars), pos
        if char == '\\':
            if pos >= len(text) or text[pos] not in '\\"n': raise ValueError("malformed escape")
            chars.append({'\\': '\\', '"': '"', 'n': '\n'}[text[pos]]); pos += 1
        elif char in '\r\n': raise ValueError("unescaped line break")
        else: chars.append(char)
    raise ValueError("unterminated quoted string")
def parse_sample(text):
    match = metric_name.match(text)
    if not match: return None
    name, pos, labels = match.group(), match.end(), {}
    if pos < len(text) and text[pos] == '{':
        pos += 1
        while True:
            while pos < len(text) and text[pos] in ' \t': pos += 1
            if pos < len(text) and text[pos] == '}': pos += 1; break
            if pos < len(text) and text[pos] == '"': key, pos = quoted(text, pos)
            else:
                match = label_name.match(text, pos)
                if not match: raise ValueError("malformed label name")
                key, pos = match.group(), match.end()
            while pos < len(text) and text[pos] in ' \t': pos += 1
            if pos >= len(text) or text[pos] != '=': raise ValueError("missing label equals")
            pos += 1
            while pos < len(text) and text[pos] in ' \t': pos += 1
            value, pos = quoted(text, pos)
            if key in labels: raise ValueError(f"duplicate label: {key!r}")
            labels[key] = value
            while pos < len(text) and text[pos] in ' \t': pos += 1
            if pos < len(text) and text[pos] == '}': pos += 1; break
            if pos >= len(text) or text[pos] != ',': raise ValueError("malformed label separator")
            pos += 1
    if pos >= len(text) or text[pos] not in ' \t': raise ValueError("missing value separator")
    tokens = text[pos:].split()
    if len(tokens) not in (1, 2) or not float_value.fullmatch(tokens[0]): raise ValueError("malformed sample value")
    if len(tokens) == 2:
        if not int64_timestamp.fullmatch(tokens[1]): raise ValueError("malformed timestamp")
        if not -(1 << 63) <= int(tokens[1]) < (1 << 63): raise ValueError("timestamp outside int64")
    return name, labels, float(tokens[0])
def parse(path):
    result, identities = {}, set()
    for line in pathlib.Path(path).read_text().splitlines():
        text = line.strip()
        if not text or text.startswith('#'): continue
        try: parsed = parse_sample(text)
        except ValueError:
            if text.startswith(watched): raise
            continue
        if parsed is None: continue
        name, labels, value = parsed
        identity = (name, tuple(sorted(labels.items())))
        if identity in identities: raise ValueError(f"duplicate metric sample: {identity}")
        identities.add(identity); result.setdefault(name, []).append((labels, value))
    return result
scrapes = [parse(path) for path in paths]
def rows(data, name, count=None):
    found = data.get(name, [])
    if count is not None and len(found) != count:
        raise ValueError(f"{name}: expected {count} samples, got {len(found)}")
    if any(not math.isfinite(value) for _, value in found):
        raise ValueError(f"{name}: non-finite sample")
    return found
def singleton(data, name):
    labels, value = rows(data, name, 1)[0]
    if labels: raise ValueError(f"{name}: unexpected labels {labels}")
    return value
def one(data, name, expected):
    value = singleton(data, name)
    if value != expected: raise ValueError(f"{name}: expected {expected}, got {value:g}")
def peer_rows(data, name, extra=()):
    found = rows(data, name, peers)
    identities = [labels.get("peer") for labels, _ in found]
    expected = {"peer", *extra}
    if None in identities or len(set(identities)) != peers or any(set(labels) != expected for labels, _ in found):
        raise ValueError(f"{name}: missing/duplicate peer or unexpected labels")
    return found
def family_rows(data, name, identities, families):
    found = rows(data, name, peers * len(families)); expected = {(peer, family) for peer in identities for family in families}
    actual = {(labels.get("peer"), labels.get("afi_safi")) for labels, _ in found}
    if actual != expected or any(set(labels) != {"peer", "afi_safi"} for labels, _ in found):
        raise ValueError(f"{name}: family/peer roster mismatch")
    return {(labels["peer"], labels["afi_safi"]): value for labels, value in found}
text = pathlib.Path(config).read_text()
if "[neighbors.add_path]" in text:
    raise ValueError("memory legs require Add-Path disabled")
expected_best = peers if mode == "private" else 0
if text.count("per_client_best = true") != expected_best:
    raise ValueError(f"{mode}: per_client_best mapping is not exact")
for data in scrapes:
    one(data, "bgp_rib_outbound_registered_peers", peers)
    one(data, "bgp_rib_ingest_channel_depth", 0)
    one(data, "bgp_rib_policy_transition_in_progress", 0)
    sessions = peer_rows(data, "bgp_peer_session_established", ("interface",)); peer_ids = {labels["peer"] for labels, _ in sessions}
    if [value for _, value in sessions] != [1.0] * peers:
        raise ValueError("not every expected session is established")
    queues = peer_rows(data, "bgp_peer_outbound_queue_depth")
    if {labels["peer"] for labels, _ in queues} != peer_ids or [value for _, value in queues] != [0.0] * peers:
        raise ValueError("every outbound queue must be zero")
    loc = rows(data, "bgp_rib_loc_prefixes", 1)
    if loc[0] != ({"afi_safi": "all"}, float(total)): raise ValueError("Loc-RIB aggregate mismatch")
    adj_in = family_rows(data, "bgp_rib_prefixes", peer_ids, ("all", "flowspec"))
    if any(adj_in[(peer, "all")] != total // peers or adj_in[(peer, "flowspec")] != 0 for peer in peer_ids):
        raise ValueError("Adj-RIB-In aggregate/non-all roster mismatch")
    expected_out = total - total // peers
    out_families = ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
    adj_out = family_rows(data, "bgp_rib_adj_out_prefixes", peer_ids, out_families)
    if any(adj_out[(peer, family)] != (expected_out if family == "all" else 0) for peer in peer_ids for family in out_families):
        raise ValueError("Adj-RIB-Out aggregate/non-all roster mismatch")
    peer_groups = peer_rows(data, "bgp_peer_update_group")
    if {labels["peer"] for labels, _ in peer_groups} != peer_ids: raise ValueError("group peer roster mismatch")
    if mode == "private":
        one(data, "bgp_update_groups", 0); one(data, "bgp_update_group_fallback_peers", peers)
        if rows(data, "bgp_update_group_members") or any(value != -1 for _, value in peer_groups):
            raise ValueError("private leg must have no groups and all peer group gauges -1")
    else:
        one(data, "bgp_update_groups", 1); one(data, "bgp_update_group_fallback_peers", 0)
        members = rows(data, "bgp_update_group_members", 1)
        if set(members[0][0]) != {"group"}: raise ValueError("group member labels invalid")
        group = members[0][0].get("group")
        ids = {value for _, value in peer_groups}
        group_id = next(iter(ids)) if len(ids) == 1 else math.nan
        if members[0][1] != peers or not math.isfinite(group_id) or group_id < 0 or group_id != int(group_id) or group != str(int(group_id)):
            raise ValueError("grouped leg must have exactly one complete shared nonnegative group")
    if allocator:
        names = ("jemalloc_allocated_bytes", "jemalloc_active_bytes",
                 "jemalloc_resident_bytes", "jemalloc_mapped_bytes")
        values = [singleton(data, name) for name in names]
        if any(value <= 0 or value != int(value) for value in values):
            raise ValueError("allocator gauges must be unique positive numeric samples")
        if values[0] > values[1]: raise ValueError("jemalloc allocated exceeds active")
stable = lambda data: sorted(
    (name, tuple(sorted(labels.items())), value)
    for name, found in data.items()
    if name.startswith("bgp_rib_") and name.endswith("_prefixes")
       or name in {"bgp_update_groups", "bgp_update_group_members",
                   "bgp_update_group_fallback_peers", "bgp_peer_update_group"}
    for labels, value in found)
if not stable(scrapes[0]) or stable(scrapes[0]) != stable(scrapes[1]) or stable(scrapes[1]) != stable(scrapes[2]):
    raise SystemExit("route/group gauges were not stable for three consecutive scrapes")
PY
}

validate_evidence() {
    python3 - "$@" <<'PY'
import datetime, math, pathlib, re, sys
root, expected_pid, expected_start = pathlib.Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
required = ["timestamps.tsv", "metrics-1.prom", "metrics-2.prom", "metrics-3.prom",
            "root.status", "root.smaps_rollup", "roster-before.tsv", "roster-after.tsv"]
for name in required:
    path = root / name
    if not path.is_file() or path.stat().st_size == 0: raise SystemExit(f"partial evidence: {name}")
timestamps = [line.split('\t') for line in (root/"timestamps.tsv").read_text().splitlines()]
if timestamps[0] != ["phase", "monotonic", "utc"] or [row[0] for row in timestamps[1:]] != ["start","scrape1","scrape2","scrape3","capture_end"] or any(len(row) != 3 for row in timestamps):
    raise SystemExit("measurement timestamps do not contain exactly one accepted capture")
mono = [float(row[1]) for row in timestamps[1:]]
utc = [datetime.datetime.strptime(row[2], "%Y-%m-%dT%H:%M:%SZ") for row in timestamps[1:]]
if not all(math.isfinite(value) for value in mono) or not all(left < right for left, right in zip(mono, mono[1:])) or mono[2]-mono[1] < 1 or mono[3]-mono[2] < 1 or any(left > right for left, right in zip(utc, utc[1:])):
    raise SystemExit("measurement timestamps are invalid, unordered, or under 1s scrape cadence")
for name, field in [("root.status", "VmRSS"), ("root.smaps_rollup", "Rss")]:
    if not re.search(rf"^{field}:\s+[1-9][0-9]*\s+kB$", (root/name).read_text(), re.M):
        raise SystemExit(f"{name}: missing numeric {field}")
def roster(name):
    lines = (root/name).read_text().splitlines()
    if lines[0] != "pid\tppid\tstarttime\trss_kib\ttree_rss_kib": raise SystemExit("bad roster header")
    rows = [line.split('\t') for line in lines[1:]]
    if not rows or any(len(row) != 5 or not all(value.isdigit() for value in row) for row in rows):
        raise SystemExit("partial PID/RSS/tree roster")
    parsed = {int(row[0]): tuple(map(int, row[1:])) for row in rows}
    if len(parsed) != len(rows) or expected_pid not in parsed or parsed[expected_pid][1] != expected_start:
        raise SystemExit("duplicate or missing root PID/starttime")
    if len({row[4] for row in rows}) != 1 or any(int(row[3]) <= 0 for row in rows) or int(rows[0][4]) != sum(int(row[3]) for row in rows):
        raise SystemExit("invalid per-PID or tree RSS")
    for pid, (ppid, _, _, _) in parsed.items():
        seen = set()
        while pid != expected_pid:
            if pid in seen or pid not in parsed: raise SystemExit("disconnected/cyclic process tree")
            seen.add(pid); pid = parsed[pid][0]
    return {(pid, values[1]) for pid, values in parsed.items()}
if roster("roster-before.tsv") != roster("roster-after.tsv"):
    raise SystemExit("PID liveness/identity changed during evidence capture")
PY
}

capture_roster() {
    python3 - "$1" "$2" <<'PY'
import pathlib, re, sys
root, output = int(sys.argv[1]), pathlib.Path(sys.argv[2])
rows = {}
for path in pathlib.Path('/proc').glob('[0-9]*/stat'):
    try:
        text = path.read_text(); pid = int(path.parent.name); tail = text[text.rfind(')')+2:].split()
        status = path.with_name('status').read_text()
        rss = int(re.search(r'^VmRSS:\s+([0-9]+)\s+kB$', status, re.M).group(1))
        rows[pid] = (int(tail[1]), int(tail[19]), rss)
    except (OSError, AttributeError, ValueError): pass
if root not in rows: raise SystemExit("root process disappeared")
selected = {root}
while True:
    added = {pid for pid, (ppid, _, _) in rows.items() if ppid in selected} - selected
    if not added: break
    selected |= added
tree = sum(rows[pid][2] for pid in selected)
with output.open('w') as stream:
    stream.write('pid\tppid\tstarttime\trss_kib\ttree_rss_kib\n')
    for pid in sorted(selected):
        ppid, start, rss = rows[pid]; stream.write(f'{pid}\t{ppid}\t{start}\t{rss}\t{tree}\n')
PY
}

terminate_group() {
    local pid=${1:-} attempt
    [[ -n $pid ]] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || true
    for ((attempt=0; attempt<100; attempt++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

validate_dhat() {
    local raw=$1 out=$2 injected=${3:-}
    mkdir -p "$out"
    if [[ -n $injected ]]; then
        python3 "$CLASSIFIER" "$raw" --output "$out/classified.tsv" --derivative "$out/raw-derivative.tsv" || return
        cp "$injected" "$out/derivative.tsv"
    else
        python3 "$CLASSIFIER" "$raw" --output "$out/classified.tsv" --derivative "$out/derivative.tsv" || return
    fi
    python3 "$CLASSIFIER" --from-derivative "$out/derivative.tsv" --output "$out/reclassified.tsv" || return
    cmp -s "$out/classified.tsv" "$out/reclassified.tsv" || return 1
    awk -F '\t' '$1=="TOTAL" {ok=($2 ~ /^[0-9]+$/ && $2>0)} END{exit !ok}' "$out/classified.tsv"
}

expect_reject() {
    local name=$1; shift
    if "$@" >/dev/null 2>&1; then echo "red-proof $name unexpectedly accepted" >&2; return 1; fi
    echo "red-proof $name=pass"
}

self_test() (
    local tmp fixture=$REPO/bench/scale/rebaseline/fixtures/dhat.json
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    validate_protocol "${PROTOCOL[@]}" || return
    expect_reject leg-reordered validate_protocol private grouped private grouped
    expect_reject leg-omitted validate_protocol private grouped grouped
    local origin=$tmp/origin.git publisher=$tmp/publisher clone=$tmp/clone cached real_git canonical aliased
    real_git=$(command -v git)
    git init -q --bare "$origin"; git init -q -b main "$publisher"
    git -C "$publisher" config user.email self@test; git -C "$publisher" config user.name self-test
    echo initial >"$publisher/source"; git -C "$publisher" add source; git -C "$publisher" commit -qm initial
    git -C "$publisher" remote add origin "$origin"; git -C "$publisher" push -q -u origin main
    git clone -q --branch main "$origin" "$clone"
    env REPO="$clone" bash -c "$(declare -f dirty_hash capture_source_identity full_source_admission source_admission); source_admission smoke; [[ -n \$COMMIT && -n \$DIRTY_STATE_SHA256 ]]"; echo "positive-proof source-bounded-capture=pass"
    env REPO="$clone" bash -c "$(declare -f dirty_hash capture_source_identity full_source_admission); full_source_admission"; echo "positive-proof source-aligned-clean=pass"
    echo untracked >"$clone/untracked"; canonical=$(env REPO="$clone" bash -c "$(declare -f dirty_hash); dirty_hash")
    aliased=$(env REPO="$clone/../clone" bash -c "$(declare -f dirty_hash); dirty_hash")
    [[ $canonical == "$aliased" ]] || return 1; rm "$clone/untracked"; echo "positive-proof source-path-alias-stable=pass"
    mkdir "$tmp/bin"; printf "#!/bin/sh\ncase \" \$* \" in *\" \$FAIL_GIT \"*) exit 9;; esac\nexec %q \"\$@\"\n" "$real_git" >"$tmp/bin/git"; chmod +x "$tmp/bin/git"
    for failure_case in status:status diff:diff untracked:ls-files; do
        IFS=: read -r proof failure <<<"$failure_case"
        expect_reject "source-$proof-failure" env FAIL_GIT="$failure" PATH="$tmp/bin:$PATH" REPO="$clone" bash -c "$(declare -f dirty_hash capture_source_identity source_admission); source_admission smoke"
    done
    echo dirty >>"$clone/source"; expect_reject source-dirty env REPO="$clone" bash -c "$(declare -f dirty_hash full_source_admission); full_source_admission"
    git -C "$clone" restore source; echo divergent >"$clone/local"; git -C "$clone" add local; git -C "$clone" -c user.email=self@test -c user.name=self-test commit -qm divergent
    expect_reject source-head-not-origin-main env REPO="$clone" bash -c "$(declare -f dirty_hash full_source_admission); full_source_admission"; git -C "$clone" reset -q --hard origin/main
    cached=$(git -C "$clone" rev-parse origin/main); echo advanced >>"$publisher/source"; git -C "$publisher" commit -qam advanced; git -C "$publisher" push -q
    [[ $(git -C "$clone" rev-parse origin/main) == "$cached" ]] || return 1
    expect_reject source-remote-main-advanced env REPO="$clone" bash -c "$(declare -f dirty_hash full_source_admission); full_source_admission"
    [[ $(git -C "$clone" rev-parse origin/main) != "$cached" ]] || return 1
    python3 - "$GEN" "$tmp" <<'PY'
import importlib.util, json, pathlib, subprocess, sys
gen, root = sys.argv[1], pathlib.Path(sys.argv[2]); spec = importlib.util.spec_from_file_location("gen", gen)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
assert module.context_doc([], "a", True, False)["cfg"] == module.context_doc([], "a", False, False)["cfg"] | {"path_hiding": True}
assert module.context_doc([], "a", False, False)["cfg"]["path_hiding"] is False
assert module.context_doc([], "a", True, False)["cfg"]["add_path"] is False
for value in ("true", "false"):
    out = root/value
    subprocess.run([sys.executable, gen, "bird", "8", "8", str(out), "--min-list", "1", "--max-list", "1", "--path-hiding", value], check=True, stdout=subprocess.DEVNULL)
first, second = [json.loads((root/value/"manifest.json").read_text()) for value in ("true", "false")]
assert first["path_hiding"] is None and second["path_hiding"] is None
assert first["path_hiding_requested"] is True and second["path_hiding_requested"] is False
assert first["path_hiding_applicable"] is False and second["path_hiding_applicable"] is False
assert first["dataset_sha256"] == second["dataset_sha256"]
out = root/"no-churn"
subprocess.run([sys.executable, gen, "bird", "8", "8", str(out), "--min-list", "1", "--max-list", "1", "--admit-churn", "false"], check=True, stdout=subprocess.DEVNULL)
third = json.loads((out/"manifest.json").read_text())
assert third["admit_churn"] is False and third["dataset_sha256"] == first["dataset_sha256"]
PY
    echo "red-proof path-hiding-mapping-and-hash=pass"
    python3 - "$tmp" <<'PY'
import pathlib, sys
root=pathlib.Path(sys.argv[1])
def metrics(mode, bad=None, step=0):
    lines=["bgp_rib_outbound_registered_peers 2e0 -3982045", "bgp_rib_ingest_channel_depth 0",
           "bgp_rib_policy_transition_in_progress 0", f"bgp_rib_loc_prefixes{{afi_safi=\"all\"}} {'NaN' if bad=='nonfinite' else 7 if bad=='wrong-routes' else 8}"]
    for n in range(2):
        peer = "p0" if bad=="duplicate-peer" and n==1 else f"p{n}"
        queue_labels = f'peer="{peer}"'
        if bad=="duplicate-label" and n==0: queue_labels += f',peer="{peer}"'
        if bad in ("malformed-label","malformed-escape") and n==0: queue_labels = f"peer={peer}" if bad=="malformed-label" else rf'peer="{peer}\q"'
        if bad=="unexpected-label" and n==0: queue_labels += ',extra="x"'
        if bad=="missing-label" and n==0: queue_labels = 'extra="x"'
        lines += [rf'bgp_peer_session_established{{interface="ether\\net\n\"quoted\"",peer="p{n}"}} 1e0 +123',
                  f'bgp_peer_outbound_queue_depth{{{queue_labels}}} {1 if bad=="queue" and n==1 else 0}']
        lines += [f'bgp_rib_prefixes{{afi_safi="{family}",peer="p{n}"}} {4 if family=="all" else int(bad=="family" and n==1)}' for family in ("all","flowspec")]
        lines += [f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="p{n}"}} {4 if family=="all" else int(bad=="adj-out-family" and n==1 and family=="vpn")}' for family in ("all","bgpls","evpn","flowspec","labeled","rtc","vpn")]
    if mode=="private":
        lines += ["bgp_update_groups 0", "bgp_update_group_fallback_peers 2"]
        lines += [f'bgp_peer_update_group{{peer="p{n}"}} -1' for n in range(2)]
    else:
        lines += [f"bgp_update_groups {2 if bad=='group' else 1}", "bgp_update_group_fallback_peers 0",
                  'bgp_update_group_members{group="7"} 2']
        lines += [f'bgp_peer_update_group{{peer="p{n}"}} {7.5 if bad=="fractional-group" else 7}' for n in range(2)]
    alloc=[1000,1000,1400,1600]
    if bad!="missing-allocator":
        lines += [f"{name} {value}" for name,value in zip(("jemalloc_allocated_bytes","jemalloc_active_bytes","jemalloc_resident_bytes","jemalloc_mapped_bytes"),alloc)]
    if bad=="allocator-conflation": lines += ["jemalloc_allocated_bytes 999"]
    if bad=="unstable" and step==2: lines[3]=lines[3].replace(" 8", " 9")
    return "\n".join(lines)+"\n"
for case,mode,bad in [("good-private","private",None),("good-grouped","grouped",None),
                      ("bad-group","grouped","group"),("bad-queue","private","queue"),
                      ("wrong-routes","private","wrong-routes"),("nonfinite","private","nonfinite"),("bad-family","private","family"),("bad-adj-out-family","private","adj-out-family"),
                      ("duplicate-label","private","duplicate-label"),("malformed-label","private","malformed-label"),("malformed-escape","private","malformed-escape"),
                      ("unexpected-label","private","unexpected-label"),("missing-label","private","missing-label"),
                      ("duplicate-peer","private","duplicate-peer"),
                      ("fractional-group","grouped","fractional-group"),("bad-allocator","private","allocator-conflation"),
                      ("missing-allocator","private","missing-allocator"),
                      ("unstable","private","unstable")]:
    d=root/case; d.mkdir(); (d/"config.toml").write_text(("per_client_best = true\n"*2) if mode=="private" else "")
    for step in range(3): (d/f"metrics-{step+1}.prom").write_text(metrics(mode,bad,step))
e=root/"evidence"; e.mkdir()
for name,text in [("timestamps.tsv","phase\tmonotonic\tutc\nstart\t0\t2026-01-01T00:00:00Z\nscrape1\t1\t2026-01-01T00:00:01Z\nscrape2\t2\t2026-01-01T00:00:02Z\nscrape3\t3\t2026-01-01T00:00:03Z\ncapture_end\t4\t2026-01-01T00:00:04Z\n"),
                  ("root.status","VmRSS:\t10 kB\n"),("root.smaps_rollup","Rss:\t10 kB\n")]: (e/name).write_text(text)
for step in range(3): (e/f"metrics-{step+1}.prom").write_text(metrics("private"))
roster="pid\tppid\tstarttime\trss_kib\ttree_rss_kib\n10\t1\t100\t10\t10\n"
(e/"roster-before.tsv").write_text(roster); (e/"roster-after.tsv").write_text(roster)
PY
    local d
    for d in good-private good-grouped; do validate_scrapes "${d#good-}" 2 8 true "$tmp/$d/config.toml" "$tmp/$d"/metrics-{1,2,3}.prom; done; echo "positive-proof prometheus-syntax=pass"
    expect_reject group-enforcement validate_scrapes grouped 2 8 true "$tmp/bad-group/config.toml" "$tmp/bad-group"/metrics-{1,2,3}.prom
    expect_reject queue-enforcement validate_scrapes private 2 8 true "$tmp/bad-queue/config.toml" "$tmp/bad-queue"/metrics-{1,2,3}.prom
    expect_reject route-count-enforcement validate_scrapes private 2 8 true "$tmp/wrong-routes/config.toml" "$tmp/wrong-routes"/metrics-{1,2,3}.prom
    expect_reject metric-parser-nonfinite validate_scrapes private 2 8 true "$tmp/nonfinite/config.toml" "$tmp/nonfinite"/metrics-{1,2,3}.prom
    expect_reject route-family-enforcement validate_scrapes private 2 8 true "$tmp/bad-family/config.toml" "$tmp/bad-family"/metrics-{1,2,3}.prom
    expect_reject adj-out-family-enforcement validate_scrapes private 2 8 true "$tmp/bad-adj-out-family/config.toml" "$tmp/bad-adj-out-family"/metrics-{1,2,3}.prom
    for d in duplicate-label malformed-label malformed-escape unexpected-label missing-label duplicate-peer; do expect_reject "metric-parser-$d" validate_scrapes private 2 8 true "$tmp/$d/config.toml" "$tmp/$d"/metrics-{1,2,3}.prom; done
    expect_reject fractional-group validate_scrapes grouped 2 8 true "$tmp/fractional-group/config.toml" "$tmp/fractional-group"/metrics-{1,2,3}.prom
    expect_reject three-scrape-stability validate_scrapes private 2 8 true "$tmp/unstable/config.toml" "$tmp/unstable"/metrics-{1,2,3}.prom
    expect_reject allocator-conflation validate_scrapes private 2 8 true "$tmp/bad-allocator/config.toml" "$tmp/bad-allocator"/metrics-{1,2,3}.prom
    expect_reject allocator-omission validate_scrapes private 2 8 true "$tmp/missing-allocator/config.toml" "$tmp/missing-allocator"/metrics-{1,2,3}.prom
    validate_evidence "$tmp/evidence" 10 100
    cp -a "$tmp/evidence" "$tmp/pid-reuse"; sed -i 's/\t100\t/\t101\t/' "$tmp/pid-reuse/roster-after.tsv"
    expect_reject pid-reuse validate_evidence "$tmp/pid-reuse" 10 100
    cp -a "$tmp/evidence" "$tmp/proc-missing"; rm "$tmp/proc-missing/root.smaps_rollup"
    expect_reject proc-omission validate_evidence "$tmp/proc-missing" 10 100
    cp -a "$tmp/evidence" "$tmp/tree-missing"; sed -i 's/\t10$//' "$tmp/tree-missing/roster-after.tsv"
    expect_reject tree-rss-omission validate_evidence "$tmp/tree-missing" 10 100
    cp -a "$tmp/evidence" "$tmp/retry-timestamps"; sed -i '3p' "$tmp/retry-timestamps/timestamps.tsv"; expect_reject timestamp-retry-accumulation validate_evidence "$tmp/retry-timestamps" 10 100
    cp -a "$tmp/evidence" "$tmp/short-cadence"; sed -i 's/scrape2\t2/scrape2\t1.5/' "$tmp/short-cadence/timestamps.tsv"; expect_reject timestamp-cadence validate_evidence "$tmp/short-cadence" 10 100
    cp -a "$tmp/evidence" "$tmp/reversed-time"; sed -i 's/capture_end\t4/capture_end\t2.5/' "$tmp/reversed-time/timestamps.tsv"; expect_reject timestamp-order-reversal validate_evidence "$tmp/reversed-time" 10 100
    cp -a "$tmp/evidence" "$tmp/root-omitted"; sed -i '2,$d' "$tmp/root-omitted"/roster-{before,after}.tsv; expect_reject roster-root-omission validate_evidence "$tmp/root-omitted" 10 100
    cp -a "$tmp/evidence" "$tmp/root-replaced"; sed -i 's/^10\t/11\t/' "$tmp/root-replaced"/roster-{before,after}.tsv; expect_reject roster-root-replacement validate_evidence "$tmp/root-replaced" 10 100
    cp -a "$tmp/evidence" "$tmp/duplicate-roster"; duplicate=$(tail -n1 "$tmp/duplicate-roster/roster-before.tsv"); printf '%s\n' "$duplicate" >>"$tmp/duplicate-roster/roster-before.tsv"; expect_reject roster-duplicate validate_evidence "$tmp/duplicate-roster" 10 100
    cp -a "$tmp/evidence" "$tmp/bad-tree"; sed -i 's/\t10$/\t11/' "$tmp/bad-tree/roster-before.tsv"; expect_reject roster-tree-sum validate_evidence "$tmp/bad-tree" 10 100
    cp -a "$tmp/evidence" "$tmp/disconnected"; printf '11\t99\t101\t10\t20\n' >>"$tmp/disconnected/roster-before.tsv"; sed -i 's/\t10$/\t20/' "$tmp/disconnected/roster-before.tsv"; expect_reject roster-disconnected validate_evidence "$tmp/disconnected" 10 100
    validate_dhat "$fixture" "$tmp/dhat-good"
    jq '.pps |= map(.gb=0)' "$fixture" >"$tmp/dhat-zero.json"
    expect_reject dhat-zero-live validate_dhat "$tmp/dhat-zero.json" "$tmp/dhat-zero"
    jq '.pps[0].gb=1 | .pps[0].fs=[]' "$fixture" >"$tmp/dhat-unsymbolized.json"
    expect_reject dhat-unsymbolized validate_dhat "$tmp/dhat-unsymbolized.json" "$tmp/dhat-unsymbolized"
    jq '.pps |= map(if .gb > 0 then .gb += 1 else . end)' "$fixture" >"$tmp/dhat-mismatch.json"
    python3 "$CLASSIFIER" "$tmp/dhat-mismatch.json" --output "$tmp/dhat-mismatch.tsv" --derivative "$tmp/dhat-bad.tsv"
    expect_reject dhat-raw-derivative-mismatch validate_dhat "$fixture" "$tmp/dhat-mismatch-check" "$tmp/dhat-bad.tsv"
    for rejection in metrics-port-fixed:METRICS_PORT:9180 port-positive:PORT:0 port-range:PORT:65536 timeout-numeric:START_TIMEOUT:no timeout-positive:START_TIMEOUT:0 start-timeout-cap:START_TIMEOUT:121 settle-timeout-cap:SETTLE_TIMEOUT:11 leg-timeout-cap:LEG_TIMEOUT:901; do
        IFS=: read -r proof knob invalid <<<"$rejection"
        if env SELF_TEST= MODE=smoke DRY_RUN_PROTOCOL=1 "$knob=$invalid" bash "$0" >/dev/null 2>&1; then die "red fixture accepted: $proof"; fi; printf 'red-proof %s=pass\n' "$proof"
    done
    echo "SELF_TEST pass"
)

if [[ ${SELF_TEST:-0} == 1 ]]; then self_test; exit; fi

case ${MODE:-} in
smoke) N_MEMBERS=${N_MEMBERS:-8}; TOTAL_PREFIXES=${TOTAL_PREFIXES:-800}; MIN_LIST=${MIN_LIST:-100}; MAX_LIST=${MAX_LIST:-100}
       ((N_MEMBERS <= 16 && TOTAL_PREFIXES <= 1600 && MAX_LIST <= 200)) || die "smoke shape exceeds bounded ceiling" ;;
dhat)  N_MEMBERS=${N_MEMBERS:-8}; TOTAL_PREFIXES=${TOTAL_PREFIXES:-800}; MIN_LIST=${MIN_LIST:-100}; MAX_LIST=${MAX_LIST:-100}
       ((N_MEMBERS <= 16 && TOTAL_PREFIXES <= 1600 && MAX_LIST <= 200)) || die "DHAT shape exceeds bounded ceiling" ;;
full)  [[ ${FULL_SHAPE:-0} == 1 ]] || die "MODE=full requires FULL_SHAPE=1"
       N_MEMBERS=${N_MEMBERS:-320}; TOTAL_PREFIXES=${TOTAL_PREFIXES:-183040}; MIN_LIST=${MIN_LIST:-1000}; MAX_LIST=${MAX_LIST:-40000}
       [[ $N_MEMBERS == 320 && $TOTAL_PREFIXES == 183040 && $MIN_LIST == 1000 && $MAX_LIST == 40000 ]] || die "full mode requires canonical shape 320,183040,1000,40000" ;;
*) echo "set MODE=smoke, MODE=dhat, or MODE=full FULL_SHAPE=1" >&2; exit 2 ;;
esac
if ! uint "$N_MEMBERS" || ! uint "$TOTAL_PREFIXES" || ! uint "$MIN_LIST" || ! uint "$MAX_LIST"; then
    die "shape values must be integers"
fi
for value in "$PORT" "$METRICS_PORT" "$START_TIMEOUT" "$SETTLE_TIMEOUT" "$LEG_TIMEOUT"; do if ! uint "$value" || ((value <= 0)); then die "ports/timeouts must be positive integers"; fi; done
if ((PORT > 65535)) || [[ $METRICS_PORT != 9179 ]]; then die "daemon port must fit u16 and metrics port is fixed at 9179"; fi
((N_MEMBERS >= 8 && TOTAL_PREFIXES % N_MEMBERS == 0 && MIN_LIST >= 1 && MIN_LIST <= MAX_LIST)) || die "shape violates generator contract"
((SETTLE_TIMEOUT <= 10)) || die "settle timeout exceeds reloadstall's bounded evidence handshake"
[[ $MODE == full ]] || ((START_TIMEOUT <= 120 && SETTLE_TIMEOUT <= 10 && LEG_TIMEOUT <= 900)) || die "bounded mode timeout ceiling exceeded"
validate_protocol "${PROTOCOL[@]}" || die "protocol order invalid"
if [[ ${DRY_RUN_PROTOCOL:-0} == 1 ]]; then
    printf 'mode=%s\nprotocol=%s\npath_hiding=%s\nadmit_churn=false\nshape=%s,%s,%s,%s\nports=%s,9179\ntimeouts=%s,%s,%s\nrss_abort_gib=100\n' \
        "$MODE" "$(IFS=,; echo "${PROTOCOL[*]}")" "$(IFS=,; echo "${PATH_HIDING[*]}")" \
        "$N_MEMBERS" "$TOTAL_PREFIXES" "$MIN_LIST" "$MAX_LIST" "$PORT" "$START_TIMEOUT" "$SETTLE_TIMEOUT" "$LEG_TIMEOUT"
    exit
fi

[[ -n ${ARTIFACT_ROOT:-} && ! -e $ARTIFACT_ROOT ]] || die "ARTIFACT_ROOT must name a fresh path"
for tool in cargo curl flock git jq python3 setsid sha256sum ss timeout; do command -v "$tool" >/dev/null || die "missing tool: $tool"; done
source_admission "$MODE" || die "source admission failed"
mkdir -p "$(dirname "$ARTIFACT_ROOT")"
umask 077; mkdir "$ARTIFACT_ROOT"; ART=$(cd "$ARTIFACT_ROOT" && pwd)
if [[ $MODE == full ]]; then "$REPO/tests/soak/preflight.sh" >"$ART/full-preflight.log" 2>&1 || exit 75; fi
LOCK=${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}; mkdir -p "$(dirname "$LOCK")"; exec {LOCK_FD}>"$LOCK"
flock -n "$LOCK_FD" || exit 75
printf 'phase\tmonotonic\tutc\tload1\tmem_available_kib\tports_free\n' >"$ART/preflight.tsv"
ports_free=true; ss -H -ltn | awk -v a=":$PORT" -v b=":$METRICS_PORT" '$4~a"$"||$4~b"$"{found=1} END{exit found?0:1}' && ports_free=false
printf 'prebuild\t%s\t%s\t%s\t%s\t%s\n' "$(monotonic)" "$(date -u +%FT%TZ)" "$(awk '{print $1}' /proc/loadavg)" \
    "$(awk '$1=="MemAvailable:"{print $2}' /proc/meminfo)" "$ports_free" >>"$ART/preflight.tsv"
[[ $ports_free == true ]] || die "benchmark ports are in use"
PROFILE=release; BUILD_FEATURES=(); [[ $MODE != dhat ]] || { PROFILE=release-prof; BUILD_FEATURES=(--features dhat-heap); }
(cd "$REPO" && cargo build --locked --profile "$PROFILE" -p rustbgpd -p rs-config-render "${BUILD_FEATURES[@]}") >"$ART/build.log" 2>&1
(cd "$REPO" && cargo build --locked --release --manifest-path bench/scale/reloadstall/Cargo.toml) >>"$ART/build.log" 2>&1
DAEMON=$REPO/target/$PROFILE/rustbgpd; RENDER=$REPO/target/$PROFILE/rs-config-render
HARNESS=$REPO/bench/scale/reloadstall/target/release/reloadstall
for binary in "$DAEMON" "$RENDER" "$HARNESS"; do [[ -x $binary ]] || die "missing binary: $binary"; done
printf 'script %s\ngenerator %s\nclassifier %s\ndaemon %s\nrenderer %s\nharness %s\n' \
    "$(hash_file "${BASH_SOURCE[0]}")" "$(hash_file "$GEN")" "$(hash_file "$CLASSIFIER")" \
    "$(hash_file "$DAEMON")" "$(hash_file "$RENDER")" "$(hash_file "$HARNESS")" >"$ART/hashes.txt"
{ rustc -vV; cargo -V; python3 --version; jq --version; } >"$ART/tools.txt" 2>&1
printf '%q ' "$0" "$@" >"$ART/argv.txt"; printf '\n' >>"$ART/argv.txt"

ACTIVE_DAEMON='' ACTIVE_HARNESS='' ACTIVE_GUARD='' RUN_DIR=''
cleanup() { local rc=$?; trap - EXIT; terminate_group "$ACTIVE_HARNESS"; terminate_group "$ACTIVE_DAEMON"; [[ -z $ACTIVE_GUARD ]] || kill "$ACTIVE_GUARD" 2>/dev/null || true; [[ -z $RUN_DIR ]] || rm -rf "$RUN_DIR"; exit "$rc"; }
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM

rss_guard() {
    local root=$1 start=$2 harness=$3 out=$4 rss
    printf 'monotonic\tutc\ttree_rss_kib\n' >"$out"
    while kill -0 "$root" 2>/dev/null && kill -0 "$harness" 2>/dev/null; do
        [[ $(awk '{print $22}' "/proc/$root/stat" 2>/dev/null) == "$start" ]] || { touch "$out.identity-abort"; break; }
        rss=$(ps -eo pid=,ppid=,rss= | awk -v root="$root" '{p[$1]=$2;r[$1]=$3} END{for(i in p){x=i;while(x in p&&x!=root&&p[x]!=x)x=p[x];if(x==root)s+=r[i]}print s+0}')
        printf '%s\t%s\t%s\n' "$(monotonic)" "$(date -u +%FT%TZ)" "$rss" >>"$out"
        if ((rss > RSS_LIMIT_KIB)); then touch "$out.rss-abort"; kill -TERM -- "-$harness" "-$root" 2>/dev/null || true; break; fi
        sleep 1
    done
}

DATASET=''
run_leg() {
    local number=$1 mode=$2 hiding=$3 label ldir start deadline accepted=0 hrc allocator=true
    label=$(printf '%02d-%s' "$number" "$mode"); ldir=$ART/$label; mkdir "$ldir"
    RUN_DIR=$(mktemp -d "/tmp/lan789-${number}.XXXXXX")
    python3 "$GEN" rustbgpd "$N_MEMBERS" "$TOTAL_PREFIXES" "$RUN_DIR" --render-bin "$RENDER" \
        --port "$PORT" --seed 61 --min-list "$MIN_LIST" --max-list "$MAX_LIST" --path-hiding "$hiding" \
        --admit-churn false >"$ldir/generator.log"
    cp "$RUN_DIR/manifest.json" "$ldir/manifest.json"
    [[ $(jq -r .path_hiding "$RUN_DIR/manifest.json") == "$hiding" ]] || die "$label path-hiding manifest mismatch"
    [[ $(jq -r .admit_churn "$RUN_DIR/manifest.json") == false ]] || die "$label churn policy mismatch"
    local digest; digest=$(jq -er .dataset_sha256 "$RUN_DIR/manifest.json")
    [[ -z $DATASET || $DATASET == "$digest" ]] || die "private/grouped dataset digests differ"
    DATASET=$digest
    (cd "$RUN_DIR" && jq -r '.runtime_files[]' manifest.json | while read -r path; do sha256sum "$path"; done) >"$ldir/scenario.sha256"
    "$DAEMON" --check "$RUN_DIR/config.toml" >"$ldir/daemon-check.log" 2>&1
    (cd "$ldir" && exec setsid "$DAEMON" "$RUN_DIR/config.toml") >"$ldir/daemon.log" 2>&1 & ACTIVE_DAEMON=$!
    start=$(awk '{print $22}' "/proc/$ACTIVE_DAEMON/stat"); deadline=$((SECONDS + START_TIMEOUT))
    until curl -fsS --max-time 1 "http://127.0.0.1:$METRICS_PORT/readyz" >/dev/null 2>&1; do
        kill -0 "$ACTIVE_DAEMON" 2>/dev/null || die "$label daemon exited"; ((SECONDS < deadline)) || die "$label startup timeout"; sleep 1
    done
    mkdir "$RUN_DIR/final-evidence"
    setsid timeout -k 10 "${LEG_TIMEOUT}s" env RELOADSTALL_EVIDENCE_DIR="$RUN_DIR/final-evidence" \
        "$HARNESS" "$N_MEMBERS" "$TOTAL_PREFIXES" "$PORT" "$ACTIVE_DAEMON" "$RUN_DIR/member.rpol" \
        "$RUN_DIR/gen-a.rpol" "$RUN_DIR/gen-b.rpol" 0 3 "$N_MEMBERS" >"$ldir/reloadstall.log" 2>&1 & ACTIVE_HARNESS=$!
    rss_guard "$ACTIVE_DAEMON" "$start" "$ACTIVE_HARNESS" "$ldir/rss.tsv" & ACTIVE_GUARD=$!
    deadline=$((SECONDS + LEG_TIMEOUT))
    until [[ -e $RUN_DIR/final-evidence/ready ]]; do
        kill -0 "$ACTIVE_HARNESS" 2>/dev/null || die "$label harness exited before evidence"; ((SECONDS < deadline)) || die "$label evidence timeout"; sleep 1
    done
    [[ $MODE == dhat ]] && allocator=false
    deadline=$((SECONDS + SETTLE_TIMEOUT))
    while ((SECONDS < deadline)); do
        rm -f "$ldir"/metrics-{1,2,3}.prom; printf 'phase\tmonotonic\tutc\nstart\t%s\t%s\n' "$(monotonic)" "$(date -u +%FT%TZ)" >"$ldir/timestamps.tsv"
        for sample in 1 2 3; do
            curl -fsS --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" >"$ldir/metrics-$sample.prom" || break
            printf 'scrape%s\t%s\t%s\n' "$sample" "$(monotonic)" "$(date -u +%FT%TZ)" >>"$ldir/timestamps.tsv"
            ((sample == 3)) || sleep 1
        done
        if validate_scrapes "$mode" "$N_MEMBERS" "$TOTAL_PREFIXES" "$allocator" "$RUN_DIR/config.toml" "$ldir"/metrics-{1,2,3}.prom 2>"$ldir/settle.error"; then accepted=1; break; fi
        sleep 1
    done
    ((accepted == 1)) || { cat "$ldir/settle.error" >&2; die "$label did not quiesce"; }
    capture_roster "$ACTIVE_DAEMON" "$ldir/roster-before.tsv"
    cp "/proc/$ACTIVE_DAEMON/status" "$ldir/root.status"; cp "/proc/$ACTIVE_DAEMON/smaps_rollup" "$ldir/root.smaps_rollup"
    capture_roster "$ACTIVE_DAEMON" "$ldir/roster-after.tsv"
    printf 'capture_end\t%s\t%s\n' "$(monotonic)" "$(date -u +%FT%TZ)" >>"$ldir/timestamps.tsv"
    validate_evidence "$ldir" "$ACTIVE_DAEMON" "$start"
    touch "$RUN_DIR/final-evidence/ack"
    set +e; wait "$ACTIVE_HARNESS"; hrc=$?; set -e; ACTIVE_HARNESS=''
    [[ -z $ACTIVE_GUARD ]] || { wait "$ACTIVE_GUARD" || true; ACTIVE_GUARD=''; }
    ((hrc == 0)) || die "$label harness failed ($hrc)"
    [[ ! -e $ldir/rss.tsv.rss-abort && ! -e $ldir/rss.tsv.identity-abort ]] || die "$label RSS/identity guard aborted"
    [[ $(awk '{print $22}' "/proc/$ACTIVE_DAEMON/stat" 2>/dev/null) == "$start" ]] || die "$label root PID identity changed"
    terminate_group "$ACTIVE_DAEMON"; ACTIVE_DAEMON=''
    if [[ $MODE == dhat ]]; then [[ -s $ldir/dhat-heap.json ]] || die "$label missing graceful DHAT JSON"; validate_dhat "$ldir/dhat-heap.json" "$ldir/dhat"; fi
    (cd "$ldir" && find . -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum) >"$ldir/evidence.sha256"
    jq -n --argjson leg "$number" --arg mode "$mode" --argjson path_hiding "$hiding" --arg dataset "$digest" \
        --arg scenario "$(hash_file "$ldir/scenario.sha256")" --arg evidence "$(hash_file "$ldir/evidence.sha256")" \
        '{status:"pass",leg:$leg,mode:$mode,path_hiding:$path_hiding,add_path:false,admit_churn:false,dataset_sha256:$dataset,scenario_roster_sha256:$scenario,evidence_roster_sha256:$evidence}' >"$ldir/status.json"
    rm -rf "$RUN_DIR"; RUN_DIR=''
}

for index in "${!PROTOCOL[@]}"; do run_leg "$((index+1))" "${PROTOCOL[index]}" "${PATH_HIDING[index]}"; done
[[ $(git -C "$REPO" rev-parse HEAD) == "$COMMIT" && $(dirty_hash) == "$DIRTY_STATE_SHA256" ]] || die "source identity changed during campaign"
jq -n --arg commit "$COMMIT" --arg dirty_state_sha256 "$DIRTY_STATE_SHA256" --arg mode "$MODE" \
    --arg dataset_sha256 "$DATASET" --argjson members "$N_MEMBERS" --argjson total_prefixes "$TOTAL_PREFIXES" \
    --argjson min_list "$MIN_LIST" --argjson max_list "$MAX_LIST" --argjson start_timeout "$START_TIMEOUT" \
    --argjson settle_timeout "$SETTLE_TIMEOUT" --argjson leg_timeout "$LEG_TIMEOUT" --argjson daemon_port "$PORT" --argjson metrics_port "$METRICS_PORT" \
    --argjson legs "$(jq -s '.' "$ART"/*/status.json)" \
    '{commit:$commit,dirty_state_sha256:$dirty_state_sha256,mode:$mode,protocol:["private","grouped","grouped","private"],path_hiding:[true,false,false,true],add_path:false,admit_churn:false,ports:{daemon:$daemon_port,metrics:$metrics_port},shape:{members:$members,total_prefixes:$total_prefixes,min_list:$min_list,max_list:$max_list},timeouts_seconds:{start:$start_timeout,settle:$settle_timeout,leg:$leg_timeout},rss_abort_gib:100,dataset_sha256:$dataset_sha256,preflight:"pass",legs:$legs}' >"$ART/manifest.json"
(cd "$ART" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) >"$ART/SHA256SUMS"
chmod -R a-w "$ART"; trap - EXIT
echo "memory attribution artifact sealed read-only: $ART"
