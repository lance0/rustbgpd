#!/usr/bin/env bash
# M106 — prove the literal template-context ingestion pipeline for the
# white-list / control-community site (the M90 proof, re-run on this site).
#
# Executes, for real, the exact pipeline the IXP filter cookbook
# advertises, against the pinned official arouteserver image:
#
#   1. `arouteserver template-context` in the pinned container, from
#      the lab's general.yml/clients.yml (with its bogons.yml and
#      bgpq4 stub — the site's AS-SETs are documentation objects);
#   2. `rs-config-render` directly on that dump (the sectioned report
#      arouteserver 1.23.2 emits);
#   3. `rustbgpd --check --strict` + `rbgp policy check` on the rendered
#      output, with the generated `datasets/` tree beside `policy/`;
#
# and asserts:
#   - the fresh dump matches the checked-in context-sectioned.yml
#     fixture byte for byte (the dump is deterministic);
#   - the render of the real dump is identical to the render of the
#     hand-authored single-document context.yml, file by file, modulo
#     the context-shape fingerprint header line (the two input forms
#     legitimately fingerprint differently);
#   - both render receipts carry the same per-client cardinalities,
#     limits, and warnings.
#
# Self-contained: needs docker, jq, and cargo — no containerlab. The
# full differential lab (verdict and export parity against BIRD) is
# scripts/test-m106-rs-white-list-control-differential.sh.
#
# Usage:
#   bash tests/interop/m106-rs-white-list-control-differential/prove-context-ingestion.sh

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../../.." && pwd)"

# Same pin as scripts/test-m90-differential.sh and the M106 driver.
ARS_IMAGE="${M90_ARS_IMAGE:-pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
step() { echo "==> $*"; }
ok() { echo "    ok: $*"; pass=$((pass + 1)); }
die() { echo "    FAIL: $*" >&2; exit 1; }

step "arouteserver template-context (pinned image, real run)"
cp "$LAB_DIR/general.yml" "$LAB_DIR/clients.yml" "$LAB_DIR/bogons.yml" \
    "$LAB_DIR/arouteserver.yml" "$LAB_DIR/bgpq4-stub.sh" "$WORK/"
mkdir -p "$WORK/cache" "$WORK/out"
chmod +x "$WORK/bgpq4-stub.sh"
chmod -R a+rwX "$WORK"
docker run --rm -v "$WORK:/site" "$ARS_IMAGE" \
    arouteserver template-context --cfg /site/arouteserver.yml \
    --output /site/out/context.yml \
    || die "arouteserver template-context failed"
[ -s "$WORK/out/context.yml" ] || die "template-context output missing or empty"
ok "template-context dumped $(wc -l <"$WORK/out/context.yml") lines"

step "fresh dump matches the checked-in sectioned fixture"
diff -u "$LAB_DIR/context-sectioned.yml" "$WORK/out/context.yml" \
    || die "context-sectioned.yml has drifted from what the pinned image emits"
ok "byte-identical to context-sectioned.yml"

step "rs-config-render on the REAL dump"
cargo run -q -p rs-config-render --manifest-path "$REPO_DIR/Cargo.toml" -- \
    --context "$WORK/out/context.yml" --out-dir "$WORK/render-real" \
    || die "render of the real dump failed"
ok "real dump rendered (exit 0 — no refusal, no implausible set, no shape drift)"

step "rs-config-render on the hand-authored single-document context"
cargo run -q -p rs-config-render --manifest-path "$REPO_DIR/Cargo.toml" -- \
    --context "$LAB_DIR/context.yml" --out-dir "$WORK/render-hand" \
    || die "render of the hand-authored context failed"
ok "hand-authored context rendered"

step "renders are identical (modulo the context-shape fingerprint line)"
real_files=$(cd "$WORK/render-real" && find . -type f ! -name render-receipt.json | sort)
hand_files=$(cd "$WORK/render-hand" && find . -type f ! -name render-receipt.json | sort)
[ "$real_files" = "$hand_files" ] || die "file sets differ: [$real_files] vs [$hand_files]"
for f in $real_files; do
    diff -u <(grep -v 'fingerprint' "$WORK/render-real/$f") \
            <(grep -v 'fingerprint' "$WORK/render-hand/$f") \
        || die "render divergence in $f"
    ok "identical: ${f#./}"
done
diff <(jq -S '{clients, warnings}' "$WORK/render-real/render-receipt.json") \
     <(jq -S '{clients, warnings}' "$WORK/render-hand/render-receipt.json") \
    || die "render receipts diverge"
# Load-bearing proof: suppressing shutdown-gated limit emission makes an exact
# receipt/config count below fail; drifting the site
# fixture makes the earlier byte-for-byte pinned-image comparison fail.
for render in render-real render-hand; do
    jq -e \
        '.clients | length == 3 and all(.[]; .max_prefixes_ipv4 == 100 and .max_prefixes_ipv6 == 12000)' \
        "$WORK/$render/render-receipt.json" >/dev/null \
        || die "$render receipt does not carry all three exact 100/12000 limits"
    [ "$(grep -c '^max_prefixes_ipv4 = 100$' "$WORK/$render/config.toml")" -eq 3 ] \
        || die "$render config does not emit exactly three IPv4 limits of 100"
    [ "$(grep -c '^max_prefixes_ipv6 = 12000$' "$WORK/$render/config.toml")" -eq 3 ] \
        || die "$render config does not emit exactly three IPv6 limits of 12000"
    jq -e '
        .schema == "rustbgpd.arouteserver-reject-communities.v1" and
        .peers == ["192.0.2.11", "192.0.2.12", "192.0.2.13"] and
        .std == {"dynamic":"65520:dyn_val","cause_map":{"3":"64512:3"}} and
        .lrg == {"dynamic":"64496:65520:dyn_val","cause_map":{"3":"64496:65521:3"}}
    ' "$WORK/$render/birdwatcher-reject-communities.json" >/dev/null \
        || die "$render reject-community artifact has the wrong peers or configured values"
done
ok "receipts, configs, and startup artifacts carry exact member data"

# Load-bearing for this site: the control matrix keeps the knob on for all
# three members, the white lists reach the datasets and the client policy,
# and the tag is scrubbed in shared hygiene.
for render in render-real render-hand; do
    [ "$(grep -c '^rs_control_communities = true$' "$WORK/$render/config.toml")" -eq 3 ] \
        || die "$render config does not keep rs_control_communities on for all three members"
    grep -qx '198.51.100.128/25 le 32' "$WORK/$render/datasets/client-as64500-1-prefixes.list" \
        || die "$render prefix dataset lacks the white-listed prefix"
    grep -qx '64510' "$WORK/$render/datasets/client-as64500-1-origins.list" \
        || die "$render origin dataset lacks the white-listed origin"
    grep -qF 'term accept-white-list-route-1 { if route.prefix in client-as64501-1-white-list-route-1 && route.origin-as == 64501 { add community 65530:2; add large-community 64496:65530:2; accept } }' \
        "$WORK/$render/policy/client-as64501-1.rpol" \
        || die "$render client policy lacks the tagged white-list accept term"
    grep -qF 'term scrub-white-list-tag { remove community 65530:2; remove large-community 64496:65530:2 }' \
        "$WORK/$render/policy/rs-hygiene.rpol" \
        || die "$render hygiene does not scrub the white-list tag"
    jq -e '[.clients[] | .white_list_routes] == [0, 1, 0]' "$WORK/$render/render-receipt.json" >/dev/null \
        || die "$render receipt does not count exactly one white-listed route for member2"
done
ok "control matrix, white-list members, tagged accept term, and hygiene scrub are rendered"

for render in render-real render-hand; do
    [ "$(find "$WORK/$render/datasets" -type f | wc -l)" -eq 6 ] \
        || die "$render does not carry exactly two datasets for each of three members"
    [ "$(grep -c '^\[policy.datasets.client-' "$WORK/$render/config.toml")" -eq 6 ] \
        || die "$render config does not bind all six per-client datasets"
done
ok "dataset directories and all six relative bindings are retained"

step "pipeline gates on the real-dump render"
cargo run -q -p rustbgpd --manifest-path "$REPO_DIR/Cargo.toml" -- \
    --check --strict "$WORK/render-real/config.toml" \
    || die "rendered config fails rustbgpd --check --strict"
ok "rustbgpd --check --strict passes"
for rpol in "$WORK"/render-real/policy/*.rpol; do
    cargo run -q -p rustbgpctl --bin rbgp --manifest-path "$REPO_DIR/Cargo.toml" -- \
        policy check "$rpol" \
        || die "rbgp policy check failed for $(basename "$rpol")"
    ok "rbgp policy check $(basename "$rpol")"
done

echo
echo "PROOF PASS: $pass checks — the advertised pipeline (arouteserver"
echo "template-context -> rs-config-render -> rustbgpd --check --strict) runs"
echo "end to end on the real pinned image, and both input forms render"
echo "identically."
