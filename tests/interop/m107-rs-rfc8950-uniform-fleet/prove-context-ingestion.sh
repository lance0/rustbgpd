#!/usr/bin/env bash
# M107 — prove the template-context ingestion pipeline for the RFC 8950
# uniform-fleet site against the pinned official arouteserver image:
#
#   1. `arouteserver template-context` in the pinned container, from the
#      lab's general.yml/clients.yml (with its bogons.yml and bgpq4 stub);
#   2. `rs-config-render` directly on that dump;
#   3. `rustbgpd --check --strict` + `rbgp policy check` on the rendered
#      output;
#
# and asserts that the fresh dump matches the checked-in
# context-sectioned.yml byte for byte, that it renders identically to the
# hand-authored context.yml (modulo the context-shape fingerprint line),
# and that both renders carry the uniform-fleet shape: both unicast
# families and strict_peer on every IPv6 session.
#
# Self-contained: needs docker, jq, and cargo — no containerlab. The live
# lab is scripts/test-m107-rs-rfc8950-uniform-fleet.sh.
#
# Usage:
#   bash tests/interop/m107-rs-rfc8950-uniform-fleet/prove-context-ingestion.sh

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../../.." && pwd)"

# Same pin as the M90 and M106 labs.
ARS_IMAGE="${M107_ARS_IMAGE:-pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66}"

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

step "rs-config-render on the REAL dump and on the hand-authored context"
cargo run -q -p rs-config-render --manifest-path "$REPO_DIR/Cargo.toml" -- \
    --context "$WORK/out/context.yml" --out-dir "$WORK/render-real" \
    || die "render of the real dump failed"
ok "real dump rendered (exit 0 — no refusal, no implausible set, no shape drift)"
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
ok "receipts agree"

step "the uniform-fleet shape is rendered"
for render in render-real render-hand; do
    [ "$(grep -c '^families = \["ipv4_unicast", "ipv6_unicast"\]$' "$WORK/$render/config.toml")" -eq 2 ] \
        || die "$render config does not carry both unicast families on both IPv6 sessions"
    [ "$(grep -c '^next_hop_ownership = "strict_peer"$' "$WORK/$render/config.toml")" -eq 2 ] \
        || die "$render config does not bind strict_peer on both sessions"
    [ "$(grep -c '^rs_control_communities = false$' "$WORK/$render/config.toml")" -eq 2 ] \
        || die "$render config does not state the control-community knob"
    grep -qx '198.51.100.0/24 le 25' "$WORK/$render/datasets/client-as64500-1-prefixes.list" \
        || die "$render IPv4 route object missing from member1's prefix dataset"
    grep -qx '2001:db8:1::/48' "$WORK/$render/datasets/client-as64500-1-prefixes.list" \
        || die "$render IPv6 route object missing from member1's prefix dataset"
done
ok "both families, strict_peer, explicit control knob, and dual-family datasets on every session"

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
echo "PROOF PASS: $pass checks — the RFC 8950 uniform-fleet site renders from"
echo "the real pinned-image dump and the hand-authored context identically,"
echo "with both unicast families and strict_peer on every IPv6 session."
