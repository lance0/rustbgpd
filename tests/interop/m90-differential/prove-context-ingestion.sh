#!/usr/bin/env bash
# M90 — prove the literal template-context ingestion pipeline.
#
# Executes, for real, the exact pipeline the IXP filter cookbook
# advertises, against the pinned official arouteserver image:
#
#   1. `arouteserver template-context` in the pinned container, from
#      the lab's general.yml/clients.yml (with its bogons.yml and
#      bgpq4 stub — the site's AS-SETs are documentation objects);
#   2. `rs-config-render` directly on that dump (the sectioned report
#      arouteserver 1.23.2 emits);
#   3. `rustbgpd --check` + `rbgp policy check` on the rendered output;
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
# full differential lab (verdict parity against BIRD) is
# scripts/test-m90-differential.sh.
#
# Usage:
#   bash tests/interop/m90-differential/prove-context-ingestion.sh

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../../.." && pwd)"

# Same pin as scripts/test-m90-differential.sh.
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
ok "receipts carry identical clients + warnings"

step "pipeline gates on the real-dump render"
cargo run -q -p rustbgpd --manifest-path "$REPO_DIR/Cargo.toml" -- \
    --check "$WORK/render-real/config.toml" \
    || die "rendered config fails rustbgpd --check"
ok "rustbgpd --check passes"
for rpol in "$WORK"/render-real/policy/*.rpol; do
    cargo run -q -p rustbgpctl --bin rbgp --manifest-path "$REPO_DIR/Cargo.toml" -- \
        policy check "$rpol" \
        || die "rbgp policy check failed for $(basename "$rpol")"
    ok "rbgp policy check $(basename "$rpol")"
done

echo
echo "PROOF PASS: $pass checks — the advertised pipeline (arouteserver"
echo "template-context -> rs-config-render -> rustbgpd --check) runs end to"
echo "end on the real pinned image, and both input forms render identically."
