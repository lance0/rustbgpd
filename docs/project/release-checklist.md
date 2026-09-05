# Release Checklist

> **Document class: REFERENCE.** This maintained page defines a contract, specification, or reusable procedure; follow any stated version scope.

Pre-publish smoke matrix for every tagged release. All items must pass before
pushing a version tag.

---

## Automated (CI)

The core `.github/workflows/ci.yml` and `.github/workflows/interop.yml`
lanes run on qualifying pull requests and main-branch pushes. Both ignore
Markdown-only changes, and interop also ignores the rest of `docs/`. The
specialized lanes below have their own trigger semantics: some are unfiltered,
while others are path-scoped. Confirm every lane applicable to the release
diff actually ran before tagging.

- [ ] `cargo fmt --check`
- [ ] `python3 scripts/check-clippy-reasons.py`
- [ ] `python3 scripts/check-v1-stable-surface.py` — stable config fields and
      object shape, native gRPC signatures/messages, CLI paths/JSON contracts,
      role classifications, compatibility floor, and the consecutive-release
      upgrade receipt still match their machine sources.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo doc --workspace --lib --no-deps --document-private-items`,
      `cargo doc -p rustbgpd --bin rustbgpd --no-deps`, and
      `cargo doc -p rustbgpctl --bin rbgp --no-deps` (warning denial comes from
      `.cargo/config.toml` `build.rustdocflags` — don't set a different
      `RUSTDOCFLAGS` env, it forks the doc-cache fingerprint and forces a
      full workspace re-doc on the next differently-flagged run)
- [ ] **MSRV gate** — `cargo check --workspace --all-targets` at the
      declared `rust-version` (kept in lockstep with the Dockerfile
      builder version)
- [ ] **Published-crate README freshness gate** — if the independently
      versioned manifest for `wire`, `fsm`, or `rpki` changed in the diff, the
      matching crate README must also be touched
- [ ] **Gate 8b BUM-filter kernel primitive**
      (`evpn_bum_filter_kernel` job) — runs the netns harness under
      `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN
      --security-opt apparmor=unconfined` against `ubuntu-latest`'s
      6.x kernel
- [ ] **Interop tier** — the PR-gated foundation interop jobs in
      `.github/workflows/interop.yml` (against FRR 10.7.1 via
      containerlab) are green; that workflow is the authoritative job
      set, so check it rather than re-listing M-numbers here.
- [ ] **Public docs contract** — `.github/workflows/public-docs-contract.yml`
      is green. It runs unfiltered on every pull request and main-branch push,
      covering metric consumers, public tracker-ID and artifact-home-path
      hygiene, pinned IXP Manager docs, and release-checklist source paths.
- [ ] **Embedding docs contract** — the `embedding-doc-contract` matrix job in
      `.github/workflows/public-docs-contract.yml` is green. Its two
      seconds-cheap Python checks now run unfiltered beside the public-docs
      contract on every pull request and main-branch push.
- [ ] **Published-crate semver contract** — when `crates/wire/`, `crates/fsm/`,
      or `crates/rpki/` changed, `.github/workflows/semver-checks.yml` is green
      for the pull request or a manual dispatch at the release commit. It is
      path-scoped on pull requests to those crate trees, its tested derivation
      helper, and its own workflow; it has no push trigger. The exact RPKI
      `0.1.0` first-publish exception applies only while crates.io returns 404
      for the name and becomes an ordinary registry baseline automatically
      once that normal release is visible.
- [ ] **IXP Manager / Bird's Eye contract** — when the IXP Manager,
      Bird's Eye, renderer, adapter, or interop-doc surface changed,
      `.github/workflows/ixp-compat.yml` ran and is green. It is path-scoped on
      pull requests and main-branch pushes and also supports manual dispatch,
      so confirm the applicable run instead of assuming a green tag build
      covered it.

## Documentation hygiene

Before tagging, skim the release and tracking docs for the low-conflict
convention in `CONTRIBUTING.md`:

- [ ] `CHANGELOG.md` `[Unreleased]` entries are in the right subsections and
      read as compact per-PR entries rather than broad rewrites of older
      shipped text.
- [ ] `docs/project/roadmap.md` has one row or checkbox per remaining concern; shipped
      slices say what landed and what remains.
- [ ] Hot tracking docs such as `docs/how-to/evpn-alpha-soak.md` and
      `docs/project/evpn-enablement.md` update exact gates/rows instead of rewriting
      unrelated summary prose.
- [ ] New config knobs follow
      [`docs/how-to/config-knob-contributor-guide.md`](../how-to/config-knob-contributor-guide.md):
      schema, validation, reload matrix, runtime consumption, persistence,
      docs, and tests all move together.
- [ ] Process-only documentation changes intentionally omit CHANGELOG entries
      unless they affect users or operators.
- [ ] Every front-door performance claim inventoried in
      [`docs/perf/receipt-provenance.json`](../perf/receipt-provenance.json) — in
      `docs/perf/README.md`, `docs/benchmarks.md`, `docs/explanation/comparison.md`, or
      `docs/explanation/ixp-evaluation.md` — cites a receipt measured within the last three
      releases, or carries an explicit measured-on date in the claim text
      (e.g. "measured 2026-07-03"). Older numbers stay quotable with their
      date; undated stale numbers do not ship. The public-docs contract checks
      every receipt link in those curated headline blocks against the manifest,
      plus commit/tag provenance and this freshness rule. The manifest does not
      catalog the whole performance corpus; the checker's sorted
      zero-inbound-link inventory covers all top-level receipts as an advisory
      so discoverability is not conflated with measurement validity.
- [ ] Cross-daemon performance claims name each comparator release and its
      release date. If a newer comparator release exists at review time,
      either refresh the affected cells or disclose the newer release beside
      the dated historical result.

## Narrow v1 RS/RR compatibility gate

The project remains public alpha outside the explicit
[`rustbgpd-rs-rr-v1`](../reference/v1-stable-contract.md) inventory. Before tagging:

- [ ] Review every change to `docs/reference/v1-stable-surface.json` as a product
      compatibility decision, not a checksum refresh. No shipped alpha or
      experimental feature becomes stable merely because it exists.
- [ ] Stable protobuf changes are additive; removed numbers/names remain
      reserved. Any changed stable service-signature digest has an explicit
      compatibility review.
- [ ] Stable config changes preserve names, types, effective defaults,
      required-field membership, and unknown-field handling, or carry the
      documented deprecation and migration window. Additive optional siblings
      remain permitted.
- [ ] rpol golden decision compatibility, stable metric names/types/label
      meanings, and stable event/JSON field meanings remain intact.
- [ ] The transaction path remains canonical for live compound mutation.
      SIGHUP wording remains file-driven reconcile with reload-matrix behavior,
      not an atomic compound-mutation guarantee.
- [ ] At least one consecutive-release upgrade fixture is accepted by the new
      release. The latest receipt must end at the workspace release-line anchor
      (`vMAJOR.MINOR.0`), while `baseline_release` must match the exact workspace
      version. Receipts form one contiguous chain of adjacent minor release
      lines from the canonical `v0.50.0` history origin, with an explicit
      transition into a new major; immutable files must still match their source
      git tag. The current workspace target is proven by its parser test before
      tagging; both tags are required once an exercise is historical. Add a new
      receipt for a real migration; do not overwrite older evidence.
- [ ] Inventoried CLI commands preserve their path and command name. Flags,
      positional arguments, defaults, exit behavior, and human output are not
      covered unless separately inventoried.

## gRPC authorization surface (per-release gate)

The `crates/api/src/authz.rs` `METHODS` matrix is the code-level source
of truth for per-method risk tiers (ADR-0064). The matrix tests prove
the matrix and the proto stay in sync and that the counts match the
published inventory — but they **cannot** prove a tier assignment is
*correct*, only that one exists. Tier correctness is a release-review
judgment. Before tagging, for every method added since the last
release:

- [ ] `cargo test -p rustbgpd-api authz` is green — this enforces:
      matrix ↔ `proto/rustbgpd.proto` membership (every RPC covered
      exactly once), `docs/reference/grpc-method-inventory.json` matches the
      matrix, `docs/reference/grpc-method-inventory.md` matches the `.json` in
      both directions, and the per-tier counts match.
- [ ] `docs/reference/grpc-method-inventory.md` was regenerated by hand to match
      the `.json`. Both are fenced to each other by the test above, so a
      forgotten regeneration fails the build instead of drifting
      silently.
- [ ] **No method sits at `read` unless it is pure liveness with zero
      topology / route / policy / state disclosure.** The tier is
      currently empty by design — anything read-only that exposes the
      network belongs at `sensitive_read`. A new method landing at
      `read` is the most likely under-tiering mistake; scrutinize it.
- [ ] **Every event / explain / route-listing surface is
      `sensitive_read`+** — `WatchEvents`, `SubscribeFromEvent`,
      `List*Events`, `Explain*`, `List*Routes`, gNMI `Subscribe`. These
      disclose routing, topology, or decision detail and must never be
      `read`.
- [ ] **Anything that injects into the dataplane/network, mutates
      process-wide or daemon-wide state, or is otherwise high-blast is
      `operator_only`** — route/FlowSpec/EVPN injection, `SetGlobal*`,
      global policy chains, `Shutdown`, `SetGracefulShutdown`.
- [ ] **Dataplane-programming guardrail.** Any *new* RPC that programs
      the kernel dataplane (FIB / VXLAN / FDB / L3VNI / nexthop groups)
      must have its tier **explicitly justified in review** — it must
      not land in `mutating` by inattention. Three methods deliberately
      sit at `Mutating` despite touching the kernel dataplane, each
      guarded by a tier-pin test in `crates/api/src/authz.rs`:
      - `EvpnService/ApplyEvpnRuntime` — ADR-0063 v1 is a single
        validated, additive L2VNI/IP-VRF apply (the EVPN sibling of
        `AddNeighbor`). If its scope widens past single-add (issue
        #210), re-evaluate its tier via an ADR update — not the pin.
      - `RibService/SetFibTable` and `RibService/DeleteFibTable` —
        validated, SIGHUP-serialized, reconciler-acked, persisted
        config-surface mutations that back-fill already-learned routes
        (the unicast sibling of dynamic-neighbor CRUD), *not*
        operator-authored injection.
        **ADR-0074** records this decision and explicitly considered and
        rejected a dedicated `dataplane_mutating` tier (no ADR-0064 role
        maps to it; `operator_only` would over-grant FIB automation). If
        their scope widens past back-filling learned routes, re-evaluate
        via an ADR-0074 update — not the pin.

      For any *fourth* such method, start from ADR-0074's split: a
      validated, persisted config surface that directs already-learned
      routes may still fit `mutating`; operator-authored injection is
      `operator_only`. Reach for a dedicated `dataplane_mutating` tier
      (captured in an ADR) only if a real case falls cleanly between
      those two.
- [ ] **Tier ↔ role boundary is intentional** — recall
      `Observer ≤ sensitive_read`, `Automation ≤ mutating`,
      `Operator ≤ operator_only`. Ask: should the Automation role be
      able to call this new method unattended? If not, it is not
      `mutating`.

## Manual smoke tests

Run these from a clean build (`cargo build --workspace --release`) before
tagging. The `--workspace` flag is required to build both `rustbgpd` and
`rbgp`.

### CLI smoke

The minimal example binds BGP port 179, and the daemon exits when the
listener cannot bind on either family — on an unprivileged runner, grant
the freshly built binary `CAP_NET_BIND_SERVICE`
(`sudo setcap cap_net_bind_service=+ep target/release/rustbgpd`) or run
the smoke against a copy of the config with an unprivileged
`listen_port` (>= 1024).

```bash
# Build both binaries
cargo build --workspace --release

# Start daemon with minimal config
./target/release/rustbgpd examples/minimal/config.toml &
DAEMON_PID=$!
sleep 2

# Verify CLI commands parse and connect
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock
./target/release/rbgp health
./target/release/rbgp global
./target/release/rbgp neighbor
./target/release/rbgp rib
./target/release/rbgp metrics

kill $DAEMON_PID
```

### Config-init smoke

Every shipped starter — all `--init-config` profiles and every config
under `examples/` — must pass `rustbgpd --check --strict`, exit 0, summary
`config OK`. Shipping a starter that trips our own unpoliced-eBGP warning
teaches the operator who runs it first that the warning is noise. Permit-all
starters stay permit-all; they say so in an explicit chain instead of by
omission.

```bash
# Each built-in profile emits a starter config that passes the strict gate.
for p in lab edge route-server; do
  ./target/release/rustbgpd --init-config "$p" > "/tmp/init-$p.toml"
  ./target/release/rustbgpd --check --strict "/tmp/init-$p.toml"  # expect: config OK
done

# Every example config, checked in place so relative `rpol_files` resolve.
for c in examples/*/config.toml; do
  ./target/release/rustbgpd --check --strict "$c"                 # expect: config OK
done

# The compose starter (examples/docker-compose/rustbgpd.toml) names a token
# path that only exists inside the container; repoint it to check it here.
sed "s#/run/rustbgpd/grpc-test-only-operator.token#$PWD/tests/fixtures/grpc-test-only-operator.token#" \
  examples/docker-compose/rustbgpd.toml > /tmp/compose-check.toml
./target/release/rustbgpd --check --strict /tmp/compose-check.toml # expect: config OK

# Guards must exit non-zero:
./target/release/rustbgpd --stdout                              # --stdout without --init-config
./target/release/rustbgpd --init-config lab --check x           # --init-config combined with --check/--diff
./target/release/rustbgpd --strict /tmp/init-lab.toml           # --strict without --check
```

### README demo smoke

Walk the [README demo](../../README.md#try-it-locally) from a clean clone and confirm:

- `docker compose up -d --build` builds and starts both services
- `rbgp summary` shows the FRR session established
- `rbgp top` opens and the sample prefix's best-path explain succeeds
- `docker compose down` stops the demo

### Host quickstart smoke

Walk the [host quickstart](../tutorials/quickstart.md) and confirm:

- the minimal config validates with `--check`
- the daemon creates the UDS socket under `/tmp/rustbgpd`
- `rbgp health`, `global`, and `neighbor` succeed with `RUSTBGPD_ADDR`
- no undocumented prerequisite or manual workaround is needed

### UDS default smoke

Verify the daemon creates the gRPC socket at the configured
`runtime_state_dir`:

```bash
ls -la /tmp/rustbgpd/grpc.sock   # should exist after daemon start
```

### EVPN Linux netns smoke

On a Linux host with iproute2, `ping`, and namespace privileges
(`CAP_NET_ADMIN` + `CAP_SYS_ADMIN`), run the privileged EVPN Linux
bundle:

```bash
sudo -E env "PATH=$PATH" bash scripts/test-evpn-linux-netns.sh
```

This wrapper runs the gated BUM, single-dst VTEP FDB, L3, FDB-NHG,
and raw `nexthop_raw` netns tests sequentially with
`EVPN_LINUX_NETNS=1`. If prerequisites are missing, it exits before
cargo with the failing `ip netns add` diagnostic.

### Token auth smoke

```bash
set -euo pipefail

echo "test-token-value" > /tmp/rustbgpd-token
cat > /tmp/rustbgpd-auth-test.toml <<'EOF'
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 1179
runtime_state_dir = "/tmp/rustbgpd-auth"

[global.telemetry]
prometheus_addr = "127.0.0.1:19179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-auth/grpc.sock"
token_file = "/tmp/rustbgpd-token"
principal = "release-smoke-observer"

# Omit explicit enforcement so the smoke exercises the Tier default.
[security.grpc.roles]
"release-smoke-observer" = "observer"
EOF

cleanup_grpc_auth_smoke() {
  if [ -n "${DAEMON_PID:-}" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf /tmp/rustbgpd-auth /tmp/rustbgpd-token \
    /tmp/rustbgpd-auth-test.toml /tmp/rustbgpd-auth-unauthenticated.log \
    /tmp/rustbgpd-auth-mrt-denied.log
}
trap cleanup_grpc_auth_smoke EXIT

./target/release/rustbgpd --check --strict /tmp/rustbgpd-auth-test.toml
./target/release/rustbgpd /tmp/rustbgpd-auth-test.toml &
DAEMON_PID=$!
sleep 2

# Without token — must fail authentication.
if ./target/release/rbgp -s unix:///tmp/rustbgpd-auth/grpc.sock health \
  >/tmp/rustbgpd-auth-unauthenticated.log 2>&1; then
  echo "unauthenticated health unexpectedly succeeded" >&2
  exit 1
fi
grep -qi "unauthenticated" /tmp/rustbgpd-auth-unauthenticated.log

# With token — health is within the observer role and must succeed.
./target/release/rbgp -s unix:///tmp/rustbgpd-auth/grpc.sock --token-file /tmp/rustbgpd-token health

# The same authenticated observer must be denied the operator-only MRT trigger.
if ./target/release/rbgp -s unix:///tmp/rustbgpd-auth/grpc.sock \
  --token-file /tmp/rustbgpd-token mrt-dump \
  >/tmp/rustbgpd-auth-mrt-denied.log 2>&1; then
  echo "observer mrt-dump unexpectedly succeeded" >&2
  exit 1
fi
grep -qi "permission denied" /tmp/rustbgpd-auth-mrt-denied.log
```

### gRPC authorization audit smoke

When ADR-0064 changes land, capture one request against a test listener and
confirm both audit surfaces move:

```bash
# With the token-auth daemon above still running:
./target/release/rbgp -s unix:///tmp/rustbgpd-auth/grpc.sock \
  --token-file /tmp/rustbgpd-token health

# Logs should include target="grpc_authz" with path, tier, result, authn,
# access_mode, and principal fields.

# Metrics should expose bounded-label decision counters, with no method path or
# principal labels:
curl -fsS http://127.0.0.1:19179/metrics | grep bgp_grpc_authz_decisions_total

# Cleanup only after the audit smoke has consumed the running daemon.
cleanup_grpc_auth_smoke
trap - EXIT
```

For external audit prep, verify the published inventory is still fenced to the
tiers the daemon enforces. `markdown_inventory_matches_machine_readable_export`
compares the per-service tables and totals of `docs/reference/grpc-method-inventory.md`
against `docs/reference/grpc-method-inventory.json` in both directions, and
`machine_readable_inventory_matches_method_matrix` compares that export against
the `METHODS` matrix, so neither published form can drift from the code without
failing:

```bash
cargo test -p rustbgpd-api authz
```

`docs/adr/0064-threat-model.md` is prose, so the structural inventory tests do
not prove its attacker assumptions or risk rankings. Review its authorization
path and residual-risk claims against the source paths named in its
**Evidence and review focus** section; do not substitute a non-empty-file check
for that review.

### Interop smoke (requires Docker + containerlab)

The following source-to-proof map is a release contract, not a summary of the
hosted workflow. `scripts/check_release_checklist_paths.py` validates both the
owner-to-proof assignments and the proof source paths. These owners cross
module boundaries: changing the shared drain primitive requires both drain
proofs, while changing the segment actor requires the DF-election proof and
both drain proofs. The hosted `Kernel Dataplane` workflow's unfiltered manual
dispatch remains the defense-in-depth full sweep.

| Source owner | Required release proofs |
| --- | --- |
| `src/evpn_es_drain.rs` | M66, M67 |
| `src/evpn_es_link_drain.rs` | M67 |
| `src/evpn_segment.rs` | M38, M66, M67 |

| Release proof | Topology | Assertion script |
| --- | --- | --- |
| `M38` | `tests/interop/m38-evpn-df-election.clab.yml` | `tests/interop/scripts/test-m38-evpn-df-election.sh` |
| `M66` | `tests/interop/m66-evpn-es-drain-handover.clab.yml` | `tests/interop/scripts/test-m66-evpn-es-drain-handover.sh` |
| `M67` | `tests/interop/m67-evpn-link-drain-failover.clab.yml` | `tests/interop/scripts/test-m67-evpn-link-drain-failover.sh` |

Run at least one from each category:

```bash
docker build --target dev -t rustbgpd:dev .

# Basic eBGP + RIB
containerlab deploy -t tests/interop/m4-frr.clab.yml
bash tests/interop/scripts/test-m4-frr.sh
containerlab destroy -t tests/interop/m4-frr.clab.yml

# Route server + policy
containerlab deploy -t tests/interop/m13-policy-frr.clab.yml
bash tests/interop/scripts/test-m13-policy-frr.sh
containerlab destroy -t tests/interop/m13-policy-frr.clab.yml

# Graceful Restart
containerlab deploy -t tests/interop/m11-gr-frr.clab.yml
bash tests/interop/scripts/test-m11-gr-frr.sh
containerlab destroy -t tests/interop/m11-gr-frr.clab.yml

# Extended next-hop / IPv6 export path
containerlab deploy -t tests/interop/m18-extnexthop-frr.clab.yml
bash tests/interop/scripts/test-m18-extnexthop-frr.sh
containerlab destroy -t tests/interop/m18-extnexthop-frr.clab.yml
```

If the release touches LLGR capability, negotiation, retained-route lifecycle,
or outbound rewriting (`crates/wire/src/capability.rs`,
`crates/fsm/src/config.rs`, `crates/fsm/src/negotiation.rs`,
`crates/rib/src/manager/graceful_restart.rs`,
`crates/rib/src/manager/peer_lifecycle.rs`, or
`crates/transport/src/session/export.rs`), also run:

```bash
containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml
bash tests/interop/scripts/test-m16-llgr-frr.sh
containerlab destroy -t tests/interop/m16-llgr-frr.clab.yml
```

If the release includes EVPN changes (any commit touching
`crates/wire/src/evpn.rs`, `crates/wire/src/pmsi.rs`, EVPN paths in
`crates/rib/src/`, the EVPN gRPC surface, `crates/evpn-linux/src/`,
`crates/evpn/src/origination.rs`, `src/evpn_dataplane.rs`,
`src/evpn_originator/`, or `src/evpn_imet.rs`), run at least one of
M29 (capability sanity) or M30 (real Type 2 reflection). Run M33
(scale) before any release that claims new performance numbers:

```bash
# Capability sanity — fastest EVPN smoke
containerlab deploy -t tests/interop/m29-evpn-rr-frr.clab.yml
bash tests/interop/scripts/test-m29-evpn-rr-frr.sh
containerlab destroy -t tests/interop/m29-evpn-rr-frr.clab.yml

# Real Type 2 MAC reflection through kernel VXLAN — full RR confidence
containerlab deploy -t tests/interop/m30-evpn-type2-frr.clab.yml
bash tests/interop/scripts/test-m30-evpn-type2-frr.sh
containerlab destroy -t tests/interop/m30-evpn-type2-frr.clab.yml

# Scale + churn (50k Type 2 routes, in-tree load generator)
containerlab deploy -t tests/interop/m33-evpn-scale.clab.yml
bash tests/interop/scripts/test-m33-evpn-scale.sh
containerlab destroy -t tests/interop/m33-evpn-scale.clab.yml --cleanup
```

If the release touches the **VTEP dataplane** (`crates/evpn-linux/`)
or **local-MAC origination** (`crates/evpn/src/origination.rs`,
`src/evpn_originator/`, `src/evpn_imet.rs`,
`crates/wire/src/pmsi.rs`), additionally run M36 (downward, Gate 7b)
and M37 (upward, Gate 7b+1) before tagging. If it touches the
**ADR-0079 adoption/reap sweep** (`crates/evpn-linux/src/reconcile.rs`),
M60 (kill-and-restart FDB adoption sweep) and M61 (kill-and-restart
L3 adoption sweep) run in the hosted `Kernel Dataplane` workflow and
can be reproduced manually the same way. M36 and M37 run in the hosted
`Kernel Dataplane` workflow; manual reproduction still requires
`CAP_NET_ADMIN` or a privileged runner:

```bash
# Build the daemon image (bidirectional VTEP needs CAP_NET_ADMIN)
docker build --target dev -t rustbgpd:dev .

# M36 — Gate 7b downward path: rustbgpd-as-VTEP, FRR-as-originator
containerlab deploy -t tests/interop/m36-evpn-vtep-smoke.clab.yml
bash tests/interop/scripts/test-m36-evpn-vtep-smoke.sh
containerlab destroy -t tests/interop/m36-evpn-vtep-smoke.clab.yml

# M37 — Gate 7b+1 upward path: rustbgpd-as-originator, FRR-as-consumer
# Validates ADR-0055 §1-§6 end-to-end (RTNLGRP_NEIGH classifier,
# Type 2 origination per RFC 7432 §15.1, Type 3 IMET with PMSI Tunnel
# label = raw 24-bit VNI per RFC 8365 §5.1.3, shutdown drain ordering)
containerlab deploy -t tests/interop/m37-evpn-local-origination.clab.yml
bash tests/interop/scripts/test-m37-evpn-local-origination.sh
containerlab destroy -t tests/interop/m37-evpn-local-origination.clab.yml
```

If the release touches **Gate 7b+2** (MAC-with-IP Type 2 via ARP/ND
suppression — `crates/evpn/src/origination_macip.rs`), also run
M37+IP. If the release touches **Gate 8 / 8b** (Type 1/4 origination
in `crates/evpn/src/origination_es.rs`, DF election in
`crates/evpn/src/df_election.rs`, ESI Label / ES-Import RT extcomms,
aliasing in `crates/evpn/src/aliasing.rs`, receive-side mass-withdraw
projection and BUM-port supervision in `src/evpn_dataplane.rs`, or
BUM-port intent/enforcement in `crates/evpn/src/dataplane.rs`,
`src/evpn_segment.rs`,
`crates/evpn-linux/src/bum_filter.rs`,
`crates/evpn-linux/src/enforcement.rs`, or
`crates/evpn-linux/src/reconcile.rs`), run M38
to validate DF election + Type 1/4 origination against a peer running
the same code; the source-to-proof map above adds M66/M67 where the daemon
owner also crosses a drain boundary. If the release touches **Gate 9 /
ADR-0059 / ADR-0087 / ADR-0090** (IP-VRF, Type 5, L3 FIB programming,
overlay-index recursion/origination, aliasing ECMP, or FDB nexthop groups),
run the hosted
`Kernel Dataplane` workflow for M39, M40, M68, M71, and future M72 as
appropriate. If it touches
**ADR-0089 VLAN-aware bridge or SVD programming**, also require M70 plus
the `dataplane_vlan_fdb` and `svd_fdb_vni` netns selectors. They can still be
reproduced manually with:

```bash
# M37+IP — Gate 7b+2 MAC-with-IP Type 2 via ARP/ND suppression
containerlab deploy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml
bash tests/interop/scripts/test-m37-evpn-mac-ip-origination.sh
containerlab destroy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml

# M38 — Gate 8 observable DF election with two VTEPs sharing an ESI
containerlab deploy -t tests/interop/m38-evpn-df-election.clab.yml
bash tests/interop/scripts/test-m38-evpn-df-election.sh
containerlab destroy -t tests/interop/m38-evpn-df-election.clab.yml

# M39 — Gate 9 symmetric Interface-less IRB Type 5 datapath
containerlab deploy -t tests/interop/m39-evpn-type5-symmetric-irb.clab.yml
bash tests/interop/scripts/test-m39-evpn-type5-symmetric-irb.sh
containerlab destroy -t tests/interop/m39-evpn-type5-symmetric-irb.clab.yml

# M40 — ADR-0059 aliasing ECMP via FDB nexthop groups
containerlab deploy -t tests/interop/m40-evpn-aliasing-ecmp-frr.clab.yml
bash tests/interop/scripts/test-m40-evpn-aliasing-ecmp-frr.sh
containerlab destroy -t tests/interop/m40-evpn-aliasing-ecmp-frr.clab.yml

# M68 — ADR-0087 GW-IP overlay-index Type 5 consumed by FRR
containerlab deploy -t tests/interop/m68-evpn-type5-gwip-overlay-index-frr.clab.yml
bash tests/interop/scripts/test-m68-evpn-type5-gwip-overlay-index-frr.sh
containerlab destroy -t tests/interop/m68-evpn-type5-gwip-overlay-index-frr.clab.yml

# M70 — ADR-0089 VLAN-aware bridge FDB attribution consumed from FRR
containerlab deploy -t tests/interop/m70-evpn-vlan-aware-bridge-frr.clab.yml
bash tests/interop/scripts/test-m70-evpn-vlan-aware-bridge-frr.sh
containerlab destroy -t tests/interop/m70-evpn-vlan-aware-bridge-frr.clab.yml --cleanup

# M71 — RFC 9136 §4.3 ESI overlay-index Type 5 single-active receive
containerlab deploy -t tests/interop/m71-evpn-esi-overlay-type5-receive-gobgp.clab.yml
bash tests/interop/scripts/test-m71-evpn-esi-overlay-type5-receive-gobgp.sh
containerlab destroy -t tests/interop/m71-evpn-esi-overlay-type5-receive-gobgp.clab.yml --cleanup
```

If the release touches **ADR-0061 / ADR-0066 / ADR-0068 general unicast FIB**
(`src/fib.rs`, `src/fib_runtime.rs`, `[[fib_tables]]`, `ListFibRoutes`,
`rbgp rib fib`, ECMP caps, `multipath_relax`, or weighted multipath), run
the hosted `Kernel Dataplane` workflow for the relevant FIB suites: M42 for
base configured-table install, M50 for ECMP, and M52 for multipath-relax. Manual
reproduction:

```bash
# M42 — ADR-0061 configured-table unicast Linux FIB runtime
docker build --target dev -t rustbgpd:dev .
containerlab deploy -t tests/interop/m42-fib-runtime-frr.clab.yml
bash tests/interop/scripts/test-m42-fib-runtime-frr.sh
containerlab destroy -t tests/interop/m42-fib-runtime-frr.clab.yml

# M50 — ADR-0066 ECMP FIB install
containerlab deploy -t tests/interop/m50-fib-ecmp-frr.clab.yml
bash tests/interop/scripts/test-m50-fib-ecmp-frr.sh
containerlab destroy -t tests/interop/m50-fib-ecmp-frr.clab.yml

# M52 — ADR-0066 multipath-relax
containerlab deploy -t tests/interop/m52-fib-ecmp-relax-frr.clab.yml
bash tests/interop/scripts/test-m52-fib-ecmp-relax-frr.sh
containerlab destroy -t tests/interop/m52-fib-ecmp-relax-frr.clab.yml
```

If the release touches **ADR-0067 BFD** (`crates/bfd`, `src/bfd_runtime.rs`,
`[[bfd_profiles]]`, `[neighbors.bfd]`, `BfdService`, `rbgp bfd`, or BFD
events / coupling), run the hosted `Kernel Dataplane` workflow for M51 and
M108.
Manual reproduction:

```bash
# M51 — single-hop BFD + RFC 5882 coupling against FRR bfdd
docker build --target dev -t rustbgpd:dev .
containerlab deploy -t tests/interop/m51-bfd-frr.clab.yml
bash tests/interop/scripts/test-m51-bfd-frr.sh
containerlab destroy -t tests/interop/m51-bfd-frr.clab.yml

# M108 — multihop BFD over routed loopbacks + RFC 5882 coupling
containerlab deploy -t tests/interop/m108-bfd-multihop-frr.clab.yml
bash tests/interop/scripts/test-m108-bfd-multihop-frr.sh
containerlab destroy -t tests/interop/m108-bfd-multihop-frr.clab.yml --cleanup
```

Also smoke the controller-injection path against a live RR (M30
container is fine):

```bash
# Inject a Type 2 route via gRPC, list it back, withdraw it
RR_ADDR=$(docker inspect clab-m30-evpn-type2-frr-rustbgpd \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'):50051
./target/release/rbgp -s "$RR_ADDR" evpn add-mac-ip \
  --rd 65000:100 --mac 02:00:00:aa:bb:cc \
  --label 100 --next-hop 10.0.0.1
./target/release/rbgp -s "$RR_ADDR" evpn --route-type 2
./target/release/rbgp -s "$RR_ADDR" evpn delete-mac-ip \
  --rd 65000:100 --mac 02:00:00:aa:bb:cc
```

If the release includes RPKI/RTR, FlowSpec, or best-path explain changes:

```bash
# RPKI/RTR cache interop (requires rpki/stayrtr:latest)
containerlab deploy -t tests/interop/m21-rpki-frr.clab.yml
bash tests/interop/scripts/test-m21-rpki-frr.sh
containerlab destroy -t tests/interop/m21-rpki-frr.clab.yml

# FlowSpec injection + distribution
containerlab deploy -t tests/interop/m22-flowspec-frr.clab.yml
bash tests/interop/scripts/test-m22-flowspec-frr.sh
containerlab destroy -t tests/interop/m22-flowspec-frr.clab.yml

# GoBGP peer (requires gobgp:interop image)
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop/
containerlab deploy -t tests/interop/m23-gobgp.clab.yml
bash tests/interop/scripts/test-m23-gobgp.sh
containerlab destroy -t tests/interop/m23-gobgp.clab.yml
```

### Docker smoke

```bash
docker build --target dev -t rustbgpd:dev .

# Verify shipped binaries are present
docker run --rm --entrypoint sh rustbgpd:dev -c \
  "ls /usr/local/bin/rustbgpd /usr/local/bin/rbgp"

# Verify rbgp parses subcommands
docker run --rm --entrypoint rbgp rustbgpd:dev --help
```

## Release steps

### Daemon release

Before rolling any versions:

- [ ] Create a dedicated `### Upgrade notes` group in the new `CHANGELOG.md`
      release section for consumer- and operator-visible semantic changes.
- [ ] Review the complete `<prev-tag>..HEAD` range for that group.
      `**Operator-visible:**` entries are inputs, not an exhaustive index;
      also capture unmarked changes such as silent semantic reinterpretations
      and removed metric-label series.
- [ ] Preview the release workflow's extracted and reflowed GitHub release body
      and confirm it preserves the `### Upgrade notes` heading and its entries.

1. Update `CHANGELOG.md` with the new version section
2. **Verify changelog completeness**: run `git log <prev-tag>..HEAD --oneline`
   and confirm every user-visible change (features, fixes, interop suites) is
   listed under the new version — not misattributed to a prior release. Check
   that current capability and version claims in README.md and docs/project/roadmap.md
   match the release. Keep the README stability baseline tied to the contract,
   not the latest daemon version; preserve dated historical records. Also
   sweep `(post-vX.Y.Z)` annotations in docs/project/roadmap.md.
3. Bump versions:
   - Root `Cargo.toml`: move `[workspace.package] version` and every
     daemon-line internal `rustbgpd-*` pin in `[workspace.dependencies]` to
     the new workspace version. Keep the independently versioned
     `rustbgpd-wire`, `rustbgpd-fsm`, and `rustbgpd-rpki` pins at the versions
     selected by their own crate manifests and release steps; never align them
     to the daemon workspace bump. Retain both `path` and `version` so
     downstream publish dry-runs resolve from crates.io.
   - `crates/wire/Cargo.toml`: bump **only** if `crates/wire/src/` changed
     since the last wire publish (see semver rules in the next section).
     Land the wire bump in its **own commit** before the workspace bump so
     the wire publish is reproducible from the commit alone.
4. Run the full checklist above (fmt, clippy `-D warnings`, test, doc
   `-D warnings`, release build)
5. Commit the final release candidate (workspace):
   `release: prep vX.Y.Z — bump workspace, roll CHANGELOG`
6. Push the final release candidate to `main`: `git push origin main`.
7. Wait for every applicable gate to pass on that exact final `main` SHA.
   When an independently published crate changed, manually dispatch
   `semver-checks.yml` at the release commit because it has no push trigger.
   - If this cycle touched `.github/workflows/release.yml`, run the
     dispatch dry-run to green in this step, after the workflow change is on
     `main`: `gh workflow run release.yml -f dry_run=true`. Workflow edits
     otherwise meet their first execution on the live tag.
8. Create and push the **annotated** tag only after step 7 is green
   (lightweight tags break the release-history convention here):
   `git tag -a vX.Y.Z -m "vX.Y.Z — <one-line headline>"`, then
   `git push origin vX.Y.Z`.
9. Confirm the annotated tag resolves to the exact main commit whose
   applicable CI, interop, documentation, security, and install-contract
   workflows were already green; those main-only workflows do not rerun for a
   tag. Then verify both tag-triggered publication workflows pass: **Release
   Binaries** (`release.yml`, including the x86_64 + aarch64 build matrix,
   artifacts, and GitHub Release) and **Container Image** (`container.yml`,
   including native amd64 + arm64 runtime verification and the GHCR manifest
   push). Both are fail-closed: each gates publication on a
   `verify-tag-version` job (tag `vX.Y.Z` must equal the workspace
   `[workspace.package]` version) and a `test` job (`cargo test --workspace` on
   the tagged commit). If you tagged a commit without the version bump, the tag
   build fails and publishes nothing — fix the bump, delete the tag, and
   re-tag.
10. **Verify container image published to GHCR** via `docker/metadata-action`'s
   semver pattern:
   - `ghcr.io/lance0/rustbgpd:X.Y.Z` (exact, immutable)
   - `ghcr.io/lance0/rustbgpd:X.Y` (rolls forward within the minor)
   - `ghcr.io/lance0/rustbgpd:latest` (auto-published for non-prerelease
     tags via the action's default `latest=auto` flavor)
   These **container-image** tags are emitted **without** the `v` prefix —
   `0.45.0`, not `v0.45.0` (`docker/metadata-action` strips it). The **git tag
   stays `vX.Y.Z`** (step 8); only the image tag drops the `v`. The container
   workflow must show both native architecture jobs green and the published
   manifest must contain exactly `linux/amd64` and `linux/arm64`. When
   `.github/workflows/container.yml` changes, dispatch it from `main` with
   `dry_run=true` before the next tag; dispatches build, load, and runtime-check
   both architectures but cannot authenticate to GHCR or publish.
11. **Verify release tarballs and packages** under
    [GitHub Releases](https://github.com/lance0/rustbgpd/releases) — each
    tag should publish version-less `rustbgpd-linux-amd64.tar.gz` and
    `rustbgpd-linux-arm64.tar.gz`, per-arch `.deb`/`.rpm` packages, the
    standalone config schema, plus per-arch `checksums-<arch>.txt`
    (covering the tarball and packages).
    Each tarball contains `rustbgpd`, `rbgp`, `rs-config-render`,
    `birdwatcher-adapter`, `LICENSE-MIT`, and `LICENSE-APACHE` plus the
    systemd unit under `share/systemd/` (presence is asserted by the
    workflow; the runtime image likewise ships both licenses at `/`).
    The version-less filenames are what powers the static
    `releases/latest/download/` URLs in `docs/how-to/deployment.md`; if the
    filenames drift, deployment.md silently breaks for new operators.
    Download one tarball and its checksum manifest, then spot-check only that
    file:

    ```sh
    awk -v file=rustbgpd-linux-amd64.tar.gz '$2 == file || $2 == "./" file { print }' \
      checksums-linux-amd64.txt | sha256sum -c -
    ```

12. **Verify GitHub release notes**: check that the release created by CI has
    accurate notes. The `release` workflow extracts the matching
    `## [X.Y.Z]` block out of `CHANGELOG.md` via awk and fails the tag build
    if the section is missing; if GitHub shows the auto-generated commit list
    anyway, fix the CHANGELOG heading and either re-tag or edit the release
    body.

### rustbgpd-wire crate release

The wire crate has its own version in `crates/wire/Cargo.toml`, decoupled
from the daemon workspace version. Only publish when the wire crate itself
changed.

1. **Did `crates/wire/` change since the last wire publish?**
   - If no: skip. Do not publish a no-op release.
   - If yes: continue.
2. Decide semver bump (see below). The `semver-checks` workflow already
   compared the crate against its latest crates.io release on the PR, so a
   bump it reported as required is not optional.
3. Update `version` in `crates/wire/Cargo.toml`, its matching root workspace
   dependency pin, root `Cargo.lock`, and `bench/scale/Cargo.lock`. Keep the
   wire publish ahead of dependent FSM or RPKI releases when moving to a new
   wire line.
4. Roll `crates/wire/CHANGELOG.md` and add a `rustbgpd-wire` entry in the
   repository-level `CHANGELOG.md`
5. Run `cargo package --locked -p rustbgpd-wire --list` and inspect the exact
   package inventory and normalized manifest.
6. `cargo publish --locked -p rustbgpd-wire --dry-run`
7. `cargo publish --locked -p rustbgpd-wire`
8. Verify the version is visible in the registry, update the declared current
   boundary and dependency snippets in `docs/reference/embedding.md`, then run
   `python3 scripts/check_embedding_versions.py`.

**Wire crate semver:**
- **Patch**: bug fixes, stricter validation, docs/test improvements
- **Minor**: new message types, attributes, helper methods, additive API changes
- **Major**: breaking API changes, changed method signatures, enum shape changes

### rustbgpd-fsm crate release

The FSM crate has its own version in `crates/fsm/Cargo.toml`, decoupled from
the daemon workspace version. Only publish when the pure FSM API or docs change;
do not force an FSM release for every daemon tag.

1. **Did `crates/fsm/` or its public examples/docs change since the last
   `rustbgpd-fsm` publish?**
   - If no: skip. Do not publish a no-op release.
   - If yes: continue.
2. Decide semver bump:
   - **Patch**: bug fixes, docs/test improvements, or backward-compatible
     fields on an existing `#[non_exhaustive]` config struct when its
     constructor preserves the prior defaults.
   - **Minor**: additive events/actions/helpers, new public types, or other
     non-breaking negotiation surfaces. An incompatible `rustbgpd-wire`
     dependency move also requires an FSM minor bump because wire types appear
     in the public FSM API.
   - **Major**: changed method signatures, removed variants, or enum/struct
     shape changes not protected by `#[non_exhaustive]`.
   The `semver-checks` workflow applies the same crates.io comparison to this
   crate on the PR.
3. Update `version` in `crates/fsm/Cargo.toml`, its matching root workspace
   dependency pin, root `Cargo.lock`, and `bench/scale/Cargo.lock`. When the
   wire line also moves, publish wire first so the FSM package can resolve it.
4. Roll `crates/fsm/CHANGELOG.md` and add a `rustbgpd-fsm` entry in the
   repository-level `CHANGELOG.md`
5. Run `cargo package --locked -p rustbgpd-fsm --list` and inspect the exact
   package inventory and normalized manifest.
6. `cargo publish --locked -p rustbgpd-fsm --dry-run`. When this release moves
   to a new wire line, a resolver failure is expected until that wire version
   is registry-visible; do not weaken verification with `--no-verify`.
7. `cargo publish --locked -p rustbgpd-fsm`
8. Verify the version is visible in the registry, update the declared current
   boundary and dependency snippets in `docs/reference/embedding.md`, then run
   `python3 scripts/check_embedding_versions.py`.

### rustbgpd-rpki crate release

The RPKI crate has its own version in `crates/rpki/Cargo.toml`, decoupled from
the daemon workspace version. Its synchronous table API and asynchronous RTR
client will share one public compatibility boundary after the first publish.

1. **Did `crates/rpki/` or its public examples/docs change since the last
   `rustbgpd-rpki` publish?**
   - If no: skip. Do not publish a no-op release.
   - If yes: continue.
2. Decide semver bump:
   - **First publish**: establish `0.1.0` directly on the intended compatible
     wire line. With no registry baseline, there is no obsolete RPKI line to
     bump away from.
   - **Patch**: backward-compatible fixes, docs/test improvements, or additive
     public API after the first release within the current `0.x`
     compatibility line.
   - **Minor**: removed/changed public items, incompatible enum or struct shape
     changes, or an incompatible `rustbgpd-wire` dependency move because wire
     types appear in public RPKI method signatures.
   The `semver-checks` workflow compares every registry-visible release with
   its latest normal crates.io baseline.
3. Update `version` in `crates/rpki/Cargo.toml`, its matching root workspace
   dependency pin, root `Cargo.lock`, and `bench/scale/Cargo.lock`.
4. Roll `crates/rpki/CHANGELOG.md`, update the crate README, and add a
   `rustbgpd-rpki` entry in the repository-level `CHANGELOG.md`.
5. Run `cargo package --locked -p rustbgpd-rpki --list`; inspect the exact
   package inventory and normalized manifest. Normal dependencies must resolve
   from crates.io with no path-only edge.
6. Run `cargo publish --locked -p rustbgpd-rpki --dry-run`. For the initial
   release prepared against a new wire line, a resolver failure is expected
   until that wire version is registry-visible; do not weaken verification
   with `--no-verify`.
7. Publish `rustbgpd-rpki`, verify the version and ownership are visible in the
   registry, then manually dispatch `semver-checks.yml` at the publish commit.
   The checked package set must now include RPKI.
8. Update the declared current boundary and dependency snippets in
   `docs/reference/embedding.md`, then run `python3 scripts/check_embedding_versions.py`.

For the initial `0.1.0` publish only, the semver workflow permits the exact
`rustbgpd-rpki 0.1.0` package to have no baseline while crates.io returns 404
for its name. Any other missing package/version, a claimed name without a
normal release, or an ambiguous registry response fails closed. Recheck the
name immediately before the real publish; the package is already
publish-enabled in its manifest.
