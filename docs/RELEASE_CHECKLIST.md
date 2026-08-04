# Release Checklist

Pre-publish smoke matrix for every tagged release. All items must pass before
pushing a version tag.

---

## Automated (CI)

These run on every push and PR (`.github/workflows/ci.yml`,
`.github/workflows/interop.yml`):

- [ ] `cargo fmt --check`
- [ ] `python3 scripts/check-clippy-reasons.py`
- [ ] `python3 scripts/check-v1-stable-surface.py` — stable config fields and
      object shape, native gRPC signatures/messages, CLI paths/JSON contracts,
      role classifications, compatibility floor, and the consecutive-release
      upgrade receipt still match their machine sources.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo doc --workspace --lib --no-deps` (warning denial comes from
      `.cargo/config.toml` `build.rustdocflags` — don't set a different
      `RUSTDOCFLAGS` env, it forks the doc-cache fingerprint and forces a
      full workspace re-doc on the next differently-flagged run)
- [ ] **MSRV gate** — `cargo check --workspace --all-targets` at the
      declared `rust-version` (kept in lockstep with the Dockerfile
      builder version)
- [ ] **Wire crate README freshness gate** — if
      `crates/wire/Cargo.toml` version changed in the diff,
      `crates/wire/README.md` must also be touched
- [ ] **Gate 8b BUM-filter kernel primitive**
      (`evpn_bum_filter_kernel` job) — runs the netns harness under
      `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN
      --security-opt apparmor=unconfined` against `ubuntu-latest`'s
      6.x kernel
- [ ] **Interop tier** — the PR-gated foundation interop jobs in
      `.github/workflows/interop.yml` (against FRR 10.3.1 via
      containerlab) are green; that workflow is the authoritative job
      set, so check it rather than re-listing M-numbers here.

## Documentation hygiene

Before tagging, skim the release and tracking docs for the low-conflict
convention in `CONTRIBUTING.md`:

- [ ] `CHANGELOG.md` `[Unreleased]` entries are in the right subsections and
      read as compact per-PR entries rather than broad rewrites of older
      shipped text.
- [ ] `ROADMAP.md` has one row or checkbox per remaining concern; shipped
      slices say what landed and what remains.
- [ ] Hot tracking docs such as `docs/evpn-alpha-soak.md` and
      `docs/evpn-enablement.md` update exact gates/rows instead of rewriting
      unrelated summary prose.
- [ ] New config knobs follow
      [`docs/config-knob-contributor-guide.md`](config-knob-contributor-guide.md):
      schema, validation, reload matrix, runtime consumption, persistence,
      docs, and tests all move together.
- [ ] Process-only documentation changes intentionally omit CHANGELOG entries
      unless they affect users or operators.
- [ ] Every README front-matter performance claim cites a receipt measured
      within the last three releases, or carries an explicit measured-on date
      in the claim text (e.g. "measured 2026-07-03"). Older numbers stay
      quotable with their date; undated stale numbers do not ship.

## Narrow v1 RS/RR compatibility gate

The project remains public alpha outside the explicit
[`rustbgpd-rs-rr-v1`](v1-stable-contract.md) inventory. Before tagging:

- [ ] Review every change to `docs/v1-stable-surface.json` as a product
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
      exactly once), `docs/grpc-method-inventory.json` matches the
      matrix, `docs/grpc-method-inventory.md` matches the `.json` in
      both directions, and the per-tier counts match.
- [ ] `docs/grpc-method-inventory.md` was regenerated by hand to match
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

Every shipped starter — both `--init-config` profiles and every config
under `examples/` — must pass `rustbgpd --check --strict`, exit 0, summary
`config OK`. Shipping a starter that trips our own unpoliced-eBGP warning
teaches the operator who runs it first that the warning is noise. Permit-all
starters stay permit-all; they say so in an explicit chain instead of by
omission.

```bash
# Each built-in profile emits a starter config that passes the strict gate.
for p in lab edge; do
  ./target/release/rustbgpd --init-config "$p" --stdout > "/tmp/init-$p.toml"
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
./target/release/rustbgpd --init-config lab --stdout --check x  # --init-config combined with --check/--diff
./target/release/rustbgpd --strict /tmp/init-lab.toml           # --strict without --check
```

### README quickstart smoke

Walk the exact README quickstart from a clean tree and confirm:

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
compares the per-service tables and totals of `docs/grpc-method-inventory.md`
against `docs/grpc-method-inventory.json` in both directions, and
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

If the release includes recent LLGR changes, also run:

```bash
containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml
bash tests/interop/scripts/test-m16-llgr-frr.sh
containerlab destroy -t tests/interop/m16-llgr-frr.clab.yml
```

If the release includes EVPN changes (any commit touching
`crates/wire/src/evpn.rs`, `crates/wire/src/pmsi.rs`, EVPN paths in
`crates/rib/src/`, the EVPN gRPC surface, `crates/evpn-linux/src/`,
`crates/evpn/src/origination.rs`, `src/evpn_dataplane.rs`,
`src/evpn_originator.rs`, or `src/evpn_imet.rs`), run at least one of
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
`src/evpn_originator.rs`, `src/evpn_imet.rs`,
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
aliasing in `crates/evpn/src/aliasing.rs`, mass-withdraw in
`crates/evpn/src/mass_withdraw.rs`, or BUM-port enforcement), run M38
to validate DF election + Type 1/4 origination against a peer running
the same code. If the release touches **Gate 9 / ADR-0059 / ADR-0087 /
ADR-0090** (IP-VRF, Type 5, L3 FIB programming, overlay-index
recursion/origination, aliasing ECMP, or FDB nexthop groups), run the hosted
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
events / coupling), run the hosted `Kernel Dataplane` workflow for M51.
Manual reproduction:

```bash
# M51 — single-hop BFD + RFC 5882 coupling against FRR bfdd
docker build --target dev -t rustbgpd:dev .
containerlab deploy -t tests/interop/m51-bfd-frr.clab.yml
bash tests/interop/scripts/test-m51-bfd-frr.sh
containerlab destroy -t tests/interop/m51-bfd-frr.clab.yml
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

1. Update `CHANGELOG.md` with the new version section
2. **Verify changelog completeness**: run `git log <prev-tag>..HEAD --oneline`
   and confirm every user-visible change (features, fixes, interop suites) is
   listed under the new version — not misattributed to a prior release. Check
   that stale counts (test totals, interop suite counts, script counts) are
   updated in CHANGELOG.md, README.md, and ROADMAP.md. Also sweep
   `(post-vX.Y.Z)` annotations in ROADMAP.md and the Maturity row in README.md.
3. Bump versions:
   - Root `Cargo.toml`: `[workspace.package] version` plus every internal
     `rustbgpd-*` pin in `[workspace.dependencies]`. Library crates that
     publish independently, such as `rustbgpd-wire`, may carry both `path`
     and `version` so downstream publish dry-runs resolve from crates.io;
     do not remove those version pins during the workspace bump.
   - `crates/wire/Cargo.toml`: bump **only** if `crates/wire/src/` changed
     since the last wire publish (see semver rules in the next section).
     Land the wire bump in its **own commit** before the workspace bump so
     the wire publish is reproducible from the commit alone.
4. Run the full checklist above (fmt, clippy `-D warnings`, test, doc
   `-D warnings`, release build)
5. Commit (workspace): `release: prep vX.Y.Z — bump workspace, roll CHANGELOG`
6. **Annotated** tag (lightweight tags break the release-history convention
   here): `git tag -a vX.Y.Z -m "vX.Y.Z — <one-line headline>"`
7. Push: `git push origin main && git push origin vX.Y.Z`
   - If this cycle touched `.github/workflows/release.yml`, run the
     dispatch dry-run to green **before pushing the tag** (after the
     workflow change is on `main`): `gh workflow run release.yml -f
     dry_run=true` — workflow edits otherwise meet their first
     execution on the live tag.
8. Verify CI passes on the tag (build matrix x86_64 + aarch64, doc, GHCR
   push, release.yml binary build + GitHub Release creation). Both
   publication workflows are fail-closed: `release.yml` and
   `container.yml` each gate publication on a `verify-tag-version` job
   (tag `vX.Y.Z` must equal the workspace `[workspace.package]`
   version) and a `test` job (`cargo test --workspace` on the tagged
   commit). If you tagged a commit without the version bump, the tag
   build fails and publishes nothing — fix the bump, delete the tag,
   and re-tag.
9. **Verify container image published to GHCR** via `docker/metadata-action`'s
   semver pattern:
   - `ghcr.io/lance0/rustbgpd:X.Y.Z` (exact, immutable)
   - `ghcr.io/lance0/rustbgpd:X.Y` (rolls forward within the minor)
   - `ghcr.io/lance0/rustbgpd:latest` (auto-published for non-prerelease
     tags via the action's default `latest=auto` flavor)
   These **container-image** tags are emitted **without** the `v` prefix —
   `0.45.0`, not `v0.45.0` (`docker/metadata-action` strips it). The **git tag
   stays `vX.Y.Z`** (step 6); only the image tag drops the `v`.
10. **Verify release tarballs and packages** under
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
    `releases/latest/download/` URLs in `docs/deployment.md`; if the
    filenames drift, deployment.md silently breaks for new operators.
    Download one tarball and its checksum manifest, then spot-check only that
    file:

    ```sh
    awk -v file=rustbgpd-linux-amd64.tar.gz '$2 == file || $2 == "./" file { print }' \
      checksums-linux-amd64.txt | sha256sum -c -
    ```

11. **Verify GitHub release notes**: check that the release created by CI has
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
2. Decide semver bump (see below)
3. Update `version` in `crates/wire/Cargo.toml`
4. Add a `rustbgpd-wire` entry in `CHANGELOG.md`
5. `cargo publish -p rustbgpd-wire --dry-run`
6. `cargo publish -p rustbgpd-wire`
7. Verify the version is visible in the registry, update the declared current
   boundary and dependency snippets in `docs/EMBEDDING.md`, then run
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
     non-breaking negotiation surfaces.
   - **Major**: changed method signatures, removed variants, or enum/struct
     shape changes not protected by `#[non_exhaustive]`.
3. Update `version` in `crates/fsm/Cargo.toml`
4. Add a `rustbgpd-fsm` entry in `CHANGELOG.md`
5. `cargo publish -p rustbgpd-fsm --dry-run`
6. `cargo publish -p rustbgpd-fsm`
7. Verify the version is visible in the registry, update the declared current
   boundary and dependency snippets in `docs/EMBEDDING.md`, then run
   `python3 scripts/check_embedding_versions.py`.
