# Threat model: rustbgpd

## What this project does and where untrusted input enters

rustbgpd is a BGP daemon for route servers, route reflectors and automation, written in Rust and targeting Linux. The
`rustbgpd` binary runs BGP sessions, keeps the RIB, applies import and export policy and exposes a gRPC management API.
`rbgp` is the operator CLI for that API. The scanned branch is `main`. The project is public alpha. Its narrow v1
compatibility contract is described in `docs/reference/stability.md`. That contract governs compatibility only, not
security scope.

Memory safety is largely handled by the language. Every workspace crate root carries `#![deny(unsafe_code)]`. Shipped
code opts out in exactly three places, each listed in `SECURITY.md`:

- the Linux socket-option module in `crates/transport` (TCP MD5, TCP-AO, GTSM);
- the exit-only watchdog in `crates/api` (`runtime_config_settlement`);
- one `setsockopt` in the daemon's `bfd_runtime`.

Memory-safety findings in those modules are welcome. Expect most real findings elsewhere to be panics, hangs, unbounded
work or allocation, authorization mistakes and protocol-logic errors.

Treat all of the following as attacker-controlled:

- **BGP peers over TCP (port 179).** This is the primary attack surface. Inbound connections from addresses that match
  no configured neighbor and no `[[dynamic_neighbors]]` range are dropped right after accept. A route server or
  reflector still has many configured peers, though, and none of them is trusted. That includes IXP members and
  dynamic neighbors. A peer controls every byte it sends: OPEN and its capabilities (4-octet AS, MP-BGP, Add-Path,
  Extended Messages, graceful restart and LLGR, route refresh / enhanced route refresh, ORF), plus UPDATE,
  NOTIFICATION, KEEPALIVE and ROUTE-REFRESH. Decoding lives in `crates/wire`, and the session FSM in `crates/fsm`.
  `crates/transport` covers framing, the session runtime and per-peer limits. Selection and distribution are in
  `crates/rib`, and policy evaluation in `crates/policy`.
  - Path attributes include AS_PATH/AS4_PATH and segment types, communities (standard, extended, large),
    ORIGINATOR_ID/CLUSTER_LIST, AIGP, unknown optional transitive attributes, and RFC 8654 messages up to 65,535 bytes.
  - NLRI covers IPv4/IPv6 unicast and the multiprotocol families in `crates/wire`: Add-Path path identifiers,
    labeled unicast, L3VPN (route distinguishers), RT-Constrain, FlowSpec (SAFI 133 component encoding), EVPN route
    types 1–6 (also `crates/evpn`) and BGP-LS.
  - RFC 7606 revised error handling is implemented in `crates/wire/src/validate.rs` and the per-family decoders.
    Each malformed UPDATE gets one disposition (`ErrorDisposition`: attribute discard, treat-as-withdraw or session
    reset, the strongest error winning per RFC 7606 §3(h)). Picking the wrong disposition is security-relevant.
- **RPKI-to-Router (RTR) caches** (`crates/rpki`: `rtr_client.rs`, `rtr_codec.rs`). The daemon dials configured caches
  over TCP and speaks RTR version 2 (ASPA), falling back to version 1. A malicious cache, or anyone able to tamper
  with that TCP stream, controls the PDUs, including serial/session state, End of Data timers and Cache Reset.
  Validated VRP and ASPA data feed route-origin and path validation in policy.
- **BFD control packets** (`crates/bfd`, decoded by the daemon's BFD runtime). This is asynchronous-mode BFD
  (RFC 5880), single-hop (RFC 5881) and multihop (RFC 5883), without BFD authentication. Packets with the A bit are
  discarded. For single-hop sessions the daemon enforces the RFC 5881 receive TTL/hop-limit 255 check.
- **The gRPC management API** (`crates/api`, `proto/`). By default it listens on an owner-only Unix socket. TCP
  listeners are opt-in and must use a bearer token (`token_file`) or native mTLS. Unauthenticated TCP listeners are
  rejected at config load. Every method has an
  authorization tier: `read`, `sensitive_read`, `mutating` or `operator_only` (`crates/api/src/authz.rs`,
  `docs/reference/grpc-method-inventory.md`, ADR-0064). Listener `max_tier` / `access_mode = "read_only"` ceilings
  and per-principal role ceilings are both enforced. Treat a lower-tier principal as untrusted with respect to
  anything above its tier. That covers mutation and credential exposure through read responses or audit logs. Config
  commits (`ApplyConfigTransaction`, `StreamApplyConfigTransaction`, `RollbackConfigTransaction`) are `operator_only`.
  Several RPCs below `operator_only` parse complex, caller-supplied text. Treat these payloads as untrusted. Parsing,
  compiling and evaluating them must not mutate state, exhaust the daemon or leak secrets:
  - candidate TOML in `DiffRuntimeConfig`, `PlanConfigTransaction` and `StreamPlanConfigTransaction`
    (`sensitive_read`) and in `ApplyEvpnRuntime` (`mutating`, including `validate_only`);
  - `.rpol` policy source and inline datasets in `PolicyService.TestPolicy` and `ComparePolicy` (`sensitive_read`,
    `crates/api/src/policy_service.rs`). These reach the rpol parser, the dataset parser, policy compilation
    (including AS-path regular expressions) and a dry-run evaluation over the RIB;
  - gNMI paths in `Get` and `Subscribe`, and AS-path segments in `RpkiService.VerifyAsPath` (all `sensitive_read`).

  The vendored OpenConfig gNMI service is served on the same listeners: `Get`, `Subscribe` and `Capabilities` are
  `sensitive_read`, and `Set` is `operator_only` because it commits config. Unauthenticated network clients of a TCP
  listener are fully untrusted.
- **Offline capture converters in `rbgp`**: `rbgp diff snapshot from-bmp` (RFC 7854 BMP byte streams) and
  `from-mrt` (MRT files) parse third-party captures (`crates/cli/src/ribsnap_bmp.rs`, `crates/cli/src/ribsnap.rs`,
  `crates/wire/src/mrt.rs`). They promise to reject malformed input with exit status 2 and never panic.
- **Bridges that sit in front of the API.** `tools/gobgp-bridge` serves one GoBGP v3 method (`AddPath`) to
  unauthenticated local clients. By design, any client that can reach it may announce and withdraw blackholes. Out of
  scope: that a client can announce a blackhole at all. In scope: escaping the documented supported subset, bypassing
  its request bounds, or getting anything other than the documented blackhole injections through to the daemon.
  `tools/mcp` (`rustbgpd-mcp`) is a read-only stdio server over the explain RPCs. It must never invoke a mutating RPC.

**Trusted inputs.** Only local operator input and `operator_only` RPCs are trusted. Local operator input means the
configuration file, `rpol` policy files and dataset files on disk, command-line flags, signals (SIGHUP reload) and
files under `runtime_state_dir`. A malicious local config, a crafted local policy or dataset, or a state directory
tampered with by the daemon's own user is out of scope. Crashes in those parsers are still worth reporting as
robustness bugs, at low severity. Text that reaches the same parsers through a `sensitive_read` or `mutating` RPC, as
listed above, is untrusted and rated by impact.

**Outbound only.** The BMP exporter (`crates/bmp`) and MRT dump writer only send or write data. The daemon does not
parse BMP from collectors. The shutdown warm checkpoint is written, not loaded at startup.

## Components that matter most / least

Most important:

1. `crates/wire`: message, attribute and NLRI decoding, and RFC 7606 classification.
2. `crates/transport` and `crates/fsm`: framing, session state, per-peer resource limits, inbound admission.
3. `crates/rib` and `crates/policy`, where peer-controlled routes are selected and filtered. Policy here means import
   and export, RPKI/ASPA validation, route-server and route-reflector export rules, and Add-Path.
4. `crates/rpki` and `crates/bfd` decoders and state machines.
5. `crates/api` authorization and the redaction of secrets (TCP MD5 passwords, TCP-AO keys, bearer tokens, candidate
   TOML) in responses, logs and audit records.

Lower priority but in scope:

- the `rbgp` capture converters;
- `tools/gobgp-bridge`, `tools/mcp` and `examples/birdwatcher-adapter`. The adapter is a read-only HTTP looking glass
  that is unauthenticated by design. Disclosing looking-glass data through it is expected.

Alpha code, scanned at lower priority: the Linux EVPN/VXLAN dataplane and FIB programming (`crates/evpn-linux`,
managed netdevs, `linux-edge-fib`). These require `CAP_NET_ADMIN` and sit outside the control-plane compatibility
contract. Lower priority affects only scan order. Severity still follows impact: a peer-triggered daemon crash there
is High, as it is anywhere else.

Out of scope:

- the `bench/` harnesses, `labs/`, `tests/`, `examples/peer-loop`, fuzz harness code itself, and `scripts/`;
- vulnerabilities in dependencies (tokio, tonic, rustls, prost, ...) unless rustbgpd uses them incorrectly;
- an attacker who already holds an `operator_only` gRPC credential, root, or the daemon's UID;
- intended features used by an appropriately authorized caller. Route injection (`InjectionService`), config
  commits, `TriggerMrtDump` and `Shutdown` are `operator_only`; neighbor add/delete, resets and soft resets are
  `mutating`. `crates/api/src/authz.rs` holds the tier of every method. Reaching any of them from a lower tier is in
  scope;
- the unauthenticated, read-only `/metrics`, `/livez` and `/readyz` endpoints, which are public by design;
- on-path attacks against peer TCP sessions configured without TCP MD5 or TCP-AO, and against BFD (unauthenticated
  by design);
- a configured BGP peer announcing routes that policy permits. Route hijacks within what policy allows are an
  operator policy matter, not a daemon bug.

## Classes of issue we want

- **Panics, aborts, hangs or livelock** reachable from peer, RTR, BFD or gRPC input. The process runs with
  `panic = unwind`. A panic that kills a session or actor task without exiting the process is still a finding,
  because that peer or the RIB can wedge.
- **Unbounded allocation or work** from small input. Examples: allocations sized by length fields, quadratic
  attribute or NLRI handling, Add-Path path-ID growth, and RTR or BFD state growth. Others are bypasses of
  `max_prefixes` and similar per-peer limits, bypasses of the bounded channels between sessions and the RIB, and
  bypasses of the inbound admission and accept-rate limits. Distinguish these from volume an operator explicitly
  configured.
- **RFC 7606 mistakes** in either direction.
  - Resetting a session where the RFC requires treat-as-withdraw or attribute discard.
  - Accepting and propagating a malformed attribute that should have been discarded or withdrawn.
  - Re-advertising malformed or unknown transitive attributes in a form that makes downstream speakers reset.
- **Session-reset amplification.** One peer's input must not reset, stall or degrade other peers' sessions, or
  trigger outbound churn to many peers out of proportion to the input.
- **Policy and validation bypass.** These are routes that import policy, RPKI/ASPA validation, `ebgp_requires_policy`
  (RFC 8212), route-server or reflector export rules, or FlowSpec validation should have rejected, but which are
  accepted, selected or advertised anyway. Wrong-peer leakage across route-server or Add-Path views also counts.
- **Authorization bypass.** A principal invokes a method above its tier or its listener's `max_tier`. Other cases: a
  read-only listener mutates state, a bearer token or client certificate is accepted when it should not be, or a
  credential leaks into read responses, logs, metrics or audit records.
- **Authentication bypass** of TCP MD5, TCP-AO or GTSM as configured, for example accepting a session that the
  configured keys or TTL bounds should reject.

## How to exercise it

The image has the checkout and build in `/src`. Every crate in `Cargo.lock` is fetched, and `CARGO_NET_OFFLINE=true`
is set. The dev profile keeps debug assertions and overflow checks on.

```sh
cd /src
cargo test --locked                       # default workspace members (all but the bench/scale harnesses)
cargo test --locked rfc7606               # a name filter reuses the prebuilt test binaries
./target/debug/rustbgpd --check examples/minimal/config.toml
```

Narrower selections such as `cargo test --locked -p rustbgpd-wire` or `--test session_lifecycle` also work offline.
They recompile part of the dependency graph first, because Cargo unifies features per selection. A plain name filter
does not.

The image builds and runs the whole suite as the unprivileged `builder` user, and the build fails if any test fails.
The audit shell is root. A few tests inject filesystem permission failures, which root bypasses, and some refuse to
run as root at all. Examples are in `tests/config_persistence_lifecycle.rs`, `src/config_transaction_control/tests.rs`
and `tools/rs-config-render/tests/`. Run those as the build user: `runuser -u builder -- cargo test --locked <filter>`.
Their failures under root are not findings.

The fuzz targets are the best entry points for decoder work. List them with
`python3 scripts/check_fuzz_target_inventory.py --print-targets`, which prints the same output as `just fuzz-list`.
Tracked seeds live in `crates/<crate>/fuzz/seeds/` for every fuzz crate except evpn.
There are 23 targets across 7 cargo-fuzz crates:

- wire: `decode_message`, `decode_open`, `decode_update`, `decode_route_refresh`, `decode_flowspec`, `decode_evpn`,
  `decode_vpn`, `decode_labeled`, `decode_rtc`, `decode_bgpls`, `encode_update`, `encode_evpn`, `parse_rd`;
- rpki: `decode_rtr_pdu`;
- bfd: `decode_bfd_control`;
- evpn: `parse_rt`;
- policy: `compile_chain`, `dataset_parse`, `explain_walk`, `rpol_compile`;
- mrt: `snapshot_reader_drain`, `warm_bundle_manifest`;
- cli: `ribsnap_convert`, which covers the `from-mrt` and `from-bmp` converters.

The pinned nightly and cargo-fuzz are installed, and every fuzz crate's dependencies are fetched. The wire targets are
prebuilt. Run fuzzers from the crate that owns `fuzz/Cargo.toml`:

```sh
cd /src/crates/wire
RUSTUP_TOOLCHAIN="$(cat /src/fuzz/rust-nightly.txt)" cargo fuzz run decode_update -- -max_total_time=60 -max_len=65535
```

Most bugs are best proved end to end against a running daemon on loopback. Here is one way to do that:

1. Copy `examples/minimal/config.toml`.
2. In the copy, set `listen_port` to a free port, the neighbor `address` to `127.0.0.2`, and `runtime_state_dir` to a
   scratch directory.
3. Start `./target/debug/rustbgpd <config>`.
4. Connect from `127.0.0.2` (bind the client socket to that source address) and send crafted bytes after a valid
   OPEN/KEEPALIVE exchange.

Inspect the daemon with `./target/debug/rbgp -s unix://<runtime_state_dir>/grpc.sock neighbor` and `rbgp rib`. The
library crates `rustbgpd-wire` and `rustbgpd-fsm` can also be driven directly from a unit test. `examples/peer-loop`
shows a minimal speaker built on them.

## How you rate severity

This is the same scale as the Severity section of `SECURITY.md`. Severity follows impact. Alpha status or a
lower scanning priority never lowers it.

A **configured peer** is any address that matches a `[[neighbors]]` entry or a `[[dynamic_neighbors]]` range. On a
route server, that means any IXP member.

| Severity | Examples |
| --- | --- |
| Critical | Memory corruption reachable from the network. An unauthenticated network client reaching `mutating` or `operator_only` gRPC methods. |
| High | Peer, RPKI cache or BFD input that crashes the daemon, hangs it or wedges the RIB, in any component, alpha code included. Unbounded memory growth to OOM from bounded input. One peer's input resetting, stalling or degrading other peers' sessions. Bypassing import policy, RPKI/ASPA validation or RFC 8212. Session hijacking or injection, including TCP MD5, TCP-AO or GTSM bypass. A lower-tier principal performing a `mutating` or `operator_only` action. Secret material (MD5/TCP-AO keys, tokens, candidate TOML) leaking through the API, logs or metrics. |
| Medium | An incorrect reset confined to the sender's own session, for example a reset where RFC 7606 requires treat-as-withdraw or attribute discard. If other peers are affected, the finding is High. Disproportionate CPU or memory that stays within configured limits. `sensitive_read` data exposed at `read` tier. Panics in the `rbgp` capture converters or in the separate GoBGP bridge process. |
| Low | Crashes from local operator-controlled config, policy or dataset files (the same text sent through a non-`operator_only` RPC is rated by impact). Panics that only debug assertions or overflow checks raise in the dev profile, with no release-profile consequence. Log-only information disclosure. |

Report the behavior of a release build (`cargo build --release`) when it differs from the dev profile.

## How reports and patches should look

Include these in each report:

- the commit;
- the input (hex bytes or a generator), the configuration it needs, and the peer and capability state;
- expected and observed behavior, with the relevant RFC section for protocol issues.

Prefer a deterministic regression test: a unit test in the owning crate, a fuzz-seed file, or a test under `tests/`
for daemon-level behavior. Pair it with a minimal root-cause patch in the shared function rather than a guard in one
caller. Group findings that share a root cause into one report. A panic reachable through several message types from
the same decoder function is one finding.
