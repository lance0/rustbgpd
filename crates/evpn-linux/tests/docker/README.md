# Docker harness — privileged netns tests

Local Docker-driven runner for the privileged tests in
`crates/evpn-linux/tests/` and `src/fib_runtime.rs`. Lets contributors
exercise the `EVPN_LINUX_NETNS=1` gated tests without needing
iproute2 / iputils-ping / a specific Rust toolchain pre-installed on
the host, and without leaking netnses into the host namespace on a
panicked test.

Same shape as the xfr `docker/` repro harness — single-purpose
Dockerfile + shell helper + this README.

## Build

```
bash crates/evpn-linux/tests/docker/run-netns-tests.sh
```

The helper builds `rustbgpd-netns-tests:latest` on first run and
caches it. Subsequent runs reuse the image unless the Dockerfile is
newer than the cached image.

Manual build (if you prefer to drive Docker yourself):

```
docker build \
  -f crates/evpn-linux/tests/docker/Dockerfile \
  -t rustbgpd-netns-tests \
  .
```

## Run

```
bash crates/evpn-linux/tests/docker/run-netns-tests.sh           # default Gate 8b BUM tests
bash crates/evpn-linux/tests/docker/run-netns-tests.sh spike     # shell spike only
bash crates/evpn-linux/tests/docker/run-netns-tests.sh roundtrip # netlink round-trip only
bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg   # FDB nexthop groups
bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg_roundtrip # FDB-NHG round-trip only
bash crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg_cve # FDB-NHG nolearning guard only
bash crates/evpn-linux/tests/docker/run-netns-tests.sh fib_runtime # ADR-0061 FIB runtime
bash crates/evpn-linux/tests/docker/run-netns-tests.sh dataplane_vlan_fdb # ADR-0089 VLAN FDB proof
bash crates/evpn-linux/tests/docker/run-netns-tests.sh svd_fdb_vni # LAN-64 SVD explicit FDB VNI proof
```

`--cap-add=NET_ADMIN` is required for `bridge link set ... flood off`
(the Gate 8b primitive). `--cap-add=SYS_ADMIN` is required for
`ip netns add` (which calls `unshare(CLONE_NEWNET)`, gated by
`CAP_SYS_ADMIN` per `unshare(2)`). The harness does **not** use
`--privileged` — both caps together are tighter than full privilege
and pass on hardened CI runners that ban privileged containers.

The repo is bind-mounted at `/work`; cargo's registry and the
workspace `target/` directory ride named volumes
(`rustbgpd-netns-tests-cargo` and `rustbgpd-netns-tests-target`) so
warm reruns take seconds instead of minutes. Override
`CARGO_CACHE_VOL` / `TARGET_CACHE_VOL` env vars to share or isolate
caches across runs.

## What it actually exercises

| Filter       | Test                                                    | What it covers                                                     |
| ------------ | ------------------------------------------------------- | ------------------------------------------------------------------ |
| `spike`      | `bum_filter_spike_validates_kernel_primitive`           | Shell-driven topology + `ping -b` + `bridge link set` flag toggle |
| `roundtrip`  | `linux_dataplane_set_bum_port_flags_round_trip`         | `LinuxDataplane::apply` → `RTM_NEWLINK` → `bridge -d link show`   |
| `fdb_nhg`    | `netns_fdb_nhg`                                         | ADR-0059 FDB nexthop group install / update / teardown            |
| `fdb_nhg_roundtrip` | `round_trip_install_and_remove_fdb_nhg`          | FDB-NHG member + group + FDB-row install, dump, and teardown      |
| `fdb_nhg_cve` | `cve_guard_blocks_install_when_learning_enabled`        | CVE-2025-39851 nolearning readiness guard for FDB-NHG installs   |
| `fib_runtime` | `fib_runtime::tests::netns_general_unicast_fib_runtime_round_trip` | ADR-0061 route install / foreign preservation / withdraw / drain |
| `dataplane_vlan_fdb` | `linux_dataplane_programs_vlan_scoped_remote_mac_add_remove` | ADR-0089 VLAN-scoped single-dst FDB add/remove and scoped delete |
| `svd_fdb_vni` | `svd_topology_is_ready_and_programs_vni_scoped_fdb_rows` | LAN-64 collect-metadata VXLAN Ready + explicit `src_vni` FDB programming / scoped-delete proof |
| `all` (default) | Gate 8b BUM tests                                    | both Gate 8b BUM tests                                             |

The shell spike asserts the five load-bearing invariants (DF allows,
Non-DF blocks all three BUM classes, known-unicast survives, restore
is symmetric, FDB programming unaffected). The Rust round-trip
asserts that the netlink-attribute encoding actually lands the
expected `flood off / mcast_flood off / bcast_flood off` triplet on
the kernel-side bridge port.

The ADR-0061 FIB runtime selector runs a same-module daemon test from
the `rustbgpd` crate. It creates a Linux netns, installs routes only
into the configured non-reserved table, asserts table / metric /
gateway / `proto bgp` shape, preserves an existing foreign route,
withdraws only daemon-owned rows, drains owned rows on shutdown, and
treats a route that was externally deleted before withdraw as
idempotent.

## Kernel requirements

- Linux >= 4.18 on the **host** for the Gate 8b BUM selectors (the
  container shares the host kernel; `IFLA_BRPORT_BCAST_FLOOD` was
  added in 4.18).
- Linux >= 5.8 on the **host** for the ADR-0059 FDB-NHG selectors
  (`RTM_NEWNEXTHOP` / `NHA_FDB` support).
- Netns-capable Linux for the ADR-0061 `fib_runtime` selector; it
  uses ordinary route-table operations rather than FDB nexthop
  groups.
- A kernel and iproute2 with VXLAN `external` / `vnifilter`, bridge
  VLAN tunnel mapping, and FDB `src_vni` support for the LAN-64
  `svd_fdb_vni` selector.
- `CONFIG_NET_NS=y` and `CONFIG_BRIDGE=y` in the host kernel
  (universal on modern Linux).

## Why a separate harness vs the existing `EVPN_LINUX_NETNS=1` path

Running `sudo -E env EVPN_LINUX_NETNS=1 cargo test ...` directly on
the host still works and is the right path for active development.
This harness is the right path when:

- The local host kernel is too old, but you have access to a Docker
  daemon backed by a modern kernel (for example Docker Desktop's VM
  or a remote Linux daemon).
- You're reviewing a PR and want to run the tests without installing
  iproute2 / iputils-ping / sudo'ing.
- You want strong cleanup guarantees — a panicking test inside the
  container can't leak netnses into the host namespace, since the
  container's own network namespace tears down on `--rm`.

Both paths exercise the same test code; the harness is just a
container around it.

## CI integration

The default Gate 8b BUM selector is wired into PR-CI via the
`evpn_bum_filter_kernel` job in `.github/workflows/ci.yml`. Every PR
runs the shell spike and Rust round-trip against the GitHub-hosted
runner's kernel (Ubuntu 24.04, kernel 6.x — well past the 4.18 floor
for `IFLA_BRPORT_BCAST_FLOOD`).

Other selectors are local / manual validation unless a workflow names
them explicitly. In particular, `fdb_nhg` and `fib_runtime` are
reviewer-run privileged smokes today, not default PR-CI gates.

The CI step pre-builds the harness image with `docker/build-push-action`
+ GHA layer caching, then invokes `run-netns-tests.sh` with
`SKIP_BUILD=1` so the helper reuses the pre-built image rather than
re-running its mtime-based rebuild check (which always fires on a
fresh checkout). Warm CI runs complete in roughly 1-2 min; cold
runs (image cache miss) in ~2-3 min.

`SKIP_BUILD=1` is also the right env var when chaining the harness
into other automation — set it whenever you've already produced
the image via some other path and don't want the helper to
second-guess.
