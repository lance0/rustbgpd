# rustbgpd-gobgp-bridge

`rustbgpd-gobgp-bridge` lets RTBH detectors that drive GoBGP announce and
withdraw blackholes through rustbgpd without client changes. It serves one
GoBGP v3 method, `apipb.GobgpApi/AddPath`, and applies each request through
rustbgpd's `InjectionService` as an ordinary authenticated gRPC client.

It is a separate binary. It never links into the daemon and is outside the
[v1 contract](../../docs/reference/stability.md): its flags, logs and
supported subset may change in any release.

## Running it

Release archives do not include the bridge. Build it from this repository:

```bash
cargo build --release --locked -p rustbgpd-gobgp-bridge
```

Run the bridge on the same host as the daemon, as the daemon's user, against
the daemon's owner-only Unix socket:

```bash
rustbgpd-gobgp-bridge \
  --listen 127.0.0.1:50051 \
  --daemon unix:///var/lib/rustbgpd/grpc.sock
```

Detectors usually hard-code GoBGP's default `localhost:50051`, so the bridge
takes that port. Keep rustbgpd's own API on its Unix socket, or move a
`[global.telemetry.grpc_tcp]` listener to another port.

To use a TCP listener instead, give its bearer token; the daemon refuses
plaintext TCP without one:

```bash
rustbgpd-gobgp-bridge \
  --listen 127.0.0.1:50051 \
  --daemon http://127.0.0.1:50052 \
  --token-file /etc/rustbgpd/bridge.token
```

| Flag | Meaning |
|------|---------|
| `--listen ADDR` | Required. Address for the GoBGP API. Must be loopback unless `--allow-non-loopback` is set. |
| `--daemon ENDPOINT` | Required. `unix:///absolute/path` or `http://host:port`. |
| `--token-file PATH` | Bearer token for the daemon listener. |
| `--allow-non-loopback` | Serve on a non-loopback address. Read the security section first. |
| `--reconcile-interval-secs N` | Seconds between reconcile passes (default 30). See [restart behaviour](#restart-behaviour). |

The bridge starts while the daemon is down and connects on the next request.
It logs each applied or refused request to stderr, with the daemon's outcome
(for example `Created`, `Unchanged`, `Deleted` or `NotPresent`), since
GoBGP's response has no field for it. Set `RUST_LOG` to change the level.

## Security

The GoBGP API has no authentication: detector clients open insecure gRPC
channels. **Any local process that can connect to the listen address can
announce and withdraw blackholes through the daemon, with the bridge's
credentials.** By running the bridge, the operator accepts that.

- The bind address is explicit. The bridge refuses a non-loopback address
  unless `--allow-non-loopback` is given, which extends the same exposure to
  every host that can reach it.
- The daemon keeps its own rule: no unauthenticated TCP. The bridge
  authenticates to the daemon through the Unix socket's file permissions or a
  bearer token, and an owner-only socket gives it operator access.
- Injected routes bypass import policy: the daemon places them directly in
  its local RIB. Export policy is the only control over what reaches peers.
  Scope what the bridge can announce with an export policy toward each
  upstream, for example allowing only locally originated /32 and /128 routes
  that carry the blackhole community on a blackhole session:

  ```toml
  [policy.definitions.rtbh-only]
  default_action = "deny"
  [[policy.definitions.rtbh-only.statements]]
  action = "permit"
  match_route_type = "local"
  prefix = "0.0.0.0/0"
  ge = 32
  match_community = ["BLACKHOLE"]
  [[policy.definitions.rtbh-only.statements]]
  action = "permit"
  match_route_type = "local"
  prefix = "::/0"
  ge = 128
  match_community = ["BLACKHOLE"]

  [[neighbors]]
  address = "192.0.2.254"
  remote_asn = 64500
  export_policy_chain = ["rtbh-only"]
  ```

## Supported subset

Anything outside this subset is rejected with a gRPC error. Nothing is
dropped silently.

| Item | Accepted |
|------|----------|
| Method | `apipb.GobgpApi/AddPath` (GoBGP v3). Every other method returns `UNIMPLEMENTED`. |
| Table | `table_type = GLOBAL`, empty `vrf_id`. |
| Family | IPv4 unicast, IPv6 unicast. |
| Encoding | `nlri_binary` with exactly one prefix, and `pattrs_binary` with one attribute per entry. The structured `nlri` and `pattrs` fields are rejected. |
| Path identifier | `identifier`, passed through as the injected path id. |
| Attributes | ORIGIN; NEXT_HOP (IPv4); MP_REACH_NLRI (IPv6, GoBGP's shape); COMMUNITIES; AS_PATH with four-octet AS_SEQUENCE segments; MULTI_EXIT_DISC; LOCAL_PREF. Each type at most once. |
| Announce | `is_withdraw = false` becomes `InjectionService.AddPath`. A next hop is required. A missing ORIGIN means IGP. |
| Withdraw | `is_withdraw = true` becomes `InjectionService.DeletePath` with `allow_missing`. Attributes are checked but not used, as GoBGP does. Withdrawing a route that is not present succeeds. |
| Response | A UUID derived from (family, prefix, path id). Repeated requests for the same path return the same UUID. |

GoBGP's IPv6 shape puts the prefix in `nlri_binary` and the next hop in an
MP_REACH_NLRI attribute. The MP_REACH_NLRI must be IPv6 unicast with one
16-octet next hop. Any NLRI inside it must be the same prefix.

A next hop of `0.0.0.0` or `::`, the usual detector default, means
next-hop-self. The daemon stores the route with the unspecified next hop and
advertises it with its own address on each session, as GoBGP does for eBGP
and iBGP peers. Route listings show `0.0.0.0` or `::`. An IPv6 route goes
only to sessions that have a local IPv6 next hop. See
[next-hop self](../../docs/reference/api.md#next-hop-self) in the API
reference for the exact rules.

A request succeeds only after rustbgpd has acknowledged the change to its
local RIB. It does not mean that any peer has received the route. Daemon
errors come back unchanged: for example `UNAVAILABLE` when the daemon cannot
be reached, `UNAUTHENTICATED` for a wrong token, and `INVALID_ARGUMENT` for a
value the daemon rejects. Malformed bytes are `INVALID_ARGUMENT`. Valid GoBGP
requests outside the subset are `UNIMPLEMENTED`.

## Restart behaviour

Injected routes live only in the daemon process. The bridge keeps, in memory,
the last acknowledged announcement for each path the detector has not
withdrawn, and any withdrawal the daemon has not acknowledged. Every reconcile
interval it retries those withdrawals, then re-adds every tracked
announcement. An unchanged re-add is a no-op in the daemon; after a daemon
restart it restores the ban. The bridge also calls the daemon's
`CheckLiveness` every half second, and starts a pass at once when the daemon
answers after a failed call. A restart quicker than one probe goes unseen,
and the periodic pass stays as the backstop. The bridge tracks at most 65,536 paths, and a new
ban beyond that is refused with `RESOURCE_EXHAUSTED` before the daemon sees it.
Each daemon call has a 10-second deadline, so a daemon that accepts the
connection but stops answering fails the request instead of stalling the
bridge. An unban is recorded for retry before its daemon call, so a timed out
or cancelled unban is still applied by a later pass.

The integration test (`tests/daemon.rs`) runs each case below against a real
rustbgpd binary. It has no BGP peers and stops the daemon cleanly, so the
table describes rustbgpd's local state only.

| Event | Result | Local blackhole state | Recovery |
|-------|--------|-----------------------|----------|
| Daemon restart | The daemon starts with no injected routes. The bridge's next liveness probe sees the daemon answer again and re-adds every tracked ban at once. | Bans are missing from the restart until that pass, within one probe interval (0.5 s) of the daemon answering, or one reconcile interval if the probes miss the restart. | None needed. |
| Bridge restart | Daemon routes are untouched. A new bridge process withdraws them normally. | The new process tracks nothing, so bans made before the restart are not replayed after a later daemon restart. A ban or unban sent while the bridge is down fails at the detector and is not retried. | Restart the bridge. Re-send any ban or unban the detector logged as failed, and any ban that must survive a later daemon restart. |
| Duplicate ban | Succeeds and returns the same UUID. The daemon keeps one route. | None. | None. |
| Duplicate unban | Succeeds as a no-op. | None. | None. |
| Unban while the daemon is unavailable | Fails with `UNAVAILABLE`, saying the bridge retries the withdrawal. The bridge stops replaying the ban at once and retries the withdrawal each pass until the daemon acknowledges it. | If the daemon was stopped, its injected routes went with it, and the ban is not replayed when it returns. If the daemon is still running but the bridge cannot reach it (socket permissions, token, an API that does not answer before the detector's deadline), the blackhole stays announced until a retry succeeds. | None needed once the daemon is reachable. Check with `rbgp rib --prefix 203.0.113.7/32`. |

Losing the daemon's local state is not the same as peers withdrawing the
route. A peer without Graceful Restart withdraws the daemon's routes when the
session drops. rustbgpd advertises Graceful Restart by default, so a helper
peer keeps them as stale routes across a stop, and a blackhole stays in force
remotely until the session comes back and the peer receives End-of-RIB, or
until its stale timers expire. Interop leg
[M126](../../tests/interop/m126-fastnetmon-rtbh/README.md) measures this with
FRR as the helper:

- After a planned rustbgpd restart, the bridge's replay races the daemon's
  End-of-RIB on the new session. If End-of-RIB wins, FRR drops the stale bans
  and learns them again when the replay lands, so the upstream briefly has no
  blackhole. The liveness probe keeps that window short; the receipt records
  the measured value.
- An unban that fails while rustbgpd is stopped leaves the stale blackhole at
  the peer until rustbgpd returns and sends End-of-RIB, or until the peer's
  restart timer expires.

A detector deadline can expire while the daemon is still applying a change.
The daemon finishes a change it has accepted, so check the RIB before
re-sending an unban that timed out.

## Tested versions

- GoBGP API: `api/gobgp.proto` from GoBGP v3.37.0.
- Detector: request bytes match FastNetMon Community 1.2.10 development
  sources (commit `2436f447`), including its IPv6 MP_REACH_NLRI encoding.
  The unit tests and the integration test replay those layouts.
- Real detector: the official FastNetMon Community 1.2.9 package bans and
  unbans an IPv4 /32 and an IPv6 /128 through the bridge to FRR 10.7.1, across
  rustbgpd and bridge restarts, in interop leg
  [M126](../../tests/interop/m126-fastnetmon-rtbh/README.md). Its GoBGP client
  is identical to the development sources above.
- rustbgpd: the version in this repository.

## Vendored protocol definition

`proto/gobgp.proto` is copied unmodified from
[GoBGP](https://github.com/osrg/gobgp) v3.37.0, Copyright (C) 2015-2017
Nippon Telegraph and Telephone Corporation. The file carries its upstream
permission notice, an MIT-style license, and the GoBGP project is licensed
under Apache-2.0. Both are permissive and compatible with this repository's
MIT OR Apache-2.0 licensing. The notice stays in the file.
