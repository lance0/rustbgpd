# Interop Test Results

Tracks interop validation against real BGP implementations. Updated with
every milestone. "Tested" means validated in the containerlab CI suite,
not "someone tried it once."

---

## Test Matrix

| Peer | Version | Topology | Status | Notes | Known Quirks | NOTIFICATIONs Observed |
|------|---------|----------|--------|-------|--------------|------------------------|
| FRR (bgpd) | 10.3.1 | `tests/interop/m0-frr.clab.yml` | Tested (M0) | All 5 tests pass | Needs `no bgp ebgp-requires-policy` | Cease on `clear bgp *` |
| FRR (bgpd) | 10.3.1 | `tests/interop/m1-frr.clab.yml` | Tested (M1, M2) | UPDATE/RIB + best-path | FRR advertises 3 prefixes via `network` | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m3-frr.clab.yml` | Tested (M3) | 3-node redistribution | 2× FRR peers, route injection | — |
| BIRD | 2.0.12 | `tests/interop/m0-bird.clab.yml` | Tested (M0) | All 5 tests pass | Needs `/run/bird` dir; sends empty UPDATE on establish | Cease/Admin Shutdown + Cease/Admin Reset |
| FRR (bgpd) | 10.3.1 | `tests/interop/m4-frr.clab.yml` | Tested (M4) | 10-peer dynamic mgmt | 8 static + 2 dynamic peers | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m10-frr-ipv6.clab.yml` | Tested (M10) | Dual-stack MP-BGP | IPv4 session, IPv6 via MP_REACH_NLRI | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m11-gr-frr.clab.yml` | Tested (M11) | Graceful Restart (RFC 4724) | Short timers (30s restart, 30s stale) | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m12-ec-frr.clab.yml` | Tested (M12) | Extended Communities (RFC 4360) | RT:65002:100 via route-map | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m13-policy-frr.clab.yml` | Tested (M13) | Policy Engine (chains, actions) | 3-node: import chain + export deny/MED/prepend | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m14-rr-frr.clab.yml` | Tested (M14) | Route Reflector (RFC 4456) | 3-node iBGP: RR + 2 clients | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m15-rr-frr.clab.yml` | Tested (M15) | Route Refresh (RFC 2918) | SoftResetIn via gRPC | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m16-llgr-frr.clab.yml` | Tested (M16) | LLGR (RFC 9494) | GR→LLGR transition, stale clearing | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m17-addpath-frr.clab.yml` | Tested (M17) | Add-Path (RFC 7911) | Multi-path send, distinct path_ids | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m18-extnexthop-frr.clab.yml` | Tested (M18) | Extended Next-Hop (RFC 8950) | Dual-stack, IPv6 NH for IPv4 | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m19-routeserver-frr.clab.yml` | Tested (M19) | Transparent Route Server | No ASN prepend, NH preservation | Needs per-neighbor `no enforce-first-as` |
| FRR (bgpd) | 10.3.1 | `tests/interop/m20-privateas-frr.clab.yml` | Tested (M20) | Private AS Removal | remove/all/replace modes | — |
| FRR + GoRTR | 10.3.1 + latest | `tests/interop/m21-rpki-frr.clab.yml` | Tested (M21) | RPKI origin validation via RTR | GoRTR serves static VRP JSON | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m22-flowspec-frr.clab.yml` | Tested (M22) | FlowSpec inject + distribute + withdraw | FRR receives only (cannot originate) | — |
| GoBGP | 4.3.0 | `tests/interop/m23-gobgp.clab.yml` | Tested (M23) | Bidirectional route exchange | Custom image: `docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop/` | — |
| FRR + BMP receiver | 10.3.1 | `tests/interop/m24-bmp-frr.clab.yml` | Tested (M24) | BMP Initiation, PeerUp, RouteMonitoring | Python TCP receiver validates message types and ordering | — |
| FRR (2x) | 10.3.1 | `tests/interop/m25-md5-gtsm-frr.clab.yml` | Tested (M25) | TCP MD5 + GTSM / TTL security | Two peers: MD5 auth + GTSM separately | — |
| Junos vMX | — | — | Stretch | Lab only, not CI | — | — |
| Arista cEOS | — | — | Stretch | Lab only, not CI | — | — |
| Cisco IOS-XE | — | — | Stretch | If available | — | — |

---

## Running Interop Tests

### Prerequisites

- Docker installed and running
- containerlab installed
- `rustbgpd:dev` Docker image built: `docker build -t rustbgpd:dev .`
- `bird:2-bookworm` Docker image built: `docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop/`

### FRR (M0)

```sh
# Deploy topology
sudo containerlab deploy -t tests/interop/m0-frr.clab.yml

# Start rustbgpd
sudo docker exec -d clab-m0-frr-rustbgpd /usr/local/bin/start-rustbgpd.sh

# Watch logs
sudo docker logs -f clab-m0-frr-rustbgpd

# Check FRR session state
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"

# Check Prometheus metrics
sudo docker exec clab-m0-frr-rustbgpd curl -s http://127.0.0.1:9179/metrics

# Tear down
sudo containerlab destroy -t tests/interop/m0-frr.clab.yml
```

### BIRD (M0)

```sh
# Build BIRD image (one-time)
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop/

# Deploy topology
containerlab deploy -t tests/interop/m0-bird.clab.yml

# Start BIRD (create run dir first)
docker exec clab-m0-bird-bird mkdir -p /run/bird
docker exec -d clab-m0-bird-bird bird -c /etc/bird/bird.conf

# Start rustbgpd
docker exec -d clab-m0-bird-rustbgpd /usr/local/bin/start-rustbgpd.sh

# Check BIRD session state
docker exec clab-m0-bird-bird birdc show protocols rustbgpd

# Check Prometheus metrics (via management IP)
curl -s http://<rustbgpd-mgmt-ip>:9179/metrics

# Tear down
containerlab destroy -t tests/interop/m0-bird.clab.yml
```

### Network Layouts

```
FRR:  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR  (10.0.0.2/24, AS 65002)
BIRD: rustbgpd (10.0.1.1/24, AS 65001) ── eth1 ─── eth1 ── BIRD (10.0.1.2/24, AS 65003)
```

IP assignment is done via `exec` commands in the topology YAML. Containerlab
`kind: linux` does not auto-assign IPs.

---

## M0 Test Procedures

### Test 1: Session Establishment

Wait for `"session established"` in rustbgpd logs and `Established` in
FRR's `show bgp summary`. Should complete within 10 seconds.

**Pass criteria:** Both sides report Established. Prometheus
`bgp_session_established_total` >= 1.

### Test 2: Metrics Endpoint

```sh
sudo docker exec clab-m0-frr-rustbgpd curl -s http://127.0.0.1:9179/metrics
```

**Pass criteria:** Endpoint responds with Prometheus text format.
`bgp_session_state_transitions_total` shows the full path:
Idle → Connect → OpenSent → OpenConfirm → Established.

### Test 3: Peer Restart Recovery

```sh
sudo docker exec clab-m0-frr-frr pkill bgpd
sudo docker exec clab-m0-frr-frr /usr/lib/frr/bgpd -d -f /etc/frr/frr.conf
# Wait ~15s
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"
```

**Pass criteria:** Session re-establishes automatically.
`bgp_session_established_total` increments. The auto-reconnect logic in
`PeerSession` injects `ManualStart` when the FSM falls to Idle without an
operator-initiated stop.

### Test 4: TCP Reset Recovery

```sh
sudo docker exec clab-m0-frr-frr vtysh -c "clear bgp *"
# Wait ~15s
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"
```

**Pass criteria:** Session re-establishes. `bgp_notifications_received_total`
shows Cease notifications from FRR.

### Test 5: Full Metrics Verification

After tests 1–4, dump metrics and verify consistency:

- `bgp_session_established_total` = number of establishments (expect 3)
- `bgp_session_flaps_total` = transitions away from Established (expect 2)
- `bgp_session_state_transitions_total` covers all visited FSM states
- `bgp_messages_sent_total` and `bgp_messages_received_total` have open,
  keepalive, and notification counters

---

## FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established in <10s |
| Metrics endpoint | PASS | Full FSM path in `state_transitions_total` |
| Peer restart recovery | PASS | Auto-reconnect, `established_total`=2 |
| TCP reset recovery | PASS | Cease NOTIFICATIONs received, `established_total`=3 |
| Full metrics dump | PASS | 3 establishments, 2 flaps, all counters consistent |
| **30-min soak** | **PASS** | **35 min, 35/35 checks, 73 keepalives, 0 flaps** |

## BIRD Test Results (2026-02-27, BIRD 2.0.12)

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established in <1s |
| Metrics endpoint | PASS | Full FSM path in `state_transitions_total` |
| Peer restart recovery | PASS | Auto-reconnect after `birdc down`, `established_total`=2 |
| TCP reset recovery | PASS | `birdc restart`, Cease NOTIFICATIONs received, `established_total`=3 |
| Full metrics dump | PASS | 3 establishments, 2 flaps, Cease subcodes 2+4 |
| **30-min soak** | **PASS** | **35 min, 35/35 checks, 0 flaps** |

---

## Per-Peer Notes

### FRR

- Primary CI target. Must not break.
- FRR 10.3.1 used for M0 validation.
- Requires `no bgp ebgp-requires-policy` in config (rustbgpd has no policy
  engine in M0, so FRR would reject the session without this).
- FRR sends Cease NOTIFICATION on `clear bgp *` (good for testing TCP reset
  recovery path).
- `kind: linux` in containerlab — IP addresses assigned via `exec` post-deploy.

### BIRD

- Primary CI target. Must not break.
- BIRD 2.0.12 (Debian bookworm package) used for M0 validation.
- Custom Docker image built from `tests/interop/Dockerfile.bird` (Debian bookworm + bird2).
- `/run/bird` directory must be created before starting bird (not present in
  the base image; bird needs it for `bird.ctl` socket).
- BIRD sends an empty UPDATE immediately after session establishment (since
  `export none` is configured). rustbgpd receives this as a valid update.
- BIRD sends Cease/Administrative Shutdown (subcode 2) on `birdc down` and
  Cease/Administrative Reset (subcode 4) on `birdc restart`.
- `kind: linux` in containerlab — IP addresses assigned via `exec` post-deploy.

### GoBGP

- Secondary CI target. Failures investigated, not gating.
- Used as a peer, not as reference implementation.

---

## Malformed OPEN Test Results (2026-02-27, FRR 10.3.1)

Config: `tests/interop/configs/rustbgpd-frr-badopen.toml` — rustbgpd expects
`remote_asn=65099` but FRR sends AS 65002.

| Check | Result | Details |
|-------|--------|---------|
| NOTIFICATION sent | PASS | Code 2 (Open Message), Subcode 2 (Bad Peer AS) |
| TCP closed after NOTIFICATION | PASS | Connection torn down immediately |
| No hot reconnect loop | PASS | Deferred reconnect timer (30s) prevents rapid cycling |
| Reconnect fires on schedule | PASS | Second attempt exactly 30s after first rejection |

Previously this scenario caused a hot loop (29K+ cycles / 10s) because
auto-reconnect injected `ManualStart` synchronously. Fixed by adding a
`reconnect_timer` to `PeerSession` that defers reconnection by
`connect_retry_secs`.

---

## Cease Subcode Compatibility

Per RFC_NOTES.md, rustbgpd sends Cease subcode 8 (Out of Resources)
for global route limit violations. Track peer behavior here:

| Peer | Accepts Subcode 8 | Fallback Needed | Notes |
|------|--------------------|-----------------|-------|
| FRR | TBD | TBD | — |
| BIRD | TBD | TBD | — |
| GoBGP | TBD | TBD | — |

---

## M1 Test Procedures

### Prerequisites (in addition to M0)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m1-frr.clab.yml`

### Network Layout

```
M1 FRR: rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 via `network` statements.

### Test 1: Routes Appear in RIB

After session reaches Established, wait for UPDATEs to propagate (typically <5s).
Query via gRPC:

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListReceivedRoutes
```

**Pass criteria:** Response contains 3 routes with prefixes 192.168.1.0,
192.168.2.0, and 10.10.0.0.

### Test 2: Route Attributes Correct

From the same gRPC response, verify:
- `origin` = 0 (IGP) — FRR `network` statements produce IGP origin
- `as_path` contains 65002
- `next_hop` = "10.0.0.2"

### Test 3: Route Withdrawal

Remove a network from FRR:

```sh
docker exec clab-m1-frr-frr vtysh -c "conf t" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" -c "end"
```

Wait ~5s, then query again.

**Pass criteria:** 192.168.2.0/24 is no longer in the response. Other routes remain.

### Test 4: Peer Restart — RIB Cleared and Repopulated

Kill FRR's bgpd, wait for session teardown, restart bgpd.

**Pass criteria:** RIB is empty after peer down, then repopulated with 3 routes
after session re-establishes.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m1-frr.sh
```

Runs all 4 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M1 FRR Test Results (2026-02-27, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m1-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 |
| ORIGIN attribute | PASS | IGP (proto3 default zero) |
| AS_PATH attribute | PASS | Contains 65002 |
| NEXT_HOP attribute | PASS | 10.0.0.2 |
| totalCount field | PASS | Present in gRPC response |
| Route withdrawal | PASS | 192.168.2.0/24 removed after `no network` |
| Remaining routes after withdrawal | PASS | 192.168.1.0/24 still present |
| RIB cleared on peer down | PASS | Empty after bgpd killed |
| Peer restart recovery | PASS | Session re-established (~33s, watchfrr + reconnect timer) |
| RIB repopulated after restart | PASS | 3/3 routes restored |

Note: Test 4 (peer restart) relies on watchfrr auto-restarting bgpd after
`killall -9`. rustbgpd reconnects after `connect_retry_secs` (default 30s).

---

## M2 Test Procedures

M2 reuses the M1 containerlab topology (`m1-frr.clab.yml`) — FRR advertising
3 prefixes to rustbgpd. With a single peer, the Loc-RIB best routes should
match the Adj-RIB-In received routes, with `best: true` set.

### Test 1: ListBestRoutes Returns Correct Routes

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes
```

**Pass criteria:** Response contains 3 routes with `best: true`, correct
`peerAddress` (10.0.0.2), and matching prefixes/attributes.

### Test 2: ListBestRoutes Pagination

```sh
# Page 1 (size 2)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes

# Page 2
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2, "page_token": "2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes
```

**Pass criteria:** Page 1 returns 2 routes with `nextPageToken: "2"`,
page 2 returns 1 route with empty `nextPageToken`.

### Test 3: M1 Regression (all existing tests still pass)

```sh
bash tests/interop/scripts/test-m1-frr.sh
```

**Pass criteria:** 15/15 tests pass — route receipt, attributes, withdrawal,
peer restart recovery all unaffected by M2 changes.

---

## M2 FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| M1 regression (15 tests) | PASS | All 15 automated tests pass |
| ListBestRoutes — 3 routes | PASS | All 3 prefixes with `best: true` |
| ListBestRoutes — peerAddress | PASS | `10.0.0.2` from `route.peer` field |
| ListBestRoutes — attributes | PASS | AS_PATH=[65002], NEXT_HOP=10.0.0.2 |
| ListBestRoutes — pagination (page 1) | PASS | 2 routes, nextPageToken="2" |
| ListBestRoutes — pagination (page 2) | PASS | 1 route, no nextPageToken |

---

## M3 Test Procedures

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m3-frr.clab.yml`

### Network Layout

```
M3 FRR (3-node):

  rustbgpd (AS 65001)
  eth1: 10.0.0.1/24        eth2: 10.0.1.1/24
       │                         │
       │                         │
  eth1: 10.0.0.2/24        eth1: 10.0.1.2/24
  FRR-A (AS 65002)          FRR-B (AS 65003)
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 via `network` statements.
FRR-B receives only (no route advertisements).

### Test 1: Route Redistribution

After sessions reach Established, FRR-A's routes should propagate through
rustbgpd to FRR-B.

```sh
docker exec clab-m3-frr-frrb vtysh -c "show bgp ipv4 unicast"
```

**Pass criteria:** FRR-B sees 3 routes from FRR-A with AS_PATH `65001 65002`.

### Test 2: Split Horizon

FRR-A should NOT receive its own routes back from rustbgpd.

```sh
docker exec clab-m3-frr-frra vtysh -c "show bgp ipv4 unicast"
```

**Pass criteria:** FRR-A sees only its own locally-originated routes, not
routes reflected back through rustbgpd.

### Test 3: Route Injection

Inject a route via gRPC and verify both peers receive it.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24, "next_hop": "10.0.0.1"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/AddPath

docker exec clab-m3-frr-frra vtysh -c "show bgp ipv4 unicast 10.99.0.0/24"
docker exec clab-m3-frr-frrb vtysh -c "show bgp ipv4 unicast 10.99.0.0/24"
```

**Pass criteria:** Both FRR-A and FRR-B see 10.99.0.0/24 with AS_PATH `65001`.

### Test 4: Withdrawal Propagation

Remove a network from FRR-A and verify FRR-B sees the withdrawal.

```sh
docker exec clab-m3-frr-frra vtysh -c "conf t" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" -c "end"
```

**Pass criteria:** FRR-B no longer sees 192.168.2.0/24.

### Test 5: DeletePath

Withdraw the injected route via gRPC.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/DeletePath
```

**Pass criteria:** Both FRR-A and FRR-B no longer see 10.99.0.0/24.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m3-frr.sh
```

Runs all 5 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M3 FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| Route redistribution (A→B) | PASS | FRR-B sees 3 routes with AS_PATH 65001 65002 |
| Split horizon | PASS | FRR-A does not receive its own routes back |
| Route injection | PASS | Both peers see 10.99.0.0/24 after AddPath |
| Withdrawal propagation | PASS | FRR-B drops 192.168.2.0/24 after FRR-A withdraws |
| DeletePath | PASS | Both peers drop 10.99.0.0/24 after DeletePath |

---

## M4 Test Procedures

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m4-frr.clab.yml`

### Network Layout

```
M4 FRR (10-node):

                        rustbgpd (AS 65001)
        eth1: 10.0.10.1   ...   eth10: 10.0.19.1
             │                        │
     10.0.10.2/24              10.0.19.2/24
     FRR-01 (AS 65010)   ...  FRR-10 (AS 65019)
```

8 FRR peers are statically configured (FRR-01 through FRR-08).
FRR-09 and FRR-10 are present in the topology but added dynamically via gRPC.
Each FRR peer advertises 2 prefixes (172.16.x0.0/24, 172.16.x1.0/24).
FRR-01 has a per-peer export policy: deny 10.0.0.0/8 le 32.

### Test 1: All 8 Static Sessions Establish

Wait for all 8 FRR peers to report `Established` via `show bgp neighbors`.

**Pass criteria:** All 8 sessions reach Established within 90s.

### Test 2: ListNeighbors Returns 8 Peers

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/ListNeighbors
```

**Pass criteria:** Response contains 8 neighbors with `SESSION_STATE_ESTABLISHED`.

### Test 3: Received Routes from All Peers

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListReceivedRoutes
```

**Pass criteria:** At least 16 routes received (2 per peer × 8 peers).
In practice, routes redistributed between peers may increase the total.

### Test 4: Per-Peer Export Policy

Inject 10.99.0.0/24 via `AddPath`. FRR-01 (with deny 10.0.0.0/8 le 32
export policy) should NOT see it. FRR-02 (no per-peer policy) should see it.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24, "next_hop": "10.0.10.1"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/AddPath

docker exec clab-m4-frr-frr-01 vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json"
docker exec clab-m4-frr-frr-02 vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json"
```

**Pass criteria:** FRR-01 does not have 10.99.0.0/24. FRR-02 does.

### Test 5: Dynamic AddNeighbor

Add FRR-09 (AS 65018) via gRPC. Verify session establishes and ListNeighbors
returns 9.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"config": {"address": "10.0.18.2", "remote_asn": 65018, "description": "frr-09-dynamic"}}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/AddNeighbor
```

**Pass criteria:** FRR-09 session reaches Established. ListNeighbors returns 9.

### Test 6: Dynamic DeleteNeighbor

Delete FRR-09 via gRPC. Verify ListNeighbors returns 8 again.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.18.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/DeleteNeighbor
```

**Pass criteria:** ListNeighbors returns 8.

### Test 7: Enable/Disable Neighbor

Disable FRR-01 via `DisableNeighbor`, verify session drops. Re-enable via
`EnableNeighbor`, verify session re-establishes.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.10.2", "reason": "test"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/DisableNeighbor

# Wait 5s, verify FRR-01 is not Established

grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.10.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/EnableNeighbor
```

**Pass criteria:** FRR-01 drops to Active/Idle after disable, then
re-establishes after enable.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m4-frr.sh
```

Runs all 7 tests automatically. Requires containerlab topology deployed,
rustbgpd started, and `grpcurl` on the host.

---

## M4 FRR Test Results (2026-02-27, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m4-frr.sh` — **17 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Static sessions (8/8) | PASS | All 8 sessions established on first attempt |
| ListNeighbors count | PASS | Returned 8 peers with SESSION_STATE_ESTABLISHED |
| Received routes | PASS | 30 routes received (>= 16 expected) |
| Per-peer export policy (FRR-01 deny) | PASS | FRR-01 correctly denied 10.99.0.0/24 |
| Per-peer export policy (FRR-02 allow) | PASS | FRR-02 received 10.99.0.0/24 |
| Dynamic AddNeighbor (FRR-09) | PASS | Session established, ListNeighbors returned 9 |
| Dynamic DeleteNeighbor (FRR-09) | PASS | ListNeighbors returned 8 after deletion |
| DisableNeighbor (FRR-01) | PASS | Session dropped to Active state |
| EnableNeighbor (FRR-01) | PASS | Session re-established on first attempt |

---

## M10 Test Procedures (MP-BGP / IPv6 Unicast)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m10-frr-ipv6.clab.yml`

### Network Layout

```
M10 FRR (dual-stack):

  rustbgpd (AS 65001)               FRR (AS 65002)
  eth1: 10.0.0.1/24                 eth1: 10.0.0.2/24
  eth1: fd00::1/64                  eth1: fd00::2/64
       │                                 │
       └─────────── eth1 ────────────────┘
```

BGP session over IPv4 (10.0.0.1 ↔ 10.0.0.2) with MP-BGP IPv6 unicast negotiated.

FRR advertises:
- IPv4: 192.168.1.0/24, 10.10.0.0/16
- IPv6: 2001:db8:1::/48, 2001:db8:2::/48

### Test 1: Session with IPv6 AFI/SAFI Capability

Wait for session to reach Established. Verify FRR sees IPv6 unicast AFI/SAFI
negotiated in the neighbor capabilities.

**Pass criteria:** `ipv6Unicast` appears in FRR's `show bgp neighbors` JSON.

### Test 2: IPv4 Routes Received (backward compat)

Query received routes via gRPC and verify IPv4 prefixes are present.

**Pass criteria:** 192.168.1.0 and 10.10.0.0 in Adj-RIB-In.

### Test 3: IPv6 Routes Received via MP_REACH_NLRI

Query received routes and verify IPv6 prefixes are present.

**Pass criteria:** 2001:db8:1:: and 2001:db8:2:: in Adj-RIB-In.

### Test 4: IPv6 Routes in Best Routes (Loc-RIB)

Query best routes and verify IPv6 prefixes appear.

**Pass criteria:** 2001:db8:1:: and 2001:db8:2:: in Loc-RIB.

### Test 5: IPv6 Route Withdrawal

Withdraw 2001:db8:2::/48 from FRR, verify it disappears from rustbgpd's RIB.
Other routes (IPv4 + remaining IPv6) must still be present.

**Pass criteria:** 2001:db8:2:: withdrawn; 2001:db8:1:: and 192.168.1.0 still present.

### Test 6: IPv6 Route Injection via gRPC

Inject 2001:db8:ff::/48 via `AddPath`, verify it appears in best routes.
Clean up via `DeletePath`.

**Pass criteria:** Injected prefix appears in Loc-RIB.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m10-frr-ipv6.sh
```

Runs all 6 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M11 Test Procedures (Graceful Restart — RFC 4724)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m11-gr-frr.clab.yml`

### Network Layout

```
M11 GR FRR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR has `bgp graceful-restart` with `restart-time 30`. rustbgpd has
`gr_restart_time = 30`, `gr_stale_routes_time = 30`. Short timers keep tests fast.

FRR advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16.

### Test 1: GR Capability Negotiated

After session reaches Established, verify FRR reports GR capability in
`show bgp neighbors` JSON. Verify `bgp_gr_stale_routes` = 0 in steady state.

**Pass criteria:** FRR sees GR capability. No stale routes in steady state.

### Test 2: Peer Restart Preserves Routes (Stale Marking)

Kill FRR's bgpd (`killall -9 bgpd`). Wait for rustbgpd to detect session down.
Query metrics to verify GR is active and routes are preserved as stale.

**Pass criteria:** `bgp_gr_active_peers` >= 1, `bgp_gr_stale_routes` >= 3,
routes still present in RIB.

### Test 3: End-of-RIB Clears Stale Flag

watchfrr restarts bgpd automatically. Wait for session re-establishment.
After FRR sends its routes + EoR, stale flags should be cleared.

**Pass criteria:** `bgp_gr_stale_routes` = 0, `bgp_gr_active_peers` = 0,
routes still present and valid.

### Test 4: GR Timer Expiry Sweeps Stale Routes

Kill FRR's bgpd AND watchfrr (prevent restart). Wait for GR restart timer
to expire (30s). Stale routes should be swept from the RIB.

**Pass criteria:** `bgp_gr_stale_routes` = 0, peer routes removed from RIB,
`bgp_gr_timer_expired_total` >= 1.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m11-gr-frr.sh
```

Runs all 4 tests automatically. Tests 1–3 run sequentially (test 2 kills bgpd,
test 3 waits for watchfrr to restart it). Test 4 kills both bgpd and watchfrr
to force timer expiry.

---

## M11 GR FRR Test Results (2026-03-01, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m11-gr-frr.sh` — **17 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB on first attempt |
| GR capability in FRR neighbor state | PASS | `gracefulRestart` present in JSON |
| No stale routes in steady state | PASS | `bgp_gr_stale_routes` = 0 |
| GR active after peer kill | PASS | `bgp_gr_active_peers` = 1 |
| Routes preserved as stale | PASS | 3 stale routes during GR |
| Routes in RIB during GR | PASS | 3 routes still present |
| Session re-established after bgpd restart | PASS | watchfrr restarted bgpd, established on attempt 5 |
| Stale cleared after EoR | PASS | `bgp_gr_stale_routes` = 0 |
| GR completed after EoR | PASS | `bgp_gr_active_peers` = 0 |
| Routes valid after GR | PASS | 3 routes still present |
| GR active after kill (no watchfrr) | PASS | `bgp_gr_active_peers` = 1 |
| Routes stale during timer wait | PASS | 3 stale routes |
| Stale swept after timer expiry | PASS | `bgp_gr_stale_routes` = 0 |
| RIB cleared after sweep | PASS | 0 routes from peer |
| Timer expired counter | PASS | `bgp_gr_timer_expired_total` = 1 |
| GR completed after expiry | PASS | `bgp_gr_active_peers` = 0 |

---

## M12 Test Procedures (Extended Communities — RFC 4360)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m12-ec-frr.clab.yml`

### Network Layout

```
M12 EC FRR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR has a route-map `EC_OUT` that applies `set extcommunity rt 65002:100` to
all outbound routes. FRR advertises: 192.168.1.0/24, 192.168.2.0/24.

### Test 1: Routes Received with Extended Communities

After session reaches Established, verify routes have the `extendedCommunities`
field populated in the gRPC response.

**Pass criteria:** Both prefixes present, `extendedCommunities` field non-empty.

### Test 2: Extended Community Values Correct

Verify the raw uint64 value matches the expected encoding for RT:65002:100
(2-octet AS specific, type 0x00, subtype 0x02).

**Pass criteria:** Decimal value `842131417596004` (= `0x0002FDEA00000064`)
appears in the route data. Both routes carry the EC.

### Test 3: Inject Route with Extended Community

Inject 10.99.0.0/24 via `AddPath` with RT:65001:42. Verify the injected route
appears in best routes with the correct EC value.

**Pass criteria:** Injected route in Loc-RIB with EC value `842127122628650`.

### Test 4: Extended Communities in Best Routes

Verify FRR-originated routes also carry extended communities in ListBestRoutes
(not just ListReceivedRoutes).

**Pass criteria:** RT:65002:100 present in best routes for FRR prefixes.

### Test 5: Delete Injected Route

Delete 10.99.0.0/24 via `DeletePath`. Verify removal. FRR routes must remain.

**Pass criteria:** Injected route removed, FRR routes still present.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m12-ec-frr.sh
```

Runs all 5 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M12 EC FRR Test Results (2026-03-01, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m12-ec-frr.sh` — **14 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on attempt 30 |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| extendedCommunities field present | PASS | Field populated in gRPC response |
| RT:65002:100 value correct | PASS | Decimal 842131417596004 matches |
| Both routes have ECs | PASS | 2 routes with extendedCommunities |
| AddPath with EC accepted | PASS | 10.99.0.0/24 injected with RT:65001:42 |
| Injected route in best routes | PASS | Present in Loc-RIB |
| Injected EC value correct | PASS | Decimal 842127122628650 matches |
| FRR route in best routes | PASS | 192.168.1.0/24 present |
| RT:65002:100 in best routes | PASS | EC preserved through best-path selection |
| DeletePath removes injected route | PASS | 10.99.0.0/24 removed |
| FRR routes survive deletion | PASS | 192.168.1.0/24 still present |

---

## M13 Test Procedures (Policy Engine)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m13-policy-frr.clab.yml`

### Network Layout

```
M13 Policy (3-node):

  FRR-A (AS 65002)          rustbgpd (AS 65001)          FRR-B (AS 65003)
  eth1: 10.0.0.2/24  ────  eth1: 10.0.0.1/24
                            eth2: 10.0.1.1/24  ────  eth1: 10.0.1.2/24
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16.
FRR-B receives only (no route advertisements).

rustbgpd import chain (named policies, GoBGP-style accumulation):
1. `deny-long-prefixes` — deny /25 and longer
2. `tag-internal` — add community 65001:100 to 10.0.0.0/8 le 16
3. `set-lp-upstream` — set LOCAL_PREF 200 for AS_PATH matching `_65002_`

rustbgpd export policy (inline first-match):
1. Deny 10.10.0.0/16
2. Permit all with MED 50 + AS_PATH prepend 65001 ×2

### Test 1: Import LOCAL_PREF

Verify 192.168.1.0/24 has LOCAL_PREF 200 (AS_PATH regex match).

### Test 2: Import Community Add

Verify 10.10.0.0/16 has standard community 65001:100 (prefix match via chain accumulation).

### Test 3: Export Deny

Verify 10.10.0.0/16 is NOT present on FRR-B. Other prefixes must be present.

### Test 4: Export MED

Verify 192.168.1.0/24 has MED 50 on FRR-B.

### Test 5: Export AS_PATH Prepend

Verify AS_PATH on FRR-B has 3× 65001 (1 natural eBGP + 2 prepended) followed by 65002.

### Test 6: Import LOCAL_PREF All Routes

Verify all 3 routes from AS 65002 have LOCAL_PREF 200.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m13-policy-frr.sh
```

---

## M13 Policy FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m13-policy-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB |
| FRR-B routes (2/2) | PASS | 10.10.0.0/16 correctly denied |
| Import LOCAL_PREF 200 | PASS | 192.168.1.0/24 has LOCAL_PREF 200 |
| Import community 65001:100 | PASS | 10.10.0.0/16 has community via chain accumulation |
| LOCAL_PREF all routes | PASS | All 3 routes from AS 65002 have LOCAL_PREF 200 |
| Export deny 10.10.0.0/16 | PASS | Not present on FRR-B |
| Export permit 192.168.x.0 | PASS | Both /24 prefixes on FRR-B |
| Export MED 50 | PASS | 192.168.1.0/24 MED=50 on FRR-B |
| Export AS_PATH prepend | PASS | 3× 65001 (1 natural + 2 prepended) |
| AS_PATH origin AS | PASS | 65002 present in AS_PATH |

---

## M14 Test Procedures (Route Reflector — RFC 4456)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m14-rr-frr.clab.yml`

### Network Layout

```
M14 Route Reflector (3-node iBGP):

  FRR-Client1 (AS 65001)          rustbgpd RR (AS 65001)          FRR-Client2 (AS 65001)
  eth1: 10.0.0.2/24  ────────  eth1: 10.0.0.1/24
  router-id: 10.0.0.2            cluster_id: 10.0.0.1
                                  eth2: 10.0.1.1/24  ────────  eth1: 10.0.1.2/24
                                                                 router-id: 10.0.1.2
```

rustbgpd is the route reflector with `cluster_id = "10.0.0.1"` and both neighbors
marked `route_reflector_client = true`.

Client1 advertises: 192.168.10.0/24, 192.168.11.0/24.
Client2 advertises: 192.168.20.0/24.

### Test 1: Client1 Routes Reflected to Client2

Verify FRR-Client2 receives 192.168.10.0/24 and 192.168.11.0/24.

### Test 2: Client2 Routes Reflected to Client1

Verify FRR-Client1 receives 192.168.20.0/24.

### Test 3: ORIGINATOR_ID Set Correctly

Verify reflected routes carry ORIGINATOR_ID matching the originator's router-id.

### Test 4: CLUSTER_LIST Contains RR Cluster ID

Verify reflected routes carry CLUSTER_LIST containing 10.0.0.1.

### Test 5: RR RIB Has All Routes

Verify rustbgpd's Loc-RIB has all 3 routes.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m14-rr-frr.sh
```

---

## M14 RR FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m14-rr-frr.sh` — **14 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (Client1) | PASS | Established on first attempt |
| Session establishment (Client2) | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB |
| Client2 has Client1 routes | PASS | 192.168.10.0/24, 192.168.11.0/24 reflected |
| Client1 has Client2 routes | PASS | 192.168.20.0/24 reflected |
| RR RIB complete | PASS | All 3 routes in Loc-RIB |
| Client1→Client2 reflection | PASS | Both /24 prefixes reflected |
| Client2→Client1 reflection | PASS | 192.168.20.0/24 reflected |
| ORIGINATOR_ID (Client1) | PASS | 10.0.0.2 (Client1's router-id) |
| ORIGINATOR_ID (Client2) | PASS | 10.0.1.2 (Client2's router-id) |
| CLUSTER_LIST | PASS | 10.0.0.1 present in route attributes |

---

## M15 Test Procedures (Route Refresh — RFC 2918 + RFC 7313)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m15-rr-frr.clab.yml`

### Network Layout

```
M15 Route Refresh:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

rustbgpd has an import policy setting LOCAL_PREF 150. FRR advertises 192.168.1.0/24
and 192.168.2.0/24. A third route (10.99.0.0/24) is added dynamically by FRR during
the test.

### Test 1: Initial Routes with Import Policy

Verify routes arrive with LOCAL_PREF 150 from the import policy.

### Test 2: SoftResetIn Triggers Re-advertisement

Trigger `SoftResetIn` via gRPC. Verify the session remains Established (no flap)
and all routes are still present.

### Test 3: Import Policy After SoftResetIn

Verify LOCAL_PREF 150 is still applied after the soft reset.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m15-rr-frr.sh
```

---

## M15 Route Refresh FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m15-rr-frr.sh` — **10 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| 192.168.1.0/24 present | PASS | In received routes |
| 192.168.2.0/24 present | PASS | In received routes |
| LOCAL_PREF = 150 on import | PASS | Import policy applied |
| New route received | PASS | 10.99.0.0/24 via normal UPDATE |
| SoftResetIn RPC completed | PASS | gRPC call succeeded |
| Session stable after SoftResetIn | PASS | Established, no flap |
| All routes after SoftResetIn | PASS | 3 routes still present |
| LOCAL_PREF after SoftResetIn | PASS | 150 still applied |

---

## M16 Test Procedures (LLGR — RFC 9494)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml`

### Network Layout

```
M16 LLGR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

rustbgpd has `graceful_restart = true`, `gr_restart_time = 15`, `llgr_stale_time = 60`.
FRR has `bgp graceful-restart` and `bgp long-lived-graceful-restart stale-time 60`.

### Test 1: Initial Routes Received

Verify routes arrive normally.

### Test 2: GR → LLGR Transition

Kill FRR's bgpd. Wait for GR timer (15s) to expire. Routes should still be present
(LLGR preserves them beyond the GR timer).

### Test 3: Reconnect Clears LLGR-Stale

watchfrr restarts bgpd. After session re-establishment and EoR, LLGR-stale state
should be cleared and routes remain valid.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m16-llgr-frr.sh
```

---

## M16 LLGR FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m16-llgr-frr.sh` — **8 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| 192.168.1.0/24 present | PASS | In received routes |
| 192.168.2.0/24 present | PASS | In received routes |
| Routes preserved after GR timer | PASS | 2 routes still present (LLGR active) |
| Session re-established | PASS | watchfrr restarted bgpd |
| Routes present after reconnect | PASS | 2 routes still present |
| LLGR-stale cleared | PASS | No stale routes after EoR |

---

## M17 Test Procedures (Add-Path — RFC 7911)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m17-addpath-frr.clab.yml`

### Network Layout

```
M17 Add-Path (4-node):

  FRR-A (AS 65002)            rustbgpd (AS 65001)             FRR-Client (AS 65004)
  eth1: 10.0.0.2/24  ────  eth1: 10.0.0.1/24                 add_path send=true
                             eth2: 10.0.1.1/24  ────  ...       send_max=4
  FRR-B (AS 65003)           eth3: 10.0.2.1/24  ────  eth1: 10.0.2.2/24
  eth1: 10.0.1.2/24  ────
```

FRR-A and FRR-B both advertise 192.168.10.0/24 (shared prefix with different AS_PATHs).
FRR-A also advertises 192.168.1.0/24; FRR-B also advertises 192.168.2.0/24.

FRR-Client has `neighbor X addpath-rx-all-paths` to accept multiple paths.

### Test 1: Routes from Both Source Peers

Verify all 4 routes appear in Adj-RIB-In (2 from FRR-A, 2 from FRR-B).

### Test 2: Multi-path on Client

Verify FRR-Client receives 2 paths for 192.168.10.0/24.

### Test 3: Distinct Path IDs

Verify the 2 advertised routes for 192.168.10.0/24 have distinct `path_id` values.

### Test 4: Unique Prefixes Forwarded

Verify unique prefixes (192.168.1.0/24, 192.168.2.0/24) are advertised to the client.

### Test 5: Different AS_PATHs

Verify the two paths for 192.168.10.0/24 on FRR-Client have different AS_PATHs
(one via AS 65002, one via AS 65003). Note: eBGP next-hop-self means both paths
share the same next-hop (rustbgpd's address), so AS_PATH is the correct differentiator.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m17-addpath-frr.sh
```

---

## M17 Add-Path FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m17-addpath-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established |
| Session establishment (FRR-Client) | PASS | Established |
| Routes received (4/4) | PASS | All 4 routes in RIB |
| FRR-A 192.168.10.0 present | PASS | Shared prefix from source A |
| FRR-A 192.168.1.0 present | PASS | Unique prefix from source A |
| FRR-B 192.168.10.0 present | PASS | Shared prefix from source B |
| FRR-B 192.168.2.0 present | PASS | Unique prefix from source B |
| Multi-path on client (2 paths) | PASS | FRR-Client has 2 paths for 192.168.10.0/24 |
| Distinct path_ids | PASS | 2 unique path IDs for shared prefix |
| 192.168.1.0/24 forwarded | PASS | Unique prefix advertised to client |
| 192.168.2.0/24 forwarded | PASS | Unique prefix advertised to client |
| Path via AS 65002 | PASS | AS_PATH differentiation correct |
| Path via AS 65003 | PASS | AS_PATH differentiation correct |

---

## M18 Test Procedures (Extended Next-Hop — RFC 8950)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m18-extnexthop-frr.clab.yml`

### Network Layout

```
M18 Extended Next-Hop (dual-stack):

  rustbgpd (AS 65001)               FRR (AS 65002)
  eth1: 10.0.0.1/24                 eth1: 10.0.0.2/24
  eth1: fd00::1/64                  eth1: fd00::2/64
       │                                 │
       └─────────── eth1 ────────────────┘
```

Both sides negotiate Extended Next-Hop capability. rustbgpd has
`families = ["ipv4_unicast", "ipv6_unicast"]` and `local_ipv6_nexthop = "fd00::1"`.

FRR has `capability extended-nexthop` and advertises:
- IPv4: 192.168.1.0/24, 192.168.2.0/24
- IPv6: 2001:db8:1::/48

### Test 1: Session with Extended Next-Hop Capability

Verify session reaches Established and Extended Next-Hop capability is negotiated.

### Test 2: IPv4 Routes Received

Verify both IPv4 prefixes are received.

### Test 3: IPv6 Routes Received

Verify the IPv6 prefix is received via MP_REACH_NLRI.

### Test 4: Injected Route Reaches FRR

Inject 10.99.0.0/24 via gRPC `AddPath` and verify FRR receives it.

### Test 5: Extended Next-Hop Negotiation Succeeded

Verify FRR receives the injected route (proves outbound encoding works with
Extended Next-Hop negotiated).

### Automated Test Script

```sh
bash tests/interop/scripts/test-m18-extnexthop-frr.sh
```

---

## M18 Extended Next-Hop FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m18-extnexthop-frr.sh` — **9 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 routes in RIB |
| Session Established state | PASS | Via FRR neighbor JSON |
| Extended Next-Hop capability | PASS | Present in neighbor capabilities |
| IPv4 192.168.1.0 received | PASS | Standard IPv4 route |
| IPv4 192.168.2.0 received | PASS | Standard IPv4 route |
| IPv6 2001:db8:1:: received | PASS | Via MP_REACH_NLRI |
| Injected route reaches FRR | PASS | 10.99.0.0/24 via AddPath |
| Extended NH negotiation works | PASS | Route received with valid next-hop |

---

## M19 Test Procedures (Transparent Route Server)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m19-routeserver-frr.clab.yml`

### Network Layout

```
M19 Transparent Route Server (3-node):

  FRR-A (AS 65002)       rustbgpd RS (AS 65001)       FRR-B (AS 65003)
  eth1: 10.0.0.2/24  ──  eth1: 10.0.0.1/24
  route_server_client     eth2: 10.0.1.1/24  ──  eth1: 10.0.1.2/24
                          ip_forward=1                 route_server_client
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24.
FRR-B advertises: 192.168.3.0/24.

Both peers are `route_server_client = true` on rustbgpd.

### Route Server Nuances

**Cross-subnet next-hop reachability:** Peers are on separate /24 subnets
(containerlab point-to-point links). Because `route_server_client` preserves
the original NEXT_HOP, FRR-B receives routes with NH=10.0.0.2 (a different
subnet). Each FRR peer needs a static route to the other's subnet via
rustbgpd, and rustbgpd needs `ip_forward=1`.

**FRR enforce-first-as (critical):** FRR 10.x enables `enforce-first-as` by
default. When rustbgpd (AS 65001) transparently forwards a route with
AS_PATH `[65002]`, FRR-B rejects it with `"incorrect first AS (must be 65001)"`.
The fix is `no neighbor X.X.X.X enforce-first-as` **per-neighbor** in each FRR
config. The global `no bgp enforce-first-as` alone is insufficient in FRR 10.3.1.

### Test 1: No ASN Prepend on FRR-B

Verify routes from FRR-A arrive at FRR-B with AS_PATH `[65002]` (no 65001 inserted).

### Test 2: NEXT_HOP Preserved on FRR-B

Verify routes show NEXT_HOP = 10.0.0.2 (FRR-A's original address).

### Test 3: No ASN Prepend on FRR-A

Verify routes from FRR-B arrive at FRR-A with AS_PATH `[65003]`.

### Test 4: NEXT_HOP Preserved on FRR-A

Verify routes show NEXT_HOP = 10.0.1.2 (FRR-B's original address).

### Test 5: All Prefixes Forwarded

Verify both FRR-A prefixes (192.168.1.0/24, 192.168.2.0/24) are present on FRR-B.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m19-routeserver-frr.sh
```

---

## M19 Route Server FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m19-routeserver-frr.sh` — **13 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established on first attempt |
| Routes in RIB (3/3) | PASS | All routes from both peers |
| FRR-B routes (3 total) | PASS | 1 local + 2 from FRR-A |
| FRR-A routes (3 total) | PASS | 2 local + 1 from FRR-B |
| AS_PATH on FRR-B contains 65002 | PASS | Origin AS preserved |
| AS_PATH on FRR-B no 65001 | PASS | Route server ASN not prepended |
| NEXT_HOP on FRR-B = 10.0.0.2 | PASS | FRR-A's original NH preserved |
| AS_PATH on FRR-A contains 65003 | PASS | Origin AS preserved |
| AS_PATH on FRR-A no 65001 | PASS | Route server ASN not prepended |
| NEXT_HOP on FRR-A = 10.0.1.2 | PASS | FRR-B's original NH preserved |
| 192.168.1.0/24 on FRR-B | PASS | Prefix forwarded |
| 192.168.2.0/24 on FRR-B | PASS | Prefix forwarded |

---

## M20 Test Procedures (Private AS Removal)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m20-privateas-frr.clab.yml`

### Network Layout

```
M20 Private AS Removal (5-node):

  FRR-Source (AS 64512)  ──  rustbgpd (AS 65001)  ──  FRR-Remove  (AS 65002)
  private AS, advertises       │                       remove_private_as = "remove"
  192.168.1.0/24 [64512]       │
  192.168.2.0/24 [64512,64000] ├──  FRR-All     (AS 65003)
  (route-map prepend)          │    remove_private_as = "all"
                               │
                               └──  FRR-Replace (AS 65004)
                                    remove_private_as = "replace"
```

FRR-Source (AS 64512, private) advertises two prefixes:
- 192.168.1.0/24 with AS_PATH `[64512]` (all-private)
- 192.168.2.0/24 with AS_PATH `[64512, 64000]` (mixed — 64000 is public, prepended via route-map)

Three observer peers each use a different `remove_private_as` mode:
- **remove**: Strip private ASNs only when the ENTIRE original path is private.
- **all**: Strip all private ASNs unconditionally.
- **replace**: Replace each private ASN with the local ASN (65001).

### Expected AS_PATHs (after rustbgpd prepends its own AS 65001)

| Prefix | Loc-RIB | remove outbound | all outbound | replace outbound |
|--------|---------|-----------------|--------------|------------------|
| 192.168.1.0/24 | `[64512]` | `[65001]` | `[65001]` | `[65001, 65001]` |
| 192.168.2.0/24 | `[64512, 64000]` | `[65001, 64512, 64000]` | `[65001, 64000]` | `[65001, 65001, 64000]` |

Note: The public ASN in the mixed path must NOT be in the 64512-65534 or
4200000000-4294967294 ranges (RFC 6996 private ASN ranges). The test uses
64000 which is below the private range threshold.

### Test 1: Source Routes Received

Verify both prefixes arrive in rustbgpd's Adj-RIB-In.

### Test 2: Remove Mode

Verify 192.168.1.0/24 has private ASNs removed (all-private path) and
192.168.2.0/24 retains private ASN 64512 (mixed path, not stripped in "remove" mode).

### Test 3: All Mode

Verify both prefixes have all private ASNs stripped. Public ASN 64000 preserved.

### Test 4: Replace Mode

Verify private ASNs are replaced with the local ASN (65001). Public ASN preserved.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m20-privateas-frr.sh
```

---

## M20 Private AS Removal FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m20-privateas-frr.sh` — **22 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (Source) | PASS | Established |
| Session establishment (Remove) | PASS | Established |
| Session establishment (All) | PASS | Established |
| Session establishment (Replace) | PASS | Established |
| Routes in RIB (2/2) | PASS | Both prefixes from source |
| Observer routes (Remove) | PASS | 2 routes received |
| Observer routes (All) | PASS | 2 routes received |
| Observer routes (Replace) | PASS | 2 routes received |
| Source: 192.168.1.0 present | PASS | All-private path |
| Source: 192.168.2.0 present | PASS | Mixed path |
| Remove: 192.168.1.0 AS_PATH=[65001] | PASS | Private ASN removed |
| Remove: 192.168.2.0 private preserved | PASS | Mixed path, not all-private |
| Remove: 192.168.2.0 public 64000 present | PASS | Public ASN preserved |
| All: 192.168.1.0 AS_PATH=[65001] | PASS | Private stripped |
| All: 192.168.2.0 private removed | PASS | 64512 stripped |
| All: 192.168.2.0 public 64000 preserved | PASS | Public ASN kept |
| All: 192.168.2.0 local ASN prepended | PASS | 65001 present |
| Replace: 192.168.1.0 2× 65001 | PASS | 1 replaced + 1 prepended |
| Replace: 192.168.1.0 no 64512 | PASS | Private ASN replaced |
| Replace: 192.168.2.0 2× 65001 | PASS | 1 replaced + 1 prepended |
| Replace: 192.168.2.0 public 64000 preserved | PASS | Public ASN kept |
| Replace: 192.168.2.0 no 64512 | PASS | Private ASN replaced |

---

## Troubleshooting

- **Docker network overlap:** Containerlab's default management network
  (172.20.20.0/24) can conflict with other Docker networks. Stop conflicting
  containers or use `containerlab deploy --reconfigure`.
- **FRR bgpd won't peer:** Ensure `-f /etc/frr/frr.conf` is passed when
  restarting bgpd manually. Without it, bgpd starts with no config.
- **No auto-reconnect:** If rustbgpd session stays in Idle after a peer
  failure, verify `stop_requested` isn't set. Only `Stop` and `Shutdown`
  commands set it.
- **Large Docker build context:** Ensure `.dockerignore` includes `target/`.
  Without it, the build context exceeds 2 GB.
- **BIRD "Cannot create control socket":** Run `mkdir -p /run/bird` inside the
  container before starting bird. The Debian package expects this directory.
- **FRR "incorrect first AS" with route server:** FRR 10.x enables
  `enforce-first-as` by default. For transparent route server setups where
  the AS_PATH doesn't start with the route server's ASN, you must add
  `no neighbor X.X.X.X enforce-first-as` per-neighbor in each FRR client
  config. The global `no bgp enforce-first-as` is insufficient in FRR 10.3.1.
- **Route server routes "0 accepted prefixes":** If FRR shows `PfxRcd=0` but
  rustbgpd reports routes sent, check `enforce-first-as` (above) and also
  verify cross-subnet next-hop reachability — preserved next-hops on different
  subnets need static routes through the route server.
- **BIRD shows "Active / Connection refused":** BIRD is trying outbound to
  rustbgpd's port 179, but rustbgpd only connects outbound in M0 (no listener).
  This is normal — rustbgpd's outbound connect will establish the session.
  If it persists, check the connect-retry timer interval.

---

## Missing Interop Coverage

Tracked gaps where code and unit tests exist but real-system interop validation
is missing. Prioritized by risk.

### P0 — High value, should validate before stable release

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| ~~**RPKI/RTR cache**~~ | ~~Done (M21)~~ | ~~GoRTR interop validated: RTR session, v2→v1 fallback, VRP delivery, origin validation (Valid/Invalid/NotFound). Found and fixed v2→v1 fallback bug.~~ |
| **ASPA/RTR v2 cache** | RTR v2 codec, ASPA PDU type 11, v1 fallback, AspaTable, unit tests | No scenario proving v2 query negotiation, v1 fallback behavior, ASPA records arriving and affecting best-path. |
| ~~**FlowSpec peer**~~ | ~~Done (M22)~~ | ~~FRR interop validated: gRPC injection, eBGP distribution, withdrawal propagation. FRR receives but cannot originate.~~ |

### P1 — Important for broader adoption

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| ~~**GoBGP as peer**~~ | ~~Done (M23)~~ | ~~GoBGP 4.3.0 interop validated: session, bidirectional route exchange, attributes, withdrawal.~~ |
| ~~**BMP collector**~~ | ~~Done (M24)~~ | ~~Python BMP receiver validates Initiation, PeerUp, RouteMonitoring messages and ordering.~~ |
| ~~**TCP MD5 / GTSM**~~ | ~~Done (M25)~~ | ~~Two-peer scenario: MD5-authenticated session + GTSM-secured session, routes exchanged over both.~~ |
| **Cease subcode 8** | Sent for global route limit violations | FRR/BIRD/GoBGP acceptance TBD (see Cease Subcode Compatibility table above). |
