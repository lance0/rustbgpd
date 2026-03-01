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
| GoBGP | 3.x | — | Planned | Secondary target | — | — |
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

Per RFC_NOTES.md, rustbgpd sends Cease subcode 4 (Out of Resources)
for global route limit violations. Track peer behavior here:

| Peer | Accepts Subcode 4 | Fallback Needed | Notes |
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
- **BIRD shows "Active / Connection refused":** BIRD is trying outbound to
  rustbgpd's port 179, but rustbgpd only connects outbound in M0 (no listener).
  This is normal — rustbgpd's outbound connect will establish the session.
  If it persists, check the connect-retry timer interval.
