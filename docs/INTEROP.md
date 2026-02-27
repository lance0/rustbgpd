# Interop Test Results

Tracks interop validation against real BGP implementations. Updated with
every milestone. "Tested" means validated in the containerlab CI suite,
not "someone tried it once."

---

## Test Matrix

| Peer | Version | Topology | Status | Notes | Known Quirks | NOTIFICATIONs Observed |
|------|---------|----------|--------|-------|--------------|------------------------|
| FRR (bgpd) | 10.3.1 | `tests/interop/m0-frr.clab.yml` | Tested (M0) | All 5 tests pass | Needs `no bgp ebgp-requires-policy` | Cease on `clear bgp *` |
| BIRD | 2.0.12 | `tests/interop/m0-bird.clab.yml` | Tested (M0) | All 5 tests pass | Needs `/run/bird` dir; sends empty UPDATE on establish | Cease/Admin Shutdown + Cease/Admin Reset |
| GoBGP | 3.x | — | Planned (M4) | Secondary target | — | — |
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

## BIRD Test Results (2026-02-27, BIRD 2.0.12)

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established in <1s |
| Metrics endpoint | PASS | Full FSM path in `state_transitions_total` |
| Peer restart recovery | PASS | Auto-reconnect after `birdc down`, `established_total`=2 |
| TCP reset recovery | PASS | `birdc restart`, Cease NOTIFICATIONs received, `established_total`=3 |
| Full metrics dump | PASS | 3 establishments, 2 flaps, Cease subcodes 2+4 |

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
