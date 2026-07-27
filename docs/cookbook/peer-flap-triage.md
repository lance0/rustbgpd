# Runbook: a peer is flapping

**When this is you:** a session keeps cycling in and out of Established
— the `BgpSessionFlapping` alert fired, or a client noticed churn.
Work top to bottom; each step narrows the cause.

## 1. Confirm and size the flap

```bash
rbgp neighbor --wide
```

The `Flaps` column is the daemon-lifetime flap count; `State/PfxRcd`
shows a prefix count only when Established. An Established peer whose
`MsgRcvd`/`MsgSent` counters have stopped moving is wedged, not
flapping. In Prometheus terms the shipped alert pack
([`examples/prometheus/rustbgpd-alerts.yml`](../../examples/prometheus/rustbgpd-alerts.yml))
fires `BgpSessionFlapping` on
`increase(bgp_session_flaps_total[15m]) > 5`; check the peer's
`bgp_session_flaps_total` and `bgp_max_prefix_exceeded_total{peer}`
series in `rbgp metrics` output for the same signal without Prometheus.

## 2. Read the session event history

```bash
rbgp events sessions --address 10.0.0.2
rbgp events watch --category session --type established,lost   # live tail
```

The event history gives timestamps and teardown reasons: hold-timer
expiry, NOTIFICATION received/sent, max-prefix cease. Regular spacing
at the hold time (default 90 s) points at a keepalive path problem;
irregular spacing points at the transport or the peer.

## 3. Match the teardown reason

- **Cease / Maximum Number of Prefixes Reached** — the peer breached an
  inbound `max_prefixes`, `max_prefixes_ipv4`, or `max_prefixes_ipv6`
  ceiling. Inspect `rbgp neighbor 10.0.0.2` before enabling it: an
  armed opt-in restart shows `Max-Prefix Action: restart` and a live
  `Max-Prefix Hold-Down` countdown. Without
  `max_prefix_restart_seconds` the default is an indefinite,
  fail-closed latch. Failure to deliver the timed session `Start`
  command consumes its one chance, returns the effective action to
  `shutdown`, and puts the manual recovery in `Last Error`; successful
  delivery clears the latch and returns the session to ordinary
  TCP/OPEN retry. Fix the peer or raise the ceiling (a hot-applied
  edit), then run `rbgp neighbor 10.0.0.2 enable` when an immediate
  manual retry is intended (subject to strict BFD withholding).
- **Hold-timer expiry** — keepalives aren't arriving: congestion, an
  overloaded peer, or an MTU/blackhole on large UPDATE bursts.
- **Send-hold expiry (RFC 9687)** — the *peer* stopped draining its
  socket; the problem is on their side.
- **TCP resets with no BGP NOTIFICATION** — MD5/TCP-AO key mismatch or
  a middlebox; see "Debugging a session that won't establish" in
  [`OPERATIONS.md`](../OPERATIONS.md).
- **BFD down events** — if the neighbor has BFD, check
  `rbgp bfd` and the `bfd_session_flaps_total{peer}` counter before
  blaming BGP.

## 4. Turn up logging for just this peer

`log_level` is a live, hot-applied per-neighbor field — setting it does
not touch the session:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
log_level = "debug"
```

Apply with SIGHUP, then follow the daemon log
(`journalctl -u rustbgpd -f | grep 10.0.0.2`). Look for NOTIFICATION
codes, capability mismatches, and hold-timer lines around each flap.

## 5. If routes (not the session) are churning

A stable session with route churn is a policy or upstream problem, not
a flap:

```bash
rbgp events --limit 50                                  # recent route events
rbgp policy explain --neighbor 10.0.0.2 --prefix 203.0.113.0/24
                                                        # opt-in: needs
                                                        # [policy.explain]
rbgp rib --prefix 203.0.113.0/24 --explain              # why this best path
```

## 6. Contain while you investigate

```bash
rbgp neighbor 10.0.0.2 disable --reason "flap triage $(date -u +%F)"
```

Disabling keeps the neighbor's config, counters, and history; `enable`
brings it back. For planned drains prefer `rbgp gshut --neighbor 10.0.0.2`
(RFC 8326) so traffic moves before the session does.
