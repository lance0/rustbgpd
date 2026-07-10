# Runbook: RR pair day-2 operations

**When this is you:** a redundant route-reflector pair (per
[route-reflector.md](route-reflector.md)) is in production and you need
to make routine changes without dropping the fleet. Rule of thumb for
every task below: change one RR, verify, then the other.

## GR settings sanity

The RR is a receiving-speaker GR/LLGR helper: on a client restart it
retains routes for the advertised restart window (RFC 4724), then
demotes to LLGR_STALE (RFC 9494) if `llgr_stale_time > 0`. Check the
peer-group template carries what you think it does:

```toml
[[peer_groups]]
name = "rr-clients"
graceful_restart = true
gr_stale_routes_time = 120
llgr_stale_time = 300
```

During a client restart, watch the helper actually helping:

```bash
rbgp metrics | grep -E 'bgp_gr_active_peers|bgp_gr_stale_routes|bgp_gr_timer_expired_total'
```

`gr_stale_routes_time` is hot-applied per the
[reload matrix](../reload-matrix.md); `graceful_restart` itself binds at
OPEN negotiation, so changing it resets the session (see below).

## Adding a client

If the fleet auto-accepts via a `[[dynamic_neighbors]]` range, a new
client inside the range needs nothing. Otherwise:

```bash
rbgp neighbor 10.0.0.42 add --remote-asn 65000 --description "new-client"
# or widen the accept range:
rbgp dynamic-neighbor add 10.0.9.0/24 --peer-group rr-clients
```

Both persist to the config file (when the daemon was started with
`--config`) before the RPC returns. Verify with `rbgp neighbor --wide`
— the `RRC` column marks reflector clients. Uniform clients join the
existing update group automatically; there is nothing to tune.

## Config edits: hot vs session reset

Before touching a live RR, classify the edit — the
[reload matrix](../reload-matrix.md) is the index, the daemon is the
oracle:

```bash
rbgp config diff /etc/rustbgpd/candidate.toml
```

Not sure what a value on the live RR *currently* is (an inherited
peer-group timer, a defaulted `hold_time`)? Dump the effective running
config first — defaults materialized, secrets redacted:

```bash
rbgp config effective
```

The diff annotates each changed field. Two classes matter here:

- **Hot-applied** (`description`, `max_prefixes`,
  `gr_stale_routes_time`, `log_level`, `remove_private_as`,
  import/export policy and chain refs, ...): applied **in place** on
  SIGHUP — session task, TCP connection, and FSM untouched; policy
  edits trigger Route Refresh / re-emit.
- **Session reset** (`families`, `add_path`, `graceful_restart`,
  `hold_time`, `md5_password`, ...): applied through an immediate
  delete + re-add of the session on SIGHUP, so the fleet sees a flap
  *now*, not at the next natural reset. Do these one RR at a time and
  confirm the other RR is carrying full state first
  (`rbgp neighbor --wide` prefix counts on the peer RR).

Mixing a hot edit and a reset edit on one neighbor applies both through
one session rebuild.

## Risky edits: commit-confirm

For anything you would want auto-rolled-back if you cut yourself off,
use a config transaction with a confirm timer instead of SIGHUP:

```bash
rbgp config plan /etc/rustbgpd/candidate.toml
# plan prints the runtime snapshot token; apply requires it:
rbgp config apply /etc/rustbgpd/candidate.toml \
  --expected-runtime-snapshot-token kv1:... \
  --confirm-id rr1-edit-$(date -u +%Y%m%d-%H%M) \
  --confirm-timeout 120

rbgp config status        # pending / confirmed / auto_reverted
rbgp config confirm rr1-edit-...   # keep it
rbgp config abort rr1-edit-...     # or roll back now
```

If the timer expires unconfirmed — or the daemon restarts inside the
window — the pre-commit config is re-applied. While a confirm is
pending, SIGHUP and other config mutators are fenced off. Full
lifecycle and failure states: [`OPERATIONS.md`](../OPERATIONS.md).

## Draining an RR for maintenance

```bash
rbgp gshut                 # tag all outbound with GRACEFUL_SHUTDOWN (RFC 8326)
# clients honoring 8326 de-pref this RR; then stop the daemon:
rbgp shutdown              # writes the GR marker, notifies peers
```

Bring it back, confirm `rbgp neighbor --wide` converges to the same
prefix counts as its twin, then repeat on the other RR.
