# rustbgpctl (rbgp)

Installs as `rbgp` — a thin gRPC wrapper over the daemon's management
surface with human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

### Runtime Snapshot

```bash
rbgp global       # ASN, router ID, listen port, TCP-AO support
rbgp health       # daemon health check
rbgp doctor       # triage checks + redacted support bundle (tar.gz)
rbgp metrics      # Prometheus metrics snapshot
rbgp top          # live terminal dashboard
```

In `rbgp top`, select a peer and open its detail, then press `r` to open the
on-demand route explorer. `v` cycles the global unicast Best table and the
peer's Received, Advertised, and Rejected tables, `f` toggles IPv4/IPv6
unicast, `/` sets an exact prefix filter (with a longer-prefixes toggle), and
`n`/`p` follow server pages while `Space`/`PgDn` move within one. `Enter` on a
Best row, or `e` with a typed or selected prefix, runs the existing export
explanation for that prefix and peer. The view is on demand; it does not
continuously poll the RIB.

### Config Transactions

```bash
rbgp config diff config.toml
# The runtime snapshot token printed by plan is opaque — capture it and pass
# it back verbatim:
RUNTIME_SNAPSHOT_TOKEN="$(rbgp --json config plan config.toml \
  | jq -r .runtime_snapshot_token)"
rbgp config apply config.toml \
  --expected-runtime-snapshot-token "$RUNTIME_SNAPSHOT_TOKEN"

# Confirmed apply: rolls back unless confirmed before the timeout.
rbgp config apply config.toml \
  --expected-runtime-snapshot-token "$RUNTIME_SNAPSHOT_TOKEN" \
  --confirm-id deploy-123 \
  --confirm-timeout 120
rbgp config status
rbgp config confirm deploy-123
rbgp config abort deploy-123
rbgp config effective                       # dump running post-defaults config (redacted TOML; -j for JSON; bounded to 384 MiB)
rbgp config history                         # list applied config transactions
rbgp config rollback <n>                    # roll back to a prior history entry (1 = previous applied config)

# Translate a BIRD 2/3 / FRR / GoBGP config (local, no daemon; policy is
# never translated — skipped constructs are reported with line numbers
# for hand-translation to .rpol). Exit codes: 0 clean, 1 error,
# 2 translated with warnings/skips, 3 refused.
rbgp config import <source> [--format bird|frr|gobgp] [--out <path>]
```

### Peers and BFD

```bash
rbgp neighbor
rbgp neighbor --wide                        # add MsgRcvd/MsgSent/Flaps/RRC/Slow/PfxRcd columns
rbgp summary                                # alias for neighbor list
rbgp neighbor <addr>
rbgp neighbor <addr> --compare <NEIGHBOR>   # compare live update-group membership
rbgp neighbor <addr> add --remote-asn <asn> [--peer-group <name>] [--families <list>] [--route-server-client|--no-route-server-client] [--per-client-best|--no-per-client-best] [--role <role>] [--strict-role|--no-strict-role] [--no-add-path]
rbgp neighbor <addr> enable
rbgp neighbor <addr> disable --reason "maintenance"
rbgp neighbor <addr> reset [--reason "maintenance"]   # Cease/Administrative Reset; static peers retry, dynamic peers reconnect inbound
rbgp neighbor <addr> softreset
rbgp neighbor <addr> refresh-out            # re-send this peer's current exportable outbound routes
rbgp neighbor <addr> delete

rbgp dynamic-neighbor list
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members
rbgp dynamic-neighbor delete 10.0.0.0/24

rbgp peer-group list                       # manage [[peer_groups]] entries
rbgp peer-group set <name> --from-file group.json
rbgp peer-group attach <addr> --group <name>   # bind a neighbor to a group
rbgp peer-group detach <addr>                  # unbind
rbgp neighbor-set list                     # manage [[neighbor_sets]] used by policy
rbgp neighbor-set set <name> --from-file set.json

rbgp bfd
rbgp bfd show <addr>
rbgp rpki validate 192.0.2.0/24 64496       # complete verdict + bounded covering VRPs
rbgp rpki caches                             # configured caches + accepted RTR epochs
```

`rpki validate` requires the daemon's first authoritative VRP snapshot. Before
that snapshot it fails with `FAILED_PRECONDITION`; an authoritative empty
snapshot returns `not_found`. JSON reports the canonical prefix, origin ASN,
typed validation, `complete`, exact `omitted`, and up to 256 effective covering
VRPs. AS0 VRPs remain visible but never authorize the queried route.

`dynamic-neighbor add` requires its peer group to exist first. The
[Quickstart operating example](../../docs/QUICKSTART.md#5-operate) creates the
passwordless `ix-members` group from ordinary JSON before adding the range.

`neighbor add` preserves omission for peer-group inheritance. Positive and
`--no-*` forms create explicit boolean overrides; any Add-Path option emits the
complete atomic block, while `--no-add-path` explicitly disables it. The CLI
sends only the presence-aware `intent` carrier and never retries with legacy
semantics; a daemon predating v0.65 rejects the RPC because it does not read
that field.

### Routes, Policy, and Dataplane

```bash
rbgp rib
rbgp rib --age                              # append original receive age
rbgp rib --count                            # best-route count only
rbgp rib lookup 203.0.113.99                # global Loc-RIB longest-prefix match
rbgp --json rib lookup 2001:db8::7/128      # same best-path explanation as JSON
rbgp rib received <addr>
rbgp rib received <addr> --prefix 203.0.113.0/24
rbgp rib received <addr> --origin-asn 64496 --limit 100
rbgp rib received <addr> --rpki-state invalid --aspa-state unknown
rbgp rib received <addr> --as-path-contains 64496
rbgp rib received <addr> --age
rbgp rib received <addr> --count
rbgp rib received <addr> --rejected         # retained rejected routes with reject reasons
rbgp rib recv <addr>                        # alias
rbgp rib advertised <addr>
rbgp rib advertised <addr> --prefix 203.0.113.0/24 --longer
rbgp rib advertised <addr> --age
rbgp rib advertised <addr> --count
rbgp rib sent <addr>                        # alias
rbgp rib --prefix <prefix> --explain
rbgp rib --prefix <prefix> --explain --explain-peer <peer>   # scope the explain to one peer's Add-Path send view
rbgp rib blackholes
rbgp rib fib
rbgp rib bgpls    # BGP-LS routes learned from peers (RFC 9552)
rbgp rib vpn      # VPNv4/VPNv6 routes (RFC 4364/4659, SAFI 128)
rbgp rib labeled  # labeled-unicast routes (RFC 8277, SAFI 4)
rbgp rib rtc      # RT-Constrain membership NLRI (RFC 4684, SAFI 132)
rbgp rib add <prefix> --nexthop <ip> [--origin <0|1|2>] [--local-pref <n>] [--med <n>] [--as-path "<asn> <asn>..."] [--communities <c1,c2,...>] [--large-communities <c1,c2,...>] [--path-id <n>]
rbgp rib delete <prefix> [--path-id <n>]
rbgp diff advertised   # compare live Adj-RIB-Out against an incumbent NDJSON snapshot (read-only; own 0/1/2 exit contract)
rbgp diff snapshot from-mrt <file> --view adj-rib-out-capture --peer <addr> --peer-asn <asn>   # offline: produce an rbgp-ribsnap/1 snapshot from an incumbent MRT dump (see docs/ribdiff.md; from-bmp for BMP captures)

rbgp policy list
rbgp policy get <name>
rbgp policy set <name> --from-file policy.json
rbgp policy delete <name>
rbgp policy chain show [--neighbor <addr>]
rbgp policy chain set-import [--neighbor <addr>] <names...>
rbgp policy chain set-export [--neighbor <addr>] <names...>
rbgp policy chain clear-import [--neighbor <addr>]
rbgp policy chain clear-export [--neighbor <addr>]
rbgp policy explain --neighbor <addr> --prefix <cidr> [--path-id <n>]
rbgp policy check <file.rpol>                          # parse, typecheck, and run in-language tests in-process (no daemon; --coverage-min for a CI coverage gate)
rbgp policy fmt <file.rpol>... [--check]               # canonical .rpol formatter (in-place; --check for CI; - = stdin)
rbgp policy test <file.rpol> --policy <name> --direction import|export [--neighbor <addr>]   # dry-run over the live RIB
rbgp policy stats [--neighbor <addr>]                     # live per-term hit counters
rbgp policy counters [--neighbor <addr>]                  # alias

rbgp flowspec
rbgp fib-table list
rbgp fib-table set edge --table-id 1000 --metric 200 --families ipv4_unicast,ipv6_unicast
```

Complete human `rib`, `rib received`, and `rib advertised` unicast listings
use `--pager auto` by default: a pager starts only when stdout is a terminal,
the terminal height is known, and the complete rendered table plus any
`--limit` footer is taller than the terminal. `--pager never` always writes
directly. `--pager always` requires a terminal and one of those three human
listings; JSON and all other commands are rejected before connecting.

The pager command is the first non-empty value of `RBGP_PAGER`, then `PAGER`,
split on ASCII whitespace without a shell. With neither set, auto mode uses
`less -FRSX` and always mode uses `less -RSX`. If auto mode cannot find the
pager executable, it writes the same rendered bytes directly; other pager
startup failures and unsuccessful exits are errors.

`rib received <addr> --rejected` reads a bounded per-peer retention buffer, not
a guaranteed complete history of rejected routes. Plain-text output reports
incomplete or unknown completeness with these warnings (using three evictions
as a concrete nonzero example):

```text
WARNING: 3 older rejected route(s) were evicted since session reset; this listing may be incomplete
WARNING: rejected-route eviction count is unavailable from this daemon; listing completeness is unknown
```

JSON output exposes `evictions_since_reset`: zero means no eviction has occurred
since the session reset, while a nonzero value means the listing may be
incomplete. A `null` value means the daemon did not report completeness; it is
compatibility evidence from an older or otherwise unreporting daemon, not the
normal output from a current server.

`policy explain` requires the daemon's import-decision cache, which is
opt-in: set `[policy.explain] enabled = true` in the daemon config. On a
stock daemon the command exits nonzero with that hint.

`--count` applies the same family, prefix, longer-prefix, origin-ASN, exact
AS-path membership, standard-community, large-community, RPKI-verdict, and
ASPA-verdict filters as the corresponding best, received, or advertised route
listing. It makes exactly one request and transfers at most one route row,
rendering `Total matching routes: N` or `{"total_count":N}` with `--json`. A
filtered count still scans the matching backend view to compute the exact
total; `--count` bounds response transfer, not server-side query work. It
cannot be combined with the rejected-route or explain views.

`rib lookup <IP|CIDR>` performs one atomic longest-prefix-match query against
the global IPv4/IPv6 Loc-RIB. A bare address is queried as `/32` or `/128`; a
CIDR keeps its supplied mask. The returned prefix can therefore be less
specific than the input. Human and JSON output use the same best-route explain
shape as `rib --prefix CIDR --explain`, including the winner, alternatives,
and comparison reasons. No covering route returns `not found`; a daemon that
predates `LookupBestPath` returns `not supported by this daemon`. The CLI does
not fall back to downloading or scanning the route table.

The accepted-route filters can be placed after `received PEER` or
`advertised PEER`, where their `--help` pages list them. The older parent form
(`rbgp rib --prefix CIDR received PEER`) remains accepted for compatibility.
Filter dimensions compose with AND semantics. Repeated standard-community
values are OR-matched with one another, as are repeated large-community
values; a route must still satisfy every other requested dimension.
`--rpki-state` accepts `valid`, `invalid`, or `not_found`; `not_found` is a
recorded per-route verdict, not a validator-readiness signal. `--aspa-state`
accepts `valid`, `invalid`, or `unknown`. `--as-path-contains ASN` compares an
exact nonzero numeric ASN against the represented `AS_SEQUENCE` and `AS_SET`
members. It does not run policy or a regular expression. RFC 9774 rejection of
newly received `AS_SET` and `AS_CONFED_SET` forms remains unchanged; this
inspection filter only sees path forms already represented in the RIB.

`--limit N` returns one server-fenced page, with `N` from 1 through the
server's 1000-row page cap. Human output says whether it is showing the first
N of the exact matching total. JSON uses
`{"routes": [...], "returned_count": N, "total_count": T, "complete": false}`.
This is the bounded inspection path for a live full table. Without `--limit`,
the CLI still follows every page and fails closed if the table changes; it
never labels a torn multi-page walk complete.

In JSON route rows, `validation_state` is the route's recorded RPKI
origin-validation verdict, not an indicator that `[rpki]` is enabled.
`not_found` means no covering VRP was present when that route was evaluated. A
daemon with no `[rpki]` sources therefore reports `not_found` for every route;
with configured and ready sources, the same value is a real uncovered-route
verdict. Use `rbgp rpki caches` or `rbgp doctor` for validator readiness—the
route field alone cannot prove it.

The full unary listings (`rib bgpls|vpn|labeled|rtc|blackholes|fib`,
`flowspec`, `evpn|evpn diagnose`, `topology nodes|links`, `orr`) return the
whole table in one response and decode up to a finite 64 MiB ceiling (roughly
0.7-1.3 million rows). A response above the ceiling still fails closed,
currently as `out of range`. The ceiling is client-side compatibility headroom
only: it does not add pagination, reduce daemon snapshot work, make filters
cheaper, guarantee arbitrary table sizes, or change third-party gRPC clients.
Paginated unicast listings, streams, and control RPCs keep tonic's 4 MiB
default.

`--age` appends an `Age` column to the human best, received, or advertised
route table. It is the age of the original RIB receive event, including in the
advertised view; it is not the age of the advertisement. Unknown timestamps
render as `-`, and future timestamps clamp to `00:00:00`. Because the daemon
supplies an epoch timestamp and the CLI reads its local clock, running the CLI
on another host can expose clock skew. `--age` cannot be combined with
`--count`, rejected-route output, or either explain view. JSON is unchanged by
the flag and always includes the raw `received_at_epoch_seconds` field.

### EVPN

```bash
rbgp evpn
rbgp evpn runtime
rbgp evpn instances
rbgp evpn nexthops
rbgp evpn vrfs
rbgp evpn diagnose
rbgp evpn es list [<esi>]                        # Ethernet Segments joined with drain/DF/FDB-NHG state (ADR-0084)
rbgp evpn es drain <esi>                         # drain an ES before access-circuit maintenance
rbgp evpn es undrain <esi>                       # undrain an ES
rbgp evpn managed-netdevs                        # rustbgpd-managed netdev ownership/status (ADR-0091)
rbgp evpn clear-duplicate-mac --vni <n> --mac <addr>   # clear a duplicate-MAC local-origin quarantine
rbgp evpn add-mac-ip ...
rbgp evpn add-imet ...
rbgp evpn add-ip-prefix ...
rbgp evpn delete-mac-ip ...
rbgp evpn delete-imet ...
rbgp evpn delete-ip-prefix ...
```

### Events and Control

```bash
rbgp events watch
rbgp events watch --backfill 50
rbgp events watch --from-event-id 41236
rbgp events watch --category bfd --type bfd_up,bfd_down,bfd_state_changed
rbgp events sessions
rbgp events policy
rbgp events evpn
rbgp watch              # legacy route-update stream

rbgp topology nodes|links   # RFC 9107 ORR topology graph from BGP-LS
rbgp orr                # RFC 9107 ORR per-vantage status
rbgp gshut [--neighbor <addr>] [--clear]   # RFC 8326 graceful-shutdown toggle
rbgp mrt-dump
rbgp shutdown
rbgp completions bash
rbgp man                # man page (roff) on stdout: rbgp man | man -l -
```

`events watch --from-event-id N` durably replays events after `N` and tails
the outbox. While the command remains running, a clean stream end or gRPC
`UNAVAILABLE` reconnects with a 1-second exponential backoff capped at 30
seconds. Every category, type, neighbor, family, and prefix filter is preserved.
The resume cursor advances from the top-level `BgpEvent.event_id` only after the
complete human or JSON record, newline, and stdout flush succeed; a lag frame
without that ID does not advance it. Other RPC statuses and output failures are
terminal. This is a process-local resume cursor, not a persisted downstream
checkpoint; use the event-bridge pattern when the consumer must store its own
confirmed cursor. Cursorless OTC subscriptions and ordinary `WatchEvents`
streams remain one-shot.

Most data-oriented commands support `--json` for machine-parseable output.
Commands with fixed formats, such as `metrics`, `completions`, and `top`, keep
their command-specific output. `--no-color` (or `NO_COLOR=1`) disables colored
text output where color is used, and colors auto-disable when output is piped to
a non-TTY.

## Familiar command map

| FRR / BIRD mental model | `rbgp` command |
|-------------------------|----------------|
| Neighbor summary | `rbgp summary` or `rbgp neighbor` |
| Received routes | `rbgp rib received <peer>` or `rbgp rib recv <peer>` |
| Advertised routes | `rbgp rib advertised <peer>` or `rbgp rib sent <peer>` |
| Count matching best/received/advertised routes | add `--count` to the corresponding command |
| Longest-prefix match for an address or CIDR | `rbgp rib lookup <IP|CIDR>` |
| Explain best path | `rbgp rib --prefix <cidr> --explain` |
| Explain export policy / gates | `rbgp rib --prefix <cidr> advertised <peer> --explain` |
| Explain import policy | `rbgp policy explain --neighbor <peer> --prefix <cidr>` |
| Policy hit counters | `rbgp policy stats` or `rbgp policy counters` |
| Route-server clients | `rbgp summary`, then `rbgp neighbor <peer>` for distribution mode |
| Bounce one session (`clear bgp <peer>`, `bgpctl neighbor <peer> clear`) | `rbgp neighbor <peer> reset [--reason <text>]` |
| Support bundle + triage checks | `rbgp doctor --output ./support.tar.gz` |

Confirmed config transaction handles must be non-empty, at most 128
characters, and contain no control characters. `--confirm-timeout` requires
`--confirm-id`; the daemon default is 600 seconds and the maximum is 86400.

## License

MIT OR Apache-2.0
