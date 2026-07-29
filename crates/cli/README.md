# rustbgpd-cli (rbgp)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

The CLI installs as `rbgp` and exposes the daemon's gRPC management surface with
human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

### Runtime Snapshot

```bash
rbgp global       # ASN, router ID, families, TCP-AO support
rbgp health       # daemon health check
rbgp doctor       # triage checks + redacted support bundle (tar.gz)
rbgp metrics      # Prometheus metrics snapshot
rbgp top          # live terminal dashboard
```

### Config Transactions

```bash
rbgp config diff config.toml
rbgp config plan config.toml
rbgp config apply config.toml \
  --expected-runtime-snapshot-token kv1:...

# Confirmed apply: rolls back unless confirmed before the timeout.
rbgp config apply config.toml \
  --expected-runtime-snapshot-token kv1:... \
  --confirm-id deploy-123 \
  --confirm-timeout 120
rbgp config status
rbgp config confirm deploy-123
rbgp config abort deploy-123
rbgp config effective                       # dump running post-defaults config (redacted TOML; -j for JSON)
rbgp config history                         # list applied config transactions
rbgp config rollback <n>                    # roll back to a prior history entry (1 = previous applied config)

# Translate a BIRD 2 / FRR / GoBGP config (local, no daemon; policy is
# never translated — skipped constructs are reported with line numbers
# for hand-translation to .rpol). Exit codes: 0 clean, 1 error,
# 2 translated with warnings/skips, 3 refused.
rbgp config import <source> [--format bird|frr|gobgp] [--out <path>]
```

### Peers and BFD

```bash
rbgp neighbor
rbgp summary                                # alias for neighbor list
rbgp neighbor <addr>
rbgp neighbor <addr> add --remote-asn <asn> [--peer-group <name>] [--max-prefix-restart-seconds <seconds>] [--role provider|rs|rs-client|customer|peer] [--strict-role] [--route-server-client] [--per-client-best]
rbgp neighbor <addr> enable
rbgp neighbor <addr> disable --reason "maintenance"
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
```

`dynamic-neighbor add` requires its peer group to exist first. The
[Quickstart operating example](../../docs/QUICKSTART.md#5-operate) creates the
passwordless `ix-members` group from ordinary JSON before adding the range.

### Routes, Policy, and Dataplane

```bash
rbgp rib
rbgp rib --age                              # append original receive age
rbgp rib --count                            # best-route count only
rbgp rib received <addr>
rbgp rib received <addr> --age
rbgp rib received <addr> --count
rbgp rib received <addr> --rejected         # retained rejected routes with reject reasons
rbgp rib recv <addr>                        # alias
rbgp rib advertised <addr>
rbgp rib advertised <addr> --age
rbgp rib advertised <addr> --count
rbgp rib sent <addr>                        # alias
rbgp rib --prefix <prefix> --explain
rbgp rib blackholes
rbgp rib fib
rbgp rib bgpls    # BGP-LS routes learned from peers (RFC 9552)
rbgp rib vpn      # VPNv4/VPNv6 routes (RFC 4364/4659, SAFI 128)
rbgp rib labeled  # labeled-unicast routes (RFC 8277, SAFI 4)
rbgp rib rtc      # RT-Constrain membership NLRI (RFC 4684, SAFI 132)
rbgp rib add <prefix> --nexthop <ip> [--origin <0|1|2>] [--local-pref <n>] [--med <n>] [--as-path "<asn> <asn>..."] [--communities <c1,c2,...>] [--large-communities <c1,c2,...>] [--path-id <n>]
rbgp rib delete <prefix> [--path-id <n>]
rbgp diff advertised   # compare live Adj-RIB-Out against an incumbent NDJSON snapshot (read-only; own 0/1/2 exit contract)

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
rbgp policy check <file.rpol>                          # parse + typecheck an .rpol file in-process (no daemon)
rbgp policy fmt <file.rpol>... [--check]               # canonical .rpol formatter (in-place; --check for CI; - = stdin)
rbgp policy test <file.rpol> --policy <name> --direction import|export [--neighbor <addr>]   # dry-run over the live RIB
rbgp policy stats [--neighbor <addr>]                     # live per-term hit counters
rbgp policy counters [--neighbor <addr>]                  # alias

rbgp flowspec
rbgp fib-table list
rbgp fib-table set edge --table-id 1000 --metric 200 --families ipv4_unicast,ipv6_unicast
```

`policy explain` requires the daemon's import-decision cache, which is
opt-in: set `[policy.explain] enabled = true` in the daemon config. On a
stock daemon the command exits nonzero with that hint.

`--count` applies the same family, prefix, longer-prefix, origin-ASN, standard
community, and large-community filters as the corresponding best, received, or
advertised route listing. It makes exactly one request and transfers at most one
route row, rendering `Total matching routes: N` or `{"total_count":N}` with
`--json`. A filtered count still scans the matching backend view to compute the
exact total; `--count` bounds response transfer, not server-side query work. It
cannot be combined with the rejected-route or explain views.

The full unary listings (`rib bgpls|vpn|labeled|rtc|blackholes|fib`,
`flowspec`, `evpn list|diagnose`, `topology nodes|links`, `orr`) return the
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
rbgp events watch --category bfd --type bfd_up,bfd_down,bfd_state_changed
rbgp events sessions
rbgp events policy
rbgp events evpn
rbgp watch              # legacy route-update stream

rbgp topology           # RFC 9107 ORR topology graph from BGP-LS
rbgp orr                # RFC 9107 ORR per-vantage status
rbgp gshut [--neighbor <addr>] [--clear]   # RFC 8326 graceful-shutdown toggle
rbgp mrt-dump
rbgp shutdown
rbgp completions bash
rbgp man                # man page (roff) on stdout: rbgp man | man -l -
```

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
| Explain best path | `rbgp rib --prefix <cidr> --explain` |
| Explain export policy / gates | `rbgp rib --prefix <cidr> advertised <peer> --explain` |
| Explain import policy | `rbgp policy explain --neighbor <peer> --prefix <cidr>` |
| Policy hit counters | `rbgp policy stats` or `rbgp policy counters` |
| Route-server clients | `rbgp summary`, then `rbgp neighbor <peer>` for distribution mode |
| Support bundle + triage checks | `rbgp doctor --output ./support.tar.gz` |

Confirmed config transaction handles must be non-empty, at most 128
characters, and contain no control characters. `--confirm-timeout` requires
`--confirm-id`; the daemon default is 600 seconds and the maximum is 86400.

## License

MIT OR Apache-2.0
