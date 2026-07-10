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
```

### Peers and BFD

```bash
rbgp neighbor
rbgp summary                                # alias for neighbor list
rbgp neighbor <addr>
rbgp neighbor <addr> add --remote-asn <asn> [--role provider|rs|rs-client|customer|peer] [--strict-role] [--route-server-client] [--per-client-best]
rbgp neighbor <addr> enable
rbgp neighbor <addr> disable --reason "maintenance"
rbgp neighbor <addr> softreset
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

### Routes, Policy, and Dataplane

```bash
rbgp rib
rbgp rib received <addr>
rbgp rib recv <addr>                        # alias
rbgp rib advertised <addr>
rbgp rib sent <addr>                        # alias
rbgp rib --prefix <prefix> --explain
rbgp rib blackholes
rbgp rib fib
rbgp rib bgpls    # BGP-LS routes learned from peers (RFC 9552)
rbgp rib vpn      # VPNv4/VPNv6 routes (RFC 4364/4659, SAFI 128)
rbgp rib labeled  # labeled-unicast routes (RFC 8277, SAFI 4)
rbgp rib rtc      # RT-Constrain membership NLRI (RFC 4684, SAFI 132)
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

### EVPN

```bash
rbgp evpn
rbgp evpn runtime
rbgp evpn instances
rbgp evpn nexthops
rbgp evpn vrfs
rbgp evpn diagnose
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
