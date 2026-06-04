# rustbgpd-cli (rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

```
rustbgpctl global                      # show ASN, router ID
rustbgpctl config diff --from-file config.toml
rustbgpctl config plan --from-file config.toml
rustbgpctl config apply --from-file config.toml --expected-runtime-snapshot-token kv1:...
rustbgpctl neighbor                    # list all peers
rustbgpctl neighbor <addr>             # peer detail
rustbgpctl neighbor <addr> add --asn <asn> [--role provider|rs|rs-client|customer|peer] [--strict-role]
rustbgpctl neighbor <addr> delete      # remove peer
rustbgpctl neighbor <addr> enable      # enable peer
rustbgpctl neighbor <addr> disable     # disable peer with reason
rustbgpctl neighbor <addr> softreset   # trigger inbound soft reset
rustbgpctl bfd                         # list BFD sessions
rustbgpctl bfd show <addr>             # BFD session detail
rustbgpctl rib                         # list best routes
rustbgpctl rib received <addr>         # received routes
rustbgpctl rib advertised <addr>       # advertised routes
rustbgpctl rib --prefix <prefix> --explain
rustbgpctl rib blackholes              # BLACKHOLE discard status
rustbgpctl rib fib                     # general FIB route status
rustbgpctl flowspec                    # list FlowSpec rules
rustbgpctl policy list                 # list named policies (names + statement counts)
rustbgpctl policy get <name>           # show one named policy
rustbgpctl policy set <name> --from-file pol.json   # create/replace from a JSON PolicyDefinition
rustbgpctl policy delete <name>        # delete a named policy
rustbgpctl policy chain show [--neighbor <addr>]    # show global (or per-neighbor) import/export chains
rustbgpctl policy chain set-import [--neighbor <addr>] <names...>   # replace the import chain
rustbgpctl policy chain set-export [--neighbor <addr>] <names...>   # replace the export chain
rustbgpctl policy chain clear-import [--neighbor <addr>]            # clear the import chain
rustbgpctl policy chain clear-export [--neighbor <addr>]            # clear the export chain
rustbgpctl policy explain --neighbor <addr> --prefix <cidr> [--path-id <n>]   # why a prefix was permitted/denied on import (ADR-0073)
rustbgpctl evpn                        # list EVPN routes (RFC 7432)
rustbgpctl evpn runtime                # committed EVPN runtime model
rustbgpctl evpn instances              # resolved L2VNI state
rustbgpctl evpn nexthops               # resolved EVPN next-hop state
rustbgpctl evpn vrfs                   # resolved IP-VRF state
rustbgpctl evpn diagnose               # EVPN readiness diagnostics
rustbgpctl evpn add-mac-ip ...         # inject EVPN Type 2 MAC/IP route
rustbgpctl evpn add-imet ...           # inject EVPN Type 3 IMET route
rustbgpctl evpn add-ip-prefix ...      # inject EVPN Type 5 IP Prefix route
rustbgpctl evpn delete-mac-ip ...      # withdraw EVPN Type 2 route
rustbgpctl evpn delete-imet ...        # withdraw EVPN Type 3 route
rustbgpctl evpn delete-ip-prefix ...   # withdraw EVPN Type 5 route
rustbgpctl watch                       # legacy route-update stream
rustbgpctl events watch                # unified live event stream
rustbgpctl events watch --category bfd # BFD up/down/state-change stream
rustbgpctl events sessions             # recent session lifecycle events
rustbgpctl events policy               # recent runtime policy changes
rustbgpctl events evpn                 # recent EVPN route events
rustbgpctl health                      # daemon health check
rustbgpctl shutdown                    # coordinated shutdown
rustbgpctl mrt-dump                    # trigger MRT dump
rustbgpctl metrics                     # Prometheus metrics snapshot
rustbgpctl top                         # live terminal dashboard
rustbgpctl completions bash            # shell completions
```

All commands support `--json` for machine-parseable output and `--no-color`
(or `NO_COLOR=1`) to disable colored output. Colors auto-disable when
output is piped to a non-TTY.

## License

MIT OR Apache-2.0
