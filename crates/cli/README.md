# rustbgpd-cli (rbgp / rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

`rbgp` is the preferred short binary name. `rustbgpctl` remains available as
a compatible long-form spelling with the same command surface.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

```
rbgp global                      # show ASN, router ID
rbgp config diff --from-file config.toml
rbgp config plan --from-file config.toml
rbgp config apply --from-file config.toml --expected-runtime-snapshot-token kv1:...
rbgp config apply --from-file config.toml --expected-runtime-snapshot-token kv1:... \
  --confirm-id deploy-123 --confirm-timeout 120
rbgp config status
rbgp config confirm deploy-123
rbgp config abort deploy-123
rbgp neighbor                    # list all peers
rbgp neighbor <addr>             # peer detail
rbgp neighbor <addr> add --asn <asn> [--role provider|rs|rs-client|customer|peer] [--strict-role]
rbgp neighbor <addr> delete      # remove peer
rbgp neighbor <addr> enable      # enable peer
rbgp neighbor <addr> disable     # disable peer with reason
rbgp neighbor <addr> softreset   # trigger inbound soft reset
rbgp bfd                         # list BFD sessions
rbgp bfd show <addr>             # BFD session detail
rbgp rib                         # list best routes
rbgp rib received <addr>         # received routes
rbgp rib advertised <addr>       # advertised routes
rbgp rib --prefix <prefix> --explain
rbgp rib blackholes              # BLACKHOLE discard status
rbgp rib fib                     # general FIB route status
rbgp flowspec                    # list FlowSpec rules
rbgp policy list                 # list named policies (names + statement counts)
rbgp policy get <name>           # show one named policy
rbgp policy set <name> --from-file pol.json   # create/replace from a JSON PolicyDefinition
rbgp policy delete <name>        # delete a named policy
rbgp policy chain show [--neighbor <addr>]    # show global (or per-neighbor) import/export chains
rbgp policy chain set-import [--neighbor <addr>] <names...>   # replace the import chain
rbgp policy chain set-export [--neighbor <addr>] <names...>   # replace the export chain
rbgp policy chain clear-import [--neighbor <addr>]            # clear the import chain
rbgp policy chain clear-export [--neighbor <addr>]            # clear the export chain
rbgp policy explain --neighbor <addr> --prefix <cidr> [--path-id <n>]   # why a prefix was permitted/denied on import (ADR-0073)
rbgp evpn                        # list EVPN routes (RFC 7432)
rbgp evpn runtime                # committed EVPN runtime model
rbgp evpn instances              # resolved L2VNI state
rbgp evpn nexthops               # resolved EVPN next-hop state
rbgp evpn vrfs                   # resolved IP-VRF state
rbgp evpn diagnose               # EVPN readiness diagnostics
rbgp evpn add-mac-ip ...         # inject EVPN Type 2 MAC/IP route
rbgp evpn add-imet ...           # inject EVPN Type 3 IMET route
rbgp evpn add-ip-prefix ...      # inject EVPN Type 5 IP Prefix route
rbgp evpn delete-mac-ip ...      # withdraw EVPN Type 2 route
rbgp evpn delete-imet ...        # withdraw EVPN Type 3 route
rbgp evpn delete-ip-prefix ...   # withdraw EVPN Type 5 route
rbgp watch                       # legacy route-update stream
rbgp events watch                # unified live event stream
rbgp events watch --category bfd # BFD up/down/state-change stream
rbgp events sessions             # recent session lifecycle events
rbgp events policy               # recent runtime policy changes
rbgp events evpn                 # recent EVPN route events
rbgp health                      # daemon health check
rbgp shutdown                    # coordinated shutdown
rbgp mrt-dump                    # trigger MRT dump
rbgp metrics                     # Prometheus metrics snapshot
rbgp top                         # live terminal dashboard
rbgp completions bash            # shell completions
```

All commands support `--json` for machine-parseable output and `--no-color`
(or `NO_COLOR=1`) to disable colored output. Colors auto-disable when
output is piped to a non-TTY.

## License

MIT OR Apache-2.0
