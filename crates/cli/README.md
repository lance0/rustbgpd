# rustbgpd-cli (rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

```
rustbgpctl global                      # show ASN, router ID
rustbgpctl neighbor list               # list all peers
rustbgpctl neighbor show <addr>        # peer detail
rustbgpctl neighbor add <addr> <asn>   # add peer at runtime
rustbgpctl neighbor delete <addr>      # remove peer
rustbgpctl neighbor enable <addr>      # enable peer
rustbgpctl neighbor disable <addr>     # disable peer with reason
rustbgpctl neighbor soft-reset <addr>  # trigger soft reset
rustbgpctl rib                         # list best routes
rustbgpctl rib received <addr>         # received routes
rustbgpctl rib advertised <addr>       # advertised routes
rustbgpctl rib blackholes              # BLACKHOLE discard status
rustbgpctl rib fib                     # general FIB route status
rustbgpctl flowspec list               # list FlowSpec rules
rustbgpctl evpn                        # list EVPN routes (RFC 7432)
rustbgpctl evpn add-mac-ip ...         # inject EVPN Type 2 MAC/IP route
rustbgpctl evpn add-imet ...           # inject EVPN Type 3 IMET route
rustbgpctl evpn delete-mac-ip ...      # withdraw EVPN Type 2 route
rustbgpctl evpn delete-imet ...        # withdraw EVPN Type 3 route
rustbgpctl watch                       # stream route events
rustbgpctl health                      # daemon health check
rustbgpctl shutdown                    # coordinated shutdown
rustbgpctl mrt-dump                    # trigger MRT dump
```

All commands support `--json` for machine-parseable output and `--no-color`
(or `NO_COLOR=1`) to disable colored output. Colors auto-disable when
output is piped to a non-TTY.

## License

MIT OR Apache-2.0
