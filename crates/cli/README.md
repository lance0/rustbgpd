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
rustbgpctl rib <received|best|advertised> <addr>  # query routes
rustbgpctl flowspec list               # list FlowSpec rules
rustbgpctl watch                       # stream route events
rustbgpctl health                      # daemon health check
rustbgpctl shutdown                    # coordinated shutdown
rustbgpctl mrt-dump                    # trigger MRT dump
```

All commands support `--json` for machine-parseable output.

## License

MIT OR Apache-2.0
