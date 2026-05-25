# rustbgpd-cli (rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

```
rustbgpctl global                      # show ASN, router ID
rustbgpctl config diff --from-file config.toml
rustbgpctl neighbor                    # list all peers
rustbgpctl neighbor <addr>             # peer detail
rustbgpctl neighbor <addr> add --asn <asn>
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
