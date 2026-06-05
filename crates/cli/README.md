# rustbgpd-cli (rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

### Runtime Snapshot

```bash
rustbgpctl global       # ASN, router ID, families, TCP-AO support
rustbgpctl health       # daemon health check
rustbgpctl metrics      # Prometheus metrics snapshot
rustbgpctl top          # live terminal dashboard
```

### Config Transactions

```bash
rustbgpctl config diff --from-file config.toml
rustbgpctl config plan --from-file config.toml
rustbgpctl config apply --from-file config.toml \
  --expected-runtime-snapshot-token kv1:...

# Confirmed apply: rolls back unless confirmed before the timeout.
rustbgpctl config apply --from-file config.toml \
  --expected-runtime-snapshot-token kv1:... \
  --confirm-id deploy-123 \
  --confirm-timeout 120
rustbgpctl config status
rustbgpctl config confirm deploy-123
rustbgpctl config abort deploy-123
```

### Peers and BFD

```bash
rustbgpctl neighbor
rustbgpctl neighbor <addr>
rustbgpctl neighbor <addr> add --asn <asn> [--role provider|rs|rs-client|customer|peer] [--strict-role]
rustbgpctl neighbor <addr> enable
rustbgpctl neighbor <addr> disable --reason "maintenance"
rustbgpctl neighbor <addr> softreset
rustbgpctl neighbor <addr> delete

rustbgpctl dynamic-neighbor list
rustbgpctl dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members
rustbgpctl dynamic-neighbor delete 10.0.0.0/24

rustbgpctl bfd
rustbgpctl bfd show <addr>
```

### Routes, Policy, and Dataplane

```bash
rustbgpctl rib
rustbgpctl rib received <addr>
rustbgpctl rib advertised <addr>
rustbgpctl rib --prefix <prefix> --explain
rustbgpctl rib blackholes
rustbgpctl rib fib

rustbgpctl policy list
rustbgpctl policy get <name>
rustbgpctl policy set <name> --from-file policy.json
rustbgpctl policy delete <name>
rustbgpctl policy chain show [--neighbor <addr>]
rustbgpctl policy chain set-import [--neighbor <addr>] <names...>
rustbgpctl policy chain set-export [--neighbor <addr>] <names...>
rustbgpctl policy chain clear-import [--neighbor <addr>]
rustbgpctl policy chain clear-export [--neighbor <addr>]
rustbgpctl policy explain --neighbor <addr> --prefix <cidr> [--path-id <n>]

rustbgpctl flowspec
rustbgpctl fib-table list
rustbgpctl fib-table set edge --table-id 1000 --metric 200 --families ipv4_unicast,ipv6_unicast
```

### EVPN

```bash
rustbgpctl evpn
rustbgpctl evpn runtime
rustbgpctl evpn instances
rustbgpctl evpn nexthops
rustbgpctl evpn vrfs
rustbgpctl evpn diagnose
rustbgpctl evpn add-mac-ip ...
rustbgpctl evpn add-imet ...
rustbgpctl evpn add-ip-prefix ...
rustbgpctl evpn delete-mac-ip ...
rustbgpctl evpn delete-imet ...
rustbgpctl evpn delete-ip-prefix ...
```

### Events and Control

```bash
rustbgpctl events watch
rustbgpctl events watch --backfill 50
rustbgpctl events watch --category bfd --type bfd_up,bfd_down,bfd_state_changed
rustbgpctl events sessions
rustbgpctl events policy
rustbgpctl events evpn
rustbgpctl watch              # legacy route-update stream

rustbgpctl mrt-dump
rustbgpctl shutdown
rustbgpctl completions bash
```

Most data-oriented commands support `--json` for machine-parseable output.
Commands with fixed formats, such as `metrics`, `completions`, and `top`, keep
their command-specific output. `--no-color` (or `NO_COLOR=1`) disables colored
text output where color is used, and colors auto-disable when output is piped to
a non-TTY.

## License

MIT OR Apache-2.0
