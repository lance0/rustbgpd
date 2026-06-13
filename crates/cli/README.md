# rustbgpd-cli (rbgp / rustbgpctl)

Command-line interface for rustbgpd. Thin gRPC wrapper for daemon
management with human-readable and JSON output modes.

The CLI installs under two interchangeable names: `rbgp` (the short,
preferred spelling used throughout the docs) and `rustbgpctl` (the
original long form). Both binaries ship in every build and expose the
identical command surface — use whichever you prefer.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Commands

### Runtime Snapshot

```bash
rbgp global       # ASN, router ID, families, TCP-AO support
rbgp health       # daemon health check
rbgp metrics      # Prometheus metrics snapshot
rbgp top          # live terminal dashboard
```

### Config Transactions

```bash
rbgp config diff --from-file config.toml
rbgp config plan --from-file config.toml
rbgp config apply --from-file config.toml \
  --expected-runtime-snapshot-token kv1:...

# Confirmed apply: rolls back unless confirmed before the timeout.
rbgp config apply --from-file config.toml \
  --expected-runtime-snapshot-token kv1:... \
  --confirm-id deploy-123 \
  --confirm-timeout 120
rbgp config status
rbgp config confirm deploy-123
rbgp config abort deploy-123
```

### Peers and BFD

```bash
rbgp neighbor
rbgp neighbor <addr>
rbgp neighbor <addr> add --asn <asn> [--role provider|rs|rs-client|customer|peer] [--strict-role]
rbgp neighbor <addr> enable
rbgp neighbor <addr> disable --reason "maintenance"
rbgp neighbor <addr> softreset
rbgp neighbor <addr> delete

rbgp dynamic-neighbor list
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members
rbgp dynamic-neighbor delete 10.0.0.0/24

rbgp bfd
rbgp bfd show <addr>
```

### Routes, Policy, and Dataplane

```bash
rbgp rib
rbgp rib received <addr>
rbgp rib advertised <addr>
rbgp rib --prefix <prefix> --explain
rbgp rib blackholes
rbgp rib fib

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

rbgp mrt-dump
rbgp shutdown
rbgp completions bash
```

Most data-oriented commands support `--json` for machine-parseable output.
Commands with fixed formats, such as `metrics`, `completions`, and `top`, keep
their command-specific output. `--no-color` (or `NO_COLOR=1`) disables colored
text output where color is used, and colors auto-disable when output is piped to
a non-TTY.

Confirmed config transaction handles must be non-empty, at most 128
characters, and contain no control characters. `--confirm-timeout` requires
`--confirm-id`; the daemon default is 600 seconds and the maximum is 86400.

## License

MIT OR Apache-2.0
