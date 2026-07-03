# IXP route server

rustbgpd as an Internet-exchange route server (RFC 7947/7948): transparent
mode for every member (NEXT_HOP preserved, no AS prepend), RFC 9234 roles
with OTC, RPKI origin validation, and both path-hiding mitigations.

| File | Purpose |
|---|---|
| `config.toml` | Daemon config: two members, RPKI, policy chain |
| `hygiene.rpol` | Import hygiene in the rpol policy language: reject AS_SET, reject ASPA-invalid — with in-language tests |

## Path-hiding (RFC 7947 §2.3), both mitigations

- **member-alpha** negotiates **Add-Path send**: it receives all candidate
  paths and runs its own best-path selection. Preferred where the member
  edge supports Add-Path receive — these peers stay update-group-shareable.
- **member-beta** cannot do Add-Path, so it sets **`per_client_best = true`**
  (requires `route_server_client`): when its export policy denies the best
  path, the route server advertises the best *permitted* candidate instead
  of hiding the prefix — the BIRD-`secondary` equivalent. Trade-off: such
  peers are excluded from update-group sharing (visible as the
  `per_client_best` reason in `rbgp neighbor show`).

## Try it

```bash
# Validate the config and the rpol policy (both offline):
rustbgpd --check config.toml
rbgp policy check hygiene.rpol

# Run, then inspect a member:
rbgp neighbor 198.51.100.3                 # Distribution Mode: per-client-best
rbgp rib advertised 198.51.100.3 --explain --prefix 203.0.113.0/24
```

The explain output for a per-client-best member shows the ranked candidate
ladder with per-candidate export-policy verdicts (which candidates were
denied by which policy term, and which one was advertised).

Members are managed dynamically via gRPC as they join and leave — see
`rbgp neighbor <addr> add --asn <asn> --route-server-client \
--per-client-best --role rs`.
