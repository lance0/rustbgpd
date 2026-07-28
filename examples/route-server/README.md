# IXP route server

rustbgpd as an Internet-exchange route server (RFC 7947/7948): transparent
mode for every member (NEXT_HOP preserved, no AS prepend), RFC 9234 roles
with OTC, RPKI origin validation, and both path-hiding mitigations.

| File | Purpose |
|---|---|
| `config.toml` | Daemon config: two members, RPKI, policy chain |
| `hygiene.rpol` | Import hygiene in the rpol policy language: reject AS_SET and ASPA-invalid paths, reject a dated dual-stack special-purpose prefix snapshot, and tag RPKI outcomes as RFC 8097 `OV_*` extended communities — with in-language tests |

## Special-purpose prefix starter

`hygiene.rpol` carries a curated starter snapshot of the IANA IPv4 and IPv6
Special-Purpose Address Registries, both updated 2025-10-09 and reviewed for
this example on 2026-07-15. It rejects the two default routes and active rows
whose `Globally Reachable` value is `False`. Active `True` or `N/A` children of
a rejected parent are accepted first. This is not a complete or live bogon
feed: terminated rows, unallocated address space, multicast, and unrelated
`True`/`N/A` rows are deliberately outside its scope.

Treat the list as deployment data. Before rollout, compare both IANA
registries with local exchange policy, update the snapshot/review dates and
the two prefix sets together, then run:

```bash
rbgp policy fmt --check hygiene.rpol
rbgp policy check hygiene.rpol
rustbgpd --check --strict config.toml
```

The long-prefix guard remains a separate, later chain member. If the exchange
accepts RFC 7999 BLACKHOLE more-specifics, do not add a blanket bypass: put a
narrow member/prefix-authorized exception inside that length policy, before
its generic deny, and test both the exception and an unauthorized control.

## Path-hiding (RFC 7947 §2.3), both mitigations

- **member-alpha** negotiates **Add-Path send**: it receives up to the eight
  best export-permitted candidates, subject to configured and negotiated
  Paths-Limit, and runs its own best-path selection. Preferred where the
  member edge supports Add-Path receive — these peers stay
  update-group-shareable.
- **member-beta** cannot do Add-Path, so it sets **`per_client_best = true`**
  (requires `route_server_client`): when its export policy denies the best
  path, the route server advertises the best *permitted* candidate instead
  of hiding the prefix — the BIRD-`secondary` equivalent. Trade-off: such
  peers are excluded from update-group sharing (visible as the
  `per_client_best` reason in `rbgp neighbor <addr>`).

## RFC 1997 `NO_EXPORT` and route-server transparency

Both members inherit the transparent default for well-known communities:
`route_server_client = true` derives `interpret_rfc1997 = false`, so routes
carrying `NO_EXPORT`/`NO_EXPORT_SUBCONFED` pass through the server unchanged
and each member enforces them at its own edge — the arouteserver / IXP
Manager convention. Set `interpret_rfc1997 = true` on a member (or the
peer-group) to have the server itself suppress tagged routes toward that
member; plain (non-RS) eBGP neighbors get that enforcement by default.

## Try it

```bash
# Validate the config and the rpol policy (both offline):
rustbgpd --check --strict config.toml
rbgp policy check hygiene.rpol

# Run, then inspect a member:
rbgp neighbor 198.51.100.3                 # Distribution Mode: per-client-best
rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.3 --explain
```

The explain output for a per-client-best member shows the ranked candidate
ladder with per-candidate export-policy verdicts (which candidates were
denied by which policy term, and which one was advertised).

Members can be added atomically as they join — see
`rbgp neighbor <addr> add --remote-asn <asn> --route-server-client \
--per-client-best --role rs --max-prefixes 50000 \
--max-prefix-restart-seconds 30`.
