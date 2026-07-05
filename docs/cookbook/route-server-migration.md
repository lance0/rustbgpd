# Route-server migration notes

This page maps common FRR, BIRD, and ARouteServer route-server concepts to
rustbgpd's config and verification surfaces. It is not a mechanical converter;
use it to build a side-by-side candidate, then run the shadow trial from the
route-server cookbook before carrying production traffic.

## Baseline rustbgpd shape

Start from:

- [`examples/route-server/config.toml`](../../examples/route-server/config.toml)
- [`examples/route-server/hygiene.rpol`](../../examples/route-server/hygiene.rpol)
- [`docs/cookbook/route-server.md`](route-server.md)

Core member shape:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
role = "route_server"
max_prefixes = 50000
import_policy_chain = ["reject-rpki-invalid", "ixp-hygiene", "prefer-rpki-valid"]
```

For path hiding, prefer Add-Path receive on the member:

```toml
[neighbors.add_path]
send = true
send_max = 8
```

For members that cannot receive Add-Path, use the RFC 7947 §2.3 per-client-best
fallback:

```toml
per_client_best = true
```

## FRR

Common FRR route-server member shape:

```frr
router bgp 65500
 neighbor 198.51.100.2 remote-as 64501
 neighbor 198.51.100.2 route-server-client
 neighbor 198.51.100.2 local-role rs
 neighbor 198.51.100.2 strict-role
 neighbor 198.51.100.2 maximum-prefix 50000
 no bgp ebgp-requires-policy
```

rustbgpd equivalent:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
route_server_client = true
role = "route_server"
strict_role = true
max_prefixes = 50000
```

Notes:

- FRR peers receiving transparent route-server paths usually need
  `no enforce-first-as` on the member side because the member AS is not first in
  reflected AS_PATHs.
- FRR route-maps map naturally to TOML policy definitions for simple match/set
  chains, or to `.rpol` for reusable hygiene logic. The M80 receipt proves
  route-for-route parity between `.rpol` and FRR route-maps for the core
  import/export pattern.
- `neighbor ... addpath-tx-all-paths` maps to `[neighbors.add_path] send = true`
  with an explicit `send_max`.

## BIRD

Common BIRD route-server ideas:

```bird
protocol bgp member_alpha {
  local as 65500;
  neighbor 198.51.100.2 as 64501;
  rs client;
  enforce first as off;
  ipv4 {
    import filter ixp_import;
    export filter ixp_export;
    add paths tx;
  };
}
```

rustbgpd equivalent:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
route_server_client = true
role = "route_server"
families = ["ipv4_unicast", "ipv6_unicast"]
import_policy_chain = ["ixp-hygiene"]

[neighbors.add_path]
send = true
send_max = 8
```

Notes:

- BIRD's `rs client` maps to `route_server_client = true`.
- BIRD's `secondary` path-hiding mitigation maps to `per_client_best = true`
  for non-Add-Path members.
- BIRD filter functions map best to `.rpol` named policies and parameterized
  policies. Keep prefix/community data in named sets so `rbgp policy check` and
  `rbgp policy test` can validate changes before reload.

## ARouteServer

ARouteServer-generated configs usually encode member inventory, max-prefix
limits, bogon / hygiene / RPKI policy, route-server transparency, and
path-hiding settings. There is no direct ARouteServer target in-tree yet.

Practical migration path:

1. Export member inventory to `[[neighbors]]` rows.
2. Convert shared prefix/community lists to `.rpol` `prefix-set` /
   `community-set` declarations.
3. Convert import hygiene to a named `.rpol` policy and keep per-member
   exceptions as parameters or per-neighbor chain overrides.
4. Choose one path-hiding mode per member:
   - Add-Path-capable members: `[neighbors.add_path] send = true`
   - legacy members: `per_client_best = true`
5. Run a shadow trial and compare `rbgp rib advertised` output against the
   incumbent route server's BMP/MRT/looking-glass view.

Minimal generated-neighbor target shape:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
route_server_client = true
role = "route_server"
max_prefixes = 50000
import_policy_chain = ["ixp-hygiene", "member-alpha-in"]
export_policy_chain = ["member-alpha-out"]
per_client_best = true
```

## Cutover checklist

1. Build the candidate config and run `rustbgpd --check`.
2. Run `rbgp policy check` for every `.rpol` file.
3. Shadow-peer the same members with a non-production listener so no accidental
   TCP/179 collision occurs.
4. Compare received and advertised views:

   ```bash
   rbgp rib recv <member>
   rbgp rib sent <member>
   rbgp rib --prefix <prefix> advertised <member> --explain
   ```

5. Confirm counters stay quiet after convergence:

   ```bash
   rbgp metrics | grep -E 'route_refresh|session_state|update_group'
   ```

6. Cut member sessions in small batches. Keep the incumbent read-only during the
   first batch so advertised-view diffs remain available.
