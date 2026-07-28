# Linux Edge FIB Example

This example shows the default-off ADR-0061 unicast FIB runtime in its
intended shape: rustbgpd learns BGP best routes, filters them through an
explicit `[[fib_tables]]` allow-list, and installs eligible routes into a
dedicated Linux route table. It does not write the main table.

## Validate

```bash
rustbgpd --check --strict examples/linux-edge-fib/config.toml
```

The starter config is expected to pass strict validation without warnings.

## Kernel Setup

Create any `ip rule` entries and forwarding policy outside rustbgpd. For
example, to send all non-local lookups through table `1000`:

```bash
sudo ip rule add priority 1000 lookup 1000
sudo ip -6 rule add priority 1000 lookup 1000
```

That rule is intentionally catch-all. For selected traffic, add a selector such
as `fwmark`, `from`, `to`, or `iif` before `lookup 1000`.

The daemon writes routes with `RTPROT_BGP` and metric `200` into table `1000`
only. Existing rows at the same prefix / table / metric that rustbgpd cannot
prove it owns are preserved and reported as `foreign_route_exists`.

At runtime this example needs enough privilege for the configured surfaces:
binding TCP/179 requires root or `CAP_NET_BIND_SERVICE`, and programming
`[[fib_tables]]` routes requires `CAP_NET_ADMIN`. The daemon user must also be
able to write `runtime_state_dir` and the UDS parent directory so the socket and
FIB ownership receipts can be created. `rustbgpd --check --strict` validates the TOML
shape but does not prove those runtime capabilities or filesystem permissions
are present.

## Inspect

```bash
rbgp rib fib
rbgp -j rib fib
ip route show table 1000
ip -6 route show table 1000
curl -s localhost:9179/metrics | grep '^bgp_fib_'
```

`max_routes` is a guardrail, not a selection policy. When the eligible count
exceeds the cap, rustbgpd freezes the table for that pass: existing owned rows
stay in place and new growth is rejected as `route_limit_exceeded`.

## Related

- [`../../docs/CONFIGURATION.md`](../../docs/CONFIGURATION.md#fib_tables)
- [`../../docs/OPERATIONS.md`](../../docs/OPERATIONS.md#view-general-fib-route-status)
- [`../../docs/adr/0061-opt-in-unicast-linux-fib-integration.md`](../../docs/adr/0061-opt-in-unicast-linux-fib-integration.md)
