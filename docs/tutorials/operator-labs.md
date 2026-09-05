# Operator labs

> **Document class: CURRENT.**

Run a local BGP exercise, introduce a fault, and use the CLI to explain it.

## Quickstart: an established session with no accepted routes

This lab reuses the [Docker Compose demo](../../examples/docker-compose/README.md):
rustbgpd and an FRR peer announcing sample routes. You remove the import policy,
observe RFC 8212 rejecting the routes, and restore the policy. The commands run
from the repository root.

You need Linux, Bash, Python 3, `just`, and Docker with the Compose plugin and
BuildKit. Your user must be able to run Docker. The first `up` builds the daemon
from this checkout and pulls the pinned FRR image; build time depends on the
machine and cache. Later runs reuse cached build layers.

Stop the ordinary Compose demo before starting this lab: both use the same
address ranges and loopback ports 50051 and 9179. The lab uses its own fixed
Compose project, `rustbgpd-lab-quickstart`, with separate containers and state.
Run one instance of this lab at a time.

```bash
just lab quickstart up
just lab quickstart verify
just lab quickstart break
just lab quickstart explain
```

`up` waits for daemon health, restores the demo import policy, and waits for FRR
to reach `Established` with `192.168.1.0/24` selected. `verify` checks that session
and route; it exits unsuccessfully if either is missing. After `break`, that
verification should fail even though the session remains established.

`explain` shows the retained rejected routes and the cached import decision.
Look for `policy_reject`, `rfc8212_missing_import_policy`, and `default-action
deny`. The missing-import-policy metric is `1`: the peer is connected, but no
explicit import policy permits its routes.

Restore the original policy and verify recovery:

```bash
just lab quickstart up
just lab quickstart verify
just lab quickstart down
```

`down` removes only this lab's Compose containers, network, and state volume.
It discards this lab's persisted configuration edits. It leaves the ordinary
Compose demo and cached images intact. Run it after a failed or interrupted
exercise too; repeating `down` is safe.

For the underlying commands, see the [manual exercise](../../examples/docker-compose/README.md#break-explain-restore).

## IXP: connected members with rejected routes

This lab runs one transparent route server, two FRR 10.7.1 members, and a
local StayRTR 0.6.4 cache. Member A (AS65002) announces `198.51.100.0/24`.
The cache authorizes that origin; member B (AS65003) receives the route with
AS_PATH `65002` and next hop `10.98.0.20`, preserved by the route server.
It uses the same host prerequisites as the quickstart lab.

```bash
just lab ixp up
just lab ixp verify
just lab ixp break
just lab ixp explain
```

`up` builds the development image from this checkout, starts the four
containers, restores member A's normal announcements, and waits for both
sessions, the VRP cache, and member B's received route. `verify` checks all
of these, including RPKI validity and transparent AS_PATH and next hop.

`break` adds AS65099 to the end of member A's outgoing AS_PATH, changing the
origin without changing the BGP session. The route is now RPKI-invalid and
the `reject-rpki-invalid` policy rejects it. The same phase announces
`203.0.113.0/25`, which has no covering VRP and is rejected independently by
`reject-long-prefixes`. It waits for both retained rejections and checks that
neither prefix is selected or present at member B. `verify` should now fail.

`explain` shows the connected members, retained rejections, the covering VRP
authorizing AS65002, and both import-policy decisions. The export explanation
stops at `best_route`: an import-rejected route cannot be advertised to member B.
Policy counters show which import terms matched.

Restore the legitimate origin and remove the extra /25:

```bash
just lab ixp up
just lab ixp verify
just lab ixp down
```

The lab uses the dedicated Compose project `rustbgpd-lab-ixp` and subnet
`10.98.0.0/24`, with no published host ports. Run one instance at a time and
avoid an overlapping local Docker network. `down` removes its containers and
network, including the temporary FRR changes; repeating it is safe. Run it
after a failed or interrupted exercise too.

The [configuration](../../labs/ixp/rustbgpd.toml) deliberately reduces IXP
policy to two teaching examples. The VRP file is a static, synthetic fixture
with expiry checking disabled in StayRTR; it is not a public RPKI validator.
For the production configuration shape, see the
[route-server example](../../examples/route-server/README.md).

## Route reflector: an unintended origin wins

This lab runs a route reflector and two FRR 10.7.1 clients in AS65001.
Client A is the intended sole origin of `198.51.100.0/24`; client B receives
its reflected route. It uses the same host prerequisites as the quickstart.

```bash
just lab rr up
just lab rr verify
just lab rr break
just lab rr explain
```

`verify` checks both client sessions, the selected source, and receipt at
client B with the original next hop and ORIGINATOR_ID. It also checks that
the reflector does not advertise the route back to its source.

`break` makes client B originate the same prefix. Its otherwise equal path
wins because B has the lower BGP Identifier. Both sessions remain
Established, but `verify` now fails because A is no longer the sole origin.
`explain` shows the winning source, the identifier tie-break, and the
`split_horizon` export stop toward that source.

Remove B's unintended announcement and verify recovery:

```bash
just lab rr up
just lab rr verify
just lab rr down
```

The lab uses the dedicated Compose project `rustbgpd-lab-rr` and subnet
`10.97.0.0/24`, with no published host ports. Run one instance at a time
and avoid overlapping local networks. Repeating `up` restores the intended
origin; repeating `down` safely removes the lab's containers and network.

For complete deployment scenarios, use the [cookbook](../cookbook/README.md).
The [interop receipts](../receipts.md) describe the separate protocol validation
labs and their measured evidence.
