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
For complete deployment scenarios, use the [cookbook](../cookbook/README.md).
The [interop receipts](../receipts.md) describe the separate protocol validation
labs and their measured evidence.
