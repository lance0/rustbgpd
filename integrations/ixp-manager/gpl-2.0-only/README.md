# IXP Manager Foil exporter

This directory contains original GPL-2.0-only integration source. It is not
part of any rustbgpd binary, binary package, release archive, or final image.
See [`LICENSE`](LICENSE).

Install `api/v4/router/server/rustbgpd/json.foil.php` beneath the same path in
the active IXP Manager `VIEW_SKIN`. IXP Manager v7.4 then renders the strict
`rustbgpd.ixp-manager.router-config/v2` JSON document through its normal router
configuration generator. The exporter reads IXP Manager's sanitized session,
IRR, max-prefix, authentication, RPKI, and route-filter state; it does not copy
or translate the upstream BIRD templates.

The exporter preserves every applicable UI filter as one ordered row,
including peer identity, distinct received and advertised prefixes, protocol,
and both actions. The Rust renderer translates the bounded pinned-v7.4 subset
exactly: advertise control actions and ordered receive AS_IS, deny, and
PREPEND. Reachable overlap is bounded into disjoint peer and exact-prefix
cells; counts above 255 or more than 4096 compiled cells refuse. Missing peers,
malformed order or prefixes, and more than 256 rows per client or 4096 total
are also refused.

Fetch that document separately through the authenticated IXP Manager API into
a regular, non-symlink mode-0600 local file. Keep API keys in the fetcher's
secret store or request header, never in a command line, JSON capture,
candidate, or receipt. The Rust renderer has no HTTP client and does not handle
IXP Manager credentials.

The exporter deliberately reports active BIRD skin overrides so the Rust
renderer can refuse instead of silently losing policy. It also distinguishes
an unset no-transit override from an explicitly empty override. This is not a
generic IXP Manager policy engine or a custom-skin translator. See
`tools/rs-config-render/README.md` for the bounded manual render and
strict-check workflow.
