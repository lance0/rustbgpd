### Upgrade notes

- API and `rbgp neighbor --json` consumers of `inbound_prefix_limits[]` must
  read `family` and `stage` instead of `scope`:
  - `scope = "aggregate"` is `family = "aggregate", stage = "accepted"`.
  - `scope = "ipv4_unicast"` is `family = "ipv4_unicast", stage = "accepted"`.
  - `scope = "ipv4_unicast_received"` is `family = "ipv4_unicast",
    stage = "received"`, and likewise for IPv6.
  - A non-unicast family keeps its label with `stage = "accepted"`.

  Tooling that matches the `max_prefix_warning` event reason or the
  `rbgp doctor` check `peer.<address>.inbound_prefix_limit.<scope>` must match
  `family <family> stage <stage>` and `inbound_prefix_limit.<family>.<stage>`.
