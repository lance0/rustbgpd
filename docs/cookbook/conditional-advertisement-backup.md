# Backup route with conditional advertisement

> **Document class: CURRENT.**

Announce a backup route to a second upstream only while the primary upstream's route is gone.

**When this is you:** You have two upstreams. Your prefix should reach the
world through transit A, and transit B should carry it only when transit A has
failed. The signal is a route: while transit A's default route is in your RIB,
the primary path is up. Conditional advertisement
([ADR-0137](../adr/0137-conditional-advertisement.md)) withholds the backup
announcement while that condition route is present, and announces it once the
condition route has been absent for `settle_time`. It works for IPv4 and IPv6
unicast and is an alpha feature outside the v1 inventory.

This recipe only controls what rustbgpd announces. rustbgpd does not install
these routes into a forwarding table.

**Proven by:** [M115](../interop.md) runs this shape against FRR 10.7.1. It
withdraws and re-announces the condition, and checks frr-b's received
routes, explain, the metrics and a wire capture of the order and timing. The
lab config is
[`tests/interop/configs/rustbgpd-m115-conditional-advertisement.toml`](../../tests/interop/configs/rustbgpd-m115-conditional-advertisement.toml).

## 1. Configure

`rustbgpd` runs as AS 64500 with transit A (AS 64501) as primary and transit
B (AS 64502) as backup. Your prefix 203.0.113.0/24 is injected locally.

```toml
config_epoch = 2

[global]
asn = 64500
router_id = "192.0.2.2"
listen_port = 179
# RFC 8212: an eBGP direction with no explicit policy carries nothing.
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Transit A's session, so the condition counts only its default route.
[policy.neighbor_sets.transit-a]
addresses = ["192.0.2.1"]

[policy.definitions.default-from-transit-a]
default_action = "deny"
[[policy.definitions.default-from-transit-a.statements]]
action = "permit"
prefix = "0.0.0.0/0"
match_neighbor_set = "transit-a"

# Accept the transits' routes, except our own space.
[policy.definitions.transit-in]
[[policy.definitions.transit-in.statements]]
action = "deny"
prefix = "203.0.113.0/24"
le = 32

# The only routes either transit may receive. It is also the predicate that
# selects the routes the conditional advertisement controls.
[policy.definitions.our-prefixes]
default_action = "deny"
[[policy.definitions.our-prefixes.statements]]
action = "permit"
prefix = "203.0.113.0/24"

# Advertise our prefixes to the attached neighbor only while transit A's
# default route is absent.
[policy.conditional_advertisements.backup-via-transit-b]
advertise_policy = "our-prefixes"
advertise_if = "absent"
condition_prefixes = ["0.0.0.0/0"]
condition_policy = "default-from-transit-a"
settle_time = 5

[[neighbors]]
address = "192.0.2.1"
remote_asn = 64501
description = "transit-a (primary)"
import_policy_chain = ["transit-in"]
export_policy_chain = ["our-prefixes"]

[[neighbors]]
address = "198.51.100.1"
remote_asn = 64502
description = "transit-b (backup)"
import_policy_chain = ["transit-in"]
export_policy_chain = ["our-prefixes"]
conditional_advertisements = ["backup-via-transit-b"]
```

Without `condition_policy`, any default route would satisfy the condition,
including one transit B sends you, and the backup would never be announced.
The export chain on both neighbors keeps transit routes from leaking between
the upstreams, and the import chain must accept transit A's default route for
the condition to see it. The conditional advertisement only filters, so transit B's
export chain still applies to the backup route when it is announced.

Validate, start, and inject the prefix:

```bash
rustbgpd --check /etc/rustbgpd/config.toml
rbgp rib add 203.0.113.0/24 --next-hop 192.0.2.2
```

At startup the definition is pending, and the backup stays suppressed until the
first observation of the condition has been stable for `settle_time`. If
transit A's default route has not arrived by then, transit B receives the
backup. Choose a `settle_time` longer than transit A normally takes to
establish and send its table, and long enough to ride out a brief flap. The
default is 5 seconds and the range is 0 to 600.

## 2. Verify

While transit A's default route is present, the metrics show the condition
present and the gate closed:

```bash
curl -s http://127.0.0.1:9179/metrics | grep '^bgp_conditional_advertisement'
```

```text
bgp_conditional_advertisement_condition{name="backup-via-transit-b",state="absent"} 0
bgp_conditional_advertisement_condition{name="backup-via-transit-b",state="present"} 1
bgp_conditional_advertisement_condition{name="backup-via-transit-b",state="unknown"} 0
bgp_conditional_advertisement_permitted{advertise_if="absent",name="backup-via-transit-b"} 0
bgp_conditional_advertisement_transitions_total{name="backup-via-transit-b"} 1
```

Explain shows why transit B does not receive the prefix. The
`conditional_advertisement` rung sits just before `export_policy`:

```bash
rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.1 --explain
```

```text
Deny: 203.0.113.0/24 to 198.51.100.1
...
  [n/a ] orf            peer installed no Outbound Route Filter
  [STOP] conditional_advertisement suppressed by conditional advertisement backup-via-transit-b: condition prefix 0.0.0.0/0 present (advertise if absent)
Reasons:
- conditional_advertisement_suppressed: suppressed by conditional advertisement backup-via-transit-b: condition prefix 0.0.0.0/0 present (advertise if absent)
```

While the backup is advertised, the rung reads `[pass]` for every route to
transit B, including routes the `advertise_policy` does not select. It reads
`n/a` in two cases: toward a neighbor with nothing attached, and for a route
the `advertise_policy` does not select while the definition is suppressing.

`rbgp neighbor 198.51.100.1` shows `Update Group: conditional_advertisement`:
attached neighbors use the per-peer export path.

### Check status

`rbgp policy conditional-advertisements` (or `rbgp policy conditional`) shows
each definition's condition, gate, and settle timer in one place:

```bash
rbgp policy conditional
```

```text
backup-via-transit-b
  advertise if:  absent
  applied:       suppress
  observed:      present for 1834.2s
  settle:        settled (settle_time 5s)
  conditions:    0.0.0.0/0 present
  attached:      198.51.100.1
```

`applied` is what the gate does now. `observed` is the current condition and
how long it has held. While a changed condition waits out `settle_time`, the
settle line reads `pending, 3.1s left (settle_time 5s)`; at startup under RFC
4724 selection deferral it reads `held by selection deferral`. Add `--json`
for scripts.

When transit A's default route is withdrawn, the condition reads `absent`
immediately. After `settle_time`, `bgp_conditional_advertisement_permitted`
becomes 1, the transitions counter increments, and transit B receives
203.0.113.0/24. When the default route returns and stays for `settle_time`, the
backup is withdrawn from transit B. A change that reverts within `settle_time`
changes nothing.

## 3. Alert

Alert while transit B carries the backup:

```promql
bgp_conditional_advertisement_permitted{name="backup-via-transit-b"} == 1
```

The gauge changes only after `settle_time`, so it already ignores a brief
flap. To catch a gate that disagrees with its condition, use the
mode-adjusted check in the
[operations reference](../reference/operations.md#conditional-advertisement-state).

## Variant: transit A sends no default route

If transit A sends a partial or full table instead of a default route, make
the condition a prefix range: any route from transit A of length /24 or
shorter counts as "transit A is up". Replace the condition predicate and the
definition's condition:

```toml
[policy.definitions.from-transit-a]
default_action = "deny"
[[policy.definitions.from-transit-a.statements]]
action = "permit"
match_neighbor_set = "transit-a"

[policy.conditional_advertisements.backup-via-transit-b]
advertise_policy = "our-prefixes"
advertise_if = "absent"
condition_prefixes = [{ prefix = "0.0.0.0/0", le = 24 }]
condition_policy = "from-transit-a"
settle_time = 5
```

`le = 24` keeps more-specific routes out of the condition; `ge` sets a lower
bound in the same way. The status line for a range shows how many prefixes in
it are present, with the first few:

```text
  conditions:    0.0.0.0/0 le 24 present (812 matching: 1.0.0.0/24, 1.0.4.0/22, 1.0.16.0/24, 1.0.64.0/18, 1.0.128.0/17, 1.1.1.0/24, 1.1.8.0/24, 1.6.0.0/16, +804 more)
```

The backup is announced only after the last such route from transit A is
gone and `settle_time` has passed. A range is matched as routes arrive and
leave, without a table walk; a wide range costs memory for each present
prefix it covers.

## Failure modes

| Symptom | Check |
|---------|-------|
| Transit B never receives the backup | The condition may still be satisfied by another default route: run `rbgp policy conditional` and explain on the backup prefix toward transit B, and read the condition state they name. Confirm `condition_policy` matches only transit A's session |
| Transit B receives the backup while transit A is up | `bgp_conditional_advertisement_condition` reads `absent`: transit A is not sending the default route, or `condition_policy` rejects it. Run `rbgp rib received 192.0.2.1` to confirm |
| Condition reads `unknown` | `condition_policy` failed to evaluate; `bgp_policy_eval_errors_total{direction="condition"}` counts it, and the applied state is held |
| Backup appears briefly at startup | Transit A took longer than `settle_time` to deliver the default route. Raise `settle_time` |

Reference: [Conditional advertisements](../reference/configuration.md#conditional-advertisements).
