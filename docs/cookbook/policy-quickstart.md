# Policy quickstart (`.rpol`)

**When this is you:** you're about to write your first real routing
policy on rustbgpd and want the workflow that keeps it honest — a
typed, compiled policy file with its unit tests *in the file*, checked
before it ever touches the daemon, dry-run against the live RIB before
it's attached, hot-swapped under traffic with SIGHUP, and explainable
per term afterwards. Full language reference:
[`rpol-language.md`](../rpol-language.md)
([ADR-0096](../adr/0096-policy-language.md)).

**Proven by:** [M80](../RECEIPTS.md#interop-labs--pr-gated-interopyml)
(route-for-route parity against FRR route-maps, `rbgp policy check`
gating, and a SIGHUP hot-apply under traffic that refreshes only the
peers whose chains changed) and M34 (SIGHUP policy soft-reset
auto-fire). The fixture this quickstart is modeled on:
[`tests/interop/configs/rustbgpd-m80-policy.rpol`](../../tests/interop/configs/rustbgpd-m80-policy.rpol).

## 1. Write the policy — `edge.rpol`

An eBGP edge shape: bogon and transit-leak guards, a customer
prefix-set with per-peer local-pref, community bookkeeping, and tests.

```rpol
prefix-set bogons {
    10.0.0.0/8 le 32, 172.16.0.0/12 le 32, 192.168.0.0/16 le 32,
    100.64.0.0/10 le 32, 0.0.0.0/8 le 32
}
prefix-set customers { 203.0.113.0/24 ge 25 le 28, 198.51.100.0/24 }
community-set scrub-marks { 65000:666 }

# Predicate policy: decides both ways so `apply()` is meaningful.
policy bogon-filter {
    term drop-bogons {
        if route.prefix in bogons { reject }
    }
    term clean { accept }
}

# Parameterized import template: each peer instantiates its own
# local-pref. peer.group matching keeps one policy for the whole
# customer fleet — note the update-group consequence in §6.
policy customer-in(peer_lp: u32) {
    term bogon-guard {
        if !apply(bogon-filter) { reject }
    }
    term transit-guard {
        # A customer must never send us a path through our transit.
        if route.as-path matches "_64620_" { reject }
    }
    term scrub {
        # Modify-and-continue: no verdict, keep walking.
        if route.communities in scrub-marks {
            remove community 65000:666;
            set med 0
        }
    }
    term customer-routes {
        if route.prefix in customers && peer.group == "customers" {
            set local-pref peer_lp;
            add community 65000:100;
            accept
        }
    }
    term default-reject { reject }
}

policy edge-out {
    term no-internal-leak {
        if route.communities has 65000:900 { reject }
    }
    term tag { add community 65000:200; accept }
}

# Tests live with the policy and run offline (`rbgp policy check`).
test accepts-customer-prefix-with-lp {
    route { prefix 203.0.113.0/26; communities [65000:666]; med 300 }
    peer { group "customers" }
    expect customer-in(150) == accept with local-pref 150, med 0, community 65000:100
}

test rejects-customer-prefix-from-wrong-group {
    route { prefix 203.0.113.0/26 }
    peer { group "transit" }
    expect customer-in(150) == reject
}

test rejects-bogon {
    route { prefix 10.1.0.0/16 }
    expect customer-in(150) == reject
}

test rejects-transit-aspath {
    route { prefix 203.0.113.0/26; as-path "65010 64620 3356" }
    expect customer-in(150) == reject
}

test export-blocks-internal {
    route { prefix 198.51.100.0/24; communities [65000:900] }
    expect edge-out == reject
}
```

Note the `peer { ... }` fixture blocks: a policy that matches on
`peer.group` (or `peer.address` / `peer.asn`) needs the test to say
which peer it is evaluating as — an omitted peer block means an empty
peer context and those predicates never match.

## 2. Check it — no daemon needed

```console
$ rbgp policy check edge.rpol
```

Parse, typecheck, and every `test` block — exit 0 clean, 1 for
diagnostics (rendered with source spans), 2 for test failures. Put
this in CI next to the config lint; M80 gates on it.

Keep the file in the canonical style with `rbgp policy fmt edge.rpol`
(one style, no options; comments and semicolons survive), and add
`rbgp policy fmt --check edge.rpol` beside `policy check` in CI —
exit 1 with a diff when a file drifts. See "Formatting" in
[the language reference](../rpol-language.md).

## 3. Wire it into the config

```toml
[global]
asn = 65000
router_id = "192.0.2.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[policy]
rpol_files = ["policies/edge.rpol"]   # relative to this config file

[peer_groups.customers]
hold_time = 90
families = ["ipv4_unicast"]

[[neighbors]]
address = "192.0.2.10"
remote_asn = 64500
description = "customer-a"
peer_group = "customers"
import_policy_chain = ["customer-in(150)"]
export_policy_chain = ["edge-out"]

[[neighbors]]
address = "192.0.2.20"
remote_asn = 64501
description = "customer-b"
peer_group = "customers"
import_policy_chain = ["customer-in(200)"]   # same template, higher LP
export_policy_chain = ["edge-out"]
```

`rustbgpd --check config.toml` validates the whole thing — including
compiling the `.rpol` file — before you restart or reload anything.

Before attaching a *candidate* policy on a running daemon, dry-run it
against the live RIB — read-only, no route state or session touched:

```console
$ rbgp policy test edge.rpol --policy "customer-in(150)" \
    --direction import --peer 192.0.2.10
```

Output: accept/reject counts, per-term hit counters, and before/after
attribute diffs for the first N modified routes.

## 4. Hot-swap under traffic

Edit `edge.rpol`, re-run `rbgp policy check`, then:

```console
$ kill -HUP $(pidof rustbgpd)
```

The planner diffs policy *content*: only peers whose effective chains
changed get a route refresh / re-evaluation (M80 asserts exactly one
peer refreshes when one peer's policy changes; M34 proves the
soft-reset auto-fire). Peers on unchanged chains are untouched.

## 5. Explain it afterwards — the trilogy

```console
# Import: why was this prefix permitted/denied from this peer?
# Per-term trace for .rpol members; backed by the per-session
# decision cache ([policy.explain], on by default — ADR-0073).
$ rbgp policy explain --neighbor 192.0.2.10 --prefix 203.0.113.0/26

# Export: the full gate ladder toward a peer; the export_policy rung
# names the deciding policy:term.
$ rbgp rib --prefix 203.0.113.0/26 advertised 192.0.2.20 --explain

# Best path: why this candidate won in the Loc-RIB.
$ rbgp rib --prefix 203.0.113.0/26 --explain
```

And the live counters — which terms are actually doing work since the
chain was installed (counters reset on chain replace):

```console
$ rbgp policy stats --peer 192.0.2.20
```

## 6. The update-group footnote

`peer.group` / `peer.address` / `peer.asn` matches make a policy's
verdict peer-dependent, so any peer whose **export** chain uses them
drops to the per-peer staging path (`policy_peer_context` in
`rbgp neighbor <address>`, [reason table](../CONFIGURATION.md#update-groups-automatic)).
Identical semantics, less sharing. Import chains don't affect
grouping, and parameterized instantiations like `customer-in(150)` vs
`customer-in(200)` on the *import* side are free. Keep peer-context
matches out of widely shared export chains on a big reflector.

## Failure modes

**`--check` fails after an `.rpol` edit but the daemon is still
running the old policy.** That is the designed order — compile errors
never reach the live daemon. On SIGHUP with a broken file, the reload
is rejected as a unit and the running config stays; fix and re-signal.

**A route you expected `accept`ed is missing.** `rbgp policy explain`
first: `not_seen` means it never arrived (look upstream), a term-named
denial means your policy did it. A denied route keeps no
modifications — a `set` executed before a later `reject` is discarded
by design.

**A test passes but the live daemon disagrees.** Usually chain
composition — another member of the effective chain rejected first —
or a peer-context mismatch between the test's `peer` fixture and the
real neighbor. `rbgp policy chain show --neighbor <addr>` prints the
effective chain order; `rbgp policy test` with `--peer` reproduces
the live evaluation against the real peer context.
