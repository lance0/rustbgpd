# `.rpol` language reference

> **Document class: REFERENCE.**

The `.rpol` language defines typed routing policy for rustbgpd.
Status: **shipped** (ADR-0096, complete). The frontend — lexer,
parser, typechecker, in-language tests, and `rbgp policy check` — the
daemon integration — `[policy] rpol_files` config references, mixed
TOML/rpol chains, SIGHUP hot-apply, and the `rbgp policy test`
live-RIB dry run — and the explain surfaces — per-term statement
traces in `rbgp policy explain` / `rbgp rib --prefix P advertised PEER --explain` and
live per-term hit counters via `rbgp policy stats` — are all live
(see "Using policies in the daemon" below). The M80 interop lab
proves route-for-route parity against FRR route-maps expressing the
same intent, plus `.rpol`-edit-under-traffic hot-apply with Route
Refresh scoped to the peers whose chains changed.

`.rpol` compiles to the same public typed IR (`rustbgpd_policy::ir`)
that TOML policy chains compile to, and is evaluated by the same
tree-walk engine. Match data (prefix sets, community sets, AS-path
regexes) compiles out of the program into shared indexed structures —
a thousand-member set costs one hash probe per route, not a
thousand-statement walk.

## Example

```rpol
# Sets: match data, compiled to indexed structures.
prefix-set customers { 10.10.0.0/16 ge 24 le 28, 192.0.2.0/24 }
community-set tagged { 65000:100, 65000:200 }

# A predicate policy: matches bogons, rejects everything else.
policy bogon-filter {
    term bogons { if route.prefix == 0.0.0.0/8 { accept } }
    term everything-else { reject }
}

# A parameterized policy: `peer_lp` is substituted at instantiation.
policy customer-in(peer_lp: u32) {
    term rpki-guard { if route.rpki == invalid { reject } }
    term customer-routes {
        if route.prefix in customers && route.communities has 65000:100 {
            set local-pref peer_lp;
            add community 65001:999;
            accept
        }
    }
    term bogon-guard { if apply(bogon-filter) { reject } }
}

# In-language tests, run by `rbgp policy check`.
test customer-in-accepts-tagged {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki valid }
    expect customer-in(200) == accept with local-pref 200
}
```

```console
$ rbgp policy check customer-in.rpol
customer-in.rpol: 1 passed, 0 failed
$ echo $?
0
```

Exit codes, in precedence order: `1` compile diagnostics (or unreadable
file), `2` in-language test failures (or no tests under
`--fail-on-empty`), `3` coverage below an explicit threshold (see
[Coverage and lints](#coverage-and-lints)), `4` a lint denied by
`--deny-lints`, otherwise `0`. The
[CLI reference](../../crates/cli/README.md#policy-check-as-a-ci-and-editor-gate)
has the full table. `--json` emits a machine-readable report with stable
compiler-stage codes: `lex-error`, `parse-error`, `resolve-error`,
`typecheck-error` and `lower-error`. The CLI reference describes their
boundaries; error messages remain in the legacy `diagnostics` array.

## Lexical structure

- **Comments**: `#` to end of line.
- **Identifiers** (set, policy, term, test, parameter names) are
  kebab-case: `[A-Za-z_][A-Za-z0-9_]*(-[A-Za-z0-9_]+)*`. Maximal munch
  is permanent (ADR-0103): `a-b` is always one identifier, so binary
  subtraction requires whitespace — `route.med - 1` subtracts,
  `route.med-1` is an unknown-field error (with a did-you-mean note).
- **Reserved keywords** (not usable as names): `prefix-set`,
  `community-set`, `asn-set`, `policy`, `term`, `test`, `if`, `else`, `set`,
  `add`, `remove`, `prepend`, `accept`, `reject`, `apply`, `in`,
  `has`, `matches`, `contains`, `ge`, `le`, `route`, `peer`,
  `expect`, `with`, `as`, `self`, `u32`. Field names (`local-pref`,
  `communities`, …) and enum members (`valid`, `internal`, …) are
  contextual, not reserved.
- **Literals** are single tokens, longest-match:
  - Prefix: `10.0.0.0/8`, `2001:db8::/32`. Host bits set beyond the
    prefix length are a compile error (not silently masked). IPv6
    literals must use the compressed `::` form — all-numeric
    full-form IPv6 is ambiguous with community literals.
  - IP address: `192.0.2.1`, `2001:db8::1`.
  - Standard community: `65000:100` (both parts u16), or a well-known
    name: `NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`,
    `BLACKHOLE`, `GRACEFUL_SHUTDOWN`.
  - Large community: `65000:1:2` (three u32), also accepted as
    `LC:65000:1:2` for parity with the TOML frontend.
  - Extended community (Route Target / Route Origin):
    `RT:65001:100`, `RO:65001:100`, `RT:192.0.2.1:5` (IPv4 admin),
    `RT:200000:100` (4-octet-AS admin). IPv4 and 4-octet-AS admins
    take a u16 local part (RFC 4360 encodings). Well-known names:
    `OV_VALID`, `OV_NOT_FOUND`, `OV_INVALID` — the RFC 8097
    origin-validation states (non-transitive opaque, type `0x43`
    sub-type `0x00`, state in the last octet), matched and
    added/removed by exact wire value.
  - Community pattern, valid only as a `community-set` or dataset member:
    a standard, large or extended literal whose fields may also be `*`,
    an inclusive range `a..b`, or `PRIVATE_AS` — `65000:*`, `*:666`,
    `65000:100..199`, `PRIVATE_AS:*`, `65000:1..9:*`, `RT:65000:*` (see
    "Sets"). A pattern is one token: `65000:*` and `65000 : *` differ.
  - Strings (AS-path regexes, peer-group names): `"..."` with `\"`
    and `\\` escapes.
- **Statement separators**: `;` between statements is conventional
  but optional (the grammar is unambiguous without it); the idiomatic
  style semicolon-terminates everything except a final verdict.

## Types

The type universe is fixed; there are no user-defined types, no maps, and
no unbounded iteration (ADR-0096 Decision 2/4; bounded `for` loops are
covered under "Loops"), and inference is trivial: every field
has a known type and every operator a fixed signature.

| Type | Values | Where |
|---|---|---|
| bool | guard expressions | `if` conditions |
| u32 | integer literals, parameters, `let` bindings | `local-pref`, `med`, `as-path.len`, `communities.len`, `large-communities.len`, `ext-communities.len`, arguments; the only arithmetic type — `+ - *` **saturate** at 0 and 4294967295, never wrap or trap, and a divisor can never be zero (see "Saturating u32 value expressions") |
| asn | `route.origin-as`, `peer.asn`, `for` loops over `route.as-path` or an asn-set, `let` bindings of these | compared with `==`, `!=`, `>=`, `<=` against an integer literal or u32 parameter (private ranges: `route.origin-as >= 64512 && route.origin-as <= 65534`), with `==`/`!=` against another ASN, probed against asn-sets, and set as a whole value (`set med route.origin-as`); **no arithmetic** |
| community value | standard community literals (`65000:1`), `for c in route.communities`, `community` parameters, `let` bindings of these | compared with `==`/`!=` against another community value, probed against community-sets (standard members only), added or removed; no arithmetic, no asn-set probe, and never equal to an ASN or an integer |
| prefix | prefix literals | `route.prefix` |
| community (3 kinds) | community literals | community lists, sets, actions |
| as-path | — (matched, never named) | `route.as-path` |
| rpki-state | `valid`, `invalid`, `not-found` | `route.rpki` |
| aspa-state | `valid`, `invalid`, `unknown` | `route.aspa` |
| route-type | `local`, `internal`, `external` | `route.route-type` |
| route-family | `ipv4-unicast`, `ipv6-unicast`, `ipv4-labeled-unicast`, `ipv6-labeled-unicast`, `vpnv4`, `vpnv6`, `ipv4-flowspec`, `ipv6-flowspec`, `vpnv4-flowspec`, `vpnv6-flowspec`, `evpn`, `rtc`, `bgp-ls`, `bgp-ls-vpn` | `route.family` |
| IP address | address literals | `route.next-hop`, `peer.address` |
| string | string literals | regexes, `peer.group` |

`ipv4-flowspec` and `ipv6-flowspec` match global FlowSpec (SAFI 133) only.
Use `vpnv4-flowspec` for IPv4 VPN FlowSpec (AFI 1 / SAFI 134,
`l3vpn_ipv4_flowspec` in configuration) and `vpnv6-flowspec` for IPv6 VPN
FlowSpec (AFI 2 / SAFI 134, `l3vpn_ipv6_flowspec` in configuration). A policy
that denies a global FlowSpec family does not deny VPN FlowSpec rules. Both
VPN families remain outside the v1 inventory. They share the
[ADR-0146 contract](../adr/0146-vpn-flowspec.md), extended to IPv6. Their
export policy can add or remove route targets with the existing
extended-community actions;
`NO_ADVERTISE` still suppresses the rule before and after policy evaluation.

## Sets

```rpol
prefix-set NAME { PREFIX [ge N] [le N], ... }
community-set NAME { COMMUNITY-LITERAL, ... }
asn-set NAME { ASN, ... }
```

Set names share one namespace across kinds and with datasets: a
prefix-set, community-set, asn-set or dataset with the same name as
another is a compile error naming both, because an `in` reference could
not tell which to probe.

- `ge`/`le` bounds are per member, with the same semantics as the
  TOML frontend (and Cisco/Juniper prefix lists): the candidate is
  masked at the member's length and its length must fall in the
  derived range (`ge` only → `ge..=address_bits`; `le` only →
  `member_len..=le`; neither → exact length). Bounds must satisfy
  `member_len <= ge <= le <= address_bits` (32 for IPv4, 128 for
  IPv6); a member whose range could never match, such as
  `10.0.0.0/24 le 16` or `10.0.0.0/24 ge 28 le 26`, is a compile
  error. Dataset snapshot files use the same grammar and the same
  rule.
- Community sets may mix standard, large, and extended members, but a
  probe reads one kind: `route.communities in S` matches the route's
  standard communities against the set's standard members only, and
  `route.large-communities` / `route.ext-communities` likewise. A
  member of another kind in a named set is a compile error for that
  probe, because it could never match there. A set that mixes kinds, such
  as the standard and large twins of a route-server action community, is
  probed with `route.any-community in S`, which matches a route community
  of any kind against the members of its kind. Datasets and set
  parameters filter by kind at runtime.
- Community-set members may be **patterns** that match a range of
  values (see "Community patterns" below).
- ASN sets hold plain ASN literals (u32; 4-byte ASNs are first-class,
  out-of-range literals are a compile error, duplicates deduplicate).
  Membership is probed by `route.origin-as in NAME` and
  `peer.asn in NAME` — one hash probe regardless of set size. Like
  strict next-hop, this is an `.rpol`-only surface: the TOML frontend
  has no equivalent.
- Sets are content-interned: identical sets (in any member order)
  share one indexed structure across all policies.
- There is no `as-path-set` in V1 — inline
  `route.as-path matches "regex"` covers the need (deliberately
  deferred; the regex engine is the existing Cisco-style matcher).

### Community patterns

A community-set or dataset member can match many values:

```rpol
community-set customer-tags {
    65000:*,            # any 65000:x
    *:666,              # x:666 for any ASN half
    65000:100..199,     # 65000:100 through 65000:199
    PRIVATE_AS:*,       # a private-use ASN half
    65000:1..9:*,       # large: 65000:1:x through 65000:9:x
    PRIVATE_AS:*:*,     # large: a private-use global administrator
    RT:65000:*          # every route target with global administrator 65000
}
```

| Kind | Fields | Examples |
|---|---|---|
| Standard | two halves, each 0–65535 | `65000:*`, `*:666`, `65000:100..199`, `PRIVATE_AS:7`, `65000:PRIVATE_AS`, `*:*` |
| Large | three parts, each 0–4294967295 (`LC:` prefix optional) | `65000:*:*`, `65000:1:*`, `65000:1..9:*`, `*:7:*`, `PRIVATE_AS:*:*` |
| Extended | `RT:` or `RO:`, then global and local administrators | `RT:65000:*`, `RT:*:666`, `RO:65000:10..20`, `RT:PRIVATE_AS:*`, `RT:192.0.2.1:*` |

- Each field is a number, `*` (every value of the field), an inclusive
  range `a..b`, or `PRIVATE_AS` — the RFC 6996 private-use ASNs,
  64512–65534 and, for a 32-bit field, 4200000000–4294967294. A
  standard-community half is 16 bits, so `PRIVATE_AS` there means
  64512–65534. A value or range end beyond the field's width, and a
  range whose low end exceeds its high end (`65000:200..100`), are
  compile errors. A pattern whose fields each hold one value
  (`65000:5..5`) is the exact member `65000:5`.
- Extended patterns compare the decoded `(global, local)` pair, the same
  encoding-agnostic identity RT/RO literals use: `RT:*:666` matches the
  2-octet-AS, 4-octet-AS and IPv4-administrator encodings alike. An IPv4
  administrator compares as its 32-bit value, so `RT:65000:*` also matches
  the route target `0.0.253.232:x`, as the exact literal `RT:65000:x`
  does. As for the literal, a pattern whose global administrator needs the
  4-octet-AS or IPv4 encoding and whose local administrator never fits in
  16 bits (`RT:192.0.2.1:70000..80000`) is a compile error.
- Patterns are members, not values. `add`, `remove`, `has` and test
  fixtures reject them; probe with `in`. In `<binding> in <set>` the
  binding is a standard community, so only the set's standard members
  and patterns can match it.
- There is no regex form; `ios-regex` and `peeras` elements of an RPL
  community set have no equivalent.

**Cost.** Exact members stay hash probes, and a set with no patterns of a
kind evaluates exactly as before. Patterns sit beside the exact members,
bucketed by a fixed field: a standard pattern by its fixed ASN half, or
else its fixed low half; a large or extended pattern by its fixed global
administrator. A pattern with no such field is compared against every
community of its kind. One route community therefore costs at most one
probe per bucket, plus the comparisons in those buckets and against the
unbucketed patterns. A set or dataset snapshot whose worst case exceeds
64 comparisons per community is a load error. The evaluation-cost budget
counts an `in` probe as one step whatever the set holds, so patterns
multiply the work behind that step by up to 64 comparisons per route
community: at the wire bound of 16,383 standard communities, about one
million comparisons for one probe of a set at the limit.

Migrating an origin lock from an AS-path regex to an ASN set:

```rpol
# Before: one regex alternation, re-matched against the rendered
# AS-path string per evaluation.
policy customer-origins-old {
    term match { if route.as-path matches "_(64500|64501|64502)$" { accept } }
    term rest { reject }
}

# After: one indexed set, one O(1) probe against the typed origin;
# reusable across policies, no regex escape gymnastics for new ASNs.
asn-set customers { 64500, 64501, 64502 }

policy customer-origins {
    term match { if route.origin-as in customers { accept } }
    term rest { reject }
}
```

## Datasets — external set content

```rpol
dataset prefix-set bogons
dataset asn-set customers
dataset community-set scrub-tags
```

A **dataset** is a named set whose members come from an
operator-maintained file instead of source text — the shape of
"data the daemon doesn't have": bogon feeds, IX participant lists,
customer origin sets, tag feeds produced by external automation. The
declaration carries only the name and kind; the daemon config binds
the name to a snapshot file:

```toml
[policy]
rpol_files = ["policies/core.rpol"]

[policy.datasets.customers]
path = "/var/lib/rustbgpd/datasets/customers.list"
```

Guards reference a dataset **exactly like a set of its kind** —
`route.prefix in bogons`, `route.origin-as in customers`,
`peer.asn in customers`, `route.communities in scrub-tags`, and the
binding/parameter forms `<binding> in customers`. Probes run the same
indexed structures in-language sets compile into, at the same cost.
The differences from a source-defined set:

- **Content is a runtime snapshot.** Each dataset has an immutable,
  atomically-swapped snapshot with a monotonic generation. Every
  evaluation pins each referenced snapshot **once at walk start** —
  one route never observes two generations of the same dataset, even
  when a refresh lands mid-walk.
- **Content changes are data, not policy.** A refresh never
  recompiles or replaces chains; installed chains see the new
  generation at their next walk, and the daemon refreshes exactly the
  peers whose chains reference the swapped dataset (Route Refresh
  inbound for import chains, forced re-advertisement for export
  chains). Unrelated peers, chains, and hit counters are untouched.
- **Namespace is shared.** Datasets live in the flat set namespace: a
  dataset and a set with the same name is a compile error, as is
  declaring one name with two kinds (across imports too). At most 16
  datasets per compilation unit.
- **Probe-only in this slice.** `for x in <dataset>` is a compile
  error — content is a runtime snapshot, so iteration bounds are not
  compile-time knowledge. Probe with `in` instead. A community dataset
  can also be the set of `remove <kind> in` / `not in` (see
  [Removing by set membership](#removing-by-set-membership)).
- **Parameter probes stay runtime probes.** `<parameter> in <set>`
  folds to a constant for source sets; against a dataset it stays a
  live probe, because the answer changes with the content.
- **Membership only — no tag maps.** A key→value dataset kind
  (prefix → customer tag, ASN → tier) is deliberately deferred: the
  language's value model is `u32` membership and comparison, and a
  map lookup would introduce a new value-producing guard form. Model
  tags as one membership dataset per tag value for now.

There is deliberately **no external code tier** — no WASM, no host
functions, no per-route callouts (ADR-0103 Decision 9). External
*computation* runs outside the daemon on its own schedule and writes
snapshot files; datasets are the entire external surface of the
policy language.

### Snapshot file format

One entry per line; `#` starts a comment; blank lines and surrounding
whitespace are ignored. Entries use the exact literal grammar of the
declared kind's set definition:

```text
# customers.list (asn-set)
64500
64501   # trailing comments are fine
4200000001
```

```text
# bogons.list (prefix-set)
10.0.0.0/8 ge 8 le 32
192.0.2.0/24
2001:db8::/32 ge 48
```

```text
# scrub-tags.list (community-set)
65000:666
65000:1:2
RT:65001:7
NO_EXPORT
65001:*          # patterns work as in a community-set
64496:1..9:*
```

Bounds: 64 MiB per file, 1,000,000 records. A line that does not
parse — or a file of the wrong kind — fails the whole snapshot with a
line-numbered error; there are no partially-loaded snapshots.

**Produce snapshots atomically**: write to a temporary file on the
same filesystem, then `rename(2)` over the target (`mv -f tmp final`)
— the daemon reads the file on refresh and must never see a torn
write. A cron job shape:

```sh
fetch-customers > /var/lib/rustbgpd/datasets/.customers.list.tmp \
  && mv -f /var/lib/rustbgpd/datasets/.customers.list.tmp \
           /var/lib/rustbgpd/datasets/customers.list
```

### Refresh, failure, and observability

Dataset files are (re)read at config load and on every SIGHUP reload —
there is no file watcher and no dedicated refresh RPC; `kill -HUP` (or
`systemctl reload`) after the rename is the refresh trigger. Refresh
semantics:

- **Content-equal re-reads are no-ops** — no generation bump, no peer
  refresh (the same content-equality discipline chain reinstalls use,
  so a SIGHUP with nothing changed touches nothing).
- **Changed content swaps atomically** and bumps the generation, then
  refreshes only the referencing peers. On the export side, when every
  referencing receiver probes the dataset only with `route.prefix in` or
  `route.origin-as in` and sends only IPv4/IPv6 unicast and VPNv4/VPNv6,
  the RIB re-evaluates only the routes whose prefix (a VPN route's inner
  prefix) or origin AS the old and new contents answer differently. Any
  other probe or family, attached conditional advertisement, or a VPN
  best-path selection still held by graceful-restart deferral
  re-evaluates every route for those peers. That full re-evaluation runs
  once per update group and sends each member only the routes whose
  export changed. Changed unicast announcements are encoded once per
  group and shared by its members; changed VPN routes are evaluated once
  per group but still encoded per session. Peers outside a group
  re-evaluate against their own Adj-RIB-Out. Receivers that also
  send another family (EVPN, labeled unicast, FlowSpec, BGP-LS or
  RT-Constrain), and every receiver while a VPN selection is held by
  deferral or a conditional advertisement is installed, instead get a
  complete per-peer resync. The
  `dataset export re-evaluation complete` log event reports which
  (`mode`, and `full_pass` = `group` or `member` for a full pass), with
  `affected_prefixes`, `affected_vpn_keys` and `elapsed_ms`.
- **A file that fails to load or parse rejects the whole reload.**
  Every declared dataset must load before anything is published, so a
  malformed or unreadable file leaves the prior snapshot serving, the
  rest of the candidate unapplied, and the candidate file on disk. The
  daemon increments `bgp_policy_dataset_refresh_errors_total{dataset}`
  and logs `SIGHUP reload rejected without runtime effect`. Empty data
  is never substituted — an empty snapshot requires an explicitly
  empty file.
- **Adding, removing, or re-mapping a dataset** (a declaration, a
  kind change, or a file path) is reloadable in the same compensated
  generation as the neighbor and policy changes that use it; see the
  [reload routes](reload-matrix.md#sighup-reload-routes) for the
  combinations that still reject. Its file must load cleanly or the
  whole load/reload is rejected, like any other config error.
- Superseded snapshots are retained only while in-flight walks still
  pin them; there is no generation history.

`rbgp policy stats` reports every dataset's kind, generation, record
count, bound path, and last refresh error. Explain traces annotate
dataset probes with the pinned generation —
`route.origin-as in customers [dataset asn-set customers, gen 7]` —
without ever dumping content.

In-language `test` blocks never read operator files: a test whose
policy probes a dataset provides the content itself with a `dataset`
override before the fixture (kind-checked against the declaration; a
missing override fails the test with a message naming the dataset):

```rpol
dataset asn-set customers

policy origin-guard {
    term customers { if route.origin-as in customers { accept } }
    term rest { reject }
}

test member-accepted {
    dataset customers { 64500, 64501 }
    route { prefix 10.0.0.0/24; as-path "64777 64500" }
    expect origin-guard == accept
}
```

`rbgp policy check` works on dataset-declaring files (tests supply
content); compiling a dataset-referencing policy for live use requires
the daemon config's bindings.

## Policies, terms, and evaluation order

```rpol
policy NAME[(param: u32, ...)] {
    [default-action accept|reject]
    term NAME { statement... }
    ...
}
```

- Terms evaluate in order. Statements inside a term are: bare
  actions, `let` bindings (see "Bindings"), `for` loops (see "Loops"),
  `apply` statements that run another policy (see "`apply` as a
  statement"), or `if <expr> { ... } [else if <expr> { ... }]... [else
  { ... }]`. The first branch whose condition matches runs, and at most
  one does. An `if` body holds actions, `let` bindings, `apply`
  statements and nested `if` statements, up to **four levels** of `if`
  (an `else if` chain of any length is one level); the fifth is a
  compile error. Loops stay in term and loop bodies.
- **Verdicts**: `accept` permits the route (with all modifications
  executed so far in this policy); `reject` denies it (a denied route
  has no attributes — modifications in a rejecting branch are
  discarded). A verdict ends the policy's evaluation.
- **Fallthrough**: if a guard doesn't match, or a matched body ends
  without a verdict, evaluation continues to the next term.
  Modifications executed along the way (Junos-style
  modify-and-continue) are kept and merged into the eventual accept.
- **End of policy without a verdict** uses the policy's `default-action`.
  When omitted, it remains `accept`, with accumulated modifications.
  An accepting policy continues the chain; a rejecting policy stops it
  and discards staged modifications.
- Statements after a bare `accept`/`reject` in the same term (or
  statements after a verdict in the same `if` body) are **unreachable
  and a compile error**.

An optional `default-action accept|reject` declaration must appear at most
once, before the first term. Its semicolon is optional. For example:

```rpol
prefix-set customers { 192.0.2.0/24 }

policy authorized-customers {
    default-action reject
    term authorized {
        if route.prefix in customers { accept }
    }
}
```

The default decides only when no term has returned a verdict. Explicit
`default-action accept` has the same behavior as omission, including continuing
to later policies in a chain. Existing unconditional terms, such as
`term reject-rest { reject }`, remain valid. A default declaration does not
detect an accidentally removed guard or conjunct: include negative route
assertions that would fail if the allowed set widened.

### Lowering into the IR (normative)

The IR's `Term` is one `(guard, action)` pair; an `.rpol` term lowers
to one or more IR terms:

- Each `if` becomes an IR term (guard = condition); its `else`
  becomes a following IR term guarded by the negated condition.
- An `else if` chain or a nested `if` adds no runtime node. Every IR
  term a branch body lowers to is guarded by the branch's **path
  condition**: the enclosing branch's path, then the negation of each
  earlier guard in the chain, then the branch's own guard, as one flat
  conjunction in that order. The final `else` takes the negations alone.
  The path conjunction evaluates its conditions in that order and stops
  at the first miss, so a branch's guard evaluates only where the source
  would reach it. A source-level `&&` makes no such promise: the compiler
  may evaluate its operands in either order (cheapest first), so
  `if A && B { ... }` is not `if A { if B { ... } }` when `B` can fail
  closed. Nest the `if` when `B` must not run unless `A` holds.
- A branch whose body always ends in `accept` or `reject` adds no
  negation to the later branches: first-match already keeps the walk from
  reaching them after it matched, and a guard that fails closed denies the
  route at the branch's own term. A chain of deciding branches therefore
  costs about what one term per branch does. A branch that can fall
  through, by only modifying the route, keeps its negation in every later
  term, so a chain of such branches re-evaluates the earlier guards and its
  cost grows with the square of its length. The compile-time cost and size
  budgets charge every re-evaluation.
- A run of bare modification actions flushes as an unconditional
  `Continue` IR term (a small IR addition made for this frontend:
  guard matched → apply modifications → keep walking this policy's
  terms).
- Each `let` becomes a `Bind` IR term: guard = the
  enclosing branch condition (`True` in term-body position; the `if`
  guard — or its negation for `else` — for a body binding), action =
  evaluate the initializer and write its frame slot. Like `Continue`
  it never decides; body bindings re-evaluate the branch guard, which
  is pure and cannot diverge.
- IR terms are named after the source statement they execute. One row of
  the term's final statement owns the bare term name: the last of its rows
  that holds the statement's own `accept` or `reject`, or, when none does,
  its last row. Every other row is the term name, then `.<statement>`, the
  1-based position of the statement in the term body (omitted when the body
  has one statement), then `.<k>`, the row's 1-based position among its
  statement's rows, when that statement lowers to more than one IR term. A
  run of modifications flushed as one `Continue` term is named after its
  last statement, and an `accept` that carries staged modifications after
  the `accept`: `term tag { add community 65000:1; accept }` lowers to
  `tag`, `term t { set med 10; if A { accept } }` to `t.1` and `t`, and
  `term t { if A { accept } else { reject } }` to `t.1` and `t`. The
  [term-name rulings](#term-name-rulings) give the stability promise and
  the edge cases. Explain traces, `rbgp policy test` term hits, and
  `rbgp policy stats` render these names, and the
  [decision corpus](#compatibility) pins every row's name, position and
  action, with the values, bindings and loop body it holds.

### Parameters

A parameterized policy is a **template**: each use site with concrete
arguments is monomorphized at compile time (clone-with-substitution;
policies are small, this is microseconds). The evaluator only ever
sees constants and interned sets, so a parameter costs nothing per
route.

```rpol
policy customer-in(lp: u32, pfx: prefix-set, tag: community, nh: ip) {
    term ours {
        if route.prefix in pfx { set local-pref lp; add community tag; set next-hop nh; accept }
    }
}
```

| Type | Argument | Where the parameter goes |
|---|---|---|
| `u32` | an integer | anywhere a u32 is expected: `set local-pref lp`, `route.local-pref >= lp`, `route.as-path contains asn`, a `prepend` operand or count |
| `prefix-set` | a prefix-set or prefix dataset name | `route.prefix in pfx` |
| `community-set` | a community-set or community dataset name | `route.communities in tags` (and the large/extended lists, and `route.any-community in tags`), `<binding> in tags`, and `remove community in tags` / `not in tags` and `remove any-community in tags` (a community-set argument gets the member checks a named set gets; a dataset argument is read at runtime, as in [Removing by set membership](#removing-by-set-membership)) |
| `asn-set` | an asn-set or ASN dataset name | `route.origin-as in origins`, `peer.asn in origins`, `<binding> in origins` |
| `community` | a standard community, `65000:100` or a well-known name such as `NO_EXPORT` | `route.communities has tag`, `add community tag`, `remove community tag`, `tag in tags`, and as a community value (`let t = tag`, `c == tag`) |
| `ip` | an IPv4 or IPv6 address | `set next-hop nh`, `route.next-hop == nh`, `peer.address == nh` |

Arguments are written the same way everywhere a policy is instantiated:
in `apply(p(...))`, in a test `expect p(...)`, and in a configured chain
reference such as `"customer-in(200, cust-65001, 65000:100, 192.0.2.1)"`.
Inside `apply`, a caller's own parameter of the same type passes through
(`apply(member(pfx))`). Each argument is checked against the parameter's
type: a set argument must name a set or dataset of that kind in the
compilation unit, and a parameter used as a `prepend` count or a
`set next-hop` operand has its argument range-checked at instantiation
(1–255 for the count, a usable unicast address for the next hop), the
same checks a literal gets at compile time. In a test the check runs at
`rbgp policy check`; in a configured chain, at load, so `rustbgpd --check`
and a SIGHUP reload reject a bad argument without runtime effect.

A set parameter cannot share a name with a set or dataset, and it is
not a loop source: a loop's bound is its set's size at compile time.

**Reserved names.** Some names already have a fixed meaning in the
positions a parameter could fill, so no parameter can take them:
- a well-known community name: `NO_EXPORT`, `NO_ADVERTISE`,
  `NO_EXPORT_SUBCONFED`, `BLACKHOLE`, `GRACEFUL_SHUTDOWN`, `OV_VALID`,
  `OV_NOT_FOUND`, `OV_INVALID`;
- an enum value of `route.rpki`, `route.aspa`, `route.route-type` or
  `route.family` (`valid`, `internal`, `ipv4-unicast`, …);
- the `prepend as` operands `origin` and `path-first`.

A `let` binding, `for` variable, function parameter, set or dataset cannot
take a well-known community name either. This includes `let` bindings inside
functions and nested blocks. Reservation is case-sensitive; names such as
`no_export` and `NO_EXPORT_COUNT` remain available.

The RFC-assigned names `NOPEER`, `ACCEPT_OWN`, `LLGR_STALE`, `NO_LLGR` and
`STANDBY_PE` are reserved in all these positions, including policy
parameters, for future literal support. They are not community literals
yet; use their numeric community values. These spellings follow the
uppercase underscore convention for the
[IANA well-known community registry](https://www.iana.org/assignments/bgp-well-known-communities/).

A `let` binding still shadows a parameter of the same name in value
positions and in `add`/`remove community`.

## Expressions

Boolean operators, loosest to tightest: `||`, `&&`, `!`. Parentheses
group. Comparisons: `==`, `!=`, `>=`, `<=`.

| Predicate | Meaning |
|---|---|
| `route.prefix == 10.0.0.0/24` | exact prefix (same network *and* length) |
| `route.prefix in customers` | prefix-set membership (mask + ge/le ranges) |
| `route.communities has 65000:100` | route carries this community (kind-checked against the field) |
| `route.communities in tagged` | a standard route community matches a standard set member (`route.large-communities` and `route.ext-communities` likewise; a set member of another kind is a compile error) |
| `route.any-community in tagged` | a route community of any kind matches a set member of its kind; for sets that mix kinds |
| `route.as-path.len >= 3` | AS-path ASN count (RFC 4271 counting) |
| `route.communities.len >= 100` | number of standard communities on the route (`route.large-communities.len` and `route.ext-communities.len` likewise; 0 when the attribute is absent); route-context-only, so it never disqualifies update-group sharing |
| `route.as-path contains 65001` | boundary-anchored ASN presence (sugar for `matches "_65001_"`) |
| `route.as-path matches "^65010"` | Cisco/Quagga-style regex; `_` is a boundary anchor |
| `route.origin-as == 64500` | origin AS — the last ASN of the rightmost non-empty `AS_SEQUENCE` (`==`/`!=` only) |
| `route.origin-as in customers` | asn-set membership (one hash probe) |
| `peer.asn in customers` | evaluation-peer ASN against the same asn-sets |
| `route.local-pref >= 200`, `route.med <= 50` | u32 comparisons; `==`/`!=` also allowed |
| `route.med + 50 >= threshold`, `route.as-path.len * 10 >= route.med` | saturating-arithmetic comparison (see "Saturating u32 value expressions"); a missing operand makes it false |
| `exists route.origin-as` | the route carries the value; also `peer.asn`, `route.med`, `route.local-pref` and `route.next-hop` (see "Conditions never fail") |
| `route.next-hop == 10.0.0.1` | next-hop equality (`==`/`!=` only) |
| `route.next-hop == peer.address` | strict next-hop — the one field-vs-field comparison; reads peer identity, so an export chain using it makes the peer ineligible for update-group sharing (`policy_peer_context`) |
| `route.rpki == invalid` | RPKI origin validation state |
| `route.aspa == unknown` | ASPA verification state |
| `route.route-type == external` | route source class |
| `route.evpn-route-type == 2` | EVPN route type (integer literal 1–6, RFC 7432 §7 / RFC 9136 / RFC 9251; `==`/`!=` only) |
| `route.family == ipv4-unicast` | typed AFI/SAFI route family (`==`/`!=` only); route-context-only, so it never disqualifies update-group sharing |
| `peer.address == 192.0.2.1` | evaluation-peer address |
| `peer.asn == 65010` | evaluation-peer ASN (`==`/`!=` only) |
| `peer.group == "leaf"` | evaluation-peer group name |
| `apply(other-policy)` / `apply(p(42))` | policy-as-predicate (below) |

**Implicit defaults** (identical to the TOML engine and RFC 4271):
comparisons against `route.local-pref` see **100** when the attribute
is absent, `route.med` sees **0**. Prefix predicates never match a
prefixless route (e.g. BGP-LS NLRIs); `route.next-hop`,
`route.route-type`, `route.evpn-route-type`, and `route.family` never
match when the corresponding attribute is absent. `route.origin-as` is
absent on empty and `AS_SET`-only paths and then matches neither `==`
nor `!=` nor `in` (`!(... in ...)` negates plainly, matching the
prefix-set precedent).

For plain comparisons on optional attributes, `!=` and explicit Boolean
negation are different. With an optional field `x` and a literal `y`:

| Field state | `x == y` | `x != y` | `!(x == y)` |
|---|---|---|---|
| Present, equal | true | false | false |
| Present, different | false | true | true |
| Absent, without an implicit default | false | false | true |

For example, an ungrouped peer matches `!(peer.group == "leaf")`, but
does not match `peer.group != "leaf"`. Include fixtures with omitted
attributes when testing guards over optional fields. `route.local-pref`
and `route.med` use their implicit defaults, so they do not have the
absent-field behavior in the last row.

`rbgp policy check` reports `optional-field-negation` for a negated test
that is false on a route without the value, so the negation matches that
route: `!(optional-field == literal)`, and for `route.origin-as` and
`peer.asn` also a comparison against a binding or parameter with any
operator, any computed comparison such as
`!(route.origin-as >= 64512)`, and a `let` binding
of such a value compared or probed (`let o = route.origin-as;` then
`!(o == 64500)` or `!(o in bogons)`). It points at the negated expression,
including inside compound guards and loops. Use `!=` for an equality when
absence must not match, test `exists` where the field supports it, or keep
the negation and test an absent-field fixture when it is intentional. The
lint does not flag defaulted `route.local-pref` or `route.med`, total fields
such as `route.rpki`, or field-to-field comparisons.

### Saturating u32 value expressions

u32 value positions — either side of a u32 comparison, and the
`set local-pref` / `set med` arguments — accept **value expressions**
(ADR-0103): arithmetic over integer literals, parameters,
`let` bindings (below), u32-typed fields (`route.local-pref`,
`route.med`, `route.as-path.len`, the three community counts such as
`route.communities.len`), and three bounded builtins. An ASN
(`route.origin-as`, `peer.asn`) is no arithmetic operand: it compares,
orders against an integer, probes an asn-set, and may be set as a whole
value; an ASN or a community in arithmetic, a builtin or a function
argument is a compile error. A comparison's left side may also carry
arithmetic when it starts with a field or a binding.

```rpol
set med route.med + 50
set local-pref min(route.local-pref * 2, 400)
if route.as-path.len * 10 >= route.med { reject }
if route.med >= threshold + 20 { set local-pref 90 }
```

- **Operators**: `+ - * / %`, with `* / %` binding tighter than
  `+ -`, and both tighter than comparisons. Parentheses group inside
  value positions (a `(` at the *start* of an `if` condition opens a
  boolean group, so lead with the field: `route.med + 2 * 3 >= n`,
  or put the parenthesized arithmetic on the right).
- **Whitespace disambiguates `-`**: identifiers are kebab-case with
  permanent maximal munch, so `route.med - 1` is subtraction and
  `route.med-1` is an unknown-field error.
- **Builtins**: `min(a, b)`, `max(a, b)`, `clamp(x, lo, hi)`.
  `clamp(x, lo, hi)` is `min(max(x, lo), hi)`, so it never fails;
  literal-only inverted bounds (`clamp(x, 10, 2)`) are a compile error,
  as a typo.
- **Arithmetic saturates.** `+`, `-` and `*` saturate per operation at 0
  and 4294967295 in every value position — comparisons, `let` and
  `set` — and never wrap, trap or fail: `set med route.med - 10` on a
  route with MED 4 sets 0, and `route.med - 100 <= 5` matches every MED
  below 100. There is no per-field ceiling.
- **Divisors cannot be zero.** The divisor of `/` or `%` must be a
  non-zero constant, or `max(e, k)` with a constant `k >= 1`; anything
  else is a compile error. Bound a variable divisor explicitly:
  `route.med / max(route.as-path.len, 1)`.
- **Constant folding.** Constant subexpressions fold at compile time:
  `set med 25 + 25` compiles to exactly what `set med 50` does. A
  literal-only expression that leaves u32 (`4294967295 + 1`, `5 - 10`)
  can only be a typo and is a compile error at its source span; an
  expression with a parameter folds with saturation, so an argument
  value never decides whether a policy loads.
- **The top of the range.** RFC 4451 notes that some implementations
  treat MED 4294967295 as "infinity" and ignore or rewrite it. Saturation
  can produce that value, so where a peer must not see it, cap one below
  it: `set med min(route.med + 50, 4294967294)`.

### Conditions never fail

**A condition never fails: a comparison or probe whose operand is missing
or cannot be computed is false, and only an action that needs a value it
cannot compute denies the route.** A missing operand is `route.origin-as`
on an empty or `AS_SET`-only path or an unknown `peer.asn`. Arithmetic
saturates, divisors are never zero and `clamp` is total, so a value that
cannot be computed is one built from a missing operand.
`route.local-pref` and `route.med` read their implicit defaults (100 / 0)
when absent, consistent with comparisons. Every form of a comparison
agrees: `route.origin-as == 64500`, `route.origin-as == (64500)`,
`route.origin-as >= 64500` and `route.origin-as == x` with a `let`
binding are all false on an origin-less route, and match neither `==` nor
`!=` there. `&&`, `||` and `!` therefore combine plain true and false
values: an operand's evaluation order never changes a verdict, and `!`
follows the truth table above (`!(route.origin-as >= 64512)` is true on
an origin-less route).

**Rejecting when a value is missing.** Say so with `exists`, which tests
whether the route carries the value (`route.origin-as`, `peer.asn`,
`route.med`, `route.local-pref`, `route.next-hop`):

```rpol
policy block-64500 {
    term no-origin { if !exists route.origin-as { reject } }
    term blocked { if route.origin-as == 64500 { reject } }
    term rest { accept }
}

test as-set-only-is-rejected {
    route { prefix 192.0.2.0/24; as-path "{64500 64501}" }
    expect block-64500 == reject
}

test others-are-accepted {
    route { prefix 192.0.2.0/24; as-path "65010 64501" }
    expect block-64500 == accept
}
```

Without the `no-origin` term the `AS_SET`-only route is accepted, because
`route.origin-as == 64500` is false on it. `exists route.med` and
`exists route.local-pref` are the only way to tell an absent attribute from
its default.

**Actions fail closed (the evaluation-error contract).** A computed `set`
value, a computed prepend operand or a community binding that cannot be
computed denies the route: staged modifications are discarded,
`bgp_policy_eval_errors_total{direction, kind}` and the chain's eval-error
counter increment (the latter with the failing policy/term retained,
surfaced by `rbgp policy stats`), a rate-limited WARN names the failing
policy and term, and explain traces render the error in place of a
verdict. Test errors with `expect … == error KIND`; a plain `reject`
expectation does not count an evaluation error as a pass.

**Update-group note.** `peer.asn` as an operand (guard or computed
`set` value) reads peer identity and keeps its peers out of shared
update groups; arithmetic over route fields alone never disqualifies
grouping.

Migration example — BIRD's arithmetic filters are the natural
comparison. A BIRD MED-dampening filter:

```text
filter pad_med {
    if bgp_med + 50 > 1000 then reject;
    bgp_med = bgp_med + 50;
    bgp_local_pref = bgp_local_pref * 2;
    accept;
}
```

becomes:

```rpol
policy pad-med {
    term dampen { if route.med + 50 >= 1001 { reject } }
    term pad {
        set med route.med + 50;
        set local-pref min(route.local-pref * 2, 400);
        accept
    }
}
```

The difference under the syntax: BIRD's integer arithmetic evaluates
in a general-purpose interpreter, and an out-of-range result is
whatever the interpreter does that day; `.rpol` arithmetic is saturating
u32, so an out-of-range result sticks at 0 or 4294967295, and the `min`
cap keeps the local-pref doubling at 400.

### Bindings — `let`

`let <name> = <value expression>` names a value in statement position
— a term body, or an `if`/`else` body (ADR-0103). The binding takes its
initializer's type: `let origin = route.origin-as` is an ASN, `let x = c`
in a `route.communities` loop is a community, and anything else is a u32,
so a typed value is never laundered through a u32:

```rpol
policy dampen {
    term score {
        let origin = route.origin-as
        let penalty = route.as-path.len * 10
        if penalty >= route.med { reject }
        if origin == 64500 { set med penalty; accept }
    }
    term rest { accept }
}
```

`let` is a contextual identifier, not a reserved word: statement
position admits no other bare identifier, so sets, policies, and
parameters named `let` keep working.

**Immutable and typed.** There is no assignment, no `var`, and no
mutation: a binding's value is fixed by its initializer for the rest
of its scope. The initializer is a value expression, and the binding
takes its type: a u32 (integer literals, u32 parameters, arithmetic,
and the u32 fields `route.local-pref`, `route.med`,
`route.as-path.len` and the community counts), an ASN
(`route.origin-as`, `peer.asn`, or another ASN binding), or a standard
community (a literal such as `65000:1`, a `community` parameter, or a
communities-loop variable). A typed value keeps its type through any
number of bindings. Binding a field that is none of these is a compile
error naming the value fields.

**Scope and shadowing (normative).**

- A term body is a scope; each `if`/`else` body is a nested scope.
  A binding is visible from its statement to the end of its scope —
  a term-body binding reaches into later `if` bodies of the same
  term; a body binding is invisible outside its body. Bindings never
  cross terms, and never escape the policy (no globals, no
  cross-route state, no closures — the purity contract).
- A `let` may shadow an earlier binding, including one in the same
  scope, and a policy parameter: the **innermost declaration wins**
  at each use. The initializer is resolved *before* its own name is
  declared, so `let x = x + 1` reads the outer `x` — shadowing, never
  self-reference.
- Resolution is **position-typed**: bindings are readable only in
  value positions. Enum
  members (`valid`, `internal`, …) still win in enum comparisons,
  `min`/`max`/`clamp` followed by `(` are still builtin calls, and
  `prepend as origin` still means the origin operand even with a
  `let origin` in scope. Compile-time-constant positions (`apply`
  arguments, prepend operands/counts, `contains`) reject bindings
  with a dedicated diagnostic — they are runtime values.
- **Use before definition is a compile error** at the use's span, as
  is any unknown name (with did-you-mean suggestions over parameters
  and visible bindings).

**Evaluation is eager.** The initializer evaluates when its statement
executes — reached in the term walk, branch taken — whether or not the
value is ever read. An initializer that is missing or cannot be computed
(an absent `route.origin-as` or `peer.asn`) binds that state instead of
a value: a condition
that reads the binding is false, and an action that needs it (`set med x`,
`add community x`) denies the route with the original error kind (see
"Conditions never fail"). Explain notes the binding as having no value. A
statement position the walk never reaches (an earlier verdict decided, the
branch not taken) never evaluates.

**Reads see the original route — never staged writes.** Route
mutation stays transactional: `set`/`add`/`remove`/`prepend` stage
modifications applied only after a complete successful evaluation, so
`set med 500` followed by `let x = route.med` binds the route's MED
*as it arrived*, not 500. Read-back of staged writes is deliberately
out of scope (it would break the memoization contract — `ExportMemo`
keys on source attributes plus modifications — and needs its own ADR
if ever demanded).

**Static slots, zero allocation.** Bindings compile to fixed slots in
a 256-slot register file (term, nested loop, and `if` scopes at the
64-binding per-scope cap; inlined function calls draw on the same
frame): slot assignment is a pure function of the source
(identical source → identical compiled form, so unchanged reloads
still diff as no-ops), sibling scopes reuse slots, and the frame is a
lazily-materialized stack array — policies without bindings pay
nothing, and no evaluation ever heap-allocates for bindings. The
**65th `let` in one scope is a compile error** at its span. The cost
DP charges each binding its initializer cost plus one slot step; each
read costs one step, so factoring a repeated subexpression through a
`let` is never more expensive than inlining it (and evaluates
identically — pinned by test).

**`apply` restriction.** A policy that declares `let` bindings cannot
be a target of `apply` this slice: `apply` inlines its target as a
pure predicate expression, which has no term walk to execute bindings
in. The compile error points at the offending `apply` and the target's
first `let`; factor the shared value into the applying policy, or use
a user function (`fn`) — the designed vehicle for composing
computed values.

Migration example — factoring a repeated computed value:

```rpol
# Before: the padded MED is computed twice and must be kept in sync.
policy pad-med-inline {
    term dampen { if route.med + 50 >= 1001 { reject } }
    term pad { set med route.med + 50; accept }
}

# After: one binding, one place to change the padding.
policy pad-med {
    term pad {
        let padded = route.med + 50
        if padded >= 1001 { reject }
        set med padded
        accept
    }
}
```

**Update-group note.** A binding whose initializer reads `peer.asn`
reads peer identity — even if the value is never used, an unknown
peer ASN already denies — so it keeps its peers out of shared update
groups, exactly like a `peer.asn` guard operand. Bindings over route
fields alone never disqualify grouping.

### Loops — `for`

`for <var> in <source> { ... }` walks a finite collection, binding
each element to an immutable loop variable — a fresh binding per
iteration, scoped to the body (ADR-0103 Decision 3). The source types
the variable: an ASN from `route.as-path` or an asn-set, a standard
community from `route.communities`:

```rpol
community-set scrub { 65000:100, 65000:200 }
asn-set bogon-asns { 64512, 65535 }

policy route-server-in {
    term scrub-communities {
        for c in route.communities {
            if c in scrub { remove community c }
        }
    }
    term bogon-path-guard {
        for asn in route.as-path {
            if asn in bogon-asns { reject }
        }
        accept
    }
}
```

`for`, `break`, and `continue` are contextual identifiers like `let`
(statement position admits no other bare identifier), so existing
names keep working. There is **no `while`** — every loop's source is
finite by construction, which is what keeps every bound provable or
runtime-meterable.

**Iteration sources — exactly three forms.**

- `route.communities` — the route's **standard** (RFC 1997)
  communities, in attribute order, as community values: compare one
  with a community literal (`if c == 65000:100 { ... }`), probe a
  community-set, or add or remove it. `route.large-communities` and
  `route.ext-communities` do not iterate (probe them with `has`/`in`);
  community-sets do not iterate either (mixed-kind members).
- `route.as-path` — every ASN in wire order: segments in order, ASNs
  within each segment in stored order, **prepend duplicates included**.
  `AS_SET` members are yielded individually in received order (note
  the asymmetry with `route.as-path.len`, which counts a whole set as
  1 per RFC 4271 §9.1.2.2). A route without an `AS_PATH` iterates zero
  times.
- A named `asn-set` — members in canonical order (sorted, deduplicated
  — the interned representation), so iteration order is deterministic
  across compiles and insertion orders. Sets larger than the 4,096
  per-loop bound are rejected at compile time (probe those with `in`).

**The loop variable in guards and actions.** It resolves like any
`let` binding, by type. An ASN compares and orders against integers and
probes an asn-set (`asn in bogon-asns` above). A community compares with
another community (`c == 65000:1`, never `c == 4259840001`), probes a
community-set whose members are all standard (`c in scrub` above; a member of another kind is a compile
error), and is staged per execution by `add community <var>` /
`remove community <var>`: the scrub-loop idiom. An ASN never probes a
community-set and a community never probes an asn-set: that is how
`0:64500` used to match ASN 64500. A u32 probes only an asn-set, and only
as a constant (a literal `let` or a u32 parameter). A community action
also takes a constant u32 standing for the community with that value. A loop removal is
explicit, so it removes well-known values such as `NO_EXPORT` too, unlike
`remove community *`. Shadowing follows
the `let` rules — the loop variable shadows outer bindings, a body
`let` may shadow it.

**`break`, `continue`, verdicts.** `break` exits the innermost loop
(the walk continues after it); `continue` skips to the next iteration.
Staged modifications before either still apply — they are control, not
verdicts. `accept`/`reject` inside the body terminate the whole policy
at that iteration, exactly as in an `if` body; staged modifications
from earlier iterations merge under an `accept` and are discarded by a
`reject`, the ordinary rules.

**Iterated collections cannot change mid-loop.** Conditions and loop
sources always read the route as it arrived — staged modifications are
never read back there (ADR-0103 Decision 2); only a community scan consults
the staged additions it cancels — so `add community` inside a
`for c in route.communities` body cannot extend its own iteration
(pinned by test).

**Bounds and fuel (ADR-0103 Decision 3).** Compilation, chain attachment,
and evaluation enforce the following bounds:

- **1,000,000 structural IR nodes per chain** (`MAX_CHAIN_NODES`). Named
  chains and finalized effective import/export chains share this cap across
  `.rpol`, TOML, legacy inline policies, and implicit GSHUT/BLACKHOLE tails.
  Each policy, lowered term, action, guard, and value-expression node counts
  once; loop bodies count once regardless of iterations. Repeated policy
  references count each occurrence. Interned match-set contents and regex
  data do not count, and unused policy definitions are not summed together.
  `compile_rpol` applies the cap when composing all zero-parameter policies.
  Oversized startup, reload, and API candidates are rejected before installation;
  policy API requests return `INVALID_ARGUMENT`. Reload installs new policy
  definitions before later chain-reference edits, so that intermediate
  combination must also fit. If a change both grows definitions and shortens
  their chains, shorten the chains and reload first, then load the larger
  definitions. An oversized registry replacement preserves the installed
  registry and chains. This is a structural size
  bound, separate from per-policy evaluation cost and runtime loop fuel; it
  is not a universal CPU-time bound. The infallible Rust `PolicyChain` and
  `compile_chain` APIs retain their trusted, hand-built IR boundary; embedding
  callers can check `compile::ChainNodeBudget` before accepting external input.

- **4,096 iterations per loop** (`MAX_LOOP_ITERATIONS`). Set sources
  are checked at compile time. Route-attribute sources are checked at
  runtime — a peer-supplied route with more elements than the cap
  (possible with RFC 8654 extended messages) is an **evaluation
  error** at the 4,097th element: uniform Deny, counter, rate-limited
  log — cap-then-error, never silent truncation.
- **Nesting ≤ 4 loops**, and the DP charges each loop at its static
  bound × per-iteration body cost — multiplicatively for nests — so a
  loop over one route attribute nested in a loop over another
  (4,096 × 4,096 steps) is rejected at compile time against the
  1,000,000-step worst-case budget (`MAX_EVAL_COST`), not metered per
  route. Nest small set loops, or restructure with membership probes.
- **At most 255 prepended ASNs per route** (`MAX_PREPEND_ASNS`, one wire
  `AS_SEQUENCE` segment). The bound is the largest total any path through
  the policy can reach: prepends add up along a path in term order and an
  `accept` ends one, so branches or terms that each prepend and accept
  count one at a time; `if` branches that fall through add up together,
  as if every guard matched; and a prepend inside a loop counts once per
  iteration of the loop's bound, an asn-set's member count or 4,096 for a
  route attribute, so a loop over a route attribute cannot prepend. The
  typechecker checks it with a parameter count at its smallest value, 1;
  instantiation rechecks with the argument, and chain attachment (and a
  test's `expect chain`) adds the members' bounds. A chain composed
  without these checks fails a route closed above 255
  (`prepend-limit-exceeded`).
- **Runtime fuel.** Every evaluation starts with `MAX_EVAL_COST` fuel,
  decremented at loop iteration steps and for the staged community
  entries that work traverses: a community scan pays one step per staged
  addition and removal of its kind, and merging a community action into
  the staged modifications pays one step per staged entry of the opposite
  operation it checks for cancellation. Staged entries have no
  compile-time bound — loops stage one per iteration and chain members
  carry them forward — so this is the work the compile-time bound cannot
  pre-pay. Other straight-line code is pre-paid, so a chain with no loops
  pays only for the few staged entries its community actions traverse.
  The trade-off is quadratic staging: a policy that loops removals over
  the route's n communities and then loops re-adding them pays roughly
  n²/2 steps, so it fails closed above about 1,400 communities.
  Exhaustion — reachable only by compounding data-dependent iteration or
  staging — is an evaluation error on the same uniform-Deny rail
  (`fuel-exhausted` in the error counters and explain traces).

**Explain.** Traces render a bounded loop summary — iteration count
plus the deciding iteration (`loop reject at iteration 3 of 3`), never
per-iteration lines. Hit counters count the loop's term once per walk;
body terms are inside the loop node and carry no counter rows.

**`apply` restriction.** Like `let`, a policy containing `for` cannot
be an `apply` target — `apply` inlines a pure predicate, which has no
walk to run iterations in.

**Update-group note.** Iterating `route.communities` / `route.as-path`
/ a set reads no peer identity and never disqualifies update-group
sharing; a `peer.*` read *inside* a loop body counts exactly as it
would outside.

Migration example — an FRR/BIRD-style AS-path bogon check without a
regex:

```rpol
# Before: anchored regex over the rendered path string.
policy bogon-guard-regex {
    term walk { if route.as-path matches "_(64512|65535)_" { reject } accept }
}

# After: typed iteration + one hash probe per ASN; the set is
# maintainable data, not pattern syntax.
asn-set bogon-asns { 64512, 65535 }
policy bogon-guard {
    term walk {
        for asn in route.as-path {
            if asn in bogon-asns { reject }
        }
        accept
    }
}
```

### Functions — `fn`

`fn NAME(param: u32, ...) -> u32 { ... }` names a pure computation
over `u32` values (ADR-0103 Decision 2):

```rpol
fn penalty(len: u32, weight: u32) -> u32 {
    let base = len * weight
    min(base, 1000)
}

policy p {
    term dampen { if penalty(route.as-path.len, 10) >= route.med { reject } }
    term rest { accept }
}
```

`fn` is a top-level contextual identifier like statement-`let`: top
level previously admitted no bare identifier, so existing names keep
working. Functions get their own namespace — duplicate `fn` names are
errors, but a set or policy may share a function's name (every
reference position is disjoint); the builtin names `min`/`max`/`clamp`
are reserved and cannot be shadowed.

**Bodies are expression-shaped.** A body is zero or more `let`
bindings followed by exactly **one result expression** — the
last-expression rule; there is no `return`. Verdicts, `set`/`add`/
`remove`/`prepend`, `if`, and `for` are policy-term territory and get
a typed diagnostic inside a body (`if` would need expression-`if`,
which does not exist in the language — `min`/`max`/`clamp` cover
selection; a later slice may revisit). Parameters and return values
are `u32` this slice, and the return type is spelled explicitly
(`-> u32`).

**Closed over nothing (normative).** A function body may not read
`route.*`/`peer.*` fields — every input arrives as a parameter, so a
function is a pure function of its arguments. This is what keeps the
hot-path analyses call-site-local: `penalty(peer.asn, 10)` counts
toward `requires_peer_context` because the *argument* reads peer
identity; `penalty(route.as-path.len, 10)` never disqualifies
update-group sharing, no matter what the body does. The compile error
says to pass the field as an argument.

**No recursion.** The call graph must form a DAG — direct or mutual
recursion is a compile error naming the cycle, exactly like `apply`.
Call chains are depth-capped at 8 (`MAX_CALL_DEPTH`), enforced in the
same Kahn-ordered cost DP as the `apply` bounds.

**Full inlining (normative).** A call is compile-time sugar for a
scope of `let` bindings: each argument binds to a caller-frame slot
(named `fn.param` in explain surfaces), each body `let` to
`fn.binding`, and the result expression to a slot named by the
rendered call itself, which the call site reads. There are **no
runtime call frames** — evaluation walks the same flat term list as
before, and a program that never calls functions pays nothing.
Consequences:

- **Evaluation is eager, like `let`.** Arguments and the body evaluate
  when the walk reaches the statement containing the call — even if a
  `&&` short-circuit would have skipped the value. A body's arithmetic
  saturates and its divisors cannot be zero, so a call has no value only
  when an argument has none (an absent `route.origin-as` or `peer.asn`),
  like a `let`: a condition on it is false, and an action that needs it
  denies the route on the uniform eval-error rail.
- **Term identity survives.** The inlined binds become IR terms of the
  *calling* statement, named like any statement that lowers to several
  terms (`<term>[.<statement>].<k>`, the statement omitted in a
  one-statement term, and one row of the final statement bare), so the
  counter grid and trace skeleton
  stay a function of the source; per-function hit counting is explicitly out of scope
  (Decision 6.3 — it would need runtime call frames).
- **Attribution names both sides.** A body's bindings render with the
  calling term's name and the qualified binding, e.g.
  `term compute.3: let share.each = share.total / max(share.parts, 1)`,
  and an action that needs a call without a value fails closed on the
  calling term, e.g.
  `term compute.4: evaluation error: `route.origin-as` has no value for this route — fail closed => reject`.
  Guards render calls source-level:
  `penalty(route.as-path.len, 10) >= route.med`.
- **Budgets compound honestly.** The cost DP charges the fully-inlined
  body per call site, against the same `MAX_APPLY_EXPANSION` /
  `MAX_EVAL_COST` budgets as `apply` — a big body called from many
  sites is rejected at compile time. Inlined bodies also consume
  caller-frame binding slots (arguments + body lets + the result, per
  call site); a term whose calls exceed the 256-slot frame is a
  compile error at the term's span.

**Calling parity.** `penalty(a, b)` evaluates exactly like writing the
body inline — same verdicts, same modifications, zero fuel (calls are
straight-line code; only loop iterations meter) — pinned by test.

**`apply` restriction.** Like `let` and `for`, a policy that calls
functions cannot be an `apply` target: calls lower to binding terms a
pure inlined predicate cannot execute. Call the function in the
applying policy instead.

Migration example — factoring a computation repeated across policies
(the step beyond a single-policy `let`):

```rpol
# Before: the damping formula is duplicated — and must be kept in
# sync — across two policies.
policy transit-in {
    term dampen { if min(route.as-path.len * 10, 1000) >= route.med { reject } }
    term rest { accept }
}
policy peer-in {
    term dampen { if min(route.as-path.len * 12, 1000) >= route.med { reject } }
    term rest { accept }
}

# After: one definition, weights at the call sites.
fn penalty(len: u32, weight: u32) -> u32 {
    let base = len * weight
    min(base, 1000)
}
policy transit-in {
    term dampen { if penalty(route.as-path.len, 10) >= route.med { reject } }
    term rest { accept }
}
policy peer-in {
    term dampen { if penalty(route.as-path.len, 12) >= route.med { reject } }
    term rest { accept }
}
```

### Route-family branching

`route.family` is the route's **typed** AFI/SAFI family, carried by the
evaluation context itself — never inferred from the shape of the
route's prefix (BGP-LS and RTC NLRIs have no prefix at all; a FlowSpec
rule's destination component is not its family). It lets one chain
attached to several families branch per family instead of being split
into near-identical per-family policies.

Migration example — before, two chains that differ only in one guard:

```rpol
policy edge-v4 { term dampen { if route.med >= 500 { reject } } term rest { accept } }
policy edge-v6 { term dampen { if route.med >= 800 { reject } } term rest { accept } }
```

after, one chain attached to both families:

```rpol
policy edge {
    term dampen-v4 { if route.family == ipv4-unicast && route.med >= 500 { reject } }
    term dampen-v6 { if route.family == ipv6-unicast && route.med >= 800 { reject } }
    term rest { accept }
}
```

Family predicates read no peer identity, so unlike `peer.*` or strict
next-hop they never push an export peer onto the ungrouped
`policy_peer_context` path — peers sharing the chain still share one
update group.

### `apply` — policy as predicate

`apply(p)` is a **boolean**: "would policy `p` permit this route?".
The applied policy's actions do *not* execute — this is a predicate,
not a Junos-style subroutine call with side effects. The compiler
inlines `p`'s first-match decision structure as a pure guard
expression; `Continue`-style modify-and-fallthrough terms in `p`
don't decide anything and are skipped.

Two consequences worth internalizing:

- Policy composition must form a **DAG** — recursion through `apply`
  (including self-application) is a compile error naming the cycle.
- With an accepting default, a policy that never `reject`s is
  constant-true under `apply`. Predicate policies should decide both
  ways: use `default-action reject` with guarded `accept` terms, or
  retain a final rejecting term (as in `bogon-filter` above).
- A policy that declares `let` bindings cannot be applied:
  the inlined predicate has no term walk to execute bindings in. The
  compile error names the target's first `let`. The same rule covers
  `for` loops and function calls (a call is sugar
  for a scope of lets).
- A policy that holds an `apply` **statement**, anywhere in its terms,
  cannot be applied either. A predicate must not have side effects: it
  only asks whether a policy would permit the route, and a called
  policy's writes would be a side effect. The compile error names the
  first `apply` statement. The called policy itself stays a valid
  predicate target.

### `apply` as a statement — calling a policy

`apply NAME` or `apply NAME(args)` in statement position runs another
policy's terms in place, as IOS-XR RPL's `apply` pastes a child policy
into its parent (ADR-0096, amendment of 2026-11-01). `apply(NAME)`, with
parentheses, stays the predicate above; written as a statement it is a
compile error that says which form to use.

```rpol
community-set scrub-tags { 65000:666 }

policy customer-common(lp: u32) {
    term bad { if route.as-path.len >= 5 { reject } }
    term tag { remove community in scrub-tags; set local-pref lp }
}

policy customer-in {
    term common { apply customer-common(200) }
    term done { accept }
}

test long-path-is-dropped {
    route { prefix 192.0.2.0/24; as-path "64500 64501 64502 64503 64504" }
    expect customer-in == reject
}

test customer-route-is-scrubbed {
    route { prefix 192.0.2.0/24; communities [65000:666, 65000:1] }
    expect customer-in == accept with local-pref 200, removes community 65000:666,
        not removed community 65000:1
}
```

- **The called policy's `reject` denies the route**, from any depth, and
  its staged writes are discarded as with any rejection.
- **Its `accept` returns to the caller.** No later term of the called
  policy runs, its writes are kept, and evaluation continues with the
  caller's next statement and later terms. An `accept` in a called policy
  never permits the route on its own.
- **Falling off its end applies its `default-action`**: `accept`, or no
  declaration, returns; `default-action reject` denies. A policy means the
  same thing when called, as a chain member and under its own tests.
- **Writes stage into the caller in order.** A later scalar write wins, and
  for a community value the later operation wins, whether the caller's or
  the called policy's (statement order, as across terms). Prepends add up
  in the same order, and the prepend cap counts a called policy's prepends
  with the call's arguments. **Every condition reads
  the route as received**, in the called policy and in the caller after
  the call, as everywhere else in the language.
- **`else if` first-match is unchanged.** A branch whose body calls a
  policy can fall through, so later branches keep its negation. After the
  called policy returns, evaluation continues after the whole `if`.
- **Where it goes.** A call is allowed in a term body, an `if` body and a
  `for` body; in a loop it runs once per iteration. The called policy may
  hold `let`, `for`, function calls, `accept` inside its loops, and its own
  `apply` statements.
- **Arguments** are checked against the called policy's parameters like any
  other reference, and range-checked against every use they reach. An
  argument is fixed at compile time, so it cannot be a `let` binding; a
  `let` that shadows a parameter makes that name the binding, in a call
  and in `apply(...)` alike.
- **Composition bounds.** Calls and `apply(...)` predicates are edges of one
  graph: a cycle through either is a compile error, and both count toward
  the eight-level depth limit and the inline size budget.

**Lowering.** A call adds no IR node kind. The called policy lowers on its
own, monomorphized with the call's arguments, with its frame slots above
the caller's live slots and one return-flag slot. The call emits a `Bind`
clearing the flag, then each called term behind "flag is clear". An
`accept` becomes a flag `Bind` and a `Continue` of its modifications behind
"flag is that term". Inside a loop body it also leaves the loop, and an
enclosing loop leaves too when the flag is set. A `default-action reject`
adds a final `Deny` behind "flag is clear". No guard of the called policy is
evaluated again after its own term, so per-route work stays linear in the
called policy's size.

**Cost.** Each call site is charged the called policy's IR nodes and
evaluation steps, plus the call-site path and the flag check on every
inlined term, plus the entry, return and fall-through terms. A
parameterized policy is charged per call, because each call instantiates
it. The caller's frame must hold its live bindings, the flag and the called
policy's frame.

**Names.** Inlined terms are named under the call statement, as the
[lowering](#lowering-into-the-ir-normative) names any statement that lowers
to several IR terms: `<term>[.<statement>].<k>/<call>:<called-term>`, for
example `common.3/customer-common(200):tag.1`, and a final call's last row
takes the bare term name, `common/customer-common(200):tag`.
Nested calls compose, and the flag's own terms are named `:#enter`,
`:#return` and `:#default` (`#` cannot begin a term name, so no source term
can collide with them). A `:#return` term follows each called loop that
can return, so a return from inside a loop is visible too. Explain traces, `rbgp policy test` term hits and
`rbgp policy stats` show these names, and in-language test coverage credits
the called policy's source terms. A call inside a `for` body is attributed
to the loop term, like any loop body.

## Actions

| Action | Effect |
|---|---|
| `accept` / `reject` | terminal verdict (see evaluation order) |
| `set local-pref <u32 \| value-expr>` | override `LOCAL_PREF`, e.g. `set local-pref min(route.local-pref * 2, 400)` |
| `set med <u32 \| value-expr>` | override `MED`, e.g. `set med route.med + 50` |
| `set next-hop <ip>` / `set next-hop self` | override `NEXT_HOP` (an unspecified or multicast address is a compile error); an IPv4 address does not apply to an IPv6 unicast route, and no next hop applies to a labeled-unicast or VPN route, where an export binding that can reach one is rejected ([details](configuration.md#route-modifications-set-actions)) |
| `add community 65001:999` / `remove community ...` | standard communities |
| `add large-community 65000:1:2` / `remove ...` | large communities |
| `remove large-community 65000:*:*` | every arrived large community with global administrator 65000 |
| `remove community *` / `remove large-community *:*:*` / `remove ext-community *` | every arrived community of that kind, except that `remove community *` keeps well-known communities (see below) |
| `remove community in scrub` / `remove community not in allow` | every arrived community of that kind that is (or, with `not in`, is not) a member of the community-set; `large-community` and `ext-community` likewise (see below) |
| `remove any-community in twins` | every arrived community, of any kind, that is a member of a set that mixes kinds (`in` only) |
| `add ext-community RT:65001:100` / `remove ...` | extended communities (RT/RO, or well-known: `add ext-community OV_INVALID`) |
| `prepend as <asn> <count>` | prepend `<count>` copies of `<asn>` (ASN: 1–4294967295; count: literal 1–255); prepends accumulate, each later one to the left, up to 255 ASNs per route (see below) |
| `prepend as self\|peer\|origin\|path-first <count>` | prepend a computed ASN (see below) |

Literal AS 0 is a compile error. A parameter that resolves to AS 0 in a
prepend action is rejected when the daemon attaches the policy chain,
including prepends inside loops. These checks reject invalid policy before
the daemon evaluates routes with it; a computed operand that evaluates to 0
denies the route, and the wire encoder also rejects AS 0 under RFC 7607.

The kind keyword must match the literal's kind (`add community
RT:...` is a compile error pointing at `add ext-community`).

**Actions apply in statement order,** within a term, across terms and
across the members of a chain: each chain member starts from the
modifications the earlier members staged. For a community value the later
operation wins: `add community X; remove community X` leaves X absent and
`remove community X; add community X` leaves it present. Later `set`s of the
same attribute win. Prepends accumulate: each prepend places its copies in
front of the path as it stands, so a later prepend's ASNs land to the left
of an earlier one's, as RPL `prepend as-path` does, and a computed operand
resolves where its prepend runs. Computed `set` values share their
attribute's slot with the literal form: a later `set` of either form
replaces an earlier one. A computed `set` value resolves
when the matched term's action executes — constant expressions have
already folded to literals at compile time, and expressions reading
route/peer fields evaluate per route (an evaluation error denies the
route; see "Value expressions").

The large-community wildcard is deliberately removal-only and accepts exactly
one decimal `u32` global administrator followed by `:*:*`, with no spaces or
prefix. It removes the arrived values with that administrator as concrete,
first-seen deduplicated removals, cancels the earlier staged additions with that
administrator (statement order), and preserves foreign administrators. An input
with more than 5,461
arrived large communities fails the route closed before scanning; the compiler
pre-pays that same conservative wire-derived bound.

The strip-all forms follow the same rules: removal-only, `*` for standard and
extended communities and `*:*:*` for large communities, concrete deduplicated
removals of the arrived values. In statement order they also cancel every
addition of the kind that an earlier statement or chain member staged, except a
well-known standard community: `add community NO_EXPORT; remove community *`
keeps `NO_EXPORT`. A later `add`, in the same policy or a later chain member,
stays. On a route without the attribute they remove nothing. Each fails the route closed above its
wire-derived bound (16,383 standard, 8,191 extended, 5,461 large communities),
and the compiler pre-pays that scan.

**`remove community *` keeps well-known communities.** Standard communities
in the range RFC 1997 reserves for well-known values, `65535:0` through
`65535:65535` (`NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`, `NOPEER`,
`BLACKHOLE`, `GRACEFUL_SHUTDOWN`, `ACCEPT_OWN`, `LLGR_STALE`, `NO_LLGR` and
the unassigned rest), stay on the route, as IOS-XR RPL `delete community
all` and `set community` without `additive` keep well-known communities.
Only the five names listed under literals have `.rpol` spellings; `NOPEER`,
`ACCEPT_OWN`, `LLGR_STALE` and `NO_LLGR` do not, so match or set them
numerically (`65535:65284`, `65535:1`, `65535:6` and `65535:7`). The
replace idiom therefore keeps a route's scoping:

```rpol
policy retag {
    term t {
        remove community *          # NO_EXPORT on the arrived route stays
        add community 65000:100
        accept
    }
}
```

Remove a well-known value by naming it: `remove community NO_EXPORT`, or
`remove community 65535:65284` for one without a name. To empty the attribute
entirely, including values with no name, remove each arrived value with a
loop, `for c in route.communities { remove community c }`, which is subject
to the loop's 4,096-element bound. Large and extended communities have no
well-known range: `remove large-community *:*:*` and `remove ext-community *`
remove every value.

### Removing by set membership

`remove <kind> in SET` removes every arrived community of the kind that is a
member of the community-set, exact or by [pattern](#community-patterns);
`remove <kind> not in SET` removes every arrived community of the kind that is
not. They are the RPL `delete community in` / `delete community not in`
forms, and they work for all three kinds:

```rpol
community-set scrub { 65000:666, 65000:1000..1999 }
community-set customer-tags { 65000:*:* }

policy customer-out {
    term scrub {
        remove community in scrub              # drop internal tags
        remove large-community not in customer-tags
        accept
    }
}

test scrubbed {
    route {
        prefix 192.0.2.0/24
        communities [65000:666, 65000:1500, 65000:100, NO_EXPORT]
        large-communities [65000:1:1, 64496:1:1]
    }
    expect customer-out == accept with only removes community 65000:666,
        removes community 65000:1500, removes large-community 64496:1:1,
        not removed community 65000:100, not removed community NO_EXPORT,
        not removed large-community 65000:1:1
}
```

- **Well-known communities.** A standard community in the RFC 1997
  well-known range is removed only by `in`, and only when the set names it
  as an exact member: `community-set kill { NO_EXPORT }` with
  `remove community in kill` strips `NO_EXPORT`. A pattern never names a
  well-known value, so `remove community in s` with `*:*` or `65535:*` in `s`
  keeps them, as `remove community *` does. `not in` never removes one, so an
  allow-list scrub (`remove community not in allow`) cannot strip
  `NO_EXPORT`. Large communities have no well-known range.
- **Extended communities with `not in`.** `remove ext-community not in SET`
  considers only route targets and route origins, in every encoding
  (2-octet AS, 4-octet AS, IPv4 administrator, transitive or not), and keeps
  every other extended community: BGP encapsulation (RFC 9012), color, EVPN
  types such as Router's MAC and ES-Import, link bandwidth, origin-validation
  state and opaque or experimental values. A set can name only RT, RO and
  origin-validation values, so without this rule an allow-list of route
  targets would strip the encapsulation, color and EVPN communities that EVPN
  reflection and SR-TE steering depend on. `remove ext-community in SET`
  removes whatever the set names, the origin-validation state included.
- **The set** must be a `community-set` whose members are all of the
  action's kind, with at least one: a member of another kind could never be
  removed, `in` with none would remove nothing and `not in` every value, and
  all three are compile errors. `remove any-community in SET` takes a set that
  mixes kinds and removes the members of every kind; it has no `not in` form,
  because an allow-list is per kind: split a mixed allow-list by kind and
  keep one `remove <kind> not in` per kind. For `ext-community not in` the
  set needs a route-target or route-origin member.
- **A community dataset** can be the set too: `remove community not in
  allowed-tags` with `dataset community-set allowed-tags`. The scan reads the
  snapshot pinned at walk start and, like a dataset probe, filters its
  members by kind at runtime, so none of the member checks above apply. The
  scan follows the current contents literally: an empty snapshot, or one with
  no member of the action's kind, removes nothing under `in` and every value
  of the kind under `not in`, except the well-known standard communities, and,
  for `ext-community not in`, every extended community that is not a route
  target or route origin. A snapshot with no route-target or route-origin
  member therefore strips every route target and route origin. Refresh
  validation is the guard: a dataset file that is missing, unreadable, too
  large or does not parse rejects the reload and keeps the prior snapshot,
  and an empty snapshot requires an explicitly empty file (see
  [Refresh, failure, and observability](#refresh-failure-and-observability)).
  A content swap reaches installed chains without recompiling them, and a
  dataset a removal reads is refreshed for every route, not only those whose
  prefix or origin AS the two snapshots answer differently.
- **Removal only, in statement order.** `add <kind> in` is a compile error.
  The scan stages concrete, deduplicated removals of the arrived values it
  selects, and cancels the earlier staged additions it selects by the same
  rule, including those of earlier chain members; values staged for removal
  by earlier actions are not staged again. As with the strip-all forms, a
  later `add` stays.
- **Cost.** One pass over the route's arrived values of the kind, bounded by
  the wire (16,383 standard, 8,191 extended, 5,461 large communities); a route
  carrying more fails closed before the scan. The compiler pre-pays one
  evaluation step per value, as for `remove community *`. Each step is one
  exact-member hash probe plus at most 64 pattern comparisons, so a set at
  the pattern limit costs up to about 1.05 million comparisons per route for
  one standard-community scan. The scan also visits the earlier staged
  additions and removals of its kind: it probes the additions the same way
  and skips values already staged for removal. Staged entries have no
  compile-time bound, so each costs one step of the evaluation's runtime
  budget, and a route that exhausts it fails closed on the evaluation-error
  rail.

### Routes that carry too many communities

The [NLNOG BGP filter guide](https://bgpfilterguide.nlnog.net/guides/many_communities/)
recommends stripping communities from routes that carry about 100 of them.
The counts are u32 fields, so the guide's summed form is one term:

```rpol
policy strip-many-communities {
    term too-many {
        if route.communities.len + route.large-communities.len + route.ext-communities.len >= 100 {
            remove community *; remove large-community *:*:*; remove ext-community *
        }
    }
    term rest { accept }
}
```

This is the guide's BIRD function:

```text
if ( ( bgp_community.len + bgp_ext_community.len + bgp_large_community.len ) >= 100 ) then {
    bgp_community.empty;
    bgp_ext_community.empty;
    bgp_large_community.empty;
}
```

OpenBGPD's `max-communities 100` matches a route with *more than* 100
values and checks each kind separately, so its three rules become one term
per kind:

```text
match from any max-communities 100 set { community delete *:* }
match from any max-ext-communities 100 set { ext-community delete * * }
match from any max-large-communities 100 set { large-community delete *:*:* }
```

```rpol
policy strip-many-communities {
    term standard { if route.communities.len >= 101 { remove community * } }
    term extended { if route.ext-communities.len >= 101 { remove ext-community * } }
    term large { if route.large-communities.len >= 101 { remove large-community *:*:* } }
    term rest { accept }
}
```

A route server passes communities through by default, so this is opt-in
ingress hygiene. Unlike BIRD's `.empty`, `remove community *` keeps
well-known values such as `NO_EXPORT`; use the loop form above if the scrub
must remove those too. Pin the threshold with fixtures on both sides of it and
`removes community *` (below).

### Computed prepend operands

`prepend as` also takes a computed operand instead of a literal ASN:

- **`self`** — the local speaker's ASN (the daemon's `[global] asn`,
  stamped onto the chain when it is attached; in-language tests state
  it with the `peer { local-as N }` fixture field).
- **`peer`** — the evaluation peer's ASN.
- **`origin`** — the route's origin AS: the last ASN of the rightmost
  non-empty `AS_SEQUENCE` (the same value `route.origin-as` reads).
  No parameter can be named `origin` (see "Parameters").
- **`path-first`** — the first ASN of a non-empty leading
  `AS_SEQUENCE` in the typed route `AS_PATH`. No parameter can be
  named `path-first` either.

`origin` and `path-first` read the path as it stands when their prepend
runs: the prepends before it, in statement order and in earlier chain
members, have already been placed. So `prepend as 65000 2; prepend as
path-first 1` places `65000 65000 65000`, and on a route that arrived
without an origin (an empty path, or only an `AS_SET`, where
`route.origin-as` has no value), `prepend as 65000 1; prepend as origin 1`
places `65000 65000`: the prepended `AS_SEQUENCE` is then the rightmost
one. Conditions still read the route as it arrived.

**Direction legality.** `self`, `origin`, and `path-first` are legal on import and
export chains. `peer` is **import-only**: on an export chain it would
prepend the *receiving* peer's own ASN, which the receiver rejects as
an own-AS loop (RFC 4271 §9.1.2) unless it runs allowas-in. A chain
using `prepend as peer` is rejected when it is attached as an export
chain (config load, reload, transaction) — a config error naming the
policy and term, never a per-route runtime surprise.

| operand  | import | export | notes |
|---|---|---|---|
| `self`   | yes | yes | outbound TE; inbound self-prepend biases best-path like the literal form already could |
| `peer`   | yes | **rejected at attach** | the inbound "prepend the neighbor's AS" idiom |
| `origin` | yes | yes | origin AS is already in the path — no loop-detection impact |
| `path-first` | yes | yes | route-derived BIRD `bgp_path.first` equivalent; does not read peer identity |

*Comparison:* FRR's `set as-path prepend last-as N` (prepend the
neighbor's AS) is its inbound route-map idiom and the model for
`prepend as peer`, which is import-only for that reason (see
**Direction legality** above).

**Failure is closed.** A computed operand resolves when the matched
term's action executes. If the value is unknown — no usable
`AS_SEQUENCE` for `origin`, no non-empty leading `AS_SEQUENCE` for
`path-first` (including a leading `AS_SET`), unknown peer ASN for `peer`, a chain
evaluated outside a daemon config for `self` — or the context value is
zero (AS 0 is prohibited on the wire, RFC 7607), the route is
**denied**: staged modifications are discarded, ASN 0 is never
prepended, and explain traces name the failing term, operand, and
reason.

**Update-group note.** `prepend as peer` reads peer identity, so (like
`peer.asn` guards) it keeps its peers out of shared update groups;
`self`, `origin`, and `path-first` never disqualify grouping.

Extended-community wire encoding follows the daemon's other
frontends: dotted-quad admin → RFC 4360 type 0x01, ASN > 65535 →
type 0x02, otherwise type 0x00 (subtype 0x02 RT / 0x03 RO).

## Tests

```rpol
test NAME {
    route { FIELD VALUE; ... }
    [peer { address IP; asn N; local-as N; group "NAME" }]
    expect POLICY[(args)] == accept|reject [with [only] ASSERTION, ...]
    expect POLICY[(args)] == error [KIND]
    expect chain [POLICY[(args)], ...] == accept|reject|error ...
    [expect ...]
}
```

Route fixture fields: `prefix`, `communities [..]`,
`large-communities [..]`, `ext-communities [..]`, `as-path "65001
65002"`, `next-hop`, `local-pref`, `med`, `rpki`, `aspa`,
`route-type`, `evpn-route-type`, `family`. Omitted fields are absent
attributes (so `local-pref`/`med` comparisons see the implicit 100/0,
`rpki` defaults to `not-found`, `aspa` to `unknown`; an omitted
`family` matches no family predicate — it is never derived from the
fixture's `prefix`).

The fixture `as-path` is decimal ASNs separated by spaces, with
`{...}` around an AS_SET: `as-path "64500 {64501 64502}"`. Anything
else (a comma, a word, an empty, nested, or unbalanced brace, segments
run together as in `64500{64501}`, an ASN above 4294967295) is a
compile diagnostic pointing at the offending character, so a typo
cannot become a silently absent or shorter path.
The fixture becomes a typed AS path, and evaluation reads it exactly
as it reads a received one: `route.as-path matches` sees the canonical
rendering (single spaces, `{64501 64502}`), `route.as-path.len` is the
RFC 4271 length (an AS_SET counts as 1, so the example has length 2),
and the origin AS is the last ASN of the rightmost AS_SEQUENCE
(`as-path "65010 64500"` has origin 64500; `as-path "{64500 64501}"`
has none). An empty string is a route without an AS path.

`with` assertions check the evaluation result's **modifications**
(the frontend has no live route to apply them to):

| assertion | passes when |
|---|---|
| `local-pref N`, `med N`, `next-hop IP\|self` | the policy sets that value |
| `prepend as ASN COUNT` | the policy's prepends place exactly `COUNT` copies of `ASN` in front of the path |
| `prepend "ASN ASN ..."` | the policy's prepends place exactly these ASNs in front of the path, leftmost first; asplain or asdot (`"666.5 666.5 2.5"`) |
| `community LIT` | `LIT` is in the add list (`large-community` / `ext-community` likewise) |
| `removes community LIT` | `LIT` is in the remove list (any community kind keyword) |
| `removes large-community GA:*:*` | every matching fixture value is in the remove list; the fixture must contain at least one match |
| `removes community *` / `removes large-community *:*:*` / `removes ext-community *` | every fixture value the matching strip-all form removes is in the remove list (for `community`, every value outside the well-known range); the fixture must carry at least one such value |
| `not removed community LIT` | `LIT` is present in the fixture and absent from the remove list (any community kind keyword) |
| `without community LIT` | `LIT` is **not** in the add list (any community kind keyword) |
| `without local-pref\|med\|next-hop\|prepend` | the policy leaves that attribute unchanged |

`expect p == accept` checks only the verdict, so a scrub or a
must-not-set guarantee needs its own assertion. Deleting the `remove`
below fails the test; without the `with` clause it would still pass:

```rpol
policy scrub {
    term internal { remove community 65530:4; remove large-community 65500:*:* }
    term rest { accept }
}
test member-cannot-send-internal-tags {
    route { communities [65530:4]; large-communities [65500:1:2, 64500:1:2] }
    expect scrub == accept with removes community 65530:4,
        removes large-community 65500:1:2, without local-pref
}
```

A wildcard scrub can be pinned with `removes large-community 65500:*:*`.
It checks the concrete matching values in the fixture. With `with only`, it does
not authorize removals outside that fixture. Pair it with
`not removed large-community 65501:1:2` and a fixture containing that value to
catch an overmatching scrub.

Extended-community removal assertions use the policy engine's decoded RT/RO
identity across encodings. Other extended communities match by their raw bytes.

`with only ASSERTION, ...` also rejects any unlisted modification, including
an extra scalar assignment, prepend, or community addition or removal. Community
lists are compared as sets, so their order and repeated assertions do not matter.
`without` and `not removed` constrain changes but do not authorize modifications
in an exact set. At least one assertion is required after `with only`; for an
empty set, use a negative assertion such as `with only without local-pref`.

`removes`, `without`, `not removed`, `only`, and `chain` are contextual words;
a policy named `chain` still works as `expect chain == accept`.
Computed prepend operands resolve
during evaluation, so the assertion states the **resolved** ASN:
`peer { asn 65010 }` + `prepend as peer 3` asserts as
`with prepend as 65010 3`. `peer { local-as N }` supplies the value
`prepend as self` resolves to (omitted ⇒ it fails closed and the
expectation is a `reject`).

**Errors are not verdicts.** An evaluation error (an action that needs
a value it cannot compute, or budget exhaustion — the ADR-0103 Decision 4
fail-closed rail; a condition never fails) FAILS an `accept` *or* `reject` expectation, with
the error kind and the failing policy/term rendered — a test cannot
accidentally pin a broken policy as "rejects correctly". To pin the
rail itself, expect it: `expect p == error` passes on any evaluation
error, and `expect p == error KIND` pins the kind (`error absent-operand`,
`error absent-prepend-operand`, ...; unknown
kinds are compile diagnostics with a suggestion). `with` assertions
cannot follow `== error` — an error discards every staged
modification. In the daemon the same route is denied; the test form
exists so CI can prove *which* rail fires:

```rpol
test missing-origin-fails-closed {
    route { as-path "{64500 64501}" }
    expect origin-pad == error absent-prepend-operand
}
```

The supported kinds are also the closed `kind` vocabulary of
`bgp_policy_eval_errors_total`:

| Kind | Runtime cause |
|---|---|
| `absent-operand` | An action needs a missing origin AS or peer ASN. |
| `absent-prepend-operand` | A computed prepend operand is missing or zero. |
| `loop-limit-exceeded` | A loop exceeds the per-loop iteration cap. |
| `fuel-exhausted` | Evaluation exhausts its work budget. |
| `divide-by-zero` | Defensive rail for a zero divisor in invalid compiled IR. |
| `remainder-by-zero` | Defensive rail for a zero remainder divisor in invalid compiled IR. |
| `unbound-local` | Defensive rail for a missing binding slot. |
| `stray-loop-control` | Defensive rail for loop control outside a loop. |
| `prepend-limit-exceeded` | Defensive rail for a chain that bypasses the static prepend cap. |
| `dataset-unpinned` | Defensive rail for a missing or wrong-kind dataset snapshot. |

The defensive rails have runtime emitters but cannot arise from correctly
compiled policies. The retired kinds `overflow`, `underflow` and
`clamp-inverted` have no runtime emitter and are no longer accepted in
`expect` statements. Arithmetic saturates and `clamp` returns
`min(max(value, lo), hi)`; expect the resulting verdict and modifications
instead. Literal-only invalid arithmetic remains a compile error.

**Chains.** `expect chain [p1, p2(300), ...]` evaluates the listed
policies as one import or export chain, in order, through the same chain
assembly the daemon uses for `import_policy_chain` / `export_policy_chain`:
a `reject` in any member ends the walk, a later member wins scalar
attributes, and a later `remove` cancels an earlier `add` of the same
community (and vice versa). Name the chain a member is configured in to
test what its routes actually receive:

```rpol
test hygiene-then-client {
    route { prefix 192.0.2.0/24; as-path "64500"; communities [65530:4] }
    expect chain [rs-hygiene, client-as64500(300)] == accept
        with removes community 65530:4, local-pref 300
}
```

The members must be defined or imported in the file under test. A
plain `expect p` is a one-member chain. A chain expectation is held to
the same `MAX_CHAIN_NODES` chain size cap as a configured chain; exceeding
it fails the test and names the member that crossed the limit.

Tests run at check time (`rbgp policy check`, CI, and
`rustbgpd --check`) without a running daemon. A daemon with
`[policy] require_passing_tests = true` also runs them on every config load
and refuses a startup or SIGHUP reload whose `.rpol` units fail their own
tests; see [the configuration reference](configuration.md). Testing a
*candidate* policy against a live RIB is `rbgp policy test` (below).

### Coverage and lints

`rbgp policy check FILE --coverage` reports which terms the `test`
blocks actually exercised — the blind spot route-map hit counters
miss and operators otherwise print-debug. For every term of every
tested policy it reports two distinct facts: was the guard ever
**evaluated** (the walk reached it), and did it ever **match**:

```text
coverage: 2/5 terms exercised by tests
matched coverage: 1/5 terms matched by tests
  policy edge-in
    term bogon-guard      evaluated 5x, matched 2x
    term customer-routes  evaluated 3x, never matched   <- no test route hits this
    term rest             never evaluated               <- earlier terms always decide
  policy unused-helper    never referenced by any test
```

"Never evaluated" means earlier terms always decided; "evaluated,
never matched" means no fixture satisfies the guard. A term counts as
*matched* in a walk when any of its conditional branches matched; an
unconditional term (`term catch-all { accept }`) matches whenever it
is reached. Parameterized policies aggregate across instantiations
(`expect p(200)` and `expect p(300)` both count toward `p`). With
imports, each policy is attributed to its defining file. An
`expect chain [...]` walk attributes each member's terms to that
member's policy, as if the member were expected on its own for the
part of the walk that reached it: when an earlier member rejects, the
later members count as tested with their terms never evaluated.

A policy's `default-action` is a fallback, not a source term: it adds no
term to coverage or hit counters. Explain reports a default verdict without
a matched term name. Test the unmatched case explicitly to exercise the
fallback; a coverage percentage does not prove that case ran.

Two boundaries, both deliberate:

- **`apply` is a predicate, not a walk.** `apply(p)` inlines `p`'s
  *decision* as a boolean guard, so term-level facts inside `p` are
  not attributable through it. A policy reached only via `apply` from
  tested policies is reported as `exercised via apply only (terms not
  attributable)` — its terms stay in the denominator; test it
  directly to cover them. `fn`s inline fully and have no terms.
- **Configured chains live in the daemon config**, which a standalone
  check cannot see; `expect chain [...]` states one explicitly. A
  policy referenced by no test and no `apply` is
  reported as such (and lint-flagged) *within these files only* — it
  may well be referenced by a config chain.

Static lints ride the same pass and need no fixtures:

- `unused-set` / `unused-dataset` / `unused-fn` — declared, never
  referenced by any policy (fn-to-fn calls count as uses).
- `unreachable-term` — an earlier term in the policy always decides.
  Statically-certain cases only: a bare `accept`/`reject`, an
  `if` chain whose branches and `else` are all terminal, or a constant
  guard that folds true (e.g. a folded builtin call). Runtime guards are
  conservatively reachable — this is not a reachability prover.
- `unreachable-branch` — an `if`, `else if` or `else` branch no route
  can reach: its guard folds to false, or an earlier guard of its chain
  folds to true. The same constant folding, no reachability proof.
- `unreferenced-policy` — no test and no `apply` names it in the
  compilation unit (with the config-chain caveat above).
- `optional-field-negation` — a negated test on an optional value, such as
  `!(optional-field == literal)` or `!(route.origin-as >= 64512)`, also
  matches a route without the value; see
  [optional comparison semantics](#expressions).

Coverage is a report: it never changes the exit code by itself. For
CI, `--coverage-min PCT` (which implies `--coverage`) exits **3**
when the exercised-term percentage falls below the threshold —
distinct from `1` (diagnostics) and `2` (test failures), which take
precedence. `--coverage-matched-min PCT` independently gates the
percentage of source terms matched by at least one test route. It
also implies `--coverage` and uses the same exit codes and precedence.
Both thresholds accept a finite percentage from **0 through 100**;
invalid values exit **2** before the policy file is loaded. Both
thresholds can be supplied; both must pass.

The matched threshold uses the same source-term denominator, including
untested and apply-only policies. A file with no terms reports 100%
for both percentages. This gate detects terms no fixture matches; it
does **not** guarantee branch coverage or detect every widened guard.
Removing a narrowing condition can increase matched coverage. Keep
negative-case fixtures that assert the intended route verdict and
modifications alongside positive fixtures.

`-j` adds a `coverage` object with stable keys
(`terms_total`, `terms_exercised`, `percent`, `terms_matched`,
`matched_percent`, per-policy `status` of
`tested`/`apply-only`/`untested`, per-term `evaluated`/`matched`
counts, and `lints` with machine-readable `kind` labels). `percent`
continues to mean evaluated-term coverage; `matched_percent` is the
separate matched-term percentage. The existing top-level `ok` describes
compilation and test success; use the process exit code to enforce a
requested coverage threshold.

## Modules and imports

```rpol
import "lib/bogons.rpol"
import "lib/customers.rpol"

policy edge-in {
    term bogon { if route.prefix in bogons { reject } }        # from lib/bogons.rpol
    term customer { if route.prefix in customers { accept } }  # from lib/customers.rpol
}
```

`import "relative/path.rpol"` is a top-level declaration that splices
another file's definitions — sets, functions, policies, and `test`
blocks — into the compilation unit. Modules are a **resolution
feature, not a language feature** (ADR-0103): after resolution the
compiled artifact is indistinguishable from one concatenated source,
and only diagnostics remember file boundaries (an error in an imported
file renders an excerpt of *that* file).

**Resolution and roots.** Import paths must be relative. Each resolves
against the importing file's directory first, then against each
configured policy root in order — `[policy] rpol_roots` in the daemon
config, repeatable `--root DIR` for `rbgp policy check`. The resolved
file (after symlinks and `..` are canonicalized away) must stay inside
the main file's directory or one of the roots; escaping every root is
a compile error. There is no ambient working-directory lookup.

**One flat namespace.** All modules share a single namespace after
resolution; defining the same set/fn/policy/test name in two modules
is a compile error naming both files. This is the deliberate V1 shape
— shared libraries (bogon lists, customer sets, hygiene policies) get
short unprefixed names at every use site. Qualified names
(`bogons.martians`) and selective imports are compatible later
extensions if real collision pain shows up; today, rename at the
definition.

**Determinism and reload identity.** Imports resolve depth-first in
declaration order — never filesystem order — and each file loads once
(diamond imports are fine; cycles are compile errors naming the
cycle). The policy identity the reload planner compares is the
**resolved module graph's content**: editing an imported leaf makes
every unit that (transitively) imports it read as changed, while a
byte-identical graph reloads as a content-equal no-op regardless of
file paths. One unit compiles all-or-nothing — a broken or missing
import anywhere rejects the whole load and the running generation is
untouched.

**Budgets.** Import nesting ≤ 8; a unit's total source ≤
`[policy] rpol_max_graph_bytes` (default 256 MiB — sized so IRR-scale
route-server renders, ~65 MB for a 320-member exchange, load with
headroom while still bounding load-time memory) across ≤ 64 files.
There is no separate per-file limit: a single oversized file exhausts
the graph budget by itself. All enforced at load with diagnostics;
evaluation never touches the filesystem. `rbgp policy check` (no
daemon config) checks against the default budget — pass
`--max-graph-bytes` to mirror a daemon whose budget was raised, so the
offline verdict matches the daemon's. The over-budget diagnostic names
the knob.

**Auditing.** `rbgp policy check FILE --list-deps [--root DIR]...`
prints the resolved graph — every module's canonical path, SHA-256
content hash, and imports — for packaging and change review.

Inline sources (`rbgp policy test`, the `TestPolicy` RPC) cannot
import: there is no filesystem to resolve against, and the diagnostic
says so. Check import-using files with `rbgp policy check`; the daemon
resolves them at config load / SIGHUP.

<a id="migration-example--extracting-a-shared-library"></a>
### Migration example

This example extracts a repeated bogon set into a shared library.

```rpol
# Before: every edge policy file carries its own bogon list.
prefix-set bogons { 10.0.0.0/8 le 32, 192.168.0.0/16 le 32, ... }
policy edge-in { term bogon { if route.prefix in bogons { reject } } ... }
```

```rpol
# lib/bogons.rpol — the shared library (sets, fns, even policies):
prefix-set bogons { 10.0.0.0/8 le 32, 192.168.0.0/16 le 32, ... }

# edge.rpol — after: one definition, imported where needed.
import "lib/bogons.rpol"
policy edge-in { term bogon { if route.prefix in bogons { reject } } ... }

test still-rejects-bogons {           # tests see imported names too
    route { prefix 10.1.0.0/24 }
    expect edge-in == reject
}
```

Because the resolved content is identical, this refactor reloads as a
no-op: no chain reinstall, no Route Refresh.

## Grammar sketch

```text
file        := (import-decl | dataset-decl | prefix-set-def | community-set-def | asn-set-def | fn-def | policy-def | test-def)*
import-decl := "import" STRING                    # contextual `import`
dataset-decl := "dataset" ("prefix-set" | "asn-set" | "community-set") IDENT   # contextual `dataset`
prefix-set-def    := "prefix-set" IDENT "{" [prefix-entry ("," prefix-entry)*] "}"
prefix-entry      := PREFIX ["ge" INT] ["le" INT]
community-set-def := "community-set" IDENT "{" [community-member ("," community-member)*] "}"
community-member  := community | COMMUNITY-PATTERN   # `65000:*`, `65000:1..9:*`, `RT:65000:*`
asn-set-def       := "asn-set" IDENT "{" [INT ("," INT)*] "}"
fn-def      := "fn" IDENT "(" [param ("," param)*] ")" "->" "u32"
               "{" fn-let* value "}"               # contextual `fn`
fn-let      := "let" IDENT "=" value [";"]
policy-def  := "policy" IDENT ["(" param ("," param)* ")"] "{" [default-decl] term* "}"
default-decl := "default-action" ("accept" | "reject") [";"]   # contextual; before all terms
param       := IDENT ":" "u32"
term        := "term" IDENT "{" stmt* "}"
stmt        := if-stmt | let-stmt | for-stmt | call-stmt | action [";"]
call-stmt   := "apply" IDENT ["(" call-arg ("," call-arg)* ")"] [";"]
call-arg    := INT | IDENT | community | IP          # checked against the parameter types
let-stmt    := "let" IDENT "=" value [";"]        # contextual `let`
for-stmt    := "for" IDENT "in" for-source "{" stmt* "}"   # contextual `for`
for-source  := "route" "." ("communities" | "as-path") | IDENT   # IDENT: asn-set
if-stmt     := "if" expr "{" body-stmt* "}" ["else" "{" body-stmt* "}"]
body-stmt   := let-stmt | call-stmt | action [";"]
action      := "accept" | "reject"
             | "break" | "continue"               # loop bodies only
             | "set" ("local-pref" | "med") value
             | "set" "next-hop" (IP | "self")
             | ("add" | "remove") ("community" | "large-community" | "ext-community") community
             | ("add" | "remove") "community" IDENT      # binding-valued
             | "remove" community-kw ["not"] "in" IDENT     # IDENT: community-set; contextual `not`
             | "prepend" "as" (u32arg | "self" | "peer" | "origin" | "path-first") INT
expr        := and ("||" and)*
and         := unary ("&&" unary)*
unary       := "!" unary | "(" expr ")" | "apply" "(" IDENT ["(" u32arg,* ")"] ")" | predicate
             | IDENT [arith-tail] ("=="|"!="|">="|"<=") value     # binding/parameter LHS
             | IDENT "in" IDENT            # binding vs asn-set / community-set
predicate   := field (("=="|"!="|">="|"<=") (rhs | value) | "in" IDENT | "has" community
             | "matches" STRING | "contains" u32arg)
             | field arith-tail ("=="|"!="|">="|"<=") value    # LHS arithmetic
             | "exists" field                                  # contextual `exists`
value       := mul (("+"|"-") mul)*                            # saturating u32
mul         := atom (("*"|"/"|"%") atom)*
atom        := INT | STD-COMMUNITY | IDENT | field | "(" value ")"   # IDENT: parameter or binding
             | ("min"|"max") "(" value "," value ")"
             | "clamp" "(" value "," value "," value ")"
             | IDENT "(" [value ("," value)*] ")"  # user-function call
field       := ("route" | "peer") ("." IDENT)+
u32arg      := INT | IDENT          # parameter reference
test-def    := "test" IDENT "{" dataset-override* route-block [peer-block] expect+ "}"
dataset-override := "dataset" IDENT "{" [member ("," member)*] "}"   # content for a declared dataset
expect      := "expect" (call | "chain" "[" call ("," call)* "]") "=="   # contextual `chain`
               (("accept"|"reject") ["with" assertion,*] | "error" [IDENT])   # IDENT: error kind
call        := IDENT ["(" INT,* ")"]
assertion   := ("local-pref" | "med") INT | "next-hop" (IP | "self")
             | "prepend" "as" INT INT | "prepend" STRING   # STRING: ASNs, leftmost first
             | ["removes" | "without"] community-kw COMMUNITY   # contextual `removes`/`without`
             | "without" ("local-pref" | "med" | "next-hop" | "prepend")
community-kw := "community" | "large-community" | "ext-community"
```

## Diagnostics

Every error carries labeled source spans (ariadne rendering), and the
compiler recovers to report multiple independent errors per file.
Unknown names (sets, datasets, policies, functions, fields, enum
members, parameters, test fixture fields) get did-you-mean suggestions
by edit distance, with a label at the suggested symbol's definition
site; an exact name match of a different kind is named as such
(`` `bogons` is an asn-set; `route.prefix in` needs a prefix-set ``)
instead of a spelling suggestion. Kind/type mismatches say what to
write instead.

```text
Error: unknown prefix-set `custmers`
   ╭─[ broken.rpol:5:28 ]
   │
 5 │         if route.prefix in custmers && route.rpki == vaild { reject }
   │                            ────┬───
   │                                ╰───── no prefix-set with this name
   │
   │ Note: did you mean `customers`?
───╯
```

## Formatting — `rbgp policy fmt`

`rbgp policy fmt FILE...` rewrites `.rpol` files into the one
canonical style — no options, no configuration (the gofmt
philosophy), so multi-file policy repos never drift.
`rbgp policy fmt --check FILE...` rewrites nothing and exits 1 with a
diff when any file is not canonically formatted — the CI mode. `-`
reads stdin and writes the formatted source to stdout (editor
integration). Exit codes: `0` all files clean/formatted, `1` a
`--check` difference or an error (unreadable file, or syntax errors —
broken files are refused, never rewritten).

The canonical style:

- Four-space indentation; one statement per line; opening braces on
  the construct's line (`policy p {`), closing braces on their own
  line.
- A `term` / `if` / `else` body stays on one line when it holds a
  single statement, contains no comments, and the line fits in 100
  columns — `term rest { accept }`,
  `term guard { if route.rpki == invalid { reject } }`. `policy`,
  `test`, `fn`, and `for` bodies always expand.
- Set bodies and test `route` / `peer` / `dataset` fixtures stay on
  one line when they fit, otherwise one member per line.
- Single spaces around operators and between tokens; none inside
  parentheses or after a call name (`min(a, b)`, `customer-in(200)`).
- Blank-line runs collapse to one; a blank line always precedes a
  top-level `policy`, `fn`, or `test` (attached comments move with
  it).
- No trailing whitespace; exactly one trailing newline. Expressions
  are never wrapped — a long guard stays on its line.

The formatter is layout-only: it never adds, removes, or reorders a
token. Semicolons stay exactly as written (they are optional in the
grammar), `import` declarations keep their order (resolution order is
semantic), and comments are preserved. Formatting is therefore
guaranteed parse-identical — and the formatter proves it on every
run, re-lexing its own output and refusing to write anything if the
token-and-comment sequence moved. Idempotence (`fmt(fmt(x)) ==
fmt(x)`) and compiled-IR identity are additionally property-tested
over every `.rpol` fixture in the repository.

## Using policies in the daemon

`.rpol` files become live daemon policy through `[policy] rpol_files`
in the config (full reference:
[`CONFIGURATION.md`](configuration.md)):

```toml
[policy]
rpol_files = ["policies/core.rpol"]        # relative to the config file
rpol_roots = ["policies/lib"]              # extra `import` roots, same resolution

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["customer-in(200)", "bogon-filter"]
```

Every file compiles (parse + typecheck) at config load; diagnostics
are load errors. Policies join the same namespace as
`[policy.definitions]` TOML policies — chains mix both freely, and
parameterized policies are instantiated by call-form (typed arguments,
checked at load; see [Parameters](#parameters)). Editing a referenced file + SIGHUP hot-applies
the change to exactly the peers whose resolved chains moved, with
Route Refresh for materially changed import policy.

### Live-RIB policy dry runs

`rbgp policy check` runs a file's own `test` blocks locally (CI-able,
no daemon). `rbgp policy test` goes further: it sends the candidate
source to a running daemon, which compiles it server-side and
evaluates the selected policy **read-only over a snapshot of the live
RIB** — no route state changes, no session impact, no policy counters
move (`SensitiveRead` authorization).

```console
$ rbgp policy test policies/core.rpol --policy "customer-in(200)" \
    --direction import --neighbor 10.0.0.2 --show-changes 2
policy "customer-in(200)" (import) over 1204 routes:
  accepted 990  rejected 214  modified 990
Term hits:
  rpki-guard                       3
  customer-routes                  990
  bogon-guard                      211
Changes (up to 2):
  10.10.1.0/24 (from 10.0.0.2):
    local_pref 100 -> 200
    communities + 65001:999
  10.10.2.0/24 (from 10.0.0.2):
    local_pref 100 -> 200
    communities + 65001:999
```

- `--direction import` evaluates the retained post-policy Adj-RIB-In
  (all peers, or one with `--neighbor`): routes import policy admitted
  when they were received or last re-evaluated, with the attributes it
  set. It can still hold routes the installed policy would now reject:
  after an import-policy change until a Route Refresh replay
  re-evaluates them (a reload requests one for affected peers;
  `rbgp neighbor <addr> refresh-in` requests one on demand), and under an
  active GR/LLGR window until re-sync/EOR. Rejected routes are not
  stored there, so the dry run shows candidate rejections or modifications
  among retained post-policy routes, but not which routes it would newly
  admit. If an earlier policy rewrote a prefix or origin attribute, the
  candidate sees that stored value rather than the original received value.
  Inspect currently rejected routes with
  `rbgp rib received PEER --rejected`, which keeps only the most recent
  rejections per peer (`[policy.reject_retention]`).
- `--direction export` evaluates Loc-RIB best routes, with `--neighbor`
  setting the peer context guards see (`peer.address`, `peer.asn`,
  `peer.group`).
- `--family ipv4_unicast|ipv6_unicast` filters the snapshot; V1 scope
  is IPv4/IPv6 unicast routes (other families are not walked).
- `--limit N` caps how many routes are evaluated (`N` ≥ 1; `--limit 0` is
  a usage error); `--all`, the default, evaluates every route.
  `--show-changes N` caps the before/after attribute diff samples.
- `--dataset NAME=PATH` supplies the contents of a candidate `.list` file
  for a dataset declared in the submitted source. Repeat it for each dataset
  the selected policy probes; a missing, duplicate, undeclared, or malformed
  binding fails the dry run. The CLI reads the files and sends their contents;
  the daemon does not read candidate paths. The source and all candidate
  contents together must fit below the 4 MiB RPC receive limit (up to 16
  datasets). Larger candidates need a smaller policy-specific input.
- `--show-rejected N` shows up to `N` candidate rejections among retained
  post-policy routes (`N` ≤ 1000), alongside the total `rejected` count.
  Samples follow the snapshot's canonical order. This previews the rejection
  of routes retained by the live daemon; it does not show routes a candidate
  would newly admit, replay the full import chain, or predict export impact.
  Without the flag, the output is unchanged.
- Compile diagnostics come back rendered exactly as `policy check`
  prints them (exit code 1); a clean run exits 0.
- `--json` emits the counts, per-term hits, and diffs structurally, plus
  `rejected_routes` when rejection sampling is requested.

Per-term hit counters answer "which term is doing the work" (the
IOS-XR `show pcl` idea); a term lowered to several IR steps reports one
row per step, named by the source statement it runs, such as `name.1` and
`name` (see [Lowering into the IR](#lowering-into-the-ir-normative)).

### Comparing a candidate with the installed export chain

`rbgp policy test` reports what one candidate policy does on its own.
Before an export-policy change on a route server or reflector, the question
is usually narrower: which routes would this peer stop receiving, start
receiving, or receive with different attributes? `rbgp policy compare`
answers it. It reads the export chain installed for the peer, builds the
candidate chain, and evaluates both read-only over the same version-fenced
walk of Loc-RIB best routes. Only routes whose outcome differs are counted:

```console
$ rbgp policy compare policies/rs.rpol --neighbor 198.51.100.3 \
    --policy client-x --replace client-x --max-samples 2
export to 198.51.100.3 over 4 routes:
  installed: rs-hygiene, client-x
  candidate: rs-hygiene, client-x
  newly rejected 1  newly accepted 0  attributes changed 1
Newly rejected (showing 1 of 1):
  198.18.0.0/15 (from 192.0.2.9)
    installed: local_pref unset -> 120
Attributes changed (showing 1 of 1):
  192.0.2.0/24 (from 192.0.2.9)
    installed: local_pref unset -> 200
    candidate: local_pref unset -> 300
```

- `--replace MEMBER --policy NAME` swaps one member of the installed chain,
  matched by its exact configured name (for example `client-x` or
  `customer-in(200)`), for `NAME` from the submitted file. Every other
  member stays in place, including members the daemon appended, so a route
  that an earlier member such as `rs-hygiene` rejects stays rejected on both
  sides and is never reported as a candidate accept.
- Without `--replace`, the repeated `--policy` values, in order, form the
  whole candidate chain, and the installed chain is replaced entirely.
- Classes: *newly rejected* (installed accepts, candidate rejects), *newly
  accepted* (installed rejects, candidate accepts), and *attributes changed*
  (both accept but the resulting attributes or next hop differ). A route
  both chains accept with the same result is not reported, even if the two
  chains reach it through different terms.
- Counts are exact over the walk; `--max-samples N` (up to 1000, default
  10) caps the routes listed per class, in canonical order. `--limit`,
  `--all`, `--family` and `--dataset` work as for `policy test`.
- Only policy chains are compared. Native egress steps (split horizon, iBGP
  and route-reflector rules, RS control communities, OTC, NO_EXPORT, ORF,
  family negotiation) apply to neither side, so a count can include routes
  those steps withhold from the peer anyway. Use
  `rbgp rib --prefix P advertised PEER --explain` for the full export ladder
  of one route.
- The installed chain is read when the walk starts, from the peer's live
  session: a peer that is not Established has no installed export chain and
  the command fails with `FAILED_PRECONDITION`. A grouped (update-group)
  member is compared through its own chain, exactly like an ungrouped peer.
- Like `policy test`, the run moves no counters, logs no evaluation
  warnings, and requires `SensitiveRead`. `--json` emits the chains, counts
  and samples structurally. The `ComparePolicy` RPC is outside the v1
  stability inventory. Export only: an import comparison over the retained
  post-policy Adj-RIB-In would not see routes the installed chain rejected.

### Explain — which term decided, and why

`.rpol` policies are first-class citizens of the daemon's explain
surfaces (ADR-0073 / ADR-0096 Decision 3.3):

- **`rbgp policy explain --neighbor A --prefix P --direction import`** (import): when the
  deciding chain member is an `.rpol` policy, the statement trace
  names the deciding **term** and lists every evaluated term with its
  guard rendered back to `.rpol` syntax and a matched / not-matched
  verdict:

  ```console
  $ rbgp policy explain --neighbor 10.0.0.2 --prefix 10.10.1.0/24 --direction import
  import policy explain — peer 10.0.0.2 prefix 10.10.1.0/24 (policy generation 3)
    permit
      decision: no policy rejected; chain default permit
      statements:
        [0] policy customer-in(200) term customer-routes permit  match: guard route.prefix in customers  set: local_pref 100 -> 200
          term rpki-guard: route.rpki == invalid => reject [not matched]
          term customer-routes: route.prefix in customers => set local-pref 200; accept [matched]
  ```

  The statement trace still names `customer-in(200)` because it records the
  members consulted. The Permit decision attribution is
  `chain_default_permit`: no member rejected the route.

  Guards render with sets shown by their source name; terms after the
  deciding one were never evaluated and carry no line. A term that
  modified without a verdict shows as `... => set med 5; continue`.
- **`rbgp rib --prefix P advertised PEER --explain`** (`ExplainAdvertisedRoute`,
  export): a Deny's policy attribution extends to `<chain-ref>:<term>` when
  the rejecting member is `.rpol` — e.g.
  `export policy "customer-in(200):transit-guard" denied this route`.
  TOML members render unchanged. A Permit after a nonempty export chain uses
  `chain_default_permit`; the modification list and live term counters retain
  the proof of which terms ran without mislabelling the final member as the
  source of the chain decision. When the deciding deny term tests validation
  state, `rpki_<state>` / `aspa_<state>` codes appear beside the export-policy
  stop and in JSON as `deny_validation`. The list is empty on other stops.

### Live per-term policy counters

Where `policy test` counts hits over a one-shot dry run, `rbgp policy
stats` reads the **live** counters of the chains actually installed on
the daemon: every route evaluated on the import or export path bumps
its matched terms' counters (relaxed atomics), and the query snapshots
them without resetting anything
(`SensitiveRead`).

```console
$ rbgp policy stats --neighbor 10.0.0.2 --direction both
10.0.0.2 export chain — 1204 routes evaluated since install (counter instance 4127)
  POLICY                           TERM                     HITS
  customer-in(200)                 rpki-guard               3
  customer-in(200)                 customer-routes          990
  bogon-filter                     bogons                   211
10.0.0.2 import chain — 890 routes evaluated since install (install generation 2)
  POLICY                           TERM                     HITS
  customer-in(200)                 rpki-guard               1
  customer-in(200)                 customer-routes          889
```

- Counters read as **since chain install**: replacing a peer's chain
  (policy reload / hot-apply / gNMI Set) installs a fresh instance and
  resets its counters to zero. A reload that re-resolves a peer to a
  **content-equal** chain skips the reinstall entirely — the installed
  instance and its counters survive; only peers whose resolved chain
  content moved reset. Export counters also restart when a peer's session
  registers again after a flap, unless the peer rejoins an update group
  that other members kept (it then shares that group's instance); a flap
  whose session task survives keeps the import counters.
- TOML chain members count too; their unnamed statements report by
  `term_index` (`statement 0`, `statement 1`, ...).
- `--direction` is required and selects **export**, **import**, or
  **both**. Export chains are read from the roster the RIB manager
  publishes; import chains are read from each session's published
  installed-counter state.
  Chainless sessions contribute no row. Every capture wait shares one
  absolute two-second deadline for the whole RPC; exhausting it fails the
  RPC as `DEADLINE_EXCEEDED`. By default a departed session, closed
  publication, or unavailable counter state fails the complete RPC as `UNAVAILABLE`, and a
  listener without the policy-stats runtime returns `FAILED_PRECONDITION`,
  all without partial rows. Counter availability does not establish session
  progress.
- Fleet `--direction import` or `both` reads may use `--allow-partial` to
  keep usable rows when selected sessions exit. Text marks the response
  `Partial import stats`; JSON adds sorted unique
  `incomplete_peer_addresses` when partial. An all-gone fleet may return no
  import rows and a nonempty incomplete list. This flag cannot be used with
  `--neighbor` or `--direction export`. Counter unavailability, stopped
  roster owners, export/dataset errors and deadlines still fail the whole
  request. Replacement sessions are not substituted into a selected roster.
- Import chains report their **install generation** (bumps on every
  chain install), so counters that reset to zero read as a chain
  replacement, not continuous history. A session's initial chain
  reports generation 0; content-equal re-resolves are not reinstalled,
  so the generation moves only when the peer's resolved chain content
  does. Export chains report their counter-instance id instead
  (`counter instance N` in text output): nonzero, shared by update-group
  members that share counters, and new whenever the counters restart,
  including at each session registration unless the peer rejoins an update
  group that other members kept. Compare it
  only for equality.
- Explain queries and `policy test` dry runs never move these
  counters — only live route evaluation counts.
- Chains that have denied routes through the **evaluation-error rail**
  (ADR-0103 Decision 4) report the count and the most recent blame
  line above the term table — `2 routes denied by evaluation errors
  (fail closed); last: absent-operand in policy origin-med term t` — the
  drill-down for a nonzero `bgp_policy_eval_errors_total{direction,
  kind}` rate. Error counts reset with the chain instance, like every
  other counter here.
- `--json` emits the rows structurally (`eval_errors`, `last_error`
  included).

## Comparison with other policy languages

This section compares `.rpol` with route maps, BIRD filters, and
GoBGP/OpenConfig statements.

- **vs FRR/Cisco route-maps:** a route-map is an ordered list of
  numbered entries over external prefix-lists / community-lists /
  as-path access-lists, with `on-match next` for fallthrough. `.rpol`
  expresses the same decisions (the M80 lab proves outcome parity
  route for route) but sets are declared next to the policies that
  use them, terms have names instead of sequence numbers, guards are
  composable boolean expressions rather than implicit ANDs of match
  clauses, and policies take parameters — one `customer-in(peer_lp)`
  replaces a route-map per peer. `.rpol` policies also take fixture
  tests and a dry run.
- **vs BIRD filters:** BIRD's filter language is a general-purpose
  interpreter — variables, arbitrary control flow, user-defined
  functions. `.rpol` is deliberately smaller: immutable bindings, only
  bounded `for` loops over finite sources, only pure non-recursive
  functions (fully inlined at compile time), no user types — so every
  policy terminates by construction and compiles to an indexed IR (a
  1,000-member set is one hash probe, not a linear scan). rustbgpd can
  also test a candidate policy read-only against the *running* daemon's
  RIB (`rbgp policy test`), trace which term decided a live route
  (`rbgp policy explain`), and read per-term live hit counters
  (`rbgp policy stats`).
- **vs GoBGP/OpenConfig statements (and rustbgpd's own TOML):** the
  same evaluation engine underneath — `.rpol` and TOML policies
  compile to one IR and mix freely in chains — so `.rpol` is a
  frontend upgrade, not a fork: named sets, parameters, composition,
  and tests on top of chain semantics that behave exactly as before.

## Migrating from BIRD and FRR

One worked example covering the two newest predicate surfaces
together — an origin lock over an ASN set, branched per address
family. This is exactly the policy shape the M80 interop lab proves
outcome-equivalent against FRR route for route (import and export).

The `.rpol` version — one policy, attached to a dual-stack peer's
import chain:

```rpol
asn-set partners { 64999, 65100 }

policy partner-in {
    term partner-v4 {
        if route.family == ipv4-unicast && route.origin-as in partners {
            set local-pref 210;
            add community 65001:604;
            accept
        }
    }
    term partner-v6 {
        if route.family == ipv6-unicast && route.origin-as in partners {
            set local-pref 220;
            add community 65001:606;
            accept
        }
    }
    term rest { accept }
}
```

The FRR route-map spelling of the same intent. The origin lock
becomes one anchored as-path regex per member (re-matched against the
rendered path string on every evaluation — the `.rpol` set is one
hash probe); the family branch has no route-map keyword, so the
classic idiom is an any-prefix match of the wanted family (a v4
prefix-list entry never matches a v6 route and vice versa), with the
route-map applied in both address families:

```text
bgp as-path access-list PARTNERS seq 5 permit _64999$
bgp as-path access-list PARTNERS seq 10 permit _65100$
ip prefix-list ANY-V4 seq 5 permit 0.0.0.0/0 le 32
ipv6 prefix-list ANY-V6 seq 5 permit ::/0 le 128
!
route-map PARTNER-IN permit 10
 match as-path PARTNERS
 match ip address prefix-list ANY-V4
 set local-preference 210
 set community 65001:604 additive
!
route-map PARTNER-IN permit 20
 match as-path PARTNERS
 match ipv6 address prefix-list ANY-V6
 set local-preference 220
 set community 65001:606 additive
!
route-map PARTNER-IN permit 30
```

The BIRD filter spelling — `bgp_path.last` is the origin AS,
`net.type` the family:

```text
define PARTNERS = [ 64999, 65100 ];

filter partner_in {
    if bgp_path.last ~ PARTNERS then {
        if net.type = NET_IP4 then {
            bgp_local_pref = 210;
            bgp_community.add((65001,604));
            accept;
        }
        if net.type = NET_IP6 then {
            bgp_local_pref = 220;
            bgp_community.add((65001,606));
            accept;
        }
    }
    accept;
}
```

What carries over mechanically: BIRD's `bgp_path.last ~ [...]` and
FRR's anchored `_ASN$` regexes both become `route.origin-as in
<asn-set>`; BIRD's `net.type` checks and FRR's per-AF route-map
application both become `route.family ==` guards on one shared
policy. What has no equivalent to migrate: the in-file `test` blocks,
`rbgp policy test` dry runs against the live RIB, and per-term live
hit counters — those come free after the rewrite.

## Migrating from IOS-XR RPL

Most RPL constructs have a direct `.rpol` spelling. Three of them have
different semantics, and a line-by-line port changes routing in those
places (1 to 3 below); replacing communities, which once differed too, now
ports directly (4). The RPL behavior below is taken from the
[IOS XR 24.x routing configuration guide for ASR 9000, "Implementing Routing Policy"](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/24xx/routing/configuration/guide/b-routing-cg-asr9000-24xx/implementing-routing-policy.html)
and the
[Cisco 8000 RPL command reference](https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/routing/cumulative/command/reference/b-routing-cr-cisco8000/m-rpl-commands-1.html)
(updated 2022-10-25).

### Construct mapping

| RPL | `.rpol` |
|---|---|
| `prefix-set NAME` with `ge`/`le`, `destination in NAME` | `prefix-set NAME { ... }`, `route.prefix in NAME` |
| `as-path originates-from '64500'` | `route.origin-as == 64500`, or `route.origin-as in <asn-set>` for many ASNs |
| `as-path length ge 50` | `route.as-path.len >= 50` |
| `as-path in (ios-regex '...')` | `route.as-path matches "..."` |
| `community matches-any NAME` | `route.communities in NAME` |
| `community-set` elements `65000:*`, `65000:[100..199]`, `private-as:*` | `community-set NAME { 65000:*, 65000:100..199, PRIVATE_AS:* }` (see [Community patterns](#community-patterns)) |
| `validation-state is invalid` | `route.rpki == invalid` |
| `set local-preference 200` | `set local-pref 200` |
| `set med 50` | `set med 50` |
| `set community (65000:100) additive` | `add community 65000:100` |
| `set community (65000:100)` | `remove community *; add community 65000:100` (see 4 below) |
| `delete community all` | `remove community *` |
| `delete community in NAME` / `delete community not in NAME` | `remove community in NAME` / `remove community not in NAME` (well-known values: see [Removing by set membership](#removing-by-set-membership)) |
| `delete extcommunity rt in NAME` / `delete extcommunity rt not in NAME` | `remove ext-community in NAME` / `remove ext-community not in NAME`; `not in` acts on route targets and route origins only, so other extended communities stay |
| `prepend as-path 65000 3` | `prepend as 65000 3` |
| `set next-hop self` | `set next-hop self` |
| `pass` followed by the policy end | `accept`, or nothing when no `default-action reject` is declared |
| `apply NAME` / `apply NAME(args)` | `apply NAME` / `apply NAME(args)` as a statement (see [`apply` as a statement](#apply-as-a-statement--calling-a-policy)); drop `default-action reject` from a ported child, since RPL children always return when they fall through |
| `if ... then ... elseif ... then ... else ... endif`, nested `if` | `if ... { ... } else if ... { ... } else { ... }`, nested up to four levels; one branch runs, and a branch without `accept` or `reject` continues with the rest of the policy |
| `drop` | `reject` |
| conditions read the route's initial data ("comparison operators always run on the initial data in the route", 24.x guide) | the same: reads never observe a staged `set` |
| `neighbor ... route-policy NAME in` | `import_policy_chain = ["NAME"]` on the neighbor (see [Using policies in the daemon](#using-policies-in-the-daemon)) |

A customer import policy written this way:

```rpol
prefix-set customer-prefixes { 192.0.2.0/24 le 26, 2001:db8:100::/40 le 48 }
asn-set customer-asns { 64500, 64501 }

policy customer-in {
    term too-long {
        if route.as-path.len >= 50 { reject }
    }
    term rpki-invalid {
        if route.rpki == invalid { reject }
    }
    term customer {
        if route.prefix in customer-prefixes && route.origin-as in customer-asns {
            set local-pref 200
            add community 65000:100
            accept
        }
    }
    term rest { reject }
}

test customer-route-is-tagged {
    route { prefix 192.0.2.0/24; as-path "64500"; rpki valid }
    expect customer-in == accept with local-pref 200, community 65000:100
}

test foreign-origin-is-dropped {
    route { prefix 192.0.2.0/24; as-path "64999" }
    expect customer-in == reject
}

test rpki-invalid-is-dropped {
    route { prefix 192.0.2.0/24; as-path "64500"; rpki invalid }
    expect customer-in == reject
}
```

### Behavior that differs

**1. The default disposition.** RPL drops a route at the end of a policy
unless the policy passed it or modified an attribute. `.rpol` accepts a
route that no term decides, unless the policy declares
`default-action reject`, and a modification never counts as a pass.

An RPL `set` also does not end the policy: later statements still run, and
a later `drop` still drops the route. A `.rpol` `accept` ends the policy at
once. A port that keeps RPL's implicit drop therefore needs
`default-action reject` and an `accept` at the end of each path on which
an RPL `set` would have passed the route, after that path's remaining
checks and modifications. Here the `set` is on the last branch, so the
`accept` can follow it directly:

```rpol
prefix-set customers { 192.0.2.0/24 le 24 }

# A literal port: the term only modifies, as an RPL `set` would.
policy literal-port {
    default-action reject
    term tag {
        if route.prefix in customers { set local-pref 200 }
    }
}

# The port that keeps RPL's outcome: accept where RPL's `set` passed.
policy ported {
    default-action reject
    term tag {
        if route.prefix in customers { set local-pref 200; accept }
    }
}

test modifying-does-not-pass {
    route { prefix 192.0.2.0/24 }
    expect literal-port == reject
}

test explicit-accept-passes {
    route { prefix 192.0.2.0/24 }
    expect ported == accept with local-pref 200
}

test unmatched-route-is-dropped {
    route { prefix 198.51.100.0/24 }
    expect ported == reject
}
```

When a later RPL statement can still drop the route, the `accept` goes after
it. This RPL policy tags customer routes and then drops long paths, so a
customer route with a long path is dropped:

```text
route-policy CUSTOMER-IN
  if destination in CUSTOMERS then
    set local-preference 200
  endif
  if as-path length ge 10 then
    drop
  endif
end-policy
```

An `accept` next to the `set` would accept that route. The port accepts in
a final term instead:

```rpol
prefix-set customers { 192.0.2.0/24 le 24 }

# Wrong: the accept skips the length check that follows.
policy accept-too-early {
    default-action reject
    term tag {
        if route.prefix in customers { set local-pref 200; accept }
    }
    term too-long {
        if route.as-path.len >= 10 { reject }
    }
}

# The port: modify, run the remaining checks, accept at the end.
policy accept-at-end {
    default-action reject
    term tag {
        if route.prefix in customers { set local-pref 200 }
    }
    term too-long {
        if route.as-path.len >= 10 { reject }
    }
    term pass-customers {
        if route.prefix in customers { accept }
    }
}

test early-accept-skips-the-length-check {
    route { prefix 192.0.2.0/24; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect accept-too-early == accept with local-pref 200
}

test long-customer-path-is-dropped {
    route { prefix 192.0.2.0/24; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect accept-at-end == reject
}

test short-customer-path-is-tagged {
    route { prefix 192.0.2.0/24; as-path "64500" }
    expect accept-at-end == accept with local-pref 200
}

test non-customer-is-dropped {
    route { prefix 198.51.100.0/24; as-path "64500" }
    expect accept-at-end == reject
}
```

Without `default-action reject`, the routes RPL would have dropped are
accepted instead:

```rpol
prefix-set customers { 192.0.2.0/24 le 24 }

# No default-action: a route no term decides is accepted.
policy no-default {
    term tag {
        if route.prefix in customers { set local-pref 200 }
    }
}

test unmatched-route-is-accepted {
    route { prefix 198.51.100.0/24 }
    expect no-default == accept with without local-pref
}
```

**2. `set med +N` and `set med -N`.** RPL saturates: a subtraction that
would go below zero sets 0, and an addition that would exceed
4294967295 sets 4294967295. `.rpol` arithmetic saturates the same way
(see "Saturating u32 value expressions"), so the literal port is exact:

```rpol
# `set med -10` and `set med +10`.
policy med-minus {
    term t { set med route.med - 10; accept }
}

policy med-plus {
    term t { set med route.med + 10; accept }
}

test floor-at-zero {
    route { prefix 192.0.2.0/24; med 4 }
    expect med-minus == accept with med 0
}

test ordinary-subtraction {
    route { prefix 192.0.2.0/24; med 50 }
    expect med-minus == accept with med 40
}

test ceiling-at-max {
    route { prefix 192.0.2.0/24; med 4294967290 }
    expect med-plus == accept with med 4294967295
}
```

**3. Repeated prepends.** RPL runs every `prepend as-path` in sequence,
each to the left of the last, and so does `.rpol`, across terms and chain
members. A literal port keeps RPL's result. The one difference is a
bound: one evaluation prepends at most 255 ASNs, the most one wire
`AS_SEQUENCE` segment holds. The compiler adds up the prepends along
every path to an `accept`, counting `if` branches that fall through
together and a prepend inside a loop once per iteration, so a policy, or
a chain when it is attached, that could exceed 255 is rejected; a prepend
inside a loop over a route attribute can never fit. RPL has no such
static limit.

```rpol
# RPL's documented example, `prepend as-path 2.5 3` then
# `prepend as-path 666.5 2`, in asplain (2.5 is 131077, 666.5 is 43646981).
policy prepend-twice {
    term t {
        prepend as 131077 3
        prepend as 43646981 2
        accept
    }
}

test later-prepend-lands-to-the-left {
    route { prefix 192.0.2.0/24; as-path "65010" }
    expect prepend-twice == accept with only prepend "666.5 666.5 2.5 2.5 2.5"
}

# Across a chain, the later member's prepend lands to the left.
policy prepend-65000 { term t { prepend as 65000 1 } }
policy prepend-65001 { term t { prepend as 65001 2 } }

test chain-prepends-accumulate {
    route { prefix 192.0.2.0/24; as-path "65010" }
    expect chain [prepend-65000, prepend-65001] == accept
        with only prepend "65001 65001 65000"
}
```

**4. Replacing communities.** RPL `set community` without `additive`
replaces the route's communities, keeping the well-known ones, and discards
the communities that earlier statements in the policy added. `.rpol` does the
same: actions apply in statement order, and `remove community *` removes every
non-well-known community the route arrived with and cancels every addition an
earlier statement, or an earlier member of the chain, staged (see "Actions").
`remove community *; add community 65000:100` is therefore the port, and an
`add community` after the replacement stays on the route, as in RPL. A full
scrub that also removes `NO_EXPORT` and the other well-known values is the
loop form, which, like any loop over a route attribute, denies a route
carrying more than 4,096 standard communities:

```rpol
# RPL `set community (65000:100)`: replace, keeping well-known values.
policy retag {
    term t {
        remove community *
        add community 65000:100
        accept
    }
}

# Remove every standard community, well-known values included.
policy scrub-all {
    term t {
        for c in route.communities { remove community c }
        accept
    }
}

# RPL `set community (65000:1) additive` followed by
# `set community (65000:100)`: the replacement discards the earlier
# addition, as in RPL.
policy tag-then-retag {
    term early { add community 65000:1 }
    term t {
        remove community *
        add community 65000:100
        accept
    }
}

# An addition after the replacement stays, as in RPL.
policy retag-then-tag {
    term t {
        remove community *
        add community 65000:100
        add community 65000:1
        accept
    }
}

policy tag-only {
    term t { add community 65000:1 }
}

test retag-keeps-no-export {
    route { prefix 192.0.2.0/24; communities [NO_EXPORT, 65010:1] }
    expect retag == accept with only removes community 65010:1,
        community 65000:100, not removed community NO_EXPORT
}

test the-replacement-discards-an-earlier-addition {
    route { prefix 192.0.2.0/24; communities [65010:1] }
    expect tag-then-retag == accept with only removes community 65010:1,
        community 65000:100, without community 65000:1
}

test a-later-addition-stays {
    route { prefix 192.0.2.0/24; communities [65010:1] }
    expect retag-then-tag == accept with only removes community 65010:1,
        community 65000:1, community 65000:100
}

test arrived-value-added-earlier-is-removed {
    route { prefix 192.0.2.0/24; communities [65000:1, 65010:1] }
    expect tag-then-retag == accept with only removes community 65000:1,
        removes community 65010:1, community 65000:100
}

test the-replacement-discards-an-earlier-chain-member-addition {
    route { prefix 192.0.2.0/24; communities [65010:1] }
    expect chain [tag-only, retag] == accept with only removes community 65010:1,
        community 65000:100, without community 65000:1
}

test scrub-all-removes-no-export {
    route { prefix 192.0.2.0/24; communities [NO_EXPORT, 65010:1] }
    expect scrub-all == accept with removes community NO_EXPORT,
        removes community 65010:1
}
```

### Constructs without a direct equivalent

These RPL constructs have no `.rpol` spelling today. Each has a form that
compiles now:

- **`as-path neighbor-is '65001'`**, with one ASN —
  `route.as-path matches "^65001_"`. `_` matches a space, a brace or either
  end of the rendered path, so the pattern matches a path whose first ASN
  is 65001, including a one-ASN path, and never a path that starts with an
  `AS_SET`.
- **`$parameter` of a set, address or community type** — declare the
  parameter with its type, such as `pfx: prefix-set`, `tag: community` or
  `nh: ip` (see "Parameters"), and pass the set name or value in the call.
- **`done`** — differs. RPL `done` accepts the route and runs no further
  policy statements. A `.rpol` `accept` ends only the current policy, and
  the neighbor's chain continues: a later member's `set` overrides the
  same attribute, community additions and removals merge, and a rejection
  by any member ends the chain with a rejection whatever its position.
  Putting the policy last in the configured chain keeps its scalar writes
  when the earlier members permit, but it cannot stop another member from
  rejecting. To skip later checks on the `done` path, keep those checks in
  later terms of the same policy, after a guarded `accept`, or make their
  chain members permit that path without modifying it. With
  `honor_graceful_shutdown` or `honor_blackhole`, the daemon's own EBGP
  import policies still run after the last configured member.

```rpol
# RPL `if gold then set local-preference 300 elseif silver then set
# local-preference 200 endif`, then `if as-path length ge 10 then drop
# endif`, then `pass`: a native `else if` whose branches continue to the
# later check.
community-set gold { 65000:1 }
community-set silver { 65000:2 }

policy tiers-then-check {
    term tiers {
        if route.communities in gold { set local-pref 300 }
        else if route.communities in silver { set local-pref 200 }
    }
    term too-long {
        if route.as-path.len >= 10 { reject }
    }
    term rest { accept }
}

# RPL `as-path neighbor-is '65001'`.
policy from-65001 {
    term t {
        if route.as-path matches "^65001_" { set local-pref 150; accept }
    }
    term rest { accept }
}

test first-branch-wins-over-a-later-branch {
    route { prefix 192.0.2.0/24; communities [65000:1, 65000:2] }
    expect tiers-then-check == accept with only local-pref 300
}

test later-check-runs-after-a-modifying-branch {
    route { prefix 192.0.2.0/24; communities [65000:1]; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect tiers-then-check == reject
}

test second-branch-applies-alone {
    route { prefix 192.0.2.0/24; communities [65000:2] }
    expect tiers-then-check == accept with only local-pref 200
}

test neighbor-is-matches-first-asn {
    route { prefix 192.0.2.0/24; as-path "65001 64500" }
    expect from-65001 == accept with local-pref 150
}

test neighbor-is-is-boundary-anchored {
    route { prefix 192.0.2.0/24; as-path "650011 64500" }
    expect from-65001 == accept with without local-pref
}

test neighbor-is-matches-a-one-asn-path {
    route { prefix 192.0.2.0/24; as-path "65001" }
    expect from-65001 == accept with local-pref 150
}

test neighbor-is-ignores-later-asns {
    route { prefix 192.0.2.0/24; as-path "64500 65001" }
    expect from-65001 == accept with without local-pref
}

# RPL `set local-preference 200` then `done`.
policy finish {
    term t { set local-pref 200; accept }
}

policy later-member {
    term t { set local-pref 100; accept }
}

policy reject-long {
    term t { if route.as-path.len >= 10 { reject } }
}

# The `done` path skips the length check that a later term holds.
policy done-then-checks {
    term done-path {
        if route.communities has 65000:1 { set local-pref 200; accept }
    }
    term too-long {
        if route.as-path.len >= 10 { reject }
    }
}

test accept-does-not-stop-the-chain {
    route { prefix 192.0.2.0/24 }
    expect chain [finish, later-member] == accept with local-pref 100
}

test last-in-the-chain-keeps-its-scalar-write {
    route { prefix 192.0.2.0/24 }
    expect chain [later-member, finish] == accept with local-pref 200
}

test a-rejection-wins-in-either-order {
    route { prefix 192.0.2.0/24; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect chain [reject-long, finish] == reject
    expect chain [finish, reject-long] == reject
}

test done-path-skips-the-later-check {
    route { prefix 192.0.2.0/24; communities [65000:1]; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect done-then-checks == accept with local-pref 200
}

test other-paths-still-run-the-check {
    route { prefix 192.0.2.0/24; as-path "64500 64501 64502 64503 64504 64505 64506 64507 64508 64509" }
    expect done-then-checks == reject
}
```

## Compatibility

Existing programs keep parsing and keep deciding the same way; a change to
an existing program's verdict or modifications is breaking even when it still
parses (see the [v1 compatibility rules](v1-stable-contract.md)). Two goldens
in `crates/policy/src/rpol/` hold the line: `lex_corpus.golden` pins how
every `.rpol` file in the tree lexes, and `decision_corpus.golden` pins the
verdict and exact staged modifications of every tracked `.rpol` file and
every `rpol` block in the repository's Markdown, run against their own `test` blocks and a fixed
route matrix, together with a case count for every language construct and
the term names every policy lowers to. A change to `decision_corpus.golden`
is a behaviour change; justify it in the PR.

### v1 construct inventory

The `rpol` section of [`v1-stable-surface.json`](v1-stable-surface.json)
classifies every construct the decision corpus names: the statements,
actions, expressions, fields, operators, operands, parameter types,
families, declarations, set members and test forms a program can use, and
the compiled IR kinds they lower to. A `v1` construct is part of the frozen
language: programs that use it keep parsing and keep their decisions.
`outside_v1` makes no promise of its own. The IR kinds are internal: a
lowering change may split, merge or rename them, but every change to them
must preserve the public semantics the corpus pins, the verdict and exact
modifications of every program, and the term names and row contents below.
A `v1` entry rests on the same evidence for every construct: the
typechecker validates it, the lowering compiles it, and corpus cases
execute it with real decisions. `route.evpn-route-type` and
`route.family == evpn`, for the scoped EVPN route-reflector role, are
checked against the supported types 1 to 6 with `==` and `!=` only, and
corpus cases run them against EVPN routes in the route matrix and the
curated programs. `scripts/check-v1-stable-surface.py` fails when the
corpus names a construct the inventory does not classify, when the
inventory names one that no longer exists, and when this table differs
from the inventory.

#### Term-name rulings

Lowered term names are part of the frozen surface: explain, test term hits
and policy stats rows show them, and the decision corpus pins each row's
name, position and action (not its guard; the decisions pin that), and
fails if one policy lowers two rows with one name. The
[lowering rule](#lowering-into-the-ir-normative)
settles these cases:

- **Stability.** A lowering change that keeps the source term and its final
  statement never renames the bare row, and renames no row of any other
  statement. It can add rows, such as a staged run split off the final
  row (`tag` gains `tag.1`), and it can renumber the `.<k>` rows of the
  one statement whose lowering changed. A source edit can rename rows:
  inserting, removing or reordering statements moves their `.<statement>`
  numbers, and replacing the final statement moves the bare name.
- **Collisions.** A source term name cannot contain `.` or `/` (names are
  kebab-case identifiers), and two terms in one policy cannot share a
  name, so a generated row such as `tag.1` or `t.1/lib:x` never matches a
  source term name. `term tag.1 { ... }` is a parse error.
- **A final statement that lowers to several IR terms** gives the bare
  name to the last row holding its own `accept` or `reject`, or, when none
  does, to its last row. Its other rows keep `.<k>`:
  `term w { set med 4; if A { accept } else { reject } }` lowers to `w.1`,
  `w.2.1` (the `accept`) and `w` (the `reject`), and
  `term q { set med 7; if A { reject } else { set med 8 } }` to `q.1`, `q`
  (the `reject`) and `q.2.2`. A row inlined from a called policy is not
  the statement's own verdict.
- **A final statement that lowers to no IR term**, such as an `if` with an
  empty body and no `else`, leaves no bare row.
- **Nested `if`, `else if` and `for`** belong to the term-body statement
  that contains them: their rows share its `.<statement>` and are told
  apart by `.<k>`. Rows inside a loop body run under the loop's one row
  and have no names of their own.
- **`apply` as a statement** names each inlined row
  `<term>[.<statement>].<k>/<call>:<called-term>`, where the called term's
  name follows the same rules inside the called policy. When the call is
  the final statement, its last row is bare, `t/lib:tag`, because a called
  policy's rows hold no verdict of the calling statement. A call whose
  policy emits no term lowers to its `:#enter` row alone.
- **A staged run that reaches the end of the term**, such as
  `term t { set med 1; add community 65000:1 }`, is named after its last
  statement, so it is the bare `t` when that statement is the final one.
- **Merged strip-all removals** (`remove community *` followed by
  `remove large-community *:*:*`) form one row named after the later
  statement.

#### Construct table

<!-- rpol-construct-inventory:start -->
| Construct | Class | Source form or reason |
|---|---|---|
| `ast.policy.default-action` | v1 | `default-action accept\|reject` policy fallback |
| `ast.policy.parameters` | v1 | parameterized policy `policy p(x: T)`, monomorphized per use |
| `ast.stmt.if` | v1 | `if <cond> { ... }` |
| `ast.stmt.else-if` | v1 | `else if` chain, first match wins |
| `ast.stmt.else` | v1 | final `else` branch |
| `ast.stmt.nested-if` | v1 | `if` inside an `if` body, at most four levels |
| `ast.stmt.for` | v1 | bounded `for <var> in <source>` loop |
| `ast.stmt.call` | v1 | `apply p(args)` statement: run a policy in place |
| `ast.for.field` | v1 | loop over `route.communities` or `route.as-path` |
| `ast.for.set` | v1 | loop over an `asn-set` |
| `ast.action.accept` | v1 | `accept` verdict |
| `ast.action.reject` | v1 | `reject` verdict |
| `ast.action.set-local-pref` | v1 | `set local-pref <value>` |
| `ast.action.set-med` | v1 | `set med <value>` |
| `ast.action.set-next-hop-self` | v1 | `set next-hop self` |
| `ast.action.set-next-hop-address` | v1 | `set next-hop <ip>` |
| `ast.action.set-next-hop-parameter` | v1 | `set next-hop <ip parameter>` |
| `ast.action.community-literal` | v1 | `add\|remove <kind> <literal>` |
| `ast.action.large-community-admin-wildcard` | v1 | `remove large-community <global>:*:*` |
| `ast.action.community-all` | v1 | `remove <kind> *`, keeping well-known standard values |
| `ast.action.community-binding` | v1 | `add\|remove community <binding>` |
| `ast.action.community-in-set` | v1 | `remove <kind> in <set>` |
| `ast.action.community-not-in-set` | v1 | `remove <kind> not in <set>` |
| `ast.community.add` | v1 | `add` community action |
| `ast.community.remove` | v1 | `remove` community action |
| `ast.community.kind.standard` | v1 | `community` action keyword, RFC 1997 |
| `ast.community.kind.large` | v1 | `large-community` action keyword, RFC 8092 |
| `ast.community.kind.extended` | v1 | `ext-community` action keyword, RFC 4360 RT/RO |
| `ast.community.kind.any` | v1 | `remove any-community in <set>`, every kind |
| `ast.literal.standard` | v1 | standard community literal or well-known name, `65000:100` |
| `ast.literal.large` | v1 | large community literal, `65000:1:2` |
| `ast.literal.route-target` | v1 | Route Target literal with an ASN administrator, `RT:65000:1` |
| `ast.literal.route-origin` | v1 | Route Origin literal with an ASN administrator, `RO:65000:1` |
| `ast.literal.route-target-ipv4` | v1 | Route Target literal with an IPv4 administrator, `RT:192.0.2.1:7` |
| `ast.literal.route-origin-ipv4` | v1 | Route Origin literal with an IPv4 administrator, `RO:192.0.2.1:7` |
| `ast.literal.well-known-ext` | v1 | `OV_VALID`/`OV_NOT_FOUND`/`OV_INVALID` literal |
| `ast.action.prepend` | v1 | `prepend as <asn\|parameter> <count>` |
| `ast.action.let` | v1 | immutable `let` binding |
| `ast.action.break` | v1 | `break` out of a loop |
| `ast.action.continue` | v1 | `continue` to the next loop iteration |
| `ast.expr.or` | v1 | `a \|\| b` |
| `ast.expr.and` | v1 | `a && b` |
| `ast.expr.not` | v1 | `!a` |
| `ast.expr.cmp` | v1 | `<field> ==\|!=\|>=\|<= <operand>` |
| `ast.expr.in` | v1 | `<field> in <set or dataset>` |
| `ast.expr.ident-in` | v1 | `<binding> in <set>` |
| `ast.expr.has` | v1 | `<community field> has <literal>` |
| `ast.expr.has-parameter` | v1 | `route.communities has <community parameter>` |
| `ast.expr.exists` | v1 | `exists <optional field>` |
| `ast.expr.matches` | v1 | `route.as-path matches "<regex>"` |
| `ast.expr.contains` | v1 | `route.as-path contains <asn>` |
| `ast.contains.literal` | v1 | `route.as-path contains <asn>` with a literal ASN |
| `ast.contains.parameter` | v1 | `route.as-path contains <parameter>` |
| `ast.expr.value-cmp` | v1 | comparison with arithmetic or a call on either side |
| `ast.expr.apply` | v1 | `apply(p)` predicate: would `p` accept |
| `ast.call-arg.integer` | v1 | integer argument to a policy call, `p(200)` |
| `ast.call-arg.name` | v1 | set, dataset or parameter name argument, `p(customers)` |
| `ast.call-arg.community` | v1 | standard community argument, `p(65000:100)` |
| `ast.call-arg.ip` | v1 | address argument, `p(192.0.2.1)` |
| `ast.value.literal` | v1 | integer literal in a value position |
| `ast.value.community` | v1 | standard community literal as a value |
| `ast.value.identifier` | v1 | parameter or binding reference |
| `ast.value.field` | v1 | u32 field read in a value position |
| `ast.value.arithmetic` | v1 | saturating arithmetic expression |
| `ast.value.call` | v1 | `min`/`max`/`clamp` or user `fn` call |
| `ast.arith.add` | v1 | `+`, saturating |
| `ast.arith.sub` | v1 | `-`, saturating at 0 |
| `ast.arith.mul` | v1 | `*`, saturating |
| `ast.arith.div` | v1 | `/` by a non-zero divisor |
| `ast.arith.rem` | v1 | `%` by a non-zero divisor |
| `ast.cmp.eq` | v1 | `==` |
| `ast.cmp.ne` | v1 | `!=` |
| `ast.cmp.ge` | v1 | `>=` |
| `ast.cmp.le` | v1 | `<=` |
| `ast.rhs.integer` | v1 | integer right-hand side, `route.med >= 50` |
| `ast.rhs.identifier` | v1 | enum value or parameter right-hand side, `route.rpki == valid` |
| `ast.rhs.ip` | v1 | address right-hand side, `route.next-hop == 192.0.2.1` |
| `ast.rhs.prefix` | v1 | prefix right-hand side, `route.prefix == 10.0.0.0/8` |
| `ast.rhs.string` | v1 | string right-hand side, `peer.group == "leaf"` |
| `ast.rhs.field` | v1 | field right-hand side, `route.next-hop == peer.address` |
| `ast.field.route.prefix` | v1 | `route.prefix` field |
| `ast.field.route.communities` | v1 | `route.communities` field |
| `ast.field.route.large-communities` | v1 | `route.large-communities` field |
| `ast.field.route.ext-communities` | v1 | `route.ext-communities` field |
| `ast.field.route.any-community` | v1 | `route.any-community in <set>`, every kind |
| `ast.field.route.as-path` | v1 | `route.as-path` field |
| `ast.field.route.as-path.len` | v1 | `route.as-path.len` |
| `ast.field.route.communities.len` | v1 | `route.communities.len` |
| `ast.field.route.large-communities.len` | v1 | `route.large-communities.len` |
| `ast.field.route.ext-communities.len` | v1 | `route.ext-communities.len` |
| `ast.field.route.origin-as` | v1 | `route.origin-as` field |
| `ast.field.route.local-pref` | v1 | `route.local-pref` field |
| `ast.field.route.med` | v1 | `route.med` field |
| `ast.field.route.next-hop` | v1 | `route.next-hop` field |
| `ast.field.route.rpki` | v1 | `route.rpki` field |
| `ast.field.route.aspa` | v1 | `route.aspa` field |
| `ast.field.route.route-type` | v1 | `route.route-type` field |
| `ast.field.route.evpn-route-type` | v1 | `route.evpn-route-type`, for the scoped EVPN reflector role |
| `ast.field.route.family` | v1 | `route.family` field |
| `ast.field.peer.address` | v1 | `peer.address` field |
| `ast.field.peer.asn` | v1 | `peer.asn` field |
| `ast.field.peer.group` | v1 | `peer.group` field |
| `ast.family.ipv4-unicast` | v1 | `route.family == ipv4-unicast` |
| `ast.family.ipv6-unicast` | v1 | `route.family == ipv6-unicast` |
| `ast.family.ipv4-labeled-unicast` | v1 | `route.family == ipv4-labeled-unicast` |
| `ast.family.ipv6-labeled-unicast` | v1 | `route.family == ipv6-labeled-unicast` |
| `ast.family.vpnv4` | v1 | `route.family == vpnv4` |
| `ast.family.vpnv6` | v1 | `route.family == vpnv6` |
| `ast.family.ipv4-flowspec` | v1 | `route.family == ipv4-flowspec` |
| `ast.family.ipv6-flowspec` | v1 | `route.family == ipv6-flowspec` |
| `ast.family.vpnv4-flowspec` | outside_v1 | IPv4 VPN FlowSpec policy family; qualification pending (ADR-0146) |
| `ast.family.vpnv6-flowspec` | outside_v1 | IPv6 VPN FlowSpec policy family; extends the ADR-0146 origination contract |
| `ast.family.evpn` | v1 | `route.family == evpn`, for the scoped EVPN reflector role |
| `ast.family.rtc` | v1 | `route.family == rtc` |
| `ast.family.bgp-ls` | v1 | `route.family == bgp-ls` |
| `ast.family.bgp-ls-vpn` | v1 | `route.family == bgp-ls-vpn` |
| `ast.prepend.self` | v1 | `prepend as self <count>` |
| `ast.prepend.peer` | v1 | `prepend as peer <count>` |
| `ast.prepend.origin` | v1 | `prepend as origin <count>` |
| `ast.prepend.path-first` | v1 | `prepend as path-first <count>` |
| `ast.prepend.literal` | v1 | `prepend as <asn> <count>` with a literal ASN |
| `ast.prepend.parameter` | v1 | `prepend as <parameter> <count>` |
| `ast.prepend.count.literal` | v1 | `prepend as <asn> <count>` with a literal count |
| `ast.prepend.count.parameter` | v1 | `prepend as <asn> <parameter>`, a parameter count |
| `ast.param.u32` | v1 | `u32` parameter type |
| `ast.param.prefix-set` | v1 | `prefix-set` parameter type |
| `ast.param.community-set` | v1 | `community-set` parameter type |
| `ast.param.asn-set` | v1 | `asn-set` parameter type |
| `ast.param.community` | v1 | `community` parameter type |
| `ast.param.ip` | v1 | `ip` parameter type |
| `ast.decl.import` | v1 | `import "path"` module import |
| `ast.decl.prefix-set` | v1 | `prefix-set` definition |
| `ast.decl.prefix-set.ge-le` | v1 | prefix-set entry `ge`/`le` bounds |
| `ast.decl.community-set` | v1 | `community-set` definition |
| `ast.decl.asn-set` | v1 | `asn-set` definition |
| `ast.decl.dataset.prefix-set` | v1 | `dataset prefix-set` declaration |
| `ast.decl.dataset.asn-set` | v1 | `dataset asn-set` declaration |
| `ast.decl.dataset.community-set` | v1 | `dataset community-set` declaration |
| `ast.decl.fn` | v1 | pure `fn` definition |
| `ast.decl.fn.let` | v1 | `let` inside a `fn` body |
| `ast.decl.test` | v1 | in-language `test` block |
| `ast.set.community.standard` | v1 | standard community member or well-known name |
| `ast.set.community.large` | v1 | large community member |
| `ast.set.community.route-target` | v1 | `RT:` member |
| `ast.set.community.route-origin` | v1 | `RO:` member |
| `ast.set.community.well-known-ext` | v1 | `OV_VALID`/`OV_NOT_FOUND`/`OV_INVALID` member |
| `ast.set.pattern.standard` | v1 | standard community pattern, `65000:*` |
| `ast.set.pattern.large` | v1 | large community pattern, `65000:1:*` |
| `ast.set.pattern.route-target` | v1 | `RT:` pattern |
| `ast.set.pattern.route-origin` | v1 | `RO:` pattern |
| `ast.set.pattern-field.range` | v1 | pattern field `*` or `a..b` |
| `ast.set.pattern-field.private-as` | v1 | pattern field `PRIVATE_AS` |
| `ast.test.dataset-override` | v1 | `dataset NAME { ... }` content in a test |
| `ast.test.route.prefix` | v1 | `route { prefix ... }` test fixture field |
| `ast.test.route.communities` | v1 | `route { communities ... }` test fixture field |
| `ast.test.route.large-communities` | v1 | `route { large-communities ... }` test fixture field |
| `ast.test.route.ext-communities` | v1 | `route { ext-communities ... }` test fixture field |
| `ast.test.route.as-path` | v1 | `route { as-path ... }` test fixture field |
| `ast.test.route.next-hop` | v1 | `route { next-hop ... }` test fixture field |
| `ast.test.route.local-pref` | v1 | `route { local-pref ... }` test fixture field |
| `ast.test.route.med` | v1 | `route { med ... }` test fixture field |
| `ast.test.route.rpki` | v1 | `route { rpki ... }` test fixture field |
| `ast.test.route.aspa` | v1 | `route { aspa ... }` test fixture field |
| `ast.test.route.route-type` | v1 | `route { route-type ... }` test fixture field |
| `ast.test.route.evpn-route-type` | v1 | `route { evpn-route-type ... }` test fixture field |
| `ast.test.route.family` | v1 | `route { family ... }` test fixture field |
| `ast.test.peer.address` | v1 | `peer { address ... }` test fixture field |
| `ast.test.peer.asn` | v1 | `peer { asn ... }` test fixture field |
| `ast.test.peer.local-as` | v1 | `peer { local-as ... }` test fixture field |
| `ast.test.peer.group` | v1 | `peer { group ... }` test fixture field |
| `ast.test.expect.chain` | v1 | `expect chain [p, q] == ...` |
| `ast.test.expect.with-only` | v1 | `with only` assertion list |
| `ast.test.expect.accept` | v1 | `expect p == accept` |
| `ast.test.expect.reject` | v1 | `expect p == reject` |
| `ast.test.expect.error` | v1 | `expect p == error [kind]` |
| `ast.test.with.local-pref` | v1 | `with local-pref N` |
| `ast.test.with.med` | v1 | `with med N` |
| `ast.test.with.next-hop` | v1 | `with next-hop <ip\|self>` |
| `ast.test.with.community` | v1 | `with <kind> <literal>` |
| `ast.test.with.prepend` | v1 | `with prepend as A N` |
| `ast.test.with.prepend-path` | v1 | `with prepend "A B"` |
| `ast.test.with.removes` | v1 | `with removes <kind> <literal>` |
| `ast.test.with.removes-large-admin` | v1 | `with removes large-community G:*:*` |
| `ast.test.with.removes-all` | v1 | `with removes <kind> *` |
| `ast.test.with.not-removed` | v1 | `with not removed <kind> <literal>` |
| `ast.test.with.without-community` | v1 | `with without <kind> <literal>` |
| `ast.test.with.without.local-pref` | v1 | `with without local-pref` |
| `ast.test.with.without.med` | v1 | `with without med` |
| `ast.test.with.without.next-hop` | v1 | `with without next-hop` |
| `ast.test.with.without.prepend` | v1 | `with without prepend` |
| `ir.guard.true` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.prefix-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.prefix-eq` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.prefix-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.community-contains` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.community-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.community-kind-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.as-path-matches` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.as-path-len` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.origin-as-eq` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.origin-as-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.origin-as-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.peer-as-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.local-pref` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.med` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.next-hop-eq` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.next-hop-eq-peer` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.next-hop-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.next-hop-ne-peer` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.neighbor-in` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.neighbor-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.route-type-is` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.route-type-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.evpn-route-type-is` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.evpn-route-type-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.family-is` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.family-ne` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.rpki-is` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.aspa-is` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.value-cmp` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.exists` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.local-in-asn-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.local-in-community-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.in-dataset` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.and` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.or` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.guard.not` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.const` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.community` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.field` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.local` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.binary` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.min` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.max` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.value.clamp` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.permit` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.deny` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.continue` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.bind` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.for-each` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.break` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.continue-loop` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.community-var` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.remove-large-community-admin` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.remove-all-communities` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.action.remove-communities-in-set` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.set-local-pref` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.set-local-pref-computed` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.set-med` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.set-med-computed` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.set-next-hop` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.prepend` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.prepend-computed` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.community-add` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.community-remove` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.large-community-add` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.large-community-remove` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.ext-community-add` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
| `ir.mod.ext-community-remove` | outside_v1 | internal compiled form; decisions that reach it are pinned through the source constructs that lower to it, and it may be split, merged or renamed |
<!-- rpol-construct-inventory:end -->

## Deliberate V1 exclusions

No `while` and no unbounded iteration of any kind — `for`
iterates finite sources only, capped and fuel-metered. No
user-defined types, no maps (safety is total by construction —
ADR-0096 Decision 2). No `as-path-set`. `if` nests at most four levels
deep (use `else if` or split the term; joining conditions with `&&` works
only where no operand can fail closed, since `&&` operands may evaluate in
either order). No
mutable state of any kind — `let` bindings are immutable, and reads never
observe staged `set` writes (read-back would break memoization and
needs its own ADR). EVPN route type takes only an integer literal
(no parameters — the value is wire-encoded u8). Full-form all-numeric
IPv6 literals (use `::` compression). These are scope decisions, not
parser accidents; each has an error message steering to the
supported form.

The ADR-0103 v2 extension program is **complete**: u32
arithmetic, `let` bindings, bounded loops, pure functions, modules
and imports, external datasets, and the metered-runtime operator
surface — eval-error counters, `rbgp policy stats` exposure,
error-pinning test expectations — have all shipped on the tree-walk
evaluator.
What deliberately did **not** ship: a bytecode tier (deferred behind
the ADR-0103 Decision 1 re-entry gate — built only if a real-workload
profile ever shows chain-walk dispatch dominating, which the
post-program re-measurement did not) and any WASM/host-function
escape hatch (rejected outright, ADR-0103 Decision 9 — external
*data* via datasets, never external code in the per-route path).
