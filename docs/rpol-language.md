# The rustbgpd policy language (`.rpol`) — reference

Status: **shipped** (ADR-0096, complete). The frontend — lexer,
parser, typechecker, in-language tests, and `rbgp policy check` — the
daemon integration — `[policy] rpol_files` config references, mixed
TOML/rpol chains, SIGHUP hot-apply, and the `rbgp policy test`
live-RIB dry run — and the explain surfaces — per-term statement
traces in `rbgp policy explain` / `rbgp rib advertised --explain` and
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
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
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

Exit codes: `0` clean, `1` compile diagnostics (or unreadable file),
`2` in-language test failures. `--json` emits a machine-readable
report.

## Lexical structure

- **Comments**: `#` to end of line.
- **Identifiers** (set, policy, term, test, parameter names) are
  kebab-case: `[A-Za-z_][A-Za-z0-9_]*(-[A-Za-z0-9_]+)*`. There is no
  arithmetic in the language, so `-` inside names is unambiguous.
- **Reserved keywords** (not usable as names): `prefix-set`,
  `community-set`, `policy`, `term`, `test`, `if`, `else`, `set`,
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
  - Strings (AS-path regexes, peer-group names): `"..."` with `\"`
    and `\\` escapes.
- **Statement separators**: `;` between statements is conventional
  but optional (the grammar is unambiguous without it); the idiomatic
  style semicolon-terminates everything except a final verdict.

## Types

The type universe is fixed; there are no user-defined types, maps, or
loops (ADR-0096 Decision 2/4), and inference is trivial: every field
has a known type and every operator a fixed signature.

| Type | Values | Where |
|---|---|---|
| bool | guard expressions | `if` conditions |
| u32 | integer literals, parameters | `local-pref`, `med`, `as-path.len`, `origin-as`, `peer.asn`, arguments |
| prefix | prefix literals | `route.prefix` |
| community (3 kinds) | community literals | community lists, sets, actions |
| as-path | — (matched, never named) | `route.as-path` |
| rpki-state | `valid`, `invalid`, `not-found` | `route.rpki` |
| aspa-state | `valid`, `invalid`, `unknown` | `route.aspa` |
| route-type | `local`, `internal`, `external` | `route.route-type` |
| route-family | `ipv4-unicast`, `ipv6-unicast`, `ipv4-labeled-unicast`, `ipv6-labeled-unicast`, `vpnv4`, `vpnv6`, `ipv4-flowspec`, `ipv6-flowspec`, `evpn`, `rtc`, `bgp-ls`, `bgp-ls-vpn` | `route.family` |
| IP address | address literals | `route.next-hop`, `peer.address` |
| string | string literals | regexes, `peer.group` |

## Sets

```rpol
prefix-set NAME { PREFIX [ge N] [le N], ... }
community-set NAME { COMMUNITY-LITERAL, ... }
asn-set NAME { ASN, ... }
```

- `ge`/`le` bounds are per member, with the same semantics as the
  TOML frontend (and Cisco/Juniper prefix lists): the candidate is
  masked at the member's length and its length must fall in the
  derived range (`ge` only → `ge..=address_bits`; `le` only →
  `member_len..=le`; neither → exact length).
- Community sets may mix standard, large, and extended members.
  Membership (`in`) matches when **any route community of any kind
  matches any member** — the set is kind-partitioned internally, and
  the field you write it against (`route.communities in tagged`)
  reads as documentation, not a kind filter.
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

## Policies, terms, and evaluation order

```rpol
policy NAME[(param: u32, ...)] {
    term NAME { statement... }
    ...
}
```

- Terms evaluate in order. Statements inside a term are: bare actions,
  or `if <expr> { actions... } [else { actions... }]`. `if` bodies are
  flat action lists — **no nested `if`** in V1 (split the condition
  with `&&` or use another term).
- **Verdicts**: `accept` permits the route (with all modifications
  executed so far in this policy); `reject` denies it (a denied route
  has no attributes — modifications in a rejecting branch are
  discarded). A verdict ends the policy's evaluation.
- **Fallthrough**: if a guard doesn't match, or a matched body ends
  without a verdict, evaluation continues to the next term.
  Modifications executed along the way (Junos-style
  modify-and-continue) are kept and merged into the eventual accept.
- **End of policy without a verdict = accept** (with any accumulated
  modifications). In chain terms: the policy raises no objection and
  the chain continues — this matches the GoBGP-style chain semantics
  the daemon already uses (each policy's permit accumulates and
  continues; a deny terminates the chain).
- Statements after a bare `accept`/`reject` in the same term (or
  actions after a verdict in the same `if` body) are **unreachable
  and a compile error**.

### Lowering into the IR (normative)

The IR's `Term` is one `(guard, action)` pair; an `.rpol` term lowers
to one or more IR terms:

- Each `if` becomes an IR term (guard = condition); its `else`
  becomes a following IR term guarded by the negated condition.
- A run of bare modification actions flushes as an unconditional
  `Continue` IR term (a small IR addition made for this frontend:
  guard matched → apply modifications → keep walking this policy's
  terms).
- When one `.rpol` term produces multiple IR terms they are named
  `<term>.<n>` (1-based); a lone IR term keeps the plain term name.
  Explain surfaces will render these names.

### Parameters

Parameters are `u32` only in V1 and can appear anywhere a u32 is
expected (`set local-pref peer_lp`, `route.local-pref >= peer_lp`,
`apply(p(peer_lp))`, `route.as-path contains asn_param`). A
parameterized policy is a **template**: each use site with concrete
arguments is monomorphized at compile time (clone-with-substitution;
policies are small, this is microseconds). The evaluator only ever
sees constants. The `prepend` count must be a literal (1–255, it is
wire-encoded as u8).

## Expressions

Boolean operators, loosest to tightest: `||`, `&&`, `!`. Parentheses
group. Comparisons: `==`, `!=`, `>=`, `<=`.

| Predicate | Meaning |
|---|---|
| `route.prefix == 10.0.0.0/24` | exact prefix (same network *and* length) |
| `route.prefix in customers` | prefix-set membership (mask + ge/le ranges) |
| `route.communities has 65000:100` | route carries this community (kind-checked against the field) |
| `route.communities in tagged` | any route community matches any set member |
| `route.as-path.len >= 3` | AS-path ASN count (RFC 4271 counting) |
| `route.as-path contains 65001` | boundary-anchored ASN presence (sugar for `matches "_65001_"`) |
| `route.as-path matches "^65010"` | Cisco/Quagga-style regex; `_` is a boundary anchor |
| `route.origin-as == 64500` | origin AS — the last ASN of the rightmost non-empty `AS_SEQUENCE` (`==`/`!=` only) |
| `route.origin-as in customers` | asn-set membership (one hash probe) |
| `peer.asn in customers` | evaluation-peer ASN against the same asn-sets |
| `route.local-pref >= 200`, `route.med <= 50` | u32 comparisons; `==`/`!=` also allowed |
| `route.next-hop == 10.0.0.1` | next-hop equality (`==`/`!=` only) |
| `route.next-hop == peer.address` | strict next-hop — the one field-vs-field comparison; reads peer identity, so an export chain using it makes the peer ineligible for update-group sharing (`policy_peer_context`) |
| `route.rpki == invalid` | RPKI origin validation state |
| `route.aspa == unknown` | ASPA verification state |
| `route.route-type == external` | route source class |
| `route.evpn-route-type == 2` | EVPN route type (integer literal 1–5, RFC 7432 §7; `==`/`!=` only) |
| `route.family == ipv4-unicast` | typed AFI/SAFI route family (`==`/`!=` only); route-context-only, so it never disqualifies update-group sharing |
| `peer.address == 192.0.2.1` | evaluation-peer address |
| `peer.asn == 65010` | evaluation-peer ASN (`==`/`!=` only) |
| `peer.group == "leaf"` | evaluation-peer group name |
| `apply(other-policy)` / `apply(p(42))` | policy-as-predicate (below) |

**Implicit defaults** (identical to the TOML engine and RFC 4271):
comparisons against `route.local-pref` see **100** when the attribute
is absent, `route.med` sees **0**. Prefix predicates never match a
prefixless route (e.g. BGP-LS NLRIs); `route.next-hop`,
`route.route-type`, and `route.evpn-route-type` never match when the
corresponding attribute is absent. `route.origin-as` is absent on
empty and `AS_SET`-only paths and then matches neither `==` nor `!=`
nor `in` (`!(... in ...)` negates plainly, matching the prefix-set
precedent).
`route.route-type`, `route.evpn-route-type`, and `route.family` never
match when the corresponding attribute is absent.

`==` on u32 fields lowers to `>= v && <= v`; `!=` is its negation.

### `route.family` — one chain, many families

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
- Since end-of-policy defaults to accept, a policy that never
  `reject`s is constant-true under `apply`. Predicate policies should
  decide both ways (see `bogon-filter` above: match → `accept`,
  final term → `reject`).

## Actions

| Action | Effect |
|---|---|
| `accept` / `reject` | terminal verdict (see evaluation order) |
| `set local-pref <u32>` | override `LOCAL_PREF` |
| `set med <u32>` | override `MED` |
| `set next-hop <ip>` / `set next-hop self` | override `NEXT_HOP` |
| `add community 65001:999` / `remove community ...` | standard communities |
| `add large-community 65000:1:2` / `remove ...` | large communities |
| `add ext-community RT:65001:100` / `remove ...` | extended communities (RT/RO, or well-known: `add ext-community OV_INVALID`) |
| `prepend as <asn> <count>` | prepend `<count>` copies of `<asn>` (count: literal 1–255) |

The kind keyword must match the literal's kind (`add community
RT:...` is a compile error pointing at `add ext-community`). Within a
policy, later `set`s of the same attribute win; across a chain, the
existing merge semantics apply (later policy wins scalars, add/remove
lists merge with later-policy-wins cancellation).

Extended-community wire encoding follows the daemon's other
frontends: dotted-quad admin → RFC 4360 type 0x01, ASN > 65535 →
type 0x02, otherwise type 0x00 (subtype 0x02 RT / 0x03 RO).

## Tests

```rpol
test NAME {
    route { FIELD VALUE; ... }
    [peer { address IP; asn N; group "NAME" }]
    expect POLICY[(args)] == accept|reject [with ASSERTION, ...]
    [expect ...]
}
```

Route fixture fields: `prefix`, `communities [..]`,
`large-communities [..]`, `ext-communities [..]`, `as-path "65001
65002"`, `next-hop`, `local-pref`, `med`, `rpki`, `aspa`,
`route-type`, `evpn-route-type`. Omitted fields are absent attributes
(so `local-pref`/`med` comparisons see the implicit 100/0, `rpki`
defaults to `not-found`, `aspa` to `unknown`). The fixture AS-path
length is the whitespace-word count of the string form; the fixture
origin AS is the last plain ASN outside `{...}` AS_SET braces
(mirroring the typed-path rule), so `as-path "65010 64500"` has
origin 64500 and `as-path "{64500 64501}"` has none.
`route-type`, `evpn-route-type`, `family`. Omitted fields are absent
attributes (so `local-pref`/`med` comparisons see the implicit 100/0,
`rpki` defaults to `not-found`, `aspa` to `unknown`; an omitted
`family` matches no family predicate — it is never derived from the
fixture's `prefix`). The fixture AS-path
length is the whitespace-word count of the string form.

`with` assertions check the evaluation result's **modifications**
(the frontend has no live route to apply them to): `local-pref N`,
`med N`, `next-hop IP|self`, `community LIT` (and
`large-community`/`ext-community`, asserting presence in the add
lists), `prepend as ASN COUNT`.

Tests run at check time (`rbgp policy check`, CI) with zero daemon
involvement. Testing a *candidate* policy against a live RIB is
`rbgp policy test` (below).

## Grammar sketch

```text
file        := (prefix-set-def | community-set-def | asn-set-def | policy-def | test-def)*
prefix-set-def    := "prefix-set" IDENT "{" [prefix-entry ("," prefix-entry)*] "}"
prefix-entry      := PREFIX ["ge" INT] ["le" INT]
community-set-def := "community-set" IDENT "{" [community ("," community)*] "}"
asn-set-def       := "asn-set" IDENT "{" [INT ("," INT)*] "}"
policy-def  := "policy" IDENT ["(" param ("," param)* ")"] "{" term* "}"
param       := IDENT ":" "u32"
term        := "term" IDENT "{" stmt* "}"
stmt        := if-stmt | action [";"]
if-stmt     := "if" expr "{" (action [";"])* "}" ["else" "{" (action [";"])* "}"]
action      := "accept" | "reject"
             | "set" ("local-pref" | "med") u32arg
             | "set" "next-hop" (IP | "self")
             | ("add" | "remove") ("community" | "large-community" | "ext-community") community
             | "prepend" "as" u32arg INT
expr        := and ("||" and)*
and         := unary ("&&" unary)*
unary       := "!" unary | "(" expr ")" | "apply" "(" IDENT ["(" u32arg,* ")"] ")" | predicate
predicate   := field (("=="|"!="|">="|"<=") rhs | "in" IDENT | "has" community
             | "matches" STRING | "contains" u32arg)
field       := ("route" | "peer") ("." IDENT)+
u32arg      := INT | IDENT          # parameter reference
test-def    := "test" IDENT "{" route-block [peer-block] expect+ "}"
expect      := "expect" IDENT ["(" INT,* ")"] "==" ("accept"|"reject") ["with" assertion,*]
```

## Diagnostics

Every error carries labeled source spans (ariadne rendering), and the
compiler recovers to report multiple independent errors per file.
Unknown names (sets, policies, fields, enum members, parameters, test
fixture fields) get did-you-mean suggestions by edit distance;
kind/type mismatches say what to write instead.

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

## Using policies in the daemon

`.rpol` files become live daemon policy through `[policy] rpol_files`
in the config (full reference:
[`CONFIGURATION.md`](CONFIGURATION.md)):

```toml
[policy]
rpol_files = ["policies/core.rpol"]        # relative to the config file

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["customer-in(200)", "bogon-filter"]
```

Every file compiles (parse + typecheck) at config load; diagnostics
are load errors. Policies join the same namespace as
`[policy.definitions]` TOML policies — chains mix both freely, and
parameterized policies are instantiated by call-form (`u32` arguments,
arity-checked at load). Editing a referenced file + SIGHUP hot-applies
the change to exactly the peers whose resolved chains moved, with
Route Refresh for materially changed import policy.

### `rbgp policy test` — dry-run against the live RIB

`rbgp policy check` runs a file's own `test` blocks locally (CI-able,
no daemon). `rbgp policy test` goes further: it sends the candidate
source to a running daemon, which compiles it server-side and
evaluates the selected policy **read-only over a snapshot of the live
RIB** — no route state changes, no session impact, no policy counters
move (`SensitiveRead` authorization).

```console
$ rbgp policy test policies/core.rpol --policy "customer-in(200)" \
    --direction import --peer 10.0.0.2 --show-changes 2
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

- `--direction import` evaluates Adj-RIB-In routes (all peers, or one
  with `--peer`); `--direction export` evaluates Loc-RIB best routes,
  with `--peer` setting the peer context guards see (`peer.address`,
  `peer.asn`, `peer.group`).
- `--family ipv4_unicast|ipv6_unicast` filters the snapshot; V1 scope
  is IPv4/IPv6 unicast routes (other families are not walked).
- `--limit N` caps how many routes are evaluated; `--show-changes N`
  caps the before/after attribute diff samples.
- Compile diagnostics come back rendered exactly as `policy check`
  prints them (exit code 1); a clean run exits 0.
- `--json` emits the counts, per-term hits, and diffs structurally.

Per-term hit counters answer "which term is doing the work" (the
IOS-XR `show pcl` idea); a term lowered to several IR steps reports as
`name.1`, `name.2`, ....

### Explain — which term decided, and why

`.rpol` policies are first-class citizens of the daemon's explain
surfaces (ADR-0073 / ADR-0096 Decision 3.3):

- **`rbgp policy explain --neighbor A --prefix P`** (import): when the
  deciding chain member is an `.rpol` policy, the statement trace
  names the deciding **term** and lists every evaluated term with its
  guard rendered back to `.rpol` syntax and a matched / not-matched
  verdict:

  ```console
  $ rbgp policy explain --neighbor 10.0.0.2 --prefix 10.10.1.0/24
  import policy explain — peer 10.0.0.2 prefix 10.10.1.0/24 (policy generation 3)
    permit
      policy:  customer-in(200)
      statements:
        [0] policy customer-in(200) term customer-routes permit  match: guard route.prefix in customers  set: local_pref 100 -> 200
          term rpki-guard: route.rpki == invalid => reject [not matched]
          term customer-routes: route.prefix in customers => set local-pref 200; accept [matched]
  ```

  Guards render with sets shown by their source name; terms after the
  deciding one were never evaluated and carry no line. A term that
  modified without a verdict shows as `... => set med 5; continue`.
- **`rbgp rib advertised --explain`** (`ExplainAdvertisedRoute`,
  export): the policy attribution extends to `<chain-ref>:<term>` when
  the deciding member is `.rpol` — e.g.
  `export policy "customer-in(200):transit-guard" denied this route`.
  TOML members render unchanged.

### `rbgp policy stats` — live per-term hit counters

Where `policy test` counts hits over a one-shot dry run, `rbgp policy
stats` reads the **live** counters of the chains actually installed on
the daemon: every route evaluated on the import or export path bumps
its matched terms' counters (relaxed atomics — no measurable eval
cost), and the query snapshots them without resetting anything
(`SensitiveRead`).

```console
$ rbgp policy stats --peer 10.0.0.2 --direction both
10.0.0.2 export chain — 1204 routes evaluated since install
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
  resets its counters to zero. A session flap does not reset the
  RIB-side export counters (the chain instance survives).
- TOML chain members count too; their unnamed statements report by
  `term_index` (`statement 0`, `statement 1`, ...).
- `--direction` selects **export** (the default), **import**, or
  **both**. Export chains are read from the RIB manager; import chains
  are read from each live session task, so a peer without a live
  session reports no import chain.
- Import chains report their **install generation** (bumps on every
  chain install, content-equal reinstalls included), so counters that
  reset to zero read as a chain replacement, not continuous history.
  Export chains do not track an install generation yet.
- Explain queries and `policy test` dry runs never move these
  counters — only live route evaluation counts.
- `--json` emits the rows structurally.

## Positioning — how `.rpol` differs from BIRD filters and route-maps

- **vs FRR/Cisco route-maps:** a route-map is an ordered list of
  numbered entries over external prefix-lists / community-lists /
  as-path access-lists, with `on-match next` for fallthrough. `.rpol`
  expresses the same decisions (the M80 lab proves outcome parity
  route for route) but sets are declared next to the policies that
  use them, terms have names instead of sequence numbers, guards are
  composable boolean expressions rather than implicit ANDs of match
  clauses, and policies take parameters — one `customer-in(peer_lp)`
  replaces a route-map per peer. Route-maps have no unit tests and no
  dry run; `.rpol` has both.
- **vs BIRD filters:** BIRD's filter language is a general-purpose
  interpreter — variables, arbitrary control flow, user-defined
  functions. `.rpol` is deliberately smaller: no loops, no variables,
  no user types, so every policy terminates by construction and
  compiles to an indexed IR (a 1,000-member set is one hash probe,
  not a linear scan). What BIRD can't do: test a candidate policy
  read-only against the *running* daemon's RIB (`rbgp policy test`),
  trace which term decided a live route (`rbgp policy explain`), or
  read per-term live hit counters (`rbgp policy stats`).
- **vs GoBGP/OpenConfig statements (and rustbgpd's own TOML):** the
  same evaluation engine underneath — `.rpol` and TOML policies
  compile to one IR and mix freely in chains — so `.rpol` is a
  frontend upgrade, not a fork: named sets, parameters, composition,
  and tests on top of chain semantics that behave exactly as before.

## Deliberate V1 exclusions

No loops, no user-defined types, no maps (safety is total by
construction — ADR-0096 Decision 2). No `as-path-set`. No `else if`
chains and no nested `if` (keep terms small; use `&&` or more terms).
No arithmetic. EVPN route type takes only an integer literal (no
parameters — the value is wire-encoded u8). Full-form all-numeric
IPv6 literals (use `::` compression). These are scope decisions, not
parser accidents; each has an error message steering to the
supported form.
